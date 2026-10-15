//! Cluster mode for the Redis client: one connection per master, each command sent to the
//! node that owns its hash slot, and redirections followed the way `redis-cli -c` and every
//! cluster library follow them.
//!
//! * The slot map comes from `CLUSTER SLOTS` on the seed node, read before the model is told
//!   the client is connected.
//! * A command goes to the owner of its keys' slot (`utils::redis_keys::slot_keys`, the same
//!   table NetGet's server routes by); a keyless one to the seed.
//! * `-MOVED <slot> <addr>`: the slot now lives at `addr`. The map is corrected for that slot
//!   at once, refreshed from `addr` in full, and the command is sent again there.
//! * `-ASK <slot> <addr>`: this one command, and only it, goes to `addr` preceded by `ASKING`;
//!   the map is left alone, because the slot is still mid-migration.
//! * At most [`MAX_REDIRECTS`] redirections per command. A command still being redirected after
//!   that is answered with the last redirection error and `redirects_exhausted`, rather than
//!   chased forever between two nodes that disagree.
//!
//! Commands run one at a time, each to completion, so pub/sub is not available here: a
//! subscribed connection never completes.
use super::resp::{self, Reply};
use crate::utils::redis_keys::{key_hash_slot, slot_keys, CLUSTER_SLOTS};
use anyhow::{bail, ensure, Context, Result};
use serde_json::Value;
use std::collections::HashMap;
use std::time::Duration;
use tokio::io::{AsyncWriteExt, BufReader};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tracing::{debug, info, warn};

/// Redirections followed for one command before giving up.
pub const MAX_REDIRECTS: usize = 5;
/// Distinct nodes the router will open connections to. A slot map naming more is refused: it
/// is not a cluster this client was asked to talk to, it is a fan-out.
pub const MAX_NODES: usize = 64;
/// How long one node may take to answer one command.
pub const NODE_REPLY_TIMEOUT: Duration = Duration::from_secs(30);

struct NodeConn {
    reader: BufReader<OwnedReadHalf>,
    writer: OwnedWriteHalf,
}

/// A redirection a node answered with.
#[derive(Debug, Clone, PartialEq)]
pub enum Redirect {
    Moved(u16, String),
    Ask(u16, String),
}

/// Read a redirection out of an error reply.
pub fn parse_redirect(reply: &Reply) -> Option<Redirect> {
    let text = reply.value.get("error")?.as_str()?;
    let mut parts = text.split_whitespace();
    let word = parts.next()?;
    let slot: u16 = parts.next()?.parse().ok()?;
    let addr = parts.next()?.to_string();
    if slot >= CLUSTER_SLOTS || !addr.contains(':') {
        return None;
    }
    match word {
        "MOVED" => Some(Redirect::Moved(slot, addr)),
        "ASK" => Some(Redirect::Ask(slot, addr)),
        _ => None,
    }
}

/// One command's outcome.
pub struct Routed {
    pub reply: Reply,
    /// The node that gave the final answer.
    pub node: String,
    pub slot: Option<u16>,
    /// Each redirection followed, as the node wrote it (`MOVED 3999 127.0.0.1:7001`).
    pub redirects: Vec<String>,
    /// The command was still being redirected after [`MAX_REDIRECTS`].
    pub exhausted: bool,
}

/// The slot map and the node connections.
pub struct Router {
    seed: String,
    slots: Vec<Option<String>>,
    conns: HashMap<String, NodeConn>,
}

impl Router {
    /// Connect to the seed and read its slot map. Fails if the seed is not a cluster node.
    pub async fn connect(seed: &str) -> Result<Router> {
        let mut router = Router {
            seed: seed.to_string(),
            slots: vec![None; usize::from(CLUSTER_SLOTS)],
            conns: HashMap::new(),
        };
        router
            .refresh(seed)
            .await
            .with_context(|| format!("reading the cluster's slot map from {seed}"))?;
        Ok(router)
    }

    /// The seed connection's local address.
    pub fn local_addr(&self) -> Option<std::net::SocketAddr> {
        self.conns.get(&self.seed)?.writer.local_addr().ok()
    }

    /// Distinct nodes in the slot map.
    pub fn nodes(&self) -> Vec<String> {
        let mut nodes: Vec<String> = self.slots.iter().flatten().cloned().collect();
        nodes.sort();
        nodes.dedup();
        nodes
    }

    /// Owner of a slot, as the map has it.
    pub fn owner(&self, slot: u16) -> Option<&str> {
        self.slots[usize::from(slot)].as_deref()
    }

    async fn conn(&mut self, addr: &str) -> Result<&mut NodeConn> {
        if !self.conns.contains_key(addr) {
            ensure!(
                self.conns.len() < MAX_NODES,
                "refusing to open a connection to a {}th cluster node",
                MAX_NODES + 1
            );
            let stream = tokio::time::timeout(NODE_REPLY_TIMEOUT, TcpStream::connect(addr))
                .await
                .with_context(|| format!("connecting to cluster node {addr} timed out"))?
                .with_context(|| format!("connecting to cluster node {addr}"))?;
            let (r, w) = stream.into_split();
            info!("Redis cluster client connected to node {}", addr);
            self.conns.insert(
                addr.to_string(),
                NodeConn {
                    reader: BufReader::new(r),
                    writer: w,
                },
            );
        }
        Ok(self.conns.get_mut(addr).expect("inserted above"))
    }

    /// One command to one node, one reply back. A node that fails mid-exchange is forgotten so
    /// the next command reconnects rather than reading a desynchronised stream.
    async fn roundtrip(&mut self, addr: &str, args: &[Vec<u8>]) -> Result<Reply> {
        let result = async {
            let conn = self.conn(addr).await?;
            conn.writer.write_all(&resp::encode_command(args)).await?;
            conn.writer.flush().await?;
            tokio::time::timeout(NODE_REPLY_TIMEOUT, resp::read_reply(&mut conn.reader))
                .await
                .with_context(|| format!("cluster node {addr} did not answer"))??
                .with_context(|| format!("cluster node {addr} closed the connection"))
        }
        .await;
        if result.is_err() {
            self.conns.remove(addr);
        }
        result
    }

    /// Replace the slot map with `CLUSTER SLOTS` as `via` reports it.
    pub async fn refresh(&mut self, via: &str) -> Result<()> {
        let reply = self
            .roundtrip(via, &[b"CLUSTER".to_vec(), b"SLOTS".to_vec()])
            .await?;
        let ranges = reply
            .value
            .as_array()
            .with_context(|| format!("CLUSTER SLOTS answered {}", reply.response))?;
        let via_host = via.rsplit_once(':').map(|(h, _)| h).unwrap_or(via);
        let mut slots: Vec<Option<String>> = vec![None; usize::from(CLUSTER_SLOTS)];
        let mut nodes = std::collections::BTreeSet::new();
        for range in ranges {
            let parts = range
                .as_array()
                .context("a CLUSTER SLOTS entry is an array")?;
            let start = parts
                .first()
                .and_then(Value::as_u64)
                .context("slot range start")?;
            let end = parts
                .get(1)
                .and_then(Value::as_u64)
                .context("slot range end")?;
            ensure!(
                start <= end && end < u64::from(CLUSTER_SLOTS),
                "CLUSTER SLOTS names slots {start}-{end}"
            );
            let master = parts
                .get(2)
                .and_then(Value::as_array)
                .context("a slot range names its master")?;
            let host = master.first().and_then(Value::as_str).unwrap_or("");
            // An empty host means "the address you reached me on".
            let host = if host.is_empty() || host == "?" {
                via_host
            } else {
                host
            };
            let port = master
                .get(1)
                .and_then(Value::as_u64)
                .filter(|p| (1..=65535).contains(p))
                .context("a master's port")?;
            let addr = format!("{host}:{port}");
            nodes.insert(addr.clone());
            ensure!(
                nodes.len() <= MAX_NODES,
                "the slot map names more than {MAX_NODES} nodes"
            );
            for slot in start..=end {
                slots[slot as usize] = Some(addr.clone());
            }
        }
        ensure!(
            !nodes.is_empty(),
            "CLUSTER SLOTS assigned no slot to any node"
        );
        debug!(
            "Redis cluster slot map from {}: {} node(s), {} slot(s) assigned",
            via,
            nodes.len(),
            slots.iter().filter(|s| s.is_some()).count()
        );
        self.slots = slots;
        // Connections to nodes that left the map are closed.
        self.conns
            .retain(|addr, _| nodes.contains(addr) || *addr == self.seed);
        Ok(())
    }

    /// Run one command against the cluster.
    pub async fn execute(&mut self, args: &[Vec<u8>]) -> Result<Routed> {
        if args.is_empty() {
            bail!("an empty command");
        }
        let slot = slot_keys(args).first().map(|k| key_hash_slot(k));
        let mut target = slot
            .and_then(|s| self.slots[usize::from(s)].clone())
            .unwrap_or_else(|| self.seed.clone());
        let mut redirects = Vec::new();
        let mut asking = false;
        let mut redirects_left = MAX_REDIRECTS;
        loop {
            if asking {
                let ok = self.roundtrip(&target, &[b"ASKING".to_vec()]).await?;
                if ok.reply_type == "error" {
                    warn!(
                        "Redis cluster node {} refused ASKING: {}",
                        target, ok.response
                    );
                }
            }
            let reply = self.roundtrip(&target, args).await?;
            let Some(redirect) = parse_redirect(&reply) else {
                return Ok(Routed {
                    reply,
                    node: target,
                    slot,
                    redirects,
                    exhausted: false,
                });
            };
            if redirects_left == 0 {
                warn!(
                    "Redis cluster: still redirected after {} redirections; giving up on this \
                     command",
                    MAX_REDIRECTS
                );
                return Ok(Routed {
                    reply,
                    node: target,
                    slot,
                    redirects,
                    exhausted: true,
                });
            }
            redirects_left -= 1;
            redirects.push(
                reply
                    .value
                    .get("error")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
            );
            match redirect {
                Redirect::Moved(moved_slot, addr) => {
                    info!(
                        "Redis cluster: slot {} moved to {}; refreshing the slot map",
                        moved_slot, addr
                    );
                    self.slots[usize::from(moved_slot)] = Some(addr.clone());
                    if let Err(e) = self.refresh(&addr).await {
                        warn!(
                            "Redis cluster: refreshing the slot map from {} failed: {:#}",
                            addr, e
                        );
                        self.slots[usize::from(moved_slot)] = Some(addr.clone());
                    }
                    target = addr;
                    asking = false;
                }
                Redirect::Ask(_, addr) => {
                    target = addr;
                    asking = true;
                }
            }
        }
    }
}

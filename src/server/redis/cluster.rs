//! Cluster mode: this server presents itself as one master of a Redis Cluster whose shape the
//! operator declares in the `cluster_nodes` startup parameter, and which the model can change
//! at runtime with `redis_cluster_set_slot`.
//!
//! There is no cluster bus and no gossip. Several NetGet Redis servers form a cluster only in
//! the sense a client can observe: each is told the same topology, each answers the
//! `CLUSTER` introspection commands from it, and each redirects a command for a key whose hash
//! slot it does not own with `-MOVED <slot> <host>:<port>` — which is everything a cluster
//! client (`redis-cli -c`, redis-rs's `ClusterClient`) navigates by. The slot arithmetic is
//! `utils::redis_keys`, shared with NetGet's own cluster client.
//!
//! Slot migration follows `CLUSTER SETSLOT`'s states. A slot this node owns and has marked
//! *migrating* to another node answers every key in it with `-ASK <slot> <target>` — Redis
//! does so only for keys it no longer holds, and this server holds no keys, so every key has
//! "already moved". A slot this node is *importing* is served only to a connection that sent
//! `ASKING` immediately before; any other command for it gets `-MOVED` to the owner.
use super::resp_value::Resp;
use crate::utils::redis_keys::CLUSTER_SLOTS;
use anyhow::{bail, ensure, Context, Result};
use serde_json::Value;
use std::collections::BTreeMap;
use std::net::SocketAddr;

/// Most nodes a topology may name. A real cluster tops out around 1000; a hand-written
/// startup parameter with more than this is a mistake, and every `CLUSTER NODES` reply is
/// proportional to it.
pub const MAX_CLUSTER_NODES: usize = 256;

/// One master in the declared topology.
#[derive(Debug, Clone, PartialEq)]
pub struct ClusterNode {
    pub id: String,
    pub host: String,
    pub port: u16,
    pub epoch: u64,
}

impl ClusterNode {
    pub fn addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

/// Where a command goes.
#[derive(Debug, Clone, PartialEq)]
pub enum Route {
    /// Served here.
    Local,
    /// `-MOVED <slot> <addr>`.
    Moved(u16, String),
    /// `-ASK <slot> <addr>`.
    Ask(u16, String),
    /// Keys in more than one slot.
    CrossSlot,
    /// The slot is assigned to no node.
    Down(u16),
}

impl Route {
    /// The RESP error this route answers with, or `None` for [`Route::Local`].
    pub fn error(&self) -> Option<String> {
        match self {
            Route::Local => None,
            Route::Moved(slot, addr) => Some(format!("MOVED {slot} {addr}")),
            Route::Ask(slot, addr) => Some(format!("ASK {slot} {addr}")),
            Route::CrossSlot => {
                Some("CROSSSLOT Keys in request don't hash to the same slot".to_string())
            }
            Route::Down(_) => Some("CLUSTERDOWN Hash slot not served".to_string()),
        }
    }
}

/// The cluster as this node sees it.
#[derive(Debug, Clone)]
pub struct ClusterState {
    pub nodes: Vec<ClusterNode>,
    pub myself: usize,
    /// Owner of each slot, as an index into `nodes`.
    owner: Vec<Option<usize>>,
    migrating: BTreeMap<u16, usize>,
    importing: BTreeMap<u16, usize>,
    current_epoch: u64,
}

/// A node id: 40 lowercase hex characters. Derived from `host:port` when the topology does not
/// give one, so every server handed the same topology names every node the same way.
fn derive_id(addr: &str) -> String {
    // FNV-1a, three lanes with different offsets, truncated to 160 bits: stable across
    // processes and Rust versions, which `DefaultHasher` does not promise.
    let mut out = String::with_capacity(48);
    for seed in [
        0xcbf2_9ce4_8422_2325u64,
        0x8422_2325_cbf2_9ce4,
        0x9ce4_cbf2_2325_8422,
    ] {
        let mut h = seed;
        for b in addr.bytes() {
            h ^= u64::from(b);
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
        out.push_str(&format!("{h:016x}"));
    }
    out.truncate(40);
    out
}

fn valid_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 255
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b':'))
}

/// Parse a slot spec: an integer, `"N"` or `"A-B"`.
pub fn parse_slots(v: &Value) -> Result<std::ops::RangeInclusive<u16>> {
    let (a, b) = match v {
        Value::Number(n) => {
            let n = n.as_u64().context("a slot is a non-negative integer")?;
            (n, n)
        }
        Value::String(s) => match s.split_once('-') {
            Some((a, b)) => (
                a.trim().parse::<u64>().context("slot range start")?,
                b.trim().parse::<u64>().context("slot range end")?,
            ),
            None => {
                let n = s.trim().parse::<u64>().context("a slot is an integer")?;
                (n, n)
            }
        },
        _ => bail!("a slot is an integer or a \"start-end\" string"),
    };
    ensure!(
        a <= b && b < u64::from(CLUSTER_SLOTS),
        "slots run from 0 to {}, start first",
        CLUSTER_SLOTS - 1
    );
    Ok(a as u16..=b as u16)
}

impl ClusterState {
    /// Build the topology from the `cluster_nodes` startup parameter.
    ///
    /// Each entry is `{"host", "port", "slots": ["0-5460", …], "id"?, "myself"?}`. Exactly one
    /// entry is `myself`; its `host` and `port` default to the address this server bound, so a
    /// server started on port 0 can still describe itself. Two nodes may not claim one slot.
    pub fn from_param(value: &Value, bound: SocketAddr) -> Result<Self> {
        let entries = value
            .as_array()
            .context("cluster_nodes is an array of nodes")?;
        ensure!(!entries.is_empty(), "cluster_nodes names no node");
        ensure!(
            entries.len() <= MAX_CLUSTER_NODES,
            "cluster_nodes names more than {MAX_CLUSTER_NODES} nodes"
        );
        let mut nodes = Vec::new();
        let mut myself = None;
        let mut owner = vec![None; usize::from(CLUSTER_SLOTS)];
        for (i, entry) in entries.iter().enumerate() {
            let is_me = entry
                .get("myself")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            if is_me {
                ensure!(
                    myself.is_none(),
                    "more than one cluster node is marked myself"
                );
                myself = Some(i);
            }
            let host = match entry.get("host").and_then(Value::as_str) {
                Some(h) => h.to_string(),
                None if is_me => {
                    if bound.ip().is_unspecified() {
                        "127.0.0.1".to_string()
                    } else {
                        bound.ip().to_string()
                    }
                }
                None => bail!("cluster node {i} has no host"),
            };
            ensure!(
                valid_host(&host),
                "cluster node {i}'s host is not a hostname or IP address"
            );
            let port = match entry.get("port").and_then(Value::as_u64) {
                Some(p) if (1..=65535).contains(&p) => p as u16,
                Some(_) => bail!("cluster node {i}'s port is out of range"),
                None if is_me => bound.port(),
                None => bail!("cluster node {i} has no port"),
            };
            let addr = format!("{host}:{port}");
            let id = match entry.get("id").and_then(Value::as_str) {
                Some(id) => {
                    ensure!(
                        id.len() == 40 && id.bytes().all(|b| b.is_ascii_hexdigit()),
                        "cluster node {i}'s id is not 40 hex characters"
                    );
                    id.to_ascii_lowercase()
                }
                None => derive_id(&addr),
            };
            if let Some(slots) = entry.get("slots") {
                let specs = slots
                    .as_array()
                    .context("a node's slots is an array of \"start-end\" ranges")?;
                for spec in specs {
                    for slot in parse_slots(spec)? {
                        let cell = &mut owner[usize::from(slot)];
                        ensure!(cell.is_none(), "slot {slot} is claimed by two nodes");
                        *cell = Some(i);
                    }
                }
            }
            nodes.push(ClusterNode {
                id,
                host,
                port,
                epoch: i as u64 + 1,
            });
        }
        let myself = myself.context("no cluster node is marked myself: true")?;
        let mut seen = std::collections::HashSet::new();
        for n in &nodes {
            ensure!(
                seen.insert(n.id.clone()),
                "two cluster nodes share id {}",
                n.id
            );
        }
        let current_epoch = nodes.len() as u64;
        Ok(ClusterState {
            nodes,
            myself,
            owner,
            migrating: BTreeMap::new(),
            importing: BTreeMap::new(),
            current_epoch,
        })
    }

    pub fn me(&self) -> &ClusterNode {
        &self.nodes[self.myself]
    }

    pub fn owner_of(&self, slot: u16) -> Option<&ClusterNode> {
        self.owner[usize::from(slot)].map(|i| &self.nodes[i])
    }

    /// Where a command whose keys hash to `slots` goes. `asking` is the connection's one-shot
    /// `ASKING` flag.
    pub fn route(&self, slots: &[u16], asking: bool) -> Route {
        let Some(&slot) = slots.first() else {
            return Route::Local;
        };
        if slots.iter().any(|s| *s != slot) {
            return Route::CrossSlot;
        }
        match self.owner[usize::from(slot)] {
            Some(i) if i == self.myself => match self.migrating.get(&slot) {
                Some(&target) => Route::Ask(slot, self.nodes[target].addr()),
                None => Route::Local,
            },
            _ if asking && self.importing.contains_key(&slot) => Route::Local,
            Some(i) => Route::Moved(slot, self.nodes[i].addr()),
            None => Route::Down(slot),
        }
    }

    fn node_index(&self, addr_or_id: &str) -> Result<usize> {
        self.nodes
            .iter()
            .position(|n| n.addr() == addr_or_id || n.id == addr_or_id)
            .with_context(|| format!("no cluster node {addr_or_id}"))
    }

    /// `CLUSTER SETSLOT`, as an action: `state` is `node` (assign to `node`), `migrating` (this
    /// node's slot, moving to `node`), `importing` (from `node`), or `stable` (clear both).
    pub fn set_slot(
        &mut self,
        slots: std::ops::RangeInclusive<u16>,
        state: &str,
        node: Option<&str>,
    ) -> Result<String> {
        let target = node.map(|n| self.node_index(n)).transpose()?;
        let count = slots.clone().count();
        match state {
            "node" => {
                let t = target.context("state node needs the node that now owns the slots")?;
                for s in slots {
                    self.owner[usize::from(s)] = Some(t);
                    self.migrating.remove(&s);
                    self.importing.remove(&s);
                }
                self.current_epoch += 1;
                self.nodes[t].epoch = self.current_epoch;
                Ok(format!(
                    "{count} slot(s) now owned by {}",
                    self.nodes[t].addr()
                ))
            }
            "migrating" => {
                let t = target.context("state migrating needs the node the slots move to")?;
                for s in slots.clone() {
                    ensure!(
                        self.owner[usize::from(s)] == Some(self.myself),
                        "slot {s} is not owned by this node, so it cannot migrate from it"
                    );
                }
                for s in slots {
                    self.migrating.insert(s, t);
                }
                Ok(format!(
                    "{count} slot(s) migrating to {}",
                    self.nodes[t].addr()
                ))
            }
            "importing" => {
                let t = target.context("state importing needs the node the slots come from")?;
                for s in slots {
                    self.importing.insert(s, t);
                }
                Ok(format!(
                    "{count} slot(s) importing from {}",
                    self.nodes[t].addr()
                ))
            }
            "stable" => {
                for s in slots {
                    self.migrating.remove(&s);
                    self.importing.remove(&s);
                }
                Ok(format!("{count} slot(s) stable"))
            }
            other => bail!("state is node, migrating, importing or stable, not {other}"),
        }
    }

    /// Contiguous runs of slots with one owner: `(start, end, node index)`.
    fn ranges(&self) -> Vec<(u16, u16, usize)> {
        let mut out: Vec<(u16, u16, usize)> = Vec::new();
        for slot in 0..CLUSTER_SLOTS {
            let Some(owner) = self.owner[usize::from(slot)] else {
                continue;
            };
            match out.last_mut() {
                Some((_, end, o)) if *o == owner && *end + 1 == slot => *end = slot,
                _ => out.push((slot, slot, owner)),
            }
        }
        out
    }

    fn assigned(&self) -> usize {
        self.owner.iter().filter(|o| o.is_some()).count()
    }

    fn node_entry(&self, i: usize) -> Resp {
        let n = &self.nodes[i];
        // Redis 7's fourth element is a map of extra networking metadata; empty here.
        Resp::Array(vec![
            Resp::bulk(&n.host),
            Resp::Int(i64::from(n.port)),
            Resp::bulk(&n.id),
            Resp::Map(vec![]),
        ])
    }

    /// `CLUSTER SLOTS`.
    pub fn slots_reply(&self) -> Resp {
        Resp::Array(
            self.ranges()
                .into_iter()
                .map(|(start, end, owner)| {
                    Resp::Array(vec![
                        Resp::Int(i64::from(start)),
                        Resp::Int(i64::from(end)),
                        self.node_entry(owner),
                    ])
                })
                .collect(),
        )
    }

    /// `CLUSTER SHARDS`: one shard per master, each with its slot ranges and its one node.
    pub fn shards_reply(&self) -> Resp {
        let ranges = self.ranges();
        Resp::Array(
            self.nodes
                .iter()
                .enumerate()
                .map(|(i, n)| {
                    let slots = ranges
                        .iter()
                        .filter(|(_, _, o)| *o == i)
                        .flat_map(|(s, e, _)| [Resp::Int(i64::from(*s)), Resp::Int(i64::from(*e))])
                        .collect();
                    Resp::Map(vec![
                        (Resp::bulk("slots"), Resp::Array(slots)),
                        (
                            Resp::bulk("nodes"),
                            Resp::Array(vec![Resp::Map(vec![
                                (Resp::bulk("id"), Resp::bulk(&n.id)),
                                (Resp::bulk("port"), Resp::Int(i64::from(n.port))),
                                (Resp::bulk("ip"), Resp::bulk(&n.host)),
                                (Resp::bulk("endpoint"), Resp::bulk(&n.host)),
                                (Resp::bulk("role"), Resp::bulk("master")),
                                (Resp::bulk("replication-offset"), Resp::Int(0)),
                                (Resp::bulk("health"), Resp::bulk("online")),
                            ])]),
                        ),
                    ])
                })
                .collect(),
        )
    }

    /// `CLUSTER NODES`: one line per node in Redis's own format.
    pub fn nodes_reply(&self) -> Resp {
        let ranges = self.ranges();
        let mut text = String::new();
        for (i, n) in self.nodes.iter().enumerate() {
            let flags = if i == self.myself {
                "myself,master"
            } else {
                "master"
            };
            text.push_str(&format!(
                "{} {}:{}@{} {} - 0 0 {} connected",
                n.id,
                n.host,
                n.port,
                u32::from(n.port) + 10000,
                flags,
                n.epoch
            ));
            for (s, e, _) in ranges.iter().filter(|(_, _, o)| *o == i) {
                if s == e {
                    text.push_str(&format!(" {s}"));
                } else {
                    text.push_str(&format!(" {s}-{e}"));
                }
            }
            if i == self.myself {
                for (slot, t) in &self.migrating {
                    text.push_str(&format!(" [{slot}->-{}]", self.nodes[*t].id));
                }
                for (slot, t) in &self.importing {
                    text.push_str(&format!(" [{slot}-<-{}]", self.nodes[*t].id));
                }
            }
            text.push('\n');
        }
        Resp::Verbatim(text)
    }

    /// `CLUSTER INFO`.
    pub fn info_reply(&self) -> Resp {
        let assigned = self.assigned();
        let state = if assigned == usize::from(CLUSTER_SLOTS) {
            "ok"
        } else {
            "fail"
        };
        let size = self
            .nodes
            .iter()
            .enumerate()
            .filter(|(i, _)| self.owner.contains(&Some(*i)))
            .count();
        let lines = [
            format!("cluster_state:{state}"),
            format!("cluster_slots_assigned:{assigned}"),
            format!("cluster_slots_ok:{assigned}"),
            "cluster_slots_pfail:0".to_string(),
            "cluster_slots_fail:0".to_string(),
            format!("cluster_known_nodes:{}", self.nodes.len()),
            format!("cluster_size:{size}"),
            format!("cluster_current_epoch:{}", self.current_epoch),
            format!("cluster_my_epoch:{}", self.me().epoch),
            "cluster_stats_messages_sent:0".to_string(),
            "cluster_stats_messages_received:0".to_string(),
            "total_cluster_links_buffer_limit_exceeded:0".to_string(),
        ];
        Resp::Verbatim(lines.iter().map(|l| format!("{l}\r\n")).collect())
    }

    /// The topology as JSON, for the model and the dashboard.
    pub fn snapshot(&self) -> Value {
        let ranges = self.ranges();
        serde_json::json!({
            "myself": self.me().addr(),
            "nodes": self.nodes.iter().enumerate().map(|(i, n)| serde_json::json!({
                "id": n.id,
                "addr": n.addr(),
                "slots": ranges.iter().filter(|(_, _, o)| *o == i)
                    .map(|(s, e, _)| format!("{s}-{e}")).collect::<Vec<_>>(),
            })).collect::<Vec<_>>(),
            "migrating": self.migrating.iter().map(|(s, t)| (s.to_string(), self.nodes[*t].addr())).collect::<BTreeMap<_, _>>(),
            "importing": self.importing.iter().map(|(s, t)| (s.to_string(), self.nodes[*t].addr())).collect::<BTreeMap<_, _>>(),
            "slots_assigned": self.assigned(),
        })
    }
}

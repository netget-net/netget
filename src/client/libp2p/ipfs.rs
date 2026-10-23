//! The dialler's IPFS side: wanting blocks over Bitswap and checking every block that comes
//! back against what was wanted before the model hears of it, and asking a peer's Kademlia
//! DHT for closer peers and providers.
use super::actions;
use crate::protocol::Event;
use crate::server::libp2p::bitswap::{self, Counts, Entry, WantSet, WantType};
use crate::server::libp2p::host::{self, Peer};
use crate::server::libp2p::ipfs::{self, Cid};
use crate::server::libp2p::kad::{self, Kind};
use crate::server::libp2p::unixfs::{self, Walk};
use crate::server::libp2p::wire;
use anyhow::{ensure, Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Mutex;

/// Block content shown to the model is cut at this many bytes (`truncated` says so); the
/// block itself was verified whole.
pub const MAX_SHOWN_BLOCK: usize = 64 * 1024;
/// CIDs one want or cancel action may name.
pub const MAX_CIDS_PER_ACTION: usize = 256;

pub fn cids(v: &Value) -> Result<Vec<Cid>> {
    let list = v["cids"]
        .as_array()
        .context("cids must be an array of CIDs")?;
    ensure!(!list.is_empty(), "cids is empty");
    ensure!(
        list.len() <= MAX_CIDS_PER_ACTION,
        "at most {MAX_CIDS_PER_ACTION} CIDs per action"
    );
    list.iter()
        .map(|c| {
            let cid = Cid::parse(c.as_str().context("each CID is a string")?)?;
            cid.supported()?;
            Ok(cid)
        })
        .collect()
}

pub fn want_type(v: &Value) -> Result<WantType> {
    match v["want"].as_str().unwrap_or("block") {
        "block" => Ok(WantType::Block),
        "have" => Ok(WantType::Have),
        other => anyhow::bail!("want must be block or have, not {other:?}"),
    }
}

/// Send one wantlist message on a stream of our own, then close it.
async fn send_wantlist(peer: &Peer, entries: Vec<Entry>) -> Result<String> {
    let Some((stream, protocol)) = host::open_negotiated(peer, bitswap::PROTOCOLS).await? else {
        anyhow::bail!("the remote does not speak Bitswap");
    };
    let msg = bitswap::Message {
        entries,
        ..Default::default()
    };
    let w = stream.writer();
    w.send(wire::length_prefixed(&bitswap::encode(
        &msg,
        bitswap::Version::of(&protocol),
    )))?;
    w.close();
    Ok(protocol)
}

/// `ipfs_bitswap_want`: remember the wants, then ask.
pub async fn want(
    peer: &Peer,
    session: &Session,
    wants: &Mutex<WantSet>,
    v: &Value,
) -> Result<String> {
    let cids = cids(v)?;
    let kind = want_type(v)?;
    {
        let mut set = wants.lock().unwrap_or_else(|e| e.into_inner());
        for c in &cids {
            set.add(*c, kind)?;
        }
    }
    let entries = cids
        .iter()
        .map(|c| Entry {
            cid: *c,
            priority: 1,
            cancel: false,
            want_type: kind,
            send_dont_have: true,
        })
        .collect::<Vec<_>>();
    let protocol = send_wantlist(peer, entries.clone()).await?;
    session.sent(&bitswap::Message {
        entries,
        ..Default::default()
    });
    Ok(format!(
        "wanted {} block(s) ({}) over {protocol}",
        cids.len(),
        kind.name()
    ))
}

/// `ipfs_bitswap_cancel`: forget the wants and tell the remote.
pub async fn cancel(
    peer: &Peer,
    session: &Session,
    wants: &Mutex<WantSet>,
    v: &Value,
) -> Result<String> {
    let cids = cids(v)?;
    {
        let mut set = wants.lock().unwrap_or_else(|e| e.into_inner());
        for c in &cids {
            set.remove(c);
        }
    }
    let entries = cids
        .iter()
        .map(|c| Entry {
            cid: *c,
            priority: 0,
            cancel: true,
            want_type: WantType::Block,
            send_dont_have: false,
        })
        .collect::<Vec<_>>();
    send_counted(peer, session, entries).await?;
    Ok(format!("cancelled {} want(s)", cids.len()))
}

/// What one received Bitswap message is worth telling the model: an event per verified
/// block and per presence for an outstanding want, and the refusals for the log. A message
/// that does not decode is an error (the caller resets its stream).
pub fn received(
    data: &[u8],
    wants: &Mutex<WantSet>,
    session: &Session,
) -> Result<(Vec<Event>, Vec<String>)> {
    let mut msg = bitswap::decode(data)?;
    session.received(&msg);
    // A running fetch takes what it is waiting for first.
    session.route(&mut msg);
    let r = {
        let mut set = wants.lock().unwrap_or_else(|e| e.into_inner());
        bitswap::accept_blocks(&msg, &mut set)
    };
    let mut events = Vec::new();
    let mut refused = r.refused;
    for b in &r.blocks {
        let d = match ipfs::describe(&b.cid, &b.data) {
            Ok(d) => d,
            Err(e) => {
                refused.push(format!(
                    "{}: its hash matches but it does not decode as {}: {e:#}",
                    b.cid,
                    ipfs::codec_name(b.cid.codec)
                ));
                continue;
            }
        };
        let shown = &d.content[..d.content.len().min(MAX_SHOWN_BLOCK)];
        let (text, encoding) = wire::shown(shown);
        events.push(Event::new(
            &actions::BLOCK_EVENT,
            json!({
                "cid": b.cid.to_string(),
                "codec": d.codec,
                "size": b.data.len(),
                "data": text,
                "encoding": encoding,
                "truncated": shown.len() < d.content.len(),
                "unixfs_type": d.unixfs_type,
                "file_size": d.file_size,
                "links": d.links.iter().map(|l| json!({
                    "cid": l.cid.to_string(), "name": l.name, "size": l.size,
                })).collect::<Vec<_>>(),
            }),
        ));
    }
    for (cid, have) in &r.presences {
        events.push(Event::new(
            &actions::PRESENCE_EVENT,
            json!({"cid": cid.to_string(), "have": have}),
        ));
    }
    if !msg.entries.is_empty() {
        refused.push(format!(
            "the remote wants {} block(s); this client does not serve blocks",
            msg.entries.len()
        ));
    }
    Ok((events, refused))
}

fn peers(list: &[kad::Peer]) -> Vec<Value> {
    list.iter().map(kad::Peer::to_json).collect()
}

/// The DHT protocol an action names (the public DHT's by default).
pub fn kad_protocol(v: &Value) -> Result<&'static str> {
    match v["protocol"].as_str() {
        None => Ok(kad::KAD),
        Some(p) => kad::PROTOCOLS
            .iter()
            .find(|x| **x == p)
            .copied()
            .with_context(|| format!("protocol must be {} or {}", kad::KAD, kad::LAN_KAD)),
    }
}

/// The request an `ipfs_kad_*` action makes.
pub fn kad_request(v: &Value) -> Result<kad::Message> {
    match v["type"].as_str().unwrap_or_default() {
        "ipfs_kad_find_node" => {
            let id = v["peer_id"].as_str().context("peer_id is required")?;
            Ok(kad::Message::request(
                Kind::FindNode,
                kad::parse_peer_id(id)?,
            ))
        }
        "ipfs_kad_get_providers" => {
            let cid = Cid::parse(v["cid"].as_str().context("cid is required")?)?;
            Ok(kad::Message::request(Kind::GetProviders, cid.multihash()))
        }
        other => anyhow::bail!("{other} is not a DHT request"),
    }
}

/// Ask the remote's DHT one question on a stream of its own: the answer, or why not.
pub async fn kad_ask(peer: &Peer, v: &Value) -> Result<Value> {
    let req = kad_request(v)?;
    let protocol = kad_protocol(v)?;
    tokio::time::timeout(kad::REQUEST_TIMEOUT, async {
        let Some((mut s, _)) = host::open_negotiated(peer, &[protocol]).await? else {
            anyhow::bail!("the remote does not serve {protocol}");
        };
        s.writer().send(wire::length_prefixed(&kad::encode(&req)))?;
        let reply = wire::read_length_prefixed(&mut s, kad::MAX_MESSAGE).await?;
        s.writer().close();
        let m = kad::decode(&reply)?;
        ensure!(
            m.kind == req.kind,
            "the remote answered {} to {}",
            m.kind.name(),
            req.kind.name()
        );
        Ok(json!({
            "protocol": protocol,
            "request": req.kind.name(),
            "key": req.key_text(),
            "closer_peers": peers(&m.closer),
            "provider_peers": peers(&m.providers),
        }))
    })
    .await
    .context("the DHT request timed out")?
}

// ---------------------------------------------------------------------------------------
// Fetching a whole DAG: `ipfs_fetch`.

/// A walk waits this long in all, and asks again for what is outstanding this often (want
/// rebroadcast, as boxo's sessions do).
pub const FETCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);
pub const REBROADCAST: std::time::Duration = std::time::Duration::from_secs(5);
/// The longest a fetch may be told to wait.
pub const MAX_FETCH_TIMEOUT_SECS: u64 = 600;
/// File bytes a fetch shows the model by default, and at most (the whole file is read,
/// verified and hashed either way).
pub const DEFAULT_FETCH_SHOWN: usize = MAX_SHOWN_BLOCK;
pub const MAX_FETCH_SHOWN: usize = 1024 * 1024;

/// What arrives for a running fetch.
pub enum Arrival {
    /// A block, under the wanted CID whose digest its bytes have.
    Block(Cid, Vec<u8>),
    /// The remote does not have a block the fetch needs.
    DontHave(Cid),
}

struct Route {
    wanted: HashMap<(u64, [u8; 32]), Cid>,
    tx: tokio::sync::mpsc::Sender<Arrival>,
}

/// The connection's Bitswap session as a dialler: the fetch running (at most one), and what
/// passed each way.
#[derive(Default)]
pub struct Session {
    route: Mutex<Option<Route>>,
    pub counts: Mutex<(Counts, Counts)>,
}

impl Session {
    fn lock(&self) -> std::sync::MutexGuard<'_, Option<Route>> {
        self.route.lock().unwrap_or_else(|e| e.into_inner())
    }
    pub fn received(&self, m: &bitswap::Message) {
        self.counts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .0
            .message(m);
    }
    pub fn sent(&self, m: &bitswap::Message) {
        self.counts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .1
            .message(m);
    }
    pub fn summary(&self) -> String {
        let c = self.counts.lock().unwrap_or_else(|e| e.into_inner());
        format!("received {} | sent {}", c.0, c.1)
    }
    /// Take out of a message what the running fetch is waiting for: blocks whose bytes hash
    /// to one of its wants (the CID was computed from the bytes when the message was read),
    /// and DONT_HAVE for one. The rest stays for the model's own wants.
    fn route(&self, m: &mut bitswap::Message) {
        let mut guard = self.lock();
        let Some(route) = guard.as_mut() else { return };
        let mut kept = Vec::new();
        for b in std::mem::take(&mut m.blocks) {
            match route.wanted.remove(&(b.cid.codec, b.cid.digest)) {
                Some(wanted) => {
                    let _ = route.tx.try_send(Arrival::Block(wanted, b.data));
                }
                None => kept.push(b),
            }
        }
        m.blocks = kept;
        m.presences.retain(|(cid, have)| {
            match (have, route.wanted.get(&(cid.codec, cid.digest))) {
                (false, Some(w)) => {
                    let _ = route.tx.try_send(Arrival::DontHave(*w));
                    false
                }
                (true, Some(_)) => false,
                _ => true,
            }
        });
    }
}

fn fetch_entries(cids: &[Cid], cancel: bool) -> Vec<Entry> {
    cids.iter()
        .map(|c| Entry {
            cid: *c,
            priority: 1,
            cancel,
            want_type: WantType::Block,
            send_dont_have: !cancel,
        })
        .collect()
}

async fn send_counted(peer: &Peer, session: &Session, entries: Vec<Entry>) -> Result<()> {
    let m = bitswap::Message {
        entries: entries.clone(),
        ..Default::default()
    };
    send_wantlist(peer, entries).await?;
    session.sent(&m);
    Ok(())
}

/// `ipfs_fetch`: walk the DAG under a CID, verifying every block, and say what it is: a
/// file's bytes (shown up to `max_bytes`, with the whole file's size and SHA-256), a
/// directory's listing, or a symlink's target. The event data for `ipfs_fetched`.
pub async fn fetch(peer: &Peer, session: &Session, v: &Value) -> Value {
    let started = crate::utils::clock::Instant::now();
    let cid_text = v["cid"].as_str().unwrap_or_default().to_string();
    let mut walk_blocks = 0;
    let result: Result<unixfs::Walked> = async {
        let (root, keep, timeout) = fetch_params(v)?;
        let (tx, mut rx) = tokio::sync::mpsc::channel(unixfs::WALK_WINDOW * 2);
        {
            let mut g = session.lock();
            ensure!(g.is_none(), "a fetch is already running on this connection");
            *g = Some(Route {
                wanted: HashMap::new(),
                tx,
            });
        }
        let mut walk = Walk::new(root, keep);
        let deadline = tokio::time::Instant::now() + timeout;
        let outcome = loop {
            match walk.step() {
                Err(e) => break Err(e),
                Ok(Some(done)) => break Ok(done.clone()),
                Ok(None) => {}
            }
            let new = walk.wants();
            if !new.is_empty() {
                if let Some(r) = session.lock().as_mut() {
                    for c in &new {
                        r.wanted.insert((c.codec, c.digest), *c);
                    }
                }
                send_counted(peer, session, fetch_entries(&new, false)).await?;
            }
            if walk.ready() {
                continue;
            }
            tokio::select! {
                a = rx.recv() => match a {
                    Some(Arrival::Block(cid, data)) => {
                        walk_blocks += 1;
                        if let Err(e) = walk.give(&cid, data) {
                            break Err(e);
                        }
                    }
                    Some(Arrival::DontHave(cid)) => {
                        break Err(anyhow::anyhow!("the remote does not have {cid}"));
                    }
                    None => break Err(anyhow::anyhow!("the connection ended")),
                },
                _ = tokio::time::sleep(REBROADCAST) => {
                    let again = walk.outstanding();
                    if !again.is_empty() {
                        send_counted(peer, session, fetch_entries(&again, false)).await?;
                    }
                }
                _ = tokio::time::sleep_until(deadline) => {
                    break Err(anyhow::anyhow!("the fetch took longer than {}s", timeout.as_secs()));
                }
            }
        };
        let left = walk.outstanding();
        if !left.is_empty() {
            let _ = send_counted(peer, session, fetch_entries(&left, true)).await;
        }
        outcome
    }
    .await;
    *session.lock() = None;
    let ms = started.elapsed().as_millis() as u64;
    match result {
        Ok(w) => {
            let (text, encoding) = wire::shown(&w.data);
            json!({
                "cid": cid_text,
                "ok": true,
                "kind": w.kind,
                "size": w.size,
                "data": text,
                "encoding": encoding,
                "truncated": (w.data.len() as u64) < w.size,
                "sha256": if w.kind == "file" { json!(hex::encode(w.sha256)) } else { Value::Null },
                "entries": w.entries.iter().map(|e| json!({
                    "name": e.name, "cid": e.cid.to_string(), "tsize": e.tsize,
                    "kind": e.kind, "size": e.size,
                })).collect::<Vec<_>>(),
                "target": w.target,
                "blocks": w.blocks,
                "depth": w.depth,
                "elapsed_ms": ms,
            })
        }
        Err(e) => json!({
            "cid": cid_text,
            "ok": false,
            "error": format!("{e:#}"),
            "blocks": walk_blocks,
            "elapsed_ms": ms,
        }),
    }
}

/// The root to walk, how many file bytes to show, and how long to wait in all.
pub fn fetch_params(v: &Value) -> Result<(Cid, usize, std::time::Duration)> {
    let root = Cid::parse(v["cid"].as_str().context("cid is required")?)?;
    root.supported()?;
    let keep = match &v["max_bytes"] {
        Value::Null => DEFAULT_FETCH_SHOWN,
        n => n
            .as_u64()
            .and_then(|n| usize::try_from(n).ok())
            .filter(|n| *n <= MAX_FETCH_SHOWN)
            .with_context(|| format!("max_bytes is 0 to {MAX_FETCH_SHOWN}"))?,
    };
    let timeout = match &v["timeout_secs"] {
        Value::Null => FETCH_TIMEOUT,
        n => std::time::Duration::from_secs(
            n.as_u64()
                .filter(|s| (1..=MAX_FETCH_TIMEOUT_SECS).contains(s))
                .with_context(|| format!("timeout_secs is 1 to {MAX_FETCH_TIMEOUT_SECS}"))?,
        ),
    };
    Ok((root, keep, timeout))
}

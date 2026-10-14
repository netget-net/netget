//! The dialler's IPFS side: wanting blocks over Bitswap and checking every block that comes
//! back against what was wanted before the model hears of it, and asking a peer's Kademlia
//! DHT for closer peers and providers.
use super::actions;
use crate::protocol::Event;
use crate::server::libp2p::bitswap::{self, Entry, WantSet, WantType};
use crate::server::libp2p::host::{self, Peer};
use crate::server::libp2p::ipfs::{self, Cid};
use crate::server::libp2p::kad::{self, Kind};
use crate::server::libp2p::wire;
use anyhow::{ensure, Context, Result};
use serde_json::{json, Value};
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
pub async fn want(peer: &Peer, wants: &Mutex<WantSet>, v: &Value) -> Result<String> {
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
        .collect();
    let protocol = send_wantlist(peer, entries).await?;
    Ok(format!(
        "wanted {} block(s) ({}) over {protocol}",
        cids.len(),
        kind.name()
    ))
}

/// `ipfs_bitswap_cancel`: forget the wants and tell the remote.
pub async fn cancel(peer: &Peer, wants: &Mutex<WantSet>, v: &Value) -> Result<String> {
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
        .collect();
    send_wantlist(peer, entries).await?;
    Ok(format!("cancelled {} want(s)", cids.len()))
}

/// What one received Bitswap message is worth telling the model: an event per verified
/// block and per presence for an outstanding want, and the refusals for the log. A message
/// that does not decode is an error (the caller resets its stream).
pub fn received(data: &[u8], wants: &Mutex<WantSet>) -> Result<(Vec<Event>, Vec<String>)> {
    let msg = bitswap::decode(data)?;
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

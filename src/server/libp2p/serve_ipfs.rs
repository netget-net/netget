//! The host's IPFS side: Bitswap wantlists and Kademlia requests, each refused in Rust when
//! it is malformed or over a bound, otherwise put to the model, whose answer Rust checks
//! before anything goes back. A failed model answers nothing: wants get DONT_HAVE (where the
//! peer asked for it) and a DHT request has its stream reset.
use super::bitswap::{self, Entry, Version};
use super::host::{self, Config, Peer};
use super::kad::{self, Kind};
use super::{actions, wire};
use crate::logging::emit::Log;
use crate::protocol::{Event, SpawnContext};
use crate::server::connection::ConnectionId;
use serde_json::{json, Value};
use std::sync::Arc;

fn reset(peer: &Peer, stream_id: u32) {
    if let Some((_, w)) = peer.writer(stream_id) {
        w.reset();
    }
}

/// One Bitswap message the peer sent. Blocks and presences sent to the host are not asked
/// for and are dropped; wants are answered.
pub async fn bitswap(
    ctx: &SpawnContext,
    id: ConnectionId,
    peer: &Arc<Peer>,
    stream_id: u32,
    data: &[u8],
) {
    let log = Log::new(Some(&ctx.status_tx));
    let msg = match bitswap::decode(data) {
        Ok(m) => m,
        Err(e) => {
            log.warn(format!(
                "libp2p connection {id} operation=bitswap decision=refused_malformed: {e:#}"
            ));
            reset(peer, stream_id);
            return;
        }
    };
    for why in &msg.unreadable {
        log.warn(format!(
            "libp2p connection {id} operation=bitswap decision=refused_unreadable: {why}"
        ));
    }
    if !msg.blocks.is_empty() || !msg.presences.is_empty() {
        log.debug(format!(
            "libp2p connection {id}: {} unrequested blocks and {} presences dropped",
            msg.blocks.len(),
            msg.presences.len()
        ));
    }
    let wants: Vec<&Entry> = msg.entries.iter().filter(|e| !e.cancel).collect();
    if wants.is_empty() {
        return;
    }
    // A CID in a codec NetGet cannot build is answered before the model is asked.
    let (servable, unservable): (Vec<Entry>, Vec<Entry>) = wants
        .into_iter()
        .cloned()
        .partition(|e| e.cid.supported().is_ok());
    for e in &unservable {
        log.info(format!(
            "libp2p connection {id} operation=bitswap decision=refused_codec cid={}: {:#}",
            e.cid,
            e.cid.supported().unwrap_err()
        ));
    }
    let mut supplied = Vec::new();
    if !servable.is_empty() {
        let event = Event::new(
            &actions::WANT_EVENT,
            json!({
                "peer_id": peer.remote_peer,
                "wants": servable.iter().map(|e| json!({
                    "cid": e.cid.to_string(),
                    "codec": super::ipfs::codec_name(e.cid.codec),
                    "want": e.want_type.name(),
                })).collect::<Vec<_>>(),
                "full": msg.full,
            }),
        );
        match super::ask(ctx, id, &event).await {
            None => {}
            Some(todo) => {
                for action in todo {
                    if action["type"] != actions::BLOCKS {
                        log.warn(format!(
                            "libp2p connection {id}: {} does not answer a wantlist; ignored",
                            action["type"]
                        ));
                        continue;
                    }
                    match actions::supplied_blocks(&action) {
                        Ok(b) => supplied.extend(b),
                        Err(e) => log.warn(format!(
                            "libp2p connection {id} operation=bitswap decision=refused_answer: {e:#}"
                        )),
                    }
                }
            }
        }
    }
    let mut answer = bitswap::answer_wants(&servable, &supplied);
    answer.dont_have.extend(
        unservable
            .iter()
            .filter(|e| e.send_dont_have)
            .map(|e| e.cid),
    );
    for why in &answer.refused {
        log.warn(format!(
            "libp2p connection {id} operation=bitswap decision=refused_block: {why}"
        ));
    }
    log.info(format!(
        "libp2p connection {id} operation=bitswap blocks={} dont_have={}",
        answer.blocks.len(),
        answer.dont_have.len()
    ));
    if let Err(e) = send_answer(ctx, id, peer, answer).await {
        log.warn(format!(
            "libp2p connection {id}: Bitswap answer not delivered: {e:#}"
        ));
    }
}

/// Answers travel on a stream the host opens, one message per bound's worth of blocks.
async fn send_answer(
    ctx: &SpawnContext,
    id: ConnectionId,
    peer: &Peer,
    answer: bitswap::Answer,
) -> anyhow::Result<()> {
    if answer.blocks.is_empty() && answer.dont_have.is_empty() {
        return Ok(());
    }
    let Some((stream, protocol)) = host::open_negotiated(peer, bitswap::PROTOCOLS).await? else {
        anyhow::bail!("the peer accepts no Bitswap protocol");
    };
    let version = Version::of(&protocol);
    let mut blocks = answer.blocks;
    if version == Version::V100 {
        // 1.0.0 names a block by its bytes as CIDv0 would, so a CIDv1 block cannot travel.
        blocks.retain(|b| b.cid.version == 0);
    }
    let message = bitswap::Message {
        blocks,
        presences: answer.dont_have.into_iter().map(|c| (c, false)).collect(),
        ..Default::default()
    };
    let writer = stream.writer();
    let mut sent = 0;
    for m in bitswap::split(message) {
        let bytes = bitswap::encode(&m, version);
        sent += bytes.len();
        writer.send(wire::length_prefixed(&bytes))?;
    }
    writer.close();
    ctx.state
        .update_connection_stats(ctx.server_id, id, None, Some(sent as u64), None, Some(1))
        .await;
    Ok(())
}

fn peers_json(peers: &[kad::Peer]) -> Vec<Value> {
    peers.iter().map(kad::Peer::to_json).collect()
}

/// One DHT request on a stream the peer opened; the answer goes back on that stream.
pub async fn kad(
    ctx: &SpawnContext,
    id: ConnectionId,
    peer: &Arc<Peer>,
    cfg: &Config,
    stream_id: u32,
    protocol: &str,
    data: &[u8],
) {
    let log = Log::new(Some(&ctx.status_tx));
    let req = match kad::decode(data) {
        Ok(m) => m,
        Err(e) => {
            log.warn(format!(
                "libp2p connection {id} operation=kad decision=refused_malformed: {e:#}"
            ));
            reset(peer, stream_id);
            return;
        }
    };
    let op = req.kind.name();
    let me = kad::Peer {
        id: cfg.identity.peer_id.clone(),
        addrs: cfg.listen_addrs.clone(),
    };
    // FIND_NODE and GET_VALUE are routing facts: the connected peers closest to the key, and
    // this host when the key is its own id. Rust answers them without the model, which also
    // spares a model call per routing-table refresh (Kubo sends dozens).
    let closest_known = closest(cfg, &req.key, &peer.remote_peer);
    let mut providers = Vec::new();
    match req.kind {
        Kind::Ping => {
            let reply = kad::Message::request(Kind::Ping, Vec::new());
            let _ = host::send(peer, stream_id, &kad::encode(&reply));
            return;
        }
        Kind::PutValue => {
            log.info(format!(
                "libp2p connection {id} operation=kad request={op} decision=refused_unsupported: records are not stored"
            ));
            reset(peer, stream_id);
            return;
        }
        Kind::FindNode | Kind::GetValue => {
            if req.kind == Kind::FindNode && kad::parse_peer_id(&req.key_text()).is_err() {
                log.warn(format!(
                    "libp2p connection {id} operation=kad request={op} decision=refused_malformed: the key is not a peer id"
                ));
                reset(peer, stream_id);
                return;
            }
            let mut reply = kad::Message::request(req.kind, req.key.clone());
            if req.key == me.id {
                reply.closer.push(me.clone());
            }
            reply.closer.extend(closest_known);
            reply.closer.truncate(kad::MAX_PEERS);
            log.debug(format!(
                "libp2p connection {id} operation=kad request={op} closer={} providers=0",
                reply.closer.len()
            ));
            send_kad(ctx, id, peer, stream_id, &reply).await;
            return;
        }
        Kind::GetProviders | Kind::AddProvider => {
            if req.key_cids().is_empty() {
                log.warn(format!(
                    "libp2p connection {id} operation=kad request={op} decision=refused_malformed: the key is not a sha2-256 multihash"
                ));
                reset(peer, stream_id);
                return;
            }
            if req.kind == Kind::AddProvider {
                // A peer may only announce itself (as go-libp2p-kad-dht requires).
                let sender = wire::unbase58(&peer.remote_peer).unwrap_or_default();
                for p in &req.providers {
                    if p.id == sender {
                        providers.push(p.clone());
                    } else {
                        log.warn(format!(
                            "libp2p connection {id} operation=kad request={op} decision=refused_provider: {} announced {}",
                            peer.remote_peer,
                            wire::base58(&p.id)
                        ));
                    }
                }
                if providers.is_empty() {
                    return;
                }
            }
        }
    }
    let event = Event::new(
        &actions::KAD_EVENT,
        json!({
            "peer_id": peer.remote_peer,
            "stream_id": stream_id,
            "protocol": protocol,
            "request": op,
            "key": req.key_text(),
            "cids": req.key_cids(),
            "providers": peers_json(&providers),
            "self": me.to_json(),
            "connected_peers": peers_json(&closest_known),
        }),
    );
    let Some(todo) = super::ask(ctx, id, &event).await else {
        // Fail closed: no provider is claimed; the asker learns at once.
        if req.kind == Kind::GetProviders {
            reset(peer, stream_id);
        }
        return;
    };
    if req.kind == Kind::AddProvider {
        // ADD_PROVIDER has no reply on the wire.
        return;
    }
    let mut reply = kad::Message::request(req.kind, req.key.clone());
    let mut said_closer = false;
    for action in todo.iter().filter(|a| a["type"] == actions::KAD_REPLY) {
        match actions::kad_peers(action, cfg) {
            Ok((closer, provs)) => {
                said_closer |= action["closer_peers"].is_array();
                reply.closer.extend(closer);
                reply.providers.extend(provs);
            }
            Err(e) => log.warn(format!(
                "libp2p connection {id} operation=kad decision=refused_answer: {e:#}"
            )),
        }
    }
    if !said_closer {
        reply.closer = closest_known;
    }
    reply.closer.truncate(kad::MAX_PEERS);
    reply.providers.truncate(kad::MAX_PEERS);
    log.info(format!(
        "libp2p connection {id} operation=kad request={op} closer={} providers={}",
        reply.closer.len(),
        reply.providers.len()
    ));
    send_kad(ctx, id, peer, stream_id, &reply).await;
}

async fn send_kad(
    ctx: &SpawnContext,
    id: ConnectionId,
    peer: &Peer,
    stream_id: u32,
    reply: &kad::Message,
) {
    let bytes = kad::encode(reply);
    if host::send(peer, stream_id, &bytes).is_ok() {
        ctx.state
            .update_connection_stats(
                ctx.server_id,
                id,
                None,
                Some(bytes.len() as u64),
                None,
                Some(1),
            )
            .await;
    }
}

/// The connected peers other than the asker, closest to `key` first by Kademlia's XOR
/// distance over SHA-256, at most k.
fn closest(cfg: &Config, key: &[u8], asker: &str) -> Vec<kad::Peer> {
    let target = super::ipfs::sha256(key);
    let mut peers: Vec<([u8; 32], kad::Peer)> = cfg
        .directory
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .filter(|(id, _)| id.as_str() != asker)
        .filter_map(|(id, addrs)| {
            let id = wire::unbase58(id).ok()?;
            let h = super::ipfs::sha256(&id);
            let mut d = [0u8; 32];
            for i in 0..32 {
                d[i] = h[i] ^ target[i];
            }
            Some((
                d,
                kad::Peer {
                    id,
                    addrs: addrs.clone(),
                },
            ))
        })
        .collect();
    peers.sort_by_key(|p| p.0);
    peers.truncate(kad::MAX_PEERS);
    peers.into_iter().map(|(_, p)| p).collect()
}

/// Peers' addresses for an answer: the model's own, or else what this host knows.
pub fn known_addrs(cfg: &Config, id: &[u8]) -> Vec<Vec<u8>> {
    if id == cfg.identity.peer_id.as_slice() {
        return cfg.listen_addrs.clone();
    }
    cfg.directory
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(&wire::base58(id))
        .cloned()
        .unwrap_or_default()
}

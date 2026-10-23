//! The host's IPFS side: Bitswap wantlists and Kademlia requests, each refused in Rust when
//! it is malformed or over a bound, otherwise put to the model, whose answer Rust checks
//! before anything goes back. A failed model answers nothing: wants get DONT_HAVE (where the
//! peer asked for it) and a DHT request has its stream reset.
use super::bitswap::{self, Counts, Entry, Version, WantType};
use super::host::{self, Config, Peer};
use super::ipfs::Cid;
use super::kad::{self, Kind};
use super::unixfs;
use super::{actions, wire};
use crate::logging::emit::Log;
use crate::protocol::{Event, SpawnContext};
use crate::server::connection::ConnectionId;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;

fn reset(peer: &Peer, stream_id: u32) {
    if let Some((_, w)) = peer.writer(stream_id) {
        w.reset();
    }
}

/// Wants a connection remembers: what the peer still wants that this host has not given it
/// (declined, or not yet known). Bounded; the oldest is forgotten first.
pub const MAX_TRACKED_WANTS: usize = bitswap::MAX_OUTSTANDING_WANTS;

/// One peer's Bitswap session with this host: its outstanding wants and what passed each way.
#[derive(Default)]
pub struct Ledger {
    /// (order, the want, whether the model answered it — declined — rather than failed)
    wants: HashMap<(u64, [u8; 32]), (u64, Entry, bool)>,
    seq: u64,
    pub received: Counts,
    pub sent: Counts,
    /// Where this connection's DHT answers go to become `ipfs_kad_answer`, and when its
    /// recent questions were asked (for the rate bound).
    pub kad_answers: Option<tokio::sync::mpsc::Sender<Value>>,
    kad_asked: std::collections::VecDeque<crate::utils::clock::Instant>,
}

/// Questions the model may put to one peer's DHT per [`KAD_QUERY_WINDOW`].
pub const MAX_KAD_QUERIES: usize = 8;
pub const KAD_QUERY_WINDOW: std::time::Duration = std::time::Duration::from_secs(60);

/// `ipfs_kad_query`: ask this peer's DHT, and queue the answer as an event. The detail of
/// what was asked, for the log and an injected command's reply.
pub async fn kad_query(
    cfg: &Config,
    peer: &Peer,
    ledger: &mut Ledger,
    action: &Value,
) -> anyhow::Result<String> {
    anyhow::ensure!(cfg.kad, "ipfs is off on this host");
    ledger
        .kad_asked
        .retain(|at| at.elapsed() < KAD_QUERY_WINDOW);
    anyhow::ensure!(
        ledger.kad_asked.len() < MAX_KAD_QUERIES,
        "at most {MAX_KAD_QUERIES} DHT questions a minute per peer"
    );
    ledger
        .kad_asked
        .push_back(crate::utils::clock::Instant::now());
    let kind = action["request"].as_str().unwrap_or_default();
    let req = kad::request_of(kind, action)?;
    let protocol = kad::protocol_of(action)?;
    let mut answer = match kad::ask(peer, protocol, &req).await {
        Ok(m) => {
            let mut j = kad::answer_json(protocol, &req, &m);
            j["ok"] = json!(true);
            j
        }
        Err(e) => {
            json!({"ok": false, "request": kind, "protocol": protocol, "error": format!("{e:#}")})
        }
    };
    answer["peer_id"] = json!(peer.remote_peer);
    let detail = answer.to_string();
    if let Some(tx) = &ledger.kad_answers {
        tx.try_send(answer)
            .map_err(|_| anyhow::anyhow!("the DHT answer queue is full"))?;
    }
    Ok(detail)
}

impl Ledger {
    fn track(&mut self, e: &Entry, declined: bool) {
        let key = (e.cid.codec, e.cid.digest);
        if !self.wants.contains_key(&key) && self.wants.len() >= MAX_TRACKED_WANTS {
            let oldest = self
                .wants
                .iter()
                .min_by_key(|(_, (s, _, _))| *s)
                .map(|(k, _)| *k);
            if let Some(oldest) = oldest {
                self.wants.remove(&oldest);
            }
        }
        self.seq += 1;
        let declined = declined || self.declined(&e.cid);
        self.wants.insert(key, (self.seq, e.clone(), declined));
    }
    /// Whether the model already answered this want without the block (a failed model is
    /// asked again the next time the peer wants it).
    fn declined(&self, cid: &Cid) -> bool {
        self.wants
            .get(&(cid.codec, cid.digest))
            .is_some_and(|(_, _, d)| *d)
    }
    fn forget(&mut self, cid: &Cid) {
        self.wants.remove(&(cid.codec, cid.digest));
    }
    /// The wants still outstanding, oldest first.
    pub fn outstanding(&self) -> Vec<Entry> {
        let mut v: Vec<&(u64, Entry, bool)> = self.wants.values().collect();
        v.sort_by_key(|(s, _, _)| *s);
        v.into_iter().map(|(_, e, _)| e.clone()).collect()
    }
    pub fn summary(&self) -> String {
        format!("received {} | sent {}", self.received, self.sent)
    }
}

enum Reply {
    Block(bitswap::Block),
    Have(Cid),
}

/// What the host's store answers for a want: the block for want-block (and for want-have
/// when the block is small, as boxo does), HAVE for a larger want-have; None when the store
/// does not hold it.
fn from_store(cfg: &Config, want: &Entry) -> Option<Reply> {
    cfg.dag.with(|store| {
        let size = store.has(&want.cid)?;
        if want.want_type == WantType::Have && size > unixfs::HAVE_AS_BLOCK {
            return Some(Reply::Have(want.cid));
        }
        store.get(&want.cid).map(|data| {
            Reply::Block(bitswap::Block {
                cid: want.cid,
                data,
            })
        })
    })
}

/// Build an add (off the runtime: it hashes every byte) and keep it in the host's store,
/// which tells every connection.
pub async fn add_content(cfg: &Config, description: Value) -> anyhow::Result<unixfs::Added> {
    let built = tokio::task::spawn_blocking(move || unixfs::add(&description))
        .await
        .map_err(|e| anyhow::anyhow!("the add did not finish: {e}"))??;
    cfg.dag.insert(built)
}

pub fn added_line(a: &unixfs::Added) -> String {
    format!(
        "operation=ipfs_add decision=added root={} kind={} name={:?} size={} blocks={}",
        a.root, a.kind, a.name, a.size, a.blocks
    )
}

/// One Bitswap message the peer sent. Blocks and presences sent to the host are not asked
/// for and are dropped. Wants are answered from the store when it holds them, otherwise by
/// the model; what neither can give is remembered, so content added later still reaches the
/// peer, and a want the model already declined is not asked again while the peer keeps it.
#[allow(clippy::too_many_arguments)]
pub async fn bitswap(
    ctx: &SpawnContext,
    id: ConnectionId,
    peer: &Arc<Peer>,
    cfg: &Config,
    ledger: &mut Ledger,
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
    let count = |cancel: bool, kind: Option<WantType>| {
        msg.entries
            .iter()
            .filter(|e| e.cancel == cancel && kind.is_none_or(|k| e.want_type == k))
            .count() as u64
    };
    let (want_block, want_have, cancels) = (
        count(false, Some(WantType::Block)),
        count(false, Some(WantType::Have)),
        count(true, None),
    );
    ledger.received.message(&msg);
    log.info(format!(
        "libp2p connection {id} operation=bitswap_in want_block={want_block} want_have={want_have} cancel={cancels} full={}",
        msg.full
    ));
    if !msg.blocks.is_empty() || !msg.presences.is_empty() {
        log.debug(format!(
            "libp2p connection {id}: {} unrequested blocks and {} presences dropped",
            msg.blocks.len(),
            msg.presences.len()
        ));
    }
    // A full wantlist replaces what the peer wanted before; a cancel withdraws one want.
    if msg.full {
        ledger.wants.clear();
    }
    for e in msg.entries.iter().filter(|e| e.cancel) {
        ledger.forget(&e.cid);
    }
    let wants: Vec<Entry> = msg.entries.iter().filter(|e| !e.cancel).cloned().collect();
    if wants.is_empty() {
        return;
    }
    let mut out = Out::default();
    let mut ask = Vec::new();
    for e in wants {
        if let Err(why) = e.cid.supported() {
            // A CID in a codec NetGet cannot build is answered before anyone is asked.
            log.info(format!(
                "libp2p connection {id} operation=bitswap decision=refused_codec cid={}: {why:#}",
                e.cid
            ));
            if e.send_dont_have {
                out.dont_have.push(e.cid);
            }
            continue;
        }
        if let Some(reply) = from_store(cfg, &e) {
            ledger.forget(&e.cid);
            out.push(reply);
        } else if ledger.declined(&e.cid) {
            // The model said no before and nothing has been added since: remember the newer
            // want, say so again, and spare the model the same question.
            ledger.track(&e, true);
            if e.send_dont_have {
                out.dont_have.push(e.cid);
            }
        } else {
            ask.push(e);
        }
    }
    let from_store_count = out.blocks.len() + out.have.len();
    if !ask.is_empty() {
        let event = Event::new(
            &actions::WANT_EVENT,
            json!({
                "peer_id": peer.remote_peer,
                "wants": ask.iter().map(|e| json!({
                    "cid": e.cid.to_string(),
                    "codec": super::ipfs::codec_name(e.cid.codec),
                    "want": e.want_type.name(),
                })).collect::<Vec<_>>(),
                "full": msg.full,
            }),
        );
        let mut supplied = Vec::new();
        let answered = super::ask(ctx, id, &event).await;
        let declined = answered.is_some();
        if let Some(todo) = answered {
            for action in todo {
                match action["type"].as_str().unwrap_or_default() {
                    actions::BLOCKS => match actions::supplied_blocks(&action) {
                        Ok(b) => supplied.extend(b),
                        Err(e) => log.warn(format!(
                            "libp2p connection {id} operation=bitswap decision=refused_answer: {e:#}"
                        )),
                    },
                    actions::ADD => match add_content(cfg, action.clone()).await {
                        Ok(a) => log.info(format!("libp2p connection {id} {}", added_line(&a))),
                        Err(e) => log.warn(format!(
                            "libp2p connection {id} operation=ipfs_add decision=refused_answer: {e:#}"
                        )),
                    },
                    other => log.warn(format!(
                        "libp2p connection {id}: {other} does not answer a wantlist; ignored"
                    )),
                }
            }
        }
        // Content the model just added answers its wants from the store; the rest go to
        // the blocks it supplied, and what is left is remembered.
        let mut rest = Vec::new();
        for e in ask {
            match from_store(cfg, &e) {
                Some(reply) => out.push(reply),
                None => rest.push(e),
            }
        }
        let answer = bitswap::answer_wants(&rest, &supplied);
        for why in &answer.refused {
            log.warn(format!(
                "libp2p connection {id} operation=bitswap decision=refused_block: {why}"
            ));
        }
        for e in &rest {
            if !answer.blocks.iter().any(|b| b.cid.same_block(&e.cid)) {
                ledger.track(e, declined);
            }
        }
        out.blocks.extend(answer.blocks);
        out.dont_have.extend(answer.dont_have);
    }
    log.info(format!(
        "libp2p connection {id} operation=bitswap blocks={} dont_have={} have={} from_store={from_store_count} tracked={}",
        out.blocks.len(),
        out.dont_have.len(),
        out.have.len(),
        ledger.wants.len()
    ));
    if let Err(e) = send_answer(ctx, id, peer, ledger, out).await {
        log.warn(format!(
            "libp2p connection {id}: Bitswap answer not delivered: {e:#}"
        ));
    }
}

/// The store changed: send every remembered want it can now answer.
pub async fn store_changed(
    ctx: &SpawnContext,
    id: ConnectionId,
    peer: &Peer,
    cfg: &Config,
    ledger: &mut Ledger,
) {
    let mut out = Out::default();
    for e in ledger.outstanding() {
        if let Some(reply) = from_store(cfg, &e) {
            ledger.forget(&e.cid);
            out.push(reply);
        }
    }
    if out.is_empty() {
        return;
    }
    let log = Log::new(Some(&ctx.status_tx));
    log.info(format!(
        "libp2p connection {id} operation=bitswap source=tracked blocks={} have={} tracked={}",
        out.blocks.len(),
        out.have.len(),
        ledger.wants.len()
    ));
    if let Err(e) = send_answer(ctx, id, peer, ledger, out).await {
        log.warn(format!(
            "libp2p connection {id}: Bitswap answer not delivered: {e:#}"
        ));
    }
}

/// Blocks the model supplied outside a wantlist (from the dashboard or MCP): each goes to
/// this peer only if it hashes to a want the peer still has. What was sent, for the reply.
pub async fn supply_tracked(
    ctx: &SpawnContext,
    id: ConnectionId,
    peer: &Peer,
    ledger: &mut Ledger,
    action: &Value,
) -> anyhow::Result<String> {
    let supplied = actions::supplied_blocks(action)?;
    let wants = ledger.outstanding();
    let answer = bitswap::answer_wants(&wants, &supplied);
    let log = Log::new(Some(&ctx.status_tx));
    for why in &answer.refused {
        log.warn(format!(
            "libp2p connection {id} operation=bitswap decision=refused_block: {why}"
        ));
    }
    let n = answer.blocks.len();
    for b in &answer.blocks {
        ledger.forget(&b.cid);
    }
    log.info(format!(
        "libp2p connection {id} operation=bitswap source=supplied blocks={n} tracked={}",
        ledger.wants.len()
    ));
    let refused = answer.refused.len();
    // A peer that already heard DONT_HAVE needs no second one.
    let out = Out {
        blocks: answer.blocks,
        ..Default::default()
    };
    send_answer(ctx, id, peer, ledger, out).await?;
    Ok(format!(
        "sent {n} block(s) to wants the peer still had ({refused} refused, {} still wanted)",
        ledger.wants.len()
    ))
}

/// One answer: blocks, HAVEs and DONT_HAVEs.
#[derive(Default)]
struct Out {
    blocks: Vec<bitswap::Block>,
    have: Vec<Cid>,
    dont_have: Vec<Cid>,
}

impl Out {
    fn push(&mut self, r: Reply) {
        match r {
            Reply::Block(b) => self.blocks.push(b),
            Reply::Have(c) => self.have.push(c),
        }
    }
    fn is_empty(&self) -> bool {
        self.blocks.is_empty() && self.have.is_empty() && self.dont_have.is_empty()
    }
}

/// Answers travel on a stream the host opens, one message per bound's worth of blocks.
async fn send_answer(
    ctx: &SpawnContext,
    id: ConnectionId,
    peer: &Peer,
    ledger: &mut Ledger,
    out: Out,
) -> anyhow::Result<()> {
    if out.is_empty() {
        return Ok(());
    }
    let Some((stream, protocol)) = host::open_negotiated(peer, bitswap::PROTOCOLS).await? else {
        anyhow::bail!("the peer accepts no Bitswap protocol");
    };
    let version = Version::of(&protocol);
    let mut blocks = out.blocks;
    if version == Version::V100 {
        // 1.0.0 names a block by its bytes as CIDv0 would, so a CIDv1 block cannot travel.
        blocks.retain(|b| b.cid.version == 0);
    }
    let mut presences: Vec<(Cid, bool)> = out.have.into_iter().map(|c| (c, true)).collect();
    presences.extend(out.dont_have.into_iter().map(|c| (c, false)));
    if version != Version::V120 {
        // HAVE and DONT_HAVE are 1.2.0's.
        presences.clear();
    }
    let message = bitswap::Message {
        blocks,
        presences,
        ..Default::default()
    };
    let writer = stream.writer();
    let mut sent = 0;
    for m in bitswap::split(message) {
        ledger.sent.message(&m);
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

/// Whether a DHT key (a sha2-256 multihash) names a block the store serves, in either codec.
fn serves(cfg: &Config, key: &[u8]) -> bool {
    let Ok((digest, used)) = super::ipfs::parse_multihash(key) else {
        return false;
    };
    used == key.len()
        && cfg.dag.with(|s| {
            [super::ipfs::DAG_PB, super::ipfs::RAW]
                .iter()
                .any(|&codec| {
                    s.has(&Cid {
                        version: 1,
                        codec,
                        digest,
                    })
                    .is_some()
                })
        })
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
            // An IPNS record, kept in Rust when it verifies and is not older than the one
            // held; the reply echoes the request, which is what the putter checks.
            let stored = match &req.record {
                Some((key, value)) if *key == req.key => cfg.dht.put(&req.key, value),
                Some(_) => Err(anyhow::anyhow!("the record's key is not the message's")),
                None => Err(anyhow::anyhow!("PUT_VALUE without a record")),
            };
            match stored {
                Ok((put, rec)) => {
                    log.info(format!(
                        "libp2p connection {id} operation=kad request={op} decision={} name={} sequence={} value={}",
                        if put == super::ipns::Put::Stored { "stored" } else { "same" },
                        wire::base58(&rec.name),
                        rec.sequence,
                        String::from_utf8_lossy(&rec.value)
                    ));
                    send_kad(ctx, id, peer, stream_id, &req).await;
                }
                Err(e) => {
                    log.warn(format!(
                        "libp2p connection {id} operation=kad request={op} decision=refused_record: {e:#}"
                    ));
                    reset(peer, stream_id);
                }
            }
            return;
        }
        Kind::FindNode | Kind::GetValue => {
            // FIND_NODE asks for the peers closest to any key, not only to a peer id: Kubo
            // looks up an IPNS record's key (`/ipns/…`) this way before it puts the record.
            // Only an empty key is malformed, as go-libp2p-kad-dht says.
            if req.key.is_empty() {
                log.warn(format!(
                    "libp2p connection {id} operation=kad request={op} decision=refused_malformed: an empty key"
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
            if req.kind == Kind::GetValue {
                if let Some(rec) = cfg.dht.get(&req.key) {
                    log.info(format!(
                        "libp2p connection {id} operation=kad request={op} source=store name={} sequence={}",
                        wire::base58(&rec.name),
                        rec.sequence
                    ));
                    reply.record = Some((req.key.clone(), rec.bytes));
                }
            }
            log.debug(format!(
                "libp2p connection {id} operation=kad request={op} closer={} providers=0 record={}",
                reply.closer.len(),
                reply.record.is_some()
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
            // Providers Rust knows of: this host for content it serves, and peers that
            // announced it with ADD_PROVIDER. Facts, answered without the model.
            if req.kind == Kind::GetProviders {
                let mut known = cfg.dht.providers(&req.key);
                if serves(cfg, &req.key) {
                    known.insert(0, me.clone());
                }
                if !known.is_empty() {
                    let mut reply = kad::Message::request(req.kind, req.key.clone());
                    known.truncate(kad::MAX_PEERS);
                    reply.providers = known;
                    reply.closer = closest_known;
                    log.info(format!(
                        "libp2p connection {id} operation=kad request={op} source=store closer={} providers={}",
                        reply.closer.len(),
                        reply.providers.len()
                    ));
                    send_kad(ctx, id, peer, stream_id, &reply).await;
                    return;
                }
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
                for p in &providers {
                    let mut p = p.clone();
                    if p.addrs.is_empty() {
                        p.addrs = known_addrs(cfg, &p.id);
                    }
                    cfg.dht.add_provider(&req.key, p);
                }
                log.info(format!(
                    "libp2p connection {id} operation=kad request={op} decision=stored key={} provider={}",
                    req.key_text(),
                    peer.remote_peer
                ));
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

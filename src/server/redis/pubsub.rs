//! Pub/sub for one Redis server: which connection is subscribed to what, and delivery of a
//! published message to every connection whose subscription matches.
//!
//! This is protocol mechanics, not storage. Nothing here outlives the connections that put it
//! here: a subscription is a fact about a live socket, and it is removed with the socket. No
//! message is retained — one that finds no subscriber is gone, as in Redis. What the model
//! decides is policy: whether a `SUBSCRIBE` is honoured, whether a `PUBLISH` is delivered and
//! what it answers, and what the server publishes on its own (`redis_publish_message`).
//!
//! # Ordering
//!
//! Every byte a connection's read loop writes goes through that connection's [`Outbox`], and
//! so does every message delivered to it, so one writer task owns the socket and frames never
//! interleave. A subscription is registered and its confirmation queued under the hub lock,
//! and a publish queues its messages under the same lock, so a subscriber reads the
//! `subscribe` confirmation before any message on that channel — the order every client
//! library relies on to know its subscription is live.
//!
//! # Bounds
//!
//! Everything a peer can grow is capped, and every cap refuses rather than truncates:
//!
//! | Bound | Value | On breach |
//! |---|---|---|
//! | [`MAX_CHANNEL_BYTES`] | 1 KiB | the command is refused |
//! | [`MAX_PATTERN_BYTES`] | 256 B | the command is refused |
//! | [`MAX_MESSAGE_BYTES`] | 1 MiB | the `PUBLISH` is refused, nothing is delivered |
//! | [`MAX_SUBSCRIPTIONS_PER_CONNECTION`] | 1024 | the whole command is refused |
//! | [`MAX_SUBSCRIPTIONS_PER_SERVER`] | 65 536 | the whole command is refused |
//! | [`MAX_PATTERNS_PER_SERVER`] | 1024 distinct | the whole command is refused |
//! | [`SUBSCRIBER_OUTPUT_LIMIT_BYTES`] | 8 MiB queued | the subscriber is disconnected |
//!
//! A publish costs, per distinct pattern, at most `pattern bytes × channel bytes` matcher
//! steps (`utils::redis_keys::glob_match` is iterative and never backtracks past the last
//! `*`), which is why both lengths and the number of distinct patterns are capped.
//!
//! The last row is Redis's `client-output-buffer-limit pubsub` hard limit: a subscriber that
//! does not read is closed rather than allowed to make the server buffer without bound. Redis
//! ships `32mb 8mb 60`; this server applies the hard limit only, at 8 MiB, because 256
//! connections at 32 MiB each is 8 GiB of somebody else's messages.
use super::resp_value::Resp;
use crate::utils::redis_keys::glob_match;
use bytes::Bytes;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::{mpsc, oneshot, watch};
use tracing::warn;

/// Longest channel name accepted, in bytes.
pub const MAX_CHANNEL_BYTES: usize = 1024;
/// Longest pattern accepted, in bytes.
pub const MAX_PATTERN_BYTES: usize = 256;
/// Largest message a `PUBLISH` (or `redis_publish_message`) may carry.
pub const MAX_MESSAGE_BYTES: usize = 1024 * 1024;
/// Channels, patterns and shard channels one connection may hold together.
pub const MAX_SUBSCRIPTIONS_PER_CONNECTION: usize = 1024;
/// Subscriptions of every kind across every connection of one server.
pub const MAX_SUBSCRIPTIONS_PER_SERVER: usize = 65_536;
/// Distinct patterns across one server — the number of matcher runs one publish costs.
pub const MAX_PATTERNS_PER_SERVER: usize = 1024;
/// Delivered-but-unwritten bytes one subscriber may have queued before it is disconnected.
pub const SUBSCRIBER_OUTPUT_LIMIT_BYTES: usize = 8 * 1024 * 1024;

/// Which namespace a subscription lives in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// `SUBSCRIBE` / `PUBLISH`.
    Channel,
    /// `PSUBSCRIBE`: a glob over channel names.
    Pattern,
    /// `SSUBSCRIBE` / `SPUBLISH`: a shard channel, routed by hash slot in a cluster.
    Shard,
}

impl Kind {
    fn subscribe_word(self) -> &'static str {
        match self {
            Kind::Channel => "subscribe",
            Kind::Pattern => "psubscribe",
            Kind::Shard => "ssubscribe",
        }
    }
    fn unsubscribe_word(self) -> &'static str {
        match self {
            Kind::Channel => "unsubscribe",
            Kind::Pattern => "punsubscribe",
            Kind::Shard => "sunsubscribe",
        }
    }
    fn max_name_bytes(self) -> usize {
        match self {
            Kind::Pattern => MAX_PATTERN_BYTES,
            _ => MAX_CHANNEL_BYTES,
        }
    }
}

// ============================================================================
// Outbox: the single writer of one connection
// ============================================================================

/// One frame on its way to a connection's socket.
pub struct OutFrame {
    pub bytes: Bytes,
    /// A delivered pub/sub message, counted against [`SUBSCRIBER_OUTPUT_LIMIT_BYTES`]. Replies
    /// are not: the read loop waits for each reply to be written before reading the next
    /// command, so they can never pile up.
    pub counted: bool,
    /// Told when the frame has been written (or failed to be).
    pub ack: Option<oneshot::Sender<std::io::Result<()>>>,
}

/// The sending side of a connection's writer task, plus the slow-consumer accounting.
#[derive(Clone)]
pub struct Outbox {
    tx: mpsc::UnboundedSender<OutFrame>,
    queued: Arc<AtomicUsize>,
    limit: usize,
    killed: Arc<watch::Sender<bool>>,
}

/// What the writer task needs: the receiving side and the shared counter.
pub struct OutboxReceiver {
    pub rx: mpsc::UnboundedReceiver<OutFrame>,
    pub queued: Arc<AtomicUsize>,
}

impl Outbox {
    pub fn new() -> (Outbox, OutboxReceiver) {
        Self::with_limit(SUBSCRIBER_OUTPUT_LIMIT_BYTES)
    }

    pub fn with_limit(limit: usize) -> (Outbox, OutboxReceiver) {
        let (tx, rx) = mpsc::unbounded_channel();
        let queued = Arc::new(AtomicUsize::new(0));
        let (killed, _) = watch::channel(false);
        (
            Outbox {
                tx,
                queued: queued.clone(),
                limit,
                killed: Arc::new(killed),
            },
            OutboxReceiver { rx, queued },
        )
    }

    /// Resolves once the connection has been marked for closing — a slow consumer, or a write
    /// that failed. The read loop selects on it, and so does every wait for a reply to be
    /// written, so a peer that has stopped reading cannot park either of them.
    pub async fn closing(&self) {
        let mut rx = self.killed.subscribe();
        let _ = rx.wait_for(|k| *k).await;
    }

    pub fn is_closing(&self) -> bool {
        *self.killed.borrow()
    }

    /// Queue a reply and wait until it is on the socket. The read loop's only write path, so a
    /// peer that stops reading still stalls its own command stream exactly as a direct write
    /// would have.
    pub async fn send_reply(&self, bytes: Vec<u8>) -> std::io::Result<()> {
        let (ack, done) = oneshot::channel();
        self.tx
            .send(OutFrame {
                bytes: Bytes::from(bytes),
                counted: false,
                ack: Some(ack),
            })
            .map_err(|_| std::io::Error::other("connection writer has stopped"))?;
        tokio::select! {
            written = done => written
                .unwrap_or_else(|_| Err(std::io::Error::other("connection writer has stopped"))),
            _ = self.closing() => Err(std::io::Error::other("connection is closing")),
        }
    }

    /// Queue a frame without waiting: subscription confirmations, which must keep their place
    /// relative to messages, and are queued under the hub lock.
    fn queue_reply(&self, bytes: Bytes) {
        let _ = self.tx.send(OutFrame {
            bytes,
            counted: false,
            ack: None,
        });
    }

    /// Queue a delivered message, unless that would take this subscriber past its output
    /// limit, in which case the subscriber is marked for disconnection.
    fn deliver(&self, bytes: Bytes) -> Delivery {
        if self.is_closing() {
            return Delivery::Gone;
        }
        let len = bytes.len();
        let before = self.queued.fetch_add(len, Ordering::AcqRel);
        if before + len > self.limit {
            self.queued.fetch_sub(len, Ordering::AcqRel);
            self.mark_killed();
            return Delivery::Overflow;
        }
        if self
            .tx
            .send(OutFrame {
                bytes,
                counted: true,
                ack: None,
            })
            .is_err()
        {
            self.queued.fetch_sub(len, Ordering::AcqRel);
            return Delivery::Gone;
        }
        Delivery::Queued
    }

    /// Mark the connection for closing and wake its read loop.
    pub fn mark_killed(&self) {
        self.killed.send_replace(true);
    }

    /// Bytes of delivered messages waiting to be written.
    pub fn queued_bytes(&self) -> usize {
        self.queued.load(Ordering::Acquire)
    }
}

/// What happened to one delivery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Delivery {
    Queued,
    /// Past the output limit: the subscriber is being disconnected.
    Overflow,
    /// The connection is already closing.
    Gone,
}

// ============================================================================
// The hub
// ============================================================================

struct Subscriber {
    outbox: Outbox,
    /// The connection's RESP version, read at delivery time: a message is a push on RESP3 and
    /// an array on RESP2.
    proto: Arc<AtomicU8>,
    channels: BTreeSet<Vec<u8>>,
    patterns: BTreeSet<Vec<u8>>,
    shard: BTreeSet<Vec<u8>>,
}

impl Subscriber {
    fn set(&self, kind: Kind) -> &BTreeSet<Vec<u8>> {
        match kind {
            Kind::Channel => &self.channels,
            Kind::Pattern => &self.patterns,
            Kind::Shard => &self.shard,
        }
    }
    fn set_mut(&mut self, kind: Kind) -> &mut BTreeSet<Vec<u8>> {
        match kind {
            Kind::Channel => &mut self.channels,
            Kind::Pattern => &mut self.patterns,
            Kind::Shard => &mut self.shard,
        }
    }
    fn total(&self) -> usize {
        self.channels.len() + self.patterns.len() + self.shard.len()
    }
    /// The count Redis reports in a confirmation: channels plus patterns, or shard channels
    /// alone for the `s` family.
    fn reported(&self, kind: Kind) -> i64 {
        match kind {
            Kind::Shard => self.shard.len() as i64,
            _ => (self.channels.len() + self.patterns.len()) as i64,
        }
    }
}

#[derive(Default)]
struct HubInner {
    subscribers: HashMap<u32, Subscriber>,
    channels: HashMap<Vec<u8>, BTreeSet<u32>>,
    patterns: HashMap<Vec<u8>, BTreeSet<u32>>,
    shard: HashMap<Vec<u8>, BTreeSet<u32>>,
    total: usize,
}

impl HubInner {
    fn index_mut(&mut self, kind: Kind) -> &mut HashMap<Vec<u8>, BTreeSet<u32>> {
        match kind {
            Kind::Channel => &mut self.channels,
            Kind::Pattern => &mut self.patterns,
            Kind::Shard => &mut self.shard,
        }
    }
    fn index(&self, kind: Kind) -> &HashMap<Vec<u8>, BTreeSet<u32>> {
        match kind {
            Kind::Channel => &self.channels,
            Kind::Pattern => &self.patterns,
            Kind::Shard => &self.shard,
        }
    }

    fn drop_subscriber(&mut self, conn: u32) {
        let Some(sub) = self.subscribers.remove(&conn) else {
            return;
        };
        for kind in [Kind::Channel, Kind::Pattern, Kind::Shard] {
            for name in sub.set(kind) {
                let index = self.index_mut(kind);
                if let Some(set) = index.get_mut(name) {
                    set.remove(&conn);
                    if set.is_empty() {
                        index.remove(name);
                    }
                }
            }
        }
        self.total -= sub.total();
    }
}

/// The subscription registry of one server.
#[derive(Default)]
pub struct PubSubHub {
    inner: Mutex<HubInner>,
}

/// A message frame for one subscriber's protocol version.
fn message_frame(
    kind: Kind,
    pattern: Option<&[u8]>,
    channel: &[u8],
    message: &[u8],
    proto: u8,
) -> Bytes {
    let mut items = vec![Resp::bulk(match (kind, pattern) {
        (Kind::Shard, _) => "smessage",
        (_, Some(_)) => "pmessage",
        _ => "message",
    })];
    if let Some(p) = pattern {
        items.push(Resp::bulk(p));
    }
    items.push(Resp::bulk(channel));
    items.push(Resp::bulk(message));
    Bytes::from(Resp::Push(items).encode(proto))
}

fn confirmation(word: &str, name: Option<&[u8]>, count: i64, proto: u8) -> Bytes {
    Bytes::from(
        Resp::Push(vec![
            Resp::bulk(word),
            name.map(Resp::bulk).unwrap_or(Resp::Null),
            Resp::Int(count),
        ])
        .encode(proto),
    )
}

/// Check one name against its length bound. `Err` is the RESP error to send.
pub fn check_name(kind: Kind, name: &[u8]) -> Result<(), String> {
    if name.len() > kind.max_name_bytes() {
        let what = if kind == Kind::Pattern {
            "pattern"
        } else {
            "channel name"
        };
        return Err(format!(
            "ERR {what} longer than {} bytes",
            kind.max_name_bytes()
        ));
    }
    Ok(())
}

/// Check a message against [`MAX_MESSAGE_BYTES`].
pub fn check_message(message: &[u8]) -> Result<(), String> {
    if message.len() > MAX_MESSAGE_BYTES {
        return Err(format!("ERR message longer than {MAX_MESSAGE_BYTES} bytes"));
    }
    Ok(())
}

impl PubSubHub {
    fn lock(&self) -> std::sync::MutexGuard<'_, HubInner> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Whether `names` could be subscribed by `conn` without breaking a bound. Called before
    /// the model is asked, so a request that can never be honoured costs no model call, and
    /// again inside [`Self::subscribe`] because the hub may have changed while it was asked.
    pub fn check_subscribe(&self, conn: u32, kind: Kind, names: &[Vec<u8>]) -> Result<(), String> {
        let inner = self.lock();
        Self::check_locked(&inner, conn, kind, names)
    }

    fn check_locked(
        inner: &HubInner,
        conn: u32,
        kind: Kind,
        names: &[Vec<u8>],
    ) -> Result<(), String> {
        for name in names {
            check_name(kind, name)?;
        }
        let existing = inner.subscribers.get(&conn);
        let new: HashSet<&Vec<u8>> = names
            .iter()
            .filter(|n| existing.is_none_or(|s| !s.set(kind).contains(*n)))
            .collect();
        let held = existing.map(Subscriber::total).unwrap_or(0);
        if held + new.len() > MAX_SUBSCRIPTIONS_PER_CONNECTION {
            return Err(format!(
                "ERR max subscriptions per connection reached ({MAX_SUBSCRIPTIONS_PER_CONNECTION})"
            ));
        }
        if inner.total + new.len() > MAX_SUBSCRIPTIONS_PER_SERVER {
            return Err(format!(
                "ERR max subscriptions per server reached ({MAX_SUBSCRIPTIONS_PER_SERVER})"
            ));
        }
        if kind == Kind::Pattern {
            let distinct_new = new
                .iter()
                .filter(|p| !inner.patterns.contains_key(**p))
                .count();
            if inner.patterns.len() + distinct_new > MAX_PATTERNS_PER_SERVER {
                return Err(format!(
                    "ERR max distinct patterns per server reached ({MAX_PATTERNS_PER_SERVER})"
                ));
            }
        }
        Ok(())
    }

    /// Subscribe `conn` to `names` and queue one confirmation per name on its outbox, in
    /// order, under the hub lock. All or nothing: a bound breached by any name refuses the
    /// whole command, and `Err` is the RESP error to send.
    pub fn subscribe(
        &self,
        conn: u32,
        outbox: &Outbox,
        proto: &Arc<AtomicU8>,
        kind: Kind,
        names: &[Vec<u8>],
    ) -> Result<(), String> {
        let mut inner = self.lock();
        Self::check_locked(&inner, conn, kind, names)?;
        let version = proto.load(Ordering::Relaxed);
        inner.subscribers.entry(conn).or_insert_with(|| Subscriber {
            outbox: outbox.clone(),
            proto: proto.clone(),
            channels: BTreeSet::new(),
            patterns: BTreeSet::new(),
            shard: BTreeSet::new(),
        });
        for name in names {
            let added = inner
                .subscribers
                .get_mut(&conn)
                .map(|s| s.set_mut(kind).insert(name.clone()))
                .unwrap_or(false);
            if added {
                inner.total += 1;
                inner
                    .index_mut(kind)
                    .entry(name.clone())
                    .or_default()
                    .insert(conn);
            }
            let count = inner
                .subscribers
                .get(&conn)
                .map(|s| s.reported(kind))
                .unwrap_or(0);
            outbox.queue_reply(confirmation(
                kind.subscribe_word(),
                Some(name),
                count,
                version,
            ));
        }
        Ok(())
    }

    /// Unsubscribe `conn` from `names`, or from everything of `kind` when `names` is empty,
    /// queuing one confirmation per name. With nothing to unsubscribe from, Redis still
    /// answers once, with a null name and the current count; so does this.
    pub fn unsubscribe(
        &self,
        conn: u32,
        outbox: &Outbox,
        proto: u8,
        kind: Kind,
        names: &[Vec<u8>],
    ) {
        let mut inner = self.lock();
        let targets: Vec<Vec<u8>> = if names.is_empty() {
            inner
                .subscribers
                .get(&conn)
                .map(|s| s.set(kind).iter().cloned().collect())
                .unwrap_or_default()
        } else {
            names.to_vec()
        };
        if targets.is_empty() {
            let count = inner
                .subscribers
                .get(&conn)
                .map(|s| s.reported(kind))
                .unwrap_or(0);
            outbox.queue_reply(confirmation(kind.unsubscribe_word(), None, count, proto));
            return;
        }
        for name in targets {
            let removed = inner
                .subscribers
                .get_mut(&conn)
                .map(|s| s.set_mut(kind).remove(&name))
                .unwrap_or(false);
            if removed {
                inner.total -= 1;
                let index = inner.index_mut(kind);
                if let Some(set) = index.get_mut(&name) {
                    set.remove(&conn);
                    if set.is_empty() {
                        index.remove(&name);
                    }
                }
            }
            let count = inner
                .subscribers
                .get(&conn)
                .map(|s| s.reported(kind))
                .unwrap_or(0);
            outbox.queue_reply(confirmation(
                kind.unsubscribe_word(),
                Some(&name),
                count,
                proto,
            ));
        }
        if inner.subscribers.get(&conn).is_some_and(|s| s.total() == 0) {
            inner.subscribers.remove(&conn);
        }
    }

    /// Forget every subscription `conn` holds, without confirmations: the connection closed,
    /// or sent `RESET`.
    pub fn remove_connection(&self, conn: u32) {
        self.lock().drop_subscriber(conn);
    }

    /// Subscriptions `conn` holds (channels + patterns + shard channels). Above zero, a RESP2
    /// connection is in subscribed mode.
    pub fn subscription_count(&self, conn: u32) -> usize {
        self.lock()
            .subscribers
            .get(&conn)
            .map(Subscriber::total)
            .unwrap_or(0)
    }

    /// How many deliveries a publish would make right now, for the model's event.
    pub fn receivers(&self, channel: &[u8], shard: bool) -> usize {
        let inner = self.lock();
        if shard {
            return inner.shard.get(channel).map(BTreeSet::len).unwrap_or(0);
        }
        inner.channels.get(channel).map(BTreeSet::len).unwrap_or(0)
            + inner
                .patterns
                .iter()
                .filter(|(p, _)| glob_match(p, channel))
                .map(|(_, subs)| subs.len())
                .sum::<usize>()
    }

    /// Deliver `message` on `channel` to every matching subscription and return how many
    /// deliveries were queued — Redis's `PUBLISH` reply, where a connection subscribed to the
    /// channel and to a matching pattern receives (and counts) twice.
    ///
    /// A subscriber the delivery would take past [`SUBSCRIBER_OUTPUT_LIMIT_BYTES`] is not
    /// counted, is dropped from the hub, and its connection is woken to close.
    pub fn publish(&self, channel: &[u8], message: &[u8], shard: bool) -> usize {
        let mut inner = self.lock();
        let mut delivered = 0;
        let mut slow: Vec<u32> = Vec::new();
        let mut gone: Vec<u32> = Vec::new();
        // Each frame shape is encoded once per protocol version, not once per subscriber.
        let mut cache: HashMap<(Option<Vec<u8>>, u8), Bytes> = HashMap::new();
        let kind = if shard { Kind::Shard } else { Kind::Channel };
        let mut targets: Vec<(u32, Option<Vec<u8>>)> = inner
            .index(kind)
            .get(channel)
            .map(|subs| subs.iter().map(|c| (*c, None)).collect())
            .unwrap_or_default();
        if !shard {
            let mut matched: Vec<(&Vec<u8>, &BTreeSet<u32>)> = inner
                .patterns
                .iter()
                .filter(|(p, _)| glob_match(p, channel))
                .collect();
            matched.sort_by(|a, b| a.0.cmp(b.0));
            for (pattern, subs) in matched {
                targets.extend(subs.iter().map(|c| (*c, Some(pattern.clone()))));
            }
        }
        for (conn, pattern) in targets {
            let Some(sub) = inner.subscribers.get(&conn) else {
                continue;
            };
            let proto = sub.proto.load(Ordering::Relaxed);
            let frame = cache
                .entry((pattern.clone(), proto))
                .or_insert_with(|| message_frame(kind, pattern.as_deref(), channel, message, proto))
                .clone();
            match sub.outbox.deliver(frame) {
                Delivery::Queued => delivered += 1,
                Delivery::Overflow if !slow.contains(&conn) => slow.push(conn),
                Delivery::Gone if !gone.contains(&conn) => gone.push(conn),
                _ => {}
            }
        }
        for conn in gone {
            inner.drop_subscriber(conn);
        }
        for conn in slow {
            warn!(
                "Redis connection {} decision=slow_consumer_disconnected: more than {} bytes of \
                 pub/sub messages queued unread; dropping its subscriptions and closing it \
                 (Redis's client-output-buffer-limit pubsub)",
                conn, SUBSCRIBER_OUTPUT_LIMIT_BYTES
            );
            inner.drop_subscriber(conn);
        }
        delivered
    }

    /// `PUBSUB CHANNELS` / `SHARDCHANNELS`: active channels, optionally filtered by a pattern.
    pub fn active_channels(&self, shard: bool, pattern: Option<&[u8]>) -> Vec<Vec<u8>> {
        let inner = self.lock();
        let index = if shard { &inner.shard } else { &inner.channels };
        let mut names: Vec<Vec<u8>> = index
            .keys()
            .filter(|c| pattern.is_none_or(|p| glob_match(p, c)))
            .cloned()
            .collect();
        names.sort();
        names
    }

    /// `PUBSUB NUMSUB` / `SHARDNUMSUB`: subscribers of each named channel.
    pub fn numsub(&self, shard: bool, channels: &[Vec<u8>]) -> Vec<(Vec<u8>, usize)> {
        let inner = self.lock();
        let index = if shard { &inner.shard } else { &inner.channels };
        channels
            .iter()
            .map(|c| (c.clone(), index.get(c).map(BTreeSet::len).unwrap_or(0)))
            .collect()
    }

    /// `PUBSUB NUMPAT`: distinct patterns subscribed across the server.
    pub fn numpat(&self) -> usize {
        self.lock().patterns.len()
    }

    /// Subscriptions across the server, for `list_redis_subscriptions`.
    pub fn snapshot(&self) -> serde_json::Value {
        let inner = self.lock();
        let names = |index: &HashMap<Vec<u8>, BTreeSet<u32>>| {
            let mut v: Vec<serde_json::Value> = index
                .iter()
                .map(|(name, subs)| {
                    serde_json::json!({
                        "name": String::from_utf8_lossy(name),
                        "subscribers": subs.len(),
                    })
                })
                .collect();
            v.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
            v
        };
        serde_json::json!({
            "channels": names(&inner.channels),
            "patterns": names(&inner.patterns),
            "shard_channels": names(&inner.shard),
            "subscribed_connections": inner.subscribers.len(),
            "total_subscriptions": inner.total,
        })
    }
}

//! Observe (RFC 7641) for the CoAP server: who is observing what, and which notification a
//! client's ACK or RST answers. Pure and synchronous, like `blockwise.rs`.
//!
//! An observer is an endpoint and a token (§3.1). A GET with Observe 0 that the model answers
//! with a 2.xx registers one, and the response carries an Observe sequence number; a GET with
//! Observe 1 on the same token removes it (§3.6). The model then pushes state with
//! `coap_notify`, which reaches every observer of the path.
//!
//! An observation also ends when the client says so on the message layer: a **RST** in reply
//! to a notification (§3.6, the "forget me" a client sends when it has lost interest), or a
//! Confirmable notification that is never acknowledged (§4.5). Both need the notification's
//! message id mapped back to its observer, which is what [`Observers::record`] keeps.
//!
//! A registration is a claim about an address the server cannot verify — UDP source addresses
//! are spoofable — so the registry bounds what one claim can cost: [`MAX_OBSERVERS_PER_IP`]
//! registrations per source IP, and every registration expires [`OBSERVER_MAX_AGE`] after it
//! was last *confirmed* (registered, re-registered, or a Confirmable notification to it was
//! acknowledged). An observer that has gone unconfirmed for half that age gets its next
//! notification as Confirmable whatever `coap_notify` asked for, which is RFC 7641 §4.5's
//! "at least every 24 hours": a live client acknowledges it and stays, a spoofed address does
//! not and is removed when the retransmissions run out.

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::time::Duration;

use crate::server::connection::ConnectionId;
use crate::utils::clock::Instant;

/// Observers one server holds at once. A registration past this is served as an ordinary
/// response without the Observe option, which is how RFC 7641 §4.1 says "not observable":
/// the client learns it is not registered rather than waiting for notifications that never
/// come.
pub const MAX_OBSERVERS: usize = 64;

/// Observers one source IP may hold at once, whatever its ports and tokens. A registration
/// past this is served without Observe, like one past [`MAX_OBSERVERS`], so one address — or
/// one spoofed victim — cannot take the whole registry.
pub const MAX_OBSERVERS_PER_IP: usize = 4;

/// How long a registration lasts without being confirmed. RFC 7641 §4.5 requires a
/// Confirmable notification at least every 24 hours; a registration nobody has confirmed for
/// that long is presumed gone and removed.
pub const OBSERVER_MAX_AGE: Duration = Duration::from_secs(24 * 60 * 60);

/// Notification message ids remembered so a RST can be matched to its observer. A client
/// answers a notification within ACK_TIMEOUT or not at all, so a window this wide is generous
/// even at one notification per observer per second. ACKs are matched against the pending
/// Confirmable notifications instead, which this window does not bound: a Confirmable
/// notification that falls out of it is still waited for.
pub const RECENT_NOTIFICATIONS: usize = 256;

/// Observe sequence numbers are 24 bits (§4.4).
pub const SEQUENCE_MASK: u32 = 0x00FF_FFFF;

/// One registration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observer {
    pub peer: SocketAddr,
    pub token: Vec<u8>,
    pub path: String,
    pub query: Option<String>,
    /// The Block2 size the client asked for on registration, if it asked; notifications larger
    /// than one block are split at this size.
    pub block_szx: Option<u8>,
    pub connection_id: ConnectionId,
}

/// What a registration did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Registered {
    Added,
    /// The same endpoint and token re-registered (§4.1): the entry is refreshed, not doubled.
    Replaced,
    /// [`MAX_OBSERVERS`] are registered already.
    Full,
    /// The peer's IP holds [`MAX_OBSERVERS_PER_IP`] registrations already.
    PeerFull,
}

/// A notification recently sent, kept only so a RST can be matched to its observer.
#[derive(Debug, Clone)]
struct Sent {
    peer: SocketAddr,
    message_id: u16,
    token: Vec<u8>,
}

#[derive(Debug, Clone)]
struct Entry {
    observer: Observer,
    /// When the registration was last confirmed: registered, re-registered, or acknowledged.
    confirmed: Instant,
}

/// The registry.
#[derive(Debug)]
pub struct Observers {
    list: Vec<Entry>,
    cap: usize,
    per_ip: usize,
    max_age: Duration,
    sequence: u32,
    /// The last [`RECENT_NOTIFICATIONS`] notifications, for matching a RST.
    sent: VecDeque<Sent>,
    /// Confirmable notifications still waiting for their ACK, by (peer, message id), holding
    /// the observer's token. Never evicted by age or count: an entry leaves only when it is
    /// acknowledged, reset, superseded by a newer Confirmable notification to the same
    /// observer (RFC 7641 §4.5.2), its observer is deregistered, or its retransmission task
    /// [`settle`](Observers::settle)s it. At most one per observer, so at most `cap`.
    pending: HashMap<(SocketAddr, u16), Vec<u8>>,
}

impl Default for Observers {
    fn default() -> Self {
        Observers::new(MAX_OBSERVERS, MAX_OBSERVERS_PER_IP, OBSERVER_MAX_AGE)
    }
}

impl Observers {
    pub fn new(cap: usize, per_ip: usize, max_age: Duration) -> Observers {
        Observers {
            list: Vec::new(),
            cap,
            per_ip,
            max_age,
            // 0 and 1 are the register/deregister values in a request; starting past them
            // keeps a notification's sequence from reading like one in a packet capture.
            sequence: 2,
            sent: VecDeque::new(),
            pending: HashMap::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.list.len()
    }

    pub fn is_empty(&self) -> bool {
        self.list.is_empty()
    }

    /// The next sequence number. Strictly increasing modulo 2^24, shared by every resource —
    /// §4.4 needs only that one observer's notifications increase.
    pub fn next_sequence(&mut self) -> u32 {
        let seq = self.sequence & SEQUENCE_MASK;
        self.sequence = (self.sequence + 1) & SEQUENCE_MASK;
        seq
    }

    /// Register `observer`, confirmed as of `now`. The same endpoint and token re-registering
    /// replaces its entry and renews its confirmation; a new one is refused past
    /// [`MAX_OBSERVERS_PER_IP`] for its IP or [`MAX_OBSERVERS`] in all.
    pub fn register(&mut self, observer: Observer, now: Instant) -> Registered {
        if let Some(existing) = self
            .list
            .iter_mut()
            .find(|e| e.observer.peer == observer.peer && e.observer.token == observer.token)
        {
            *existing = Entry {
                observer,
                confirmed: now,
            };
            return Registered::Replaced;
        }
        let ip = observer.peer.ip();
        if self
            .list
            .iter()
            .filter(|e| e.observer.peer.ip() == ip)
            .count()
            >= self.per_ip
        {
            return Registered::PeerFull;
        }
        if self.list.len() >= self.cap {
            return Registered::Full;
        }
        self.list.push(Entry {
            observer,
            confirmed: now,
        });
        Registered::Added
    }

    /// Remove every registration not confirmed within the maximum age, returning them.
    pub fn expire(&mut self, now: Instant) -> Vec<Observer> {
        let max_age = self.max_age;
        let mut expired = Vec::new();
        self.list.retain(|e| {
            let keep = now.saturating_duration_since(e.confirmed) < max_age;
            if !keep {
                expired.push(e.observer.clone());
            }
            keep
        });
        for observer in &expired {
            self.pending
                .retain(|(p, _), t| !(*p == observer.peer && *t == observer.token));
        }
        expired
    }

    /// Whether the next notification to this observer must be Confirmable because it has gone
    /// unconfirmed for half the maximum age (RFC 7641 §4.5).
    pub fn needs_confirmation(&self, peer: SocketAddr, token: &[u8], now: Instant) -> bool {
        let half = self.max_age / 2;
        self.list.iter().any(|e| {
            e.observer.peer == peer
                && e.observer.token == token
                && now.saturating_duration_since(e.confirmed) >= half
        })
    }

    /// Remove the observation `peer` holds under `token`. True if there was one.
    pub fn deregister(&mut self, peer: SocketAddr, token: &[u8]) -> bool {
        let before = self.list.len();
        self.list
            .retain(|e| !(e.observer.peer == peer && e.observer.token == token));
        self.pending
            .retain(|(p, _), t| !(*p == peer && t.as_slice() == token));
        before != self.list.len()
    }

    /// Every observer of `path`, in registration order.
    pub fn of_path(&self, path: &str) -> Vec<Observer> {
        self.list
            .iter()
            .filter(|e| e.observer.path == path)
            .map(|e| e.observer.clone())
            .collect()
    }

    /// Every registration, for the dashboard and the docs.
    pub fn all(&self) -> Vec<Observer> {
        self.list.iter().map(|e| e.observer.clone()).collect()
    }

    /// Remember that a notification went to `peer` with `message_id`. A `confirmable` one is
    /// also held as pending until it is acknowledged or settled, replacing any earlier pending
    /// notification to the same observer — only the newest is retransmitted (RFC 7641 §4.5.2).
    pub fn record(&mut self, peer: SocketAddr, message_id: u16, token: &[u8], confirmable: bool) {
        self.sent
            .retain(|s| !(s.peer == peer && s.message_id == message_id));
        self.sent.push_back(Sent {
            peer,
            message_id,
            token: token.to_vec(),
        });
        while self.sent.len() > RECENT_NOTIFICATIONS {
            self.sent.pop_front();
        }
        self.pending.remove(&(peer, message_id));
        if confirmable {
            self.pending
                .retain(|(p, _), t| !(*p == peer && t.as_slice() == token));
            self.pending.insert((peer, message_id), token.to_vec());
        }
    }

    /// An empty ACK from `peer`. True if it acknowledged a pending Confirmable notification,
    /// which also renews the observer's confirmation as of `now`.
    pub fn acknowledge(&mut self, peer: SocketAddr, message_id: u16, now: Instant) -> bool {
        let Some(token) = self.pending.remove(&(peer, message_id)) else {
            return false;
        };
        if let Some(entry) = self
            .list
            .iter_mut()
            .find(|e| e.observer.peer == peer && e.observer.token == token)
        {
            entry.confirmed = now;
        }
        true
    }

    /// Whether a Confirmable notification is still waiting for its ACK: it is pending and its
    /// observer is still registered. A notification that is not pending was acknowledged,
    /// reset, superseded or settled — never merely forgotten, because pending entries are not
    /// evicted.
    pub fn awaiting_ack(&self, peer: SocketAddr, message_id: u16) -> bool {
        self.pending.get(&(peer, message_id)).is_some_and(|token| {
            self.list
                .iter()
                .any(|e| e.observer.peer == peer && &e.observer.token == token)
        })
    }

    /// Stop waiting for an ACK to this notification: its retransmission task has ended.
    pub fn settle(&mut self, peer: SocketAddr, message_id: u16) {
        self.pending.remove(&(peer, message_id));
    }

    /// Confirmable notifications waiting for their ACK.
    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    /// A RST from `peer`: if it answers a notification, that observation ends (§3.6). Returns
    /// the observer removed.
    pub fn reset(&mut self, peer: SocketAddr, message_id: u16) -> Option<Observer> {
        let token = match self.pending.remove(&(peer, message_id)) {
            Some(token) => token,
            None => self
                .sent
                .iter()
                .find(|s| s.peer == peer && s.message_id == message_id)?
                .token
                .clone(),
        };
        let observer = self
            .list
            .iter()
            .find(|e| e.observer.peer == peer && e.observer.token == token)
            .map(|e| e.observer.clone())?;
        self.deregister(peer, &token);
        Some(observer)
    }
}

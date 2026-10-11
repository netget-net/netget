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

use std::collections::VecDeque;
use std::net::SocketAddr;

use crate::server::connection::ConnectionId;

/// Observers one server holds at once. A registration past this is served as an ordinary
/// response without the Observe option, which is how RFC 7641 §4.1 says "not observable":
/// the client learns it is not registered rather than waiting for notifications that never
/// come.
pub const MAX_OBSERVERS: usize = 64;

/// Notification message ids remembered so a RST or ACK can be matched to its observer. A
/// client answers a notification within ACK_TIMEOUT or not at all, so a window this wide is
/// generous even at one notification per observer per second.
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
}

#[derive(Debug, Clone)]
struct Sent {
    peer: SocketAddr,
    message_id: u16,
    token: Vec<u8>,
    confirmable: bool,
    acknowledged: bool,
}

/// The registry.
#[derive(Debug)]
pub struct Observers {
    list: Vec<Observer>,
    cap: usize,
    sequence: u32,
    sent: VecDeque<Sent>,
}

impl Default for Observers {
    fn default() -> Self {
        Observers::new(MAX_OBSERVERS)
    }
}

impl Observers {
    pub fn new(cap: usize) -> Observers {
        Observers {
            list: Vec::new(),
            cap,
            // 0 and 1 are the register/deregister values in a request; starting past them
            // keeps a notification's sequence from reading like one in a packet capture.
            sequence: 2,
            sent: VecDeque::new(),
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

    pub fn register(&mut self, observer: Observer) -> Registered {
        if let Some(existing) = self
            .list
            .iter_mut()
            .find(|o| o.peer == observer.peer && o.token == observer.token)
        {
            *existing = observer;
            return Registered::Replaced;
        }
        if self.list.len() >= self.cap {
            return Registered::Full;
        }
        self.list.push(observer);
        Registered::Added
    }

    /// Remove the observation `peer` holds under `token`. True if there was one.
    pub fn deregister(&mut self, peer: SocketAddr, token: &[u8]) -> bool {
        let before = self.list.len();
        self.list.retain(|o| !(o.peer == peer && o.token == token));
        before != self.list.len()
    }

    /// Every observer of `path`, in registration order.
    pub fn of_path(&self, path: &str) -> Vec<Observer> {
        self.list
            .iter()
            .filter(|o| o.path == path)
            .cloned()
            .collect()
    }

    /// Every registration, for the dashboard and the docs.
    pub fn all(&self) -> Vec<Observer> {
        self.list.clone()
    }

    /// Remember that a notification went to `peer` with `message_id`.
    pub fn record(&mut self, peer: SocketAddr, message_id: u16, token: &[u8], confirmable: bool) {
        self.sent
            .retain(|s| !(s.peer == peer && s.message_id == message_id));
        self.sent.push_back(Sent {
            peer,
            message_id,
            token: token.to_vec(),
            confirmable,
            acknowledged: false,
        });
        while self.sent.len() > RECENT_NOTIFICATIONS {
            self.sent.pop_front();
        }
    }

    /// An empty ACK from `peer`. True if it acknowledged a Confirmable notification.
    pub fn acknowledge(&mut self, peer: SocketAddr, message_id: u16) -> bool {
        match self
            .sent
            .iter_mut()
            .find(|s| s.peer == peer && s.message_id == message_id && s.confirmable)
        {
            Some(sent) => {
                sent.acknowledged = true;
                true
            }
            None => false,
        }
    }

    /// Whether a Confirmable notification is still waiting for its ACK. False once acknowledged,
    /// once its observer is gone, or once it fell out of the window.
    pub fn awaiting_ack(&self, peer: SocketAddr, message_id: u16) -> bool {
        self.sent.iter().any(|s| {
            s.peer == peer
                && s.message_id == message_id
                && s.confirmable
                && !s.acknowledged
                && self
                    .list
                    .iter()
                    .any(|o| o.peer == peer && o.token == s.token)
        })
    }

    /// A RST from `peer`: if it answers a notification, that observation ends (§3.6). Returns
    /// the observer removed.
    pub fn reset(&mut self, peer: SocketAddr, message_id: u16) -> Option<Observer> {
        let token = self
            .sent
            .iter()
            .find(|s| s.peer == peer && s.message_id == message_id)?
            .token
            .clone();
        let observer = self
            .list
            .iter()
            .find(|o| o.peer == peer && o.token == token)
            .cloned()?;
        self.deregister(peer, &token);
        Some(observer)
    }
}

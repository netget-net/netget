//! Open subscriptions, per connection and across the relay.
//!
//! This is not storage. It holds only what NIP-01 makes a relay responsible for while a
//! subscription is open — its id and filters — so that `CLOSE` needs no model call, so that the
//! events the model supplies can be held to the filters that asked for them, and so that an
//! event the model accepts reaches every other subscriber whose filters match it. Nothing is
//! kept after a subscription closes, and no event is kept at all.

use super::wire::{self, Event, Filter};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// What the connection's single writer sends.
#[derive(Debug)]
pub enum Outbound {
    /// One relay message (a JSON array) as a text frame.
    Text(String),
    /// A close frame; the writer sends nothing after it.
    Close { code: u16, reason: String },
    /// The idle keepalive.
    Ping(Vec<u8>),
    /// The connection is over: flush what was queued before this and stop.
    Shutdown,
}

impl Outbound {
    /// Payload size, for the connection's outbound bound (`utils::outbox`).
    pub fn weight(&self) -> usize {
        match self {
            Outbound::Text(t) => t.len(),
            Outbound::Close { reason, .. } => reason.len(),
            Outbound::Ping(p) => p.len(),
            Outbound::Shutdown => 0,
        }
    }
}

#[derive(Debug)]
struct Subscription {
    filters: Vec<Filter>,
    generation: u64,
}

#[derive(Debug, Default)]
struct Subscriptions {
    open: HashMap<String, Subscription>,
    next_generation: u64,
    /// The REQ the model is answering right now, if any: its id and generation.
    answering: Option<(String, u64)>,
}

/// One connection's subscriptions and the sender its frames go through.
#[derive(Debug)]
pub struct ConnShared {
    pub connection_id: u32,
    out_tx: crate::utils::outbox::OutboxSender<Outbound>,
    subs: Mutex<Subscriptions>,
}

impl ConnShared {
    pub fn new(connection_id: u32, out_tx: crate::utils::outbox::OutboxSender<Outbound>) -> Self {
        Self {
            connection_id,
            out_tx,
            subs: Mutex::new(Subscriptions::default()),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Subscriptions> {
        self.subs
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Queue one relay message.
    pub fn send(&self, message: String) {
        let _ = self.out_tx.send(Outbound::Text(message));
    }

    pub fn out_tx(&self) -> &crate::utils::outbox::OutboxSender<Outbound> {
        &self.out_tx
    }

    /// Open (or, NIP-01, overwrite) a subscription. Returns its generation, or the `CLOSED`
    /// message when the connection already holds [`wire::MAX_SUBSCRIPTIONS`].
    pub fn open(&self, subscription_id: &str, filters: Vec<Filter>) -> Result<u64, String> {
        let mut subs = self.lock();
        if !subs.open.contains_key(subscription_id) && subs.open.len() >= wire::MAX_SUBSCRIPTIONS {
            return Err(format!(
                "rate-limited: at most {} open subscriptions per connection; CLOSE one first",
                wire::MAX_SUBSCRIPTIONS
            ));
        }
        subs.next_generation += 1;
        let generation = subs.next_generation;
        subs.open.insert(
            subscription_id.to_string(),
            Subscription {
                filters,
                generation,
            },
        );
        Ok(generation)
    }

    /// Close a subscription. Whether it was open.
    pub fn close(&self, subscription_id: &str) -> bool {
        self.lock().open.remove(subscription_id).is_some()
    }

    /// Whether this exact subscription — not a later REQ reusing its id — is still open.
    pub fn is_open(&self, subscription_id: &str, generation: u64) -> bool {
        self.lock()
            .open
            .get(subscription_id)
            .is_some_and(|s| s.generation == generation)
    }

    pub fn open_count(&self) -> usize {
        self.lock().open.len()
    }

    /// Mark the REQ whose answer the model is producing.
    pub fn begin_answer(&self, subscription_id: &str, generation: u64) {
        self.lock().answering = Some((subscription_id.to_string(), generation));
    }

    pub fn end_answer(&self) {
        self.lock().answering = None;
    }

    /// The subscription an action addresses: the one it names, else the REQ being answered.
    /// Returns its id, its filters, and whether `limit` applies (only to the answer to the REQ
    /// itself — NIP-01's limit is on the initial query).
    pub fn target(&self, named: Option<&str>) -> Result<(String, Vec<Filter>, bool), String> {
        let subs = self.lock();
        let answering = subs.answering.clone();
        let id = match (named.filter(|n| !n.is_empty()), &answering) {
            (Some(n), _) => n.to_string(),
            (None, Some((id, _))) => id.clone(),
            (None, None) => {
                return Err(
                    "this action can only run while answering a nostr_req, or with the \
                     subscription_id of a subscription this connection has open"
                        .to_string(),
                )
            }
        };
        let Some(sub) = subs.open.get(&id) else {
            return Err(format!(
                "subscription {:?} is not open on this connection",
                crate::utils::truncate_for_log(&id, 64)
            ));
        };
        let apply_limit = answering
            .as_ref()
            .is_some_and(|(a, generation)| *a == id && *generation == sub.generation);
        Ok((id, sub.filters.clone(), apply_limit))
    }

    /// The subscriptions whose filters match `event`, ignoring `limit`.
    pub fn matching(&self, event: &Event) -> Vec<String> {
        self.lock()
            .open
            .iter()
            .filter(|(_, s)| s.filters.iter().any(|f| f.matches(event)))
            .map(|(id, _)| id.clone())
            .collect()
    }
}

/// Every connection of one relay, for delivering accepted events to live subscriptions.
#[derive(Debug, Default)]
pub struct Relay {
    connections: Mutex<HashMap<u32, Arc<ConnShared>>>,
}

impl Relay {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<u32, Arc<ConnShared>>> {
        self.connections
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub fn add(&self, conn: Arc<ConnShared>) {
        self.lock().insert(conn.connection_id, conn);
    }

    pub fn remove(&self, connection_id: u32) {
        self.lock().remove(&connection_id);
    }

    /// Send an accepted event to every open subscription it matches, on every connection —
    /// the publisher's own included, as NIP-01 relays do. Returns how many subscriptions got it.
    pub fn broadcast(&self, event: &Event) -> usize {
        let connections: Vec<Arc<ConnShared>> = self.lock().values().cloned().collect();
        let mut delivered = 0;
        for conn in connections {
            for subscription_id in conn.matching(event) {
                conn.send(wire::event_message(&subscription_id, event));
                delivered += 1;
            }
        }
        delivered
    }
}

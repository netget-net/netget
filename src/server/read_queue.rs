//! One connection's reads, answered one at a time and in the order they arrived.
//!
//! The byte-stream servers here (`tcp`, `tls`, `socket_file`, `bitcoin`) read on one task and
//! answer on another, so the reader can go back to `read()` while the model — or a script, or a
//! person behind a `manual` rule — composes the answer. What arrives meanwhile has to wait its
//! turn, and that turn has to be decided by the reader, in the order the reads came, under the
//! same lock that says whether an answer is in flight. Each of these servers once decided it in
//! a task spawned per read instead: the task read the state under one lock acquisition and set
//! it under another, so two reads could both find the connection [`ReadState::Idle`] and be
//! answered at once, and since nothing orders spawned tasks a later read could be answered
//! first. On a stream with no message ids the peer cannot tell that a reply belongs to another
//! message. The answering side had the mirror image: "is the queue empty?" and "go Idle" were
//! separate acquisitions, so a read queued between them waited until the peer sent something
//! else.
//!
//! [`ReadQueue`] is the state machine without the lock: each server keeps one inside the
//! per-connection entry its own `Mutex` guards, and every method is one decision made while that
//! guard is held. The rules it encodes:
//!
//! - [`ReadQueue::admit`] is called by the reader for every read, in order. It either starts an
//!   answer (the connection moves to [`ReadState::Processing`] and the caller spawns the one
//!   task that answers it) or queues the read behind the answer in flight.
//! - The answering task leaves `Processing` only through [`ReadQueue::next_or_idle`] (the next
//!   queued payload, or `Idle` when there is none) or [`ReadQueue::hold_for_more`] (the model
//!   said `wait_for_more`). So exactly one answer runs per connection at a time.
//!
//! What "the next payload" is depends on batching: with it on, everything waiting; off, the
//! oldest read on its own. Bytes held for `wait_for_more` are one message with whatever completes
//! it, so they are always taken whole.

use std::collections::VecDeque;

/// Where a connection's reads stand.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ReadState {
    /// Nothing in flight; the next read starts an answer.
    #[default]
    Idle,
    /// An answer is in flight; reads queue behind it.
    Processing,
    /// The model asked for more: the held bytes are the front of the next answer's payload.
    Accumulating,
}

/// What [`ReadQueue::admit`] decided about one read.
#[derive(Debug, PartialEq, Eq)]
pub enum Admitted {
    /// The read starts an answer, with this payload. The caller must run exactly one answering
    /// task for it.
    Start(Vec<u8>),
    /// The read is queued behind the answer in flight; this many bytes are now queued.
    Queued(usize),
}

/// What [`ReadQueue::hold_for_more`] decided.
#[derive(Debug, PartialEq, Eq)]
pub enum Held {
    /// Nothing arrived during the call: this many bytes are held, the connection is
    /// [`ReadState::Accumulating`], and the answering task ends. The next read joins them.
    Waiting(usize),
    /// Bytes arrived during the call — they are the "more" the model asked for. The connection
    /// stays `Processing` and the answering task goes round again with this payload.
    Resume(Vec<u8>),
}

impl Held {
    /// How many bytes the connection is now holding for the message, either way.
    pub fn len(&self) -> usize {
        match self {
            Held::Waiting(len) => *len,
            Held::Resume(payload) => payload.len(),
        }
    }

    /// Whether nothing is held at all.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// A connection's read state machine and the reads waiting behind its answer.
#[derive(Debug, Default)]
pub struct ReadQueue {
    state: ReadState,
    queued: Vec<u8>,
    /// Where each queued read ended, oldest first, summing to `queued.len()`. With batching off
    /// the next answer takes one read rather than the whole queue.
    chunks: VecDeque<usize>,
}

impl ReadQueue {
    /// A connection with nothing in flight.
    pub fn idle() -> Self {
        Self::default()
    }

    /// A connection whose connect event is being answered: reads queue behind it until the
    /// connect handler takes them with [`Self::next_or_idle`].
    pub fn answering() -> Self {
        Self {
            state: ReadState::Processing,
            ..Self::default()
        }
    }

    /// Where the connection stands.
    pub fn state(&self) -> ReadState {
        self.state
    }

    /// Whether an answer is in flight, so a read now would be queued.
    pub fn is_answering(&self) -> bool {
        self.state == ReadState::Processing
    }

    /// Bytes waiting: queued behind an answer, or held for `wait_for_more`.
    pub fn queued_len(&self) -> usize {
        self.queued.len()
    }

    /// Take one read, in the order the reader got it.
    ///
    /// Called by the reader itself, never from a task spawned per read, with the connection's
    /// lock held. An `Idle` or `Accumulating` connection moves to `Processing` and the read
    /// becomes (the end of) the payload of a new answer; a `Processing` one queues it. Bounding
    /// the queue is the caller's: [`Admitted::Queued`] carries the length to compare.
    pub fn admit(&mut self, data: &[u8], batching: bool) -> Admitted {
        if self.state != ReadState::Processing {
            // Bytes held for `wait_for_more` are one message with whatever completes it, so
            // they are always taken whole; otherwise batching decides.
            let take_all = batching || self.state == ReadState::Accumulating;
            self.state = ReadState::Processing;
            self.push(data);
            return Admitted::Start(self.take_next(take_all));
        }
        self.push(data);
        Admitted::Queued(self.queued.len())
    }

    /// The answering task's next payload, or `None` with the connection moved to `Idle` when
    /// nothing is queued — one decision, so a read cannot be queued in between and stranded.
    ///
    /// Taken, not peeked: a payload left in place is answered again on every pass.
    pub fn next_or_idle(&mut self, batching: bool) -> Option<Vec<u8>> {
        let next = self.take_next(batching);
        if next.is_empty() {
            self.state = ReadState::Idle;
            None
        } else {
            Some(next)
        }
    }

    /// Everything waiting, as one payload, leaving the state alone. For a framed protocol whose
    /// answering task still holds unparsed bytes and only needs what has arrived since.
    pub fn take_all(&mut self) -> Vec<u8> {
        self.take_next(true)
    }

    /// The model answered `fragment` with `wait_for_more`: these bytes are an incomplete
    /// message, so they go back to the *head* of the queue, ahead of whatever arrived during
    /// the call, as one payload.
    ///
    /// If something did arrive during the call it is the "more" the model asked for, and parking
    /// it until the next read would strand a peer that has already sent its whole message — so
    /// the joined payload is handed straight back and the connection stays `Processing`. Decided
    /// in one step, so the reader can never find the connection `Accumulating` in between and
    /// start a second answer.
    pub fn hold_for_more(&mut self, fragment: &[u8]) -> Held {
        let arrived_during_call = !self.queued.is_empty();
        let mut merged = Vec::with_capacity(fragment.len() + self.queued.len());
        merged.extend_from_slice(fragment);
        merged.append(&mut self.queued);
        self.chunks.clear();
        if arrived_during_call {
            self.state = ReadState::Processing;
            return Held::Resume(merged);
        }
        if !merged.is_empty() {
            self.chunks.push_back(merged.len());
        }
        self.queued = merged;
        self.state = ReadState::Accumulating;
        Held::Waiting(self.queued.len())
    }

    /// Give up on the answer in flight without closing the connection: `Idle`, with anything
    /// queued left for the next read to start with. For a protocol that has lost its framing
    /// and has nothing to answer.
    pub fn abandon(&mut self) {
        self.state = ReadState::Idle;
    }

    fn push(&mut self, data: &[u8]) {
        if !data.is_empty() {
            self.queued.extend_from_slice(data);
            self.chunks.push_back(data.len());
        }
    }

    /// The whole queue when `take_all`, else the oldest read.
    fn take_next(&mut self, take_all: bool) -> Vec<u8> {
        if take_all || self.chunks.len() <= 1 {
            self.chunks.clear();
            return std::mem::take(&mut self.queued);
        }
        let n = self
            .chunks
            .pop_front()
            .unwrap_or(self.queued.len())
            .min(self.queued.len());
        self.queued.drain(..n).collect()
    }
}

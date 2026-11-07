//! A copy of each prepared-statement command, taken beneath `opensrv-mysql`.
//!
//! `opensrv-mysql` reads `COM_STMT_EXECUTE` itself and hands `on_execute` a `ParamParser` whose
//! fields are private and whose only public reader panics on malformed input (see
//! [`super::stmt_params`]). So the bytes are taken where the crate cannot hide them: in the
//! reader the crate reads from — the same generic-reader seam `packet_limit` uses.
//! [`CommandTapReader`] frames the stream alongside the crate, and for three commands queues
//! what the shim will need when `on_execute` runs:
//!
//! - `COM_STMT_EXECUTE` (`0x17`): the whole payload after the command byte, for
//!   [`super::stmt_params::parse_execute`].
//! - `COM_STMT_SEND_LONG_DATA` (`0x18`): statement, parameter, and a **bounded prefix** of the
//!   chunk with its length — long data is how a client sends a value larger than a packet, so
//!   only what the model will be shown is kept.
//! - `COM_STMT_RESET` (`0x1A`): the statement whose long data is discarded. The crate discards
//!   its own copy of the long data; this tells the shim to discard the prefix it keeps for the
//!   model.
//!
//! # Pairing a capture with the `on_execute` it belongs to
//!
//! The crate processes packets strictly in order and calls `on_execute` once per execute it
//! parses, so a FIFO queue pairs them. Two rules keep that true:
//!
//! - **Only commands are captured.** A command is a packet whose sequence id is `0`; every
//!   packet of the connection phase (the handshake response is sequence `1`) is skipped, so a
//!   handshake that happens to begin `0x17` is never mistaken for an execute.
//! - **Only what the crate will parse is captured.** Its parser (`commands.rs`, `execute` and
//!   `send_long_data`) needs at least 9 and 6 bytes after the command byte; a shorter packet
//!   fails to parse there and never reaches the shim (the crate answers a short execute ERR
//!   1835 itself, and a short long-data chunk not at all) — so it is not queued.
//!
//! The shim then checks the statement id of what it pops against the one the crate gave it,
//! and refuses rather than decode a packet that is not the one being executed.
//!
//! # Reads are passed through as they come
//!
//! The tap neither splits nor joins reads: it observes whatever the reader beneath it returns.
//! A read may end mid-packet or hold several packets, and the framing above follows either.
//! The crate's own reader copes with both because NetGet builds `netget-opensrv-mysql`
//! (github.com/netget-net/opensrv), whose `PacketReader::next_async` no longer parses the first
//! of two packets in one read out of a buffer it has just freed — upstream 0.7.0 does, which
//! drew a stray OK for each of two pipelined `COM_STMT_SEND_LONG_DATA` chunks (as `mysql_async`
//! sends them) and left every reply after it one behind.
//! `stmt_params_test.rs::pipelined_commands_through_the_tap_each_get_their_own_reply` drives
//! the crate through the tap with exactly that burst in one write;
//! `tests/vendored_opensrv_patch_test.rs` drives the bare crate.
//!
//! # Bounds
//!
//! An execute is copied whole, so its size is bounded by `packet_limit::MAX_PACKET_BYTES`,
//! which trips beneath this reader before the bytes reach it. The queue is bounded in entries
//! ([`MAX_QUEUED`]); the crate only reads ahead of what it is processing by one read's worth,
//! so a client cannot normally get near it, and one that does has every later execute refused
//! (the queue stops capturing and says so) rather than paired with the wrong packet.

use std::collections::{HashMap, HashSet, VecDeque};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{ready, Context, Poll};

use tokio::io::{AsyncRead, ReadBuf};

use super::packet_limit::FULL_PACKET_PAYLOAD;
use super::stmt_params::MAX_RENDERED_VALUE_BYTES;

const COM_STMT_EXECUTE: u8 = 0x17;
const COM_STMT_SEND_LONG_DATA: u8 = 0x18;
const COM_STMT_CLOSE: u8 = 0x19;
const COM_STMT_RESET: u8 = 0x1A;

/// Bytes after the command byte that `opensrv-mysql`'s parser needs before it calls the shim.
const MIN_EXECUTE_BODY: usize = 4 + 1 + 4;
const MIN_LONG_DATA_BODY: usize = 4 + 2;
const MIN_RESET_BODY: usize = 4;

/// Most captured commands held at once.
pub const MAX_QUEUED: usize = 4096;

/// One captured command, in wire order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Captured {
    /// A `COM_STMT_EXECUTE` payload, everything after the `0x17`.
    Execute(Vec<u8>),
    /// One `COM_STMT_SEND_LONG_DATA` chunk.
    LongData {
        stmt_id: u32,
        param: u16,
        /// At most [`MAX_RENDERED_VALUE_BYTES`] + 4 bytes of the chunk.
        prefix: Vec<u8>,
        /// The chunk's full length.
        len: u64,
    },
    /// A `COM_STMT_RESET`.
    Reset { stmt_id: u32 },
    /// [`LongDataGate`] withheld a `COM_STMT_SEND_LONG_DATA` chunk for this statement from the
    /// crate because it would have crossed a long-data bound. The statement's next execute is
    /// refused.
    LongDataRefused { stmt_id: u32 },
}

/// The queue shared between the reader and the shim.
#[derive(Debug, Default)]
pub struct CommandTap {
    queue: Mutex<VecDeque<Captured>>,
    overflowed: AtomicBool,
}

/// What the shim gets back for one `on_execute`.
#[derive(Debug, Default)]
pub struct ExecuteCapture {
    /// Long-data chunks and resets that arrived before this execute, in order, to be applied
    /// to the statements they name before decoding.
    pub preceding: Vec<Captured>,
    /// The execute's payload, or `None` when none was captured for this statement id.
    pub payload: Option<Vec<u8>>,
    /// Executes captured ahead of this one whose statement id did not match — a desync that
    /// should never happen, reported so the shim can log it.
    pub discarded: usize,
    /// Whether the queue ever overflowed. Once it has, captures are incomplete and the shim
    /// refuses every execute rather than risk a wrong pairing.
    pub overflowed: bool,
}

impl CommandTap {
    fn push(&self, item: Captured) {
        if self.overflowed.load(Ordering::SeqCst) {
            return;
        }
        let mut q = self.queue.lock().unwrap_or_else(|p| p.into_inner());
        if q.len() >= MAX_QUEUED {
            q.clear();
            self.overflowed.store(true, Ordering::SeqCst);
            return;
        }
        q.push_back(item);
    }

    /// Take everything up to and including the next execute of `stmt_id`.
    pub fn take_execute(&self, stmt_id: u32) -> ExecuteCapture {
        let mut out = ExecuteCapture {
            overflowed: self.overflowed.load(Ordering::SeqCst),
            ..Default::default()
        };
        let mut q = self.queue.lock().unwrap_or_else(|p| p.into_inner());
        while let Some(item) = q.pop_front() {
            match item {
                Captured::Execute(payload) => {
                    let id = payload
                        .get(..4)
                        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]));
                    if id == Some(stmt_id) {
                        out.payload = Some(payload);
                        break;
                    }
                    out.discarded += 1;
                }
                other => out.preceding.push(other),
            }
        }
        out
    }

    /// Take everything queued, in order (for tests).
    pub fn drain(&self) -> Vec<Captured> {
        self.queue
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .drain(..)
            .collect()
    }

    /// How many commands are queued (for tests).
    pub fn queued(&self) -> usize {
        self.queue.lock().unwrap_or_else(|p| p.into_inner()).len()
    }
}

/// What the reader is doing with the logical packet in progress.
#[derive(Debug)]
enum Capture {
    /// Not a command, or not one of the three; pass through.
    Skip,
    /// A sequence-0 packet whose first payload byte has not arrived yet.
    Undecided,
    Execute(Vec<u8>),
    LongData {
        head: Vec<u8>,
        prefix: Vec<u8>,
        len: u64,
    },
    Reset(Vec<u8>),
}

/// An `AsyncRead` that passes every byte through unchanged and queues copies of the
/// prepared-statement commands in it. See the module docs.
pub struct CommandTapReader<R> {
    inner: R,
    tap: Arc<CommandTap>,
    header: [u8; 4],
    header_len: usize,
    payload_remaining: usize,
    /// Whether the current fragment is a full `FULL_PACKET_PAYLOAD` one, so the logical packet
    /// continues in the next.
    continues: bool,
    /// Whether the next header starts a new logical packet.
    at_packet_start: bool,
    capture: Capture,
}

/// Largest single read [`LongDataGate`] makes of a packet's payload.
const MAX_READ_CHUNK: usize = 64 * 1024;

impl<R> CommandTapReader<R> {
    pub fn new(inner: R, tap: Arc<CommandTap>) -> Self {
        Self {
            inner,
            tap,
            header: [0u8; 4],
            header_len: 0,
            payload_remaining: 0,
            continues: false,
            at_packet_start: true,
            capture: Capture::Skip,
        }
    }

    pub fn into_inner(self) -> R {
        self.inner
    }

    fn feed_payload(&mut self, mut bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        if matches!(self.capture, Capture::Undecided) {
            let (first, rest) = (bytes[0], &bytes[1..]);
            self.capture = match first {
                COM_STMT_EXECUTE => Capture::Execute(Vec::new()),
                COM_STMT_SEND_LONG_DATA => Capture::LongData {
                    head: Vec::with_capacity(MIN_LONG_DATA_BODY),
                    prefix: Vec::new(),
                    len: 0,
                },
                COM_STMT_RESET => Capture::Reset(Vec::new()),
                _ => Capture::Skip,
            };
            bytes = rest;
        }
        match &mut self.capture {
            Capture::Execute(buf) => buf.extend_from_slice(bytes),
            Capture::Reset(buf) => {
                let keep = MIN_RESET_BODY.saturating_sub(buf.len()).min(bytes.len());
                buf.extend_from_slice(&bytes[..keep]);
            }
            Capture::LongData { head, prefix, len } => {
                let h = MIN_LONG_DATA_BODY
                    .saturating_sub(head.len())
                    .min(bytes.len());
                head.extend_from_slice(&bytes[..h]);
                let data = &bytes[h..];
                let keep = (MAX_RENDERED_VALUE_BYTES + 4)
                    .saturating_sub(prefix.len())
                    .min(data.len());
                prefix.extend_from_slice(&data[..keep]);
                *len = len.saturating_add(data.len() as u64);
            }
            Capture::Skip | Capture::Undecided => {}
        }
    }

    /// The logical packet ended: queue what was captured, if the crate will act on it.
    fn finish_packet(&mut self) {
        match std::mem::replace(&mut self.capture, Capture::Skip) {
            Capture::Execute(buf) if buf.len() >= MIN_EXECUTE_BODY => {
                self.tap.push(Captured::Execute(buf));
            }
            Capture::LongData { head, prefix, len } if head.len() >= MIN_LONG_DATA_BODY => {
                self.tap.push(Captured::LongData {
                    stmt_id: u32::from_le_bytes([head[0], head[1], head[2], head[3]]),
                    param: u16::from_le_bytes([head[4], head[5]]),
                    prefix,
                    len,
                });
            }
            Capture::Reset(buf) if buf.len() >= MIN_RESET_BODY => {
                self.tap.push(Captured::Reset {
                    stmt_id: u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]),
                });
            }
            _ => {}
        }
        self.at_packet_start = true;
    }

    /// Track one read's bytes through the framing.
    fn observe(&mut self, bytes: &[u8]) {
        let mut i = 0usize;
        while i < bytes.len() {
            if self.payload_remaining > 0 {
                let take = self.payload_remaining.min(bytes.len() - i);
                self.feed_payload(&bytes[i..i + take]);
                self.payload_remaining -= take;
                i += take;
                if self.payload_remaining == 0 && !self.continues {
                    self.finish_packet();
                }
                continue;
            }

            let need = 4 - self.header_len;
            let take = need.min(bytes.len() - i);
            self.header[self.header_len..self.header_len + take]
                .copy_from_slice(&bytes[i..i + take]);
            self.header_len += take;
            i += take;
            if self.header_len < 4 {
                break;
            }
            self.header_len = 0;

            let declared =
                u32::from_le_bytes([self.header[0], self.header[1], self.header[2], 0]) as usize;
            let sequence = self.header[3];
            if self.at_packet_start {
                self.at_packet_start = false;
                self.capture = if sequence == 0 {
                    Capture::Undecided
                } else {
                    Capture::Skip
                };
            }
            self.continues = declared == FULL_PACKET_PAYLOAD;
            self.payload_remaining = declared;
            if declared == 0 && !self.continues {
                self.finish_packet();
            }
        }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for CommandTapReader<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let res = Pin::new(&mut this.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = res {
            this.observe(&buf.filled()[before..]);
        }
        res
    }
}

// ---------------------------------------------------------------------------------------------
// The long-data bound
// ---------------------------------------------------------------------------------------------

/// Most long data one statement may accumulate between executes: `max_allowed_packet`.
///
/// `mysqld` refuses a parameter whose long data passes `max_allowed_packet`, at the next
/// execute. This server holds the same number per **statement** (across all its parameters),
/// which is stricter, and it is the number the server publishes for that variable.
pub const LONG_DATA_PER_STATEMENT: u64 = super::packet_limit::MAX_PACKET_BYTES as u64;

/// Most long data one connection may accumulate across all its statements: two statements'
/// worth. Without it a peer could hold [`LONG_DATA_PER_STATEMENT`] in each of the 4096
/// statements a connection may prepare.
pub const LONG_DATA_PER_CONNECTION: u64 = 2 * LONG_DATA_PER_STATEMENT;

/// Bytes of a packet's payload the gate reads before deciding: command byte, statement id,
/// parameter index.
const GATE_PEEK: usize = 7;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GateStage {
    /// Collecting the next packet header.
    Header,
    /// Collecting the first bytes of a command's payload, holding the header back.
    Peek { need: usize },
    /// Passing (or discarding) the rest of the current packet's payload.
    Pass,
}

/// A reader beneath [`CommandTapReader`] that withholds `COM_STMT_SEND_LONG_DATA` chunks past
/// the long-data bounds, so `opensrv-mysql` never stores them.
///
/// # Why it has to be here
///
/// `opensrv-mysql` 0.7.0 appends every chunk to the statement's buffer with no limit
/// (`src/lib.rs:663-678`: `long_data.entry(param).or_insert_with(Vec::new).extend(data)`) and
/// keeps it until that statement is executed or closed. Each chunk is bounded by the packet
/// limit, but their number is not, so a peer that sends chunks and never executes makes the
/// process hold as much as it cares to send. The crate offers no hook, so the decision is
/// taken where the bytes still are: each long-data packet is looked at — its header and
/// first [`GATE_PEEK`] payload bytes held back — and either handed up whole or read and
/// dropped whole. A command with no reply can be dropped without desynchronising anything;
/// the refusal is reported at the statement's next execute, which is where `mysqld` reports
/// it too (ERR 1105, `Parameter of prepared statement which is set through
/// mysql_send_long_data() is longer than 'max_allowed_packet' bytes`).
///
/// The count for a statement is released when its execute or `COM_STMT_CLOSE` passes.
/// `COM_STMT_RESET` releases nothing, although the crate discards the statement's long data on
/// it too: the count, and a refusal already queued for the statement, stay until its next
/// execute or close. That errs towards refusing — a client that resets and re-sends can be
/// refused sooner than `mysqld` would refuse it — and never towards holding more than the
/// bounds.
///
/// A chunk is decided by its first fragment. One that chains past 16 MiB is admitted on that
/// fragment's length and counted as it passes, so the bound can be overshot by at most one
/// packet — itself bounded by `packet_limit::MAX_PACKET_BYTES`, beneath this reader.
pub struct LongDataGate<R> {
    inner: R,
    tap: Arc<CommandTap>,
    per_statement: u64,
    per_connection: u64,
    /// Long-data bytes the crate holds, by statement.
    held_by_statement: HashMap<u32, u64>,
    held_total: u64,
    /// Statements already refused since their last execute, so a flood of oversized chunks
    /// queues one refusal, not one per chunk.
    refused: HashSet<u32>,

    stage: GateStage,
    header: [u8; 4],
    header_len: usize,
    declared: usize,
    peek: Vec<u8>,
    /// Header and peeked bytes decided on and owed to the caller.
    owed: Vec<u8>,
    owed_pos: usize,
    payload_remaining: usize,
    /// The current physical packet is a full fragment, so the logical packet continues.
    continues: bool,
    /// The next header continues a logical packet rather than starting one.
    in_logical: bool,
    /// The logical packet in progress is being discarded.
    dropping: bool,
    /// The logical packet in progress is admitted long data for this statement.
    counting: Option<u32>,
    scratch: Vec<u8>,
}

impl<R> LongDataGate<R> {
    /// Wrap `inner` with the production bounds.
    pub fn new(inner: R, tap: Arc<CommandTap>) -> Self {
        Self::with_limits(
            inner,
            tap,
            LONG_DATA_PER_STATEMENT,
            LONG_DATA_PER_CONNECTION,
        )
    }

    /// Wrap `inner` with arbitrary bounds, so a test can reach them without moving 64 MiB.
    /// Nothing in `src/` passes anything but the production values.
    pub fn with_limits(
        inner: R,
        tap: Arc<CommandTap>,
        per_statement: u64,
        per_connection: u64,
    ) -> Self {
        Self {
            inner,
            tap,
            per_statement,
            per_connection,
            held_by_statement: HashMap::new(),
            held_total: 0,
            refused: HashSet::new(),
            stage: GateStage::Header,
            header: [0; 4],
            header_len: 0,
            declared: 0,
            peek: Vec::with_capacity(GATE_PEEK),
            owed: Vec::with_capacity(4 + GATE_PEEK),
            owed_pos: 0,
            payload_remaining: 0,
            continues: false,
            in_logical: false,
            dropping: false,
            counting: None,
            scratch: Vec::new(),
        }
    }

    pub fn into_inner(self) -> R {
        self.inner
    }

    fn release(&mut self, stmt_id: u32) {
        if let Some(n) = self.held_by_statement.remove(&stmt_id) {
            self.held_total = self.held_total.saturating_sub(n);
        }
        self.refused.remove(&stmt_id);
    }

    fn count(&mut self, stmt_id: u32, n: u64) {
        let e = self.held_by_statement.entry(stmt_id).or_insert(0);
        *e = e.saturating_add(n);
        self.held_total = self.held_total.saturating_add(n);
    }

    /// Decide the logical packet whose header and first payload bytes are in hand.
    fn decide(&mut self) {
        let p = self.peek.clone();
        let p = p.as_slice();
        let id = |p: &[u8]| u32::from_le_bytes([p[1], p[2], p[3], p[4]]);
        self.dropping = false;
        self.counting = None;
        match p.first() {
            Some(&COM_STMT_SEND_LONG_DATA) if p.len() >= GATE_PEEK => {
                let stmt_id = id(p);
                let data = (self.declared - GATE_PEEK) as u64;
                let held = self.held_by_statement.get(&stmt_id).copied().unwrap_or(0);
                if self.refused.contains(&stmt_id)
                    || held.saturating_add(data) > self.per_statement
                    || self.held_total.saturating_add(data) > self.per_connection
                {
                    self.dropping = true;
                    if self.refused.insert(stmt_id) {
                        self.tap.push(Captured::LongDataRefused { stmt_id });
                    }
                } else {
                    self.count(stmt_id, data);
                    self.counting = Some(stmt_id);
                }
            }
            Some(&COM_STMT_EXECUTE) if self.declared > MIN_EXECUTE_BODY && p.len() >= 5 => {
                self.release(id(p));
            }
            Some(&COM_STMT_CLOSE) if self.declared > MIN_RESET_BODY && p.len() >= 5 => {
                self.release(id(p));
            }
            _ => {}
        }
    }

    /// The header is complete: set up the packet it announces.
    fn on_header(&mut self) {
        self.header_len = 0;
        self.declared =
            u32::from_le_bytes([self.header[0], self.header[1], self.header[2], 0]) as usize;
        let sequence = self.header[3];
        self.continues = self.declared == FULL_PACKET_PAYLOAD;
        self.payload_remaining = self.declared;
        if self.in_logical {
            // A continuation fragment inherits its logical packet's decision.
            if !self.dropping {
                self.owed.extend_from_slice(&self.header);
                if let Some(stmt_id) = self.counting {
                    self.count(stmt_id, self.declared as u64);
                }
            }
            self.stage = GateStage::Pass;
        } else if sequence == 0 && self.declared > 0 {
            self.peek.clear();
            self.stage = GateStage::Peek {
                need: GATE_PEEK.min(self.declared),
            };
        } else {
            self.dropping = false;
            self.counting = None;
            self.owed.extend_from_slice(&self.header);
            self.stage = GateStage::Pass;
        }
    }
}

impl<R: AsyncRead + Unpin> LongDataGate<R> {
    /// Read up to `len` bytes from `inner` into `scratch`; `Ok(0)` is end of stream.
    fn read_inner(&mut self, cx: &mut Context<'_>, len: usize) -> Poll<std::io::Result<usize>> {
        if self.scratch.len() < len {
            self.scratch.resize(len, 0);
        }
        let mut rb = ReadBuf::new(&mut self.scratch[..len]);
        match Pin::new(&mut self.inner).poll_read(cx, &mut rb) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(rb.filled().len())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for LongDataGate<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            if this.owed_pos < this.owed.len() {
                let n = (this.owed.len() - this.owed_pos).min(buf.remaining());
                buf.put_slice(&this.owed[this.owed_pos..this.owed_pos + n]);
                this.owed_pos += n;
                if this.owed_pos == this.owed.len() {
                    this.owed.clear();
                    this.owed_pos = 0;
                }
                return Poll::Ready(Ok(()));
            }
            match this.stage {
                GateStage::Header => {
                    let want = 4 - this.header_len;
                    let n = ready!(this.read_inner(cx, want))?;
                    if n == 0 {
                        // End of stream mid-header: hand up what there is and let the crate
                        // report the truncation.
                        let partial = this.header[..this.header_len].to_vec();
                        this.header_len = 0;
                        if partial.is_empty() {
                            return Poll::Ready(Ok(()));
                        }
                        this.owed.extend_from_slice(&partial);
                        continue;
                    }
                    let (start, end) = (this.header_len, this.header_len + n);
                    this.header[start..end].copy_from_slice(&this.scratch[..n]);
                    this.header_len = end;
                    if this.header_len == 4 {
                        this.on_header();
                    }
                }
                GateStage::Peek { need } => {
                    let want = need - this.peek.len();
                    let n = ready!(this.read_inner(cx, want))?;
                    if n == 0 || this.peek.len() + n == need {
                        this.peek.extend_from_slice(&this.scratch[..n]);
                        this.payload_remaining -= this.peek.len();
                        if n == 0 {
                            // Truncated: pass on what arrived, undecided.
                            this.dropping = false;
                            this.counting = None;
                        } else {
                            this.decide();
                        }
                        if !this.dropping {
                            this.owed.extend_from_slice(&this.header);
                            this.owed.extend_from_slice(&this.peek);
                        }
                        this.stage = GateStage::Pass;
                        if n == 0 && this.owed.is_empty() {
                            return Poll::Ready(Ok(()));
                        }
                    } else {
                        this.peek.extend_from_slice(&this.scratch[..n]);
                    }
                }
                GateStage::Pass => {
                    if this.payload_remaining == 0 {
                        this.in_logical = this.continues;
                        if !this.continues {
                            this.dropping = false;
                            this.counting = None;
                        }
                        this.stage = GateStage::Header;
                        continue;
                    }
                    let want = this.payload_remaining.min(MAX_READ_CHUNK);
                    if this.dropping {
                        let n = ready!(this.read_inner(cx, want))?;
                        if n == 0 {
                            return Poll::Ready(Ok(()));
                        }
                        this.payload_remaining -= n;
                    } else {
                        let n = ready!(this.read_inner(cx, want.min(buf.remaining())))?;
                        if n > 0 {
                            buf.put_slice(&this.scratch[..n]);
                            this.payload_remaining -= n;
                        }
                        return Poll::Ready(Ok(()));
                    }
                }
            }
        }
    }
}

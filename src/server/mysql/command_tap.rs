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
//! - `COM_STMT_RESET` (`0x1A`): the statement whose long data is discarded. `opensrv-mysql`
//!   does not parse this command at all (it answers OK), so its effect on long data is ours.
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
//!   fails to parse there, is answered OK, and never reaches the shim — so it is not queued.
//!
//! The shim then checks the statement id of what it pops against the one the crate gave it,
//! and refuses rather than decode a packet that is not the one being executed.
//!
//! # One packet per read
//!
//! The reader also hands the crate **at most the rest of one packet per read** — the header,
//! then the payload — and this is a memory-safety fix, not a convenience.
//! `opensrv-mysql` 0.7.0's `PacketReader::next_async` (`src/packet_reader.rs:131-141`) builds
//! the slice it parses from `self.bytes` with `slice::from_raw_parts`, and when that read
//! held more than one packet it runs `self.bytes = rest.to_vec()` before returning the parsed
//! packet. The assignment frees the buffer the returned packet still points into, so the
//! first of two pipelined commands is parsed from freed memory. Measured here: a client
//! sending two `COM_STMT_SEND_LONG_DATA` chunks back to back (as `mysql_async` does) got a
//! stray OK packet — the allocator had overwritten the freed bytes, the first chunk no longer
//! parsed, and the crate answered its parse failure with OK — which desynchronised every
//! reply after it. `COM_STMT_CLOSE` followed by the next command, which a client's statement
//! cache does routinely, is the same shape. With no read crossing a packet boundary the
//! remainder is always empty when a packet completes and that branch never runs.
//! `stmt_params_test.rs::pipelined_commands_reach_opensrv_one_packet_per_read` drives the
//! crate directly to show it.
//!
//! # Bounds
//!
//! An execute is copied whole, so its size is bounded by `packet_limit::MAX_PACKET_BYTES`,
//! which trips beneath this reader before the bytes reach it. The queue is bounded in entries
//! ([`MAX_QUEUED`]); the crate only reads ahead of what it is processing by one read's worth,
//! so a client cannot normally get near it, and one that does has every later execute refused
//! (the queue stops capturing and says so) rather than paired with the wrong packet.

use std::collections::VecDeque;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, ReadBuf};

use super::packet_limit::FULL_PACKET_PAYLOAD;
use super::stmt_params::MAX_RENDERED_VALUE_BYTES;

const COM_STMT_EXECUTE: u8 = 0x17;
const COM_STMT_SEND_LONG_DATA: u8 = 0x18;
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
    /// Where each read lands before it is handed up; at most [`MAX_READ_CHUNK`] bytes.
    scratch: Vec<u8>,
}

/// Largest single read handed to `opensrv-mysql`.
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
            scratch: Vec::new(),
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
        // Never more than the rest of the current packet (its header, or its payload): see
        // "One packet per read" in the module docs.
        let want = if this.payload_remaining > 0 {
            this.payload_remaining
        } else {
            4 - this.header_len
        };
        let limit = want.min(buf.remaining()).min(MAX_READ_CHUNK);
        if limit == 0 {
            return Pin::new(&mut this.inner).poll_read(cx, buf);
        }
        // Taken out of `self` for the duration, so `observe` can borrow `self` mutably while
        // the bytes it reads are still in hand.
        let mut scratch = std::mem::take(&mut this.scratch);
        if scratch.len() < limit {
            scratch.resize(limit, 0);
        }
        let mut sub = ReadBuf::new(&mut scratch[..limit]);
        let res = Pin::new(&mut this.inner).poll_read(cx, &mut sub);
        let n = sub.filled().len();
        if let Poll::Ready(Ok(())) = res {
            if n > 0 {
                buf.put_slice(&scratch[..n]);
                this.observe(&scratch[..n]);
            }
        }
        this.scratch = scratch;
        res
    }
}

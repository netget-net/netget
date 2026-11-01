//! A bound on the largest MySQL packet a stranger can make this server buffer.
//!
//! # The defect
//!
//! `opensrv-mysql` 0.7.0 has no maximum-packet check anywhere. Its `PacketReader::next_async`
//! grows `self.bytes` by `max(1 MiB, len * 2)` until a whole *logical* packet has been
//! buffered, and `packet()` assembles that logical packet with
//! `nom::multi::fold_many0(fullpacket, …)` — an unbounded fold over 16 MiB continuation
//! packets, each of which extends a `Vec`. So the peer decides how much this process
//! allocates, and it decides before authentication and before any model call: the very first
//! thing a client sends is its handshake response, read through exactly this path.
//!
//! Worse, the server *publishes* a bound. `opensrv-mysql` answers
//! `SELECT @@max_allowed_packet` itself, with `67108864`, without ever consulting the shim —
//! and never compares an incoming packet against it. A published bound that is not enforced is
//! worse than no bound: a client sizes its writes by the number it was given.
//!
//! # The bound
//!
//! [`MAX_PACKET_BYTES`] is that same 67108864, so the number the server publishes and the
//! number it enforces are one number. The refusal is MySQL's own: error **1153
//! `ER_NET_PACKET_TOO_LARGE`**, SQLSTATE `08S01`, which is precisely what a real MySQL server
//! sends when `max_allowed_packet` is exceeded, carrying the message a real server carries.
//!
//! # Where it is enforced
//!
//! Here, in a reader that sits *beneath* `opensrv-mysql` and decides each packet from the
//! length the peer **declared** in its 4-byte header, before that packet's payload is read and
//! therefore before anything is allocated for it. Bounding what has already arrived would be
//! the NATS `HPUB` mistake — there the limit was applied to `total − header`, so `header ==
//! total` passed every check and thirty bytes on the wire bought a 4 GB buffer.
//!
//! For a chained packet the accumulation is what is bounded, not each fragment: a fragment
//! whose declared length is exactly [`FULL_PACKET_PAYLOAD`] means "more follows", so the
//! logical packet's declared size is the running sum, and it is that sum which is compared
//! against the bound at every header.

use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, ReadBuf};

/// Largest logical MySQL packet this server will read, in payload bytes.
///
/// Exactly the value `opensrv-mysql` answers `SELECT @@max_allowed_packet` with, and it is
/// chosen for that reason rather than for being a round number: the point of this bound is
/// that the server stops publishing a ceiling it does not apply. Enforcing anything *smaller*
/// than the published value would leave the same mismatch pointing the other way — a client
/// that sized a write by `@@max_allowed_packet` would be refused at a length the server had
/// told it was acceptable.
pub const MAX_PACKET_BYTES: usize = 67_108_864;

/// Payload length that means "this packet is a fragment; the next one continues it".
///
/// 2^24 − 1, the largest value the 3-byte little-endian length header can carry. A packet
/// declaring exactly this is never the end of a logical packet — that is the protocol's own
/// framing rule, and it is the construct that makes `fold_many0` unbounded.
pub const FULL_PACKET_PAYLOAD: usize = 0x00FF_FFFF;

/// What the limiting reader tells the connection task after it has refused.
///
/// A reader can only return an `io::Error`, and an `io::Error` is indistinguishable from a
/// read timeout or a reset by the time `run_on` has turned it into its own error type. The
/// connection task needs three things to answer in MySQL's vocabulary — that the bound was the
/// reason, the sequence id the refusal must carry, and the size to log — so they are recorded
/// here rather than parsed back out of an error string.
#[derive(Debug, Default)]
pub struct PacketLimitTrip {
    tripped: AtomicBool,
    /// Sequence id of the header that crossed the bound. The ERR packet answering it must
    /// carry this plus one, or a conforming client discards the reply as out of order.
    sequence: AtomicU8,
    /// Declared size of the logical packet at the moment it crossed, for the log line.
    declared: AtomicUsize,
    /// Which rule refused: [`Refusal`] as a `u8`, so the trip stays lock-free.
    reason: AtomicU8,
}

/// Why the reader refused a packet header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The logical packet's declared size crossed [`MAX_PACKET_BYTES`].
    TooLarge,
    /// A sequence id `opensrv-mysql` 0.7.0 would panic on — see [`PacketLimitReader`].
    OutOfOrder,
}

impl PacketLimitTrip {
    /// Whether the bound refused a packet on this connection.
    pub fn tripped(&self) -> bool {
        self.tripped.load(Ordering::SeqCst)
    }

    /// Which rule refused. Meaningful only once [`Self::tripped`] is true.
    pub fn refusal(&self) -> Refusal {
        if self.reason.load(Ordering::SeqCst) == Refusal::OutOfOrder as u8 {
            Refusal::OutOfOrder
        } else {
            Refusal::TooLarge
        }
    }

    /// The ERR packet that answers the refusal, carrying [`Self::reply_sequence`].
    pub fn refusal_packet(&self) -> Vec<u8> {
        match self.refusal() {
            Refusal::TooLarge => packet_too_large_err(self.reply_sequence()),
            Refusal::OutOfOrder => packets_out_of_order_err(self.reply_sequence()),
        }
    }

    /// Sequence id the refusal must carry: one past the header that crossed the bound.
    pub fn reply_sequence(&self) -> u8 {
        self.sequence.load(Ordering::SeqCst).wrapping_add(1)
    }

    /// Declared size of the logical packet that crossed the bound.
    pub fn declared_bytes(&self) -> usize {
        self.declared.load(Ordering::SeqCst)
    }

    fn record(&self, refusal: Refusal, sequence: u8, declared: usize) {
        self.sequence.store(sequence, Ordering::SeqCst);
        self.declared.store(declared, Ordering::SeqCst);
        self.reason.store(refusal as u8, Ordering::SeqCst);
        self.tripped.store(true, Ordering::SeqCst);
    }
}

/// An `AsyncRead` that refuses a MySQL packet larger than its bound, before the payload is read.
///
/// It buffers nothing of its own beyond a four-byte header: bytes are handed straight through
/// to the caller and the framing is tracked alongside them. That is what makes it safe to put
/// beneath a crate that does its own buffering — the decision is taken on the header, so the
/// crate underneath never sees the payload it would have allocated for.
///
/// # Sequence ids
///
/// The same header carries the one other number `opensrv-mysql` 0.7.0 trusts until it panics:
///
/// - Every packet it reads is answered with `writer.set_seq(seq + 1)` on the client's `u8`
///   sequence id (`lib.rs:389`, `:502`, `:563`). A client sending sequence id `0xFF` overflows
///   that addition, which is a panic wherever overflow checks are on — every debug and test
///   build. Nothing legitimate sends it: a client's packets in one exchange start at 0 (a
///   command) or 1 (the handshake response) and a chain long enough to reach 255 would be
///   4 GiB, sixty-four times [`MAX_PACKET_BYTES`].
/// - A chained packet is reassembled by `packet()` with `assert_eq!(nseq, seq + 1)` between
///   fragments and `assert_eq!(last.0, full.0 + 1)` before the final one
///   (`packet_reader.rs:252`, `:266`). A peer that numbers its fragments any other way panics
///   the connection task — before authentication, since the handshake response is read the
///   same way.
///
/// Both are refused here, from the header, with [`Refusal::OutOfOrder`]: MySQL's own 1156
/// `ER_NET_PACKETS_OUT_OF_ORDER` is what the connection task then answers.
pub struct PacketLimitReader<R> {
    inner: R,
    limit: usize,
    trip: Arc<PacketLimitTrip>,
    /// Bytes of the current 4-byte packet header seen so far.
    header: [u8; 4],
    header_len: usize,
    /// Payload bytes still to pass through before the next header begins.
    payload_remaining: usize,
    /// Declared payload bytes accumulated so far for the logical packet being assembled.
    /// Non-zero only while a chain of [`FULL_PACKET_PAYLOAD`] fragments is in progress.
    logical_declared: usize,
    /// Sequence id of the last fragment while a chain is in progress; the next header must
    /// carry this plus one.
    chain_sequence: Option<u8>,
}

impl<R> PacketLimitReader<R> {
    /// Wrap `inner` with the production bound.
    pub fn new(inner: R, trip: Arc<PacketLimitTrip>) -> Self {
        Self::with_limit(inner, MAX_PACKET_BYTES, trip)
    }

    /// Wrap `inner` with an arbitrary bound.
    ///
    /// Exists so a test can drive the framing decision at a size that fits in a test rather
    /// than having to move 64 MiB to reach the production ceiling. It is **not** a knob:
    /// nothing in `src/` calls this with anything but [`MAX_PACKET_BYTES`], because a bound
    /// decided by configuration is a bound decided by whoever writes the configuration.
    pub fn with_limit(inner: R, limit: usize, trip: Arc<PacketLimitTrip>) -> Self {
        Self {
            inner,
            limit,
            trip,
            header: [0u8; 4],
            header_len: 0,
            payload_remaining: 0,
            logical_declared: 0,
            chain_sequence: None,
        }
    }

    /// Give the wrapped reader back, framing checks and all state dropped.
    ///
    /// Used for the lingering drain after a refusal: draining through the limiter would trip
    /// it again on the very bytes it is discarding.
    pub fn into_inner(self) -> R {
        self.inner
    }

    /// Track `bytes` through the framing, refusing at the first header that crosses the bound.
    ///
    /// Returns `Err(())` on refusal, having recorded the sequence id and the declared size.
    fn observe(&mut self, bytes: &[u8]) -> Result<(), ()> {
        let mut i = 0usize;
        while i < bytes.len() {
            if self.payload_remaining > 0 {
                let take = self.payload_remaining.min(bytes.len() - i);
                self.payload_remaining -= take;
                i += take;
                continue;
            }

            let need = 4 - self.header_len;
            let take = need.min(bytes.len() - i);
            self.header[self.header_len..self.header_len + take]
                .copy_from_slice(&bytes[i..i + take]);
            self.header_len += take;
            i += take;
            if self.header_len < 4 {
                // A header split across two reads. Nothing is decided until all four bytes
                // are in hand — deciding on a partial length is how a bound comes to be
                // applied to the wrong number.
                break;
            }
            self.header_len = 0;

            let declared =
                u32::from_le_bytes([self.header[0], self.header[1], self.header[2], 0]) as usize;
            let sequence = self.header[3];
            let logical = self.logical_declared.saturating_add(declared);

            if logical > self.limit {
                self.trip.record(Refusal::TooLarge, sequence, logical);
                return Err(());
            }

            let out_of_order = sequence == u8::MAX
                || self
                    .chain_sequence
                    .is_some_and(|previous| sequence != previous.wrapping_add(1));
            if out_of_order {
                self.trip.record(Refusal::OutOfOrder, sequence, logical);
                return Err(());
            }

            self.payload_remaining = declared;
            // A fragment of exactly FULL_PACKET_PAYLOAD continues into the next packet, so the
            // logical size carries over. Anything shorter ends the logical packet.
            if declared == FULL_PACKET_PAYLOAD {
                self.logical_declared = logical;
                self.chain_sequence = Some(sequence);
            } else {
                self.logical_declared = 0;
                self.chain_sequence = None;
            }
        }
        Ok(())
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for PacketLimitReader<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        match Pin::new(&mut this.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                let filled = buf.filled().len();
                if filled > before {
                    // Copied rather than borrowed because `observe` takes `&mut self` while
                    // `buf` borrows from the caller; the slice is one read's worth, never a
                    // packet's worth, so this is bounded by the caller's buffer.
                    let fresh = buf.filled()[before..filled].to_vec();
                    if this.observe(&fresh).is_err() {
                        let reason = match this.trip.refusal() {
                            Refusal::TooLarge => "MySQL packet exceeds max_allowed_packet",
                            Refusal::OutOfOrder => "MySQL packet sequence id out of order",
                        };
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            reason,
                        )));
                    }
                }
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

/// The ERR packet a peer gets when its packet crosses [`MAX_PACKET_BYTES`].
///
/// Laid out by hand because it is a wire packet, and matching a real MySQL server byte for
/// byte is the whole point: 3-byte little-endian payload length, sequence id, `0xFF` marking
/// an ERR packet, error number 1153 little-endian, the `#` SQL-state marker, the five
/// characters of SQLSTATE `08S01`, and the message text MySQL itself uses. A client that
/// reads only the error number sees 1153; one that classifies by SQLSTATE sees the
/// communication-link-failure class; one that shows the operator a string sees the same
/// sentence it would see from mysqld.
///
/// `sequence` must be one past the header that was refused. MySQL numbers packets within a
/// command, and a reply whose sequence does not follow the request is discarded by a
/// conforming client as "packet out of order" — so getting this wrong turns a clear refusal
/// back into the silence this bound exists to replace.
pub fn packet_too_large_err(sequence: u8) -> Vec<u8> {
    const ER_NET_PACKET_TOO_LARGE: u16 = 1153;
    err_packet(
        sequence,
        ER_NET_PACKET_TOO_LARGE,
        b"Got a packet bigger than 'max_allowed_packet' bytes",
    )
}

/// The ERR packet a peer gets when a header carries a sequence id [`PacketLimitReader`]
/// refuses: error **1156 `ER_NET_PACKETS_OUT_OF_ORDER`**, SQLSTATE `08S01`, with mysqld's own
/// message — what a real server answers a client whose packet numbering it cannot follow.
pub fn packets_out_of_order_err(sequence: u8) -> Vec<u8> {
    const ER_NET_PACKETS_OUT_OF_ORDER: u16 = 1156;
    err_packet(
        sequence,
        ER_NET_PACKETS_OUT_OF_ORDER,
        b"Got packets out of order",
    )
}

/// A communication-class (`08S01`) ERR packet, framed with `sequence`.
fn err_packet(sequence: u8, code: u16, message: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(9 + message.len());
    payload.push(0xFF);
    payload.extend_from_slice(&code.to_le_bytes());
    payload.push(b'#');
    payload.extend_from_slice(b"08S01");
    payload.extend_from_slice(message);

    let len = payload.len();
    let mut packet = Vec::with_capacity(4 + len);
    packet.push((len & 0xFF) as u8);
    packet.push(((len >> 8) & 0xFF) as u8);
    packet.push(((len >> 16) & 0xFF) as u8);
    packet.push(sequence);
    packet.extend_from_slice(&payload);
    packet
}

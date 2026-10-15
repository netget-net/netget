//! A connection cap for accept loops, and the refusal that says why.
//!
//! # The problem this closes
//!
//! Every TCP accept loop in this tree used to accept without limit. A peer that connects and
//! says nothing holds a socket, a task and an [`AppState`](crate::state::app_state::AppState)
//! connection entry for as long as it likes; a thousand of them is a free denial of service,
//! pre-authentication, on a server that will happily accept a thousand more. Per-connection
//! read timeouts bound how long *one* peer can stall, and are the other half of this — but a
//! timeout alone still lets an attacker hold `timeout × rate` connections at once. Only a cap
//! turns "bounded per connection" into "bounded".
//!
//! # Why it refuses out loud
//!
//! A cap that silently drops the socket is worse than no cap at all: the client cannot tell a
//! full server from a crashed one, so it retries immediately and forever, and the operator
//! sees an outage with no cause. So [`accept_bounded`] writes the caller's own bytes before
//! closing, and each protocol supplies the phrasing its *own* clients already understand —
//! MySQL error 1040, RESP `-ERR max number of clients reached`, HTTP `503`, and so on. The
//! bytes live in each protocol's `mod.rs`, not here: a table of per-protocol literals in a
//! shared module would be exactly the centralised per-protocol logic this codebase forbids.
//! This module knows only "some bytes, or none".
//!
//! Where a protocol has no way to say it — the peer speaks first and every server message is a
//! positive assertion — the right answer is an empty slice and a plain close, for the same
//! reason twenty protocols are deliberately silent on an LLM failure: a fabricated reply is
//! worse than silence. The refusal is still logged, and the log line is the diagnosis.
//!
//! # Usage
//!
//! ```ignore
//! const MAX_CONNECTIONS: usize = accept_bounded::DEFAULT_MAX_CONNECTIONS;
//! const BUSY: &[u8] = b"-ERR max number of clients reached\r\n";
//!
//! let limiter = ConnectionLimiter::new(MAX_CONNECTIONS);
//! loop {
//!     let (socket, peer, permit) =
//!         match accept_bounded(&listener, &limiter, BUSY, "REDIS", Some(&status_tx)).await {
//!             Ok(v) => v,
//!             Err(e) => { /* the listener itself failed; break */ }
//!         };
//!     tokio::spawn(async move {
//!         let _permit = permit; // held for the life of the connection
//!         handle(socket).await;
//!     });
//! }
//! ```
//!
//! [`accept_bounded`] never returns a refused connection: it loops internally, so the caller's
//! loop only ever sees peers that were admitted. The [`ConnectionPermit`] it returns must be
//! moved into the connection task — dropping it early releases the slot while the connection
//! is still live, which silently un-caps the server.

use crate::logging::emit::Log;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, OwnedSemaphorePermit, Semaphore};

/// Concurrent connections a server admits before it starts refusing.
///
/// 256, which is what `src/server/nfs/guard.rs` chose on its own reasoning and the only number
/// in this tree that was ever argued for: each admitted connection costs a bounded amount of
/// memory, so the cap is what multiplies that bound into a total. It is deliberately generous
/// — far above anything a human operator or a test harness produces, and far below what an
/// attacker needs for the socket exhaustion to matter. A protocol whose per-connection cost is
/// unusually high (a large read buffer, a long-lived session) declares its own smaller value
/// and says why in the comment; one that multiplexes everything over few connections may
/// declare a smaller one still.
///
/// This is not a tuning knob exposed to the model or the operator: a bound decided by
/// configuration is a bound an attacker can ask you to raise.
pub const DEFAULT_MAX_CONNECTIONS: usize = 256;

/// How long a refusal is given to reach the peer before the socket is dropped anyway.
///
/// A peer that has filled our send buffer and stopped reading must not be able to hold the
/// *refusal* open either — that would turn the cap into the same resource hole it closes.
const REFUSAL_WRITE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Tracks how many connections a server currently has admitted.
///
/// Cheap to clone; every clone refers to the same count.
#[derive(Clone, Debug)]
pub struct ConnectionLimiter {
    slots: Arc<Semaphore>,
    max: usize,
}

impl ConnectionLimiter {
    /// A limiter admitting at most `max` connections at once.
    ///
    /// `max` of zero would refuse everything, which is never what a caller means, so it is
    /// clamped to one.
    pub fn new(max: usize) -> Self {
        let max = max.max(1);
        Self {
            slots: Arc::new(Semaphore::new(max)),
            max,
        }
    }

    /// The cap this limiter was built with, for log lines and tests.
    pub fn max(&self) -> usize {
        self.max
    }

    /// Connections currently admitted.
    pub fn in_use(&self) -> usize {
        self.max - self.slots.available_permits()
    }

    /// Take a slot, or `None` if the server is at its cap.
    ///
    /// Never waits: queueing a peer that is over the cap is just a slower way of holding the
    /// resource it was refused.
    pub fn try_acquire(&self) -> Option<ConnectionPermit> {
        Arc::clone(&self.slots)
            .try_acquire_owned()
            .ok()
            .map(|permit| ConnectionPermit { _permit: permit })
    }
}

/// One admitted connection's slot. Released when dropped, so it must live as long as the
/// connection task does.
#[derive(Debug)]
pub struct ConnectionPermit {
    _permit: OwnedSemaphorePermit,
}

/// Accept the next connection the server has room for, refusing the ones it does not.
///
/// Returns only admitted peers. A peer over the cap is answered with `refusal` (skipped when
/// empty), logged at WARN with `decision=fail_closed_connection_cap`, closed, and never seen
/// by the caller.
///
/// `Err` means the *listener* failed, which is the caller's signal to break its accept loop —
/// exactly the errors `TcpListener::accept` already returns.
pub async fn accept_bounded(
    listener: &TcpListener,
    limiter: &ConnectionLimiter,
    refusal: &[u8],
    protocol: &str,
    status_tx: Option<&mpsc::UnboundedSender<String>>,
) -> std::io::Result<(TcpStream, SocketAddr, ConnectionPermit)> {
    loop {
        let (socket, peer_addr) = listener.accept().await?;

        match limiter.try_acquire() {
            Some(permit) => return Ok((socket, peer_addr, permit)),
            None => {
                Log::new(status_tx).warn(format!(
                    "{} connection from {} refused decision=fail_closed_connection_cap \
                     (limit {} concurrent)",
                    protocol,
                    peer_addr,
                    limiter.max()
                ));
                refuse(socket, refusal).await;
            }
        }
    }
}

/// [`accept_bounded`] for a Unix domain socket listener (`socket_file`, `ssh_agent`).
///
/// A filesystem socket is exposed to every local process that can write the node, and a peer
/// that connects and says nothing holds a task and an `AppState` entry exactly as a TCP peer
/// does, so it needs the same cap. There is no peer address to log, so the refusal line names
/// the listener's own path instead.
#[cfg(unix)]
pub async fn accept_bounded_unix(
    listener: &tokio::net::UnixListener,
    limiter: &ConnectionLimiter,
    refusal: &[u8],
    protocol: &str,
    status_tx: Option<&mpsc::UnboundedSender<String>>,
) -> std::io::Result<(tokio::net::UnixStream, ConnectionPermit)> {
    loop {
        let (socket, _) = listener.accept().await?;

        match limiter.try_acquire() {
            Some(permit) => return Ok((socket, permit)),
            None => {
                let path = listener
                    .local_addr()
                    .ok()
                    .and_then(|a| a.as_pathname().map(|p| p.display().to_string()))
                    .unwrap_or_else(|| "<unnamed>".to_string());
                Log::new(status_tx).warn(format!(
                    "{} connection on {} refused decision=fail_closed_connection_cap \
                     (limit {} concurrent)",
                    protocol,
                    path,
                    limiter.max()
                ));
                refuse(socket, refusal).await;
            }
        }
    }
}

/// Write the protocol's "busy" bytes and close.
///
/// Both halves are best-effort and time-bounded: the peer is already being refused, so nothing
/// here may block the accept loop. Bytes first, then an explicit shutdown so the peer reads the
/// refusal followed by a clean EOF rather than a reset that discards it.
async fn refuse<S: tokio::io::AsyncWrite + Unpin>(mut socket: S, refusal: &[u8]) {
    let _ = tokio::time::timeout(REFUSAL_WRITE_TIMEOUT, async {
        if !refusal.is_empty() {
            let _ = socket.write_all(refusal).await;
            let _ = socket.flush().await;
        }
        let _ = socket.shutdown().await;
    })
    .await;
}

/// Bound the upload tail discarded after an HTTP response has been flushed and the write
/// side half-closed. Two MiB covers the one-MiB overrun exercised by real HTTP clients,
/// including framing; two seconds also bounds a silent peer. Nothing is buffered or modelled.
const RESPONSE_DRAIN_BYTES: usize = 2 * 1024 * 1024;
const RESPONSE_DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

/// Discard an in-flight upload tail after flushing the response and half-closing writes.
///
/// Dropping a TCP socket while unread upload bytes remain can send RST and erase a 413
/// before the client reads it. The absolute time and byte budgets let an ordinary upload
/// finish without allowing an endless or silent peer to keep the connection task alive.
/// This runs only after the HTTP connection completes, outside live handler work.
pub(crate) async fn drain_after_response(reader: &mut (impl AsyncRead + Unpin)) {
    use tokio::io::AsyncReadExt;

    let deadline = tokio::time::Instant::now() + RESPONSE_DRAIN_TIMEOUT;
    let mut remaining = RESPONSE_DRAIN_BYTES;
    let mut scratch = [0u8; 8192];
    while remaining > 0 {
        let read_size = remaining.min(scratch.len());
        match tokio::time::timeout_at(deadline, reader.read(&mut scratch[..read_size])).await {
            Ok(Ok(n)) if n > 0 => remaining -= n,
            _ => break,
        }
    }
}

// ---------------------------------------------------------------------------------------
// Read deadlines where the protocol's loop is not ours
// ---------------------------------------------------------------------------------------
//
// Most servers here own their read loop, and the right shape there is the one
// `src/server/whois/mod.rs` uses: wrap the `read()` — and *only* the `read()` — in
// `tokio::time::timeout`, so the model round-trip and a `manual` rule parking an event for a
// human sit outside the deadline by construction. Two protocols hand their socket to a crate
// that owns the loop instead (`msql-srv`, `pgwire`), and the two types below are how they get
// the same guarantee.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, ReadBuf};

/// An [`AsyncRead`] that fails with [`std::io::ErrorKind::TimedOut`] when the peer sends
/// nothing for `idle`.
///
/// This exists for a crate that takes a generic reader and runs the protocol loop itself, where
/// there is no `read()` call of ours to wrap.
///
/// **Why it cannot evict a live-but-slow operation.** The deadline is armed lazily, when a read
/// is polled and finds nothing, and disarmed the moment bytes arrive. While the crate is off
/// doing something else with what it read — an LLM round-trip, a `manual` event parked for a
/// human at the dashboard — this reader is not being polled at all, so no clock is running. The
/// next poll after that work finishes arms a *fresh* deadline rather than inheriting a stale
/// one. That lazy arming is the whole correctness argument: a version that reset the deadline
/// only on a successful read would fire immediately after any pause longer than `idle`, which
/// is exactly the live-transfer eviction this project already learned about from TFTP.
pub struct IdleTimeoutReader<R> {
    inner: R,
    /// Bound until the peer's first byte. Kept separate because "has said nothing at all" and
    /// "has gone quiet mid-session" deserve different answers — the whois pair, expressed for a
    /// loop that is not ours.
    first: Duration,
    idle: Duration,
    seen_bytes: bool,
    /// Armed only while a read is outstanding with no bytes yet.
    deadline: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl<R> IdleTimeoutReader<R> {
    /// One bound for every read.
    pub fn new(inner: R, idle: Duration) -> Self {
        Self::with_first(inner, idle, idle)
    }

    /// `first` until the peer's first byte arrives, `idle` for every read after that.
    pub fn with_first(inner: R, first: Duration, idle: Duration) -> Self {
        Self {
            inner,
            first,
            idle,
            seen_bytes: false,
            deadline: None,
        }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for IdleTimeoutReader<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        match Pin::new(&mut this.inner).poll_read(cx, buf) {
            Poll::Ready(result) => {
                // Bytes (or EOF, or an error): whatever happens next is not this reader's
                // business, so disarm.
                this.deadline = None;
                if result.is_ok() && buf.filled().len() > before {
                    this.seen_bytes = true;
                }
                Poll::Ready(result)
            }
            Poll::Pending => {
                let bound = if this.seen_bytes {
                    this.idle
                } else {
                    this.first
                };
                let deadline = this
                    .deadline
                    .get_or_insert_with(|| Box::pin(tokio::time::sleep(bound)));
                match deadline.as_mut().poll(cx) {
                    Poll::Ready(()) => {
                        this.deadline = None;
                        Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "peer sent nothing before the idle deadline",
                        )))
                    }
                    Poll::Pending => Poll::Pending,
                }
            }
        }
    }
}

/// Whether a connection whose loop belongs to a crate is idle, and since when.
///
/// [`IdleTimeoutReader`] is the better answer wherever the crate takes a generic reader.
/// `pgwire` does not — `process_socket` takes a concrete `TcpStream` — so PostgreSQL bounds its
/// idle time from the outside instead, with a watchdog reading this.
///
/// The `in_flight` counter is what keeps that watchdog honest. A connection parked on an LLM
/// call, or on a `manual` rule waiting for a human, is *working*, not idle, and must never be
/// closed from under itself; the handler raises the counter for the whole of that work, and
/// [`watch_idle`] refuses to fire while it is non-zero. Wall-clock alone would have made the
/// bound "longer than the longest park anyone configures", which is a guess rather than a rule.
#[derive(Debug)]
pub struct ConnectionActivity {
    /// Milliseconds since this process's clock epoch at the last sign of life.
    last: AtomicU64,
    /// Operations currently being answered on this connection.
    in_flight: AtomicUsize,
}

impl Default for ConnectionActivity {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnectionActivity {
    pub fn new() -> Self {
        Self {
            last: AtomicU64::new(now_millis()),
            in_flight: AtomicUsize::new(0),
        }
    }

    /// Note that something crossed the connection.
    pub fn touch(&self) {
        self.last.store(now_millis(), Ordering::Relaxed);
    }

    /// Mark the start of work the peer is waiting on. Pair with [`Self::end_work`].
    pub fn begin_work(&self) {
        self.touch();
        self.in_flight.fetch_add(1, Ordering::SeqCst);
    }

    /// Mark the end of that work, and treat its completion as activity.
    pub fn end_work(&self) {
        self.in_flight.fetch_sub(1, Ordering::SeqCst);
        self.touch();
    }

    /// Mark the connection busy until the returned guard is dropped.
    ///
    /// Preferred over a bare [`Self::begin_work`]/[`Self::end_work`] pair anywhere the work has
    /// more than one exit — a `?`, an early `return`, an unwinding panic. Leaking the mark
    /// pins the connection "busy" forever and silently disables the idle bound, which is the
    /// worst possible failure for a guard nobody is looking at.
    pub fn busy(self: &Arc<Self>) -> BusyGuard {
        self.begin_work();
        BusyGuard(Arc::clone(self))
    }

    /// How long the connection has been doing nothing at all. `None` while work is in flight,
    /// which is the whole point: busy is not idle.
    pub fn idle_for(&self) -> Option<Duration> {
        if self.in_flight.load(Ordering::SeqCst) > 0 {
            return None;
        }
        let last = self.last.load(Ordering::Relaxed);
        Some(Duration::from_millis(now_millis().saturating_sub(last)))
    }
}

/// Holds a connection "busy" for its lifetime. See [`ConnectionActivity::busy`].
pub struct BusyGuard(Arc<ConnectionActivity>);

impl Drop for BusyGuard {
    fn drop(&mut self) {
        self.0.end_work();
    }
}

/// Watch a [`ConnectionActivity`] and resolve once it has been idle for `idle`.
///
/// Returns as soon as the bound is exceeded; the caller decides what to do about it (PostgreSQL
/// aborts the connection task). This polls rather than waking on an event because the thing
/// being watched is the *absence* of events, and a coarse tick costs nothing when the bound is
/// minutes.
pub async fn watch_idle(activity: Arc<ConnectionActivity>, idle: Duration) {
    let tick = (idle / 20).clamp(Duration::from_millis(250), Duration::from_secs(15));
    loop {
        tokio::time::sleep(tick).await;
        if let Some(elapsed) = activity.idle_for() {
            if elapsed >= idle {
                return;
            }
        }
    }
}

/// [`watch_idle`] for a session protocol whose client may legitimately say nothing for a long
/// time: resolve once `activity` has been idle for `idle`, having called `probe` once at half
/// of it.
///
/// This is the shape for WebSocket-carried servers (`websocket`, `webrtc`, `webrtc_signaling`):
/// the probe queues a Ping, every RFC 6455 endpoint answers a Ping with a Pong by itself, and the
/// caller touches `activity` on every inbound frame — so a live-but-silent client is never
/// closed, and what reaches the bound is a peer that has stopped reading or vanished without a
/// FIN. The bound is on liveness, not on conversation.
///
/// The probe fires once per silent stretch, not per tick: any activity starts a new stretch, and
/// a busy connection (work in flight) is neither probed nor reported idle.
pub async fn watch_idle_with_probe<F: FnMut()>(
    activity: Arc<ConnectionActivity>,
    idle: Duration,
    mut probe: F,
) {
    let tick = (idle / 20).clamp(Duration::from_millis(100), Duration::from_secs(15));
    let mut probed = false;
    loop {
        tokio::time::sleep(tick).await;
        match activity.idle_for() {
            Some(elapsed) if elapsed >= idle => return,
            Some(elapsed) if elapsed >= idle / 2 => {
                if !probed {
                    probe();
                    probed = true;
                }
            }
            // Busy, or heard from recently: the next silent stretch gets its own probe.
            _ => probed = false,
        }
    }
}

/// The payload of the keepalive Ping the WebSocket-carried servers send through
/// [`watch_idle_with_probe`]. A Pong echoes it (RFC 6455 §5.5.3); it is not checked, because any
/// frame is proof of life, but it makes the Ping identifiable in a capture.
pub const KEEPALIVE_PING_PAYLOAD: &[u8] = b"netget-keepalive";

/// Milliseconds on a monotonic clock. `utils::clock` rather than `std::time::Instant`, which
/// panics on wasm32 (see the project CLAUDE.md).
fn now_millis() -> u64 {
    crate::utils::clock::Instant::now()
        .duration_since(*PROCESS_START)
        .as_millis() as u64
}

static PROCESS_START: std::sync::LazyLock<crate::utils::clock::Instant> =
    std::sync::LazyLock::new(crate::utils::clock::Instant::now);

#[cfg(test)]
mod response_drain_tests {
    use super::*;

    #[tokio::test]
    async fn response_drain_stops_at_the_byte_budget() {
        let bytes = vec![0; RESPONSE_DRAIN_BYTES + 1];
        let mut reader = bytes.as_slice();
        drain_after_response(&mut reader).await;
        assert_eq!(
            reader.len(),
            1,
            "an endless uploader cannot keep the task alive"
        );
    }

    #[tokio::test]
    async fn response_drain_stops_even_when_the_peer_keeps_its_write_half_open() {
        let (mut reader, _silent_peer) = tokio::io::duplex(1);
        let started = tokio::time::Instant::now();
        tokio::time::timeout(
            RESPONSE_DRAIN_TIMEOUT + std::time::Duration::from_secs(5),
            drain_after_response(&mut reader),
        )
        .await
        .expect("a silent peer cannot keep the task alive");
        assert!(started.elapsed() >= RESPONSE_DRAIN_TIMEOUT);
    }
}

//! A per-connection outbound queue with a bound, for writer tasks fed by synchronous senders.
//!
//! Several stream servers funnel every write for a connection through one channel drained by
//! a writer task, so that frames produced by the read loop, by a keepalive timer and by other
//! connections (a publish fanned out to subscribers, a relayed message) never interleave. The
//! senders are synchronous — closures, executor arms, fan-out loops holding a `std` mutex — so
//! they cannot wait for room, and an unbounded channel let a peer that stops reading grow its
//! queue for as long as anyone kept producing for it: its own requests answered, or every
//! message published to a topic it subscribed to.
//!
//! The policy is Redis's for a slow pub/sub client: **a connection whose queue passes its bound
//! is cut off.** The frame that did not fit is dropped and counted, every later send fails at
//! once, and the receiver returns `None`, abandoning what is still queued. Dropping frames and
//! carrying on is not offered: a stream with a frame missing from the middle is corrupt, and a
//! peer that is not reading has nothing to gain from the rest. The first overflow is logged with
//! the connection's label.
//!
//! Cutting off also **ends the connection** when the adopter has handed the outbox its socket
//! ([`OutboxSender::close_on_cut_off`] with a [`ConnectionCloser`] taken before the stream is
//! split or wrapped). The socket is shut down in both directions at the moment of overflow:
//! the writer, which is usually blocked writing to a peer that does not read, fails at once;
//! the reader reads EOF and runs the protocol's own close path, so the connection is marked
//! closed and its slot released; and the peer reads what was already sent, then EOF. Without
//! it a peer that never reads would keep its socket and its slot until its read deadline.
//!
//! The bound is in items and in bytes. A single item larger than the byte bound is still
//! accepted when the queue is empty: an idle queue means the peer is keeping up, and the
//! protocol's own size limits govern how large one frame may be.

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

use tokio::sync::mpsc;

/// How much one connection's queue may hold before the connection is cut off.
#[derive(Debug, Clone, Copy)]
pub struct OutboxLimits {
    pub max_items: usize,
    pub max_bytes: usize,
}

impl OutboxLimits {
    /// 4096 frames or 8 MiB, the size Redis allows a pub/sub client's output buffer before it
    /// disconnects it. Ample for a peer that reads; a queue that fills is a peer that does not.
    pub const DEFAULT: Self = Self {
        max_items: 4096,
        max_bytes: 8 * 1024 * 1024,
    };
}

struct Shared<T> {
    label: String,
    limits: OutboxLimits,
    weight: fn(&T) -> usize,
    queued_bytes: AtomicUsize,
    overflowed: AtomicBool,
    dropped: AtomicU64,
    /// Shut down when the peer is cut off; released when the writer's receiver is dropped.
    closer: std::sync::Mutex<Option<ConnectionCloser>>,
}

/// A handle that can end one TCP connection from anywhere: a duplicate of its socket, used only
/// to `shutdown` it. Taken with [`ConnectionCloser::for_stream`] before the stream is split or
/// wrapped (TLS, WebSocket framing), because afterwards nothing reaches the socket.
///
/// The duplicate keeps the socket open for as long as it lives, so the outbox holds it only
/// while the connection's writer does (it is dropped with the [`OutboxReceiver`]), and the
/// writer already holds the socket open itself.
pub struct ConnectionCloser {
    #[cfg(not(target_arch = "wasm32"))]
    socket: Option<socket2::Socket>,
}

impl ConnectionCloser {
    /// A closer for `stream`'s connection. In the browser build, or if the socket cannot be
    /// duplicated, it closes nothing and the cut-off peer keeps its socket until its read
    /// deadline, as it would without one.
    pub fn for_stream(stream: &tokio::net::TcpStream) -> Self {
        #[cfg(not(target_arch = "wasm32"))]
        {
            let socket = socket2::SockRef::from(stream).try_clone();
            if let Err(e) = &socket {
                tracing::warn!("outbox: cannot duplicate a socket to close it on cut-off: {e}");
            }
            Self {
                socket: socket.ok(),
            }
        }
        #[cfg(target_arch = "wasm32")]
        {
            let _ = stream;
            Self {}
        }
    }

    /// Shut the connection down in both directions.
    fn shutdown(&self) {
        #[cfg(not(target_arch = "wasm32"))]
        if let Some(socket) = &self.socket {
            let _ = socket.shutdown(std::net::Shutdown::Both);
        }
    }
}

/// The sending side. Cloneable; `send` never waits.
pub struct OutboxSender<T> {
    tx: mpsc::Sender<T>,
    shared: Arc<Shared<T>>,
}

impl<T> Clone for OutboxSender<T> {
    fn clone(&self) -> Self {
        Self {
            tx: self.tx.clone(),
            shared: self.shared.clone(),
        }
    }
}

impl<T> std::fmt::Debug for OutboxSender<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OutboxSender")
            .field("label", &self.shared.label)
            .field("overflowed", &self.overflowed())
            .finish()
    }
}

/// The writer task's side.
pub struct OutboxReceiver<T> {
    rx: mpsc::Receiver<T>,
    shared: Arc<Shared<T>>,
}

/// A bounded outbox. `label` names the connection in the overflow log line; `weight` gives an
/// item's size in bytes.
pub fn channel<T>(
    label: impl Into<String>,
    limits: OutboxLimits,
    weight: fn(&T) -> usize,
) -> (OutboxSender<T>, OutboxReceiver<T>) {
    let (tx, rx) = mpsc::channel(limits.max_items.max(1));
    let shared = Arc::new(Shared {
        label: label.into(),
        limits,
        weight,
        queued_bytes: AtomicUsize::new(0),
        overflowed: AtomicBool::new(false),
        dropped: AtomicU64::new(0),
        closer: std::sync::Mutex::new(None),
    });
    (
        OutboxSender {
            tx,
            shared: shared.clone(),
        },
        OutboxReceiver { rx, shared },
    )
}

/// An outbox of byte frames, weighed by length.
pub fn bytes_channel(
    label: impl Into<String>,
    limits: OutboxLimits,
) -> (OutboxSender<Vec<u8>>, OutboxReceiver<Vec<u8>>) {
    channel(label, limits, Vec::len)
}

impl<T> OutboxSender<T> {
    /// Queue `item` for the writer. Fails, returning the item, when the writer is gone or the
    /// connection has been cut off; an item that does not fit cuts it off.
    pub fn send(&self, item: T) -> Result<(), mpsc::error::SendError<T>> {
        let shared = &self.shared;
        if shared.overflowed.load(Ordering::Acquire) {
            shared.dropped.fetch_add(1, Ordering::Relaxed);
            return Err(mpsc::error::SendError(item));
        }
        let weight = (shared.weight)(&item);
        let queued = shared.queued_bytes.load(Ordering::Acquire);
        if queued > 0 && queued.saturating_add(weight) > shared.limits.max_bytes {
            self.overflow();
            return Err(mpsc::error::SendError(item));
        }
        shared.queued_bytes.fetch_add(weight, Ordering::AcqRel);
        match self.tx.try_send(item) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Full(item)) => {
                shared.queued_bytes.fetch_sub(weight, Ordering::AcqRel);
                self.overflow();
                Err(mpsc::error::SendError(item))
            }
            Err(mpsc::error::TrySendError::Closed(item)) => {
                shared.queued_bytes.fetch_sub(weight, Ordering::AcqRel);
                Err(mpsc::error::SendError(item))
            }
        }
    }

    fn overflow(&self) {
        let shared = &self.shared;
        shared.dropped.fetch_add(1, Ordering::Relaxed);
        if !shared.overflowed.swap(true, Ordering::AcqRel) {
            tracing::warn!(
                "{}: outbound queue passed {} frames / {} bytes; the peer is not reading, so \
                 the connection is cut off decision=outbox_overflow",
                shared.label,
                shared.limits.max_items,
                shared.limits.max_bytes
            );
            if let Some(closer) = shared
                .closer
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take()
            {
                closer.shutdown();
            }
        }
    }

    /// End the connection, not just its writer, when its peer is cut off. Call once, right
    /// after creating the outbox; if the peer has already been cut off, the connection is
    /// ended now.
    pub fn close_on_cut_off(&self, closer: ConnectionCloser) {
        if self.overflowed() {
            closer.shutdown();
            return;
        }
        *self.shared.closer.lock().unwrap_or_else(|e| e.into_inner()) = Some(closer);
    }

    /// Whether this connection has been cut off for not reading.
    pub fn overflowed(&self) -> bool {
        self.shared.overflowed.load(Ordering::Acquire)
    }

    /// Frames refused since the connection was cut off, the one that cut it off included.
    pub fn dropped(&self) -> u64 {
        self.shared.dropped.load(Ordering::Relaxed)
    }

    /// Whether the writer is gone.
    pub fn is_closed(&self) -> bool {
        self.tx.is_closed()
    }
}

impl<T> Drop for OutboxReceiver<T> {
    fn drop(&mut self) {
        // The writer is gone, so the connection is ending by its own path; let the socket go.
        self.shared
            .closer
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
    }
}

impl<T> OutboxReceiver<T> {
    /// The next queued item, or `None` once every sender is gone or the connection has been
    /// cut off (what is still queued is then abandoned).
    pub async fn recv(&mut self) -> Option<T> {
        if self.shared.overflowed.load(Ordering::Acquire) {
            return None;
        }
        let item = self.rx.recv().await?;
        self.taken(&item);
        if self.shared.overflowed.load(Ordering::Acquire) {
            return None;
        }
        Some(item)
    }

    /// [`Self::recv`] without waiting.
    pub fn try_recv(&mut self) -> Result<T, mpsc::error::TryRecvError> {
        if self.shared.overflowed.load(Ordering::Acquire) {
            return Err(mpsc::error::TryRecvError::Disconnected);
        }
        let item = self.rx.try_recv()?;
        self.taken(&item);
        Ok(item)
    }

    fn taken(&self, item: &T) {
        let weight = (self.shared.weight)(item);
        self.shared.queued_bytes.fetch_sub(weight, Ordering::AcqRel);
    }

    /// Whether this connection has been cut off for not reading.
    pub fn overflowed(&self) -> bool {
        self.shared.overflowed.load(Ordering::Acquire)
    }
}

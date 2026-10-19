//! A registered reader task feeding a bounded queue, for clients whose server sends free-form
//! bytes (the proxied byte streams of `socks5`, `http_proxy` and `tor`).
//!
//! A client that calls the model inline in its read loop cannot batch: whatever the server
//! sends during the call merges in the kernel buffer and arrives as one read, so batching off
//! and on are indistinguishable. Reading on a task of its own keeps each read's boundaries in
//! the queue while the model answers, so the answering loop can take one read per call
//! (batching off) or everything waiting (batching on). This is the `tcp` client's shape,
//! shared by the clients that have the same byte-stream problem.

use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::sync::mpsc;

use crate::state::app_state::AppState;
use crate::state::ClientId;

/// How many reads may wait while the model answers an earlier one. Each is at most one
/// [`READ_BUFFER_BYTES`] read, so at most 256 KiB waits; past it the reader stops reading, the
/// socket's receive window fills, and the server is held back by TCP itself.
pub const READ_QUEUE_CHUNKS: usize = crate::protocol::metadata::MAX_BATCH_EVENTS;

/// The size of one read.
pub const READ_BUFFER_BYTES: usize = 8192;

/// What the reader task hands the answering loop.
pub enum Inbound {
    Data(Vec<u8>),
    Closed,
    Failed(String),
}

/// The receiving end of a client's reader task. Dropping it aborts the reader.
pub struct InboundQueue {
    rx: mpsc::Receiver<Inbound>,
    reader: tokio::task::AbortHandle,
}

impl InboundQueue {
    /// Start reading `read_half` on a task registered to `client_id`, so `stop_client` aborts
    /// it with the rest of the client.
    pub async fn spawn<R>(app_state: &AppState, client_id: ClientId, mut read_half: R) -> Self
    where
        R: AsyncRead + Unpin + Send + 'static,
    {
        let (tx, rx) = mpsc::channel::<Inbound>(READ_QUEUE_CHUNKS);
        let reader = app_state
            .spawn_client_task(client_id, async move {
                let mut buffer = vec![0u8; READ_BUFFER_BYTES];
                loop {
                    let message = match read_half.read(&mut buffer).await {
                        Ok(0) => Inbound::Closed,
                        Ok(n) => Inbound::Data(buffer[..n].to_vec()),
                        Err(e) => Inbound::Failed(e.to_string()),
                    };
                    let last = !matches!(message, Inbound::Data(_));
                    if tx.send(message).await.is_err() || last {
                        break;
                    }
                }
            })
            .await;
        Self { rx, reader }
    }

    /// The next read. Cancellation-safe, so it can sit in a `select!` beside the command
    /// channel. A reader that is gone reads as the end of the stream.
    pub async fn recv(&mut self) -> Inbound {
        self.rx.recv().await.unwrap_or(Inbound::Closed)
    }

    /// Append every read already waiting to `data`. An end of stream or a read error found
    /// while sweeping stops the sweep and is returned, for the caller to handle after it has
    /// answered what came before it.
    pub fn drain_into(&mut self, data: &mut Vec<u8>) -> Option<Inbound> {
        while let Ok(more) = self.rx.try_recv() {
            match more {
                Inbound::Data(more) => data.extend_from_slice(&more),
                other => return Some(other),
            }
        }
        None
    }
}

impl Drop for InboundQueue {
    fn drop(&mut self) {
        self.reader.abort();
    }
}

//! A transport that answers every request it received before it reports the end of its input.
//!
//! rmcp's serve loop stops the moment the transport's input ends, and a tool call still being
//! handled at that moment has its response dropped: the handler runs in its own task and hands
//! the response back to a loop that is no longer there. So a caller that writes its requests
//! and closes stdin, which is how a shell pipeline or a one-shot script drives `netget --mcp`,
//! got the answer to `initialize` and nothing after it.
//!
//! [`DrainOnEof`] wraps rmcp's own stdio transport. It records the id of every request it
//! receives and forgets it once a response or error with that id has been written. When the
//! input ends it reports the end only after every recorded id has been answered, bounded by
//! [`DRAIN_LIMIT`] so a call that never finishes cannot hold the process open forever.

use std::collections::HashSet;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rmcp::model::{JsonRpcMessage, RequestId};
use rmcp::service::{RxJsonRpcMessage, TxJsonRpcMessage};
use rmcp::transport::async_rw::AsyncRwTransport;
use rmcp::transport::Transport;
use rmcp::RoleServer;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Notify;
use tracing::{info, warn};

/// Longest the server keeps answering after its input has ended. Five minutes is the default
/// window a `manual` handler gives a person to answer one parked request, which is the longest
/// a tool call normally waits on anything.
pub const DRAIN_LIMIT: Duration = Duration::from_secs(300);

/// Requests received and not yet answered.
#[derive(Default)]
struct Outstanding {
    ids: Mutex<HashSet<RequestId>>,
    changed: Notify,
}

impl Outstanding {
    fn insert(&self, id: RequestId) {
        self.ids.lock().expect("outstanding ids").insert(id);
    }

    fn answer(&self, id: &RequestId) {
        self.ids.lock().expect("outstanding ids").remove(id);
        self.changed.notify_waiters();
    }

    fn count(&self) -> usize {
        self.ids.lock().expect("outstanding ids").len()
    }

    /// Resolve once nothing is outstanding.
    async fn drained(&self) {
        loop {
            let notified = self.changed.notified();
            tokio::pin!(notified);
            // Registered before the check, so an answer written between the check and the
            // await still wakes it.
            notified.as_mut().enable();
            if self.count() == 0 {
                return;
            }
            notified.await;
        }
    }
}

/// See the module documentation.
pub struct DrainOnEof<T> {
    inner: T,
    outstanding: Arc<Outstanding>,
    /// Set when the input ends. rmcp drops and re-creates the receive future whenever another
    /// event wins its select, so after the end the reader is not polled again, the wait is
    /// announced once, and every re-created future shares one deadline.
    drain_deadline: Option<tokio::time::Instant>,
}

impl<T> DrainOnEof<T> {
    pub fn new(inner: T) -> Self {
        Self {
            inner,
            outstanding: Arc::new(Outstanding::default()),
            drain_deadline: None,
        }
    }
}

/// rmcp's newline-delimited JSON-RPC transport over `read` and `write`, wrapped so it drains
/// before it reports the end of its input. `netget --mcp` uses it over stdin and stdout.
pub fn drain_on_eof_transport<R, W>(
    read: R,
    write: W,
) -> DrainOnEof<AsyncRwTransport<RoleServer, R, W>>
where
    R: Send + AsyncRead + Unpin,
    W: Send + AsyncWrite + Unpin + 'static,
{
    DrainOnEof::new(AsyncRwTransport::new_server(read, write))
}

impl<T> Transport<RoleServer> for DrainOnEof<T>
where
    T: Transport<RoleServer>,
{
    type Error = T::Error;

    fn send(
        &mut self,
        item: TxJsonRpcMessage<RoleServer>,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send + 'static {
        let answered = match &item {
            JsonRpcMessage::Response(response) => Some(response.id.clone()),
            JsonRpcMessage::Error(error) => Some(error.id.clone()),
            _ => None,
        };
        let sending = self.inner.send(item);
        let outstanding = Arc::clone(&self.outstanding);
        async move {
            let result = sending.await;
            // Forgotten whether or not the write succeeded: a response that could not be
            // written will not be written later either, and waiting on it would only hold the
            // process open until the limit.
            if let Some(id) = answered {
                outstanding.answer(&id);
            }
            result
        }
    }

    fn receive(&mut self) -> impl Future<Output = Option<RxJsonRpcMessage<RoleServer>>> + Send {
        async move {
            let deadline = match self.drain_deadline {
                Some(deadline) => deadline,
                None => {
                    if let Some(message) = self.inner.receive().await {
                        if let JsonRpcMessage::Request(request) = &message {
                            // Subscription streams are cancelled on disconnect; they must
                            // not hold EOF open for the ordinary request drain deadline.
                            if !matches!(&request.request, rmcp::model::ClientRequest::CustomRequest(r) if matches!(r.method.as_str(), "events/stream" | "subscriptions/listen"))
                            {
                                self.outstanding.insert(request.id.clone());
                            }
                        }
                        if let JsonRpcMessage::Notification(notification) = &message {
                            if let rmcp::model::ClientNotification::CancelledNotification(
                                cancelled,
                            ) = &notification.notification
                            {
                                self.outstanding.answer(&cancelled.params.request_id);
                            }
                        }
                        return Some(message);
                    }
                    let pending = self.outstanding.count();
                    if pending > 0 {
                        info!(
                            "MCP input ended with {pending} request(s) still being answered; \
                             finishing them before shutting down"
                        );
                    }
                    let deadline = tokio::time::Instant::now() + DRAIN_LIMIT;
                    self.drain_deadline = Some(deadline);
                    deadline
                }
            };
            if tokio::time::timeout_at(deadline, self.outstanding.drained())
                .await
                .is_err()
            {
                warn!(
                    "MCP input ended and {} request(s) were still unanswered after {}s; \
                     shutting down without them",
                    self.outstanding.count(),
                    DRAIN_LIMIT.as_secs()
                );
            }
            None
        }
    }

    fn close(&mut self) -> impl Future<Output = Result<(), Self::Error>> + Send {
        self.inner.close()
    }
}

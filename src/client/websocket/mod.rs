//! WebSocket (RFC 6455) client.
//!
//! `tokio-tungstenite`'s `connect_async` performs the whole HTTP Upgrade handshake, including
//! generating the 16-byte `Sec-WebSocket-Key` nonce and verifying the server's
//! `Sec-WebSocket-Accept`, and its `Role::Client` framing masks every outgoing frame with a
//! fresh 32-bit key as RFC 6455 §5.3 requires. What is written here is the part NetGet owns:
//! turning the offered subprotocols and extra headers into the request, and turning received
//! frames into events the model answers with actions.
//!
//! ws:// only. The `tokio-tungstenite` dependency is built without a TLS backend, so wss://
//! is refused with a clear error rather than silently downgraded.

pub mod actions;

pub use actions::WebSocketClientProtocol;

use anyhow::{Context, Result};
use futures::stream::StreamExt;
use futures::SinkExt;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::{HeaderName, HeaderValue};
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::protocol::CloseFrame;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, error, info, trace, warn};

use crate::client::llm_budget::{call_llm_for_client, call_llm_for_client_batch};
use crate::llm::actions::client_trait::{Client, ClientActionResult};
use crate::llm::ollama_client::OllamaClient;
use crate::llm::ClientLlmResult;
use crate::protocol::Event;
use crate::server::websocket::actions::{encode_inbound_payload, WsOut};
use crate::state::app_state::AppState;
use crate::state::{ClientId, ClientStatus};
use actions::{
    WEBSOCKET_CLIENT_BINARY_MESSAGE_EVENT, WEBSOCKET_CLIENT_CLOSED_EVENT,
    WEBSOCKET_CLIENT_CONNECTED_EVENT, WEBSOCKET_CLIENT_TEXT_MESSAGE_EVENT,
};

#[derive(Debug, Clone)]
enum Inbound {
    Text(String),
    Binary(Vec<u8>),
}

impl Inbound {
    fn merge(self, next: Inbound) -> std::result::Result<Inbound, (Inbound, Inbound)> {
        match (self, next) {
            (Inbound::Text(mut a), Inbound::Text(b)) => {
                a.push_str(&b);
                Ok(Inbound::Text(a))
            }
            (Inbound::Binary(mut a), Inbound::Binary(b)) => {
                a.extend_from_slice(&b);
                Ok(Inbound::Binary(a))
            }
            (a, b) => Err((a, b)),
        }
    }
}

impl Inbound {
    fn len(&self) -> usize {
        match self {
            Inbound::Text(t) => t.len(),
            Inbound::Binary(b) => b.len(),
        }
    }
}

/// How many messages may wait for the model while a turn is running.
///
/// The read loop must never block on the model — that is the whole point of running it
/// separately, since a read loop that waits stops answering Pings — so a message that does not
/// fit is dropped and logged with `decision=turn_queue_full` rather than stalling the socket.
/// 256 unanswered messages is already many minutes of model time.
const TURN_QUEUE_CAPACITY: usize = 256;

/// Largest message accepted from the server, after inflation when permessage-deflate is on:
/// tungstenite's own default, which this client used before it dialled its own socket.
const MAX_INBOUND_MESSAGE_BYTES: usize = 64 << 20;
/// Largest single frame accepted: tungstenite's own default.
const MAX_INBOUND_FRAME_BYTES: usize = 16 << 20;

/// Whether the client offers RFC 7692 permessage-deflate (`permessage_deflate`).
pub const DEFAULT_PERMESSAGE_DEFLATE: bool = true;

/// The queued payload bytes allowed at once, alongside [`TURN_QUEUE_CAPACITY`].
///
/// The count alone is not a memory bound: tungstenite's default message limit is 64 MiB, so
/// 256 of them would be 16 GiB. 16 MiB caps what a flooding server can pin per client while a
/// turn is parked; one message larger than that is still accepted when the queue is empty,
/// because refusing it outright would make the limit a second, undeclared max message size.
const TURN_QUEUE_MAX_BYTES: usize = 16 * 1024 * 1024;

/// One thing the model is asked about, in arrival order.
enum WsTurn {
    Connected {
        remote_addr: String,
        path: String,
        subprotocol: String,
        permessage_deflate: Option<crate::server::websocket::deflate::DeflateParams>,
    },
    Message(Inbound),
    Closed {
        code: u16,
        reason: String,
    },
}

/// Put a message on the turn queue without ever waiting for room.
fn enqueue_inbound(
    turn_tx: &mpsc::Sender<WsTurn>,
    queued_bytes: &std::sync::atomic::AtomicUsize,
    frame: Inbound,
    client_id: ClientId,
) {
    use std::sync::atomic::Ordering;
    let len = frame.len();
    let already = queued_bytes.load(Ordering::SeqCst);
    if already > 0 && already.saturating_add(len) > TURN_QUEUE_MAX_BYTES {
        warn!(
            "WebSocket client {} dropped a {}-byte message: {} bytes already wait for the model \
             decision=turn_queue_full",
            client_id, len, already
        );
        return;
    }
    queued_bytes.fetch_add(len, Ordering::SeqCst);
    match turn_tx.try_send(WsTurn::Message(frame)) {
        Ok(()) => {}
        Err(mpsc::error::TrySendError::Full(_)) => {
            queued_bytes.fetch_sub(len, Ordering::SeqCst);
            warn!(
                "WebSocket client {} dropped a {}-byte message: {} messages already wait for \
                 the model decision=turn_queue_full",
                client_id, len, TURN_QUEUE_CAPACITY
            );
        }
        // The turn task has ended (aborted with the client); nothing to answer.
        Err(mpsc::error::TrySendError::Closed(_)) => {
            queued_bytes.fetch_sub(len, Ordering::SeqCst);
        }
    }
}

struct ClientData {
    /// The message the model answered `wait_for_websocket_data` to: the next message of the
    /// same kind is joined onto it and the whole is offered again.
    pending: Option<Inbound>,
    memory: String,
}

pub struct WebSocketClient;

impl WebSocketClient {
    /// Connect, run the `websocket_client_connected` event, and start the read loop.
    pub async fn connect_with_llm_actions(
        ctx: crate::protocol::ConnectContext,
    ) -> Result<SocketAddr> {
        let crate::protocol::ConnectContext {
            remote_addr,
            llm_client,
            state: app_state,
            status_tx,
            client_id,
            startup_params,
        } = ctx;

        // Every parameter read here is declared in `get_startup_parameters()`.
        let offer_deflate = match startup_params.as_ref() {
            Some(params) => params
                .get_optional_bool("permessage_deflate")
                .map_err(|e| anyhow::anyhow!("WebSocket client parameter error: {e}"))?
                .unwrap_or(DEFAULT_PERMESSAGE_DEFLATE),
            None => DEFAULT_PERMESSAGE_DEFLATE,
        };
        let (path, subprotocols, extra_headers) = match startup_params.as_ref() {
            Some(params) => {
                let path = params
                    .get_optional_string("path")
                    .map_err(|e| anyhow::anyhow!("WebSocket client parameter error: {e}"))?
                    .unwrap_or_else(|| "/".to_string());
                let subprotocols: Vec<String> = params
                    .get_optional_array("subprotocols")
                    .map_err(|e| anyhow::anyhow!("WebSocket client parameter error: {e}"))?
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(|s| s.trim().to_string()))
                            .filter(|s| !s.is_empty())
                            .collect()
                    })
                    .unwrap_or_default();
                let headers = params
                    .get_optional_object("headers")
                    .map_err(|e| anyhow::anyhow!("WebSocket client parameter error: {e}"))?
                    .map(|obj| {
                        obj.iter()
                            .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                (path, subprotocols, headers)
            }
            None => ("/".to_string(), Vec::new(), Vec::new()),
        };

        let path = if path.starts_with('/') {
            path
        } else {
            format!("/{path}")
        };

        // `remote_addr` may already be a URL (the TUI accepts either); normalise both shapes.
        let url = if remote_addr.starts_with("ws://") {
            remote_addr.clone()
        } else if remote_addr.starts_with("wss://") || remote_addr.starts_with("https://") {
            anyhow::bail!(
                "wss:// is not supported: the WebSocket client is built without a TLS backend. \
                 Use ws:// (optionally behind a local TLS terminator)."
            );
        } else {
            let host = remote_addr
                .trim_start_matches("http://")
                .trim_end_matches('/');
            format!("ws://{host}{path}")
        };

        let mut request = url
            .as_str()
            .into_client_request()
            .with_context(|| format!("Invalid WebSocket URL: {url}"))?;

        if !subprotocols.is_empty() {
            let value = subprotocols.join(", ");
            request.headers_mut().insert(
                "sec-websocket-protocol",
                HeaderValue::from_str(&value)
                    .with_context(|| format!("Invalid subprotocol list: {value:?}"))?,
            );
        }
        for (name, value) in &extra_headers {
            let header_name = HeaderName::from_bytes(name.to_ascii_lowercase().as_bytes())
                .with_context(|| format!("Invalid header name: {name:?}"))?;
            // The handshake headers are computed by the library; silently letting a caller
            // overwrite Sec-WebSocket-Key would break the accept-key check it then performs.
            if matches!(
                header_name.as_str(),
                "sec-websocket-key"
                    | "sec-websocket-version"
                    | "sec-websocket-accept"
                    | "connection"
                    | "upgrade"
                    | "host"
            ) {
                warn!(
                    "WebSocket client ignoring handshake header {:?} supplied in 'headers'",
                    name
                );
                continue;
            }
            request.headers_mut().insert(
                header_name,
                HeaderValue::from_str(value)
                    .with_context(|| format!("Invalid value for header {name:?}"))?,
            );
        }

        if offer_deflate {
            request.headers_mut().insert(
                "sec-websocket-extensions",
                HeaderValue::from_static(crate::server::websocket::deflate::CLIENT_OFFER),
            );
        }

        // The socket is dialled here rather than by `connect_async` so the RFC 7692 layer can
        // sit beneath tungstenite: it reads the 101 itself and switches to frame mode at the
        // exact byte the response head ends.
        let authority = request
            .uri()
            .authority()
            .map(|a| a.to_string())
            .with_context(|| format!("WebSocket URL has no host: {url}"))?;
        let dial = if authority.contains(':') {
            authority
        } else {
            format!("{authority}:80")
        };
        let tcp = tokio::net::TcpStream::connect(&dial)
            .await
            .with_context(|| format!("WebSocket TCP connect to {dial} failed"))?;
        let local_addr = tcp.local_addr()?;
        let config = WebSocketConfig {
            max_message_size: Some(MAX_INBOUND_MESSAGE_BYTES),
            max_frame_size: Some(MAX_INBOUND_FRAME_BYTES),
            ..Default::default()
        };
        let stream = crate::server::websocket::deflate::DeflateStream::client(
            tcp,
            MAX_INBOUND_MESSAGE_BYTES,
            MAX_INBOUND_FRAME_BYTES,
        );
        let (ws_stream, response) =
            tokio_tungstenite::client_async_with_config(request, stream, Some(config))
                .await
                .with_context(|| format!("WebSocket handshake failed against {url}"))?;
        let permessage_deflate = ws_stream.get_ref().active();

        let negotiated = response
            .headers()
            .get("sec-websocket-protocol")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.trim().to_string())
            .unwrap_or_default();

        info!(
            "WebSocket client {} connected to {} (subprotocol {:?}, permessage-deflate {})",
            client_id,
            url,
            negotiated,
            permessage_deflate.is_some()
        );
        app_state
            .update_client_status(client_id, ClientStatus::Connected)
            .await;
        let _ = status_tx.send(format!(
            "[CLIENT] WebSocket client {client_id} connected to {url}"
        ));
        let _ = status_tx.send("__UPDATE_UI__".to_string());

        let (sink, mut stream) = ws_stream.split();
        // The sink is shared rather than owned by the writer task: the injected-command loop
        // writes through it too, and it needs `send`'s own result to report a truthful
        // outcome instead of "queued somewhere". A frame is written under the lock, so the
        // two producers can never interleave halves of a frame.
        let sink = Arc::new(Mutex::new(sink));
        let (out_tx, mut out_rx) = mpsc::unbounded_channel::<WsOut>();

        // One writer for the connection, so frames produced by different handlers cannot
        // interleave and no lock is held across an LLM call.
        let writer_sink = sink.clone();
        let writer_handle = tokio::spawn(async move {
            while let Some(out) = out_rx.recv().await {
                let closing = matches!(out, WsOut::Close { .. });
                let message = ws_out_to_message(out);
                let mut guard = writer_sink.lock().await;
                if let Err(e) = guard.send(message).await {
                    debug!("WebSocket client write failed: {}", e);
                    break;
                }
                if closing {
                    let _ = guard.flush().await;
                    break;
                }
            }
            let _ = writer_sink.lock().await.flush().await;
        });

        let data = Arc::new(Mutex::new(ClientData {
            pending: None,
            memory: String::new(),
        }));

        // Command channel for injected actions (the dashboard's [ send ]). Registered BEFORE
        // the connected-event LLM call below, which a manual `*` rule can park for minutes —
        // the operator has to be able to push a frame out while it waits.
        let command_rx =
            crate::client::command_support::register_command_channel(&app_state, client_id).await;
        let cmd_sink = sink.clone();
        let cmd_state = app_state.clone();
        let cmd_status_tx = status_tx.clone();
        let cmd_task = tokio::spawn(async move {
            Self::command_loop(command_rx, cmd_sink, client_id, cmd_state, cmd_status_tx).await;
        });
        app_state.register_client_task(client_id, cmd_task).await;

        // Two tasks per connection, because the socket and the model run on different clocks.
        // A model turn can take minutes — a `manual` rule parks it for a human for up to 300s —
        // and tungstenite answers a Ping only when the stream is polled: the Pong it queues on
        // reading a Ping is flushed by the *next* read. A read loop that awaited the model
        // stopped doing that, and a server with a liveness bound (NetGet's own closes a peer
        // that sends no frame, not even a Pong, for `idle_timeout_secs`) hung up on it.
        //
        // So the read loop only reads: it answers Pings by polling, and hands every message to
        // the turn task over a queue. The turn task answers them one at a time, in order —
        // `websocket_client_connected` first — which is also what keeps two model turns from
        // ever overlapping on this connection.
        let (turn_tx, turn_rx) = mpsc::channel::<WsTurn>(TURN_QUEUE_CAPACITY);
        let queued_bytes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        // Queued before either task starts, so it is always the first turn.
        let _ = turn_tx.try_send(WsTurn::Connected {
            remote_addr: remote_addr.clone(),
            path: path.clone(),
            subprotocol: negotiated.clone(),
            permessage_deflate,
        });

        let turn_abort = app_state
            .spawn_client_task(
                client_id,
                Self::run_model_turns(
                    turn_rx,
                    client_id,
                    llm_client,
                    app_state.clone(),
                    status_tx.clone(),
                    out_tx.clone(),
                    data,
                    queued_bytes.clone(),
                ),
            )
            .await;

        let read_state = app_state.clone();
        let read_status_tx = status_tx.clone();
        app_state
            .spawn_client_task(client_id, async move {
                let mut clean_close = false;
                while let Some(message) = stream.next().await {
                    match message {
                        Ok(Message::Text(text)) => {
                            trace!("WebSocket client {} <- text {:?}", client_id, text);
                            enqueue_inbound(
                                &turn_tx,
                                &queued_bytes,
                                Inbound::Text(text),
                                client_id,
                            );
                        }
                        Ok(Message::Binary(bytes)) => {
                            trace!(
                                "WebSocket client {} <- binary {} bytes: {}",
                                client_id,
                                bytes.len(),
                                hex::encode(&bytes)
                            );
                            enqueue_inbound(
                                &turn_tx,
                                &queued_bytes,
                                Inbound::Binary(bytes),
                                client_id,
                            );
                        }
                        Ok(Message::Ping(_)) => {
                            // tungstenite queued the Pong; the next `stream.next()` flushes it.
                            debug!("WebSocket client {} <- ping (pong queued)", client_id);
                        }
                        Ok(Message::Pong(_)) => {
                            debug!("WebSocket client {} <- pong", client_id);
                        }
                        Ok(Message::Close(frame)) => {
                            let (code, reason) = match &frame {
                                Some(f) => (u16::from(f.code), f.reason.to_string()),
                                None => (1005u16, String::new()),
                            };
                            info!(
                                "WebSocket client {} closed by server: code={} reason={:?}",
                                client_id, code, reason
                            );
                            // Behind whatever is already queued, so the model hears about the
                            // close after the messages that preceded it.
                            if turn_tx.try_send(WsTurn::Closed { code, reason }).is_err() {
                                warn!(
                                    "WebSocket client {} could not queue its close event \
                                     decision=turn_queue_full",
                                    client_id
                                );
                            }
                            clean_close = true;
                            break;
                        }
                        Ok(Message::Frame(_)) => {}
                        Err(e) => {
                            debug!("WebSocket client {} read ended: {}", client_id, e);
                            break;
                        }
                    }
                }

                if !clean_close {
                    // The socket died without a Close: there is no event to report, and a turn
                    // still running — or parked for a human — has nothing left to answer on.
                    turn_abort.abort();
                }
                read_state
                    .update_client_status(client_id, ClientStatus::Disconnected)
                    .await;
                // Every exit path lands here: drop the command handle so the dashboard stops
                // offering [ send ] on a dead connection, and so the command loop's channel
                // closes and its task ends.
                read_state.remove_client_handle(client_id).await;
                let _ =
                    read_status_tx.send(format!("[CLIENT] WebSocket client {client_id} closed"));
                let _ = read_status_tx.send("__UPDATE_UI__".to_string());
            })
            .await;

        // The writer ends when every sender is dropped, which happens when the turn task and
        // its clones go away. Nothing waits on it here so `connect` can return promptly.
        drop(writer_handle);
        drop(out_tx);

        Ok(local_addr)
    }

    /// Answer queued messages with the model, one at a time and in arrival order.
    #[allow(clippy::too_many_arguments)]
    async fn run_model_turns(
        mut turn_rx: mpsc::Receiver<WsTurn>,
        client_id: ClientId,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        out_tx: mpsc::UnboundedSender<WsOut>,
        data: Arc<Mutex<ClientData>>,
        queued_bytes: Arc<std::sync::atomic::AtomicUsize>,
    ) {
        while let Some(turn) = turn_rx.recv().await {
            match turn {
                WsTurn::Connected {
                    remote_addr,
                    path,
                    subprotocol,
                    permessage_deflate,
                } => {
                    Self::emit_connected(
                        client_id,
                        remote_addr,
                        path,
                        subprotocol,
                        permessage_deflate,
                        &llm_client,
                        &app_state,
                        &status_tx,
                        &out_tx,
                        &data,
                    )
                    .await;
                }
                WsTurn::Message(frame) => {
                    queued_bytes.fetch_sub(frame.len(), std::sync::atomic::Ordering::SeqCst);
                    // This message, plus - with batching on - every message already waiting:
                    // what the server sent while the model answered the previous turn. A close
                    // found while sweeping is answered after them, as it arrived.
                    let mut frames = vec![frame];
                    let mut closed: Option<(u16, String)> = None;
                    if app_state
                        .client_conversation_settings(client_id)
                        .await
                        .is_some_and(|(_, batching)| batching)
                    {
                        while frames.len() < crate::protocol::metadata::MAX_BATCH_EVENTS {
                            match turn_rx.try_recv() {
                                Ok(WsTurn::Message(more)) => {
                                    queued_bytes
                                        .fetch_sub(more.len(), std::sync::atomic::Ordering::SeqCst);
                                    frames.push(more);
                                }
                                Ok(WsTurn::Closed { code, reason }) => {
                                    closed = Some((code, reason));
                                    break;
                                }
                                // Queued once, before either task starts: never behind a message.
                                Ok(WsTurn::Connected { .. }) => {}
                                Err(_) => break,
                            }
                        }
                    }
                    Self::handle_inbound(
                        frames,
                        client_id,
                        &llm_client,
                        &app_state,
                        &status_tx,
                        &out_tx,
                        &data,
                    )
                    .await;
                    if let Some((code, reason)) = closed {
                        Self::emit_closed(
                            client_id,
                            code,
                            reason,
                            &llm_client,
                            &app_state,
                            &status_tx,
                            &out_tx,
                            &data,
                        )
                        .await;
                        break;
                    }
                }
                WsTurn::Closed { code, reason } => {
                    Self::emit_closed(
                        client_id,
                        code,
                        reason,
                        &llm_client,
                        &app_state,
                        &status_tx,
                        &out_tx,
                        &data,
                    )
                    .await;
                    break;
                }
            }
        }
    }

    /// `websocket_client_connected` — the client's chance to speak first.
    #[allow(clippy::too_many_arguments)]
    async fn emit_connected(
        client_id: ClientId,
        remote_addr: String,
        path: String,
        subprotocol: String,
        permessage_deflate: Option<crate::server::websocket::deflate::DeflateParams>,
        llm_client: &OllamaClient,
        app_state: &Arc<AppState>,
        status_tx: &mpsc::UnboundedSender<String>,
        out_tx: &mpsc::UnboundedSender<WsOut>,
        data: &Arc<Mutex<ClientData>>,
    ) {
        let Some(instruction) = app_state.get_instruction_for_client(client_id).await else {
            return;
        };
        let event = Event::new(
            &WEBSOCKET_CLIENT_CONNECTED_EVENT,
            serde_json::json!({
                "remote_addr": remote_addr,
                "path": path,
                "subprotocol": subprotocol,
                "permessage_deflate": permessage_deflate.map(|p| p.to_json()),
            }),
        );
        let protocol = WebSocketClientProtocol::for_connection(out_tx.clone());
        let memory = { data.lock().await.memory.clone() };
        match call_llm_for_client(
            llm_client,
            app_state,
            client_id.to_string(),
            &instruction,
            &memory,
            Some(&event),
            &protocol,
            status_tx,
        )
        .await
        {
            Ok(ClientLlmResult {
                actions,
                memory_updates,
            }) => {
                if let Some(mem) = memory_updates {
                    data.lock().await.memory = mem;
                }
                for action in actions {
                    if let Err(e) = protocol.execute_action(action) {
                        error!("WebSocket client action failed after connect: {}", e);
                        let _ = status_tx.send(format!("[CLIENT] WebSocket action failed: {e}"));
                    }
                }
            }
            Err(e) => {
                error!("LLM error on websocket_client_connected: {}", e);
                let _ = status_tx.send(format!("[CLIENT] WebSocket LLM error: {e}"));
            }
        }
    }

    /// Drain injected commands until the channel closes (the client was removed, or the read
    /// loop exited) or an injected close/disconnect ends the session.
    ///
    /// The generic `command_support::handle_stream_client_command` cannot serve this client:
    /// its write half is a `Sink<Message>`, not an `AsyncWrite`, and every wire verb yields
    /// `ClientActionResult::Custom`. So the action is executed through the protocol's **own**
    /// `execute_action` — the same code the LLM path runs, including the RFC 6455 validation
    /// of close codes and ping payload lengths — against a private frame channel that this
    /// loop then drains and writes itself. That is what makes a truthful byte count possible:
    /// the frames are written and flushed here, not handed to another task.
    async fn command_loop<S>(
        mut command_rx: mpsc::Receiver<crate::state::client_handles::ClientCommand>,
        sink: Arc<Mutex<S>>,
        client_id: ClientId,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
    ) where
        S: futures::Sink<Message> + Unpin + Send,
        S::Error: std::fmt::Display,
    {
        use crate::llm::actions::protocol_trait::Protocol;
        use crate::state::client_handles::ClientSendOutcome;
        use crate::state::AccessLogOwner;

        // A private frame channel, drained synchronously below, so `execute_action` produces
        // exactly the frames this command asked for and nothing else can be attributed to it.
        let (frame_tx, mut frame_rx) = mpsc::unbounded_channel::<WsOut>();
        let protocol = WebSocketClientProtocol::for_connection(frame_tx);

        while let Some(command) = command_rx.recv().await {
            let action = command.action.clone();
            let executed = protocol.execute_action(action.clone());

            // Whatever `execute_action` queued belongs to this command.
            let mut frames: Vec<WsOut> = Vec::new();
            while let Ok(frame) = frame_rx.try_recv() {
                frames.push(frame);
            }

            let mut bytes_sent = 0usize;
            let mut write_error: Option<String> = None;
            for frame in frames {
                // Payload bytes: the RFC 6455 header and the client mask are added by the
                // framing layer and are not reported here.
                let payload_len = match &frame {
                    WsOut::Text(t) => t.len(),
                    WsOut::Binary(b) => b.len(),
                    WsOut::Ping(p) => p.len(),
                    WsOut::Close { reason, .. } => reason.len(),
                };
                let message = ws_out_to_message(frame);
                let mut guard = sink.lock().await;
                match guard.send(message).await {
                    // `SinkExt::send` flushes, so the bytes really are on the socket.
                    Ok(()) => bytes_sent += payload_len,
                    Err(e) => {
                        write_error = Some(e.to_string());
                        break;
                    }
                }
            }

            let outcome: anyhow::Result<ClientSendOutcome> = match (&executed, &write_error) {
                (_, Some(e)) => Err(anyhow::anyhow!("WebSocket write failed: {e}")),
                (Err(e), None) => Ok(ClientSendOutcome::Rejected {
                    error: e.to_string(),
                }),
                (Ok(ClientActionResult::Disconnect), None) => Ok(ClientSendOutcome::Disconnected),
                (Ok(ClientActionResult::WaitForMore), None) => Ok(ClientSendOutcome::Executed {
                    detail: "wait_for_websocket_data: nothing written".to_string(),
                }),
                (Ok(_), None) => {
                    if bytes_sent > 0 {
                        Ok(ClientSendOutcome::Sent { bytes_sent })
                    } else {
                        Ok(ClientSendOutcome::Executed {
                            detail: "executed; the frame carried an empty payload".to_string(),
                        })
                    }
                }
            };

            let outcome_json = match &outcome {
                Ok(outcome) => serde_json::to_value(outcome).unwrap_or(serde_json::Value::Null),
                Err(e) => serde_json::json!({"error": e.to_string()}),
            };
            app_state
                .record_access_log(
                    AccessLogOwner::Client(client_id.as_u32()),
                    protocol.protocol_name(),
                    None,
                    "injected_action",
                    action,
                    vec![outcome_json],
                )
                .await;

            let disconnect = matches!(outcome, Ok(ClientSendOutcome::Disconnected));
            if let Err(e) = &outcome {
                error!(
                    "WebSocket client {} injected action failed: {}",
                    client_id, e
                );
                let _ = status_tx.send(format!(
                    "[WARN] Client {client_id} injected action failed: {e}"
                ));
            }
            let _ = status_tx.send("__UPDATE_UI__".to_string());
            crate::client::command_support::reply(command, outcome);

            if disconnect || write_error.is_some() {
                // `close_websocket` already put the closing frame on the wire above; closing
                // the sink ends the TCP side so the read loop sees the connection go away.
                let _ = sink.lock().await.close().await;
                // Drop the handle here rather than waiting for the read loop: it may still be
                // inside the `websocket_client_closed` LLM call, and this client cannot accept
                // another command either way.
                app_state.remove_client_handle(client_id).await;
                let _ = status_tx.send("__UPDATE_UI__".to_string());
                break;
            }
        }
    }

    /// Answer one or more messages - several when they arrived during the previous turn and
    /// the client batches - in one model call through `call_llm_for_client_batch`, one event
    /// per message, the newest the trigger.
    #[allow(clippy::too_many_arguments)]
    async fn handle_inbound(
        mut frames: Vec<Inbound>,
        client_id: ClientId,
        llm_client: &OllamaClient,
        app_state: &Arc<AppState>,
        status_tx: &mpsc::UnboundedSender<String>,
        out_tx: &mpsc::UnboundedSender<WsOut>,
        data: &Arc<Mutex<ClientData>>,
    ) {
        // A message held by `wait_for_websocket_data` is the front of the first one: joined
        // when they are of the same kind, offered just before it otherwise.
        if let Some(pending) = data.lock().await.pending.take() {
            let first = frames.remove(0);
            match pending.merge(first) {
                Ok(merged) => frames.insert(0, merged),
                Err((held, new)) => {
                    frames.insert(0, new);
                    frames.insert(0, held);
                }
            }
        }

        let Some(instruction) = app_state.get_instruction_for_client(client_id).await else {
            return;
        };

        let events: Vec<Event> = frames
            .iter()
            .map(|frame| match frame {
                Inbound::Text(text) => Event::new(
                    &WEBSOCKET_CLIENT_TEXT_MESSAGE_EVENT,
                    serde_json::json!({ "text": text, "message_bytes": text.len() }),
                ),
                Inbound::Binary(bytes) => {
                    let (payload, encoding) = encode_inbound_payload(bytes);
                    Event::new(
                        &WEBSOCKET_CLIENT_BINARY_MESSAGE_EVENT,
                        serde_json::json!({
                            "data": payload,
                            "encoding": encoding,
                            "message_bytes": bytes.len(),
                        }),
                    )
                }
            })
            .collect();

        let protocol = WebSocketClientProtocol::for_connection(out_tx.clone());
        let memory = { data.lock().await.memory.clone() };

        match call_llm_for_client_batch(
            llm_client,
            app_state,
            client_id.to_string(),
            &instruction,
            &memory,
            &events,
            &protocol,
            status_tx,
        )
        .await
        {
            Ok(ClientLlmResult {
                actions,
                memory_updates,
            }) => {
                if let Some(mem) = memory_updates {
                    data.lock().await.memory = mem;
                }
                let mut should_wait = false;
                let mut should_stop = false;
                for action in actions {
                    match protocol.execute_action(action) {
                        Ok(ClientActionResult::WaitForMore) => should_wait = true,
                        Ok(ClientActionResult::Disconnect) => should_stop = true,
                        Ok(_) => {}
                        Err(e) => {
                            error!("WebSocket client action failed: {}", e);
                            let _ =
                                status_tx.send(format!("[CLIENT] WebSocket action failed: {e}"));
                        }
                    }
                }
                // In a batch the wait is for the newest message; the earlier ones were whole
                // messages the model has answered.
                if should_wait && !should_stop {
                    data.lock().await.pending = frames.pop();
                }
            }
            Err(e) => {
                error!("LLM error for WebSocket client {}: {}", client_id, e);
                let _ = status_tx.send(format!("[CLIENT] WebSocket LLM error: {e}"));
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn emit_closed(
        client_id: ClientId,
        code: u16,
        reason: String,
        llm_client: &OllamaClient,
        app_state: &Arc<AppState>,
        status_tx: &mpsc::UnboundedSender<String>,
        out_tx: &mpsc::UnboundedSender<WsOut>,
        data: &Arc<Mutex<ClientData>>,
    ) {
        let Some(instruction) = app_state.get_instruction_for_client(client_id).await else {
            return;
        };
        let event = Event::new(
            &WEBSOCKET_CLIENT_CLOSED_EVENT,
            serde_json::json!({ "code": code, "reason": reason }),
        );
        let protocol = WebSocketClientProtocol::for_connection(out_tx.clone());
        let memory = { data.lock().await.memory.clone() };
        match call_llm_for_client(
            llm_client,
            app_state,
            client_id.to_string(),
            &instruction,
            &memory,
            Some(&event),
            &protocol,
            status_tx,
        )
        .await
        {
            Ok(ClientLlmResult {
                actions,
                memory_updates,
            }) => {
                // The socket is closed, so a `send_message` here has nowhere to go — but the
                // pattern used to be `{ memory_updates, .. }`, which dropped the actions
                // without saying so. Reporting them means an operator can see the model tried
                // to answer a close with a send, which is a prompt worth fixing rather than a
                // silence.
                if !actions.is_empty() {
                    let _ = status_tx.send(format!(
                        "[CLIENT] WebSocket client {} is closed; {} action(s) from \
                         websocket_client_closed were not sent",
                        client_id,
                        actions.len()
                    ));
                }
                if let Some(mem) = memory_updates {
                    data.lock().await.memory = mem;
                }
            }
            Err(e) => debug!("WebSocket client close handler failed: {}", e),
        }
    }
}

/// Turn one outbound frame request into a tungstenite message. Shared by the writer task and
/// the injected-command loop so the two cannot encode a frame differently.
fn ws_out_to_message(out: WsOut) -> Message {
    match out {
        WsOut::Text(t) => Message::Text(t),
        WsOut::Binary(b) => Message::Binary(b),
        WsOut::Ping(p) => Message::Ping(p),
        WsOut::Close { code, reason } => Message::Close(Some(CloseFrame {
            code: CloseCode::from(code),
            reason: reason.into(),
        })),
    }
}

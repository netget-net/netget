//! Nostr relay (NIP-01 over WebSocket, NIP-11 on plain HTTP) — the model is the relay's policy
//! and its archive.
//!
//! One TCP connection carries one HTTP request head. What it asks for decides the rest:
//!
//! - **a WebSocket upgrade** — the handshake is answered here (`http.rs`) and the socket is
//!   handed to tungstenite for framing; every text frame is a NIP-01 message;
//! - **a GET with `Accept: application/nostr+json`** — the NIP-11 document, built from startup
//!   parameters, with no model call;
//! - **anything else** — a one-line page for a browser, a CORS preflight, or an HTTP error.
//!
//! # Who decides what
//!
//! NetGet owns everything NIP-01 makes mechanical, and none of it costs a model call:
//!
//! 1. **An event's id and signature.** `wire::verify_event` recomputes the id and checks the
//!    BIP-340 signature; a forged or corrupted event is answered `OK false "invalid: …"` and
//!    never reaches the model.
//! 2. **Malformed messages, subscription limits, `CLOSE`.** Answered `NOTICE` or `CLOSED`, or,
//!    for `CLOSE`, simply done.
//! 3. **Framing of every answer.** The model says accept or reject; NetGet writes the `OK`. The
//!    model supplies kinds, contents and tags; NetGet signs them with the relay's key
//!    (`wire::RelayKey`), drops any the subscription's own filters exclude, sends them, then
//!    `EOSE`.
//! 4. **Delivery.** An event the model accepts is sent at once to every open subscription it
//!    matches, on every connection. It is not kept.
//!
//! The model decides: whether each published event is taken (`nostr_event`), and which events
//! answer each subscription (`nostr_req`).
//!
//! # Failure is an answer, never silence
//!
//! A published event whose decision cannot be made — backend down, a model that answered
//! nothing — is refused: `OK false "error: …"`, or `"rate-limited: …"` when the backend is
//! overloaded. A subscription that cannot be answered is `CLOSED` the same way. Silence on an
//! `EVENT` would leave the publisher waiting; accepting would be fail-open. The texts are fixed
//! literals; the error itself goes to the log with `decision=fail_closed_llm_error`.
//!
//! # One connection, three futures, one task
//!
//! The reader (frames in, mechanical answers, idle watchdog), the worker (one message at a time
//! to the model, in arrival order) and the writer (the only thing that writes to the socket)
//! run inside the connection's own tracked task, so `stop_server` aborting that task ends all
//! three. Messages wait for the worker in a queue of [`MAX_QUEUED_MESSAGES`]; past it a
//! published event is refused `rate-limited:` rather than buffered without bound.

pub mod actions;
pub mod http;
pub mod subscriptions;
pub mod wire;

use crate::llm::action_helper::call_llm;
use crate::llm::actions::protocol_trait::ActionResult;
use crate::llm::ollama_client::OllamaClient;
use crate::logging::emit::Log;
use crate::protocol::Event;
use crate::server::accept_bounded::{ConnectionActivity, ConnectionPermit};
use crate::server::connection::ConnectionId;
use crate::state::app_state::AppState;
use crate::state::server::{ConnectionState, ConnectionStatus, ProtocolConnectionInfo};
use crate::state::ServerId;
use actions::NostrProtocol;
use anyhow::Result;
use futures::stream::{SplitSink, SplitStream, StreamExt};
use futures::SinkExt;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use subscriptions::{ConnShared, Outbound, Relay};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::protocol::{CloseFrame, Role, WebSocketConfig};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;
use wire::{ClientMessage, RelayKey};

pub use wire::MAX_MESSAGE_BYTES;

/// How long a connected peer has to send its whole HTTP request head. Every Nostr client sends
/// the upgrade at once; nothing in this phase involves the model or a human.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// How long an open WebSocket may go without a single frame from the client.
///
/// A subscription is entitled to sit open with nothing arriving, so the bound is on the peer's
/// liveness: at half of it the relay sends a Ping, every RFC 6455 endpoint answers by itself,
/// and a Pong is a frame. What reaches the bound is a peer that stopped reading or vanished
/// without a FIN. Never fires while a message is being answered — a model call, or a `manual`
/// rule parked for a human (300 s by default; this is twice that, as in `websocket`). Declared
/// as `idle_timeout_secs`.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(600);

/// Concurrent connections admitted before new ones are refused — the house default.
const MAX_CONNECTIONS: usize = crate::server::accept_bounded::DEFAULT_MAX_CONNECTIONS;

/// Messages waiting for the worker on one connection. Mechanical answers (refusals, `CLOSE`)
/// do not queue; only what needs the model does.
pub const MAX_QUEUED_MESSAGES: usize = 64;

/// How long to wait for the other side of a closing handshake, and for queued frames to drain,
/// once a connection is ending.
const CLOSE_GRACE: Duration = Duration::from_secs(5);

/// What a peer over [`MAX_CONNECTIONS`] gets. A Nostr client is a WebSocket client and so an
/// HTTP client first (RFC 6455 §4.1): 503 with `Retry-After` is the refusal every client
/// reports as a failed handshake.
static CONNECTION_CAP_REFUSAL: std::sync::LazyLock<Vec<u8>> = std::sync::LazyLock::new(|| {
    http::response(
        503,
        "text/plain; charset=utf-8",
        "Retry-After: 30\r\n",
        "Too many connections, try again later\n",
    )
});

/// Fixed texts NetGet answers with when the model cannot. Nothing from an error reaches a peer.
const EVENT_UNAVAILABLE: &str = "error: the relay could not decide on this event";
const EVENT_OVERLOADED: &str = "rate-limited: the relay is at capacity, retry later";
const EVENT_UNDECIDED: &str = "error: the relay made no decision on this event";
const REQ_UNAVAILABLE: &str = "error: the relay could not answer this subscription";
const REQ_OVERLOADED: &str = "rate-limited: the relay is at capacity, retry later";
const QUEUE_FULL: &str = "rate-limited: too many messages waiting on this connection";

/// Startup configuration, resolved from parameters.
#[derive(Debug, Clone)]
pub struct RelayConfig {
    pub info: http::RelayInfo,
    pub handshake_timeout: Duration,
    pub idle_timeout: Duration,
}

/// What every connection of one relay shares.
struct ServerShared {
    llm_client: OllamaClient,
    app_state: Arc<AppState>,
    status_tx: mpsc::UnboundedSender<String>,
    server_id: ServerId,
    key: Arc<RelayKey>,
    relay: Relay,
    config: RelayConfig,
    info_document: serde_json::Value,
    local_addr: SocketAddr,
}

impl ServerShared {
    fn log(&self) -> Log<'_> {
        Log::new(Some(&self.status_tx))
    }
}

pub struct NostrServer;

impl NostrServer {
    pub async fn spawn_with_llm_actions(
        listen_addr: SocketAddr,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        server_id: ServerId,
        key: Arc<RelayKey>,
        config: RelayConfig,
    ) -> Result<SocketAddr> {
        let listener =
            crate::server::socket_helpers::create_reusable_tcp_listener(listen_addr).await?;
        let local_addr = listener.local_addr()?;
        Log::new(Some(&status_tx)).info(format!(
            "Nostr relay listening on {} (ws://{}), relay pubkey {}",
            local_addr,
            local_addr,
            key.pubkey_hex()
        ));

        let shared = Arc::new(ServerShared {
            llm_client,
            app_state: app_state.clone(),
            status_tx: status_tx.clone(),
            server_id,
            key,
            relay: Relay::new(),
            info_document: config.info.document(),
            config,
            local_addr,
        });

        let limiter = crate::server::accept_bounded::ConnectionLimiter::new(MAX_CONNECTIONS);
        let accept_shared = shared.clone();
        let accept_handle = tokio::spawn(async move {
            loop {
                match crate::server::accept_bounded::accept_bounded(
                    &listener,
                    &limiter,
                    &CONNECTION_CAP_REFUSAL,
                    "Nostr",
                    Some(&accept_shared.status_tx),
                )
                .await
                {
                    Ok((socket, peer_addr, permit)) => {
                        let shared = accept_shared.clone();
                        // Tracked, not detached: stop_server must abort this task too.
                        accept_shared
                            .app_state
                            .spawn_server_task(server_id, async move {
                                handle_connection(shared, socket, peer_addr, permit).await;
                            })
                            .await;
                    }
                    Err(e) => {
                        accept_shared
                            .log()
                            .error(format!("Nostr accept error: {}", e));
                        break;
                    }
                }
            }
        });

        app_state
            .register_server_task(server_id, accept_handle)
            .await;
        let _ = status_tx.send("__UPDATE_UI__".to_string());
        Ok(local_addr)
    }
}

/// One accepted connection, start to finish. The permit is held for all of it, so
/// [`MAX_CONNECTIONS`] caps live connections.
async fn handle_connection(
    server: Arc<ServerShared>,
    socket: TcpStream,
    peer_addr: SocketAddr,
    _permit: ConnectionPermit,
) {
    let connection_id = ConnectionId::new(server.app_state.get_next_unified_id().await);
    let now = crate::utils::clock::Instant::now();
    server
        .app_state
        .add_connection_to_server(
            server.server_id,
            ConnectionState {
                id: connection_id,
                remote_addr: peer_addr,
                local_addr: server.local_addr,
                bytes_sent: 0,
                bytes_received: 0,
                packets_sent: 0,
                packets_received: 0,
                last_activity: now,
                status: ConnectionStatus::Active,
                status_changed_at: now,
                protocol_info: ProtocolConnectionInfo::new(serde_json::json!({"state": "HTTP"})),
            },
        )
        .await;
    let _ = server.status_tx.send("__UPDATE_UI__".to_string());

    serve(&server, socket, peer_addr, connection_id).await;

    server
        .app_state
        .remove_peer_handle(server.server_id, connection_id.as_u32())
        .await;
    server.relay.remove(connection_id.as_u32());
    server
        .app_state
        .close_connection_on_server(server.server_id, connection_id)
        .await;
    let _ = server.status_tx.send("__UPDATE_UI__".to_string());
}

/// Why reading the request head stopped.
enum HeadRead {
    Head(Vec<u8>, Vec<u8>),
    TooLarge,
    Closed,
}

async fn read_head(socket: &mut TcpStream) -> HeadRead {
    let mut buf: Vec<u8> = Vec::with_capacity(1024);
    let mut chunk = [0u8; 2048];
    loop {
        if let Some(pos) = http::find_head_end(&buf) {
            let leftover = buf.split_off(pos + 4);
            buf.truncate(pos);
            return HeadRead::Head(buf, leftover);
        }
        if buf.len() > http::MAX_REQUEST_HEAD {
            return HeadRead::TooLarge;
        }
        match socket.read(&mut chunk).await {
            Ok(0) | Err(_) => return HeadRead::Closed,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
}

async fn reply_and_close(
    server: &ServerShared,
    socket: &mut TcpStream,
    connection_id: ConnectionId,
    bytes: &[u8],
) {
    if socket.write_all(bytes).await.is_ok() {
        let _ = socket.flush().await;
        server
            .app_state
            .update_connection_stats(
                server.server_id,
                connection_id,
                None,
                Some(bytes.len() as u64),
                None,
                Some(1),
            )
            .await;
    }
    let _ = socket.shutdown().await;
}

async fn serve(
    server: &Arc<ServerShared>,
    mut socket: TcpStream,
    peer_addr: SocketAddr,
    connection_id: ConnectionId,
) {
    let log = server.log();
    let (head_bytes, leftover) =
        match tokio::time::timeout(server.config.handshake_timeout, read_head(&mut socket)).await {
            Err(_) => {
                log.info(format!(
                    "Nostr peer {} sent no complete request within {}s; closing \
                 decision=fail_closed_handshake_timeout",
                    peer_addr,
                    server.config.handshake_timeout.as_secs()
                ));
                let reply = http::error_response(408, "Timed out waiting for the HTTP request");
                reply_and_close(server, &mut socket, connection_id, &reply).await;
                return;
            }
            Ok(HeadRead::TooLarge) => {
                log.warn(format!(
                    "Nostr peer {} sent a request head over {} bytes \
                 decision=fail_closed_head_too_large",
                    peer_addr,
                    http::MAX_REQUEST_HEAD
                ));
                let reply = http::error_response(431, "Request head too large");
                reply_and_close(server, &mut socket, connection_id, &reply).await;
                return;
            }
            Ok(HeadRead::Closed) => return,
            Ok(HeadRead::Head(head, leftover)) => (head, leftover),
        };
    server
        .app_state
        .update_connection_stats(
            server.server_id,
            connection_id,
            Some(head_bytes.len() as u64 + 4),
            None,
            Some(1),
            None,
        )
        .await;

    let head = match http::parse_request_head(&head_bytes) {
        Ok(head) => head,
        Err(why) => {
            log.info(format!(
                "Nostr peer {} sent a malformed request ({}) decision=fail_closed_malformed",
                peer_addr, why
            ));
            let reply = http::error_response(400, "Malformed HTTP request");
            reply_and_close(server, &mut socket, connection_id, &reply).await;
            return;
        }
    };

    if head.wants_upgrade() {
        let key = match http::validate_upgrade(&head) {
            Ok(key) => key,
            Err((status, reason)) => {
                log.info(format!(
                    "Nostr upgrade from {} refused ({} {}) decision=fail_closed_bad_upgrade",
                    peer_addr, status, reason
                ));
                let reply = http::error_response(status, reason);
                reply_and_close(server, &mut socket, connection_id, &reply).await;
                return;
            }
        };
        if socket
            .write_all(http::accept_response(&key).as_bytes())
            .await
            .is_err()
        {
            return;
        }
        let _ = socket.flush().await;
        session(server, socket, leftover, peer_addr, connection_id).await;
        return;
    }

    let reply = if head.method.eq_ignore_ascii_case("OPTIONS") {
        http::preflight_response()
    } else if !head.method.eq_ignore_ascii_case("GET") {
        http::error_response(
            405,
            "A Nostr relay answers GET: a WebSocket upgrade or NIP-11",
        )
    } else if head.wants_relay_info() {
        log.info(format!(
            "Nostr NIP-11 relay information to {} decision=relay_info",
            peer_addr
        ));
        http::relay_info_response(&server.info_document)
    } else {
        http::browser_response()
    };
    reply_and_close(server, &mut socket, connection_id, &reply).await;
}

/// Writes one connection's injected actions (the dashboard's `[ message ]`, MCP
/// `send_to_peer`) as WebSocket frames: every `write` is one relay message, a shutdown is a
/// close frame. `peer_support` writes each rendered frame with one `write_all`.
struct FrameWriter {
    tx: crate::utils::outbox::OutboxSender<Outbound>,
}

impl tokio::io::AsyncWrite for FrameWriter {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let text = String::from_utf8_lossy(buf).into_owned();
        std::task::Poll::Ready(
            self.tx
                .send(Outbound::Text(text))
                .map(|_| buf.len())
                .map_err(|_| std::io::Error::new(std::io::ErrorKind::BrokenPipe, "closed")),
        )
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let _ = self.tx.send(Outbound::Close {
            code: 1000,
            reason: "closed by the relay operator".to_string(),
        });
        std::task::Poll::Ready(Ok(()))
    }
}

/// Something that needs the model, waiting its turn.
enum Job {
    Event(wire::Event),
    Req {
        subscription_id: String,
        generation: u64,
        filters: Vec<wire::Filter>,
    },
}

/// How the reader stopped.
enum ReaderExit {
    PeerClosed,
    Idle,
    TooBig,
    Error,
}

/// Everything one open WebSocket's three futures share.
struct Session {
    server: Arc<ServerShared>,
    conn: Arc<ConnShared>,
    protocol: Arc<NostrProtocol>,
    activity: Arc<ConnectionActivity>,
    connection_id: ConnectionId,
}

async fn session(
    server: &Arc<ServerShared>,
    socket: TcpStream,
    leftover: Vec<u8>,
    peer_addr: SocketAddr,
    connection_id: ConnectionId,
) {
    let ws_config = WebSocketConfig {
        max_message_size: Some(wire::MAX_MESSAGE_BYTES),
        max_frame_size: Some(wire::MAX_MESSAGE_BYTES),
        // RFC 6455 §5.1: a server MUST fail the connection on an unmasked client frame.
        accept_unmasked_frames: false,
        ..Default::default()
    };
    // `from_partially_read`: a client may pipeline its first message behind the request head.
    // Taken before the socket is wrapped: cutting off a subscriber that does not read ends its
    // connection.
    let closer = crate::utils::outbox::ConnectionCloser::for_stream(&socket);
    let ws =
        WebSocketStream::from_partially_read(socket, leftover, Role::Server, Some(ws_config)).await;
    let (sink, stream) = ws.split();

    // Bounded: an accepted EVENT is broadcast to every matching subscription, so a subscriber
    // that stops reading is cut off rather than queued for (`utils::outbox`).
    let (out_tx, out_rx) = crate::utils::outbox::channel(
        format!("Nostr connection {connection_id}"),
        crate::utils::outbox::OutboxLimits::DEFAULT,
        Outbound::weight,
    );
    out_tx.close_on_cut_off(closer);
    let conn = Arc::new(ConnShared::new(connection_id.as_u32(), out_tx.clone()));
    server.relay.add(conn.clone());
    let protocol = Arc::new(NostrProtocol::for_connection(
        server.key.clone(),
        conn.clone(),
    ));

    let peer_rx = crate::server::peer_support::register_peer_channel(
        &server.app_state,
        server.server_id,
        connection_id.as_u32(),
    )
    .await;
    crate::server::peer_support::spawn_peer_command_task(
        peer_rx,
        protocol.clone(),
        server.app_state.clone(),
        server.server_id,
        connection_id.as_u32(),
        Arc::new(Mutex::new(FrameWriter { tx: out_tx.clone() })),
        server.status_tx.clone(),
    );

    server
        .app_state
        .with_server_mut(server.server_id, |instance| {
            if let Some(c) = instance.connections.get_mut(&connection_id) {
                c.protocol_info = ProtocolConnectionInfo::new(serde_json::json!({
                    "state": "WebSocket",
                }));
            }
        })
        .await;
    server.log().info(format!(
        "Nostr client {} connected from {}",
        connection_id, peer_addr
    ));

    let session = Session {
        server: server.clone(),
        conn,
        protocol,
        activity: Arc::new(ConnectionActivity::new()),
        connection_id,
    };
    let (job_tx, job_rx) = mpsc::channel::<Job>(MAX_QUEUED_MESSAGES);

    let writer = session.write_frames(sink, out_rx);
    let reader = session.read_frames(stream, job_tx);
    let worker = session.answer_jobs(job_rx);
    tokio::pin!(writer, reader, worker);

    let exit = tokio::select! {
        exit = &mut reader => Some(exit),
        _ = &mut writer => None,
        // Ends only once the reader has dropped the queue's sender, i.e. never first.
        _ = &mut worker => None,
    };
    match exit {
        // The writer sent a close frame (the model's close_connection, the operator's
        // disconnect) or failed: give the peer a moment to answer the close.
        None => {
            let _ = tokio::time::timeout(CLOSE_GRACE, &mut reader).await;
        }
        Some(exit) => {
            match exit {
                ReaderExit::Idle => {
                    session.server.log().info(format!(
                        "Nostr {} sent no frame for {}s, not even a Pong; closing \
                         decision=fail_closed_idle_timeout",
                        connection_id,
                        session.server.config.idle_timeout.as_secs()
                    ));
                    let _ = out_tx.send(Outbound::Close {
                        code: 1001,
                        reason: "idle timeout".to_string(),
                    });
                }
                ReaderExit::TooBig => {
                    session.server.log().warn(format!(
                        "Nostr {} sent a message over {} bytes; closing with 1009 \
                         decision=fail_closed_message_too_large",
                        connection_id,
                        wire::MAX_MESSAGE_BYTES
                    ));
                    let _ = out_tx.send(Outbound::Close {
                        code: 1009,
                        reason: "message too big".to_string(),
                    });
                }
                ReaderExit::PeerClosed | ReaderExit::Error => {}
            }
            let _ = out_tx.send(Outbound::Shutdown);
            let _ = tokio::time::timeout(CLOSE_GRACE, &mut writer).await;
        }
    }
    session.server.log().info(format!(
        "Nostr client {} from {} disconnected",
        connection_id, peer_addr
    ));
}

impl Session {
    fn log(&self) -> Log<'_> {
        self.server.log()
    }

    async fn write_frames(
        &self,
        mut sink: SplitSink<WebSocketStream<TcpStream>, Message>,
        mut out_rx: crate::utils::outbox::OutboxReceiver<Outbound>,
    ) {
        while let Some(out) = out_rx.recv().await {
            let (message, closing) = match out {
                Outbound::Text(text) => (Message::Text(text), false),
                Outbound::Ping(payload) => (Message::Ping(payload), false),
                Outbound::Close { code, reason } => (
                    Message::Close(Some(CloseFrame {
                        code: CloseCode::from(code),
                        reason: reason.into(),
                    })),
                    true,
                ),
                Outbound::Shutdown => {
                    let _ = sink.flush().await;
                    return;
                }
            };
            let len = match &message {
                Message::Text(t) => t.len(),
                _ => 0,
            };
            if sink.send(message).await.is_err() {
                return;
            }
            if len > 0 {
                self.server
                    .app_state
                    .update_connection_stats(
                        self.server.server_id,
                        self.connection_id,
                        None,
                        Some(len as u64),
                        None,
                        Some(1),
                    )
                    .await;
            }
            if closing {
                // RFC 6455 §7.1.2: nothing is sent after a close frame.
                return;
            }
        }
    }

    async fn read_frames(
        &self,
        mut stream: SplitStream<WebSocketStream<TcpStream>>,
        job_tx: mpsc::Sender<Job>,
    ) -> ReaderExit {
        let idle = self.server.config.idle_timeout;
        loop {
            let keepalive = self.conn.out_tx().clone();
            let message = tokio::select! {
                message = stream.next() => message,
                _ = crate::server::accept_bounded::watch_idle_with_probe(
                    Arc::clone(&self.activity),
                    idle,
                    move || {
                        let _ = keepalive.send(Outbound::Ping(
                            crate::server::accept_bounded::KEEPALIVE_PING_PAYLOAD.to_vec(),
                        ));
                    },
                ) => return ReaderExit::Idle,
            };
            let Some(message) = message else {
                return ReaderExit::PeerClosed;
            };
            self.activity.touch();
            match message {
                Ok(Message::Text(text)) => {
                    self.server
                        .app_state
                        .update_connection_stats(
                            self.server.server_id,
                            self.connection_id,
                            Some(text.len() as u64),
                            None,
                            Some(1),
                            None,
                        )
                        .await;
                    self.on_text(&text, &job_tx);
                }
                Ok(Message::Binary(_)) => {
                    self.log().info(format!(
                        "Nostr {} sent a binary frame decision=fail_closed_malformed",
                        self.connection_id
                    ));
                    self.conn.send(wire::notice_message(
                        "invalid: NIP-01 messages are JSON text frames",
                    ));
                }
                Ok(Message::Close(_)) => return ReaderExit::PeerClosed,
                Ok(_) => {}
                Err(tokio_tungstenite::tungstenite::Error::Capacity(_)) => {
                    return ReaderExit::TooBig
                }
                Err(e) => {
                    self.log()
                        .debug(format!("Nostr {} read error: {}", self.connection_id, e));
                    return ReaderExit::Error;
                }
            }
        }
    }

    /// One text frame: answer what is mechanical, queue what needs the model.
    fn on_text(&self, text: &str, job_tx: &mpsc::Sender<Job>) {
        let log = self.log();
        match wire::parse_client_message(text) {
            Err(refusal) => {
                log.info(format!(
                    "Nostr {} message refused without the model decision={}",
                    self.connection_id, refusal.decision
                ));
                self.conn.send(refusal.reply);
            }
            Ok(ClientMessage::Close { subscription_id }) => {
                let was_open = self.conn.close(&subscription_id);
                log.info(format!(
                    "Nostr {} CLOSE {} ({}) decision=subscription_closed",
                    self.connection_id,
                    crate::utils::truncate_for_log(&subscription_id, 64),
                    if was_open { "closed" } else { "was not open" }
                ));
            }
            Ok(ClientMessage::Req {
                subscription_id,
                filters,
            }) => match self.conn.open(&subscription_id, filters.clone()) {
                Err(message) => {
                    log.info(format!(
                        "Nostr {} REQ {} refused decision=fail_closed_too_many_subscriptions",
                        self.connection_id,
                        crate::utils::truncate_for_log(&subscription_id, 64)
                    ));
                    self.conn
                        .send(wire::closed_message(&subscription_id, &message));
                }
                Ok(generation) => {
                    let job = Job::Req {
                        subscription_id: subscription_id.clone(),
                        generation,
                        filters,
                    };
                    if job_tx.try_send(job).is_err() {
                        self.conn.close(&subscription_id);
                        log.warn(format!(
                            "Nostr {} REQ {} refused decision=fail_closed_queue_full",
                            self.connection_id,
                            crate::utils::truncate_for_log(&subscription_id, 64)
                        ));
                        self.conn
                            .send(wire::closed_message(&subscription_id, QUEUE_FULL));
                    }
                }
            },
            Ok(ClientMessage::Event(event)) => {
                let id = event.id.clone();
                if job_tx.try_send(Job::Event(event)).is_err() {
                    log.warn(format!(
                        "Nostr {} EVENT {} refused decision=fail_closed_queue_full",
                        self.connection_id, id
                    ));
                    self.conn.send(wire::ok_message(&id, false, QUEUE_FULL));
                }
            }
        }
    }

    async fn answer_jobs(&self, mut job_rx: mpsc::Receiver<Job>) {
        while let Some(job) = job_rx.recv().await {
            let _busy = self.activity.busy();
            match job {
                Job::Event(event) => self.answer_event(event).await,
                Job::Req {
                    subscription_id,
                    generation,
                    filters,
                } => self.answer_req(subscription_id, generation, filters).await,
            }
        }
    }

    async fn ask(&self, event: &Event) -> Result<crate::llm::actions::executor::ExecutionResult> {
        call_llm(
            &self.server.llm_client,
            &self.server.app_state,
            self.server.server_id,
            Some(self.connection_id),
            event,
            self.protocol.as_ref(),
        )
        .await
    }

    async fn answer_event(&self, event: wire::Event) {
        let log = self.log();
        let content = crate::utils::truncate_str(&event.content, actions::MAX_CONTENT_FOR_MODEL);
        let tags: Vec<&Vec<String>> = event
            .tags
            .iter()
            .take(actions::MAX_TAGS_FOR_MODEL)
            .collect();
        let llm_event = Event::new(
            &actions::NOSTR_EVENT_EVENT,
            serde_json::json!({
                "id": event.id,
                "pubkey": event.pubkey,
                "kind": event.kind,
                "created_at": event.created_at,
                "tags": tags,
                "tag_count": event.tags.len(),
                "content": content,
                "content_truncated": content.len() < event.content.len(),
                "answer_with": actions::event_answer_with(event.kind),
            }),
        );
        let result = match self.ask(&llm_event).await {
            Ok(result) => result,
            Err(e) => {
                let (category, message) = match crate::utils::WireFailure::classify(&e) {
                    crate::utils::WireFailure::Overloaded => ("overloaded", EVENT_OVERLOADED),
                    crate::utils::WireFailure::Unavailable => ("unavailable", EVENT_UNAVAILABLE),
                };
                log.warn(format!(
                    "Nostr {} EVENT {} decision=fail_closed_llm_error category={}",
                    self.connection_id, event.id, category
                ));
                log.debug(format!("Nostr LLM call failed: {}", e));
                self.conn.send(wire::ok_message(&event.id, false, message));
                return;
            }
        };
        for message in &result.messages {
            log.info(message);
        }

        let mut verdict: Option<std::result::Result<(), String>> = None;
        let mut frames: Vec<String> = Vec::new();
        let mut close = false;
        for item in flatten(result.protocol_results) {
            match item {
                ActionResult::Custom { name, data } if verdict.is_none() => match name.as_str() {
                    "accept_nostr_event" => verdict = Some(Ok(())),
                    "reject_nostr_event" => {
                        verdict = Some(Err(data
                            .get("reason")
                            .and_then(|r| r.as_str())
                            .unwrap_or("blocked:")
                            .to_string()))
                    }
                    _ => {}
                },
                ActionResult::Output(bytes) => frames.push(String::from_utf8_lossy(&bytes).into()),
                ActionResult::CloseConnection => close = true,
                _ => {}
            }
        }

        match verdict {
            Some(Ok(())) => {
                self.conn.send(wire::ok_message(&event.id, true, ""));
                let delivered = self.server.relay.broadcast(&event);
                log.info(format!(
                    "Nostr {} EVENT {} kind {} decision=model_answer accepted, delivered to {} \
                     subscription(s)",
                    self.connection_id, event.id, event.kind, delivered
                ));
            }
            Some(Err(reason)) => {
                log.info(format!(
                    "Nostr {} EVENT {} kind {} decision=model_reject ({})",
                    self.connection_id, event.id, event.kind, reason
                ));
                self.conn.send(wire::ok_message(&event.id, false, &reason));
            }
            None => {
                let decision = if result.raw_actions.is_empty() {
                    "model_silent"
                } else {
                    "fail_closed_bad_action"
                };
                log.warn(format!(
                    "Nostr {} EVENT {} decision={} ({} failed action(s)); refusing",
                    self.connection_id,
                    event.id,
                    decision,
                    result.failures.len()
                ));
                self.conn
                    .send(wire::ok_message(&event.id, false, EVENT_UNDECIDED));
            }
        }
        for frame in frames {
            self.conn.send(frame);
        }
        if close {
            let _ = self.conn.out_tx().send(Outbound::Close {
                code: 1000,
                reason: String::new(),
            });
        }
    }

    async fn answer_req(
        &self,
        subscription_id: String,
        generation: u64,
        filters: Vec<wire::Filter>,
    ) {
        let log = self.log();
        if !self.conn.is_open(&subscription_id, generation) {
            log.info(format!(
                "Nostr {} REQ {} was closed before it was answered decision=stale_request_dropped",
                self.connection_id,
                crate::utils::truncate_for_log(&subscription_id, 64)
            ));
            return;
        }
        let llm_event = Event::new(
            &actions::NOSTR_REQ_EVENT,
            serde_json::json!({
                "subscription_id": subscription_id,
                "filters": filters.iter().map(|f| f.raw.clone()).collect::<Vec<_>>(),
                "relay_pubkey": self.server.key.pubkey_hex(),
                "answer_with": actions::req_answer_with(
                    &subscription_id,
                    &filters,
                    self.server.key.pubkey_hex(),
                ),
            }),
        );
        self.conn.begin_answer(&subscription_id, generation);
        let outcome = self.ask(&llm_event).await;
        self.conn.end_answer();

        let result = match outcome {
            Ok(result) => result,
            Err(e) => {
                let (category, message) = match crate::utils::WireFailure::classify(&e) {
                    crate::utils::WireFailure::Overloaded => ("overloaded", REQ_OVERLOADED),
                    crate::utils::WireFailure::Unavailable => ("unavailable", REQ_UNAVAILABLE),
                };
                log.warn(format!(
                    "Nostr {} REQ {} decision=fail_closed_llm_error category={}",
                    self.connection_id,
                    crate::utils::truncate_for_log(&subscription_id, 64),
                    category
                ));
                log.debug(format!("Nostr LLM call failed: {}", e));
                if self.conn.is_open(&subscription_id, generation) {
                    self.conn.close(&subscription_id);
                    self.conn
                        .send(wire::closed_message(&subscription_id, message));
                }
                return;
            }
        };
        for message in &result.messages {
            log.info(message);
        }
        let answered = result
            .protocol_result_actions
            .iter()
            .any(|a| a == "send_nostr_events");
        let mut frames: Vec<String> = Vec::new();
        let mut close = false;
        for item in flatten(result.protocol_results) {
            match item {
                ActionResult::Output(bytes) => frames.push(String::from_utf8_lossy(&bytes).into()),
                ActionResult::CloseConnection => close = true,
                _ => {}
            }
        }
        let events_sent = frames
            .iter()
            .filter(|f| f.starts_with("[\"EVENT\""))
            .count();
        let subject = format!(
            "Nostr {} REQ {}",
            self.connection_id,
            crate::utils::truncate_for_log(&subscription_id, 64)
        );

        if !self.conn.is_open(&subscription_id, generation) {
            let closed_by_model = frames.iter().any(|f| {
                serde_json::from_str::<serde_json::Value>(f).is_ok_and(|v| {
                    v.get(0).and_then(|x| x.as_str()) == Some("CLOSED")
                        && v.get(1).and_then(|x| x.as_str()) == Some(subscription_id.as_str())
                })
            });
            if closed_by_model {
                log.info(format!(
                    "{} decision=model_reject (subscription closed)",
                    subject
                ));
                for frame in frames {
                    self.conn.send(frame);
                }
            } else {
                log.info(format!(
                    "{} was closed or replaced while the model answered; its events are not \
                     sent decision=stale_answer_dropped",
                    subject
                ));
            }
        } else if !result.failures.is_empty() && !answered {
            log.warn(format!(
                "{} decision=fail_closed_bad_action: {}",
                subject,
                result
                    .failures
                    .iter()
                    .map(|f| format!("{}: {}", f.action, f.error))
                    .collect::<Vec<_>>()
                    .join("; ")
            ));
            self.conn.close(&subscription_id);
            self.conn
                .send(wire::closed_message(&subscription_id, REQ_UNAVAILABLE));
        } else {
            let decision = if result.raw_actions.is_empty() {
                "model_silent"
            } else {
                "model_answer"
            };
            log.info(format!(
                "{} decision={} events={} then EOSE",
                subject, decision, events_sent
            ));
            for frame in frames {
                self.conn.send(frame);
            }
            self.conn.send(wire::eose_message(&subscription_id));
        }
        if close {
            let _ = self.conn.out_tx().send(Outbound::Close {
                code: 1000,
                reason: String::new(),
            });
        }
    }
}

/// Depth-first, in order: `Multiple` is how `send_nostr_events` returns one frame per event.
fn flatten(results: Vec<ActionResult>) -> Vec<ActionResult> {
    let mut out = Vec::new();
    let mut stack: Vec<ActionResult> = results.into_iter().rev().collect();
    while let Some(item) = stack.pop() {
        match item {
            ActionResult::Multiple(items) => stack.extend(items.into_iter().rev()),
            other => out.push(other),
        }
    }
    out
}

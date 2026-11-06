//! WebRTC Signaling Server - WebSocket-based SDP relay for WebRTC connections
pub mod actions;

use anyhow::{Context, Result};
use futures::{SinkExt, StreamExt};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};
use tokio_tungstenite::{
    accept_async_with_config,
    tungstenite::{protocol::WebSocketConfig, Message},
};
use tracing::{debug, error, info, trace, warn};

use crate::llm::action_helper::call_llm;
use crate::llm::ollama_client::OllamaClient;
use crate::logging::emit::Log;
use crate::protocol::Event;
use crate::server::connection::ConnectionId;
use crate::server::WebRtcSignalingProtocol;
use crate::state::app_state::AppState;
use crate::state::ServerId;
use actions::{
    WEBRTC_SIGNALING_MESSAGE_RECEIVED_EVENT, WEBRTC_SIGNALING_PEER_CONNECTED_EVENT,
    WEBRTC_SIGNALING_PEER_DISCONNECTED_EVENT,
};

/// Unique identifier for a signaling peer
pub type PeerId = String;

/// Longest a peer may take to complete the WebSocket upgrade.
const SIGNALING_HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Largest WebSocket message accepted, and this server's declared `max_inbound_bytes`.
/// Signaling carries SDP and ICE candidates; a large real offer is a few kilobytes.
///
/// tungstenite enforces it on the length a frame header declares, before the payload is read,
/// and on the reassembled message; the upgrade request itself is capped by tungstenite's
/// handshake reader at 64 KiB. Over the limit the peer gets a WebSocket close with code 1009
/// (Message Too Big) and the connection ends.
pub const SIGNALING_MAX_MESSAGE_BYTES: usize = 256 * 1024;

/// The close frame for a message over [`SIGNALING_MAX_MESSAGE_BYTES`]: RFC 6455's 1009, with a
/// fixed reason.
fn message_too_big_close() -> Message {
    Message::Close(Some(tokio_tungstenite::tungstenite::protocol::CloseFrame {
        code: tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Size,
        reason: "message too big".into(),
    }))
}

/// How long a signalling connection may go without a single frame from the peer.
///
/// A signalling relay's peers are silent most of the time by design —
/// a registered peer waits, possibly for minutes, for another peer's offer or candidate — so a
/// bound on silence alone would evict exactly the peers the relay exists for. The bound is on the peer's **liveness**, not its conversation: at half of it the server
/// sends a Ping (`accept_bounded::watch_idle_with_probe`), every RFC 6455 endpoint answers a Ping
/// with a Pong by itself — a browser tab, tungstenite, NetGet's own client — and any inbound
/// frame resets the clock. What reaches the bound is a peer that has stopped reading or vanished
/// without a FIN, and it is closed with 1001 ("going away") and `decision=idle_timeout`.
///
/// 600 seconds, the number `websocket` uses and for the same reason: NetGet's own WebRTC client
/// (`src/client/webrtc/mod.rs`) does not read its signalling socket while its connected-event
/// model turn runs, and a `manual` rule parks that turn for up to 300 seconds; twice that window
/// keeps the operator's own peer. Declared as the `idle_timeout_secs` startup parameter.
pub const IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(600);

/// Largest number of peers that may be registered at once.
///
/// The registry is keyed on a string the peer chooses, so without this one host
/// can register until memory runs out. The protocol's own CLAUDE.md recommended
/// "1,000-10,000 concurrent peers" while nothing enforced anything.
const SIGNALING_MAX_PEERS: usize = 1024;

/// Longest peer id accepted. The id is echoed in log lines, in the registration
/// event and on every relayed frame, so an unbounded one is stored and repeated
/// many times over.
const MAX_PEER_ID_BYTES: usize = 128;

/// Concurrent connections this server admits before it starts refusing.
///
/// **1024, not the house default of 256, and the number is
/// [`SIGNALING_MAX_PEERS`] on purpose.** One connection here carries at most one registered
/// peer for its lifetime, so the accept cap and the registry cap measure the same population
/// from two sides. Taking
/// [`crate::server::accept_bounded::DEFAULT_MAX_CONNECTIONS`] would have silently replaced
/// this server's declared 1024-peer capacity with an undocumented 256 and made
/// [`SIGNALING_MAX_PEERS`]'s own refusal path unreachable — a bound that reads as protection
/// and can never fire, which is the `PrivilegedPort(3690)` failure in a different costume.
/// Going higher would be the opposite mistake: admitting sockets the registry has already
/// decided it has no room for, so the extra slots buy nothing but a longer path to the same
/// refusal.
///
/// [`SIGNALING_HANDSHAKE_TIMEOUT`] bounds how long one peer holds a slot before it has
/// upgraded; only this bounds how many of them there can be at once. The per-connection cost
/// is a socket, two tasks and at most [`SIGNALING_MAX_MESSAGE_BYTES`] of transient reassembly,
/// which is what makes 1024 of them a bounded total rather than a large one.
const MAX_CONNECTIONS: usize = SIGNALING_MAX_PEERS;

/// The body of [`CONNECTION_CAP_REFUSAL`].
const CONNECTION_CAP_BODY: &str = "Too many signaling connections, try again later.\n";

/// What a peer over [`MAX_CONNECTIONS`] is told before the socket closes.
///
/// **This server's own refusals are signaling frames, and a refused peer cannot read one.**
/// A registration turned away by [`SIGNALING_MAX_PEERS`] gets an `error` message that names
/// the reason — but that is a WebSocket text frame, and a peer refused at the accept has not
/// completed the RFC 6455 upgrade, so it has no frame parser running. Writing signaling JSON
/// to a socket still waiting for an HTTP response is the mis-parse this codebase refuses to
/// ship; the client reports a malformed handshake rather than a full server.
///
/// What it *is* in the middle of is an ordinary HTTP/1.1 GET (RFC 6455 §4.1), so 503 with
/// `Retry-After` is inside the protocol rather than beside it, and every WebSocket client
/// surfaces a non-101 status as a failed handshake carrying that code. RFC 9112 §3.3 allows
/// the response before the request is complete, and `Connection: close` tells a client still
/// writing its head to stop and read.
static CONNECTION_CAP_REFUSAL: std::sync::LazyLock<Vec<u8>> = std::sync::LazyLock::new(|| {
    format!(
        "HTTP/1.1 503 Service Unavailable\r\nRetry-After: 30\r\nContent-Type: \
         text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        CONNECTION_CAP_BODY.len(),
        CONNECTION_CAP_BODY
    )
    .into_bytes()
});

/// Signaling message types
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type")]
pub enum SignalingMessage {
    /// Register with a peer ID
    #[serde(rename = "register")]
    Register { peer_id: String },

    /// SDP offer
    #[serde(rename = "offer")]
    Offer {
        from: String,
        to: String,
        sdp: serde_json::Value,
    },

    /// SDP answer
    #[serde(rename = "answer")]
    Answer {
        from: String,
        to: String,
        sdp: serde_json::Value,
    },

    /// ICE candidate
    #[serde(rename = "ice_candidate")]
    IceCandidate {
        from: String,
        to: String,
        candidate: serde_json::Value,
    },

    /// Error message
    #[serde(rename = "error")]
    Error { message: String },

    /// Registration success
    #[serde(rename = "registered")]
    Registered { peer_id: String },

    /// Generic relay message
    #[serde(rename = "relay")]
    Relay {
        from: String,
        to: String,
        data: serde_json::Value,
    },
}

/// Peer connection data
///
/// Holds a channel into the connection's writer task rather than the `SplitSink` itself.
/// That is the whole fix for the relay: `register_peer` used to take ownership of the
/// sink, so `handle_connection` could not keep reading and had to `break` immediately
/// after a successful registration — which ran the disconnect cleanup, unregistered the
/// peer that had just registered, and dropped its socket. No peer was ever registered for
/// longer than one statement, so `forward_message` could never find a recipient and not a
/// single offer, answer or ICE candidate was ever relayed.
struct PeerConnection {
    #[allow(dead_code)]
    peer_id: PeerId,
    /// Messages queued here are written by this connection's writer task.
    out_tx: crate::utils::outbox::OutboxSender<Message>,
    #[allow(dead_code)]
    remote_addr: SocketAddr,
    #[allow(dead_code)]
    connection_id: ConnectionId,
}

/// WebRTC signaling server shared state
pub struct WebRtcSignalingServerData {
    /// Connected peers indexed by peer ID
    peers: Arc<Mutex<HashMap<PeerId, PeerConnection>>>,
}

impl Default for WebRtcSignalingServerData {
    fn default() -> Self {
        Self::new()
    }
}

impl WebRtcSignalingServerData {
    pub fn new() -> Self {
        Self {
            peers: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Register a new peer
    async fn register_peer(
        &self,
        peer_id: PeerId,
        out_tx: crate::utils::outbox::OutboxSender<Message>,
        remote_addr: SocketAddr,
        connection_id: ConnectionId,
    ) -> Result<()> {
        if peer_id.is_empty() || peer_id.len() > MAX_PEER_ID_BYTES {
            anyhow::bail!(
                "Peer ID must be 1-{} bytes, got {}",
                MAX_PEER_ID_BYTES,
                peer_id.len()
            );
        }

        let mut peers = self.peers.lock().await;
        if peers.len() >= SIGNALING_MAX_PEERS {
            anyhow::bail!(
                "Signaling server is full ({} peers registered)",
                SIGNALING_MAX_PEERS
            );
        }
        if peers.contains_key(&peer_id) {
            anyhow::bail!("Peer ID {} already registered", peer_id);
        }

        peers.insert(
            peer_id.clone(),
            PeerConnection {
                peer_id: peer_id.clone(),
                out_tx,
                remote_addr,
                connection_id,
            },
        );
        info!("Registered signaling peer: {}", peer_id);

        Ok(())
    }

    /// Unregister a peer
    pub async fn unregister_peer(&self, peer_id: &str) {
        let mut peers = self.peers.lock().await;
        peers.remove(peer_id);
        info!("Unregistered signaling peer: {}", peer_id);
    }

    /// Forward message to a specific peer
    pub async fn forward_message(&self, to: &str, message: &SignalingMessage) -> Result<()> {
        let msg_json = serde_json::to_string(message)?;
        let peers = self.peers.lock().await;
        let peer_conn = peers.get(to).context(format!("Peer {} not found", to))?;
        peer_conn
            .out_tx
            .send(Message::Text(msg_json))
            .context("Peer's writer task has stopped")?;
        drop(peers);

        trace!("Forwarded message to peer {}: {:?}", to, message);
        Ok(())
    }

    /// Send a message to one peer without requiring it to be the relay target
    pub async fn send_to_peer(&self, peer_id: &str, text: String) -> Result<()> {
        let peers = self.peers.lock().await;
        let peer_conn = peers
            .get(peer_id)
            .context(format!("Peer {} not found", peer_id))?;
        peer_conn
            .out_tx
            .send(Message::Text(text))
            .context("Peer's writer task has stopped")?;
        Ok(())
    }

    /// List all connected peer IDs
    pub async fn list_peers(&self) -> Vec<String> {
        self.peers.lock().await.keys().cloned().collect()
    }

    /// Get peer count
    pub async fn peer_count(&self) -> usize {
        self.peers.lock().await.len()
    }
}

/// WebRTC signaling server
pub struct WebRtcSignalingServer;

impl WebRtcSignalingServer {
    /// Spawn the WebRTC signaling server
    pub async fn spawn_with_llm_actions(
        listen_addr: SocketAddr,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        server_id: ServerId,
        idle_timeout: std::time::Duration,
    ) -> Result<SocketAddr> {
        let listener = TcpListener::bind(listen_addr).await?;
        let local_addr = listener.local_addr()?;
        Log::new(Some(&status_tx)).info(format!(
            "WebRTC Signaling server listening on {}",
            local_addr
        ));

        // Create server data
        //
        // This used to be followed by a `set_protocol_field("server_data_ptr",
        // Arc::into_raw(...) as usize)`. Nothing in the tree ever read that field
        // and nothing ever called `Arc::from_raw`, so it leaked one `Arc` per
        // server start and wrote a live heap address into server state that the
        // TUI and MCP surfaces will happily print — an ASLR disclosure bought for
        // a capability nobody used.
        let server_data = Arc::new(WebRtcSignalingServerData::new());

        let protocol = Arc::new(WebRtcSignalingProtocol::new());

        // Spawn accept loop
        let task_registrar = app_state.clone();
        let limiter = crate::server::accept_bounded::ConnectionLimiter::new(MAX_CONNECTIONS);
        let cap_status_tx = status_tx.clone();
        let accept_handle = tokio::spawn(async move {
            loop {
                match crate::server::accept_bounded::accept_bounded(
                    &listener,
                    &limiter,
                    &CONNECTION_CAP_REFUSAL,
                    "WEBRTC_SIGNALING",
                    Some(&cap_status_tx),
                )
                .await
                {
                    Ok((stream, remote_addr, permit)) => {
                        info!("Signaling server accepted connection from {}", remote_addr);

                        let server_data_clone = Arc::clone(&server_data);
                        let app_state_clone = Arc::clone(&app_state);
                        let status_tx_clone = status_tx.clone();
                        let llm_client_clone = llm_client.clone();
                        let protocol_clone = Arc::clone(&protocol);

                        // Tracked, not detached: stop_server must abort this task too.
                        let task_owner = app_state.clone();
                        task_owner
                            .spawn_server_task(server_id, async move {
                                // Released when this task ends, and this task is the whole of
                                // the connection: `handle_connection` spawns a writer task but
                                // `.await`s it on its only exit path, so there is nothing left
                                // holding the socket when this future resolves and
                                // `MAX_CONNECTIONS` caps live connections rather than accepts.
                                let _permit = permit;
                                if let Err(e) = Self::handle_connection(
                                    stream,
                                    remote_addr,
                                    server_data_clone,
                                    app_state_clone,
                                    status_tx_clone,
                                    llm_client_clone,
                                    server_id,
                                    protocol_clone,
                                    idle_timeout,
                                )
                                .await
                                {
                                    error!(
                                        "Error handling signaling connection from {}: {}",
                                        remote_addr, e
                                    );
                                }
                            })
                            .await;
                    }
                    Err(e) => {
                        error!("Error accepting signaling connection: {}", e);
                    }
                }
            }
        });

        task_registrar
            .register_server_task(server_id, accept_handle)
            .await;

        Ok(local_addr)
    }

    #[allow(clippy::too_many_arguments)]
    async fn handle_connection(
        stream: TcpStream,
        remote_addr: SocketAddr,
        server_data: Arc<WebRtcSignalingServerData>,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        llm_client: OllamaClient,
        server_id: ServerId,
        protocol: Arc<WebRtcSignalingProtocol>,
        idle_timeout: std::time::Duration,
    ) -> Result<()> {
        // Upgrade to WebSocket.
        //
        // Two bounds, both absent before and both reachable pre-registration by
        // anyone who can open a TCP connection:
        //
        // * The handshake gets a deadline. A socket that connects and never sends
        //   an HTTP upgrade parked inside `accept_async` forever, holding a task
        //   and an fd while remaining invisible to the dashboard — a connection is
        //   only added to `AppState` once it registers.
        // * Frames get a size limit. Bare `accept_async` takes tungstenite's
        //   defaults of 64 MiB per message and 16 MiB per frame, so a single peer
        //   could make the server buffer 64 MiB, and a peer id is just a string in
        //   a frame. Signaling carries SDP and ICE candidates; the largest real
        //   offer is a few kilobytes, so 256 KiB is generous by two orders of
        //   magnitude and still bounds the damage.
        let config = WebSocketConfig {
            max_message_size: Some(SIGNALING_MAX_MESSAGE_BYTES),
            max_frame_size: Some(SIGNALING_MAX_MESSAGE_BYTES),
            ..Default::default()
        };
        // Taken before the socket is wrapped: cutting off a peer that does not read ends its
        // connection.
        let closer = crate::utils::outbox::ConnectionCloser::for_stream(&stream);
        let ws_stream = tokio::time::timeout(
            SIGNALING_HANDSHAKE_TIMEOUT,
            accept_async_with_config(stream, Some(config)),
        )
        .await
        .map_err(|_| {
            anyhow::anyhow!(
                "WebSocket handshake from {} did not complete within {:?}",
                remote_addr,
                SIGNALING_HANDSHAKE_TIMEOUT
            )
        })??;
        info!("WebSocket connection established with {}", remote_addr);

        let (mut ws_tx, mut ws_rx) = ws_stream.split();

        // One writer task owns the sink. Everything that wants to write — this read loop,
        // and any other peer relaying towards us — queues on `out_tx` instead. Handing the
        // sink itself to the peer registry is what previously forced the read loop to
        // terminate on registration.
        // Bounded: other peers relay towards this one, so a peer that stops reading is cut
        // off rather than queued for (`utils::outbox`).
        let (out_tx, mut out_rx) = crate::utils::outbox::channel(
            format!("WebRTC signalling connection {remote_addr}"),
            crate::utils::outbox::OutboxLimits::DEFAULT,
            Message::len,
        );
        out_tx.close_on_cut_off(closer);
        let writer = tokio::spawn(async move {
            while let Some(msg) = out_rx.recv().await {
                if let Err(e) = ws_tx.send(msg).await {
                    debug!("Signaling writer stopped: {}", e);
                    break;
                }
            }
            let _ = ws_tx.close().await;
        });

        let mut peer_id: Option<PeerId> = None;
        let mut connection_id: Option<ConnectionId> = None;

        // Touched by every inbound frame, Pongs included, and busy while one is handled.
        let activity = Arc::new(crate::server::accept_bounded::ConnectionActivity::new());

        // Handle incoming messages
        loop {
            let keepalive_tx = out_tx.clone();
            let msg_result = tokio::select! {
                msg = ws_rx.next() => msg,
                _ = crate::server::accept_bounded::watch_idle_with_probe(
                    Arc::clone(&activity),
                    idle_timeout,
                    move || {
                        let _ = keepalive_tx.send(Message::Ping(
                            crate::server::accept_bounded::KEEPALIVE_PING_PAYLOAD.to_vec(),
                        ));
                    },
                ) => {
                    info!(
                        "WebRTC signaling peer {} sent no frame for {}s, not even a Pong; \
                         closing decision=idle_timeout",
                        remote_addr,
                        idle_timeout.as_secs()
                    );
                    let _ = out_tx.send(Message::Close(Some(
                        tokio_tungstenite::tungstenite::protocol::CloseFrame {
                            code: tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Away,
                            reason: "idle timeout".into(),
                        },
                    )));
                    break;
                }
            };
            let Some(msg_result) = msg_result else { break };
            // Busy for the rest of this iteration. Registration and its connected event run
            // inline, so the watchdog is not even polled while they are outstanding — but the
            // guard's release is what gives the connection a fresh bound afterwards. Without it,
            // an event parked for a human longer than the bound would come back to a clock that
            // had long run out, and the peer would be closed the instant it was answered.
            let _busy = activity.busy();
            match msg_result {
                Ok(Message::Text(text)) => {
                    trace!("Received signaling message: {}", text);

                    // Parse message
                    let message: SignalingMessage = match serde_json::from_str(&text) {
                        Ok(m) => m,
                        Err(e) => {
                            // The error goes to the log; the peer gets a category. serde's
                            // message names the enum's variants and the exact column it
                            // choked on ("unknown variant `foo`, expected one of `register`,
                            // `offer`, ... at line 1 column 15"), and that was going verbatim
                            // to an unauthenticated stranger. Same rule as
                            // `crate::utils::WireFailure`, which does not apply here only
                            // because this is a parse failure rather than a backend one.
                            warn!(
                                "Invalid signaling message from {}: {}",
                                remote_addr,
                                crate::utils::truncate_for_log(&e.to_string(), 300)
                            );
                            let _ = Self::reply(
                                &out_tx,
                                &SignalingMessage::Error {
                                    message: "invalid signaling message: expected a JSON \
                                              object with a 'type' of register, offer, \
                                              answer, ice_candidate or relay"
                                        .to_string(),
                                },
                            );
                            continue;
                        }
                    };

                    match message {
                        SignalingMessage::Register {
                            peer_id: new_peer_id,
                        } => {
                            if peer_id.is_some() {
                                let _ = Self::reply(
                                    &out_tx,
                                    &SignalingMessage::Error {
                                        message: "This connection is already registered"
                                            .to_string(),
                                    },
                                );
                                continue;
                            }

                            let conn_id = ConnectionId::new(app_state.get_next_unified_id().await);

                            match server_data
                                .register_peer(
                                    new_peer_id.clone(),
                                    out_tx.clone(),
                                    remote_addr,
                                    conn_id,
                                )
                                .await
                            {
                                Ok(_) => {
                                    peer_id = Some(new_peer_id.clone());
                                    connection_id = Some(conn_id);

                                    // Add connection to server
                                    use crate::state::server::{
                                        ConnectionState as ServerConnectionState, ConnectionStatus,
                                        ProtocolConnectionInfo,
                                    };
                                    let now = crate::utils::clock::Instant::now();
                                    let conn_state = ServerConnectionState {
                                        id: conn_id,
                                        remote_addr,
                                        local_addr: "0.0.0.0:0".parse().unwrap(),
                                        bytes_sent: 0,
                                        bytes_received: 0,
                                        packets_sent: 0,
                                        packets_received: 0,
                                        last_activity: now,
                                        status: ConnectionStatus::Active,
                                        status_changed_at: now,
                                        protocol_info: ProtocolConnectionInfo::new(
                                            serde_json::json!({
                                                "peer_id": new_peer_id,
                                            }),
                                        ),
                                    };
                                    app_state
                                        .add_connection_to_server(server_id, conn_state)
                                        .await;
                                    let _ = status_tx.send("__UPDATE_UI__".to_string());

                                    // Confirm registration. `SignalingMessage::Registered`
                                    // was defined but never sent, so a client waiting for
                                    // it (as the documented protocol says it may) hung.
                                    let _ = Self::reply(
                                        &out_tx,
                                        &SignalingMessage::Registered {
                                            peer_id: new_peer_id.clone(),
                                        },
                                    );
                                    Log::new(Some(&status_tx)).info(format!(
                                        "WebRTC signaling peer '{}' registered from {}",
                                        new_peer_id, remote_addr
                                    ));

                                    // Fire connected event
                                    let event = Event::new(
                                        &WEBRTC_SIGNALING_PEER_CONNECTED_EVENT,
                                        serde_json::json!({
                                            "peer_id": new_peer_id,
                                            "remote_addr": remote_addr.to_string(),
                                            "peer_count": server_data.peer_count().await,
                                        }),
                                    );

                                    match call_llm(
                                        &llm_client,
                                        &app_state,
                                        server_id,
                                        Some(conn_id),
                                        &event,
                                        protocol.as_ref(),
                                    )
                                    .await
                                    {
                                        Ok(result) => {
                                            let subject = format!(
                                                "WebRTC signaling peer '{}' \
                                                 webrtc_signaling_peer_connected",
                                                new_peer_id
                                            );
                                            if Self::apply_results(
                                                result, &subject, &out_tx, &status_tx,
                                            ) {
                                                break;
                                            }
                                        }
                                        Err(e) => {
                                            // This is the one signaling event the model can
                                            // act on (`send_signaling_message`,
                                            // `disconnect_peer`), so a peer may legitimately
                                            // be waiting for what the model decides. Swallowed,
                                            // that wait ended at the peer's own timeout. Say so
                                            // in the protocol's own vocabulary instead - and
                                            // never invent the reply the model did not give.
                                            //
                                            // The tag is NOT `fail_closed_*`, and that is
                                            // deliberate: registration completed and the
                                            // `registered` frame went out *before* this call,
                                            // so the peer keeps every capability it had. The
                                            // backend failing denied it nothing. Calling that
                                            // fail-closed would put a line that refused
                                            // nothing in front of every
                                            // `grep decision=fail_closed`, and would hide the
                                            // real property: this peer was admitted without
                                            // the model ever being consulted.
                                            Log::new(Some(&status_tx)).error(format!(
                                                "WebRTC signaling peer '{}' \
                                                 webrtc_signaling_peer_connected \
                                                 decision=llm_error_peer_admitted \
                                                 category={}: LLM call failed ({}) - sent \
                                                 error frame, registration stands",
                                                new_peer_id,
                                                Self::failure_category(&e),
                                                e
                                            ));
                                            let _ = Self::reply(
                                                &out_tx,
                                                &SignalingMessage::Error {
                                                    message: format!(
                                                        "Server-side handler for peer '{}' \
                                                         failed; registration stands but no \
                                                         handler response follows",
                                                        new_peer_id
                                                    ),
                                                },
                                            );
                                        }
                                    }
                                }
                                Err(e) => {
                                    // The protocol refused this registration — an empty or
                                    // over-long id, a duplicate, or a full registry. No model
                                    // was consulted, so this is neither a model decision nor a
                                    // backend failure; `protocol_error` says which.
                                    Log::new(Some(&status_tx)).warn(format!(
                                        "WebRTC signaling refused registration of '{}' from {} \
                                         decision=protocol_error: {}",
                                        new_peer_id, remote_addr, e
                                    ));
                                    let _ = Self::reply(
                                        &out_tx,
                                        &SignalingMessage::Error {
                                            message: e.to_string(),
                                        },
                                    );
                                }
                            }
                        }
                        SignalingMessage::Offer { .. }
                        | SignalingMessage::Answer { .. }
                        | SignalingMessage::IceCandidate { .. }
                        | SignalingMessage::Relay { .. } => {
                            let (kind, claimed_from, to) = match &message {
                                SignalingMessage::Offer { from, to, .. } => {
                                    ("offer", from.clone(), to.clone())
                                }
                                SignalingMessage::Answer { from, to, .. } => {
                                    ("answer", from.clone(), to.clone())
                                }
                                SignalingMessage::IceCandidate { from, to, .. } => {
                                    ("ice_candidate", from.clone(), to.clone())
                                }
                                SignalingMessage::Relay { from, to, .. } => {
                                    ("relay", from.clone(), to.clone())
                                }
                                _ => unreachable!(),
                            };

                            // A sender must have registered. Nothing checked this: an
                            // anonymous socket that never sent `register` could inject
                            // offers, answers, ICE candidates and arbitrary `relay` JSON at
                            // any registered peer. A relay with no identity at all on the
                            // sending side is not a relay, it is an open injection point,
                            // and the peer on the far end has no way to tell the difference.
                            let Some(sender_id) = peer_id.clone() else {
                                let _ = Self::reply(
                                    &out_tx,
                                    &SignalingMessage::Error {
                                        message: "register before sending offer, answer, \
                                                  ice_candidate or relay"
                                            .to_string(),
                                    },
                                );
                                Log::new(Some(&status_tx)).warn(format!(
                                    "WebRTC signaling refused {} from unregistered {}",
                                    kind, remote_addr
                                ));
                                continue;
                            };

                            // And `from` is this connection's registered id, not whatever
                            // the frame claimed. It was taken verbatim, so any registered
                            // peer could send an offer that both the recipient and the
                            // `webrtc_signaling_message_received` event attributed to
                            // somebody else — and the recipient would answer *that* peer,
                            // splicing a stranger into a session it is not part of.
                            //
                            // A mismatch is rewritten rather than refused: the field is
                            // redundant (the connection already identifies the sender) and
                            // clients that fill it in correctly are unaffected.
                            if claimed_from != sender_id {
                                Log::new(Some(&status_tx)).warn(format!(
                                    "WebRTC signaling rewrote forged 'from' on a {}: peer '{}' \
                                     claimed to be '{}'",
                                    kind, sender_id, claimed_from
                                ));
                            }
                            let from = sender_id;
                            let message = Self::with_sender(message, &from);

                            // Relay: a signaling server is a relay, and putting a model
                            // round-trip in front of every ICE candidate would break any
                            // real browser peer.
                            let delivered = match server_data.forward_message(&to, &message).await {
                                Ok(()) => true,
                                Err(e) => {
                                    warn!(
                                        "Failed to forward {} from {} to {}: {}",
                                        kind, from, to, e
                                    );
                                    let _ = Self::reply(
                                        &out_tx,
                                        &SignalingMessage::Error {
                                            message: format!(
                                                "Cannot deliver {} to {}: {}",
                                                kind, to, e
                                            ),
                                        },
                                    );
                                    false
                                }
                            };

                            Log::new(Some(&status_tx)).debug(format!(
                                "WebRTC signaling {} {} -> {} ({})",
                                kind,
                                from,
                                to,
                                if delivered {
                                    "delivered"
                                } else {
                                    "undeliverable"
                                }
                            ));

                            // Notify the LLM out of band so observation never delays relay.
                            let event = Event::new(
                                &WEBRTC_SIGNALING_MESSAGE_RECEIVED_EVENT,
                                serde_json::json!({
                                    "peer_id": from,
                                    "message_type": kind,
                                    "target_peer": to,
                                    "delivered": delivered,
                                }),
                            );
                            let llm = llm_client.clone();
                            let state = app_state.clone();
                            let proto = protocol.clone();
                            let status = status_tx.clone();
                            let observed = format!("{} {} -> {}", kind, from, to);
                            // Tracked, not detached: stop_server must abort this task too.
                            let task_owner = app_state.clone();
                            task_owner
                                .spawn_server_task(server_id, async move {
                                    if let Err(e) = call_llm(
                                        &llm,
                                        &state,
                                        server_id,
                                        None,
                                        &event,
                                        proto.as_ref(),
                                    )
                                    .await
                                    {
                                        // Deliberately silent on the wire, and that is the only
                                        // correct answer here: `webrtc_signaling_message_received`
                                        // is declared `.with_no_actions()` and fires *after* the
                                        // relay has already been decided and already reported to
                                        // the sender. The model cannot speak to the peer on the
                                        // success path either, so an error frame on this path
                                        // would announce a failure the peer's signaling did not
                                        // suffer and could abort a negotiation that succeeded.
                                        // The operator is who needs to know, so say it loudly
                                        // there.
                                        // `llm_error_notice_only`: nothing was pending on this
                                        // call. The relay was decided in Rust and already
                                        // reported to the sender, and the event is declared
                                        // `.with_no_actions()`, so the failure refused nothing
                                        // and withheld nothing the model could have sent.
                                        Log::new(Some(&status)).error(format!(
                                        "WebRTC signaling {} webrtc_signaling_message_received \
                                         decision=llm_error_notice_only: LLM call failed ({}) - \
                                         message was already relayed, no frame sent",
                                        observed, e
                                    ));
                                    }
                                })
                                .await;
                        }
                        other => {
                            debug!("Ignoring signaling message: {:?}", other);
                        }
                    }
                }
                Ok(Message::Close(_)) => {
                    info!("Signaling connection closed by peer");
                    break;
                }
                Ok(_) => {
                    // Ignore binary, ping, pong messages
                }
                Err(tokio_tungstenite::tungstenite::Error::Capacity(e)) => {
                    warn!(
                        "Signaling message from {} over {} bytes \
                         decision=fail_closed_message_too_large: {}",
                        remote_addr, SIGNALING_MAX_MESSAGE_BYTES, e
                    );
                    let _ = out_tx.send(message_too_big_close());
                    break;
                }
                Err(e) => {
                    warn!("WebSocket error: {}", e);
                    break;
                }
            }
        }

        // Cleanup on disconnect
        if let Some(pid) = peer_id {
            server_data.unregister_peer(&pid).await;

            // Fire disconnected event
            let event = Event::new(
                &WEBRTC_SIGNALING_PEER_DISCONNECTED_EVENT,
                serde_json::json!({
                    "peer_id": pid,
                    "peer_count": server_data.peer_count().await,
                }),
            );

            if let Err(e) = call_llm(
                &llm_client,
                &app_state,
                server_id,
                connection_id,
                &event,
                protocol.as_ref(),
            )
            .await
            {
                // Silence is forced here rather than chosen: this fires because the peer's
                // socket has already gone, so there is nobody left to answer in any
                // vocabulary. `webrtc_signaling_peer_disconnected` is declared
                // `.with_no_actions()` for the same reason. Log it loudly and carry on with
                // the cleanup below - the connection must still be torn down.
                // `llm_error_notice_only` for the same reason as the relay path: the socket is
                // already gone, the event is `.with_no_actions()`, and nothing was refused.
                Log::new(Some(&status_tx)).error(format!(
                    "WebRTC signaling peer '{}' webrtc_signaling_peer_disconnected \
                     decision=llm_error_notice_only: LLM call failed on disconnect ({}) - peer \
                     already gone, nothing sent",
                    pid, e
                ));
            }

            // Remove connection from server
            if let Some(conn_id) = connection_id {
                app_state
                    .remove_connection_from_server(server_id, conn_id)
                    .await;
                let _ = status_tx.send("__UPDATE_UI__".to_string());
            }
        }

        // Dropping our sender lets the writer task finish once the registry copy is gone.
        drop(out_tx);
        let _ = writer.await;

        Ok(())
    }

    /// `"overloaded"` or `"unavailable"` for a backend failure.
    ///
    /// Signaling has one error frame and it carries no code, so the wire cannot tell a
    /// saturated backend from a dead one. The log can, and this is where it does — the same
    /// `category=` split `radius` uses next to its own decision token.
    fn failure_category(e: &anyhow::Error) -> &'static str {
        match crate::utils::wire_failure::WireFailure::classify(e) {
            crate::utils::wire_failure::WireFailure::Overloaded => "overloaded",
            crate::utils::wire_failure::WireFailure::Unavailable => "unavailable",
        }
    }

    fn reply(
        out_tx: &crate::utils::outbox::OutboxSender<Message>,
        message: &SignalingMessage,
    ) -> Result<()> {
        out_tx.send(Message::Text(serde_json::to_string(message)?))?;
        Ok(())
    }

    /// Replace a relayed message's `from` with the sender's registered peer id.
    ///
    /// The wire field is whatever the sender typed; this connection's identity is
    /// what it registered. Delivering the former lets any peer forge an offer from
    /// any other, so the latter is what goes out and what the event reports.
    fn with_sender(message: SignalingMessage, sender: &str) -> SignalingMessage {
        match message {
            SignalingMessage::Offer { to, sdp, .. } => SignalingMessage::Offer {
                from: sender.to_string(),
                to,
                sdp,
            },
            SignalingMessage::Answer { to, sdp, .. } => SignalingMessage::Answer {
                from: sender.to_string(),
                to,
                sdp,
            },
            SignalingMessage::IceCandidate { to, candidate, .. } => {
                SignalingMessage::IceCandidate {
                    from: sender.to_string(),
                    to,
                    candidate,
                }
            }
            SignalingMessage::Relay { to, data, .. } => SignalingMessage::Relay {
                from: sender.to_string(),
                to,
                data,
            },
            other => other,
        }
    }

    /// Execute whatever the LLM returned for a signaling event.
    ///
    /// Returns true if the connection should be closed.
    ///
    /// `subject` names the peer and event the answer belongs to, so the `decision=` line this
    /// emits identifies a request rather than floating free.
    fn apply_results(
        result: crate::llm::actions::executor::ExecutionResult,
        subject: &str,
        out_tx: &crate::utils::outbox::OutboxSender<Message>,
        status_tx: &mpsc::UnboundedSender<String>,
    ) -> bool {
        let log = Log::new(Some(status_tx));
        for message in &result.messages {
            log.info(format!("{}", message));
        }

        let mut close = false;
        let mut sent = 0usize;
        let mut undecodable = 0usize;
        for protocol_result in result.protocol_results {
            match protocol_result {
                crate::llm::ActionResult::Output(bytes) => match String::from_utf8(bytes) {
                    Ok(text) => {
                        let _ = out_tx.send(Message::Text(text));
                        sent += 1;
                    }
                    Err(e) => {
                        undecodable += 1;
                        error!("Signaling action produced non-UTF-8 output: {}", e);
                    }
                },
                crate::llm::ActionResult::CloseConnection => close = true,
                _ => {}
            }
        }

        // Exactly one `decision=` line per answered event. Without it, a model that told this
        // peer nothing and a model that could not be reached looked identical: neither put a
        // frame on the wire, and neither said anything in the log.
        if undecodable > 0 && sent == 0 && !close {
            log.error(format!(
                "{} decision=fail_closed_bad_action: the answer's output was not valid UTF-8, \
                 so no signaling frame could be sent",
                subject
            ));
        } else if close {
            log.info(format!(
                "{} decision=model_reject: the model disconnected the peer",
                subject
            ));
        } else if sent > 0 {
            log.info(format!(
                "{} decision=model_answer: {} signaling frame(s) sent",
                subject, sent
            ));
        } else if result.raw_actions.is_empty() {
            log.warn(format!(
                "{} decision=model_silent: no action, so nothing was sent to the peer",
                subject
            ));
        } else if !result.failures.is_empty() {
            log.error(format!(
                "{} decision=fail_closed_bad_action: {}",
                subject,
                result
                    .failures
                    .iter()
                    .map(|f| format!("{}: {}", f.action, f.error))
                    .collect::<Vec<_>>()
                    .join("; ")
            ));
        } else {
            // Actions ran and none of them addressed this peer — `notify_operator` and friends.
            log.warn(format!(
                "{} decision=model_silent: the answer produced no signaling frame",
                subject
            ));
        }

        close
    }
}

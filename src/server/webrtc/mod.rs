//! WebRTC server: real peer connections carrying **data channels only** (no media).
//!
//! # Signalling
//!
//! WebRTC needs an out-of-band channel to exchange SDP. This server embeds one: it binds a
//! TCP listener on its configured port and speaks a tiny JSON protocol over WebSocket
//! (`tokio-tungstenite`, already declared by the `webrtc` feature). One WebSocket
//! connection carries exactly one peer:
//!
//! ```text
//! peer  -> {"type":"offer","peer_id":"alice","sdp":{"type":"offer","sdp":"v=0\r\n..."}}
//! netget-> {"type":"answer","peer_id":"alice","sdp":{"type":"answer","sdp":"v=0\r\n..."}}
//! netget-> {"type":"rejected","peer_id":"alice","reason":"..."}        (LLM said no)
//! netget-> {"type":"error","message":"..."}                            (malformed input)
//! ```
//!
//! ICE is **not** trickled: the offerer must gather its candidates before sending the offer,
//! and this server gathers all of its own before it answers. That removes the ICE-candidate
//! relay entirely, which is what makes a self-contained single-socket signalling channel
//! sufficient.
//!
//! The peer connection's lifetime is tied to its signalling WebSocket: when the socket
//! closes, the `RTCPeerConnection` is closed too. That is deliberate — it gives deterministic
//! cleanup for a protocol whose transport is otherwise invisible to the process.
//!
//! # Division of labour
//!
//! Rust owns the transport (webrtc-rs does ICE/DTLS/SCTP). The LLM decides *content*:
//! whether to accept an offer at all (`webrtc_offer_received` -> `accept_offer` /
//! `reject_offer`) and what to say on the data channel (`webrtc_peer_connected` and
//! `webrtc_message_received` -> `send_message` / `disconnect` / `wait_for_more`). No raw
//! SDP is ever handed to the model: it sees a structured summary of the offer and answers
//! with a decision, and this file keeps the SDP.
//!
//! The offer path is **fail-closed**. An LLM error, or a reply with no decision action in
//! it, rejects the offer; only an explicit `accept_offer` accepts. A model's explicit
//! `reject_offer` carries its own reason, so refusal and silence are distinguishable in the
//! signalling frame the peer receives.
//!
//! # Failure reaches the peer as a category, never as an error string
//!
//! Nothing derived from an internal error is written to the signalling socket or the data
//! channel. A backend failure on the offer path rejects with
//! [`crate::utils::WireFailure::prefixed_text`], and one on the data-channel path writes the
//! same category text on the channel rather than going silent and leaving the peer waiting.
//! The three outcomes stay apart in the log via a `decision=` tag: `model_reject` (the model
//! refused), `fail_closed_no_decision` (the model answered nothing usable), and
//! `fail_closed_backend_overloaded` / `fail_closed_backend_error` (the call itself failed —
//! kept distinct so an operator can tell a saturated backend from a broken one, which is the
//! `503`-vs-`500` distinction in a protocol that has no status codes of its own).

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

/// Longest a peer may take to complete the signalling WebSocket upgrade.
const SIGNALLING_HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Largest signalling message accepted, and this server's declared `max_inbound_bytes`.
/// One SDP offer or answer; a large real one is a few kilobytes.
///
/// tungstenite enforces it on the length a frame header declares, before the payload is read,
/// and on the reassembled message. It is the largest thing NetGet itself buffers from a peer:
/// data-channel messages are read by webrtc-rs into a fixed 65 535-byte buffer (a larger one
/// closes the channel inside the crate) and SCTP reassembly is capped by webrtc-sctp's 1 MiB
/// receive window, which drops DATA once full. Over the limit the peer gets a WebSocket close
/// with code 1009 (Message Too Big) and the connection ends.
pub const SIGNALLING_MAX_MESSAGE_BYTES: usize = 256 * 1024;

/// The close frame for a signalling message over [`SIGNALLING_MAX_MESSAGE_BYTES`]: RFC 6455's
/// 1009, with a fixed reason.
fn message_too_big_close() -> Message {
    Message::Close(Some(tokio_tungstenite::tungstenite::protocol::CloseFrame {
        code: tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Size,
        reason: "message too big".into(),
    }))
}

/// How long a signalling connection may go without a single frame from the peer.
///
/// The signalling WebSocket *is* the peer's lifetime here — the
/// peer connection it negotiates is torn down when it closes — so between the answer and the end
/// of the session it is normally silent while the data channel carries the traffic, and the
/// handshake deadline says nothing about that stretch. The bound is on the peer's **liveness**, not its conversation: at half of it the server
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

/// Largest number of data-channel events queued behind one in-flight LLM call.
///
/// Each queued event costs its own model round-trip when it is drained, so a peer
/// flooding the channel during a slow call both grows this without bound and buys
/// itself an unbounded number of calls. Dropping the oldest keeps the newest
/// traffic, which is what a conversation cares about.
const MAX_QUEUED_EVENTS: usize = 64;
use tracing::{debug, error, info, trace, warn};
use webrtc::api::interceptor_registry::register_default_interceptors;
use webrtc::api::media_engine::MediaEngine;
use webrtc::api::APIBuilder;
use webrtc::data_channel::data_channel_message::DataChannelMessage;
use webrtc::data_channel::RTCDataChannel;
use webrtc::ice_transport::ice_server::RTCIceServer;
use webrtc::interceptor::registry::Registry;
use webrtc::peer_connection::configuration::RTCConfiguration;
use webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState;
use webrtc::peer_connection::sdp::sdp_type::RTCSdpType;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;
use webrtc::peer_connection::RTCPeerConnection;

use crate::llm::action_helper::call_llm;
use crate::llm::ollama_client::OllamaClient;
use crate::llm::ActionResult;
use crate::protocol::Event;
use crate::server::connection::ConnectionId;
use crate::state::app_state::AppState;
use crate::state::ServerId;
use crate::utils::WireFailure;
use actions::{
    WEBRTC_MESSAGE_RECEIVED_EVENT, WEBRTC_OFFER_RECEIVED_EVENT, WEBRTC_PEER_CONNECTED_EVENT,
};

/// Unique identifier for a WebRTC peer
pub type PeerId = String;

/// Longest peer identifier accepted from the wire.
const MAX_PEER_ID_LEN: usize = 128;

/// Concurrent signalling connections this server admits before it starts refusing.
///
/// [`crate::server::accept_bounded::DEFAULT_MAX_CONNECTIONS`]. **`max_peers` is not this
/// bound and cannot be**: it gates *accepted offers*, so it counts peers that have already
/// completed a WebSocket handshake, sent an SDP offer and been approved by a handler, and a
/// stranger who merely connects is nowhere near it. [`SIGNALLING_HANDSHAKE_TIMEOUT`] bounds
/// how long one such stranger holds a socket, but ten seconds times an unbounded arrival rate
/// is still unbounded, so this is the only bound on the *number* of pre-admission peers.
///
/// The house default sits above `max_peers` on purpose. A signalling connection carries
/// exactly one peer for its lifetime (a second offer on the same socket is refused below), so
/// in a healthy server the two counts are nearly the same; the headroom is what a peer
/// negotiating *now* needs in order to reach `max_peers` and be told so in WebRTC's own
/// vocabulary — a `Rejected` frame naming the limit — rather than being turned away at the
/// accept with a generic 503. At the default `max_peers` of 32 that headroom is ample.
///
/// **Said plainly, because it is the one place these two numbers fight**: `max_peers` is a
/// startup parameter and may be set as high as 65535, and above 256 this constant becomes the
/// effective ceiling — offers 257 and beyond are refused at the accept rather than by the
/// peer registry. That is deliberate rather than an oversight. `accept_bounded`'s own rule is
/// that a bound decided by configuration is a bound an attacker can ask you to raise, so the
/// resource cap stays fixed and the configurable one may only make the server *stricter*.
const MAX_CONNECTIONS: usize = crate::server::accept_bounded::DEFAULT_MAX_CONNECTIONS;

/// The body of [`CONNECTION_CAP_REFUSAL`].
const CONNECTION_CAP_BODY: &str = "Too many signalling connections, try again later.\n";

/// What a peer over [`MAX_CONNECTIONS`] is told before the socket closes.
///
/// **WebRTC's own vocabulary does not reach this far, and HTTP's does.** This server has a
/// `Rejected` signalling frame that names the reason, and it is what a peer over `max_peers`
/// receives — but a `Rejected` frame is a *WebSocket text message*, and a peer refused at the
/// accept has not completed the RFC 6455 upgrade, so it has no frame parser running to read
/// one. Writing signalling JSON onto a socket still expecting an HTTP response is the mis-parse
/// this codebase refuses to ship.
///
/// The handshake it *is* in the middle of is an ordinary HTTP/1.1 GET (RFC 6455 §4.1), so 503
/// with `Retry-After` is inside the protocol rather than beside it, and every WebSocket client
/// surfaces a non-101 status as a failed handshake carrying that code. Sending it before the
/// request head has arrived is legal — RFC 9112 §3.3 lets a server answer before the request is
/// complete — and `Connection: close` tells a client still writing to stop and read.
static CONNECTION_CAP_REFUSAL: std::sync::LazyLock<Vec<u8>> = std::sync::LazyLock::new(|| {
    format!(
        "HTTP/1.1 503 Service Unavailable\r\nRetry-After: 30\r\nContent-Type: \
         text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        CONNECTION_CAP_BODY.len(),
        CONNECTION_CAP_BODY
    )
    .into_bytes()
});

/// Name used for the `ActionResult::Custom` carrying the model's offer decision.
pub(crate) const OFFER_DECISION_RESULT: &str = "webrtc_offer_decision";

/// Signalling frames exchanged over the WebSocket.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type")]
pub enum WebRtcSignal {
    /// Peer -> server: an SDP offer with all ICE candidates already gathered.
    #[serde(rename = "offer")]
    Offer {
        peer_id: String,
        /// Either `{"type":"offer","sdp":"..."}` or the raw SDP string.
        sdp: serde_json::Value,
    },

    /// Server -> peer: the SDP answer, ICE candidates included.
    #[serde(rename = "answer")]
    Answer {
        peer_id: String,
        sdp: serde_json::Value,
    },

    /// Server -> peer: the LLM declined this offer.
    #[serde(rename = "rejected")]
    Rejected { peer_id: String, reason: String },

    /// Server -> peer: the frame could not be processed at all.
    #[serde(rename = "error")]
    Error { message: String },
}

/// Connection state for LLM processing (one machine per peer)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnectionState {
    Idle,
    Processing,
    Accumulating,
}

/// One data-channel event awaiting the LLM.
#[derive(Debug, Clone)]
enum PeerEvent {
    Connected { channel_label: String },
    Message { text: String, is_binary: bool },
}

/// Per-peer data
struct PeerData {
    state: ConnectionState,
    /// Messages that arrived while an LLM call for this peer was in flight.
    queued: Vec<PeerEvent>,
    peer_connection: Arc<RTCPeerConnection>,
    data_channel: Option<Arc<RTCDataChannel>>,
    connection_id: ConnectionId,
}

/// WebRTC server data shared across all peers
pub struct WebRtcServerData {
    /// Peer connections indexed by peer ID
    peers: Arc<Mutex<HashMap<PeerId, PeerData>>>,
    /// WebRTC API for creating peer connections
    api: Arc<webrtc::api::API>,
    /// ICE server configuration (empty means host candidates only)
    ice_servers: Vec<RTCIceServer>,
    /// Refuse offers once this many peers are connected
    max_peers: usize,
}

impl WebRtcServerData {
    /// Build the webrtc-rs API object and peer table.
    ///
    /// `ice_server_urls` is empty by default: with no STUN/TURN configured the server offers
    /// host candidates only, which is what works on localhost and a LAN, and — importantly —
    /// contacts no external endpoint. A caller that needs NAT traversal passes STUN/TURN URLs
    /// through the `ice_servers` startup parameter.
    pub fn new(ice_server_urls: Vec<String>, max_peers: usize) -> Result<Self> {
        let mut m = MediaEngine::default();
        let registry = Registry::new();
        let registry = register_default_interceptors(registry, &mut m)?;

        let api = APIBuilder::new()
            .with_media_engine(m)
            .with_interceptor_registry(registry)
            .build();

        let ice_servers = ice_server_urls
            .into_iter()
            .map(|url| RTCIceServer {
                urls: vec![url],
                ..Default::default()
            })
            .collect();

        Ok(Self {
            peers: Arc::new(Mutex::new(HashMap::new())),
            api: Arc::new(api),
            ice_servers,
            max_peers,
        })
    }

    /// Accept an SDP offer from a peer and produce the answer.
    ///
    /// The peer is inserted into the peer table *before* the remote description is applied,
    /// because `on_data_channel` can fire as soon as SCTP comes up and must find it there.
    #[allow(clippy::too_many_arguments)]
    async fn accept_offer(
        self: &Arc<Self>,
        peer_id: PeerId,
        offer: RTCSessionDescription,
        connection_id: ConnectionId,
        signalling_addr: SocketAddr,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        server_id: ServerId,
    ) -> Result<serde_json::Value> {
        info!("WebRTC server accepting offer from peer {}", peer_id);

        let config = RTCConfiguration {
            ice_servers: self.ice_servers.clone(),
            ..Default::default()
        };

        let peer_connection = Arc::new(
            self.api
                .new_peer_connection(config)
                .await
                .context("Failed to create RTCPeerConnection")?,
        );

        // Register the peer before anything can fire a callback that looks for it.
        {
            let mut peers = self.peers.lock().await;
            peers.insert(
                peer_id.clone(),
                PeerData {
                    state: ConnectionState::Idle,
                    queued: Vec::new(),
                    peer_connection: Arc::clone(&peer_connection),
                    data_channel: None,
                    connection_id,
                },
            );
        }

        let ctx = PeerCtx {
            server_data: Arc::clone(self),
            peer_id: peer_id.clone(),
            connection_id,
            server_id,
            app_state: Arc::clone(&app_state),
            llm_client,
            status_tx: status_tx.clone(),
        };

        // Incoming data channel (the offerer creates it; we only ever accept one).
        let dc_ctx = ctx.clone();
        peer_connection.on_data_channel(Box::new(move |data_channel: Arc<RTCDataChannel>| {
            let ctx = dc_ctx.clone();
            Box::pin(async move {
                let label = data_channel.label().to_string();
                info!(
                    "WebRTC server received data channel '{}' from peer {}",
                    label, ctx.peer_id
                );

                {
                    let mut peers = ctx.server_data.peers.lock().await;
                    if let Some(peer) = peers.get_mut(&ctx.peer_id) {
                        peer.data_channel = Some(Arc::clone(&data_channel));
                    }
                }

                let open_ctx = ctx.clone();
                let open_label = label.clone();
                data_channel.on_open(Box::new(move || {
                    let ctx = open_ctx.clone();
                    let channel_label = open_label.clone();
                    Box::pin(async move {
                        info!(
                            "WebRTC data channel '{}' open for peer {}",
                            channel_label, ctx.peer_id
                        );
                        let _ = ctx
                            .status_tx
                            .send(format!("[SERVER] WebRTC peer {} connected", ctx.peer_id));
                        let _ = ctx.status_tx.send("__UPDATE_UI__".to_string());
                        ctx.handle_peer_event(PeerEvent::Connected { channel_label })
                            .await;
                    })
                }));

                let msg_ctx = ctx.clone();
                data_channel.on_message(Box::new(move |msg: DataChannelMessage| {
                    let ctx = msg_ctx.clone();
                    Box::pin(async move {
                        let text = String::from_utf8_lossy(&msg.data).to_string();
                        trace!(
                            "WebRTC server received {} bytes from peer {}",
                            msg.data.len(),
                            ctx.peer_id
                        );
                        ctx.record_traffic(msg.data.len() as u64, 0).await;
                        ctx.handle_peer_event(PeerEvent::Message {
                            text,
                            is_binary: !msg.is_string,
                        })
                        .await;
                    })
                }));
            })
        }));

        // Connection teardown.
        let state_ctx = ctx.clone();
        peer_connection.on_peer_connection_state_change(Box::new(
            move |state: RTCPeerConnectionState| {
                let ctx = state_ctx.clone();
                Box::pin(async move {
                    debug!("WebRTC peer {} connection state: {:?}", ctx.peer_id, state);
                    if matches!(
                        state,
                        RTCPeerConnectionState::Failed
                            | RTCPeerConnectionState::Closed
                            | RTCPeerConnectionState::Disconnected
                    ) {
                        ctx.teardown(&format!("connection state {:?}", state)).await;
                    }
                })
            },
        ));

        // Offer -> answer. Anything that fails from here on must not leave a half-registered
        // peer behind, so each error path unregisters before returning.
        let answer = match Self::negotiate(&peer_connection, offer).await {
            Ok(answer) => answer,
            Err(e) => {
                ctx.teardown("negotiation failed").await;
                return Err(e);
            }
        };

        // Register the connection with the server instance for the TUI / access log.
        use crate::state::server::{
            ConnectionState as ServerConnectionState, ConnectionStatus, ProtocolConnectionInfo,
        };
        let now = crate::utils::clock::Instant::now();
        let unspecified = SocketAddr::from(([0, 0, 0, 0], 0));
        let conn_state = ServerConnectionState {
            id: connection_id,
            // WebRTC is peer-to-peer over ICE, so there is no single stable remote
            // address for the *media* path; the signalling socket's address is the
            // one thing that is both stable and true, so it is what the dashboard
            // and the access log show.
            //
            // This comment used to say the address "is recorded by the caller
            // instead". No caller did: the row read 0.0.0.0:0 for the life of
            // every peer. A comment asserting that something happens elsewhere is
            // worth checking — that is the whole reason this one survived.
            remote_addr: signalling_addr,
            local_addr: unspecified,
            bytes_sent: 0,
            bytes_received: 0,
            packets_sent: 0,
            packets_received: 0,
            last_activity: now,
            status: ConnectionStatus::Active,
            status_changed_at: now,
            protocol_info: ProtocolConnectionInfo::new(serde_json::json!({
                "peer_id": peer_id,
                "state": "Idle",
            })),
        };
        app_state
            .add_connection_to_server(server_id, conn_state)
            .await;

        info!("WebRTC server generated SDP answer for peer {}", peer_id);
        serde_json::to_value(&answer).context("Failed to serialise SDP answer")
    }

    /// Apply the offer, create the answer and wait for ICE gathering to finish.
    async fn negotiate(
        peer_connection: &Arc<RTCPeerConnection>,
        offer: RTCSessionDescription,
    ) -> Result<RTCSessionDescription> {
        peer_connection
            .set_remote_description(offer)
            .await
            .context("Peer's SDP offer was rejected by the WebRTC stack")?;

        let answer = peer_connection
            .create_answer(None)
            .await
            .context("Failed to create SDP answer")?;

        // `gathering_complete_promise` must be taken before the local description is set,
        // otherwise gathering can finish before anyone is listening and the promise never
        // resolves.
        let mut gather_complete = peer_connection.gathering_complete_promise().await;
        peer_connection
            .set_local_description(answer)
            .await
            .context("Failed to set local description")?;
        let _ = gather_complete.recv().await;

        peer_connection
            .local_description()
            .await
            .context("No local description after ICE gathering")
    }

    /// Number of peers currently registered.
    pub async fn peer_count(&self) -> usize {
        self.peers.lock().await.len()
    }

    /// Whether a peer id is already taken.
    pub async fn has_peer(&self, peer_id: &str) -> bool {
        self.peers.lock().await.contains_key(peer_id)
    }

    /// List all active peer IDs
    pub async fn list_peers(&self) -> Vec<String> {
        self.peers.lock().await.keys().cloned().collect()
    }

    /// Send a text message to a specific peer over its data channel.
    pub async fn send_to_peer(&self, peer_id: &str, message: String) -> Result<()> {
        let channel = {
            let peers = self.peers.lock().await;
            let peer = peers
                .get(peer_id)
                .with_context(|| format!("Peer {} not found", peer_id))?;
            peer.data_channel.clone()
        };
        let channel =
            channel.with_context(|| format!("Data channel not open for peer {}", peer_id))?;
        channel
            .send_text(message)
            .await
            .with_context(|| format!("Failed to send to peer {}", peer_id))?;
        Ok(())
    }
}

/// Everything a peer callback needs, in one cheaply cloned bundle.
///
/// Callbacks are `FnMut` boxes that must own their captures, so without this every callback
/// body would begin with eight `Arc::clone` lines.
#[derive(Clone)]
struct PeerCtx {
    server_data: Arc<WebRtcServerData>,
    peer_id: PeerId,
    connection_id: ConnectionId,
    server_id: ServerId,
    app_state: Arc<AppState>,
    llm_client: OllamaClient,
    status_tx: mpsc::UnboundedSender<String>,
}

impl PeerCtx {
    /// Per-peer state machine: Idle -> Processing -> (Accumulating) -> Idle.
    ///
    /// Only one LLM call per peer is ever in flight. Events that arrive during a call are
    /// queued and drained by the task that owns the machine, so nothing is dropped and no
    /// two calls race on the same data channel.
    async fn handle_peer_event(&self, event: PeerEvent) {
        // Claim the machine, or queue and return.
        let claimed = {
            let mut peers = self.server_data.peers.lock().await;
            match peers.get_mut(&self.peer_id) {
                Some(peer) => match peer.state {
                    ConnectionState::Idle => {
                        peer.state = ConnectionState::Processing;
                        true
                    }
                    ConnectionState::Processing | ConnectionState::Accumulating => {
                        peer.state = ConnectionState::Accumulating;
                        // Bounded: this was an unbounded `Vec` fed by whatever the
                        // peer sends while one LLM call is in flight, and each
                        // entry later costs its own round-trip. Dropping the
                        // oldest keeps the newest traffic, which is what a
                        // conversation cares about, and the WARN says so rather
                        // than losing messages silently.
                        if peer.queued.len() >= MAX_QUEUED_EVENTS {
                            peer.queued.remove(0);
                            warn!(
                                "WebRTC peer {} queued more than {} events during one LLM \
                                 call; dropping the oldest",
                                self.peer_id, MAX_QUEUED_EVENTS
                            );
                        }
                        peer.queued.push(event.clone());
                        false
                    }
                },
                None => {
                    warn!("WebRTC event for unknown peer {} — dropping", self.peer_id);
                    false
                }
            }
        };
        if !claimed {
            return;
        }

        let mut current = event;
        loop {
            self.process_event(current).await;

            let next = {
                let mut peers = self.server_data.peers.lock().await;
                match peers.get_mut(&self.peer_id) {
                    Some(peer) if !peer.queued.is_empty() => {
                        peer.state = ConnectionState::Processing;
                        Some(peer.queued.remove(0))
                    }
                    Some(peer) => {
                        peer.state = ConnectionState::Idle;
                        None
                    }
                    None => None,
                }
            };
            match next {
                Some(event) => current = event,
                None => break,
            }
        }
    }

    /// One LLM round-trip for one data-channel event, and the actions it produced.
    async fn process_event(&self, event: PeerEvent) {
        let netget_event = match &event {
            PeerEvent::Connected { channel_label } => Event::new(
                &WEBRTC_PEER_CONNECTED_EVENT,
                serde_json::json!({
                    "peer_id": self.peer_id,
                    "channel_label": channel_label,
                }),
            ),
            PeerEvent::Message { text, is_binary } => Event::new(
                &WEBRTC_MESSAGE_RECEIVED_EVENT,
                serde_json::json!({
                    "peer_id": self.peer_id,
                    "message": text,
                    "is_binary": is_binary,
                }),
            ),
        };

        let protocol = crate::server::WebRtcProtocol::new();
        let result = match call_llm(
            &self.llm_client,
            &self.app_state,
            self.server_id,
            Some(self.connection_id),
            &netget_event,
            &protocol,
        )
        .await
        {
            Ok(result) => result,
            Err(e) => {
                // Silence would leave the peer waiting on a data channel that will never
                // answer. It gets a category on that channel; the error stays in the log.
                let failure = WireFailure::classify(&e);
                let decision = backend_failure_tag(failure);
                crate::logging::emit::Log::to(&self.status_tx).error(format!(
                    "WebRTC peer {} ({}) (decision={}): no response generated, LLM call \
                     failed: {}",
                    self.peer_id,
                    netget_event.id(),
                    decision,
                    e
                ));
                self.send_on_channel(failure.prefixed_text().to_string())
                    .await;
                return;
            }
        };

        let mut outputs: Vec<Vec<u8>> = Vec::new();
        let mut close = false;
        for action_result in &result.protocol_results {
            collect_result(action_result, &mut outputs, &mut close);
        }

        for bytes in outputs {
            self.send_on_channel(String::from_utf8_lossy(&bytes).to_string())
                .await;
        }

        if close {
            info!("WebRTC closing peer {} on model request", self.peer_id);
            self.teardown("closed by model").await;
        }
    }

    /// Add one data-channel message to this connection's counters.
    ///
    /// Nothing called `update_connection_stats` here, so the rail's `↓/↑` columns
    /// stayed at the zeros the connection was registered with for the life of
    /// every peer — a live data channel was indistinguishable from an idle one.
    /// The 10-second idle sweep is not a hazard: `connectionless()` is correctly
    /// not declared, so it never looks at these connections.
    async fn record_traffic(&self, received: u64, sent: u64) {
        self.app_state
            .update_connection_stats(
                self.server_id,
                self.connection_id,
                (received > 0).then_some(received),
                (sent > 0).then_some(sent),
                (received > 0).then_some(1),
                (sent > 0).then_some(1),
            )
            .await;
    }

    /// Write one text message on this peer's data channel, if it has an open one.
    async fn send_on_channel(&self, text: String) {
        let channel = {
            let peers = self.server_data.peers.lock().await;
            peers
                .get(&self.peer_id)
                .and_then(|peer| peer.data_channel.clone())
        };
        match channel {
            Some(channel) => match channel.send_text(text).await {
                Ok(n) => {
                    trace!("WebRTC sent {} bytes to peer {}", n, self.peer_id);
                    self.record_traffic(0, n as u64).await;
                }
                Err(e) => error!("WebRTC failed to send to peer {}: {}", self.peer_id, e),
            },
            None => warn!(
                "WebRTC has no open data channel for peer {}; response dropped",
                self.peer_id
            ),
        }
    }

    /// Remove the peer, close its `RTCPeerConnection` and drop its connection record.
    ///
    /// Idempotent: the peer connection state callback and the signalling socket's cleanup
    /// both call it, and whichever loses removes nothing.
    async fn teardown(&self, reason: &str) {
        let peer = {
            let mut peers = self.server_data.peers.lock().await;
            peers.remove(&self.peer_id)
        };
        let Some(peer) = peer else {
            return;
        };

        info!("WebRTC peer {} torn down: {}", self.peer_id, reason);
        let _ = peer.peer_connection.close().await;
        self.app_state
            .remove_connection_from_server(self.server_id, peer.connection_id)
            .await;
        let _ = self.status_tx.send(format!(
            "[SERVER] WebRTC peer {} disconnected",
            self.peer_id
        ));
        let _ = self.status_tx.send("__UPDATE_UI__".to_string());
    }
}

/// Flatten an `ActionResult` (which may nest via `Multiple`) into outputs and a close flag.
fn collect_result(result: &ActionResult, outputs: &mut Vec<Vec<u8>>, close: &mut bool) {
    match result {
        ActionResult::Output(bytes) => outputs.push(bytes.clone()),
        ActionResult::CloseConnection => *close = true,
        ActionResult::Multiple(inner) => {
            for r in inner {
                collect_result(r, outputs, close);
            }
        }
        ActionResult::WaitForMore | ActionResult::NoAction | ActionResult::Custom { .. } => {}
    }
}

/// The model's verdict on an incoming offer.
enum OfferDecision {
    Accept,
    /// Refuse the offer. `reason` is peer-visible free text and must never carry an internal
    /// error; `decision` is the log tag that keeps a model refusal, a model silence and a
    /// backend failure distinguishable after the fact.
    Reject {
        reason: String,
        decision: &'static str,
    },
}

/// WebRTC server: WebSocket signalling in front of webrtc-rs peer connections.
pub struct WebRtcServer;

impl WebRtcServer {
    /// Bind the signalling listener and start accepting peers.
    ///
    /// Returns only once the socket is bound, so a bind failure surfaces as
    /// `ServerStatus::Error` rather than a server that reports Running and listens to
    /// nothing.
    #[allow(clippy::too_many_arguments)]
    pub async fn spawn_with_llm_actions(
        listen_addr: SocketAddr,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        server_id: ServerId,
        ice_server_urls: Vec<String>,
        max_peers: usize,
        idle_timeout: std::time::Duration,
    ) -> Result<SocketAddr> {
        let listener = TcpListener::bind(listen_addr)
            .await
            .with_context(|| format!("WebRTC signalling failed to bind {}", listen_addr))?;
        let local_addr = listener
            .local_addr()
            .context("WebRTC signalling socket has no local address")?;

        let server_data = Arc::new(WebRtcServerData::new(ice_server_urls, max_peers)?);

        crate::logging::emit::Log::to(&status_tx).info(format!(
            "WebRTC data-channel server, WebSocket SDP signalling, listening on {}",
            local_addr
        ));

        let accept_state = Arc::clone(&app_state);
        let limiter = crate::server::accept_bounded::ConnectionLimiter::new(MAX_CONNECTIONS);
        let cap_status_tx = status_tx.clone();
        let accept_handle = tokio::spawn(async move {
            loop {
                match crate::server::accept_bounded::accept_bounded(
                    &listener,
                    &limiter,
                    &CONNECTION_CAP_REFUSAL,
                    "WEBRTC",
                    Some(&cap_status_tx),
                )
                .await
                {
                    Ok((stream, remote_addr, permit)) => {
                        let server_data = Arc::clone(&server_data);
                        let app_state = Arc::clone(&app_state);
                        let status_tx = status_tx.clone();
                        let llm_client = llm_client.clone();
                        // Tracked, not detached: stop_server must abort this task too.
                        let task_owner = app_state.clone();
                        task_owner
                            .spawn_server_task(server_id, async move {
                                // Released when this task ends, and this task is the whole of
                                // the connection: `handle_signalling` spawns a writer task but
                                // `.await`s it on its only exit path, and the peer connection
                                // it negotiates is torn down there too, so `MAX_CONNECTIONS`
                                // caps live signalling connections rather than accepts.
                                let _permit = permit;
                                if let Err(e) = Self::handle_signalling(
                                    stream,
                                    remote_addr,
                                    server_data,
                                    app_state,
                                    status_tx,
                                    llm_client,
                                    server_id,
                                    idle_timeout,
                                )
                                .await
                                {
                                    debug!(
                                        "WebRTC signalling connection from {} ended: {}",
                                        remote_addr, e
                                    );
                                }
                            })
                            .await;
                    }
                    Err(e) => {
                        error!("WebRTC signalling accept failed: {}", e);
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    }
                }
            }
        });

        accept_state
            .register_server_task(server_id, accept_handle)
            .await;

        Ok(local_addr)
    }

    /// One signalling WebSocket = one peer.
    #[allow(clippy::too_many_arguments)]
    async fn handle_signalling(
        stream: TcpStream,
        remote_addr: SocketAddr,
        server_data: Arc<WebRtcServerData>,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        llm_client: OllamaClient,
        server_id: ServerId,
        idle_timeout: std::time::Duration,
    ) -> Result<()> {
        // Two bounds, both absent before and both reachable by anyone who can open
        // a TCP connection — `max_peers` gates *accepted offers*, so it bounds
        // neither of these:
        //
        // * The handshake gets a deadline. A socket that connects and never sends
        //   an HTTP upgrade parked inside `accept_async` forever, holding a task
        //   and an fd.
        // * Frames get a size limit. Bare `accept_async` takes tungstenite's
        //   defaults of 64 MiB per message and 16 MiB per frame, so a single
        //   pre-admission peer could make the server buffer 64 MiB. Signalling
        //   here carries one SDP offer or answer; the largest real one is a few
        //   kilobytes, so 256 KiB is generous by two orders of magnitude.
        let config = WebSocketConfig {
            max_message_size: Some(SIGNALLING_MAX_MESSAGE_BYTES),
            max_frame_size: Some(SIGNALLING_MAX_MESSAGE_BYTES),
            ..Default::default()
        };
        // Taken before the socket is wrapped: cutting off a peer that does not read ends its
        // connection.
        let closer = crate::utils::outbox::ConnectionCloser::for_stream(&stream);
        let ws = tokio::time::timeout(
            SIGNALLING_HANDSHAKE_TIMEOUT,
            accept_async_with_config(stream, Some(config)),
        )
        .await
        .map_err(|_| {
            anyhow::anyhow!(
                "WebSocket handshake from {} did not complete within {:?}",
                remote_addr,
                SIGNALLING_HANDSHAKE_TIMEOUT
            )
        })?
        .context("WebSocket handshake failed")?;
        debug!(
            "WebRTC signalling connection established with {}",
            remote_addr
        );

        let (mut ws_tx, mut ws_rx) = ws.split();

        // A writer task owns the sink so the read loop never blocks on a slow peer.
        // Bounded: every bad frame is answered at once, so a peer that sends without reading
        // is cut off rather than queued for (`utils::outbox`).
        let (out_tx, mut out_rx) = crate::utils::outbox::channel(
            format!("WebRTC signalling connection {remote_addr}"),
            crate::utils::outbox::OutboxLimits::DEFAULT,
            Message::len,
        );
        out_tx.close_on_cut_off(closer);
        let writer = tokio::spawn(async move {
            while let Some(msg) = out_rx.recv().await {
                if ws_tx.send(msg).await.is_err() {
                    break;
                }
            }
            let _ = ws_tx.close().await;
        });

        let mut peer_ctx: Option<PeerCtx> = None;

        // Touched by every inbound frame, Pongs included, and busy while one is handled.
        let activity = Arc::new(crate::server::accept_bounded::ConnectionActivity::new());

        loop {
            let keepalive_tx = out_tx.clone();
            let frame = tokio::select! {
                frame = ws_rx.next() => frame,
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
                        "WebRTC signalling from {} sent no frame for {}s, not even a Pong; \
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
            let Some(frame) = frame else { break };
            // Busy for the rest of this iteration. The offer decision below runs inline, so the
            // watchdog is not even polled while it is outstanding — but the guard's release is
            // what gives the connection a fresh bound afterwards. Without it, a decision parked
            // for a human longer than the bound would come back to a clock that had long run
            // out, and the peer would be closed the instant its answer was sent.
            let _busy = activity.busy();
            let frame = match frame {
                Ok(frame) => frame,
                Err(tokio_tungstenite::tungstenite::Error::Capacity(e)) => {
                    warn!(
                        "WebRTC signalling message from {} over {} bytes \
                         decision=fail_closed_message_too_large: {}",
                        remote_addr, SIGNALLING_MAX_MESSAGE_BYTES, e
                    );
                    let _ = out_tx.send(message_too_big_close());
                    break;
                }
                Err(e) => {
                    debug!("WebRTC signalling read error from {}: {}", remote_addr, e);
                    break;
                }
            };

            let text = match frame {
                Message::Text(text) => text,
                Message::Close(_) => break,
                Message::Binary(_) => {
                    send_signal(
                        &out_tx,
                        &WebRtcSignal::Error {
                            message: "signalling frames must be JSON text".to_string(),
                        },
                    );
                    continue;
                }
                Message::Ping(_) | Message::Pong(_) | Message::Frame(_) => continue,
            };

            let signal: WebRtcSignal = match serde_json::from_str(&text) {
                Ok(signal) => signal,
                Err(e) => {
                    // serde's message quotes the offending input and names internal types, so
                    // it is logged rather than sent - see `crate::utils::wire_failure`.
                    debug!("WebRTC signalling frame did not parse: {e}");
                    send_signal(
                        &out_tx,
                        &WebRtcSignal::Error {
                            message: "malformed signalling frame".to_string(),
                        },
                    );
                    continue;
                }
            };

            let (peer_id, sdp) = match signal {
                WebRtcSignal::Offer { peer_id, sdp } => (peer_id, sdp),
                other => {
                    send_signal(
                        &out_tx,
                        &WebRtcSignal::Error {
                            message: format!(
                                "only 'offer' frames are accepted by this server, got '{}'",
                                signal_name(&other)
                            ),
                        },
                    );
                    continue;
                }
            };

            if peer_ctx.is_some() {
                send_signal(
                    &out_tx,
                    &WebRtcSignal::Error {
                        message: "this signalling connection already carries a peer; open a new \
                                  WebSocket for another peer"
                            .to_string(),
                    },
                );
                continue;
            }

            let peer_id = peer_id.trim().to_string();
            if peer_id.is_empty() || peer_id.chars().count() > MAX_PEER_ID_LEN {
                send_signal(
                    &out_tx,
                    &WebRtcSignal::Error {
                        message: format!("peer_id must be 1..={} characters", MAX_PEER_ID_LEN),
                    },
                );
                continue;
            }

            if server_data.has_peer(&peer_id).await {
                send_signal(
                    &out_tx,
                    &WebRtcSignal::Error {
                        message: format!("peer_id '{}' is already connected", peer_id),
                    },
                );
                continue;
            }

            if server_data.peer_count().await >= server_data.max_peers {
                send_signal(
                    &out_tx,
                    &WebRtcSignal::Rejected {
                        peer_id: peer_id.clone(),
                        reason: format!(
                            "server is at its max_peers limit of {}",
                            server_data.max_peers
                        ),
                    },
                );
                continue;
            }

            let offer = match parse_offer(&sdp) {
                Ok(offer) => offer,
                Err(e) => {
                    debug!("WebRTC SDP offer was unusable: {e}");
                    send_signal(
                        &out_tx,
                        &WebRtcSignal::Error {
                            message: "unusable SDP offer".to_string(),
                        },
                    );
                    continue;
                }
            };

            let connection_id = ConnectionId::new(app_state.get_next_unified_id().await);

            let decision = Self::decide_offer(
                &peer_id,
                remote_addr,
                &offer,
                connection_id,
                &llm_client,
                &app_state,
                server_id,
            )
            .await;

            match decision {
                OfferDecision::Reject { reason, decision } => {
                    info!(
                        "WebRTC offer from {} rejected (decision={}): {}",
                        peer_id, decision, reason
                    );
                    let _ = status_tx.send(format!(
                        "[SERVER] WebRTC offer from {} rejected (decision={}): {}",
                        peer_id, decision, reason
                    ));
                    send_signal(
                        &out_tx,
                        &WebRtcSignal::Rejected {
                            peer_id: peer_id.clone(),
                            reason,
                        },
                    );
                }
                OfferDecision::Accept => {
                    match server_data
                        .accept_offer(
                            peer_id.clone(),
                            offer,
                            connection_id,
                            remote_addr,
                            llm_client.clone(),
                            Arc::clone(&app_state),
                            status_tx.clone(),
                            server_id,
                        )
                        .await
                    {
                        Ok(answer) => {
                            peer_ctx = Some(PeerCtx {
                                server_data: Arc::clone(&server_data),
                                peer_id: peer_id.clone(),
                                connection_id,
                                server_id,
                                app_state: Arc::clone(&app_state),
                                llm_client: llm_client.clone(),
                                status_tx: status_tx.clone(),
                            });
                            send_signal(
                                &out_tx,
                                &WebRtcSignal::Answer {
                                    peer_id: peer_id.clone(),
                                    sdp: answer,
                                },
                            );
                        }
                        Err(e) => {
                            // webrtc-rs' error names library internals; log it, and tell the
                            // peer only that negotiation did not complete.
                            error!(
                                "WebRTC failed to answer peer {} (decision=negotiation_failed): {}",
                                peer_id, e
                            );
                            send_signal(
                                &out_tx,
                                &WebRtcSignal::Error {
                                    message: "the peer connection could not be established"
                                        .to_string(),
                                },
                            );
                        }
                    }
                }
            }
        }

        // The peer connection's lifetime is the signalling socket's lifetime.
        if let Some(ctx) = peer_ctx {
            ctx.teardown("signalling connection closed").await;
        }
        drop(out_tx);
        let _ = writer.await;
        Ok(())
    }

    /// Ask the LLM whether to accept this offer. Anything other than an explicit
    /// `accept_offer` is a refusal.
    #[allow(clippy::too_many_arguments)]
    async fn decide_offer(
        peer_id: &str,
        remote_addr: SocketAddr,
        offer: &RTCSessionDescription,
        connection_id: ConnectionId,
        llm_client: &OllamaClient,
        app_state: &Arc<AppState>,
        server_id: ServerId,
    ) -> OfferDecision {
        let summary = summarise_offer(&offer.sdp);
        let event = Event::new(
            &WEBRTC_OFFER_RECEIVED_EVENT,
            serde_json::json!({
                "peer_id": peer_id,
                "remote_addr": remote_addr.to_string(),
                "requests_data_channel": summary.data_channel,
                "media_kinds": summary.media_kinds,
            }),
        );

        let protocol = crate::server::WebRtcProtocol::new();
        let result = match call_llm(
            llm_client,
            app_state,
            server_id,
            Some(connection_id),
            &event,
            &protocol,
        )
        .await
        {
            Ok(result) => result,
            Err(e) => {
                // The peer gets a category; the error itself stays in the log. See
                // `crate::utils::wire_failure`.
                let failure = WireFailure::classify(&e);
                let decision = backend_failure_tag(failure);
                error!(
                    "WebRTC offer decision failed for peer {} (decision={}): {}",
                    peer_id, decision, e
                );
                return OfferDecision::Reject {
                    reason: failure.prefixed_text().to_string(),
                    decision,
                };
            }
        };

        for action_result in &result.protocol_results {
            if let Some(decision) = offer_decision(action_result) {
                return decision;
            }
        }

        OfferDecision::Reject {
            reason: "the model returned no accept_offer or reject_offer action; refusing by \
                     default"
                .to_string(),
            decision: "fail_closed_no_decision",
        }
    }
}

/// The `decision=` log tag for a backend failure.
///
/// Overload and everything else are kept apart because they are the same distinction a
/// protocol with status codes expresses as 503 vs 500: one says "retry", the other does not.
/// The signalling protocol has no codes, so the split lives in the log and in the two
/// `WireFailure` texts.
fn backend_failure_tag(failure: WireFailure) -> &'static str {
    if failure.is_overloaded() {
        "fail_closed_backend_overloaded"
    } else {
        "fail_closed_backend_error"
    }
}

/// Extract an offer decision from an action result, descending into `Multiple`.
fn offer_decision(result: &ActionResult) -> Option<OfferDecision> {
    match result {
        ActionResult::Custom { name, data } if name == OFFER_DECISION_RESULT => {
            if data
                .get("accept")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
            {
                Some(OfferDecision::Accept)
            } else {
                Some(OfferDecision::Reject {
                    reason: data
                        .get("reason")
                        .and_then(|v| v.as_str())
                        .unwrap_or("the model rejected this offer")
                        .to_string(),
                    decision: "model_reject",
                })
            }
        }
        ActionResult::Multiple(inner) => inner.iter().find_map(offer_decision),
        _ => None,
    }
}

/// Frame name for error messages.
fn signal_name(signal: &WebRtcSignal) -> &'static str {
    match signal {
        WebRtcSignal::Offer { .. } => "offer",
        WebRtcSignal::Answer { .. } => "answer",
        WebRtcSignal::Rejected { .. } => "rejected",
        WebRtcSignal::Error { .. } => "error",
    }
}

/// Queue a signalling frame for the writer task.
fn send_signal(out_tx: &crate::utils::outbox::OutboxSender<Message>, signal: &WebRtcSignal) {
    match serde_json::to_string(signal) {
        Ok(json) => {
            let _ = out_tx.send(Message::Text(json));
        }
        Err(e) => error!("WebRTC failed to serialise signalling frame: {}", e),
    }
}

/// Accept either `{"type":"offer","sdp":"..."}` or a bare SDP string.
///
/// The SDP body is parsed here, before the model is consulted: an offer webrtc-rs cannot
/// read is not worth an LLM round-trip, and `set_remote_description` would only reject it
/// afterwards — with the peer already counted as a decision the model made.
fn parse_offer(sdp: &serde_json::Value) -> Result<RTCSessionDescription> {
    let raw = match sdp.as_str() {
        Some(raw) => raw.to_string(),
        None => {
            let description: RTCSessionDescription = serde_json::from_value(sdp.clone())
                .context("expected {\"type\":\"offer\",\"sdp\":\"...\"} or an SDP string")?;
            if description.sdp_type != RTCSdpType::Offer {
                anyhow::bail!(
                    "expected an SDP of type 'offer', got '{}'",
                    description.sdp_type
                );
            }
            description.sdp
        }
    };

    RTCSessionDescription::offer(raw).context("SDP could not be parsed as an offer")
}

/// Structured, model-facing view of an SDP offer.
struct OfferSummary {
    data_channel: bool,
    media_kinds: Vec<String>,
}

/// Summarise an SDP offer for the model.
///
/// The model never sees the SDP itself — it is long, it is not something a model can
/// usefully edit, and an action parameter carrying it would violate the structured-fields
/// rule. It sees only what it needs to decide: whether a data channel is requested and what
/// media, if any, the peer wants (this server supports none).
fn summarise_offer(sdp: &str) -> OfferSummary {
    let mut data_channel = false;
    let mut media_kinds = Vec::new();
    for line in sdp.lines() {
        let Some(media) = line.trim().strip_prefix("m=") else {
            continue;
        };
        let kind = media.split_whitespace().next().unwrap_or("");
        match kind {
            "application" => data_channel = true,
            "" => {}
            other => {
                let other = other.to_string();
                if !media_kinds.contains(&other) {
                    media_kinds.push(other);
                }
            }
        }
    }
    OfferSummary {
        data_channel,
        media_kinds,
    }
}

//! WebRTC client implementation (data channels only, no media)
//!
//! Enhancements:
//! - WebSocket signaling support for automatic SDP exchange
//! - Multi-channel support (create multiple data channels)
//! - Binary data support (hex encoding/decoding)

pub mod actions;

pub use actions::WebRtcClientProtocol;

use anyhow::{Context, Result};
use futures::{SinkExt, StreamExt};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use tokio_tungstenite::{connect_async, tungstenite::Message as WsMessage};
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
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;
use webrtc::peer_connection::RTCPeerConnection;

use crate::client::llm_budget::{call_llm_for_client, call_llm_for_client_batch};
use crate::client::webrtc::actions::{
    WEBRTC_CLIENT_CHANNEL_OPENED_EVENT, WEBRTC_CLIENT_MESSAGE_RECEIVED_EVENT,
    WEBRTC_CLIENT_SIGNALING_CONNECTED_EVENT,
};
use crate::llm::ollama_client::OllamaClient;
use crate::llm::ClientLlmResult;
use crate::protocol::Event;
use crate::state::app_state::AppState;
use crate::state::{ClientId, ClientStatus};

/// Signaling mode for WebRTC connection setup
#[derive(Debug, Clone, PartialEq)]
pub enum SignalingMode {
    /// Manual SDP exchange (user copy-paste)
    Manual,
    /// Automatic SDP exchange via WebSocket signaling server
    WebSocket { url: String, peer_id: String },
}

/// How many messages one channel may hold while the model answers an earlier one. Past it the
/// channel's message handler waits, which stops webrtc-rs reading the channel, so SCTP flow
/// control holds the peer back rather than anything being dropped.
const CHANNEL_QUEUE_MESSAGES: usize = crate::protocol::metadata::MAX_BATCH_EVENTS;

/// Per-channel data
struct ChannelData {
    /// The live channel, used to send on it from outside the on_message closure
    /// (injected commands go through this).
    channel: Arc<RTCDataChannel>,
}

/// Per-client data for LLM handling
struct ClientData {
    shutdown: tokio_util::sync::CancellationToken,
    memory: String,
    channels: HashMap<String, ChannelData>, // channel_label -> data
}

/// Owns the async close operation even when AppState aborts the client tasks.
#[derive(Clone)]
pub struct PeerConnectionGuard(Arc<PeerCleanup>);
struct PeerCleanup {
    peer: Arc<RTCPeerConnection>,
    shutdown: tokio_util::sync::CancellationToken,
}
impl PeerConnectionGuard {
    pub fn new(peer: Arc<RTCPeerConnection>) -> Self {
        Self(Arc::new(PeerCleanup {
            peer,
            shutdown: tokio_util::sync::CancellationToken::new(),
        }))
    }
    pub fn cancellation_token(&self) -> tokio_util::sync::CancellationToken {
        self.0.shutdown.clone()
    }
}
impl Drop for PeerCleanup {
    fn drop(&mut self) {
        self.shutdown.cancel();
        let peer = self.peer.clone();
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                if let Err(error) = peer.close().await {
                    tracing::warn!("WebRTC close failed: {error}");
                }
            });
        }
    }
}

/// WebRTC client that connects via data channels (no media)
pub struct WebRtcClient;

impl WebRtcClient {
    /// Connect to a WebRTC peer with integrated LLM actions
    ///
    /// Supports two signaling modes:
    /// - Manual: remote_addr = "manual" (user exchanges SDP)
    /// - WebSocket: remote_addr = "ws://server:port/peer_id" (automatic signaling)
    pub async fn connect_with_llm_actions(
        remote_addr: String,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        client_id: ClientId,
        startup_params: Option<crate::protocol::StartupParams>,
    ) -> Result<SocketAddr> {
        info!(
            "WebRTC client {} initializing for {}",
            client_id, remote_addr
        );

        // Parse signaling mode from remote_addr
        let signaling_mode =
            if remote_addr.starts_with("ws://") || remote_addr.starts_with("wss://") {
                // WebSocket signaling: ws://server:port/peer_id or wss://server:port/peer_id
                let parts: Vec<&str> = remote_addr.rsplitn(2, '/').collect();
                if parts.len() != 2 {
                    return Err(anyhow::anyhow!(
                        "Invalid WebSocket URL format. Expected: ws://server:port/peer_id"
                    ));
                }
                let peer_id = parts[0].to_string();
                let url = parts[1].to_string();
                SignalingMode::WebSocket {
                    url: format!("{}/", url), // Reconstruct base URL
                    peer_id,
                }
            } else {
                SignalingMode::Manual
            };

        info!(
            "WebRTC client {} using signaling mode: {:?}",
            client_id, signaling_mode
        );

        // Create a MediaEngine
        let mut m = MediaEngine::default();

        // Create an InterceptorRegistry and register default interceptors
        let registry = Registry::new();
        let registry = register_default_interceptors(registry, &mut m)?;

        // Create the API object with the MediaEngine
        let api = APIBuilder::new()
            .with_media_engine(m)
            .with_interceptor_registry(registry)
            .build();

        // Configure ICE servers. `ice_servers` was declared in `get_startup_parameters()`
        // and never read, so the Google STUN server was hardcoded for every client; it is now
        // the default and nothing more. An explicitly empty array means host candidates only,
        // which is what a purely local peer wants.
        let ice_urls: Vec<String> = match startup_params.as_ref() {
            Some(params) => match params
                .get_optional_array("ice_servers")
                .map_err(|e| anyhow::anyhow!("WebRTC client parameter error: {e}"))?
            {
                Some(arr) => arr
                    .iter()
                    .filter_map(|v| v.as_str().map(|s| s.trim().to_string()))
                    .filter(|s| !s.is_empty())
                    .collect(),
                None => Vec::new(),
            },
            // No ICE server by default.
            //
            // This used to default to `stun:stun.l.google.com:19302`, so starting a
            // WebRTC client — for any reason, including a loopback test — sent a
            // binding request to Google. The *server* was fixed for exactly this
            // reason (see `src/server/webrtc/CLAUDE.md`) and the client was left
            // behind, which is why `tests/client/webrtc/command_channel_test.rs` has
            // to pass `"ice_servers": []` explicitly to keep the repo's
            // localhost-only rule.
            //
            // An empty list is correct for host candidates, which is what a
            // loopback or LAN peer uses. Pass `ice_servers` to reach anything
            // behind NAT — the operator chooses which third party to talk to.
            None => Vec::new(),
        };
        let config = RTCConfiguration {
            ice_servers: ice_urls
                .into_iter()
                .map(|url| RTCIceServer {
                    urls: vec![url],
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        };

        // Create peer connection
        let peer_connection = Arc::new(api.new_peer_connection(config).await?);
        let lifetime = PeerConnectionGuard::new(peer_connection.clone());
        info!("WebRTC client {} created peer connection", client_id);

        // Initialize client data
        let client_data = Arc::new(Mutex::new(ClientData {
            shutdown: lifetime.cancellation_token(),
            memory: String::new(),
            channels: HashMap::new(),
        }));

        // Create default data channel
        let data_channel = peer_connection.create_data_channel("netget", None).await?;
        info!("WebRTC client {} created data channel 'netget'", client_id);

        // Setup data channel handlers
        Self::setup_data_channel_handlers(
            Arc::clone(&data_channel),
            "netget".to_string(),
            client_id,
            Arc::clone(&client_data),
            Arc::clone(&app_state),
            status_tx.clone(),
            llm_client.clone(),
        )
        .await;

        // Add channel to client data
        client_data.lock().await.channels.insert(
            "netget".to_string(),
            ChannelData {
                channel: Arc::clone(&data_channel),
            },
        );

        // Handle connection state changes
        let status_tx_state = status_tx.clone();
        let app_state_state = Arc::clone(&app_state);
        peer_connection.on_peer_connection_state_change(Box::new(
            move |state: RTCPeerConnectionState| {
                let status_tx = status_tx_state.clone();
                let app_state = Arc::clone(&app_state_state);
                Box::pin(async move {
                    info!("WebRTC client {} connection state: {:?}", client_id, state);
                    match state {
                        RTCPeerConnectionState::Connected => {
                            app_state
                                .update_client_status(client_id, ClientStatus::Connected)
                                .await;
                            let _ = status_tx
                                .send(format!("[CLIENT] WebRTC client {} connected", client_id));
                            let _ = status_tx.send("__UPDATE_UI__".to_string());
                        }
                        RTCPeerConnectionState::Failed | RTCPeerConnectionState::Closed => {
                            app_state
                                .update_client_status(client_id, ClientStatus::Disconnected)
                                .await;
                            // The connection is gone: drop the command handle so the
                            // dashboard stops offering [ send ] into it.
                            app_state.remove_client_handle(client_id).await;
                            let _ = status_tx
                                .send(format!("[CLIENT] WebRTC client {} disconnected", client_id));
                            let _ = status_tx.send("__UPDATE_UI__".to_string());
                        }
                        _ => {}
                    }
                })
            },
        ));

        // Command and signaling tasks own the peer connection through real Arcs.
        // Keep only serializable signaling metadata in the client state.
        app_state
            .with_client_mut(client_id, |client| {
                client.set_protocol_field(
                    "signaling_mode".to_string(),
                    match &signaling_mode {
                        SignalingMode::Manual => serde_json::json!("manual"),
                        SignalingMode::WebSocket { url, peer_id } => serde_json::json!({
                            "mode": "websocket",
                            "url": url,
                            "peer_id": peer_id
                        }),
                    },
                );
            })
            .await;

        // Command channel for injected actions (the dashboard's [ send ]). Registered BEFORE
        // signaling runs: the WebSocket mode makes an LLM call on
        // `webrtc_signaling_connected`, and a manual `*` rule parks that call until a human
        // answers - [ send ] has to work for the whole park.
        let command_rx =
            crate::client::command_support::register_command_channel(&app_state, client_id).await;
        let cmd_pc = Arc::clone(&peer_connection);
        let cmd_data = Arc::clone(&client_data);
        let cmd_state = Arc::clone(&app_state);
        let cmd_status_tx = status_tx.clone();
        let cmd_llm = llm_client.clone();
        let cmd_lifetime = lifetime.clone();
        let cmd_task = tokio::spawn(async move {
            let _lifetime = cmd_lifetime;
            Self::command_loop(
                command_rx,
                cmd_pc,
                cmd_data,
                client_id,
                cmd_state,
                cmd_status_tx,
                cmd_llm,
            )
            .await;
        });
        app_state.register_client_task(client_id, cmd_task).await;

        let signaling_result = match signaling_mode {
            SignalingMode::Manual => {
                // Manual mode: create offer and display to user
                Self::manual_signaling(
                    peer_connection.clone(),
                    client_id,
                    Arc::clone(&app_state),
                    status_tx.clone(),
                )
                .await
            }
            SignalingMode::WebSocket { url, peer_id } => {
                // WebSocket mode: connect to signaling server
                Self::websocket_signaling(
                    peer_connection.clone(),
                    client_id,
                    url,
                    peer_id,
                    Arc::clone(&app_state),
                    status_tx.clone(),
                    llm_client,
                )
                .await
            }
        };
        if let Err(error) = signaling_result {
            app_state.remove_client_handle(client_id).await;
            let _ = peer_connection.close().await;
            return Err(error);
        }

        // Spawn cleanup task
        let app_state_cleanup = Arc::clone(&app_state);
        // Registered with AppState so stop_client can abort this task —
        // dropping a JoinHandle only detaches it in Tokio.
        let task_registrar = app_state.clone();
        let task_handle = tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;

                // Check if client was removed
                if app_state_cleanup.get_client(client_id).await.is_none() {
                    info!("WebRTC client {} stopped", client_id);
                    // Also ends `command_loop`, whose channel closes with the handle.
                    app_state_cleanup.remove_client_handle(client_id).await;
                    break;
                }
            }
        });
        task_registrar
            .register_client_task(client_id, task_handle)
            .await;

        // Return a dummy local address (WebRTC is peer-to-peer)
        Ok("0.0.0.0:0".parse().unwrap())
    }

    /// Manual signaling: create offer and display to user
    async fn manual_signaling(
        peer_connection: Arc<RTCPeerConnection>,
        client_id: ClientId,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
    ) -> Result<()> {
        // Create offer
        let offer = peer_connection.create_offer(None).await?;
        peer_connection.set_local_description(offer).await?;

        // Wait for ICE gathering to complete
        let mut gather_complete = peer_connection.gathering_complete_promise().await;
        let _ = gather_complete.recv().await;

        // Get the local description with ICE candidates
        let local_desc = peer_connection
            .local_description()
            .await
            .context("No local description available")?;

        // Store the SDP offer for the user to exchange with peer
        let offer_json = serde_json::to_string_pretty(&local_desc)?;
        app_state
            .with_client_mut(client_id, |client| {
                client.set_protocol_field("sdp_offer".to_string(), serde_json::json!(offer_json));
            })
            .await;

        info!(
            "WebRTC client {} generated SDP offer (manual mode)",
            client_id
        );
        let _ = status_tx.send(format!(
            "[CLIENT] WebRTC client {} waiting for SDP answer",
            client_id
        ));
        let _ = status_tx.send(format!("SDP Offer (send to peer):\n{}", offer_json));
        let _ = status_tx.send("__UPDATE_UI__".to_string());

        Ok(())
    }

    /// WebSocket signaling: connect to signaling server and auto-exchange SDP
    async fn websocket_signaling(
        peer_connection: Arc<RTCPeerConnection>,
        client_id: ClientId,
        url: String,
        peer_id: String,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        llm_client: OllamaClient,
    ) -> Result<()> {
        info!(
            "WebRTC client {} connecting to signaling server: {}",
            client_id, url
        );

        // Connect to WebSocket signaling server
        let (ws_stream, _) = connect_async(&url)
            .await
            .context("Failed to connect to signaling server")?;

        let (mut ws_tx, mut ws_rx) = ws_stream.split();

        info!("WebRTC client {} connected to signaling server", client_id);
        let _ = status_tx.send(format!(
            "[CLIENT] WebRTC client {} connected to signaling server",
            client_id
        ));

        // Send registration message
        let register_msg = serde_json::json!({
            "type": "register",
            "peer_id": peer_id,
        });
        ws_tx
            .send(WsMessage::Text(register_msg.to_string()))
            .await
            .context("Failed to send registration")?;

        debug!("WebRTC client {} registered as '{}'", client_id, peer_id);

        // Trigger signaling connected event
        let protocol = Arc::new(crate::client::webrtc::actions::WebRtcClientProtocol::new());
        let event = Event::new(
            &WEBRTC_CLIENT_SIGNALING_CONNECTED_EVENT,
            serde_json::json!({
                "peer_id": peer_id,
                "server_url": url,
            }),
        );

        if let Some(instruction) = app_state.get_instruction_for_client(client_id).await {
            match call_llm_for_client(
                &llm_client,
                &app_state,
                client_id.to_string(),
                &instruction,
                "",
                Some(&event),
                protocol.as_ref(),
                &status_tx,
            )
            .await
            {
                Ok(ClientLlmResult {
                    actions,
                    memory_updates,
                }) => {
                    if let Some(mem) = memory_updates {
                        app_state.set_memory_for_client(client_id, mem).await;
                    }
                    // Signaling is connected but no data channel exists yet, so there is
                    // genuinely nothing to send on. Say which actions could not run rather
                    // than dropping them silently -- and note that the memory update WAS
                    // being dropped too, so anything the model learned here was lost.
                    if !actions.is_empty() {
                        info!(
                            "WebRTC client {}: {} action(s) answered at signaling-connected \
                             cannot run yet -- no data channel is open; they are actionable \
                             at webrtc_channel_opened",
                            client_id,
                            actions.len()
                        );
                    }
                }
                Err(e) => {
                    warn!(
                        "LLM error for WebRTC client {} signaling connected: {}",
                        client_id, e
                    );
                }
            }
        }

        // Create offer
        let offer = peer_connection.create_offer(None).await?;
        peer_connection.set_local_description(offer).await?;

        // Wait for ICE gathering
        let mut gather_complete = peer_connection.gathering_complete_promise().await;
        let _ = gather_complete.recv().await;

        let local_desc = peer_connection
            .local_description()
            .await
            .context("No local description")?;

        info!(
            "WebRTC client {} generated SDP offer (WebSocket mode)",
            client_id
        );

        // Send offer to signaling server (to be forwarded to remote peer)
        // Note: This assumes a target peer ID is known. In practice, the LLM might provide this
        // or it could be configured. For now, we'll store the offer and wait for the LLM to
        // trigger sending it via an action.
        let offer_json = serde_json::to_value(&local_desc)?;
        app_state
            .with_client_mut(client_id, |client| {
                client.set_protocol_field("sdp_offer".to_string(), offer_json.clone());
            })
            .await;

        // Spawn WebSocket message handler
        let pc_for_ws = Arc::clone(&peer_connection);
        let status_tx_ws = status_tx.clone();
        let app_state_ws = Arc::clone(&app_state);

        // Registered with AppState so stop_client can abort this task —
        // dropping a JoinHandle only detaches it in Tokio.
        let task_registrar = app_state.clone();
        let task_handle = tokio::spawn(async move {
            while let Some(msg_result) = ws_rx.next().await {
                match msg_result {
                    Ok(WsMessage::Text(text)) => {
                        trace!(
                            "WebRTC client {} received signaling message: {}",
                            client_id,
                            text
                        );

                        // Parse signaling message
                        if let Ok(msg) = serde_json::from_str::<serde_json::Value>(&text) {
                            let msg_type = msg.get("type").and_then(|v| v.as_str());

                            match msg_type {
                                Some("registered") => {
                                    info!(
                                        "WebRTC client {} registered with signaling server",
                                        client_id
                                    );
                                    let _ = status_tx_ws
                                        .send(format!("[CLIENT] Registered as '{}'", peer_id));
                                }
                                Some("answer") => {
                                    // Received SDP answer from remote peer
                                    if let Some(sdp) = msg.get("sdp") {
                                        info!("WebRTC client {} received SDP answer", client_id);

                                        match serde_json::from_value::<RTCSessionDescription>(
                                            sdp.clone(),
                                        ) {
                                            Ok(answer) => {
                                                if let Err(e) =
                                                    pc_for_ws.set_remote_description(answer).await
                                                {
                                                    error!(
                                                        "WebRTC client {} failed to set remote description: {}",
                                                        client_id, e
                                                    );
                                                } else {
                                                    info!(
                                                        "WebRTC client {} connection established via signaling",
                                                        client_id
                                                    );
                                                    app_state_ws
                                                        .update_client_status(
                                                            client_id,
                                                            ClientStatus::Connected,
                                                        )
                                                        .await;
                                                }
                                            }
                                            Err(e) => {
                                                error!(
                                                    "WebRTC client {} failed to parse SDP answer: {}",
                                                    client_id, e
                                                );
                                            }
                                        }
                                    }
                                }
                                Some("ice_candidate") => {
                                    // Handle ICE candidate (not implemented in basic version)
                                    trace!("WebRTC client {} received ICE candidate", client_id);
                                }
                                Some("error") => {
                                    if let Some(error_msg) =
                                        msg.get("message").and_then(|v| v.as_str())
                                    {
                                        error!(
                                            "WebRTC client {} signaling error: {}",
                                            client_id, error_msg
                                        );
                                        let _ = status_tx_ws.send(format!(
                                            "[CLIENT] Signaling error: {}",
                                            error_msg
                                        ));
                                    }
                                }
                                _ => {
                                    trace!(
                                        "WebRTC client {} unknown signaling message type",
                                        client_id
                                    );
                                }
                            }
                        }
                    }
                    Ok(WsMessage::Close(_)) => {
                        info!(
                            "WebRTC client {} signaling server closed connection",
                            client_id
                        );
                        break;
                    }
                    Err(e) => {
                        error!("WebRTC client {} signaling error: {}", client_id, e);
                        break;
                    }
                    _ => {}
                }
            }
        });
        task_registrar
            .register_client_task(client_id, task_handle)
            .await;

        Ok(())
    }

    /// Setup handlers for a data channel
    async fn setup_data_channel_handlers(
        data_channel: Arc<RTCDataChannel>,
        channel_label: String,
        client_id: ClientId,
        client_data: Arc<Mutex<ClientData>>,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        llm_client: OllamaClient,
    ) {
        // On open handler
        let client_data_on_open = Arc::downgrade(&client_data);
        let app_state_on_open = Arc::clone(&app_state);
        let status_tx_on_open = status_tx.clone();
        let llm_on_open = llm_client.clone();
        let label_on_open = channel_label.clone();
        // The channel itself, so an action the model returns when the channel opens can
        // actually be sent. Without it the answer had nowhere to go and was dropped.
        let dc_on_open = Arc::downgrade(&data_channel);

        data_channel.on_open(Box::new(move || {
            let app_state = Arc::clone(&app_state_on_open);
            let status_tx = status_tx_on_open.clone();
            let client_data = client_data_on_open.upgrade();
            let llm_client = llm_on_open.clone();
            let label = label_on_open.clone();
            let dc = dc_on_open.upgrade();

            Box::pin(async move {
                let (Some(client_data), Some(dc)) = (client_data, dc) else {
                    return;
                };
                info!(
                    "WebRTC client {} data channel '{}' opened",
                    client_id, label
                );
                let _ = status_tx.send(format!(
                    "[CLIENT] WebRTC client {} channel '{}' opened",
                    client_id, label
                ));
                let _ = status_tx.send("__UPDATE_UI__".to_string());

                // Call LLM with channel opened event
                if let Some(instruction) = app_state.get_instruction_for_client(client_id).await {
                    let protocol =
                        Arc::new(crate::client::webrtc::actions::WebRtcClientProtocol::new());
                    let event = Event::new(
                        &WEBRTC_CLIENT_CHANNEL_OPENED_EVENT,
                        serde_json::json!({
                            "channel_label": label,
                        }),
                    );

                    let memory = client_data.lock().await.memory.clone();

                    let shutdown = client_data.lock().await.shutdown.clone();
                    let call = call_llm_for_client(
                        &llm_client,
                        &app_state,
                        client_id.to_string(),
                        &instruction,
                        &memory,
                        Some(&event),
                        protocol.as_ref(),
                        &status_tx,
                    );
                    let result = tokio::select! { _ = shutdown.cancelled() => return, result = call => result };
                    match result {
                        Ok(ClientLlmResult {
                            actions,
                            memory_updates,
                        }) => {
                            if let Some(mem) = memory_updates {
                                client_data.lock().await.memory = mem;
                            }

                            // Send what the model asked for. These were discarded, so a
                            // model told to greet the peer as soon as the channel opened
                            // could not: the opening message is exactly what this event
                            // exists to prompt, and nothing came of it.
                            //
                            // Same execution shape as the on_message handler below; a
                            // send raises no event, so this cannot loop.
                            use crate::llm::actions::client_trait::{Client, ClientActionResult};
                            for action in actions {
                                match protocol.as_ref().execute_action(action) {
                                    Ok(ClientActionResult::SendData(bytes)) => {
                                        match dc.send(&bytes.into()).await {
                                            Ok(n) => info!(
                                                "WebRTC client {} sent {} bytes on '{}' \
                                                 when the channel opened",
                                                client_id, n, label
                                            ),
                                            Err(e) => error!(
                                                "WebRTC client {} failed to send on '{}': {}",
                                                client_id, label, e
                                            ),
                                        }
                                    }
                                    Ok(ClientActionResult::Disconnect) => {
                                        info!(
                                            "WebRTC client {} closing channel '{}' on the \
                                             model's request",
                                            client_id, label
                                        );
                                        let _ = dc.close().await;
                                    }
                                    Ok(_) => {}
                                    Err(e) => error!(
                                        "WebRTC client {} rejected its own channel-open \
                                         action: {}",
                                        client_id, e
                                    ),
                                }
                            }
                        }
                        Err(e) => {
                            error!(
                                "LLM error for WebRTC client {} on channel open: {}",
                                client_id, e
                            );
                        }
                    }
                }
            })
        }));

        // Messages. webrtc-rs awaits this handler before it reads the channel again, so a
        // handler that called the model itself (as this one did) left everything the peer sent
        // during the call unread in SCTP, and its "queue while processing" arm could never run.
        // The handler only queues now; the channel's answering task below takes one message per
        // call (batching off) or everything waiting (on).
        let (message_tx, mut message_rx) = mpsc::channel::<(String, bool)>(CHANNEL_QUEUE_MESSAGES);
        let client_data_on_msg = Arc::downgrade(&client_data);
        let label_on_msg = channel_label.clone();
        let dc_on_msg = Arc::downgrade(&data_channel);

        data_channel.on_message(Box::new(move |msg: DataChannelMessage| {
            let client_data = client_data_on_msg.upgrade();
            let dc = dc_on_msg.upgrade();
            let label = label_on_msg.clone();
            let message_tx = message_tx.clone();

            Box::pin(async move {
                let (Some(client_data), Some(dc)) = (client_data, dc) else {
                    return;
                };
                if msg.data.len() > 1024 * 1024 {
                    warn!("WebRTC data message exceeds 1 MiB; closing channel");
                    let _ = dc.close().await;
                    return;
                }
                let is_binary = !msg.is_string;
                let message_text = if is_binary {
                    // Hex encode binary data
                    hex::encode(&msg.data)
                } else {
                    String::from_utf8_lossy(&msg.data).to_string()
                };

                trace!(
                    "WebRTC client {} received message on '{}': {} (binary: {})",
                    client_id,
                    label,
                    if is_binary { "hex data" } else { &message_text },
                    is_binary
                );

                if !client_data.lock().await.channels.contains_key(&label) {
                    warn!(
                        "WebRTC client {} received message on unknown channel '{}'",
                        client_id, label
                    );
                    return;
                }
                drop(client_data);
                // Waits while the queue is full: webrtc-rs stops reading, and the peer is held
                // back by flow control.
                let _ = message_tx.send((message_text, is_binary)).await;
            })
        }));

        // The channel's answering task. It holds the channel and the client data weakly, like
        // the handlers, so it ends when the channel is dropped (its handler, and with it the
        // queue's sender, goes too) or when the client shuts down.
        let client_data_weak = Arc::downgrade(&client_data);
        let dc_weak = Arc::downgrade(&data_channel);
        let label = channel_label;
        let state = Arc::clone(&app_state);
        let shutdown = client_data.lock().await.shutdown.clone();
        app_state
            .spawn_client_task(client_id, async move {
                let protocol = crate::client::webrtc::actions::WebRtcClientProtocol::new();
                loop {
                    let first = tokio::select! {
                        _ = shutdown.cancelled() => return,
                        message = message_rx.recv() => match message {
                            Some(message) => message,
                            None => return,
                        },
                    };
                    let mut messages = vec![first];
                    if state
                        .client_conversation_settings(client_id)
                        .await
                        .is_some_and(|(_, batching)| batching)
                    {
                        while messages.len() < crate::protocol::metadata::MAX_BATCH_EVENTS {
                            match message_rx.try_recv() {
                                Ok(message) => messages.push(message),
                                Err(_) => break,
                            }
                        }
                    }
                    let (Some(client_data), Some(dc)) =
                        (client_data_weak.upgrade(), dc_weak.upgrade())
                    else {
                        return;
                    };
                    let Some(instruction) = state.get_instruction_for_client(client_id).await
                    else {
                        continue;
                    };
                    let events: Vec<Event> = messages
                        .into_iter()
                        .map(|(message, is_binary)| {
                            Event::new(
                                &WEBRTC_CLIENT_MESSAGE_RECEIVED_EVENT,
                                serde_json::json!({
                                    "channel_label": label,
                                    "message": message,
                                    "is_binary": is_binary,
                                }),
                            )
                        })
                        .collect();
                    let memory = client_data.lock().await.memory.clone();
                    let call = call_llm_for_client_batch(
                        &llm_client,
                        &state,
                        client_id.to_string(),
                        &instruction,
                        &memory,
                        &events,
                        &protocol,
                        &status_tx,
                    );
                    let result = tokio::select! { _ = shutdown.cancelled() => return, result = call => result };
                    match result {
                        Ok(ClientLlmResult { actions, memory_updates }) => {
                            if let Some(mem) = memory_updates {
                                client_data.lock().await.memory = mem;
                            }
                            for action in actions {
                                use crate::llm::actions::client_trait::{Client, ClientActionResult};
                                match protocol.execute_action(action) {
                                    Ok(ClientActionResult::SendData(bytes)) => {
                                        match dc.send(&bytes.into()).await {
                                            Ok(_) => trace!("WebRTC client {} sent message on '{}'", client_id, label),
                                            Err(e) => error!("WebRTC client {} failed to send on '{}': {}", client_id, label, e),
                                        }
                                    }
                                    Ok(ClientActionResult::Disconnect) => {
                                        info!("WebRTC client {} closing channel '{}'", client_id, label);
                                        let _ = dc.close().await;
                                    }
                                    Ok(ClientActionResult::WaitForMore) => {
                                        trace!("WebRTC client {} waiting for more data on '{}'", client_id, label);
                                    }
                                    _ => {}
                                }
                            }
                        }
                        Err(e) => {
                            error!("LLM error for WebRTC client {} on '{}': {}", client_id, label, e);
                        }
                    }
                }
            })
            .await;
    }

    // Three `pub async fn`s used to live here — `apply_answer`, `create_channel` and
    // `send_on_channel` — and all three are gone. They had no callers anywhere in
    // `src/` or `tests/`, and two of them resurrected an `RTCPeerConnection` from an
    // integer read back out of `protocol_data`:
    //
    //     let pc = unsafe { Arc::from_raw(pc_ptr as *const RTCPeerConnection) };
    //
    // with no liveness check of any kind. The live paths for the first two are in
    // `command_loop` below, which holds the real `Arc` and needs no `unsafe` at all;
    // `send_on_channel` was a `// TODO: Get channel from stored client data`
    // followed by `Ok(())`, i.e. a public function that reported success and sent
    // nothing — the fail-open shape the root CLAUDE.md names as the most dangerous
    // pattern in this codebase, sitting one function away from a live send path.

    /// Drain injected commands (the dashboard's \[ send \]) until the channel closes - the
    /// client was removed, or the peer connection failed - or an injected `disconnect` ends
    /// the session.
    ///
    /// This is option (a) of the library-driven archetype: the `RTCPeerConnection` and every
    /// `RTCDataChannel` are already behind `Arc`s that outlive `connect()`, so the command
    /// loop holds clones of them and needs no restructuring. `RTCDataChannel::send` returns
    /// the number of bytes it wrote to the SCTP stream, so an injected message reports a real
    /// `Sent { bytes_sent }` rather than a guess.
    #[allow(clippy::too_many_arguments)]
    async fn command_loop(
        mut command_rx: mpsc::Receiver<crate::state::client_handles::ClientCommand>,
        peer_connection: Arc<RTCPeerConnection>,
        client_data: Arc<Mutex<ClientData>>,
        client_id: ClientId,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        llm_client: OllamaClient,
    ) {
        use crate::llm::actions::client_trait::{Client, ClientActionResult};
        use crate::llm::actions::protocol_trait::Protocol;
        use crate::state::client_handles::ClientSendOutcome;
        use crate::state::AccessLogOwner;

        let protocol = WebRtcClientProtocol::new();

        while let Some(command) = command_rx.recv().await {
            let action = command.action.clone();
            // `execute_action` folds `send_message`/`send_binary` into a bare `SendData` and
            // drops the `channel` parameter it declares, so the target channel is read from
            // the action here. The default is the channel `connect()` always creates.
            let label = action
                .get("channel")
                .and_then(|v| v.as_str())
                .unwrap_or("netget")
                .to_string();

            let outcome: Result<ClientSendOutcome> = match protocol.execute_action(action.clone()) {
                Err(e) => Ok(ClientSendOutcome::Rejected {
                    error: e.to_string(),
                }),
                Ok(ClientActionResult::SendData(bytes)) => {
                    let channel = {
                        client_data
                            .lock()
                            .await
                            .channels
                            .get(&label)
                            .map(|c| Arc::clone(&c.channel))
                    };
                    match channel {
                        None => Ok(ClientSendOutcome::Rejected {
                            error: format!(
                                "this client has no data channel labelled '{label}'; \
                                 open one with create_channel first"
                            ),
                        }),
                        Some(channel) => match channel.send(&bytes.into()).await {
                            Ok(bytes_sent) => Ok(ClientSendOutcome::Sent { bytes_sent }),
                            Err(e) => Err(anyhow::anyhow!(
                                "data channel '{}' is {} - send failed: {}",
                                label,
                                channel.ready_state(),
                                e
                            )),
                        },
                    }
                }
                Ok(ClientActionResult::Custom { name, data }) => match name.as_str() {
                    "create_channel" => {
                        let new_label = data
                            .get("channel_label")
                            .and_then(|v| v.as_str())
                            .unwrap_or("netget")
                            .to_string();
                        match peer_connection.create_data_channel(&new_label, None).await {
                            Ok(channel) => {
                                Self::setup_data_channel_handlers(
                                    Arc::clone(&channel),
                                    new_label.clone(),
                                    client_id,
                                    Arc::clone(&client_data),
                                    Arc::clone(&app_state),
                                    status_tx.clone(),
                                    llm_client.clone(),
                                )
                                .await;
                                client_data
                                    .lock()
                                    .await
                                    .channels
                                    .insert(new_label.clone(), ChannelData { channel });
                                Ok(ClientSendOutcome::Executed {
                                    detail: format!(
                                        "data channel '{new_label}' created; it carries data \
                                         once the peer connection is established"
                                    ),
                                })
                            }
                            Err(e) => Err(anyhow::anyhow!("create_data_channel failed: {e}")),
                        }
                    }
                    "apply_answer" => {
                        let answer_json = data
                            .get("answer_json")
                            .and_then(|v| v.as_str())
                            .unwrap_or_default();
                        match serde_json::from_str::<RTCSessionDescription>(answer_json) {
                            Ok(answer) => {
                                match peer_connection.set_remote_description(answer).await {
                                    Ok(()) => Ok(ClientSendOutcome::Executed {
                                        detail: "SDP answer applied; ICE and DTLS now proceed"
                                            .to_string(),
                                    }),
                                    Err(e) => {
                                        Err(anyhow::anyhow!("set_remote_description failed: {e}"))
                                    }
                                }
                            }
                            Err(e) => Ok(ClientSendOutcome::Rejected {
                                error: format!("answer_json is not an SDP answer: {e}"),
                            }),
                        }
                    }
                    // Honest gap, and `Rejected` rather than `Executed` because that is
                    // the variant callers branch on. The detail string said "was NOT
                    // sent" in as many words while the outcome read as success, so the
                    // dashboard drew a tick and any programmatic caller matching on
                    // `Executed` concluded the offer had gone out. The signaling
                    // WebSocket sink is owned by `websocket_signaling`'s own task and is
                    // not reachable from here, and in manual mode there is no signaling
                    // connection at all.
                    "send_offer" => Ok(ClientSendOutcome::Rejected {
                        error: "send_offer cannot be injected: the signaling WebSocket sink \
                                belongs to the signaling task and is not reachable from a \
                                command, and manual mode has no signaling connection at all"
                            .to_string(),
                    }),
                    other => Ok(ClientSendOutcome::Rejected {
                        error: format!("WebRTC client cannot apply custom result '{other}'"),
                    }),
                },
                Ok(ClientActionResult::Disconnect) => {
                    let channels: Vec<Arc<RTCDataChannel>> = {
                        client_data
                            .lock()
                            .await
                            .channels
                            .values()
                            .map(|c| Arc::clone(&c.channel))
                            .collect()
                    };
                    for channel in channels {
                        let _ = channel.close().await;
                    }
                    if let Err(e) = peer_connection.close().await {
                        debug!("WebRTC client {} close: {}", client_id, e);
                    }
                    Ok(ClientSendOutcome::Disconnected)
                }
                Ok(ClientActionResult::WaitForMore) => Ok(ClientSendOutcome::Executed {
                    detail: "waiting for the next message; nothing sent".to_string(),
                }),
                Ok(ClientActionResult::NoAction) => Ok(ClientSendOutcome::Executed {
                    detail: "no_action: nothing sent".to_string(),
                }),
                Ok(ClientActionResult::Multiple(_)) => Ok(ClientSendOutcome::Rejected {
                    error: "WebRTC client does not support Multiple action results".to_string(),
                }),
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
                error!("WebRTC client {} injected action failed: {}", client_id, e);
                let _ = status_tx.send(format!(
                    "[WARN] Client {} injected action failed: {}",
                    client_id, e
                ));
            }
            let _ = status_tx.send("__UPDATE_UI__".to_string());
            crate::client::command_support::reply(command, outcome);

            if disconnect {
                app_state.remove_client_handle(client_id).await;
                break;
            }
        }
    }
}

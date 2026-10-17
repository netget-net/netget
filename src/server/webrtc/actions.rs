//! WebRTC server protocol actions.
//!
//! Three events, all reachable (see `mod.rs` for the signalling transport that makes them
//! so):
//!
//! - `webrtc_offer_received` — a peer sent an SDP offer over the signalling WebSocket. The
//!   model answers `accept_offer` or `reject_offer`. This path is fail-closed: `mod.rs`
//!   treats anything else, including an LLM error, as a refusal.
//! - `webrtc_peer_connected` — the data channel opened.
//! - `webrtc_message_received` — the peer sent a data-channel message.
//!
//! The last two accept `send_message` / `disconnect` / `wait_for_more`.
//!
//! No action carries SDP, ICE candidates or raw bytes. The model decides *whether* to admit
//! a peer and *what to say* on the channel; the SDP never leaves Rust.
//!
//! `get_async_actions` is deliberately empty: server-side async actions are advertised
//! nowhere in the LLM prompt path (only `call_llm_for_client` reads them, and that is the
//! client trait), so declaring `list_peers`/`send_to_peer` here would advertise a capability
//! the model has no way to invoke. `WebRtcServerData::list_peers` / `send_to_peer` exist for
//! callers that hold the live server data.

use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter, ParameterDefinition,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::EventType;
use crate::state::app_state::AppState;
use anyhow::{Context, Result};
use serde_json::json;
use std::sync::LazyLock;

use super::OFFER_DECISION_RESULT;

/// Default cap on simultaneous peers, overridable with the `max_peers` startup parameter.
pub const DEFAULT_MAX_PEERS: usize = 32;

/// A peer offered a WebRTC connection over the signalling WebSocket.
pub static WEBRTC_OFFER_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "webrtc_offer_received",
        "A peer sent a WebRTC SDP offer. Decide whether to admit it. Answering with anything \
         other than accept_offer refuses the peer.",
        json!({
            "type": "accept_offer"
        }),
    )
    .with_actions(offer_actions())
    .with_parameters(vec![
        Parameter {
            name: "peer_id".to_string(),
            type_hint: "string".to_string(),
            description: "Identifier the peer chose for itself".to_string(),
            required: true,
        },
        Parameter {
            name: "remote_addr".to_string(),
            type_hint: "string".to_string(),
            description: "Address the signalling connection came from".to_string(),
            required: true,
        },
        Parameter {
            name: "requests_data_channel".to_string(),
            type_hint: "boolean".to_string(),
            description: "Whether the offer contains a data channel (this server supports \
                          nothing else)"
                .to_string(),
            required: true,
        },
        Parameter {
            name: "media_kinds".to_string(),
            type_hint: "array".to_string(),
            description: "Media the peer asked for, e.g. [\"audio\"]. This server carries no \
                          media, so a non-empty list means part of the offer cannot be served."
                .to_string(),
            required: true,
        },
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("WebRTC offer from {peer_id} ({remote_addr})")
            .with_debug("WebRTC offer peer_id={peer_id} data_channel={requests_data_channel}")
            .with_trace("WebRTC offer: {json_pretty(.)}"),
    )
});

/// WebRTC peer connected event (data channel opened)
pub static WEBRTC_PEER_CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "webrtc_peer_connected",
        "WebRTC data channel opened and ready to send messages",
        json!({
            "type": "send_message",
            "message": "Welcome to NetGet WebRTC server!"
        }),
    )
    .with_actions(sync_actions())
    .with_parameters(vec![
        Parameter {
            name: "peer_id".to_string(),
            type_hint: "string".to_string(),
            description: "Unique peer identifier".to_string(),
            required: true,
        },
        Parameter {
            name: "channel_label".to_string(),
            type_hint: "string".to_string(),
            description: "Data channel label chosen by the peer".to_string(),
            required: true,
        },
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("WebRTC peer {peer_id} connected (channel: {channel_label})")
            .with_debug("WebRTC peer_id={peer_id} channel={channel_label}")
            .with_trace("WebRTC connected: {json_pretty(.)}"),
    )
});

/// WebRTC message received event
pub static WEBRTC_MESSAGE_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "webrtc_message_received",
        "Message received from WebRTC peer over the data channel",
        json!({
            "type": "send_message",
            "message": "Message received"
        }),
    )
    .with_actions(sync_actions())
    .with_parameters(vec![
        Parameter {
            name: "peer_id".to_string(),
            type_hint: "string".to_string(),
            description: "Unique peer identifier".to_string(),
            required: true,
        },
        Parameter {
            name: "message".to_string(),
            type_hint: "string".to_string(),
            description: "Received message text".to_string(),
            required: true,
        },
        Parameter {
            name: "is_binary".to_string(),
            type_hint: "boolean".to_string(),
            description: "True if the peer sent a binary frame; its bytes are rendered as \
                          lossy UTF-8 in 'message'"
                .to_string(),
            required: true,
        },
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("WebRTC {peer_id} <- {preview(message,50)}")
            .with_debug("WebRTC message from peer_id={peer_id} binary={is_binary}")
            .with_trace("WebRTC message: {json_pretty(.)}"),
    )
});

/// Actions available while deciding on an incoming offer.
fn offer_actions() -> Vec<ActionDefinition> {
    vec![
        ActionDefinition {
            name: "accept_offer".to_string(),
            description: "Admit this peer: answer its SDP offer and open the data channel"
                .to_string(),
            parameters: vec![],
            example: json!({
                "type": "accept_offer"
            }),
            log_template: Some(
                LogTemplate::new()
                    .with_info("-> WebRTC accept offer")
                    .with_debug("WebRTC accept_offer"),
            ),
        },
        ActionDefinition {
            name: "reject_offer".to_string(),
            description: "Refuse this peer. The reason is sent back in the signalling response."
                .to_string(),
            parameters: vec![Parameter {
                name: "reason".to_string(),
                type_hint: "string".to_string(),
                description: "Why the peer is being refused. Optional: a refusal with no \
                              reason is still a refusal, and the peer gets a generic one. \
                              This was declared required while the executor defaulted it, \
                              which is the wrong half of that pair to fix — refusing to \
                              execute a rejection because it lacked a sentence would turn a \
                              model's denial into an error, and an error is not a denial."
                    .to_string(),
                required: false,
            }],
            example: json!({
                "type": "reject_offer",
                "reason": "unknown peer"
            }),
            log_template: Some(
                LogTemplate::new()
                    .with_info("-> WebRTC reject offer: {reason}")
                    .with_debug("WebRTC reject_offer reason={reason}"),
            ),
        },
    ]
}

/// Actions available on an open data channel.
fn sync_actions() -> Vec<ActionDefinition> {
    vec![
        ActionDefinition {
            name: "send_message".to_string(),
            description: "Send a text message on this peer's data channel".to_string(),
            parameters: vec![Parameter {
                name: "message".to_string(),
                type_hint: "string".to_string(),
                description: "Message text to send".to_string(),
                required: true,
            }],
            example: json!({
                "type": "send_message",
                "message": "Reply message"
            }),
            log_template: Some(
                LogTemplate::new()
                    .with_info("-> WebRTC message")
                    .with_debug("WebRTC send_message"),
            ),
        },
        ActionDefinition {
            name: "disconnect".to_string(),
            description: "Close the peer connection".to_string(),
            parameters: vec![],
            example: json!({
                "type": "disconnect"
            }),
            log_template: Some(
                LogTemplate::new()
                    .with_info("-> WebRTC disconnect")
                    .with_debug("WebRTC disconnect"),
            ),
        },
        ActionDefinition {
            name: "wait_for_more".to_string(),
            description: "Wait for more messages before responding".to_string(),
            parameters: vec![],
            example: json!({
                "type": "wait_for_more"
            }),
            log_template: Some(
                LogTemplate::new()
                    .with_info("-> WebRTC wait")
                    .with_debug("WebRTC wait_for_more"),
            ),
        },
    ]
}

/// WebRTC server protocol action handler
pub struct WebRtcProtocol;

impl WebRtcProtocol {
    pub fn new() -> Self {
        Self
    }
}

impl Default for WebRtcProtocol {
    fn default() -> Self {
        Self::new()
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for WebRtcProtocol {
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "ice_servers".to_string(),
                description: "STUN/TURN server URLs for ICE. Default is none, which uses host \
                              candidates only — correct for localhost and LAN peers, and it \
                              contacts no third party. Add a STUN server for NAT traversal."
                    .to_string(),
                type_hint: "array".to_string(),
                required: false,
                example: json!(["stun:stun.l.google.com:19302"]),
                default: None,
            },
            ParameterDefinition {
                name: "max_peers".to_string(),
                description: format!(
                    "Refuse offers once this many peers are connected (default {})",
                    DEFAULT_MAX_PEERS
                ),
                type_hint: "integer".to_string(),
                required: false,
                example: json!(32),
                default: None,
            },
            ParameterDefinition {
                name: "idle_timeout_secs".to_string(),
                description: "Seconds the signalling WebSocket may carry no frame at all before \
                              the server closes it, ending the peer (default 600). The server \
                              pings at half of it and every WebSocket client answers \
                              automatically, so a live peer is never closed."
                    .to_string(),
                type_hint: "integer".to_string(),
                required: false,
                example: json!(600),
                default: Some(serde_json::json!(super::IDLE_TIMEOUT.as_secs())),
            },
        ]
    }

    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        // Deliberately empty; see the module header.
        Vec::new()
    }

    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        let mut actions = offer_actions();
        actions.extend(sync_actions());
        actions
    }

    fn protocol_name(&self) -> &'static str {
        "WebRTC"
    }

    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            WEBRTC_OFFER_RECEIVED_EVENT.clone(),
            WEBRTC_PEER_CONNECTED_EVENT.clone(),
            WEBRTC_MESSAGE_RECEIVED_EVENT.clone(),
        ]
    }

    fn stack_name(&self) -> &'static str {
        "ETH>IP>UDP>DTLS>SCTP>DataChannel"
    }

    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "webrtc",
            "webrtc server",
            "data channel",
            "peer to peer",
            "p2p",
        ]
    }

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Beta)
            // The signalling WebSocket's message limit; data-channel messages are capped lower
            // inside webrtc-rs. Tested in tests/server/webrtc/inbound_limit_test.rs.
            .max_inbound_bytes(crate::server::webrtc::SIGNALLING_MAX_MESSAGE_BYTES)
            .implementation(
                "webrtc-rs 0.11 peer connections with built-in WebSocket signalling \
                 (tokio-tungstenite): the server binds its port, answers SDP offers and runs \
                 data channels over DTLS/SCTP",
            )
            .llm_control(
                "Admission (accept_offer / reject_offer, fail-closed) and data-channel content \
                 (send_message / disconnect / wait_for_more). SDP and ICE stay in Rust.",
            )
            .e2e_testing(
                "webrtc-rs 0.11 is the peer, not a mock: an `RTCPeerConnection` creates a data \
                 channel, gathers a real SDP offer, exchanges SDP over the server's signalling \
                 WebSocket, completes ICE, DTLS and SCTP, and the test asserts the exact \
                 messages that crossed the channel in both directions — the peer's send is what \
                 provokes the server's reply, so receiving it proves both directions \
                 (tests/server/webrtc/e2e_test.rs::test_webrtc_data_channel_message_round_trip, \
                 not #[ignore]d)",
            )
            .notes(
                "Browser interoperability is still unverified — webrtc-rs is a real independent \
                 peer, but it is not Chrome or Firefox, and that is the check a human should \
                 make before this goes past Beta. Data channels only — no audio or video, and a \
                 media m-line in an offer is reported to the model but never served. ICE is not \
                 trickled: the peer must \
                 gather candidates before sending its offer. One peer per signalling \
                 WebSocket, and closing that socket closes the peer connection. Binary \
                 data-channel frames are surfaced to the model as lossy UTF-8; replies are \
                 always text.",
            )
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }

    fn description(&self) -> &'static str {
        "WebRTC data-channel server with built-in WebSocket signalling (no media)"
    }

    fn example_prompt(&self) -> &'static str {
        "Open a WebRTC server on port 9000 that accepts peers and echoes data channel messages"
    }

    fn group_name(&self) -> &'static str {
        "Real-time"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;

        // Deterministic: echo each data-channel message back to the peer, no LLM
        // call.
        let script = r#"import json, sys
data = json.load(sys.stdin)
event = data["event"]
if data["event_type_id"] == "webrtc_message_received":
    actions = [{"type": "send_message", "message": event.get("message", "")}]
else:
    actions = []
print(json.dumps({"actions": actions}))"#;

        StartupExamples::new(
            // LLM mode
            json!({
                "type": "open_server",
                "port": 9000,
                "base_stack": "webrtc",
                "instruction": "WebRTC data channel server. Accept offers from peers whose peer_id starts with 'guest', and echo every message back."
            }),
            // Script mode
            json!({
                "type": "open_server",
                "port": 9000,
                "base_stack": "webrtc",
                "event_handlers": [{
                    "event_pattern": "webrtc_message_received",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": script
                    }
                }]
            }),
            // Static mode
            json!({
                "type": "open_server",
                "port": 9000,
                "base_stack": "webrtc",
                "event_handlers": [
                    {
                        "event_pattern": "webrtc_offer_received",
                        "handler": {
                            "type": "static",
                            "actions": [{"type": "accept_offer"}]
                        }
                    },
                    {
                        "event_pattern": "webrtc_peer_connected",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "send_message",
                                "message": "Welcome to NetGet WebRTC server!"
                            }]
                        }
                    }
                ]
            }),
        )
    }
}

// Implement Server trait (server-specific functionality)
impl Server for WebRtcProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::server::webrtc::WebRtcServer;

            let mut ice_servers: Vec<String> = Vec::new();
            let mut max_peers = DEFAULT_MAX_PEERS;
            let mut idle_timeout = crate::server::webrtc::IDLE_TIMEOUT;

            if let Some(params) = &ctx.startup_params {
                if let Some(urls) = params.get_optional_array("ice_servers")? {
                    for url in urls {
                        match url.as_str() {
                            Some(url) => ice_servers.push(url.to_string()),
                            None => anyhow::bail!(
                                "Invalid startup parameter 'ice_servers': every entry must be a \
                                 STUN/TURN URL string, got {}",
                                url
                            ),
                        }
                    }
                }
                if let Some(limit) = params.get_optional_u64("max_peers")? {
                    if limit == 0 {
                        anyhow::bail!("Invalid startup parameter 'max_peers': must be at least 1");
                    }
                    max_peers = limit.min(u16::MAX as u64) as usize;
                }
                if let Some(secs) = params.get_optional_u64("idle_timeout_secs")? {
                    idle_timeout = std::time::Duration::from_secs(secs);
                }
            }

            let listen_addr = ctx
                .socket_addr()
                .unwrap_or_else(|| ctx.legacy_listen_addr());

            WebRtcServer::spawn_with_llm_actions(
                listen_addr,
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.server_id,
                ice_servers,
                max_peers,
                idle_timeout,
            )
            .await
        })
    }

    fn execute_action(&self, action: serde_json::Value) -> Result<ActionResult> {
        let action_type = action
            .get("type")
            .and_then(|v| v.as_str())
            .context("Missing 'type' field in action")?;

        match action_type {
            // The admission decision is carried back to the signalling task as a Custom
            // result; `webrtc::WebRtcServer::decide_offer` is the consumer.
            "accept_offer" => Ok(ActionResult::Custom {
                name: OFFER_DECISION_RESULT.to_string(),
                data: json!({ "accept": true }),
            }),
            "reject_offer" => {
                let reason = action
                    .get("reason")
                    .and_then(|v| v.as_str())
                    .unwrap_or("the model rejected this offer")
                    .to_string();
                Ok(ActionResult::Custom {
                    name: OFFER_DECISION_RESULT.to_string(),
                    data: json!({ "accept": false, "reason": reason }),
                })
            }
            "send_message" => {
                let message = action
                    .get("message")
                    .and_then(|v| v.as_str())
                    .context("Missing 'message' field")?
                    .to_string();

                Ok(ActionResult::Output(message.into_bytes()))
            }
            "disconnect" => Ok(ActionResult::CloseConnection),
            "wait_for_more" => Ok(ActionResult::WaitForMore),
            _ => Err(anyhow::anyhow!(
                "Unknown WebRTC server action: {}",
                action_type
            )),
        }
    }
}

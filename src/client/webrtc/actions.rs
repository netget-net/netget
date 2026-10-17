//! WebRTC client protocol actions implementation

use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, Parameter, ParameterDefinition,
};
use crate::protocol::EventType;
use crate::state::app_state::AppState;
use anyhow::{Context, Result};
use serde_json::json;
use std::sync::LazyLock;

/// WebRTC client channel opened event (supports multi-channel)
pub static WEBRTC_CLIENT_CHANNEL_OPENED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "webrtc_channel_opened",
        "WebRTC data channel opened (supports multiple channels)",
        json!({
            "type": "send_message",
            "channel": "netget",
            "message": "Hello, peer!"
        }),
    )
    .with_parameters(vec![Parameter {
        name: "channel_label".to_string(),
        type_hint: "string".to_string(),
        description: "Data channel label".to_string(),
        required: true,
    }])
});

/// WebRTC client message received event (enhanced with channel label and binary support)
pub static WEBRTC_CLIENT_MESSAGE_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "webrtc_message_received",
        "Message received from WebRTC peer on data channel",
        json!({
            "type": "send_message",
            "message": "Reply message"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "channel_label".to_string(),
            type_hint: "string".to_string(),
            description: "Data channel label where message was received".to_string(),
            required: true,
        },
        Parameter {
            name: "message".to_string(),
            type_hint: "string".to_string(),
            description: "Received message (text or hex-encoded binary)".to_string(),
            required: true,
        },
        Parameter {
            name: "is_binary".to_string(),
            type_hint: "boolean".to_string(),
            description: "Whether message is hex-encoded binary data".to_string(),
            required: true,
        },
    ])
});

/// WebRTC client signaling connected event (WebSocket mode)
pub static WEBRTC_CLIENT_SIGNALING_CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "webrtc_signaling_connected",
        "Connected to WebSocket signaling server",
        json!({
            "type": "wait_for_more"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "peer_id".to_string(),
            type_hint: "string".to_string(),
            description: "Registered peer ID on signaling server".to_string(),
            required: true,
        },
        Parameter {
            name: "server_url".to_string(),
            type_hint: "string".to_string(),
            description: "Signaling server WebSocket URL".to_string(),
            required: true,
        },
    ])
});

/// WebRTC client protocol action handler
pub struct WebRtcClientProtocol;

impl WebRtcClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for WebRtcClientProtocol {
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![ParameterDefinition {
            name: "ice_servers".to_string(),
            description: "STUN/TURN servers for ICE. Default: NONE — host candidates \
                              only, which is what a loopback or LAN peer uses. Set this to \
                              reach anything behind NAT; the default used to be Google's \
                              public STUN server, so merely starting a client talked to a \
                              third party."
                .to_string(),
            type_hint: "array".to_string(),
            required: false,
            example: json!(["stun:stun.example.com:3478", "turn:turn.example.com:3478"]),
            default: None,
        }]
    }

    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![
            ActionDefinition {
                name: "send_message".to_string(),
                description:
                    "Send a text or binary message over a data channel (use 'hex:' prefix for binary)"
                        .to_string(),
                parameters: vec![
                    Parameter {
                        name: "channel".to_string(),
                        type_hint: "string".to_string(),
                        description: "Channel label (default: 'netget')".to_string(),
                        required: false,
                    },
                    Parameter {
                        name: "message".to_string(),
                        type_hint: "string".to_string(),
                        description: "Message text or 'hex:HEXDATA' for binary".to_string(),
                        required: true,
                    },
                ],
                example: json!({
                    "type": "send_message",
                    "channel": "netget",
                    "message": "Hello, WebRTC peer!"
                }),
            log_template: None,
            },
            ActionDefinition {
                name: "send_binary".to_string(),
                description: "Send binary data over a data channel (hex-encoded)".to_string(),
                parameters: vec![
                    Parameter {
                        name: "channel".to_string(),
                        type_hint: "string".to_string(),
                        description: "Channel label (default: 'netget')".to_string(),
                        required: false,
                    },
                    Parameter {
                        name: "hex_data".to_string(),
                        type_hint: "string".to_string(),
                        description: "Hex-encoded binary data (e.g., '48656c6c6f')".to_string(),
                        required: true,
                    },
                ],
                example: json!({
                    "type": "send_binary",
                    "channel": "netget",
                    "hex_data": "48656c6c6f"
                }),
            log_template: None,
            },
            ActionDefinition {
                name: "apply_answer".to_string(),
                description: "Apply the SDP answer from the remote peer to complete connection (manual mode)"
                    .to_string(),
                parameters: vec![Parameter {
                    name: "answer_json".to_string(),
                    type_hint: "string".to_string(),
                    description: "SDP answer JSON from peer".to_string(),
                    required: true,
                }],
                example: json!({
                    "type": "apply_answer",
                    "answer_json": "{\"type\":\"answer\",\"sdp\":\"...\"}"
                }),
            log_template: None,
            },
            ActionDefinition {
                name: "create_channel".to_string(),
                description: "Create a new data channel on the existing connection".to_string(),
                parameters: vec![Parameter {
                    name: "channel_label".to_string(),
                    type_hint: "string".to_string(),
                    description: "Label for the new data channel".to_string(),
                    required: true,
                }],
                example: json!({
                    "type": "create_channel",
                    "channel_label": "file-transfer"
                }),
            log_template: None,
            },
            ActionDefinition {
                name: "send_offer".to_string(),
                description: "Send SDP offer to remote peer via signaling server (WebSocket mode)"
                    .to_string(),
                parameters: vec![Parameter {
                    name: "target_peer".to_string(),
                    type_hint: "string".to_string(),
                    description: "Target peer ID on signaling server".to_string(),
                    required: true,
                }],
                example: json!({
                    "type": "send_offer",
                    "target_peer": "peer-bob"
                }),
            log_template: None,
            },
            ActionDefinition {
                name: "disconnect".to_string(),
                description: "Close all data channels and the peer connection".to_string(),
                parameters: vec![],
                example: json!({
                    "type": "disconnect"
                }),
            log_template: None,
            },
        ]
    }

    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            ActionDefinition {
                name: "send_message".to_string(),
                description:
                    "Send a message in response to received data (text or 'hex:' prefix for binary)"
                        .to_string(),
                parameters: vec![
                    Parameter {
                        name: "channel".to_string(),
                        type_hint: "string".to_string(),
                        description: "Channel label (optional, uses receiving channel)".to_string(),
                        required: false,
                    },
                    Parameter {
                        name: "message".to_string(),
                        type_hint: "string".to_string(),
                        description: "Message text or 'hex:HEXDATA' for binary".to_string(),
                        required: true,
                    },
                ],
                example: json!({
                    "type": "send_message",
                    "message": "Reply message"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "disconnect".to_string(),
                description: "Close the connection".to_string(),
                parameters: vec![],
                example: json!({
                    "type": "disconnect"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "wait_for_more".to_string(),
                description: "Wait for more messages before responding".to_string(),
                parameters: vec![],
                example: json!({
                    "type": "wait_for_more"
                }),
                log_template: None,
            },
        ]
    }

    fn protocol_name(&self) -> &'static str {
        "WebRTC"
    }

    /// The events this client raises — **the same `LazyLock` statics it actually
    /// emits**, not fresh copies.
    ///
    /// This used to build four inline `EventType`s whose `example` was
    /// `{"type": "placeholder", …}` and which carried no parameters, while the
    /// statics above (which do carry parameters) were the ones emitted. Three
    /// consequences, all invisible:
    ///
    /// * `placeholder` is not an action any executor accepts, so the one worked
    ///   example per event was unusable.
    /// * The parameter lists were not shown here at all.
    /// * `webrtc_connected` was declared and emitted by **nothing**. Because it was
    ///   inline rather than a `&CONST` emit site, `event_emit_sites_test` — which
    ///   scans for constants — could not see it, so a never-emitted event was still
    ///   offered to operators as a routing pattern. It is removed rather than
    ///   relabelled: it was described as "(deprecated)", but nothing ever fired it,
    ///   so there is no deprecation, only an absence.
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            WEBRTC_CLIENT_CHANNEL_OPENED_EVENT.clone(),
            WEBRTC_CLIENT_MESSAGE_RECEIVED_EVENT.clone(),
            WEBRTC_CLIENT_SIGNALING_CONNECTED_EVENT.clone(),
        ]
    }

    fn stack_name(&self) -> &'static str {
        "ETH>IP>UDP>DTLS>SCTP>DataChannel"
    }

    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "webrtc",
            "webrtc client",
            "data channel",
            "peer to peer",
            "p2p",
            "signaling",
        ]
    }

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .implementation("webrtc-rs for data channels with WebSocket signaling support")
            .llm_control("Full control over data channels, signaling, and binary/text messaging")
            .e2e_testing("Manual SDP exchange or WebSocket signaling with local/remote peers")
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }

    fn description(&self) -> &'static str {
        "WebRTC client for peer-to-peer data channels (text/binary, manual or WebSocket signaling)"
    }

    fn example_prompt(&self) -> &'static str {
        "Open WebRTC client with automatic signaling or manual SDP exchange"
    }

    fn group_name(&self) -> &'static str {
        "Real-time"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        use serde_json::json;

        StartupExamples::new(
            // LLM mode: LLM controls WebRTC data channel messaging
            json!({
                "type": "open_client",
                "remote_addr": "ws://localhost:8080/alice",
                "base_stack": "webrtc",
                "instruction": "Connect via signaling server and send hello message to peer bob"
            }),
            // Script mode: Code-based WebRTC message handling
            json!({
                "type": "open_client",
                "remote_addr": "ws://localhost:8080/alice",
                "base_stack": "webrtc",
                "event_handlers": [{
                    "event_pattern": "webrtc_message_received",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "<webrtc_client_handler>"
                    }
                }]
            }),
            // Static mode: Fixed WebRTC message exchange
            json!({
                "type": "open_client",
                "remote_addr": "ws://localhost:8080/alice",
                "base_stack": "webrtc",
                "event_handlers": [
                    {
                        "event_pattern": "webrtc_channel_opened",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "send_message",
                                "message": "Hello, peer!"
                            }]
                        }
                    },
                    {
                        "event_pattern": "webrtc_message_received",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "disconnect"
                            }]
                        }
                    }
                ]
            }),
        )
    }
}

// Implement Client trait (client-specific functionality)
impl Client for WebRtcClientProtocol {
    fn connect(
        &self,
        ctx: crate::protocol::ConnectContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::client::webrtc::WebRtcClient;
            WebRtcClient::connect_with_llm_actions(
                ctx.remote_addr,
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.client_id,
                ctx.startup_params,
            )
            .await
        })
    }

    fn execute_action(&self, action: serde_json::Value) -> Result<ClientActionResult> {
        let action_type = action
            .get("type")
            .and_then(|v| v.as_str())
            .context("Missing 'type' field in action")?;

        match action_type {
            "send_message" => {
                let message = action
                    .get("message")
                    .and_then(|v| v.as_str())
                    .context("Missing 'message' field")?
                    .to_string();

                // Check if message has hex: prefix for binary data
                let bytes = if let Some(hex_str) = message.strip_prefix("hex:") {
                    // Decode hex to bytes
                    hex::decode(hex_str).context("Invalid hex data in message")?
                } else {
                    // Send as text
                    message.into_bytes()
                };

                Ok(ClientActionResult::SendData(bytes))
            }
            "send_binary" => {
                let hex_data = action
                    .get("hex_data")
                    .and_then(|v| v.as_str())
                    .context("Missing 'hex_data' field")?;

                // Decode hex to bytes
                let bytes = hex::decode(hex_data).context("Invalid hex data")?;

                Ok(ClientActionResult::SendData(bytes))
            }
            "apply_answer" => {
                let answer_json = action
                    .get("answer_json")
                    .and_then(|v| v.as_str())
                    .context("Missing 'answer_json' field")?
                    .to_string();

                // Return custom result for async processing
                Ok(ClientActionResult::Custom {
                    name: "apply_answer".to_string(),
                    data: json!({
                        "answer_json": answer_json,
                    }),
                })
            }
            "create_channel" => {
                let channel_label = action
                    .get("channel_label")
                    .and_then(|v| v.as_str())
                    .context("Missing 'channel_label' field")?
                    .to_string();

                // Return custom result for async processing
                Ok(ClientActionResult::Custom {
                    name: "create_channel".to_string(),
                    data: json!({
                        "channel_label": channel_label,
                    }),
                })
            }
            "send_offer" => {
                let target_peer = action
                    .get("target_peer")
                    .and_then(|v| v.as_str())
                    .context("Missing 'target_peer' field")?
                    .to_string();

                // Return custom result for async processing
                Ok(ClientActionResult::Custom {
                    name: "send_offer".to_string(),
                    data: json!({
                        "target_peer": target_peer,
                    }),
                })
            }
            "disconnect" => Ok(ClientActionResult::Disconnect),
            "wait_for_more" => Ok(ClientActionResult::WaitForMore),
            _ => Err(anyhow::anyhow!(
                "Unknown WebRTC client action: {}",
                action_type
            )),
        }
    }
}

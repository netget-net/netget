//! WebSocket (RFC 6455) client actions, events and metadata.
//!
//! The client mirrors the server's vocabulary deliberately: `send_websocket_text`,
//! `send_websocket_binary` (with the same `data` + `encoding` pair), `send_websocket_ping` and
//! `close_websocket` mean the same thing in both directions, so a prompt written for one side
//! reads correctly on the other. Masking is the only asymmetry and it is handled by the
//! framing layer — RFC 6455 §5.3 requires every client-to-server frame to be masked with a
//! fresh 32-bit key, and `tungstenite` does that for `Role::Client` without being asked.

use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, Parameter, ParameterDefinition,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::EventType;
use crate::server::websocket::actions::{decode_outbound_payload, WsOut};
use crate::state::app_state::AppState;
use anyhow::{Context, Result};
use serde_json::json;
use std::sync::LazyLock;
use tokio::sync::mpsc;
use tracing::debug;

/// WebSocket client action handler.
///
/// Two shapes, as on the server side: the registry-wide instance used for documentation and
/// `connect()`, and a per-connection instance that owns the outbound channel and can therefore
/// actually put a frame on the wire.
pub struct WebSocketClientProtocol {
    out_tx: Option<mpsc::UnboundedSender<WsOut>>,
}

impl Default for WebSocketClientProtocol {
    fn default() -> Self {
        Self::new()
    }
}

impl WebSocketClientProtocol {
    pub fn new() -> Self {
        Self { out_tx: None }
    }

    pub fn for_connection(out_tx: mpsc::UnboundedSender<WsOut>) -> Self {
        Self {
            out_tx: Some(out_tx),
        }
    }

    fn send(&self, msg: WsOut) -> Result<()> {
        let tx = self
            .out_tx
            .as_ref()
            .context("This WebSocket client action needs an open connection")?;
        tx.send(msg)
            .map_err(|_| anyhow::anyhow!("WebSocket connection is already closed"))
    }
}

impl Protocol for WebSocketClientProtocol {
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "path".to_string(),
                type_hint: "string".to_string(),
                description:
                    "Request path (and optional query string) to open the WebSocket on, e.g. \
                     \"/ws\" or \"/stream?token=abc\". Defaults to \"/\"."
                        .to_string(),
                required: false,
                example: json!("/ws"),
                default: None,
            },
            ParameterDefinition {
                name: "subprotocols".to_string(),
                type_hint: "array".to_string(),
                description:
                    "Subprotocols to offer in Sec-WebSocket-Protocol, most preferred first. The \
                     server picks at most one and it is reported in the \
                     websocket_client_connected event."
                        .to_string(),
                required: false,
                example: json!(["chat", "superchat"]),
                default: None,
            },
            ParameterDefinition {
                name: "headers".to_string(),
                type_hint: "object".to_string(),
                description: "Extra request headers to send with the upgrade, e.g. \
                     {\"Authorization\": \"Bearer …\", \"Origin\": \"https://example.com\"}. \
                     The RFC 6455 handshake headers are set automatically and cannot be \
                     overridden."
                    .to_string(),
                required: false,
                example: json!({"Origin": "https://example.com"}),
                default: None,
            },
            ParameterDefinition {
                name: "permessage_deflate".to_string(),
                type_hint: "boolean".to_string(),
                description: "Offer RFC 7692 permessage-deflate in the upgrade, so the server may \
                     compress messages in both directions (default true). Messages reach the \
                     handler as plain text either way; whether the server accepted is reported \
                     in websocket_client_connected."
                    .to_string(),
                required: false,
                example: json!(true),
                default: Some(json!(super::DEFAULT_PERMESSAGE_DEFLATE)),
            },
        ]
    }

    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        client_actions()
    }

    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        client_actions()
    }

    fn protocol_name(&self) -> &'static str {
        // Same canonical name and stack as the server side, which is the repo's convention
        // (TcpClientProtocol is "TCP" too). The two registries are separate, so there is no
        // collision, and `base_stack: "websocket"` resolves on both.
        "WebSocket"
    }

    fn get_event_types(&self) -> Vec<EventType> {
        get_websocket_client_event_types()
    }

    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>HTTP>WebSocket"
    }

    fn keywords(&self) -> Vec<&'static str> {
        // The client registry's `parse_from_str` has no protocol-name step and matches
        // keywords by substring, so the bare "websocket" is what makes `base_stack:
        // "websocket"` (and "websocket_client") resolve at all.
        vec![
            "websocket",
            "web socket",
            "websocket client",
            "connect to websocket",
            "rfc 6455",
        ]
    }

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{
            DevelopmentState, PrivilegeRequirement, ProtocolMetadataV2,
        };

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation(
                "tokio-tungstenite 0.21 connect_async; client-to-server masking, fragmentation \
                 and the close handshake are handled by the framing layer",
            )
            .llm_control(
                "Every text and binary frame sent, ping payloads, the close code and reason, \
                 and which subprotocols to offer at connect time",
            )
            .e2e_testing(
                "The NetGet WebSocket server and websocat 1.14.1 in server mode (-s); RFC 7692 \
                 permessage-deflate against Python websockets 15 (12-bit windows, its \
                 default) and Node ws 8 (no context takeover), with a relay reading RSV1 off \
                 the wire (tests/client/websocket/deflate_real_server_test.rs)",
            )
            .notes(
                "ws:// only — wss:// is not supported because the tokio-tungstenite dependency \
                 is built without a TLS backend. permessage-deflate is offered by default \
                 (permessage_deflate) and applied beneath tungstenite. Pong frames are logged \
                 rather than surfaced as an event. Validated against websocat 1.14.1 running as \
                 the server.",
            )
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }

    fn description(&self) -> &'static str {
        "WebSocket (RFC 6455) client for connecting to ws:// endpoints"
    }

    fn example_prompt(&self) -> &'static str {
        "Connect to the WebSocket at 127.0.0.1:9001/ws, send a subscribe message, and summarise every update"
    }

    fn group_name(&self) -> &'static str {
        "Application"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;

        StartupExamples::new(
            json!({
                "type": "open_client",
                "remote_addr": "127.0.0.1:9001",
                "base_stack": "websocket",
                "startup_params": {"path": "/ws", "subprotocols": ["chat"]},
                "instruction": "Connect, send {\"op\":\"subscribe\",\"channel\":\"ticker\"} once connected, \
                                and report each update you receive."
            }),
            json!({
                "type": "open_client",
                "remote_addr": "127.0.0.1:9001",
                "base_stack": "websocket",
                "event_handlers": [{
                    "event_pattern": "websocket_client_text_message",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "respond([{'type': 'send_websocket_text', 'text': event['text'].upper()}])"
                    }
                }]
            }),
            json!({
                "type": "open_client",
                "remote_addr": "127.0.0.1:9001",
                "base_stack": "websocket",
                "event_handlers": [
                    {
                        "event_pattern": "websocket_client_connected",
                        "handler": {
                            "type": "static",
                            "actions": [{"type": "send_websocket_text", "text": "hello"}]
                        }
                    },
                    {
                        "event_pattern": "websocket_client_text_message",
                        "handler": {
                            "type": "static",
                            "actions": [{"type": "close_websocket", "code": 1000, "reason": "done"}]
                        }
                    }
                ]
            }),
        )
    }
}

impl Client for WebSocketClientProtocol {
    fn connect(
        &self,
        ctx: crate::protocol::ConnectContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::client::websocket::WebSocketClient;
            WebSocketClient::connect_with_llm_actions(ctx).await
        })
    }

    fn execute_action(&self, action: serde_json::Value) -> Result<ClientActionResult> {
        let action_type = action
            .get("type")
            .and_then(|v| v.as_str())
            .context("Missing 'type' field in action")?;

        match action_type {
            "send_websocket_text" => {
                let text = action
                    .get("text")
                    .and_then(|v| v.as_str())
                    .context("Missing 'text' for send_websocket_text")?
                    .to_string();
                debug!("WebSocket client -> text {} bytes", text.len());
                let bytes = text.len();
                self.send(WsOut::Text(text))?;
                Ok(ClientActionResult::Custom {
                    name: "send_websocket_text".to_string(),
                    data: json!({ "bytes": bytes }),
                })
            }
            "send_websocket_binary" => {
                let data = action
                    .get("data")
                    .and_then(|v| v.as_str())
                    .context("Missing 'data' for send_websocket_binary")?;
                let bytes =
                    decode_outbound_payload(data, action.get("encoding").and_then(|v| v.as_str()))?;
                debug!("WebSocket client -> binary {} bytes", bytes.len());
                let len = bytes.len();
                self.send(WsOut::Binary(bytes))?;
                Ok(ClientActionResult::Custom {
                    name: "send_websocket_binary".to_string(),
                    data: json!({ "bytes": len }),
                })
            }
            "send_websocket_ping" => {
                let payload = action
                    .get("payload")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .as_bytes()
                    .to_vec();
                if payload.len() > 125 {
                    return Err(anyhow::anyhow!(
                        "Ping payload is {} bytes; RFC 6455 §5.5 limits control frames to 125",
                        payload.len()
                    ));
                }
                self.send(WsOut::Ping(payload))?;
                Ok(ClientActionResult::Custom {
                    name: "send_websocket_ping".to_string(),
                    data: json!({}),
                })
            }
            "close_websocket" => {
                let code = action.get("code").and_then(|v| v.as_u64()).unwrap_or(1000);
                let valid = (1000..=1003).contains(&code)
                    || (1007..=1011).contains(&code)
                    || (3000..=4999).contains(&code);
                if !valid {
                    return Err(anyhow::anyhow!(
                        "close code {} is not sendable; use 1000-1003, 1007-1011 or 3000-4999 \
                         (1005, 1006 and 1015 are reserved)",
                        code
                    ));
                }
                let reason = action
                    .get("reason")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                if reason.len() > 123 {
                    return Err(anyhow::anyhow!(
                        "close reason is {} bytes; the limit is 123",
                        reason.len()
                    ));
                }
                self.send(WsOut::Close {
                    code: code as u16,
                    reason,
                })?;
                Ok(ClientActionResult::Disconnect)
            }
            "disconnect" => {
                // Drop the TCP connection without a closing handshake. `close_websocket` is
                // the polite form and should be preferred.
                Ok(ClientActionResult::Disconnect)
            }
            "wait_for_websocket_data" => Ok(ClientActionResult::WaitForMore),
            _ => Err(anyhow::anyhow!(
                "Unknown WebSocket client action: {}",
                action_type
            )),
        }
    }
}

// ============================================================================
// Action definitions
// ============================================================================

fn client_actions() -> Vec<ActionDefinition> {
    vec![
        send_text_action(),
        send_binary_action(),
        send_ping_action(),
        wait_for_data_action(),
        close_action(),
        disconnect_action(),
    ]
}

fn send_text_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_websocket_text".to_string(),
        description: "Send a WebSocket text frame to the server.".to_string(),
        parameters: vec![Parameter {
            name: "text".to_string(),
            type_hint: "string".to_string(),
            description: "The message body, sent as UTF-8. Put serialised JSON here as a string."
                .to_string(),
            required: true,
        }],
        example: json!({"type": "send_websocket_text", "text": "{\"op\":\"subscribe\"}"}),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> WS text")
                .with_trace("WebSocket client text: {preview(text,200)}"),
        ),
    }
}

fn send_binary_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_websocket_binary".to_string(),
        description:
            "Send a WebSocket binary frame to the server. 'data' plus 'encoding' is the same \
             pair a websocket_client_binary_message event carries, so echoing is passing both \
             fields straight through."
                .to_string(),
        parameters: vec![
            Parameter {
                name: "data".to_string(),
                type_hint: "string".to_string(),
                description: "The payload, interpreted according to 'encoding'.".to_string(),
                required: true,
            },
            Parameter {
                name: "encoding".to_string(),
                type_hint: "string".to_string(),
                description:
                    "\"utf8\" (default) sends the characters of 'data' unchanged; \"base64\" \
                     and \"hex\" decode 'data' into bytes. There is no auto-detection."
                        .to_string(),
                required: false,
            },
        ],
        example: json!({"type": "send_websocket_binary", "data": "AP/+AQ==", "encoding": "base64"}),
        log_template: Some(LogTemplate::new().with_info("-> WS binary")),
    }
}

fn send_ping_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_websocket_ping".to_string(),
        description:
            "Send a ping control frame. The server's pong is logged and does not raise an event."
                .to_string(),
        parameters: vec![Parameter {
            name: "payload".to_string(),
            type_hint: "string".to_string(),
            description: "Optional payload, at most 125 bytes.".to_string(),
            required: false,
        }],
        example: json!({"type": "send_websocket_ping", "payload": "keepalive"}),
        log_template: Some(LogTemplate::new().with_debug("WebSocket client ping")),
    }
}

fn wait_for_data_action() -> ActionDefinition {
    ActionDefinition {
        name: "wait_for_websocket_data".to_string(),
        description:
            "Do not act on this message yet; hold it and join the next message of the same kind \
             onto it before deciding."
                .to_string(),
        parameters: vec![],
        example: json!({"type": "wait_for_websocket_data"}),
        log_template: Some(LogTemplate::new().with_debug("WebSocket client waiting for more")),
    }
}

fn close_action() -> ActionDefinition {
    ActionDefinition {
        name: "close_websocket".to_string(),
        description:
            "Close politely: send a close frame with a status code and let the server answer."
                .to_string(),
        parameters: vec![
            Parameter {
                name: "code".to_string(),
                type_hint: "integer".to_string(),
                description:
                    "Close status code (default 1000, normal). 1001 going away, 1008 policy \
                     violation, 1011 internal error, or 3000-4999 for your own meanings."
                        .to_string(),
                required: false,
            },
            Parameter {
                name: "reason".to_string(),
                type_hint: "string".to_string(),
                description: "Optional explanation, at most 123 bytes.".to_string(),
                required: false,
            },
        ],
        example: json!({"type": "close_websocket", "code": 1000, "reason": "done"}),
        log_template: Some(LogTemplate::new().with_info("WS client close {code}")),
    }
}

fn disconnect_action() -> ActionDefinition {
    ActionDefinition {
        name: "disconnect".to_string(),
        description:
            "Drop the connection immediately without a closing handshake. Prefer close_websocket."
                .to_string(),
        parameters: vec![],
        example: json!({"type": "disconnect"}),
        log_template: Some(LogTemplate::new().with_info("WS client disconnect")),
    }
}

// ============================================================================
// Event types — every one of these is emitted by src/client/websocket/mod.rs
// ============================================================================

fn connected_actions() -> Vec<ActionDefinition> {
    vec![
        send_text_action(),
        send_binary_action(),
        send_ping_action(),
        close_action(),
        disconnect_action(),
    ]
}

pub static WEBSOCKET_CLIENT_CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "websocket_client_connected",
        "The WebSocket handshake completed. Send the first message now if the protocol expects \
         the client to speak first.",
        json!({"type": "send_websocket_text", "text": "{\"op\":\"subscribe\"}"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "remote_addr".to_string(),
            type_hint: "string".to_string(),
            description: "Address of the server that was connected to".to_string(),
            required: true,
        },
        Parameter {
            name: "path".to_string(),
            type_hint: "string".to_string(),
            description: "Request path the connection was opened on".to_string(),
            required: true,
        },
        Parameter {
            name: "subprotocol".to_string(),
            type_hint: "string".to_string(),
            description:
                "The subprotocol the server agreed on, or empty if it chose none. Never a value \
                 that was not offered."
                    .to_string(),
            required: false,
        },
        Parameter {
            name: "permessage_deflate".to_string(),
            type_hint: "object".to_string(),
            description: "The RFC 7692 compression parameters the server accepted, or null when \
                 the connection is uncompressed"
                .to_string(),
            required: false,
        },
    ])
    .with_actions(connected_actions())
    .with_log_template(
        LogTemplate::new()
            .with_info("WS client connected to {remote_addr}{path}")
            .with_debug("WebSocket client connected subprotocol={subprotocol}"),
    )
});

pub static WEBSOCKET_CLIENT_TEXT_MESSAGE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "websocket_client_text_message",
        "A text message arrived from the server.",
        json!({"type": "send_websocket_text", "text": "ack"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "text".to_string(),
            type_hint: "string".to_string(),
            description: "The complete message, reassembled from any fragments".to_string(),
            required: true,
        },
        Parameter {
            name: "message_bytes".to_string(),
            type_hint: "integer".to_string(),
            description: "Length of the message in bytes".to_string(),
            required: true,
        },
    ])
    .with_actions({
        let mut a = connected_actions();
        a.push(wait_for_data_action());
        a
    })
    .with_alternative_example(json!({"type": "close_websocket", "code": 1000, "reason": "done"}))
    .with_log_template(
        LogTemplate::new()
            .with_info("WS client <- text {message_bytes}B")
            .with_trace("WebSocket client text: {preview(text,200)}"),
    )
});

pub static WEBSOCKET_CLIENT_BINARY_MESSAGE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "websocket_client_binary_message",
        "A binary message arrived from the server. To echo it back unchanged, pass this event's \
         'data' AND its 'encoding' straight into send_websocket_binary.",
        json!({"type": "send_websocket_binary", "data": "AP/+AQ==", "encoding": "base64"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "data".to_string(),
            type_hint: "string".to_string(),
            description: "The payload, read according to the 'encoding' field".to_string(),
            required: true,
        },
        Parameter {
            name: "encoding".to_string(),
            type_hint: "string".to_string(),
            description: "\"utf8\" when every byte is printable ASCII, otherwise \"base64\". \
                 send_websocket_binary accepts the same values, so the pair round-trips."
                .to_string(),
            required: true,
        },
        Parameter {
            name: "message_bytes".to_string(),
            type_hint: "integer".to_string(),
            description: "Length of the decoded message in bytes".to_string(),
            required: true,
        },
    ])
    .with_actions({
        let mut a = connected_actions();
        a.push(wait_for_data_action());
        a
    })
    .with_log_template(LogTemplate::new().with_info("WS client <- binary {message_bytes}B"))
});

pub static WEBSOCKET_CLIENT_CLOSED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "websocket_client_closed",
        "The server closed the connection. Record what happened; nothing more can be sent.",
        json!({"type": "show_message", "message": "server closed the WebSocket"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "code".to_string(),
            type_hint: "integer".to_string(),
            description: "Close status code, or 1005 when the server sent none".to_string(),
            required: true,
        },
        Parameter {
            name: "reason".to_string(),
            type_hint: "string".to_string(),
            description: "Close reason text, or empty".to_string(),
            required: false,
        },
    ])
    // Nothing can go on the wire after the closing handshake, so the common actions
    // (show_message, set_memory, append_to_log) are the only honest vocabulary here.
    .with_no_actions()
    .with_log_template(LogTemplate::new().with_info("WS client closed code={code}"))
});

pub fn get_websocket_client_event_types() -> Vec<EventType> {
    vec![
        WEBSOCKET_CLIENT_CONNECTED_EVENT.clone(),
        WEBSOCKET_CLIENT_TEXT_MESSAGE_EVENT.clone(),
        WEBSOCKET_CLIENT_BINARY_MESSAGE_EVENT.clone(),
        WEBSOCKET_CLIENT_CLOSED_EVENT.clone(),
    ]
}

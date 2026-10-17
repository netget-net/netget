//! TCP client protocol actions implementation

use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, Parameter,
};
use crate::protocol::EventType;
use crate::state::app_state::AppState;
use anyhow::{Context, Result};
use serde_json::json;
use std::sync::LazyLock;

/// TCP client connected event
pub static TCP_CLIENT_CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "tcp_connected",
        "TCP client successfully connected to server",
        serde_json::json!({
            "type": "send_tcp_data",
            "data": "48656c6c6f"
        }),
    )
    .with_parameters(vec![Parameter {
        name: "remote_addr".to_string(),
        type_hint: "string".to_string(),
        description: "Remote server address".to_string(),
        required: true,
    }])
});

/// TCP client data received event
pub static TCP_CLIENT_DATA_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "tcp_data_received",
        "Data received from TCP server",
        json!({"type": "placeholder", "event_id": "tcp_data_received"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "data_hex".to_string(),
            type_hint: "string".to_string(),
            description: "The data received (as hex string)".to_string(),
            required: true,
        },
        Parameter {
            name: "data_length".to_string(),
            type_hint: "number".to_string(),
            description: "Length of data in bytes".to_string(),
            required: true,
        },
    ])
});

/// TCP client protocol action handler
pub struct TcpClientProtocol;

impl Default for TcpClientProtocol {
    fn default() -> Self {
        Self::new()
    }
}

impl TcpClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for TcpClientProtocol {
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![
            ActionDefinition {
                name: "send_tcp_data".to_string(),
                description: "Send raw TCP data to the server (UTF-8 string or hex-encoded)"
                    .to_string(),
                parameters: vec![
                    Parameter {
                        name: "data".to_string(),
                        type_hint: "string".to_string(),
                        description: "UTF-8 string data to send (preferred for text)".to_string(),
                        required: false,
                    },
                    Parameter {
                        name: "data_hex".to_string(),
                        type_hint: "string".to_string(),
                        description: "Hexadecimal encoded data to send (for binary data)"
                            .to_string(),
                        required: false,
                    },
                ],
                example: json!({
                    "type": "send_tcp_data",
                    "data": "Hello World"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "disconnect".to_string(),
                description: "Disconnect from the TCP server".to_string(),
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
                name: "send_tcp_data".to_string(),
                description:
                    "Send TCP data in response to received data (UTF-8 string or hex-encoded)"
                        .to_string(),
                parameters: vec![
                    Parameter {
                        name: "data".to_string(),
                        type_hint: "string".to_string(),
                        description: "UTF-8 string data to send (preferred for text)".to_string(),
                        required: false,
                    },
                    Parameter {
                        name: "data_hex".to_string(),
                        type_hint: "string".to_string(),
                        description: "Hexadecimal encoded data to send (for binary data)"
                            .to_string(),
                        required: false,
                    },
                ],
                example: json!({
                    "type": "send_tcp_data",
                    "data": "Hello World"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "wait_for_more".to_string(),
                description: "Wait for more data before responding".to_string(),
                parameters: vec![],
                example: json!({
                    "type": "wait_for_more"
                }),
                log_template: None,
            },
        ]
    }
    fn protocol_name(&self) -> &'static str {
        "TCP"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            EventType::new(
                "tcp_connected",
                "Triggered when TCP client connects to server",
                json!({"type": "placeholder", "event_id": "tcp_connected"}),
            ),
            EventType::new(
                "tcp_data_received",
                "Triggered when TCP client receives data from server",
                json!({"type": "placeholder", "event_id": "tcp_data_received"}),
            ),
        ]
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["tcp", "tcp client", "connect to tcp"]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .implementation("Tokio TcpStream for raw TCP connections")
            .llm_control("Full control over sent/received bytes")
            .e2e_testing("nc (netcat) as test server")
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "TCP client for connecting to TCP servers"
    }
    fn example_prompt(&self) -> &'static str {
        "Connect to TCP at localhost:8080 and send 'HELLO'"
    }
    fn group_name(&self) -> &'static str {
        "Core"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        use serde_json::json;

        StartupExamples::new(
            // LLM mode: LLM controls TCP client interactions
            json!({
                "type": "open_client",
                "remote_addr": "example.com:9000",
                "base_stack": "tcp",
                "instruction": "Connect to the TCP server and send a greeting, then echo any responses"
            }),
            // Script mode: Code-based deterministic responses
            json!({
                "type": "open_client",
                "remote_addr": "example.com:9000",
                "base_stack": "tcp",
                "event_handlers": [{
                    "event_pattern": "tcp_data_received",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "<tcp_client_handler>"
                    }
                }]
            }),
            // Static mode: Fixed responses
            json!({
                "type": "open_client",
                "remote_addr": "example.com:9000",
                "base_stack": "tcp",
                "event_handlers": [
                    {
                        "event_pattern": "tcp_connected",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "send_tcp_data",
                                "data": "HELLO\r\n"
                            }]
                        }
                    },
                    {
                        "event_pattern": "tcp_data_received",
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
impl Client for TcpClientProtocol {
    fn connect(
        &self,
        ctx: crate::protocol::ConnectContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::client::tcp::TcpClient;
            TcpClient::connect_with_llm_actions(
                ctx.remote_addr,
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.client_id,
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
            "send_tcp_data" => {
                // Support both UTF-8 string (data) and hex-encoded (data_hex)
                // Prefer UTF-8 for easier LLM interaction
                let data = if let Some(utf8_data) = action.get("data").and_then(|v| v.as_str()) {
                    // UTF-8 string provided
                    utf8_data.as_bytes().to_vec()
                } else if let Some(hex_data) = action.get("data_hex").and_then(|v| v.as_str()) {
                    // Hex string provided
                    hex::decode(hex_data).context("Invalid hex data in data_hex field")?
                } else {
                    return Err(anyhow::anyhow!(
                        "Missing 'data' or 'data_hex' field in send_tcp_data action"
                    ));
                };

                Ok(ClientActionResult::SendData(data))
            }
            "disconnect" => Ok(ClientActionResult::Disconnect),
            "wait_for_more" => Ok(ClientActionResult::WaitForMore),
            _ => Err(anyhow::anyhow!(
                "Unknown TCP client action: {}",
                action_type
            )),
        }
    }
}

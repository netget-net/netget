//! UDP client protocol actions implementation

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

/// UDP client connected event (socket bound and ready)
pub static UDP_CLIENT_CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "udp_connected",
        "UDP client socket bound and ready to send/receive",
        json!({
            "type": "send_udp_datagram",
            "data_hex": "48656c6c6f"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "remote_addr".to_string(),
            type_hint: "string".to_string(),
            description: "Default remote server address".to_string(),
            required: true,
        },
        Parameter {
            name: "local_addr".to_string(),
            type_hint: "string".to_string(),
            description: "Local socket address".to_string(),
            required: true,
        },
    ])
});

/// UDP client datagram received event
pub static UDP_CLIENT_DATAGRAM_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "udp_datagram_received",
        "Datagram received from UDP server",
        json!({"type": "placeholder", "event_id": "udp_datagram_received"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "data_hex".to_string(),
            type_hint: "string".to_string(),
            description: "The datagram data (as hex string)".to_string(),
            required: true,
        },
        Parameter {
            name: "data_length".to_string(),
            type_hint: "number".to_string(),
            description: "Length of data in bytes".to_string(),
            required: true,
        },
        Parameter {
            name: "source_addr".to_string(),
            type_hint: "string".to_string(),
            description: "Source address of the datagram".to_string(),
            required: true,
        },
    ])
});

/// UDP client protocol action handler
pub struct UdpClientProtocol;

impl Default for UdpClientProtocol {
    fn default() -> Self {
        Self::new()
    }
}

impl UdpClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for UdpClientProtocol {
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![
            ActionDefinition {
                name: "send_udp_datagram".to_string(),
                description: "Send a UDP datagram to a specific address".to_string(),
                parameters: vec![
                    Parameter {
                        name: "data_hex".to_string(),
                        type_hint: "string".to_string(),
                        description: "Hexadecimal encoded data to send".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "target_addr".to_string(),
                        type_hint: "string".to_string(),
                        description: "Optional target address (defaults to remote_addr)"
                            .to_string(),
                        required: false,
                    },
                ],
                example: json!({
                    "type": "send_udp_datagram",
                    "data_hex": "48656c6c6f",
                    "target_addr": "127.0.0.1:8080"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "change_target".to_string(),
                description: "Change the default target address for datagrams".to_string(),
                parameters: vec![Parameter {
                    name: "new_target".to_string(),
                    type_hint: "string".to_string(),
                    description: "New default target address".to_string(),
                    required: true,
                }],
                example: json!({
                    "type": "change_target",
                    "new_target": "127.0.0.1:9090"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "close_socket".to_string(),
                description: "Close the UDP socket".to_string(),
                parameters: vec![],
                example: json!({
                    "type": "close_socket"
                }),
                log_template: None,
            },
        ]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            ActionDefinition {
                name: "send_udp_datagram".to_string(),
                description: "Send UDP datagram in response to received datagram".to_string(),
                parameters: vec![
                    Parameter {
                        name: "data_hex".to_string(),
                        type_hint: "string".to_string(),
                        description: "Hexadecimal encoded data to send".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "target_addr".to_string(),
                        type_hint: "string".to_string(),
                        description:
                            "Optional target address (defaults to source of received datagram)"
                                .to_string(),
                        required: false,
                    },
                ],
                example: json!({
                    "type": "send_udp_datagram",
                    "data_hex": "48656c6c6f"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "wait_for_more".to_string(),
                description: "Wait for more datagrams before responding".to_string(),
                parameters: vec![],
                example: json!({
                    "type": "wait_for_more"
                }),
                log_template: None,
            },
        ]
    }
    fn protocol_name(&self) -> &'static str {
        "UDP"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            EventType::new(
                "udp_connected",
                "Triggered when UDP client socket is bound and ready",
                json!({"type": "placeholder", "event_id": "udp_connected"}),
            ),
            EventType::new(
                "udp_datagram_received",
                "Triggered when UDP client receives a datagram",
                json!({"type": "placeholder", "event_id": "udp_datagram_received"}),
            ),
        ]
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>UDP"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["udp", "udp client", "connect to udp", "datagram"]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .implementation("Tokio UdpSocket for connectionless datagram communication")
            .llm_control("Full control over datagrams, target addresses, and responses")
            .e2e_testing("nc (netcat) with -u flag as test server")
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "UDP client for sending and receiving datagrams"
    }
    fn example_prompt(&self) -> &'static str {
        "Connect to UDP at localhost:8080 and send 'HELLO'"
    }
    fn group_name(&self) -> &'static str {
        "Core"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        use serde_json::json;

        StartupExamples::new(
            // LLM mode: LLM handles UDP client
            json!({
                "type": "open_client",
                "remote_addr": "127.0.0.1:8080",
                "base_stack": "udp",
                "instruction": "Send a UDP datagram containing 'HELLO' and echo any responses"
            }),
            // Script mode: Code-based UDP handling
            json!({
                "type": "open_client",
                "remote_addr": "127.0.0.1:8080",
                "base_stack": "udp",
                "event_handlers": [{
                    "event_pattern": "udp_datagram_received",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "<udp_handler>"
                    }
                }]
            }),
            // Static mode: Fixed UDP response
            json!({
                "type": "open_client",
                "remote_addr": "127.0.0.1:8080",
                "base_stack": "udp",
                "event_handlers": [{
                    "event_pattern": "udp_connected",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "send_udp_datagram",
                            "data_hex": "48454c4c4f"
                        }]
                    }
                }]
            }),
        )
    }
}

// Implement Client trait (client-specific functionality)
impl Client for UdpClientProtocol {
    fn connect(
        &self,
        ctx: crate::protocol::ConnectContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::client::udp::UdpClient;
            UdpClient::connect_with_llm_actions(
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
            "send_udp_datagram" => {
                let data_hex = action
                    .get("data_hex")
                    .and_then(|v| v.as_str())
                    .context("Missing 'data_hex' field")?;

                let data = hex::decode(data_hex).context("Invalid hex data")?;

                // Target address is optional, handled in Custom action
                let target_addr = action
                    .get("target_addr")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());

                Ok(ClientActionResult::Custom {
                    name: "send_udp_datagram".to_string(),
                    data: json!({
                        "data": data,
                        "target_addr": target_addr,
                    }),
                })
            }
            "change_target" => {
                let new_target = action
                    .get("new_target")
                    .and_then(|v| v.as_str())
                    .context("Missing 'new_target' field")?;

                Ok(ClientActionResult::Custom {
                    name: "change_target".to_string(),
                    data: json!({
                        "new_target": new_target,
                    }),
                })
            }
            "close_socket" => Ok(ClientActionResult::Disconnect),
            "wait_for_more" => Ok(ClientActionResult::WaitForMore),
            _ => Err(anyhow::anyhow!(
                "Unknown UDP client action: {}",
                action_type
            )),
        }
    }
}

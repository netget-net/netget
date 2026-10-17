//! TURN client protocol actions implementation

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

/// TURN client connected event
pub static TURN_CLIENT_CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "turn_connected",
        "TURN client successfully connected to server",
        json!({
            "type": "allocate_turn_relay",
            "lifetime_seconds": 600
        }),
    )
    .with_parameters(vec![Parameter {
        name: "remote_addr".to_string(),
        type_hint: "string".to_string(),
        description: "TURN server address".to_string(),
        required: true,
    }])
});

/// TURN client allocation success event
pub static TURN_CLIENT_ALLOCATED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "turn_allocated",
        "TURN relay address allocated successfully",
        json!({
            "type": "create_permission",
            "peer_address": "192.168.1.100:5000"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "relay_address".to_string(),
            type_hint: "string".to_string(),
            description: "The allocated relay address (IP:port)".to_string(),
            required: true,
        },
        Parameter {
            name: "lifetime_seconds".to_string(),
            type_hint: "number".to_string(),
            description: "Allocation lifetime in seconds".to_string(),
            required: true,
        },
        Parameter {
            name: "transaction_id".to_string(),
            type_hint: "string".to_string(),
            description: "Transaction ID (hex)".to_string(),
            required: true,
        },
    ])
});

/// TURN client data received event
pub static TURN_CLIENT_DATA_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "turn_data_received",
        "Data received from peer via TURN relay",
        json!({
            "type": "send_turn_data",
            "peer_address": "192.168.1.100:5000",
            "data_hex": "48656c6c6f"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "peer_address".to_string(),
            type_hint: "string".to_string(),
            description: "Peer address that sent the data".to_string(),
            required: true,
        },
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

/// TURN client permission created event
pub static TURN_CLIENT_PERMISSION_CREATED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "turn_permission_created",
        "Permission created for peer address",
        json!({
            "type": "wait_for_more"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "peer_address".to_string(),
            type_hint: "string".to_string(),
            description: "Peer address granted permission. Recovered by correlating the \
                          response's transaction ID with the CreatePermission request that \
                          named this peer — RFC 8656 section 9.4 makes the Success Response \
                          empty, so the server does not repeat it. A response whose \
                          transaction ID matches nothing this client sent raises no event at \
                          all rather than reporting a peer it cannot name."
                .to_string(),
            required: true,
        },
        Parameter {
            name: "transaction_id".to_string(),
            type_hint: "string".to_string(),
            description: "Transaction ID of the CreatePermission exchange (hex)".to_string(),
            required: true,
        },
    ])
});

/// TURN client allocation refreshed event
pub static TURN_CLIENT_REFRESHED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "turn_refreshed",
        "TURN allocation lifetime extended",
        // Not `placeholder`: the example is what the model copies, and no executor
        // accepts an action by that name.
        json!({
            "type": "refresh_allocation",
            "lifetime_seconds": 600
        }),
    )
    .with_parameters(vec![Parameter {
        name: "lifetime_seconds".to_string(),
        type_hint: "number".to_string(),
        description: "New lifetime in seconds".to_string(),
        required: true,
    }])
});

/// TURN client protocol action handler
pub struct TurnClientProtocol;

impl TurnClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for TurnClientProtocol {
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![
            ActionDefinition {
                name: "allocate_turn_relay".to_string(),
                description: "Request a relay address allocation from TURN server".to_string(),
                parameters: vec![Parameter {
                    name: "lifetime_seconds".to_string(),
                    type_hint: "number".to_string(),
                    description: "Requested lifetime in seconds (default: 600)".to_string(),
                    required: false,
                }],
                example: json!({
                    "type": "allocate_turn_relay",
                    "lifetime_seconds": 600
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "create_permission".to_string(),
                description: "Create permission for a peer address to send/receive data"
                    .to_string(),
                parameters: vec![Parameter {
                    name: "peer_address".to_string(),
                    type_hint: "string".to_string(),
                    description: "Peer IP:port to grant permission (e.g., '192.168.1.100:5000')"
                        .to_string(),
                    required: true,
                }],
                example: json!({
                    "type": "create_permission",
                    "peer_address": "192.168.1.100:5000"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "send_turn_data".to_string(),
                description: "Send data to peer via TURN relay".to_string(),
                parameters: vec![
                    Parameter {
                        name: "peer_address".to_string(),
                        type_hint: "string".to_string(),
                        description: "Peer IP:port to send data to".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "data_hex".to_string(),
                        type_hint: "string".to_string(),
                        description: "Data to send (as hex string)".to_string(),
                        required: true,
                    },
                ],
                example: json!({
                    "type": "send_turn_data",
                    "peer_address": "192.168.1.100:5000",
                    "data_hex": "48656c6c6f"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "refresh_allocation".to_string(),
                description: "Refresh TURN allocation to extend lifetime".to_string(),
                parameters: vec![Parameter {
                    name: "lifetime_seconds".to_string(),
                    type_hint: "number".to_string(),
                    description: "New lifetime in seconds (0 to delete allocation)".to_string(),
                    required: false,
                }],
                example: json!({
                    "type": "refresh_allocation",
                    "lifetime_seconds": 600
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "disconnect".to_string(),
                description: "Disconnect from TURN server".to_string(),
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
                name: "send_turn_data".to_string(),
                description: "Send data to peer via TURN relay in response to received data"
                    .to_string(),
                parameters: vec![
                    Parameter {
                        name: "peer_address".to_string(),
                        type_hint: "string".to_string(),
                        description: "Peer IP:port to send data to".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "data_hex".to_string(),
                        type_hint: "string".to_string(),
                        description: "Data to send (as hex string)".to_string(),
                        required: true,
                    },
                ],
                example: json!({
                    "type": "send_turn_data",
                    "peer_address": "192.168.1.100:5000",
                    "data_hex": "48656c6c6f"
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
        "TURN"
    }
    /// The events this client raises — **the same `LazyLock` statics it actually
    /// emits**, not fresh copies.
    ///
    /// This used to build five brand-new `EventType`s whose `example` was
    /// `{"type": "placeholder", "event_id": …}` and which carried no parameters at
    /// all. `placeholder` is not an action any executor accepts, so the one
    /// worked example an operator or model sees for each event was unusable, and
    /// the parameter list the statics do carry was invisible here. Two
    /// descriptions of the same event that can drift are one too many; there is
    /// now a single source.
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            TURN_CLIENT_CONNECTED_EVENT.clone(),
            TURN_CLIENT_ALLOCATED_EVENT.clone(),
            TURN_CLIENT_DATA_RECEIVED_EVENT.clone(),
            TURN_CLIENT_PERMISSION_CREATED_EVENT.clone(),
            TURN_CLIENT_REFRESHED_EVENT.clone(),
        ]
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>UDP>STUN/TURN"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["turn", "turn client", "relay", "nat traversal", "webrtc"]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            // NOT webrtc-turn, which this claimed for a long time. That crate is an
            // optional dependency of the `turn` feature and nothing in src/ calls
            // it; every byte here is hand-built on the STUN message format.
            .implementation(
                "Manual TURN client (RFC 8656) on the STUN message format — Allocate, \
                 Refresh, CreatePermission and Send indications are built and parsed here, \
                 not by a library",
            )
            .llm_control("Full control over allocations, permissions, and relay data")
            .e2e_testing(
                "NetGet TURN server as test server; tests/client/turn/command_channel_test.rs \
                 asserts the datagrams reach a real socket and \
                 tests/client/turn/response_parsing_test.rs asserts an Allocate Success \
                 Response is decoded and that malformed ones do not kill the read loop",
            )
            .notes(
                "remote_addr must be a literal IP:port — it is parsed with \
                 `SocketAddr::parse` and hostnames are rejected. No authentication: \
                 MESSAGE-INTEGRITY, USERNAME, REALM and NONCE are not implemented, so this \
                 cannot talk to a public TURN service, only to one that grants without \
                 credentials. Responses are correlated by transaction ID only for \
                 CreatePermission; an Allocate or Refresh response from any source that can \
                 reach the client's ephemeral port is accepted, so do not point this at an \
                 untrusted network. UDP allocations only: no TCP, no TLS, no ChannelBind, and \
                 no automatic refresh — the model must refresh before the lifetime expires.",
            )
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "TURN client for NAT traversal relay"
    }
    fn example_prompt(&self) -> &'static str {
        "Connect to TURN server at 127.0.0.1:3478 and allocate a relay address"
    }
    fn group_name(&self) -> &'static str {
        "Network Infrastructure"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        use serde_json::json;

        StartupExamples::new(
            // LLM mode: LLM controls TURN relay
            json!({
                "type": "open_client",
                "remote_addr": "127.0.0.1:3478",
                "base_stack": "turn",
                "instruction": "Allocate a relay address and create permission for peer 192.168.1.100:5000"
            }),
            // Script mode: Code-based TURN handling
            json!({
                "type": "open_client",
                "remote_addr": "127.0.0.1:3478",
                "base_stack": "turn",
                "event_handlers": [{
                    "event_pattern": "turn_data_received",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "<turn_client_handler>"
                    }
                }]
            }),
            // Static mode: Fixed relay allocation
            json!({
                "type": "open_client",
                "remote_addr": "127.0.0.1:3478",
                "base_stack": "turn",
                "event_handlers": [
                    {
                        "event_pattern": "turn_connected",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "allocate_turn_relay",
                                "lifetime_seconds": 600
                            }]
                        }
                    },
                    {
                        "event_pattern": "turn_allocated",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "create_permission",
                                "peer_address": "192.168.1.100:5000"
                            }]
                        }
                    }
                ]
            }),
        )
    }
}

// Implement Client trait (client-specific functionality)
impl Client for TurnClientProtocol {
    fn connect(
        &self,
        ctx: crate::protocol::ConnectContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::client::turn::TurnClient;
            TurnClient::connect_with_llm_actions(
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
            "allocate_turn_relay" => {
                let lifetime = action
                    .get("lifetime_seconds")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(600);

                Ok(ClientActionResult::Custom {
                    name: "allocate".to_string(),
                    data: json!({
                        "lifetime_seconds": lifetime
                    }),
                })
            }
            "create_permission" => {
                let peer_address = action
                    .get("peer_address")
                    .and_then(|v| v.as_str())
                    .context("Missing 'peer_address' field")?;

                Ok(ClientActionResult::Custom {
                    name: "create_permission".to_string(),
                    data: json!({
                        "peer_address": peer_address
                    }),
                })
            }
            "send_turn_data" => {
                let peer_address = action
                    .get("peer_address")
                    .and_then(|v| v.as_str())
                    .context("Missing 'peer_address' field")?;

                let data_hex = action
                    .get("data_hex")
                    .and_then(|v| v.as_str())
                    .context("Missing 'data_hex' field")?;

                let data = hex::decode(data_hex).context("Invalid hex data")?;

                Ok(ClientActionResult::Custom {
                    name: "send_indication".to_string(),
                    data: json!({
                        "peer_address": peer_address,
                        "data": data
                    }),
                })
            }
            "refresh_allocation" => {
                let lifetime = action
                    .get("lifetime_seconds")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(600);

                Ok(ClientActionResult::Custom {
                    name: "refresh".to_string(),
                    data: json!({
                        "lifetime_seconds": lifetime
                    }),
                })
            }
            "disconnect" => Ok(ClientActionResult::Disconnect),
            "wait_for_more" => Ok(ClientActionResult::WaitForMore),
            _ => Err(anyhow::anyhow!(
                "Unknown TURN client action: {}",
                action_type
            )),
        }
    }
}

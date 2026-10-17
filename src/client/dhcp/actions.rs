//! DHCP client protocol actions implementation

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

/// DHCP client connected event
pub static DHCP_CLIENT_CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "dhcp_connected",
        "DHCP client initialized and ready to send requests",
        json!({"type": "wait_for_more"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "server_addr".to_string(),
            type_hint: "string".to_string(),
            description: "DHCP server address".to_string(),
            required: true,
        },
        Parameter {
            name: "local_addr".to_string(),
            type_hint: "string".to_string(),
            description: "Local address bound to port 68".to_string(),
            required: true,
        },
    ])
});

/// DHCP client response received event
pub static DHCP_CLIENT_RESPONSE_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new("dhcp_response_received", "DHCP response received from server", json!({"type": "placeholder", "event_id": "dhcp_response_received"}))
    .with_parameters(vec![
        Parameter {
            name: "message_type".to_string(),
            type_hint: "string".to_string(),
            description: "DHCP message type (OFFER, ACK, NAK, etc.)".to_string(),
            required: true,
        },
        Parameter {
            name: "details".to_string(),
            type_hint: "object".to_string(),
            description: "Parsed DHCP response details (offered_ip, server_ip, subnet_mask, router, dns_servers, lease_time)".to_string(),
            required: true,
        },
    ])
});

/// DHCP client protocol action handler
pub struct DhcpClientProtocol;

impl DhcpClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for DhcpClientProtocol {
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![
                ActionDefinition {
                    name: "dhcp_discover".to_string(),
                    description: "Send DHCP DISCOVER message to find DHCP servers".to_string(),
                    parameters: vec![
                        Parameter {
                            name: "mac_address".to_string(),
                            type_hint: "string".to_string(),
                            description: "Client MAC address (e.g., '00:11:22:33:44:55'). Optional, defaults to '00:00:00:00:00:00'".to_string(),
                            required: false,
                        },
                        Parameter {
                            name: "requested_ip".to_string(),
                            type_hint: "string".to_string(),
                            description: "Requested IP address (optional)".to_string(),
                            required: false,
                        },
                        Parameter {
                            name: "broadcast".to_string(),
                            type_hint: "boolean".to_string(),
                            description: "Send as broadcast (default: true)".to_string(),
                            required: false,
                        },
                    ],
                    example: json!({
                        "type": "dhcp_discover",
                        "mac_address": "00:11:22:33:44:55",
                        "broadcast": true
                    }),
                log_template: None,
                },
                ActionDefinition {
                    name: "dhcp_request".to_string(),
                    description: "Send DHCP REQUEST message to request IP address".to_string(),
                    parameters: vec![
                        Parameter {
                            name: "requested_ip".to_string(),
                            type_hint: "string".to_string(),
                            description: "IP address to request (required)".to_string(),
                            required: true,
                        },
                        Parameter {
                            name: "server_ip".to_string(),
                            type_hint: "string".to_string(),
                            description: "DHCP server IP address (optional)".to_string(),
                            required: false,
                        },
                        Parameter {
                            name: "mac_address".to_string(),
                            type_hint: "string".to_string(),
                            description: "Client MAC address (e.g., '00:11:22:33:44:55'). Optional, defaults to '00:00:00:00:00:00'".to_string(),
                            required: false,
                        },
                        Parameter {
                            name: "broadcast".to_string(),
                            type_hint: "boolean".to_string(),
                            description: "Send as broadcast (default: true)".to_string(),
                            required: false,
                        },
                    ],
                    example: json!({
                        "type": "dhcp_request",
                        "requested_ip": "192.168.1.100",
                        "server_ip": "192.168.1.1",
                        "mac_address": "00:11:22:33:44:55",
                        "broadcast": true
                    }),
                log_template: None,
                },
                ActionDefinition {
                    name: "dhcp_inform".to_string(),
                    description: "Send DHCP INFORM message to query network configuration".to_string(),
                    parameters: vec![
                        Parameter {
                            name: "current_ip".to_string(),
                            type_hint: "string".to_string(),
                            description: "Current IP address of the client".to_string(),
                            required: true,
                        },
                        Parameter {
                            name: "mac_address".to_string(),
                            type_hint: "string".to_string(),
                            description: "Client MAC address (e.g., '00:11:22:33:44:55'). Optional, defaults to '00:00:00:00:00:00'".to_string(),
                            required: false,
                        },
                    ],
                    example: json!({
                        "type": "dhcp_inform",
                        "current_ip": "192.168.1.50",
                        "mac_address": "00:11:22:33:44:55"
                    }),
                log_template: None,
                },
                ActionDefinition {
                    name: "disconnect".to_string(),
                    description: "Disconnect from the DHCP server".to_string(),
                    parameters: vec![],
                    example: json!({
                        "type": "disconnect"
                    }),
                log_template: None,
                },
            ]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![ActionDefinition {
            name: "wait_for_more".to_string(),
            description: "Wait for more DHCP responses before taking action".to_string(),
            parameters: vec![],
            example: json!({
                "type": "wait_for_more"
            }),
            log_template: None,
        }]
    }
    fn protocol_name(&self) -> &'static str {
        "DHCP"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>UDP>DHCP"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            DHCP_CLIENT_CONNECTED_EVENT.clone(),
            DHCP_CLIENT_RESPONSE_RECEIVED_EVENT.clone(),
        ]
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["dhcp", "dhcp client", "connect to dhcp"]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{
            DevelopmentState, PrivilegeRequirement, ProtocolMetadataV2,
        };

        ProtocolMetadataV2::builder()
                .state(DevelopmentState::Experimental)
                .privilege_requirement(PrivilegeRequirement::PrivilegedPort(68))
                .implementation("dhcproto v0.12 for DHCP protocol parsing")
                .llm_control("DISCOVER, REQUEST, INFORM message control")
                .e2e_testing("NetGet DHCP server as test target")
                .notes("Requires elevated privileges to bind port 68. For testing only, does NOT configure OS network.")
                .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
                .batching(crate::protocol::metadata::BatchingMode::Unsupported)
                .build()
    }
    fn description(&self) -> &'static str {
        "DHCP client for IP address discovery and network testing"
    }
    fn example_prompt(&self) -> &'static str {
        "Connect to DHCP server at 192.168.1.1 and send DISCOVER"
    }
    fn group_name(&self) -> &'static str {
        "Core"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        use serde_json::json;

        StartupExamples::new(
            // LLM mode: LLM controls DHCP discovery
            json!({
                "type": "open_client",
                "remote_addr": "255.255.255.255:67",
                "base_stack": "dhcp",
                "instruction": "Send DHCP DISCOVER with MAC 00:11:22:33:44:55 and report the offered IP"
            }),
            // Script mode: Code-based deterministic responses
            json!({
                "type": "open_client",
                "remote_addr": "255.255.255.255:67",
                "base_stack": "dhcp",
                "event_handlers": [{
                    "event_pattern": "dhcp_response_received",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "<dhcp_client_handler>"
                    }
                }]
            }),
            // Static mode: Fixed DHCP discover on connect
            json!({
                "type": "open_client",
                "remote_addr": "255.255.255.255:67",
                "base_stack": "dhcp",
                "event_handlers": [
                    {
                        "event_pattern": "dhcp_connected",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "dhcp_discover",
                                "mac_address": "00:11:22:33:44:55",
                                "broadcast": true
                            }]
                        }
                    },
                    {
                        "event_pattern": "dhcp_response_received",
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
impl Client for DhcpClientProtocol {
    fn connect(
        &self,
        ctx: crate::protocol::ConnectContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::client::dhcp::DhcpClient;
            DhcpClient::connect_with_llm_actions(
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
            "dhcp_discover" => Ok(ClientActionResult::Custom {
                name: "dhcp_discover".to_string(),
                data: action,
            }),
            "dhcp_request" => Ok(ClientActionResult::Custom {
                name: "dhcp_request".to_string(),
                data: action,
            }),
            "dhcp_inform" => Ok(ClientActionResult::Custom {
                name: "dhcp_inform".to_string(),
                data: action,
            }),
            "disconnect" => Ok(ClientActionResult::Disconnect),
            "wait_for_more" => Ok(ClientActionResult::WaitForMore),
            _ => Err(anyhow::anyhow!(
                "Unknown DHCP client action: {}",
                action_type
            )),
        }
    }
}

//! BOOTP client protocol actions implementation

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

/// BOOTP client connected event (sent when UDP socket is bound and ready)
pub static BOOTP_CLIENT_CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "bootp_connected",
        "BOOTP client ready to send requests",
        json!({"type": "placeholder", "event_id": "bootp_connected"}),
    )
    .with_parameters(vec![Parameter {
        name: "server_addr".to_string(),
        type_hint: "string".to_string(),
        description: "BOOTP/DHCP server address".to_string(),
        required: true,
    }])
});

/// BOOTP reply received event
pub static BOOTP_REPLY_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "bootp_reply_received",
        "BOOTP reply received from server",
        json!({"type": "placeholder", "event_id": "bootp_reply_received"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "assigned_ip".to_string(),
            type_hint: "string".to_string(),
            description: "IP address assigned by BOOTP server (yiaddr)".to_string(),
            required: true,
        },
        Parameter {
            name: "server_ip".to_string(),
            type_hint: "string".to_string(),
            description: "BOOTP server IP address (siaddr)".to_string(),
            required: true,
        },
        Parameter {
            name: "boot_filename".to_string(),
            type_hint: "string".to_string(),
            description: "Boot file name (e.g., 'pxelinux.0')".to_string(),
            required: false,
        },
        Parameter {
            name: "gateway_ip".to_string(),
            type_hint: "string".to_string(),
            description: "Gateway IP address (giaddr)".to_string(),
            required: false,
        },
    ])
});

/// BOOTP client protocol action handler
#[derive(Default)]
pub struct BootpClientProtocol;

impl BootpClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for BootpClientProtocol {
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![
            ActionDefinition {
                name: "send_bootp_request".to_string(),
                description: "Send a BOOTP request to discover boot server and IP address"
                    .to_string(),
                parameters: vec![
                    Parameter {
                        name: "client_mac".to_string(),
                        type_hint: "string".to_string(),
                        description: "Client MAC address (format: 00:11:22:33:44:55)".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "broadcast".to_string(),
                        type_hint: "boolean".to_string(),
                        description: "Use broadcast (true) or unicast (false)".to_string(),
                        required: false,
                    },
                ],
                example: json!({
                    "type": "send_bootp_request",
                    "client_mac": "00:11:22:33:44:55",
                    "broadcast": true
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "disconnect".to_string(),
                description: "Close the BOOTP client".to_string(),
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
                name: "send_bootp_request".to_string(),
                description: "Send another BOOTP request in response to a reply".to_string(),
                parameters: vec![
                    Parameter {
                        name: "client_mac".to_string(),
                        type_hint: "string".to_string(),
                        description: "Client MAC address (format: 00:11:22:33:44:55)".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "broadcast".to_string(),
                        type_hint: "boolean".to_string(),
                        description: "Use broadcast (true) or unicast (false)".to_string(),
                        required: false,
                    },
                ],
                example: json!({
                    "type": "send_bootp_request",
                    "client_mac": "00:11:22:33:44:55",
                    "broadcast": true
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "wait_for_more".to_string(),
                description: "Wait for more BOOTP replies before responding".to_string(),
                parameters: vec![],
                example: json!({
                    "type": "wait_for_more"
                }),
                log_template: None,
            },
        ]
    }
    fn protocol_name(&self) -> &'static str {
        "BOOTP"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            EventType::new(
                "bootp_connected",
                "Triggered when BOOTP client is ready",
                json!({"type": "placeholder", "event_id": "bootp_connected"}),
            ),
            EventType::new(
                "bootp_reply_received",
                "Triggered when BOOTP reply is received from server",
                json!({"type": "placeholder", "event_id": "bootp_reply_received"}),
            ),
        ]
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>UDP>BOOTP"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["bootp", "bootp client", "bootstrap protocol"]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .implementation("dhcproto crate for BOOTP packet encoding/decoding")
            .llm_control("Full control over BOOTP requests and reply interpretation")
            .e2e_testing("dnsmasq or isc-dhcp-server for BOOTP testing")
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "BOOTP client for diskless workstation boot discovery (PXE boot, TFTP server location)"
    }
    fn example_prompt(&self) -> &'static str {
        "Connect to BOOTP server at 192.168.1.1:67 and request boot information for MAC 00:11:22:33:44:55"
    }
    fn group_name(&self) -> &'static str {
        "Network Services"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        use serde_json::json;

        StartupExamples::new(
            // LLM mode: LLM controls BOOTP discovery
            json!({
                "type": "open_client",
                "remote_addr": "192.168.1.1:67",
                "base_stack": "bootp",
                "instruction": "Request boot information for MAC 00:11:22:33:44:55 and report the boot server and filename"
            }),
            // Script mode: Code-based deterministic responses
            json!({
                "type": "open_client",
                "remote_addr": "192.168.1.1:67",
                "base_stack": "bootp",
                "event_handlers": [{
                    "event_pattern": "bootp_reply_received",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "<bootp_client_handler>"
                    }
                }]
            }),
            // Static mode: Fixed BOOTP request on connect
            json!({
                "type": "open_client",
                "remote_addr": "192.168.1.1:67",
                "base_stack": "bootp",
                "event_handlers": [
                    {
                        "event_pattern": "bootp_connected",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "send_bootp_request",
                                "client_mac": "00:11:22:33:44:55",
                                "broadcast": true
                            }]
                        }
                    },
                    {
                        "event_pattern": "bootp_reply_received",
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
impl Client for BootpClientProtocol {
    fn connect(
        &self,
        ctx: crate::protocol::ConnectContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::client::bootp::BootpClient;
            BootpClient::connect_with_llm_actions(
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
            "send_bootp_request" => {
                let client_mac = action
                    .get("client_mac")
                    .and_then(|v| v.as_str())
                    .context("Missing 'client_mac' field")?;

                let broadcast = action
                    .get("broadcast")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(true);

                Ok(ClientActionResult::Custom {
                    name: "send_bootp_request".to_string(),
                    data: json!({
                        "client_mac": client_mac,
                        "broadcast": broadcast,
                    }),
                })
            }
            "disconnect" => Ok(ClientActionResult::Disconnect),
            "wait_for_more" => Ok(ClientActionResult::WaitForMore),
            _ => Err(anyhow::anyhow!(
                "Unknown BOOTP client action: {}",
                action_type
            )),
        }
    }
}

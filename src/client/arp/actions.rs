//! ARP client protocol actions implementation

use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, Parameter, ParameterDefinition,
};
use crate::protocol::{ConnectContext, EventType};
use crate::state::app_state::AppState;
use anyhow::{Context, Result};
use serde_json::json;
use std::sync::LazyLock;

/// ARP client started event
pub static ARP_CLIENT_STARTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "arp_client_started",
        "ARP client successfully started on network interface",
        json!({"type": "wait_for_more"}),
    )
    .with_parameters(vec![Parameter {
        name: "interface".to_string(),
        type_hint: "string".to_string(),
        description: "Network interface name".to_string(),
        required: true,
    }])
});

/// ARP response received event
pub static ARP_CLIENT_RESPONSE_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "arp_response_received",
        "ARP response received from network",
        json!({"type": "send_arp_reply", "sender_mac": "aa:bb:cc:dd:ee:ff", "sender_ip": "192.168.1.100", "target_mac": "11:22:33:44:55:66", "target_ip": "192.168.1.1"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "operation".to_string(),
            type_hint: "string".to_string(),
            description: "ARP operation (REQUEST or REPLY)".to_string(),
            required: true,
        },
        Parameter {
            name: "sender_mac".to_string(),
            type_hint: "string".to_string(),
            description: "Sender MAC address".to_string(),
            required: true,
        },
        Parameter {
            name: "sender_ip".to_string(),
            type_hint: "string".to_string(),
            description: "Sender IP address".to_string(),
            required: true,
        },
        Parameter {
            name: "target_mac".to_string(),
            type_hint: "string".to_string(),
            description: "Target MAC address".to_string(),
            required: true,
        },
        Parameter {
            name: "target_ip".to_string(),
            type_hint: "string".to_string(),
            description: "Target IP address".to_string(),
            required: true,
        },
    ])
});

/// ARP client protocol action handler
#[derive(Default)]
pub struct ArpClientProtocol;

impl ArpClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for ArpClientProtocol {
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![
            ActionDefinition {
                name: "send_arp_request".to_string(),
                description: "Send an ARP request (who-has query)".to_string(),
                parameters: vec![
                    Parameter {
                        name: "sender_mac".to_string(),
                        type_hint: "string".to_string(),
                        description: "Source MAC address (format: aa:bb:cc:dd:ee:ff)".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "sender_ip".to_string(),
                        type_hint: "string".to_string(),
                        description: "Source IP address".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "target_ip".to_string(),
                        type_hint: "string".to_string(),
                        description: "Target IP address to query".to_string(),
                        required: true,
                    },
                ],
                example: json!({
                    "type": "send_arp_request",
                    "sender_mac": "aa:bb:cc:dd:ee:ff",
                    "sender_ip": "192.168.1.100",
                    "target_ip": "192.168.1.1"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "send_arp_reply".to_string(),
                description: "Send an ARP reply (gratuitous ARP)".to_string(),
                parameters: vec![
                    Parameter {
                        name: "sender_mac".to_string(),
                        type_hint: "string".to_string(),
                        description: "Source MAC address".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "sender_ip".to_string(),
                        type_hint: "string".to_string(),
                        description: "Source IP address".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "target_mac".to_string(),
                        type_hint: "string".to_string(),
                        description: "Target MAC address".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "target_ip".to_string(),
                        type_hint: "string".to_string(),
                        description: "Target IP address".to_string(),
                        required: true,
                    },
                ],
                example: json!({
                    "type": "send_arp_reply",
                    "sender_mac": "aa:bb:cc:dd:ee:ff",
                    "sender_ip": "192.168.1.100",
                    "target_mac": "11:22:33:44:55:66",
                    "target_ip": "192.168.1.1"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "stop_capture".to_string(),
                description: "Stop ARP capture and close client".to_string(),
                parameters: vec![],
                example: json!({
                    "type": "stop_capture"
                }),
                log_template: None,
            },
        ]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            ActionDefinition {
                name: "send_arp_request".to_string(),
                description: "Send ARP request in response to received ARP packet".to_string(),
                parameters: vec![
                    Parameter {
                        name: "sender_mac".to_string(),
                        type_hint: "string".to_string(),
                        description: "Source MAC address".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "sender_ip".to_string(),
                        type_hint: "string".to_string(),
                        description: "Source IP address".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "target_ip".to_string(),
                        type_hint: "string".to_string(),
                        description: "Target IP to query".to_string(),
                        required: true,
                    },
                ],
                example: json!({
                    "type": "send_arp_request",
                    "sender_mac": "aa:bb:cc:dd:ee:ff",
                    "sender_ip": "192.168.1.100",
                    "target_ip": "192.168.1.1"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "send_arp_reply".to_string(),
                description: "Send ARP reply in response to received ARP packet".to_string(),
                parameters: vec![
                    Parameter {
                        name: "sender_mac".to_string(),
                        type_hint: "string".to_string(),
                        description: "Source MAC address".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "sender_ip".to_string(),
                        type_hint: "string".to_string(),
                        description: "Source IP address".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "target_mac".to_string(),
                        type_hint: "string".to_string(),
                        description: "Target MAC address".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "target_ip".to_string(),
                        type_hint: "string".to_string(),
                        description: "Target IP address".to_string(),
                        required: true,
                    },
                ],
                example: json!({
                    "type": "send_arp_reply",
                    "sender_mac": "aa:bb:cc:dd:ee:ff",
                    "sender_ip": "192.168.1.100",
                    "target_mac": "11:22:33:44:55:66",
                    "target_ip": "192.168.1.1"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "wait_for_more".to_string(),
                description: "Continue monitoring for ARP packets".to_string(),
                parameters: vec![],
                example: json!({
                    "type": "wait_for_more"
                }),
                log_template: None,
            },
        ]
    }
    fn protocol_name(&self) -> &'static str {
        "ARP"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            EventType::new(
                "arp_client_started",
                "Triggered when ARP client starts capturing",
                json!({"type": "wait_for_more"}),
            ),
            EventType::new(
                "arp_response_received",
                "Triggered when ARP packet is received",
                json!({"type": "send_arp_reply", "sender_mac": "aa:bb:cc:dd:ee:ff", "sender_ip": "192.168.1.100", "target_mac": "11:22:33:44:55:66", "target_ip": "192.168.1.1"}),
            ),
        ]
    }
    fn stack_name(&self) -> &'static str {
        "ETH>ARP"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["arp", "arp client", "address resolution", "layer 2"]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{
            DevelopmentState, PrivilegeRequirement, ProtocolMetadataV2,
        };

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            // Both pcap handles - the capture and the injection one - need root, read
            // access to /dev/bpf* on macOS/BSD, or CAP_NET_RAW on Linux. `PacketCapture`,
            // not `RawSockets`: this goes through libpcap, not a SOCK_RAW socket, and the
            // datalink client (the same pcap shape) declares the same. Note that
            // `client_startup` does not currently gate on this the way `server_startup`
            // does, so it is documentation for the operator and the TUI rather than a
            // check - `connect()` awaiting the pcap open is what actually refuses.
            .privilege_requirement(PrivilegeRequirement::PacketCapture)
            .implementation("pcap + pnet for ARP packet capture and injection")
            .llm_control("Send ARP requests/replies, monitor ARP traffic")
            .e2e_testing(
                "tests/client/arp/command_channel_test.rs runs unprivileged in every ordinary \
                 test run: it asserts that a capture which cannot open makes connect() return \
                 Err rather than leaving the client Connected, and drives the injected-command \
                 surface end to end (Sent/Rejected/Disconnected, and the access-log record) by \
                 standing in for the pcap injection thread. Only the branch proving libpcap \
                 itself accepted the frame needs root, and it is #[ignore]d.",
            )
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "ARP client for sending ARP requests and monitoring ARP traffic"
    }
    fn example_prompt(&self) -> &'static str {
        "Monitor ARP on eth0 and send who-has query for 192.168.1.1"
    }
    fn group_name(&self) -> &'static str {
        "Core"
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![ParameterDefinition {
            name: "interface".to_string(),
            type_hint: "string".to_string(),
            description: "Network interface name (e.g., eth0, en0)".to_string(),
            required: true,
            example: json!("eth0"),
            default: None,
        }]
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        use serde_json::json;

        StartupExamples::new(
            // LLM mode: LLM handles ARP client
            json!({
                "type": "open_client",
                "remote_addr": "eth0",
                "base_stack": "arp",
                "instruction": "Send ARP requests for 192.168.1.0/24 and discover live hosts",
                "startup_params": {
                    "interface": "eth0"
                }
            }),
            // Script mode: Code-based ARP handling
            json!({
                "type": "open_client",
                "remote_addr": "eth0",
                "base_stack": "arp",
                "startup_params": {
                    "interface": "eth0"
                },
                "event_handlers": [{
                    "event_pattern": "arp_response_received",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "<arp_handler>"
                    }
                }]
            }),
            // Static mode: Fixed ARP request
            json!({
                "type": "open_client",
                "remote_addr": "eth0",
                "base_stack": "arp",
                "startup_params": {
                    "interface": "eth0"
                },
                "event_handlers": [{
                    "event_pattern": "arp_client_started",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "send_arp_request",
                            "sender_mac": "aa:bb:cc:dd:ee:ff",
                            "sender_ip": "192.168.1.100",
                            "target_ip": "192.168.1.1"
                        }]
                    }
                }]
            }),
        )
    }
}

// Implement Client trait (client-specific functionality)
impl Client for ArpClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::client::arp::ArpClient;
            ArpClient::start_with_llm_actions(
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
            "send_arp_request" => {
                let sender_mac = action
                    .get("sender_mac")
                    .and_then(|v| v.as_str())
                    .context("Missing 'sender_mac' field")?;
                let sender_ip = action
                    .get("sender_ip")
                    .and_then(|v| v.as_str())
                    .context("Missing 'sender_ip' field")?;
                let target_ip = action
                    .get("target_ip")
                    .and_then(|v| v.as_str())
                    .context("Missing 'target_ip' field")?;

                Ok(ClientActionResult::Custom {
                    name: "send_arp_request".to_string(),
                    data: json!({
                        "sender_mac": sender_mac,
                        "sender_ip": sender_ip,
                        "target_ip": target_ip,
                    }),
                })
            }
            "send_arp_reply" => {
                let sender_mac = action
                    .get("sender_mac")
                    .and_then(|v| v.as_str())
                    .context("Missing 'sender_mac' field")?;
                let sender_ip = action
                    .get("sender_ip")
                    .and_then(|v| v.as_str())
                    .context("Missing 'sender_ip' field")?;
                let target_mac = action
                    .get("target_mac")
                    .and_then(|v| v.as_str())
                    .context("Missing 'target_mac' field")?;
                let target_ip = action
                    .get("target_ip")
                    .and_then(|v| v.as_str())
                    .context("Missing 'target_ip' field")?;

                Ok(ClientActionResult::Custom {
                    name: "send_arp_reply".to_string(),
                    data: json!({
                        "sender_mac": sender_mac,
                        "sender_ip": sender_ip,
                        "target_mac": target_mac,
                        "target_ip": target_ip,
                    }),
                })
            }
            "stop_capture" => Ok(ClientActionResult::Disconnect),
            "wait_for_more" => Ok(ClientActionResult::WaitForMore),
            _ => Err(anyhow::anyhow!(
                "Unknown ARP client action: {}",
                action_type
            )),
        }
    }
}

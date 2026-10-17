//! mDNS client protocol actions implementation

use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, Parameter,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::EventType;
use crate::state::app_state::AppState;
use anyhow::{Context, Result};
use serde_json::json;
use std::sync::LazyLock;

/// mDNS client connected event
pub static MDNS_CLIENT_CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "mdns_connected",
        "mDNS client initialized and ready for service discovery",
        json!({"type": "browse_service", "service_type": "_http._tcp.local"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "status".to_string(),
            type_hint: "string".to_string(),
            description: "Connection status".to_string(),
            required: true,
        },
        Parameter {
            name: "message".to_string(),
            type_hint: "string".to_string(),
            description: "Status message".to_string(),
            required: false,
        },
    ])
});

/// mDNS service found event
pub static MDNS_CLIENT_SERVICE_FOUND_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "mdns_service_found",
        "mDNS service instance discovered on the local network",
        json!({"type": "wait_for_more"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "service_type".to_string(),
            type_hint: "string".to_string(),
            description: "Service type (e.g., '_http._tcp.local')".to_string(),
            required: true,
        },
        Parameter {
            name: "fullname".to_string(),
            type_hint: "string".to_string(),
            description: "Full service instance name".to_string(),
            required: true,
        },
    ])
});

/// mDNS service resolved event
pub static MDNS_CLIENT_SERVICE_RESOLVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "mdns_service_resolved",
        "mDNS service fully resolved with IP addresses and port",
        json!({"type": "wait_for_more"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "fullname".to_string(),
            type_hint: "string".to_string(),
            description: "Full service instance name".to_string(),
            required: true,
        },
        Parameter {
            name: "hostname".to_string(),
            type_hint: "string".to_string(),
            description: "Service hostname".to_string(),
            required: true,
        },
        Parameter {
            name: "addresses".to_string(),
            type_hint: "array".to_string(),
            description: "List of IP addresses".to_string(),
            required: true,
        },
        Parameter {
            name: "port".to_string(),
            type_hint: "number".to_string(),
            description: "Service port number".to_string(),
            required: true,
        },
        Parameter {
            name: "properties".to_string(),
            type_hint: "array".to_string(),
            description: "Service TXT record properties".to_string(),
            required: false,
        },
    ])
});

/// mDNS client protocol action handler
pub struct MdnsClientProtocol;

impl MdnsClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for MdnsClientProtocol {
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![
                ActionDefinition {
                    name: "browse_service".to_string(),
                    description: "Browse for mDNS services of a specific type on the local network".to_string(),
                    parameters: vec![
                        Parameter {
                            name: "service_type".to_string(),
                            type_hint: "string".to_string(),
                            description: "Service type to browse for (e.g., '_http._tcp.local', '_ssh._tcp.local', '_printer._tcp.local')".to_string(),
                            required: true,
                        },
                    ],
                    example: json!({
                        "type": "browse_service",
                        "service_type": "_http._tcp.local"
                    }),
                log_template: None,
                },
                ActionDefinition {
                    name: "resolve_hostname".to_string(),
                    description: "Resolve a .local hostname to IP addresses using mDNS".to_string(),
                    parameters: vec![
                        Parameter {
                            name: "hostname".to_string(),
                            type_hint: "string".to_string(),
                            description: "Hostname to resolve (e.g., 'myserver.local')".to_string(),
                            required: true,
                        },
                    ],
                    example: json!({
                        "type": "resolve_hostname",
                        "hostname": "myserver.local"
                    }),
                log_template: None,
                },
                ActionDefinition {
                    name: "disconnect".to_string(),
                    description: "Stop mDNS service discovery and disconnect".to_string(),
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
            description: "Wait for more service discovery events before responding".to_string(),
            parameters: vec![],
            example: json!({
                "type": "wait_for_more"
            }),
            log_template: Some(
                LogTemplate::new()
                    .with_info("-> mDNS wait for more")
                    .with_debug("mDNS wait_for_more"),
            ),
        }]
    }
    fn protocol_name(&self) -> &'static str {
        "mDNS"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            EventType::new(
                "mdns_connected",
                "Triggered when mDNS client is initialized",
                json!({"type": "wait_for_more"}),
            ),
            EventType::new(
                "mdns_service_found",
                "Triggered when an mDNS service is discovered",
                json!({"type": "wait_for_more"}),
            ),
            EventType::new(
                "mdns_service_resolved",
                "Triggered when an mDNS service is fully resolved with IP and port",
                json!({"type": "wait_for_more"}),
            ),
        ]
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>UDP>mDNS"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "mdns",
            "multicast dns",
            "service discovery",
            "zeroconf",
            "bonjour",
            ".local",
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .implementation("mdns-sd crate for RFC 6762 and RFC 6763 compliance")
            .llm_control("Browse services, resolve hostnames, analyze service properties")
            .e2e_testing("Built-in macOS/Linux mDNS responders for testing")
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "mDNS client for discovering services on the local network"
    }
    fn example_prompt(&self) -> &'static str {
        "Browse for HTTP services on the local network using mDNS"
    }
    fn group_name(&self) -> &'static str {
        "DNS"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        use serde_json::json;

        StartupExamples::new(
            // LLM mode: LLM controls mDNS service discovery
            json!({
                "type": "open_client",
                "remote_addr": "0.0.0.0:5353",
                "base_stack": "mdns",
                "instruction": "Browse for HTTP services on the local network and list all discovered web servers"
            }),
            // Script mode: Code-based deterministic responses
            json!({
                "type": "open_client",
                "remote_addr": "0.0.0.0:5353",
                "base_stack": "mdns",
                "event_handlers": [{
                    "event_pattern": "mdns_service_resolved",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "<mdns_client_handler>"
                    }
                }]
            }),
            // Static mode: Fixed mDNS browse on connect
            json!({
                "type": "open_client",
                "remote_addr": "0.0.0.0:5353",
                "base_stack": "mdns",
                "event_handlers": [
                    {
                        "event_pattern": "mdns_connected",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "browse_service",
                                "service_type": "_http._tcp.local"
                            }]
                        }
                    },
                    {
                        "event_pattern": "mdns_service_resolved",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "wait_for_more"
                            }]
                        }
                    }
                ]
            }),
        )
    }
}

// Implement Client trait (client-specific functionality)
impl Client for MdnsClientProtocol {
    fn connect(
        &self,
        ctx: crate::protocol::ConnectContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::client::mdns::MdnsClient;
            MdnsClient::connect_with_llm_actions(
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
            "browse_service" => {
                let service_type = action
                    .get("service_type")
                    .and_then(|v| v.as_str())
                    .context("Missing 'service_type' field")?;

                Ok(ClientActionResult::Custom {
                    name: "browse_service".to_string(),
                    data: json!({
                        "service_type": service_type
                    }),
                })
            }
            "resolve_hostname" => {
                let hostname = action
                    .get("hostname")
                    .and_then(|v| v.as_str())
                    .context("Missing 'hostname' field")?;

                Ok(ClientActionResult::Custom {
                    name: "resolve_hostname".to_string(),
                    data: json!({
                        "hostname": hostname
                    }),
                })
            }
            "disconnect" => Ok(ClientActionResult::Disconnect),
            "wait_for_more" => Ok(ClientActionResult::WaitForMore),
            _ => Err(anyhow::anyhow!(
                "Unknown mDNS client action: {}",
                action_type
            )),
        }
    }
}

//! DoT (DNS over TLS) client protocol actions implementation

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

/// DoT client connected event
pub static DOT_CLIENT_CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "dot_connected",
        "DoT client connected to DNS-over-TLS server",
        json!({"type": "send_dns_query", "domain": "example.com", "query_type": "A"}),
    )
    .with_parameters(vec![Parameter {
        name: "remote_addr".to_string(),
        type_hint: "string".to_string(),
        description: "DNS-over-TLS server address".to_string(),
        required: true,
    }])
});

/// DoT client response received event
pub static DOT_CLIENT_RESPONSE_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "dot_response_received",
        "DNS response received from DoT server",
        json!({"type": "send_dns_query", "domain": "mail.example.com", "query_type": "MX"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "query_id".to_string(),
            type_hint: "number".to_string(),
            description: "DNS query ID".to_string(),
            required: true,
        },
        Parameter {
            name: "response_code".to_string(),
            type_hint: "string".to_string(),
            description: "DNS response code (NOERROR, NXDOMAIN, etc.)".to_string(),
            required: true,
        },
        Parameter {
            name: "answers".to_string(),
            type_hint: "array".to_string(),
            description: "DNS answer records".to_string(),
            required: true,
        },
        Parameter {
            name: "authorities".to_string(),
            type_hint: "array".to_string(),
            description: "DNS authority records".to_string(),
            required: true,
        },
        Parameter {
            name: "additionals".to_string(),
            type_hint: "array".to_string(),
            description: "DNS additional records".to_string(),
            required: true,
        },
    ])
});

/// DoT client protocol action handler
pub struct DotClientProtocol;

impl DotClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for DotClientProtocol {
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "verify_tls".to_string(),
                description: "Verify TLS certificate (default: true)".to_string(),
                type_hint: "boolean".to_string(),
                required: false,
                example: json!(true),
                default: None,
            },
            ParameterDefinition {
                name: "server_name".to_string(),
                description:
                    "Server name for TLS SNI (optional, defaults to hostname from address)"
                        .to_string(),
                type_hint: "string".to_string(),
                required: false,
                example: json!("dns.google"),
                default: None,
            },
        ]
    }
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![
            ActionDefinition {
                name: "send_dns_query".to_string(),
                description: "Send a DNS query to the DoT server".to_string(),
                parameters: vec![
                    Parameter {
                        name: "domain".to_string(),
                        type_hint: "string".to_string(),
                        description: "Domain name to query".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "query_type".to_string(),
                        type_hint: "string".to_string(),
                        description: "DNS query type (A, AAAA, MX, TXT, CNAME, NS, etc.)"
                            .to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "recursive".to_string(),
                        type_hint: "boolean".to_string(),
                        description: "Request recursive resolution (default: true)".to_string(),
                        required: false,
                    },
                ],
                example: json!({
                    "type": "send_dns_query",
                    "domain": "example.com",
                    "query_type": "A",
                    "recursive": true
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "disconnect".to_string(),
                description: "Disconnect from the DoT server".to_string(),
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
                name: "send_dns_query".to_string(),
                description: "Send another DNS query in response to received data".to_string(),
                parameters: vec![
                    Parameter {
                        name: "domain".to_string(),
                        type_hint: "string".to_string(),
                        description: "Domain name to query".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "query_type".to_string(),
                        type_hint: "string".to_string(),
                        description: "DNS query type".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "recursive".to_string(),
                        type_hint: "boolean".to_string(),
                        description: "Request recursive resolution".to_string(),
                        required: false,
                    },
                ],
                example: json!({
                    "type": "send_dns_query",
                    "domain": "example.org",
                    "query_type": "AAAA"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "wait_for_more".to_string(),
                description: "Wait for more DNS responses without sending a query".to_string(),
                parameters: vec![],
                example: json!({
                    "type": "wait_for_more"
                }),
                log_template: None,
            },
        ]
    }
    fn protocol_name(&self) -> &'static str {
        "DoT"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            EventType::new(
                "dot_connected",
                "Triggered when DoT client connects to server",
                json!({"type": "placeholder", "event_id": "dot_connected"}),
            ),
            EventType::new(
                "dot_response_received",
                "Triggered when DoT client receives a DNS response",
                json!({"type": "placeholder", "event_id": "dot_response_received"}),
            ),
        ]
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>TLS>DNS"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "dot",
            "dns over tls",
            "dns-over-tls",
            "dns tls",
            "secure dns",
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .implementation("hickory-dns with rustls for TLS transport")
            .llm_control("Full control over DNS queries (domain, type, recursive flag)")
            .e2e_testing("Public DoT servers (dns.google:853, 1.1.1.1:853)")
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "DoT (DNS over TLS) client for secure DNS queries"
    }
    fn example_prompt(&self) -> &'static str {
        "Connect to dns.google:853 and query example.com A record"
    }
    fn group_name(&self) -> &'static str {
        "DNS"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        use serde_json::json;

        StartupExamples::new(
            // LLM mode: LLM controls DNS queries over TLS
            json!({
                "type": "open_client",
                "remote_addr": "dns.google:853",
                "base_stack": "dot",
                "instruction": "Query example.com for A and AAAA records, then report the IP addresses"
            }),
            // Script mode: Code-based deterministic responses
            json!({
                "type": "open_client",
                "remote_addr": "dns.google:853",
                "base_stack": "dot",
                "event_handlers": [{
                    "event_pattern": "dot_response_received",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "<dot_client_handler>"
                    }
                }]
            }),
            // Static mode: Fixed DNS query on connect
            json!({
                "type": "open_client",
                "remote_addr": "dns.google:853",
                "base_stack": "dot",
                "event_handlers": [
                    {
                        "event_pattern": "dot_connected",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "send_dns_query",
                                "domain": "example.com",
                                "query_type": "A"
                            }]
                        }
                    },
                    {
                        "event_pattern": "dot_response_received",
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
impl Client for DotClientProtocol {
    fn connect(
        &self,
        ctx: crate::protocol::ConnectContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::client::dot::DotClient;
            DotClient::connect_with_llm_actions(
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
            "send_dns_query" => {
                let domain = action
                    .get("domain")
                    .and_then(|v| v.as_str())
                    .context("Missing 'domain' field")?
                    .to_string();

                let query_type = action
                    .get("query_type")
                    .and_then(|v| v.as_str())
                    .context("Missing 'query_type' field")?
                    .to_string();

                let recursive = action
                    .get("recursive")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(true);

                // Return custom result with query data
                Ok(ClientActionResult::Custom {
                    name: "dns_query".to_string(),
                    data: json!({
                        "domain": domain,
                        "query_type": query_type,
                        "recursive": recursive,
                    }),
                })
            }
            "disconnect" => Ok(ClientActionResult::Disconnect),
            "wait_for_more" => Ok(ClientActionResult::WaitForMore),
            _ => Err(anyhow::anyhow!(
                "Unknown DoT client action: {}",
                action_type
            )),
        }
    }
}

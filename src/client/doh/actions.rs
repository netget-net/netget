//! DNS-over-HTTPS (DoH) client protocol actions implementation

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

/// DoH client connected event
pub static DOH_CLIENT_CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "doh_connected",
        "DoH client successfully connected to DNS-over-HTTPS server",
        json!({"type": "query_dns", "domain": "example.com", "record_type": "A"}),
    )
    .with_parameters(vec![Parameter {
        name: "server_url".to_string(),
        type_hint: "string".to_string(),
        description: "DoH server URL (e.g., https://dns.google/dns-query)".to_string(),
        required: true,
    }])
});

/// DoH client response received event
pub static DOH_CLIENT_RESPONSE_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "doh_response_received",
        "DNS response received from DoH server",
        json!({"type": "query_dns", "domain": "mail.example.com", "record_type": "MX"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "query_id".to_string(),
            type_hint: "number".to_string(),
            description: "DNS query ID".to_string(),
            required: true,
        },
        Parameter {
            name: "domain".to_string(),
            type_hint: "string".to_string(),
            description: "Domain name queried".to_string(),
            required: true,
        },
        Parameter {
            name: "query_type".to_string(),
            type_hint: "string".to_string(),
            description: "DNS record type (A, AAAA, MX, etc.)".to_string(),
            required: true,
        },
        Parameter {
            name: "answers".to_string(),
            type_hint: "array".to_string(),
            description: "Array of DNS answers".to_string(),
            required: true,
        },
        Parameter {
            name: "status".to_string(),
            type_hint: "string".to_string(),
            description: "Response status (NoError, NXDomain, etc.)".to_string(),
            required: true,
        },
    ])
});

/// DoH client protocol action handler
pub struct DohClientProtocol;

impl DohClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for DohClientProtocol {
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "ca_cert_pem".to_string(),
                description: "PEM-encoded certificate to trust in addition to the system \
                              roots. Use this to reach a DoH server presenting a private-CA \
                              or self-signed certificate -- including NetGet's own DoH \
                              server, which serves a self-signed cert by default."
                    .to_string(),
                type_hint: "string".to_string(),
                required: false,
                example: json!("-----BEGIN CERTIFICATE-----\n..."),
                default: None,
            },
            ParameterDefinition {
                name: "insecure_skip_verify".to_string(),
                description: "Disable certificate verification entirely. Off by default, \
                              and deliberately named for what it does: it accepts ANY \
                              certificate, so a DoH connection made with it is not \
                              authenticated and offers no protection against interception. \
                              Prefer `ca_cert_pem`, which trusts one certificate rather \
                              than all of them."
                    .to_string(),
                type_hint: "boolean".to_string(),
                required: false,
                example: json!(false),
                default: None,
            },
        ]
    }

    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![
            ActionDefinition {
                name: "query_dns".to_string(),
                description: "Make a DNS query over HTTPS".to_string(),
                parameters: vec![
                    Parameter {
                        name: "domain".to_string(),
                        type_hint: "string".to_string(),
                        description: "Domain name to query (e.g., example.com)".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "record_type".to_string(),
                        type_hint: "string".to_string(),
                        description:
                            "DNS record type: A, AAAA, MX, TXT, CNAME, NS, SOA, PTR, SRV, etc."
                                .to_string(),
                        required: false,
                    },
                    Parameter {
                        name: "use_get".to_string(),
                        type_hint: "boolean".to_string(),
                        description: "Use HTTP GET method instead of POST (default: false)"
                            .to_string(),
                        required: false,
                    },
                ],
                example: json!({
                    "type": "query_dns",
                    "domain": "example.com",
                    "record_type": "A",
                    "use_get": false
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "disconnect".to_string(),
                description: "Disconnect from the DoH server".to_string(),
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
                name: "query_dns".to_string(),
                description: "Make another DNS query in response to received data".to_string(),
                parameters: vec![
                    Parameter {
                        name: "domain".to_string(),
                        type_hint: "string".to_string(),
                        description: "Domain name to query".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "record_type".to_string(),
                        type_hint: "string".to_string(),
                        description: "DNS record type (A, AAAA, MX, etc.)".to_string(),
                        required: false,
                    },
                ],
                example: json!({
                    "type": "query_dns",
                    "domain": "mail.example.com",
                    "record_type": "A"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "wait_for_more".to_string(),
                description: "Wait for user to trigger more queries".to_string(),
                parameters: vec![],
                example: json!({
                    "type": "wait_for_more"
                }),
                log_template: None,
            },
        ]
    }
    fn protocol_name(&self) -> &'static str {
        "DNS-over-HTTPS"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            EventType::new(
                "doh_connected",
                "Triggered when DoH client connects to server",
                json!({"type": "placeholder", "event_id": "doh_connected"}),
            ),
            EventType::new(
                "doh_response_received",
                "Triggered when DoH client receives a DNS response",
                json!({"type": "placeholder", "event_id": "doh_response_received"}),
            ),
        ]
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>TLS>HTTP/2>DNS"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "doh",
            "dns-over-https",
            "doh client",
            "dns client",
            "secure dns",
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .implementation("hickory-client with DNS-over-HTTPS support")
            .llm_control("Full control over DNS queries with LLM-driven decision making")
            .e2e_testing("Public DoH servers (Google, Cloudflare)")
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "DNS-over-HTTPS (DoH) client for secure DNS resolution over HTTPS (RFC 8484)"
    }
    fn example_prompt(&self) -> &'static str {
        "Connect to Google DoH at https://dns.google/dns-query and resolve example.com"
    }
    fn group_name(&self) -> &'static str {
        "DNS"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        use serde_json::json;

        StartupExamples::new(
            // LLM mode: LLM controls DNS queries over HTTPS
            json!({
                "type": "open_client",
                "remote_addr": "dns.google:443",
                "base_stack": "doh",
                "instruction": "Query example.com for all record types and summarize the DNS configuration"
            }),
            // Script mode: Code-based deterministic responses
            json!({
                "type": "open_client",
                "remote_addr": "dns.google:443",
                "base_stack": "doh",
                "event_handlers": [{
                    "event_pattern": "doh_response_received",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "<doh_client_handler>"
                    }
                }]
            }),
            // Static mode: Fixed DNS query on connect
            json!({
                "type": "open_client",
                "remote_addr": "dns.google:443",
                "base_stack": "doh",
                "event_handlers": [
                    {
                        "event_pattern": "doh_connected",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "query_dns",
                                "domain": "example.com",
                                "record_type": "A"
                            }]
                        }
                    },
                    {
                        "event_pattern": "doh_response_received",
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
impl Client for DohClientProtocol {
    fn connect(
        &self,
        ctx: crate::protocol::ConnectContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::client::doh::DohClient;
            DohClient::connect_with_llm_actions(
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
            "query_dns" => {
                let domain = action
                    .get("domain")
                    .and_then(|v| v.as_str())
                    .context("Missing 'domain' field")?
                    .to_string();

                let record_type = action
                    .get("record_type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("A")
                    .to_string();

                let use_get = action
                    .get("use_get")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);

                Ok(ClientActionResult::Custom {
                    name: "dns_query".to_string(),
                    data: json!({
                        "domain": domain,
                        "record_type": record_type,
                        "use_get": use_get,
                    }),
                })
            }
            "disconnect" => Ok(ClientActionResult::Disconnect),
            "wait_for_more" => Ok(ClientActionResult::WaitForMore),
            _ => Err(anyhow::anyhow!(
                "Unknown DoH client action: {}",
                action_type
            )),
        }
    }
}

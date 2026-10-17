//! DNS client protocol actions implementation

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

/// Most records one zone transfer may bring in before it is abandoned.
pub const MAX_TRANSFER_RECORDS: usize = 100_000;

/// How many of a transfer's records the model is shown, and the only ones kept; the rest
/// are counted.
pub const MAX_REPORTED_RECORDS: usize = 200;

/// Most bytes of DNS messages one zone transfer may bring in before it is abandoned. A record
/// can be nearly 64 KiB, so the record count alone does not bound what a server can send.
pub const MAX_TRANSFER_BYTES: usize = 64 * 1024 * 1024;

/// How long a zone transfer may take.
pub const TRANSFER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// A zone transfer finished.
pub static DNS_CLIENT_ZONE_TRANSFER_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "dns_zone_transfer_received",
        "A zone transfer finished. 'form' says what came back: \"full\" (the whole zone), \
         \"incremental\" (an IXFR difference: SOA old, deleted records, SOA new, added records, \
         per change), \"current\" (the SOA alone: the serial asked from is the latest), or \
         \"none\" (refused or empty; see response_code).",
        json!({"type": "placeholder", "event_id": "dns_zone_transfer_received"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "zone".to_string(),
            type_hint: "string".to_string(),
            description: "The zone transferred".to_string(),
            required: true,
        },
        Parameter {
            name: "transfer_type".to_string(),
            type_hint: "string".to_string(),
            description: "\"AXFR\" when the whole zone was asked for, \"IXFR\" when the \
                changes since a serial were; 'form' says what actually came back"
                .to_string(),
            required: true,
        },
        Parameter {
            name: "form".to_string(),
            type_hint: "string".to_string(),
            description: "full, incremental, current or none".to_string(),
            required: true,
        },
        Parameter {
            name: "serial".to_string(),
            type_hint: "number".to_string(),
            description: "The zone's current SOA serial".to_string(),
            required: false,
        },
        Parameter {
            name: "record_count".to_string(),
            type_hint: "number".to_string(),
            description: "Records received, SOAs included".to_string(),
            required: true,
        },
        Parameter {
            name: "messages".to_string(),
            type_hint: "number".to_string(),
            description: "DNS messages the transfer took".to_string(),
            required: true,
        },
        Parameter {
            name: "records".to_string(),
            type_hint: "array".to_string(),
            description: "The records, in transfer order; the first 200 when 'truncated'"
                .to_string(),
            required: true,
        },
        Parameter {
            name: "truncated".to_string(),
            type_hint: "boolean".to_string(),
            description: "More records arrived than are listed".to_string(),
            required: true,
        },
        Parameter {
            name: "response_code".to_string(),
            type_hint: "string".to_string(),
            description: "NOERROR, or the refusal (REFUSED, NOTAUTH, ...)".to_string(),
            required: true,
        },
    ])
});

/// DNS client connected event
pub static DNS_CLIENT_CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "dns_connected",
        "DNS client successfully connected to DNS server",
        serde_json::json!({
            "type": "send_dns_query",
            "domain": "example.com",
            "query_type": "A"
        }),
    )
    .with_parameters(vec![Parameter {
        name: "remote_addr".to_string(),
        type_hint: "string".to_string(),
        description: "DNS server address".to_string(),
        required: true,
    }])
});

/// DNS client response received event
pub static DNS_CLIENT_RESPONSE_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "dns_response_received",
        "DNS response received from server",
        json!({"type": "placeholder", "event_id": "dns_response_received"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "query_id".to_string(),
            type_hint: "number".to_string(),
            description: "DNS query transaction ID".to_string(),
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
            description: "DNS query type (A, AAAA, MX, etc.)".to_string(),
            required: true,
        },
        Parameter {
            name: "answers".to_string(),
            type_hint: "array".to_string(),
            description: "Array of answer records".to_string(),
            required: true,
        },
        Parameter {
            name: "response_code".to_string(),
            type_hint: "string".to_string(),
            description: "DNS response code (NOERROR, NXDOMAIN, SERVFAIL, etc.)".to_string(),
            required: true,
        },
        Parameter {
            name: "authority".to_string(),
            type_hint: "array".to_string(),
            description: "Authority records: the SOA of a negative answer, and with dnssec \
                its NSEC proof and their signatures"
                .to_string(),
            required: false,
        },
        Parameter {
            name: "authenticated_data".to_string(),
            type_hint: "boolean".to_string(),
            description: "The AD bit: a validating resolver vouches for the answer. An \
                authoritative server never sets it; this client does not validate."
                .to_string(),
            required: true,
        },
        Parameter {
            name: "truncated".to_string(),
            type_hint: "boolean".to_string(),
            description: "The TC bit: the answer did not fit UDP".to_string(),
            required: true,
        },
    ])
});

/// DNS client protocol action handler
pub struct DnsClientProtocol;

impl Default for DnsClientProtocol {
    fn default() -> Self {
        Self::new()
    }
}

impl DnsClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

fn dnssec_param() -> Parameter {
    Parameter {
        name: "dnssec".to_string(),
        type_hint: "boolean".to_string(),
        description: "Set the DO bit, asking for the RRSIG and NSEC records that sign the \
            answer (default: false). They are reported in answers and authority."
            .to_string(),
        required: false,
    }
}

fn zone_transfer_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_dns_zone_transfer".to_string(),
        description: "Transfer a zone from the server over TCP: the whole zone (AXFR), or with \
            'serial' only the changes since that serial (IXFR). The result arrives as \
            dns_zone_transfer_received."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "zone".to_string(),
                type_hint: "string".to_string(),
                description: "The zone, e.g. \"example.com.\"".to_string(),
                required: true,
            },
            Parameter {
                name: "serial".to_string(),
                type_hint: "number".to_string(),
                description: "Ask for IXFR from this SOA serial; omit for AXFR".to_string(),
                required: false,
            },
        ],
        example: json!({"type": "send_dns_zone_transfer", "zone": "example.com."}),
        log_template: Some(
            crate::protocol::log_template::LogTemplate::new()
                .with_info("DNS transfer {zone}")
                .with_debug("DNS send_dns_zone_transfer {zone} serial={serial}"),
        ),
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for DnsClientProtocol {
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![
            ActionDefinition {
                name: "send_dns_query".to_string(),
                description: "Send a DNS query to the server".to_string(),
                parameters: vec![
                    Parameter {
                        name: "domain".to_string(),
                        type_hint: "string".to_string(),
                        description: "Domain name to query (e.g., example.com)".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "query_type".to_string(),
                        type_hint: "string".to_string(),
                        description:
                            "DNS query type (A, AAAA, MX, TXT, CNAME, NS, SOA, PTR, SRV, etc.)"
                                .to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "recursion_desired".to_string(),
                        type_hint: "boolean".to_string(),
                        description: "Request recursive resolution (default: true)".to_string(),
                        required: false,
                    },
                    dnssec_param(),
                ],
                example: json!({
                    "type": "send_dns_query",
                    "domain": "example.com",
                    "query_type": "A",
                    "recursion_desired": true
                }),
                log_template: None,
            },
            zone_transfer_action(),
            ActionDefinition {
                name: "disconnect".to_string(),
                description: "Disconnect from the DNS server".to_string(),
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
                        name: "recursion_desired".to_string(),
                        type_hint: "boolean".to_string(),
                        description: "Request recursive resolution".to_string(),
                        required: false,
                    },
                    dnssec_param(),
                ],
                example: json!({
                    "type": "send_dns_query",
                    "domain": "mail.example.com",
                    "query_type": "A"
                }),
                log_template: None,
            },
            zone_transfer_action(),
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
        "DNS"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            EventType::new(
                "dns_connected",
                "Triggered when DNS client connects to server",
                json!({"type": "placeholder", "event_id": "dns_connected"}),
            ),
            EventType::new(
                "dns_response_received",
                "Triggered when DNS client receives a response",
                json!({"type": "placeholder", "event_id": "dns_response_received"}),
            ),
            DNS_CLIENT_ZONE_TRANSFER_EVENT.clone(),
        ]
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>UDP>DNS"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["dns", "dns client", "connect to dns", "domain name system"]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            // BETA, October 2026, on all four conditions of the client bar: (1) the peer is
            // ISC BIND's named, a third-party authoritative server, not NetGet's DNS server;
            // (2) the test fails, naming bind9, when named or dig is absent; (3) a real
            // session: a DO query answered with named's RRSIG, an AXFR of the signed zone, and
            // after an edit and a reload an IXFR difference; (4) the client acts on its
            // handler's answers, asserted from the server's side — dig reads the same zone and
            // named logs the AXFR and IXFR it served. Removing the DO bit fails the test.
            .state(DevelopmentState::Beta)
            .implementation(
                "hickory-client over UDP for queries (each message built by hand, so RD and the \
                 EDNS DO bit reach the wire); a TCP hickory-client per zone transfer",
            )
            .llm_control(
                "Queries (name, type, recursion, DNSSEC) and zone transfers (AXFR, or IXFR from a \
                 serial)",
            )
            .e2e_testing(
                "tests/client/dns/real_server_test.rs against ISC BIND named (bind9), \
                 unprivileged on loopback with a zone it signs inline: a DO query reports \
                 named's RRSIG (type covered, algorithm 13, signer); an AXFR reports the same \
                 record count dig reads, DNSKEY, NSEC and RRSIG included; after the zone is \
                 edited and named reloaded, an injected IXFR from the old serial reports the \
                 incremental form with the deleted record before the added one; named's log \
                 shows both transfers served. No skip: a missing named or dig fails the test.",
            )
            .notes(
                "The client reports DNSSEC records and the AD bit but does not validate \
                 signatures itself. A transfer stops past 100,000 records or 60 s, and the \
                 model is shown the first 200 records with the count. No TSIG.",
            )
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "DNS client for domain name resolution"
    }
    fn example_prompt(&self) -> &'static str {
        "Connect to DNS at 8.8.8.8:53 and query A records for example.com"
    }
    fn group_name(&self) -> &'static str {
        "DNS"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        use serde_json::json;

        StartupExamples::new(
            // LLM mode: LLM controls DNS client interactions
            json!({
                "type": "open_client",
                "remote_addr": "8.8.8.8:53",
                "base_stack": "dns",
                "instruction": "Query A record for example.com and report the IP addresses"
            }),
            // Script mode: Code-based deterministic responses
            json!({
                "type": "open_client",
                "remote_addr": "8.8.8.8:53",
                "base_stack": "dns",
                "event_handlers": [{
                    "event_pattern": "dns_response_received",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "<dns_client_handler>"
                    }
                }]
            }),
            // Static mode: Fixed responses
            json!({
                "type": "open_client",
                "remote_addr": "8.8.8.8:53",
                "base_stack": "dns",
                "event_handlers": [
                    {
                        "event_pattern": "dns_connected",
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
                        "event_pattern": "dns_response_received",
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
impl Client for DnsClientProtocol {
    fn connect(
        &self,
        ctx: crate::protocol::ConnectContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::client::dns::DnsClient;
            DnsClient::connect_with_llm_actions(
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

                let recursion_desired = action
                    .get("recursion_desired")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(true);
                let dnssec = match action.get("dnssec") {
                    None | Some(serde_json::Value::Null) => false,
                    Some(v) => v.as_bool().context("'dnssec' must be true or false")?,
                };

                // Return custom result with query data
                Ok(ClientActionResult::Custom {
                    name: "dns_query".to_string(),
                    data: json!({
                        "domain": domain,
                        "query_type": query_type,
                        "recursion_desired": recursion_desired,
                        "dnssec": dnssec,
                    }),
                })
            }
            "send_dns_zone_transfer" => {
                let zone = action
                    .get("zone")
                    .and_then(|v| v.as_str())
                    .context("Missing 'zone' field, e.g. \"example.com.\"")?
                    .to_string();
                let serial = match action.get("serial") {
                    None | Some(serde_json::Value::Null) => None,
                    Some(v) => Some(
                        v.as_u64()
                            .filter(|s| *s <= u64::from(u32::MAX))
                            .context("'serial' must be an SOA serial, 0 to 4294967295")?,
                    ),
                };
                Ok(ClientActionResult::Custom {
                    name: "dns_zone_transfer".to_string(),
                    data: json!({"zone": zone, "serial": serial}),
                })
            }
            "disconnect" => Ok(ClientActionResult::Disconnect),
            "wait_for_more" => Ok(ClientActionResult::WaitForMore),
            _ => Err(anyhow::anyhow!(
                "Unknown DNS client action: {}",
                action_type
            )),
        }
    }
}

//! DNS-over-TLS protocol actions implementation
//!
//! Reuses DNS actions since DoT is just DNS delivered over TLS.

use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::EventType;
use crate::server::dns::actions::DnsProtocol;
use crate::state::app_state::AppState;
use anyhow::Result;
use serde_json::json;
use std::sync::LazyLock;

/// Event type constant for DoT queries
/// Reuses DNS action definitions since DoT delegates to DnsProtocol
pub static DOT_QUERY_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    // The DNS actions that answer a query (not the zone-transfer ones: no transfer event here)
    let dns_actions = DnsProtocol::query_actions();

    EventType::new(
        "dot_query",
        "Client sent DNS query over TLS",
        json!({"type": "placeholder", "event_id": "dot_query"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "query_id".to_string(),
            type_hint: "number".to_string(),
            description: "DNS query ID from the request packet".to_string(),
            required: true,
        },
        Parameter {
            name: "domain".to_string(),
            type_hint: "string".to_string(),
            description: "Domain name being queried".to_string(),
            required: true,
        },
        Parameter {
            name: "query_type".to_string(),
            type_hint: "string".to_string(),
            description: "DNS query type (A, AAAA, MX, TXT, CNAME, etc.)".to_string(),
            required: true,
        },
        Parameter {
            name: "peer_addr".to_string(),
            type_hint: "string".to_string(),
            description: "Client IP address and port".to_string(),
            required: true,
        },
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("DoT {query_type} {domain}")
            .with_debug("DoT query from {peer_addr}: {query_type} {domain}")
            .with_trace("DoT: {json_pretty(.)}"),
    )
    .with_actions(dns_actions)
});

/// DoT protocol action handler
/// Delegates to DNS protocol for action execution since DoT is DNS over TLS
pub struct DotProtocol {
    dns_protocol: DnsProtocol,
}

impl DotProtocol {
    pub fn new() -> Self {
        Self {
            dns_protocol: DnsProtocol::new(),
        }
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for DotProtocol {
    fn get_startup_parameters(&self) -> Vec<crate::llm::actions::ParameterDefinition> {
        vec![crate::llm::actions::ParameterDefinition {
            name: "idle_timeout_secs".to_string(),
            type_hint: "number".to_string(),
            description: "Seconds an established DoT connection may wait for its next query \
                          before the server closes it (RFC 7858 §3.4 leaves this to the \
                          server). 1-3600; resolvers pin one connection and reuse it, so the \
                          default is generous. A query being answered never counts as idle."
                .to_string(),
            required: false,
            example: json!(300),
            default: Some(json!(super::IDLE_READ_TIMEOUT.as_secs())),
        }]
    }
    fn get_async_actions(&self, state: &AppState) -> Vec<ActionDefinition> {
        self.dns_protocol.get_async_actions(state)
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        DnsProtocol::query_actions()
    }
    fn protocol_name(&self) -> &'static str {
        "DoT"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![DOT_QUERY_EVENT.clone()]
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>TLS>DNS"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["dot", "dns-over-tls", "dns over tls"]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{
            DevelopmentState, PrivilegeRequirement, ProtocolMetadataV2,
        };

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Stable)
            // RFC 7858 assigns DoT to TCP/853, which is a privileged port.
            .privilege_requirement(PrivilegeRequirement::PrivilegedPort(853))
            .well_known_port(853)
            .implementation("hickory-proto + tokio-rustls; DNS actions and action execution are delegated to the DNS protocol")
            .llm_control("Same as DNS (delegates to DNS protocol)")
            .e2e_testing(
                "STABLE, November 2026, on the six conditions; see 'Maturity: the six conditions' in \
                 src/server/dot/AGENTS.md. (1) TWO independent resolvers, neither #[ignore]d and \
                 neither able to skip: tests/server/dot/real_client_test.rs drives kdig (Knot \
                 DNS, GnuTLS) and dig (ISC BIND 9.20, OpenSSL) through `+tls`. Each picks the \
                 transaction id, matches the reply against it, confirms the question and renders \
                 the answer: A for two names with two addresses, AAAA, MX (preference 4660, so a \
                 byte-swap is visible), TXT, CNAME and NXDOMAIN; dig runs with its defaults, \
                 EDNS and a COOKIE offered, and reads the OPT the server echoes. Verified by \
                 answering with a fixed transaction id: both discard the reply. (2) PCAP ORACLE: \
                 kdig's sessions cross a recording relay with SSLKEYLOGFILE; tshark decrypts \
                 them and must dissect DNS in the server's direction (dig writes no key log). \
                 (3) FUZZ: fuzz/fuzz_targets/dns_message.rs, dns_screen then Message::from_vec, \
                 the pair every query goes through, with a pointer-chain bomb in its corpus. \
                 (4) BOUNDS: tests/server/dot/bounds_test.rs and connection_bounds_test.rs, one \
                 test per bound at its boundary, each verified by removal. (6) No #[ignore] and \
                 no skip gate. UNPROVEN: certificate validation of any kind (self-signed, and \
                 neither client authenticates it), client auth, EDNS padding.",
            )
            .notes(
                "Self-signed certs only, no client auth. Answers through dns::StreamQuery, the DNS \
                 server's own answer rules: one message per query, SERVFAIL for a backend failure, \
                 an unparseable or oversize answer and an answer with nothing sendable, FORMERR \
                 for no question; a message that does not decode closes the connection. \
                 idle_timeout_secs (default 300) bounds the wait for the next query.",
            )
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "DNS-over-TLS server for secure domain resolution"
    }
    fn example_prompt(&self) -> &'static str {
        "DNS-over-TLS server on port 853 resolving all queries to 93.184.216.34"
    }
    fn group_name(&self) -> &'static str {
        "Core"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        StartupExamples::new(
            // LLM-driven example
            json!({
                "type": "open_server",
                "port": 853,
                "base_stack": "dot",
                "instruction": "DNS-over-TLS server resolving all A queries for example.com to 93.184.216.34, NXDOMAIN for others"
            }),
            // Script-based example
            json!({
                "type": "open_server",
                "port": 853,
                "base_stack": "dot",
                "event_handlers": [{
                    "event_pattern": "dot_query",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "# Echo the client's transaction ID and queried name\nif event.get('domain', '').rstrip('.') == 'example.com':\n    respond([{'type': 'send_dns_a_response', 'query_id': event['query_id'], 'domain': event['domain'], 'ip': '93.184.216.34', 'ttl': 300}])\nelse:\n    respond([{'type': 'send_dns_nxdomain', 'query_id': event['query_id'], 'domain': event['domain'], 'query_type': event.get('query_type', 'A')}])"
                    }
                }]
            }),
            // Static handler example: static actions are fixed JSON with no
            // access to the event, so they cannot echo the client's random
            // transaction ID or the queried name. Dropping queries is the only
            // thing static mode does correctly for DNS-over-TLS; use script
            // mode for deterministic answers.
            json!({
                "type": "open_server",
                "port": 853,
                "base_stack": "dot",
                "event_handlers": [{
                    "event_pattern": "dot_query",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "ignore_query"
                        }]
                    }
                }]
            }),
        )
    }
}

// Implement Server trait (server-specific functionality)
impl Server for DotProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::server::dot::DotServer;
            let idle = ctx
                .startup_params
                .as_ref()
                .map(|p| p.get_optional_u64("idle_timeout_secs"))
                .transpose()?
                .flatten()
                .unwrap_or(super::IDLE_READ_TIMEOUT.as_secs());
            if !(1..=super::MAX_IDLE_TIMEOUT_SECS).contains(&idle) {
                anyhow::bail!(
                    "idle_timeout_secs must be between 1 and {}, got {idle}",
                    super::MAX_IDLE_TIMEOUT_SECS
                );
            }
            // DotServer::spawn binds the listener before returning, so bind
            // failures surface here and the address it returns is the real
            // bound address (resolving port 0 to the OS-assigned port).
            DotServer::spawn(
                ctx.legacy_listen_addr(),
                ctx.llm_client,
                ctx.state,
                ctx.server_id,
                ctx.status_tx,
                std::time::Duration::from_secs(idle),
            )
            .await
        })
    }
    fn execute_action(&self, action: serde_json::Value) -> Result<ActionResult> {
        self.dns_protocol.execute_action(action)
    }
}

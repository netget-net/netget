//! DNS-over-HTTPS protocol actions implementation
//!
//! Reuses DNS actions since DoH is just DNS delivered over HTTPS.

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

/// Event type constant for DoH queries
/// Reuses DNS action definitions since DoH delegates to DnsProtocol
pub static DOH_QUERY_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    // The DNS actions that answer a query (not the zone-transfer ones: no transfer event here)
    let dns_actions = DnsProtocol::query_actions();

    EventType::new(
        "doh_query",
        "Client sent DNS query over HTTPS",
        json!({"type": "placeholder", "event_id": "doh_query"}),
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
        Parameter {
            name: "method".to_string(),
            type_hint: "string".to_string(),
            description: "HTTP method used (GET or POST)".to_string(),
            required: true,
        },
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("DoH {query_type} {domain} via {method}")
            .with_debug("DoH query from {peer_addr}: {query_type} {domain} via {method}")
            .with_trace("DoH: {json_pretty(.)}"),
    )
    .with_actions(dns_actions)
});

/// DoH protocol action handler
/// Delegates to DNS protocol for action execution since DoH is DNS over HTTPS
pub struct DohProtocol {
    dns_protocol: DnsProtocol,
}

impl DohProtocol {
    pub fn new() -> Self {
        Self {
            dns_protocol: DnsProtocol::new(),
        }
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for DohProtocol {
    fn get_startup_parameters(&self) -> Vec<crate::llm::actions::ParameterDefinition> {
        vec![crate::llm::actions::ParameterDefinition {
            name: "idle_timeout_secs".to_string(),
            type_hint: "number".to_string(),
            description: "Seconds an established DoH connection may carry no query before the \
                          server sends GOAWAY and closes it. Default 300, above the 90 seconds \
                          reqwest keeps an idle pooled connection. A query still being \
                          answered never counts as idle."
                .to_string(),
            required: false,
            example: json!(300),
            default: Some(serde_json::json!(
                super::IDLE_BETWEEN_QUERIES_TIMEOUT.as_secs()
            )),
        }]
    }
    fn get_async_actions(&self, state: &AppState) -> Vec<ActionDefinition> {
        self.dns_protocol.get_async_actions(state)
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        DnsProtocol::query_actions()
    }
    fn protocol_name(&self) -> &'static str {
        "DoH"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![DOH_QUERY_EVENT.clone()]
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>TLS>HTTP2>DNS"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["doh", "dns-over-https", "dns over https"]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{
            DevelopmentState, PrivilegeRequirement, ProtocolMetadataV2,
        };

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Beta)
            // DoH is normally served on TCP/443, which is a privileged port.
            .privilege_requirement(PrivilegeRequirement::PrivilegedPort(443))
            .well_known_port(443)
            .implementation("hickory-proto + hyper + tokio-rustls; DNS actions and action execution are delegated to the DNS protocol")
            .llm_control("Same as DNS (delegates to DNS protocol)")
            .e2e_testing(
                "TWO independent peers, neither #[ignore]d and neither able to skip. \
                 (1) tests/server/doh/real_client_test.rs drives the real kdig binary (Knot DNS \
                 3.6, a C implementation sharing no code with this tree) through BOTH RFC 8484 \
                 encodings it chose for itself -- `+https` POSTing application/dns-message and \
                 `+https-get` sending GET ?dns=<base64url>. kdig is a resolver, not a decoder: \
                 it picks the transaction id, matches the reply against it, confirms the \
                 question section and renders the answer through its own presentation writer. \
                 Two queries for different names with different addresses, so a reply bound to \
                 the wrong question is visible. The test FAILS, naming `brew install knot`, \
                 when kdig is absent. \
                 (2) tests/server/doh/e2e_test.rs: reqwest (hyper + rustls) is an independent \
                 HTTP/2 and TLS implementation and exercises both encodings, the latter sent \
                 with mixed case and a charset parameter. It asserts the 200 status, the \
                 Content-Type, that the transaction id and question are echoed, and the address \
                 by value. \
                 THAT SECOND TEST WAS HALF CIRCULAR AND IS NO LONGER THE WHOLE RATING. reqwest \
                 proves an HTTP server answers, not that the DNS on top is right, and the DNS \
                 message is decoded with hickory-proto -- the codec this server encodes with. \
                 ALPN was also unproven, because that client connects with \
                 http2_prior_knowledge() and skips ALPN entirely; kdig negotiates it, and \
                 changing the advertised protocol from h2 to http/1.1 now fails the test with \
                 kdig's own TLS alert. Verified the same way for the transaction id: answering \
                 with a fixed id instead of the client's fails the test. \
                 UNPROVEN: certificate validation of any kind. The certificate is self-signed, \
                 and kdig is run with a path-only authority so it keeps the opportunistic \
                 profile -- naming an authority makes it verify, and an IP literal there is \
                 rejected as SNI by rustls outright.",
            )
            .notes("GET/POST, HTTP/2 only (no HTTP/1.1), self-signed certs, any request path accepted. Advertises ALPN h2 - without it a negotiating client falls back to HTTP/1.1, which this server does not speak")
            .max_inbound_bytes(crate::server::doh::MAX_DOH_BODY_BYTES as usize)
            .request_only("DNS over HTTPS only answers queries; a server cannot send a peer anything unprompted")
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "DNS-over-HTTPS server for secure domain resolution"
    }
    fn example_prompt(&self) -> &'static str {
        "DNS-over-HTTPS server on port 443 resolving all queries to 93.184.216.34"
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
                "port": 443,
                "base_stack": "doh",
                "instruction": "DNS-over-HTTPS server resolving all A queries for example.com to 93.184.216.34, NXDOMAIN for others"
            }),
            // Script-based example
            json!({
                "type": "open_server",
                "port": 443,
                "base_stack": "doh",
                "event_handlers": [{
                    "event_pattern": "doh_query",
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
            // thing static mode does correctly for DNS-over-HTTPS; use script
            // mode for deterministic answers.
            json!({
                "type": "open_server",
                "port": 443,
                "base_stack": "doh",
                "event_handlers": [{
                    "event_pattern": "doh_query",
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
impl Server for DohProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::server::doh::DohServer;
            // DohServer::spawn binds the listener before returning, so bind
            // failures surface here and the address it returns is the real
            // bound address (resolving port 0 to the OS-assigned port).
            // The idle bound is the operator's to tune; the default is argued beside
            // IDLE_BETWEEN_QUERIES_TIMEOUT in mod.rs.
            let idle_timeout = ctx
                .startup_params
                .as_ref()
                .map(|p| p.get_optional_u64("idle_timeout_secs"))
                .transpose()?
                .flatten()
                .map(std::time::Duration::from_secs)
                .unwrap_or(crate::server::doh::IDLE_BETWEEN_QUERIES_TIMEOUT);
            DohServer::spawn(
                ctx.legacy_listen_addr(),
                ctx.llm_client,
                ctx.state,
                ctx.server_id,
                ctx.status_tx,
                idle_timeout,
            )
            .await
        })
    }
    fn execute_action(&self, action: serde_json::Value) -> Result<ActionResult> {
        self.dns_protocol.execute_action(action)
    }
}

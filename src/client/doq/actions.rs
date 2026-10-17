//! DoQ uses the existing typed DNS query vocabulary and its own transport events.
use crate::client::dns::actions::{
    DnsClientProtocol, DNS_CLIENT_CONNECTED_EVENT, DNS_CLIENT_RESPONSE_RECEIVED_EVENT,
};
use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, Parameter, ParameterDefinition, StartupExamples,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::{ConnectContext, EventType};
use crate::server::doq::wire::*;
use crate::state::AppState;
use anyhow::Result;
use serde_json::{json, Value};
use std::sync::LazyLock;

// Reuse the DNS action vocabulary, with descriptions and logs for the DoQ transport.
fn doq_actions(mut actions: Vec<ActionDefinition>) -> Vec<ActionDefinition> {
    for action in &mut actions {
        match action.name.as_str() {
            "send_dns_query" => {
                if let Some(parameter) = action
                    .parameters
                    .iter_mut()
                    .find(|parameter| parameter.name == "query_type")
                {
                    parameter.description = "DNS record type to query, such as A, AAAA, MX or TXT. AXFR and IXFR are not supported.".into();
                }
                action.log_template = Some(
                    LogTemplate::new()
                        .with_info("-> DoQ {domain} {query_type}")
                        .with_debug("DoQ send_dns_query: {domain} {query_type} recursion_desired={recursion_desired}"),
                );
            }
            "disconnect" => {
                action.log_template = Some(LogTemplate::new().with_info("-> DoQ disconnect"));
            }
            "wait_for_more" => {
                action.log_template = Some(LogTemplate::new().with_info("DoQ wait for more data"));
            }
            _ => {}
        }
    }
    actions
}

pub static DOQ_CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "doq_connected",
        "Authenticated DoQ connection established",
        json!({"type":"send_dns_query","domain":"example.com","query_type":"A"}),
    )
    .with_parameters(DNS_CLIENT_CONNECTED_EVENT.parameters.clone())
    .with_actions(DoqClientProtocol::new().get_sync_actions())
});
pub static DOQ_RESPONSE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "doq_response_received",
        "Complete DNS response on a QUIC query stream",
        json!({"type":"wait_for_more"}),
    )
    .with_parameters(DNS_CLIENT_RESPONSE_RECEIVED_EVENT.parameters.clone())
    .with_actions(DoqClientProtocol::new().get_sync_actions())
});
pub static DOQ_ERROR_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "doq_query_error",
        "A DoQ transaction failed or timed out",
        json!({"type":"wait_for_more"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "domain".into(),
            type_hint: "string".into(),
            description: "The DNS name that could not be queried, such as example.com.".into(),
            required: true,
        },
        Parameter {
            name: "query_type".into(),
            type_hint: "string".into(),
            description: "Queried DNS record type".into(),
            required: true,
        },
        Parameter {
            name: "error".into(),
            type_hint: "string".into(),
            description: "Local query failure description".into(),
            required: true,
        },
    ])
    .with_actions(DoqClientProtocol::new().get_sync_actions())
});

#[derive(Default)]
pub struct DoqClientProtocol;
impl DoqClientProtocol {
    pub fn new() -> Self {
        Self
    }
}
impl Protocol for DoqClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "DoQ"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>UDP>QUIC>DNS"
    }
    fn description(&self) -> &'static str {
        "DNS over QUIC client with certificate validation and reusable concurrent query streams"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["doq", "dns-over-quic", "dns over quic"]
    }
    fn group_name(&self) -> &'static str {
        "DNS"
    }
    fn example_prompt(&self) -> &'static str {
        "Connect to dns.example:853 over DoQ and query the AAAA records for example.com"
    }
    fn get_async_actions(&self, state: &AppState) -> Vec<ActionDefinition> {
        doq_actions(DnsClientProtocol::new().get_async_actions(state))
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        doq_actions(DnsClientProtocol::new().get_sync_actions())
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            DOQ_CONNECTED_EVENT.clone(),
            DOQ_RESPONSE_EVENT.clone(),
            DOQ_ERROR_EVENT.clone(),
        ]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            parameter(
                "server_name",
                "TLS authentication name and SNI; defaults to the address hostname",
                json!("dns.example"),
                None,
            ),
            parameter(
                "ca_cert_path",
                "Additional trusted PEM CA or self-signed server certificate",
                json!("ca.pem"),
                None,
            ),
            parameter(
                "handshake_timeout_secs",
                "Resolution and TLS handshake deadline, 1..60 seconds",
                json!(10),
                Some(json!(HANDSHAKE_TIMEOUT.as_secs())),
            ),
            parameter(
                "exchange_timeout_secs",
                "Whole stream query/response deadline, 1..300 seconds",
                json!(30),
                Some(json!(EXCHANGE_TIMEOUT.as_secs())),
            ),
            parameter(
                "idle_timeout_secs",
                "QUIC idle timeout, 1..3600 seconds",
                json!(300),
                Some(json!(IDLE_TIMEOUT.as_secs())),
            ),
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};
        ProtocolMetadataV2::builder().state(DevelopmentState::Experimental)
            .implementation("quinn/rustls with hickory-proto DNS messages; public roots plus optional PEM trust")
            .llm_control("Typed DNS queries, response/error events, bounded follow-up actions and disconnect")
            .e2e_testing("Loopback TLS/framing, injected commands, event follow-ups, cancellation and shutdown; independent-server evidence recorded in tests/client/doq/AGENTS.md")
            .notes("Certificate and hostname validation always enabled. Single-question ordinary queries only; no AXFR/IXFR, automatic reconnect, 0-RTT or transport fallback. Maximum 32 active exchanges and four queries per automatic action chain.")
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn get_startup_examples(&self) -> StartupExamples {
        StartupExamples::new(
            json!({"type":"open_client","protocol":"doq","remote_addr":"dns.example:853","instruction":"Query A records for example.com"}),
            json!({"type":"open_client","protocol":"doq","remote_addr":"dns.example:853","event_handlers":[{"event_pattern":"doq_connected","handler":{"type":"script","language":"python","code":"import json,sys\nevent=json.load(sys.stdin)['event']\ndef respond(actions):\n    print(json.dumps({'actions':actions}))\nrespond([{'type':'send_dns_query','domain':'example.com','query_type':'A'}])"}}]}),
            json!({"type":"open_client","protocol":"doq","remote_addr":"dns.example:853","event_handlers":[{"event_pattern":"doq_connected","handler":{"type":"static","actions":[{"type":"send_dns_query","domain":"example.com","query_type":"A"}]}},{"event_pattern":"doq_response_received","handler":{"type":"static","actions":[{"type":"disconnect"}]}}]}),
        )
    }
}
impl Client for DoqClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::DoqClient::connect(ctx))
    }
    fn execute_action(&self, action: Value) -> Result<ClientActionResult> {
        let result = DnsClientProtocol::new().execute_action(action)?;
        if let ClientActionResult::Custom { name, data } = &result {
            if name == "dns_query" {
                super::build_query(data)?;
            }
        }
        Ok(result)
    }
}

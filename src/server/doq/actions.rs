//! Structured DNS response actions, delegated to the existing DNS codec.
use super::wire::*;
use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, ParameterDefinition, StartupExamples,
};
use crate::protocol::{EventType, SpawnContext};
use crate::server::dns::actions::DnsProtocol;
use crate::state::AppState;
use anyhow::{bail, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

pub static DOQ_QUERY_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "doq_query",
        "DNS query on a dedicated QUIC stream",
        json!({"type":"send_dns_a_response","domain":"example.com","ip":"192.0.2.1","query_id":0}),
    )
    .with_parameters(vec![
        crate::llm::actions::Parameter {
            name: "domain".into(),
            type_hint: "string".into(),
            description: "Queried DNS name".into(),
            required: true,
        },
        crate::llm::actions::Parameter {
            name: "query_type".into(),
            type_hint: "string".into(),
            description: "DNS record type".into(),
            required: true,
        },
        crate::llm::actions::Parameter {
            name: "query_id".into(),
            type_hint: "number".into(),
            description: "Always zero on DoQ".into(),
            required: true,
        },
        crate::llm::actions::Parameter {
            name: "stream_id".into(),
            type_hint: "number".into(),
            description: "QUIC stream identifying this transaction".into(),
            required: true,
        },
        crate::llm::actions::Parameter {
            name: "peer_addr".into(),
            type_hint: "string".into(),
            description: "Remote IP and UDP port".into(),
            required: true,
        },
    ])
    .with_actions(DoqProtocol::new().get_sync_actions())
});

#[derive(Default)]
pub struct DoqProtocol;
impl DoqProtocol {
    pub fn new() -> Self {
        Self
    }
}
impl Protocol for DoqProtocol {
    fn protocol_name(&self) -> &'static str {
        "DoQ"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>UDP>QUIC>DNS"
    }
    fn description(&self) -> &'static str {
        "DNS over QUIC (RFC 9250), with independent query streams and authenticated TLS"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["doq", "dns-over-quic", "dns over quic"]
    }
    fn group_name(&self) -> &'static str {
        "DNS"
    }
    fn example_prompt(&self) -> &'static str {
        "Serve DNS over QUIC on UDP 8853, answering example.com with 192.0.2.1"
    }
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        DnsProtocol::query_actions()
            .into_iter()
            .filter(|a| a.name != "send_dns_response")
            .collect()
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![DOQ_QUERY_EVENT.clone()]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            parameter(
                "cert_path",
                "PEM certificate chain; requires key_path",
                json!("server.pem"),
                None,
            ),
            parameter(
                "key_path",
                "PEM private key; requires cert_path",
                json!("server-key.pem"),
                None,
            ),
            parameter(
                "handshake_timeout_secs",
                "QUIC handshake deadline, 1..60 seconds",
                json!(10),
                Some(json!(HANDSHAKE_TIMEOUT.as_secs())),
            ),
            parameter(
                "exchange_timeout_secs",
                "Deadline for a query to arrive whole (FIN included) and be answered, 1..300 seconds: past it a query still arriving has its stream reset with DOQ_UNSPECIFIED_ERROR and one being answered gets SERVFAIL",
                json!(30),
                Some(json!(EXCHANGE_TIMEOUT.as_secs())),
            ),
            parameter(
                "idle_timeout_secs",
                "QUIC idle timeout (the effective one is the lower of the two endpoints'), 1..3600 seconds",
                json!(300),
                Some(json!(IDLE_TIMEOUT.as_secs())),
            ),
            parameter(
                "max_connections",
                "Maximum simultaneous connections including handshakes, 1..256",
                json!(64),
                Some(json!(MAX_CONNECTIONS)),
            ),
            parameter(
                "max_streams",
                "Maximum query streams a connection may have open at once, granted as QUIC stream credit, 1..32",
                json!(32),
                Some(json!(MAX_STREAMS)),
            ),
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{
            DevelopmentState, PrivilegeRequirement, ProtocolMetadataV2,
        };
        ProtocolMetadataV2::builder().state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::PrivilegedPort(853)).well_known_udp_port(853)
            .max_inbound_bytes(super::wire::MAX_FRAME_BYTES)
            .implementation("quinn 0.11 and rustls 0.23 for QUIC; queries answered through the DNS server's own rules (dns::StreamQuery) on hickory-proto 0.26")
            .llm_control("The DNS server's query actions (A, AAAA, CNAME, MX, TXT, NXDOMAIN, REFUSED, any records, ignore_query) per QUIC query stream; no raw send_dns_response")
            .e2e_testing("Knot kdig +quic (libngtcp2, certificate and hostname verified) and AdGuard dnsproxy as a DoQ upstream client (quic-go + miekg/dns), both hard-failing when absent; loopback framing, every declared bound from both sides, answer outcomes and cleanup in tests/server/doq/")
            .notes("Single-question IN-class QUERY only (others FORMERR or NOTIMP without the model); no AXFR/IXFR, DNSSEC signing, recursive resolver, 0-RTT, EDNS padding (RFC 9250 section 5.4 asks for padding) or server-initiated messages. PEM certificate/key supported; generated localhost certificate otherwise. Experimental: no pcap oracle and no fuzz target of its own yet.")
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn get_startup_examples(&self) -> StartupExamples {
        StartupExamples::new(
            json!({"type":"open_server","base_stack":"doq","port":8853,"instruction":"Answer A queries for example.com with 192.0.2.1"}),
            json!({"type":"open_server","base_stack":"doq","port":8853,"event_handlers":[{"event_pattern":"doq_query","handler":{"type":"script","language":"python","code":"import json,sys\nevent=json.load(sys.stdin)['event']\ndef respond(actions):\n    print(json.dumps({'actions':actions}))\nrespond([{'type':'send_dns_a_response','query_id':0,'domain':event['domain'],'ip':'192.0.2.1'}])"}}]}),
            json!({"type":"open_server","base_stack":"doq","port":8853,"event_handlers":[{"event_pattern":"doq_query","handler":{"type":"static","actions":[{"type":"ignore_query"}]}}]}),
        )
    }
}
impl Server for DoqProtocol {
    fn spawn(
        &self,
        ctx: SpawnContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::DoqServer::spawn(ctx))
    }
    fn execute_action(&self, mut action: Value) -> Result<ActionResult> {
        let name = action.get("type").and_then(Value::as_str).unwrap_or("");
        if !self.get_sync_actions().iter().any(|a| a.name == name) {
            bail!("Unknown DoQ action: {name}");
        }
        // The transport owns correlation. A model-supplied nonzero ID must never leak to DoQ.
        if let Some(obj) = action.as_object_mut() {
            obj.insert("query_id".into(), json!(0));
        }
        DnsProtocol::new().execute_action(action)
    }
}

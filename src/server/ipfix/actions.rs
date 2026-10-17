use super::codec::{
    DEFAULT_LLM_FALLBACK, DEFAULT_SESSION_IDLE, DEFAULT_TEMPLATE_TTL, MAX_MESSAGE_BYTES,
};
use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter, ParameterDefinition, StartupExamples,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::{
    metadata::{DevelopmentState, ProtocolMetadataV2},
    EventType, SpawnContext,
};
use crate::state::app_state::AppState;
use anyhow::{bail, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;
#[derive(Default)]
pub struct IpfixProtocol;
impl IpfixProtocol {
    pub fn new() -> Self {
        Self
    }
}
pub fn parameter(name: &str, type_hint: &str, description: &str, required: bool) -> Parameter {
    Parameter {
        name: name.into(),
        type_hint: type_hint.into(),
        description: description.into(),
        required,
    }
}
fn collect() -> ActionDefinition {
    ActionDefinition{name:"collect_ipfix_records".into(),description:"Observe validated typed IPFIX records in the bounded common access log. UDP has no acknowledgment; no persistence or aggregation.".into(),parameters:vec![],example:json!({"type":"collect_ipfix_records"}),log_template:Some(LogTemplate::new().with_info("Collect validated IPFIX records"))}
}
pub static IPFIX_MESSAGE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new("ipfix_message","One validated UDP IPFIX message. Ordered field values align with each set's template; unsupported IEs retain descriptors and null values without raw bytes. Sequence gaps are observations, not recovery.",collect().example).with_parameters(vec![parameter("message","object","Export time, domain, sequence/tracking, template changes, ignored UDP withdrawals, typed data sets, unknown-set descriptors and record count. Scope fields are the first scope_count ordered fields; duplicate IE occurrences preserve order.",true),parameter("source_addr","string","Exporter IP and UDP source port, scoped to this collector socket",true)]).with_actions(vec![collect()])
});
pub fn duration_parameter(name: &str, default: u64, description: &str) -> ParameterDefinition {
    ParameterDefinition {
        name: name.into(),
        type_hint: "number".into(),
        description: description.into(),
        required: false,
        example: json!(default),
        default: Some(json!(default)),
    }
}
impl Protocol for IpfixProtocol {
    fn protocol_name(&self) -> &'static str {
        "IPFIX"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>UDP>IPFIX"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["ipfix", "ipfix-udp"]
    }
    fn description(&self) -> &'static str {
        "Typed bounded UDP IPFIX templates, options and records; no model calls by default"
    }
    fn example_prompt(&self) -> &'static str {
        "Collect IPFIX records on UDP4739"
    }
    fn group_name(&self) -> &'static str {
        "Network Management"
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![collect()]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![IPFIX_MESSAGE_EVENT.clone()]
    }
    fn metadata(&self) -> ProtocolMetadataV2 {
        ProtocolMetadataV2::builder().deliberately_silent().state(DevelopmentState::Experimental).well_known_udp_port(4739).max_inbound_bytes(MAX_MESSAGE_BYTES).implementation("Native bounded RFC7011 UDP framing and transient template/sequence state; typed IANA subset, no protocol library dependency").llm_control("Ordered typed records through common handlers/shared memory; llm_fallback=false collects unmatched messages without model calls").e2e_testing("Independent pinned Python IPFIX0.9.7 exporter/decoder and official GoFlow2 2.2.7 collector; native pair, malformed/bounds, template/sequence/lifecycle checks").notes("Experimental UDP subset, not full RFC7011 compliance: no mandatory SCTP, TCP/TLS/DTLS, authentication, retransmission recovery, flow store, persistence or aggregation.8192byte messages,64sets,256records,32fields,1024byte scalar/string/unknown fields;128peer/domain sessions,32templates/session,1024global templates;32queued handler events. Configurable template TTL(default600s) and session idle(default1800s), each1..86400s. Unknown/enterprise values discarded with descriptors; unknown template sets counted but not buffered and sequence expectation becomes untracked. UDP withdrawals ignored; identical refresh extends TTL without a template-change report; redefinitions replace in wire order; malformed messages do not partially mutate template/sequence state. Sequence modulo2^32 counts data/options records; out-of-order/duplicate observations do not regress expected sequence. No ACK/error replies; failed handlers are logged and cannot roll back prior wire-state parsing. No fuzz/pcap/full information-model claim.").history(crate::protocol::metadata::HistoryMode::Off)
        .batching(crate::protocol::metadata::BatchingMode::Unsupported)
        .build()
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            duration_parameter(
                "template_ttl_seconds",
                DEFAULT_TEMPLATE_TTL,
                "Template lifetime since refresh,1..86400seconds; a wire cache only",
            ),
            duration_parameter(
                "session_idle_seconds",
                DEFAULT_SESSION_IDLE,
                "Peer/domain idle state expiry,1..86400seconds",
            ),
            ParameterDefinition {
                name: "llm_fallback".into(),
                type_hint: "boolean".into(),
                description:
                    "Opt unmatched messages into model calls; explicit handlers always run".into(),
                required: false,
                example: json!(true),
                default: Some(json!(DEFAULT_LLM_FALLBACK)),
            },
        ]
    }
    fn get_startup_examples(&self) -> StartupExamples {
        StartupExamples::new(
            json!({"type":"open_server","base_stack":"ipfix","port":4739,"startup_params":{"llm_fallback":true},"instruction":"Inspect flow records"}),
            json!({"type":"open_server","base_stack":"ipfix","port":4739,"event_handlers":[{"event_pattern":"ipfix_message","handler":{"type":"script","language":"python","code":"import json,sys\njson.load(sys.stdin)\nprint(json.dumps({'actions':[{'type':'collect_ipfix_records'}]}))"}}]}),
            json!({"type":"open_server","base_stack":"ipfix","port":4739,"event_handlers":[{"event_pattern":"ipfix_message","handler":{"type":"static","actions":[collect().example]}}]}),
        )
    }
}
impl Server for IpfixProtocol {
    fn spawn(
        &self,
        ctx: SpawnContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::IpfixServer::spawn(ctx))
    }
    fn execute_action(&self, action: Value) -> Result<ActionResult> {
        match action["type"].as_str() {
            Some("collect_ipfix_records") => Ok(ActionResult::NoAction),
            _ => bail!("unknown IPFIX collector action"),
        }
    }
}

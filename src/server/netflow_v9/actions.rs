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
pub struct NetflowV9Protocol;
impl NetflowV9Protocol {
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
    ActionDefinition{name:"collect_netflow_v9_records".into(),description:"Observe validated typed NETFLOW_V9 records in the bounded common access log. UDP has no acknowledgment; no persistence or aggregation.".into(),parameters:vec![],example:json!({"type":"collect_netflow_v9_records"}),log_template:Some(LogTemplate::new().with_info("NetFlow v9 records observed without acknowledgment"))}
}
pub static NETFLOW_V9_MESSAGE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new("netflow_v9_message","One validated UDP NETFLOW_V9 message. Ordered field values align with each set's template; unsupported v9 fields retain descriptors and null values without raw bytes. Sequence gaps are observations, not recovery.",collect().example).with_parameters(vec![parameter("message","object","Export time, domain, sequence/tracking, template changes, header total record Count/status, sysUpTime, typed data sets, unknown-set descriptors and record count. Scope fields are the first scope_count ordered fields; duplicate IE occurrences preserve order.",true),parameter("source_addr","string","Exporter IP and UDP source port, scoped to this collector socket",true)]).with_actions(vec![collect()])
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
impl Protocol for NetflowV9Protocol {
    fn protocol_name(&self) -> &'static str {
        "NetFlowV9"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>UDP>NetFlowV9"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["netflow-v9", "netflowv9", "netflow_v9"]
    }
    fn description(&self) -> &'static str {
        "Typed bounded UDP NetFlow v9 templates, options and records; no model calls by default"
    }
    fn example_prompt(&self) -> &'static str {
        "Collect NETFLOW_V9 records on UDP2055"
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
        vec![NETFLOW_V9_MESSAGE_EVENT.clone()]
    }
    fn metadata(&self) -> ProtocolMetadataV2 {
        ProtocolMetadataV2::builder().deliberately_silent().request_only("One-way UDP collector: no replies or unsolicited messages").state(DevelopmentState::Experimental).well_known_udp_port(2055).max_inbound_bytes(MAX_MESSAGE_BYTES)
        .implementation("Native RFC3954 version9 UDP header, normal/options templates, fixed typed fields and transient cache; no linked protocol dependency")
        .llm_control("Ordered typed records through common handlers/shared memory; llm_fallback=false observes unmatched datagrams without model calls")
        .e2e_testing("Literal header/count/scopes both directions; required unmodified softflowd1.1.1 upstream legacy exporter and actual GoFlow2 2.2.7 collector; atomic bounds, source/sequence, expiry, silent failures and owned cancellation")
        .notes("Experimental bounded UDP subset, not full RFC3954 compliance.20byte header Count includes all normal/options template and data/options records; sequence counts export packets modulo2^32 including template-only packets. Source-IP+Source-ID cache key intentionally ignores UDP port.8192bytes,64flowsets,32templates/message,256data records,32fields,1..1024byte fixed fields,minimum record4bytes to avoid ambiguous padding;128sessions,32templates/session,1024global templates,32queued events.35 selected RFC scalar fields plus5 unsigned options scopes; unsupported field values discarded as null with full16bit descriptors, no IPFIX enterprise bit or variable-length encoding. Unknown-template data not buffered; Count then marked unverifiable but packet tracking continues. Known-record Count mismatch and malformed packet fail atomically. Identical templates refresh TTL600s, differing templates replace in arrival order; idle1800s; both1..86400s. A backwards Unix export clock on an advancing packet clears candidate templates; lower uptime only flagged due wrap/restart/reordering ambiguity. No withdrawal format, ACK/error replies, authentication, TCP/SCTP/TLS, full vendor model, flow storage, aggregation, durability, delayed-data recovery, fuzz or capture claim. Common handler failure cannot undo committed wire parsing.").history(crate::protocol::metadata::HistoryMode::Off)
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
            json!({"type":"open_server","base_stack":"netflow_v9","port":2055,"startup_params":{"llm_fallback":true},"instruction":"Inspect flow records"}),
            json!({"type":"open_server","base_stack":"netflow_v9","port":2055,"event_handlers":[{"event_pattern":"netflow_v9_message","handler":{"type":"script","language":"python","code":"import json,sys\njson.load(sys.stdin)\nprint(json.dumps({'actions':[{'type':'collect_netflow_v9_records'}]}))"}}]}),
            json!({"type":"open_server","base_stack":"netflow_v9","port":2055,"event_handlers":[{"event_pattern":"netflow_v9_message","handler":{"type":"static","actions":[collect().example]}}]}),
        )
    }
}
impl Server for NetflowV9Protocol {
    fn spawn(
        &self,
        ctx: SpawnContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::NetflowV9Server::spawn(ctx))
    }
    fn execute_action(&self, action: Value) -> Result<ActionResult> {
        match action["type"].as_str() {
            Some("collect_netflow_v9_records") => Ok(ActionResult::NoAction),
            _ => bail!("unknown NETFLOW_V9 collector action"),
        }
    }
}

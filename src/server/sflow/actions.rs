use super::codec::{DEFAULT_LLM_FALLBACK, DEFAULT_SESSION_IDLE, MAX_MESSAGE_BYTES};
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
pub struct SflowProtocol;
impl SflowProtocol {
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
    ActionDefinition { name:"collect_sflow_samples".into(),
        description:"Observe typed sFlow samples through the bounded common access log. UDP is silent; no protocol flow store, persistence or aggregation.".into(),
        parameters:vec![],example:json!({"type":"collect_sflow_samples"}),log_template:Some(LogTemplate::new().with_info("sFlow samples collected; UDP remains silent")) }
}
pub static SFLOW_MESSAGE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new("sflow_message","A validated sFlow v5 UDP datagram. Selected flow/counter records are typed; header payload and unsupported record bytes are discarded. Datagram sequence gaps and uptime decreases are observations, not reliable delivery/reboot identification.",collect().example)
        .with_parameters(vec![parameter("message","object","Agent address,sub-agent,datagram sequence,uptime,compact/expanded samples,selected typed records,unknown enterprise/format/byte counts and bounded sequence diagnostics",true),
            parameter("source_addr","string","UDP exporter IP and port, scoped to this collector",true)])
        .with_actions(vec![collect()])
});
impl Protocol for SflowProtocol {
    fn protocol_name(&self) -> &'static str {
        "sFlow"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>UDP>SFLOW"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["sflow", "sflow-v5"]
    }
    fn description(&self) -> &'static str {
        "Typed bounded sFlow v5 UDP flow/counter collector; no model calls by default"
    }
    fn example_prompt(&self) -> &'static str {
        "Collect sFlow samples on UDP6343"
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
        vec![SFLOW_MESSAGE_EVENT.clone()]
    }
    fn metadata(&self) -> ProtocolMetadataV2 {
        ProtocolMetadataV2::builder().deliberately_silent().state(DevelopmentState::Experimental)
            .well_known_udp_port(6343).max_inbound_bytes(MAX_MESSAGE_BYTES)
            .implementation("Native bounded sFlow v5 XDR collector; compact/expanded flow/counter samples, typed selected records and transient sequence diagnostics")
            .llm_control("Common event handlers/shared memory/access log; llm_fallback=false collects unmatched samples without a model call; all UDP outcomes are silent and decision-tagged")
            .e2e_testing("Pinned unmodified BSD Cistern public exporter/decoder with explicit known source-ID workaround; actual GoFlow2 collector, literal dual wire/typed golden, malformed/bounds/sequence/owned lifecycle checks")
            .notes("Experimental v5 telemetry subset, not a full sFlow collector/agent: no SNMP configuration, aggregation/domain store, persistence, authentication, ACK, reliable delivery, sampler or packet capture. Four sample formats; flow records1(header)/2(Ethernet)/3(IPv4)/4(IPv6)/1001(switch), counters1(interface)/2(Ethernet)/5(VLAN). Header summaries cover Ethernet/up to2VLANs,IPv4/IPv6,ports/TCP flags,up to8IPv6 extensions; truncated/unknown headers remain metadata-only and payloads never reach model data. No checksum/capture-integrity claim.8192bytes/datagram,32samples,64records/sample,256records,256headerbytes,4096unknownbytes,128sessions,32queued events+oneactive. Cache key exporterIP/port+declared agent+subagent;session_idle_seconds(default1800,1..86400) expires on ingest and owned1s tick. Datagram sequence modulo2^32; late/duplicate does not regress, loweruptime diagnostic does not prove reboot; expiry resets expectation. Caller-owned sample sequence per sFlow instance is passed through, not inferred per datasource. Failed handler actions do not roll back prior wire state/common actions. No fuzz/pcap/full compliance claim.")
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "session_idle_seconds".into(),
                type_hint: "number".into(),
                description:
                    "UDP exporter/agent/sub-agent diagnostic state idle timeout,1..86400seconds"
                        .into(),
                required: false,
                example: json!(DEFAULT_SESSION_IDLE),
                default: Some(json!(DEFAULT_SESSION_IDLE)),
            },
            ParameterDefinition {
                name: "llm_fallback".into(),
                type_hint: "boolean".into(),
                description:
                    "Enable unmatched model calls; explicit matching handlers always dispatch"
                        .into(),
                required: false,
                example: json!(true),
                default: Some(json!(DEFAULT_LLM_FALLBACK)),
            },
        ]
    }
    fn get_startup_examples(&self) -> StartupExamples {
        StartupExamples::new(
            json!({"type":"open_server","base_stack":"sflow","port":6343,"startup_params":{"llm_fallback":true},"instruction":"Review telemetry"}),
            json!({"type":"open_server","base_stack":"sflow","port":6343,"event_handlers":[{"event_pattern":"sflow_message","handler":{"type":"script","language":"python","code":"import json,sys\njson.load(sys.stdin)\nprint(json.dumps({'actions':[{'type':'collect_sflow_samples'}]}))"}}]}),
            json!({"type":"open_server","base_stack":"sflow","port":6343,"event_handlers":[{"event_pattern":"sflow_message","handler":{"type":"static","actions":[collect().example]}}]}),
        )
    }
}
impl Server for SflowProtocol {
    fn spawn(
        &self,
        ctx: SpawnContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::SflowServer::spawn(ctx))
    }
    fn execute_action(&self, action: Value) -> Result<ActionResult> {
        match action["type"].as_str() {
            Some("collect_sflow_samples") => Ok(ActionResult::NoAction),
            _ => bail!("unknown sFlow collector action"),
        }
    }
}

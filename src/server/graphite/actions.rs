use super::codec::{DEFAULT_LLM_FALLBACK, MAX_LINE_BYTES};
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
pub struct GraphiteProtocol;
impl GraphiteProtocol {
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
fn collect_action() -> ActionDefinition {
    ActionDefinition { name: "collect_graphite_batch".into(), description: "Observe validated Carbon metrics in the bounded access log. No time-series database, aggregation or acknowledgment.".into(), parameters: vec![], example: json!({"type":"collect_graphite_batch"}), log_template: Some(LogTemplate::new().with_info("Graphite Carbon batch observed")) }
}
pub static GRAPHITE_BATCH_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new("graphite_batch", "A bounded batch of complete Carbon plaintext lines. TCP read boundaries determine batching; sender action boundaries are not preserved. Unmatched events collect without model calls by default.", collect_action().example)
        .with_parameters(vec![parameter("metrics", "array", "Objects with path (UTF-8 string), value (finite number), timestamp (UNIX seconds). Incoming -1 timestamps resolve to receiver time.", true), parameter("record_count", "number", "Number of metrics", true), parameter("source_addr", "string", "TCP peer address", true)])
        .with_actions(vec![collect_action()])
});
impl Protocol for GraphiteProtocol {
    fn protocol_name(&self) -> &'static str {
        "Graphite"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>Graphite"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["graphite", "carbon"]
    }
    fn description(&self) -> &'static str {
        "Bounded Carbon plaintext TCP metric collector; no model calls by default"
    }
    fn example_prompt(&self) -> &'static str {
        "Collect Graphite Carbon plaintext metrics on TCP port 2003"
    }
    fn group_name(&self) -> &'static str {
        "Network Services"
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![collect_action()]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![GRAPHITE_BATCH_EVENT.clone()]
    }
    fn metadata(&self) -> ProtocolMetadataV2 {
        ProtocolMetadataV2::builder().request_only("Carbon plaintext collectors never send application replies or unsolicited peer messages").deliberately_silent().state(DevelopmentState::Experimental).well_known_port(2003)
            .max_inbound_bytes(MAX_LINE_BYTES)
            .request_only("Carbon plaintext is a one-way metric stream; the collector has no replies or unsolicited server messages")
            .implementation("Native bounded Carbon plaintext TCP codec, no added dependencies")
            .llm_control("Explicit handlers process bounded batches; llm_fallback=false collects unmatched batches without model calls")
            .e2e_testing("Structured codec, fragmented/coalesced stream and lifecycle tests; independent Graphyte and official Carbon peers")
            .notes("TCP only; 4096 bytes per line, 256 metrics per dispatch, 256 connections, 30s frame read deadline excluding handler time. No Pickle, UDP, Whisper storage, query API, TLS or authentication. Tags in metric paths pass through without interpretation.").history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![ParameterDefinition { name: "llm_fallback".into(), type_hint: "boolean".into(), description: "Opt unmatched metric batches into model reasoning. False collects without model calls. Configured static/script/manual/LLM handlers always run.".into(), required: false, example: json!(true), default: Some(json!(DEFAULT_LLM_FALLBACK)) }]
    }
    fn get_startup_examples(&self) -> StartupExamples {
        StartupExamples::new(
            json!({"type":"open_server","base_stack":"graphite","port":2003,"startup_params":{"llm_fallback":true},"instruction":"Summarize suspicious metric batches"}),
            json!({"type":"open_server","base_stack":"graphite","port":2003,"event_handlers":[{"event_pattern":"graphite_batch","handler":{"type":"script","language":"python","code":"import json,sys\njson.load(sys.stdin)\nprint(json.dumps({'actions':[{'type':'collect_graphite_batch'}]}))"}}]}),
            json!({"type":"open_server","base_stack":"graphite","port":2003,"event_handlers":[{"event_pattern":"graphite_batch","handler":{"type":"static","actions":[{"type":"collect_graphite_batch"}]}}]}),
        )
    }
}
impl Server for GraphiteProtocol {
    fn spawn(
        &self,
        ctx: SpawnContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::GraphiteServer::spawn(ctx))
    }
    fn execute_action(&self, action: Value) -> Result<ActionResult> {
        match action["type"].as_str() {
            Some("collect_graphite_batch") => Ok(ActionResult::NoAction),
            _ => bail!("unknown Graphite collector action"),
        }
    }
}

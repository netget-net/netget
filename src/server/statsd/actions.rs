use super::codec::{DEFAULT_DIALECT, DEFAULT_LLM_FALLBACK, MAX_DATAGRAM_BYTES};
use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter, ParameterDefinition, StartupExamples,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};
use crate::protocol::{EventType, SpawnContext};
use crate::state::app_state::AppState;
use anyhow::{bail, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

pub struct StatsdProtocol;
impl Default for StatsdProtocol {
    fn default() -> Self {
        Self::new()
    }
}
impl StatsdProtocol {
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
pub fn dialect_parameter() -> ParameterDefinition {
    ParameterDefinition { name: "dialect".into(), type_hint: "string".into(), description: "dogstatsd accepts StatsD metrics plus histogram/distribution, tags, events and service checks. statsd rejects these extensions.".into(), required: false, example: json!("statsd"), default: Some(json!(DEFAULT_DIALECT)) }
}
pub fn collect_action() -> ActionDefinition {
    ActionDefinition { name: "collect_statsd_batch".into(), description: "Observe this batch in the bounded access log. Does not aggregate, persist, or acknowledge metrics; UDP has no response.".into(), parameters: vec![], example: json!({"type":"collect_statsd_batch"}), log_template: Some(LogTemplate::new().with_info("StatsD batch observed")) }
}
pub static STATSD_BATCH_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new("statsd_batch", "One validated UDP datagram containing typed metric/event/service_check records. Defaults to access-log collection without model calls; explicit handlers always run.", json!({"type":"collect_statsd_batch"}))
        .with_parameters(vec![parameter("records", "array", "Typed records. Metric: kind, name, value (string preserving signed gauge delta), metric_type, optional sample_rate/tags. Event: kind, title, text and optional timestamp/hostname/aggregation_key/priority/source_type/alert_type/tags. Service check: kind, name, status (0..3), optional timestamp/hostname/tags/message.", true), parameter("source_addr", "string", "UDP sender address", true), parameter("dialect", "string", "statsd or dogstatsd", true), parameter("record_count", "number", "Number of records", true)])
        .with_actions(vec![collect_action()])
});
impl Protocol for StatsdProtocol {
    fn protocol_name(&self) -> &'static str {
        "StatsD"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>UDP>StatsD"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["statsd", "dogstatsd"]
    }
    fn description(&self) -> &'static str {
        "Bounded UDP StatsD and DogStatsD batch collector; no model calls by default"
    }
    fn example_prompt(&self) -> &'static str {
        "Collect StatsD and DogStatsD metrics on UDP port 8125"
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
        vec![STATSD_BATCH_EVENT.clone()]
    }
    fn metadata(&self) -> ProtocolMetadataV2 {
        ProtocolMetadataV2::builder().connectionless()
            // StatsD/DogStatsD is one-way UDP: no acknowledgment or negative response exists.
            .deliberately_silent().state(DevelopmentState::Experimental).well_known_udp_port(8125)
            .max_inbound_bytes(MAX_DATAGRAM_BYTES)
            .implementation("Native bounded UTF-8 UDP codec, no additional dependencies")
            .llm_control("Explicit handlers process entire batches; llm_fallback=false collects unmatched batches without model calls")
            .e2e_testing("Typed codec vectors and real UDP wire/lifecycle tests; see tests/server/statsd/AGENTS.md for independent implementation evidence")
            .notes("8 KiB / 256 records per datagram. No aggregation, persistence, replies, origin metadata or packed values. DogStatsD is the default dialect.")
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![dialect_parameter(), ParameterDefinition { name: "llm_fallback".into(), type_hint: "boolean".into(), description: "Opt unmatched batches into LLM reasoning. False records them without model calls. Configured script/static/manual/LLM handlers always run.".into(), required: false, example: json!(true), default: Some(json!(DEFAULT_LLM_FALLBACK)) }]
    }
    fn get_startup_examples(&self) -> StartupExamples {
        StartupExamples::new(
            json!({"type":"open_server","base_stack":"statsd","port":8125,"startup_params":{"llm_fallback":true},"instruction":"Summarize suspicious metric batches"}),
            json!({"type":"open_server","base_stack":"statsd","port":8125,"event_handlers":[{"event_pattern":"statsd_batch","handler":{"type":"script","language":"python","code":"import json, sys\nbatch = json.load(sys.stdin)\nprint(json.dumps({'actions': [{'type': 'collect_statsd_batch'}]}))"}}]}),
            json!({"type":"open_server","base_stack":"statsd","port":8125,"event_handlers":[{"event_pattern":"statsd_batch","handler":{"type":"static","actions":[{"type":"collect_statsd_batch"}]}}]}),
        )
    }
}
impl Server for StatsdProtocol {
    fn spawn(
        &self,
        ctx: SpawnContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::StatsdServer::spawn(ctx))
    }
    fn execute_action(&self, action: Value) -> Result<ActionResult> {
        match action["type"].as_str() {
            Some("collect_statsd_batch") => Ok(ActionResult::NoAction),
            _ => bail!("unknown StatsD server action"),
        }
    }
}

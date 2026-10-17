use super::codec::{DEFAULT_LLM_FALLBACK, MAX_FRAME_BYTES};
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
pub struct FluentForwardProtocol;
impl FluentForwardProtocol {
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
    ActionDefinition { name: "accept_forward_batch".into(), description: "Accept a validated Forward batch; send a native correlated ACK when requested. No persistent event store.".into(), parameters: vec![], example: json!({"type":"accept_forward_batch"}), log_template: Some(LogTemplate::new().with_info("Fluent Forward batch accepted")) }
}
fn reject_action() -> ActionDefinition {
    ActionDefinition {
        name: "reject_forward_batch".into(),
        description: "Reject this batch by closing the peer without ACK".into(),
        parameters: vec![],
        example: json!({"type":"reject_forward_batch"}),
        log_template: Some(
            LogTemplate::new().with_info("Fluent Forward batch rejected; close without ACK"),
        ),
    }
}
pub static FORWARD_BATCH_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new("forward_batch","A complete Message/Forward/PackedForward/gzip PackedForward batch. Each entry has typed timestamp seconds/optional nanoseconds and a JSON record. Opaque chunk IDs stay inside the transport.",collect_action().example)
 .with_parameters(vec![parameter("tag","string","Fluent event tag",true),parameter("entries","array","Timestamp/record entries",true),parameter("record_count","number","Number of records in this Forward batch",true),parameter("mode","string","message, forward, packed, compressed_packed",true),parameter("ack_requested","boolean","Peer requested correlated acceptance",true),parameter("source_addr","string","Remote IP and TCP port of the Forward emitter",true)])
 .with_actions(vec![collect_action(),reject_action()])
});
impl Protocol for FluentForwardProtocol {
    fn protocol_name(&self) -> &'static str {
        "FluentForward"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>FluentForward"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "fluent-forward",
            "fluent_forward",
            "fluentforward",
            "fluentd",
        ]
    }
    fn description(&self) -> &'static str {
        "Bounded Fluent Forward MessagePack collector with correlated ACKs; no model calls by default"
    }
    fn example_prompt(&self) -> &'static str {
        "Collect Fluent Forward events on TCP port 24224"
    }
    fn group_name(&self) -> &'static str {
        "Network Services"
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![collect_action(), reject_action()]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![FORWARD_BATCH_EVENT.clone()]
    }
    fn metadata(&self) -> ProtocolMetadataV2 {
        // Forward has no negative-ACK grammar; a failed handler closes without ACK.
        ProtocolMetadataV2::builder().request_only("Forward acceptance or rejection requires the current inbound batch; ACKs must echo its transport-owned chunk token, so unsolicited replies are not supported.").deliberately_silent().state(DevelopmentState::Experimental).well_known_port(24224)
            .max_inbound_bytes(MAX_FRAME_BYTES)
            .implementation("Native bounded MessagePack/EventTime and gzip PackedForward via flate2")
            .llm_control("Explicit handlers process bounded batches; llm_fallback=false collects unmatched batches without model calls")
            .e2e_testing("Four carrier modes, correlated ACK and bounds/lifecycle tests; independent fluent-logger and official Fluentd peers")
            .notes("256KiB frame/decompressed entries; 256 records, nesting depth 32, 16384 MessagePack values, tag 1024 bytes, 256 TCP peers, 30s absolute frame deadline. Typed JSON record values only. No secure-forward handshake, TLS, JSON convenience framing, UDP heartbeat, persistence, automatic retry or deduplication.").history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![ParameterDefinition { name: "llm_fallback".into(), type_hint: "boolean".into(), description: "Opt unmatched event batches into model reasoning. False collects without model calls. Configured static/script/manual/LLM handlers always run.".into(), required: false, example: json!(true), default: Some(json!(DEFAULT_LLM_FALLBACK)) }]
    }
    fn get_startup_examples(&self) -> StartupExamples {
        StartupExamples::new(
            json!({"type":"open_server","base_stack":"fluent-forward","port":24224,"startup_params":{"llm_fallback":true},"instruction":"Summarize suspicious event batches"}),
            json!({"type":"open_server","base_stack":"fluent-forward","port":24224,"event_handlers":[{"event_pattern":"forward_batch","handler":{"type":"script","language":"python","code":"import json,sys\njson.load(sys.stdin)\nprint(json.dumps({'actions':[{'type':'accept_forward_batch'}]}))"}}]}),
            json!({"type":"open_server","base_stack":"fluent-forward","port":24224,"event_handlers":[{"event_pattern":"forward_batch","handler":{"type":"static","actions":[{"type":"accept_forward_batch"}]}}]}),
        )
    }
}
impl Server for FluentForwardProtocol {
    fn spawn(
        &self,
        ctx: SpawnContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::FluentForwardServer::spawn(ctx))
    }
    fn execute_action(&self, action: Value) -> Result<ActionResult> {
        match action["type"].as_str() {
            Some("accept_forward_batch") => Ok(ActionResult::NoAction),
            Some("reject_forward_batch") => Ok(ActionResult::CloseConnection),
            _ => bail!("unknown FluentForward collector action"),
        }
    }
}

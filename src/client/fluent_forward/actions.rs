use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, StartupExamples,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::{
    metadata::{DevelopmentState, ProtocolMetadataV2},
    ConnectContext, EventType,
};
use crate::server::fluent_forward::{
    actions::parameter,
    codec::{self, Batch},
};
use crate::state::app_state::AppState;
use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

#[derive(Default)]
pub struct FluentForwardClientProtocol;
impl FluentForwardClientProtocol {
    pub fn new() -> Self {
        Self
    }
}
pub fn send_action() -> ActionDefinition {
    ActionDefinition {name:"send_forward_batch".into(),description:"Send a typed Fluent Forward batch. require_ack generates an internal chunk ID and raises forward_ack after correlated receipt. Send outcome confirms local write only. No automatic retry.".into(),parameters:vec![parameter("batch","object","tag; 1..256 entries each timestamp={seconds, optional nanoseconds<1e9}, record=JSON object; mode message(1 entry), forward(default), packed or compressed_packed; require_ack bool. 256KiB encoded/decompressed, depth32/value16384 limits.",true)],example:json!({"type":"send_forward_batch","batch":{"tag":"demo.logs","entries":[{"timestamp":{"seconds":1700000000,"nanoseconds":250000000},"record":{"message":"Started"}}],"mode":"forward","require_ack":true}}),log_template: Some(LogTemplate::new().with_info("-> Fluent Forward tag={batch.tag} entries={batch.entries_len} mode={batch.mode} require_ack={batch.require_ack}"))}
}
fn disconnect_action() -> ActionDefinition {
    ActionDefinition {
        name: "disconnect".into(),
        description: "Close the Forward TCP connection and remove its command handle".into(),
        parameters: vec![],
        example: json!({"type":"disconnect"}),
        log_template: Some(LogTemplate::new().with_info("-> Fluent Forward disconnect")),
    }
}
pub static FORWARD_CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "forward_connected",
        "TCP Forward transport ready; unauthenticated operation starts without greeting.",
        send_action().example,
    )
    .with_parameters(vec![
        parameter("remote_addr", "string", "Collector address", true),
        parameter("local_addr", "string", "Emitter address", true),
    ])
    .with_actions(vec![send_action(), disconnect_action()])
});
pub static FORWARD_ACK_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new("forward_ack","Collector sent a matching ACK for a pending batch. Correlation token stays inside the transport; receipt is not persistence.",send_action().example).with_parameters(vec![parameter("tag","string","Forward tag of the acknowledged batch",true),parameter("record_count","number","Accepted entries",true)]).with_actions(vec![send_action(),disconnect_action()])
});
impl Protocol for FluentForwardClientProtocol {
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
        "Emit typed Fluent Forward logs with optional correlated acknowledgments"
    }
    fn example_prompt(&self) -> &'static str {
        "Send a structured Fluent Forward log to localhost:24224"
    }
    fn group_name(&self) -> &'static str {
        "Network Services"
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        vec![send_action(), disconnect_action()]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![FORWARD_CONNECTED_EVENT.clone(), FORWARD_ACK_EVENT.clone()]
    }
    fn metadata(&self) -> ProtocolMetadataV2 {
        ProtocolMetadataV2::builder().state(DevelopmentState::Experimental).well_known_port(24224).implementation("Native bounded MessagePack/EventTime and gzip PackedForward encoder/ACK correlation").llm_control("Connected and correlated ACK events with standard memory, bounded follow-ups and live command injection").e2e_testing("Four event carriers against official Fluentd in_forward; independent fluent-logger emits to collector").notes("256KiB frame; 256 records; depth32/16384 values; 32 pending ACKs/events, 8 follow-up depth, 32 handler actions; 10s connect/write/ACK deadlines. No secure-forward handshake/TLS, UDP heartbeat, JSON framing, persistence or retry. ACK confirms handler acceptance, not durable delivery.").history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
        .batching(crate::protocol::metadata::BatchingMode::Unsupported)
        .build()
    }
    fn get_startup_examples(&self) -> StartupExamples {
        StartupExamples::new(
            json!({"type":"open_client","base_stack":"fluent-forward","remote_addr":"localhost:24224","instruction":"Send an informational startup log"}),
            json!({"type":"open_client","base_stack":"fluent-forward","remote_addr":"localhost:24224","event_handlers":[{"event_pattern":"forward_connected","handler":{"type":"script","language":"python","code":"import json,sys\njson.load(sys.stdin)\nprint(json.dumps({'actions':[{'type':'send_forward_batch','batch':{'tag':'demo.logs','entries':[{'timestamp':{'seconds':1700000000},'record':{'message':'Started'}}]}}]}))"}}]}),
            json!({"type":"open_client","base_stack":"fluent-forward","remote_addr":"localhost:24224","event_handlers":[{"event_pattern":"forward_connected","handler":{"type":"static","actions":[send_action().example]}}]}),
        )
    }
}
impl Client for FluentForwardClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::FluentForwardClient::connect(ctx))
    }
    fn execute_action(&self, action: Value) -> Result<ClientActionResult> {
        match action["type"].as_str() {
            Some("send_forward_batch") => {
                let batch: Batch =
                    serde_json::from_value(action.get("batch").context("missing batch")?.clone())?;
                codec::encode_batch(&batch, None)?;
                Ok(ClientActionResult::Custom {
                    name: "send_forward_batch".into(),
                    data: serde_json::to_value(batch)?,
                })
            }
            Some("disconnect") => Ok(ClientActionResult::Disconnect),
            _ => bail!("unknown FluentForward emitter action"),
        }
    }
}

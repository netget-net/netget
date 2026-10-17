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
use crate::server::graphite::{
    actions::parameter,
    codec::{self, Metric},
};
use crate::state::app_state::AppState;
use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

#[derive(Default)]
pub struct GraphiteClientProtocol;
impl GraphiteClientProtocol {
    pub fn new() -> Self {
        Self
    }
}
pub fn send_action() -> ActionDefinition {
    ActionDefinition { name: "send_graphite_batch".into(), description: "Send timestamped Carbon plaintext metrics over TCP. Validates the whole action before writing. A successful write confirms local transport acceptance, not collector persistence. No automatic retries.".into(), parameters: vec![parameter("metrics", "array", "1..256 objects with path (nonempty UTF-8 without whitespace/control), value (finite number), timestamp (nonnegative UNIX seconds, possibly fractional; -1 requests receiver time). Each encoded line <=4096 bytes; action <=64KiB. Semicolon tags are opaque parts of path.", true)], example: json!({"type":"send_graphite_batch","metrics":[{"path":"servers.demo.load","value":0.5,"timestamp":1700000000}]}), log_template: Some(LogTemplate::new().with_info("-> Graphite Carbon metrics={metrics_len}")) }
}
fn disconnect_action() -> ActionDefinition {
    ActionDefinition {
        name: "disconnect".into(),
        description: "Close the Carbon TCP connection and remove its command handle".into(),
        parameters: vec![],
        example: json!({"type":"disconnect"}),
        log_template: Some(LogTemplate::new().with_info("-> Graphite Carbon disconnect")),
    }
}
pub static GRAPHITE_CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new("graphite_connected", "TCP connection established; Carbon plaintext has no greeting or per-metric acknowledgments.", send_action().example)
        .with_parameters(vec![parameter("remote_addr", "string", "Collector address", true), parameter("local_addr", "string", "Emitter address", true)])
        .with_actions(vec![send_action(), disconnect_action()])
});
impl Protocol for GraphiteClientProtocol {
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
        "Emit structured timestamped Graphite Carbon plaintext metrics over TCP"
    }
    fn example_prompt(&self) -> &'static str {
        "Send a Graphite metric servers.demo.load with value 0.5 to localhost:2003"
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
        vec![GRAPHITE_CONNECTED_EVENT.clone()]
    }
    fn metadata(&self) -> ProtocolMetadataV2 {
        ProtocolMetadataV2::builder().state(DevelopmentState::Experimental).well_known_port(2003)
            .implementation("Native UTF-8 Carbon plaintext TCP encoder with bounded action batches")
            .llm_control("One connected event; structured metric batches also available via command injection")
            .e2e_testing("Exact wire, handler, rejection and lifecycle tests; official Carbon MetricLineReceiver interoperability")
            .notes("TCP only; no UDP, Pickle, TLS, authentication, storage/query API, acknowledgment or retry. 4096 bytes per line, 64KiB/256 metrics per action; 10s connect/write deadline.").history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn get_startup_examples(&self) -> StartupExamples {
        StartupExamples::new(
            json!({"type":"open_client","base_stack":"graphite","remote_addr":"localhost:2003","instruction":"Send servers.demo.load 0.5 at receiver time (-1)"}),
            json!({"type":"open_client","base_stack":"graphite","remote_addr":"localhost:2003","event_handlers":[{"event_pattern":"graphite_connected","handler":{"type":"script","language":"python","code":"import json,sys\njson.load(sys.stdin)\nprint(json.dumps({'actions':[{'type':'send_graphite_batch','metrics':[{'path':'servers.demo.load','value':0.5,'timestamp':-1}]}]}))"}}]}),
            json!({"type":"open_client","base_stack":"graphite","remote_addr":"localhost:2003","event_handlers":[{"event_pattern":"graphite_connected","handler":{"type":"static","actions":[send_action().example]}}]}),
        )
    }
}
impl Client for GraphiteClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::GraphiteClient::connect(ctx))
    }
    fn execute_action(&self, action: Value) -> Result<ClientActionResult> {
        match action["type"].as_str() {
            Some("send_graphite_batch") => {
                let metrics: Vec<Metric> = serde_json::from_value(
                    action.get("metrics").context("missing metrics")?.clone(),
                )
                .context("invalid structured metrics")?;
                codec::encode_batch(&metrics)?;
                Ok(ClientActionResult::Custom {
                    name: "send_graphite_batch".into(),
                    data: serde_json::to_value(metrics)?,
                })
            }
            Some("disconnect") => Ok(ClientActionResult::Disconnect),
            _ => bail!("unknown Graphite emitter action"),
        }
    }
}

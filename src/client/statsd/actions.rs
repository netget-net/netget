use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, ParameterDefinition, StartupExamples,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};
use crate::protocol::{ConnectContext, EventType};
use crate::server::statsd::{
    actions::{dialect_parameter, parameter},
    codec::{self, Dialect, Record},
};
use crate::state::app_state::AppState;
use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

pub struct StatsdClientProtocol;
impl Default for StatsdClientProtocol {
    fn default() -> Self {
        Self::new()
    }
}
impl StatsdClientProtocol {
    pub fn new() -> Self {
        Self
    }
}
pub fn send_action() -> ActionDefinition {
    ActionDefinition { name:"send_statsd_batch".into(), description:"Encode and emit 1..256 structured records in one UDP datagram, capped at 8192 bytes. No acknowledgment or delivery guarantee. A signed gauge value such as +2 is a delta; -2 also means a delta, not an absolute negative gauge.".into(), parameters:vec![parameter("records", "array", "Objects tagged kind: metric (name, value string, metric_type c/g/ms/s/h/d, optional sample_rate number (DogStatsD 0..1, classic StatsD >0..1) and tags string array); event (title/text, optional timestamp/hostname/aggregation_key/priority normal|low/source_type/alert_type error|warning|info|success/tags); service_check (name/status 0..3, optional timestamp/hostname/tags/message). DogStatsD extensions require dogstatsd dialect. No packed metric values or origin metadata.", true)], example:json!({"type":"send_statsd_batch","records":[{"kind":"metric","name":"requests","value":"1","metric_type":"c","tags":["env:test"]}]}), log_template: Some(LogTemplate::new().with_info("-> StatsD records={records_len}")) }
}
fn disconnect_action() -> ActionDefinition {
    ActionDefinition {
        name: "disconnect".into(),
        description: "Close the emitter socket and remove its command handle".into(),
        parameters: vec![],
        example: json!({"type":"disconnect"}),
        log_template: Some(LogTemplate::new().with_info("-> StatsD disconnect")),
    }
}
pub static STATSD_CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "statsd_connected",
        "UDP emitter ready. No handshake or confirmation that a collector exists.",
        send_action().example,
    )
    .with_parameters(vec![
        parameter("remote_addr", "string", "Collector address", true),
        parameter("local_addr", "string", "Emitter address", true),
        parameter("dialect", "string", "statsd or dogstatsd", true),
    ])
    .with_actions(vec![send_action(), disconnect_action()])
});

impl Protocol for StatsdClientProtocol {
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
        "Emit structured StatsD or DogStatsD metric/event/service-check batches over UDP"
    }
    fn example_prompt(&self) -> &'static str {
        "Send a requests counter with value 1 to StatsD at localhost:8125"
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
        vec![STATSD_CONNECTED_EVENT.clone()]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![dialect_parameter()]
    }
    fn metadata(&self) -> ProtocolMetadataV2 {
        ProtocolMetadataV2::builder().state(DevelopmentState::Experimental).well_known_udp_port(8125)
            .implementation("Native UTF-8 UDP codec shared with collector; no additional dependencies")
            .llm_control("One connected event; structured batch actions also available via command injection")
            .e2e_testing("Exact UDP wire fixtures, handler and lifecycle tests; independent receiver evidence in tests/client/statsd/AGENTS.md")
            .notes("8 KiB / 256 records per datagram. No delivery acknowledgment, retries, TCP, Unix sockets, aggregation or sampling decisions; sample_rate is metadata. Default dialect dogstatsd.").history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn get_startup_examples(&self) -> StartupExamples {
        let action = json!({"type":"send_statsd_batch","records":[{"kind":"metric","name":"requests","value":"1","metric_type":"c"}]});
        StartupExamples::new(
            json!({"type":"open_client","base_stack":"statsd","remote_addr":"localhost:8125","instruction":"Send one requests counter value 1"}),
            json!({"type":"open_client","base_stack":"statsd","remote_addr":"localhost:8125","event_handlers":[{"event_pattern":"statsd_connected","handler":{"type":"script","language":"python","code":"import json, sys\njson.load(sys.stdin)\nprint(json.dumps({'actions': [{'type': 'send_statsd_batch', 'records': [{'kind': 'metric', 'name': 'requests', 'value': '1', 'metric_type': 'c'}]}]}))"}}]}),
            json!({"type":"open_client","base_stack":"statsd","remote_addr":"localhost:8125","event_handlers":[{"event_pattern":"statsd_connected","handler":{"type":"static","actions":[action]}}]}),
        )
    }
}
impl Client for StatsdClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::StatsdClient::connect(ctx))
    }
    fn execute_action(&self, action: Value) -> Result<ClientActionResult> {
        match action["type"].as_str() {
            Some("send_statsd_batch") => {
                let records: Vec<Record> = serde_json::from_value(
                    action.get("records").context("missing records")?.clone(),
                )
                .context("invalid structured records")?;
                codec::encode_datagram(&records, Dialect::Dogstatsd)?;
                Ok(ClientActionResult::Custom {
                    name: "send_statsd_batch".into(),
                    data: serde_json::to_value(records)?,
                })
            }
            Some("disconnect") => Ok(ClientActionResult::Disconnect),
            _ => bail!("unknown StatsD client action"),
        }
    }
}

use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, ParameterDefinition, StartupExamples,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::{
    metadata::{DevelopmentState, ProtocolMetadataV2},
    ConnectContext, EventType,
};
use crate::server::prometheus_remote_write::{
    actions::parameter,
    codec::{self, WriteBatch, DEFAULT_PATH, DEFAULT_RETRY_429},
};
use crate::state::app_state::AppState;
use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;
#[derive(Default)]
pub struct PrometheusRemoteWriteClientProtocol;
impl PrometheusRemoteWriteClientProtocol {
    pub fn new() -> Self {
        Self
    }
}
pub fn write_action() -> ActionDefinition {
    ActionDefinition { name:"write_remote_samples".into(), description:"Submit one typed published1.0 float-sample batch. Retry5xx/transport failures with backoff while connected;429 opt-in. Caller must preserve per-series order across batches and supply stale markers when appropriate.".into(), parameters:vec![parameter("batch","object","series[{labels:{name:nonempty UTF-8 value},samples:[{timestamp_ms:i64,value:finite number|nan|+inf|-inf|stale}]}]; empty series array is a v1 probe",true)], example:json!({"type":"write_remote_samples","batch":{"series":[{"labels":{"__name__":"example_temperature","site":"one"},"samples":[{"timestamp_ms":1700000000000i64,"value":21.5}]}]}}), log_template:Some(LogTemplate::new().with_info("Remote write action {type} queued")) }
}
fn disconnect() -> ActionDefinition {
    ActionDefinition { name:"disconnect".into(),description:"Cancel logical session, pending exchange/backoff and parked handler; unsent volatile samples are lost".into(),parameters:vec![],example:json!({"type":"disconnect"}),log_template:Some(LogTemplate::new().with_info("Remote write action {type} queued")) }
}
pub static REMOTE_WRITE_CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "remote_write_connected",
        "Logical HTTP origin ready; no TCP until a validated write",
        write_action().example,
    )
    .with_parameters(vec![parameter(
        "remote_addr",
        "string",
        "Collector HTTP origin address",
        true,
    )])
    .with_actions(vec![write_action(), disconnect()])
});
pub static REMOTE_WRITE_RESPONSE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new("remote_write_response","Final HTTP outcome: any2xx accepted;4xx other than opted-in429 terminal.5xx retry until acceptance/cancellation. Response body ignored. No durability/exactly-once promise.",write_action().example).with_parameters(vec![parameter("series_count","number","Submitted series",true),parameter("sample_count","number","Submitted float samples",true),parameter("status","number","Terminal HTTP status",true),parameter("accepted","boolean","True for any terminal 2xx response; durability is unconfirmed",true),parameter("attempts","number","HTTP attempts including retries",true),parameter("durable_storage_confirmed","boolean","Always false; HTTP acceptance alone is insufficient",true)]).with_actions(vec![write_action(),disconnect()])
});
impl Protocol for PrometheusRemoteWriteClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "PrometheusRemoteWrite"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>HTTP>PrometheusRemoteWrite"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "prometheus-remote-write",
            "remote-write",
            "prometheus-write",
        ]
    }
    fn group_name(&self) -> &'static str {
        "Network Services"
    }
    fn description(&self) -> &'static str {
        "Typed published remote write1.0 float-sample emitter with cancellable retry backoff"
    }
    fn example_prompt(&self) -> &'static str {
        "Send remote write float samples to localhost9090"
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        vec![write_action(), disconnect()]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            REMOTE_WRITE_CONNECTED_EVENT.clone(),
            REMOTE_WRITE_RESPONSE_EVENT.clone(),
        ]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "auth_token".into(),
                type_hint: "string".into(),
                description: "Optional Bearer token<=1024 printable ASCII; excluded from handlers"
                    .into(),
                required: false,
                example: json!("collector-secret"),
                default: None,
            },
            ParameterDefinition {
                name: "path".into(),
                type_hint: "string".into(),
                description: "Absolute HTTP write path<=1024 bytes, no query/fragment".into(),
                required: false,
                example: json!("/receive"),
                default: Some(json!(DEFAULT_PATH)),
            },
            ParameterDefinition {
                name: "retry_429".into(),
                type_hint: "boolean".into(),
                description: "Retry429 like5xx while connected; otherwise429 is terminal".into(),
                required: false,
                example: json!(true),
                default: Some(json!(DEFAULT_RETRY_429)),
            },
        ]
    }
    fn metadata(&self) -> ProtocolMetadataV2 {
        ProtocolMetadataV2::builder().state(DevelopmentState::Experimental).well_known_port(9090).implementation("Native bounded public1.0 protobuf/Snappy block encoding; owned Hyper HTTP/1.1 exchange and exponential backoff")
            .llm_control("Connected/typed terminal-response events and common shared memory; injection/disconnect independent of parked handlers and retry IO")
            .e2e_testing("Required pinned official Prometheus3.15.0 TSDB readback; actual independent Prometheus sender; literal codec, retry/errors and owned cancellation checks")
            .notes("Published1.0 float-sample selected scope, not full Prometheus agent/conformance. Cleartext HTTP origin and configurable path(default/api/v1/write), optional Bearer; required headers fixed, no custom override.256KiB wire/decoded body,128series/2048samples/32labels,128byte legacy ASCII names/2048byte nonempty UTF-8 values. One in-flight batch,32queued events/actions,followup depth8,64KiB ignored response body,64/32KiB headers,10s each exchange.5xx and IO/framing failures retry indefinitely while connected with100ms..5s exponential backoff;429 optional, other HTTP statuses terminal,any2xx accepted,redirects not followed,Retry-After ignored. Identical retry body can duplicate remotely. Per-batch sample order validated; caller owns cross-batch order/stale lifecycle. Cancellation drops volatile samples; no WAL,dedup,storage,scraping/discovery,automatic stale detection,metadata/exemplars/native histograms,2.0,TLS/basic/cloud auth,queries,fuzz orpcap. Logical local address0.0.0.0:0;freshTCPperattempt.").history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn get_startup_examples(&self) -> StartupExamples {
        StartupExamples::new(
            json!({"type":"open_client","base_stack":"prometheus-remote-write","remote_addr":"http://localhost:9090","instruction":"Send one float batch"}),
            json!({"type":"open_client","base_stack":"prometheus-remote-write","remote_addr":"http://localhost:9090","event_handlers":[{"event_pattern":"remote_write_connected","handler":{"type":"script","language":"python","code":"import json,sys\njson.load(sys.stdin)\nprint(json.dumps({'actions':[{'type':'disconnect'}]}))"}}]}),
            json!({"type":"open_client","base_stack":"prometheus-remote-write","remote_addr":"http://localhost:9090","event_handlers":[{"event_pattern":"remote_write_connected","handler":{"type":"static","actions":[write_action().example]}}]}),
        )
    }
}
impl Client for PrometheusRemoteWriteClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::PrometheusRemoteWriteClient::connect(ctx))
    }
    fn execute_action(&self, action: Value) -> Result<ClientActionResult> {
        match action["type"].as_str() {
            Some("write_remote_samples") => {
                let batch: WriteBatch =
                    serde_json::from_value(action.get("batch").context("batch required")?.clone())?;
                codec::encode_batch(&batch)?;
                Ok(ClientActionResult::Custom {
                    name: "write_remote_samples".into(),
                    data: serde_json::to_value(batch)?,
                })
            }
            Some("disconnect") => Ok(ClientActionResult::Disconnect),
            _ => bail!("unknown remote write emitter action"),
        }
    }
}

use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, ParameterDefinition, StartupExamples,
};
use crate::protocol::{
    log_template::LogTemplate,
    metadata::{DevelopmentState, ProtocolMetadataV2},
    ConnectContext, EventType,
};
use crate::server::loki::{
    actions::parameter,
    codec::{self, PushBatch},
};
use crate::state::app_state::AppState;
use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;
#[derive(Default)]
pub struct LokiClientProtocol;
impl LokiClientProtocol {
    pub fn new() -> Self {
        Self
    }
}
pub fn write_action() -> ActionDefinition {
    ActionDefinition{name:"push_loki_entries".into(),description:"Submit one validated typed Loki push, with explicit status/error/tenant/encoding completion and no automatic retries.204 means receiver acceptance.".into(),parameters:vec![parameter("batch","object","optional tenant_id,encoding json(default)/gzip_json/snappy_protobuf,streams[{labels:{name:value},entries:[{timestamp_ns:i64,line:string,structured_metadata:{name:value}(optional)}]}]",true)],example:json!({"type":"push_loki_entries","batch":{"tenant_id":"tenant-one","encoding":"snappy_protobuf","streams":[{"labels":{"app":"example"},"entries":[{"timestamp_ns":1700000000000000000i64,"line":"Hello 名","structured_metadata":{"trace_id":"123"}}]}]}}),log_template:Some(LogTemplate::new().with_info("Push Loki log entries"))}
}
fn disconnect() -> ActionDefinition {
    ActionDefinition {
        name: "disconnect".into(),
        description: "Cancel logical session, parked handlers and pending HTTP exchange".into(),
        parameters: vec![],
        example: json!({"type":"disconnect"}),
        log_template: Some(LogTemplate::new().with_info("Disconnect Loki client")),
    }
}
pub static LOKI_CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "loki_connected",
        "Logical HTTP origin ready; no TCP until a fully validated push",
        write_action().example,
    )
    .with_parameters(vec![parameter(
        "remote_addr",
        "string",
        "Cleartext HTTP origin of the Loki push receiver",
        true,
    )])
    .with_actions(vec![write_action(), disconnect()])
});
pub static LOKI_RESPONSE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new("loki_push_response","Typed push outcome;204accepted,260blocked,other supported error statuses explicit. No retry/persistence/atomicity promise.",write_action().example).with_parameters(vec![parameter("tenant_id","string","Submitted tenant or fake",true),parameter("encoding","string","Carrier used for the submitted batch: json, gzip_json or snappy_protobuf",true),parameter("stream_count","number","Number of label streams in the submitted batch",true),parameter("entry_count","number","Number of log entries in the submitted batch",true),parameter("status","number","Receiver HTTP response status; 204 accepts the push, 260 blocks ingestion",true),parameter("error","object|null","message for rejection, including260",true),parameter("retry_after_seconds","number|null","Optional receiver retry delay in seconds; this client never retries automatically",true)]).with_actions(vec![write_action(),disconnect()])
});
impl Protocol for LokiClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "Loki"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>HTTP>Loki"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["loki", "loki-push"]
    }
    fn group_name(&self) -> &'static str {
        "Network Services"
    }
    fn description(&self) -> &'static str {
        "Typed Loki JSON/gzip/protobuf-Snappy push emitter with tenant and rejection events"
    }
    fn example_prompt(&self) -> &'static str {
        "Push typed logs to Loki at http://localhost:3100"
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        vec![write_action(), disconnect()]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![LOKI_CONNECTED_EVENT.clone(), LOKI_RESPONSE_EVENT.clone()]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![ParameterDefinition{name:"auth_token".into(),type_hint:"string".into(),description:"Optional proxy-style Bearer token<=1024printable ASCII; not built-in Loki authentication; excluded from handlers".into(),required:false,example:json!("collector-secret"),default:None}]
    }
    fn metadata(&self) -> ProtocolMetadataV2 {
        ProtocolMetadataV2::builder().state(DevelopmentState::Experimental).well_known_port(3100).implementation("Native bounded public protobuf/Snappy block encoder and JSON/gzip; owned Hyper HTTP/1.1 exchanges").llm_control("Connected/typed response events, common shared memory and command injection independent of parked handlers/IO").e2e_testing("Official Loki3.7.8 readback and Alloy1.20.1 writer; native pair/errors/lifecycle/bounds").notes("Cleartext HTTP origin only; POST /loki/api/v1/push; optional tenant/Bearer;JSON/gzip JSON/Snappy protobuf.256KiB wire/decoded body,64streams/1024entries,16KiB line,32labels/64metadata,128byte ASCII names/2048values,150tenant/1024token;64KiB response/4096byte error,32KiB/64headers,10s whole exchange,one in-flight request,32queued events/actions,followup depth8.204only success;260blocked and supported4xx/5xx typed; numeric Retry-After1..3600only429/503. No TLS/proxy/basic/cloud auth, redirects, retries, queries, durable store, order/retention/ACL enforcement, OTLP,partial acceptance,fuzz orpcap. Logical local address0.0.0.0:0; fresh TCP per push.").history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
        .batching(crate::protocol::metadata::BatchingMode::Unsupported)
        .build()
    }
    fn get_startup_examples(&self) -> StartupExamples {
        StartupExamples::new(
            json!({"type":"open_client","base_stack":"loki","remote_addr":"http://localhost:3100","instruction":"Push one log entry"}),
            json!({"type":"open_client","base_stack":"loki","remote_addr":"http://localhost:3100","event_handlers":[{"event_pattern":"loki_connected","handler":{"type":"script","language":"python","code":"import json,sys\njson.load(sys.stdin)\nprint(json.dumps({'actions':[{'type':'disconnect'}]}))"}}]}),
            json!({"type":"open_client","base_stack":"loki","remote_addr":"http://localhost:3100","event_handlers":[{"event_pattern":"loki_connected","handler":{"type":"static","actions":[write_action().example]}}]}),
        )
    }
}
impl Client for LokiClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::LokiClient::connect(ctx))
    }
    fn execute_action(&self, action: Value) -> Result<ClientActionResult> {
        match action["type"].as_str() {
            Some("push_loki_entries") => {
                let batch: PushBatch =
                    serde_json::from_value(action.get("batch").context("batch required")?.clone())?;
                codec::encode_batch(&batch)?;
                Ok(ClientActionResult::Custom {
                    name: "push_loki_entries".into(),
                    data: serde_json::to_value(batch)?,
                })
            }
            Some("disconnect") => Ok(ClientActionResult::Disconnect),
            _ => bail!("unknown Loki emitter action"),
        }
    }
}

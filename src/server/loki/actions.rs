use super::codec::{DEFAULT_LLM_FALLBACK, DEFAULT_REQUIRE_TENANT, MAX_BODY_BYTES};
use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter, ParameterDefinition, StartupExamples,
};
use crate::protocol::{
    log_template::LogTemplate,
    metadata::{DevelopmentState, ProtocolMetadataV2},
    EventType, SpawnContext,
};
use crate::state::app_state::AppState;
use anyhow::{bail, ensure, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::LazyLock;
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum Decision {
    Accept,
    Reject {
        status: u16,
        message: String,
        retry_after_seconds: Option<u16>,
    },
}
pub fn parameter(name: &str, type_hint: &str, description: &str, required: bool) -> Parameter {
    Parameter {
        name: name.into(),
        type_hint: type_hint.into(),
        description: description.into(),
        required,
    }
}
fn accept() -> ActionDefinition {
    ActionDefinition{name:"accept_loki_entries".into(),description:"Accept all validated entries with204. Acceptance means handler observation, not durable storage; no private stream database.".into(),parameters:vec![],example:json!({"type":"accept_loki_entries"}),log_template:Some(LogTemplate::new().with_info("Accept Loki log entries"))}
}
fn reject() -> ActionDefinition {
    ActionDefinition{name:"reject_loki_entries".into(),description:"Reject this batch with a bounded Loki plain-text HTTP error.260 explicitly means blocked ingestion. Retry advice never schedules retries.".into(),parameters:vec![parameter("status","number","HTTP refusal status: 260 for blocked ingestion, or 400, 401, 403, 404, 413, 415, 422, 429, 500 or 503",true),parameter("message","string","UTF-8 explanation<=4096bytes; tab/newline allowed",true),parameter("retry_after_seconds","number","Optional Retry-After delay, 1..3600 seconds; valid only with status 429 or 503",false)],example:json!({"type":"reject_loki_entries","status":429,"message":"Tenant ingestion quota","retry_after_seconds":3}),log_template:Some(LogTemplate::new().with_info("Reject Loki log entries with status {status}"))}
}
pub static LOKI_PUSH_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new("loki_push","Validated typed stream labels, entries with signed nanosecond timestamps/log lines/string metadata, tenant identity and encoding. Raw compressed bodies and bearer credentials are excluded.",accept().example).with_parameters(vec![parameter("tenant_id","string","Single tenant or fake when header absent",true),parameter("tenant_provided","boolean","Explicit X-Scope-OrgID received",true),parameter("encoding","string","json/gzip_json/snappy_protobuf",true),parameter("streams","array","labels and typed entries(timestamp_ns,line,structured_metadata)",true),parameter("authenticated","boolean","Token verified or no token configured",true),parameter("auth_required","boolean","Bearer token configured",true),parameter("source_addr","string","Remote socket address of the HTTP peer that submitted this push",true)]).with_actions(vec![accept(),reject()])
});
#[derive(Default)]
pub struct LokiProtocol;
impl LokiProtocol {
    pub fn new() -> Self {
        Self
    }
}
impl Protocol for LokiProtocol {
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
        "Bounded typed Loki JSON/gzip and protobuf/Snappy collector; unmatched logs collect without model calls"
    }
    fn example_prompt(&self) -> &'static str {
        "Collect Loki log pushes on localhost port3100"
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![accept(), reject()]
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![LOKI_PUSH_EVENT.clone()]
    }
    fn metadata(&self) -> ProtocolMetadataV2 {
        ProtocolMetadataV2::builder().answers_on_failure().state(DevelopmentState::Experimental).well_known_port(3100).max_inbound_bytes(MAX_BODY_BYTES).request_only("HTTP push request/response; no unsolicited messages")
.implementation("Native public push schema and bounded Snappy block codec; JSON and existing flate2 gzip; owned Hyper HTTP/1.1 collector")
.llm_control("Typed logs/labels/metadata and tenant facts through common handlers/shared memory; unmatched collection has no model calls unless llm_fallback=true")
.e2e_testing("Pinned official Loki3.7.8 service readback and maintained Alloy1.20.1 protobuf/Snappy writer; native pair, malformed/bounds/auth/error/cancellation checks")
.notes("Experimental POST /loki/api/v1/push only: JSON, gzip JSON, Snappy protobuf; optional single tenant header (fake if absent), require_tenant flag, optional proxy-style Bearer check (not Loki-built-in authentication).256KiB wire/decoded body;64streams/1024entries;16KiB UTF-8 lines;32labels/64metadata;ASCII identifier names<=128bytes,values<=2048bytes; tenant150/token1024bytes;16384protobuf fields/JSON depth8;256connections;32KiB/64headers;30s header/body,10s decision-write. Reserved __ stream labels and duplicate stream sets/keys rejected; strict push fields and signed i64 nanoseconds. Empty successful handler accepts; failed/multiple decisions503. No TLS/proxy/cloud auth, durable store, per-tenant ACL, querying, retention/order enforcement, partial acceptance, OTLP, retries, fuzz or pcap.").history(crate::protocol::metadata::HistoryMode::Off)
.batching(crate::protocol::metadata::BatchingMode::Unsupported)
.build()
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![ParameterDefinition{name:"auth_token".into(),type_hint:"string".into(),description:"Optional proxy-style Bearer token<=1024printable ASCII; never included in event data; absent means anonymous".into(),required:false,example:json!("collector-secret"),default:None},ParameterDefinition{name:"require_tenant".into(),type_hint:"boolean".into(),description:"Require one valid X-Scope-OrgID. Identity is not authorization or a tenant database.".into(),required:false,example:json!(true),default:Some(json!(DEFAULT_REQUIRE_TENANT))},ParameterDefinition{name:"llm_fallback".into(),type_hint:"boolean".into(),description:"Opt unmatched pushes into model calls; explicit handlers always run".into(),required:false,example:json!(true),default:Some(json!(DEFAULT_LLM_FALLBACK))}]
    }
    fn get_startup_examples(&self) -> StartupExamples {
        StartupExamples::new(
            json!({"type":"open_server","base_stack":"loki","port":3100,"startup_params":{"llm_fallback":true},"instruction":"Decide which log pushes to accept"}),
            json!({"type":"open_server","base_stack":"loki","port":3100,"event_handlers":[{"event_pattern":"loki_push","handler":{"type":"script","language":"python","code":"import json,sys\njson.load(sys.stdin)\nprint(json.dumps({'actions':[{'type':'accept_loki_entries'}]}))"}}]}),
            json!({"type":"open_server","base_stack":"loki","port":3100,"event_handlers":[{"event_pattern":"loki_push","handler":{"type":"static","actions":[accept().example]}}]}),
        )
    }
}
impl Server for LokiProtocol {
    fn spawn(
        &self,
        ctx: SpawnContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::LokiServer::spawn(ctx))
    }
    fn execute_action(&self, action: Value) -> Result<ActionResult> {
        let decision = match action["type"].as_str() {
            Some("accept_loki_entries") => Decision::Accept,
            Some("reject_loki_entries") => {
                let status = u16::try_from(action["status"].as_u64().context("status required")?)?;
                ensure!(
                    [260, 400, 401, 403, 404, 413, 415, 422, 429, 500, 503].contains(&status),
                    "unsupported rejection status"
                );
                let message = action["message"].as_str().context("message required")?;
                ensure!(
                    !message.is_empty()
                        && message.len() <= 4096
                        && !message
                            .chars()
                            .any(|c| c.is_control() && !matches!(c, '\t' | '\n' | '\r')),
                    "error message byte/control limit"
                );
                let retry = action
                    .get("retry_after_seconds")
                    .map(|v| {
                        u16::try_from(v.as_u64().context("integer retry advice required")?)
                            .map_err(anyhow::Error::from)
                    })
                    .transpose()?;
                if let Some(n) = retry {
                    ensure!(
                        (1..=3600).contains(&n) && [429, 503].contains(&status),
                        "Retry-After1..3600only429/503"
                    );
                }
                Decision::Reject {
                    status,
                    message: message.into(),
                    retry_after_seconds: retry,
                }
            }
            _ => bail!("unknown Loki collector action"),
        };
        Ok(ActionResult::Custom {
            name: "loki_push_decision".into(),
            data: serde_json::to_value(decision)?,
        })
    }
}

use super::codec::{DEFAULT_LLM_FALLBACK, DEFAULT_PATH, MAX_BODY_BYTES};
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
    ActionDefinition { name:"accept_remote_write_samples".into(), description:"Accept all validated v1 float samples with204; handler observation only, no durable TSDB or protocol storage.".into(), parameters:vec![], example:json!({"type":"accept_remote_write_samples"}), log_template:Some(LogTemplate::new().with_info("Remote write action {type} queued")) }
}
fn reject() -> ActionDefinition {
    ActionDefinition { name:"reject_remote_write_samples".into(), description:"Reject the whole batch:400 invalid/non-retryable;429 optional backoff;500/503 retryable. Common-action failure overrides acceptance.".into(), parameters:vec![parameter("status","number","400,429,500 or503",true),parameter("message","string","Nonempty UTF-8 text<=4096 bytes",true),parameter("retry_after_seconds","number","Optional1..3600 on429/503",false)], example:json!({"type":"reject_remote_write_samples","status":503,"message":"Temporarily unavailable","retry_after_seconds":1}), log_template:Some(LogTemplate::new().with_info("Remote write action {type} queued")) }
}
pub static REMOTE_WRITE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new("remote_write_request","Validated published remote write1.0 float series; labels, signed millisecond timestamps, finite values or nan/+inf/-inf/stale. Unknown optional fields counted and discarded; no credentials/raw body.", accept().example).with_parameters(vec![parameter("series","array","[{labels:{name:value},samples:[{timestamp_ms:i64,value:number|nan|+inf|-inf|stale}]}]",true),parameter("series_count","number","Series in this request",true),parameter("sample_count","number","Float samples in this request",true),parameter("ignored_fields","number","Unknown/reserved fields discarded, not ingested",true),parameter("version","string","Published remote-write wire version 1.0",true),parameter("source_addr","string","HTTP sender socket address",true),parameter("authenticated","boolean","Token verified or anonymous",true),parameter("auth_required","boolean","Bearer token configured",true),parameter("durable_storage","boolean","Always false; common handler observation only",true)]).with_actions(vec![accept(),reject()])
});
#[derive(Default)]
pub struct PrometheusRemoteWriteProtocol;
impl PrometheusRemoteWriteProtocol {
    pub fn new() -> Self {
        Self
    }
}
impl Protocol for PrometheusRemoteWriteProtocol {
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
        "Published remote write1.0 typed protobuf/Snappy float-sample collector"
    }
    fn example_prompt(&self) -> &'static str {
        "Collect remote write samples on localhost9090"
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![accept(), reject()]
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![REMOTE_WRITE_EVENT.clone()]
    }
    fn metadata(&self) -> ProtocolMetadataV2 {
        ProtocolMetadataV2::builder().answers_on_failure().request_only("HTTP write request/response; no unsolicited messages").state(DevelopmentState::Experimental).well_known_port(9090).max_inbound_bytes(MAX_BODY_BYTES)
            .implementation("Native bounded published1.0 prometheus.WriteRequest protobuf and Snappy block codec, owned Hyper HTTP/1.1 tasks")
            .llm_control("Typed float samples and exact stale-marker meaning through common handlers/shared memory; default no-model observation, optional llm_fallback")
            .e2e_testing("Required pinned official Prometheus3.15.0 sender/receiver services, literal dual wire oracle and native bounds/error/lifecycle checks")
            .notes("Selected published1.0 float-sample scope, not a full monitoring agent/TSDB. POST configured path(default/api/v1/write), required0.1.0 version/User-Agent/protobuf/Snappy headers; optional Bearer token.256KiB wire/decoded body,128series/2048samples/32labels,128byte legacy ASCII names/2048byte nonempty UTF-8 values,32768protobuf fields,256connections,32KiB/64headers,30s header/body,10s response write. Sorted unique labels; per-request sample ordering; duplicate series rejected; empty whole negotiation request accepted. Reserved/unknown optional fields discarded with count; exemplars/native histograms rejected. Successful empty/common-only handler accepts; failed actions/multiple decisions503.204means handler observation only, not durable persistence or deduplication. No TLS/basic/cloud auth,2.0,metadata ingestion,queries,protocol store,cross-request timestamp enforcement,fuzz orpcap.").history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
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
                description: "Absolute HTTP write path<=1024 ASCII bytes, no query/fragment".into(),
                required: false,
                example: json!("/receive"),
                default: Some(json!(DEFAULT_PATH)),
            },
            ParameterDefinition {
                name: "llm_fallback".into(),
                type_hint: "boolean".into(),
                description: "Opt unmatched writes into model calls; explicit handlers always run"
                    .into(),
                required: false,
                example: json!(true),
                default: Some(json!(DEFAULT_LLM_FALLBACK)),
            },
        ]
    }
    fn get_startup_examples(&self) -> StartupExamples {
        StartupExamples::new(
            json!({"type":"open_server","base_stack":"prometheus-remote-write","port":9090,"startup_params":{"llm_fallback":true},"instruction":"Decide which samples to accept"}),
            json!({"type":"open_server","base_stack":"prometheus-remote-write","port":9090,"event_handlers":[{"event_pattern":"remote_write_request","handler":{"type":"script","language":"python","code":"import json,sys\njson.load(sys.stdin)\nprint(json.dumps({'actions':[{'type':'accept_remote_write_samples'}]}))"}}]}),
            json!({"type":"open_server","base_stack":"prometheus-remote-write","port":9090,"event_handlers":[{"event_pattern":"remote_write_request","handler":{"type":"static","actions":[accept().example]}}]}),
        )
    }
}
impl Server for PrometheusRemoteWriteProtocol {
    fn spawn(
        &self,
        ctx: SpawnContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::PrometheusRemoteWriteServer::spawn(ctx))
    }
    fn execute_action(&self, action: Value) -> Result<ActionResult> {
        let decision = match action["type"].as_str() {
            Some("accept_remote_write_samples") => Decision::Accept,
            Some("reject_remote_write_samples") => {
                let status = u16::try_from(action["status"].as_u64().context("status required")?)?;
                ensure!(
                    [400, 429, 500, 503].contains(&status),
                    "unsupported rejection status"
                );
                let message = action["message"].as_str().context("message required")?;
                ensure!(
                    !message.is_empty() && message.len() <= 4096,
                    "rejection message byte limit"
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
                        "invalid retry advice range/status"
                    );
                }
                Decision::Reject {
                    status,
                    message: message.into(),
                    retry_after_seconds: retry,
                }
            }
            _ => bail!("unknown remote write collector action"),
        };
        Ok(ActionResult::Custom {
            name: "remote_write_decision".into(),
            data: serde_json::to_value(decision)?,
        })
    }
}

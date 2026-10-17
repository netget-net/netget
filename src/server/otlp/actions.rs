//! OTLP actions: what the model is told about an export, and how its verdict becomes a response.
//!
//! The model is the receiver's judgement. It sees a structured summary of each export — never
//! the payload — and answers with one verdict: take it all, take part of it, or refuse it with
//! an HTTP status. NetGet encodes the response body in the request's own encoding.

use super::codec;
use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::EventType;
use crate::state::app_state::AppState;
use anyhow::{anyhow, Context, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

pub struct OtlpProtocol;

impl OtlpProtocol {
    pub fn new() -> Self {
        Self
    }
}

impl Default for OtlpProtocol {
    fn default() -> Self {
        Self::new()
    }
}

/// The name of every structured answer this protocol's executor returns.
pub const ANSWER: &str = "otlp_answer";

/// A verdict, read back from what [`OtlpProtocol::execute_action`] returned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Accept,
    Partial {
        rejected: i64,
        error_message: String,
    },
    Reject {
        status: u16,
        message: String,
        retry_after_secs: Option<u64>,
    },
}

impl Verdict {
    pub fn from_result(result: &ActionResult) -> Option<Verdict> {
        let ActionResult::Custom { name, data } = result else {
            return None;
        };
        if name != ANSWER {
            return None;
        }
        match data.get("kind")?.as_str()? {
            "accept" => Some(Verdict::Accept),
            "partial" => Some(Verdict::Partial {
                rejected: data.get("rejected")?.as_i64()?,
                error_message: data.get("error_message")?.as_str()?.to_string(),
            }),
            "reject" => Some(Verdict::Reject {
                status: u16::try_from(data.get("code")?.as_u64()?).ok()?,
                message: data.get("message")?.as_str()?.to_string(),
                retry_after_secs: data.get("retry_after_secs").and_then(Value::as_u64),
            }),
            _ => None,
        }
    }
}

impl Protocol for OtlpProtocol {
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        Vec::new()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![accept_action(), partial_action(), reject_action()]
    }
    fn protocol_name(&self) -> &'static str {
        "OTLP"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![OTLP_EXPORT_EVENT.clone()]
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>HTTP>OTLP"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "otlp",
            "opentelemetry",
            "otel",
            "otel collector",
            "traces",
            "telemetry receiver",
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{
            DevelopmentState, PrivilegeRequirement, ProtocolMetadataV2,
        };

        ProtocolMetadataV2::builder()
            // HTTP has independent exporter evidence; the expanded gRPC scope stays Experimental.
            .state(DevelopmentState::Experimental)
            .well_known_port(4318)
            // 4318 is unprivileged, and so is every port a test picks.
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation(
                "hyper HTTP/1.1 and HTTP/2 receiver with generated tonic unary gRPC Export services for traces, metrics and logs; POST /v1/traces, /v1/metrics and /v1/logs in \
                 application/x-protobuf (decoded with the OpenTelemetry project's own \
                 opentelemetry-proto types) or application/json (walked as JSON), with \
                 Content-Encoding gzip held to the same size cap after inflation. Every \
                 response body - full success, partial success, google.rpc.Status - is \
                 encoded by NetGet in the request's encoding.",
            )
            .llm_control(
                "The verdict on each export, from a summary of it (signal, service, resource \
                 attributes, counts, the first span names, metric names or log bodies): \
                 accept it, accept part of it (a partial success naming how many items were \
                 rejected and why), or refuse it with an HTTP status - 429/502/503/504 ask the \
                 client to retry, 400/401/403/413/500 drop the data.",
            )
            .e2e_testing(
                "tests/server/otlp/real_client_test.rs drives otel-cli (equinix-labs, Go, the \
                 OpenTelemetry Go SDK's OTLP/HTTP exporter) sending a span over \
                 http/protobuf and asserts the handler saw its name and service, and \
                 telemetrygen (the OpenTelemetry Collector project's load generator) sending \
                 metrics and logs over OTLP/HTTP, asserting the metric and log counts and a \
                 rejection it reports. Both fail, never skip, when absent. \
                 tests/server/otlp/grpc_test.rs drives those exporters over gRPC, including \
                 a PERMISSION_DENIED refusal, and covers all three generated services, \
                 exact size boundaries, RPC admission, deadlines and cancellation. \
                 tests/client/otlp drives official core Collector 0.162.0 over both transports \
                 with plain/gzip exports and verified custom-CA TLS, plus native pairing. \
                 tests/server/otlp/e2e_test.rs covers the mocked-model path over JSON and \
                 protobuf.",
            )
            .notes(
                "Implements OTLP/HTTP and OTLP/gRPC receiver sides: the three signal paths, both HTTP \
                 encodings, gzip, full and partial success, and google.rpc.Status failures \
                 with the specification's HTTP statuses (415 for another Content-Type or \
                 Content-Encoding, 404 for another path, 405 for another method). Not \
                 implemented: receiver TLS, profiles, and any storage or forwarding - \
                 NetGet keeps nothing it received. Bodies are capped at 4 MiB after \
                 inflation; a payload that does not decode is refused 400 by NetGet without \
                 asking the model. On backend failure the export is refused 503 with \
                 Retry-After (overloaded) or 500, with a fixed message. Expanded gRPC surface remains Experimental: 16 HTTP/2 streams per connection, 64 active RPCs before decoding, one bounded message per unary Export, 30-second whole-RPC deadline including body/model, and connection-owned stream tasks.",
            )
            .max_inbound_bytes(codec::MAX_BODY_BYTES)
            // LLM failure: 503 + Retry-After when the backend is saturated, 500 otherwise, each
            // with a fixed google.rpc.Status message. Never an invented 200.
            .answers_on_failure()
            .request_only("OTLP HTTP/gRPC exports are request/response; a receiver cannot send an exporter anything unprompted")
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "OpenTelemetry HTTP/gRPC receiver - the model decides which exports are accepted"
    }
    fn example_prompt(&self) -> &'static str {
        "OTLP receiver on port 4318 - accept traces from the checkout service and refuse \
         everything else with 403"
    }
    fn group_name(&self) -> &'static str {
        "Application"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        StartupExamples::new(
            json!({
                "type": "open_server",
                "port": 4318,
                "base_stack": "otlp",
                "instruction": "OpenTelemetry receiver. Accept everything the checkout \
                                service sends. Refuse data from any other service with 403."
            }),
            json!({
                "type": "open_server",
                "port": 4318,
                "base_stack": "otlp",
                "event_handlers": [{
                    "event_pattern": "otlp_export",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "import json, sys\ne = json.load(sys.stdin)['event']\nif e.get('service_name') == 'checkout':\n    a = [{'type': 'accept_otlp'}]\nelse:\n    a = [{'type': 'reject_otlp', 'code': 403, 'message': 'unknown service'}]\nprint(json.dumps({'actions': a}))"
                    }
                }]
            }),
            json!({
                "type": "open_server",
                "port": 4318,
                "base_stack": "otlp",
                "event_handlers": [{
                    "event_pattern": "otlp_export",
                    "handler": {"type": "static", "actions": [{"type": "accept_otlp"}]}
                }]
            }),
        )
    }
}

impl Server for OtlpProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            crate::server::otlp::OtlpServer::spawn_with_llm_actions(
                ctx.legacy_listen_addr(),
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.server_id,
            )
            .await
        })
    }

    fn execute_action(&self, action: Value) -> Result<ActionResult> {
        let action_type = action
            .get("type")
            .and_then(|v| v.as_str())
            .context("Missing 'type' field in action")?;
        let text = |name: &str| {
            let raw = action.get(name).and_then(Value::as_str).unwrap_or("");
            crate::utils::truncate_for_log(&crate::utils::sanitize::line_field(raw), 512)
        };
        let number = |name: &str| {
            action.get(name).and_then(|v| {
                v.as_u64()
                    .or_else(|| v.as_str().and_then(|s| s.trim().parse().ok()))
            })
        };
        let data = match action_type {
            "accept_otlp" => json!({"kind": "accept"}),
            "accept_otlp_partially" => {
                let rejected = number("rejected")
                    .context("accept_otlp_partially needs 'rejected', a whole number")?;
                let rejected =
                    i64::try_from(rejected).map_err(|_| anyhow!("'rejected' is out of range"))?;
                json!({"kind": "partial", "rejected": rejected, "error_message": text("error_message")})
            }
            "reject_otlp" => {
                let code = number("code").context("reject_otlp needs 'code', an HTTP status")?;
                let code = u16::try_from(code)
                    .ok()
                    .filter(|c| codec::REJECT_STATUSES.contains(c))
                    .ok_or_else(|| {
                        anyhow!(
                            "reject_otlp: code {code} is not one OTLP defines; use one of {:?}",
                            codec::REJECT_STATUSES
                        )
                    })?;
                let mut data = json!({"kind": "reject", "code": code, "message": text("message")});
                if let Some(secs) = number("retry_after_secs") {
                    data["retry_after_secs"] = json!(secs.min(3600));
                }
                data
            }
            _ => return Err(anyhow!("Unknown OTLP action: {}", action_type)),
        };
        Ok(ActionResult::Custom {
            name: ANSWER.to_string(),
            data,
        })
    }
}

fn accept_action() -> ActionDefinition {
    ActionDefinition {
        name: "accept_otlp".to_string(),
        description: "Accept the whole export: the client receives a full success and \
                      discards its copy."
            .to_string(),
        parameters: vec![],
        example: json!({"type": "accept_otlp"}),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> OTLP accepted")
                .with_debug("OTLP accept_otlp"),
        ),
    }
}

fn partial_action() -> ActionDefinition {
    ActionDefinition {
        name: "accept_otlp_partially".to_string(),
        description: "Accept the export but report that some of its items were dropped (an \
                      OTLP partial success): spans for traces, data points for metrics, log \
                      records for logs. The client does not retry."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "rejected".to_string(),
                type_hint: "number".to_string(),
                description: "How many spans, data points or log records were dropped, at \
                              most the count the event gives"
                    .to_string(),
                required: true,
            },
            Parameter {
                name: "error_message".to_string(),
                type_hint: "string".to_string(),
                description: "One line saying why they were dropped".to_string(),
                required: true,
            },
        ],
        example: json!({
            "type": "accept_otlp_partially",
            "rejected": 1,
            "error_message": "<why>"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> OTLP partial success ({rejected} rejected)")
                .with_debug("OTLP accept_otlp_partially: rejected={rejected}"),
        ),
    }
}

fn reject_action() -> ActionDefinition {
    ActionDefinition {
        name: "reject_otlp".to_string(),
        description: "Refuse the whole export with an HTTP status. 429, 502, 503 and 504 ask \
                      the client to retry later (add retry_after_secs); 400 (invalid data), \
                      401, 403, 413 and 500 make it drop the data."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "code".to_string(),
                type_hint: "number".to_string(),
                description: "The HTTP status".to_string(),
                required: true,
            }
            .with_choices(codec::REJECT_STATUSES.iter().map(|c| c.to_string())),
            Parameter {
                name: "message".to_string(),
                type_hint: "string".to_string(),
                description: "One line saying why, sent in the google.rpc.Status body".to_string(),
                required: true,
            },
            Parameter {
                name: "retry_after_secs".to_string(),
                type_hint: "number".to_string(),
                description: "Seconds before retrying: HTTP Retry-After on 429/502/503/504; gRPC RetryInfo. gRPC 429 needs this recovery hint to be retryable"
                    .to_string(),
                required: false,
            },
        ],
        example: json!({"type": "reject_otlp", "code": 403, "message": "<why>"}),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> OTLP rejected {code}")
                .with_debug("OTLP reject_otlp: code={code}"),
        ),
    }
}

fn param(name: &str, type_hint: &str, description: &str) -> Parameter {
    Parameter {
        name: name.to_string(),
        type_hint: type_hint.to_string(),
        description: description.to_string(),
        required: true,
    }
}

fn optional(name: &str, type_hint: &str, description: &str) -> Parameter {
    Parameter {
        required: false,
        ..param(name, type_hint, description)
    }
}

/// The `answer_with` field of `otlp_export`.
pub fn answer_with(signal: codec::Signal, count: usize) -> String {
    format!(
        "exactly one action, decided by what your instructions say about this service and \
         this data: accept_otlp to take all {count} {items}; accept_otlp_partially with how \
         many of them your instructions say to drop and why; or reject_otlp with 403 for a \
         sender your instructions refuse, 400 for data they call invalid, or 429/503 to have \
         the client retry later. For grpc, use retry_after_secs with 429 to signal that exhaustion can recover",
        items = signal.items()
    )
}

/// `POST /v1/traces`, `/v1/metrics` and `/v1/logs`.
pub static OTLP_EXPORT_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "otlp_export",
        "An OpenTelemetry client exported telemetry. You see a summary, not the data. Answer \
         with exactly one verdict: accept_otlp, accept_otlp_partially or reject_otlp. \
         answer_with says which fits.",
        json!({"type": "accept_otlp"}),
    )
    .with_parameters(vec![
        param("signal", "string", "traces, metrics or logs")
            .with_choices(["traces", "metrics", "logs"]),
        param(
            "transport",
            "string",
            "OTLP transport used for this export: http or grpc",
        )
        .with_choices(["http", "grpc"]),
        param("encoding", "string", "How the client encoded the export")
            .with_choices(["protobuf", "json"]),
        param(
            "compressed",
            "boolean",
            "Whether the body was gzip-compressed",
        ),
        param(
            "body_bytes",
            "number",
            "The export's size in bytes, uncompressed",
        ),
        param(
            "resource_count",
            "number",
            "How many resources (sending processes or services) the export covers",
        ),
        param(
            "service_name",
            "string",
            "The first resource's service.name attribute (empty if absent)",
        ),
        optional(
            "service_names",
            "array",
            "Every distinct service.name, when there is more than one (up to 5)",
        ),
        param(
            "resource_attributes",
            "object",
            "The first resource's attributes as name -> text (up to 20)",
        ),
        optional("span_count", "number", "traces: how many spans"),
        optional(
            "error_span_count",
            "number",
            "traces: how many spans have status ERROR",
        ),
        optional("span_names", "array", "traces: the first 10 span names"),
        optional("metric_count", "number", "metrics: how many metrics"),
        optional(
            "data_point_count",
            "number",
            "metrics: how many data points across them",
        ),
        optional(
            "metric_names",
            "array",
            "metrics: the first 10 metric names",
        ),
        optional("log_record_count", "number", "logs: how many log records"),
        optional(
            "error_log_count",
            "number",
            "logs: how many records are at severity ERROR or above",
        ),
        optional(
            "log_bodies",
            "array",
            "logs: the first 5 log bodies as text, each cut at 200 bytes",
        ),
        param(
            "answer_with",
            "string",
            "Which verdict this export takes, and what decides it",
        ),
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("OTLP {signal} from {service_name}")
            .with_debug("OTLP otlp_export: signal={signal} encoding={encoding} bytes={body_bytes}"),
    )
    .with_actions(vec![accept_action(), partial_action(), reject_action()])
    .with_alternative_example(json!({"type": "reject_otlp", "code": 403, "message": "<why>"}))
});

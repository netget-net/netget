use crate::{
    llm::actions::{
        client_trait::{Client, ClientActionResult},
        protocol_trait::Protocol,
        ActionDefinition, Parameter, ParameterDefinition, StartupExamples,
    },
    protocol::{log_template::LogTemplate, ConnectContext, EventType},
    state::AppState,
};
use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;
fn field(name: &str, hint: &str, description: &str, required: bool) -> Parameter {
    Parameter {
        name: name.into(),
        type_hint: hint.into(),
        description: description.into(),
        required,
    }
}
fn event(id: &str, description: &str, parameters: Vec<Parameter>) -> EventType {
    EventType::new(id, description, json!({"type":"wait_for_more"}))
        .with_parameters(parameters)
        .with_actions(OtlpClientProtocol.get_sync_actions())
}
pub static CONNECTED: LazyLock<EventType> = LazyLock::new(|| {
    event(
        "otlp_connected",
        "OTLP transport connected",
        vec![
            field(
                "remote_addr",
                "string",
                "Remote socket address of the OpenTelemetry receiver",
                true,
            ),
            field(
                "transport",
                "string",
                "Transport used for this export: grpc or http",
                true,
            ),
            field(
                "tls_verified",
                "boolean",
                "TLS certificate and server name verified",
                true,
            ),
            field("server_name", "string", "Authenticated TLS name", false),
        ],
    )
});
pub static RESULT: LazyLock<EventType> = LazyLock::new(|| {
    event(
        "otlp_export_result",
        "Export acknowledgement or gRPC failure; partial success is never retryable",
        vec![
            field("signal", "string", "traces, metrics or logs", true),
            field("transport", "string", "Transport used for this export: grpc or http", true),
            field("service_name", "string", "Exported service", true),
            field("items", "number", "Exported item count", true),
            field("result", "string", "accepted, partial_success or rejected", true),
            field("rejected", "number", "Rejected item count on partial success", true),
            field("message", "string", "Bounded status diagnostic", true),
            field(
                "retryable", "boolean",
                "Whether an explicit later retry is appropriate; NetGet never retries automatically",
                true,
            ),
            field("retry_after_secs", "number", "Receiver retry delay, if supplied", false),
            field("http_status", "number", "HTTP status for HTTP transport", false),
            field("grpc_code", "number", "Receiver or library gRPC status code", false),
        ],
    )
});
pub static ERROR: LazyLock<EventType> = LazyLock::new(|| {
    event(
        "otlp_export_error",
        "Local transport, response decoding or export deadline failure",
        vec![
            field("action_type", "string", "Failed export action", true),
            field("error", "string", "Bounded local error", true),
        ],
    )
});
#[derive(Default)]
pub struct OtlpClientProtocol;
impl OtlpClientProtocol {
    pub fn new() -> Self {
        Self
    }
}
impl Protocol for OtlpClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "OTLP"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>HTTP>OTLP"
    }
    fn description(&self) -> &'static str {
        "Bounded typed telemetry exporter over OTLP/gRPC or OTLP/HTTP protobuf"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "otlp",
            "otel",
            "opentelemetry",
            "export telemetry",
            "collector",
        ]
    }
    fn group_name(&self) -> &'static str {
        "Application"
    }
    fn example_prompt(&self) -> &'static str {
        "Export a gauge data point to a trusted OpenTelemetry Collector"
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        self.get_sync_actions()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        let common = || {
            vec![
                field("service_name", "string", "Service name, 1..256 bytes", true),
                field(
                    "resource_attributes", "object",
                    "At most 32 flat scalar attributes; keys 256 bytes, strings 1024 bytes; use service_name for service.name",
                    false,
                ),
                field("scope_name", "string", "Instrumentation scope, at most 256 bytes; default netget", false),
            ]
        };
        let action = |name: &str,
                      description: &str,
                      parameters: Vec<Parameter>,
                      example: Value,
                      log_message: &str| {
            ActionDefinition {
                name: name.into(),
                description: description.into(),
                parameters,
                example,
                log_template: Some(LogTemplate::new().with_info(log_message)),
            }
        };
        let mut traces = common();
        traces.push(field("spans","array","1..128 spans: name; nonzero trace_id (32 hex), span_id (16 hex), optional parent_span_id (16 hex); positive start_time_unix_nano/end_time_unix_nano u64 with end>=start; optional kind internal/server/client/producer/consumer, status unset/ok/error, status_message and flat attributes",true));
        let mut logs = common();
        logs.push(field("logs","array","1..128 records: body (1..4096 bytes), positive time_unix_nano u64; optional severity_number 0..24 (default 9), severity_text, paired trace_id/span_id and flat attributes",true));
        let mut gauge = common();
        gauge.extend([
            field("name", "string", "Metric name, 1..256 bytes", true),
            field("description", "string", "Optional gauge metric description, at most 256 bytes", false),
            field("unit", "string", "Optional gauge metric unit, at most 64 bytes", false),
            field(
                "data_points", "array",
                "1..128 gauge points: positive time_unix_nano u64, value (i64 or finite float), optional flat attributes",
                true,
            ),
        ]);
        vec![
            action(
                "export_otlp_traces",
                "Export typed spans; no binary payload, span events or links",
                traces,
                json!({"type":"export_otlp_traces","service_name":"checkout","spans":[{"name":"charge card","trace_id":"0102030405060708090a0b0c0d0e0f10","span_id":"0102030405060708","start_time_unix_nano":1720000000000000000u64,"end_time_unix_nano":1720000000001000000u64,"kind":"client","status":"ok"}]}),
                "Export OTLP traces for {service_name}",
            ),
            action(
                "export_otlp_logs",
                "Export UTF-8 text log records",
                logs,
                json!({"type":"export_otlp_logs","service_name":"checkout","logs":[{"body":"payment accepted","time_unix_nano":1720000000000000000u64,"severity_number":9}]}),
                "Export OTLP logs for {service_name}",
            ),
            action(
                "export_otlp_gauge",
                "Export one gauge metric with typed numeric data points",
                gauge,
                json!({"type":"export_otlp_gauge","service_name":"checkout","name":"queue.depth","unit":"1","data_points":[{"value":3,"time_unix_nano":1720000000000000000u64}]}),
                "Export OTLP gauge {name} for {service_name}",
            ),
            action(
                "disconnect",
                "Cancel exports and handlers, close the owned transport",
                vec![],
                json!({"type":"disconnect"}),
                "Disconnect OTLP exporter",
            ),
            action(
                "wait_for_more",
                "Wait for another event or injected export",
                vec![],
                json!({"type":"wait_for_more"}),
                "Wait for the next OTLP exporter event",
            ),
        ]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![CONNECTED.clone(), RESULT.clone(), ERROR.clone()]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        let p =
            |name: &str, hint: &str, description: &str, example: Value, default: Option<Value>| {
                ParameterDefinition {
                    name: name.into(),
                    type_hint: hint.into(),
                    description: description.into(),
                    required: false,
                    example,
                    default,
                }
            };
        vec![
            p(
                "transport",
                "string",
                "grpc (default) or http; HTTP uses protobuf over HTTP/1.1",
                json!("grpc"),
                Some(json!(super::DEFAULT_TRANSPORT)),
            ),
            p(
                "tls",
                "boolean",
                "Use authenticated TLS (default true); false explicitly selects cleartext",
                json!(true),
                Some(json!(super::DEFAULT_TLS)),
            ),
            p(
                "gzip",
                "boolean",
                "Compress export requests (default false); responses support none/gzip",
                json!(true),
                Some(json!(super::DEFAULT_GZIP)),
            ),
            p(
                "ca_cert_path",
                "string",
                "Operator PEM trust file, at most 1 MiB, added to public roots",
                json!("collector-ca.pem"),
                None,
            ),
            p(
                "server_name",
                "string",
                "TLS certificate name override; default receiver hostname",
                json!("collector.example"),
                None,
            ),
            p(
                "connect_timeout_secs",
                "number",
                "Whole DNS/TCP/TLS/transport connection deadline, 1..60 seconds",
                json!(10),
                Some(json!(super::CONNECT_TIMEOUT.as_secs())),
            ),
            p(
                "export_timeout_secs",
                "number",
                "Whole export and response deadline including queue wait, 1..300 seconds",
                json!(30),
                Some(json!(super::EXPORT_TIMEOUT.as_secs())),
            ),
            p(
                "idle_timeout_secs",
                "number",
                "Inactivity without an export or handler, 1..3600 seconds",
                json!(120),
                Some(json!(super::IDLE_TIMEOUT.as_secs())),
            ),
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};
        ProtocolMetadataV2::builder().state(DevelopmentState::Experimental)
            .implementation("Generated opentelemetry-proto0.29/tonic0.12 unary gRPC exporter and owned hyper HTTP/1.1 protobuf connection; authenticated rustls TLS, optional custom CA and gzip")
            .llm_control("Typed spans, UTF-8 logs and one gauge metric per export; semantic receiver verdicts, partial success and retry hints; injected actions and shared static/script/manual/model handlers")
            .e2e_testing("tests/client/otlp requires official OpenTelemetry Collector0.162.0 for both transports and all three signals; direct NetGet pairing and transport/response/cancellation bounds")
            .notes("128 items/export, 32 scalar attributes/object, 1 MiB encoded export, 4 MiB response before/after inflation, 16 total exports/handlers, four follow-up levels. Socket guard closes internally spawned tonic transport tasks. No automatic retry/reconnect, persistent telemetry, raw protobuf/JSON actions, histogram/sum/exemplar/profile export, span events/links, mTLS or proxy. Expanded subset remains Experimental")
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn get_startup_examples(&self) -> StartupExamples {
        let base = || json!({"type":"open_client","protocol":"otlp","remote_addr":"collector.example:4317","startup_params":{"transport":"grpc","tls":true}});
        let mut llm = base();
        llm["instruction"]=json!("Export a gauge named queue.depth from checkout, with the current Unix timestamp in nanoseconds, then disconnect after its result. Never retry a partial success.");
        let mut script = base();
        script["event_handlers"] = json!([{"event_pattern":"*","handler":{"type":"script","language":"python","code":"import json,sys,time\nt=json.load(sys.stdin)['event_type_id']\na=[]\nif t=='otlp_connected': a=[{'type':'export_otlp_gauge','service_name':'checkout','name':'queue.depth','data_points':[{'value':3,'time_unix_nano':time.time_ns()}]}]\nelif t in ('otlp_export_result','otlp_export_error'): a=[{'type':'disconnect'}]\nprint(json.dumps({'actions':a}))"}}]);
        let mut fixed = base();
        fixed["event_handlers"] = json!([{"event_pattern":"otlp_connected","handler":{"type":"static","actions":[self.get_sync_actions()[2].example.clone()]}},{"event_pattern":"otlp_export_result","handler":{"type":"static","actions":[{"type":"disconnect"}]}},{"event_pattern":"otlp_export_error","handler":{"type":"static","actions":[{"type":"disconnect"}]}}]);
        StartupExamples::new(llm, script, fixed)
    }
}
impl Client for OtlpClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::OtlpClient::connect(ctx))
    }
    fn execute_action(&self, action: Value) -> Result<ClientActionResult> {
        match action["type"].as_str().context("missing type")? {
            "export_otlp_traces" | "export_otlp_logs" | "export_otlp_gauge" => {
                super::wire::build(&action)?;
                Ok(ClientActionResult::Custom {
                    name: "otlp_export".into(),
                    data: action,
                })
            }
            "disconnect" => Ok(ClientActionResult::Disconnect),
            "wait_for_more" => Ok(ClientActionResult::WaitForMore),
            name => bail!("unknown OTLP client action: {name}"),
        }
    }
}

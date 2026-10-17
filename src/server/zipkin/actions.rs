use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter, ParameterDefinition, StartupExamples,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::{EventType, SpawnContext};
use crate::state::app_state::AppState;
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

#[derive(Default)]
pub struct ZipkinProtocol;
impl ZipkinProtocol {
    pub fn new() -> Self {
        Self
    }
}

pub fn parameter(name: &str, kind: &str, description: &str, required: bool) -> Parameter {
    Parameter {
        name: name.into(),
        type_hint: kind.into(),
        description: description.into(),
        required,
    }
}

pub fn action(
    name: &str,
    description: &str,
    parameters: Vec<Parameter>,
    example: Value,
    log: &str,
) -> ActionDefinition {
    ActionDefinition {
        name: name.into(),
        description: description.into(),
        parameters,
        example,
        log_template: Some(LogTemplate::new().with_info(log)),
    }
}

pub const SPAN_NOTE: &str = "Zipkin v2 spans: traceId (16/32 lower-hex), id (16 lower-hex), optional parentId, name, kind CLIENT/SERVER/PRODUCER/CONSUMER, timestamp and duration in microseconds, localEndpoint/remoteEndpoint {serviceName, ipv4, ipv6, port}, annotations [{timestamp, value}], tags {key: value}";

fn accept_action() -> ActionDefinition {
    action(
        "zipkin_accept",
        "Accept the reported spans: the reporter gets 202 Accepted.",
        vec![],
        json!({"type":"zipkin_accept"}),
        "-> Zipkin 202 Accepted",
    )
}

fn reject_action() -> ActionDefinition {
    action(
        "zipkin_reject",
        "Refuse the request with an HTTP error status and a plain-text message.",
        vec![
            parameter(
                "status",
                "number",
                "400, 403, 404, 413, 429, 500 or 503",
                true,
            ),
            parameter(
                "message",
                "string",
                "Plain-text explanation, at most 1024 bytes",
                true,
            ),
        ],
        json!({"type":"zipkin_reject","status":429,"message":"sampling budget exhausted"}),
        "-> Zipkin {status} {message}",
    )
}

fn result_action() -> ActionDefinition {
    action(
        "zipkin_query_result",
        "Answer a query with 200 and a JSON result in the shape the endpoint promises: services, spans, remoteServices and autocomplete* take an array of names; trace takes an array of spans; traces and traceMany an array of traces (each an array of spans); dependencies an array of {parent, child, callCount, errorCount}.",
        vec![parameter("result", "array", SPAN_NOTE, true)],
        json!({"type":"zipkin_query_result","result":["frontend","backend"]}),
        "-> Zipkin query result {preview(result,100)}",
    )
}

pub static SPANS_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "zipkin_spans",
        "A reporter POSTed spans to /api/v2/spans. Accept them (202) or refuse with a status; no answer accepts.",
        accept_action().example.clone(),
    )
    .with_parameters(vec![
        parameter("spans", "array", SPAN_NOTE, true),
        parameter("span_count", "number", "How many spans the report carried", true),
        parameter(
            "services",
            "array",
            "Distinct local service names in the report",
            true,
        ),
        parameter("remote_addr", "string", "Reporter address and port", true),
    ])
    .with_actions(vec![accept_action(), reject_action()])
});

pub static QUERY_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "zipkin_query",
        "A client called the Zipkin read API (GET /api/v2/<endpoint>). Answer with a result in the endpoint's shape, or refuse (404 for an unknown trace).",
        result_action().example.clone(),
    )
    .with_parameters(vec![
        parameter(
            "endpoint",
            "string",
            "services, spans, remoteServices, traces, trace, traceMany, dependencies, autocompleteKeys or autocompleteValues",
            true,
        ),
        parameter(
            "trace_id",
            "string",
            "For endpoint trace: the requested trace id, padded",
            false,
        ),
        parameter(
            "query",
            "object",
            "The query parameters, e.g. {\"serviceName\": \"frontend\"}",
            true,
        ),
        parameter("remote_addr", "string", "Client address and port", true),
    ])
    .with_actions(vec![result_action(), reject_action()])
});

pub fn check_reject(v: &Value) -> Result<()> {
    let status = v["status"].as_u64().context("status required")?;
    ensure!(
        [400, 403, 404, 413, 429, 500, 503].contains(&status),
        "status must be 400, 403, 404, 413, 429, 500 or 503"
    );
    let message = v["message"].as_str().context("message required")?;
    ensure!(
        message.len() <= 1024 && !crate::utils::sanitize::has_controls(message),
        "message must be at most 1024 bytes without control characters"
    );
    Ok(())
}

impl Protocol for ZipkinProtocol {
    fn protocol_name(&self) -> &'static str {
        "Zipkin"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>HTTP>Zipkin"
    }
    fn description(&self) -> &'static str {
        "Zipkin collector and read API: reporters POST v2 spans, the handler accepts them and answers trace queries"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["zipkin", "tracing", "spans", "distributed tracing"]
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![accept_action(), reject_action(), result_action()]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![SPANS_EVENT.clone(), QUERY_EVENT.clone()]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .well_known_port(9411)
            .implementation("HTTP/1.1 via hyper: POST /api/v2/spans (JSON v2, identity or gzip) and the GET /api/v2 read API; spans validated and canonicalised the way zipkin-server does")
            .llm_control("Whether each report is accepted, and every query answer — NetGet stores no spans, so the handler (or its memory) is the storage")
            .e2e_testing("tests/server/zipkin: openzipkin/zipkin-go's HTTP reporter and query decode, and OpenTelemetry Python's Zipkin JSON exporter, as independent clients; bounds and refusals from raw HTTP")
            .notes("JSON v2 only: no proto3, Thrift or v1 endpoint, no TLS, no /api/v2/... UI routes. Bodies are capped at 1 MiB before and after gzip, 1000 spans per report, 256 tags and annotations per span. One request per connection. A handler failure answers 503 with a generic message and never a fabricated result; an empty report is accepted without a handler call.")
            .request_only("Every response answers an HTTP request")
            .answers_on_failure()
            .max_inbound_bytes(super::wire::MAX_BODY_BYTES)
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Zipkin collector on port 9411 that remembers the services it has seen"
    }
    fn get_startup_examples(&self) -> StartupExamples {
        let llm = json!({"type":"open_server","base_stack":"zipkin","port":9411,"instruction":"Accept every report; remember service names and answer /api/v2/services from memory"});
        let mut scripted = llm.clone();
        scripted["event_handlers"] = json!([{"event_pattern":"*","handler":{"type":"script","language":"python","code":"import json,sys\nx=json.load(sys.stdin)\nif x['event_type_id']=='zipkin_spans':\n    a={'type':'zipkin_accept'}\nelse:\n    a={'type':'zipkin_query_result','result':[]}\nprint(json.dumps({'actions':[a]}))"}}]);
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([{"event_pattern":"zipkin_spans","handler":{"type":"static","actions":[{"type":"zipkin_accept"}]}}]);
        StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Network Services"
    }
}

impl Server for ZipkinProtocol {
    fn spawn(
        &self,
        ctx: SpawnContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::spawn(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ActionResult> {
        let name = v["type"].as_str().unwrap_or_default().to_string();
        match name.as_str() {
            "zipkin_accept" => {}
            "zipkin_reject" => check_reject(&v)?,
            // The shape depends on the endpoint, which the answering path checks.
            "zipkin_query_result" => ensure!(v["result"].is_array(), "result must be an array"),
            _ => bail!("Unknown Zipkin server action"),
        }
        Ok(ActionResult::Custom { name, data: v })
    }
}

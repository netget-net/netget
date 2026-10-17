use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, ParameterDefinition, StartupExamples,
};
use crate::protocol::{ConnectContext, EventType};
use crate::server::zipkin::{
    actions::{action, parameter, SPAN_NOTE},
    wire,
};
use crate::state::app_state::AppState;
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

#[derive(Default)]
pub struct ZipkinClientProtocol;
impl ZipkinClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

fn report_action() -> ActionDefinition {
    action(
        "zipkin_report",
        "POST spans to the collector's /api/v2/spans; the outcome arrives as zipkin_report_result.",
        vec![
            parameter("spans", "array", SPAN_NOTE, true),
            parameter(
                "gzip",
                "boolean",
                "Compress the body with gzip (default false)",
                false,
            ),
        ],
        json!({"type":"zipkin_report","spans":[{"traceId":"5af7183fb1d4cf5f","id":"352bff9a74ca9ad2","name":"get /cart","kind":"SERVER","timestamp":1700000000000000u64,"duration":2500,"localEndpoint":{"serviceName":"frontend"},"tags":{"http.method":"GET"}}]}),
        "-> Zipkin report {preview(spans,100)}",
    )
}

fn query_action() -> ActionDefinition {
    action(
        "zipkin_query",
        "GET a read-API endpoint; the answer arrives as zipkin_query_result.",
        vec![
            parameter(
                "endpoint",
                "string",
                "services, spans, remoteServices, traces, trace, traceMany, dependencies, autocompleteKeys or autocompleteValues",
                true,
            ),
            parameter(
                "trace_id",
                "string",
                "Required for endpoint trace: the trace id to fetch",
                false,
            ),
            parameter(
                "query",
                "object",
                "Query parameters the endpoint takes, e.g. {\"serviceName\": \"frontend\"}",
                false,
            ),
        ],
        json!({"type":"zipkin_query","endpoint":"trace","trace_id":"5af7183fb1d4cf5f"}),
        "-> Zipkin query {endpoint}",
    )
}

fn disconnect_action() -> ActionDefinition {
    action(
        "disconnect",
        "End this Zipkin reporter session; no connection stays open between requests.",
        vec![],
        json!({"type":"disconnect"}),
        "-> Zipkin disconnect",
    )
}

pub fn actions() -> Vec<ActionDefinition> {
    vec![report_action(), query_action(), disconnect_action()]
}

pub static CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "zipkin_connected",
        "The reporter is ready; each report or query opens its own HTTP connection.",
        report_action().example.clone(),
    )
    .with_parameters(vec![parameter(
        "remote_addr",
        "string",
        "The collector's HTTP origin",
        true,
    )])
    .with_actions(actions())
});

pub static REPORT_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "zipkin_report_result",
        "The collector answered a report: 202 means accepted.",
        query_action().example.clone(),
    )
    .with_parameters(vec![
        parameter("status", "number", "HTTP status of the report", true),
        parameter("accepted", "boolean", "True when the status is 2xx", true),
        parameter("span_count", "number", "Spans the report carried", true),
        parameter(
            "message",
            "string",
            "The collector's error text, empty on success",
            true,
        ),
    ])
    .with_actions(actions())
});

pub static QUERY_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "zipkin_query_result",
        "The collector answered a query. result holds the decoded, validated JSON on 200.",
        disconnect_action().example.clone(),
    )
    .with_parameters(vec![
        parameter("endpoint", "string", "The endpoint that was queried", true),
        parameter("status", "number", "HTTP status of the query", true),
        parameter(
            "result",
            "array|null",
            "Names, spans, traces or links by endpoint",
            true,
        ),
        parameter(
            "message",
            "string",
            "Error text when status is not 200",
            true,
        ),
    ])
    .with_actions(actions())
});

/// Validate a query action and build its request path.
pub fn query_path(v: &Value) -> Result<(String, wire::Shape)> {
    let endpoint = v["endpoint"].as_str().context("endpoint required")?;
    let (allowed, shape) = wire::endpoint_shape(endpoint).context("unknown Zipkin endpoint")?;
    let mut path = format!("/api/v2/{endpoint}");
    if endpoint == "trace" {
        let id = wire::trace_id(v.get("trace_id").context("trace_id required")?)?;
        path.push('/');
        path.push_str(&id);
    }
    if let Some(q) = v.get("query").filter(|q| !q.is_null()) {
        let q = q.as_object().context("query must be an object")?;
        let mut sep = '?';
        for (k, value) in q {
            ensure!(
                allowed.contains(&k.as_str()),
                "{endpoint} does not take {k}"
            );
            let value = match value {
                Value::String(s) => s.clone(),
                Value::Number(n) => n.to_string(),
                _ => bail!("query values must be strings or numbers"),
            };
            path.push(sep);
            path.push_str(&wire::escape(k));
            path.push('=');
            path.push_str(&wire::escape(&value));
            sep = '&';
        }
    }
    Ok((path, shape))
}

impl Protocol for ZipkinClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "Zipkin"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>HTTP>Zipkin"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["zipkin", "zipkin reporter", "tracing", "spans"]
    }
    fn description(&self) -> &'static str {
        "Zipkin reporter: POSTs v2 spans to a collector and queries its read API"
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        actions()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            CONNECTED_EVENT.clone(),
            REPORT_EVENT.clone(),
            QUERY_EVENT.clone(),
        ]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation("HTTP/1.1 via hyper, one connection per request: POST /api/v2/spans (JSON v2, optional gzip) and GET on the read API, with spans validated before sending and after receiving")
            .llm_control("Which spans to report and which queries to run, and what to do with each answer")
            .e2e_testing("tests/client/zipkin: the official Zipkin server (zipkin-server 3.5.1, in-memory storage) and Jaeger all-in-one's Zipkin collector, each read back through its own query API")
            .notes("JSON v2 only, cleartext HTTP. Request and response bodies are capped at 1 MiB, reports at 1000 spans. A handler chain stops after 8 follow-ups.")
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Report a two-span trace to the Zipkin collector at localhost:9411, then fetch it back"
    }
    fn get_startup_examples(&self) -> StartupExamples {
        let llm = json!({"type":"open_client","protocol":"zipkin","remote_addr":"127.0.0.1:9411","instruction":"Report one SERVER span for service frontend, then list the services"});
        let mut scripted = llm.clone();
        scripted["event_handlers"] = json!([{"event_pattern":"zipkin_connected","handler":{"type":"script","language":"python","code":"import json\nprint(json.dumps({'actions':[{'type':'zipkin_query','endpoint':'services'}]}))"}}]);
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([{"event_pattern":"zipkin_connected","handler":{"type":"static","actions":[{"type":"zipkin_query","endpoint":"services"}]}}]);
        StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Network Services"
    }
}

impl Client for ZipkinClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::connect(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ClientActionResult> {
        let name = v["type"].as_str().unwrap_or_default().to_string();
        match name.as_str() {
            "disconnect" => return Ok(ClientActionResult::Disconnect),
            "zipkin_report" => {
                let spans = wire::spans(v.get("spans").context("spans required")?)?;
                ensure!(!spans.is_empty(), "spans must not be empty");
                ensure!(
                    v.get("gzip").is_none_or(|g| g.is_null() || g.is_boolean()),
                    "gzip must be a boolean"
                );
            }
            "zipkin_query" => {
                query_path(&v)?;
            }
            _ => bail!("Unknown Zipkin client action"),
        }
        Ok(ClientActionResult::Custom { name, data: v })
    }
}

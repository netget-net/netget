//! What the model decides as a server-sent-events server: which requests get a stream, what
//! each stream carries, and what is broadcast to every subscriber. Rust owns the HTTP framing,
//! the event-stream encoding, keep-alive comments and the subscriber table.
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

pub const ACCEPT: &str = "sse_accept";
pub const EVENT: &str = "sse_event";
pub const COMMENT: &str = "sse_comment";
pub const CLOSE: &str = "sse_close";
pub const RESPOND: &str = "sse_respond";
pub const BROADCAST: &str = "sse_broadcast";
/// How often an idle stream gets a keep-alive comment.
pub const KEEPALIVE_SECS: u64 = 15;
/// A `retry:` hint at most (one hour), in milliseconds.
pub const MAX_RETRY_MS: u64 = 3_600_000;

#[derive(Default)]
pub struct SseProtocol;
impl SseProtocol {
    pub fn new() -> Self {
        Self
    }
}

pub fn p(name: &str, kind: &str, description: &str, required: bool) -> Parameter {
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
) -> ActionDefinition {
    ActionDefinition {
        name: name.into(),
        description: description.into(),
        parameters,
        example,
        log_template: Some(LogTemplate::new().with_info(format!("-> SSE {name}"))),
    }
}

fn event_params() -> Vec<Parameter> {
    vec![
        p(
            "data",
            "string",
            "The event's data; each line of it becomes one data: line",
            true,
        ),
        p(
            "event",
            "string",
            "The event type (the client's addEventListener name); omitted means message",
            false,
        ),
        p(
            "id",
            "string",
            "The event ID; a reconnecting client sends the last one back as Last-Event-ID",
            false,
        ),
    ]
}

pub fn actions() -> Vec<ActionDefinition> {
    vec![
        action(
            ACCEPT,
            "Answer the request with an event stream (200 text/event-stream) and keep it open. Events in the same answer follow at once",
            vec![p("retry_ms", "number", "Tell the client how long to wait before reconnecting, in milliseconds", false)],
            json!({"type": ACCEPT, "retry_ms": 3000}),
        ),
        action(
            EVENT,
            "Send one event on this stream (accepting the request first if it is not a stream yet)",
            event_params(),
            json!({"type": EVENT, "event": "update", "id": "1", "data": "hello"}),
        ),
        action(
            COMMENT,
            "Send a comment line, which clients ignore",
            vec![p("text", "string", "The comment, one line", true)],
            json!({"type": COMMENT, "text": "still here"}),
        ),
        action(
            CLOSE,
            "End this stream. A browser EventSource reconnects after its retry delay with Last-Event-ID",
            vec![],
            json!({"type": CLOSE}),
        ),
        action(
            RESPOND,
            "Answer with an ordinary HTTP response instead of a stream: 204 tells an EventSource to stop reconnecting, 401/404 refuse",
            vec![
                p("status", "number", "HTTP status, 200-599", true),
                p("body", "string", "Response body text (default empty)", false),
                p("content_type", "string", "Content-Type of the body (default text/plain; charset=utf-8)", false),
            ],
            json!({"type": RESPOND, "status": 404, "body": "no such stream"}),
        ),
        action(
            BROADCAST,
            "Send one event to every open stream (or only those on one path)",
            {
                let mut v = event_params();
                v.push(p("path", "string", "Only streams opened on this path, e.g. /news (default every stream)", false));
                v
            },
            json!({"type": BROADCAST, "path": "/news", "event": "post", "id": "7", "data": "new article"}),
        ),
    ]
}

pub static REQUEST_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "sse_request",
        "An HTTP request arrived: answer it with a stream (sse_accept and events), an ordinary response, or a broadcast",
        json!({"type": ACCEPT}),
    )
    .with_parameters(vec![
        p("method", "string", "The HTTP method (GET or HEAD)", true),
        p("path", "string", "The request path without the query, e.g. /news", true),
        p("query", "object", "The query string's parameters", true),
        p("last_event_id", "string", "Last-Event-ID a reconnecting client sent (the last event ID it saw), empty on a first connection", true),
        p("accept", "string", "The Accept header (an EventSource sends text/event-stream)", false),
        p("user_agent", "string", "The User-Agent header", false),
        p("client_ip", "string", "Where the request came from", true),
    ])
    .with_actions(actions())
});

pub fn check(v: &Value) -> Result<()> {
    let text = |k: &str, required: bool| -> Result<Option<String>> {
        match v.get(k).filter(|x| !x.is_null()) {
            Some(Value::String(s)) => Ok(Some(s.clone())),
            Some(other) => Ok(Some(other.to_string())),
            None => {
                ensure!(!required, "{k} is required");
                Ok(None)
            }
        }
    };
    match v["type"].as_str().unwrap_or_default() {
        ACCEPT => {
            if let Some(r) = v.get("retry_ms").filter(|x| !x.is_null()) {
                ensure!(
                    r.as_u64().is_some_and(|r| r <= MAX_RETRY_MS),
                    "retry_ms is 0..={MAX_RETRY_MS}"
                );
            }
        }
        EVENT | BROADCAST => {
            let data = text("data", true)?.unwrap_or_default();
            super::wire::encode_event(
                text("event", false)?.as_deref(),
                text("id", false)?.as_deref(),
                &data,
                None,
            )?;
            if let Some(path) = text("path", false)? {
                ensure!(
                    path.starts_with('/') && path.len() <= 2048,
                    "path starts with /"
                );
            }
        }
        COMMENT => {
            super::wire::encode_comment(&text("text", true)?.unwrap_or_default())?;
        }
        CLOSE => {}
        RESPOND => {
            let status = v["status"].as_u64().context("status is a number")?;
            ensure!((200..=599).contains(&status), "status is 200..=599");
            if let Some(ct) = text("content_type", false)? {
                ensure!(!ct.contains(['\r', '\n']), "content_type is one line");
            }
            ensure!(
                text("body", false)?.is_none_or(|b| b.len() <= 1024 * 1024),
                "body is at most 1 MiB"
            );
        }
        other => bail!("Unknown SSE action {other:?}"),
    }
    Ok(())
}

/// The encoded event for `sse_event`/`sse_broadcast`.
pub fn encode(v: &Value) -> Result<Vec<u8>> {
    let s = |k: &str| match v.get(k) {
        Some(Value::String(s)) => Some(s.clone()),
        Some(Value::Null) | None => None,
        Some(other) => Some(other.to_string()),
    };
    super::wire::encode_event(
        s("event").as_deref(),
        s("id").as_deref(),
        &s("data").unwrap_or_default(),
        None,
    )
}

impl Protocol for SseProtocol {
    fn protocol_name(&self) -> &'static str {
        "SSE"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>HTTP>SSE"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "sse",
            "server-sent events",
            "eventsource",
            "event stream",
            "text/event-stream",
        ]
    }
    fn description(&self) -> &'static str {
        "Server-sent events server: streams events to EventSource clients, per stream and by broadcast"
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        actions()
            .into_iter()
            .filter(|a| a.name == BROADCAST)
            .collect()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        actions()
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![REQUEST_EVENT.clone()]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![ParameterDefinition {
            name: "keepalive_secs".into(),
            type_hint: "number".into(),
            description: "Seconds (1..=3600) an open stream may be silent before a keep-alive comment is sent".into(),
            required: false,
            example: json!(15),
            default: Some(json!(KEEPALIVE_SECS)),
        }]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation("Hand-rolled HTTP/1.1 over Tokio TCP: one request per connection, answered with a text/event-stream kept open (keep-alive comments, retry hints) or an ordinary response; WHATWG event-stream encoding; a per-server subscriber table for broadcasts; each stream registered as a peer for injected events")
            .llm_control("Which requests get a stream, what each stream says and when it ends, and what is broadcast to every subscriber")
            .e2e_testing("tests/server/sse: the eventsource npm package (WHATWG EventSource, reconnecting with Last-Event-ID) and Python's httpx-sse read NetGet's streams, broadcasts and injected events")
            .notes("HTTP/1.1 only, no TLS, no request bodies (GET/HEAD); one request per connection. Request heads are capped at 16 KiB and 10 s; event data at 1 MiB.")
            .answers_on_failure()
            .max_inbound_bytes(super::MAX_REQUEST_HEAD_BYTES)
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Event stream on port 8080 that greets each subscriber of /news and broadcasts whatever is posted to /post?msg="
    }
    fn get_startup_examples(&self) -> StartupExamples {
        let llm = json!({"type":"open_server","base_stack":"sse","port":8080,
            "instruction":"Stream /news: greet each subscriber with an event. A request to /post?msg=X broadcasts X to /news and answers 202"});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([{"event_pattern":"sse_request","handler":{"type":"static","actions":[
            {"type":ACCEPT,"retry_ms":3000},{"type":EVENT,"event":"welcome","id":"1","data":"hello"}]}}]);
        let mut scripted = llm.clone();
        scripted["event_handlers"] = json!([{"event_pattern":"*","handler":{"type":"script","language":"python",
            "code":"import json,sys\ne=json.load(sys.stdin)['event']\nif e['path']=='/post':\n  a=[{'type':'sse_broadcast','path':'/news','data':e['query'].get('msg','')},{'type':'sse_respond','status':202}]\nelse:\n  a=[{'type':'sse_accept'},{'type':'sse_event','data':'welcome'}]\nprint(json.dumps({'actions':a}))"}}]);
        StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Web & File"
    }
}

impl Server for SseProtocol {
    fn spawn(
        &self,
        ctx: SpawnContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::spawn(ctx))
    }

    fn execute_action_with_state<'a>(
        &'a self,
        action: Value,
        state: AppState,
        server_id: Option<crate::state::ServerId>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<ActionResult>> + Send + 'a>>
    {
        if action["type"].as_str() != Some(BROADCAST) {
            let result = self.execute_action(action);
            return Box::pin(async move { result });
        }
        Box::pin(async move {
            check(&action)?;
            let id = server_id.context("sse_broadcast needs the running SSE server")?;
            let bytes = encode(&action)?;
            let delivered = super::broadcast(&state, id, action["path"].as_str(), &bytes).await;
            Ok(ActionResult::Custom {
                name: BROADCAST.into(),
                data: json!({"delivered": delivered}),
            })
        })
    }

    fn execute_action(&self, action: Value) -> Result<ActionResult> {
        check(&action)?;
        Ok(match action["type"].as_str().unwrap_or_default() {
            EVENT => ActionResult::Output(encode(&action)?),
            COMMENT => ActionResult::Output(super::wire::encode_comment(
                action["text"].as_str().unwrap_or_default(),
            )?),
            CLOSE => ActionResult::CloseConnection,
            name => ActionResult::Custom {
                name: name.into(),
                data: action,
            },
        })
    }
}

//! What the model does as a server-sent-events client: hear each event of a stream, and decide
//! whether to reconnect or stop. Rust owns the HTTP request, the event-stream parsing, and the
//! reconnects with Last-Event-ID that EventSource makes.
use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, ParameterDefinition, StartupExamples,
};
use crate::protocol::{ConnectContext, EventType};
use crate::server::sse::actions::{action, p};
use crate::state::app_state::AppState;
use anyhow::{bail, ensure, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

pub const RECONNECT: &str = "sse_reconnect";

#[derive(Default)]
pub struct SseClientProtocol;
impl SseClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

pub fn actions() -> Vec<ActionDefinition> {
    vec![
        action(
            RECONNECT,
            "Drop the stream and open it again now, sending Last-Event-ID so the server can resume",
            vec![p(
                "last_event_id",
                "string",
                "The Last-Event-ID to send (default the last event ID seen)",
                false,
            )],
            json!({"type": RECONNECT}),
        ),
        action(
            "disconnect",
            "Close the stream and stop; no further reconnects",
            vec![],
            json!({"type": "disconnect"}),
        ),
    ]
}

fn event(id: &str, description: &str, params: Vec<crate::llm::actions::Parameter>) -> EventType {
    EventType::new(id, description, json!({"type": "disconnect"}))
        .with_parameters(params)
        .with_actions(actions())
}

pub static CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event(
        "sse_connected",
        "The stream opened (200 text/event-stream).",
        vec![
            p(
                "url",
                "string",
                "The stream URL this connection requested",
                true,
            ),
            p(
                "last_event_id",
                "string",
                "The Last-Event-ID this connection sent (empty on the first)",
                true,
            ),
            p(
                "attempt",
                "number",
                "Which connection this is: 1 for the first, more after reconnects",
                true,
            ),
        ],
    )
});

pub static MESSAGE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event(
        "sse_event_received",
        "An event arrived on the stream.",
        vec![
            p(
                "event",
                "string",
                "The event type (message when the server named none)",
                true,
            ),
            p(
                "data",
                "string",
                "The event's data, lines joined with newlines",
                true,
            ),
            p(
                "id",
                "string",
                "The last event ID after this event (sent back as Last-Event-ID on a reconnect)",
                true,
            ),
        ],
    )
});

pub static ENDED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event(
        "sse_stream_ended",
        "The stream stopped: it closed, the server refused it, or reconnects ran out.",
        vec![
            p(
                "reason",
                "string",
                "closed, refused, error or no_more_reconnects",
                true,
            ),
            p(
                "status",
                "number",
                "The HTTP status when the server refused (204 means stop for good)",
                false,
            ),
            p("body", "string", "The start of a refusal's body", false),
            p("error", "string", "What failed, for an error", false),
            p(
                "reconnecting_in_ms",
                "number",
                "Set when the client will reconnect by itself after this long",
                false,
            ),
        ],
    )
});

pub fn check(v: &Value) -> Result<()> {
    match v["type"].as_str().unwrap_or_default() {
        RECONNECT => {
            if let Some(id) = v.get("last_event_id").filter(|x| !x.is_null()) {
                let id = id.as_str().unwrap_or_default();
                ensure!(
                    id.len() <= 1024 && !id.contains(['\r', '\n', '\0']),
                    "last_event_id is one line"
                );
            }
        }
        other => bail!("Unknown SSE client action {other:?}"),
    }
    Ok(())
}

impl Protocol for SseClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "SSE"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>HTTP>SSE"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "sse client",
            "eventsource",
            "server-sent events",
            "event stream",
        ]
    }
    fn description(&self) -> &'static str {
        "Server-sent events client: reads an event stream like EventSource, reconnecting with Last-Event-ID"
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
            MESSAGE_EVENT.clone(),
            ENDED_EVENT.clone(),
        ]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "last_event_id".into(),
                type_hint: "string".into(),
                description: "Last-Event-ID to send on the first connection, to resume a stream"
                    .into(),
                required: false,
                example: json!("42"),
                default: None,
            },
            ParameterDefinition {
                name: "max_reconnects".into(),
                type_hint: "number".into(),
                description: "How many times (0..=100) a closed stream is reopened by itself"
                    .into(),
                required: false,
                example: json!(5),
                default: Some(json!(super::MAX_RECONNECTS)),
            },
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation("Hand-rolled HTTP/1.1 GET over Tokio TCP (Content-Length, chunked and close-delimited bodies), the WHATWG event-stream parser shared with the SSE server, and EventSource's reconnects: the server's retry hint, Last-Event-ID, no reconnect after a 204 or any other refusal")
            .llm_control("What to make of each event, and whether to reconnect or stop")
            .e2e_testing("tests/client/sse: sse-starlette (Starlette under uvicorn) and aiohttp-sse streams, each closing mid-stream so the reconnect's Last-Event-ID is checked on the server")
            .notes("http:// only (no TLS), no redirects, no request headers beyond Accept, Cache-Control and Last-Event-ID. Lines are capped at 64 KiB and an event's data at 1 MiB. A handler chain stops after 8 follow-ups.")
            .max_inbound_bytes(crate::server::sse::wire::MAX_EVENT_BYTES)
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            // Stream events that arrive while the model answers are read and parsed during the
            // call and answered together in the next one (`client/sse/mod.rs`).
            .batching(crate::protocol::metadata::BatchingMode::On)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Subscribe to http://127.0.0.1:8080/news and tell me each headline as it arrives"
    }
    fn get_startup_examples(&self) -> StartupExamples {
        let llm = json!({"type":"open_client","protocol":"sse","remote_addr":"http://127.0.0.1:8080/news",
            "instruction":"Report each event; disconnect after an event of type bye"});
        let mut static_example = llm.clone();
        static_example["event_handlers"] =
            json!([{"event_pattern":"*","handler":{"type":"static","actions":[]}}]);
        let mut scripted = llm.clone();
        scripted["event_handlers"] = json!([{"event_pattern":"*","handler":{"type":"script","language":"python",
            "code":"import json,sys\ni=json.load(sys.stdin)\nbye=i['event_type_id']=='sse_event_received' and i['event']['event']=='bye'\nprint(json.dumps({'actions':[{'type':'disconnect'}] if bye else []}))"}}]);
        StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Web & File"
    }
}

impl Client for SseClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::connect(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ClientActionResult> {
        let name = v["type"].as_str().unwrap_or_default().to_string();
        if name == "disconnect" {
            return Ok(ClientActionResult::Disconnect);
        }
        check(&v)?;
        Ok(ClientActionResult::Custom { name, data: v })
    }
}

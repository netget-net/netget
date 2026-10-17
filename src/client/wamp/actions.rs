use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, ParameterDefinition,
};
use crate::protocol::{ConnectContext, EventType};
use crate::server::wamp::actions::{action, parameter, payload_params};
use crate::server::wamp::uri::uri_ok;
use anyhow::{bail, ensure, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

#[derive(Default)]
pub struct WampClientProtocol;
impl WampClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

fn with_payload(mut p: Vec<crate::llm::actions::Parameter>) -> Vec<crate::llm::actions::Parameter> {
    p.extend(payload_params());
    p
}

fn subscribe() -> ActionDefinition {
    action(
        "wamp_subscribe",
        "Subscribe to a topic; events arrive as wamp_event",
        vec![parameter("topic", "string", "Topic URI, or pattern for prefix / wildcard matching (wildcard: empty components match anything, e.g. com..update)", true), parameter("match", "string", "exact (default), prefix or wildcard", false)],
        json!({"type": "wamp_subscribe", "topic": "com.example.tick"}),
    )
}
fn unsubscribe() -> ActionDefinition {
    action(
        "wamp_unsubscribe",
        "Remove this session's subscription to a topic",
        vec![parameter(
            "topic",
            "string",
            "The topic (or pattern) subscribed to",
            true,
        )],
        json!({"type": "wamp_unsubscribe", "topic": "com.example.tick"}),
    )
}
fn publish() -> ActionDefinition {
    action(
        "wamp_publish",
        "Publish an event to a topic",
        with_payload(vec![
            parameter(
                "topic",
                "string",
                "Topic URI, dot-separated, e.g. com.example.news",
                true,
            ),
            parameter(
                "acknowledge",
                "boolean",
                "Ask the router to confirm with PUBLISHED (default true)",
                false,
            ),
            parameter(
                "exclude_me",
                "boolean",
                "Leave this session out even if subscribed (default true)",
                false,
            ),
        ]),
        json!({"type": "wamp_publish", "topic": "com.example.news", "args": ["hello"]}),
    )
}
fn call() -> ActionDefinition {
    action(
        "wamp_call",
        "Call a procedure; the answer arrives as wamp_reply",
        with_payload(vec![parameter(
            "procedure",
            "string",
            "Procedure URI, dot-separated, e.g. com.example.add2",
            true,
        )]),
        json!({"type": "wamp_call", "procedure": "com.example.add2", "args": [2, 3]}),
    )
}
fn register() -> ActionDefinition {
    action(
        "wamp_register",
        "Register a procedure this session answers; calls arrive as wamp_invocation",
        vec![parameter(
            "procedure",
            "string",
            "Procedure URI, dot-separated, e.g. com.example.add2",
            true,
        )],
        json!({"type": "wamp_register", "procedure": "com.example.echo"}),
    )
}
fn unregister() -> ActionDefinition {
    action(
        "wamp_unregister",
        "Withdraw a procedure this session registered",
        vec![parameter(
            "procedure",
            "string",
            "Procedure URI, dot-separated, e.g. com.example.add2",
            true,
        )],
        json!({"type": "wamp_unregister", "procedure": "com.example.echo"}),
    )
}
fn yield_() -> ActionDefinition {
    action(
        "wamp_yield",
        "Answer an invocation with its result",
        with_payload(vec![parameter(
            "invocation",
            "number",
            "The invocation's request ID from wamp_invocation (default: the oldest unanswered)",
            false,
        )]),
        json!({"type": "wamp_yield", "args": ["echo"]}),
    )
}
fn error() -> ActionDefinition {
    action(
        "wamp_error",
        "Answer an invocation with an error",
        with_payload(vec![
            parameter(
                "error",
                "string",
                "Error URI, e.g. com.example.error.invalid_input",
                true,
            ),
            parameter(
                "invocation",
                "number",
                "The invocation's request ID from wamp_invocation (default: the oldest unanswered)",
                false,
            ),
        ]),
        json!({"type": "wamp_error", "error": "com.example.error.invalid_input", "args": ["bad input"]}),
    )
}
fn goodbye() -> ActionDefinition {
    action(
        "wamp_goodbye",
        "Leave the realm with GOODBYE and close",
        vec![],
        json!({"type": "wamp_goodbye"}),
    )
}
fn disconnect() -> ActionDefinition {
    action(
        "disconnect",
        "Close the WebSocket without a GOODBYE",
        vec![],
        json!({"type": "disconnect"}),
    )
}
fn actions() -> Vec<ActionDefinition> {
    vec![
        subscribe(),
        unsubscribe(),
        publish(),
        call(),
        register(),
        unregister(),
        yield_(),
        error(),
        goodbye(),
        disconnect(),
    ]
}

pub static WELCOME_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "wamp_welcome",
        "The router admitted this session to the realm",
        subscribe().example.clone(),
    )
    .with_parameters(vec![
        parameter("session", "number", "This session's WAMP ID", true),
        parameter("realm", "string", "The realm joined", true),
        parameter(
            "roles",
            "array",
            "Router roles announced: broker and/or dealer",
            true,
        ),
    ])
    .with_actions(actions())
});
pub static REPLY_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "wamp_reply",
        "The router's answer to a subscribe, unsubscribe, publish, call, register or unregister",
        json!({"type": "wamp_goodbye"}),
    )
    .with_parameters(vec![
        parameter(
            "operation",
            "string",
            "subscribe, unsubscribe, publish, call, register or unregister",
            true,
        ),
        parameter("target", "string", "The topic or procedure", true),
        parameter(
            "ok",
            "boolean",
            "false when the router answered ERROR",
            true,
        ),
        parameter("args", "array", "call: result or error arguments", false),
        parameter(
            "kwargs",
            "object",
            "call: result or error keyword arguments",
            false,
        ),
        parameter("error", "string", "The error URI when ok is false", false),
    ])
    .with_actions(actions())
});
pub static EVENT_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "wamp_event",
        "An event published to a topic this session subscribed to",
        json!({"type": "wamp_publish", "topic": "com.example.seen", "args": ["got it"]}),
    )
    .with_parameters(vec![
        parameter(
            "topic",
            "string",
            "The topic (the subscription's, or the actual topic for pattern subscriptions)",
            true,
        ),
        parameter("args", "array", "Positional arguments", true),
        parameter("kwargs", "object", "Keyword arguments", true),
        parameter(
            "publication",
            "number",
            "The router's ID for this publication (the same for every subscriber that received it)",
            true,
        ),
    ])
    .with_actions(actions())
});
pub static INVOCATION_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new("wamp_invocation", "A call to a procedure this session registered; answer with wamp_yield or wamp_error (no answer is wamp.error.unavailable)", yield_().example.clone())
        .with_parameters(vec![
            parameter("invocation", "number", "Request ID to answer", true),
            parameter("procedure", "string", "The procedure called", true),
            parameter("args", "array", "Positional arguments", true),
            parameter("kwargs", "object", "Keyword arguments", true),
        ])
        .with_actions(vec![yield_(), error()])
});
pub static LEFT_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "wamp_left",
        "The session ended",
        disconnect().example.clone(),
    )
    .with_parameters(vec![parameter(
        "reason",
        "string",
        "GOODBYE / ABORT reason URI or why the connection closed",
        true,
    )])
    .with_actions(vec![disconnect()])
});

impl Protocol for WampClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "WAMP"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>HTTP>WebSocket>WAMP"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "wamp",
            "web application messaging protocol",
            "rpc",
            "pubsub",
            "caller",
            "callee",
            "subscriber",
        ]
    }
    fn description(&self) -> &'static str {
        "WAMP v2 client (JSON over WebSocket) in all four roles: caller, callee, publisher, subscriber"
    }
    fn get_async_actions(&self, _: &crate::state::app_state::AppState) -> Vec<ActionDefinition> {
        actions()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            WELCOME_EVENT.clone(),
            REPLY_EVENT.clone(),
            EVENT_EVENT.clone(),
            INVOCATION_EVENT.clone(),
            LEFT_EVENT.clone(),
        ]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        let p =
            |name: &str, kind: &str, description: &str, example: Value, default: Option<Value>| {
                ParameterDefinition {
                    name: name.into(),
                    type_hint: kind.into(),
                    description: description.into(),
                    required: false,
                    example,
                    default,
                }
            };
        vec![
            p(
                "realm",
                "string",
                "Realm (routing domain) to join, as a URI, e.g. realm1",
                json!("realm1"),
                Some(json!(super::DEFAULT_REALM)),
            ),
            p(
                "path",
                "string",
                "WebSocket path on the router",
                json!("/ws"),
                Some(json!(super::DEFAULT_PATH)),
            ),
            p(
                "authid",
                "string",
                "authid to announce in HELLO (anonymous authentication)",
                json!("netget"),
                None,
            ),
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation("tokio-tungstenite with the wamp.2.json subprotocol; hand-written WAMP v2 basic-profile session in all four roles")
            .llm_control("What to call, publish, subscribe and register, and the answer to every invocation of a registered procedure")
            .e2e_testing("tests/client/wamp: the nexus 3.3.0 router (Go; independent) with a nexus callee, publisher and subscriber: call, error, subscribe, publish, register and answer invocations")
            .notes("JSON serializer only; anonymous authentication; ws:// only; no progressive results or cancellation.")
            .max_inbound_bytes(crate::server::wamp::MAX_MESSAGE)
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Join realm1 on the WAMP router at 127.0.0.1:8080 and call com.example.add2 with 2 and 3"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let llm = json!({"type":"open_client","protocol":"wamp","remote_addr":"127.0.0.1:8080","instruction":"Call com.example.add2 with 2 and 3","startup_params":{"realm":"realm1"}});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([
            {"event_pattern":"wamp_welcome","handler":{"type":"static","actions":[call().example]}},
            {"event_pattern":"wamp_invocation","handler":{"type":"static","actions":[{"type":"wamp_error","error":"wamp.error.no_such_procedure"}]}},
            {"event_pattern":"*","handler":{"type":"static","actions":[]}}
        ]);
        let mut scripted = static_example.clone();
        scripted["event_handlers"][1]["handler"] = json!({"type":"script","language":"python","code":"import json,sys\ne=json.load(sys.stdin)['event']\nprint(json.dumps({'actions':[{'type':'wamp_yield','invocation':e['invocation'],'args':e['args']}]}))"});
        crate::llm::actions::StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Application"
    }
}

fn payload_ok(v: &Value) -> Result<()> {
    if let Some(a) = v.get("args").filter(|a| !a.is_null()) {
        ensure!(a.is_array(), "args is an array");
    }
    if let Some(k) = v.get("kwargs").filter(|k| !k.is_null()) {
        ensure!(k.is_object(), "kwargs is an object");
    }
    Ok(())
}

impl Client for WampClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::connect(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ClientActionResult> {
        ensure!(
            crate::utils::json_budget::within_budget(&v, 1024 * 1024, 100_000, 32),
            "action exceeds the WAMP bounds"
        );
        let s = |k: &str, empty_ok: bool| v[k].as_str().is_some_and(|u| uri_ok(u, empty_ok));
        match v["type"].as_str() {
            Some("wamp_subscribe") => {
                let policy = v["match"].as_str().unwrap_or("exact");
                ensure!(
                    matches!(policy, "exact" | "prefix" | "wildcard"),
                    "match is exact, prefix or wildcard"
                );
                ensure!(s("topic", policy == "wildcard"), "topic is a URI");
            }
            Some("wamp_unsubscribe") => ensure!(
                v["topic"].as_str().is_some_and(|t| !t.is_empty()),
                "topic is required"
            ),
            Some("wamp_publish") => {
                ensure!(s("topic", false), "topic is a URI");
                payload_ok(&v)?;
            }
            Some("wamp_call") => {
                ensure!(s("procedure", false), "procedure is a URI");
                payload_ok(&v)?;
            }
            Some("wamp_register" | "wamp_unregister") => {
                ensure!(s("procedure", false), "procedure is a URI")
            }
            Some("wamp_yield") => payload_ok(&v)?,
            Some("wamp_error") => {
                ensure!(s("error", false), "error is an error URI");
                payload_ok(&v)?;
            }
            Some("wamp_goodbye") => {}
            Some("disconnect") => return Ok(ClientActionResult::Disconnect),
            _ => bail!("Unknown WAMP client action"),
        }
        Ok(ClientActionResult::Custom {
            name: v["type"].as_str().unwrap_or_default().into(),
            data: v,
        })
    }
}

use super::uri;
use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter, ParameterDefinition,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::{EventType, SpawnContext};
use crate::state::app_state::AppState;
use anyhow::{bail, ensure, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

#[derive(Default)]
pub struct WampProtocol;
impl WampProtocol {
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
) -> ActionDefinition {
    ActionDefinition {
        name: name.into(),
        description: description.into(),
        parameters,
        example,
        log_template: Some(LogTemplate::new().with_info(format!("-> WAMP {name}"))),
    }
}

pub fn payload_params() -> Vec<Parameter> {
    vec![
        parameter(
            "args",
            "array",
            "Positional arguments (any JSON values)",
            false,
        ),
        parameter(
            "kwargs",
            "object",
            "Keyword arguments (a JSON object)",
            false,
        ),
    ]
}

fn welcome() -> ActionDefinition {
    action(
        "wamp_welcome",
        "Admit the session to the realm; Rust sends WELCOME with a new session ID and the broker and dealer roles",
        vec![parameter("authrole", "string", "Role to announce in WELCOME (default anonymous)", false)],
        json!({"type": "wamp_welcome", "authrole": "user"}),
    )
}
fn abort() -> ActionDefinition {
    action(
        "wamp_abort",
        "Refuse the session with ABORT and close",
        vec![
            parameter(
                "reason",
                "string",
                "Error URI, e.g. wamp.error.no_such_realm or wamp.error.not_authorized",
                true,
            ),
            parameter(
                "message",
                "string",
                "Human-readable message, up to 256 characters",
                false,
            ),
        ],
        json!({"type": "wamp_abort", "reason": "wamp.error.no_such_realm", "message": "this router serves realm1 only"}),
    )
}
pub fn result() -> ActionDefinition {
    action(
        "wamp_result",
        "Answer the call with RESULT carrying these arguments",
        payload_params(),
        json!({"type": "wamp_result", "args": [5], "kwargs": {}}),
    )
}
pub fn error() -> ActionDefinition {
    let mut p = vec![parameter(
        "error",
        "string",
        "Error URI, e.g. com.example.error.invalid_input or wamp.error.no_such_procedure",
        true,
    )];
    p.extend(payload_params());
    action(
        "wamp_error",
        "Answer the call with ERROR",
        p,
        json!({"type": "wamp_error", "error": "com.example.error.invalid_input", "args": ["a and b must be numbers"]}),
    )
}
pub fn publish() -> ActionDefinition {
    let mut p = vec![parameter(
        "topic",
        "string",
        "Topic URI to publish to in this session's realm",
        true,
    )];
    p.extend(payload_params());
    action("wamp_publish", "Publish an event from the router to every session subscribed to a matching topic in this session's realm", p, json!({"type": "wamp_publish", "topic": "com.example.news", "args": ["router says hello"]}))
}

pub static HELLO_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new("wamp_hello", "A client asks to join a realm (HELLO). The WebSocket subprotocol and message shape were checked by Rust.", welcome().example.clone())
        .with_parameters(vec![
            parameter("realm", "string", "Realm URI requested", true),
            parameter("roles", "array", "Roles the client announced: caller, callee, publisher, subscriber", true),
            parameter("authid", "string", "authid the client offered, when any", false),
            parameter("authmethods", "array", "Authentication methods offered (only anonymous is supported)", false),
        ])
        .with_actions(vec![welcome(), abort()])
});
pub static CALL_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new("wamp_call", "A CALL to a procedure no session in the realm has registered; the router itself answers it", result().example.clone())
        .with_parameters(vec![
            parameter("realm", "string", "The caller's realm", true),
            parameter("procedure", "string", "Procedure URI called", true),
            parameter("args", "array", "Positional arguments", true),
            parameter("kwargs", "object", "Keyword arguments", true),
            parameter("caller_session", "number", "The caller's WAMP session ID", true),
        ])
        .with_actions(vec![result(), error()])
});

fn payload_ok(v: &Value) -> Result<()> {
    if let Some(a) = v.get("args").filter(|a| !a.is_null()) {
        ensure!(a.is_array(), "args is an array");
    }
    if let Some(k) = v.get("kwargs").filter(|k| !k.is_null()) {
        ensure!(k.is_object(), "kwargs is an object");
    }
    Ok(())
}

pub fn check_answer(v: &Value) -> Result<()> {
    ensure!(
        crate::utils::json_budget::within_budget(v, 1024 * 1024, 100_000, 32),
        "answer exceeds the WAMP bounds"
    );
    match v["type"].as_str() {
        Some("wamp_welcome") => {
            if let Some(r) = v.get("authrole").filter(|r| !r.is_null()) {
                ensure!(
                    r.as_str().is_some_and(|r| uri::uri_ok(r, false)),
                    "authrole is a URI-like name"
                );
            }
        }
        Some("wamp_abort") => {
            ensure!(
                v["reason"].as_str().is_some_and(|r| uri::uri_ok(r, false)),
                "reason is an error URI"
            );
            if let Some(m) = v.get("message").filter(|m| !m.is_null()) {
                ensure!(
                    m.as_str().is_some_and(
                        |m| m.len() <= 256 && !crate::utils::sanitize::has_controls(&m)
                    ),
                    "message is up to 256 printable characters"
                );
            }
        }
        Some("wamp_result") => payload_ok(v)?,
        Some("wamp_error") => {
            ensure!(
                v["error"].as_str().is_some_and(|e| uri::uri_ok(e, false)),
                "error is an error URI"
            );
            payload_ok(v)?;
        }
        Some("wamp_publish") => {
            ensure!(
                v["topic"].as_str().is_some_and(|t| uri::uri_ok(t, false)),
                "topic is a URI"
            );
            payload_ok(v)?;
        }
        _ => bail!("Unknown WAMP server action"),
    }
    Ok(())
}

fn startup(
    name: &str,
    kind: &str,
    description: &str,
    example: Value,
    default: Option<Value>,
) -> ParameterDefinition {
    ParameterDefinition {
        name: name.into(),
        type_hint: kind.into(),
        description: description.into(),
        required: false,
        example,
        default,
    }
}

impl Protocol for WampProtocol {
    fn protocol_name(&self) -> &'static str {
        "WAMP"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>HTTP>WebSocket>WAMP"
    }
    fn description(&self) -> &'static str {
        "WAMP v2 router (basic profile, JSON over WebSocket): realms, routed RPC and pub/sub; the handler admits sessions and answers calls nobody registered"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "wamp",
            "web application messaging protocol",
            "router",
            "rpc",
            "pubsub",
            "autobahn",
            "crossbar",
        ]
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        vec![publish()]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![welcome(), abort(), result(), error()]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![HELLO_EVENT.clone(), CALL_EVENT.clone()]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            startup(
                "hello_timeout_secs",
                "integer",
                "Seconds a new WebSocket has to send HELLO",
                json!(5),
                Some(json!(super::HELLO_TIMEOUT.as_secs())),
            ),
            startup(
                "max_message_bytes",
                "integer",
                "Largest WAMP message accepted",
                json!(65536),
                Some(json!(super::MAX_MESSAGE)),
            ),
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation("tokio-tungstenite WebSocket with the wamp.2.json subprotocol; hand-written WAMP v2 basic-profile router: realms, sessions, exact/prefix/wildcard subscriptions, publisher exclusion and black/white listing, single-callee registrations, call routing with INVOCATION/YIELD/ERROR")
            .llm_control("Which sessions join which realm, and the answer to every call no client has registered")
            .e2e_testing("tests/server/wamp: autobahn-python 24.4.2 and nexus 3.3.0 (Go; independent) join, register, subscribe, call through the router, publish with acknowledgement, call router procedures, get router errors and are refused a realm")
            .notes("JSON serializer only (no MessagePack, CBOR or RawSocket); anonymous authentication only; no progressive results, call cancellation, shared registrations, meta API or event history.")
            .answers_on_failure()
            .max_inbound_bytes(super::MAX_MESSAGE)
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "WAMP router on port 8080 for realm1 whose com.example.time procedure returns the current time"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let llm = json!({"type":"open_server","base_stack":"wamp","port":8080,"instruction":"Admit realm1 only; answer com.example.time with the current UTC time"});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([
            {"event_pattern":"wamp_hello","handler":{"type":"static","actions":[{"type":"wamp_welcome"}]}},
            {"event_pattern":"wamp_call","handler":{"type":"static","actions":[{"type":"wamp_error","error":"wamp.error.no_such_procedure"}]}}
        ]);
        let mut scripted = static_example.clone();
        scripted["event_handlers"][1]["handler"] = json!({"type":"script","language":"python","code":"import json,sys\ne=json.load(sys.stdin)['event']\nif e['procedure']=='com.example.add':\n    print(json.dumps({'actions':[{'type':'wamp_result','args':[sum(e['args'])]}]}))\nelse:\n    print(json.dumps({'actions':[{'type':'wamp_error','error':'wamp.error.no_such_procedure'}]}))"});
        crate::llm::actions::StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Application"
    }
}

impl Server for WampProtocol {
    fn spawn(
        &self,
        ctx: SpawnContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::spawn(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ActionResult> {
        check_answer(&v)?;
        Ok(ActionResult::Custom {
            name: v["type"].as_str().unwrap_or_default().into(),
            data: v,
        })
    }
}

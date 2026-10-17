use super::model;
use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter, ParameterDefinition,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::{EventType, SpawnContext};
use crate::state::app_state::AppState;
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

#[derive(Default)]
pub struct A2aProtocol;
impl A2aProtocol {
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
    let log_template = match name {
        "a2a_reply" => LogTemplate::new().with_info("-> A2A reply"),
        _ => LogTemplate::new().with_info(format!("-> A2A {name}")),
    };
    ActionDefinition {
        name: name.into(),
        description: description.into(),
        parameters,
        example,
        log_template: Some(log_template),
    }
}

pub const ERROR_NAMES: &[(&str, i64)] = &[
    ("task_not_found", model::TASK_NOT_FOUND),
    ("task_not_cancelable", model::TASK_NOT_CANCELABLE),
    ("unsupported_operation", model::UNSUPPORTED_OPERATION),
    (
        "content_type_not_supported",
        model::CONTENT_TYPE_NOT_SUPPORTED,
    ),
    ("invalid_params", -32602),
];

fn reply_action() -> ActionDefinition {
    action(
        "a2a_reply",
        "Answer the pending A2A request. Rust builds the protobuf-JSON envelope, ids, timestamps and (for streaming) the SSE sequence. Supply exactly one of: message {text, parts} (a direct agent reply), task {id, state, text, artifacts} (SendMessage, GetTask, CancelTask), tasks [task, ...] (ListTasks), error {code, message}.",
        vec![
            parameter("message", "object", "{text, parts: [{text}|{data}|{url, filename, media_type}]} — a direct agent message", false),
            parameter("task", "object", "{id (omit for a new task), state: submitted|working|completed|failed|canceled|input_required|rejected|auth_required, text (status message), artifacts: [{name, text, parts}]}", false),
            parameter("tasks", "array", "ListTasks result: task objects as above (each with its id)", false),
            parameter("error", "object", "{code: task_not_found|task_not_cancelable|unsupported_operation|content_type_not_supported|invalid_params, message}", false),
        ],
        json!({"type":"a2a_reply","task":{"state":"completed","artifacts":[{"name":"answer","text":"42"}]}}),
    )
}

pub static MESSAGE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "a2a_message",
        "A user message via SendMessage or SendStreamingMessage. Answer with a direct message or a task; there is no task store in Rust (keep state in memory if later GetTask calls must find it).",
        reply_action().example.clone(),
    )
    .with_parameters(vec![
        parameter("method", "string", "SendMessage or SendStreamingMessage", true),
        parameter("text", "string", "The message's text parts joined by newlines", true),
        parameter("parts", "array", "Every part: {kind: text|data|file, ...}; inline file bytes are given by size only", true),
        parameter("message_id", "string", "The caller's message id", true),
        parameter("context_id", "string", "Conversation context id (Rust generates one when absent)", true),
        parameter("task_id", "string", "Existing task this message continues, if any", false),
    ])
    .with_actions(vec![reply_action()])
});

pub static TASK_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new("a2a_task_request", "GetTask, CancelTask or ListTasks. Answer from what you remember of earlier tasks, or with task_not_found / task_not_cancelable.", json!({"type":"a2a_reply","error":{"code":"task_not_found","message":"no such task"}}))
        .with_parameters(vec![
            parameter("method", "string", "GetTask, CancelTask or ListTasks", true),
            parameter("task_id", "string", "Task id for GetTask/CancelTask", false),
            parameter("params", "object", "The request's params (historyLength, contextId, pageSize, ...)", true),
        ])
        .with_actions(vec![reply_action()])
});

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

impl Protocol for A2aProtocol {
    fn protocol_name(&self) -> &'static str {
        "A2A"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>HTTP>A2A"
    }
    fn description(&self) -> &'static str {
        "Agent2Agent (A2A) protocol 1.0 agent over JSON-RPC with streaming"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["a2a", "agent2agent", "agent card", "ai agent", "json-rpc"]
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![reply_action()]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![MESSAGE_EVENT.clone(), TASK_EVENT.clone()]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            startup(
                "agent_name",
                "string",
                "Agent card name",
                json!("Travel Agent"),
                Some(json!(super::DEFAULT_NAME)),
            ),
            startup(
                "agent_description",
                "string",
                "Agent card description",
                json!("Books trips"),
                Some(json!(super::DEFAULT_DESCRIPTION)),
            ),
            startup(
                "skills",
                "array",
                "Agent card skills: [{id, name, description, tags: [..], examples: [..]}]",
                json!([{"id":"book","name":"Book","description":"Book a flight","tags":["travel"]}]),
                None,
            ),
            startup(
                "streaming",
                "boolean",
                "Advertise and serve SendStreamingMessage (SSE)",
                json!(true),
                Some(json!(super::DEFAULT_STREAMING)),
            ),
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation("hyper HTTP/1.1; agent card at /.well-known/agent-card.json; JSON-RPC 2.0 with A2A-Version 1.0; protobuf-JSON messages, tasks and SSE stream responses built and checked in Rust")
            .llm_control("Every reply: direct messages, task states and artifacts, task lookups and cancellation answers")
            .e2e_testing("tests/server/a2a: a2a-sdk 1.2.1 client (independent) resolves the card, sends, streams, gets and cancels; JSON-RPC and version refusals")
            .notes("No task store: GetTask/CancelTask/ListTasks are answered by the handler (persist with memory or SQLite). Push notifications, SubscribeToTask, the extended card, the HTTP+JSON and gRPC bindings and 0.3 compatibility are not implemented. 1 MiB bodies.")
            .request_only("A2A answers each JSON-RPC request; push notifications are not offered")
            .answers_on_failure()
            .max_inbound_bytes(model::MAX_BODY_BYTES)
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "A2A agent named Echo that answers every message with its text reversed"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let llm = json!({"type":"open_server","base_stack":"a2a","port":8080,"instruction":"You are a helpful travel agent"});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([
            {"event_pattern":"a2a_message","handler":{"type":"static","actions":[{"type":"a2a_reply","message":{"text":"Hello from NetGet"}}]}},
            {"event_pattern":"a2a_task_request","handler":{"type":"static","actions":[{"type":"a2a_reply","error":{"code":"task_not_found","message":"no tasks"}}]}}
        ]);
        let mut scripted = static_example.clone();
        scripted["event_handlers"][0]["handler"] = json!({"type":"script","language":"python","code":"import json,sys\ne=json.load(sys.stdin)['event']\nprint(json.dumps({'actions':[{'type':'a2a_reply','message':{'text':e['text'][::-1]}}]}))"});
        crate::llm::actions::StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "AI & Agents"
    }
}

impl Server for A2aProtocol {
    fn spawn(
        &self,
        ctx: SpawnContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::spawn(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ActionResult> {
        match v["type"].as_str() {
            Some("a2a_reply") => {
                validate_reply(&v)?;
                Ok(ActionResult::Custom {
                    name: "a2a_reply".into(),
                    data: v,
                })
            }
            _ => bail!("Unknown A2A server action"),
        }
    }
}

pub fn validate_reply(v: &Value) -> Result<()> {
    ensure!(model::budget_ok(v), "reply exceeds the A2A bounds");
    let present: Vec<&str> = ["message", "task", "tasks", "error"]
        .into_iter()
        .filter(|k| v.get(*k).is_some_and(|x| !x.is_null()))
        .collect();
    ensure!(
        present.len() == 1,
        "a2a_reply needs exactly one of message, task, tasks, error"
    );
    match present[0] {
        "message" => {
            model::parts_from(v["message"]["text"].as_str(), v["message"].get("parts"))?;
        }
        "task" => {
            model::task(&v["task"], "x", "x")?;
        }
        "tasks" => {
            for t in v["tasks"].as_array().context("tasks must be an array")? {
                ensure!(
                    t.get("id").is_some_and(Value::is_string),
                    "each listed task needs its id"
                );
                model::task(t, "x", "x")?;
            }
        }
        _ => {
            let code = v["error"]["code"]
                .as_str()
                .context("error.code is required")?;
            ensure!(
                ERROR_NAMES.iter().any(|(n, _)| *n == code),
                "unknown error code '{code}'"
            );
        }
    }
    Ok(())
}

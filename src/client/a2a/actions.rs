use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, ParameterDefinition,
};
use crate::protocol::{ConnectContext, EventType};
use crate::server::a2a::actions::{action, parameter};
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

#[derive(Default)]
pub struct A2aClientProtocol;
impl A2aClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

fn send_action() -> ActionDefinition {
    action(
        "a2a_send_message",
        "Send a user message to the agent (SendMessage, or SendStreamingMessage when stream is true and the card advertises streaming). Rust builds the message, ids and A2A-Version header.",
        vec![
            parameter("text", "string", "What to tell the agent, sent as the message's text part (1 byte to 256 KiB)", true),
            parameter("data", "object", "Optional structured data part", false),
            parameter("context_id", "string", "Continue this conversation context", false),
            parameter("task_id", "string", "Continue this task (e.g. after input_required)", false),
            parameter("stream", "boolean", "Use SendStreamingMessage and collect the SSE events", false),
        ],
        json!({"type":"a2a_send_message","text":"Book a flight to Lisbon"}),
    )
}
fn get_action() -> ActionDefinition {
    action(
        "a2a_get_task",
        "Fetch a task by id (GetTask)",
        vec![
            parameter("task_id", "string", "Task id returned earlier", true),
            parameter(
                "history_length",
                "number",
                "Messages of history to include",
                false,
            ),
        ],
        json!({"type":"a2a_get_task","task_id":"<task id>"}),
    )
}
fn cancel_action() -> ActionDefinition {
    action(
        "a2a_cancel_task",
        "Ask the agent to cancel a task (CancelTask)",
        vec![parameter("task_id", "string", "Task id to cancel", true)],
        json!({"type":"a2a_cancel_task","task_id":"<task id>"}),
    )
}
fn list_action() -> ActionDefinition {
    action(
        "a2a_list_tasks",
        "List the agent's tasks (ListTasks)",
        vec![
            parameter("context_id", "string", "Only tasks of this context", false),
            parameter(
                "page_size",
                "number",
                "Maximum tasks to return in one page, 1 to 100 (the agent's default when omitted)",
                false,
            ),
        ],
        json!({"type":"a2a_list_tasks"}),
    )
}
fn disconnect_action() -> ActionDefinition {
    action(
        "disconnect",
        "Stop this A2A client",
        vec![],
        json!({"type":"disconnect"}),
    )
}
fn actions() -> Vec<ActionDefinition> {
    vec![
        send_action(),
        get_action(),
        cancel_action(),
        list_action(),
        disconnect_action(),
    ]
}

pub static CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "a2a_connected",
        "The agent card was fetched and offers a JSON-RPC interface for protocol 1.0",
        send_action().example.clone(),
    )
    .with_parameters(vec![
        parameter("name", "string", "Agent name from the card", true),
        parameter("description", "string", "Agent description", true),
        parameter("skills", "array", "Skills the agent advertises", true),
        parameter("streaming", "boolean", "Whether the agent streams", true),
        parameter(
            "rpc_url",
            "string",
            "JSON-RPC endpoint the client will use",
            true,
        ),
    ])
    .with_actions(actions())
});
pub static RESPONSE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "a2a_response",
        "The agent's answer to the last request",
        disconnect_action().example.clone(),
    )
    .with_parameters(vec![
        parameter("method", "string", "The JSON-RPC method sent", true),
        parameter(
            "result",
            "object",
            "The result: {task}|{message} for sends, a task for Get/Cancel, {tasks} for List",
            false,
        ),
        parameter(
            "error",
            "object",
            "JSON-RPC error {code, message}, e.g. -32001 task not found",
            false,
        ),
        parameter(
            "stream_events",
            "array",
            "For streaming sends: every StreamResponse received in order (up to 256)",
            false,
        ),
        parameter(
            "task_id",
            "string",
            "Task id the answer is about, when there is one",
            false,
        ),
        parameter(
            "state",
            "string",
            "Last known task state (completed, working, canceled, ...)",
            false,
        ),
    ])
    .with_actions(actions())
});

impl Protocol for A2aClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "A2A"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>HTTP>A2A"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["a2a", "agent2agent", "agent client", "json-rpc"]
    }
    fn description(&self) -> &'static str {
        "A2A 1.0 client: resolves an agent card, sends and streams messages, manages tasks"
    }
    fn get_async_actions(&self, _: &crate::state::app_state::AppState) -> Vec<ActionDefinition> {
        actions()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![CONNECTED_EVENT.clone(), RESPONSE_EVENT.clone()]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![ParameterDefinition {
            name: "allow_card_redirect".into(),
            type_hint: "boolean".into(),
            description: "Follow an agent card whose JSON-RPC url names a different host than remote_addr (off: such a card is refused, so a client pointed at one agent cannot be sent elsewhere)".into(),
            required: false,
            example: json!(true),
            default: Some(json!(super::DEFAULT_ALLOW_REDIRECT)),
        }]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation("Shared http_fetch client (reqwest natively, no redirects); agent card resolution; JSON-RPC 2.0 with A2A-Version 1.0; SSE stream collection; results checked against the 1.0 shapes")
            .llm_control("What to ask the agent, whether to stream, and which tasks to fetch, list or cancel")
            .e2e_testing("tests/client/a2a: an a2a-sdk 1.2.1 agent (independent) answers a direct message, a streamed task, GetTask and CancelTask; NetGet pair and refusals")
            .notes("JSON-RPC binding only (no HTTP+JSON or gRPC, no push notifications, no 0.3). Streams are collected whole (1 MiB, 256 events, 30 s). A card pointing at another host is refused unless allow_card_redirect.")
            .max_inbound_bytes(crate::server::a2a::model::MAX_BODY_BYTES)
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Ask the A2A agent at 127.0.0.1:8080 to summarise today's tasks"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let llm = json!({"type":"open_client","protocol":"a2a","remote_addr":"127.0.0.1:8080","instruction":"Ask the agent for the weather in Lisbon"});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([
            {"event_pattern":"a2a_connected","handler":{"type":"static","actions":[send_action().example]}},
            {"event_pattern":"a2a_response","handler":{"type":"static","actions":[]}}
        ]);
        let mut scripted = static_example.clone();
        scripted["event_handlers"][1]["handler"] = json!({"type":"script","language":"python","code":"import json\nprint(json.dumps({'actions':[]}))"});
        crate::llm::actions::StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "AI & Agents"
    }
}

impl Client for A2aClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::connect(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ClientActionResult> {
        let id_ok = |k: &str| -> Result<()> {
            if let Some(x) = v.get(k).filter(|x| !x.is_null()) {
                let s = x
                    .as_str()
                    .with_context(|| format!("{k} must be a string"))?;
                ensure!(
                    !s.is_empty() && s.len() <= 256,
                    "{k} must be 1..=256 characters"
                );
            }
            Ok(())
        };
        match v["type"].as_str() {
            Some("a2a_send_message") => {
                let t = v["text"].as_str().context("text is required")?;
                ensure!(
                    !t.is_empty() && t.len() <= crate::server::a2a::model::MAX_TEXT_BYTES,
                    "text must be 1 byte..256 KiB"
                );
                id_ok("context_id")?;
                id_ok("task_id")?;
            }
            Some("a2a_get_task" | "a2a_cancel_task") => {
                ensure!(
                    v.get("task_id").is_some_and(|t| t.is_string()),
                    "task_id is required"
                );
                id_ok("task_id")?;
            }
            Some("a2a_list_tasks") => {
                if let Some(n) = v.get("page_size").and_then(Value::as_u64) {
                    ensure!((1..=100).contains(&n), "page_size must be 1..=100");
                }
            }
            Some("disconnect") => return Ok(ClientActionResult::Disconnect),
            _ => bail!("Unknown A2A client action"),
        }
        Ok(ClientActionResult::Custom {
            name: v["type"].as_str().unwrap_or_default().into(),
            data: v,
        })
    }
}

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

use super::wire;

#[derive(Default)]
pub struct AnthropicProtocol;
impl AnthropicProtocol {
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

fn reply_action() -> ActionDefinition {
    action(
        "anthropic_reply",
        "Answer the request with the assistant's message: text, tool calls, or both. NetGet adds the id, model and usage, and streams it when the caller asked to.",
        vec![
            parameter("text", "string", "The assistant's text (one text block); use content for several blocks or tool calls", false),
            parameter("content", "array", "Content blocks in order: {type: text, text} or {type: tool_use, name, input (object), id?}", false),
            parameter("stop_reason", "string", "end_turn, max_tokens, stop_sequence, tool_use, pause_turn or refusal; defaults to tool_use when a tool is called, else end_turn", false),
            parameter("stop_sequence", "string", "The stop sequence that ended the text, with stop_reason stop_sequence", false),
            parameter("input_tokens", "number", "Reported input tokens; estimated as characters/4 when omitted", false),
            parameter("output_tokens", "number", "Reported output tokens; estimated as characters/4 when omitted", false),
        ],
        json!({"type":"anthropic_reply","text":"Hello! How can I help?"}),
        "-> Anthropic reply {preview(text,80)}",
    )
}

fn error_action() -> ActionDefinition {
    action(
        "anthropic_error",
        "Refuse the request with one of Anthropic's error types; the HTTP status follows from the type.",
        vec![
            parameter("error_type", "string", "invalid_request_error (400), authentication_error (401), permission_error (403), not_found_error (404), request_too_large (413), rate_limit_error (429), api_error (500) or overloaded_error (529)", true),
            parameter("message", "string", "The error message the caller will read", true),
        ],
        json!({"type":"anthropic_error","error_type":"rate_limit_error","message":"Number of requests has exceeded your rate limit"}),
        "-> Anthropic error {error_type}",
    )
}

pub fn sync_actions() -> Vec<ActionDefinition> {
    vec![reply_action(), error_action()]
}

pub static MESSAGE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "anthropic_message",
        "A client asked POST /v1/messages for the assistant's next message.",
        json!({"type":"anthropic_reply","text":"Hello! How can I help?"}),
    )
    .with_parameters(vec![
        parameter("model", "string", "The model the caller named", true),
        parameter("max_tokens", "number", "The most output tokens the caller allows", true),
        parameter("system", "string", "The system prompt, or null", false),
        parameter("messages", "array", "The conversation: each {role, content: [blocks]}; text, tool_use, tool_result, and image/document described by type and size only", true),
        parameter("tools", "array", "Tools the caller offers: each {name, description, input_schema}", false),
        parameter("tool_choice", "object", "auto, any, tool {name} or none, as the caller sent it", false),
        parameter("stop_sequences", "array", "Strings that end the text when generated", false),
        parameter("stream", "boolean", "Whether the caller asked for server-sent events (NetGet streams the reply either way)", true),
        parameter("api_key_present", "boolean", "Whether the request carried x-api-key or a bearer token (its value is never shown)", true),
    ])
    .with_actions(sync_actions())
});

impl Protocol for AnthropicProtocol {
    fn protocol_name(&self) -> &'static str {
        "Anthropic"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>HTTP>Anthropic"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["anthropic", "claude", "messages api", "llm api"]
    }
    fn description(&self) -> &'static str {
        "Anthropic Messages API server: /v1/messages (plain and streaming), count_tokens and models, answered by the handler"
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        sync_actions()
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![MESSAGE_EVENT.clone()]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "api_key".into(),
                type_hint: "string".into(),
                description: "When set, every request must carry this key in x-api-key (or Authorization: Bearer); any other gets 401 authentication_error without asking the handler".into(),
                required: false,
                example: json!("sk-ant-netget-test"),
                default: None,
            },
            ParameterDefinition {
                name: "models".into(),
                type_hint: "array".into(),
                description: "Model ids /v1/models lists and /v1/models/{id} finds".into(),
                required: false,
                example: json!(["claude-netget-1", "claude-netget-fast"]),
                default: Some(json!([wire::DEFAULT_MODEL])),
            },
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation("HTTP/1.1 via hyper: POST /v1/messages (JSON, or server-sent events with message_start, ping, content_block_start/delta/stop with text_delta and input_json_delta, message_delta, message_stop), POST /v1/messages/count_tokens, GET /v1/models and /v1/models/{id}; Anthropic's request validation and error envelope, msg_/toolu_/req_ ids")
            .llm_control("Every assistant message — text, tool calls and stop reason — or a refusal with one of Anthropic's error types")
            .e2e_testing("tests/server/anthropic: the official anthropic Python SDK and @anthropic-ai/sdk (TypeScript) as independent clients, plain and streaming, with tool use; raw HTTP for validation, bounds and failure")
            .notes("Token counts are estimates (characters/4) unless the handler gives them, count_tokens included. The reply is computed before anything is sent, so a stream is the whole message cut into deltas, and an error arrives as an HTTP status rather than mid-stream. No batches, files, prompt caching or extended thinking output. Image and document blocks are described to the handler by type and size, never their bytes. A handler failure answers 529 overloaded_error or 500 api_error, never a fabricated message.")
            .request_only("Every response answers an HTTP request")
            .answers_on_failure()
            .max_inbound_bytes(wire::MAX_BODY)
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Anthropic-compatible API on port 8000 that answers as a terse pirate"
    }
    fn get_startup_examples(&self) -> StartupExamples {
        let llm = json!({"type":"open_server","base_stack":"anthropic","port":8000,"instruction":"Answer every message briefly, as a pirate"});
        let mut scripted = llm.clone();
        scripted["event_handlers"] = json!([{"event_pattern":"anthropic_message","handler":{"type":"script","language":"python","code":"import json,sys\ne=json.load(sys.stdin)['event']\nlast=e['messages'][-1]['content'][-1].get('text','')\nprint(json.dumps({'actions':[{'type':'anthropic_reply','text':'You said: '+last}]}))"}}]);
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([{"event_pattern":"anthropic_message","handler":{"type":"static","actions":[{"type":"anthropic_reply","text":"Arr."}]}}]);
        StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "AI & API"
    }
}

/// Check an `anthropic_error`.
pub fn check_error(v: &Value) -> Result<()> {
    let t = v["error_type"].as_str().context("error_type required")?;
    ensure!(
        wire::status_of(t).is_some(),
        "error_type must be one of Anthropic's error types"
    );
    let m = v["message"].as_str().context("message required")?;
    ensure!(m.len() <= 4096, "message at most 4096 bytes");
    Ok(())
}

impl Server for AnthropicProtocol {
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
            "anthropic_reply" => {
                let content = wire::reply_content(&v)?;
                wire::stop_reason(&v, &content)?;
                for k in ["input_tokens", "output_tokens"] {
                    ensure!(
                        v[k].is_null() || v[k].as_u64().is_some(),
                        "{k} must be a non-negative integer"
                    );
                }
            }
            "anthropic_error" => check_error(&v)?,
            _ => bail!("Unknown Anthropic server action"),
        }
        Ok(ActionResult::Custom { name, data: v })
    }
}

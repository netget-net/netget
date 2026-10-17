use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, ParameterDefinition, StartupExamples,
};
use crate::protocol::{ConnectContext, EventType};
use crate::server::anthropic::actions::{action, parameter};
use crate::state::app_state::AppState;
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Map, Value};
use std::sync::LazyLock;

/// The `anthropic-version` header sent unless the startup parameter names another.
pub const API_VERSION: &str = "2023-06-01";
/// max_tokens sent when an action names none.
pub const DEFAULT_MAX_TOKENS: u64 = 1024;

#[derive(Default)]
pub struct AnthropicClientProtocol;
impl AnthropicClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

fn message_parameters(with_max_tokens: bool) -> Vec<crate::llm::actions::Parameter> {
    let mut p = vec![
        parameter("prompt", "string", "Shorthand for one user message with this text; give prompt or messages", false),
        parameter("messages", "array", "The conversation: each {role: user|assistant, content: string or [blocks]} (tool_result blocks answer tool_use)", false),
        parameter("system", "string", "System prompt: instructions the model follows for the whole conversation", false),
        parameter("model", "string", "Model id; defaults to the client's model startup parameter", false),
        parameter("tools", "array", "Tools to offer: each {name, description, input_schema}", false),
        parameter("tool_choice", "object", "{type: auto|any|none} or {type: tool, name}", false),
    ];
    if with_max_tokens {
        p.extend([
            parameter(
                "max_tokens",
                "number",
                "Most output tokens (default 1024)",
                false,
            ),
            parameter("temperature", "number", "Sampling temperature, 0..1", false),
            parameter(
                "stop_sequences",
                "array",
                "Strings that end generation",
                false,
            ),
            parameter(
                "stream",
                "boolean",
                "Ask for server-sent events; the stream is reassembled into one message either way",
                false,
            ),
        ]);
    }
    p
}

pub fn actions() -> Vec<ActionDefinition> {
    vec![
        action(
            "anthropic_create_message",
            "POST /v1/messages: ask the server for the assistant's next message; its text, tool calls, stop reason and usage come back.",
            message_parameters(true),
            json!({"type":"anthropic_create_message","prompt":"Say hello in five words","max_tokens":64}),
            "-> Anthropic messages {preview(prompt,60)}",
        ),
        action(
            "anthropic_count_tokens",
            "POST /v1/messages/count_tokens: how many input tokens the server counts for these messages.",
            message_parameters(false),
            json!({"type":"anthropic_count_tokens","prompt":"How many tokens is this?"}),
            "-> Anthropic count_tokens",
        ),
        action(
            "anthropic_list_models",
            "GET /v1/models: the models the server offers.",
            vec![],
            json!({"type":"anthropic_list_models"}),
            "-> Anthropic models",
        ),
        action(
            "anthropic_get_model",
            "GET /v1/models/{model_id}: one model, or not_found_error.",
            vec![parameter("model_id", "string", "The model id to look up", true)],
            json!({"type":"anthropic_get_model","model_id":"claude-netget-1"}),
            "-> Anthropic model {model_id}",
        ),
        action(
            "disconnect",
            "Stop this client; no further requests are sent.",
            vec![],
            json!({"type":"disconnect"}),
            "-> Anthropic client stop",
        ),
    ]
}

pub static CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "anthropic_connected",
        "The client is ready to send requests to the API.",
        json!({"type":"anthropic_create_message","prompt":"Hello"}),
    )
    .with_parameters(vec![parameter(
        "remote_addr",
        "string",
        "The API's origin",
        true,
    )])
    .with_actions(actions())
});

pub static RESPONSE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "anthropic_response",
        "The API answered a request.",
        json!({"type":"anthropic_create_message","messages":[{"role":"user","content":"Thanks"}]}),
    )
    .with_parameters(vec![
        parameter("operation", "string", "The action that was sent", true),
        parameter(
            "status",
            "number",
            "HTTP status code of the answer: 200 on success, else see error",
            true,
        ),
        parameter(
            "message",
            "object",
            "For a message: {id, model, text, content, stop_reason, stop_sequence, usage}",
            false,
        ),
        parameter(
            "streamed",
            "object",
            "For a streamed message: how many of each event type arrived",
            false,
        ),
        parameter("input_tokens", "number", "For count_tokens", false),
        parameter(
            "models",
            "array",
            "For the models list (ids), or the one model looked up",
            false,
        ),
        parameter(
            "error",
            "object",
            "When refused: {type, message} from Anthropic's error envelope",
            false,
        ),
    ])
    .with_actions(actions())
});

impl Protocol for AnthropicClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "Anthropic"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>HTTP>Anthropic"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["anthropic", "claude", "messages api"]
    }
    fn description(&self) -> &'static str {
        "Anthropic Messages API client: messages (plain or streamed), count_tokens and models"
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        actions()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![CONNECTED_EVENT.clone(), RESPONSE_EVENT.clone()]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "api_key".into(),
                type_hint: "string".into(),
                description: "Sent as x-api-key on every request; never shown in events".into(),
                required: false,
                example: json!("sk-ant-netget-test"),
                default: None,
            },
            ParameterDefinition {
                name: "anthropic_version".into(),
                type_hint: "string".into(),
                description: "The anthropic-version header".into(),
                required: false,
                example: json!("2023-06-01"),
                default: Some(json!(API_VERSION)),
            },
            ParameterDefinition {
                name: "model".into(),
                type_hint: "string".into(),
                description: "Model id used when an action names none".into(),
                required: false,
                example: json!("claude-sonnet-4-5"),
                default: None,
            },
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation("HTTP/1.1 via hyper, one connection per request: /v1/messages (JSON or server-sent events, reassembled into one message), /v1/messages/count_tokens, /v1/models, with x-api-key and anthropic-version")
            .llm_control("What to ask and with which tools, and what to do with each answer — including answering a tool_use with a tool_result")
            .e2e_testing("tests/client/anthropic: NetGet's own server; llama.cpp's llama-server (its Anthropic-compatible /v1/messages, with a 260K-parameter test model) as an independent server")
            .notes("Plain HTTP only (no TLS), so it reaches a local or proxied server, not api.anthropic.com directly. Responses are capped at 8 MiB and 120 s. Image and document blocks pass through as given. A handler chain stops after 8 follow-ups.")
            .max_inbound_bytes(crate::server::anthropic::wire::MAX_BODY)
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Ask the Anthropic-compatible API at 127.0.0.1:8000 for a haiku, streamed"
    }
    fn get_startup_examples(&self) -> StartupExamples {
        let llm = json!({"type":"open_client","protocol":"anthropic","remote_addr":"127.0.0.1:8000","instruction":"Ask for a haiku about networks"});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([{"event_pattern":"anthropic_connected","handler":{"type":"static","actions":[{"type":"anthropic_create_message","model":"claude-netget-1","prompt":"Write a haiku about packets","stream":true}]}}]);
        let mut scripted = llm.clone();
        scripted["event_handlers"] = json!([{"event_pattern":"anthropic_response","handler":{"type":"script","language":"python","code":"import json,sys\ne=json.load(sys.stdin)['event']\nprint(json.dumps({'actions':[]}))"}}]);
        StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "AI & API"
    }
}

/// The client's defaults, from its startup parameters.
#[derive(Clone, Default)]
pub struct Defaults {
    pub api_key: Option<String>,
    pub version: String,
    pub model: Option<String>,
}

fn messages_of(v: &Value) -> Result<Value> {
    match (&v["messages"], v["prompt"].as_str()) {
        (Value::Array(m), None) => {
            ensure!(!m.is_empty(), "messages must not be empty");
            ensure!(m.len() <= 1000, "at most 1000 messages");
            for (i, msg) in m.iter().enumerate() {
                let role = msg["role"].as_str().unwrap_or_default();
                ensure!(
                    role == "user" || role == "assistant",
                    "messages.{i}.role must be user or assistant"
                );
                ensure!(
                    msg["content"].is_string() || msg["content"].is_array(),
                    "messages.{i}.content must be text or blocks"
                );
            }
            Ok(Value::Array(m.clone()))
        }
        (Value::Null, Some(p)) => Ok(json!([{"role": "user", "content": p}])),
        (Value::Null, None) => bail!("give prompt or messages"),
        _ => bail!("give prompt or messages, not both"),
    }
}

/// The request one action sends: method, path and JSON body.
pub fn request(v: &Value, d: &Defaults) -> Result<(&'static str, String, Option<Value>)> {
    let kind = v["type"].as_str().unwrap_or_default();
    let model = || -> Result<String> {
        v["model"]
            .as_str()
            .map(str::to_string)
            .or_else(|| d.model.clone())
            .filter(|m| !m.is_empty())
            .context("model required: name one in the action or the model startup parameter")
    };
    Ok(match kind {
        "anthropic_create_message" | "anthropic_count_tokens" => {
            let mut body = Map::new();
            body.insert("model".into(), json!(model()?));
            body.insert("messages".into(), messages_of(v)?);
            if let Some(s) = v["system"].as_str() {
                body.insert("system".into(), json!(s));
            }
            if !v["tools"].is_null() {
                let tools = v["tools"].as_array().context("tools must be an array")?;
                ensure!(tools.len() <= 256, "at most 256 tools");
                for t in tools {
                    ensure!(t["name"].is_string(), "each tool needs a name");
                }
                body.insert("tools".into(), v["tools"].clone());
            }
            if !v["tool_choice"].is_null() {
                ensure!(
                    v["tool_choice"].is_object(),
                    "tool_choice must be an object"
                );
                body.insert("tool_choice".into(), v["tool_choice"].clone());
            }
            if kind == "anthropic_count_tokens" {
                return Ok((
                    "POST",
                    "/v1/messages/count_tokens".into(),
                    Some(Value::Object(body)),
                ));
            }
            let max = match &v["max_tokens"] {
                Value::Null => DEFAULT_MAX_TOKENS,
                m => m
                    .as_u64()
                    .filter(|n| *n >= 1)
                    .context("max_tokens must be a positive integer")?,
            };
            body.insert("max_tokens".into(), json!(max));
            if !v["temperature"].is_null() {
                let t = v["temperature"]
                    .as_f64()
                    .context("temperature must be a number")?;
                ensure!(
                    (0.0..=1.0).contains(&t),
                    "temperature must be between 0 and 1"
                );
                body.insert("temperature".into(), json!(t));
            }
            if !v["stop_sequences"].is_null() {
                let s = v["stop_sequences"]
                    .as_array()
                    .context("stop_sequences must be an array")?;
                ensure!(
                    s.iter().all(Value::is_string),
                    "stop_sequences must be strings"
                );
                body.insert("stop_sequences".into(), v["stop_sequences"].clone());
            }
            if v["stream"] == true {
                body.insert("stream".into(), json!(true));
            }
            ("POST", "/v1/messages".into(), Some(Value::Object(body)))
        }
        "anthropic_list_models" => ("GET", "/v1/models".into(), None),
        "anthropic_get_model" => {
            let id = v["model_id"].as_str().context("model_id required")?;
            ensure!(
                !id.is_empty()
                    && id.len() <= 256
                    && id
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"-_.:@".contains(&b)),
                "model_id must be 1..=256 characters of [A-Za-z0-9-_.:@]"
            );
            ("GET", format!("/v1/models/{id}"), None)
        }
        other => bail!("Unknown Anthropic client action {other}"),
    })
}

impl Client for AnthropicClientProtocol {
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
        // Checked against a placeholder model: the session checks again with its own defaults.
        let d = Defaults {
            model: Some("m".into()),
            ..Defaults::default()
        };
        request(&v, &d)?;
        Ok(ClientActionResult::Custom { name, data: v })
    }
}

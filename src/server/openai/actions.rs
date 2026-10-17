//! OpenAI protocol actions implementation

use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter,
};
use crate::protocol::EventType;
use crate::state::app_state::AppState;
use anyhow::{Context, Result};
use serde_json::json;
use std::sync::LazyLock;
use tracing::debug;

use crate::protocol::log_template::LogTemplate;

/// OpenAI request event (for /v1/models, /v1/chat/completions, etc.)
pub static OPENAI_REQUEST_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "openai_request",
        "An OpenAI-compatible API request arrived. Answer with exactly one action chosen by \
         'path': /v1/chat/completions -> openai_chat_response, /v1/models -> \
         openai_models_response. Any request may instead be refused with openai_error_response.",
        json!({
            "type": "openai_chat_response",
            "content": "Hello! How can I help you today?",
            "model": "gpt-4"
        }),
    )
    .with_alternative_example(json!({
        "type": "openai_models_response",
        "models": ["gpt-4", "gpt-3.5-turbo"]
    }))
    .with_alternative_example(json!({
        "type": "openai_error_response",
        "message": "Unsupported endpoint",
        "error_type": "invalid_request_error",
        "status": 404
    }))
    // This is the protocol's only event, so without an action list `call_llm` would offer the
    // model nothing but set_memory/show_message and reject every response it produced. All three
    // sync actions apply here: the event covers every path, and any of them may be refused.
    .with_actions(vec![
        openai_chat_response_action(),
        openai_models_response_action(),
        openai_error_response_action(),
    ])
    .with_parameters(vec![
        Parameter {
            name: "method".to_string(),
            type_hint: "string".to_string(),
            description: "HTTP method (GET, POST)".to_string(),
            required: true,
        },
        Parameter {
            name: "path".to_string(),
            type_hint: "string".to_string(),
            description: "Request path (/v1/models, /v1/chat/completions)".to_string(),
            required: true,
        },
        Parameter {
            name: "body".to_string(),
            type_hint: "string".to_string(),
            description: "Request body (JSON string for POST requests)".to_string(),
            required: false,
        },
    ])
});

/// OpenAI protocol action handler
pub struct OpenAiProtocol {}

impl Default for OpenAiProtocol {
    fn default() -> Self {
        Self::new()
    }
}

impl OpenAiProtocol {
    pub fn new() -> Self {
        Self {}
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for OpenAiProtocol {
    fn get_startup_parameters(&self) -> Vec<crate::llm::actions::ParameterDefinition> {
        vec![
            crate::llm::actions::ParameterDefinition {
                name: "first_byte_timeout_secs".to_string(),
                type_hint: "number".to_string(),
                description:
                    "Seconds a connected peer may send no request at all before the server \
                     closes it. Default 30: HTTP is client-speaks-first, and NetGet's own \
                     OpenAI client opens no socket until it has a request to send, so nothing \
                     here is ever connected and waiting on a person."
                        .to_string(),
                required: false,
                example: json!(30),
                default: Some(serde_json::json!(super::FIRST_BYTE_READ_TIMEOUT.as_secs())),
            },
            crate::llm::actions::ParameterDefinition {
                name: "idle_timeout_secs".to_string(),
                type_hint: "number".to_string(),
                description:
                    "Seconds an established connection may sit silent between requests before \
                     the server closes it. Default 300, chosen to stay above the 90 seconds \
                     reqwest and most OpenAI SDKs keep an idle pooled connection: a shorter \
                     bound races the pool and loses a non-idempotent completion request."
                        .to_string(),
                required: false,
                example: json!(300),
                default: Some(serde_json::json!(
                    super::IDLE_BETWEEN_REQUESTS_TIMEOUT.as_secs()
                )),
            },
        ]
    }
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![list_active_chats_action()]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            openai_chat_response_action(),
            openai_models_response_action(),
            openai_error_response_action(),
        ]
    }
    fn protocol_name(&self) -> &'static str {
        "OpenAI"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        get_openai_event_types()
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>HTTP>OPENAI"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["openai"]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Beta)
            .implementation("hyper with OpenAI-compatible HTTP endpoints")
            .llm_control("Event/action system - LLM generates OpenAI responses")
            .e2e_testing(
                "tests/server/openai/e2e_test.rs, 10 LLM calls. Verified against the real \
                 async-openai 0.26 Rust client: models().list(), chat().create() and the 404 \
                 path, all deserialized into the SDK's own types (a malformed error body would \
                 surface as a transport failure, not OpenAIError::ApiError). reqwest covers the \
                 raw JSON envelope the SDK hides. No Python SDK is involved - an earlier version \
                 of this field claimed one. Streaming, function calling and embeddings are \
                 untested.",
            )
            .notes("OpenAI-compatible API with LLM-driven responses")
            .max_inbound_bytes(crate::server::openai::MAX_REQUEST_BODY_BYTES)
            .request_only("The OpenAI API is HTTP request/response; a server cannot send a peer anything unprompted")
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "OpenAI-compatible API server"
    }
    fn example_prompt(&self) -> &'static str {
        "Start an OpenAI-compatible API server on port 11435"
    }
    fn group_name(&self) -> &'static str {
        "AI & API"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;

        StartupExamples::new(
            // LLM mode: instruction-based
            json!({
                "type": "open_server",
                "port": 11434,
                "base_stack": "openai",
                "instruction": "OpenAI-compatible API server. Respond to chat completions with helpful responses and list available models on /v1/models"
            }),
            // Script mode: event_handlers with script handler
            json!({
                "type": "open_server",
                "port": 11434,
                "base_stack": "openai",
                "event_handlers": [{
                    "event_pattern": "openai_request",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "if event['path'] == '/v1/models':\n    action('openai_models_response', models=['gpt-4', 'gpt-3.5-turbo'])\nelse:\n    action('openai_chat_response', content='Hello from script!', model='gpt-4')"
                    }
                }]
            }),
            // Static mode: event_handlers with static actions
            json!({
                "type": "open_server",
                "port": 11434,
                "base_stack": "openai",
                "event_handlers": [{
                    "event_pattern": "openai_request",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "openai_chat_response",
                            "content": "I am a static OpenAI response",
                            "model": "gpt-3.5-turbo"
                        }]
                    }
                }]
            }),
        )
    }
}

// Implement Server trait (server-specific functionality)
impl Server for OpenAiProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::server::openai::OpenAiServer;

            // Both read deadlines are the operator's to choose: who is on the other end is
            // the only thing that decides them, and only the operator knows that.
            let secs = |name: &str| -> anyhow::Result<Option<u64>> {
                Ok(ctx
                    .startup_params
                    .as_ref()
                    .map(|p| p.get_optional_u64(name))
                    .transpose()?
                    .flatten())
            };
            let first_byte_timeout_secs = secs("first_byte_timeout_secs")?;
            let idle_timeout_secs = secs("idle_timeout_secs")?;

            OpenAiServer::spawn_with_llm_actions(
                ctx.legacy_listen_addr(),
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                false,
                ctx.server_id,
                first_byte_timeout_secs,
                idle_timeout_secs,
            )
            .await
        })
    }
    fn execute_action(&self, action: serde_json::Value) -> Result<ActionResult> {
        let action_type = action
            .get("type")
            .and_then(|v| v.as_str())
            .context("Missing 'type' field in action")?;

        match action_type {
            "openai_chat_response" => self.execute_openai_chat_response(action),
            "openai_models_response" => self.execute_openai_models_response(action),
            "openai_error_response" => self.execute_openai_error_response(action),
            "list_active_chats" => self.execute_list_active_chats(action),
            _ => Err(anyhow::anyhow!("Unknown OpenAI action: {}", action_type)),
        }
    }
}

impl OpenAiProtocol {
    fn execute_openai_chat_response(&self, action: serde_json::Value) -> Result<ActionResult> {
        let content = action
            .get("content")
            .and_then(|v| v.as_str())
            .context("Missing 'content' field")?;

        let model = action
            .get("model")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        debug!(
            "OpenAI chat response: {} chars, model={}",
            content.len(),
            model
        );

        // Build OpenAI-compatible chat completion response
        let completion_id = format!("chatcmpl-{}", chrono::Utc::now().timestamp());
        let created = crate::utils::clock::SystemTime::now()
            .duration_since(crate::utils::clock::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let response = json!({
            "id": completion_id,
            "object": "chat.completion",
            "created": created,
            "model": model,
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": content
                },
                "finish_reason": "stop"
            }],
            "usage": {
                "prompt_tokens": 0,
                "completion_tokens": 0,
                "total_tokens": 0
            }
        });

        Ok(ActionResult::Custom {
            name: "openai_response".to_string(),
            data: json!({
                "status": 200,
                "headers": vec![("Content-Type".to_string(), "application/json".to_string())],
                "body": response.to_string()
            }),
        })
    }

    fn execute_openai_models_response(&self, action: serde_json::Value) -> Result<ActionResult> {
        let models = action
            .get("models")
            .and_then(|v| v.as_array())
            .context("Missing 'models' array")?;

        debug!("OpenAI models response: {} models", models.len());

        // Convert to OpenAI format
        let openai_models: Vec<serde_json::Value> = models
            .iter()
            .map(|model_name| {
                let name = model_name.as_str().unwrap_or("unknown");
                json!({
                    "id": name,
                    "object": "model",
                    "created": 1686935002,
                    "owned_by": "ollama"
                })
            })
            .collect();

        let response = json!({
            "object": "list",
            "data": openai_models
        });

        Ok(ActionResult::Custom {
            name: "openai_response".to_string(),
            data: json!({
                "status": 200,
                "headers": vec![("Content-Type".to_string(), "application/json".to_string())],
                "body": response.to_string()
            }),
        })
    }

    fn execute_openai_error_response(&self, action: serde_json::Value) -> Result<ActionResult> {
        let message = action
            .get("message")
            .and_then(|v| v.as_str())
            .unwrap_or("An error occurred");

        let error_type = action
            .get("error_type")
            .and_then(|v| v.as_str())
            .unwrap_or("server_error");

        // `as u16` wraps: `status: 65736` is 200, and this action is the model's only way to
        // return an OpenAI-shaped error. The client then reads a 200 whose body happens to
        // carry an `error` object, which an OpenAI SDK treats as a successful completion with
        // unexpected fields. Refuse, rather than clamp to something else it did not ask for.
        let status = match action.get("status") {
            None => 500,
            Some(v) if v.is_null() => 500,
            Some(v) => {
                let raw = v.as_u64().ok_or_else(|| {
                    anyhow::anyhow!("send_openai_error 'status' must be a number, got {v}")
                })?;
                if !(100..=599).contains(&raw) {
                    return Err(anyhow::anyhow!(
                        "send_openai_error 'status' {raw} is not an HTTP status code; use \
                         100-599 (400 invalid request, 401 bad key, 429 rate limited, 500 \
                         server error)"
                    ));
                }
                raw as u16
            }
        };

        debug!("OpenAI error response: {} ({})", message, status);

        let response = json!({
            "error": {
                "message": message,
                "type": error_type,
                "code": "error"
            }
        });

        Ok(ActionResult::Custom {
            name: "openai_response".to_string(),
            data: json!({
                "status": status,
                "headers": vec![("Content-Type".to_string(), "application/json".to_string())],
                "body": response.to_string()
            }),
        })
    }

    fn execute_list_active_chats(&self, _action: serde_json::Value) -> Result<ActionResult> {
        debug!("OpenAI list active chats");

        // This is a placeholder - in a real implementation, we'd track chat sessions
        Ok(ActionResult::Custom {
            name: "list_active_chats".to_string(),
            data: json!({"chats": []}),
        })
    }
}

/// Action definition: Send OpenAI chat completion response
pub fn openai_chat_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "openai_chat_response".to_string(),
        description: "Send a chat completion response in OpenAI format".to_string(),
        parameters: vec![
            Parameter {
                name: "content".to_string(),
                type_hint: "string".to_string(),
                description: "The assistant's response text".to_string(),
                required: true,
            },
            Parameter {
                name: "model".to_string(),
                type_hint: "string".to_string(),
                description: "Model name (e.g., 'gpt-3.5-turbo')".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "openai_chat_response",
            "content": "Hello! How can I help you today?",
            "model": "gpt-3.5-turbo"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> OpenAI chat {model} ({content_len} chars)")
                .with_debug("OpenAI openai_chat_response: model={model} content_len={content_len}"),
        ),
    }
}

/// Action definition: Send models list response
pub fn openai_models_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "openai_models_response".to_string(),
        description: "Respond to GET /v1/models with available models".to_string(),
        parameters: vec![Parameter {
            name: "models".to_string(),
            type_hint: "array".to_string(),
            description: "Array of model names (e.g., ['gpt-3.5-turbo', 'gpt-4'])".to_string(),
            required: true,
        }],
        example: json!({
            "type": "openai_models_response",
            "models": ["gpt-3.5-turbo", "gpt-4"]
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> OpenAI models ({models_len} available)")
                .with_debug("OpenAI openai_models_response: models_count={models_len}"),
        ),
    }
}

/// Action definition: Send error response
pub fn openai_error_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "openai_error_response".to_string(),
        description: "Send an error response in OpenAI format".to_string(),
        parameters: vec![
            Parameter {
                name: "message".to_string(),
                type_hint: "string".to_string(),
                description: "Error message".to_string(),
                required: true,
            },
            Parameter {
                name: "error_type".to_string(),
                type_hint: "string".to_string(),
                description: "Error type (e.g., 'invalid_request_error', 'server_error')"
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "status".to_string(),
                type_hint: "number".to_string(),
                description: "HTTP status code (default: 500)".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "openai_error_response",
            "message": "Invalid API key",
            "error_type": "invalid_request_error",
            "status": 401
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> OpenAI error {status}: {message}")
                .with_debug("OpenAI openai_error_response: status={status} type={error_type} message={message}"),
        ),
    }
}

/// Action definition: List active chat sessions
pub fn list_active_chats_action() -> ActionDefinition {
    ActionDefinition {
        name: "list_active_chats".to_string(),
        description: "List currently active chat sessions".to_string(),
        parameters: vec![],
        example: json!({
            "type": "list_active_chats"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> OpenAI list active chats")
                .with_debug("OpenAI list_active_chats"),
        ),
    }
}

/// Get OpenAI event types
pub fn get_openai_event_types() -> Vec<EventType> {
    vec![OPENAI_REQUEST_EVENT.clone()]
}

//! OpenAI client protocol actions implementation

use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, Parameter, ParameterDefinition,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::EventType;
use crate::state::app_state::AppState;
use anyhow::{Context, Result};
use serde_json::json;
use std::sync::LazyLock;

/// OpenAI client connected event
pub static OPENAI_CLIENT_CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "openai_connected",
        "OpenAI client initialized and ready to make API requests",
        json!({
            "type": "send_chat_completion",
            "messages": [
                {"role": "user", "content": "Hello!"}
            ],
            "model": "gpt-3.5-turbo"
        }),
    )
    .with_parameters(vec![Parameter {
        name: "api_endpoint".to_string(),
        type_hint: "string".to_string(),
        description: "OpenAI API endpoint URL".to_string(),
        required: true,
    }])
});

/// OpenAI client response received event
pub static OPENAI_CLIENT_RESPONSE_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "openai_response_received",
        "Response received from OpenAI API",
        json!({
            "type": "send_chat_completion",
            "messages": [
                {"role": "user", "content": "Follow-up question"}
            ]
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "response_type".to_string(),
            type_hint: "string".to_string(),
            description: "Type of response (chat_completion, embedding, etc.)".to_string(),
            required: true,
        },
        Parameter {
            name: "content".to_string(),
            type_hint: "string".to_string(),
            description: "Response content or error message".to_string(),
            required: true,
        },
        Parameter {
            name: "model".to_string(),
            type_hint: "string".to_string(),
            description: "Model used for the request".to_string(),
            required: false,
        },
        Parameter {
            name: "usage".to_string(),
            type_hint: "object".to_string(),
            description: "Token usage statistics".to_string(),
            required: false,
        },
    ])
});

/// Largest `max_tokens` this client will forward.
///
/// Comfortably above any real model's context window, so it never truncates a legitimate
/// request; its job is to keep the value inside `u32` and away from the narrowing casts that
/// used to sit between the model and the wire.
const MAX_COMPLETION_TOKENS: u64 = 1_000_000;

/// OpenAI client protocol action handler
pub struct OpenAiClientProtocol;

impl Default for OpenAiClientProtocol {
    fn default() -> Self {
        Self::new()
    }
}

impl OpenAiClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for OpenAiClientProtocol {
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "api_key".to_string(),
                description: "OpenAI API key for authentication".to_string(),
                type_hint: "string".to_string(),
                required: true,
                example: json!("sk-..."),
                default: None,
            },
            ParameterDefinition {
                name: "default_model".to_string(),
                description: "Default model to use for requests".to_string(),
                type_hint: "string".to_string(),
                required: false,
                example: json!("gpt-4"),
                default: None,
            },
            ParameterDefinition {
                name: "organization".to_string(),
                description: "OpenAI organization ID".to_string(),
                type_hint: "string".to_string(),
                required: false,
                example: json!("org-..."),
                default: None,
            },
        ]
    }
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![
            ActionDefinition {
                name: "send_chat_completion".to_string(),
                description: "Send a chat completion request to OpenAI".to_string(),
                parameters: vec![
                    Parameter {
                        name: "messages".to_string(),
                        type_hint: "array".to_string(),
                        description: "Array of message objects with role and content".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "model".to_string(),
                        type_hint: "string".to_string(),
                        description: "Model to use (e.g., gpt-4, gpt-3.5-turbo)".to_string(),
                        required: false,
                    },
                    Parameter {
                        name: "temperature".to_string(),
                        type_hint: "number".to_string(),
                        description: "Sampling temperature (0.0 to 2.0)".to_string(),
                        required: false,
                    },
                    Parameter {
                        name: "max_tokens".to_string(),
                        type_hint: "number".to_string(),
                        description: "Maximum tokens to generate".to_string(),
                        required: false,
                    },
                    Parameter {
                        name: "functions".to_string(),
                        type_hint: "array".to_string(),
                        description: "Array of function definitions for function calling"
                            .to_string(),
                        required: false,
                    },
                ],
                example: json!({
                    "type": "send_chat_completion",
                    "messages": [
                        {"role": "user", "content": "Hello!"}
                    ],
                    "model": "gpt-3.5-turbo"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "send_embedding_request".to_string(),
                description: "Generate embeddings for text".to_string(),
                parameters: vec![
                    Parameter {
                        name: "input".to_string(),
                        type_hint: "string | array".to_string(),
                        description: "Text or array of texts to embed".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "model".to_string(),
                        type_hint: "string".to_string(),
                        description: "Embedding model to use (e.g., text-embedding-ada-002)"
                            .to_string(),
                        required: false,
                    },
                ],
                example: json!({
                    "type": "send_embedding_request",
                    "input": "The quick brown fox",
                    "model": "text-embedding-ada-002"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "disconnect".to_string(),
                description: "Close the OpenAI client connection".to_string(),
                parameters: vec![],
                example: json!({
                    "type": "disconnect"
                }),
                log_template: None,
            },
        ]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![ActionDefinition {
            name: "send_chat_completion".to_string(),
            description: "Send another chat completion in response to received data".to_string(),
            parameters: vec![
                Parameter {
                    name: "messages".to_string(),
                    type_hint: "array".to_string(),
                    description: "Array of message objects".to_string(),
                    required: true,
                },
                Parameter {
                    name: "model".to_string(),
                    type_hint: "string".to_string(),
                    description: "Model to use".to_string(),
                    required: false,
                },
            ],
            example: json!({
                "type": "send_chat_completion",
                "messages": [
                    {"role": "user", "content": "Follow-up question"}
                ]
            }),
            log_template: Some(
                LogTemplate::new()
                    .with_info("-> OpenAI chat completion ({model})")
                    .with_debug("OpenAI send_chat_completion: model={model}"),
            ),
        }]
    }
    fn protocol_name(&self) -> &'static str {
        "OpenAI"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            EventType::new(
                "openai_connected",
                "Triggered when OpenAI client is initialized",
                json!({"type": "placeholder", "event_id": "openai_connected"}),
            ),
            EventType::new(
                "openai_response_received",
                "Triggered when OpenAI client receives a response",
                json!({"type": "placeholder", "event_id": "openai_response_received"}),
            ),
        ]
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>TLS>HTTPS>OpenAI"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["openai", "openai client", "gpt", "chatgpt", "openai api"]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .implementation(
                "async-openai 0.26 over a reqwest client built once per endpoint on \
                 spawn_blocking, so the platform root store is not loaded on the async \
                 runtime and a literal-IP host skips the system resolver. The API base comes \
                 from remote_addr and nothing else: an absent one refuses rather than \
                 reaching async-openai's default of https://api.openai.com/v1.",
            )
            .llm_control("Full control over chat completions, embeddings, and function calling")
            .e2e_testing(
                "tests/client/openai/. endpoint_and_limits_test pins the API base against \
                 the vendor default and the max_tokens/temperature ranges; \
                 command_channel_test drives the injected-action path against a loopback \
                 OpenAI-shaped stub; e2e_test starts the real binary against a dead loopback \
                 port. No test contacts api.openai.com and no real key is involved, so this \
                 is not validation against the real API.",
            )
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "OpenAI API client for LLM interactions"
    }
    fn example_prompt(&self) -> &'static str {
        "Connect to OpenAI and ask GPT-4 to explain quantum computing"
    }
    fn group_name(&self) -> &'static str {
        "AI & API"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        use serde_json::json;

        StartupExamples::new(
            // LLM mode: LLM controls OpenAI API interactions
            json!({
                "type": "open_client",
                "remote_addr": "https://api.openai.com",
                "base_stack": "openai",
                "instruction": "Ask GPT-4 to explain quantum computing in simple terms",
                "startup_params": {
                    "api_key": "sk-...",
                    "default_model": "gpt-4"
                }
            }),
            // Script mode: Code-based OpenAI interactions
            json!({
                "type": "open_client",
                "remote_addr": "https://api.openai.com",
                "base_stack": "openai",
                "startup_params": {
                    "api_key": "sk-...",
                    "default_model": "gpt-3.5-turbo"
                },
                "event_handlers": [{
                    "event_pattern": "openai_response_received",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "<openai_client_handler>"
                    }
                }]
            }),
            // Static mode: Fixed chat completion request
            json!({
                "type": "open_client",
                "remote_addr": "https://api.openai.com",
                "base_stack": "openai",
                "startup_params": {
                    "api_key": "sk-...",
                    "default_model": "gpt-3.5-turbo"
                },
                "event_handlers": [
                    {
                        "event_pattern": "openai_connected",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "send_chat_completion",
                                "messages": [
                                    {"role": "user", "content": "Hello!"}
                                ],
                                "model": "gpt-3.5-turbo"
                            }]
                        }
                    },
                    {
                        "event_pattern": "openai_response_received",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "disconnect"
                            }]
                        }
                    }
                ]
            }),
        )
    }
}

// Implement Client trait (client-specific functionality)
impl Client for OpenAiClientProtocol {
    fn connect(
        &self,
        ctx: crate::protocol::ConnectContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::client::openai::OpenAiClient;
            OpenAiClient::connect_with_llm_actions(
                ctx.remote_addr,
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.client_id,
                ctx.startup_params,
            )
            .await
        })
    }
    fn execute_action(&self, action: serde_json::Value) -> Result<ClientActionResult> {
        let action_type = action
            .get("type")
            .and_then(|v| v.as_str())
            .context("Missing 'type' field in action")?;

        match action_type {
            "send_chat_completion" => {
                let messages = action
                    .get("messages")
                    .context("Missing 'messages' field")?
                    .clone();

                let model = action
                    .get("model")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());

                // `as f32` turns a NaN or an out-of-range value into something the request
                // serialiser cannot represent, and OpenAI's own range is 0.0-2.0. Refuse
                // rather than send a number the API will reject with a message the model
                // never sees.
                let temperature = match action.get("temperature") {
                    None | Some(serde_json::Value::Null) => None,
                    Some(v) => {
                        let t = v.as_f64().ok_or_else(|| {
                            anyhow::anyhow!(
                                "send_chat_completion 'temperature' must be a number, got {v}"
                            )
                        })?;
                        if !t.is_finite() || !(0.0..=2.0).contains(&t) {
                            return Err(anyhow::anyhow!(
                                "send_chat_completion 'temperature' {t} is out of range; use \
                                 0.0-2.0"
                            ));
                        }
                        Some(t)
                    }
                };

                // Two narrowing casts used to sit between the model and the wire: `as u32`
                // here and `as u16` where the request was built. `max_tokens: 70000` became
                // 4464 and `max_tokens: 4294967296` became 0 — a budget silently replaced by
                // a different, smaller one, which reads on the wire as a deliberate choice.
                // Refuse instead, and name the range so the repair loop can correct it.
                let max_tokens = match action.get("max_tokens") {
                    None | Some(serde_json::Value::Null) => None,
                    Some(v) => {
                        let n = v.as_u64().ok_or_else(|| {
                            anyhow::anyhow!(
                                "send_chat_completion 'max_tokens' must be a positive whole \
                                 number, got {v}"
                            )
                        })?;
                        if n == 0 || n > MAX_COMPLETION_TOKENS {
                            return Err(anyhow::anyhow!(
                                "send_chat_completion 'max_tokens' {n} is out of range; use \
                                 1-{MAX_COMPLETION_TOKENS}"
                            ));
                        }
                        Some(n as u32)
                    }
                };

                let functions = action.get("functions").cloned();

                Ok(ClientActionResult::Custom {
                    name: "openai_chat_completion".to_string(),
                    data: json!({
                        "messages": messages,
                        "model": model,
                        "temperature": temperature,
                        "max_tokens": max_tokens,
                        "functions": functions,
                    }),
                })
            }
            "send_embedding_request" => {
                let input = action
                    .get("input")
                    .context("Missing 'input' field")?
                    .clone();

                let model = action
                    .get("model")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());

                Ok(ClientActionResult::Custom {
                    name: "openai_embedding".to_string(),
                    data: json!({
                        "input": input,
                        "model": model,
                    }),
                })
            }
            "disconnect" => Ok(ClientActionResult::Disconnect),
            _ => Err(anyhow::anyhow!(
                "Unknown OpenAI client action: {}",
                action_type
            )),
        }
    }
}

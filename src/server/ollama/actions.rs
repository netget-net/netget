//! Ollama protocol actions implementation

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

/// Ollama generate request event
pub static OLLAMA_GENERATE_REQUEST_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "ollama_generate_request",
        "A client called /api/generate. Answer with ollama_generate_response carrying the \
         completion text, or refuse with ollama_error_response.",
        json!({
            "type": "ollama_generate_response",
            "response_text": "The capital of France is Paris."
        }),
    )
    // Per-endpoint narrowing: /api/generate is answered with a generate response, never with a
    // chat or model-list response. `call_llm` builds the model's tool list from the event type
    // rather than from get_sync_actions(), so before this the model was offered none of them.
    .with_actions(vec![
        ollama_generate_response_action(),
        ollama_error_response_action(),
    ])
    .with_parameters(vec![
        Parameter {
            name: "model".to_string(),
            type_hint: "string".to_string(),
            description: "Model name requested".to_string(),
            required: true,
        },
        Parameter {
            name: "prompt".to_string(),
            type_hint: "string".to_string(),
            description: "Prompt text".to_string(),
            required: true,
        },
        Parameter {
            name: "stream".to_string(),
            type_hint: "boolean".to_string(),
            description: "Whether streaming is requested".to_string(),
            required: false,
        },
    ])
});

/// Ollama chat request event
pub static OLLAMA_CHAT_REQUEST_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "ollama_chat_request",
        "A client called /api/chat. Answer with ollama_chat_response carrying the assistant \
         message, or refuse with ollama_error_response.",
        json!({
            "type": "ollama_chat_response",
            "message_content": "Hello! How can I help you today?"
        }),
    )
    .with_actions(vec![
        ollama_chat_response_action(),
        ollama_error_response_action(),
    ])
    .with_parameters(vec![
        Parameter {
            name: "model".to_string(),
            type_hint: "string".to_string(),
            description: "Model name requested".to_string(),
            required: true,
        },
        Parameter {
            name: "messages".to_string(),
            type_hint: "array".to_string(),
            description: "Chat messages".to_string(),
            required: true,
        },
        Parameter {
            name: "stream".to_string(),
            type_hint: "boolean".to_string(),
            description: "Whether streaming is requested".to_string(),
            required: false,
        },
    ])
});

/// Ollama models request event
pub static OLLAMA_MODELS_REQUEST_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "ollama_models_request",
        "A client called /api/tags to list the models this server offers. Answer with \
         ollama_models_response, or refuse with ollama_error_response.",
        json!({
            "type": "ollama_models_response",
            "models": ["llama2", "codellama", "mistral"]
        }),
    )
    .with_actions(vec![
        ollama_models_response_action(),
        ollama_error_response_action(),
    ])
});

/// Acknowledge a model-management operation.
///
/// Separate from `ollama_error_response` so that accept and refuse share no code path — the
/// separation `src/server/radius/` established.
fn ollama_admin_ok_action() -> ActionDefinition {
    ActionDefinition {
        name: "ollama_admin_ok".to_string(),
        description: "Confirm a model-management operation (pull, create, copy, delete). \
                      Without this action the operation is refused - there is no implicit \
                      success."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "digest".to_string(),
                type_hint: "string".to_string(),
                description: "Digest to report for a pull, e.g. \"sha256:...\". Omit for other \
                              operations."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "total".to_string(),
                type_hint: "number".to_string(),
                description: "Total size in bytes to report for a pull. Omit for other \
                              operations."
                    .to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "ollama_admin_ok",
            "digest": "sha256:2f4b1c1e0a",
            "total": 3826793677i64
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> Ollama {operation} acknowledged")
                .with_debug("Ollama ollama_admin_ok: digest={digest} total={total}"),
        ),
    }
}

/// Answer `/api/show` with a model's details.
fn ollama_show_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "ollama_show_response".to_string(),
        description: "Return the details of the model /api/show asked about. Without this \
                      action the request is refused - nothing is invented."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "modelfile".to_string(),
                type_hint: "string".to_string(),
                description: "Modelfile contents, e.g. \"FROM llama2\"".to_string(),
                required: false,
            },
            Parameter {
                name: "parameters".to_string(),
                type_hint: "string".to_string(),
                description: "Parameter block, e.g. \"temperature 0.7\"".to_string(),
                required: false,
            },
            Parameter {
                name: "template".to_string(),
                type_hint: "string".to_string(),
                description: "Prompt template".to_string(),
                required: false,
            },
            Parameter {
                name: "details".to_string(),
                type_hint: "object".to_string(),
                description: "Details object, e.g. {\"format\": \"gguf\", \"family\": \"llama\"}"
                    .to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "ollama_show_response",
            "modelfile": "FROM llama2",
            "details": {"format": "gguf", "family": "llama"}
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> Ollama show answered")
                .with_debug("Ollama ollama_show_response: modelfile={modelfile}"),
        ),
    }
}

/// `/api/show`: a client asking what a model is.
///
/// This used to answer with a fabricated Modelfile (`FROM {name}`), a hardcoded
/// `temperature 0.7` and a `gguf`/`llama` details block, for any name at all and without an
/// event — so a server told "this instance serves only llama2" described every model a client
/// asked about, including ones it had just refused to pull.
pub static OLLAMA_SHOW_REQUEST_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "ollama_show_request",
        "A client asked /api/show for a model's details. Answer with ollama_show_response, or \
         refuse with ollama_error_response.",
        json!({
            "type": "ollama_show_response",
            "modelfile": "FROM llama2"
        }),
    )
    .with_parameters(vec![Parameter {
        name: "model".to_string(),
        type_hint: "string".to_string(),
        description: "Model the client asked about".to_string(),
        required: true,
    }])
    .with_actions(vec![
        ollama_show_response_action(),
        ollama_error_response_action(),
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("{client_ip} Ollama show {model}")
            .with_debug("Ollama show request: model={model}"),
    )
});

/// Answer `/api/embeddings` with a vector, or with the dimensionality of one.
fn ollama_embeddings_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "ollama_embeddings_response".to_string(),
        description: "Answer the /api/embeddings request. Supply `embedding` when the exact \
                      vector matters, or `dimensions` when only its shape does - a \
                      `dimensions`-only answer returns a deterministic ramp, which is a \
                      well-formed vector but carries no meaning. Without this action the \
                      request is refused; nothing is invented."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "embedding".to_string(),
                type_hint: "array".to_string(),
                description: "The embedding vector, as an array of numbers".to_string(),
                required: false,
            },
            Parameter {
                name: "dimensions".to_string(),
                type_hint: "number".to_string(),
                description: "Length of the vector to return when `embedding` is omitted \
                              (1-4096). Real Ollama models are 384-8192 wide; 768 is typical."
                    .to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "ollama_embeddings_response",
            "dimensions": 768
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> Ollama embeddings ({dimensions} dimensions)")
                .with_debug("Ollama ollama_embeddings_response: dimensions={dimensions}"),
        ),
    }
}

/// `/api/embeddings`: a client asking for a vector.
///
/// This used to answer every request with a hardcoded 768-element ramp, with no event, no
/// `call_llm` anywhere in the path and no way for the server's instruction to reach it - the
/// same defect `/api/show` and the four model-management endpoints had. A server told "this
/// instance serves only llama2" embedded for every model name asked of it, and a server the
/// operator had told to refuse everything embedded anyway.
pub static OLLAMA_EMBEDDINGS_REQUEST_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "ollama_embeddings_request",
        "A client asked /api/embeddings to embed a prompt. Answer with \
         ollama_embeddings_response, or refuse with ollama_error_response.",
        json!({
            "type": "ollama_embeddings_response",
            "dimensions": 768
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "model".to_string(),
            type_hint: "string".to_string(),
            description: "Model the client asked to embed with".to_string(),
            required: true,
        },
        Parameter {
            name: "prompt".to_string(),
            type_hint: "string".to_string(),
            description: "Text the client asked to embed".to_string(),
            required: false,
        },
    ])
    .with_actions(vec![
        ollama_embeddings_response_action(),
        ollama_error_response_action(),
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("{client_ip} Ollama embeddings {model}")
            .with_debug("Ollama embeddings request: model={model}"),
    )
});

/// Model-management event: `/api/pull`, `/api/create`, `/api/copy`, `/api/delete`.
///
/// These four endpoints used to answer `{"status":"success"}` unconditionally, without an
/// event and without consulting the model at all — so a server told "this instance only
/// serves llama2, refuse everything else" reported every pull as downloaded and every delete
/// as removed. `/api/pull` additionally invented a digest of `sha256:0000000000000000`.
pub static OLLAMA_ADMIN_REQUEST_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "ollama_admin_request",
        "A client asked to pull, create, copy or delete a model. Confirm with \
         ollama_admin_ok, or refuse with ollama_error_response.",
        json!({
            "type": "ollama_admin_ok"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "operation".to_string(),
            type_hint: "string".to_string(),
            description: "One of: pull, create, copy, delete".to_string(),
            required: true,
        },
        Parameter {
            name: "model".to_string(),
            type_hint: "string".to_string(),
            description: "Model the request names (the `name` or `model` field)".to_string(),
            required: false,
        },
        Parameter {
            name: "destination".to_string(),
            type_hint: "string".to_string(),
            description: "Destination model name, for copy".to_string(),
            required: false,
        },
    ])
    .with_actions(vec![
        ollama_admin_ok_action(),
        ollama_error_response_action(),
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("{client_ip} Ollama {operation} {model}")
            .with_debug("Ollama admin {operation}: model={model} destination={destination}"),
    )
});

/// Ollama protocol action handler
pub struct OllamaProtocol {}

impl OllamaProtocol {
    pub fn new() -> Self {
        Self {}
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for OllamaProtocol {
    fn get_startup_parameters(&self) -> Vec<crate::llm::actions::ParameterDefinition> {
        vec![
            crate::llm::actions::ParameterDefinition {
                name: "first_byte_timeout_secs".to_string(),
                type_hint: "number".to_string(),
                description:
                    "Seconds a connected peer may send no request at all before the server \
                     closes it. Default 30: HTTP is client-speaks-first, and NetGet's own \
                     Ollama client opens no socket until it has a request to send, so nothing \
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
                     reqwest keeps an idle pooled connection: a shorter bound races the pool \
                     and loses a non-idempotent /api/generate."
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
        vec![]
    }

    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            ollama_generate_response_action(),
            ollama_chat_response_action(),
            ollama_models_response_action(),
            ollama_admin_ok_action(),
            ollama_show_response_action(),
            ollama_embeddings_response_action(),
            ollama_error_response_action(),
        ]
    }

    fn protocol_name(&self) -> &'static str {
        "Ollama"
    }

    fn get_event_types(&self) -> Vec<EventType> {
        get_ollama_event_types()
    }

    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>HTTP>OLLAMA"
    }

    fn keywords(&self) -> Vec<&'static str> {
        vec!["ollama", "llm", "ai"]
    }

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Beta)
            .well_known_port(11434)
            .implementation("hyper with Ollama-compatible HTTP endpoints")
            .llm_control(
                "Every endpoint is a model decision: /api/generate, /api/chat, /api/tags, \
                 /api/show, /api/embeddings and the four model-management endpoints each \
                 raise an event and refuse when the model does not answer.",
            )
            .e2e_testing(
                "tests/server/ollama/e2e_test.rs. Driven by ollama-rs 0.3 - the same \
                 third-party crate netget uses to talk to a real Ollama, here in the client \
                 role - for /api/tags, /api/generate and /api/chat, plus reqwest for the raw \
                 JSON envelope, the refusal paths and the endpoints ollama-rs does not \
                 expose. An earlier version of this field claimed an \"ollama Python \
                 library\"; no Python was ever involved.",
            )
            .notes(
                "Mock Ollama API server for testing and honeypot purposes. Beta rests on \
                 real_client_test.rs: ollama-rs deserialises our /api/tags, /api/generate \
                 and /api/chat envelopes for itself, it is an unconditional dependency so \
                 the evidence runs wherever --features ollama compiles, and it is not \
                 circular - this server frames with hyper and serde_json, never with \
                 ollama-rs. Not Stable: streaming is assembled whole in memory rather than \
                 chunked, no client has driven the four model-management endpoints, and \
                 nothing validates an Authorization header (none is read, so the model \
                 cannot make that call either).",
            )
            .max_inbound_bytes(crate::server::ollama::MAX_REQUEST_BODY_BYTES)
            .request_only("The Ollama API is HTTP request/response; a server cannot send a peer anything unprompted")
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }

    fn description(&self) -> &'static str {
        "Ollama-compatible API server"
    }

    fn example_prompt(&self) -> &'static str {
        "Start an Ollama-compatible API server on port 11435"
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
                "port": 11435,
                "base_stack": "ollama",
                "instruction": "Ollama-compatible API server. Respond to /api/generate and /api/chat requests with helpful LLM responses, and list models on /api/tags"
            }),
            // Script mode: event_handlers with script handler
            json!({
                "type": "open_server",
                "port": 11435,
                "base_stack": "ollama",
                "event_handlers": [{
                    "event_pattern": "ollama_chat_request",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "model = event.get('model', 'llama2')\naction('ollama_chat_response', message_content=f'Hello from {model}!')"
                    }
                }]
            }),
            // Static mode: event_handlers with static actions
            json!({
                "type": "open_server",
                "port": 11435,
                "base_stack": "ollama",
                "event_handlers": [{
                    "event_pattern": "ollama_models_request",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "ollama_models_response",
                            "models": ["llama2", "codellama", "mistral"]
                        }]
                    }
                }]
            }),
        )
    }
}

// Implement Server trait (server-specific functionality)
impl Server for OllamaProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::server::ollama::OllamaServer;

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

            OllamaServer::spawn_with_llm_actions(
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
            "ollama_generate_response" => self.execute_ollama_generate_response(action),
            "ollama_chat_response" => self.execute_ollama_chat_response(action),
            "ollama_models_response" => self.execute_ollama_models_response(action),
            "ollama_admin_ok" => {
                let mut data = json!({});
                if let Some(d) = action.get("digest").and_then(|v| v.as_str()) {
                    data["digest"] = json!(d);
                }
                if let Some(t) = action.get("total").and_then(|v| v.as_u64()) {
                    data["total"] = json!(t);
                }
                Ok(ActionResult::Custom {
                    name: "ollama_admin_ok".to_string(),
                    data,
                })
            }
            "ollama_show_response" => {
                let mut data = json!({});
                for field in ["modelfile", "parameters", "template"] {
                    if let Some(v) = action.get(field).and_then(|v| v.as_str()) {
                        data[field] = json!(v);
                    }
                }
                if let Some(d) = action.get("details") {
                    data["details"] = d.clone();
                }
                Ok(ActionResult::Custom {
                    name: "ollama_show_response".to_string(),
                    data,
                })
            }
            "ollama_embeddings_response" => self.execute_ollama_embeddings_response(action),
            "ollama_error_response" => self.execute_ollama_error_response(action),
            _ => Err(anyhow::anyhow!("Unknown Ollama action: {}", action_type)),
        }
    }
}

impl OllamaProtocol {
    fn execute_ollama_generate_response(&self, _action: serde_json::Value) -> Result<ActionResult> {
        debug!("Execute: ollama_generate_response");
        Ok(ActionResult::Custom {
            name: "ollama_generate_response".to_string(),
            data: json!({"status": "acknowledged"}),
        })
    }

    fn execute_ollama_chat_response(&self, _action: serde_json::Value) -> Result<ActionResult> {
        debug!("Execute: ollama_chat_response");
        Ok(ActionResult::Custom {
            name: "ollama_chat_response".to_string(),
            data: json!({"status": "acknowledged"}),
        })
    }

    fn execute_ollama_models_response(&self, _action: serde_json::Value) -> Result<ActionResult> {
        debug!("Execute: ollama_models_response");
        Ok(ActionResult::Custom {
            name: "ollama_models_response".to_string(),
            data: json!({"status": "acknowledged"}),
        })
    }

    /// Build the `/api/embeddings` vector the model asked for.
    ///
    /// `dimensions` is validated here rather than where the response is built, so an
    /// unusable value is refused while the repair loop can still correct it. The cap is not
    /// cosmetic: the vector is serialised into the reply and `dimensions` is model-supplied,
    /// so an unbounded value is an allocation a single request can name.
    fn execute_ollama_embeddings_response(
        &self,
        action: serde_json::Value,
    ) -> Result<ActionResult> {
        const MAX_DIMENSIONS: u64 = 4096;

        if let Some(values) = action.get("embedding") {
            let values = values
                .as_array()
                .context("ollama_embeddings_response 'embedding' must be an array of numbers")?;
            if values.is_empty() {
                return Err(anyhow::anyhow!(
                    "ollama_embeddings_response 'embedding' must not be empty; omit it and \
                     give 'dimensions' instead, or refuse with ollama_error_response"
                ));
            }
            if values.len() as u64 > MAX_DIMENSIONS {
                return Err(anyhow::anyhow!(
                    "ollama_embeddings_response 'embedding' has {} elements; the limit is {}",
                    values.len(),
                    MAX_DIMENSIONS
                ));
            }
            let vector: Vec<f64> = values
                .iter()
                .map(|v| {
                    v.as_f64().ok_or_else(|| {
                        anyhow::anyhow!(
                            "ollama_embeddings_response 'embedding' must contain only \
                             numbers, got {v}"
                        )
                    })
                })
                .collect::<Result<_>>()?;
            debug!(
                "Execute: ollama_embeddings_response ({} given)",
                vector.len()
            );
            return Ok(ActionResult::Custom {
                name: "ollama_embeddings_response".to_string(),
                data: json!({ "embedding": vector }),
            });
        }

        let dimensions = action.get("dimensions").and_then(|v| v.as_u64()).context(
            "ollama_embeddings_response needs either 'embedding' (an array of numbers) or \
             'dimensions' (how long a vector to return)",
        )?;
        if dimensions == 0 || dimensions > MAX_DIMENSIONS {
            return Err(anyhow::anyhow!(
                "ollama_embeddings_response 'dimensions' {} is out of range; use 1-{} (768 \
                 is a typical embedding width)",
                dimensions,
                MAX_DIMENSIONS
            ));
        }

        // A deterministic ramp. It is not an embedding of anything, and the action's own
        // description says so - the alternative is asking a model to emit 768 floats.
        let vector: Vec<f64> = (0..dimensions)
            .map(|i| i as f64 / dimensions as f64)
            .collect();
        debug!("Execute: ollama_embeddings_response ({dimensions} dimensions)");
        Ok(ActionResult::Custom {
            name: "ollama_embeddings_response".to_string(),
            data: json!({ "embedding": vector }),
        })
    }

    fn execute_ollama_error_response(&self, _action: serde_json::Value) -> Result<ActionResult> {
        debug!("Execute: ollama_error_response");
        Ok(ActionResult::Custom {
            name: "ollama_error_response".to_string(),
            data: json!({"status": "acknowledged"}),
        })
    }
}

// Action definitions
fn ollama_generate_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "ollama_generate_response".to_string(),
        description: "Respond to /api/generate request with LLM-generated text".to_string(),
        parameters: vec![Parameter {
            name: "response_text".to_string(),
            type_hint: "string".to_string(),
            description: "Generated text response".to_string(),
            required: true,
        }],
        example: json!({
            "type": "ollama_generate_response",
            "response_text": "The capital of France is Paris."
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> Ollama generate ({response_text_len} chars)")
                .with_debug("Ollama ollama_generate_response: response_len={response_text_len}"),
        ),
    }
}

fn ollama_chat_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "ollama_chat_response".to_string(),
        description: "Respond to /api/chat request with chat message".to_string(),
        parameters: vec![Parameter {
            name: "message_content".to_string(),
            type_hint: "string".to_string(),
            description: "Chat message content".to_string(),
            required: true,
        }],
        example: json!({
            "type": "ollama_chat_response",
            "message_content": "Hello! How can I help you today?"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> Ollama chat ({message_content_len} chars)")
                .with_debug("Ollama ollama_chat_response: content_len={message_content_len}"),
        ),
    }
}

fn ollama_models_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "ollama_models_response".to_string(),
        description: "Respond to /api/tags with list of models".to_string(),
        parameters: vec![Parameter {
            name: "models".to_string(),
            type_hint: "array".to_string(),
            description: "List of model names".to_string(),
            required: true,
        }],
        example: json!({
            "type": "ollama_models_response",
            "models": ["llama2", "codellama", "mistral"]
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> Ollama models ({models_len} available)")
                .with_debug("Ollama ollama_models_response: models_count={models_len}"),
        ),
    }
}

fn ollama_error_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "ollama_error_response".to_string(),
        description: "Refuse this request. Returns the message as Ollama's \
            {\"error\": \"...\"} body with a 4xx status, instead of answering it."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "error_message".to_string(),
                type_hint: "string".to_string(),
                description: "Error message to return".to_string(),
                required: true,
            },
            Parameter {
                name: "status_code".to_string(),
                type_hint: "number".to_string(),
                description: "HTTP status for the refusal. Defaults to 400; real Ollama \
                    answers 404 for an unknown model."
                    .to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "ollama_error_response",
            "error_message": "Model not found",
            "status_code": 404
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> Ollama error: {error_message}")
                .with_debug("Ollama ollama_error_response: {error_message}"),
        ),
    }
}

/// Get Ollama-specific event types
///
/// These are clones of the constants `mod.rs` passes to `call_llm`, so the documented event
/// catalog and the action list the model is actually offered cannot diverge.
fn get_ollama_event_types() -> Vec<EventType> {
    vec![
        OLLAMA_GENERATE_REQUEST_EVENT.clone(),
        OLLAMA_CHAT_REQUEST_EVENT.clone(),
        OLLAMA_MODELS_REQUEST_EVENT.clone(),
        OLLAMA_ADMIN_REQUEST_EVENT.clone(),
        OLLAMA_SHOW_REQUEST_EVENT.clone(),
        OLLAMA_EMBEDDINGS_REQUEST_EVENT.clone(),
    ]
}

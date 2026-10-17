//! JSON-RPC protocol actions implementation

use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::EventType;
use crate::state::app_state::AppState;
use anyhow::{Context, Result};
use serde_json::json;
use std::sync::LazyLock;
use tracing::debug;

/// JSON-RPC protocol action handler
pub struct JsonRpcProtocol {}

impl JsonRpcProtocol {
    pub fn new() -> Self {
        Self {}
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for JsonRpcProtocol {
    /// None. `send_first` used to be declared here and was bound as `_send_first`
    /// in the server, i.e. accepted and ignored: JSON-RPC over HTTP is strictly
    /// client-initiated, so there is nothing to send first.
    fn get_startup_parameters(&self) -> Vec<crate::llm::actions::ParameterDefinition> {
        vec![]
    }
    /// None. `list_rpc_methods` used to be declared here; it ignored its input,
    /// always returned an empty list, and its result was consumed by nobody, so it
    /// cost prompt tokens to advertise a method-discovery feature that does not
    /// exist. There is no method registry: the model answers every call.
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![jsonrpc_success_action(), jsonrpc_error_action()]
    }
    fn protocol_name(&self) -> &'static str {
        "JSON-RPC"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        get_jsonrpc_event_types()
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>HTTP>JSONRPC"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["jsonrpc", "json-rpc", "json rpc", "rpc"]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .implementation("Manual JSON-RPC 2.0 over HTTP POST (hyper 1)")
            .llm_control("Every method call: result value or error code/message/data")
            .e2e_testing("curl and mocked in-process HTTP")
            .notes(
                "Single requests, batches and notifications. The response id is taken \
                 from the request, never from the model. Notifications (no id member) \
                 get HTTP 204 and, in a batch, no array entry. Every batch member is a \
                 separate model call and batch length is not capped, so a large batch is \
                 expensive. Any path is accepted; there is no routing, auth or rate \
                 limiting, and non-POST gets an Invalid Request body rather than 405.",
            )
            .max_inbound_bytes(crate::server::jsonrpc::MAX_REQUEST_BODY_BYTES)
            .request_only("JSON-RPC over HTTP is HTTP request/response; a server cannot send a peer anything unprompted")
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "JSON-RPC 2.0 server"
    }
    fn example_prompt(&self) -> &'static str {
        "Start a JSON-RPC 2.0 server on port 8000"
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
                "port": 8000,
                "base_stack": "jsonrpc",
                "instruction": "JSON-RPC 2.0 server. Implement add(a,b), subtract(a,b), and echo(message) methods. Return -32601 for unknown methods"
            }),
            // Script mode: event_handlers with script handler
            json!({
                "type": "open_server",
                "port": 8000,
                "base_stack": "jsonrpc",
                "event_handlers": [{
                    "event_pattern": "jsonrpc_method_call",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "method = event.get('method', '')\nparams = event.get('params', [])\nif method == 'add' and len(params) >= 2:\n    action('jsonrpc_success', result=params[0] + params[1])\nelse:\n    action('jsonrpc_error', code=-32601, message='Method not found')"
                    }
                }]
            }),
            // Static mode: event_handlers with static actions
            json!({
                "type": "open_server",
                "port": 8000,
                "base_stack": "jsonrpc",
                "event_handlers": [{
                    "event_pattern": "jsonrpc_method_call",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "jsonrpc_success",
                            "result": {"status": "ok", "version": "1.0.0"}
                        }]
                    }
                }]
            }),
        )
    }
}

// Implement Server trait (server-specific functionality)
impl Server for JsonRpcProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::server::jsonrpc::JsonRpcServer;
            // `send_first` stays declared so a caller that passes `false` still validates - an
            // undeclared key is refused outright - but `true` is refused rather than ignored.
            // It was read here, threaded through spawn, and dropped at the far end as
            // `_send_first`: a knob advertised to the model, plumbed through three hops, and
            // silently doing nothing. JSON-RPC: a request must precede any response, and an unsolicited notification is not what this flag was offering.
            let send_first = ctx
                .startup_params
                .as_ref()
                .map(|p| p.get_optional_bool("send_first"))
                .transpose()?
                .flatten()
                .unwrap_or(false);
            if send_first {
                return Err(anyhow::anyhow!(
                    "send_first is not supported by the JSON-RPC server: a request must precede any response, and an unsolicited notification is not what this flag was offering"
                ));
            }

            JsonRpcServer::spawn_with_llm_actions(
                ctx.legacy_listen_addr(),
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                send_first,
                ctx.server_id,
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
            "jsonrpc_success" => self.execute_jsonrpc_success(action),
            "jsonrpc_error" => self.execute_jsonrpc_error(action),
            _ => Err(anyhow::anyhow!("Unknown JSON-RPC action: {}", action_type)),
        }
    }
}

impl JsonRpcProtocol {
    fn execute_jsonrpc_success(&self, action: serde_json::Value) -> Result<ActionResult> {
        let result = action
            .get("result")
            .context("Missing 'result' field")?
            .clone();

        let id = action.get("id").cloned().unwrap_or(serde_json::Value::Null);

        debug!(
            "JSON-RPC success response: result={:?}, id={:?}",
            result, id
        );

        // Build JSON-RPC 2.0 success response
        let response = json!({
            "jsonrpc": "2.0",
            "result": result,
            "id": id
        });

        Ok(ActionResult::Custom {
            name: "jsonrpc_response".to_string(),
            data: response,
        })
    }

    fn execute_jsonrpc_error(&self, action: serde_json::Value) -> Result<ActionResult> {
        // Kept as i64: the spec says "integer", and `as i32` silently wrapped, so
        // a model emitting 4294967296 produced code 0.
        let code = action.get("code").and_then(|v| v.as_i64()).context(
            "Missing or non-integer 'code' field (JSON-RPC error codes are integers, e.g. -32601)",
        )?;

        let message = action
            .get("message")
            .and_then(|v| v.as_str())
            .context("Missing 'message' field")?;

        let data = action.get("data").cloned();

        let id = action.get("id").cloned().unwrap_or(serde_json::Value::Null);

        debug!(
            "JSON-RPC error response: code={}, message={}, id={:?}",
            code, message, id
        );

        // Build JSON-RPC 2.0 error response
        let mut error = json!({
            "code": code,
            "message": message
        });

        if let Some(data_val) = data {
            error
                .as_object_mut()
                .unwrap()
                .insert("data".to_string(), data_val);
        }

        let response = json!({
            "jsonrpc": "2.0",
            "error": error,
            "id": id
        });

        Ok(ActionResult::Custom {
            name: "jsonrpc_response".to_string(),
            data: response,
        })
    }
}

/// Action definition: Send JSON-RPC success response
pub fn jsonrpc_success_action() -> ActionDefinition {
    ActionDefinition {
        name: "jsonrpc_success".to_string(),
        description: "Answer a JSON-RPC method call with a result. The response id is \
                      copied from the request automatically, so do not set one."
            .to_string(),
        parameters: vec![Parameter {
            name: "result".to_string(),
            type_hint: "any".to_string(),
            description: "Whatever the method returns. Any JSON type: an object, an \
                          array, a string, a number, a boolean, or null."
                .to_string(),
            required: true,
        }],
        example: json!({
            "type": "jsonrpc_success",
            "result": {"status": "ok", "data": [1, 2, 3]}
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> JSON-RPC success id={id}")
                .with_debug("JSON-RPC jsonrpc_success: id={id}"),
        ),
    }
}

/// Action definition: Send JSON-RPC error response
pub fn jsonrpc_error_action() -> ActionDefinition {
    ActionDefinition {
        name: "jsonrpc_error".to_string(),
        description: "Answer a JSON-RPC method call with an error. The response id is \
                      copied from the request automatically, so do not set one."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "code".to_string(),
                type_hint: "number".to_string(),
                description: "Error code (JSON-RPC standard: -32700 Parse error, -32600 Invalid Request, -32601 Method not found, -32602 Invalid params, -32603 Internal error, -32000 to -32099 Server error)".to_string(),
                required: true,
            },
            Parameter {
                name: "message".to_string(),
                type_hint: "string".to_string(),
                description: "Human-readable error message".to_string(),
                required: true,
            },
            Parameter {
                name: "data".to_string(),
                type_hint: "any".to_string(),
                description: "Optional extra detail about the failure, e.g. which \
                              parameter was wrong. Any JSON value."
                    .to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "jsonrpc_error",
            "code": -32601,
            "message": "Method not found"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> JSON-RPC error {code}: {message}")
                .with_debug("JSON-RPC jsonrpc_error: code={code} message={message}"),
        ),
    }
}

/// JSON-RPC method call event - triggered when client sends a JSON-RPC request
pub static JSONRPC_METHOD_CALL_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "jsonrpc_method_call",
        "JSON-RPC 2.0 method call received",
        // A bare action, not a {"actions": [...]} wrapper — a response_example is a
        // single action object or an array of them, never the outer envelope.
        json!({"type": "jsonrpc_success", "result": 8}),
    )
    .with_parameters(vec![
        Parameter {
            name: "method".to_string(),
            type_hint: "string".to_string(),
            description: "The RPC method name being called".to_string(),
            required: true,
        },
        Parameter {
            name: "params".to_string(),
            type_hint: "any".to_string(),
            description: "Method parameters (can be array, object, or omitted)".to_string(),
            required: false,
        },
        Parameter {
            name: "id".to_string(),
            type_hint: "string|number|null".to_string(),
            description: "The request's correlation id, with its original JSON type. \
                          You never need to echo it: it is copied into the response for \
                          you. Null when the request carried no id."
                .to_string(),
            required: false,
        },
        Parameter {
            name: "is_notification".to_string(),
            type_hint: "boolean".to_string(),
            description: "True when the request had no id member. A notification must \
                          not be answered: anything you return is discarded and the \
                          client gets HTTP 204."
                .to_string(),
            required: true,
        },
    ])
    .with_actions(vec![jsonrpc_success_action(), jsonrpc_error_action()])
    .with_log_template(
        LogTemplate::new()
            .with_info("JSON-RPC {method}")
            .with_debug("JSON-RPC method={method}, id={id}")
            .with_trace("JSON-RPC: {json_pretty(.)}"),
    )
});

/// Get JSON-RPC event types
pub fn get_jsonrpc_event_types() -> Vec<EventType> {
    vec![JSONRPC_METHOD_CALL_EVENT.clone()]
}

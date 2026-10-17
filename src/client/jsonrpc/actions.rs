//! JSON-RPC 2.0 client protocol actions implementation

use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, Parameter, ParameterDefinition,
};
use crate::protocol::EventType;
use crate::state::app_state::AppState;
use anyhow::{Context, Result};
use serde_json::json;
use std::sync::LazyLock;

/// JSON-RPC client connected event
pub static JSONRPC_CLIENT_CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "jsonrpc_connected",
        "JSON-RPC client initialized and ready to send requests",
        json!({"type": "send_jsonrpc_request", "method": "add", "params": [5, 3], "id": 1}),
    )
    .with_parameters(vec![Parameter {
        name: "endpoint".to_string(),
        type_hint: "string".to_string(),
        description: "JSON-RPC endpoint URL".to_string(),
        required: true,
    }])
});

/// JSON-RPC client response received event
pub static JSONRPC_CLIENT_RESPONSE_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "jsonrpc_response_received",
        "JSON-RPC response received from server",
        json!({"type": "send_jsonrpc_request", "method": "getStatus", "id": 2}),
    )
    .with_parameters(vec![
        Parameter {
            name: "id".to_string(),
            type_hint: "number | string | null".to_string(),
            description: "Request ID matching the original request".to_string(),
            required: false,
        },
        Parameter {
            name: "result".to_string(),
            type_hint: "any".to_string(),
            description: "Result value (if success)".to_string(),
            required: false,
        },
        Parameter {
            name: "error".to_string(),
            type_hint: "object".to_string(),
            description: "Error object with code, message, and optional data (if error)"
                .to_string(),
            required: false,
        },
    ])
});

/// JSON-RPC client protocol action handler
pub struct JsonRpcClientProtocol;

impl JsonRpcClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for JsonRpcClientProtocol {
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![ParameterDefinition {
            name: "default_headers".to_string(),
            description: "Default headers to include in all requests".to_string(),
            type_hint: "object".to_string(),
            required: false,
            example: json!({
                "Authorization": "Bearer token123",
                "Content-Type": "application/json"
            }),
            default: None,
        }]
    }
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![
            ActionDefinition {
                name: "send_jsonrpc_request".to_string(),
                description: "Send a JSON-RPC 2.0 request to the server".to_string(),
                parameters: vec![
                    Parameter {
                        name: "method".to_string(),
                        type_hint: "string".to_string(),
                        description: "JSON-RPC method name".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "params".to_string(),
                        type_hint: "array | object".to_string(),
                        description: "Method parameters (array or object)".to_string(),
                        required: false,
                    },
                    Parameter {
                        name: "id".to_string(),
                        type_hint: "number | string".to_string(),
                        description: "Request ID (omit for notification)".to_string(),
                        required: false,
                    },
                ],
                example: json!({
                    "type": "send_jsonrpc_request",
                    "method": "add",
                    "params": [5, 3],
                    "id": 1
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "send_jsonrpc_batch".to_string(),
                description: "Send a batch of JSON-RPC 2.0 requests".to_string(),
                parameters: vec![Parameter {
                    name: "requests".to_string(),
                    type_hint: "array".to_string(),
                    description: "Array of JSON-RPC request objects".to_string(),
                    required: true,
                }],
                example: json!({
                    "type": "send_jsonrpc_batch",
                    "requests": [
                        {"method": "add", "params": [1, 2], "id": 1},
                        {"method": "multiply", "params": [3, 4], "id": 2}
                    ]
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "disconnect".to_string(),
                description: "Disconnect from the JSON-RPC server".to_string(),
                parameters: vec![],
                example: json!({
                    "type": "disconnect"
                }),
                log_template: None,
            },
        ]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            ActionDefinition {
                name: "wait_for_more".to_string(),
                description:
                    "Do nothing and wait for the next JSON-RPC response. The correct answer \
                    when what arrived needs no follow-up -- without it the model has to \
                    invent an action it does not want."
                        .to_string(),
                parameters: vec![],
                example: json!({
                    "type": "wait_for_more"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "send_jsonrpc_request".to_string(),
                description: "Send another JSON-RPC request in response to received data"
                    .to_string(),
                parameters: vec![
                    Parameter {
                        name: "method".to_string(),
                        type_hint: "string".to_string(),
                        description: "JSON-RPC method name".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "params".to_string(),
                        type_hint: "array | object".to_string(),
                        description: "Method parameters".to_string(),
                        required: false,
                    },
                    Parameter {
                        name: "id".to_string(),
                        type_hint: "number | string".to_string(),
                        description: "Request ID".to_string(),
                        required: false,
                    },
                ],
                example: json!({
                    "type": "send_jsonrpc_request",
                    "method": "getStatus",
                    "id": 2
                }),
                log_template: None,
            },
        ]
    }
    fn protocol_name(&self) -> &'static str {
        "JSON-RPC"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            EventType::new(
                "jsonrpc_connected",
                "Triggered when JSON-RPC client is initialized",
                json!({"type": "send_jsonrpc_request", "method": "add", "params": [5, 3], "id": 1}),
            ),
            EventType::new(
                "jsonrpc_response_received",
                "Triggered when JSON-RPC client receives a response",
                json!({"type": "send_jsonrpc_request", "method": "getStatus", "id": 2}),
            ),
        ]
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>HTTP>JSON-RPC"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["jsonrpc", "json-rpc", "json rpc", "rpc"]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .implementation("reqwest HTTP client with JSON-RPC 2.0 format")
            .llm_control("Full control over RPC methods, parameters, batch requests")
            .e2e_testing("Local JSON-RPC server or public JSON-RPC API")
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "JSON-RPC 2.0 client for making remote procedure calls"
    }
    fn example_prompt(&self) -> &'static str {
        "Connect to JSON-RPC server at http://localhost:8080 and call method 'add' with params [5, 3]"
    }
    fn group_name(&self) -> &'static str {
        "RPC"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        use serde_json::json;

        StartupExamples::new(
            // LLM mode: LLM controls JSON-RPC method calls
            json!({
                "type": "open_client",
                "remote_addr": "http://localhost:8080",
                "base_stack": "jsonrpc",
                "instruction": "Call the 'add' method with params [5, 3] and report the result"
            }),
            // Script mode: Code-based JSON-RPC handling
            json!({
                "type": "open_client",
                "remote_addr": "http://localhost:8080",
                "base_stack": "jsonrpc",
                "event_handlers": [{
                    "event_pattern": "jsonrpc_response_received",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "<jsonrpc_client_handler>"
                    }
                }]
            }),
            // Static mode: Fixed JSON-RPC method call
            json!({
                "type": "open_client",
                "remote_addr": "http://localhost:8080",
                "base_stack": "jsonrpc",
                "event_handlers": [
                    {
                        "event_pattern": "jsonrpc_connected",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "send_jsonrpc_request",
                                "method": "add",
                                "params": [5, 3],
                                "id": 1
                            }]
                        }
                    },
                    {
                        "event_pattern": "jsonrpc_response_received",
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
impl Client for JsonRpcClientProtocol {
    fn connect(
        &self,
        ctx: crate::protocol::ConnectContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::client::jsonrpc::JsonRpcClient;
            JsonRpcClient::connect_with_llm_actions(
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
            "send_jsonrpc_request" => {
                let method = action
                    .get("method")
                    .and_then(|v| v.as_str())
                    .context("Missing 'method' field")?
                    .to_string();

                let params = action.get("params").cloned();
                let id = action.get("id").cloned();

                // Return custom result with request data
                Ok(ClientActionResult::Custom {
                    name: "jsonrpc_request".to_string(),
                    data: json!({
                        "method": method,
                        "params": params,
                        "id": id,
                    }),
                })
            }
            "send_jsonrpc_batch" => {
                let requests = action
                    .get("requests")
                    .and_then(|v| v.as_array())
                    .context("Missing 'requests' array")?
                    .clone();

                Ok(ClientActionResult::Custom {
                    name: "jsonrpc_batch".to_string(),
                    data: json!({
                        "requests": requests,
                    }),
                })
            }
            "disconnect" => Ok(ClientActionResult::Disconnect),
            // Declared in get_sync_actions, so it has to be executable here too --
            // advertising a name the executor rejects shows the model a tool it is
            // then punished for using.
            "wait_for_more" => Ok(ClientActionResult::WaitForMore),
            _ => Err(anyhow::anyhow!(
                "Unknown JSON-RPC client action: {}",
                action_type
            )),
        }
    }
}

//! OpenAPI client protocol actions implementation

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

/// OpenAPI client connected event
pub static OPENAPI_CLIENT_CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "openapi_client_connected",
        "OpenAPI client initialized with specification loaded",
        json!({"type": "execute_operation", "operation_id": "listUsers", "path_params": {}, "query_params": {}}),
    )
    .with_parameters(vec![
        Parameter {
            name: "base_url".to_string(),
            type_hint: "string".to_string(),
            description: "Base URL for API requests".to_string(),
            required: true,
        },
        Parameter {
            name: "spec_title".to_string(),
            type_hint: "string".to_string(),
            description: "OpenAPI specification title".to_string(),
            required: false,
        },
        Parameter {
            name: "spec_version".to_string(),
            type_hint: "string".to_string(),
            description: "OpenAPI specification version".to_string(),
            required: false,
        },
        Parameter {
            name: "operation_count".to_string(),
            type_hint: "number".to_string(),
            description: "Number of operations in the spec".to_string(),
            required: false,
        },
        Parameter {
            name: "operations".to_string(),
            type_hint: "array".to_string(),
            description: "List of available operations with operation_id, method, path, summary".to_string(),
            required: false,
        },
    ])
});

/// OpenAPI operation response event
pub static OPENAPI_OPERATION_RESPONSE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "openapi_operation_response",
        "Response received from executing an OpenAPI operation",
        json!({"type": "execute_operation", "operation_id": "getUser", "path_params": {"id": "123"}, "query_params": {}}),
    )
    .with_parameters(vec![
        Parameter {
            name: "operation_id".to_string(),
            type_hint: "string".to_string(),
            description: "Operation ID that was executed".to_string(),
            required: true,
        },
        Parameter {
            name: "method".to_string(),
            type_hint: "string".to_string(),
            description: "HTTP method used".to_string(),
            required: true,
        },
        Parameter {
            name: "path".to_string(),
            type_hint: "string".to_string(),
            description: "Path that was requested".to_string(),
            required: true,
        },
        Parameter {
            name: "status_code".to_string(),
            type_hint: "number".to_string(),
            description: "HTTP status code".to_string(),
            required: true,
        },
        Parameter {
            name: "status_text".to_string(),
            type_hint: "string".to_string(),
            description: "HTTP status text".to_string(),
            required: true,
        },
        Parameter {
            name: "headers".to_string(),
            type_hint: "object".to_string(),
            description: "Response headers".to_string(),
            required: true,
        },
        Parameter {
            name: "body".to_string(),
            type_hint: "string".to_string(),
            description: "Response body".to_string(),
            required: true,
        },
    ])
});

/// OpenAPI client protocol action handler
pub struct OpenApiClientProtocol;

impl Default for OpenApiClientProtocol {
    fn default() -> Self {
        Self::new()
    }
}

impl OpenApiClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for OpenApiClientProtocol {
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "spec".to_string(),
                description: "OpenAPI 3.x specification in YAML or JSON format (inline)"
                    .to_string(),
                type_hint: "string".to_string(),
                required: false,
                example: json!(
                    "openapi: 3.1.0\ninfo:\n  title: My API\n  version: 1.0.0\npaths:\n  /users:\n    get:\n      operationId: listUsers\n      responses:\n        '200':\n          description: List users"
                ),
                default: None,
            },
            #[cfg(not(target_arch = "wasm32"))]
            ParameterDefinition {
                name: "spec_file".to_string(),
                description: "Path to OpenAPI specification file (YAML or JSON)".to_string(),
                type_hint: "string".to_string(),
                required: false,
                example: json!("/path/to/openapi.yaml"),
                default: None,
            },
            ParameterDefinition {
                name: "base_url".to_string(),
                description:
                    "Override base URL (default: first server in spec or http://remote_addr)"
                        .to_string(),
                type_hint: "string".to_string(),
                required: false,
                example: json!("https://api.example.com"),
                default: None,
            },
        ]
    }

    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![
            ActionDefinition {
                name: "execute_operation".to_string(),
                description: "Execute an OpenAPI operation by operation ID".to_string(),
                parameters: vec![
                    Parameter {
                        name: "operation_id".to_string(),
                        type_hint: "string".to_string(),
                        description:
                            "Operation ID from OpenAPI spec (e.g., 'listUsers', 'createTodo')"
                                .to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "path_params".to_string(),
                        type_hint: "object".to_string(),
                        description: "Path parameters (e.g., {\"id\": \"123\"} for /users/{id})"
                            .to_string(),
                        required: false,
                    },
                    Parameter {
                        name: "query_params".to_string(),
                        type_hint: "object".to_string(),
                        description:
                            "Query parameters (e.g., {\"page\": \"1\", \"limit\": \"10\"})"
                                .to_string(),
                        required: false,
                    },
                    Parameter {
                        name: "headers".to_string(),
                        type_hint: "object".to_string(),
                        description: "Override request headers (merged with spec defaults)"
                            .to_string(),
                        required: false,
                    },
                    Parameter {
                        name: "body".to_string(),
                        type_hint: "object".to_string(),
                        description: "Request body (JSON object matching spec schema)".to_string(),
                        required: false,
                    },
                ],
                example: json!({
                    "type": "execute_operation",
                    "operation_id": "listUsers",
                    "path_params": {},
                    "query_params": {"page": "1", "limit": "10"},
                    "headers": {"Authorization": "Bearer token123"},
                    "body": null
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "list_operations".to_string(),
                description: "List all available operations from the OpenAPI spec".to_string(),
                parameters: vec![],
                example: json!({
                    "type": "list_operations"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "get_operation_details".to_string(),
                description: "Get detailed information about a specific operation".to_string(),
                parameters: vec![Parameter {
                    name: "operation_id".to_string(),
                    type_hint: "string".to_string(),
                    description: "Operation ID to inspect".to_string(),
                    required: true,
                }],
                example: json!({
                    "type": "get_operation_details",
                    "operation_id": "listUsers"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "disconnect".to_string(),
                description: "Stop the OpenAPI client".to_string(),
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
            name: "execute_operation".to_string(),
            description: "Execute another OpenAPI operation in response to received data"
                .to_string(),
            parameters: vec![
                Parameter {
                    name: "operation_id".to_string(),
                    type_hint: "string".to_string(),
                    description: "Operation ID from OpenAPI spec".to_string(),
                    required: true,
                },
                Parameter {
                    name: "path_params".to_string(),
                    type_hint: "object".to_string(),
                    description: "Path parameters".to_string(),
                    required: false,
                },
                Parameter {
                    name: "query_params".to_string(),
                    type_hint: "object".to_string(),
                    description: "Query parameters".to_string(),
                    required: false,
                },
                Parameter {
                    name: "headers".to_string(),
                    type_hint: "object".to_string(),
                    description: "Request headers".to_string(),
                    required: false,
                },
                Parameter {
                    name: "body".to_string(),
                    type_hint: "object".to_string(),
                    description: "Request body".to_string(),
                    required: false,
                },
            ],
            example: json!({
                "type": "execute_operation",
                "operation_id": "createUser",
                "body": {"name": "Alice", "email": "alice@example.com"}
            }),
            log_template: Some(
                LogTemplate::new()
                    .with_info("-> OpenAPI operation {operation_id}")
                    .with_debug("OpenAPI execute_operation: operation_id={operation_id}"),
            ),
        }]
    }

    fn protocol_name(&self) -> &'static str {
        "OpenAPI"
    }

    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            EventType::new(
                "openapi_client_connected",
                "Triggered when OpenAPI client is initialized with spec",
                json!({"type": "placeholder", "event_id": "openapi_client_connected"}),
            ),
            EventType::new(
                "openapi_operation_response",
                "Triggered when OpenAPI operation response is received",
                json!({"type": "placeholder", "event_id": "openapi_operation_response"}),
            ),
        ]
    }

    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>HTTP>OPENAPI"
    }

    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "openapi",
            "openapi client",
            "rest",
            "rest api",
            "api client",
            "swagger",
        ]
    }

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .implementation("openapi-rs parser, reqwest HTTP client (HTTP/1.1, HTTP/2)")
            .llm_control("Operation selection, parameter provision, spec-driven requests")
            .e2e_testing(
                "tests/client/openapi/. target_precedence_test pins that remote_addr wins \
                 over the spec's servers[0] - the spec must not be able to retarget the \
                 client - and that base_url overrides both; command_channel_test drives the \
                 injected-operation path against a loopback stub; e2e_test runs the real \
                 binary against a NetGet OpenAPI server. The peer is always netget or a stub \
                 written in the test, never a third-party OpenAPI implementation.",
            )
            .notes("Spec-driven request construction, path parameter substitution")
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }

    fn description(&self) -> &'static str {
        "OpenAPI specification-driven HTTP client"
    }

    fn example_prompt(&self) -> &'static str {
        "Connect to https://api.example.com with OpenAPI spec and test all operations"
    }

    fn group_name(&self) -> &'static str {
        "AI & API"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        use serde_json::json;

        StartupExamples::new(
            // LLM mode: LLM controls OpenAPI operations
            json!({
                "type": "open_client",
                "remote_addr": "https://api.example.com",
                "base_stack": "openapi",
                "instruction": "List available operations and test the listUsers endpoint",
                "startup_params": {
                    "spec_file": "/path/to/openapi.yaml"
                }
            }),
            // Script mode: Code-based operation response handling
            json!({
                "type": "open_client",
                "remote_addr": "https://api.example.com",
                "base_stack": "openapi",
                "startup_params": {
                    "spec_file": "/path/to/openapi.yaml"
                },
                "event_handlers": [{
                    "event_pattern": "openapi_operation_response",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "<openapi_client_handler>"
                    }
                }]
            }),
            // Static mode: Fixed OpenAPI operation execution
            json!({
                "type": "open_client",
                "remote_addr": "https://api.example.com",
                "base_stack": "openapi",
                "startup_params": {
                    "spec_file": "/path/to/openapi.yaml"
                },
                "event_handlers": [
                    {
                        "event_pattern": "openapi_client_connected",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "execute_operation",
                                "operation_id": "listUsers",
                                "path_params": {},
                                "query_params": {"page": "1", "limit": "10"}
                            }]
                        }
                    },
                    {
                        "event_pattern": "openapi_operation_response",
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
impl Client for OpenApiClientProtocol {
    fn connect(
        &self,
        ctx: crate::protocol::ConnectContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::client::openapi::OpenApiClient;
            // Extract startup parameters into JSON for compatibility
            let mut params = serde_json::Map::new();
            if let Some(sp) = &ctx.startup_params {
                if let Some(spec) = sp.get_optional_string("spec")? {
                    params.insert("spec".to_string(), serde_json::json!(spec));
                }
                #[cfg(not(target_arch = "wasm32"))]
                if let Some(spec_file) = sp.get_optional_string("spec_file")? {
                    params.insert("spec_file".to_string(), serde_json::json!(spec_file));
                }
                if let Some(base_url) = sp.get_optional_string("base_url")? {
                    params.insert("base_url".to_string(), serde_json::json!(base_url));
                }
            }
            let startup_params = serde_json::Value::Object(params);

            OpenApiClient::connect_with_llm_actions(
                ctx.remote_addr,
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.client_id,
                startup_params,
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
            "execute_operation" => {
                let operation_id = action
                    .get("operation_id")
                    .and_then(|v| v.as_str())
                    .context("Missing 'operation_id' field")?
                    .to_string();

                let path_params = action
                    .get("path_params")
                    .and_then(|v| v.as_object())
                    .cloned()
                    .unwrap_or_default();

                let query_params = action
                    .get("query_params")
                    .and_then(|v| v.as_object())
                    .cloned()
                    .unwrap_or_default();

                let headers = action.get("headers").and_then(|v| v.as_object()).cloned();

                let body = action.get("body").cloned().unwrap_or(json!(null));

                // Return custom result with operation data
                Ok(ClientActionResult::Custom {
                    name: "openapi_operation".to_string(),
                    data: json!({
                        "operation_id": operation_id,
                        "path_params": path_params,
                        "query_params": query_params,
                        "headers": headers,
                        "body": body,
                    }),
                })
            }
            "list_operations" => {
                // This is handled by returning NoAction - the operation list is already sent
                // in the connected event
                Ok(ClientActionResult::NoAction)
            }
            "get_operation_details" => {
                // For now, return NoAction - could enhance to return operation details
                Ok(ClientActionResult::NoAction)
            }
            "disconnect" => Ok(ClientActionResult::Disconnect),
            _ => Err(anyhow::anyhow!(
                "Unknown OpenAPI client action: {}",
                action_type
            )),
        }
    }
}

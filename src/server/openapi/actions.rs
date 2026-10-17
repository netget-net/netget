//! OpenAPI protocol actions for LLM integration

use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::EventType;
use crate::state::app_state::AppState;
use anyhow::{anyhow, Result};
use serde_json::{json, Value as JsonValue};
use std::sync::LazyLock;
use tracing::{debug, error, warn};

/// OpenAPI request event - triggered when client sends an HTTP request to OpenAPI server
pub static OPENAPI_REQUEST_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "openapi_request",
        "HTTP request received by OpenAPI server",
        json!({
            "type": "send_openapi_response",
            "status_code": 200,
            "headers": {"content-type": "application/json"},
            "body": "[{\"id\": 1, \"title\": \"Buy milk\", \"done\": false}]"
        }),
    )
    .with_alternative_example(json!({
        "type": "send_validation_error",
        "status_code": 400,
        "message": "Field 'title' is required"
    }))
    // `call_llm` builds the model's tool list from `event.event_type.actions`, not from
    // `get_sync_actions()`. With this list empty the model was told "No specific actions
    // available for this event" and had no way to answer a request at all.
    .with_actions(OpenApiProtocol.get_sync_actions())
    .with_parameters(vec![
        Parameter {
            name: "method".to_string(),
            type_hint: "string".to_string(),
            description: "HTTP method (GET, POST, etc.)".to_string(),
            required: true,
        },
        Parameter {
            name: "path".to_string(),
            type_hint: "string".to_string(),
            description: "Request path".to_string(),
            required: true,
        },
        Parameter {
            name: "uri".to_string(),
            type_hint: "string".to_string(),
            description: "Full request URI".to_string(),
            required: true,
        },
        Parameter {
            name: "headers".to_string(),
            type_hint: "object".to_string(),
            description: "Request headers as key-value pairs".to_string(),
            required: false,
        },
        Parameter {
            name: "body".to_string(),
            type_hint: "string".to_string(),
            description: "Request body".to_string(),
            required: false,
        },
        Parameter {
            name: "spec_info".to_string(),
            type_hint: "object".to_string(),
            description: "Information about loaded OpenAPI spec".to_string(),
            required: false,
        },
        Parameter {
            name: "matched_route".to_string(),
            type_hint: "object".to_string(),
            description: "Matched route information (only present if route matched). Contains: operation_id, path_template, path_params (extracted parameters like {id}), and operation (full OpenAPI operation spec)".to_string(),
            required: false,
        },
    ])
});

/// Read a model-supplied HTTP status, refusing anything that is not one.
///
/// This was `as_i64()? as u16`, which narrows in silence in both directions: `65736` is
/// `200` and `-1` is `65535`. `send_validation_error` is how the model reports that a request
/// failed schema validation, so the one field carrying that refusal could arrive as the
/// success it was refusing. Refusing beats clamping — a clamp to 599 is not what the model
/// asked for either, and the message is what the repair loop reads.
fn required_status(action: &serde_json::Value, action_name: &str) -> Result<u16> {
    let value = action
        .get("status_code")
        .ok_or_else(|| anyhow!("Missing status_code parameter for {action_name}"))?;
    let raw = value
        .as_i64()
        .ok_or_else(|| anyhow!("{action_name} status_code must be a number, got {value}"))?;
    if !(100..=599).contains(&raw) {
        return Err(anyhow!(
            "{action_name} status_code {raw} is not an HTTP status code; use 100-599 \
             (400 for a bad request, 404 for an unmatched route, 500 for a server fault)"
        ));
    }
    Ok(raw as u16)
}

/// OpenAPI protocol implementation
#[derive(Clone)]
pub struct OpenApiProtocol;

impl OpenApiProtocol {
    pub fn new() -> Self {
        Self
    }
}

impl Default for OpenApiProtocol {
    fn default() -> Self {
        Self::new()
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for OpenApiProtocol {
    fn protocol_name(&self) -> &'static str {
        "OpenAPI"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>HTTP>OPENAPI"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["openapi", "rest", "rest api", "api", "swagger"]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![OPENAPI_REQUEST_EVENT.clone()]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .implementation("openapi-rs parser, matchit router, hyper HTTP")
            .llm_control("All API responses, spec compliance/violations")
            .e2e_testing("reqwest HTTP client")
            .notes("Dynamic spec loading, intentional violations for testing")
            .max_inbound_bytes(crate::server::openapi::MAX_REQUEST_BODY_BYTES)
            .request_only("An OpenAPI service is HTTP request/response; a server cannot send a peer anything unprompted")
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "OpenAPI specification server"
    }
    fn example_prompt(&self) -> &'static str {
        "Start an OpenAPI server for a TODO API on port 8080"
    }
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![
                ActionDefinition {
                    name: "reload_spec".to_string(),
                    description: "Reload or update the OpenAPI specification at runtime".to_string(),
                    parameters: vec![
                        Parameter {
                            name: "spec".to_string(),
                            type_hint: "string".to_string(),
                            description: "OpenAPI 3.1 specification in YAML or JSON format".to_string(),
                            required: true,
                        },
                    ],
                    example: serde_json::json!({"type": "reload_spec", "spec": "openapi: 3.1.0\ninfo:\n  title: My API\n  version: 1.0.0\npaths:\n  /users:\n    get:\n      responses:\n        '200':\n          description: List users"}),
                log_template: Some(
                    LogTemplate::new()
                        .with_info("-> OpenAPI spec reloaded")
                        .with_debug("OpenAPI reload_spec: spec_len={spec_len}"),
                ),
                },
                ActionDefinition {
                    name: "get_spec_info".to_string(),
                    description: "Get summary information about the loaded OpenAPI specification".to_string(),
                    parameters: vec![],
                    example: serde_json::json!({"type": "get_spec_info"}),
                log_template: Some(
                    LogTemplate::new()
                        .with_info("-> OpenAPI spec info requested")
                        .with_debug("OpenAPI get_spec_info"),
                ),
                },
                ActionDefinition {
                    name: "configure_error_handling".to_string(),
                    description: "Configure whether to ask LLM for invalid requests (404/405/400). By default, these errors are handled immediately without LLM. Enable this to let LLM customize error responses for honeypot purposes.".to_string(),
                    parameters: vec![
                        Parameter {
                            name: "llm_on_invalid".to_string(),
                            type_hint: "boolean".to_string(),
                            description: "If true, ask LLM for 404/405/400 errors. If false (default), return immediate RFC-compliant error responses.".to_string(),
                            required: true,
                        },
                    ],
                    example: serde_json::json!({"type": "configure_error_handling", "llm_on_invalid": false}),
                log_template: Some(
                    LogTemplate::new()
                        .with_info("-> OpenAPI error handling: llm_on_invalid={llm_on_invalid}")
                        .with_debug("OpenAPI configure_error_handling: llm_on_invalid={llm_on_invalid}"),
                ),
                },
            ]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
                ActionDefinition {
                    name: "provide_openapi_spec".to_string(),
                    description: "Provide the OpenAPI specification (used during server startup)".to_string(),
                    parameters: vec![
                        Parameter {
                            name: "spec".to_string(),
                            type_hint: "string".to_string(),
                            description: "OpenAPI 3.1 specification in YAML or JSON format".to_string(),
                            required: true,
                        },
                    ],
                    example: serde_json::json!({"type": "provide_openapi_spec", "spec": "openapi: 3.1.0\ninfo:\n  title: TODO API\n  version: 1.0.0\npaths:\n  /todos:\n    get:\n      operationId: listTodos\n      responses:\n        '200':\n          description: List of todos\n          content:\n            application/json:\n              schema:\n                type: array\n                items:\n                  type: object\n                  properties:\n                    id:\n                      type: integer\n                    title:\n                      type: string\n                    done:\n                      type: boolean"}),
                log_template: Some(
                    LogTemplate::new()
                        .with_info("-> OpenAPI spec provided")
                        .with_debug("OpenAPI provide_openapi_spec: spec_len={spec_len}"),
                ),
                },
                ActionDefinition {
                    name: "send_openapi_response".to_string(),
                    description: "Send an HTTP response for an OpenAPI request".to_string(),
                    parameters: vec![
                        Parameter {
                            name: "status_code".to_string(),
                            type_hint: "number".to_string(),
                            description: "HTTP status code (e.g., 200, 404, 500)".to_string(),
                            required: true,
                        },
                        Parameter {
                            name: "headers".to_string(),
                            type_hint: "object".to_string(),
                            description: "HTTP response headers as key-value pairs".to_string(),
                            required: false,
                        },
                        Parameter {
                            name: "body".to_string(),
                            type_hint: "string".to_string(),
                            description: "Response body (JSON, XML, plain text, etc.)".to_string(),
                            required: false,
                        },
                        Parameter {
                            name: "spec_compliant".to_string(),
                            type_hint: "boolean".to_string(),
                            description: "Set false to record that this response deliberately violates the loaded spec (for testing how a client handles a misbehaving server). Only affects logging; the response is sent either way. Default true.".to_string(),
                            required: false,
                        },
                    ],
                    example: serde_json::json!({"type": "send_openapi_response", "status_code": 200, "headers": {"content-type": "application/json"}, "body": "[{\"id\": 1, \"title\": \"Buy milk\", \"done\": false}]"}),
                log_template: Some(
                    LogTemplate::new()
                        .with_info("-> OpenAPI {status_code} ({body_len}B)")
                        .with_debug("OpenAPI send_openapi_response: status={status_code} body_len={body_len}"),
                ),
                },
                ActionDefinition {
                    name: "send_validation_error".to_string(),
                    description: "Send an HTTP error response for invalid requests (400, 405, 415, etc.)".to_string(),
                    parameters: vec![
                        Parameter {
                            name: "status_code".to_string(),
                            type_hint: "number".to_string(),
                            description: "HTTP error status code (400=Bad Request, 405=Method Not Allowed, 415=Unsupported Media Type, etc.)".to_string(),
                            required: true,
                        },
                        Parameter {
                            name: "message".to_string(),
                            type_hint: "string".to_string(),
                            description: "Error message explaining the validation failure".to_string(),
                            required: true,
                        },
                    ],
                    example: serde_json::json!({"type": "send_validation_error", "status_code": 405, "message": "Method GET not allowed for path /users, expected POST"}),
                log_template: Some(
                    LogTemplate::new()
                        .with_info("-> OpenAPI {status_code}: {message}")
                        .with_debug("OpenAPI send_validation_error: status={status_code} message={message}"),
                ),
                },
            ]
    }
    fn get_startup_parameters(&self) -> Vec<crate::llm::actions::ParameterDefinition> {
        use crate::llm::actions::ParameterDefinition;
        // `spec_file` used to be declared here (and documented on
        // `OpenApiServer::spawn_with_llm_actions`) but nothing ever read it: spawn only looks
        // at `spec`, and errors out with "requires 'spec' parameter" when it is absent. A
        // caller passing only `spec_file` therefore got a hard startup failure. Removed
        // rather than implemented — the server deliberately wants inline content, and giving
        // model-supplied input an arbitrary-file-read into an auth-adjacent server is not a
        // trade worth making. Read the file and pass its contents as `spec`.
        vec![ParameterDefinition {
            name: "spec".to_string(),
            type_hint: "string".to_string(),
            description:
                "OpenAPI 3.x specification in YAML or JSON format. Inline content only — to serve \
                 a spec that lives on disk, read the file and pass its contents here."
                    .to_string(),
            required: false,
            example: serde_json::json!("openapi: 3.1.0\ninfo:\n  title: My API\n  version: 1.0.0"),
            default: None,
        }]
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
                "port": 8080,
                "base_stack": "openapi",
                "instruction": "OpenAPI server for TODO API. GET /todos returns list, POST /todos creates item, GET /todos/{id} returns single item",
                "startup_params": {
                    "spec": "openapi: 3.1.0\ninfo:\n  title: TODO API\n  version: 1.0.0\npaths:\n  /todos:\n    get:\n      operationId: listTodos\n      responses:\n        '200':\n          description: List of todos"
                }
            }),
            // Script mode: event_handlers with script handler
            json!({
                "type": "open_server",
                "port": 8080,
                "base_stack": "openapi",
                "startup_params": {
                    "spec": "openapi: 3.1.0\ninfo:\n  title: API\n  version: 1.0.0\npaths:\n  /items:\n    get:\n      operationId: listItems\n      responses:\n        '200':\n          description: OK"
                },
                "event_handlers": [{
                    "event_pattern": "openapi_request",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "path = event.get('path', '')\nif path == '/items':\n    action('send_openapi_response', status_code=200, headers={'content-type': 'application/json'}, body='[{\"id\": 1}]')\nelse:\n    action('send_openapi_response', status_code=404, body='{\"error\": \"Not found\"}')"
                    }
                }]
            }),
            // Static mode: event_handlers with static actions
            json!({
                "type": "open_server",
                "port": 8080,
                "base_stack": "openapi",
                "startup_params": {
                    "spec": "openapi: 3.1.0\ninfo:\n  title: Health API\n  version: 1.0.0\npaths:\n  /health:\n    get:\n      operationId: healthCheck\n      responses:\n        '200':\n          description: OK"
                },
                "event_handlers": [{
                    "event_pattern": "openapi_request",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "send_openapi_response",
                            "status_code": 200,
                            "headers": {"content-type": "application/json"},
                            "body": "{\"status\": \"healthy\"}"
                        }]
                    }
                }]
            }),
        )
    }
}

// Implement Server trait (server-specific functionality)
impl Server for OpenApiProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::server::openapi::OpenApiServer;
            OpenApiServer::spawn_with_llm_actions(
                ctx.legacy_listen_addr(),
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.server_id,
                ctx.startup_params,
            )
            .await
        })
    }
    fn execute_action(&self, action: JsonValue) -> Result<ActionResult> {
        let action_type = action["type"]
            .as_str()
            .ok_or_else(|| anyhow!("Missing action type"))?;

        match action_type {
            "provide_openapi_spec" => {
                let spec = action["spec"]
                    .as_str()
                    .ok_or_else(|| anyhow!("Missing spec parameter"))?;

                debug!("OpenAPI spec provided: {} bytes", spec.len());

                Ok(ActionResult::Custom {
                    name: "load_openapi_spec".to_string(),
                    data: serde_json::json!({
                        "spec": spec
                    }),
                })
            }
            "send_openapi_response" => {
                let status_code = required_status(&action, "send_openapi_response")?;

                let headers = action["headers"].as_object().cloned().unwrap_or_default();

                let body = action["body"].as_str().unwrap_or("").to_string();

                let spec_compliant = action["spec_compliant"].as_bool().unwrap_or(true);

                let compliance_status = if spec_compliant {
                    "compliant"
                } else {
                    "non-compliant (intentional)"
                };
                debug!(
                    "OpenAPI response: {} {} bytes, spec: {}",
                    status_code,
                    body.len(),
                    compliance_status
                );

                Ok(ActionResult::Custom {
                    name: "send_openapi_response".to_string(),
                    data: serde_json::json!({
                        "status_code": status_code,
                        "headers": headers,
                        "body": body,
                        "spec_compliant": spec_compliant
                    }),
                })
            }
            "send_validation_error" => {
                let status_code = required_status(&action, "send_validation_error")?;

                let message = action["message"]
                    .as_str()
                    .ok_or_else(|| anyhow!("Missing message parameter"))?;

                warn!("OpenAPI validation error: {} - {}", status_code, message);

                Ok(ActionResult::Custom {
                    name: "send_validation_error".to_string(),
                    data: serde_json::json!({
                        "status_code": status_code,
                        "message": message
                    }),
                })
            }
            "reload_spec" => {
                let spec = action["spec"]
                    .as_str()
                    .ok_or_else(|| anyhow!("Missing spec parameter"))?;

                debug!("OpenAPI spec reload requested: {} bytes", spec.len());

                Ok(ActionResult::Custom {
                    name: "reload_spec".to_string(),
                    data: serde_json::json!({
                        "spec": spec,
                        "reload": true
                    }),
                })
            }
            "get_spec_info" => {
                debug!("OpenAPI spec info requested");
                Ok(ActionResult::NoAction)
            }
            "configure_error_handling" => {
                let llm_on_invalid = action["llm_on_invalid"]
                    .as_bool()
                    .ok_or_else(|| anyhow!("Missing llm_on_invalid parameter"))?;

                debug!(
                    "OpenAPI error handling configured: llm_on_invalid={}",
                    llm_on_invalid
                );

                Ok(ActionResult::Custom {
                    name: "configure_error_handling".to_string(),
                    data: serde_json::json!({
                        "llm_on_invalid": llm_on_invalid
                    }),
                })
            }
            _ => {
                error!("Unknown OpenAPI action: {}", action_type);
                Err(anyhow!("Unknown action type: {}", action_type))
            }
        }
    }
}

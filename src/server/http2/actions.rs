//! HTTP/2 protocol actions implementation

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

/// HTTP/2 protocol action handler
pub struct Http2Protocol;

impl Default for Http2Protocol {
    fn default() -> Self {
        Self::new()
    }
}

impl Http2Protocol {
    pub fn new() -> Self {
        Self
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for Http2Protocol {
    fn get_startup_parameters(&self) -> Vec<crate::llm::actions::ParameterDefinition> {
        let mut params = crate::server::tls_cert_manager::get_tls_startup_parameters();
        params.extend(crate::server::http_common::handler::request_handling_startup_parameters());
        params.push(crate::llm::actions::ParameterDefinition {
            name: "first_byte_timeout_secs".to_string(),
            type_hint: "number".to_string(),
            description: "Seconds a connected peer may send nothing at all (no TLS ClientHello, \
                          no HTTP/2 preface) before the server closes it. Default 30: HTTP/2 is \
                          client-speaks-first, and NetGet's own HTTP/2 client opens no socket \
                          until it has a request to send."
                .to_string(),
            required: false,
            example: json!(30),
            default: Some(serde_json::json!(
                super::h2_server::FIRST_BYTE_READ_TIMEOUT.as_secs()
            )),
        });
        params.push(crate::llm::actions::ParameterDefinition {
            name: "idle_timeout_secs".to_string(),
            type_hint: "number".to_string(),
            description: "Seconds an established connection may carry no request before the \
                          server sends GOAWAY and closes it. Default 300, above the 90 seconds \
                          reqwest keeps an idle pooled connection. A request still being \
                          answered never counts as idle."
                .to_string(),
            required: false,
            example: json!(300),
            default: Some(serde_json::json!(
                super::h2_server::IDLE_BETWEEN_REQUESTS_TIMEOUT.as_secs()
            )),
        });
        params
    }
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        // HTTP/2 has no async actions - it's purely request-response
        Vec::new()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![send_http2_response_action(), push_resource_action()]
    }
    fn protocol_name(&self) -> &'static str {
        "HTTP2"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        get_http2_event_types()
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>HTTP/2"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "http2",
            "http/2",
            "http 2",
            "http2 server",
            "http/2 server",
            "via http2",
            "via http/2",
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{
            DevelopmentState, PrivilegeRequirement, ProtocolMetadataV2,
        };

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            // HTTP/2 normally runs on 443 (TLS); h2c is often 80. The preflight
            // check only fires when the requested port is actually < 1024.
            .privilege_requirement(PrivilegeRequirement::PrivilegedPort(443))
            .well_known_port(443)
            .implementation("h2 crate directly (server push), optional TLS via rustls")
            .llm_control("Response content (status, headers, text body) + server push")
            .e2e_testing("h2/reqwest + mocked LLM, tests/server/http2/e2e_test.rs (3 scenarios)")
            .notes(
                "Text bodies only, no streaming; ALPN is not negotiated, so a browser will not \
                 pick HTTP/2 over TLS on its own - clients must select h2 explicitly or use h2c",
            )
            .max_inbound_bytes(crate::server::http_common::MAX_REQUEST_BODY_BYTES)
            .request_only("HTTP/2 only answers requests; every response and push rides a stream the peer opened")
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "Web server serving HTTP/2 traffic with multiplexing and header compression"
    }
    fn example_prompt(&self) -> &'static str {
        "HTTP/2 server on port 8443 serving JSON API with fast multiplexed responses"
    }
    fn group_name(&self) -> &'static str {
        "Core"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;

        // Deterministic: answer every HTTP/2 request with a fixed JSON body, no
        // LLM call.
        let script = r#"import json, sys
data = json.load(sys.stdin)
event = data["event"]
if data["event_type_id"] == "http2_request":
    actions = [{"type": "send_http2_response", "status": 200,
                "headers": {"Content-Type": "application/json"},
                "body": '{"message": "Hello from HTTP/2!"}'}]
else:
    actions = []
print(json.dumps({"actions": actions}))"#;

        StartupExamples::new(
            json!({
                "type": "open_server",
                "port": 8443,
                "base_stack": "http2",
                "instruction": "HTTP/2 server with multiplexing and fast responses"
            }),
            json!({
                "type": "open_server",
                "port": 8443,
                "base_stack": "http2",
                "event_handlers": [{
                    "event_pattern": "http2_request",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": script
                    }
                }]
            }),
            json!({
                "type": "open_server",
                "port": 8443,
                "base_stack": "http2",
                "event_handlers": [{
                    "event_pattern": "http2_request",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "send_http2_response",
                            "status": 200,
                            "headers": {
                                "Content-Type": "application/json"
                            },
                            "body": "{\"message\": \"Hello from HTTP/2!\"}"
                        }]
                    }
                }]
            }),
        )
    }
}

// Implement Server trait (server-specific functionality)
impl Server for Http2Protocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::server::http2::H2Server;

            // Parse TLS configuration from startup_params
            let tls_config = if let Some(ref params) = ctx.startup_params {
                match crate::server::tls_cert_manager::extract_tls_config_from_params(params) {
                    Ok(config) => config,
                    Err(e) => {
                        return Err(anyhow::anyhow!("Failed to create TLS config: {}", e));
                    }
                }
            } else {
                None
            };

            // Both bounds are the operator's to tune; the defaults are argued beside
            // FIRST_BYTE_READ_TIMEOUT and IDLE_BETWEEN_REQUESTS_TIMEOUT in h2_server.rs.
            let secs = |name: &str| -> anyhow::Result<Option<u64>> {
                Ok(ctx
                    .startup_params
                    .as_ref()
                    .map(|p| p.get_optional_u64(name))
                    .transpose()?
                    .flatten())
            };
            let bounds = crate::server::http2::h2_server::H2Bounds::from_secs(
                secs("first_byte_timeout_secs")?,
                secs("idle_timeout_secs")?,
            );

            // Use h2-based server for full server push support
            H2Server::spawn_with_push_support(
                ctx.legacy_listen_addr(),
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.server_id,
                tls_config,
                bounds,
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
            "send_http2_response" => self.execute_send_http2_response(action),
            "push_resource" => self.execute_push_resource(action),
            _ => Err(anyhow::anyhow!("Unknown HTTP/2 action: {action_type}")),
        }
    }
}

impl Http2Protocol {
    /// Execute send_http2_response sync action
    fn execute_send_http2_response(&self, action: serde_json::Value) -> Result<ActionResult> {
        // Use shared action execution logic
        crate::server::http_common::execute_http_response_action(action)
    }

    /// Execute push_resource sync action (server push)
    fn execute_push_resource(&self, action: serde_json::Value) -> Result<ActionResult> {
        use anyhow::Context;
        use serde_json::json;

        let path = action
            .get("path")
            .and_then(|v| v.as_str())
            .context("Missing 'path' parameter")?;

        // Range-checked rather than cast: `65736 as u16` is 200, so an out-of-range value
        // would silently become a plausible status instead of being reported.
        let status = match action.get("status") {
            None | Some(serde_json::Value::Null) => 200u16,
            Some(v) => v
                .as_u64()
                .filter(|s| (100..=599).contains(s))
                .with_context(|| {
                    format!(
                        "Invalid 'status' parameter {}: expected an HTTP status code between \
                         100 and 599",
                        v
                    )
                })? as u16,
        };

        let headers = action
            .get("headers")
            .and_then(|v| v.as_object())
            .cloned()
            .unwrap_or_default();

        let body = action.get("body").and_then(|v| v.as_str()).unwrap_or("");

        let method = action
            .get("method")
            .and_then(|v| v.as_str())
            .unwrap_or("GET");

        // Return push data as structured JSON that h2_server will recognize
        let push_data = json!({
            "_push_directive": true,
            "path": path,
            "method": method,
            "status": status,
            "headers": headers,
            "body": body
        });

        tracing::debug!("Queued server push for {}", path);

        Ok(ActionResult::Output(
            serde_json::to_vec(&push_data).context("Failed to serialize push data")?,
        ))
    }
}

/// Action definition for send_http2_response (sync)
fn send_http2_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_http2_response".to_string(),
        description: "Respond to the HTTP/2 request that triggered this event. Emit it exactly \
            once per request: the response is sent complete, in one piece. There is no way to \
            stream or chunk it, and the body is sent as UTF-8 text, so binary payloads cannot be \
            produced. ALWAYS emit exactly one send_http2_response for every request — if you \
            emit none, the server has no answer to send and refuses the stream with 500 (or the \
            server's configured default_response, if it has one). push_resource does not count: \
            a PUSH_PROMISE is an extra resource offered alongside an answer, not the answer."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "status".to_string(),
                type_hint: "number".to_string(),
                description:
                    "HTTP status code as a number between 100 and 599 (e.g. 200, 404, 500)."
                        .to_string(),
                required: true,
            },
            Parameter {
                name: "headers".to_string(),
                type_hint: "object".to_string(),
                description: "Optional response headers as a flat name->value object. Do not set \
                    HTTP/2 pseudo-headers (:status, :path, ...) or content-length; they are \
                    handled by the server. Illegal header names/values are dropped."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "body".to_string(),
                type_hint: "string".to_string(),
                description: "Response body as text. Optional: omit for an empty body (204/304). \
                    A JSON object or array is serialized to compact JSON text. Text only - bytes \
                    cannot be sent."
                    .to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_http2_response",
            "status": 200,
            "headers": {
                "Content-Type": "application/json"
            },
            "body": "{\"message\": \"Hello from HTTP/2!\"}"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> HTTP/2 {status}")
                .with_debug("HTTP/2 send_http2_response: status={status}"),
        ),
    }
}

/// Action definition for push_resource (sync) - HTTP/2 server push
fn push_resource_action() -> ActionDefinition {
    ActionDefinition {
        name: "push_resource".to_string(),
        description: "Push a resource to the client proactively (HTTP/2 server push). Emit it \
            alongside send_http2_response in the same batch; pushes are sent before the main \
            response. Clients may refuse pushes (most modern browsers have disabled them), in \
            which case the push is dropped and only the main response is delivered. Text bodies \
            only."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "path".to_string(),
                type_hint: "string".to_string(),
                description: "Resource path to push (e.g., /style.css)".to_string(),
                required: true,
            },
            // Read by the executor and forwarded in the push directive, but declared nowhere,
            // so every push was a GET whatever the model intended.
            Parameter {
                name: "method".to_string(),
                type_hint: "string".to_string(),
                description: "Method for the pushed request (default: GET). RFC 7540 §8.2 \
                    allows only safe, cacheable methods - GET or HEAD."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "status".to_string(),
                type_hint: "number".to_string(),
                description: "HTTP status code (default: 200)".to_string(),
                required: false,
            },
            Parameter {
                name: "headers".to_string(),
                type_hint: "object".to_string(),
                description: "Response headers as key-value pairs".to_string(),
                required: false,
            },
            Parameter {
                name: "body".to_string(),
                type_hint: "string".to_string(),
                description: "Resource content to push".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "push_resource",
            "path": "/style.css",
            "status": 200,
            "headers": {
                "Content-Type": "text/css"
            },
            "body": "body { margin: 0; }"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> HTTP/2 PUSH {path}")
                .with_debug("HTTP/2 push_resource: path={path}, status={status}"),
        ),
    }
}

// ============================================================================
// HTTP/2 Action Constants
// ============================================================================

pub static SEND_HTTP2_RESPONSE_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(send_http2_response_action);
pub static PUSH_RESOURCE_ACTION: LazyLock<ActionDefinition> = LazyLock::new(push_resource_action);

// ============================================================================
// HTTP/2 Event Type Constants
// ============================================================================

/// HTTP/2 request event - triggered when client sends an HTTP/2 request
pub static HTTP2_REQUEST_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "http2_request",
        "HTTP/2 request received from client",
        json!({"type": "placeholder", "event_id": "http2_request"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "method".to_string(),
            type_hint: "string".to_string(),
            description: "HTTP method (GET, POST, etc.)".to_string(),
            required: true,
        },
        Parameter {
            name: "uri".to_string(),
            type_hint: "string".to_string(),
            description: "Request URI".to_string(),
            required: true,
        },
        Parameter {
            name: "version".to_string(),
            type_hint: "string".to_string(),
            description: "HTTP version (HTTP/2.0)".to_string(),
            required: true,
        },
        Parameter {
            name: "headers".to_string(),
            type_hint: "object".to_string(),
            description: "Request headers as key-value pairs".to_string(),
            required: true,
        },
        Parameter {
            name: "body".to_string(),
            type_hint: "string".to_string(),
            description:
                "Request body decoded as UTF-8 text (empty string when there is no body). \
                Bytes that are not valid UTF-8 are replaced with U+FFFD, so when body_is_binary \
                is true this field is lossy and must not be treated as the exact request payload."
                    .to_string(),
            required: false,
        },
        Parameter {
            name: "body_bytes".to_string(),
            type_hint: "number".to_string(),
            description: "Size of the request body in bytes, before UTF-8 decoding.".to_string(),
            required: false,
        },
        Parameter {
            name: "body_is_binary".to_string(),
            type_hint: "boolean".to_string(),
            description: "Present and true only when the request body is not valid UTF-8. The \
                body field is then a lossy decoding; the raw bytes are not available to you."
                .to_string(),
            required: false,
        },
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("{method} {uri}")
            .with_debug("HTTP/2 {method} {uri} v{version}")
            .with_trace("HTTP/2: {json_pretty(.)}"),
    )
    .with_actions(vec![
        SEND_HTTP2_RESPONSE_ACTION.clone(),
        PUSH_RESOURCE_ACTION.clone(),
    ])
});

/// Get HTTP/2 event types
pub fn get_http2_event_types() -> Vec<EventType> {
    vec![HTTP2_REQUEST_EVENT.clone()]
}

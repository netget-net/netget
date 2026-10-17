//! HTTP/2 client protocol actions implementation

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

/// HTTP/2 client connected event
pub static HTTP2_CLIENT_CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "http2_connected",
        "HTTP/2 client initialized and ready to send requests",
        json!({
            "type": "send_http2_request",
            "method": "GET",
            "path": "/api/status"
        }),
    )
    .with_parameters(vec![Parameter {
        name: "base_url".to_string(),
        type_hint: "string".to_string(),
        description: "Base URL for HTTP/2 requests".to_string(),
        required: true,
    }])
});

/// HTTP/2 client response received event
pub static HTTP2_CLIENT_RESPONSE_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "http2_response_received",
        "HTTP/2 response received from server",
        json!({
            "type": "send_http2_request",
            "method": "POST",
            "path": "/api/data",
            "body": "{\"key\": \"value\"}"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "status_code".to_string(),
            type_hint: "number".to_string(),
            description: "HTTP status code".to_string(),
            required: true,
        },
        Parameter {
            name: "http_version".to_string(),
            type_hint: "string".to_string(),
            description: "HTTP version (should be HTTP/2.0)".to_string(),
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

/// HTTP/2 client protocol action handler
#[derive(Default)]
pub struct Http2ClientProtocol;

impl Http2ClientProtocol {
    pub fn new() -> Self {
        Self::default()
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for Http2ClientProtocol {
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![ParameterDefinition {
            name: "default_headers".to_string(),
            description: "Default headers to include in all requests".to_string(),
            type_hint: "object".to_string(),
            required: false,
            example: json!({
                "User-Agent": "NetGet/1.0",
                "Accept": "application/json"
            }),
            default: None,
        }]
    }
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![
            ActionDefinition {
                name: "send_http2_request".to_string(),
                description: "Send an HTTP/2 request to the server".to_string(),
                parameters: vec![
                    Parameter {
                        name: "method".to_string(),
                        type_hint: "string".to_string(),
                        description: "HTTP method (GET, POST, PUT, DELETE, etc.)".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "path".to_string(),
                        type_hint: "string".to_string(),
                        description: "Request path (e.g., /api/users), resolved against the client's base URL. An absolute URL is accepted only on that same origin; another host needs its own client".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "headers".to_string(),
                        type_hint: "object".to_string(),
                        description: "Request headers".to_string(),
                        required: false,
                    },
                    Parameter {
                        name: "body".to_string(),
                        type_hint: "string".to_string(),
                        description: "Request body".to_string(),
                        required: false,
                    },
                ],
                example: json!({
                    "type": "send_http2_request",
                    "method": "GET",
                    "path": "/api/status",
                    "headers": {
                        "Accept": "application/json"
                    }
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "disconnect".to_string(),
                description: "Disconnect from the HTTP/2 server".to_string(),
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
                description: "Do nothing and wait for the next HTTP/2 response. The correct \
                    answer when what arrived needs no follow-up -- without it the model has \
                    to invent an action it does not want."
                    .to_string(),
                parameters: vec![],
                example: json!({ "type": "wait_for_more" }),
                log_template: None,
            },
            ActionDefinition {
                name: "send_http2_request".to_string(),
                description: "Send another HTTP/2 request in response to received data".to_string(),
                parameters: vec![
                    Parameter {
                        name: "method".to_string(),
                        type_hint: "string".to_string(),
                        description: "HTTP method".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "path".to_string(),
                        type_hint: "string".to_string(),
                        description: "Request path, resolved against the client's base URL. An absolute URL is accepted only on that same origin; another host needs its own client".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "headers".to_string(),
                        type_hint: "object".to_string(),
                        description: "Request headers".to_string(),
                        required: false,
                    },
                    Parameter {
                        name: "body".to_string(),
                        type_hint: "string".to_string(),
                        description: "Request body".to_string(),
                        required: false,
                    },
                ],
                example: json!({
                    "type": "send_http2_request",
                    "method": "POST",
                    "path": "/api/data",
                    "body": "{\"key\": \"value\"}"
                }),
                log_template: None,
            },
        ]
    }
    fn protocol_name(&self) -> &'static str {
        "HTTP2"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            EventType::new(
                "http2_connected",
                "Triggered when HTTP/2 client is initialized",
                json!({"type": "placeholder", "event_id": "http2_connected"}),
            ),
            EventType::new(
                "http2_response_received",
                "Triggered when HTTP/2 client receives a response",
                json!({"type": "placeholder", "event_id": "http2_response_received"}),
            ),
        ]
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>HTTP/2"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "http2",
            "http/2",
            "http 2",
            "http2 client",
            "connect to http2",
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .implementation("reqwest HTTP/2 client library with http2_prior_knowledge")
            .llm_control("Full control over requests (method, path, headers, body)")
            .e2e_testing("HTTP/2 test server or nghttp2.org")
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "HTTP/2 client for making multiplexed web requests"
    }
    fn example_prompt(&self) -> &'static str {
        "Connect to https://http2.golang.org and fetch /reqinfo"
    }
    fn group_name(&self) -> &'static str {
        "Core"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        use serde_json::json;

        StartupExamples::new(
            // LLM mode: LLM handles HTTP/2 client
            json!({
                "type": "open_client",
                "remote_addr": "https://http2.golang.org",
                "base_stack": "http2",
                "instruction": "Fetch /reqinfo and display the HTTP/2 server information"
            }),
            // Script mode: Code-based HTTP/2 handling
            json!({
                "type": "open_client",
                "remote_addr": "https://httpbin.org",
                "base_stack": "http2",
                "event_handlers": [{
                    "event_pattern": "http2_response_received",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "<http2_handler>"
                    }
                }]
            }),
            // Static mode: Fixed HTTP/2 request
            json!({
                "type": "open_client",
                "remote_addr": "https://httpbin.org",
                "base_stack": "http2",
                "event_handlers": [{
                    "event_pattern": "http2_connected",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "send_http2_request",
                            "method": "GET",
                            "path": "/get",
                            "headers": {"Accept": "application/json"}
                        }]
                    }
                }]
            }),
        )
    }
}

// Implement Client trait (client-specific functionality)
impl Client for Http2ClientProtocol {
    fn connect(
        &self,
        ctx: crate::protocol::ConnectContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::client::http2::Http2Client;
            Http2Client::connect_with_llm_actions(
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
            "send_http2_request" => {
                let method = action
                    .get("method")
                    .and_then(|v| v.as_str())
                    .context("Missing 'method' field")?
                    .to_string();

                let path = action
                    .get("path")
                    .and_then(|v| v.as_str())
                    .context("Missing 'path' field")?
                    .to_string();

                let headers = action.get("headers").and_then(|v| v.as_object()).cloned();

                let body = action
                    .get("body")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());

                // Return custom result with request data
                Ok(ClientActionResult::Custom {
                    name: "http2_request".to_string(),
                    data: json!({
                        "method": method,
                        "path": path,
                        "headers": headers,
                        "body": body,
                    }),
                })
            }
            "disconnect" => Ok(ClientActionResult::Disconnect),
            // Declared above, so it must be executable here too.
            "wait_for_more" => Ok(ClientActionResult::WaitForMore),
            _ => Err(anyhow::anyhow!(
                "Unknown HTTP/2 client action: {}",
                action_type
            )),
        }
    }
}

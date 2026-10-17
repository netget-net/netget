//! HTTP client protocol actions implementation

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

/// HTTP client connected event
pub static HTTP_CLIENT_CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "http_connected",
        "HTTP client initialized and ready to send requests",
        serde_json::json!({
            "type": "send_http_request",
            "method": "GET",
            "path": "/"
        }),
    )
    .with_parameters(vec![Parameter {
        name: "base_url".to_string(),
        type_hint: "string".to_string(),
        description: "Base URL for HTTP requests".to_string(),
        required: true,
    }])
});

/// HTTP client response received event
pub static HTTP_CLIENT_RESPONSE_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "http_response_received",
        "HTTP response received from server",
        serde_json::json!({
            "type": "send_http_request",
            "method": "GET",
            "path": "/api/next"
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

/// HTTP client protocol action handler
pub struct HttpClientProtocol;

impl Default for HttpClientProtocol {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for HttpClientProtocol {
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
                name: "send_http_request".to_string(),
                description: "Send an HTTP request to the server".to_string(),
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
                    "type": "send_http_request",
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
                description: "Disconnect from the HTTP server".to_string(),
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
                name: "send_http_request".to_string(),
                description: "Send another HTTP request in response to received data".to_string(),
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
                    "type": "send_http_request",
                    "method": "POST",
                    "path": "/api/data",
                    "body": "{\"key\": \"value\"}"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "wait_for_more".to_string(),
                description:
                    "Take no action and wait for the next response. Use when nothing should be \
                 sent yet."
                        .to_string(),
                parameters: vec![],
                example: json!({ "type": "wait_for_more" }),
                log_template: None,
            },
        ]
    }
    fn protocol_name(&self) -> &'static str {
        "HTTP"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            EventType::new(
                "http_connected",
                "Triggered when HTTP client is initialized",
                json!({"type": "placeholder", "event_id": "http_connected"}),
            ),
            EventType::new(
                "http_response_received",
                "Triggered when HTTP client receives a response",
                json!({"type": "placeholder", "event_id": "http_response_received"}),
            ),
        ]
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>HTTP"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["http", "http client", "connect to http", "https"]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Beta)
            .implementation(
                "reqwest HTTP/HTTPS client library (HTTP/1.1, HTTP/2 via rustls); in the browser \
                 build hyper's HTTP/1.1 client over the virtual loopback (plain http:// only)",
            )
            .llm_control("Full control over requests (method, path, headers, body)")
            .e2e_testing(
                "tests/client/http/real_server_test.rs, 5 LLM calls, against nginx (C, its own \
                 HTTP parser; NetGet's client is reqwest/hyper). The model GETs a static file, \
                 POSTs a header built from that file with a 13-byte body, and GETs a missing \
                 path; nginx's own access log must hold exactly those request lines, the \
                 model's header value, the default_headers User-Agent, the body length and the \
                 200/200/404 statuses. HTTP is this client's protocol, so a real HTTP server is \
                 the right peer. Not #[ignore]d, and a missing nginx fails the test rather than \
                 skipping it.",
            )
            .notes(
                "Validated against nginx over plain HTTP/1.1. HTTPS, HTTP/2, redirects and \
                 compressed bodies are not exercised against a real server. A response body is \
                 read whole up to 8 MiB and refused past it. The browser transport \
                 (transport.rs) is exercised against NetGet's own servers only, chunked \
                 responses included.",
            )
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "HTTP/HTTPS client for making web requests (HTTP/1.1, HTTP/2)"
    }
    fn example_prompt(&self) -> &'static str {
        "Connect to https://example.com and fetch /api/status"
    }
    fn group_name(&self) -> &'static str {
        "Core"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        use serde_json::json;

        StartupExamples::new(
            // LLM mode: LLM controls HTTP client interactions
            json!({
                "type": "open_client",
                "remote_addr": "https://api.example.com",
                "base_stack": "http",
                "instruction": "Fetch the API status and report the results"
            }),
            // Script mode: Code-based deterministic responses
            json!({
                "type": "open_client",
                "remote_addr": "https://api.example.com",
                "base_stack": "http",
                "event_handlers": [{
                    "event_pattern": "http_response_received",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "<http_client_handler>"
                    }
                }]
            }),
            // Static mode: Fixed responses
            json!({
                "type": "open_client",
                "remote_addr": "https://api.example.com",
                "base_stack": "http",
                "event_handlers": [
                    {
                        "event_pattern": "http_connected",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "send_http_request",
                                "method": "GET",
                                "path": "/health",
                                "headers": {"Accept": "application/json"}
                            }]
                        }
                    },
                    {
                        "event_pattern": "http_response_received",
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
impl Client for HttpClientProtocol {
    fn connect(
        &self,
        ctx: crate::protocol::ConnectContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::client::http::HttpClient;
            HttpClient::connect_with_llm_actions(
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
            "send_http_request" => {
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
                    name: "http_request".to_string(),
                    data: json!({
                        "method": method,
                        "path": path,
                        "headers": headers,
                        "body": body,
                    }),
                })
            }
            "disconnect" => Ok(ClientActionResult::Disconnect),
            // CLAUDE.md lists wait_for_more as one of the three standard client
            // sync actions, and ftp/imap/doh/rip/tcp/dns all implement it. These two
            // did not, so returning it was an "unknown action" error the client then
            // swallowed -- two suites passed while sending an action the client
            // could never obey.
            "wait_for_more" => Ok(ClientActionResult::WaitForMore),
            _ => Err(anyhow::anyhow!(
                "Unknown HTTP client action: {}",
                action_type
            )),
        }
    }
}

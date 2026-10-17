//! HTTP/3 client protocol actions implementation

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

/// HTTP/3 client connected event
pub static HTTP3_CLIENT_CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "http3_connected",
        "HTTP/3 client connected via QUIC and ready to send requests",
        json!({
            "type": "send_http3_request",
            "method": "GET",
            "path": "/api/status",
            "priority": 5
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "base_url".to_string(),
            type_hint: "string".to_string(),
            description: "Base URL for HTTP/3 requests".to_string(),
            required: true,
        },
        Parameter {
            name: "remote_addr".to_string(),
            type_hint: "string".to_string(),
            description: "Authenticated target of this reusable QUIC session".to_string(),
            required: true,
        },
    ])
    .with_actions(Http3ClientProtocol::new().get_sync_actions())
});

/// HTTP/3 client response received event
pub static HTTP3_CLIENT_RESPONSE_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "http3_response_received",
        "HTTP/3 response received from server",
        json!({
            "type": "send_http3_request",
            "method": "POST",
            "path": "/api/data",
            "body": "{\"key\": \"value\"}",
            "priority": 3
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
            description: "Complete UTF-8 response body, at most 8 MiB".to_string(),
            required: true,
        },
        Parameter {
            name: "trailers".into(),
            type_hint: "object".into(),
            description: "Trailing response headers".into(),
            required: true,
        },
        Parameter {
            name: "stream_id".to_string(),
            type_hint: "number".to_string(),
            description: "Index of this request stream on the reusable QUIC connection."
                .to_string(),
            required: true,
        },
    ])
    .with_actions(Http3ClientProtocol::new().get_sync_actions())
});

pub static HTTP3_CLIENT_ERROR_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "http3_request_failed",
        "HTTP/3 exchange failed",
        json!({"type":"wait_for_more"}),
    )
    .with_parameters(vec![Parameter {
        name: "error".into(),
        type_hint: "string".into(),
        description: "Local failure description".into(),
        required: true,
    }])
    .with_actions(Http3ClientProtocol::new().get_sync_actions())
});

/// HTTP/3 client protocol action handler
#[derive(Default)]
pub struct Http3ClientProtocol;

impl Http3ClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for Http3ClientProtocol {
    /// The reusable session uses authenticated TLS without 0-RTT or migration.
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        let mut parameters = crate::utils::quic::client_parameters();
        parameters.push(ParameterDefinition {
            name: "default_headers".to_string(),
            description: "Default headers to include in all requests".to_string(),
            type_hint: "object".to_string(),
            required: false,
            example: json!({
                "User-Agent": "NetGet-HTTP3/1.0",
                "Accept": "application/json"
            }),
            default: None,
        });
        parameters
    }
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        self.get_sync_actions()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            ActionDefinition {
                name: "send_http3_request".to_string(),
                description: "Send another HTTP/3 request in response to received data".to_string(),
                parameters: vec![
                    Parameter {
                        name: "method".to_string(),
                        type_hint: "string".to_string(),
                        description: "HTTP request method, such as GET or POST".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "path".to_string(),
                        type_hint: "string".to_string(),
                        description: "Origin-form path and optional query string".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "headers".to_string(),
                        type_hint: "object".to_string(),
                        description: "Request headers".to_string(),
                        required: false,
                    },
                    Parameter {
                        name: "trailers".into(),
                        type_hint: "object".into(),
                        description: "Trailing request headers".into(),
                        required: false,
                    },
                    Parameter {
                        name: "body".to_string(),
                        type_hint: "string".to_string(),
                        description: "UTF-8 request body, at most 8 MiB".to_string(),
                        required: false,
                    },
                    Parameter {
                        name: "priority".to_string(),
                        type_hint: "number".to_string(),
                        description: "RFC 9218 urgency, 0-7, sent as the `priority: u=N` request \
                            header. **Lower is more urgent** (0 = most urgent, 7 = least); \
                            the RFC default is 3, and omitting this sends no header at all, \
                            which is not the same as sending u=3. It is a hint the server \
                            uses when scheduling responses; a server may ignore it."
                            .to_string(),
                        required: false,
                    },
                ],
                example: json!({
                    "type": "send_http3_request",
                    "method": "POST",
                    "path": "/api/data",
                    "body": "{\"key\": \"value\"}",
                    "priority": 3
                }),
                log_template: Some(
                    LogTemplate::new().with_info("-> HTTP3 {method} {path} body_bytes={body_len}"),
                ),
            },
            ActionDefinition {
                name: "disconnect".into(),
                description: "Close the QUIC session and cancel active requests".into(),
                parameters: vec![],
                example: json!({"type":"disconnect"}),
                log_template: Some(LogTemplate::new().with_info("-> HTTP3 disconnect")),
            },
            ActionDefinition {
                name: "wait_for_more".to_string(),
                description: "Take no action and wait for the next response. Use when nothing \
                should be sent yet."
                    .to_string(),
                parameters: vec![],
                example: json!({ "type": "wait_for_more" }),
                log_template: Some(
                    LogTemplate::new().with_info("HTTP3 waiting for another response"),
                ),
            },
        ]
    }
    fn protocol_name(&self) -> &'static str {
        "HTTP3"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            HTTP3_CLIENT_CONNECTED_EVENT.clone(),
            HTTP3_CLIENT_RESPONSE_RECEIVED_EVENT.clone(),
            HTTP3_CLIENT_ERROR_EVENT.clone(),
        ]
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>UDP>QUIC>HTTP3"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["http3", "http/3", "quic", "h3", "connect to http3"]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .implementation("quinn 0.11 + rustls 0.23 + h3 0.0.8, authenticated reusable RFC 9114 session with an owned control/QPACK driver. h3-quinn 0.0.10 has a local pending-read cancellation patch.")
            .llm_control("Method, origin-form path, headers, UTF-8 body, request trailers and RFC 9218 urgency 0..7. Injected and handler requests multiplex concurrently; up to 32 active exchanges and handlers, with four follow-up levels.")
            .e2e_testing("Independent pinned aioquic 1.3.0 server tests GET/POST/header/priority/trailers, multiplexing, response bounds, trust/name failures, timeout and disconnect/removal. NetGet pair and real server tests cover both roles. No tests are ignored or skip missing peers.")
            .notes("32 KiB field sections, 8 MiB UTF-8 bodies, bounded handshake/exchange/idle deadlines. System roots plus explicit ca_cert_path; optional server_name. No 0-RTT, server push, DATAGRAM, WebTransport or migration. Experimental: no second independent implementation, pcap oracle or fuzz target.")
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "HTTP/3 client for making web requests over QUIC"
    }
    fn example_prompt(&self) -> &'static str {
        "Connect to localhost:4433 using a trusted certificate and fetch /api/status over HTTP/3"
    }
    fn group_name(&self) -> &'static str {
        "Core"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        use serde_json::json;

        StartupExamples::new(
            // LLM mode: LLM handles HTTP/3 client
            json!({
                "type": "open_client",
                "remote_addr": "localhost:4433",
                "startup_params": {"ca_cert_path":"cert.pem","server_name":"localhost"},
                "base_stack": "http3",
                "instruction": "Fetch /api/status and display QUIC connection info"
            }),
            // Script mode: Code-based HTTP/3 handling
            json!({
                "type": "open_client",
                "remote_addr": "localhost:4433",
                "startup_params": {"ca_cert_path":"cert.pem","server_name":"localhost"},
                "base_stack": "http3",
                "event_handlers": [{
                    "event_pattern": "http3_response_received",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "<http3_handler>"
                    }
                }]
            }),
            // Static mode: Fixed HTTP/3 request
            json!({
                "type": "open_client",
                "remote_addr": "localhost:4433",
                "startup_params": {"ca_cert_path":"cert.pem","server_name":"localhost"},
                "base_stack": "http3",
                "event_handlers": [{
                    "event_pattern": "http3_connected",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "send_http3_request",
                            "method": "GET",
                            "path": "/api/status",
                            "priority": 5
                        }]
                    }
                }]
            }),
        )
    }
}

// Implement Client trait (client-specific functionality)
impl Client for Http3ClientProtocol {
    fn connect(
        &self,
        ctx: crate::protocol::ConnectContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::client::http3::Http3Client;
            Http3Client::connect(ctx).await
        })
    }
    fn execute_action(&self, action: serde_json::Value) -> Result<ClientActionResult> {
        let action_type = action
            .get("type")
            .and_then(|v| v.as_str())
            .context("Missing 'type' field in action")?;

        match action_type {
            "send_http3_request" => {
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

                let headers = match action.get("headers") {
                    None | Some(serde_json::Value::Null) => None,
                    Some(value) => Some(
                        value
                            .as_object()
                            .context("headers must be an object")?
                            .clone(),
                    ),
                };

                let body = match action.get("body") {
                    None | Some(serde_json::Value::Null) => None,
                    Some(value) => {
                        Some(value.as_str().context("body must be a string")?.to_owned())
                    }
                };

                let priority = action
                    .get("priority")
                    .filter(|value| !value.is_null())
                    .map(|_| crate::client::wire_values::number::<u8>(&action, "priority", 0))
                    .transpose()?;
                anyhow::ensure!(priority.is_none_or(|p| p <= 7), "priority must be 0..7");

                // Return custom result with request data
                Ok(ClientActionResult::Custom {
                    name: "http3_request".to_string(),
                    data: json!({
                        "method": method,
                        "path": path,
                        "headers": headers,
                        "body": body,
                        "priority": priority,
                        "trailers": action.get("trailers"),
                    }),
                })
            }
            "disconnect" => Ok(ClientActionResult::Disconnect),
            "wait_for_more" => Ok(ClientActionResult::WaitForMore),
            _ => Err(anyhow::anyhow!(
                "Unknown HTTP/3 client action: {}",
                action_type
            )),
        }
    }
}

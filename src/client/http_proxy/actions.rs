//! HTTP proxy client protocol actions implementation

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

/// HTTP proxy client connected event
pub static HTTP_PROXY_CLIENT_CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "http_proxy_connected",
        "HTTP proxy client connected to proxy server",
        json!({
            "type": "establish_tunnel",
            "target_host": "example.com",
            "target_port": 443
        }),
    )
    .with_parameters(vec![Parameter {
        name: "proxy_addr".to_string(),
        type_hint: "string".to_string(),
        description: "HTTP proxy server address".to_string(),
        required: true,
    }])
});

/// HTTP proxy tunnel established event
pub static HTTP_PROXY_TUNNEL_ESTABLISHED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "http_proxy_tunnel_established",
        "HTTP CONNECT tunnel successfully established",
        json!({
            "type": "send_http_request",
            "method": "GET",
            "path": "/",
            "headers": {"Host": "example.com"}
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "target_host".to_string(),
            type_hint: "string".to_string(),
            description: "Target host for tunnel".to_string(),
            required: true,
        },
        Parameter {
            name: "target_port".to_string(),
            type_hint: "number".to_string(),
            description: "Target port for tunnel".to_string(),
            required: true,
        },
        Parameter {
            name: "status_code".to_string(),
            type_hint: "number".to_string(),
            description: "HTTP status code from proxy".to_string(),
            required: true,
        },
    ])
});

/// HTTP proxy response received event
pub static HTTP_PROXY_RESPONSE_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "http_proxy_response_received",
        "HTTP response received via proxy tunnel",
        json!({
            "type": "send_data",
            "data_hex": "48656c6c6f"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "data_hex".to_string(),
            type_hint: "string".to_string(),
            description: "Response data (as hex string)".to_string(),
            required: true,
        },
        Parameter {
            name: "data_length".to_string(),
            type_hint: "number".to_string(),
            description: "Length of response data in bytes".to_string(),
            required: true,
        },
    ])
});

/// HTTP proxy client protocol action handler
#[derive(Default)]
pub struct HttpProxyClientProtocol;

impl HttpProxyClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for HttpProxyClientProtocol {
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "proxy_auth".to_string(),
                description: "Proxy authentication credentials (username:password)".to_string(),
                type_hint: "string".to_string(),
                required: false,
                example: json!("username:password"),
                default: None,
            },
            ParameterDefinition {
                name: "default_target".to_string(),
                description: "Default target host:port for CONNECT tunnel".to_string(),
                type_hint: "string".to_string(),
                required: false,
                example: json!("example.com:80"),
                default: None,
            },
        ]
    }
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![
            ActionDefinition {
                name: "establish_tunnel".to_string(),
                description: "Establish HTTP CONNECT tunnel to target".to_string(),
                parameters: vec![
                    Parameter {
                        name: "target_host".to_string(),
                        type_hint: "string".to_string(),
                        description: "Target hostname or IP".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "target_port".to_string(),
                        type_hint: "number".to_string(),
                        description: "Target port".to_string(),
                        required: true,
                    },
                ],
                example: json!({
                    "type": "establish_tunnel",
                    "target_host": "example.com",
                    "target_port": 443
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "send_http_request".to_string(),
                description: "Send HTTP request via established tunnel".to_string(),
                parameters: vec![
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
                        name: "headers".to_string(),
                        type_hint: "object".to_string(),
                        description: "HTTP headers".to_string(),
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
                    "path": "/",
                    "headers": {
                        "Host": "example.com",
                        "User-Agent": "NetGet/1.0"
                    }
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "send_data".to_string(),
                description: "Send raw data through the proxy tunnel".to_string(),
                parameters: vec![Parameter {
                    name: "data_hex".to_string(),
                    type_hint: "string".to_string(),
                    description: "Hexadecimal encoded data to send".to_string(),
                    required: true,
                }],
                example: json!({
                    "type": "send_data",
                    "data_hex": "48656c6c6f"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "disconnect".to_string(),
                description: "Disconnect from the proxy server".to_string(),
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
                description: "Send HTTP request in response to received data".to_string(),
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
                        description: "Request path".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "headers".to_string(),
                        type_hint: "object".to_string(),
                        description: "HTTP headers".to_string(),
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
                name: "send_data".to_string(),
                description: "Send raw data in response to received data".to_string(),
                parameters: vec![Parameter {
                    name: "data_hex".to_string(),
                    type_hint: "string".to_string(),
                    description: "Hexadecimal encoded data to send".to_string(),
                    required: true,
                }],
                example: json!({
                    "type": "send_data",
                    "data_hex": "48656c6c6f"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "wait_for_more".to_string(),
                description: "Wait for more data before responding".to_string(),
                parameters: vec![],
                example: json!({
                    "type": "wait_for_more"
                }),
                log_template: None,
            },
        ]
    }
    fn protocol_name(&self) -> &'static str {
        "HTTP Proxy"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            EventType::new(
                "http_proxy_connected",
                "Triggered when HTTP proxy client connects to proxy server",
                json!({"type": "placeholder", "event_id": "http_proxy_connected"}),
            ),
            EventType::new(
                "http_proxy_tunnel_established",
                "Triggered when HTTP CONNECT tunnel is established",
                json!({"type": "placeholder", "event_id": "http_proxy_tunnel_established"}),
            ),
            EventType::new(
                "http_proxy_response_received",
                "Triggered when data is received via proxy tunnel",
                json!({"type": "placeholder", "event_id": "http_proxy_response_received"}),
            ),
        ]
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>HTTP"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "http proxy",
            "http proxy client",
            "connect via proxy",
            "proxy",
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .implementation("Tokio TcpStream with HTTP CONNECT protocol")
            .llm_control("Full control over tunnel establishment and data transmission")
            .e2e_testing("Squid proxy or tinyproxy as test proxy")
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "HTTP proxy client for tunneling connections through HTTP proxies"
    }
    fn example_prompt(&self) -> &'static str {
        "Connect via HTTP proxy at localhost:8080 to reach example.com:443"
    }
    fn group_name(&self) -> &'static str {
        "Proxy"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        use serde_json::json;

        StartupExamples::new(
            // LLM mode: LLM controls HTTP proxy tunnel
            json!({
                "type": "open_client",
                "remote_addr": "localhost:8080",
                "base_stack": "http_proxy",
                "instruction": "Establish tunnel to example.com:443 and send a GET request"
            }),
            // Script mode: Code-based proxy handling
            json!({
                "type": "open_client",
                "remote_addr": "localhost:8080",
                "base_stack": "http_proxy",
                "event_handlers": [{
                    "event_pattern": "http_proxy_response_received",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "<http_proxy_client_handler>"
                    }
                }]
            }),
            // Static mode: Fixed tunnel establishment
            json!({
                "type": "open_client",
                "remote_addr": "localhost:8080",
                "base_stack": "http_proxy",
                "event_handlers": [
                    {
                        "event_pattern": "http_proxy_connected",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "establish_tunnel",
                                "target_host": "example.com",
                                "target_port": 80
                            }]
                        }
                    },
                    {
                        "event_pattern": "http_proxy_tunnel_established",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "send_http_request",
                                "method": "GET",
                                "path": "/",
                                "headers": {"Host": "example.com"}
                            }]
                        }
                    }
                ]
            }),
        )
    }
}

// Implement Client trait (client-specific functionality)
impl Client for HttpProxyClientProtocol {
    fn connect(
        &self,
        ctx: crate::protocol::ConnectContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::client::http_proxy::HttpProxyClient;
            HttpProxyClient::connect_with_llm_actions(
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
            "establish_tunnel" => {
                let target_host = action
                    .get("target_host")
                    .and_then(|v| v.as_str())
                    .context("Missing 'target_host' field")?
                    .to_string();

                // Range-checked, not narrowed. `as u16` wraps in silence, so
                // `target_port: 66079` became 543 and the CONNECT went to a *different
                // service on the same host* than the one the model named — quietly, with
                // every log line downstream reporting the port it ended up at rather than
                // the one it was asked for. A client that loses its target must fail rather
                // than pick one.
                let raw = action
                    .get("target_port")
                    .and_then(|v| v.as_u64())
                    .context("Missing 'target_port' field")?;
                if !(1..=65535).contains(&raw) {
                    return Err(anyhow::anyhow!(
                        "'target_port' {raw} is not a TCP port (1-65535). Truncating it \
                         would tunnel to a different service than the one named."
                    ));
                }
                let target_port = raw as u16;

                Ok(ClientActionResult::Custom {
                    name: "establish_tunnel".to_string(),
                    data: json!({
                        "target_host": target_host,
                        "target_port": target_port,
                    }),
                })
            }
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

                // Build HTTP request string
                let mut request = format!("{} {} HTTP/1.1\r\n", method, path);

                // Add headers
                if let Some(hdrs) = headers {
                    for (key, value) in hdrs {
                        if let Some(val_str) = value.as_str() {
                            request.push_str(&format!("{}: {}\r\n", key, val_str));
                        }
                    }
                }

                // End headers
                request.push_str("\r\n");

                // Add body if present
                if let Some(body_str) = body {
                    request.push_str(&body_str);
                }

                Ok(ClientActionResult::SendData(request.into_bytes()))
            }
            "send_data" => {
                let data_hex = action
                    .get("data_hex")
                    .and_then(|v| v.as_str())
                    .context("Missing 'data_hex' field")?;

                let data = hex::decode(data_hex).context("Invalid hex data")?;

                Ok(ClientActionResult::SendData(data))
            }
            "disconnect" => Ok(ClientActionResult::Disconnect),
            "wait_for_more" => Ok(ClientActionResult::WaitForMore),
            _ => Err(anyhow::anyhow!(
                "Unknown HTTP proxy client action: {}",
                action_type
            )),
        }
    }
}

//! TLS client protocol actions implementation

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

/// TLS client connected event - emitted after successful TLS handshake
pub static TLS_CLIENT_CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "tls_client_connected",
        "TLS client successfully completed handshake with server",
        json!({
            "type": "send_tls_data",
            "data": "Hello"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "remote_addr".to_string(),
            type_hint: "string".to_string(),
            description: "Remote TLS server address".to_string(),
            required: true,
        },
        Parameter {
            name: "server_name".to_string(),
            type_hint: "string".to_string(),
            description: "SNI server name used for TLS handshake".to_string(),
            required: true,
        },
    ])
});

/// TLS client data received event - emitted when encrypted data is received
pub static TLS_CLIENT_DATA_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "tls_client_data_received",
        "Data received from TLS server (decrypted)",
        json!({
            "type": "send_tls_data",
            "data": "Response"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "data".to_string(),
            type_hint: "string".to_string(),
            description: "The decrypted data received (UTF-8 text or hex for binary)".to_string(),
            required: true,
        },
        Parameter {
            name: "data_length".to_string(),
            type_hint: "number".to_string(),
            description: "Length of data in bytes".to_string(),
            required: true,
        },
    ])
});

/// TLS client protocol action handler
pub struct TlsClientProtocol;

impl Default for TlsClientProtocol {
    fn default() -> Self {
        Self::new()
    }
}

impl TlsClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for TlsClientProtocol {
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "accept_invalid_certs".to_string(),
                type_hint: "boolean".to_string(),
                description:
                    "Accept self-signed or invalid certificates (useful for testing, default: false)"
                        .to_string(),
                required: false,
                example: json!(false),
                default: None,
            },
            ParameterDefinition {
                name: "server_name".to_string(),
                type_hint: "string".to_string(),
                description: "SNI server name for TLS handshake (default: derived from remote_addr hostname)"
                    .to_string(),
                required: false,
                example: json!("example.com"),
                default: None,
            },
            ParameterDefinition {
                name: "custom_ca_cert_pem".to_string(),
                type_hint: "string".to_string(),
                description: "Custom CA certificate in PEM format to use for validation (instead of system roots)"
                    .to_string(),
                required: false,
                example: json!("-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"),
                default: None,
            },
        ]
    }

    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![
            ActionDefinition {
                name: "send_tls_data".to_string(),
                description: "Send data over TLS connection (UTF-8 string or hex-encoded)"
                    .to_string(),
                parameters: vec![
                    Parameter {
                        name: "data".to_string(),
                        type_hint: "string".to_string(),
                        description: "UTF-8 string data to send (preferred for text)".to_string(),
                        required: false,
                    },
                    Parameter {
                        name: "data_hex".to_string(),
                        type_hint: "string".to_string(),
                        description: "Hexadecimal encoded data to send (for binary data)"
                            .to_string(),
                        required: false,
                    },
                ],
                example: json!({
                    "type": "send_tls_data",
                    "data": "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "disconnect".to_string(),
                description: "Disconnect from the TLS server".to_string(),
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
                name: "send_tls_data".to_string(),
                description:
                    "Send TLS data in response to received data (UTF-8 string or hex-encoded)"
                        .to_string(),
                parameters: vec![
                    Parameter {
                        name: "data".to_string(),
                        type_hint: "string".to_string(),
                        description: "UTF-8 string data to send (preferred for text)".to_string(),
                        required: false,
                    },
                    Parameter {
                        name: "data_hex".to_string(),
                        type_hint: "string".to_string(),
                        description: "Hexadecimal encoded data to send (for binary data)"
                            .to_string(),
                        required: false,
                    },
                ],
                example: json!({
                    "type": "send_tls_data",
                    "data": "Response data"
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
        "TLS"
    }

    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            EventType::new(
                "tls_client_connected",
                "Triggered when TLS client completes handshake with server",
                json!({"type": "placeholder", "event_id": "tls_client_connected"}),
            ),
            EventType::new(
                "tls_client_data_received",
                "Triggered when TLS client receives decrypted data from server",
                json!({"type": "placeholder", "event_id": "tls_client_data_received"}),
            ),
        ]
    }

    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>TLS"
    }

    fn keywords(&self) -> Vec<&'static str> {
        vec!["tls", "ssl", "tls client", "connect to tls", "https"]
    }

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .implementation("tokio-rustls TLS client with certificate validation control")
            .llm_control("Full control over encrypted data exchange")
            .e2e_testing("NetGet TLS server for testing")
            .notes("Generic TLS client for encrypted protocols - LLM implements application layer")
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            // A reader task queues each read while the model answers; with batching on the
            // answering loop joins everything waiting into one payload, as the tcp client does.
            .batching(crate::protocol::metadata::BatchingMode::On)
            .build()
    }

    fn description(&self) -> &'static str {
        "TLS client for connecting to TLS/SSL servers"
    }

    fn example_prompt(&self) -> &'static str {
        "Connect to TLS at localhost:8443 and send an HTTP request"
    }

    fn group_name(&self) -> &'static str {
        "Core"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        use serde_json::json;

        StartupExamples::new(
            // LLM mode: LLM handles TLS client
            json!({
                "type": "open_client",
                "remote_addr": "example.com:443",
                "base_stack": "tls",
                "instruction": "Send an HTTPS GET request and display the response"
            }),
            // Script mode: Code-based TLS handling
            json!({
                "type": "open_client",
                "remote_addr": "example.com:443",
                "base_stack": "tls",
                "event_handlers": [{
                    "event_pattern": "tls_client_data_received",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "<tls_handler>"
                    }
                }]
            }),
            // Static mode: Fixed TLS request
            json!({
                "type": "open_client",
                "remote_addr": "example.com:443",
                "base_stack": "tls",
                "event_handlers": [{
                    "event_pattern": "tls_client_connected",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "send_tls_data",
                            "data": "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"
                        }]
                    }
                }]
            }),
        )
    }
}

// Implement Client trait (client-specific functionality)
impl Client for TlsClientProtocol {
    fn connect(
        &self,
        ctx: crate::protocol::ConnectContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::client::tls::TlsClient;
            TlsClient::connect_with_llm_actions(
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
            "send_tls_data" => {
                // Support both UTF-8 string (data) and hex-encoded (data_hex)
                // Prefer UTF-8 for easier LLM interaction
                let data = if let Some(utf8_data) = action.get("data").and_then(|v| v.as_str()) {
                    // UTF-8 string provided
                    utf8_data.as_bytes().to_vec()
                } else if let Some(hex_data) = action.get("data_hex").and_then(|v| v.as_str()) {
                    // Hex string provided
                    hex::decode(hex_data).context("Invalid hex data in data_hex field")?
                } else {
                    return Err(anyhow::anyhow!(
                        "Missing 'data' or 'data_hex' field in send_tls_data action"
                    ));
                };

                Ok(ClientActionResult::SendData(data))
            }
            "disconnect" => Ok(ClientActionResult::Disconnect),
            "wait_for_more" => Ok(ClientActionResult::WaitForMore),
            _ => Err(anyhow::anyhow!(
                "Unknown TLS client action: {}",
                action_type
            )),
        }
    }
}

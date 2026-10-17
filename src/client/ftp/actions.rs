//! FTP client protocol actions implementation
//!
//! Implements FTP client actions for LLM-controlled FTP connections.

use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, Parameter,
};
use crate::protocol::EventType;
use crate::state::app_state::AppState;
use anyhow::{Context, Result};
use serde_json::json;
use std::sync::LazyLock;

/// FTP client connected event
pub static FTP_CLIENT_CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "ftp_connected",
        "FTP client successfully connected to server",
        json!({"type": "wait_for_more"}),
    )
    .with_parameters(vec![Parameter {
        name: "remote_addr".to_string(),
        type_hint: "string".to_string(),
        description: "Remote FTP server address".to_string(),
        required: true,
    }])
});

/// FTP client response received event
pub static FTP_CLIENT_RESPONSE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "ftp_response",
        "Response received from FTP server",
        json!({"type": "send_ftp_command", "command": "USER anonymous"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "response".to_string(),
            type_hint: "string".to_string(),
            description: "The full response line from the server".to_string(),
            required: true,
        },
        Parameter {
            name: "response_code".to_string(),
            type_hint: "number".to_string(),
            description: "The FTP response code (e.g., 220, 230, 550)".to_string(),
            required: false,
        },
    ])
});

/// FTP client protocol action handler
pub struct FtpClientProtocol;

impl Default for FtpClientProtocol {
    fn default() -> Self {
        Self::new()
    }
}

impl FtpClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for FtpClientProtocol {
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![
            ActionDefinition {
                name: "send_ftp_command".to_string(),
                description: "Send an FTP command to the server".to_string(),
                parameters: vec![Parameter {
                    name: "command".to_string(),
                    type_hint: "string".to_string(),
                    description: "FTP command (e.g., 'USER anonymous', 'LIST', 'QUIT')".to_string(),
                    required: true,
                }],
                example: json!({
                    "type": "send_ftp_command",
                    "command": "USER anonymous"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "disconnect".to_string(),
                description: "Disconnect from the FTP server".to_string(),
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
                name: "send_ftp_command".to_string(),
                description: "Send FTP command in response to server message".to_string(),
                parameters: vec![Parameter {
                    name: "command".to_string(),
                    type_hint: "string".to_string(),
                    description: "FTP command to send".to_string(),
                    required: true,
                }],
                example: json!({
                    "type": "send_ftp_command",
                    "command": "PASS guest@example.com"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "wait_for_more".to_string(),
                description: "Wait for more data from the server before responding".to_string(),
                parameters: vec![],
                example: json!({
                    "type": "wait_for_more"
                }),
                log_template: None,
            },
        ]
    }

    fn protocol_name(&self) -> &'static str {
        "FTP"
    }

    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            FTP_CLIENT_CONNECTED_EVENT.clone(),
            FTP_CLIENT_RESPONSE_EVENT.clone(),
        ]
    }

    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>FTP"
    }

    fn keywords(&self) -> Vec<&'static str> {
        vec!["ftp client", "connect to ftp", "ftp connect"]
    }

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .implementation("Tokio TcpStream with line-based FTP protocol")
            .llm_control("Full control over FTP commands")
            .e2e_testing("Local FTP server (vsftpd, netget FTP server)")
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }

    fn description(&self) -> &'static str {
        "FTP client for connecting to FTP servers"
    }

    fn example_prompt(&self) -> &'static str {
        "Connect to ftp://localhost:21 and list files using anonymous login"
    }

    fn group_name(&self) -> &'static str {
        "Application"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        use serde_json::json;

        StartupExamples::new(
            // LLM mode: LLM controls FTP client interactions
            json!({
                "type": "open_client",
                "remote_addr": "ftp.example.com:21",
                "base_stack": "ftp",
                "instruction": "Login anonymously and list the root directory files"
            }),
            // Script mode: Code-based deterministic responses
            json!({
                "type": "open_client",
                "remote_addr": "ftp.example.com:21",
                "base_stack": "ftp",
                "event_handlers": [{
                    "event_pattern": "ftp_response",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "<ftp_client_handler>"
                    }
                }]
            }),
            // Static mode: Fixed responses - login sequence
            json!({
                "type": "open_client",
                "remote_addr": "ftp.example.com:21",
                "base_stack": "ftp",
                "event_handlers": [
                    {
                        "event_pattern": "ftp_connected",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "wait_for_more"
                            }]
                        }
                    },
                    {
                        "event_pattern": "ftp_response",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "send_ftp_command",
                                "command": "QUIT"
                            }]
                        }
                    }
                ]
            }),
        )
    }
}

// Implement Client trait (client-specific functionality)
impl Client for FtpClientProtocol {
    fn connect(
        &self,
        ctx: crate::protocol::ConnectContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::client::ftp::FtpClient;
            FtpClient::connect_with_llm_actions(
                ctx.remote_addr,
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.client_id,
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
            "send_ftp_command" => {
                let command = action
                    .get("command")
                    .and_then(|v| v.as_str())
                    .context("Missing 'command' parameter in send_ftp_command action")?;

                // FTP commands must end with CRLF
                let data = if command.ends_with("\r\n") {
                    command.as_bytes().to_vec()
                } else if command.ends_with('\n') {
                    format!("{}\r", command.trim_end_matches('\n')).into_bytes()
                } else {
                    format!("{}\r\n", command).into_bytes()
                };

                Ok(ClientActionResult::SendData(data))
            }
            "disconnect" => Ok(ClientActionResult::Disconnect),
            "wait_for_more" => Ok(ClientActionResult::WaitForMore),
            _ => Err(anyhow::anyhow!(
                "Unknown FTP client action: {}",
                action_type
            )),
        }
    }
}

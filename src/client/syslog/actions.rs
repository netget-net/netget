//! Syslog client protocol actions implementation

use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, Parameter, ParameterDefinition,
};
use crate::protocol::ConnectContext;
use crate::protocol::EventType;
use crate::state::app_state::AppState;
use anyhow::{Context, Result};
use serde_json::json;
use std::sync::LazyLock;

/// Syslog client connected event
pub static SYSLOG_CLIENT_CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "syslog_connected",
        "Syslog client successfully connected to server",
        json!({
            "type": "send_syslog_message",
            "facility": "user",
            "severity": "info",
            "message": "Connection established"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "remote_addr".to_string(),
            type_hint: "string".to_string(),
            description: "Remote syslog server address".to_string(),
            required: true,
        },
        Parameter {
            name: "protocol".to_string(),
            type_hint: "string".to_string(),
            description: "Transport protocol (tcp or udp)".to_string(),
            required: true,
        },
    ])
});

/// Syslog client protocol action handler
pub struct SyslogClientProtocol;

impl SyslogClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for SyslogClientProtocol {
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![
                ActionDefinition {
                    name: "send_syslog_message".to_string(),
                    description: "Send a syslog message to the server".to_string(),
                    parameters: vec![
                        Parameter {
                            name: "facility".to_string(),
                            type_hint: "string".to_string(),
                            description: "Syslog facility (kern, user, mail, daemon, auth, syslog, lpr, news, uucp, cron, authpriv, ftp, ntp, security, console, solaris-cron, local0-local7)".to_string(),
                            required: true,
                        },
                        Parameter {
                            name: "severity".to_string(),
                            type_hint: "string".to_string(),
                            description: "Syslog severity (emerg, alert, crit, err, warning, notice, info, debug)".to_string(),
                            required: true,
                        },
                        Parameter {
                            name: "message".to_string(),
                            type_hint: "string".to_string(),
                            description: "The log message to send".to_string(),
                            required: true,
                        },
                        Parameter {
                            name: "hostname".to_string(),
                            type_hint: "string".to_string(),
                            description: "Hostname (optional, defaults to 'netget')".to_string(),
                            required: false,
                        },
                        Parameter {
                            name: "app_name".to_string(),
                            type_hint: "string".to_string(),
                            description: "Application name (optional, defaults to 'netget')".to_string(),
                            required: false,
                        },
                        Parameter {
                            name: "proc_id".to_string(),
                            type_hint: "string".to_string(),
                            description: "Process ID (optional, defaults to '-')".to_string(),
                            required: false,
                        },
                        Parameter {
                            name: "msg_id".to_string(),
                            type_hint: "string".to_string(),
                            description: "Message ID (optional, defaults to '-')".to_string(),
                            required: false,
                        },
                    ],
                    example: json!({
                        "type": "send_syslog_message",
                        "facility": "user",
                        "severity": "info",
                        "message": "Test log message from netget",
                        "hostname": "netget-host",
                        "app_name": "netget"
                    }),
                log_template: None,
                },
                ActionDefinition {
                    name: "disconnect".to_string(),
                    description: "Disconnect from the syslog server (TCP only)".to_string(),
                    parameters: vec![],
                    example: json!({
                        "type": "disconnect"
                    }),
                log_template: None,
                },
            ]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![]
    }
    fn protocol_name(&self) -> &'static str {
        "Syslog"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            EventType::new(
                "syslog_connected",
                "Triggered when syslog client connects to server",
                json!({"type": "placeholder", "event_id": "syslog_connected"}),
            ),
            EventType::new(
                "syslog_message_sent",
                "Triggered when syslog message is sent",
                json!({"type": "placeholder", "event_id": "syslog_message_sent"}),
            ),
        ]
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP/UDP>Syslog"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["syslog", "syslog client", "logging"]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .implementation("RFC 5424 syslog over TCP or UDP")
            .llm_control("Full control over facility, severity, and message content")
            .e2e_testing("rsyslog or syslog-ng as test server")
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "Syslog client for sending log messages to remote syslog servers"
    }
    fn example_prompt(&self) -> &'static str {
        "Send a syslog message with facility 'user' and severity 'info' to localhost:514"
    }
    fn group_name(&self) -> &'static str {
        "Logging"
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![ParameterDefinition {
            name: "protocol".to_string(),
            description: "Transport protocol (tcp or udp, defaults to udp)".to_string(),
            type_hint: "string".to_string(),
            required: false,
            example: json!("tcp"),
            default: None,
        }]
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        use serde_json::json;

        StartupExamples::new(
            // LLM mode: LLM controls syslog messages
            json!({
                "type": "open_client",
                "remote_addr": "localhost:514",
                "base_stack": "syslog",
                "instruction": "Send a user info log message about application startup"
            }),
            // Script mode: Code-based log generation
            json!({
                "type": "open_client",
                "remote_addr": "localhost:514",
                "base_stack": "syslog",
                "event_handlers": [{
                    "event_pattern": "syslog_connected",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "<syslog_client_handler>"
                    }
                }]
            }),
            // Static mode: Fixed log messages
            json!({
                "type": "open_client",
                "remote_addr": "localhost:514",
                "base_stack": "syslog",
                "event_handlers": [
                    {
                        "event_pattern": "syslog_connected",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "send_syslog_message",
                                "facility": "user",
                                "severity": "info",
                                "message": "NetGet client connected",
                                "hostname": "netget-host",
                                "app_name": "netget"
                            }]
                        }
                    }
                ]
            }),
        )
    }
}

// Implement Client trait (client-specific functionality)
impl Client for SyslogClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::client::syslog::SyslogClient;
            SyslogClient::connect_with_llm_actions(
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
            "send_syslog_message" => {
                let facility = action
                    .get("facility")
                    .and_then(|v| v.as_str())
                    .context("Missing 'facility' field")?;

                let severity = action
                    .get("severity")
                    .and_then(|v| v.as_str())
                    .context("Missing 'severity' field")?;

                let message = action
                    .get("message")
                    .and_then(|v| v.as_str())
                    .context("Missing 'message' field")?;

                let hostname = action
                    .get("hostname")
                    .and_then(|v| v.as_str())
                    .unwrap_or("netget");

                let app_name = action
                    .get("app_name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("netget");

                let proc_id = action
                    .get("proc_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("-");

                let msg_id = action.get("msg_id").and_then(|v| v.as_str()).unwrap_or("-");

                Ok(ClientActionResult::Custom {
                    name: "send_syslog_message".to_string(),
                    data: json!({
                        "facility": facility,
                        "severity": severity,
                        "message": message,
                        "hostname": hostname,
                        "app_name": app_name,
                        "proc_id": proc_id,
                        "msg_id": msg_id,
                    }),
                })
            }
            "disconnect" => Ok(ClientActionResult::Disconnect),
            _ => Err(anyhow::anyhow!(
                "Unknown syslog client action: {}",
                action_type
            )),
        }
    }
}

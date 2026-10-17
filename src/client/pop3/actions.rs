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

/// Event: POP3 client connected to server
pub static POP3_CLIENT_CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "pop3_connected",
        "POP3 client connected to server",
        json!({"type": "placeholder", "event_id": "pop3_connected"}),
    )
    .with_parameters(vec![Parameter {
        name: "pop3_server".to_string(),
        type_hint: "string".to_string(),
        description: "POP3 server hostname".to_string(),
        required: true,
    }])
});

/// Event: POP3 response received from server
pub static POP3_CLIENT_RESPONSE_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "pop3_response_received",
        "POP3 response received from server",
        json!({
            "type": "send_pop3_command",
            "command": "USER alice"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "response".to_string(),
            type_hint: "string".to_string(),
            description: "POP3 server response (e.g., '+OK' or '-ERR')".to_string(),
            required: true,
        },
        Parameter {
            name: "is_ok".to_string(),
            type_hint: "boolean".to_string(),
            description: "Whether response is +OK (true) or -ERR (false)".to_string(),
            required: true,
        },
    ])
});

pub struct Pop3ClientProtocol;

impl Default for Pop3ClientProtocol {
    fn default() -> Self {
        Self::new()
    }
}

impl Pop3ClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for Pop3ClientProtocol {
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![ParameterDefinition {
            name: "use_tls".to_string(),
            description: "Must be false. This client speaks POP3 over a plain TCP socket and implements no TLS, so `use_tls: true` is REFUSED at connect with an error rather than silently producing a cleartext session carrying the USER/PASS exchange. Terminate TLS in front of the server instead."
                .to_string(),
            type_hint: "boolean".to_string(),
            required: false,
            example: json!(false),
            default: None,
        }]
    }

    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        // `modify_pop3_instruction` used to be advertised here and was unrunnable: this
        // protocol's `execute_action` rejects the name ("Unknown POP3 client action"), and no
        // generic client-side instruction plumbing exists — a client reads `instruction` once
        // at connect and never re-reads it. Advertising it only cost the model a retry.
        vec![ActionDefinition {
            name: "disconnect".to_string(),
            description: "Disconnect from POP3 server".to_string(),
            parameters: vec![],
            example: json!({
                "type": "disconnect"
            }),
            log_template: None,
        }]
    }

    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            ActionDefinition {
                name: "send_pop3_command".to_string(),
                description: "Send a POP3 command to the server".to_string(),
                parameters: vec![Parameter {
                    name: "command".to_string(),
                    type_hint: "string".to_string(),
                    description:
                        "POP3 command to send (e.g., 'USER alice', 'PASS secret', 'STAT', 'LIST', 'RETR 1', 'QUIT')"
                            .to_string(),
                    required: true,
                }],
                example: json!({
                    "type": "send_pop3_command",
                    "command": "USER alice"
                }),
            log_template: None,
            },
            ActionDefinition {
                name: "disconnect".to_string(),
                description: "Disconnect from POP3 server".to_string(),
                parameters: vec![],
                example: json!({
                    "type": "disconnect"
                }),
            log_template: None,
            },
            ActionDefinition {
                name: "wait_for_more".to_string(),
                description: "Wait for more data from server".to_string(),
                parameters: vec![],
                example: json!({
                    "type": "wait_for_more"
                }),
            log_template: None,
            },
        ]
    }

    fn protocol_name(&self) -> &'static str {
        "POP3"
    }

    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            EventType::new(
                "pop3_connected",
                "Triggered when POP3 client connects to server",
                json!({"type": "placeholder", "event_id": "pop3_connected"}),
            ),
            EventType::new(
                "pop3_response_received",
                "Triggered when POP3 client receives a response from server",
                json!({"type": "placeholder", "event_id": "pop3_response_received"}),
            ),
        ]
    }

    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>POP3"
    }

    fn keywords(&self) -> Vec<&'static str> {
        vec!["pop3", "pop3 client", "connect to pop3", "pop3s"]
    }

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .implementation(
                "Custom TCP/TLS client using tokio and rustls for POP3/POP3S email retrieval",
            )
            .llm_control("Full control over POP3 commands (USER, PASS, STAT, LIST, RETR, DELE)")
            .e2e_testing("NetGet POP3 server or local Dovecot server")
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }

    fn description(&self) -> &'static str {
        "POP3/POP3S client for retrieving email from mailboxes"
    }

    fn example_prompt(&self) -> &'static str {
        "Connect to pop.gmail.com:995 with TLS and authenticate as user@example.com"
    }

    fn group_name(&self) -> &'static str {
        "Application"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        use serde_json::json;

        StartupExamples::new(
            // LLM mode: LLM controls POP3 operations
            json!({
                "type": "open_client",
                "remote_addr": "pop.example.com:995",
                "base_stack": "pop3",
                "instruction": "Authenticate with USER alice and PASS secret, then retrieve all messages"
            }),
            // Script mode: Code-based deterministic responses
            json!({
                "type": "open_client",
                "remote_addr": "pop.example.com:995",
                "base_stack": "pop3",
                "event_handlers": [{
                    "event_pattern": "pop3_response_received",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "<pop3_client_handler>"
                    }
                }]
            }),
            // Static mode: Fixed POP3 authentication on connect
            json!({
                "type": "open_client",
                "remote_addr": "pop.example.com:995",
                "base_stack": "pop3",
                "event_handlers": [
                    {
                        "event_pattern": "pop3_connected",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "send_pop3_command",
                                "command": "USER alice"
                            }]
                        }
                    },
                    {
                        "event_pattern": "pop3_response_received",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "wait_for_more"
                            }]
                        }
                    }
                ]
            }),
        )
    }
}

// Implement Client trait (client-specific functionality)
impl Client for Pop3ClientProtocol {
    fn connect(
        &self,
        ctx: crate::protocol::ConnectContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            crate::client::pop3::Pop3Client::connect_with_llm_actions(
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
            "send_pop3_command" => {
                let command = action
                    .get("command")
                    .and_then(|v| v.as_str())
                    .context("Missing 'command' parameter")?
                    .to_string();

                Ok(ClientActionResult::Custom {
                    name: "pop3_command".to_string(),
                    data: json!({ "command": command }),
                })
            }
            "disconnect" => Ok(ClientActionResult::Disconnect),
            "wait_for_more" => Ok(ClientActionResult::WaitForMore),
            _ => Err(anyhow::anyhow!(
                "Unknown POP3 client action: {}",
                action_type
            )),
        }
    }
}

//! SMTP client protocol actions implementation

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

/// SMTP client connected event
pub static SMTP_CLIENT_CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "smtp_connected",
        "SMTP client connected to server and ready to send emails",
        json!({
            "type": "send_email",
            "from": "sender@example.com",
            "to": ["recipient@example.com"],
            "subject": "Follow-up Email",
            "body": "This is a follow-up email."
        }),
    )
    .with_parameters(vec![Parameter {
        name: "smtp_server".to_string(),
        type_hint: "string".to_string(),
        description: "SMTP server hostname".to_string(),
        required: true,
    }])
});

/// SMTP email sent event
pub static SMTP_CLIENT_EMAIL_SENT_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "smtp_email_sent",
        "Email successfully sent via SMTP",
        json!({"type": "placeholder", "event_id": "smtp_email_sent"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "to".to_string(),
            type_hint: "array".to_string(),
            description: "Recipient email addresses".to_string(),
            required: true,
        },
        Parameter {
            name: "subject".to_string(),
            type_hint: "string".to_string(),
            description: "Email subject".to_string(),
            required: true,
        },
        Parameter {
            name: "success".to_string(),
            type_hint: "boolean".to_string(),
            description: "Whether email was sent successfully".to_string(),
            required: true,
        },
    ])
});

/// SMTP client protocol action handler
#[derive(Default)]
pub struct SmtpClientProtocol;

impl SmtpClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for SmtpClientProtocol {
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "username".to_string(),
                description: "SMTP authentication username (optional)".to_string(),
                type_hint: "string".to_string(),
                required: false,
                example: json!("user@example.com"),
                default: None,
            },
            ParameterDefinition {
                name: "password".to_string(),
                description: "SMTP authentication password (optional)".to_string(),
                type_hint: "string".to_string(),
                required: false,
                example: json!("secret123"),
                default: None,
            },
            ParameterDefinition {
                name: "use_tls".to_string(),
                description: "Use STARTTLS for secure connection (default: true)".to_string(),
                type_hint: "boolean".to_string(),
                required: false,
                example: json!(true),
                default: None,
            },
        ]
    }
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![
            ActionDefinition {
                name: "send_email".to_string(),
                description: "Send an email via SMTP".to_string(),
                parameters: vec![
                    Parameter {
                        name: "from".to_string(),
                        type_hint: "string".to_string(),
                        description: "Sender email address".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "to".to_string(),
                        type_hint: "array".to_string(),
                        description: "Recipient email addresses".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "subject".to_string(),
                        type_hint: "string".to_string(),
                        description: "Email subject".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "body".to_string(),
                        type_hint: "string".to_string(),
                        description: "Email body (plain text)".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "username".to_string(),
                        type_hint: "string".to_string(),
                        description: "SMTP authentication username (optional)".to_string(),
                        required: false,
                    },
                    Parameter {
                        name: "password".to_string(),
                        type_hint: "string".to_string(),
                        description: "SMTP authentication password (optional)".to_string(),
                        required: false,
                    },
                    Parameter {
                        name: "use_tls".to_string(),
                        type_hint: "boolean".to_string(),
                        description: "Use STARTTLS (default: true)".to_string(),
                        required: false,
                    },
                ],
                example: json!({
                    "type": "send_email",
                    "from": "sender@example.com",
                    "to": ["recipient@example.com"],
                    "subject": "Test Email",
                    "body": "Hello, this is a test email from NetGet SMTP client.",
                    "use_tls": true
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "disconnect".to_string(),
                description: "Disconnect from the SMTP server".to_string(),
                parameters: vec![],
                example: json!({
                    "type": "disconnect"
                }),
                log_template: None,
            },
        ]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![ActionDefinition {
            name: "send_email".to_string(),
            description: "Send another email in response to previous operation".to_string(),
            parameters: vec![
                Parameter {
                    name: "from".to_string(),
                    type_hint: "string".to_string(),
                    description: "Sender email address".to_string(),
                    required: true,
                },
                Parameter {
                    name: "to".to_string(),
                    type_hint: "array".to_string(),
                    description: "Recipient email addresses".to_string(),
                    required: true,
                },
                Parameter {
                    name: "subject".to_string(),
                    type_hint: "string".to_string(),
                    description: "Email subject".to_string(),
                    required: true,
                },
                Parameter {
                    name: "body".to_string(),
                    type_hint: "string".to_string(),
                    description: "Email body".to_string(),
                    required: true,
                },
            ],
            example: json!({
                "type": "send_email",
                "from": "sender@example.com",
                "to": ["recipient@example.com"],
                "subject": "Follow-up Email",
                "body": "This is a follow-up email."
            }),
            log_template: None,
        }]
    }
    fn protocol_name(&self) -> &'static str {
        "SMTP"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            EventType::new(
                "smtp_connected",
                "Triggered when SMTP client connects to server",
                json!({"type": "placeholder", "event_id": "smtp_connected"}),
            ),
            EventType::new(
                "smtp_email_sent",
                "Triggered when email is successfully sent",
                json!({"type": "placeholder", "event_id": "smtp_email_sent"}),
            ),
        ]
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>SMTP"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["smtp", "smtp client", "email", "send email", "mail"]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .implementation("lettre library with STARTTLS support")
            .llm_control("Full control over email composition (from, to, subject, body, auth)")
            .e2e_testing("Local SMTP server or test mail service")
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "SMTP client for sending emails"
    }
    fn example_prompt(&self) -> &'static str {
        "Connect to SMTP server at smtp.example.com:587 and send an email to user@example.com"
    }
    fn group_name(&self) -> &'static str {
        "Email"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        use serde_json::json;

        StartupExamples::new(
            // LLM mode: LLM controls email sending
            json!({
                "type": "open_client",
                "remote_addr": "smtp.example.com:587",
                "base_stack": "smtp",
                "instruction": "Send a test email to user@example.com with subject 'Hello' and body 'Test message'"
            }),
            // Script mode: Code-based deterministic responses
            json!({
                "type": "open_client",
                "remote_addr": "smtp.example.com:587",
                "base_stack": "smtp",
                "event_handlers": [{
                    "event_pattern": "smtp_email_sent",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "<smtp_client_handler>"
                    }
                }]
            }),
            // Static mode: Fixed email send on connect
            json!({
                "type": "open_client",
                "remote_addr": "smtp.example.com:587",
                "base_stack": "smtp",
                "event_handlers": [
                    {
                        "event_pattern": "smtp_connected",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "send_email",
                                "from": "sender@example.com",
                                "to": ["recipient@example.com"],
                                "subject": "Test Email",
                                "body": "Hello from NetGet SMTP client."
                            }]
                        }
                    },
                    {
                        "event_pattern": "smtp_email_sent",
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
impl Client for SmtpClientProtocol {
    fn connect(
        &self,
        ctx: crate::protocol::ConnectContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::client::smtp::SmtpClient;
            SmtpClient::connect_with_llm_actions(
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
            "send_email" => {
                let from = action
                    .get("from")
                    .and_then(|v| v.as_str())
                    .context("Missing 'from' field")?
                    .to_string();

                let to = action
                    .get("to")
                    .and_then(|v| v.as_array())
                    .context("Missing 'to' field or not an array")?
                    .iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect::<Vec<_>>();

                if to.is_empty() {
                    return Err(anyhow::anyhow!(
                        "'to' field must contain at least one email address"
                    ));
                }

                let subject = action
                    .get("subject")
                    .and_then(|v| v.as_str())
                    .context("Missing 'subject' field")?
                    .to_string();

                let body = action
                    .get("body")
                    .and_then(|v| v.as_str())
                    .context("Missing 'body' field")?
                    .to_string();

                let username = action
                    .get("username")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());

                let password = action
                    .get("password")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());

                // Deliberately `Option`, not `unwrap_or(true)`. Defaulting here made "the
                // action omitted use_tls" indistinguishable from "the action asked for TLS",
                // so the declared `use_tls` startup parameter could never apply to a message
                // the model did not explicitly mark. The default now lives in one place, at
                // the point of delivery.
                let use_tls = action.get("use_tls").and_then(|v| v.as_bool());

                // Return custom result with email data
                Ok(ClientActionResult::Custom {
                    name: "smtp_send_email".to_string(),
                    data: json!({
                        "from": from,
                        "to": to,
                        "subject": subject,
                        "body": body,
                        "username": username,
                        "password": password,
                        "use_tls": use_tls,
                    }),
                })
            }
            "disconnect" => Ok(ClientActionResult::Disconnect),
            _ => Err(anyhow::anyhow!(
                "Unknown SMTP client action: {}",
                action_type
            )),
        }
    }
}

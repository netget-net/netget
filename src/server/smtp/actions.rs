//! SMTP protocol actions implementation

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
use tracing::debug;

/// SMTP protocol action handler
pub struct SmtpProtocol;

impl SmtpProtocol {
    pub fn new() -> Self {
        Self
    }

    fn execute_send_smtp_greeting(&self, action: serde_json::Value) -> Result<ActionResult> {
        let hostname = action
            .get("hostname")
            .and_then(|v| v.as_str())
            .unwrap_or("localhost");

        let message = action
            .get("message")
            .and_then(|v| v.as_str())
            .unwrap_or("ESMTP Service Ready");

        let response = format!("220 {} {}\r\n", hostname, message);

        debug!("SMTP sending greeting: {}", response.trim());
        Ok(ActionResult::Output(response.as_bytes().to_vec()))
    }

    fn execute_send_smtp_ok(&self, action: serde_json::Value) -> Result<ActionResult> {
        let message = action
            .get("message")
            .and_then(|v| v.as_str())
            .unwrap_or("OK");

        let response = format!("250 {}\r\n", message);

        debug!("SMTP sending OK: {}", message);
        Ok(ActionResult::Output(response.as_bytes().to_vec()))
    }

    fn execute_send_smtp_start_data(&self, _action: serde_json::Value) -> Result<ActionResult> {
        let response = "354 Start mail input; end with <CRLF>.<CRLF>\r\n";

        debug!("SMTP sending start data");
        Ok(ActionResult::Output(response.as_bytes().to_vec()))
    }

    fn execute_send_smtp_error(&self, action: serde_json::Value) -> Result<ActionResult> {
        let code = action.get("code").and_then(|v| v.as_u64()).unwrap_or(500);

        let message = action
            .get("message")
            .and_then(|v| v.as_str())
            .context("Missing 'message' parameter")?;

        let response = format!("{} {}\r\n", code, message);

        debug!("SMTP sending error {}: {}", code, message);
        Ok(ActionResult::Output(response.as_bytes().to_vec()))
    }

    fn execute_send_smtp_quit(&self, action: serde_json::Value) -> Result<ActionResult> {
        let hostname = action
            .get("hostname")
            .and_then(|v| v.as_str())
            .unwrap_or("localhost");

        let response = format!("221 {} closing connection\r\n", hostname);

        debug!("SMTP sending QUIT response");
        Ok(ActionResult::Output(response.as_bytes().to_vec()))
    }

    fn execute_send_smtp_message(&self, action: serde_json::Value) -> Result<ActionResult> {
        let message = action
            .get("message")
            .and_then(|v| v.as_str())
            .context("Missing 'message' parameter")?;

        // Ensure message ends with \r\n
        let formatted = if message.ends_with("\r\n") {
            message.to_string()
        } else if message.ends_with('\n') {
            format!("{}\r", message.trim_end_matches('\n'))
        } else {
            format!("{}\r\n", message)
        };

        debug!("SMTP sending custom message: {}", formatted.trim());
        Ok(ActionResult::Output(formatted.as_bytes().to_vec()))
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for SmtpProtocol {
    fn get_startup_parameters(&self) -> Vec<crate::llm::actions::ParameterDefinition> {
        use crate::llm::actions::ParameterDefinition;
        vec![
                ParameterDefinition {
                    name: "enable_tls".to_string(),
                    type_hint: "boolean".to_string(),
                    description: "Enable SMTPS (implicit TLS) mode (default: false)".to_string(),
                    required: false,
                    example: json!(true),
                    default: None,
                },
                ParameterDefinition {
                    name: "tls_common_name".to_string(),
                    type_hint: "string".to_string(),
                    description: "TLS certificate Common Name (CN) (default: 'netget-smtp-server')".to_string(),
                    required: false,
                    example: json!("mail.example.com"),
                    default: None,
                },
                ParameterDefinition {
                    name: "tls_san_dns_names".to_string(),
                    type_hint: "array".to_string(),
                    description: "TLS certificate Subject Alternative Names (DNS names) (default: ['localhost', '*.local'])".to_string(),
                    required: false,
                    example: json!(["mail.example.com", "localhost", "*.example.com"]),
                    default: None,
                },
                ParameterDefinition {
                    name: "tls_validity_days".to_string(),
                    type_hint: "integer".to_string(),
                    description: "TLS certificate validity period in days (default: 365)".to_string(),
                    required: false,
                    example: json!(365),
                    default: None,
                },
                ParameterDefinition {
                    name: "tls_organization".to_string(),
                    type_hint: "string".to_string(),
                    description: "TLS certificate Organization (O) (default: 'NetGet')".to_string(),
                    required: false,
                    example: json!("Example Corp"),
                    default: None,
                },
                ParameterDefinition {
                    name: "tls_organizational_unit".to_string(),
                    type_hint: "string".to_string(),
                    description: "TLS certificate Organizational Unit (OU) (default: 'SMTP Server')".to_string(),
                    required: false,
                    example: json!("IT Department"),
                    default: None,
                },
            ]
    }
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        // SMTP doesn't need async actions for now
        Vec::new()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            send_smtp_greeting_action(),
            send_smtp_ok_action(),
            send_smtp_start_data_action(),
            send_smtp_error_action(),
            send_smtp_quit_action(),
            send_smtp_message_action(),
            wait_for_more_action(),
            close_connection_action(),
        ]
    }
    fn protocol_name(&self) -> &'static str {
        "SMTP"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        get_smtp_event_types()
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>SMTP"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["smtp", "mail", "email"]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{
            DevelopmentState, PrivilegeRequirement, ProtocolMetadataV2,
        };

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .implementation(
                "Manual line-based parsing with tokio, optional implicit TLS via rustls",
            )
            .llm_control("All SMTP commands + responses")
            .e2e_testing("Raw TCP client driving the SMTP command sequence")
            .privilege_requirement(PrivilegeRequirement::PrivilegedPort(25))
            .well_known_port(25)
            .notes(
                "Accepts mail but stores nothing - the model answers every command. No AUTH, no \
                 STARTTLS, no PIPELINING. Every DATA body line costs one model call unless an \
                 event handler is configured.",
            )
            .max_inbound_bytes(crate::server::smtp::MAX_LINE_BYTES)
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "SMTP/SMTPS mail server"
    }
    fn example_prompt(&self) -> &'static str {
        "Start an SMTP mail server on port 25 (or 'Start an SMTPS mail server on port 465 with TLS enabled')"
    }
    fn group_name(&self) -> &'static str {
        "Application"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        // Deterministic SMTP state machine: standard replies for each command
        // verb. Reads the event from stdin and switches on event_type_id. EHLO and
        // HELO never reach a handler: NetGet answers them itself.
        let script = r#"import json, sys
data = json.load(sys.stdin)
event = data["event"]
if data["event_type_id"] == "smtp_command":
    cmd = event.get("command", "").upper()
    if cmd == "CONNECTION_ESTABLISHED":
        actions = [{"type": "send_smtp_greeting", "hostname": "mail.example.com"}]
    elif cmd.startswith("MAIL FROM"):
        actions = [{"type": "send_smtp_ok", "message": "Sender OK"}]
    elif cmd.startswith("RCPT TO"):
        actions = [{"type": "send_smtp_ok", "message": "Recipient OK"}]
    elif cmd == "DATA":
        actions = [{"type": "send_smtp_start_data"}]
    elif cmd == "QUIT":
        actions = [{"type": "send_smtp_quit"}]
    else:
        actions = [{"type": "send_smtp_ok"}]
else:
    actions = []
print(json.dumps({"actions": actions}))"#;

        StartupExamples::new(
            // LLM mode: policy decisions per recipient — real reasoning.
            json!({
                "type": "open_server",
                "port": 25,
                "base_stack": "smtp",
                "instruction": "Act as the SMTP server for example.com: complete the SMTP handshake, accept mail only for recipients @example.com and reject any other recipient with a 550 error, and note the subject line of each accepted message."
            }),
            // Script mode: standard SMTP flow with fixed replies, no LLM call.
            json!({
                "type": "open_server",
                "port": 25,
                "base_stack": "smtp",
                "event_handlers": [{
                    "event_pattern": "smtp_command",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": script
                    }
                }]
            }),
            // Static handler example
            json!({
                "type": "open_server",
                "port": 25,
                "base_stack": "smtp",
                "event_handlers": [{
                    "event_pattern": "smtp_command",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "send_smtp_ok",
                            "message": "OK"
                        }]
                    }
                }]
            }),
        )
    }
}

// Implement Server trait (server-specific functionality)
impl Server for SmtpProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::server::smtp::SmtpServer;

            // Check if TLS should be enabled via startup parameters
            let tls_config = if let Some(ref params) = ctx.startup_params {
                if params.get_optional_bool("enable_tls")?.unwrap_or(false) {
                    // Generate TLS configuration
                    let common_name = params.get_optional_string("tls_common_name")?;
                    let san_dns_names =
                        params.get_optional_array("tls_san_dns_names")?.map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_str())
                                .map(|s| s.to_string())
                                .collect::<Vec<_>>()
                        });
                    let validity_days = params.get_optional_i64("tls_validity_days")?;
                    let organization = params.get_optional_string("tls_organization")?;
                    let organizational_unit =
                        params.get_optional_string("tls_organizational_unit")?;

                    // Fail the spawn rather than falling back to plain text. Logging the error
                    // and returning None handed a caller who explicitly asked for SMTPS a
                    // cleartext mail port that reported itself as Running.
                    Some(
                        crate::server::tls_cert_manager::generate_custom_tls_config(
                            common_name,
                            san_dns_names,
                            validity_days,
                            organization,
                            organizational_unit,
                        )
                        .context("enable_tls was requested but the SMTPS certificate could not be generated")?,
                    )
                } else {
                    None
                }
            } else {
                None
            };

            SmtpServer::spawn_with_llm_actions(
                ctx.legacy_listen_addr(),
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.server_id,
                tls_config,
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
            "send_smtp_greeting" => self.execute_send_smtp_greeting(action),
            "send_smtp_ok" => self.execute_send_smtp_ok(action),
            "send_smtp_start_data" => self.execute_send_smtp_start_data(action),
            "send_smtp_error" => self.execute_send_smtp_error(action),
            "send_smtp_quit" => self.execute_send_smtp_quit(action),
            "send_smtp_message" => self.execute_send_smtp_message(action),
            "wait_for_more" => Ok(ActionResult::WaitForMore),
            "close_connection" => Ok(ActionResult::CloseConnection),
            _ => Err(anyhow::anyhow!("Unknown SMTP action: {}", action_type)),
        }
    }
}

// Action definitions

fn send_smtp_greeting_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_smtp_greeting".to_string(),
        description: "The 220 banner, sent once when a client connects (the \
                      CONNECTION_ESTABLISHED event) and never in answer to a command. The \
                      line is '220 <hostname> <message>'. When your instruction names a \
                      banner, that text goes in message, word for word."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "hostname".to_string(),
                type_hint: "string".to_string(),
                description: "Server hostname (default: localhost)".to_string(),
                required: false,
            },
            Parameter {
                name: "message".to_string(),
                type_hint: "string".to_string(),
                description: "Banner text after the hostname: the banner your instruction \
                              gives, verbatim (default: 'ESMTP Service Ready')"
                    .to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_smtp_greeting",
            "hostname": "mx.example.invalid",
            "message": "ESMTP"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> SMTP 220 {hostname}")
                .with_debug("SMTP send_smtp_greeting: {hostname}"),
        ),
    }
}

fn send_smtp_ok_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_smtp_ok".to_string(),
        description: "A 250 reply: accepts a MAIL FROM sender, a RCPT TO recipient, the \
                      end of a message ('.'), RSET or NOOP. Never the answer to \
                      CONNECTION_ESTABLISHED - that is send_smtp_greeting."
            .to_string(),
        parameters: vec![Parameter {
            name: "message".to_string(),
            type_hint: "string".to_string(),
            description: "OK message (default: 'OK')".to_string(),
            required: false,
        }],
        example: json!({
            "type": "send_smtp_ok",
            "message": "Requested mail action okay, completed"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> SMTP 250 {message}")
                .with_debug("SMTP send_smtp_ok: {message}"),
        ),
    }
}

fn send_smtp_start_data_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_smtp_start_data".to_string(),
        description: "Send SMTP start data response (354)".to_string(),
        parameters: vec![],
        example: json!({
            "type": "send_smtp_start_data"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> SMTP 354 Start data")
                .with_debug("SMTP send_smtp_start_data"),
        ),
    }
}

fn send_smtp_error_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_smtp_error".to_string(),
        description: "A 4xx/5xx refusal. 550 refuses a recipient (RCPT TO) or sender \
                      (MAIL FROM) the instruction does not accept; 500 is an unrecognised \
                      command."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "code".to_string(),
                type_hint: "number".to_string(),
                description: "SMTP error code (e.g., 550, 500) (default: 500)".to_string(),
                required: false,
            },
            Parameter {
                name: "message".to_string(),
                type_hint: "string".to_string(),
                description: "Error message".to_string(),
                required: true,
            },
        ],
        example: json!({
            "type": "send_smtp_error",
            "code": 550,
            "message": "Mailbox unavailable"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> SMTP {code} {message}")
                .with_debug("SMTP send_smtp_error: {code} {message}"),
        ),
    }
}

fn send_smtp_quit_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_smtp_quit".to_string(),
        description: "Send SMTP QUIT response (221) and prepare to close".to_string(),
        parameters: vec![Parameter {
            name: "hostname".to_string(),
            type_hint: "string".to_string(),
            description: "Server hostname (default: localhost)".to_string(),
            required: false,
        }],
        example: json!({
            "type": "send_smtp_quit",
            "hostname": "mail.example.com"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> SMTP 221 closing")
                .with_debug("SMTP send_smtp_quit: {hostname}"),
        ),
    }
}

fn send_smtp_message_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_smtp_message".to_string(),
        description: "Send a custom SMTP message (raw)".to_string(),
        parameters: vec![Parameter {
            name: "message".to_string(),
            type_hint: "string".to_string(),
            description: "SMTP message (will auto-add \\r\\n if not present)".to_string(),
            required: true,
        }],
        example: json!({
            "type": "send_smtp_message",
            "message": "250 2.1.0 Sender OK"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> SMTP {message}")
                .with_debug("SMTP send_smtp_message: {message}"),
        ),
    }
}

fn wait_for_more_action() -> ActionDefinition {
    ActionDefinition {
        name: "wait_for_more".to_string(),
        description: "Wait for more data before responding".to_string(),
        parameters: vec![],
        example: json!({
            "type": "wait_for_more"
        }),
        log_template: Some(LogTemplate::new().with_debug("SMTP waiting for more data")),
    }
}

fn close_connection_action() -> ActionDefinition {
    ActionDefinition {
        name: "close_connection".to_string(),
        description: "Close the SMTP connection".to_string(),
        parameters: vec![],
        example: json!({
            "type": "close_connection"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("SMTP connection closed")
                .with_debug("SMTP close_connection"),
        ),
    }
}

// ============================================================================
// SMTP Action Constants
// ============================================================================

pub static SEND_SMTP_GREETING_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(|| send_smtp_greeting_action());
pub static SEND_SMTP_OK_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(|| send_smtp_ok_action());
pub static SEND_SMTP_START_DATA_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(|| send_smtp_start_data_action());
pub static SEND_SMTP_ERROR_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(|| send_smtp_error_action());
pub static SEND_SMTP_QUIT_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(|| send_smtp_quit_action());
pub static SEND_SMTP_MESSAGE_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(|| send_smtp_message_action());
pub static WAIT_FOR_MORE_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(|| wait_for_more_action());
pub static CLOSE_CONNECTION_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(|| close_connection_action());

// ============================================================================
// SMTP Event Type Constants
// ============================================================================

/// SMTP command event - triggered when client sends an SMTP command
pub static SMTP_COMMAND_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "smtp_command",
        "SMTP command line received from client. The synthetic command \
         'CONNECTION_ESTABLISHED' is delivered once when a client connects and is answered \
         with send_smtp_greeting; no later command is. EHLO and HELO are answered by NetGet \
         and never reach you. Each command gets exactly one reply, and answer_with names the \
         action for this one. During DATA every line of the message body arrives as its own \
         event, ending with a line containing only '.'",
        json!({"type": "send_smtp_ok", "message": "2.1.0 Sender OK"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "command".to_string(),
            type_hint: "string".to_string(),
            description: "The SMTP command received (e.g. 'MAIL FROM:<sender@example.com>'), \
                          or 'CONNECTION_ESTABLISHED' on a new connection"
                .to_string(),
            required: true,
        },
        Parameter {
            name: "answer_with".to_string(),
            type_hint: "string".to_string(),
            description: "Which action answers this command, and with which reply code".to_string(),
            required: false,
        },
        Parameter {
            name: "address".to_string(),
            type_hint: "string".to_string(),
            description: "MAIL FROM / RCPT TO only: the mailbox inside the angle brackets"
                .to_string(),
            required: false,
        },
        Parameter {
            name: "domain".to_string(),
            type_hint: "string".to_string(),
            description: "MAIL FROM / RCPT TO only: the part of the address after '@'".to_string(),
            required: false,
        },
    ])
    .with_actions(vec![
        SEND_SMTP_GREETING_ACTION.clone(),
        SEND_SMTP_OK_ACTION.clone(),
        SEND_SMTP_START_DATA_ACTION.clone(),
        SEND_SMTP_ERROR_ACTION.clone(),
        SEND_SMTP_QUIT_ACTION.clone(),
        SEND_SMTP_MESSAGE_ACTION.clone(),
        WAIT_FOR_MORE_ACTION.clone(),
        CLOSE_CONNECTION_ACTION.clone(),
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("SMTP: {command}")
            .with_debug("SMTP command: {command}")
            .with_trace("SMTP: {json_pretty(.)}"),
    )
});

/// Get SMTP event types
pub fn get_smtp_event_types() -> Vec<EventType> {
    vec![SMTP_COMMAND_EVENT.clone()]
}

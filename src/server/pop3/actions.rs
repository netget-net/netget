use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter, ParameterDefinition,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::EventType;
use crate::state::app_state::AppState;
use anyhow::{Context, Result};
use serde_json::json;
use std::sync::LazyLock;
use tracing::debug;

/// Event: POP3 command received from client
///
/// This is the only event the POP3 server emits, so its action list must carry the protocol's
/// full response vocabulary: `call_llm` builds the model's tool list from
/// `event.event_type.actions`, never from [`Protocol::get_sync_actions`]. The list is taken
/// straight from `get_sync_actions()` so the two can never drift apart.
pub static POP3_COMMAND_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "pop3_command",
        "POP3 command received from client (USER, PASS, STAT, LIST, RETR, DELE, QUIT, etc.). \
         The literal command 'CONNECTION_ESTABLISHED' is sent once when a client connects and \
         must be answered with send_pop3_greeting. CAPA is answered by NetGet and never reaches \
         you. Each command gets exactly one reply, and answer_with names the action for this \
         one.",
        json!({"type": "send_pop3_ok", "message": "command processed"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "command".to_string(),
            type_hint: "string".to_string(),
            description:
                "The POP3 command line (e.g., 'USER alice', 'STAT', 'RETR 1'), or the synthetic \
                 'CONNECTION_ESTABLISHED' on a new connection"
                    .to_string(),
            required: true,
        },
        Parameter {
            name: "connection_id".to_string(),
            type_hint: "string".to_string(),
            description: "Unique connection identifier".to_string(),
            required: true,
        },
        Parameter {
            name: "answer_with".to_string(),
            type_hint: "string".to_string(),
            description: "Which action answers this command".to_string(),
            required: false,
        },
        Parameter {
            name: "message_number".to_string(),
            type_hint: "number".to_string(),
            description: "RETR, TOP, LIST, UIDL, DELE: the message the command names".to_string(),
            required: false,
        },
        Parameter {
            name: "lines".to_string(),
            type_hint: "number".to_string(),
            description: "TOP only: how many body lines to send".to_string(),
            required: false,
        },
    ])
    .with_actions(Pop3Protocol::new().get_sync_actions())
    .with_log_template(
        LogTemplate::new()
            .with_info("POP3 command: {command}")
            .with_debug("POP3 {command} on {connection_id}")
            .with_trace("POP3: {json_pretty(.)}"),
    )
});

/// The message a `send_pop3_retr` carries, as text: `content` verbatim when the model wrote
/// the whole message, otherwise built from the structured fields.
///
/// The structured form exists because a small model asked for "the message whose subject is
/// X" writes `"subject": "X"` far more reliably than it writes RFC 5322 header syntax inside
/// one string. NetGet writes the header lines (`From`, `To`, `Subject`, `Date`, in that order,
/// each only when given), the blank line, and the body.
fn pop3_message_text(action: &serde_json::Value) -> Result<String> {
    if let Some(content) = action.get("content").and_then(|v| v.as_str()) {
        return Ok(content.to_string());
    }
    let field = |name: &str| action.get(name).and_then(|v| v.as_str());
    let mut text = String::new();
    for (header, name) in [
        ("From", "from"),
        ("To", "to"),
        ("Subject", "subject"),
        ("Date", "date"),
    ] {
        if let Some(value) = field(name) {
            // A header value is one line; a newline in it would start a forged header.
            let value = value.replace(['\r', '\n'], " ");
            text.push_str(&format!("{header}: {value}\n"));
        }
    }
    let body = field("body");
    if text.is_empty() && body.is_none() {
        anyhow::bail!(
            "send_pop3_retr needs the message: either 'content' (headers, a blank line, the \
             body) or the fields from, to, subject and body"
        );
    }
    text.push('\n');
    text.push_str(body.unwrap_or(""));
    Ok(text)
}

/// Prepare LLM-supplied message text for a POP3 multi-line response body.
///
/// Two things the model cannot be expected to get right, and which break real clients when
/// they are wrong (RFC 1939 §3, "Responses to certain commands are multi-line"):
///
/// 1. **Byte-stuffing.** A body line beginning with `.` would otherwise be read as the
///    response terminator, truncating the message. Such lines get a second leading `.`,
///    which the client strips.
/// 2. **Line endings.** Bare `\n` is normalised to `\r\n`, and the body is terminated with
///    `\r\n` so the following `.\r\n` starts on its own line.
///
/// The result always ends with `\r\n` (or is empty), so callers can append `.\r\n` directly.
pub fn format_pop3_multiline_body(content: &str) -> String {
    if content.is_empty() {
        return String::new();
    }

    let mut out = String::with_capacity(content.len() + 16);
    for line in content.replace("\r\n", "\n").split('\n') {
        if line.starts_with('.') {
            out.push('.');
        }
        out.push_str(line);
        out.push_str("\r\n");
    }

    // `split` yields a trailing empty field when the content already ended in a newline;
    // that produced one spurious blank line, so drop it.
    if content.ends_with('\n') {
        out.truncate(out.len() - 2);
    }

    out
}

pub struct Pop3Protocol;

impl Pop3Protocol {
    pub fn new() -> Self {
        Self
    }

    fn execute_send_pop3_greeting(&self, action: serde_json::Value) -> Result<ActionResult> {
        let message = action
            .get("message")
            .and_then(|v| v.as_str())
            .unwrap_or("POP3 server ready");

        let response = format!("+OK {}\r\n", message);

        debug!("POP3 sending greeting: {}", response.trim());
        Ok(ActionResult::Output(response.as_bytes().to_vec()))
    }

    fn execute_send_pop3_ok(&self, action: serde_json::Value) -> Result<ActionResult> {
        let message = action.get("message").and_then(|v| v.as_str()).unwrap_or("");

        let response = if message.is_empty() {
            "+OK\r\n".to_string()
        } else {
            format!("+OK {}\r\n", message)
        };

        debug!("POP3 sending +OK: {}", message);
        Ok(ActionResult::Output(response.as_bytes().to_vec()))
    }

    fn execute_send_pop3_err(&self, action: serde_json::Value) -> Result<ActionResult> {
        let message = action
            .get("message")
            .and_then(|v| v.as_str())
            .context("Missing 'message' parameter")?;

        let response = format!("-ERR {}\r\n", message);

        debug!("POP3 sending -ERR: {}", message);
        Ok(ActionResult::Output(response.as_bytes().to_vec()))
    }

    fn execute_send_pop3_stat(&self, action: serde_json::Value) -> Result<ActionResult> {
        let message_count = action
            .get("message_count")
            .and_then(|v| v.as_u64())
            .context("Missing 'message_count' parameter")?;

        let total_size = action
            .get("total_size")
            .and_then(|v| v.as_u64())
            .context("Missing 'total_size' parameter")?;

        let response = format!("+OK {} {}\r\n", message_count, total_size);

        debug!(
            "POP3 sending STAT: {} messages, {} bytes",
            message_count, total_size
        );
        Ok(ActionResult::Output(response.as_bytes().to_vec()))
    }

    fn execute_send_pop3_list(&self, action: serde_json::Value) -> Result<ActionResult> {
        let messages = action
            .get("messages")
            .and_then(|v| v.as_array())
            .context("Missing 'messages' parameter")?;

        let mut response = format!("+OK {} messages\r\n", messages.len());
        for msg in messages {
            let id = msg.get("id").and_then(|v| v.as_u64()).unwrap_or(0);
            let size = msg.get("size").and_then(|v| v.as_u64()).unwrap_or(0);
            response.push_str(&format!("{} {}\r\n", id, size));
        }
        response.push_str(".\r\n");

        debug!("POP3 sending LIST with {} messages", messages.len());
        Ok(ActionResult::Output(response.as_bytes().to_vec()))
    }

    fn execute_send_pop3_uidl(&self, action: serde_json::Value) -> Result<ActionResult> {
        let messages = action
            .get("messages")
            .and_then(|v| v.as_array())
            .context("Missing 'messages' parameter")?;

        let mut response = format!("+OK {} messages\r\n", messages.len());
        for msg in messages {
            let id = msg.get("id").and_then(|v| v.as_u64()).unwrap_or(0);
            let uidl = msg.get("uidl").and_then(|v| v.as_str()).unwrap_or("");
            response.push_str(&format!("{} {}\r\n", id, uidl));
        }
        response.push_str(".\r\n");

        debug!("POP3 sending UIDL with {} messages", messages.len());
        Ok(ActionResult::Output(response.as_bytes().to_vec()))
    }

    fn execute_send_pop3_retr(&self, action: serde_json::Value) -> Result<ActionResult> {
        let content = pop3_message_text(&action)?;

        let body = format_pop3_multiline_body(&content);

        // RFC 1939 treats the octet count as informational (the terminating "." is what ends
        // the response), so an LLM-supplied `size` is honoured, but omitting it yields the
        // byte count actually written - which is what a client comparing the two expects.
        let size = action
            .get("size")
            .and_then(|v| v.as_u64())
            .unwrap_or_else(|| body.len() as u64);

        let response = format!("+OK {} octets\r\n{}.\r\n", size, body);

        debug!("POP3 sending RETR with {} octets", size);
        Ok(ActionResult::Output(response.into_bytes()))
    }

    fn execute_send_pop3_top(&self, action: serde_json::Value) -> Result<ActionResult> {
        let content = action
            .get("content")
            .and_then(|v| v.as_str())
            .context("Missing 'content' parameter")?;

        let response = format!("+OK\r\n{}.\r\n", format_pop3_multiline_body(content));

        debug!("POP3 sending TOP");
        Ok(ActionResult::Output(response.into_bytes()))
    }

    fn execute_send_pop3_message(&self, action: serde_json::Value) -> Result<ActionResult> {
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

        debug!("POP3 sending custom message: {}", formatted.trim());
        Ok(ActionResult::Output(formatted.as_bytes().to_vec()))
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for Pop3Protocol {
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        // No TLS parameters. Six (`enable_tls`, `tls_common_name`, `tls_san_dns_names`,
        // `tls_validity_days`, `tls_organization`, `tls_organizational_unit`) used to be
        // declared here while `spawn` hardcoded `tls_config = None`, so a caller asking for
        // POP3S got a plain-text listener and no warning. Declaring nothing makes
        // `enable_tls: true` fail loudly instead. See the note in `spawn`.
        //
        // The two below are the read deadlines. Their right value is a property of who is on
        // the other end, which only the operator knows.
        vec![
            ParameterDefinition {
                name: "first_byte_timeout_secs".to_string(),
                type_hint: "number".to_string(),
                description: "Seconds a connected peer may send no command at all - not even \
                              a CAPA or USER after the +OK greeting - before the server closes \
                              it. Default 300, matching the window a `manual` rule gives a \
                              human to answer one event. The peer is often NetGet's own POP3 \
                              client, which reads the greeting in its read loop and writes \
                              nothing until an action or [ send message ] says to. Lower it to \
                              60, Dovecot's `login_timeout`, for a listener exposed to \
                              strangers."
                    .to_string(),
                required: false,
                example: json!(300),
                default: Some(serde_json::json!(
                    super::FIRST_COMMAND_READ_TIMEOUT.as_secs()
                )),
            },
            ParameterDefinition {
                name: "idle_timeout_secs".to_string(),
                type_hint: "number".to_string(),
                description: "Seconds an established session may go without a further command \
                              before the server closes it. Default 600. RFC 1939 section 3 \
                              says this timer MUST be at least 10 minutes, so a value below \
                              600 puts the server outside the specification - it is accepted, \
                              but that is the trade you are making."
                    .to_string(),
                required: false,
                example: json!(600),
                default: Some(serde_json::json!(
                    super::IDLE_BETWEEN_COMMANDS_TIMEOUT.as_secs()
                )),
            },
        ]
    }

    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        // No user-triggered actions. A `close_pop3_connection` action used to be advertised
        // here, but `execute_action` had no arm for it, so every attempt to use it failed with
        // "Unknown POP3 action". Connections are closed from the command loop via the sync
        // `close_connection` action instead.
        Vec::new()
    }

    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            ActionDefinition {
                name: "send_pop3_ok".to_string(),
                description: "A single +OK line: accepts USER, PASS, DELE, NOOP, RSET, QUIT, or \
                              answers LIST/UIDL for one message. Never the answer to RETR, TOP, \
                              STAT or a whole-mailbox LIST - those have their own actions, and \
                              a bare +OK leaves the client waiting for data that never comes."
                    .to_string(),
                parameters: vec![Parameter {
                    name: "message".to_string(),
                    type_hint: "string".to_string(),
                    description: "Optional message after +OK".to_string(),
                    required: false,
                }],
                example: json!({
                    "type": "send_pop3_ok",
                    "message": "user accepted"
                }),
                log_template: Some(
                    LogTemplate::new()
                        .with_info("-> POP3 +OK {message}")
                        .with_debug("POP3 send_pop3_ok: message={message}"),
                ),
            },
            ActionDefinition {
                name: "send_pop3_err".to_string(),
                description: "Send POP3 -ERR response".to_string(),
                parameters: vec![Parameter {
                    name: "message".to_string(),
                    type_hint: "string".to_string(),
                    description: "Error message".to_string(),
                    required: true,
                }],
                example: json!({
                    "type": "send_pop3_err",
                    "message": "Invalid credentials"
                }),
                log_template: Some(
                    LogTemplate::new()
                        .with_info("-> POP3 -ERR {message}")
                        .with_debug("POP3 send_pop3_err: message={message}"),
                ),
            },
            ActionDefinition {
                name: "send_pop3_greeting".to_string(),
                description: "Send POP3 greeting banner (sent automatically on connect)"
                    .to_string(),
                parameters: vec![Parameter {
                    name: "message".to_string(),
                    type_hint: "string".to_string(),
                    description: "Greeting message (e.g., server name)".to_string(),
                    required: false,
                }],
                example: json!({
                    "type": "send_pop3_greeting",
                    "message": "POP3 server ready"
                }),
                log_template: Some(
                    LogTemplate::new()
                        .with_info("-> POP3 greeting: {message}")
                        .with_debug("POP3 send_pop3_greeting: message={message}"),
                ),
            },
            ActionDefinition {
                name: "send_pop3_stat".to_string(),
                description: "Send POP3 STAT response with message count and total size"
                    .to_string(),
                parameters: vec![
                    Parameter {
                        name: "message_count".to_string(),
                        type_hint: "number".to_string(),
                        description: "Number of messages in mailbox".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "total_size".to_string(),
                        type_hint: "number".to_string(),
                        description: "Total size of all messages in octets".to_string(),
                        required: true,
                    },
                ],
                example: json!({
                    "type": "send_pop3_stat",
                    "message_count": 3,
                    "total_size": 1024
                }),
                log_template: Some(
                    LogTemplate::new()
                        .with_info("-> POP3 STAT {message_count} {total_size}")
                        .with_debug(
                            "POP3 send_pop3_stat: {message_count} messages, {total_size} bytes",
                        ),
                ),
            },
            ActionDefinition {
                name: "send_pop3_list".to_string(),
                description: "Send POP3 LIST response with message sizes".to_string(),
                parameters: vec![Parameter {
                    name: "messages".to_string(),
                    type_hint: "array".to_string(),
                    description: "Array of message objects with 'id' and 'size' fields".to_string(),
                    required: true,
                }],
                example: json!({
                    "type": "send_pop3_list",
                    "messages": [{"id": 1, "size": 512}, {"id": 2, "size": 256}]
                }),
                log_template: Some(
                    LogTemplate::new()
                        .with_info("-> POP3 LIST {messages_len} messages")
                        .with_debug("POP3 send_pop3_list: {messages_len} messages"),
                ),
            },
            ActionDefinition {
                name: "send_pop3_uidl".to_string(),
                description: "Send POP3 UIDL response with unique message identifiers".to_string(),
                parameters: vec![Parameter {
                    name: "messages".to_string(),
                    type_hint: "array".to_string(),
                    description: "Array of message objects with 'id' and 'uidl' fields".to_string(),
                    required: true,
                }],
                example: json!({
                    "type": "send_pop3_uidl",
                    "messages": [{"id": 1, "uidl": "msg-abc123"}, {"id": 2, "uidl": "msg-def456"}]
                }),
                log_template: Some(
                    LogTemplate::new()
                        .with_info("-> POP3 UIDL {messages_len} messages")
                        .with_debug("POP3 send_pop3_uidl: {messages_len} messages"),
                ),
            },
            ActionDefinition {
                name: "send_pop3_retr".to_string(),
                description: "The answer to RETR: the whole message. Give it as from, to, \
                              subject and body and NetGet writes the header lines, or as \
                              content (headers, a blank line, the body). NetGet adds the octet \
                              count and the terminating '.' line, converts newlines to CRLF and \
                              byte-stuffs any line starting with '.'. The example's values are \
                              placeholders; send the message your instruction describes."
                    .to_string(),
                parameters: vec![
                    Parameter {
                        name: "from".to_string(),
                        type_hint: "string".to_string(),
                        description: "Sender address (the From header)".to_string(),
                        required: false,
                    },
                    Parameter {
                        name: "to".to_string(),
                        type_hint: "string".to_string(),
                        description: "Recipient address (the To header)".to_string(),
                        required: false,
                    },
                    Parameter {
                        name: "subject".to_string(),
                        type_hint: "string".to_string(),
                        description: "The Subject header, verbatim".to_string(),
                        required: false,
                    },
                    Parameter {
                        name: "date".to_string(),
                        type_hint: "string".to_string(),
                        description: "The Date header (optional)".to_string(),
                        required: false,
                    },
                    Parameter {
                        name: "body".to_string(),
                        type_hint: "string".to_string(),
                        description: "Message body text".to_string(),
                        required: false,
                    },
                    Parameter {
                        name: "content".to_string(),
                        type_hint: "string".to_string(),
                        description: "Instead of the fields above: the whole message as RFC \
                                      5322 text - headers, a blank line, then the body"
                            .to_string(),
                        required: false,
                    },
                    Parameter {
                        name: "size".to_string(),
                        type_hint: "number".to_string(),
                        description: "Octet count to advertise. Omit it and NetGet reports the \
                                      real byte length of what it sends."
                            .to_string(),
                        required: false,
                    },
                ],
                example: json!({
                    "type": "send_pop3_retr",
                    "from": "sender@example.invalid",
                    "to": "mailbox@example.invalid",
                    "subject": "Example subject",
                    "body": "Example body."
                }),
                log_template: Some(
                    LogTemplate::new()
                        .with_info("-> POP3 RETR {size}B")
                        .with_debug("POP3 send_pop3_retr: size={size} bytes"),
                ),
            },
            ActionDefinition {
                name: "send_pop3_top".to_string(),
                description: "Send POP3 TOP response: full headers plus the first N body lines \
                              the client asked for. NetGet adds the terminating '.' line and \
                              handles CRLF and byte-stuffing."
                    .to_string(),
                parameters: vec![Parameter {
                    name: "content".to_string(),
                    type_hint: "string".to_string(),
                    description: "Email headers, a blank line, then the requested body lines"
                        .to_string(),
                    required: true,
                }],
                example: json!({
                    "type": "send_pop3_top",
                    "content": "From: sender@example.com\nTo: recipient@example.com\nSubject: Test\n\nFirst line"
                }),
                log_template: Some(
                    LogTemplate::new()
                        .with_info("-> POP3 TOP")
                        .with_debug("POP3 send_pop3_top"),
                ),
            },
            ActionDefinition {
                name: "send_pop3_message".to_string(),
                description: "Send custom POP3 response".to_string(),
                parameters: vec![Parameter {
                    name: "message".to_string(),
                    type_hint: "string".to_string(),
                    description: "Full POP3 response line (including +OK or -ERR)".to_string(),
                    required: true,
                }],
                example: json!({
                    "type": "send_pop3_message",
                    "message": "+OK Custom response"
                }),
                log_template: Some(
                    LogTemplate::new()
                        .with_info("-> POP3: {preview(message,60)}")
                        .with_debug("POP3 send_pop3_message: {message}"),
                ),
            },
            ActionDefinition {
                name: "wait_for_more".to_string(),
                description: "Do not send any response, wait for more commands from client"
                    .to_string(),
                parameters: vec![],
                example: json!({
                    "type": "wait_for_more"
                }),
                log_template: Some(
                    LogTemplate::new()
                        .with_info("POP3 waiting for more data")
                        .with_debug("POP3 wait_for_more"),
                ),
            },
            ActionDefinition {
                name: "close_connection".to_string(),
                description: "Close the POP3 connection".to_string(),
                parameters: vec![],
                example: json!({
                    "type": "close_connection"
                }),
                log_template: Some(
                    LogTemplate::new()
                        .with_info("POP3 connection closed")
                        .with_debug("POP3 close_connection"),
                ),
            },
        ]
    }

    fn protocol_name(&self) -> &'static str {
        "POP3"
    }

    fn get_event_types(&self) -> Vec<EventType> {
        // Must be the same EventType the server actually emits. Building a second, ad-hoc one
        // here previously meant the documentation served to the model advertised no parameters,
        // no actions and a "placeholder" response example.
        vec![POP3_COMMAND_EVENT.clone()]
    }

    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>POP3"
    }

    fn keywords(&self) -> Vec<&'static str> {
        vec!["pop3", "pop3 server", "via pop3", "post office protocol"]
    }

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{
            DevelopmentState, PrivilegeRequirement, ProtocolMetadataV2,
        };

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .implementation(
                "Manual line-based TCP implementation with full LLM control over protocol responses",
            )
            .llm_control("Full control over POP3 responses (+OK, -ERR, STAT, LIST, RETR, etc.)")
            .e2e_testing("Manual TCP client with line-based protocol testing")
            .privilege_requirement(PrivilegeRequirement::PrivilegedPort(110))
            .well_known_port(110)
            .max_inbound_bytes(crate::server::pop3::MAX_COMMAND_BYTES)
            .notes(
                "No mailbox storage: the model answers STAT/LIST/RETR itself. Plain TCP only - \
                 neither POP3S nor STLS is available.",
            )
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }

    fn description(&self) -> &'static str {
        "POP3 email retrieval server (RFC 1939)"
    }

    fn example_prompt(&self) -> &'static str {
        "Listen on port 110 via POP3. Accept all authentication and return 3 test messages."
    }

    fn group_name(&self) -> &'static str {
        "Application"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        StartupExamples::new(
            // LLM-driven example
            json!({
                "type": "open_server",
                "port": 110,
                "base_stack": "pop3",
                "instruction": "POP3 server with 3 test messages, accept any credentials"
            }),
            // Script-based example
            json!({
                "type": "open_server",
                "port": 110,
                "base_stack": "pop3",
                "event_handlers": [{
                    "event_pattern": "pop3_command",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "# Handle POP3 commands\ncmd = event.get('command', '').upper()\nif cmd.startswith('USER'):\n    respond([{'type': 'send_pop3_ok', 'message': 'user accepted'}])\nelif cmd.startswith('PASS'):\n    respond([{'type': 'send_pop3_ok', 'message': 'logged in, 3 messages'}])\nelif cmd == 'STAT':\n    respond([{'type': 'send_pop3_stat', 'message_count': 3, 'total_size': 1024}])\nelif cmd == 'LIST':\n    respond([{'type': 'send_pop3_list', 'messages': [{'id': 1, 'size': 512}, {'id': 2, 'size': 256}, {'id': 3, 'size': 256}]}])\nelif cmd == 'QUIT':\n    respond([{'type': 'send_pop3_ok', 'message': 'bye'}])\nelse:\n    respond([{'type': 'send_pop3_ok'}])"
                    }
                }]
            }),
            // Static handler example
            json!({
                "type": "open_server",
                "port": 110,
                "base_stack": "pop3",
                "event_handlers": [{
                    "event_pattern": "pop3_command",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "send_pop3_ok",
                            "message": "OK"
                        }]
                    }
                }]
            }),
        )
    }
}

// Implement Server trait (server-specific functionality)
impl Server for Pop3Protocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::server::pop3::Pop3Server;

            // POP3S (implicit TLS) is not reachable yet. `Pop3Server` already implements the
            // whole TLS path and takes the config, but building one needs
            // `crate::server::tls_cert_manager`, which `src/server/mod.rs` gates on
            // `dot`/`doh`/`http`/`smtp`/`tls` and not on `pop3`. Adding `feature = "pop3"` to
            // that cfg list is all this needs; until then POP3 declares no TLS startup
            // parameters rather than accepting ones it silently drops.
            let tls_config = None;

            // Both read deadlines are the operator's to choose: who is on the other end is
            // the only thing that decides them, and only the operator knows that.
            let secs = |name: &str| -> anyhow::Result<Option<u64>> {
                Ok(ctx
                    .startup_params
                    .as_ref()
                    .map(|p| p.get_optional_u64(name))
                    .transpose()?
                    .flatten())
            };
            let first_byte_timeout_secs = secs("first_byte_timeout_secs")?;
            let idle_timeout_secs = secs("idle_timeout_secs")?;

            Pop3Server::spawn_with_llm_actions(
                ctx.legacy_listen_addr(),
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.server_id,
                tls_config,
                first_byte_timeout_secs,
                idle_timeout_secs,
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
            "send_pop3_greeting" => self.execute_send_pop3_greeting(action),
            "send_pop3_ok" => self.execute_send_pop3_ok(action),
            "send_pop3_err" => self.execute_send_pop3_err(action),
            "send_pop3_stat" => self.execute_send_pop3_stat(action),
            "send_pop3_list" => self.execute_send_pop3_list(action),
            "send_pop3_uidl" => self.execute_send_pop3_uidl(action),
            "send_pop3_retr" => self.execute_send_pop3_retr(action),
            "send_pop3_top" => self.execute_send_pop3_top(action),
            "send_pop3_message" => self.execute_send_pop3_message(action),
            "wait_for_more" => Ok(ActionResult::WaitForMore),
            "close_connection" => Ok(ActionResult::CloseConnection),
            _ => Err(anyhow::anyhow!("Unknown POP3 action: {}", action_type)),
        }
    }
}

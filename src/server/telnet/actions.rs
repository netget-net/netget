//! Telnet protocol actions implementation

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

/// Telnet protocol action handler
pub struct TelnetProtocol;

impl TelnetProtocol {
    pub fn new() -> Self {
        Self
    }

    fn execute_send_telnet_message(&self, action: serde_json::Value) -> Result<ActionResult> {
        let message = action
            .get("message")
            .and_then(|v| v.as_str())
            .context("Missing 'message' parameter")?;

        debug!("Telnet sending message: {}", message.trim());
        Ok(ActionResult::Output(message.as_bytes().to_vec()))
    }

    fn execute_send_telnet_line(&self, action: serde_json::Value) -> Result<ActionResult> {
        let line = action
            .get("line")
            .and_then(|v| v.as_str())
            .context("Missing 'line' parameter")?;

        // Ensure the line ends with exactly one CRLF.
        let formatted = if line.ends_with("\r\n") {
            line.to_string()
        } else if let Some(stripped) = line.strip_suffix('\n') {
            format!("{}\r\n", stripped)
        } else {
            format!("{}\r\n", line)
        };

        debug!("Telnet sending line: {}", formatted.trim());
        Ok(ActionResult::Output(formatted.as_bytes().to_vec()))
    }

    fn execute_send_telnet_prompt(&self, action: serde_json::Value) -> Result<ActionResult> {
        let prompt = action
            .get("prompt")
            .and_then(|v| v.as_str())
            .unwrap_or("> ");

        debug!("Telnet sending prompt: {:?}", prompt);
        Ok(ActionResult::Output(prompt.as_bytes().to_vec()))
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for TelnetProtocol {
    fn get_startup_parameters(&self) -> Vec<crate::llm::actions::ParameterDefinition> {
        vec![
                crate::llm::actions::ParameterDefinition {
                    name: "send_first".to_string(),
                    type_hint: "boolean".to_string(),
                    description: "The peer is owed a greeting: a telnet_connection_opened answer with nothing in it is logged as a missing banner, and a backend failure prints a notice line. telnet_connection_opened is raised for every connection either way, and nothing the client types is read until it has been answered".to_string(),
                    required: false,
                    example: serde_json::json!(true),
                    default: None,
                },
                crate::llm::actions::ParameterDefinition {
                    name: "first_byte_timeout_secs".to_string(),
                    type_hint: "number".to_string(),
                    description: "Seconds a connected peer may send no line at all before the \
                                  server closes it. Default 300, matching the window a \
                                  `manual` rule gives a human to answer one event - which is \
                                  the relevant number, because the other end of a telnet \
                                  session is usually a person, and NetGet's own telnet client \
                                  writes nothing until an action or [ send message ] says to. \
                                  Lower it (120 was the old value) for a listener exposed to \
                                  strangers."
                        .to_string(),
                    required: false,
                    example: serde_json::json!(300),
                    default: Some(serde_json::json!(super::FIRST_LINE_READ_TIMEOUT.as_secs())),
                },
                crate::llm::actions::ParameterDefinition {
                    name: "idle_timeout_secs".to_string(),
                    type_hint: "number".to_string(),
                    description: "Seconds an established session may go without a further line \
                                  before the server closes it. Default 600, which is Cisco \
                                  IOS's `exec-timeout 10 0` for vty lines - a person thinks, \
                                  reads output and types again, so this is on a human \
                                  timescale rather than a machine one."
                        .to_string(),
                    required: false,
                    example: serde_json::json!(600),
                    default: Some(serde_json::json!(super::IDLE_BETWEEN_LINES_TIMEOUT.as_secs())),
                },
            ]
    }
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        // Telnet doesn't need async actions for now
        Vec::new()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            send_telnet_message_action(),
            send_telnet_line_action(),
            send_telnet_prompt_action(),
            wait_for_more_action(),
            close_connection_action(),
        ]
    }
    fn protocol_name(&self) -> &'static str {
        "Telnet"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        get_telnet_event_types()
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>Telnet"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["telnet"]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{
            DevelopmentState, PrivilegeRequirement, ProtocolMetadataV2,
        };

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::PrivilegedPort(23))
            .well_known_port(23)
            .implementation(
                "Line-based text over TCP. IAC sequences are stripped from the stream but not \
                 answered; lines are capped at 8 KiB.",
            )
            .llm_control("Every byte sent to the terminal")
            .e2e_testing(
                "tests/server/telnet/: test.rs (echo, prompt, multiple lines, concurrent \
                 connections) and llm_failure_test.rs over raw TCP, plus line_framing_test.rs, \
                 which sends a real telnet(1) negotiation preamble and asserts the handler \
                 received the typed line alone, and asserts an 8 KiB run with no newline is \
                 refused rather than buffered.",
            )
            .notes(
                "Telnet-lite: IAC/WILL/WONT/DO/DONT and subnegotiations are recognised only \
                 well enough to be removed from the data stream, never answered, so a real \
                 telnet client stays in its default line mode and gets no reply to its offers. \
                 Absent: character-at-a-time mode, TTYPE/NAWS, terminal emulation, TLS.",
            )
            .max_inbound_bytes(crate::server::telnet::MAX_LINE_BYTES)
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "Telnet terminal server"
    }
    fn example_prompt(&self) -> &'static str {
        "Start a telnet server on port 23 that echoes commands"
    }
    fn group_name(&self) -> &'static str {
        "Application"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        use serde_json::json;

        // Deterministic: echo each line back to the client, no LLM call.
        let script = r#"import json, sys
data = json.load(sys.stdin)
event = data["event"]
if data["event_type_id"] == "telnet_message_received":
    actions = [{"type": "send_telnet_line",
                "line": "you said: " + str(event.get("message", ""))}]
else:
    actions = []
print(json.dumps({"actions": actions}))"#;

        StartupExamples::new(
            // LLM mode: LLM handles all Telnet responses intelligently
            json!({
                "type": "open_server",
                "port": 23,
                "base_stack": "telnet",
                "send_first": true,
                "instruction": "Telnet terminal server: greet with a login banner on connect, then handle user commands"
            }),
            // Script mode: Code-based deterministic responses
            json!({
                "type": "open_server",
                "port": 23,
                "base_stack": "telnet",
                "event_handlers": [{
                    "event_pattern": "telnet_message_received",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": script
                    }
                }]
            }),
            // Static mode: Fixed responses
            json!({
                "type": "open_server",
                "port": 23,
                "base_stack": "telnet",
                "event_handlers": [{
                    "event_pattern": "telnet_message_received",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "send_telnet_line",
                            "line": "Command received"
                        }]
                    }
                }]
            }),
        )
    }
}

// Implement Server trait (server-specific functionality)
impl Server for TelnetProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::server::telnet::TelnetServer;
            let send_first = ctx
                .startup_params
                .as_ref()
                .map(|p| p.get_optional_bool("send_first"))
                .transpose()?
                .flatten()
                .unwrap_or(false);

            #[allow(deprecated)]
            let listen_addr = ctx.socket_addr().unwrap_or(ctx.legacy_listen_addr());

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

            TelnetServer::spawn_with_llm_actions(
                listen_addr,
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.server_id,
                send_first,
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
            "send_telnet_message" => self.execute_send_telnet_message(action),
            "send_telnet_line" => self.execute_send_telnet_line(action),
            "send_telnet_prompt" => self.execute_send_telnet_prompt(action),
            "wait_for_more" => Ok(ActionResult::WaitForMore),
            "close_connection" => Ok(ActionResult::CloseConnection),
            _ => Err(anyhow::anyhow!("Unknown Telnet action: {}", action_type)),
        }
    }
}

// Action definitions

fn send_telnet_message_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_telnet_message".to_string(),
        description: "Send a raw Telnet message (exact bytes, no modification)".to_string(),
        parameters: vec![Parameter {
            name: "message".to_string(),
            type_hint: "string".to_string(),
            description: "Message to send (sent as-is, no newline added)".to_string(),
            required: true,
        }],
        example: json!({
            "type": "send_telnet_message",
            "message": "Hello\r\n"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> Telnet: {preview(message,60)}")
                .with_debug("Telnet send_telnet_message: {message_len} bytes"),
        ),
    }
}

fn send_telnet_line_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_telnet_line".to_string(),
        description: "Send a line of text (automatically adds \\r\\n if not present)".to_string(),
        parameters: vec![Parameter {
            name: "line".to_string(),
            type_hint: "string".to_string(),
            description: "Line of text to send".to_string(),
            required: true,
        }],
        example: json!({
            "type": "send_telnet_line",
            "line": "Welcome to the Telnet server!"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> Telnet: {preview(line,60)}")
                .with_debug("Telnet send_telnet_line: {line}"),
        ),
    }
}

fn send_telnet_prompt_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_telnet_prompt".to_string(),
        description: "Send only a prompt such as '> ' or '$ ': no newline and no other text. \
            A prompt says nothing by itself; to answer the line, use send_telnet_line (and a \
            prompt after it if you want one)."
            .to_string(),
        parameters: vec![Parameter {
            name: "prompt".to_string(),
            type_hint: "string".to_string(),
            description: "Prompt text (default: '> ')".to_string(),
            required: false,
        }],
        example: json!({
            "type": "send_telnet_prompt",
            "prompt": "$ "
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> Telnet prompt: {prompt}")
                .with_debug("Telnet send_telnet_prompt: prompt={prompt}"),
        ),
    }
}

fn wait_for_more_action() -> ActionDefinition {
    ActionDefinition {
        name: "wait_for_more".to_string(),
        description: "Send nothing and wait for the client's next line. Use it when the line you \
            just received is only part of a command (e.g. you asked for a username and want the \
            password before replying). The server reads lines strictly in order, so this simply \
            means 'no response for this line'."
            .to_string(),
        parameters: vec![],
        example: json!({
            "type": "wait_for_more"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("Telnet waiting for more data")
                .with_debug("Telnet wait_for_more"),
        ),
    }
}

fn close_connection_action() -> ActionDefinition {
    ActionDefinition {
        name: "close_connection".to_string(),
        description: "Close the Telnet connection".to_string(),
        parameters: vec![],
        example: json!({
            "type": "close_connection"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("Telnet connection closed")
                .with_debug("Telnet close_connection"),
        ),
    }
}

// ============================================================================
// Telnet Event Type Constants
// ============================================================================

/// Raised for every connection, before the first line is read.
pub static TELNET_CONNECTION_OPENED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "telnet_connection_opened",
        "A client opened a Telnet connection and nothing has been sent yet. Raised for every \
         connection. If the instruction asks to greet connecting clients, show a banner or ask \
         for a login, send it now. Otherwise answer with no actions at all \
         ({\"actions\": []}) and wait for the client to type - do not invent a greeting \
         nobody asked for. The client has typed nothing, so there is no message to react to.",
        json!({
            "type": "send_telnet_message",
            "message": "Welcome to NetGet\r\nlogin: "
        }),
    )
    // Data: `connect_event_data()` - nothing received yet, and the answer that calls for.
    .with_actions(vec![
        send_telnet_message_action(),
        send_telnet_line_action(),
        send_telnet_prompt_action(),
        close_connection_action(),
    ])
    .with_parameters(crate::protocol::event_type::connect_event_parameters())
    .raised_on_every_connection()
    .with_log_template(
        LogTemplate::new()
            .with_info("Telnet connection opened from {client_ip}")
            .with_debug("Telnet connection opened from {client_ip}:{client_port}")
            .with_trace("Telnet connection opened: {json_pretty(.)}"),
    )
});

pub static TELNET_MESSAGE_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "telnet_message_received",
        "A complete line of text arrived from a Telnet client. Lines are split on \\n and the \
         trailing whitespace/CR is trimmed before you see them. A line longer than 8 KiB with \
         no newline in it is refused by the server and never raises this event. The event \
         carries this one line only: nothing said earlier on the connection is repeated in it, \
         so whatever a later line depends on (a game in progress, a login step, a current \
         directory) has to be kept in memory with set_memory.",
        json!({
            "type": "send_telnet_line",
            "line": "Command received. Processing..."
        }),
    )
    .with_parameters(vec![Parameter {
        name: "message".to_string(),
        type_hint: "string".to_string(),
        description: "The line the client sent, trimmed of its trailing CR/LF and surrounding \
            whitespace. Telnet option negotiation is removed before you see it, so a real \
            telnet client's IAC (0xFF) sequences never appear here - but the server does not \
            *answer* them either, so the client stays in its default line mode"
            .to_string(),
        required: true,
    }])
    .with_actions(vec![
        send_telnet_message_action(),
        send_telnet_line_action(),
        send_telnet_prompt_action(),
        wait_for_more_action(),
        close_connection_action(),
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("Telnet {client_ip}: {preview(message,80)}")
            .with_debug("Telnet message from {client_ip}:{client_port}")
            .with_trace("Telnet: {json_pretty(.)}"),
    )
});

pub fn get_telnet_event_types() -> Vec<EventType> {
    vec![
        TELNET_CONNECTION_OPENED_EVENT.clone(),
        TELNET_MESSAGE_RECEIVED_EVENT.clone(),
    ]
}

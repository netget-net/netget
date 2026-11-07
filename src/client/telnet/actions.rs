//! Telnet client protocol actions implementation

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

/// The Telnet end of line, RFC 854's NVT newline. Every line this client sends ends in it.
pub const LINE_ENDING: &str = "\r\n";

/// The bytes `send_command` puts on the wire: the line, without any line ending the model
/// wrote itself, then [`LINE_ENDING`]. A model that writes `"hello\r\n"` means one line, and
/// sending it as `hello\r\n\r\n` would hand a line-based server an empty second line.
pub fn line_bytes(line: &str) -> Vec<u8> {
    let mut out = line.trim_end_matches(['\r', '\n']).as_bytes().to_vec();
    out.extend_from_slice(LINE_ENDING.as_bytes());
    out
}

/// Send a line, with the line ending appended for you. The usual answer.
///
/// The descriptions here and on `send_text` and `telnet_data_received` decide which of the two
/// a model picks, and they were measured: llama3.1:8b, the quiz question of the restart-check
/// measurement replayed over seeds (`src/client/telnet/AGENTS.md` has the table). Worded as "a
/// text command" beside a `send_text` "for where the server is waiting mid-line", the model
/// answered with `send_text` on 8 of 50 seeds, and on 22 of 30 once the restart check had told
/// it `send_command {"command":"hello"}` was not to be sent again. Worded as below it did on
/// none of either. Renaming the action, folding the two into one with a `line_ending` field,
/// rewording the event alone or not offering `send_text` all left more answers empty.
fn send_command_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_command".to_string(),
        description: "Send one line to the Telnet server: an answer, a reply, a login name or a \
                      command. The line ending (CRLF) is added for you. This is the normal way \
                      to answer anything the server says."
            .to_string(),
        parameters: vec![Parameter {
            name: "command".to_string(),
            type_hint: "string".to_string(),
            description: "The line to send, without a line ending".to_string(),
            required: true,
        }],
        example: json!({
            "type": "send_command",
            "command": "ls -la"
        }),
        log_template: None,
    }
}

/// Send exact text with no line ending, for a server that reads keys or waits on the same line.
fn send_text_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_text".to_string(),
        description: "Send text with NO line ending. A line-based server does not see it until \
                      a line ending follows, so do not use it to answer a question or a prompt; \
                      use send_command. Only for a server that reads single keys or waits for \
                      more on the same line."
            .to_string(),
        parameters: vec![Parameter {
            name: "text".to_string(),
            type_hint: "string".to_string(),
            description: "The characters to send, with nothing added".to_string(),
            required: true,
        }],
        example: json!({
            "type": "send_text",
            "text": "y"
        }),
        log_template: None,
    }
}

/// Say nothing and read again.
fn wait_for_more_action() -> ActionDefinition {
    ActionDefinition {
        name: "wait_for_more".to_string(),
        description: "Send nothing and wait for the server's next write. Use it when what \
                      arrived is only part of a prompt or a banner."
            .to_string(),
        parameters: vec![],
        example: json!({
            "type": "wait_for_more"
        }),
        log_template: None,
    }
}

/// Hang up.
fn disconnect_action() -> ActionDefinition {
    ActionDefinition {
        name: "disconnect".to_string(),
        description: "Disconnect from the Telnet server".to_string(),
        parameters: vec![],
        example: json!({
            "type": "disconnect"
        }),
        log_template: None,
    }
}

/// Telnet client connected event
pub static TELNET_CLIENT_CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "telnet_connected",
        "Telnet client successfully connected to server. Nothing has arrived yet - many \
         servers send a banner or a login prompt unprompted, so wait_for_more is often the \
         right first answer.",
        json!({
            "type": "wait_for_more"
        }),
    )
    .with_parameters(vec![Parameter {
        name: "remote_addr".to_string(),
        type_hint: "string".to_string(),
        description: "Remote server address".to_string(),
        required: true,
    }])
    .with_actions(vec![
        send_command_action(),
        send_text_action(),
        wait_for_more_action(),
        disconnect_action(),
    ])
});

/// Telnet client data received event
pub static TELNET_CLIENT_DATA_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "telnet_data_received",
        "Data received from Telnet server, with option negotiation already stripped and \
         answered. Reply with send_command (one line, the usual answer), or wait_for_more if \
         this looks like part of a prompt you have not finished reading.",
        // Rendered verbatim into the documentation the model reads, so it has to be an action
        // the executor accepts. This was `{"type": "placeholder"}`.
        json!({
            "type": "send_command",
            "command": "whoami"
        }),
    )
    // `raw_hex` used to be here too — the whole read, hex-encoded, up to 16 KB of hex per
    // turn. The repo's action/event rules forbid it ("never put raw bytes or base64 in action
    // parameters or event data"): models cannot reliably parse hex, the negotiation it
    // exposed is answered in Rust rather than by the model, and it doubled the prompt for
    // nothing.
    .with_parameters(vec![Parameter {
        name: "data".to_string(),
        type_hint: "string".to_string(),
        description: "The text the server sent, with Telnet IAC sequences removed".to_string(),
        required: true,
    }])
    .with_actions(vec![
        send_command_action(),
        send_text_action(),
        wait_for_more_action(),
        disconnect_action(),
    ])
});

/// Telnet client protocol action handler
pub struct TelnetClientProtocol;

impl TelnetClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for TelnetClientProtocol {
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![
            send_command_action(),
            send_text_action(),
            wait_for_more_action(),
            disconnect_action(),
        ]
    }
    /// The same four.
    ///
    /// A client has one LLM entry point, so the async/sync split cannot express a narrowing,
    /// and the two readers that matter union the lists: `client_llm_action_set` for the model
    /// and `client_action_names_for_pattern` for `event_handlers` validation, which no longer
    /// reads the sync list alone — `disconnect` was async-only and a static handler naming it
    /// was rejected as an unknown action until that was fixed centrally.
    ///
    /// The copy stays because a third reader still takes the sync list by itself:
    /// `cli::tasks`'s `execute_single_task` builds a **client-scoped scheduled task**'s
    /// action list from `get_sync_actions()` alone, and `ConversationHandler` rejects
    /// everything outside it. Union there too and this list can go.
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            send_command_action(),
            send_text_action(),
            wait_for_more_action(),
            disconnect_action(),
        ]
    }
    fn protocol_name(&self) -> &'static str {
        "Telnet"
    }
    /// The statics above, which are the ones `mod.rs` emits.
    ///
    /// This used to build three `EventType`s inline: two duplicating the statics' ids but
    /// with no parameters and `{"type": "placeholder"}` as the example action — so the model
    /// was shown `placeholder` as the way to answer, and `remote_addr`/`data` were documented
    /// nowhere it could read — plus a third, `telnet_option_negotiated`, that **nothing in
    /// `src/` ever raised**. An `event_handlers` rule on it could never match and the model
    /// was told to expect something that does not exist. It is gone rather than emitted:
    /// option negotiation is answered here in Rust, deliberately, and the model has no say in
    /// it, so an event per option would be noise with nothing to decide.
    ///
    /// `event_emit_sites_test` misses a case like that precisely because the `EventType` is
    /// built inline instead of being a named static it can find.
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            TELNET_CLIENT_CONNECTED_EVENT.clone(),
            TELNET_CLIENT_DATA_RECEIVED_EVENT.clone(),
        ]
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>Telnet"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "telnet",
            "telnet client",
            "connect to telnet",
            "remote shell",
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .implementation("Raw TCP with Telnet option negotiation")
            .llm_control("Send commands and respond to server output, automatic option negotiation")
            .e2e_testing("telnetd or netcat as test server")
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            // Reads that arrive while the model answers wait in a queue and are answered in
            // one call, one event per read (`client/telnet/mod.rs`).
            .batching(crate::protocol::metadata::BatchingMode::On)
            .build()
    }
    fn description(&self) -> &'static str {
        "Telnet client for connecting to Telnet servers and executing commands"
    }
    fn example_prompt(&self) -> &'static str {
        "Connect to Telnet at localhost:23 and run 'whoami' command"
    }
    fn group_name(&self) -> &'static str {
        "Infrastructure"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        use serde_json::json;

        StartupExamples::new(
            // LLM mode: LLM controls Telnet session
            json!({
                "type": "open_client",
                "remote_addr": "localhost:23",
                "base_stack": "telnet",
                "instruction": "Login and execute 'whoami' command"
            }),
            // Script mode: Code-based command handling
            json!({
                "type": "open_client",
                "remote_addr": "localhost:23",
                "base_stack": "telnet",
                "event_handlers": [{
                    "event_pattern": "telnet_data_received",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "<telnet_client_handler>"
                    }
                }]
            }),
            // Static mode: Fixed command sequence
            json!({
                "type": "open_client",
                "remote_addr": "localhost:23",
                "base_stack": "telnet",
                "event_handlers": [
                    {
                        "event_pattern": "telnet_connected",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "send_command",
                                "command": "whoami"
                            }]
                        }
                    },
                    {
                        "event_pattern": "telnet_data_received",
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
impl Client for TelnetClientProtocol {
    fn connect(
        &self,
        ctx: crate::protocol::ConnectContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::client::telnet::TelnetClient;
            TelnetClient::connect_with_llm_actions(
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
            "send_command" => {
                let command = action
                    .get("command")
                    .and_then(|v| v.as_str())
                    .context("Missing 'command' field")?;

                Ok(ClientActionResult::SendData(line_bytes(command)))
            }
            "send_text" => {
                let text = action
                    .get("text")
                    .and_then(|v| v.as_str())
                    .context("Missing 'text' field")?;

                let data = text.as_bytes().to_vec();
                Ok(ClientActionResult::SendData(data))
            }
            "disconnect" => Ok(ClientActionResult::Disconnect),
            "wait_for_more" => Ok(ClientActionResult::WaitForMore),
            _ => Err(anyhow::anyhow!(
                "Unknown Telnet client action: {}",
                action_type
            )),
        }
    }
}

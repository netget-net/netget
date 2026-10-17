//! Pseudo-terminal (PTY) protocol actions implementation.
//!
//! Platform: Unix/Linux/macOS only. The server owns the PTY master and role-plays a program with
//! a terminal: the model decides what appears on the terminal (prompts, output) and how to react
//! to what a real terminal program (`cat`, `screen`, a shell) types on the slave.
#![cfg(unix)]

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

/// PTY protocol action handler.
///
/// Stateless: the server ([`crate::server::pty::PtyServer`]) owns the master fd. The model reacts
/// to bytes a terminal program typed on the slave and decides the bytes that appear on the
/// terminal — "the model owns the payload, NetGet owns the plumbing", over a pseudo-terminal.
pub struct PtyProtocol;

impl PtyProtocol {
    pub fn new() -> Self {
        Self
    }
}

impl Default for PtyProtocol {
    fn default() -> Self {
        Self::new()
    }
}

impl Protocol for PtyProtocol {
    /// A PTY has no host and no port; opt into the port-optional startup path.
    fn default_binding(&self) -> Option<crate::protocol::BindingDefaults> {
        Some(crate::protocol::BindingDefaults {
            mac_address: None,
            interface: None,
            host: None,
            port: None,
        })
    }

    fn get_startup_parameters(&self) -> Vec<crate::llm::actions::ParameterDefinition> {
        vec![
            crate::llm::actions::ParameterDefinition {
                name: "link_path".to_string(),
                type_hint: "string".to_string(),
                description: "Optional filesystem path to symlink to the allocated slave PTY device \
                    (e.g. /dev/ttys003), so a terminal program can open it at a stable path. \
                    Without it the slave device name is only visible in the logs. A terminal client \
                    then opens this path: `screen ./netget.pty`, `cat ./netget.pty`."
                    .to_string(),
                required: false,
                example: serde_json::json!("./netget.pty"),
                default: None,
            },
            crate::llm::actions::ParameterDefinition {
                name: "send_first".to_string(),
                type_hint: "boolean".to_string(),
                description: "If true, raise a pty_opened event as soon as the PTY is ready so the \
                    model can print an initial banner or prompt onto the terminal before any input."
                    .to_string(),
                required: false,
                example: serde_json::json!(true),
                default: None,
            },
        ]
    }

    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        // No user-triggered actions: output is produced in reaction to terminal events.
        Vec::new()
    }

    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![write_pty_output_action()]
    }

    fn protocol_name(&self) -> &'static str {
        "PTY"
    }

    fn get_event_types(&self) -> Vec<EventType> {
        get_pty_event_types()
    }

    fn stack_name(&self) -> &'static str {
        "PTY"
    }

    fn keywords(&self) -> Vec<&'static str> {
        vec!["pseudo_terminal", "pty_master", "fake_tty"]
    }

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .implementation("libc::openpty; slave set raw (cfmakeraw); master via tokio AsyncFd")
            .llm_control("Full byte stream: reacts to terminal input, writes bytes onto the PTY")
            .e2e_testing("Real terminal client opens the slave device and drives it (std::fs)")
            .notes(
                "Pseudo-terminal. The server holds the master and role-plays a program with a \
                 terminal; a real terminal program opens the slave (symlinked at `link_path`). The \
                 slave is put in raw mode (no echo, no canonical line buffering) so the model owns \
                 the exact byte stream. Validated against a std::fs client opening the slave \
                 device, not NetGet-against-NetGet.",
            )
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            // Reads from the terminal while the model is answering are queued by a separate reader
            // task and answered together through `call_llm_batch` (batching on) or one read
            // per call (off).
            .batching(crate::protocol::metadata::BatchingMode::On)
            .build()
    }

    fn description(&self) -> &'static str {
        "Pseudo-terminal server: the LLM role-plays a program driving a terminal"
    }

    fn example_prompt(&self) -> &'static str {
        "Open a PTY symlinked at ./netget.pty, print the prompt 'netget$ ' on connect, and answer the 'whoami' command with 'root'"
    }

    fn group_name(&self) -> &'static str {
        "Core"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;

        // Deterministic: echo each input back to the pty, no LLM call.
        let script = r#"import json, sys
data = json.load(sys.stdin)
event = data["event"]
if data["event_type_id"] == "pty_input_received":
    actions = [{"type": "write_pty_output", "data": str(event.get("data", ""))}]
else:
    actions = []
print(json.dumps({"actions": actions}))"#;

        // Protocol parameters go inside `startup_params`. `CommonAction::OpenServer`
        // (`src/llm/actions/common.rs`) declares a fixed field set -- host, port, interface,
        // mac_address, send_first, instruction, startup_params, event_handlers, scheduled_tasks --
        // and serde silently drops anything else, so a top-level `link_path` never reaches
        // `spawn()` and the server fails to start at all. These examples had it at the top level;
        // `tests/examples/protocol_examples_test.rs` starts every protocol from its own declared
        // examples and reported exactly that.
        //
        // `send_first` is the exception and stays at the top level: it *is* a declared
        // `OpenServer` field, and `server_startup` folds it into `startup_params` for any
        // protocol that declares it.
        StartupExamples::new(
            json!({
                "type": "open_server",
                "base_stack": "pty",
                "startup_params": { "link_path": "./netget.pty" },
                "send_first": true,
                "instruction": "Print 'netget$ ' then act as a minimal shell"
            }),
            json!({
                "type": "open_server",
                "base_stack": "pty",
                "startup_params": { "link_path": "./netget.pty" },
                "event_handlers": [{
                    "event_pattern": "pty_input_received",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": script
                    }
                }]
            }),
            json!({
                "type": "open_server",
                "base_stack": "pty",
                "startup_params": { "link_path": "./netget.pty" },
                "send_first": true,
                "event_handlers": [
                    {
                        "event_pattern": "pty_opened",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "write_pty_output",
                                "data": "netget$ "
                            }]
                        }
                    },
                    {
                        "event_pattern": "pty_input_received",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "write_pty_output",
                                "data": "root\n"
                            }]
                        }
                    }
                ]
            }),
        )
    }
}

impl Server for PtyProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            let link_path = ctx
                .startup_params
                .as_ref()
                .map(|p| p.get_optional_string("link_path"))
                .transpose()?
                .flatten();

            let send_first = ctx
                .startup_params
                .as_ref()
                .map(|p| p.get_optional_bool("send_first"))
                .transpose()?
                .flatten()
                .unwrap_or(false);

            use crate::server::pty::PtyServer;
            PtyServer::spawn_with_llm_actions(
                link_path.map(std::path::PathBuf::from),
                send_first,
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.server_id,
            )
            .await?;

            // A PTY has no IP address; report the placeholder used by other pathless protocols.
            Ok("127.0.0.1:0".parse().unwrap())
        })
    }

    fn execute_action(&self, action: serde_json::Value) -> Result<ActionResult> {
        let action_type = action
            .get("type")
            .and_then(|v| v.as_str())
            .context("Missing 'type' field in action")?;

        match action_type {
            "write_pty_output" => {
                let data = action
                    .get("data")
                    .and_then(|v| v.as_str())
                    .context("Missing 'data' parameter")?;
                Ok(ActionResult::Output(decode_outbound_data(data, &action)?))
            }
            _ => Err(anyhow::anyhow!("Unknown pty action: {action_type}")),
        }
    }
}

/// Turn the `data` field of an outbound action into the exact bytes to write to the PTY, honouring
/// the action's optional `encoding` field. Mirrors `socket_file`/`named_pipe`.
fn decode_outbound_data(data: &str, action: &serde_json::Value) -> Result<Vec<u8>> {
    let encoding = action
        .get("encoding")
        .and_then(|v| v.as_str())
        .unwrap_or("utf8");

    match encoding {
        "utf8" => Ok(data.as_bytes().to_vec()),
        "hex" => hex::decode(data).map_err(|e| {
            anyhow::anyhow!(
                "'data' was declared as \"encoding\": \"hex\" but is not valid hex ({e}). \
                 Hex payloads are two hex digits per byte with no separators. To write this \
                 value as literal text, omit 'encoding' or set it to \"utf8\"."
            )
        }),
        other => Err(anyhow::anyhow!(
            "Invalid 'encoding' value {other:?}. Valid values are \"utf8\" (default) and \"hex\"."
        )),
    }
}

/// Shared `encoding` parameter for every action carrying an outbound `data` field.
fn encoding_parameter() -> Parameter {
    Parameter {
        name: "encoding".to_string(),
        type_hint: "string".to_string(),
        description: "How to convert 'data' into the bytes written to the terminal. \"utf8\" (the \
            default when omitted) writes the characters of 'data' unchanged - use it for text. \
            \"hex\" decodes 'data' as hex-encoded bytes, two hex digits per byte - use it for \
            control sequences or binary, e.g. {\"data\": \"1b5b326a\", \"encoding\": \"hex\"} writes \
            the ANSI clear-screen sequence. No other values are accepted"
            .to_string(),
        required: false,
    }
}

/// Action definition for write_pty_output (sync).
fn write_pty_output_action() -> ActionDefinition {
    ActionDefinition {
        name: "write_pty_output".to_string(),
        description: "Write bytes onto the pseudo-terminal so they appear to the terminal program \
            reading the slave (its 'screen'). The 'data' field holds the payload and the optional \
            'encoding' field says how to turn it into bytes: omit 'encoding' (or use \"utf8\") to \
            write characters as-is, or set \"encoding\": \"hex\" to write 'data' decoded from hex \
            (useful for ANSI escape sequences)."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "data".to_string(),
                type_hint: "string".to_string(),
                description:
                    "Text to display on the terminal. Interpreted according to 'encoding'; \
                    by default written as-is (UTF-8). Include your own newlines."
                        .to_string(),
                required: true,
            },
            encoding_parameter(),
        ],
        example: json!({
            "type": "write_pty_output",
            "data": "netget$ ",
            "encoding": "utf8"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> PTY {data_len}B")
                .with_debug("PTY write_pty_output: data_len={data_len}"),
        ),
    }
}

// ============================================================================
// PTY Action / Event Constants
// ============================================================================

pub static WRITE_PTY_OUTPUT_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(write_pty_output_action);

/// PTY opened event - raised once at startup when `send_first` is set, so the model can emit a
/// banner/prompt before any input. Emitted only under `send_first` (same pattern as
/// `socket_file_connection_opened`).
pub static PTY_OPENED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "pty_opened",
        "Pseudo-terminal is ready (send an initial banner/prompt if desired)",
        json!({
            "type": "write_pty_output",
            "data": "netget$ "
        }),
    )
    .with_parameters(vec![Parameter {
        name: "slave_path".to_string(),
        type_hint: "string".to_string(),
        description: "Filesystem path of the slave PTY device a terminal program should open."
            .to_string(),
        required: false,
    }])
    .with_actions(vec![WRITE_PTY_OUTPUT_ACTION.clone()])
});

/// PTY input received event - raised when the terminal program writes (types) on the slave.
pub static PTY_INPUT_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "pty_input_received",
        "A terminal program typed/wrote data on the pseudo-terminal",
        json!({
            "type": "write_pty_output",
            "data": "root\n"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "data".to_string(),
            type_hint: "string".to_string(),
            description: "The bytes the terminal program wrote. Read it according to 'encoding'."
                .to_string(),
            required: true,
        },
        Parameter {
            name: "encoding".to_string(),
            type_hint: "string".to_string(),
            description:
                "How to read 'data': \"utf8\" means literal text, \"hex\" means the bytes \
                hex-encoded (used when they are not all printable ASCII)."
                    .to_string(),
            required: true,
        },
    ])
    .with_actions(vec![WRITE_PTY_OUTPUT_ACTION.clone()])
});

/// Get PTY event types.
pub fn get_pty_event_types() -> Vec<EventType> {
    vec![PTY_OPENED_EVENT.clone(), PTY_INPUT_RECEIVED_EVENT.clone()]
}

//! Named pipe (POSIX FIFO) protocol actions implementation
//!
//! Platform: Unix/Linux/macOS only (uses `mkfifo`). Windows named pipes are a
//! different primitive and are out of scope here; a Windows path would be a
//! `#[cfg(windows)]` follow-up.
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

/// Named pipe (FIFO) protocol action handler.
///
/// Stateless: the server ([`crate::server::named_pipe::NamedPipeServer`]) owns the file
/// descriptors. The model reacts to bytes a writer put on the FIFO and decides what bytes to
/// write back to the optional response FIFO — the same "the model owns the payload, NetGet owns
/// the plumbing" contract as `socket_file`, addressed by a FIFO path instead of a socket path.
pub struct NamedPipeProtocol;

impl NamedPipeProtocol {
    pub fn new() -> Self {
        Self
    }
}

impl Default for NamedPipeProtocol {
    fn default() -> Self {
        Self::new()
    }
}

impl Protocol for NamedPipeProtocol {
    /// A FIFO has no host and no port; opt into the port-optional startup path.
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
                name: "pipe_path".to_string(),
                type_hint: "string".to_string(),
                description: "Filesystem path of the FIFO to create and read from. A writer \
                    process writes to this path (e.g. `echo hi > ./netget.fifo`) and each write \
                    raises a named_pipe_data_received event."
                    .to_string(),
                required: true,
                example: serde_json::json!("./netget.fifo"),
                default: None,
            },
            crate::llm::actions::ParameterDefinition {
                name: "response_pipe_path".to_string(),
                type_hint: "string".to_string(),
                description: "Optional path of a second FIFO to create and WRITE responses to. A \
                    reader process reads this path (e.g. `cat ./netget.resp.fifo`) to receive what \
                    write_named_pipe_data emits. Omit it for a read-only sink where the model just \
                    observes writer input; write_named_pipe_data then has nowhere to go and is \
                    logged as a warning."
                    .to_string(),
                required: false,
                example: serde_json::json!("./netget.resp.fifo"),
                default: None,
            },
        ]
    }

    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        // No user-triggered actions: a FIFO reacts to writer input, and there is no per-connection
        // routing for an out-of-band async send.
        Vec::new()
    }

    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![write_named_pipe_data_action()]
    }

    fn protocol_name(&self) -> &'static str {
        "NAMED_PIPE"
    }

    fn get_event_types(&self) -> Vec<EventType> {
        get_named_pipe_event_types()
    }

    fn stack_name(&self) -> &'static str {
        "NAMED_PIPE"
    }

    fn keywords(&self) -> Vec<&'static str> {
        vec!["named_pipe", "posix_fifo", "mkfifo_ipc"]
    }

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .implementation("POSIX FIFO via libc::mkfifo; read side wrapped in tokio AsyncFd")
            .llm_control("Full byte stream: reacts to writer bytes, emits bytes to a response FIFO")
            .e2e_testing("Real independent std::fs writer/reader on the FIFO paths")
            .notes(
                "Unix FIFO (mkfifo). The server reads `pipe_path` and, if `response_pipe_path` is \
                 given, writes model output to it. Validated against a std::fs writer/reader, not \
                 NetGet-against-NetGet. Windows named pipes are a different primitive and are out \
                 of scope (a #[cfg(windows)] follow-up).",
            )
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            // Chunks written to the FIFO while the model is answering are queued by a separate reader
            // task and answered together through `call_llm_batch` (batching on) or one read
            // per call (off).
            .batching(crate::protocol::metadata::BatchingMode::On)
            .build()
    }

    fn description(&self) -> &'static str {
        "POSIX named pipe (FIFO) server: reads a FIFO and lets the LLM react to writer input"
    }

    fn example_prompt(&self) -> &'static str {
        "Create a FIFO at ./netget.fifo and, for every line written to it, write 'ACK: <line>' to the response FIFO ./netget.resp.fifo"
    }

    fn group_name(&self) -> &'static str {
        "Core"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;

        // Deterministic: reply "OK" to every message on the named pipe, no LLM
        // call.
        let script = r#"import json, sys
data = json.load(sys.stdin)
event = data["event"]
if data["event_type_id"] == "named_pipe_data_received":
    actions = [{"type": "write_named_pipe_data", "data": "OK"}]
else:
    actions = []
print(json.dumps({"actions": actions}))"#;

        // Protocol parameters go inside `startup_params`. `CommonAction::OpenServer`
        // (`src/llm/actions/common.rs`) declares a fixed field set -- host, port, interface,
        // mac_address, send_first, instruction, startup_params, event_handlers, scheduled_tasks --
        // and serde silently drops anything else, so a top-level `pipe_path` never reaches
        // `spawn()` and the server fails to start at all. These examples had it at the top level;
        // `tests/examples/protocol_examples_test.rs` starts every protocol from its own declared
        // examples and reported exactly that.
        StartupExamples::new(
            json!({
                "type": "open_server",
                "base_stack": "named_pipe",
                "startup_params": {
                    "pipe_path": "./netget.fifo",
                    "response_pipe_path": "./netget.resp.fifo"
                },
                "instruction": "FIFO server that answers each write with 'ACK: <data>'"
            }),
            json!({
                "type": "open_server",
                "base_stack": "named_pipe",
                "startup_params": { "pipe_path": "./netget.fifo" },
                "event_handlers": [{
                    "event_pattern": "named_pipe_data_received",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": script
                    }
                }]
            }),
            json!({
                "type": "open_server",
                "base_stack": "named_pipe",
                "startup_params": {
                    "pipe_path": "./netget.fifo",
                    "response_pipe_path": "./netget.resp.fifo"
                },
                "event_handlers": [{
                    "event_pattern": "named_pipe_data_received",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "write_named_pipe_data",
                            "data": "ACK\n"
                        }]
                    }
                }]
            }),
        )
    }
}

impl Server for NamedPipeProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            let pipe_path = ctx
                .startup_params
                .as_ref()
                .map(|p| p.get_string("pipe_path"))
                .transpose()?
                .ok_or_else(|| anyhow::anyhow!("pipe_path parameter is required"))?;

            let response_pipe_path = ctx
                .startup_params
                .as_ref()
                .map(|p| p.get_optional_string("response_pipe_path"))
                .transpose()?
                .flatten();

            use crate::server::named_pipe::NamedPipeServer;
            NamedPipeServer::spawn_with_llm_actions(
                std::path::PathBuf::from(pipe_path),
                response_pipe_path.map(std::path::PathBuf::from),
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.server_id,
            )
            .await?;

            // A FIFO has no IP address; report the placeholder used by other pathless protocols.
            Ok("127.0.0.1:0".parse().unwrap())
        })
    }

    fn execute_action(&self, action: serde_json::Value) -> Result<ActionResult> {
        let action_type = action
            .get("type")
            .and_then(|v| v.as_str())
            .context("Missing 'type' field in action")?;

        match action_type {
            "write_named_pipe_data" => {
                let data = action
                    .get("data")
                    .and_then(|v| v.as_str())
                    .context("Missing 'data' parameter")?;
                Ok(ActionResult::Output(decode_outbound_data(data, &action)?))
            }
            _ => Err(anyhow::anyhow!("Unknown named pipe action: {action_type}")),
        }
    }
}

/// Turn the `data` field of an outbound action into the exact bytes to write, honouring the
/// action's optional `encoding` field. Mirrors `socket_file` so echoing a payload is symmetric.
///
/// - `encoding` absent or `"utf8"`: the string's UTF-8 bytes are written verbatim.
/// - `encoding` = `"hex"`: `data` is decoded as hex, so `"48656c6c6f"` writes `Hello`.
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
            "Invalid 'encoding' value {other:?}. Valid values are \"utf8\" (default, write the \
             characters of 'data' as-is) and \"hex\" (decode 'data' as hex-encoded bytes)."
        )),
    }
}

/// Shared `encoding` parameter for every action carrying an outbound `data` field.
fn encoding_parameter() -> Parameter {
    Parameter {
        name: "encoding".to_string(),
        type_hint: "string".to_string(),
        description: "How to convert 'data' into the bytes written to the response FIFO. \"utf8\" \
            (the default when omitted) writes the characters of 'data' unchanged - use it for text. \
            \"hex\" decodes 'data' as hex-encoded bytes, two hex digits per byte - use it for \
            binary, e.g. {\"data\": \"48656c6c6f\", \"encoding\": \"hex\"} writes the 5 bytes \
            'Hello'. No other values are accepted"
            .to_string(),
        required: false,
    }
}

/// Action definition for write_named_pipe_data (sync).
fn write_named_pipe_data_action() -> ActionDefinition {
    ActionDefinition {
        name: "write_named_pipe_data".to_string(),
        description:
            "Write data to the response FIFO (response_pipe_path). The 'data' field holds \
            the payload and the optional 'encoding' field says how to turn it into bytes: omit \
            'encoding' (or use \"utf8\") to write the characters as-is, or set \"encoding\": \
            \"hex\" to write 'data' decoded from hex. If no response_pipe_path was configured this \
            output has nowhere to go and is logged as a warning."
                .to_string(),
        parameters: vec![
            Parameter {
                name: "data".to_string(),
                type_hint: "string".to_string(),
                description: "Data to write. Interpreted according to 'encoding'; by default the \
                    characters of this string are written as-is (UTF-8)."
                    .to_string(),
                required: true,
            },
            encoding_parameter(),
        ],
        example: json!({
            "type": "write_named_pipe_data",
            "data": "ACK\n",
            "encoding": "utf8"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> FIFO {data_len}B")
                .with_debug("FIFO write_named_pipe_data: data_len={data_len}"),
        ),
    }
}

// ============================================================================
// Named Pipe Action / Event Constants
// ============================================================================

pub static WRITE_NAMED_PIPE_DATA_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(write_named_pipe_data_action);

/// Named pipe data received event - raised for each chunk a writer puts on the FIFO.
pub static NAMED_PIPE_DATA_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "named_pipe_data_received",
        "Data written to the named pipe (FIFO) by a writer process",
        json!({
            "type": "write_named_pipe_data",
            "data": "ACK\n"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "data".to_string(),
            type_hint: "string".to_string(),
            description:
                "The bytes written to the FIFO. Read it according to the 'encoding' field."
                    .to_string(),
            required: true,
        },
        Parameter {
            name: "encoding".to_string(),
            type_hint: "string".to_string(),
            description:
                "How to read 'data': \"utf8\" means literal text, \"hex\" means the bytes \
                hex-encoded (used when they are not all printable ASCII). To echo the bytes back \
                unchanged, pass the same 'data' and 'encoding' to write_named_pipe_data."
                    .to_string(),
            required: true,
        },
    ])
    .with_actions(vec![WRITE_NAMED_PIPE_DATA_ACTION.clone()])
});

/// Get named pipe event types.
pub fn get_named_pipe_event_types() -> Vec<EventType> {
    vec![NAMED_PIPE_DATA_RECEIVED_EVENT.clone()]
}

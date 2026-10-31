//! Standard I/O (stdin/stdout/stderr) protocol actions implementation.
//!
//! Platform: Unix/Linux/macOS only. NetGet itself becomes the child process behind a pipe
//! (`someprogram | netget ... | otherprogram`): it reads lines from its own stdin, and the model
//! decides what to emit on stdout/stderr in response.
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

/// Standard I/O protocol action handler.
///
/// Stateless: the server ([`crate::server::stdio::StdioServer`]) owns the process's stdin/stdout/
/// stderr. The model reads lines the upstream program pipes in and decides the bytes emitted to
/// the downstream program — "the model owns the payload, NetGet owns the plumbing", over the
/// process's own standard streams.
pub struct StdioProtocol;

impl StdioProtocol {
    pub fn new() -> Self {
        Self
    }
}

impl Default for StdioProtocol {
    fn default() -> Self {
        Self::new()
    }
}

impl Protocol for StdioProtocol {
    /// stdio has no host and no port; opt into the port-optional startup path.
    fn default_binding(&self) -> Option<crate::protocol::BindingDefaults> {
        Some(crate::protocol::BindingDefaults {
            mac_address: None,
            interface: None,
            host: None,
            port: None,
        })
    }

    fn get_startup_parameters(&self) -> Vec<crate::llm::actions::ParameterDefinition> {
        vec![crate::llm::actions::ParameterDefinition {
            name: "send_first".to_string(),
            type_hint: "boolean".to_string(),
            description: "If true, raise a stdio_started event as soon as stdin is claimed so the \
                model can emit an initial banner/prompt on stdout before any input arrives."
                .to_string(),
            required: false,
            example: serde_json::json!(true),
            default: None,
        }]
    }

    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        // No user-triggered actions: output is produced in reaction to stdin.
        Vec::new()
    }

    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            write_stdout_action(),
            write_stderr_action(),
            close_stdio_action(),
        ]
    }

    fn protocol_name(&self) -> &'static str {
        "STDIO"
    }

    fn get_event_types(&self) -> Vec<EventType> {
        get_stdio_event_types()
    }

    fn stack_name(&self) -> &'static str {
        "STDIO"
    }

    fn keywords(&self) -> Vec<&'static str> {
        vec!["standard_io", "stdin_stdout", "pipe_filter"]
    }

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .implementation("tokio stdin/stdout/stderr; refuses under a TTY or MCP-stdio")
            .llm_control("Full control of stdout/stderr bytes in response to stdin lines")
            .e2e_testing("Real child process: netget spawned with piped stdin/stdout")
            .notes(
                "Speaks over the process's own stdin/stdout/stderr, so NetGet drops in as a pipe \
                 filter (prog | netget ... | prog). REFUSES to start under an interactive terminal \
                 (the TUI owns the terminal) and under --mcp stdio (JSON-RPC owns stdin/stdout); \
                 only one stdio server per process. Intended for headless/one-shot piped use. \
                 Validated by spawning the netget binary as a child with piped stdin/stdout.",
            )
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            // Reads from stdin while the model is answering are queued by a separate reader
            // task and answered together through `call_llm_batch` (batching on) or one read
            // per call (off).
            .batching(crate::protocol::metadata::BatchingMode::On)
            .build()
    }

    fn description(&self) -> &'static str {
        "Standard I/O server: NetGet acts as a pipe filter, the LLM drives stdout/stderr"
    }

    fn example_prompt(&self) -> &'static str {
        "Act as a stdio filter: for each line on stdin, uppercase it and print it to stdout"
    }

    fn group_name(&self) -> &'static str {
        "Core"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;

        // Deterministic: echo each line back on stdout, no LLM call.
        let script = r#"import json, sys
data = json.load(sys.stdin)
event = data["event"]
if data["event_type_id"] == "stdio_input_received":
    actions = [{"type": "write_stdout",
                "data": "you said: " + str(event.get("data", ""))}]
else:
    actions = []
print(json.dumps({"actions": actions}))"#;

        StartupExamples::new(
            json!({
                "type": "open_server",
                "base_stack": "stdio",
                "instruction": "For each stdin line, echo it back uppercased on stdout"
            }),
            json!({
                "type": "open_server",
                "base_stack": "stdio",
                "event_handlers": [{
                    "event_pattern": "stdio_input_received",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": script
                    }
                }]
            }),
            json!({
                "type": "open_server",
                "base_stack": "stdio",
                "event_handlers": [{
                    "event_pattern": "stdio_input_received",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "write_stdout",
                            "data": "ACK\n"
                        }]
                    }
                }]
            }),
        )
    }
}

impl Server for StdioProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            let send_first = ctx
                .startup_params
                .as_ref()
                .map(|p| p.get_optional_bool("send_first"))
                .transpose()?
                .flatten()
                .unwrap_or(false);

            use crate::server::stdio::StdioServer;
            StdioServer::spawn_with_llm_actions(
                send_first,
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.server_id,
            )
            .await?;

            // stdio has no IP address; report the placeholder used by other pathless protocols.
            Ok("127.0.0.1:0".parse().unwrap())
        })
    }

    fn execute_action(&self, action: serde_json::Value) -> Result<ActionResult> {
        let action_type = action
            .get("type")
            .and_then(|v| v.as_str())
            .context("Missing 'type' field in action")?;

        match action_type {
            "write_stdout" => {
                let data = action
                    .get("data")
                    .and_then(|v| v.as_str())
                    .context("Missing 'data' parameter")?;
                Ok(ActionResult::Output(decode_outbound_data(data, &action)?))
            }
            "write_stderr" => {
                let data = action
                    .get("data")
                    .and_then(|v| v.as_str())
                    .context("Missing 'data' parameter")?;
                let bytes = decode_outbound_data(data, &action)?;
                // stderr goes out-of-band from the stdout Output channel, carried as a Custom
                // result the server writes to fd 2. The hex here is internal server<->executor
                // plumbing, never model-facing.
                Ok(ActionResult::Custom {
                    name: "stdio_stderr".to_string(),
                    data: json!({ "hex": hex::encode(bytes) }),
                })
            }
            "close_stdio" => Ok(ActionResult::CloseConnection),
            _ => Err(anyhow::anyhow!("Unknown stdio action: {action_type}")),
        }
    }
}

/// Turn the `data` field of an outbound action into bytes, honouring the optional `encoding`
/// field. Mirrors `socket_file` so behaviour is symmetric with inbound `encoding`.
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
        description: "How to convert 'data' into the bytes emitted. \"utf8\" (the default when \
            omitted) emits the characters of 'data' unchanged - use it for text. \"hex\" decodes \
            'data' as hex-encoded bytes, two hex digits per byte - use it for binary. No other \
            values are accepted"
            .to_string(),
        required: false,
    }
}

/// Action definition for write_stdout (sync).
fn write_stdout_action() -> ActionDefinition {
    ActionDefinition {
        name: "write_stdout".to_string(),
        description: "Write bytes to the process's stdout (fd 1), i.e. to the downstream program \
            in the pipe. 'data' holds the payload; optional 'encoding' (\"utf8\" default, \"hex\") \
            says how to turn it into bytes. Include your own newlines."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "data".to_string(),
                type_hint: "string".to_string(),
                description: "Data to write to stdout. Interpreted according to 'encoding'."
                    .to_string(),
                required: true,
            },
            encoding_parameter(),
        ],
        example: json!({
            "type": "write_stdout",
            "data": "ACK\n",
            "encoding": "utf8"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> STDOUT {data_len}B")
                .with_debug("STDIO write_stdout: data_len={data_len}"),
        ),
    }
}

/// Action definition for write_stderr (sync).
fn write_stderr_action() -> ActionDefinition {
    ActionDefinition {
        name: "write_stderr".to_string(),
        description: "Write bytes to the process's stderr (fd 2), i.e. diagnostics that do not go \
            down the stdout pipe. Same 'data' / 'encoding' fields as write_stdout."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "data".to_string(),
                type_hint: "string".to_string(),
                description: "Data to write to stderr. Interpreted according to 'encoding'."
                    .to_string(),
                required: true,
            },
            encoding_parameter(),
        ],
        example: json!({
            "type": "write_stderr",
            "data": "warning: bad input\n",
            "encoding": "utf8"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> STDERR {data_len}B")
                .with_debug("STDIO write_stderr: data_len={data_len}"),
        ),
    }
}

/// Action definition for close_stdio (sync).
fn close_stdio_action() -> ActionDefinition {
    ActionDefinition {
        name: "close_stdio".to_string(),
        description: "Stop reading stdin and end the stdio session (as if the filter reached EOF)."
            .to_string(),
        parameters: vec![],
        example: json!({ "type": "close_stdio" }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> STDIO close")
                .with_debug("STDIO close_stdio"),
        ),
    }
}

// ============================================================================
// stdio Action / Event Constants
// ============================================================================

pub static WRITE_STDOUT_ACTION: LazyLock<ActionDefinition> = LazyLock::new(write_stdout_action);
pub static WRITE_STDERR_ACTION: LazyLock<ActionDefinition> = LazyLock::new(write_stderr_action);
pub static CLOSE_STDIO_ACTION: LazyLock<ActionDefinition> = LazyLock::new(close_stdio_action);

/// The two output actions plus close, attached to input-bearing events.
fn responder_actions() -> Vec<ActionDefinition> {
    vec![
        WRITE_STDOUT_ACTION.clone(),
        WRITE_STDERR_ACTION.clone(),
        CLOSE_STDIO_ACTION.clone(),
    ]
}

/// stdio started event - raised once at startup when `send_first` is set, so the model can emit a
/// banner before any input (same conditional pattern as `socket_file_connection_opened`).
pub static STDIO_STARTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "stdio_started",
        "stdin has been claimed and nothing has been read yet. Raised only when the server \
         was started with send_first: emit the initial banner or prompt on stdout now.",
        json!({
            "type": "write_stdout",
            "data": "ready\n"
        }),
    )
    .with_parameters(vec![])
    .with_actions(responder_actions())
});

/// stdio input received event - raised for each chunk read from stdin.
pub static STDIO_INPUT_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "stdio_input_received",
        "A chunk/line was read from stdin (the upstream program in the pipe)",
        json!({
            "type": "write_stdout",
            "data": "ACK\n"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "data".to_string(),
            type_hint: "string".to_string(),
            description: "The bytes read from stdin. Read it according to 'encoding'.".to_string(),
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
    .with_actions(responder_actions())
});

/// stdio input closed event - raised when stdin reaches EOF (the upstream program closed the pipe).
pub static STDIO_INPUT_CLOSED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "stdio_input_closed",
        "stdin reached EOF (upstream closed the pipe); emit any final output",
        json!({
            "type": "write_stdout",
            "data": "bye\n"
        }),
    )
    .with_parameters(vec![])
    .with_actions(vec![
        WRITE_STDOUT_ACTION.clone(),
        WRITE_STDERR_ACTION.clone(),
    ])
});

/// Get stdio event types.
pub fn get_stdio_event_types() -> Vec<EventType> {
    vec![
        STDIO_STARTED_EVENT.clone(),
        STDIO_INPUT_RECEIVED_EVENT.clone(),
        STDIO_INPUT_CLOSED_EVENT.clone(),
    ]
}

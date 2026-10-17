//! Socket file protocol actions implementation
//!
//! Platform: Unix/Linux only (uses Unix domain sockets)
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

/// Socket file protocol action handler
///
/// Stateless: the server ([`crate::server::socket_file::SocketFileServer`]) owns the
/// connection map, because only it holds the write halves. This type previously kept a
/// second, always-empty map of its own to back `send_to_connection` / `list_connections`
/// async actions; nothing ever inserted into it and nothing routed their results to a
/// connection, so those actions were advertised to the model and did nothing. They are gone.
pub struct SocketFileProtocol;

impl SocketFileProtocol {
    pub fn new() -> Self {
        Self
    }
}

impl Default for SocketFileProtocol {
    fn default() -> Self {
        Self::new()
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for SocketFileProtocol {
    /// A Unix socket has no host and no port.
    ///
    /// Without this, `server_startup.rs` treats the protocol as "unmigrated" and *requires* a
    /// `port`, so `start_server {"protocol": "socket_file", "socket_path": "..."}` failed with
    /// "requires 'port' parameter" and there was no way to start this protocol over MCP at
    /// all. Declaring empty binding defaults opts into the path where port is optional; the
    /// listen address that path computes is ignored, since the server binds `socket_path`.
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
                name: "socket_path".to_string(),
                type_hint: "string".to_string(),
                description: "Filesystem path for the Unix domain socket file (e.g., ./netget.sock)".to_string(),
                required: true,
                example: serde_json::json!("./netget.sock"),
                default: None,
            },
            crate::llm::actions::ParameterDefinition {
                name: "send_first".to_string(),
                type_hint: "boolean".to_string(),
                description: "Whether the server should send the first message after connection (e.g., for greeting banners)".to_string(),
                required: false,
                example: serde_json::json!(false),
                default: None,
            },
            crate::llm::actions::ParameterDefinition {
                name: "first_byte_timeout_secs".to_string(),
                type_hint: "number".to_string(),
                description: "Seconds a connected peer may send nothing before the server closes \
                              it. Default 300, matching the window a `manual` rule gives a human \
                              to answer one event - a peer is often NetGet's own socket_file \
                              client waiting for someone to use [ send message ]."
                    .to_string(),
                required: false,
                example: serde_json::json!(300),
                default: Some(serde_json::json!(super::FIRST_BYTE_READ_TIMEOUT.as_secs())),
            },
            crate::llm::actions::ParameterDefinition {
                name: "idle_timeout_secs".to_string(),
                type_hint: "number".to_string(),
                description: "Seconds an established session may be silent between messages \
                              before the server closes it. Default 900. A message still being \
                              answered never counts as silence."
                    .to_string(),
                required: false,
                example: serde_json::json!(900),
                default: Some(serde_json::json!(super::IDLE_BETWEEN_MESSAGES_TIMEOUT.as_secs())),
            },
        ]
    }

    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        // No user-triggered actions: a Unix socket server has nothing to say to a connection
        // outside a request/response exchange, and there is no mechanism to route an async
        // action's output to a specific connection.
        Vec::new()
    }

    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            send_socket_data_action(),
            wait_for_more_action(),
            close_this_connection_action(),
        ]
    }

    fn protocol_name(&self) -> &'static str {
        "SOCKET_FILE"
    }

    fn get_event_types(&self) -> Vec<EventType> {
        get_socket_file_event_types()
    }

    fn stack_name(&self) -> &'static str {
        "UNIX_SOCKET"
    }

    fn keywords(&self) -> Vec<&'static str> {
        vec!["socket_file", "unix_socket", "ipc"]
    }

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .implementation("Manual Unix domain socket handling with tokio; socket file chmod 0600")
            .llm_control("Full byte stream control - all sent/received data")
            .e2e_testing("A real, independent tokio::net::UnixStream peer; no third-party client")
            .notes(
                "Unix domain socket for IPC - a filesystem socket file instead of IP:port. The \
                 socket node is chmod'd to 0600 right after bind, because bind creates it \
                 0777 & ~umask and both Linux and macOS check write permission on the node at \
                 connect(2): the default would otherwise let any local user speak to it. The \
                 peer is a local descriptor, so no independent third-party client exists and \
                 nothing here supports a rating above Experimental.",
            )
            .max_inbound_bytes(crate::server::socket_file::MAX_QUEUED_BYTES)
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            // Bytes arriving during a call are the next call's payload, whole (batching on) or
            // one read at a time (off) — `ConnectionData::take_next`, the same shape as `tcp`.
            .batching(crate::protocol::metadata::BatchingMode::On)
            .build()
    }

    fn description(&self) -> &'static str {
        "Unix domain socket server for inter-process communication"
    }

    fn example_prompt(&self) -> &'static str {
        "Create socket file at ./myapp.sock and echo back any data received"
    }

    fn group_name(&self) -> &'static str {
        "Core"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;

        // Deterministic: reply "OK" to every message on the unix socket, no LLM
        // call.
        let script = r#"import json, sys
data = json.load(sys.stdin)
event = data["event"]
if data["event_type_id"] == "socket_file_data_received":
    actions = [{"type": "send_socket_data", "data": "OK"}]
else:
    actions = []
print(json.dumps({"actions": actions}))"#;

        // Protocol parameters go inside `startup_params`. `CommonAction::OpenServer`
        // (`src/llm/actions/common.rs`) declares a fixed field set -- host, port, interface,
        // mac_address, send_first, instruction, startup_params, event_handlers, scheduled_tasks --
        // and serde silently drops anything else, so a top-level `socket_path` never reaches
        // `spawn()` and the server fails to start at all. These examples had it at the top level;
        // `tests/examples/protocol_examples_test.rs` starts every protocol from its own declared
        // examples and reported exactly that.
        StartupExamples::new(
            json!({
                "type": "open_server",
                "base_stack": "socket_file",
                "startup_params": { "socket_path": "./netget.sock" },
                "instruction": "Unix socket IPC server that echoes data"
            }),
            json!({
                "type": "open_server",
                "base_stack": "socket_file",
                "startup_params": { "socket_path": "./netget.sock" },
                "event_handlers": [{
                    "event_pattern": "socket_file_data_received",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": script
                    }
                }]
            }),
            json!({
                "type": "open_server",
                "base_stack": "socket_file",
                "startup_params": { "socket_path": "./netget.sock" },
                "event_handlers": [
                    {
                        "event_pattern": "socket_file_connection_opened",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "send_socket_data",
                                "data": "READY\n"
                            }]
                        }
                    },
                    {
                        "event_pattern": "socket_file_data_received",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "send_socket_data",
                                "data": "ACK\n"
                            }]
                        }
                    }
                ]
            }),
        )
    }
}

// Implement Server trait (server-specific functionality)
impl Server for SocketFileProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            // Extract socket_path and send_first from startup_params
            let socket_path = ctx
                .startup_params
                .as_ref()
                .map(|p| p.get_string("socket_path"))
                .transpose()?
                .ok_or_else(|| anyhow::anyhow!("socket_path parameter is required"))?;

            let send_first = ctx
                .startup_params
                .as_ref()
                .map(|p| p.get_optional_bool("send_first"))
                .transpose()?
                .flatten()
                .unwrap_or(false);

            // Both read bounds are the operator's to tune; the defaults are argued beside
            // FIRST_BYTE_READ_TIMEOUT and IDLE_BETWEEN_MESSAGES_TIMEOUT in mod.rs.
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

            use crate::server::socket_file::SocketFileServer;
            let socket_path_buf = std::path::PathBuf::from(socket_path);
            let _result_path = SocketFileServer::spawn_with_llm_actions(
                socket_path_buf,
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                send_first,
                ctx.server_id,
                first_byte_timeout_secs,
                idle_timeout_secs,
            )
            .await?;

            // Return a dummy SocketAddr since Unix sockets don't have IP addresses
            // Store the actual socket path in the server instance
            Ok("127.0.0.1:0".parse().unwrap())
        })
    }

    fn execute_action(&self, action: serde_json::Value) -> Result<ActionResult> {
        let action_type = action
            .get("type")
            .and_then(|v| v.as_str())
            .context("Missing 'type' field in action")?;

        match action_type {
            "send_socket_data" => self.execute_send_socket_data(action),
            "wait_for_more" => Ok(ActionResult::WaitForMore),
            // `close_this_connection` is the advertised name; `close_connection` is accepted
            // as an alias because models reach for it out of habit.
            "close_this_connection" | "close_connection" => Ok(ActionResult::CloseConnection),
            _ => Err(anyhow::anyhow!("Unknown socket file action: {action_type}")),
        }
    }
}

impl SocketFileProtocol {
    /// Execute send_socket_data sync action
    fn execute_send_socket_data(&self, action: serde_json::Value) -> Result<ActionResult> {
        let data = action
            .get("data")
            .and_then(|v| v.as_str())
            .context("Missing 'data' parameter")?;

        Ok(ActionResult::Output(decode_outbound_data(data, &action)?))
    }
}

/// Turn the `data` field of an outbound action into the exact bytes to put on the wire,
/// honouring the action's optional `encoding` field.
///
/// - `encoding` absent or `"utf8"`: the string's UTF-8 bytes are sent verbatim.
/// - `encoding` = `"hex"`: `data` is decoded as hex, so `"48656c6c6f"` sends `Hello`.
///
/// There is deliberately no auto-detection: `"48656c6c6f"` is both valid text and valid hex,
/// so the caller must say which it means. Inbound data carries the same `encoding` field on
/// the `socket_file_data_received` event, which makes echoing a payload back symmetric.
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
                 Hex payloads are two hex digits per byte with no separators. To send this \
                 value as literal text, omit 'encoding' or set it to \"utf8\"."
            )
        }),
        other => Err(anyhow::anyhow!(
            "Invalid 'encoding' value {other:?}. Valid values are \"utf8\" (default, send the \
             characters of 'data' as-is) and \"hex\" (decode 'data' as hex-encoded bytes)."
        )),
    }
}

/// Shared `encoding` parameter for every action that carries an outbound `data` field.
fn encoding_parameter() -> Parameter {
    Parameter {
        name: "encoding".to_string(),
        type_hint: "string".to_string(),
        description: "How to convert 'data' into the bytes put on the wire. \"utf8\" (the default when omitted) sends the characters of 'data' unchanged - use it for text protocols. \"hex\" decodes 'data' as hex-encoded bytes, two hex digits per byte - use it for binary protocols, e.g. {\"data\": \"48656c6c6f\", \"encoding\": \"hex\"} sends the 5 bytes 'Hello', whereas the same 'data' without \"encoding\": \"hex\" sends the 10 characters 4-8-6-5-6-c-6-c-6-f. No other values are accepted".to_string(),
        required: false,
    }
}

/// Action definition for send_socket_data (sync)
fn send_socket_data_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_socket_data".to_string(),
        description: "Send data over the current Unix domain socket connection. The 'data' field holds the payload and the optional 'encoding' field says how to turn it into bytes: omit 'encoding' (or use \"utf8\") to send the string's characters as-is, or set \"encoding\": \"hex\" to send 'data' decoded from hex. There is no auto-detection - a string like \"48656c6c6f\" is sent literally unless you set \"encoding\": \"hex\".".to_string(),
        parameters: vec![
            Parameter {
                name: "data".to_string(),
                type_hint: "string".to_string(),
                description: "Data to send. Interpreted according to 'encoding': by default the characters of this string are sent as-is (UTF-8)".to_string(),
                required: true,
            },
            encoding_parameter(),
        ],
        example: json!({
            "type": "send_socket_data",
            "data": "ACK\n",
            "encoding": "utf8"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> SOCK {data_len}B")
                .with_debug("SOCK send_socket_data: data_len={data_len}"),
        ),
    }
}

/// Action definition for wait_for_more (sync)
fn wait_for_more_action() -> ActionDefinition {
    ActionDefinition {
        name: "wait_for_more".to_string(),
        description: "Wait for more data before responding (accumulate incomplete data)"
            .to_string(),
        parameters: vec![],
        example: json!({
            "type": "wait_for_more"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> SOCK waiting for more")
                .with_debug("SOCK wait_for_more"),
        ),
    }
}

/// Action definition for close_this_connection (sync)
fn close_this_connection_action() -> ActionDefinition {
    ActionDefinition {
        name: "close_this_connection".to_string(),
        description: "Close the current socket file connection".to_string(),
        parameters: vec![],
        example: json!({
            "type": "close_this_connection"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> SOCK close connection")
                .with_debug("SOCK close_this_connection"),
        ),
    }
}

// ============================================================================
// Socket File Action Constants
// ============================================================================

pub static SEND_SOCKET_DATA_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(send_socket_data_action);
pub static WAIT_FOR_MORE_ACTION: LazyLock<ActionDefinition> = LazyLock::new(wait_for_more_action);
pub static CLOSE_THIS_CONNECTION_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(close_this_connection_action);

// ============================================================================
// Socket File Event Type Constants
// ============================================================================

/// Socket file connection opened event - triggered when new connection is established
pub static SOCKET_FILE_CONNECTION_OPENED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "socket_file_connection_opened",
        "New Unix domain socket connection established (send initial greeting/banner if needed)",
        json!({
            "type": "send_socket_data",
            "data": "READY\n"
        }),
    )
    .with_parameters(vec![])
    .with_actions(vec![
        SEND_SOCKET_DATA_ACTION.clone(),
        CLOSE_THIS_CONNECTION_ACTION.clone(),
    ])
});

/// Socket file data received event - triggered when data is received on connection
pub static SOCKET_FILE_DATA_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "socket_file_data_received",
        "Data received on Unix domain socket connection",
        json!({
            "type": "send_socket_data",
            "data": "ACK\n"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "data".to_string(),
            type_hint: "string".to_string(),
            description: "The data received from the client. Read it according to the 'encoding' field of this event".to_string(),
            required: true,
        },
        Parameter {
            name: "encoding".to_string(),
            type_hint: "string".to_string(),
            description: "How to read 'data': \"utf8\" means 'data' is the received bytes as literal text, \"hex\" means 'data' is the received bytes hex-encoded (two hex digits per byte, used whenever the bytes are not all printable ASCII). To echo the received bytes back unchanged, pass the same 'data' and 'encoding' to send_socket_data".to_string(),
            required: true,
        },
    ])
    .with_actions(vec![
        SEND_SOCKET_DATA_ACTION.clone(),
        WAIT_FOR_MORE_ACTION.clone(),
        CLOSE_THIS_CONNECTION_ACTION.clone(),
    ])
});

/// Get socket file event types
pub fn get_socket_file_event_types() -> Vec<EventType> {
    vec![
        SOCKET_FILE_CONNECTION_OPENED_EVENT.clone(),
        SOCKET_FILE_DATA_RECEIVED_EVENT.clone(),
    ]
}

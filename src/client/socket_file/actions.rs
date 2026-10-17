//! Socket File client protocol actions implementation

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

/// Socket File client connected event.
///
/// Carries `socket_path` and attaches the two actions a client may take on connect, so a model
/// meant to speak first has a vocabulary to do it with.
pub static SOCKET_FILE_CLIENT_CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "socket_file_connected",
        "Socket File client successfully connected to Unix domain socket",
        json!({
            "type": "send_socket_file_data",
            "data": "PING\n"
        }),
    )
    .with_parameters(vec![Parameter {
        name: "socket_path".to_string(),
        type_hint: "string".to_string(),
        description: "Unix domain socket path".to_string(),
        required: true,
    }])
    .with_actions(vec![
        send_socket_file_data_action("Send data to the Unix domain socket"),
        disconnect_action(),
    ])
});

/// Socket File client data received event.
///
/// `data` + `encoding` mirror the socket_file *server*, so echoing a payload back means passing
/// the same two fields to `send_socket_file_data`. The event used to carry `data_hex` only, which
/// made every text exchange a hex-encoding exercise for the model - the shape CLAUDE.md's "never
/// put raw bytes in event data" rule exists to prevent.
pub static SOCKET_FILE_CLIENT_DATA_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "socket_file_data_received",
        "Data received from Unix domain socket",
        json!({
            "type": "send_socket_file_data",
            "data": "PONG\n"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "data".to_string(),
            type_hint: "string".to_string(),
            description: "The bytes received from the socket. Read it according to 'encoding'."
                .to_string(),
            required: true,
        },
        Parameter {
            name: "encoding".to_string(),
            type_hint: "string".to_string(),
            description:
                "How to read 'data': \"utf8\" means literal text, \"hex\" means the bytes \
                hex-encoded (used whenever they are not all printable ASCII). To echo the bytes \
                back unchanged, pass the same 'data' and 'encoding' to send_socket_file_data."
                    .to_string(),
            required: true,
        },
        Parameter {
            name: "data_length".to_string(),
            type_hint: "number".to_string(),
            description: "Length of the received data in bytes".to_string(),
            required: true,
        },
    ])
    .with_actions(vec![
        send_socket_file_data_action("Send data in response to the bytes just received"),
        wait_for_more_action(),
        disconnect_action(),
    ])
});

/// Turn an outbound action's payload into bytes.
///
/// `data` plus an optional `encoding` (`"utf8"` default, `"hex"`) is the declared shape and
/// mirrors the socket_file server. `data_hex` is still accepted because it was the only shape
/// this client ever advertised and models reach for it out of habit; it means exactly
/// `{"data": ..., "encoding": "hex"}`.
fn decode_outbound_data(action: &serde_json::Value) -> Result<Vec<u8>> {
    if let Some(data) = action.get("data").and_then(|v| v.as_str()) {
        let encoding = action
            .get("encoding")
            .and_then(|v| v.as_str())
            .unwrap_or("utf8");
        return match encoding {
            "utf8" => Ok(data.as_bytes().to_vec()),
            "hex" => hex::decode(data).map_err(|e| {
                anyhow::anyhow!(
                    "'data' was declared as \"encoding\": \"hex\" but is not valid hex ({e}). \
                     Hex payloads are two hex digits per byte with no separators. To send this \
                     value as literal text, omit 'encoding' or set it to \"utf8\"."
                )
            }),
            other => Err(anyhow::anyhow!(
                "Invalid 'encoding' value {other:?}. Valid values are \"utf8\" (default, send \
                 the characters of 'data' as-is) and \"hex\" (decode 'data' as hex-encoded \
                 bytes)."
            )),
        };
    }
    if let Some(hex_str) = action.get("data_hex").and_then(|v| v.as_str()) {
        return hex::decode(hex_str).map_err(|e| {
            anyhow::anyhow!(
                "'data_hex' is not valid hex ({e}). Prefer 'data' with the optional 'encoding' \
                 field: text as {{\"data\": \"PING\"}}, bytes as \
                 {{\"data\": \"48656c6c6f\", \"encoding\": \"hex\"}}."
            )
        });
    }
    Err(anyhow::anyhow!(
        "Missing 'data' field. Send text as {{\"data\": \"PING\"}} or bytes as \
         {{\"data\": \"48656c6c6f\", \"encoding\": \"hex\"}}."
    ))
}

/// Shared `encoding` parameter for the outbound `data` field.
fn encoding_parameter() -> Parameter {
    Parameter {
        name: "encoding".to_string(),
        type_hint: "string".to_string(),
        description: "How to convert 'data' into the bytes put on the socket. \"utf8\" (the \
            default when omitted) sends the characters of 'data' unchanged - use it for text. \
            \"hex\" decodes 'data' as hex-encoded bytes, two hex digits per byte - use it for \
            binary, e.g. {\"data\": \"48656c6c6f\", \"encoding\": \"hex\"} sends the 5 bytes \
            'Hello'. No other values are accepted"
            .to_string(),
        required: false,
    }
}

/// `send_socket_file_data`, with a caller-supplied lead line so the async (user-triggered) and
/// sync (event response) copies read correctly without diverging in their fields.
fn send_socket_file_data_action(description: &str) -> ActionDefinition {
    ActionDefinition {
        name: "send_socket_file_data".to_string(),
        description: format!(
            "{description}. The 'data' field holds the payload and the optional 'encoding' field \
             says how to turn it into bytes: omit 'encoding' (or use \"utf8\") to send the \
             characters as-is, or set \"encoding\": \"hex\" to send 'data' decoded from hex. \
             There is no auto-detection."
        ),
        parameters: vec![
            Parameter {
                name: "data".to_string(),
                type_hint: "string".to_string(),
                description: "Data to send. Interpreted according to 'encoding': by default the \
                    characters of this string are sent as-is (UTF-8)."
                    .to_string(),
                required: true,
            },
            encoding_parameter(),
        ],
        example: json!({
            "type": "send_socket_file_data",
            "data": "PING\n",
            "encoding": "utf8"
        }),
        log_template: Some(
            crate::protocol::log_template::LogTemplate::new()
                .with_info("-> SOCK {data_len}B")
                .with_debug("SOCK send_socket_file_data: data_len={data_len}"),
        ),
    }
}

/// `disconnect`: close the Unix socket connection and end the read loop.
fn disconnect_action() -> ActionDefinition {
    ActionDefinition {
        name: "disconnect".to_string(),
        description: "Close the Unix domain socket connection and stop reading from it."
            .to_string(),
        parameters: vec![],
        example: json!({
            "type": "disconnect"
        }),
        log_template: Some(
            crate::protocol::log_template::LogTemplate::new()
                .with_info("-> SOCK disconnect")
                .with_debug("SOCK disconnect"),
        ),
    }
}

/// `wait_for_more`: the bytes just received are an incomplete message; say nothing yet.
fn wait_for_more_action() -> ActionDefinition {
    ActionDefinition {
        name: "wait_for_more".to_string(),
        description: "Wait for more data before responding (the bytes received so far are an \
            incomplete message)."
            .to_string(),
        parameters: vec![],
        example: json!({
            "type": "wait_for_more"
        }),
        log_template: None,
    }
}

/// Socket File client protocol action handler
pub struct SocketFileClientProtocol;

impl SocketFileClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

impl Default for SocketFileClientProtocol {
    fn default() -> Self {
        Self::new()
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for SocketFileClientProtocol {
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![
            send_socket_file_data_action("Send data to the Unix domain socket"),
            disconnect_action(),
        ]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            send_socket_file_data_action("Send data in response to the bytes just received"),
            wait_for_more_action(),
            disconnect_action(),
        ]
    }
    fn protocol_name(&self) -> &'static str {
        "SocketFile"
    }
    /// The two event types this client raises - the very statics its read loop emits.
    ///
    /// This used to build two *separate* `EventType`s here whose example action was
    /// `{"type": "placeholder"}` and which declared neither the real parameters nor any actions,
    /// so the model was shown one description of an event and handed another at runtime.
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            SOCKET_FILE_CLIENT_CONNECTED_EVENT.clone(),
            SOCKET_FILE_CLIENT_DATA_RECEIVED_EVENT.clone(),
        ]
    }
    fn stack_name(&self) -> &'static str {
        "UnixSocket"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "socket file",
            "unix socket",
            "domain socket",
            "socket-file",
            "socketfile",
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .implementation("Tokio UnixStream for Unix domain socket connections")
            .llm_control("Full control over sent/received bytes")
            .e2e_testing("A real tokio UnixListener peer in-process; no third-party client exists")
            .notes(
                "Unix domain socket client. The peer is a local descriptor, so there is no \
                 independent third-party implementation to validate against and no route past \
                 Experimental on the usual evidence. The tests drive a real UnixListener peer \
                 in-process: connect, connect-time send, the peer's reply, the client's answer.",
            )
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "Socket File client for connecting to Unix domain sockets"
    }
    fn example_prompt(&self) -> &'static str {
        "Connect to socket file at ./app.sock and send 'HELLO'"
    }
    fn group_name(&self) -> &'static str {
        "Core"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        use serde_json::json;

        StartupExamples::new(
            // LLM mode: LLM handles Unix socket client
            json!({
                "type": "open_client",
                "remote_addr": "./app.sock",
                "base_stack": "socket-file",
                "instruction": "Connect to Unix socket and send 'PING', echo responses"
            }),
            // Script mode: Code-based socket handling
            json!({
                "type": "open_client",
                "remote_addr": "./app.sock",
                "base_stack": "socket-file",
                "event_handlers": [{
                    "event_pattern": "socket_file_data_received",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "<socket_file_handler>"
                    }
                }]
            }),
            // Static mode: Fixed socket response
            json!({
                "type": "open_client",
                "remote_addr": "./app.sock",
                "base_stack": "socket-file",
                "event_handlers": [{
                    "event_pattern": "socket_file_connected",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "send_socket_file_data",
                            "data": "HELLO\n"
                        }]
                    }
                }]
            }),
        )
    }
}

// Implement Client trait (client-specific functionality)
impl Client for SocketFileClientProtocol {
    fn connect(
        &self,
        ctx: crate::protocol::ConnectContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::client::socket_file::SocketFileClient;
            SocketFileClient::connect_with_llm_actions(
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
            "send_socket_file_data" => {
                Ok(ClientActionResult::SendData(decode_outbound_data(&action)?))
            }
            "disconnect" => Ok(ClientActionResult::Disconnect),
            "wait_for_more" => Ok(ClientActionResult::WaitForMore),
            _ => Err(anyhow::anyhow!(
                "Unknown Socket File client action: {}",
                action_type
            )),
        }
    }
}

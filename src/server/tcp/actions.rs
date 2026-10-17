//! TCP protocol actions implementation

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

/// TCP protocol action handler.
///
/// Stateless. The running server ([`crate::server::tcp::TcpServer`]) owns the connection map,
/// because only it holds the write halves. This type used to keep a second map of its own to
/// back `send_to_connection` / `list_connections` async actions; nothing ever inserted into it,
/// so `list_connections` always saw zero connections and `send_to_connection` could not route
/// anywhere. Both actions are gone — the same removal `socket_file` made for the same reason.
#[derive(Default)]
pub struct TcpProtocol;

impl TcpProtocol {
    pub fn new() -> Self {
        Self
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for TcpProtocol {
    fn get_startup_parameters(&self) -> Vec<crate::llm::actions::ParameterDefinition> {
        vec![
                crate::llm::actions::ParameterDefinition {
                    name: "send_first".to_string(),
                    type_hint: "boolean".to_string(),
                    description: "Set true when the server speaks first (a banner, a greeting, a login prompt). It is the only way tcp_connection_opened is raised: then nothing the peer sends is read until that event has been answered, a silent answer is logged as a missing greeting, and a failed one closes the connection. Left false (the default), generic TCP is client-speaks-first and no connect event is raised, so a connection costs no model call until the client sends something.".to_string(),
                    required: false,
                    example: serde_json::json!(false),
                    default: None,
                },
                crate::llm::actions::ParameterDefinition {
                    name: "first_byte_timeout_secs".to_string(),
                    type_hint: "number".to_string(),
                    description: "Seconds a connected peer may send nothing before the server \
                                  closes it. Default 300, matching the window a `manual` rule \
                                  gives a human to answer one event - a peer is often NetGet's \
                                  own client waiting for someone to use [ send message ]. \
                                  Lower it for a listener exposed to strangers."
                        .to_string(),
                    required: false,
                    example: serde_json::json!(300),
                    default: Some(serde_json::json!(super::FIRST_BYTE_READ_TIMEOUT.as_secs())),
                },
                crate::llm::actions::ParameterDefinition {
                    name: "idle_timeout_secs".to_string(),
                    type_hint: "number".to_string(),
                    description: "Seconds an established session may be silent between messages \
                                  before the server closes it. Default 900."
                        .to_string(),
                    required: false,
                    example: serde_json::json!(900),
                    default: Some(serde_json::json!(super::IDLE_BETWEEN_MESSAGES_TIMEOUT.as_secs())),
                },
            ]
    }
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        // Only `close_connection` survives here. `send_to_connection` and `list_connections`
        // were advertised for a long time and could not work: nothing ever told this type about
        // a connection, so `list_connections` always saw none, and the executor's `Output` is
        // written to whichever connection is being handled — so `send_to_connection` parsed,
        // validated and then discarded its `connection_id` and wrote to a different peer than
        // the model asked for. `socket_file` removed the same pair for the same reason.
        vec![close_connection_action()]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            send_tcp_data_action(),
            wait_for_more_action(),
            close_this_connection_action(),
        ]
    }
    fn protocol_name(&self) -> &'static str {
        "TCP"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        get_tcp_event_types()
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP"
    }
    fn keywords(&self) -> Vec<&'static str> {
        // No "ftp": it was here from before a real FTP protocol existed, and a request for an
        // FTP server resolved to raw TCP. FTP is its own protocol now and owns that keyword.
        vec!["tcp", "raw", "custom"]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Beta)
            .implementation("Manual TCP socket handling with tokio")
            .llm_control("Full byte stream control - all sent/received data")
            .e2e_testing("tokio::net::TcpStream")
            .notes("Basis for FTP, SMTP, custom protocols")
            .max_inbound_bytes(crate::server::tcp::MAX_QUEUED_BYTES)
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "Raw TCP socket server for custom protocols"
    }
    fn example_prompt(&self) -> &'static str {
        "Pretend to be FTP server on port 2121; serve file accounts.csv with 'balance,0'"
    }
    fn group_name(&self) -> &'static str {
        "Core"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        use serde_json::json;

        // The textbook deterministic case: echo received bytes straight back.
        // Inbound 'data' is hex-encoded when the bytes are not printable, so the
        // handler echoes the 'encoding' field back unchanged to stay symmetric.
        let script = r#"import json, sys
data = json.load(sys.stdin)
event = data["event"]
if data["event_type_id"] == "tcp_data_received":
    actions = [{"type": "send_tcp_data",
                "data": event.get("data", ""),
                "encoding": event.get("encoding", "utf8")}]
else:
    actions = []
print(json.dumps({"actions": actions}))"#;

        StartupExamples::new(
            // LLM mode: dynamic, per-line reasoning over a raw TCP stream.
            json!({
                "type": "open_server",
                "port": 9000,
                "base_stack": "tcp",
                "instruction": "Act as a line-based chat server: send a greeting when a client connects, and for each line of text the client sends, reply in character with a short response that references what they said."
            }),
            // Script mode: a pure echo server, no LLM call.
            json!({
                "type": "open_server",
                "port": 9000,
                "base_stack": "tcp",
                "event_handlers": [{
                    "event_pattern": "tcp_data_received",
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
                "port": 9000,
                "base_stack": "tcp",
                "event_handlers": [
                    {
                        "event_pattern": "tcp_connection_opened",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "send_tcp_data",
                                "data": "220 Welcome\r\n"
                            }]
                        }
                    },
                    {
                        "event_pattern": "tcp_data_received",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "send_tcp_data",
                                "data": "OK\r\n"
                            }]
                        }
                    }
                ]
            }),
        )
    }
}

// Implement Server trait (server-specific functionality)
impl Server for TcpProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            // Extract send_first from startup_params
            let send_first = ctx
                .startup_params
                .as_ref()
                .map(|p| p.get_optional_bool("send_first"))
                .transpose()?
                .flatten()
                .unwrap_or(false);

            // Both bounds are tunable because their right value is a property of who is on the
            // other end, which only the operator knows. The defaults serve NetGet's own client
            // waiting on a human; a listener exposed to strangers wants them much lower.
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

            use crate::server::tcp::TcpServer;
            let listen_addr = ctx.legacy_listen_addr();
            TcpServer::spawn_with_llm_actions(
                listen_addr,
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                send_first,
                ctx.server_id,
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
            // `connection_id` is accepted and ignored: every caller of this executor already
            // owns exactly one connection (the LLM path handles one; the dashboard's peer task
            // targets one). It is *optional* because [ disconnect this peer ] injects a bare
            // `{"type": "close_connection"}` (`src/tui/keymap.rs`), and requiring the field made
            // that button fail with "Missing 'connection_id' parameter" on the one protocol
            // every other protocol is told to copy.
            "close_connection" => Ok(ActionResult::CloseConnection),
            "send_tcp_data" => self.execute_send_tcp_data(action),
            "wait_for_more" => Ok(ActionResult::WaitForMore),
            "close_this_connection" => Ok(ActionResult::CloseConnection),
            _ => Err(anyhow::anyhow!("Unknown TCP action: {action_type}")),
        }
    }
}

impl TcpProtocol {
    /// Execute send_tcp_data sync action
    fn execute_send_tcp_data(&self, action: serde_json::Value) -> Result<ActionResult> {
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
/// - `encoding` absent or `"utf8"`: the string's UTF-8 bytes are sent verbatim (default,
///   backwards compatible).
/// - `encoding` = `"hex"`: `data` is decoded as hex, so `"48656c6c6f"` sends the 5 bytes
///   `Hello`.
///
/// There is deliberately no auto-detection: `"48656c6c6f"` is both valid text and valid
/// hex, so the caller must say which it means.
fn decode_outbound_data(data: &str, action: &serde_json::Value) -> Result<Vec<u8>> {
    let encoding = action
        .get("encoding")
        .and_then(|v| v.as_str())
        .unwrap_or("utf8");

    match encoding {
        "utf8" => Ok(data.as_bytes().to_vec()),
        "hex" => {
            // Tolerate whitespace/`0x` grouping that models frequently emit.
            let cleaned: String = data
                .chars()
                .filter(|c| !c.is_ascii_whitespace() && *c != ':')
                .collect();
            let cleaned = cleaned.strip_prefix("0x").unwrap_or(&cleaned);

            if cleaned.len() % 2 != 0 {
                return Err(anyhow::anyhow!(
                    "Invalid hex in 'data': expected an even number of hex digits, got {} \
                     ({data:?}). Each byte is two hex digits, e.g. \"48656c6c6f\" = \"Hello\".",
                    cleaned.len()
                ));
            }

            hex::decode(cleaned).map_err(|e| {
                anyhow::anyhow!(
                    "Invalid hex in 'data' ({data:?}): {e}. Use only 0-9/a-f, two digits per \
                     byte, e.g. \"48656c6c6f\" = \"Hello\". To send this string as literal \
                     text, omit 'encoding' or set it to \"utf8\"."
                )
            })
        }
        other => Err(anyhow::anyhow!(
            "Invalid 'encoding' value {other:?}. Valid values are \"utf8\" (default, send the \
             string's characters as-is) and \"hex\" (decode the string as hex-encoded bytes)."
        )),
    }
}

/// Shared `encoding` parameter for every action that carries an outbound `data` field.
///
/// Declared as a closed choice set (`with_choices`): the executor accepts exactly
/// `utf8` and `hex` (see [`decode_outbound_data`]), so the TUI composer offers a
/// selector and the native tool schemas advertise the pair as an enum.
fn encoding_parameter() -> Parameter {
    Parameter {
        name: "encoding".to_string(),
        type_hint: "string".to_string(),
        description: "How to convert 'data' into the bytes put on the wire. \"utf8\" (the default when omitted) sends the characters of 'data' unchanged - use it for text protocols such as FTP/SMTP/HTTP. \"hex\" decodes 'data' as hex-encoded bytes, two hex digits per byte - use it for binary protocols, e.g. {\"data\": \"48656c6c6f\", \"encoding\": \"hex\"} sends the 5 bytes 'Hello', whereas the same 'data' without \"encoding\": \"hex\" sends the 10 characters 4-8-6-5-6-c-6-c-6-f. No other values are accepted".to_string(),
        required: false,
    }
    .with_choices(["utf8", "hex"])
}

/// Action definition for close_connection (async)
///
/// `connection_id` is optional and ignored — see the executor. It stays declared so an existing
/// prompt or handler that supplies one is not rejected.
fn close_connection_action() -> ActionDefinition {
    ActionDefinition {
        name: "close_connection".to_string(),
        description: "Close the TCP connection this action is executed against. Equivalent to \
                      close_this_connection."
            .to_string(),
        parameters: vec![Parameter {
            name: "connection_id".to_string(),
            type_hint: "string".to_string(),
            description:
                "Optional and ignored: the connection being handled is always the one closed"
                    .to_string(),
            required: false,
        }],
        example: json!({
            "type": "close_connection"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("TCP close connection")
                .with_debug("TCP close_connection"),
        ),
    }
}

/// Action definition for send_tcp_data (sync)
fn send_tcp_data_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_tcp_data".to_string(),
        description: "IMPORTANT: Use this action to send data over TCP connections. This is the ONLY correct action for TCP responses - do NOT use generic 'send_data' or 'show_message' actions. The 'data' field holds the payload and the optional 'encoding' field says how to turn it into bytes: omit 'encoding' (or use \"utf8\") to send the string's characters as-is, or set \"encoding\": \"hex\" to send 'data' decoded from hex. There is no auto-detection - a string like \"48656c6c6f\" is sent literally unless you set \"encoding\": \"hex\".".to_string(),
        parameters: vec![
            Parameter {
                name: "data".to_string(),
                type_hint: "string".to_string(),
                description: "Payload to send over the TCP connection. Interpreted according to 'encoding': as literal text by default, or as hex-encoded bytes when \"encoding\": \"hex\"".to_string(),
                required: true,
            },
            encoding_parameter(),
        ],
        example: json!({
            "type": "send_tcp_data",
            "data": "220 Welcome\r\n",
            "encoding": "utf8"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> {output_bytes}B")
                .with_debug("TCP send {output_bytes}B")
                .with_trace("TCP send: {preview(data,200)}"),
        ),
    }
}

/// Action definition for wait_for_more (sync)
fn wait_for_more_action() -> ActionDefinition {
    ActionDefinition {
        name: "wait_for_more".to_string(),
        // This text has been wrong in both directions. It first promised an accumulation the
        // server did not perform, then conceded that the fragment was dropped. The server now
        // keeps it: WaitForMore pushes the payload back to the head of `queued_data`, so the
        // next event carries this fragment joined to whatever arrived after it. QUIC's action
        // of the same name still drops it — the two raw-stream protocols have drifted and
        // `src/server/quic` needs the same repair.
        description: "Answer this event with nothing and wait for the peer to send the rest. \
            Use it when the bytes you were given are an incomplete message: they are kept, and \
            the next event you receive on this connection carries them joined to everything \
            that arrives afterwards, as one payload. You do not need to copy the fragment into \
            your memory."
            .to_string(),
        parameters: vec![],
        example: json!({
            "type": "wait_for_more"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_debug("TCP waiting for more data")
                .with_trace("wait_for_more action"),
        ),
    }
}

/// Action definition for close_this_connection (sync)
fn close_this_connection_action() -> ActionDefinition {
    ActionDefinition {
        name: "close_this_connection".to_string(),
        description: "Close the current TCP connection".to_string(),
        parameters: vec![],
        example: json!({
            "type": "close_this_connection"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("TCP connection closed")
                .with_debug("TCP closing connection"),
        ),
    }
}

// ============================================================================
// TCP Action Constants
// ============================================================================

pub static SEND_TCP_DATA_ACTION: LazyLock<ActionDefinition> = LazyLock::new(send_tcp_data_action);
pub static WAIT_FOR_MORE_ACTION: LazyLock<ActionDefinition> = LazyLock::new(wait_for_more_action);
pub static CLOSE_THIS_CONNECTION_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(close_this_connection_action);

// ============================================================================
// TCP Event Type Constants
// ============================================================================

/// TCP connection opened event - triggered when new connection is established
pub static TCP_CONNECTION_OPENED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "tcp_connection_opened",
        "A client has just connected and has not sent anything yet. Raised only when the \
         server was started with send_first, which means the client is owed a greeting: send \
         the banner or prompt now with send_tcp_data. Nothing the client sends is read until \
         this is answered.",
        serde_json::json!({
            "type": "send_tcp_data",
            "data": "220 Welcome to server\r\n"
        }),
    )
    // Data: `connect_event_data()` - nothing received yet, and the answer that calls for.
    .with_actions(vec![
        SEND_TCP_DATA_ACTION.clone(),
        CLOSE_THIS_CONNECTION_ACTION.clone(),
    ])
    .with_parameters(crate::protocol::event_type::connect_event_parameters())
    .with_log_template(
        LogTemplate::new()
            .with_info("TCP connection from {client_ip}:{client_port}")
            .with_debug("TCP connection opened from {client_ip}:{client_port}")
            .with_trace("TCP connection: {json_pretty(.)}"),
    )
});

/// TCP data received event - triggered when data is received on connection
pub static TCP_DATA_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "tcp_data_received",
        "Data received on TCP connection",
        serde_json::json!({
            "type": "send_tcp_data",
            "data": "48656c6c6f",
            "encoding": "hex"
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
            description: "How to read 'data': \"utf8\" means 'data' is the received bytes as literal text, \"hex\" means 'data' is the received bytes hex-encoded (two hex digits per byte, used whenever the bytes are not all printable ASCII). To echo the received bytes back unchanged, pass the same 'data' and 'encoding' to send_tcp_data".to_string(),
            required: true,
        },
    ])
    .with_actions(vec![
        SEND_TCP_DATA_ACTION.clone(),
        WAIT_FOR_MORE_ACTION.clone(),
        CLOSE_THIS_CONNECTION_ACTION.clone(),
    ])
    .with_alternative_example(serde_json::json!({
        "type": "wait_for_more"
    }))
    // close_this_connection, not close_connection: `call_llm` builds this event's tool list
    // from the actions above, so an example naming a verb that is not in it showed the model a
    // tool it had never been given.
    .with_alternative_example(serde_json::json!({
        "type": "close_this_connection"
    }))
    .with_log_template(
        LogTemplate::new()
            .with_info("{client_ip}:{client_port} <- {data_len}B -> {response_bytes}B")
            .with_debug("TCP received {data_len}B from {client_ip}:{client_port}")
            .with_trace("TCP data: {preview(data,200)}"),
    )
});

/// Get TCP event types
pub fn get_tcp_event_types() -> Vec<EventType> {
    vec![
        TCP_CONNECTION_OPENED_EVENT.clone(),
        TCP_DATA_RECEIVED_EVENT.clone(),
    ]
}

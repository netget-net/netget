//! QUIC protocol actions implementation

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

/// QUIC protocol action handler.
///
/// Deliberately stateless. It used to carry a `streams: Arc<Mutex<HashMap<..>>>` map with
/// `add_stream` / `remove_stream` / `list_stream_ids` / `with_streams` and a `StreamData`
/// struct — nothing in the tree ever called any of them. They were left over from the
/// async `send_to_stream` / `close_stream` / `list_streams` actions that were removed for
/// having no executor that owns a quinn `SendStream` (see `get_async_actions` below).
/// A registry that is never populated reads as if the async path works; the real stream
/// map lives in `src/server/quic/mod.rs`, owned by the server task that can write to it.
#[derive(Default)]
pub struct QuicProtocol;

impl QuicProtocol {
    pub fn new() -> Self {
        Self
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for QuicProtocol {
    fn get_startup_parameters(&self) -> Vec<crate::llm::actions::ParameterDefinition> {
        // The shared TLS parameter list, minus `tls_enabled`.
        //
        // QUIC is TLS 1.3 unconditionally (RFC 9001), so a `tls_enabled` switch has no
        // meaning here - and worse, it used to gate the others: `extract_tls_config_from_params`
        // returns `Ok(None)` when `tls_enabled` is absent or false, so `cert_path`/`key_path`
        // and every self-signed field were accepted, silently discarded, and a fresh default
        // certificate generated instead. Declaring only the parameters this protocol actually
        // reads means an operator-supplied certificate now takes effect, and a caller who
        // passes `tls_enabled` gets a clean error naming the keys that do exist.
        crate::server::tls_cert_manager::get_tls_startup_parameters()
            .into_iter()
            .filter(|p| p.name != "tls_enabled")
            .collect()
    }
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        // Intentionally empty. `send_to_stream`, `close_stream` and
        // `list_streams` used to be advertised here, but nothing ever consumed
        // their results: the async (user-triggered) path has no stream context,
        // so the bytes were serialized into an ActionResult that was dropped on
        // the floor and the model was told an action had succeeded when nothing
        // reached the wire. Do not re-add them without an executor that owns the
        // quinn SendStream (see src/server/quic/CLAUDE.md).
        Vec::new()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            send_quic_data_action(),
            wait_for_more_action(),
            close_this_stream_action(),
            send_quic_datagram_action(),
        ]
    }
    fn protocol_name(&self) -> &'static str {
        "QUIC"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        get_quic_event_types()
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>UDP>QUIC"
    }
    fn keywords(&self) -> Vec<&'static str> {
        // Deliberately no `http3` keyword. This server does not speak RFC 9114,
        // so resolving "http3" here would hand a request for an HTTP/3 server a
        // raw QUIC socket that no HTTP/3 client can use - the same silent
        // mis-resolution that `ftp` -> TCP used to cause. NetGet's HTTP/3
        // *client* keeps the `http3` name because it really is HTTP/3.
        vec!["quic", "quic streams", "quic server", "raw quic"]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{
            DevelopmentState, PrivilegeRequirement, ProtocolMetadataV2,
        };

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Beta)
            // QUIC's default port is UDP 443; the preflight check only fires
            // when the requested port is actually < 1024.
            .privilege_requirement(PrivilegeRequirement::PrivilegedPort(443))
            .well_known_udp_port(443)
            .implementation("quinn v0.11 raw QUIC streams with TLS 1.3 (no HTTP/3 framing layer)")
            .llm_control(
                "Full stream control - every byte sent and received on bidirectional streams. \
                 Both directions carry an explicit `encoding` field (utf8 default, hex, \
                 base64), so arbitrary binary payloads survive a round trip.",
            )
            .e2e_testing(
                "quinn::Endpoint client + mocked LLM, tests/server/quic/e2e_test.rs. Verified: \
                 text echo, a fixed custom response, two concurrent streams, and a binary \
                 round trip in which the 8 bytes 00 ff fe 01 80 7f c3 28 (non-printable and \
                 not valid UTF-8) are sent in, handed to the model as hex, echoed back through \
                 send_quic_data with encoding=\"hex\", and asserted byte-for-byte on the \
                 client. Independent aioquic 1.3.0 peers additionally verify authenticated raw-stream exchanges.",
            )
            .notes(
                "Raw QUIC streams (RFC 9000/9001), NOT an RFC 9114 HTTP/3 server: bidirectional \
                 streams under ALPN netget-quic with no HEADERS/DATA frames and no QPACK, so real HTTP/3 \
                 clients (curl --http3, browsers, and NetGet's own http3 client) cannot talk to \
                 it. The peer must be a raw QUIC client. request_filter is not supported. \
                 RFC 9221 DATAGRAM frames are negotiated: each raises quic_datagram_received \
                 (one turn at a time per connection; Quinn's 64 KiB buffer drops the excess) \
                 and send_quic_datagram answers on the same connection - verified against \
                 aioquic and quic-go in tests/server/quic/datagram_test.rs.",
            )
            .max_inbound_bytes(crate::server::quic::MAX_STREAM_QUEUE_BYTES)
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "QUIC server with multiplexed bidirectional streams (raw stream bytes, not HTTP/3 framing)"
    }
    fn example_prompt(&self) -> &'static str {
        "QUIC stream echo server on port 4433; echo back all data received on each stream"
    }
    fn group_name(&self) -> &'static str {
        "Core"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;

        // Deterministic: echo received stream data back on the same stream, no
        // LLM call.
        // Note what this echoes: `data` AND `encoding`, passed straight through. Dropping
        // `encoding` would put a hex *string* back on the wire for any non-printable
        // payload instead of the bytes — the exact asymmetry the encoding field exists to
        // remove, and what `test_quic_binary_echo_round_trip` guards. There is also no
        // `stream_id` parameter on `send_quic_data` (the action always answers the stream
        // that raised the event), so the old example taught the model a field that does
        // not exist.
        let script = r#"import json, sys
data = json.load(sys.stdin)
event = data["event"]
if data["event_type_id"] == "quic_data_received":
    actions = [{"type": "send_quic_data",
                "data": str(event.get("data", "")),
                "encoding": event.get("encoding", "utf8")}]
else:
    actions = []
print(json.dumps({"actions": actions}))"#;

        StartupExamples::new(
            json!({
                "type": "open_server",
                "port": 4433,
                "base_stack": "quic",
                "instruction": "QUIC multiplexed stream server with TLS 1.3"
            }),
            json!({
                "type": "open_server",
                "port": 4433,
                "base_stack": "quic",
                "event_handlers": [{
                    "event_pattern": "quic_data_received",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": script
                    }
                }]
            }),
            json!({
                "type": "open_server",
                "port": 4433,
                "base_stack": "quic",
                "event_handlers": [
                    {
                        "event_pattern": "quic_stream_opened",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "send_quic_data",
                                "data": "Hello QUIC\n"
                            }]
                        }
                    },
                    {
                        "event_pattern": "quic_data_received",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "send_quic_data",
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
impl Server for QuicProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::server::quic::QuicServer;

            let _ = rustls::crypto::ring::default_provider().install_default();
            // QUIC always uses TLS 1.3, so the certificate parameters are read directly
            // rather than through `extract_tls_config_from_params`, whose `tls_enabled`
            // gate would discard them. Every parameter declared in
            // `get_startup_parameters` above is read here.
            let tls_config = match ctx.startup_params.as_ref() {
                Some(params) => {
                    crate::server::tls_cert_manager::extract_required_tls_config_from_params(params)
                        .map_err(|e| anyhow::anyhow!("Failed to create QUIC TLS config: {}", e))?
                }
                None => crate::server::tls_cert_manager::generate_default_tls_config()
                    .map_err(|e| anyhow::anyhow!("Failed to generate default TLS config: {}", e))?,
            };
            let tls_config = Some(tls_config);

            QuicServer::spawn_with_llm_actions(
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
            "send_quic_data" => self.execute_send_quic_data(action),
            "wait_for_more" => Ok(ActionResult::WaitForMore),
            "close_this_stream" => Ok(ActionResult::CloseConnection),
            "send_quic_datagram" => {
                let bytes = datagram_payload(&action)?;
                Ok(ActionResult::Custom {
                    name: DATAGRAM_RESULT.into(),
                    data: json!(hex::encode(bytes)),
                })
            }
            _ => Err(anyhow::anyhow!("Unknown QUIC action: {action_type}")),
        }
    }
}

impl QuicProtocol {
    /// Execute send_quic_data sync action
    fn execute_send_quic_data(&self, action: serde_json::Value) -> Result<ActionResult> {
        let data = action
            .get("data")
            .and_then(|v| v.as_str())
            .context("Missing 'data' parameter")?;
        let encoding = action.get("encoding").and_then(|v| v.as_str());

        let bytes = decode_quic_payload(data, encoding)?;
        anyhow::ensure!(
            bytes.len() <= crate::server::quic::MAX_STREAM_QUEUE_BYTES,
            "QUIC response exceeds 1 MiB"
        );
        Ok(ActionResult::Output(bytes))
    }
}

// ============================================================================
// Stream payload encoding
//
// A QUIC stream carries arbitrary bytes, so both directions carry an explicit
// `encoding` field beside the payload string. There is deliberately no sniffing:
// "48656c6c6f" is simultaneously valid text and valid hex, and only the sender
// knows which it means. Before this existed the two directions disagreed -
// inbound hex-encoded any non-printable payload while outbound wrote the string
// verbatim - so a QUIC echo server could not echo binary. Same shape as the
// `send_tcp_data` defect fixed in d70bb5b5.
// ============================================================================

/// Turn the `data` field of `send_quic_data` into the exact bytes written to the stream,
/// honouring the action's optional `encoding` field.
///
/// - absent, `"utf8"` or `"text"`: the string's UTF-8 bytes, verbatim (default)
/// - `"hex"`: two hex digits per byte, so `"48656c6c6f"` writes the 5 bytes `Hello`
/// - `"base64"`: standard base64, so `"SGVsbG8="` writes the same 5 bytes
///
/// `"text"` is accepted as a synonym for `"utf8"` because that is the name the inbound
/// event used before this pair was made symmetric.
pub const MAX_ENCODED_QUIC_BYTES: usize = 4 * 1024 * 1024;

pub fn decode_quic_payload(data: &str, encoding: Option<&str>) -> Result<Vec<u8>> {
    anyhow::ensure!(
        data.len() <= MAX_ENCODED_QUIC_BYTES,
        "Encoded QUIC payload exceeds 4 MiB"
    );
    anyhow::ensure!(
        encoding.is_none_or(|e| e.len() <= 16),
        "Invalid QUIC payload encoding"
    );
    use base64::Engine as _;

    match encoding.unwrap_or("utf8") {
        "utf8" | "text" => Ok(data.as_bytes().to_vec()),
        "hex" => {
            // Tolerate the whitespace / `:` grouping / `0x` prefix models often emit.
            let cleaned: String = data
                .chars()
                .filter(|c| !c.is_ascii_whitespace() && *c != ':')
                .collect();
            let cleaned = cleaned.strip_prefix("0x").unwrap_or(&cleaned);
            if cleaned.len() % 2 != 0 {
                return Err(anyhow::anyhow!(
                    "Invalid hex in 'data': expected an even number of hex digits, got {} \
                     bytes. Each byte is two hex digits, e.g. \"48656c6c6f\" = \"Hello\".",
                    cleaned.len()
                ));
            }
            hex::decode(cleaned).map_err(|e| {
                anyhow::anyhow!(
                    "Invalid hex in 'data': {e}. Use only 0-9/a-f, two digits per \
                     byte. To send this string as literal text, omit 'encoding' or set it to \
                     \"utf8\"."
                )
            })
        }
        "base64" => {
            let cleaned: String = data.chars().filter(|c| !c.is_ascii_whitespace()).collect();
            base64::engine::general_purpose::STANDARD
                .decode(&cleaned)
                .map_err(|e| {
                    anyhow::anyhow!(
                        "Invalid base64 in 'data': {e}. To send this string as \
                         literal text, omit 'encoding' or set it to \"utf8\"."
                    )
                })
        }
        other => Err(anyhow::anyhow!(
            "Invalid 'encoding' value {other:?}. Valid values are \"utf8\" (default, send the \
             string's characters as-is), \"hex\" and \"base64\"."
        )),
    }
}

/// Render bytes received on a stream for the model, with the `encoding` name that says how
/// to read them back.
///
/// Symmetric with [`decode_quic_payload`]: feeding the returned pair straight into
/// `send_quic_data`'s `data` and `encoding` puts the original bytes back on the wire.
pub fn encode_quic_payload(bytes: &[u8]) -> (String, &'static str) {
    if bytes
        .iter()
        .all(|&b| b.is_ascii_graphic() || b.is_ascii_whitespace())
    {
        (String::from_utf8_lossy(bytes).to_string(), "utf8")
    } else {
        (hex::encode(bytes), "hex")
    }
}

/// Shared `encoding` parameter for the outbound `data` field.
fn encoding_parameter() -> Parameter {
    Parameter {
        name: "encoding".to_string(),
        type_hint: "string".to_string(),
        description: "How to convert 'data' into the bytes written to the stream. \"utf8\" (the \
            default when omitted) writes the characters of 'data' unchanged - use it for text. \
            \"hex\" decodes 'data' as hex-encoded bytes, two hex digits per byte, and \
            \"base64\" as standard base64 - use one of those for binary, e.g. {\"data\": \
            \"48656c6c6f\", \"encoding\": \"hex\"} writes the 5 bytes 'Hello', whereas the same \
            'data' without \"encoding\": \"hex\" writes the 10 characters 4-8-6-5-6-c-6-c-6-f. \
            To echo a quic_data_received event back unchanged, pass its 'data' and its \
            'encoding' straight through. No other values are accepted"
            .to_string(),
        required: false,
    }
}

/// Action definition for send_quic_data (sync)
fn send_quic_data_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_quic_data".to_string(),
        description: "Send data on the QUIC stream that triggered this event. The stream carries \
            raw bytes - there is no HTTP/3 framing, so if the peer expects an HTTP-shaped reply \
            you must write the full message yourself."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "data".to_string(),
                type_hint: "string".to_string(),
                description: "Payload to write to the stream. Interpreted according to \
                    'encoding': by default the characters of this string are written as-is \
                    (UTF-8)."
                    .to_string(),
                required: true,
            },
            encoding_parameter(),
        ],
        example: json!({
            "type": "send_quic_data",
            "data": "Hello from QUIC\n",
            "encoding": "utf8"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> QUIC data")
                .with_debug("QUIC send_quic_data"),
        ),
    }
}

/// The `ActionResult::Custom` name a `send_quic_datagram` executes to; its data is the
/// payload as hex, which the connection's datagram handler decodes and sends.
pub const DATAGRAM_RESULT: &str = "quic_datagram";

/// Largest DATAGRAM payload an action may ask for. A frame must fit one UDP packet, and the
/// actual limit is the connection's (`max_datagram_size` in the events), always below this.
pub const MAX_DATAGRAM_BYTES: usize = 1500;

/// The bytes of a `send_quic_datagram` action, shared by server and client.
pub fn datagram_payload(action: &serde_json::Value) -> Result<Vec<u8>> {
    let data = action
        .get("data")
        .and_then(|v| v.as_str())
        .context("Missing 'data' parameter")?;
    let bytes = decode_quic_payload(data, action.get("encoding").and_then(|v| v.as_str()))?;
    anyhow::ensure!(
        bytes.len() <= MAX_DATAGRAM_BYTES,
        "A QUIC datagram carries at most one packet's worth ({MAX_DATAGRAM_BYTES} bytes, and \
         the connection's max_datagram_size below that); use send_quic_data for more"
    );
    Ok(bytes)
}

/// Action definition for send_quic_datagram (sync)
fn send_quic_datagram_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_quic_datagram".to_string(),
        description: "Send an unreliable RFC 9221 DATAGRAM frame on this QUIC connection: no \
            stream, no retransmission, no ordering, at most max_datagram_size bytes. Use it \
            to answer a quic_datagram_received event."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "data".to_string(),
                type_hint: "string".to_string(),
                description: "Datagram payload, read according to 'encoding' (UTF-8 text by \
                    default)."
                    .to_string(),
                required: true,
            },
            encoding_parameter(),
        ],
        example: json!({
            "type": "send_quic_datagram",
            "data": "pong",
            "encoding": "utf8"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> QUIC datagram")
                .with_debug("QUIC send_quic_datagram"),
        ),
    }
}

/// Action definition for wait_for_more (sync)
fn wait_for_more_action() -> ActionDefinition {
    ActionDefinition {
        name: "wait_for_more".to_string(),
        // The old text was "accumulate incomplete protocol data", which promises something
        // the server does not do: the payload you were shown is not prepended to the next
        // event. Only bytes that arrive *during* the LLM call are merged in. Saying so is
        // the difference between a model that stores the fragment and one that loses it.
        description: "Answer this event with nothing and wait for the peer to send more. Use \
            it when the bytes you were given are an incomplete message. IMPORTANT: the bytes \
            in THIS event are not repeated in the next one — each event carries only what \
            has arrived since the last. If you need this fragment to make sense of what comes \
            next, put it in your memory now, because you will not be shown it again."
            .to_string(),
        parameters: vec![],
        example: json!({
            "type": "wait_for_more"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("QUIC wait for more")
                .with_debug("QUIC wait_for_more"),
        ),
    }
}

/// Action definition for close_this_stream (sync)
fn close_this_stream_action() -> ActionDefinition {
    ActionDefinition {
        name: "close_this_stream".to_string(),
        description: "Close the current QUIC stream".to_string(),
        parameters: vec![],
        example: json!({
            "type": "close_this_stream"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("QUIC close this stream")
                .with_debug("QUIC close_this_stream"),
        ),
    }
}

// ============================================================================
// QUIC Action Constants
// ============================================================================

pub static SEND_QUIC_DATA_ACTION: LazyLock<ActionDefinition> = LazyLock::new(send_quic_data_action);
pub static WAIT_FOR_MORE_ACTION: LazyLock<ActionDefinition> = LazyLock::new(wait_for_more_action);
pub static CLOSE_THIS_STREAM_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(close_this_stream_action);
pub static SEND_QUIC_DATAGRAM_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(send_quic_datagram_action);

// ============================================================================
// QUIC Event Type Constants
// ============================================================================

/// QUIC connection opened event - triggered when new connection is established
pub static QUIC_CONNECTION_OPENED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "quic_connection_opened",
        "A QUIC connection was established (TLS 1.3 complete), but the client has not opened a \
         stream yet. Purely informational: every send action needs a stream to write to, and \
         none exists yet. Act on quic_stream_opened instead.",
        json!({"type": "show_message", "message": "QUIC connection established"}),
    )
    // No parameters - just connection opened notification
    .with_log_template(
        LogTemplate::new()
            .with_info("QUIC connection opened")
            .with_debug("QUIC connection established with TLS 1.3")
            .with_trace("QUIC connection: {json_pretty(.)}"),
    )
    // Deliberately none: send_quic_data and close_this_stream both address a stream, and this
    // event fires before any stream exists. `.with_no_actions()` rather than an empty list so
    // this reads as intentional - see tests/event_action_declarations_test.rs.
    .with_no_actions()
});

/// QUIC stream opened event - triggered when client opens a new stream
pub static QUIC_STREAM_OPENED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "quic_stream_opened",
        "New bidirectional stream opened by client",
        json!({"type": "send_quic_data", "data": "Hello QUIC"}),
    )
    .with_parameters(vec![Parameter {
        name: "stream_id".to_string(),
        type_hint: "string".to_string(),
        description: "The stream ID (QUIC uses per-connection stream numbering)".to_string(),
        required: true,
    }])
    .with_log_template(
        LogTemplate::new()
            .with_info("QUIC stream opened: {stream_id}")
            .with_debug("QUIC stream {stream_id} opened")
            .with_trace("QUIC stream: {json_pretty(.)}"),
    )
    .with_actions(vec![
        SEND_QUIC_DATA_ACTION.clone(),
        CLOSE_THIS_STREAM_ACTION.clone(),
    ])
});

/// QUIC data received event - triggered when data is received on a stream
pub static QUIC_DATA_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "quic_data_received",
        "Data received on QUIC stream",
        json!({"type": "placeholder", "event_id": "quic_data_received"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "stream_id".to_string(),
            type_hint: "string".to_string(),
            description: "The stream ID this data was received on".to_string(),
            required: true,
        },
        Parameter {
            name: "data".to_string(),
            type_hint: "string".to_string(),
            description: "The data received on the stream. Read it according to the \
                    'encoding' field of this event."
                .to_string(),
            required: true,
        },
        Parameter {
            name: "encoding".to_string(),
            type_hint: "string".to_string(),
            description: "How to read 'data': \"utf8\" means 'data' is the received bytes as \
                    literal text, \"hex\" means 'data' is the received bytes hex-encoded (two \
                    hex digits per byte, used whenever the bytes are not all printable ASCII). \
                    To echo the received bytes back unchanged, pass the same 'data' and the same \
                    'encoding' to send_quic_data."
                .to_string(),
            required: true,
        },
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("QUIC data on {stream_id}")
            .with_debug("QUIC data received on stream {stream_id}")
            .with_trace("QUIC data: {json_pretty(.)}"),
    )
    .with_actions(vec![
        SEND_QUIC_DATA_ACTION.clone(),
        WAIT_FOR_MORE_ACTION.clone(),
        CLOSE_THIS_STREAM_ACTION.clone(),
    ])
});

/// An RFC 9221 DATAGRAM frame arrived on a connection.
pub static QUIC_DATAGRAM_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "quic_datagram_received",
        "An unreliable QUIC DATAGRAM frame (RFC 9221) arrived on the connection - not on a \
         stream. Answer with send_quic_datagram, or with nothing: a datagram needs no reply.",
        json!({"type": "send_quic_datagram", "data": "pong"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "data".to_string(),
            type_hint: "string".to_string(),
            description: "The datagram's payload, read according to 'encoding'".to_string(),
            required: true,
        },
        Parameter {
            name: "encoding".to_string(),
            type_hint: "string".to_string(),
            description: "\"utf8\" when the payload is printable text, \"hex\" otherwise. \
                To echo it, pass 'data' and 'encoding' to send_quic_datagram unchanged."
                .to_string(),
            required: true,
        },
        Parameter {
            name: "bytes".to_string(),
            type_hint: "number".to_string(),
            description: "Payload length in bytes".to_string(),
            required: true,
        },
        Parameter {
            name: "max_datagram_size".to_string(),
            type_hint: "number".to_string(),
            description: "Largest datagram payload the peer accepts now; a reply must fit"
                .to_string(),
            required: true,
        },
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("QUIC datagram ({bytes} bytes)")
            .with_debug("QUIC datagram received: {bytes} bytes")
            .with_trace("QUIC datagram: {json_pretty(.)}"),
    )
    .with_actions(vec![SEND_QUIC_DATAGRAM_ACTION.clone()])
});

/// Get QUIC event types
pub fn get_quic_event_types() -> Vec<EventType> {
    vec![
        QUIC_CONNECTION_OPENED_EVENT.clone(),
        QUIC_STREAM_OPENED_EVENT.clone(),
        QUIC_DATA_RECEIVED_EVENT.clone(),
        QUIC_DATAGRAM_RECEIVED_EVENT.clone(),
    ]
}

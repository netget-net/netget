//! UDP protocol actions implementation

use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::EventType;
use crate::state::app_state::AppState;
use anyhow::{Context, Result};
use serde_json::json;
use std::net::SocketAddr;
use std::sync::{Arc, LazyLock};
use tokio::net::UdpSocket;

/// UDP protocol action handler
pub struct UdpProtocol {
    /// The running server's socket, when this instance belongs to one.
    ///
    /// `None` for the registry's copy (`UdpProtocol::new()`), which only describes actions and
    /// events. `send_to_address` needs it and says so when it is missing.
    socket: Option<Arc<UdpSocket>>,
}

impl Default for UdpProtocol {
    fn default() -> Self {
        Self::new()
    }
}

impl UdpProtocol {
    pub fn new() -> Self {
        Self { socket: None }
    }

    pub fn with_socket(socket: Arc<UdpSocket>) -> Self {
        Self {
            socket: Some(socket),
        }
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for UdpProtocol {
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![send_to_address_action()]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![send_udp_response_action(), ignore_datagram_action()]
    }
    fn protocol_name(&self) -> &'static str {
        "UDP"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        get_udp_event_types()
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>UDP"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["udp"]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, PortTransport, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .port_transport(PortTransport::Udp)
            .connectionless()
            // Deliberately silent: raw UDP has no error vocabulary of its own. Whatever the payload
            // protocol is, NetGet does not know it on this path, so any bytes sent on failure would
            // be a guess a peer might parse as an answer.
            .deliberately_silent()
            .state(DevelopmentState::Beta)
            .implementation("Manual UDP socket handling with tokio")
            .llm_control("Full datagram control - all sent/received data")
            .e2e_testing("std::net::UdpSocket")
            .notes("Stateless, used by DNS/DHCP/NTP")
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "UDP datagram server"
    }
    fn example_prompt(&self) -> &'static str {
        "Listen on port 5000 via UDP"
    }
    fn group_name(&self) -> &'static str {
        "Core"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;

        // Deterministic: reply "PONG" to every datagram, no LLM call.
        let script = r#"import json, sys
data = json.load(sys.stdin)
event = data["event"]
if data["event_type_id"] == "udp_datagram_received":
    actions = [{"type": "send_udp_response", "data": "PONG"}]
else:
    actions = []
print(json.dumps({"actions": actions}))"#;

        StartupExamples::new(
            json!({
                "type": "open_server",
                "port": 9000,
                "base_stack": "udp",
                "instruction": "UDP echo server that responds to datagrams"
            }),
            json!({
                "type": "open_server",
                "port": 9000,
                "base_stack": "udp",
                "event_handlers": [{
                    "event_pattern": "udp_datagram_received",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": script
                    }
                }]
            }),
            json!({
                "type": "open_server",
                "port": 9000,
                "base_stack": "udp",
                "event_handlers": [{
                    "event_pattern": "udp_datagram_received",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "send_udp_response",
                            "data": "PONG"
                        }]
                    }
                }]
            }),
        )
    }
}

// Implement Server trait (server-specific functionality)
impl Server for UdpProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::server::udp::UdpServer;
            UdpServer::spawn_with_llm_actions(
                ctx.legacy_listen_addr(),
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.server_id,
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
            "send_to_address" => self.execute_send_to_address(action),
            "send_udp_response" => self.execute_send_udp_response(action),
            "ignore_datagram" => Ok(ActionResult::NoAction),
            _ => Err(anyhow::anyhow!("Unknown UDP action: {}", action_type)),
        }
    }
}

impl UdpProtocol {
    /// Turn an action's `data` field into the bytes to put on the wire.
    ///
    /// `encoding` selects the interpretation:
    /// - `"text"` (or `"utf8"`) - the string's UTF-8 bytes, verbatim
    /// - `"hex"`   - hex-decoded, and an error if it is not valid hex
    /// - absent or `"auto"` - hex if the string happens to parse as hex, otherwise text
    ///
    /// `"utf8"` is accepted because the TCP server's equivalent field spells it that way, and a
    /// model that has just been writing `send_tcp_data` reaches for it here. It used to be
    /// rejected outright with "Unknown encoding 'utf8'", which lost the whole datagram over a
    /// spelling.
    ///
    /// `auto` is the historical behaviour and stays the default so existing prompts, handlers
    /// and tests keep working, but it is genuinely ambiguous and worth avoiding: any even-length
    /// string of hex digits is taken as hex. `{"data": "1234"}` puts two bytes (0x12 0x34) on
    /// the wire, not the four characters "1234"; so do "abcd", "DEADBEEF" and "0000". Pass
    /// `"encoding": "text"` whenever the payload is text.
    ///
    /// When `auto` actually resolves to hex the guess is logged at WARN. It is the one case
    /// where a caller can be silently misunderstood, and the whole reason the TCP server was
    /// given an explicit `encoding` field instead (see the top-level CLAUDE.md); making it
    /// visible is what separates "the model chose hex" from "we guessed hex at its text".
    fn decode_payload(action: &serde_json::Value) -> Result<Vec<u8>> {
        let data = action
            .get("data")
            .and_then(|v| v.as_str())
            .context("Missing 'data' parameter")?;

        match action.get("encoding").and_then(|v| v.as_str()) {
            Some("text") | Some("utf8") => Ok(data.as_bytes().to_vec()),
            Some("hex") => hex::decode(data)
                .context("encoding is 'hex' but 'data' is not valid hex")
                .map_err(Into::into),
            Some(other) if other != "auto" => Err(anyhow::anyhow!(
                "Unknown encoding '{}': expected 'text' (or 'utf8'), 'hex' or 'auto'",
                other
            )),
            _ => match hex::decode(data) {
                Ok(bytes) => {
                    tracing::warn!(
                        "UDP 'data' had no 'encoding' and parses as hex, so {} characters were \
                         decoded to {} bytes. If it was meant as text, pass \
                         \"encoding\": \"text\" - this guess is the one way a payload can be \
                         silently corrupted here.",
                        data.len(),
                        bytes.len()
                    );
                    Ok(bytes)
                }
                Err(_) => Ok(data.as_bytes().to_vec()),
            },
        }
    }

    /// Execute send_to_address async action.
    ///
    /// The address used to be parsed for validation and then **discarded**: the result was a
    /// plain `Output`, and the handler in `mod.rs` writes every `Output` back to the peer that
    /// sent the current datagram. So an action whose entire purpose is "send somewhere else"
    /// sent to the same place as `send_udp_response`, and the model was never told.
    ///
    /// It now writes the datagram itself, through the server's own socket, and returns
    /// `NoAction` so `mod.rs` does not additionally echo the payload to the current peer.
    /// `try_send_to` rather than `send_to` because this executor is synchronous; a UDP send
    /// does not block in practice, and the one case where it can (a full socket buffer) is
    /// reported rather than swallowed.
    fn execute_send_to_address(&self, action: serde_json::Value) -> Result<ActionResult> {
        let address = action
            .get("address")
            .and_then(|v| v.as_str())
            .context("Missing 'address' parameter")?;

        let addr: SocketAddr = address.parse().context("Invalid socket address format")?;
        let payload = Self::decode_payload(&action)?;

        let Some(socket) = self.socket.as_ref() else {
            // Phrased so the whole-tree example audit classifies this as needing runtime
            // context, which is exactly what it is: the registry's copy of this protocol has no
            // socket, only the one the running server built does.
            return Err(anyhow::anyhow!(
                "send_to_address can only run while answering a udp_datagram_received event on a \
                 running UDP server: no socket is bound in this context"
            ));
        };

        match socket.try_send_to(&payload, addr) {
            Ok(sent) => {
                tracing::debug!("UDP send_to_address: {} bytes to {}", sent, addr);
                Ok(ActionResult::NoAction)
            }
            Err(e) => Err(anyhow::anyhow!(
                "send_to_address could not write {} bytes to {}: {}",
                payload.len(),
                addr,
                e
            )),
        }
    }

    /// Execute send_udp_response sync action
    fn execute_send_udp_response(&self, action: serde_json::Value) -> Result<ActionResult> {
        Ok(ActionResult::Output(Self::decode_payload(&action)?))
    }
}

/// The `encoding` parameter shared by the two sending actions.
fn encoding_parameter() -> Parameter {
    Parameter {
        name: "encoding".to_string(),
        type_hint: "string".to_string(),
        description: "How to read 'data': 'text' (or 'utf8') for literal UTF-8, 'hex' for \
                      hex-decoded binary, 'auto' (the default) to guess. ALWAYS set it \
                      explicitly - under 'auto' any even-length run of hex digits is taken as \
                      hex, so \"1234\" sends the two bytes 0x12 0x34 rather than the four \
                      characters, and so do \"abcd\", \"DEADBEEF\" and \"0000\". The \
                      udp_datagram_received event tells you which encoding it used; reply with \
                      the same one."
            .to_string(),
        required: false,
    }
    .with_choices(["text", "hex", "auto"])
}

/// Action definition for send_to_address
fn send_to_address_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_to_address".to_string(),
        description: "Send a UDP datagram to an address other than the current peer, from this \
                      server's own socket. Use send_udp_response to answer the peer that sent \
                      the datagram you are handling."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "address".to_string(),
                type_hint: "string".to_string(),
                description: "Target address in format 'IP:port' (e.g., '127.0.0.1:8080')"
                    .to_string(),
                required: true,
            },
            Parameter {
                name: "data".to_string(),
                type_hint: "string".to_string(),
                description: "Data to send (see 'encoding')".to_string(),
                required: true,
            },
            encoding_parameter(),
        ],
        example: json!({
            "type": "send_to_address",
            "address": "127.0.0.1:8080",
            "data": "Hello from UDP",
            "encoding": "text"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> UDP to {address}")
                .with_debug("UDP send_to_address: address={address}"),
        ),
    }
}

/// Action definition for send_udp_response
fn send_udp_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_udp_response".to_string(),
        description: "Send UDP response back to the peer that sent the current datagram. To \
                      send the datagram back unchanged (an echo), put the event's data_preview \
                      in data and its data_encoding in encoding - that is the datagram itself, \
                      not a description of it."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "data".to_string(),
                type_hint: "string".to_string(),
                description: "Response payload, sent exactly as written (see 'encoding'). \
                              The literal bytes to send: for an echo, the event's data_preview."
                    .to_string(),
                required: true,
            },
            encoding_parameter(),
        ],
        example: json!({
            "type": "send_udp_response",
            "data": "Response data",
            "encoding": "text"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> UDP response {output_bytes}B")
                .with_debug("UDP send_udp_response: {output_bytes}B")
                .with_trace("UDP response: {preview(data,200)}"),
        ),
    }
}

/// Action definition for ignore_datagram
fn ignore_datagram_action() -> ActionDefinition {
    ActionDefinition {
        name: "ignore_datagram".to_string(),
        description: "Ignore this datagram and don't send a response".to_string(),
        parameters: vec![],
        example: json!({
            "type": "ignore_datagram"
        }),
        log_template: Some(LogTemplate::new().with_debug("UDP ignore_datagram")),
    }
}

// ============================================================================
// UDP Event Type Constants
// ============================================================================

pub static UDP_DATAGRAM_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "udp_datagram_received",
        "UDP datagram received from a peer. Reply in the same encoding the event reports.",
        json!({
            "type": "send_udp_response",
            "data": "PONG",
            "encoding": "text"
        }),
    )
    .with_alternative_example(json!({
        "type": "send_udp_response",
        "data": "48656c6c6f",
        "encoding": "hex"
    }))
    .with_parameters(vec![
        Parameter {
            name: "peer_address".to_string(),
            type_hint: "string".to_string(),
            description: "Source address of the datagram (IP:port)".to_string(),
            required: true,
        },
        Parameter {
            name: "data_length".to_string(),
            type_hint: "number".to_string(),
            description: "Length of the received data in bytes".to_string(),
            required: true,
        },
        Parameter {
            name: "data_encoding".to_string(),
            type_hint: "string".to_string(),
            description: "How data_preview is rendered: 'text' if the payload is printable \
                          ASCII, otherwise 'hex'. Use the same value when replying."
                .to_string(),
            required: true,
        },
        Parameter {
            name: "data_preview".to_string(),
            type_hint: "string".to_string(),
            description: "The received payload itself, as text or hex per data_encoding. It \
                          is the whole datagram unless it ends in '...' (payloads over 200 \
                          bytes are cut there). Echoing means sending this string back."
                .to_string(),
            required: false,
        },
    ])
    // `send_to_address` belongs here as well as in the async list. `call_llm` builds a server's
    // tool list from the *event*, so leaving it out meant the only place the action could
    // actually work — inside the running server, which is the only context that owns a socket —
    // was the one place the model was never offered it. Outside that context it now says so
    // rather than pretending to have sent something.
    .with_actions(vec![
        send_udp_response_action(),
        send_to_address_action(),
        ignore_datagram_action(),
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("UDP {data_length}B from {peer_address}")
            .with_debug("UDP datagram: {data_length}B from {peer_address}")
            .with_trace("UDP data: {preview(data_preview,200)}"),
    )
});

pub fn get_udp_event_types() -> Vec<EventType> {
    vec![UDP_DATAGRAM_RECEIVED_EVENT.clone()]
}

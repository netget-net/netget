//! SOCKS5 client protocol actions implementation

use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, Parameter, ParameterDefinition,
};
use crate::protocol::EventType;
use crate::state::app_state::AppState;
use anyhow::{Context, Result};
use serde_json::json;
use std::sync::LazyLock;

/// Turn an outbound data action into the exact bytes to put on the wire.
///
/// The model-facing spelling is `data` plus an optional `encoding`:
///
/// - `encoding` absent or `"utf8"`: the characters of `data` are sent verbatim. This is the
///   default because the thing a SOCKS5 tunnel usually carries is a request a person can read.
/// - `encoding` = `"hex"`: `data` is decoded as hex, so `"48656c6c6f"` sends the 5 bytes
///   `Hello`.
///
/// There is deliberately **no auto-detection**. `"48656c6c6f"` is simultaneously valid text
/// and valid hex, and only the sender knows which it means — sniffing is the `send_tcp_data`
/// bug wearing a different hat.
///
/// `data_hex` is the field this action used to declare, and it is still accepted so that an
/// existing static handler or stored prompt keeps working. It is no longer advertised, and it
/// means exactly `{"data": <the hex>, "encoding": "hex"}`. Supplying **both** `data` and
/// `data_hex` is refused rather than resolved by precedence: the two say different things
/// about the same wire bytes and guessing which one the caller meant is how the original bug
/// happened.
pub fn decode_outbound_data(action: &serde_json::Value) -> Result<Vec<u8>> {
    let data = action.get("data").and_then(|v| v.as_str());
    let legacy = action.get("data_hex").and_then(|v| v.as_str());

    match (data, legacy) {
        (Some(_), Some(_)) => Err(anyhow::anyhow!(
            "Both 'data' and 'data_hex' were supplied. Send exactly one: 'data' with an \
             optional 'encoding' (\"utf8\" by default, or \"hex\"), or the deprecated \
             'data_hex'. They are not combined and neither takes precedence."
        )),
        (Some(text), None) => decode_with_encoding(text, action),
        (None, Some(h)) => decode_hex_field(h, "data_hex"),
        (None, None) => Err(anyhow::anyhow!(
            "Missing 'data' field. Put the payload in 'data' and, when it is binary, add \
             \"encoding\": \"hex\"."
        )),
    }
}

fn decode_with_encoding(data: &str, action: &serde_json::Value) -> Result<Vec<u8>> {
    match action
        .get("encoding")
        .and_then(|v| v.as_str())
        .unwrap_or("utf8")
    {
        "utf8" => Ok(data.as_bytes().to_vec()),
        "hex" => decode_hex_field(data, "data"),
        other => Err(anyhow::anyhow!(
            "Invalid 'encoding' value {other:?}. Valid values are \"utf8\" (default, send the \
             string's characters as-is) and \"hex\" (decode the string as hex-encoded bytes)."
        )),
    }
}

/// Hex with the separators a model naturally writes stripped, and a refusal that names the
/// field and says how to send the same string as literal text instead.
fn decode_hex_field(value: &str, field: &str) -> Result<Vec<u8>> {
    let cleaned: String = value
        .chars()
        .filter(|c| !c.is_ascii_whitespace() && *c != ':')
        .collect();
    let cleaned = cleaned.strip_prefix("0x").unwrap_or(&cleaned);

    if cleaned.len() % 2 != 0 {
        return Err(anyhow::anyhow!(
            "Invalid hex in '{field}': expected an even number of hex digits, got {} \
             ({value:?}). Each byte is two hex digits, e.g. \"48656c6c6f\" = \"Hello\".",
            cleaned.len()
        ));
    }

    hex::decode(cleaned).map_err(|e| {
        anyhow::anyhow!(
            "Invalid hex in '{field}' ({value:?}): {e}. Use only 0-9/a-f, two digits per byte, \
             e.g. \"48656c6c6f\" = \"Hello\". To send this string as literal text, put it in \
             'data' and omit 'encoding' (or set it to \"utf8\")."
        )
    })
}

/// What received bytes look like to the model: `data`, `encoding`, `data_length`.
///
/// Printable ASCII is passed through as text so the model can read an HTTP response for what
/// it is; anything else is hex-encoded and `encoding` says so. The pair round-trips — handing
/// this `data` and `encoding` straight back to `send_socks5_data` puts the same bytes on the
/// wire — which is exactly what the field used to make impossible: it was `data_hex` only, so
/// every readable payload reached the model as hex it had to decode in its head.
pub fn inbound_event_fields(data: &[u8]) -> serde_json::Value {
    let (text, encoding) = if data
        .iter()
        .all(|&b| b.is_ascii_graphic() || b.is_ascii_whitespace())
    {
        (String::from_utf8_lossy(data).to_string(), "utf8")
    } else {
        (hex::encode(data), "hex")
    };

    json!({
        "data": text,
        "encoding": encoding,
        "data_length": data.len(),
    })
}

/// The one description both spellings of `send_socks5_data` share.
///
/// It says outright that nothing is sniffed, because the whole point of the `encoding` field
/// is that a string like `"48656c6c6f"` is ambiguous and the model has to resolve it.
const SEND_DATA_DESCRIPTION: &str = "Send a payload through the established SOCKS5 tunnel to \
     the target server. The 'data' field holds the payload and the optional 'encoding' field \
     says how to turn it into bytes: omit 'encoding' (or use \"utf8\") to send the string's \
     characters as-is, or set \"encoding\": \"hex\" to send 'data' decoded from hex. There \
     is no auto-detection - a string like \"48656c6c6f\" is sent literally unless you set \
     \"encoding\": \"hex\".";

/// The `data` parameter every outbound SOCKS5 action carries.
fn data_parameter() -> Parameter {
    Parameter {
        name: "data".to_string(),
        type_hint: "string".to_string(),
        description: "Payload to send through the SOCKS5 tunnel to the target. Interpreted \
                      according to 'encoding': as literal text by default, or as hex-encoded \
                      bytes when \"encoding\": \"hex\"."
            .to_string(),
        required: true,
    }
}

/// The `encoding` parameter, a closed choice set matching [`decode_with_encoding`].
fn encoding_parameter() -> Parameter {
    Parameter {
        name: "encoding".to_string(),
        type_hint: "string".to_string(),
        description: "How to convert 'data' into the bytes put on the wire. \"utf8\" (the \
                      default when omitted) sends the characters of 'data' unchanged - use it \
                      for text protocols such as HTTP. \"hex\" decodes 'data' as hex-encoded \
                      bytes, two hex digits per byte. There is no auto-detection: \
                      {\"data\": \"48656c6c6f\"} sends the 10 characters 4-8-6-5-6-c-6-c-6-f, \
                      and only {\"data\": \"48656c6c6f\", \"encoding\": \"hex\"} sends the \
                      5 bytes 'Hello'. No other values are accepted."
            .to_string(),
        required: false,
    }
    .with_choices(["utf8", "hex"])
}

/// SOCKS5 client connected event
pub static SOCKS5_CLIENT_CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "socks5_connected",
        "SOCKS5 client successfully connected through proxy",
        json!({
            "type": "send_socks5_data",
            "data": "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
            "encoding": "utf8"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "proxy_addr".to_string(),
            type_hint: "string".to_string(),
            description: "SOCKS5 proxy server address".to_string(),
            required: true,
        },
        Parameter {
            name: "target_addr".to_string(),
            type_hint: "string".to_string(),
            description: "Target server address through proxy".to_string(),
            required: true,
        },
    ])
});

/// SOCKS5 client data received event
pub static SOCKS5_CLIENT_DATA_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "socks5_data_received",
        "Data received from target server through SOCKS5 proxy",
        json!({
            "type": "send_socks5_data",
            "data": "GET /next HTTP/1.1\r\nHost: example.com\r\n\r\n",
            "encoding": "utf8"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "data".to_string(),
            type_hint: "string".to_string(),
            description: "The data received from the target. Read it according to the \
                          'encoding' field of this event."
                .to_string(),
            required: true,
        },
        Parameter {
            name: "encoding".to_string(),
            type_hint: "string".to_string(),
            description: "How to read 'data': \"utf8\" means 'data' is the received bytes as \
                          literal text, \"hex\" means it is those bytes hex-encoded (two hex \
                          digits per byte, used whenever they are not all printable ASCII). To \
                          send the same bytes back unchanged, pass this 'data' and 'encoding' \
                          straight to send_socks5_data."
                .to_string(),
            required: true,
        },
        Parameter {
            name: "data_length".to_string(),
            type_hint: "number".to_string(),
            description: "Length of the received data in bytes, before any encoding".to_string(),
            required: true,
        },
    ])
});

/// SOCKS5 client protocol action handler
pub struct Socks5ClientProtocol;

impl Socks5ClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for Socks5ClientProtocol {
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "target_addr".to_string(),
                description: "Target server address to connect through SOCKS5 proxy (host:port)"
                    .to_string(),
                type_hint: "string".to_string(),
                required: true,
                example: json!("example.com:80"),
                default: None,
            },
            ParameterDefinition {
                name: "auth_username".to_string(),
                description: "Username for SOCKS5 authentication (optional)".to_string(),
                type_hint: "string".to_string(),
                required: false,
                example: json!("user"),
                default: None,
            },
            ParameterDefinition {
                name: "auth_password".to_string(),
                description: "Password for SOCKS5 authentication (optional)".to_string(),
                type_hint: "string".to_string(),
                required: false,
                example: json!("password"),
                default: None,
            },
        ]
    }
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![
            ActionDefinition {
                name: "send_socks5_data".to_string(),
                description: SEND_DATA_DESCRIPTION.to_string(),
                parameters: vec![data_parameter(), encoding_parameter()],
                example: json!({
                    "type": "send_socks5_data",
                    "data": "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
                    "encoding": "utf8"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "disconnect".to_string(),
                description: "Disconnect from SOCKS5 proxy and target server".to_string(),
                parameters: vec![],
                example: json!({
                    "type": "disconnect"
                }),
                log_template: None,
            },
        ]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            ActionDefinition {
                name: "send_socks5_data".to_string(),
                description: format!(
                    "Send data through the SOCKS5 tunnel in response to data received from the \
                     target. {SEND_DATA_DESCRIPTION}"
                ),
                parameters: vec![data_parameter(), encoding_parameter()],
                example: json!({
                    "type": "send_socks5_data",
                    "data": "GET /next HTTP/1.1\r\nHost: example.com\r\n\r\n",
                    "encoding": "utf8"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "wait_for_more".to_string(),
                description: "Wait for more data before responding".to_string(),
                parameters: vec![],
                example: json!({
                    "type": "wait_for_more"
                }),
                log_template: None,
            },
        ]
    }
    fn protocol_name(&self) -> &'static str {
        "SOCKS5"
    }
    /// Clone the statics the client actually emits, rather than rebuilding them.
    ///
    /// The two rebuilt copies carried `{"type": "placeholder", ...}` — an example
    /// `execute_action` refuses outright as `Unknown SOCKS5 client action: placeholder` — and
    /// no parameters at all. `get_event_types()` is the copy the model is shown, so it was
    /// given no fields and one example that cannot work, while the correct `send_socks5_data`
    /// examples sat unused in the statics above. This is the identical drift the Tor client
    /// had, fixed the identical way.
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            SOCKS5_CLIENT_CONNECTED_EVENT.clone(),
            SOCKS5_CLIENT_DATA_RECEIVED_EVENT.clone(),
        ]
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>SOCKS5"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "socks5",
            "socks",
            "proxy",
            "socks5 client",
            "connect via socks5",
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .implementation("tokio-socks library for SOCKS5 protocol")
            .llm_control(
                "Full control over target address, authentication, and data flow through proxy",
            )
            .e2e_testing("Dante or SS5 SOCKS5 server for testing")
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            // What the target sends through the tunnel while the model answers waits in a
            // queue: joined into one payload with batching on, one read per call with it off
            // (`client/inbound_queue.rs`).
            .batching(crate::protocol::metadata::BatchingMode::On)
            .build()
    }
    fn description(&self) -> &'static str {
        "SOCKS5 client for connecting to servers through a SOCKS5 proxy"
    }
    fn example_prompt(&self) -> &'static str {
        "Connect to example.com:80 through SOCKS5 proxy at localhost:1080"
    }
    fn group_name(&self) -> &'static str {
        "Proxy"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        use serde_json::json;

        StartupExamples::new(
            // LLM mode: LLM controls SOCKS5 tunnel
            json!({
                "type": "open_client",
                "remote_addr": "localhost:1080",
                "base_stack": "socks5",
                "startup_params": {
                    "target_addr": "example.com:80"
                },
                "instruction": "Send an HTTP GET request through the SOCKS5 tunnel"
            }),
            // Script mode: Code-based SOCKS5 handling
            json!({
                "type": "open_client",
                "remote_addr": "localhost:1080",
                "base_stack": "socks5",
                "startup_params": {
                    "target_addr": "example.com:80"
                },
                "event_handlers": [{
                    "event_pattern": "socks5_data_received",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "<socks5_client_handler>"
                    }
                }]
            }),
            // Static mode: Fixed data send through tunnel
            json!({
                "type": "open_client",
                "remote_addr": "localhost:1080",
                "base_stack": "socks5",
                "startup_params": {
                    "target_addr": "example.com:80"
                },
                "event_handlers": [
                    {
                        "event_pattern": "socks5_connected",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "send_socks5_data",
                                "data": "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
                                "encoding": "utf8"
                            }]
                        }
                    },
                    {
                        "event_pattern": "socks5_data_received",
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
impl Client for Socks5ClientProtocol {
    fn connect(
        &self,
        ctx: crate::protocol::ConnectContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::client::socks5::Socks5Client;
            Socks5Client::connect_with_llm_actions(
                ctx.remote_addr,
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.client_id,
                ctx.startup_params,
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
            "send_socks5_data" => Ok(ClientActionResult::SendData(decode_outbound_data(&action)?)),
            "disconnect" => Ok(ClientActionResult::Disconnect),
            "wait_for_more" => Ok(ClientActionResult::WaitForMore),
            _ => Err(anyhow::anyhow!(
                "Unknown SOCKS5 client action: {}",
                action_type
            )),
        }
    }
}

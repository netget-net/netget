//! Tor client protocol actions implementation

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
///   default because what a Tor circuit usually carries is a request a person can read.
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
/// this `data` and `encoding` straight back to `send_tor_data` puts the same bytes on the
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

/// The one description both spellings of `send_tor_data` share.
///
/// It says outright that nothing is sniffed, because the whole point of the `encoding` field
/// is that a string like `"48656c6c6f"` is ambiguous and the model has to resolve it.
const SEND_DATA_DESCRIPTION: &str = "Send a payload to the destination through the established \
     Tor circuit. The 'data' field holds the payload and the optional 'encoding' field says \
     how to turn it into bytes: omit 'encoding' (or use \"utf8\") to send the string's \
     characters as-is, or set \"encoding\": \"hex\" to send 'data' decoded from hex. There \
     is no auto-detection - a string like \"48656c6c6f\" is sent literally unless you set \
     \"encoding\": \"hex\".";

/// The `data` parameter every outbound Tor action carries.
fn data_parameter() -> Parameter {
    Parameter {
        name: "data".to_string(),
        type_hint: "string".to_string(),
        description: "Payload to send to the destination through the Tor circuit. Interpreted \
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

/// Tor client connected event
pub static TOR_CLIENT_CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "tor_connected",
        "Tor client successfully connected through Tor network",
        json!({
            "type": "send_tor_data",
            "data": "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
            "encoding": "utf8"
        }),
    )
    .with_parameters(vec![Parameter {
        name: "target".to_string(),
        type_hint: "string".to_string(),
        description: "Target address (can be regular hostname:port or .onion:port)".to_string(),
        required: true,
    }])
});

/// Tor client data received event
pub static TOR_CLIENT_DATA_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "tor_data_received",
        "Data received from destination through Tor",
        json!({
            "type": "send_tor_data",
            "data": "GET /next HTTP/1.1\r\nHost: example.com\r\n\r\n",
            "encoding": "utf8"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "data".to_string(),
            type_hint: "string".to_string(),
            description: "The data received from the destination. Read it according to the \
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
                          straight to send_tor_data."
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

/// Tor bootstrap complete event (directory consensus downloaded)
#[cfg(unix)]
pub static TOR_BOOTSTRAP_COMPLETE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "tor_bootstrap_complete",
        "Tor client finished bootstrapping and downloaded network consensus",
        json!({
            "type": "send_tor_data",
            "data": "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
            "encoding": "utf8"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "relay_count".to_string(),
            type_hint: "number".to_string(),
            description: "Number of relays in consensus".to_string(),
            required: true,
        },
        Parameter {
            name: "valid_after".to_string(),
            type_hint: "string".to_string(),
            description: "Consensus valid-after timestamp".to_string(),
            required: true,
        },
    ])
});

/// Tor client protocol action handler
pub struct TorClientProtocol;

impl TorClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for TorClientProtocol {
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "directory_server".to_string(),
                type_hint: "string".to_string(),
                description: "Custom Tor relay address (e.g., '127.0.0.1:9001') to bootstrap from, using BEGIN_DIR (directory over circuit) instead of the public Tor network. Pair with a local tor_relay server for offline use. Exactly one of this or allow_public_tor_network must be given; without either the client refuses to start.".to_string(),
                required: false,
                example: json!("127.0.0.1:9001"),
                default: None,
            },
            ParameterDefinition {
                name: crate::client::tor::ALLOW_PUBLIC_TOR_NETWORK_PARAM.to_string(),
                type_hint: "boolean".to_string(),
                description: "Opt in to bootstrapping against the REAL Tor directory authorities on the public internet. Off by default: bootstrapping contacts third parties before the requested destination is even looked at, so opening a Tor client would otherwise reach the internet no matter what you asked it to connect to. Set true only when you intend outbound public traffic.".to_string(),
                required: false,
                example: json!(true),
                default: None,
            },
        ]
    }

    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![
            ActionDefinition {
                name: "send_tor_data".to_string(),
                description: SEND_DATA_DESCRIPTION.to_string(),
                parameters: vec![data_parameter(), encoding_parameter()],
                example: json!({
                    "type": "send_tor_data",
                    "data": "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
                    "encoding": "utf8"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "disconnect".to_string(),
                description: "Disconnect from the Tor circuit".to_string(),
                parameters: vec![],
                example: json!({
                    "type": "disconnect"
                }),
                log_template: None,
            },
            #[cfg(unix)]
            ActionDefinition {
                name: "get_consensus_info".to_string(),
                description: "Get network consensus metadata (relay count, validity times)"
                    .to_string(),
                parameters: vec![],
                example: json!({
                    "type": "get_consensus_info"
                }),
                log_template: None,
            },
            #[cfg(unix)]
            ActionDefinition {
                name: "list_relays".to_string(),
                description: "List relays from the Tor network consensus".to_string(),
                parameters: vec![Parameter {
                    name: "limit".to_string(),
                    type_hint: "number".to_string(),
                    description: "Maximum number of relays to return (default: 100)".to_string(),
                    required: false,
                }],
                example: json!({
                    "type": "list_relays",
                    "limit": 50
                }),
                log_template: None,
            },
            #[cfg(unix)]
            ActionDefinition {
                name: "search_relays".to_string(),
                description: "Search for relays matching criteria (flags, nickname pattern)"
                    .to_string(),
                parameters: vec![
                    Parameter {
                        name: "flags".to_string(),
                        type_hint: "array".to_string(),
                        description: "Required flags (e.g., [\"Guard\", \"Exit\", \"Fast\"])"
                            .to_string(),
                        required: false,
                    },
                    Parameter {
                        name: "nickname".to_string(),
                        type_hint: "string".to_string(),
                        description: "Nickname pattern to match".to_string(),
                        required: false,
                    },
                    Parameter {
                        name: "limit".to_string(),
                        type_hint: "number".to_string(),
                        description: "Maximum results (default: 100)".to_string(),
                        required: false,
                    },
                ],
                example: json!({
                    "type": "search_relays",
                    "flags": ["Exit", "Fast"],
                    "limit": 20
                }),
                log_template: None,
            },
        ]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            ActionDefinition {
                name: "send_tor_data".to_string(),
                description: format!(
                    "Send data through the Tor circuit in response to data received from the \
                     destination. {SEND_DATA_DESCRIPTION}"
                ),
                parameters: vec![data_parameter(), encoding_parameter()],
                example: json!({
                    "type": "send_tor_data",
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
        "Tor"
    }
    /// Clone the statics the client actually emits, rather than rebuilding them.
    ///
    /// The two rebuilt copies carried `{"type": "placeholder", ...}` — an example
    /// `execute_action` refuses outright as `Unknown Tor client action: placeholder` — and
    /// no parameters at all. `get_event_types()` is the copy the model is shown, so it was
    /// given no fields and one example that cannot work, while the correct `send_tor_data`
    /// examples sat unused in the statics three screens above. The bootstrap event below
    /// was already cloned properly, which made the drift visible in the same function.
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            TOR_CLIENT_CONNECTED_EVENT.clone(),
            TOR_CLIENT_DATA_RECEIVED_EVENT.clone(),
            // Emitted but never advertised until now: mod.rs raises it once the Tor
            // directory bootstrap finishes, and nothing told the model it existed, so no
            // handler could be written for the one event that says the circuit is usable.
            TOR_BOOTSTRAP_COMPLETE_EVENT.clone(),
        ]
    }
    fn stack_name(&self) -> &'static str {
        "Tor>TCP"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["tor", "tor client", "onion", "anonymous", "privacy"]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .implementation("Arti Tor client (pure Rust Tor implementation)")
            .llm_control("Full control over data sent/received through Tor circuits")
            .e2e_testing("Connect to onion services or regular hosts through Tor")
            .notes(
                "REACHES THE PUBLIC INTERNET ONLY ON EXPLICIT OPT-IN. arti's \
                 create_bootstrapped() contacts the real Tor directory authorities BEFORE it \
                 looks at the requested address (~14s), so merely opening this client used to \
                 make outbound connections to third parties whatever the destination was. It \
                 now refuses to start unless the caller passes either `directory_server` (a \
                 directory to bootstrap from, e.g. a local `127.0.0.1:9001` tor_relay) or \
                 `allow_public_tor_network: true`. Passing both is refused rather than \
                 guessed. Bootstrap is 10-30s even when permitted.",
            )
            .build()
    }
    fn description(&self) -> &'static str {
        "Tor client for anonymous connections through the Tor network"
    }
    fn example_prompt(&self) -> &'static str {
        "Connect to example.onion:80 through Tor and send HTTP GET request"
    }
    fn group_name(&self) -> &'static str {
        "VPN & Tunneling"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        use serde_json::json;

        StartupExamples::new(
            // LLM mode: LLM controls Tor connection.
            //
            // Every example carries a bootstrap choice, because without one the client refuses
            // to start. An example a model can copy verbatim into a refusal is worse than no
            // example. The public network is the opt-in here; swap in
            // `{"directory_server": "127.0.0.1:9001"}` to bootstrap from a local tor_relay.
            json!({
                "type": "open_client",
                "remote_addr": "example.com:80",
                "base_stack": "tor",
                "startup_params": {"allow_public_tor_network": true},
                "instruction": "Connect to the destination through Tor and send an HTTP GET request"
            }),
            // Script mode: Code-based Tor handling
            json!({
                "type": "open_client",
                "remote_addr": "example.com:80",
                "base_stack": "tor",
                "startup_params": {"allow_public_tor_network": true},
                "event_handlers": [{
                    "event_pattern": "tor_connected",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "<tor_client_handler>"
                    }
                }]
            }),
            // Static mode: Fixed Tor action
            json!({
                "type": "open_client",
                "remote_addr": "example.com:80",
                "base_stack": "tor",
                "startup_params": {"allow_public_tor_network": true},
                "event_handlers": [
                    {
                        "event_pattern": "tor_connected",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "send_tor_data",
                                "data": "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
                                "encoding": "utf8"
                            }]
                        }
                    },
                    {
                        "event_pattern": "tor_data_received",
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
impl Client for TorClientProtocol {
    fn connect(
        &self,
        ctx: crate::protocol::ConnectContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::client::tor::TorClient;
            TorClient::connect_with_llm_actions(
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
            "send_tor_data" => Ok(ClientActionResult::SendData(decode_outbound_data(&action)?)),
            "disconnect" => Ok(ClientActionResult::Disconnect),
            "wait_for_more" => Ok(ClientActionResult::WaitForMore),

            // Directory query actions (processed async in connect loop)
            #[cfg(unix)]
            "get_consensus_info" | "list_relays" | "search_relays" => {
                Ok(ClientActionResult::Custom {
                    name: action_type.to_string(),
                    data: action.clone(),
                })
            }

            _ => Err(anyhow::anyhow!(
                "Unknown Tor client action: {}",
                action_type
            )),
        }
    }
}

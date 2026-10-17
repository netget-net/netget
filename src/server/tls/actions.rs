//! TLS protocol actions implementation

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

/// TLS protocol action handler
pub struct TlsProtocol {}

impl TlsProtocol {
    pub fn new() -> Self {
        Self {}
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for TlsProtocol {
    fn get_startup_parameters(&self) -> Vec<crate::llm::actions::ParameterDefinition> {
        vec![
                crate::llm::actions::ParameterDefinition {
                    name: "send_first".to_string(),
                    type_hint: "boolean".to_string(),
                    description: "Set true when the server speaks first after the handshake (a banner or prompt). It is the only way tls_connection_opened is raised: then nothing the peer sends is read until that event has been answered, a silent answer is logged as a missing greeting, and a failed one closes the connection. Left false (the default), no connect event is raised and a connection costs no model call until the client sends something.".to_string(),
                    required: false,
                    example: serde_json::json!(false),
                    default: None,
                },
                crate::llm::actions::ParameterDefinition {
                    name: "cert_path".to_string(),
                    type_hint: "string".to_string(),
                    description: "Path to TLS certificate file (PEM format). If not provided, a self-signed certificate will be generated.".to_string(),
                    required: false,
                    example: serde_json::json!("/path/to/cert.pem"),
                    default: None,
                },
                crate::llm::actions::ParameterDefinition {
                    name: "key_path".to_string(),
                    type_hint: "string".to_string(),
                    description: "Path to TLS private key file (PEM format). Required if cert_path is provided.".to_string(),
                    required: false,
                    example: serde_json::json!("/path/to/key.pem"),
                    default: None,
                },
                // Three read deadlines, not two, because the handshake wait and the wait for
                // the first application record face different peers: one that has not proved
                // it speaks TLS, and one that has. See src/server/tls/mod.rs.
                crate::llm::actions::ParameterDefinition {
                    name: "handshake_timeout_secs".to_string(),
                    type_hint: "number".to_string(),
                    description: "Seconds a peer that has opened a TCP socket may take to \
                                  complete the TLS handshake. Default 60. Every real client \
                                  sends ClientHello immediately and finishes in one \
                                  round-trip, NetGet's own TLS client included, and nothing in \
                                  this phase involves the model - so this one does not need to \
                                  be generous."
                        .to_string(),
                    required: false,
                    example: serde_json::json!(60),
                    default: Some(serde_json::json!(super::HANDSHAKE_READ_TIMEOUT.as_secs())),
                },
                crate::llm::actions::ParameterDefinition {
                    name: "first_byte_timeout_secs".to_string(),
                    type_hint: "number".to_string(),
                    description: "Seconds a peer that has COMPLETED the handshake may send no \
                                  application record before the server closes it. Default 300, \
                                  matching the window a `manual` rule gives a human to answer \
                                  one event. The peer is often NetGet's own TLS client, which \
                                  handshakes inside connect() and then writes no application \
                                  bytes until an action or [ send message ] says to. Lower it \
                                  (60 was the old value) for a listener exposed to strangers."
                        .to_string(),
                    required: false,
                    example: serde_json::json!(300),
                    default: Some(serde_json::json!(super::FIRST_RECORD_READ_TIMEOUT.as_secs())),
                },
                crate::llm::actions::ParameterDefinition {
                    name: "idle_timeout_secs".to_string(),
                    type_hint: "number".to_string(),
                    description: "Seconds a connection that has already carried application \
                                  data may go without a further record before the server \
                                  closes it. Default 300. TLS is a carrier, so what counts as \
                                  idle is a property of whatever rides on it - which is why \
                                  this is yours to set. Time spent waiting on an answer of \
                                  ours is not counted against the peer."
                        .to_string(),
                    required: false,
                    example: serde_json::json!(300),
                    default: Some(serde_json::json!(super::IDLE_AFTER_DATA_TIMEOUT.as_secs())),
                },
            ]
    }
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            send_tls_data_action(),
            wait_for_more_action(),
            close_this_connection_action(),
        ]
    }
    fn protocol_name(&self) -> &'static str {
        "TLS"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        get_tls_event_types()
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>TLS"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["tls", "ssl", "secure", "encrypted"]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .implementation("TLS transport layer using tokio-rustls; self-signed certificate by default, or cert_path/key_path")
            // Not a record size — rustls bounds those at 2^14 by the spec. This is what one
            // connection may accumulate while an answer is in flight, which is the number a
            // peer actually controls: see `MAX_QUEUED_BYTES`.
            .max_inbound_bytes(crate::server::tls::MAX_QUEUED_BYTES)
            .llm_control("Full control over application protocol on top of TLS; text or hex payloads")
            .e2e_testing("openssl s_client / native TLS client")
            .notes("Generic TLS server for custom protocols - LLM implements application layer. No client certificate authentication (no mTLS)")
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "Generic TLS server for implementing custom encrypted protocols"
    }
    fn example_prompt(&self) -> &'static str {
        "Listen on port 8443 via TLS; implement a simple chat protocol over encrypted connection"
    }
    fn group_name(&self) -> &'static str {
        "Core"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;

        // Deterministic: reply "OK" to every decrypted record, no LLM call.
        let script = r#"import json, sys
data = json.load(sys.stdin)
event = data["event"]
if data["event_type_id"] == "tls_data_received":
    actions = [{"type": "send_tls_data", "data": "OK\r\n"}]
else:
    actions = []
print(json.dumps({"actions": actions}))"#;

        StartupExamples::new(
            json!({
                "type": "open_server",
                "port": 8443,
                "base_stack": "tls",
                "instruction": "Secure TLS server for custom encrypted protocols"
            }),
            json!({
                "type": "open_server",
                "port": 8443,
                "base_stack": "tls",
                "event_handlers": [{
                    "event_pattern": "tls_data_received",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": script
                    }
                }]
            }),
            json!({
                "type": "open_server",
                "port": 8443,
                "base_stack": "tls",
                "event_handlers": [
                    {
                        "event_pattern": "tls_connection_opened",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "send_tls_data",
                                "data": "220 Welcome to secure server\r\n"
                            }]
                        }
                    },
                    {
                        "event_pattern": "tls_data_received",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "send_tls_data",
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
impl Server for TlsProtocol {
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

            // Extract custom TLS config if provided
            let tls_config = if let Some(ref params) = ctx.startup_params {
                let cert_path = params.get_optional_string("cert_path")?;
                let key_path = params.get_optional_string("key_path")?;

                match (cert_path, key_path) {
                    (Some(cert), Some(key)) => {
                        // Load custom certificates from files
                        Some(crate::server::tls_cert_manager::load_tls_config_from_files(
                            &cert, &key,
                        )?)
                    }
                    (Some(_), None) | (None, Some(_)) => {
                        return Err(anyhow::anyhow!(
                            "Both cert_path and key_path must be provided together"
                        ));
                    }
                    (None, None) => None, // Use default self-signed certificate
                }
            } else {
                None
            };

            // All three read deadlines are the operator's to choose: who is on the other end
            // and what rides on this carrier are the only things that decide them, and only
            // the operator knows either.
            let secs = |name: &str| -> anyhow::Result<Option<u64>> {
                Ok(ctx
                    .startup_params
                    .as_ref()
                    .map(|p| p.get_optional_u64(name))
                    .transpose()?
                    .flatten())
            };
            let handshake_timeout_secs = secs("handshake_timeout_secs")?;
            let first_byte_timeout_secs = secs("first_byte_timeout_secs")?;
            let idle_timeout_secs = secs("idle_timeout_secs")?;

            use crate::server::tls::TlsServer;
            TlsServer::spawn_with_llm_actions(
                ctx.legacy_listen_addr(),
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                send_first,
                ctx.server_id,
                tls_config,
                handshake_timeout_secs,
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
            "send_tls_data" => self.execute_send_tls_data(action),
            "wait_for_more" => Ok(ActionResult::WaitForMore),
            "close_this_connection" => Ok(ActionResult::CloseConnection),
            // The dashboard's `[ disconnect this peer ]` injects a bare
            // `{"type": "close_connection"}` (`src/tui/actions.rs`) whatever the protocol calls
            // its own close verb, so a server that advertises only `close_this_connection`
            // answers that button with "Unknown TLS action". Accepted as an alias rather than
            // advertised — `close_this_connection` stays the one name the model is offered.
            "close_connection" => Ok(ActionResult::CloseConnection),
            _ => Err(anyhow::anyhow!("Unknown TLS action: {action_type}")),
        }
    }
}

impl TlsProtocol {
    /// Execute send_tls_data sync action
    fn execute_send_tls_data(&self, action: serde_json::Value) -> Result<ActionResult> {
        let data = action
            .get("data")
            .and_then(|v| v.as_str())
            .context("Missing 'data' parameter")?;

        Ok(ActionResult::Output(decode_outbound_data(data, &action)?))
    }
}

/// Turn the `data` field of an outbound action into the exact bytes to put on
/// the wire, honouring the action's optional `encoding` field.
///
/// - `encoding` absent or `"utf8"`: the string's UTF-8 bytes are sent verbatim.
/// - `encoding` = `"hex"`: `data` is decoded as hex, so `"48656c6c6f"` sends the
///   five bytes `Hello`.
///
/// `tls_data_received` hands binary payloads to the model as hex, so without this
/// the round trip was asymmetric: a model echoing back what it was given put the
/// literal ASCII hex digits on the wire.
///
/// There is deliberately no auto-detection: `"48656c6c6f"` is both valid text and
/// valid hex, so the caller must say which it means.
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
                     text instead, omit 'encoding' or set it to \"utf8\"."
                )
            })
        }
        other => Err(anyhow::anyhow!(
            "Unknown 'encoding' value {other:?}. Valid values are \"utf8\" (default, send the \
             string's bytes as-is) and \"hex\" (decode the string as hex first)."
        )),
    }
}

/// Action definition for send_tls_data (sync)
fn send_tls_data_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_tls_data".to_string(),
        description: "Send data over the current TLS connection (TLS encryption is applied automatically)".to_string(),
        parameters: vec![
            Parameter {
                name: "data".to_string(),
                type_hint: "string".to_string(),
                description: "Payload to send. Interpreted according to 'encoding'.".to_string(),
                required: true,
            },
            Parameter {
                name: "encoding".to_string(),
                type_hint: "string".to_string(),
                description: "How to interpret 'data': \"utf8\" (default) sends the string's bytes verbatim; \"hex\" decodes it as hex first, so \"48656c6c6f\" sends the 5 bytes \"Hello\". Use \"hex\" for binary protocols - tls_data_received reports binary payloads as hex.".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_tls_data",
            "data": "Hello over TLS\r\n"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> TLS {data_len}B")
                .with_debug("TLS send: {data_len} bytes"),
        ),
    }
}

/// Action definition for wait_for_more (sync)
fn wait_for_more_action() -> ActionDefinition {
    ActionDefinition {
        name: "wait_for_more".to_string(),
        description: "Wait for more data before responding (accumulate incomplete protocol data)"
            .to_string(),
        parameters: vec![],
        example: json!({
            "type": "wait_for_more"
        }),
        log_template: Some(LogTemplate::new().with_debug("TLS waiting for more data")),
    }
}

/// Action definition for close_this_connection (sync)
fn close_this_connection_action() -> ActionDefinition {
    ActionDefinition {
        name: "close_this_connection".to_string(),
        description: "Close the current TLS connection".to_string(),
        parameters: vec![],
        example: json!({
            "type": "close_this_connection"
        }),
        log_template: Some(LogTemplate::new().with_info("-> TLS connection closed")),
    }
}

// ============================================================================
// TLS Action Constants
// ============================================================================

pub static SEND_TLS_DATA_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(|| send_tls_data_action());
pub static WAIT_FOR_MORE_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(|| wait_for_more_action());
pub static CLOSE_THIS_CONNECTION_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(|| close_this_connection_action());

// ============================================================================
// TLS Event Type Constants
// ============================================================================

/// TLS connection opened event - triggered when TLS handshake completes
pub static TLS_CONNECTION_OPENED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "tls_connection_opened",
        "TLS handshake complete; the client has sent nothing yet. Raised only when the \
         server was started with send_first, which means the client is owed a greeting: send \
         the banner or prompt now with send_tls_data. Nothing the client sends is read until \
         this is answered.",
        json!({
            "type": "send_tls_data",
            "data": "220 Welcome to secure server\r\n"
        }),
    )
    // Data: `connect_event_data()` - nothing received yet, and the answer that calls for.
    .with_actions(vec![
        SEND_TLS_DATA_ACTION.clone(),
        CLOSE_THIS_CONNECTION_ACTION.clone(),
    ])
    .with_parameters(crate::protocol::event_type::connect_event_parameters())
    .with_log_template(
        LogTemplate::new()
            .with_info("{client_ip} TLS connected")
            .with_debug("TLS handshake complete from {client_ip}"),
    )
});

/// TLS data received event - triggered when data is received on encrypted connection
pub static TLS_DATA_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "tls_data_received",
        "Data received on TLS connection (implement your application protocol here)",
        json!({
            "type": "send_tls_data",
            "data": "OK Data received\r\n"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "data".to_string(),
            type_hint: "string".to_string(),
            description: "The data received. Printable payloads arrive as text; anything else arrives hex-encoded. Check 'encoding' to tell which.".to_string(),
            required: true,
        },
        Parameter {
            name: "encoding".to_string(),
            type_hint: "string".to_string(),
            description: "How 'data' is encoded: \"utf8\" (printable text) or \"hex\" (binary). To echo a hex payload back, pass the same encoding to send_tls_data.".to_string(),
            required: true,
        },
    ])
    .with_actions(vec![
        SEND_TLS_DATA_ACTION.clone(),
        WAIT_FOR_MORE_ACTION.clone(),
        CLOSE_THIS_CONNECTION_ACTION.clone(),
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("{client_ip} TLS <- {data_len}B ({duration_ms}ms)")
            .with_debug("TLS data from {client_ip}: {data_len} bytes")
            .with_trace("TLS data: {data}"),
    )
});

/// Get TLS event types
pub fn get_tls_event_types() -> Vec<EventType> {
    vec![
        TLS_CONNECTION_OPENED_EVENT.clone(),
        TLS_DATA_RECEIVED_EVENT.clone(),
    ]
}

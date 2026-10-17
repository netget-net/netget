//! STOMP 1.2 protocol actions.
//!
//! What the model decides here is *content*: whether to admit a connection, what a MESSAGE
//! carries, whether to refuse. Framing, header escaping, the NUL terminator, the `receipt`
//! handshake and the heart-beat negotiation are all done in Rust (`frame.rs` and `mod.rs`) —
//! they are mechanical, and a model that gets any of them wrong produces a stream no real
//! client can recover from.

use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::EventType;
use crate::server::stomp::frame::{error_frame, receipt_frame, StompFrame};
use crate::state::app_state::AppState;
use anyhow::{Context, Result};
use serde_json::json;
use std::sync::LazyLock;

/// The version this server speaks. Only 1.2 — `mod.rs` refuses a `CONNECT` whose
/// `accept-version` does not include it, rather than silently answering a dialect it does not
/// implement.
pub const STOMP_VERSION: &str = "1.2";

/// Heart-beating is negotiated off, unconditionally.
///
/// The server implements no heart-beat timer, so any other value would be a promise it does
/// not keep — and a client that believes it will hear from us every N ms tears the connection
/// down when it does not. `send_stomp_connected` deliberately has **no** heart-beat parameter
/// for the same reason: the model cannot advertise what the code does not do.
pub const STOMP_HEARTBEAT: &str = "0,0";

pub struct StompProtocol;

impl StompProtocol {
    pub fn new() -> Self {
        Self
    }
}

impl Default for StompProtocol {
    fn default() -> Self {
        Self::new()
    }
}

impl Protocol for StompProtocol {
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        // STOMP is purely reactive: every frame this server writes answers one the client
        // sent. Nothing here can be issued out of band.
        Vec::new()
    }

    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            send_stomp_connected_action(),
            send_stomp_message_action(),
            send_stomp_receipt_action(),
            send_stomp_error_action(),
            close_connection_action(),
        ]
    }

    fn protocol_name(&self) -> &'static str {
        "STOMP"
    }

    fn get_event_types(&self) -> Vec<EventType> {
        get_stomp_event_types()
    }

    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>STOMP"
    }

    fn keywords(&self) -> Vec<&'static str> {
        vec!["stomp"]
    }

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{
            DevelopmentState, PrivilegeRequirement, ProtocolMetadataV2,
        };

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Beta)
            .privilege_requirement(PrivilegeRequirement::None)
            .well_known_port(61613)
            .implementation(
                "Hand-rolled STOMP 1.2 codec over tokio TCP (src/server/stomp/frame.rs). No \
                 third-party STOMP crate on the server side: header escaping, the \
                 content-length/NUL body rule and the receipt handshake are ~300 lines and a \
                 dependency would not have removed the part that matters.",
            )
            .llm_control(
                "Whether to admit a CONNECT, the contents of MESSAGE frames, and whether to \
                 refuse with ERROR. Framing, header escaping, receipts and heart-beat \
                 negotiation are deterministic Rust.",
            )
            .e2e_testing(
                "Driven by the async-stomp 0.6.3 client (tests/server/stomp/e2e_test.rs), which \
                 is not #[ignore]d and cannot skip - it is a compiled-in crate dependency, so \
                 there is nothing to detect as missing. Connector::connect() completes the \
                 handshake and async-stomp's own parser decodes every later frame. \
                 raw_socket_test.rs covers what a client library cannot express (a NUL body, a \
                 frame before the handshake, a refused accept-version, broken framing) and \
                 codec_test.rs pins the codec against spec byte literals.",
            )
            .notes(
                "Beta on the evidence of a real third-party client: async-stomp 0.6.3 completes \
                 CONNECT -> CONNECTED -> SUBSCRIBE -> MESSAGE -> SEND -> MESSAGE -> DISCONNECT \
                 -> RECEIPT -> close against this server, decoding each frame with its own \
                 parser, and separately decodes a refusal as an ERROR frame. A negative control \
                 was run: dropping the CONNECTED 'version' header makes async-stomp's handshake \
                 fail and the test fail, so it is not passing vacuously. NOT IMPLEMENTED, and \
                 none of it is hidden from the peer: heart-beating (always negotiated 0,0, \
                 which is a legal configuration rather than a silent omission), transactions \
                 (BEGIN/COMMIT/ABORT are acknowledged and otherwise ignored - holding messages \
                 until COMMIT would be storage, which protocols may not implement; the \
                 transaction header still reaches the model on the SEND event), subscription \
                 bookkeeping, message redelivery, STOMP 1.0/1.1 (refused with an ERROR naming \
                 version:1.2) and TLS. UNPROVEN: interop with brokers' own clients \
                 (ActiveMQ/RabbitMQ STOMP), and concurrent sessions.",
            )
            .max_inbound_bytes(crate::server::stomp::frame::MAX_FRAME_BYTES)
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }

    fn description(&self) -> &'static str {
        "STOMP 1.2 message broker server"
    }

    fn example_prompt(&self) -> &'static str {
        "STOMP broker on port 61613 - accept any login and deliver a greeting message to \
         whoever subscribes to /queue/test"
    }

    fn group_name(&self) -> &'static str {
        "Application"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        StartupExamples::new(
            json!({
                "type": "open_server",
                "port": 61613,
                "base_stack": "stomp",
                "instruction": "STOMP broker: accept every CONNECT, and when a client subscribes to a destination send it one MESSAGE describing that destination"
            }),
            json!({
                "type": "open_server",
                "port": 61613,
                "base_stack": "stomp",
                "event_handlers": [{
                    "event_pattern": "stomp_connect",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "# Admit anyone, naming the session after the login they offered\nlogin = event.get('login') or 'anonymous'\nrespond([{'type': 'send_stomp_connected', 'session': 'session-' + login, 'server': 'netget/stomp'}])"
                    }
                }]
            }),
            json!({
                "type": "open_server",
                "port": 61613,
                "base_stack": "stomp",
                "event_handlers": [{
                    "event_pattern": "stomp_connect",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "send_stomp_connected",
                            "version": "1.2",
                            "session": "session-1",
                            "server": "netget/stomp"
                        }]
                    }
                }]
            }),
        )
    }
}

impl Server for StompProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::server::stomp::StompServer;
            StompServer::spawn_with_llm_actions(
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
            "send_stomp_connected" => execute_send_connected(&action),
            "send_stomp_message" => execute_send_message(&action),
            "send_stomp_receipt" => execute_send_receipt(&action),
            "send_stomp_error" => execute_send_error(&action),
            "close_connection" => Ok(ActionResult::CloseConnection),
            other => Err(anyhow::anyhow!("Unknown STOMP action: {}", other)),
        }
    }
}

// === executors ===

fn execute_send_connected(action: &serde_json::Value) -> Result<ActionResult> {
    let version = action
        .get("version")
        .and_then(|v| v.as_str())
        .unwrap_or(STOMP_VERSION);
    if version != STOMP_VERSION {
        return Err(anyhow::anyhow!(
            "This server implements STOMP {STOMP_VERSION} only; 'version' must be \
             \"{STOMP_VERSION}\" (got {version:?})"
        ));
    }

    let mut headers = vec![("version".to_string(), version.to_string())];
    if let Some(session) = action.get("session").and_then(|v| v.as_str()) {
        reject_unescapable("session", session)?;
        headers.push(("session".to_string(), session.to_string()));
    }
    if let Some(server) = action.get("server").and_then(|v| v.as_str()) {
        reject_unescapable("server", server)?;
        headers.push(("server".to_string(), server.to_string()));
    }
    // Never taken from the action: see STOMP_HEARTBEAT.
    headers.push(("heart-beat".to_string(), STOMP_HEARTBEAT.to_string()));

    Ok(ActionResult::Output(
        StompFrame::new("CONNECTED", headers, Vec::new()).encode(),
    ))
}

/// Refuse a value that would forge a header on a `CONNECTED` frame.
///
/// This is the one place in this protocol where the model's string reaches the wire without
/// the escaper in front of it: STOMP 1.2 exempts `CONNECT`/`STOMP`/`CONNECTED` from escaping,
/// so `encode()` writes their header values raw. A `session` containing a newline injects an
/// arbitrary extra header; `\n\n` ends the header block and starts a body. The protocol's own
/// startup example builds the session out of peer input (`'session-' + login`), so this is
/// reachable from a script handler as readily as from the model.
///
/// It also keeps the documented interop honest: `async-stomp` unescapes `CONNECTED` headers
/// unconditionally, so a value with a backslash in it would come back changed.
fn reject_unescapable(field: &str, value: &str) -> Result<()> {
    if !crate::server::stomp::frame::is_safe_unescaped_header(value) {
        return Err(anyhow::anyhow!(
            "'{field}' may not contain a newline, carriage return, colon or NUL: CONNECTED \
             headers are exempt from STOMP 1.2 escaping, so such a value would forge a header \
             rather than appear in this one"
        ));
    }
    Ok(())
}

fn execute_send_message(action: &serde_json::Value) -> Result<ActionResult> {
    let destination = required_str(action, "destination")?;
    let subscription = required_str(action, "subscription")?;
    let message_id = required_str(action, "message_id")?;
    let body = decode_body(action)?;

    let mut headers = vec![
        ("destination".to_string(), destination),
        ("subscription".to_string(), subscription),
        ("message-id".to_string(), message_id),
    ];
    if let Some(content_type) = action.get("content_type").and_then(|v| v.as_str()) {
        headers.push(("content-type".to_string(), content_type.to_string()));
    }
    headers.extend(extra_headers(action)?);

    Ok(ActionResult::Output(
        StompFrame::new("MESSAGE", headers, body).encode(),
    ))
}

fn execute_send_receipt(action: &serde_json::Value) -> Result<ActionResult> {
    let receipt_id = required_str(action, "receipt_id")?;
    Ok(ActionResult::Output(receipt_frame(&receipt_id)))
}

fn execute_send_error(action: &serde_json::Value) -> Result<ActionResult> {
    let message = required_str(action, "message")?;
    let body = action
        .get("body")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    Ok(ActionResult::Output(error_frame(&message, &body)))
}

fn required_str(action: &serde_json::Value, key: &str) -> Result<String> {
    action
        .get(key)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .with_context(|| format!("Missing or non-string '{key}' parameter"))
}

/// Decode `body` according to the **explicit** `encoding` field.
///
/// There is no sniffing, deliberately: `"48656c6c6f"` is simultaneously valid text and valid
/// hex, and only the sender knows which it means. This is the same contract the inbound
/// `stomp_send` event uses (`body` plus `body_encoding`), so echoing a received body straight
/// back reproduces the exact bytes.
fn decode_body(action: &serde_json::Value) -> Result<Vec<u8>> {
    let body = action.get("body").and_then(|v| v.as_str()).unwrap_or("");
    match action
        .get("encoding")
        .and_then(|v| v.as_str())
        .unwrap_or("utf8")
    {
        "utf8" => Ok(body.as_bytes().to_vec()),
        "hex" => {
            let cleaned: String = body
                .trim()
                .trim_start_matches("0x")
                .chars()
                .filter(|c| !c.is_whitespace() && *c != ':')
                .collect();
            hex::decode(&cleaned).map_err(|e| {
                anyhow::anyhow!("'body' is not valid hex although encoding is \"hex\": {e}")
            })
        }
        other => Err(anyhow::anyhow!(
            "Unknown 'encoding' {other:?}; valid values are \"utf8\" (default) and \"hex\""
        )),
    }
}

/// Model-supplied extra headers.
///
/// `content-length` is dropped: it is computed from the body the model actually sent, and a
/// wrong one supplied here would truncate the frame or make the peer wait for bytes that never
/// come. Nested values are refused rather than stringified, because there is no
/// representation of a JSON object in a STOMP header that a client could read back.
fn extra_headers(action: &serde_json::Value) -> Result<Vec<(String, String)>> {
    let Some(map) = action.get("headers").and_then(|v| v.as_object()) else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for (k, v) in map {
        if k == "content-length" {
            continue;
        }
        let value = match v {
            serde_json::Value::String(s) => s.clone(),
            serde_json::Value::Number(n) => n.to_string(),
            serde_json::Value::Bool(b) => b.to_string(),
            serde_json::Value::Null => continue,
            _ => {
                return Err(anyhow::anyhow!(
                    "header {k:?} must be a string, number or boolean; a STOMP header cannot \
                     carry a nested object or array"
                ))
            }
        };
        out.push((k.clone(), value));
    }
    Ok(out)
}

// === action definitions ===

fn send_stomp_connected_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_stomp_connected".to_string(),
        description: format!(
            "Accept the client's CONNECT and open the session. This or send_stomp_error is the \
             only valid answer to stomp_connect - STOMP has no third option, and a client that \
             gets neither blocks. Heart-beating is always negotiated off ({STOMP_HEARTBEAT}) \
             because this server implements no heart-beat timer, so there is no parameter for it."
        ),
        parameters: vec![
            Parameter {
                name: "version".to_string(),
                type_hint: "string".to_string(),
                description: format!(
                    "Negotiated protocol version. Only \"{STOMP_VERSION}\" is implemented; \
                     omit to use it."
                ),
                required: false,
            },
            Parameter {
                name: "session".to_string(),
                type_hint: "string".to_string(),
                description: "Session identifier shown to the client".to_string(),
                required: false,
            },
            Parameter {
                name: "server".to_string(),
                type_hint: "string".to_string(),
                description: "Server name/version string, e.g. \"netget/stomp\"".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_stomp_connected",
            "version": "1.2",
            "session": "session-1",
            "server": "netget/stomp"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> STOMP CONNECTED (session {session})")
                .with_debug("STOMP send_stomp_connected: session={session} server={server}"),
        ),
    }
}

fn send_stomp_message_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_stomp_message".to_string(),
        description: "Deliver a MESSAGE frame to the client. `subscription` must be the id the \
                      client used in its SUBSCRIBE, or the client will discard the frame; \
                      `message_id` is yours to choose and must be unique within the session."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "destination".to_string(),
                type_hint: "string".to_string(),
                description: "Destination the message belongs to, e.g. \"/queue/test\"".to_string(),
                required: true,
            },
            Parameter {
                name: "subscription".to_string(),
                type_hint: "string".to_string(),
                description: "The subscription id from the client's SUBSCRIBE frame".to_string(),
                required: true,
            },
            Parameter {
                name: "message_id".to_string(),
                type_hint: "string".to_string(),
                description: "Unique identifier for this message".to_string(),
                required: true,
            },
            Parameter {
                name: "body".to_string(),
                type_hint: "string".to_string(),
                description: "Message body, interpreted according to `encoding`".to_string(),
                required: false,
            },
            Parameter {
                name: "encoding".to_string(),
                type_hint: "string".to_string(),
                description: "How to read `body`: \"utf8\" (default) sends the characters as \
                              they are; \"hex\" decodes hex digits into bytes. There is no \
                              sniffing - say which you mean."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "content_type".to_string(),
                type_hint: "string".to_string(),
                description: "MIME type of the body, e.g. \"text/plain\"".to_string(),
                required: false,
            },
            Parameter {
                name: "headers".to_string(),
                type_hint: "object".to_string(),
                description: "Additional headers as a flat string-to-string map. \
                              `content-length` is ignored - it is computed from the body."
                    .to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_stomp_message",
            "destination": "/queue/test",
            "subscription": "sub-0",
            "message_id": "msg-1",
            "content_type": "text/plain",
            "body": "hello from netget",
            "encoding": "utf8"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> STOMP MESSAGE {destination} (sub {subscription})")
                .with_debug(
                    "STOMP send_stomp_message: destination={destination} \
                     subscription={subscription} message_id={message_id}",
                ),
        ),
    }
}

fn send_stomp_receipt_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_stomp_receipt".to_string(),
        description: "Send a RECEIPT frame. You rarely need this: any client frame carrying a \
                      `receipt` header is answered with a RECEIPT automatically once the frame \
                      has been processed. Use it only to acknowledge something out of band."
            .to_string(),
        parameters: vec![Parameter {
            name: "receipt_id".to_string(),
            type_hint: "string".to_string(),
            description: "Value of the client's `receipt` header".to_string(),
            required: true,
        }],
        example: json!({"type": "send_stomp_receipt", "receipt_id": "receipt-1"}),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> STOMP RECEIPT {receipt_id}")
                .with_debug("STOMP send_stomp_receipt: receipt_id={receipt_id}"),
        ),
    }
}

fn send_stomp_error_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_stomp_error".to_string(),
        description: "Refuse with an ERROR frame. The STOMP spec requires the connection to be \
                      closed afterwards, and this server does so automatically - so this is a \
                      final answer, not something to follow with more frames."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "message".to_string(),
                type_hint: "string".to_string(),
                description: "Short reason, becomes the `message` header".to_string(),
                required: true,
            },
            Parameter {
                name: "body".to_string(),
                type_hint: "string".to_string(),
                description: "Longer explanation, becomes the frame body".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_stomp_error",
            "message": "authentication failed",
            "body": "The login/passcode pair was not recognised."
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> STOMP ERROR: {message}")
                .with_debug("STOMP send_stomp_error: {message}"),
        ),
    }
}

fn close_connection_action() -> ActionDefinition {
    ActionDefinition {
        name: "close_connection".to_string(),
        description: "Close the STOMP connection without saying anything further".to_string(),
        parameters: vec![],
        example: json!({"type": "close_connection"}),
        log_template: Some(
            LogTemplate::new()
                .with_info("STOMP connection closed")
                .with_debug("STOMP close_connection"),
        ),
    }
}

// === event types ===

/// Actions that make sense once a session is open.
fn session_actions() -> Vec<ActionDefinition> {
    vec![
        send_stomp_message_action(),
        send_stomp_receipt_action(),
        send_stomp_error_action(),
        close_connection_action(),
    ]
}

/// Client sent `CONNECT` (or its `STOMP` synonym).
pub static STOMP_CONNECT_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "stomp_connect",
        "Client opened a STOMP session with a CONNECT or STOMP frame. Answer with \
         send_stomp_connected to admit it or send_stomp_error to refuse; the client blocks \
         until one of the two arrives.",
        json!({
            "type": "send_stomp_connected",
            "version": "1.2",
            "session": "session-1",
            "server": "netget/stomp"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "accept_version".to_string(),
            type_hint: "string".to_string(),
            description: "Comma-separated versions the client accepts".to_string(),
            required: false,
        },
        Parameter {
            name: "host".to_string(),
            type_hint: "string".to_string(),
            description: "Virtual host the client asked for".to_string(),
            required: false,
        },
        Parameter {
            name: "login".to_string(),
            type_hint: "string".to_string(),
            description: "Login name offered by the client, if any".to_string(),
            required: false,
        },
        Parameter {
            name: "passcode".to_string(),
            type_hint: "string".to_string(),
            description: "Passcode offered by the client, if any".to_string(),
            required: false,
        },
        Parameter {
            name: "heart_beat".to_string(),
            type_hint: "string".to_string(),
            description: "The client's requested heart-beat pair. Informational only: this \
                          server always negotiates 0,0."
                .to_string(),
            required: false,
        },
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("STOMP CONNECT host={host} login={login}")
            .with_debug("STOMP connect: accept_version={accept_version} host={host} login={login}")
            .with_trace("STOMP connect: {json_pretty(.)}"),
    )
    .with_actions(vec![
        send_stomp_connected_action(),
        send_stomp_error_action(),
        close_connection_action(),
    ])
    .with_alternative_example(json!({
        "type": "send_stomp_error",
        "message": "authentication failed",
        "body": "The login/passcode pair was not recognised."
    }))
});

/// Client published a frame with `SEND`.
pub static STOMP_SEND_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "stomp_send",
        "Client published a message to a destination. A broker normally says nothing in reply, \
         so answering with no action is legitimate; deliver it onward with send_stomp_message \
         if a subscriber should see it.",
        json!({
            "type": "send_stomp_message",
            "destination": "/queue/test",
            "subscription": "sub-0",
            "message_id": "msg-1",
            "body": "hello from netget",
            "encoding": "utf8"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "destination".to_string(),
            type_hint: "string".to_string(),
            description: "Destination the client published to".to_string(),
            required: true,
        },
        Parameter {
            name: "body".to_string(),
            type_hint: "string".to_string(),
            description: "The message body, read according to body_encoding".to_string(),
            required: false,
        },
        Parameter {
            name: "body_encoding".to_string(),
            type_hint: "string".to_string(),
            description: "\"utf8\" when the body was printable text, \"hex\" when it was not. \
                          Pass it through to send_stomp_message's `encoding` to echo the exact \
                          bytes back."
                .to_string(),
            required: true,
        },
        Parameter {
            name: "headers".to_string(),
            type_hint: "object".to_string(),
            description: "Every other header on the frame, including content-type and any \
                          transaction id"
                .to_string(),
            required: false,
        },
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("STOMP SEND {destination}")
            .with_debug("STOMP send: destination={destination} encoding={body_encoding}")
            .with_trace("STOMP send: {json_pretty(.)}"),
    )
    .with_actions(session_actions())
});

/// Client subscribed to a destination.
pub static STOMP_SUBSCRIBE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "stomp_subscribe",
        "Client subscribed to a destination. Send it messages with send_stomp_message, quoting \
         this subscription id.",
        json!({
            "type": "send_stomp_message",
            "destination": "/queue/test",
            "subscription": "sub-0",
            "message_id": "msg-1",
            "body": "welcome",
            "encoding": "utf8"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "destination".to_string(),
            type_hint: "string".to_string(),
            description: "Destination subscribed to".to_string(),
            required: true,
        },
        Parameter {
            name: "id".to_string(),
            type_hint: "string".to_string(),
            description: "Subscription id chosen by the client; quote it in send_stomp_message"
                .to_string(),
            required: true,
        },
        Parameter {
            name: "ack_mode".to_string(),
            type_hint: "string".to_string(),
            description: "\"auto\" (default), \"client\" or \"client-individual\"".to_string(),
            required: false,
        },
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("STOMP SUBSCRIBE {destination} (id {id})")
            .with_debug("STOMP subscribe: destination={destination} id={id} ack={ack_mode}")
            .with_trace("STOMP subscribe: {json_pretty(.)}"),
    )
    .with_actions(session_actions())
});

/// Client cancelled a subscription.
pub static STOMP_UNSUBSCRIBE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "stomp_unsubscribe",
        "Client cancelled a subscription. Answering with no action is the normal case - any \
         receipt the frame asked for is sent for you. Use send_stomp_message only if a \
         message still has to go out on another subscription.",
        json!({
            "type": "send_stomp_message",
            "destination": "/queue/test",
            "subscription": "sub-1",
            "message_id": "msg-9",
            "body": "sent on a subscription that is still open",
            "encoding": "utf8"
        }),
    )
    .with_parameters(vec![Parameter {
        name: "id".to_string(),
        type_hint: "string".to_string(),
        description: "Subscription id being cancelled".to_string(),
        required: true,
    }])
    .with_log_template(
        LogTemplate::new()
            .with_info("STOMP UNSUBSCRIBE id={id}")
            .with_debug("STOMP unsubscribe: id={id}")
            .with_trace("STOMP unsubscribe: {json_pretty(.)}"),
    )
    .with_actions(session_actions())
});

/// Client acknowledged a message.
pub static STOMP_ACK_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "stomp_ack",
        "Client acknowledged a message it had been sent. Answering with no action is \
         legitimate; the usual reason to answer is to send the next message now that this one \
         is settled. Any receipt the frame asked for is sent for you.",
        json!({
            "type": "send_stomp_message",
            "destination": "/queue/test",
            "subscription": "sub-0",
            "message_id": "msg-2",
            "body": "the next message",
            "encoding": "utf8"
        }),
    )
    .with_parameters(vec![Parameter {
        name: "id".to_string(),
        type_hint: "string".to_string(),
        description: "The ack id, which is the message-id of the MESSAGE being acknowledged"
            .to_string(),
        required: true,
    }])
    .with_log_template(
        LogTemplate::new()
            .with_info("STOMP ACK id={id}")
            .with_debug("STOMP ack: id={id}")
            .with_trace("STOMP ack: {json_pretty(.)}"),
    )
    .with_actions(session_actions())
});

/// Client rejected a message.
pub static STOMP_NACK_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "stomp_nack",
        "Client rejected a message it had been sent. This server does not redeliver on its own \
         - resend it with send_stomp_message if that is what you want, or answer with no \
         action to drop it. Any receipt the frame asked for is sent for you.",
        json!({
            "type": "send_stomp_message",
            "destination": "/queue/test",
            "subscription": "sub-0",
            "message_id": "msg-1-retry",
            "body": "redelivered after NACK",
            "encoding": "utf8"
        }),
    )
    .with_parameters(vec![Parameter {
        name: "id".to_string(),
        type_hint: "string".to_string(),
        description: "The ack id, which is the message-id of the MESSAGE being rejected"
            .to_string(),
        required: true,
    }])
    .with_log_template(
        LogTemplate::new()
            .with_info("STOMP NACK id={id}")
            .with_debug("STOMP nack: id={id}")
            .with_trace("STOMP nack: {json_pretty(.)}"),
    )
    .with_actions(session_actions())
});

/// Client is closing the session.
pub static STOMP_DISCONNECT_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "stomp_disconnect",
        "Client is shutting the session down. The connection closes as soon as this is handled \
         (and after its receipt, if it asked for one), so this is the last chance to say \
         anything.",
        json!({"type": "close_connection"}),
    )
    .with_parameters(vec![Parameter {
        name: "receipt".to_string(),
        type_hint: "string".to_string(),
        description: "The receipt id the client asked for, if any. It is answered \
                      automatically; this field is here so a handler can see it."
            .to_string(),
        required: false,
    }])
    .with_log_template(
        LogTemplate::new()
            .with_info("STOMP DISCONNECT")
            .with_debug("STOMP disconnect: receipt={receipt}")
            .with_trace("STOMP disconnect: {json_pretty(.)}"),
    )
    .with_actions(vec![
        send_stomp_message_action(),
        send_stomp_receipt_action(),
        close_connection_action(),
    ])
});

pub fn get_stomp_event_types() -> Vec<EventType> {
    vec![
        STOMP_CONNECT_EVENT.clone(),
        STOMP_SEND_EVENT.clone(),
        STOMP_SUBSCRIBE_EVENT.clone(),
        STOMP_UNSUBSCRIBE_EVENT.clone(),
        STOMP_ACK_EVENT.clone(),
        STOMP_NACK_EVENT.clone(),
        STOMP_DISCONNECT_EVENT.clone(),
    ]
}

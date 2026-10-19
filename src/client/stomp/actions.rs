//! STOMP 1.2 client actions.
//!
//! The division of labour mirrors the server side (`src/server/stomp/`): everything
//! mechanical is Rust and is never asked of the model — frame boundaries, header escaping,
//! the `content-length`/NUL body rule, the `accept-version` handshake and the receipt that
//! makes `DISCONNECT` graceful. What the model decides is *content*: which destination to
//! subscribe to, what to publish, whether a delivered message deserves an `ACK` or a `NACK`,
//! and when the session is over.
//!
//! The codec itself is [`crate::server::stomp::frame`], reused verbatim rather than copied.
//! Its two private helpers (`decode_body`, `extra_headers`) are not reachable from here, so
//! their client-side equivalents live in this file; see `src/client/stomp/CLAUDE.md`.

use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, Parameter, ParameterDefinition,
};
use crate::protocol::EventType;
use crate::server::stomp::frame::StompFrame;
use crate::state::app_state::AppState;
use anyhow::{Context, Result};
use serde_json::json;
use std::sync::LazyLock;

/// The only protocol version this client offers in `accept-version`, and the only one it will
/// accept back in `CONNECTED`.
///
/// Offering `1.0,1.1,1.2` would mean being prepared to speak whichever the broker picks, and
/// this client implements 1.2 only — the `ack` header on `ACK`/`NACK` is 1.2-shaped, and 1.1
/// wants `message-id`/`subscription` instead. Advertising a dialect we cannot speak is the
/// same class of lie as advertising heart-beats we do not send.
pub const STOMP_ACCEPT_VERSION: &str = "1.2";

/// Heart-beating is negotiated off, unconditionally.
///
/// This client runs no heart-beat timer and never emits a bare EOL, so any other value would
/// promise a broker something it will not get — and a broker that believes it will hear from
/// us every N ms tears the connection down when it does not. `0` in our send position also
/// makes the negotiated interval zero in both directions per the spec's formula, so a
/// compliant broker stops expecting them. There is deliberately no startup parameter for it.
pub const STOMP_HEARTBEAT: &str = "0,0";

/// The `receipt` header the `disconnect` action puts on its `DISCONNECT` frame.
///
/// The spec's graceful shutdown is DISCONNECT-with-receipt, then wait for the matching
/// `RECEIPT`, then close — that is the only way a publisher learns the broker durably took
/// everything it sent. Fixing the id here rather than letting the model choose one means the
/// read loop can recognise the acknowledgement of *its own* shutdown without tracking any
/// state, and it works identically for a model-produced action and one injected from the
/// dashboard.
pub const DISCONNECT_RECEIPT_ID: &str = "netget-stomp-disconnect";

/// Raised once the broker's `CONNECTED` has been received and validated.
///
/// This fires *after* the handshake has been checked, never before: a session that did not
/// produce a well-formed `CONNECTED` is refused in `connect()` and no event is raised at all.
pub static STOMP_CLIENT_CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "stomp_connected",
        "The STOMP session is open: the broker answered CONNECT with a valid CONNECTED frame",
        json!({
            "type": "send_stomp_subscribe",
            "destination": "/queue/test",
            "id": "sub-0",
            "ack_mode": "auto"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "version".to_string(),
            type_hint: "string".to_string(),
            description: "Protocol version the broker agreed to (always 1.2 here)".to_string(),
            required: true,
        },
        Parameter {
            name: "session".to_string(),
            type_hint: "string".to_string(),
            description: "Broker-assigned session identifier, empty if the broker sent none"
                .to_string(),
            required: false,
        },
        Parameter {
            name: "server".to_string(),
            type_hint: "string".to_string(),
            description: "Broker software identification, empty if the broker sent none"
                .to_string(),
            required: false,
        },
    ])
    .with_actions(vec![
        send_stomp_subscribe_action(),
        send_stomp_send_action(),
        disconnect_action(),
        wait_for_more_action(),
    ])
});

/// Raised for every `MESSAGE` frame the broker delivers to one of our subscriptions.
pub static STOMP_CLIENT_MESSAGE_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "stomp_message_received",
        "A MESSAGE frame was delivered on one of this client's subscriptions",
        json!({
            "type": "send_stomp_send",
            "destination": "/queue/replies",
            "body": "got it",
            "encoding": "utf8"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "destination".to_string(),
            type_hint: "string".to_string(),
            description: "Destination the message was published to".to_string(),
            required: true,
        },
        Parameter {
            name: "message_id".to_string(),
            type_hint: "string".to_string(),
            description: "Broker-assigned message identifier".to_string(),
            required: true,
        },
        Parameter {
            name: "subscription".to_string(),
            type_hint: "string".to_string(),
            description: "Id of the subscription this delivery belongs to - the same id that \
                          was passed to send_stomp_subscribe"
                .to_string(),
            required: true,
        },
        Parameter {
            name: "headers".to_string(),
            type_hint: "object".to_string(),
            description: "Every other header on the frame, as a flat string map. When the \
                          subscription uses ack_mode \"client\" or \"client-individual\" the \
                          broker puts an \"ack\" header here, and its value is what \
                          send_stomp_ack / send_stomp_nack take as their 'id'."
                .to_string(),
            required: false,
        },
        Parameter {
            name: "body".to_string(),
            type_hint: "string".to_string(),
            description: "The message body, encoded as body_encoding says".to_string(),
            required: false,
        },
        Parameter {
            name: "body_encoding".to_string(),
            type_hint: "string".to_string(),
            description: "\"utf8\" when the body was printable text, \"hex\" when it was \
                          binary. Pass both fields straight into send_stomp_send to republish \
                          the exact bytes."
                .to_string(),
            required: true,
        },
    ])
    .with_actions(vec![
        send_stomp_send_action(),
        send_stomp_ack_action(),
        send_stomp_nack_action(),
        send_stomp_subscribe_action(),
        send_stomp_unsubscribe_action(),
        wait_for_more_action(),
        disconnect_action(),
    ])
});

/// Raised for every `RECEIPT` frame, except the one acknowledging our own `DISCONNECT`.
///
/// That one ends the session, so asking the model what to do about it would spend a model call
/// on a connection that is already closing and whose answer could not be written anywhere.
pub static STOMP_CLIENT_RECEIPT_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "stomp_receipt_received",
        "The broker acknowledged a frame that carried a receipt header",
        json!({"type": "wait_for_more"}),
    )
    .with_parameters(vec![Parameter {
        name: "receipt_id".to_string(),
        type_hint: "string".to_string(),
        description: "Value of the receipt-id header, matching the receipt asked for".to_string(),
        required: true,
    }])
    .with_actions(vec![
        wait_for_more_action(),
        send_stomp_send_action(),
        disconnect_action(),
    ])
});

/// Raised for an `ERROR` frame. The broker closes the connection after sending one, so this is
/// the last thing the model hears on this session.
pub static STOMP_CLIENT_ERROR_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "stomp_error_received",
        "The broker sent an ERROR frame; per the STOMP specification it closes the connection \
         immediately afterwards, so this session is over",
        json!({"type": "wait_for_more"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "message".to_string(),
            type_hint: "string".to_string(),
            description: "The ERROR frame's 'message' header - the broker's short reason"
                .to_string(),
            required: false,
        },
        Parameter {
            name: "body".to_string(),
            type_hint: "string".to_string(),
            description: "The ERROR frame's body, encoded as body_encoding says".to_string(),
            required: false,
        },
        Parameter {
            name: "body_encoding".to_string(),
            type_hint: "string".to_string(),
            description: "\"utf8\" when the body was printable text, \"hex\" when it was binary"
                .to_string(),
            required: true,
        },
    ])
    // Nothing can be written to a connection the broker is closing, so the only useful answers
    // are the common actions (set_memory, show_message, append_to_log) plus an explicit
    // acknowledgement that there is nothing to send.
    .with_actions(vec![wait_for_more_action()])
});

/// STOMP 1.2 client protocol action handler.
pub struct StompClientProtocol;

impl StompClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

impl Default for StompClientProtocol {
    fn default() -> Self {
        Self::new()
    }
}

impl Protocol for StompClientProtocol {
    /// The whole vocabulary lives here.
    ///
    /// `call_llm_for_client` advertises the union of async, sync and the firing event's own
    /// actions (`client_llm_action_set`), and a client has a single LLM entry point, so a
    /// sync/async split cannot express a narrowing the way a server's can. Declaring the list
    /// once and attaching per-event subsets to the event types is the shape that says
    /// something; duplicating it into `get_sync_actions()` would say nothing.
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![
            send_stomp_subscribe_action(),
            send_stomp_send_action(),
            send_stomp_unsubscribe_action(),
            send_stomp_ack_action(),
            send_stomp_nack_action(),
            wait_for_more_action(),
            disconnect_action(),
        ]
    }

    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        Vec::new()
    }

    fn protocol_name(&self) -> &'static str {
        "STOMP"
    }

    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            STOMP_CLIENT_CONNECTED_EVENT.clone(),
            STOMP_CLIENT_MESSAGE_RECEIVED_EVENT.clone(),
            STOMP_CLIENT_RECEIPT_RECEIVED_EVENT.clone(),
            STOMP_CLIENT_ERROR_RECEIVED_EVENT.clone(),
        ]
    }

    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>STOMP"
    }

    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "stomp",
            "stomp client",
            "message broker client",
            "subscribe to a queue",
        ]
    }

    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "host".to_string(),
                type_hint: "string".to_string(),
                description: "Virtual host for the CONNECT frame's 'host' header. Defaults to \
                              the host part of remote_addr, which is what the specification \
                              says a client should send when it has no better answer."
                    .to_string(),
                required: false,
                example: json!("/"),
                default: None,
            },
            ParameterDefinition {
                name: "login".to_string(),
                type_hint: "string".to_string(),
                description: "Value for the CONNECT frame's 'login' header. Omitted entirely \
                              when not supplied."
                    .to_string(),
                required: false,
                example: json!("guest"),
                default: None,
            },
            ParameterDefinition {
                name: "passcode".to_string(),
                type_hint: "string".to_string(),
                description: "Value for the CONNECT frame's 'passcode' header. Sent in \
                              cleartext - this client has no TLS."
                    .to_string(),
                required: false,
                example: json!("guest"),
                default: None,
            },
            ParameterDefinition {
                name: "use_stomp_command".to_string(),
                type_hint: "boolean".to_string(),
                description: "Send the 1.2-preferred 'STOMP' command instead of 'CONNECT'. \
                              Identical otherwise; some brokers log the two differently and \
                              1.0-only brokers reject STOMP, which is the point of the choice."
                    .to_string(),
                required: false,
                example: json!(false),
                default: None,
            },
            ParameterDefinition {
                name: "handshake_timeout_secs".to_string(),
                type_hint: "number".to_string(),
                description: "How long to wait for the broker's CONNECTED before giving up \
                              (default 20). A broker that never answers must not leave the \
                              client wedged in Connecting."
                    .to_string(),
                required: false,
                example: json!(20),
                default: None,
            },
        ]
    }

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{
            DevelopmentState, PrivilegeRequirement, ProtocolMetadataV2,
        };

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation(
                "Tokio TCP driving the STOMP 1.2 codec in src/server/stomp/frame.rs, reused \
                 rather than duplicated. The handshake, the content-length/NUL body rule, \
                 header escaping and the DISCONNECT receipt are deterministic Rust; the model \
                 chooses destinations, bodies and acknowledgements.",
            )
            .llm_control(
                "SUBSCRIBE / SEND / UNSUBSCRIBE / ACK / NACK / DISCONNECT, decided per event. \
                 The model never sees or writes frame bytes.",
            )
            .e2e_testing(
                "tests/client/stomp/e2e_test.rs drives this client against NetGet's own STOMP \
                 server over a real TCP socket, plus a hand-written broker that answers the \
                 handshake wrongly. Not #[ignore]d and it cannot skip - there is no external \
                 binary to detect as missing.",
            )
            .notes(
                "EXPERIMENTAL, and precisely so: the only peer this client has ever been run \
                 against is NetGet's own STOMP server. That is same-project evidence - it \
                 shows the two halves of this repository agree with each other, not that \
                 either matches RFC-equivalent broker behaviour, and a shared misreading of \
                 the specification would be invisible to it. The async-stomp crate cannot \
                 close the gap because it is itself a client. Beta needs one exchange against \
                 a real broker (ActiveMQ, or RabbitMQ with the STOMP plugin); \
                 src/client/stomp/CLAUDE.md spells out the exact test. NOT IMPLEMENTED, and \
                 none of it is hidden: heart-beating (negotiated 0,0, which is a legal \
                 configuration rather than a silent omission), transactions \
                 (BEGIN/COMMIT/ABORT), STOMP 1.0/1.1 (a CONNECTED naming any other version is \
                 refused rather than guessed at) and TLS, so login/passcode travel in \
                 cleartext.",
            )
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            // Frames that arrive while the model answers wait on the reader task's queue and
            // are answered in one call, one event per frame (`run_session` in mod.rs).
            .batching(crate::protocol::metadata::BatchingMode::On)
            .build()
    }

    fn description(&self) -> &'static str {
        "STOMP 1.2 client for subscribing to and publishing on a message broker"
    }

    fn example_prompt(&self) -> &'static str {
        "Connect to the STOMP broker at 127.0.0.1:61613, subscribe to /queue/test, and reply \
         on /queue/replies to whatever arrives"
    }

    fn group_name(&self) -> &'static str {
        "Application"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;

        StartupExamples::new(
            // LLM mode: the model drives the whole session.
            json!({
                "type": "open_client",
                "remote_addr": "127.0.0.1:61613",
                "base_stack": "stomp",
                "instruction": "Subscribe to /queue/test and reply on /queue/replies to every \
                                message that arrives"
            }),
            // Script mode: deterministic handling of each delivery.
            json!({
                "type": "open_client",
                "remote_addr": "127.0.0.1:61613",
                "base_stack": "stomp",
                "event_handlers": [{
                    "event_pattern": "stomp_message_received",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "respond([{'type': 'send_stomp_send', 'destination': '/queue/replies', 'body': event['body'], 'encoding': event['body_encoding']}])"
                    }
                }]
            }),
            // Static mode: subscribe on connect, then say nothing.
            json!({
                "type": "open_client",
                "remote_addr": "127.0.0.1:61613",
                "base_stack": "stomp",
                "event_handlers": [
                    {
                        "event_pattern": "stomp_connected",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "send_stomp_subscribe",
                                "destination": "/queue/test",
                                "id": "sub-0",
                                "ack_mode": "auto"
                            }]
                        }
                    },
                    {
                        "event_pattern": "stomp_message_received",
                        "handler": {
                            "type": "static",
                            "actions": [{"type": "wait_for_more"}]
                        }
                    }
                ]
            }),
        )
    }
}

impl Client for StompClientProtocol {
    fn connect(
        &self,
        ctx: crate::protocol::ConnectContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            crate::client::stomp::StompClient::connect_with_llm_actions(
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
            "send_stomp_subscribe" => {
                let destination = required_str(&action, "destination")?;
                let id = required_str(&action, "id")?;
                let ack_mode = action
                    .get("ack_mode")
                    .and_then(|v| v.as_str())
                    .unwrap_or("auto")
                    .to_string();
                if !matches!(ack_mode.as_str(), "auto" | "client" | "client-individual") {
                    return Err(anyhow::anyhow!(
                        "'ack_mode' must be \"auto\", \"client\" or \"client-individual\"; got \
                         {ack_mode:?}"
                    ));
                }
                let mut headers = vec![
                    ("destination".to_string(), destination),
                    ("id".to_string(), id),
                    ("ack".to_string(), ack_mode),
                ];
                push_receipt(&mut headers, &action);
                Ok(ClientActionResult::SendData(
                    StompFrame::new("SUBSCRIBE", headers, Vec::new()).encode(),
                ))
            }

            "send_stomp_send" => {
                let destination = required_str(&action, "destination")?;
                let body = decode_body(&action)?;
                let mut headers = vec![("destination".to_string(), destination)];
                if let Some(content_type) = action.get("content_type").and_then(|v| v.as_str()) {
                    headers.push(("content-type".to_string(), content_type.to_string()));
                }
                headers.extend(extra_headers(&action)?);
                push_receipt(&mut headers, &action);
                Ok(ClientActionResult::SendData(
                    StompFrame::new("SEND", headers, body).encode(),
                ))
            }

            "send_stomp_unsubscribe" => {
                let id = required_str(&action, "id")?;
                let mut headers = vec![("id".to_string(), id)];
                push_receipt(&mut headers, &action);
                Ok(ClientActionResult::SendData(
                    StompFrame::new("UNSUBSCRIBE", headers, Vec::new()).encode(),
                ))
            }

            "send_stomp_ack" | "send_stomp_nack" => {
                let id = required_str(&action, "id")?;
                let command = if action_type == "send_stomp_ack" {
                    "ACK"
                } else {
                    "NACK"
                };
                let mut headers = vec![("id".to_string(), id)];
                push_receipt(&mut headers, &action);
                Ok(ClientActionResult::SendData(
                    StompFrame::new(command, headers, Vec::new()).encode(),
                ))
            }

            "wait_for_more" => Ok(ClientActionResult::WaitForMore),

            // The graceful shutdown the specification defines, not a socket close: the frame
            // carries a fixed receipt and the read loop closes when the matching RECEIPT comes
            // back (or when the grace period lapses). Returning
            // `ClientActionResult::Disconnect` here would hang up before the broker had
            // acknowledged anything we published.
            "disconnect" => Ok(ClientActionResult::SendData(
                StompFrame::new(
                    "DISCONNECT",
                    vec![("receipt".to_string(), DISCONNECT_RECEIPT_ID.to_string())],
                    Vec::new(),
                )
                .encode(),
            )),

            other => Err(anyhow::anyhow!("Unknown STOMP client action: {other}")),
        }
    }
}

// === helpers ===

fn required_str(action: &serde_json::Value, key: &str) -> Result<String> {
    action
        .get(key)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .with_context(|| format!("Missing or non-string '{key}' parameter"))
}

/// Attach an optional `receipt` header, which is how a client asks the broker to confirm a
/// frame it would otherwise never hear about again.
fn push_receipt(headers: &mut Vec<(String, String)>, action: &serde_json::Value) {
    if let Some(receipt) = action.get("receipt").and_then(|v| v.as_str()) {
        if !receipt.is_empty() {
            headers.push(("receipt".to_string(), receipt.to_string()));
        }
    }
}

/// Decode `body` according to the **explicit** `encoding` field.
///
/// Never sniffed: `"48656c6c6f"` is simultaneously valid text and valid hex, and only the
/// sender knows which it means (the `send_tcp_data` bug, `d70bb5b5`). This is the same
/// contract the inbound `stomp_message_received` event uses, so passing a received
/// `body`/`body_encoding` pair straight into `send_stomp_send` republishes the exact bytes.
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
            "Invalid 'encoding' {other:?}; valid values are \"utf8\" (default) and \"hex\""
        )),
    }
}

/// Model-supplied extra headers for `SEND`.
///
/// `content-length` is dropped: the codec computes it from the body actually sent, and a wrong
/// one either truncates the frame or makes the broker wait for bytes that never arrive.
/// `destination`, `content-type` and `receipt` are dropped too — each has its own named
/// parameter, and a duplicate header is resolved by first-occurrence-wins, so allowing both
/// routes would make which one applies depend on map ordering. Nested values are refused
/// rather than stringified: there is no representation of a JSON object in a STOMP header that
/// a broker could read back.
fn extra_headers(action: &serde_json::Value) -> Result<Vec<(String, String)>> {
    let Some(map) = action.get("headers").and_then(|v| v.as_object()) else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for (k, v) in map {
        if matches!(
            k.as_str(),
            "content-length" | "destination" | "content-type" | "receipt"
        ) {
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

fn send_stomp_subscribe_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_stomp_subscribe".to_string(),
        description: "Subscribe to a destination. The 'id' is chosen by this client, not the \
                      broker, and every MESSAGE delivered for this subscription quotes it back \
                      in stomp_message_received's 'subscription' field - so pick one you can \
                      recognise and reuse it for send_stomp_unsubscribe."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "destination".to_string(),
                type_hint: "string".to_string(),
                description: "Destination to subscribe to, e.g. /queue/test or /topic/news"
                    .to_string(),
                required: true,
            },
            Parameter {
                name: "id".to_string(),
                type_hint: "string".to_string(),
                description: "Subscription id, unique within this connection".to_string(),
                required: true,
            },
            Parameter {
                name: "ack_mode".to_string(),
                type_hint: "string".to_string(),
                description: "\"auto\" (default - the broker considers a message delivered as \
                              soon as it is sent), \"client\" (cumulative: an ACK also \
                              acknowledges everything before it) or \"client-individual\". \
                              Anything but \"auto\" means you must answer each delivery with \
                              send_stomp_ack or send_stomp_nack."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "receipt".to_string(),
                type_hint: "string".to_string(),
                description: "Ask the broker to confirm this frame with a RECEIPT carrying this \
                              id, delivered as a stomp_receipt_received event"
                    .to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_stomp_subscribe",
            "destination": "/queue/test",
            "id": "sub-0",
            "ack_mode": "auto"
        }),
        log_template: None,
    }
}

fn send_stomp_send_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_stomp_send".to_string(),
        description: "Publish a message to a destination. The body's encoding is explicit and \
                      is never guessed: pass a stomp_message_received event's 'body' and \
                      'body_encoding' straight through to republish the exact bytes."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "destination".to_string(),
                type_hint: "string".to_string(),
                description: "Destination to publish to, e.g. /queue/replies".to_string(),
                required: true,
            },
            Parameter {
                name: "body".to_string(),
                type_hint: "string".to_string(),
                description: "Message body, interpreted according to 'encoding'".to_string(),
                required: false,
            },
            Parameter {
                name: "encoding".to_string(),
                type_hint: "string".to_string(),
                description: "\"utf8\" (default) or \"hex\" for binary bodies. There is no \
                              sniffing - \"48656c6c6f\" is valid as both."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "content_type".to_string(),
                type_hint: "string".to_string(),
                description: "Value for the content-type header, e.g. text/plain".to_string(),
                required: false,
            },
            Parameter {
                name: "headers".to_string(),
                type_hint: "object".to_string(),
                description: "Extra headers as a flat string map. content-length is computed \
                              and cannot be set here; destination, content-type and receipt \
                              have their own parameters."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "receipt".to_string(),
                type_hint: "string".to_string(),
                description: "Ask the broker to confirm this publish with a RECEIPT carrying \
                              this id"
                    .to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_stomp_send",
            "destination": "/queue/replies",
            "body": "hello from netget",
            "encoding": "utf8",
            "content_type": "text/plain"
        }),
        log_template: None,
    }
}

fn send_stomp_unsubscribe_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_stomp_unsubscribe".to_string(),
        description: "Cancel a subscription. Takes the same id that was passed to \
                      send_stomp_subscribe; the broker stops delivering for it."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "id".to_string(),
                type_hint: "string".to_string(),
                description: "Subscription id to cancel".to_string(),
                required: true,
            },
            Parameter {
                name: "receipt".to_string(),
                type_hint: "string".to_string(),
                description: "Ask the broker to confirm with a RECEIPT carrying this id"
                    .to_string(),
                required: false,
            },
        ],
        example: json!({"type": "send_stomp_unsubscribe", "id": "sub-0"}),
        log_template: None,
    }
}

fn send_stomp_ack_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_stomp_ack".to_string(),
        description: "Acknowledge a delivered message. Only meaningful when the subscription \
                      was made with ack_mode \"client\" or \"client-individual\". The 'id' is \
                      the delivered frame's own \"ack\" header, which arrives inside the \
                      stomp_message_received event's 'headers' map - it is not the message_id."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "id".to_string(),
                type_hint: "string".to_string(),
                description: "The delivered MESSAGE frame's \"ack\" header value".to_string(),
                required: true,
            },
            Parameter {
                name: "receipt".to_string(),
                type_hint: "string".to_string(),
                description: "Ask the broker to confirm with a RECEIPT carrying this id"
                    .to_string(),
                required: false,
            },
        ],
        example: json!({"type": "send_stomp_ack", "id": "ack-1"}),
        log_template: None,
    }
}

fn send_stomp_nack_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_stomp_nack".to_string(),
        description: "Refuse a delivered message, telling the broker it was not processed. \
                      Same 'id' as send_stomp_ack - the delivered frame's \"ack\" header. What \
                      the broker then does with the message (redeliver, dead-letter, drop) is \
                      its own policy."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "id".to_string(),
                type_hint: "string".to_string(),
                description: "The delivered MESSAGE frame's \"ack\" header value".to_string(),
                required: true,
            },
            Parameter {
                name: "receipt".to_string(),
                type_hint: "string".to_string(),
                description: "Ask the broker to confirm with a RECEIPT carrying this id"
                    .to_string(),
                required: false,
            },
        ],
        example: json!({"type": "send_stomp_nack", "id": "ack-1"}),
        log_template: None,
    }
}

fn wait_for_more_action() -> ActionDefinition {
    ActionDefinition {
        name: "wait_for_more".to_string(),
        description: "Send nothing and keep the session open, waiting for the next frame. This \
                      is a real answer, distinct from failing to answer."
            .to_string(),
        parameters: vec![],
        example: json!({"type": "wait_for_more"}),
        log_template: None,
    }
}

fn disconnect_action() -> ActionDefinition {
    ActionDefinition {
        name: "disconnect".to_string(),
        description: "End the session the way the specification defines it: a DISCONNECT frame \
                      carrying a receipt, then the connection closes once the broker's RECEIPT \
                      comes back. That acknowledgement is what tells a publisher the broker \
                      durably took everything it sent, so this is not the same as hanging up."
            .to_string(),
        parameters: vec![],
        example: json!({"type": "disconnect"}),
        log_template: None,
    }
}

//! NATS client actions, events and metadata.
//!
//! This is the client half of the NATS client protocol: NetGet dials a broker, reads its
//! `INFO`, sends `CONNECT`, and then participates as a peer — `SUB`, `UNSUB`, `PUB`/`HPUB` out,
//! `MSG`/`HMSG`/`+OK`/`-ERR`/`PING`/`PONG` in.
//!
//! What the model decides is *what to say on the fabric*: which subjects to subscribe to, and
//! what to publish in reply to what arrives. What it never sees is the keepalive — `PING` is
//! answered with `PONG` in Rust by the reader task, because a broker whose `PING` goes
//! unanswered for two intervals declares the connection stale and drops it, and a parked
//! manual handler would take minutes.

use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, Parameter,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::EventType;
use crate::state::app_state::AppState;
use anyhow::{Context, Result};
use serde_json::json;
use std::sync::LazyLock;

/// Raised once, after the broker's `INFO` has been read and `CONNECT` written.
///
/// This is the model's chance to subscribe. A client that subscribes to nothing hears
/// nothing, so `send_nats_subscribe` is the expected answer; the `subscribe_subjects` startup
/// parameter covers the same ground deterministically for an operator who does not want to
/// spend a model round-trip (or park a human) before the first message can arrive.
pub static NATS_CLIENT_CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "nats_connected",
        "Connected to a NATS broker: its INFO greeting was read and CONNECT was sent",
        json!({
            "type": "send_nats_subscribe",
            "subject": "orders.>",
            "sid": "1"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "remote_addr".to_string(),
            type_hint: "string".to_string(),
            description: "Broker address this client is connected to".to_string(),
            required: true,
        },
        Parameter {
            name: "server_name".to_string(),
            type_hint: "string".to_string(),
            description: "The broker's self-reported name from INFO".to_string(),
            required: true,
        },
        Parameter {
            name: "server_id".to_string(),
            type_hint: "string".to_string(),
            description: "The broker's opaque id from INFO".to_string(),
            required: true,
        },
        Parameter {
            name: "version".to_string(),
            type_hint: "string".to_string(),
            description: "The broker's advertised NATS version, e.g. \"2.10.0\"".to_string(),
            required: true,
        },
        Parameter {
            name: "max_payload".to_string(),
            type_hint: "number".to_string(),
            description: "Largest payload the broker will accept, in bytes. A larger publish is \
                          refused with -ERR 'Maximum Payload Violation' and the connection is \
                          closed, so do not exceed it"
                .to_string(),
            required: true,
        },
        Parameter {
            name: "headers".to_string(),
            type_hint: "boolean".to_string(),
            description: "Whether the broker supports the header protocol (HPUB/HMSG). When \
                          false, do not set 'headers' on send_nats_publish"
                .to_string(),
            required: true,
        },
        Parameter {
            name: "auth_required".to_string(),
            type_hint: "boolean".to_string(),
            description: "Whether the broker requires credentials. This client sends none, so \
                          when this is true expect -ERR 'Authorization Violation'"
                .to_string(),
            required: true,
        },
        Parameter {
            name: "tls_required".to_string(),
            type_hint: "boolean".to_string(),
            description: "Whether the broker requires TLS. This client speaks plaintext only, so \
                          when this is true the connection cannot proceed"
                .to_string(),
            required: true,
        },
        Parameter {
            name: "subscriptions".to_string(),
            type_hint: "array".to_string(),
            description: "Subscriptions already sent from the 'subscribe_subjects' startup \
                          parameter, each {subject, sid}. Do not subscribe to these again, and \
                          do not reuse their sids"
                .to_string(),
            required: true,
        },
        Parameter {
            name: "info".to_string(),
            type_hint: "object".to_string(),
            description: "The full INFO document verbatim, for any field not broken out above"
                .to_string(),
            required: true,
        },
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("NATS connected to {server_name} ({version}) at {remote_addr}")
            .with_debug("NATS connected: {remote_addr} server={server_name} version={version}")
            .with_trace("NATS INFO: {json_pretty(info)}"),
    )
    .with_actions(vec![
        send_nats_subscribe_action(),
        send_nats_publish_action(),
        send_nats_request_action(),
        wait_for_more_action(),
        disconnect_action(),
    ])
    .with_alternative_example(json!({"type": "wait_for_more"}))
});

/// Raised for every `MSG`/`HMSG` the broker delivers.
///
/// This is the event the whole client exists for: the model reads live traffic off the fabric
/// and may answer with a `send_nats_publish` on the same connection.
pub static NATS_CLIENT_MESSAGE_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "nats_message_received",
        "A message was delivered on one of this client's subscriptions",
        json!({
            "type": "send_nats_publish",
            "subject": "orders.ack",
            "payload": "acknowledged"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "subject".to_string(),
            type_hint: "string".to_string(),
            description: "Concrete subject the message was published on (never a wildcard, even \
                          when the subscription used one)"
                .to_string(),
            required: true,
        },
        Parameter {
            name: "sid".to_string(),
            type_hint: "string".to_string(),
            description: "Subscription id this arrived on — the sid given to send_nats_subscribe"
                .to_string(),
            required: true,
        },
        Parameter {
            name: "reply_to".to_string(),
            type_hint: "string".to_string(),
            description: "Reply subject when the sender expects an answer, otherwise null. \
                          Publish to this subject with send_nats_publish to answer the requester"
                .to_string(),
            required: false,
        },
        Parameter {
            name: "payload".to_string(),
            type_hint: "string".to_string(),
            description: "The message body: the text itself when every byte is printable, \
                          otherwise hex. 'payload_encoding' says which"
                .to_string(),
            required: true,
        },
        Parameter {
            name: "payload_encoding".to_string(),
            type_hint: "string".to_string(),
            description: "\"utf8\" or \"hex\", describing 'payload'. Pass it through as \
                          'encoding' on send_nats_publish to forward the bytes unchanged"
                .to_string(),
            required: true,
        },
        Parameter {
            name: "headers".to_string(),
            type_hint: "object".to_string(),
            description: "Headers from an HMSG as a flat object, empty for a plain MSG".to_string(),
            required: true,
        },
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("<- NATS MSG {subject} sid={sid}")
            .with_debug("NATS message: subject={subject} sid={sid} reply_to={reply_to}")
            .with_trace("NATS message: {json_pretty(.)}"),
    )
    .with_actions(vec![
        send_nats_publish_action(),
        send_nats_subscribe_action(),
        send_nats_unsubscribe_action(),
        send_nats_request_action(),
        wait_for_more_action(),
        disconnect_action(),
    ])
    .with_alternative_example(json!({"type": "wait_for_more"}))
});

/// Raised for a `-ERR` that is not a permissions violation.
///
/// A NATS broker treats most `-ERR` frames as fatal and hangs up immediately afterwards, so
/// by the time the model reads this the socket is usually already closing. It is raised
/// anyway: the text is the only explanation anyone gets for why the session ended.
pub static NATS_CLIENT_ERROR_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "nats_error_received",
        "The broker sent -ERR. Most -ERR frames are fatal and the broker hangs up right after",
        json!({"type": "wait_for_more"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "message".to_string(),
            type_hint: "string".to_string(),
            description: "The error text between the single quotes, e.g. \"Authorization \
                          Violation\", \"Maximum Payload Violation\", \"Unknown Protocol \
                          Operation\""
                .to_string(),
            required: true,
        },
        Parameter {
            name: "fatal".to_string(),
            type_hint: "boolean".to_string(),
            description: "True for the errors a broker closes the connection after (everything \
                          except a permissions violation). When true, nothing further can be \
                          sent on this connection"
                .to_string(),
            required: true,
        },
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("<- NATS -ERR {message}")
            .with_debug("NATS error: {message} fatal={fatal}"),
    )
    .with_actions(vec![wait_for_more_action(), disconnect_action()])
    .with_alternative_example(json!({"type": "disconnect"}))
});

/// Raised for a `-ERR 'Permissions Violation for …'`.
///
/// Split out from [`NATS_CLIENT_ERROR_RECEIVED_EVENT`] because it is the one `-ERR` a broker
/// does **not** hang up after, and the one the model can actually do something about: the
/// subject it just used is denied, and it may pick another.
pub static NATS_CLIENT_PERMISSION_ERROR_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "nats_permission_error",
        "The broker denied a publish or a subscription. The connection stays open",
        json!({"type": "wait_for_more"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "message".to_string(),
            type_hint: "string".to_string(),
            description: "The full error text, e.g. \"Permissions Violation for Publish to \
                          \\\"orders.eu\\\"\""
                .to_string(),
            required: true,
        },
        Parameter {
            name: "operation".to_string(),
            type_hint: "string".to_string(),
            description: "\"publish\", \"subscription\", or \"unknown\" when the text did not \
                          name one"
                .to_string(),
            required: true,
        },
        Parameter {
            name: "subject".to_string(),
            type_hint: "string".to_string(),
            description: "The denied subject when the broker named one, otherwise null. Do not \
                          retry this subject — the denial is a permission, not a transient \
                          failure"
                .to_string(),
            required: false,
        },
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("<- NATS permission denied: {operation} {subject}")
            .with_debug("NATS permission error: {message}"),
    )
    .with_actions(vec![
        send_nats_subscribe_action(),
        send_nats_publish_action(),
        wait_for_more_action(),
        disconnect_action(),
    ])
    .with_alternative_example(json!({"type": "disconnect"}))
});

pub struct NatsClientProtocol {
    /// The inbox JetStream replies come back under (see `jetstream.rs`).
    js_inbox: String,
}

impl NatsClientProtocol {
    pub fn new() -> Self {
        Self::with_inbox("_INBOX.ngjs0".to_string())
    }

    /// A protocol whose JetStream requests reply under `js_inbox`.
    pub fn with_inbox(js_inbox: String) -> Self {
        Self { js_inbox }
    }
}

impl Default for NatsClientProtocol {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Wire encoding helpers
// ============================================================================

/// A NATS control line is whitespace-delimited and CRLF-terminated, so a token containing
/// whitespace or a control character would forge a second frame — a subscription to a subject
/// nobody asked for, or a publish that becomes two.
///
/// Rejecting is louder than stripping, which is why it rejects. Same rule as the server half
/// (`src/server/nats/actions.rs::check_token`).
fn check_token(value: &str, field: &str) -> Result<()> {
    if value.is_empty() {
        return Err(anyhow::anyhow!("'{field}' must not be empty"));
    }
    if value.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(anyhow::anyhow!(
            "'{field}' ({value:?}) contains whitespace or a control character. NATS control \
             lines are space-delimited and CRLF-terminated, so such a value cannot be sent."
        ));
    }
    Ok(())
}

/// Turn `payload` into wire bytes according to the action's explicit `encoding`.
///
/// No sniffing: `"48656c6c6f"` is simultaneously valid text and valid hex, and only the sender
/// knows which it means. That is the `send_tcp_data` bug, and this is the shape that avoids it.
pub fn decode_payload(action: &serde_json::Value) -> Result<Vec<u8>> {
    let payload = action.get("payload").and_then(|v| v.as_str()).unwrap_or("");
    let encoding = action
        .get("encoding")
        .and_then(|v| v.as_str())
        .unwrap_or("utf8");

    match encoding {
        "utf8" => Ok(payload.as_bytes().to_vec()),
        "hex" => {
            let cleaned: String = payload
                .chars()
                .filter(|c| !c.is_ascii_whitespace() && *c != ':')
                .collect();
            let cleaned = cleaned.strip_prefix("0x").unwrap_or(&cleaned);
            if cleaned.len() % 2 != 0 {
                return Err(anyhow::anyhow!(
                    "Invalid hex in 'payload': expected an even number of hex digits, got {}",
                    cleaned.len()
                ));
            }
            hex::decode(cleaned).map_err(|e| {
                anyhow::anyhow!(
                    "Invalid hex in 'payload' ({payload:?}): {e}. Use two hex digits per byte, \
                     e.g. \"48656c6c6f\" = \"Hello\". To send the string as literal text, omit \
                     'encoding' or set it to \"utf8\"."
                )
            })
        }
        other => Err(anyhow::anyhow!(
            "Invalid 'encoding' value {other:?}. Valid values are \"utf8\" (default) and \"hex\"."
        )),
    }
}

/// Render the `headers` object as a `NATS/1.0` header block for `HPUB`.
fn encode_headers(headers: &serde_json::Map<String, serde_json::Value>) -> Result<Vec<u8>> {
    let mut out = String::from("NATS/1.0\r\n");
    for (name, value) in headers {
        let value = value
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Header {name:?} must be a string, got {value}"))?;
        if name.is_empty() || name.contains([':', '\r', '\n']) || name.contains(' ') {
            return Err(anyhow::anyhow!(
                "Invalid header name {name:?}: must be non-empty and contain no ':', space, CR \
                 or LF"
            ));
        }
        if value.contains(['\r', '\n']) {
            return Err(anyhow::anyhow!(
                "Invalid value for header {name:?}: must contain no CR or LF"
            ));
        }
        out.push_str(name);
        out.push_str(": ");
        out.push_str(value);
        out.push_str("\r\n");
    }
    out.push_str("\r\n");
    Ok(out.into_bytes())
}

/// Build the `PUB`/`HPUB` frame for a publish-shaped action.
///
/// Shared by `send_nats_publish` and `send_nats_request`, which differ only in whether the
/// reply subject is optional and whether a subscription precedes the frame.
fn build_publish_frame(
    subject: &str,
    reply_to: Option<&str>,
    payload: &[u8],
    headers: Option<&[u8]>,
) -> Vec<u8> {
    let mut frame = Vec::new();
    match headers {
        // HPUB <subject> [reply-to] <#header bytes> <#total bytes>
        Some(block) => {
            let head = match reply_to {
                Some(reply) => format!(
                    "HPUB {} {} {} {}\r\n",
                    subject,
                    reply,
                    block.len(),
                    block.len() + payload.len()
                ),
                None => format!(
                    "HPUB {} {} {}\r\n",
                    subject,
                    block.len(),
                    block.len() + payload.len()
                ),
            };
            frame.extend_from_slice(head.as_bytes());
            frame.extend_from_slice(block);
        }
        // PUB <subject> [reply-to] <#bytes>
        None => {
            let head = match reply_to {
                Some(reply) => format!("PUB {} {} {}\r\n", subject, reply, payload.len()),
                None => format!("PUB {} {}\r\n", subject, payload.len()),
            };
            frame.extend_from_slice(head.as_bytes());
        }
    }
    frame.extend_from_slice(payload);
    frame.extend_from_slice(b"\r\n");
    frame
}

/// Read the optional `headers` object off an action, rejecting anything that is not a flat
/// object of strings. An empty object means "plain PUB", not "an empty header block".
fn optional_header_block(action: &serde_json::Value) -> Result<Option<Vec<u8>>> {
    match action.get("headers") {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::Object(map)) if map.is_empty() => Ok(None),
        Some(serde_json::Value::Object(map)) => Ok(Some(encode_headers(map)?)),
        Some(other) => Err(anyhow::anyhow!(
            "'headers' must be an object of string values, got {other}"
        )),
    }
}

/// `sid` arrives as a string on the wire but models routinely produce a bare number, and both
/// are unambiguous here — so both are accepted and normalised to the wire form.
fn read_sid(action: &serde_json::Value) -> Result<String> {
    let sid = match action.get("sid") {
        Some(serde_json::Value::String(s)) => s.clone(),
        Some(serde_json::Value::Number(n)) => n.to_string(),
        Some(other) => {
            return Err(anyhow::anyhow!(
                "'sid' must be a string or a number, got {other}"
            ))
        }
        None => return Err(anyhow::anyhow!("Missing 'sid' parameter")),
    };
    check_token(&sid, "sid")?;
    Ok(sid)
}

fn execute_send_nats_publish(action: &serde_json::Value) -> Result<ClientActionResult> {
    let subject = action
        .get("subject")
        .and_then(|v| v.as_str())
        .context("Missing 'subject' parameter")?;
    check_token(subject, "subject")?;

    let reply_to = action.get("reply_to").and_then(|v| v.as_str());
    if let Some(reply_to) = reply_to {
        check_token(reply_to, "reply_to")?;
    }

    let payload = decode_payload(action)?;
    let headers = optional_header_block(action)?;

    Ok(ClientActionResult::SendData(build_publish_frame(
        subject,
        reply_to,
        &payload,
        headers.as_deref(),
    )))
}

fn execute_send_nats_subscribe(action: &serde_json::Value) -> Result<ClientActionResult> {
    let subject = action
        .get("subject")
        .and_then(|v| v.as_str())
        .context("Missing 'subject' parameter")?;
    check_token(subject, "subject")?;
    let sid = read_sid(action)?;

    let queue_group = action.get("queue_group").and_then(|v| v.as_str());
    if let Some(queue_group) = queue_group {
        check_token(queue_group, "queue_group")?;
    }

    let line = match queue_group {
        Some(queue) => format!("SUB {} {} {}\r\n", subject, queue, sid),
        None => format!("SUB {} {}\r\n", subject, sid),
    };
    Ok(ClientActionResult::SendData(line.into_bytes()))
}

fn execute_send_nats_unsubscribe(action: &serde_json::Value) -> Result<ClientActionResult> {
    let sid = read_sid(action)?;
    let line = match action.get("max_msgs") {
        None | Some(serde_json::Value::Null) => format!("UNSUB {}\r\n", sid),
        Some(v) => {
            let max = v.as_u64().ok_or_else(|| {
                anyhow::anyhow!("'max_msgs' must be a non-negative whole number, got {v}")
            })?;
            format!("UNSUB {} {}\r\n", sid, max)
        }
    };
    Ok(ClientActionResult::SendData(line.into_bytes()))
}

/// `send_nats_request` is three frames, not one: subscribe to the reply subject, auto-unsub
/// after a single reply, then publish with that subject as `reply-to`.
///
/// They are emitted as one `SendData` so they reach the broker in one write, in order. The
/// `UNSUB <sid> 1` is what makes this a *request* rather than a permanent inbox — without it
/// the reply subscription would live for the rest of the session.
fn execute_send_nats_request(action: &serde_json::Value) -> Result<ClientActionResult> {
    let subject = action
        .get("subject")
        .and_then(|v| v.as_str())
        .context("Missing 'subject' parameter")?;
    check_token(subject, "subject")?;

    let reply_to = action
        .get("reply_to")
        .and_then(|v| v.as_str())
        .context("Missing 'reply_to' parameter: a request needs a subject to be answered on")?;
    check_token(reply_to, "reply_to")?;

    let sid = read_sid(action)?;
    let payload = decode_payload(action)?;
    let headers = optional_header_block(action)?;

    let mut frames = format!("SUB {} {}\r\nUNSUB {} 1\r\n", reply_to, sid, sid).into_bytes();
    frames.extend_from_slice(&build_publish_frame(
        subject,
        Some(reply_to),
        &payload,
        headers.as_deref(),
    ));
    Ok(ClientActionResult::SendData(frames))
}

// ============================================================================
// Action definitions
// ============================================================================

fn encoding_parameter() -> Parameter {
    Parameter {
        name: "encoding".to_string(),
        type_hint: "string".to_string(),
        description: "How to turn 'payload' into the bytes on the wire. \"utf8\" (the default \
                      when omitted) sends the characters unchanged. \"hex\" decodes the string \
                      as hex, two digits per byte, so {\"payload\": \"48656c6c6f\", \"encoding\": \
                      \"hex\"} sends the 5 bytes 'Hello'. Echo back the 'payload_encoding' of a \
                      nats_message_received event to forward a payload unchanged. No other \
                      values are accepted"
            .to_string(),
        required: false,
    }
    .with_choices(["utf8", "hex"])
}

fn send_nats_publish_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_nats_publish".to_string(),
        description: "Publish a message to a subject on the broker. This is how this client \
                      speaks: everything else on the fabric hears it only if the broker routes \
                      it to a subscriber. To answer a request, publish to the 'reply_to' \
                      subject of the nats_message_received event that asked"
            .to_string(),
        parameters: vec![
            Parameter {
                name: "subject".to_string(),
                type_hint: "string".to_string(),
                description: "Subject to publish on, e.g. \"orders.eu\". Must be concrete — \
                              wildcards ('*' and '>') are for subscriptions, not publishes"
                    .to_string(),
                required: true,
            },
            Parameter {
                name: "payload".to_string(),
                type_hint: "string".to_string(),
                description: "The message body. Omit for an empty message".to_string(),
                required: false,
            },
            encoding_parameter(),
            Parameter {
                name: "reply_to".to_string(),
                type_hint: "string".to_string(),
                description: "Subject a reply should be sent to. Set this to the 'reply_to' of a \
                              nats_message_received event to answer that request, or to a \
                              subject this client has subscribed to in order to ask one"
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "headers".to_string(),
                type_hint: "object".to_string(),
                description: "Optional flat object of string headers, sent as HPUB. Only use \
                              this when the nats_connected event reported headers=true"
                    .to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_nats_publish",
            "subject": "orders.eu",
            "payload": "{\"order\":42,\"status\":\"accepted\"}"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> NATS PUB {subject}")
                .with_debug("NATS publish: subject={subject} reply_to={reply_to}")
                .with_trace("NATS publish: {json_pretty(.)}"),
        ),
    }
}

fn send_nats_subscribe_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_nats_subscribe".to_string(),
        description: "Subscribe to a subject. Nothing is delivered to this client until it \
                      subscribes, so this is normally the first thing to do after connecting. \
                      Every message that matches arrives as a nats_message_received event \
                      carrying this 'sid'"
            .to_string(),
        parameters: vec![
            Parameter {
                name: "subject".to_string(),
                type_hint: "string".to_string(),
                description: "Subject filter. '*' matches exactly one token and '>' matches one \
                              or more and must be last, so \"orders.*\" matches \"orders.eu\" \
                              but not \"orders.eu.new\", and \"orders.>\" matches both"
                    .to_string(),
                required: true,
            },
            Parameter {
                name: "sid".to_string(),
                type_hint: "string".to_string(),
                description: "Subscription id you choose, unique on this connection. It comes \
                              back on every nats_message_received for this subscription and is \
                              what send_nats_unsubscribe cancels. Numeric strings such as \"1\", \
                              \"2\" are conventional"
                    .to_string(),
                required: true,
            },
            Parameter {
                name: "queue_group".to_string(),
                type_hint: "string".to_string(),
                description: "Optional queue group. The broker delivers each message to only one \
                              member of a group, which is how work is shared between consumers"
                    .to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_nats_subscribe",
            "subject": "orders.>",
            "sid": "1"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> NATS SUB {subject} sid={sid}")
                .with_debug("NATS subscribe: subject={subject} sid={sid} queue={queue_group}"),
        ),
    }
}

fn send_nats_unsubscribe_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_nats_unsubscribe".to_string(),
        description: "Cancel a subscription, so nothing further arrives on that sid".to_string(),
        parameters: vec![
            Parameter {
                name: "sid".to_string(),
                type_hint: "string".to_string(),
                description: "The sid given to send_nats_subscribe".to_string(),
                required: true,
            },
            Parameter {
                name: "max_msgs".to_string(),
                type_hint: "number".to_string(),
                description: "Optional: leave the subscription alive until this many messages \
                              have been delivered on it in total, then drop it. Omit to \
                              unsubscribe immediately"
                    .to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_nats_unsubscribe",
            "sid": "1"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> NATS UNSUB sid={sid}")
                .with_debug("NATS unsubscribe: sid={sid} max_msgs={max_msgs}"),
        ),
    }
}

fn send_nats_request_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_nats_request".to_string(),
        description: "Ask a question and get one answer back: subscribes to a reply subject, \
                      arms it to expire after a single message, and publishes with that subject \
                      as reply-to. The answer arrives as a nats_message_received event on the \
                      'sid' given here. Use this instead of send_nats_publish whenever a \
                      response is expected"
            .to_string(),
        parameters: vec![
            Parameter {
                name: "subject".to_string(),
                type_hint: "string".to_string(),
                description: "Subject to send the request to, e.g. \"service.time\"".to_string(),
                required: true,
            },
            Parameter {
                name: "reply_to".to_string(),
                type_hint: "string".to_string(),
                description: "Subject the answer will come back on. Pick one nothing else uses; \
                              the NATS convention is \"_INBOX.<something-unique>\""
                    .to_string(),
                required: true,
            },
            Parameter {
                name: "sid".to_string(),
                type_hint: "string".to_string(),
                description: "Subscription id for the reply subject, unique on this connection. \
                              The answer arrives as a nats_message_received event carrying it"
                    .to_string(),
                required: true,
            },
            Parameter {
                name: "payload".to_string(),
                type_hint: "string".to_string(),
                description: "The request body. Omit for an empty request".to_string(),
                required: false,
            },
            encoding_parameter(),
            Parameter {
                name: "headers".to_string(),
                type_hint: "object".to_string(),
                description: "Optional flat object of string headers, sent as HPUB".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_nats_request",
            "subject": "service.time",
            "reply_to": "_INBOX.netget.1",
            "sid": "900",
            "payload": ""
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> NATS REQ {subject} reply={reply_to}")
                .with_debug("NATS request: subject={subject} reply_to={reply_to} sid={sid}"),
        ),
    }
}

fn wait_for_more_action() -> ActionDefinition {
    ActionDefinition {
        name: "wait_for_more".to_string(),
        description: "Say nothing and keep listening. This is a real answer, not a no-op: most \
                      messages on a fabric need no reply, and the connection stays open with \
                      its subscriptions intact"
            .to_string(),
        parameters: vec![],
        example: json!({"type": "wait_for_more"}),
        log_template: None,
    }
}

fn disconnect_action() -> ActionDefinition {
    ActionDefinition {
        name: "disconnect".to_string(),
        description: "Close the connection to the broker. Anything sent in the same answer is \
                      written first"
            .to_string(),
        parameters: vec![],
        example: json!({"type": "disconnect"}),
        log_template: Some(LogTemplate::new().with_info("NATS client disconnecting")),
    }
}

impl Protocol for NatsClientProtocol {
    fn get_startup_parameters(&self) -> Vec<crate::llm::actions::ParameterDefinition> {
        use crate::llm::actions::ParameterDefinition;
        vec![
            ParameterDefinition {
                name: "client_name".to_string(),
                type_hint: "string".to_string(),
                description: "Name sent in the CONNECT document (default \"netget\"). Brokers \
                              display it in their connection list and their logs; it has no \
                              effect on routing."
                    .to_string(),
                required: false,
                example: json!("netget"),
                default: None,
            },
            ParameterDefinition {
                name: "verbose".to_string(),
                type_hint: "boolean".to_string(),
                description: "Ask the broker to acknowledge every command with +OK (default \
                              false). The acknowledgements are logged and never shown to the \
                              model - they are bookkeeping, not decisions - so this is only \
                              useful for debugging what the broker accepted."
                    .to_string(),
                required: false,
                example: json!(false),
                default: None,
            },
            ParameterDefinition {
                name: "subscribe_subjects".to_string(),
                type_hint: "array".to_string(),
                description: "Subjects to SUB immediately after CONNECT, before the model is \
                              asked anything. Sids are assigned in order starting at 1 and are \
                              reported in the nats_connected event. Use this when messages may \
                              arrive at once: an instance created from the dashboard parks its \
                              events for a human, and a subscriber that waits for that answer \
                              before subscribing misses everything published in the meantime."
                    .to_string(),
                required: false,
                example: json!(["orders.>"]),
                default: None,
            },
        ]
    }

    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        // The whole vocabulary lives here. `client_llm_action_set` is the union of async, sync
        // and the firing event's own actions, so a client cannot express a narrowing and
        // duplicating this list into get_sync_actions() would buy nothing - see the doc comment
        // on `crate::llm::actions::client_trait::client_llm_action_set`.
        vec![
            send_nats_subscribe_action(),
            send_nats_publish_action(),
            send_nats_request_action(),
            send_nats_unsubscribe_action(),
            wait_for_more_action(),
            disconnect_action(),
        ]
        .into_iter()
        .chain(super::jetstream::actions())
        .collect()
    }

    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        Vec::new()
    }

    fn protocol_name(&self) -> &'static str {
        "NATS"
    }

    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            NATS_CLIENT_CONNECTED_EVENT.clone(),
            NATS_CLIENT_MESSAGE_RECEIVED_EVENT.clone(),
            NATS_CLIENT_ERROR_RECEIVED_EVENT.clone(),
            NATS_CLIENT_PERMISSION_ERROR_EVENT.clone(),
        ]
        .into_iter()
        .chain(super::jetstream::event_types())
        .collect()
    }

    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>NATS"
    }

    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "nats",
            "nats client",
            "connect to nats",
            "publish subscribe",
            "pub/sub",
            "message bus",
        ]
    }

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{
            DevelopmentState, PrivilegeRequirement, ProtocolMetadataV2,
        };

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Beta)
            // Nothing privileged: NATS' default port 4222 is a destination here, not a bind.
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation(
                "Hand-written NATS client-protocol codec on tokio (no NATS library). Two tasks \
                 per connection: a reader that frames INFO/MSG/HMSG/+OK/-ERR/PING/PONG and \
                 answers PING with PONG itself, and a dispatcher that owns the LLM calls and \
                 the injected-command channel. The reader never blocks on the model, so a \
                 parked manual handler cannot get the connection declared stale.",
            )
            .llm_control(
                "What this client says on the fabric: it chooses subjects to subscribe to on \
                 nats_connected, and answers each nats_message_received with a publish, a \
                 request, another subscription, or wait_for_more. It never sees PING/PONG or \
                 the verbose +OK acknowledgements.",
            )
            .e2e_testing(
                "tests/client/nats/e2e_test.rs, 13 LLM calls. The Beta rating rests on \
                 test_nats_client_round_trips_through_the_official_nats_server: the official Go \
                 nats-server 2.14 routes the traffic and async-nats 0.50 is the peer that asks \
                 and reads the answer, so neither end is ours. async-nats requests a subject \
                 NetGet subscribed to, nats-server delivers it, the model authors a reply that \
                 quotes the request, and nats-server routes it back to async-nats' own inbox. \
                 It is not #[ignore]d and cannot silently skip: a missing nats-server binary \
                 fails the test with a message saying so, because a skip-when-missing gate \
                 would leave this rating resting on nothing. Three further tests cover what a \
                 real broker cannot show: the parser directly (no broker, no LLM), exact \
                 outbound bytes against a hand-written broker, and -ERR classification.",
            )
            .notes(
                "Validated against the official nats-server binary, which accepts NetGet's \
                 CONNECT document, matches its SUB with its own routing table and routes the \
                 model's reply back to an independent client. Browser-grade breadth is not \
                 claimed: what is proven is one full publish/subscribe/request round trip. \
                 Implements the client protocol only: INFO/MSG/HMSG/+OK/-ERR/PING/PONG inbound, \
                 CONNECT/PUB/HPUB/SUB/UNSUB/PONG outbound. PING is answered with PONG in Rust \
                 by the reader task, never by the model, because a keepalive behind a parked \
                 manual handler gets the connection declared stale. No TLS, no authentication \
                 (a broker with auth_required answers -ERR 'Authorization Violation'), no \
                 automatic reconnect and no cluster failover - a connect_urls \
                 list in INFO is reported to the model and otherwise ignored. No client-side \
                 subscription table: sids are the model's to choose and track, and UNSUB with \
                 max_msgs is sent as the protocol defines it and counted by the broker, not \
                 here - that counting is exercised only by the real nats-server, since NetGet's \
                 own server records the threshold without counting. JetStream, when INFO \
                 advertises it: nats_js_api/publish/fetch/ack actions and typed reply events, \
                 driven against nats-server -js (tests/client/nats/jetstream_test.rs).",
            )
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            // Frames the broker sends while the model answers wait on the reader→dispatcher
            // queue and are answered in one call, one event per message (`run_dispatcher`).
            .batching(crate::protocol::metadata::BatchingMode::On)
            .build()
    }

    fn description(&self) -> &'static str {
        "NATS client - joins a real messaging fabric and lets the model subscribe, read live \
         traffic and publish replies"
    }

    fn example_prompt(&self) -> &'static str {
        "Connect to the NATS broker at localhost:4222, subscribe to orders.>, and publish a \
         short acknowledgement to orders.ack for every order you see"
    }

    fn group_name(&self) -> &'static str {
        "Application"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;

        // Deterministic echo responder: everything that arrives on a subscription is
        // acknowledged on its reply subject, with zero LLM calls.
        let script = r#"import json, sys
data = json.load(sys.stdin)
event = data["event"]
actions = []
if data["event_type_id"] == "nats_message_received" and event.get("reply_to"):
    actions.append({"type": "send_nats_publish",
                    "subject": event["reply_to"],
                    "payload": "ack: " + event.get("payload", ""),
                    "encoding": event.get("payload_encoding", "utf8")})
else:
    actions.append({"type": "wait_for_more"})
print(json.dumps({"actions": actions}))"#;

        StartupExamples::new(
            json!({
                "type": "open_client",
                "remote_addr": "localhost:4222",
                "base_stack": "nats",
                "instruction": "Subscribe to orders.> and, for every order message you see, publish a one-line summary to orders.audit."
            }),
            json!({
                "type": "open_client",
                "remote_addr": "localhost:4222",
                "base_stack": "nats",
                "subscribe_subjects": ["service.>"],
                "event_handlers": [{
                    "event_pattern": "nats_message_received",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": script
                    }
                }]
            }),
            json!({
                "type": "open_client",
                "remote_addr": "localhost:4222",
                "base_stack": "nats",
                "event_handlers": [{
                    "event_pattern": "nats_connected",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "send_nats_subscribe",
                            "subject": "orders.>",
                            "sid": "1"
                        }]
                    }
                }]
            }),
        )
    }
}

impl Client for NatsClientProtocol {
    fn connect(
        &self,
        ctx: crate::protocol::ConnectContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::client::nats::{NatsClient, NatsConnectOptions};

            // Every parameter is optional, and every error is propagated rather than
            // unwrapped: this JSON comes from the model or an MCP caller, and a panic here
            // kills the request task before it can answer.
            let options = match &ctx.startup_params {
                Some(params) => {
                    let client_name = params.get_optional_string("client_name")?;
                    let verbose = params.get_optional_bool("verbose")?;
                    let subjects = match params.get_optional_array("subscribe_subjects")? {
                        Some(values) => {
                            let mut out = Vec::new();
                            for value in values {
                                let subject = value.as_str().ok_or_else(|| {
                                    anyhow::anyhow!(
                                        "'subscribe_subjects' must be an array of subject \
                                         strings, got {value}"
                                    )
                                })?;
                                check_token(subject, "subscribe_subjects")?;
                                out.push(subject.to_string());
                            }
                            out
                        }
                        None => Vec::new(),
                    };
                    NatsConnectOptions {
                        client_name: client_name.unwrap_or_else(|| "netget".to_string()),
                        verbose: verbose.unwrap_or(false),
                        subscribe_subjects: subjects,
                    }
                }
                None => NatsConnectOptions::default(),
            };

            NatsClient::connect_with_llm_actions(
                ctx.remote_addr,
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.client_id,
                options,
            )
            .await
        })
    }

    fn execute_action(&self, action: serde_json::Value) -> Result<ClientActionResult> {
        let action_type = action
            .get("type")
            .and_then(|v| v.as_str())
            .context("Missing 'type' field in action")?;

        if let Some(result) = super::jetstream::execute(&self.js_inbox, &action) {
            return result;
        }
        match action_type {
            "send_nats_publish" => execute_send_nats_publish(&action),
            "send_nats_subscribe" => execute_send_nats_subscribe(&action),
            "send_nats_unsubscribe" => execute_send_nats_unsubscribe(&action),
            "send_nats_request" => execute_send_nats_request(&action),
            "wait_for_more" => Ok(ClientActionResult::WaitForMore),
            "disconnect" => Ok(ClientActionResult::Disconnect),
            _ => Err(anyhow::anyhow!(
                "Unknown NATS client action: {}",
                action_type
            )),
        }
    }
}

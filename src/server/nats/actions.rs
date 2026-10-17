//! NATS protocol actions, events and metadata.
//!
//! The wire format is the NATS client protocol: CRLF-terminated control lines, with
//! `PUB`/`HPUB` carrying a byte-counted payload. Everything the model can put on the wire
//! is one of the actions below; everything it is asked about is one of the four events.
//!
//! Two things are deliberately **not** decisions and never reach the model: `PING` is
//! answered with `PONG` in Rust, and the verbose-mode `+OK` acknowledgements are written by
//! the connection loop. Both are keepalive/bookkeeping, and paying an LLM round-trip for
//! them would stall a real client's connect (`async-nats` sends `CONNECT` and `PING`
//! together and waits for the reply).

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

/// Whether JetStream is served when `jetstream` is not given at startup.
pub const DEFAULT_JETSTREAM: bool = false;

/// Largest `PUB` payload accepted when `max_payload` is not given at startup.
///
/// 1 MiB is the NATS server's own default, and clients read it out of `INFO` to decide
/// what they may send, so it is a real bound rather than documentation.
pub const DEFAULT_MAX_PAYLOAD: u64 = 1_048_576;

/// The largest `max_payload` this server will start with, and so the largest single message it
/// can ever be made to buffer: this server's declared `max_inbound_bytes`.
///
/// `max_payload` is an operator knob, and until this existed it was a `u64` with no ceiling, so
/// the per-message bound was whatever number the operator — or the model starting the server —
/// typed. 64 MiB is nats-server's own default `max_pending`, which it will not let `max_payload`
/// exceed. A larger request is refused at startup with an error naming both numbers rather than
/// clamped, so nobody runs a server believing it accepts more than it does.
pub const MAX_PAYLOAD_CEILING: u64 = 64 * 1024 * 1024;

/// `proto` field advertised in `INFO`. 1 means the client may send `HPUB` and expect
/// `HMSG`, which this server supports in both directions.
pub const NATS_PROTO_VERSION: u8 = 1;

/// Version string advertised in `INFO`.
///
/// Clients gate optional features on this, so it has to parse as a NATS server version.
/// It is a compatibility claim about the *client protocol*, not about feature parity:
/// JetStream is served only with `jetstream: true`, and there is no clustering and no
/// authentication. See
/// `src/server/nats/CLAUDE.md`.
pub const ADVERTISED_VERSION: &str = "2.10.0";

pub struct NatsProtocol;

impl NatsProtocol {
    pub fn new() -> Self {
        Self
    }
}

impl Default for NatsProtocol {
    fn default() -> Self {
        Self::new()
    }
}

impl Protocol for NatsProtocol {
    fn get_startup_parameters(&self) -> Vec<crate::llm::actions::ParameterDefinition> {
        use crate::llm::actions::ParameterDefinition;
        vec![
            ParameterDefinition {
                name: "server_name".to_string(),
                type_hint: "string".to_string(),
                description: "Name reported in the INFO greeting every client receives on \
                              connect (default \"netget-nats\"). Clients display it and use it \
                              in their own logs; it has no effect on routing."
                    .to_string(),
                required: false,
                example: json!("netget-nats"),
                default: None,
            },
            ParameterDefinition {
                name: "max_payload".to_string(),
                type_hint: "number".to_string(),
                description: "Largest PUB/HPUB payload accepted, in bytes (default 1048576, at \
                              most 67108864). Advertised in INFO so clients refuse to send \
                              more, and enforced on the size a PUB declares: a larger payload \
                              is answered with -ERR 'Maximum Payload Violation' and the \
                              connection is closed. A value above 67108864 refuses to start."
                    .to_string(),
                required: false,
                example: json!(1_048_576),
                default: Some(serde_json::json!(DEFAULT_MAX_PAYLOAD)),
            },
            ParameterDefinition {
                name: "jetstream".to_string(),
                type_hint: "boolean".to_string(),
                description: "Serve JetStream (default false): INFO advertises it, and $JS.API \
                              requests, publishes to streams' subjects, pulls and acks become \
                              nats_js_* events. NetGet stores no messages - the handler owns \
                              streams and their contents."
                    .to_string(),
                required: false,
                example: json!(true),
                default: Some(serde_json::json!(DEFAULT_JETSTREAM)),
            },
        ]
    }

    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        // Nothing a user can trigger out of band: every NATS frame this server writes is a
        // reply to something the peer said on that same connection. The dashboard's
        // "message this peer" reaches the sync actions below through the peer handle.
        Vec::new()
    }

    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            send_nats_message_action(),
            send_nats_info_action(),
            send_ok_action(),
            send_err_action(),
            send_ping_action(),
            close_connection_action(),
        ]
        .into_iter()
        .chain(super::jetstream::actions())
        .collect()
    }

    fn protocol_name(&self) -> &'static str {
        "NATS"
    }

    fn get_event_types(&self) -> Vec<EventType> {
        let mut events = get_nats_event_types();
        events.extend(super::jetstream::event_types());
        events
    }

    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>NATS"
    }

    fn keywords(&self) -> Vec<&'static str> {
        vec!["nats"]
    }

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{
            DevelopmentState, PrivilegeRequirement, ProtocolMetadataV2,
        };

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Beta)
            // Default port 4222 is unprivileged. Declaring PrivilegedPort(4222) would be
            // dead code - the preflight only fires below 1024.
            .privilege_requirement(PrivilegeRequirement::None)
            .well_known_port(4222)
            // The per-instance bound is `max_payload` (1 MiB by default), checked against the
            // size a PUB/HPUB declares before its payload is buffered; this is the ceiling no
            // configuration can exceed. Tested in tests/server/nats/inbound_limit_test.rs.
            .max_inbound_bytes(crate::server::nats::actions::MAX_PAYLOAD_CEILING as usize)
            .implementation(
                "Hand-written NATS client-protocol codec on tokio (no NATS library). Per \
                 connection: a reader task frames CONTROL lines and byte-counted payloads and \
                 answers PING/verbose +OK itself, and a single dispatcher task owns the \
                 subscription table and serialises the LLM calls.",
            )
            .llm_control(
                "What a subscriber receives: the model answers nats_publish/nats_subscribe with \
                 the MSG/HMSG frames to deliver, and may answer +OK, -ERR, INFO or a hang-up. \
                 It does not see PING or the verbose acknowledgements.",
            )
            .e2e_testing(
                "tests/server/nats/e2e_test.rs, 8 LLM calls. The maturity rating rests on \
                 test_nats_delivers_model_authored_message_to_async_nats: the official \
                 async-nats 0.50 client completes CONNECT/PING/PONG, subscribes, publishes, \
                 and receives a MSG the model authored - subject, payload and reply subject \
                 all asserted from inside the client's own Message struct. It is not \
                 #[ignore]d and cannot skip: the client is a dev-dependency, so it is present \
                 wherever the suite compiles.",
            )
            .notes(
                "Implements the client protocol only: INFO/CONNECT/PUB/HPUB/SUB/UNSUB/PING/PONG \
                 inbound, MSG/HMSG/INFO/+OK/-ERR/PING outbound. There is no message store, no \
                 automatic subject routing, no queue-group load balancing, no \
                 authentication, no TLS and no clustering - the model decides what every \
                 subscriber receives, which is the point. The per-connection subscription table \
                 is a hint offered to the model in nats_publish.matching_subscriptions, never \
                 an enforcement: nothing is delivered unless the model says so, and 'UNSUB \
                 <sid> <max>' does not count deliveries. Cross-connection delivery is not \
                 possible from an event: an action writes to the connection that raised it. \
                 INFO advertises version 2.10.0 so clients enable the header protocol; that is \
                 a client-protocol claim, not feature parity. With jetstream: true, $JS.API \
                 requests, publishes to streams' subjects, pulls and acks are nats_js_* events: \
                 Rust owns the envelopes, ack subjects and end-of-batch statuses, the handler \
                 owns the streams' contents (nothing is stored); nats.go's jetstream package \
                 and nats-py complete create/publish/consume/ack/info/delete against it \
                 (tests/server/nats/jetstream_test.rs).",
            )
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }

    fn description(&self) -> &'static str {
        "NATS pub/sub broker - the model decides what each subscriber receives"
    }

    fn example_prompt(&self) -> &'static str {
        "NATS server on port 4222 - when a client publishes, deliver a message back to every \
         matching subscriber summarising what was published"
    }

    fn group_name(&self) -> &'static str {
        "Application"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;

        // Deterministic echo: deliver the published payload to the first subscription the
        // event says matches. `matching_subscriptions` is what makes this writable without
        // the script having to remember anything.
        let script = r#"import json, sys
data = json.load(sys.stdin)
event = data["event"]
actions = []
if data["event_type_id"] == "nats_publish":
    for sub in event.get("matching_subscriptions", []):
        actions.append({"type": "send_nats_message",
                        "subject": event.get("subject", ""),
                        "sid": sub["sid"],
                        "payload": event.get("payload", ""),
                        "encoding": event.get("payload_encoding", "utf8")})
print(json.dumps({"actions": actions}))"#;

        StartupExamples::new(
            json!({
                "type": "open_server",
                "port": 4222,
                "base_stack": "nats",
                "instruction": "Act as a NATS broker for a telemetry demo. When a client publishes to a subject, deliver a MSG to every subscription listed in matching_subscriptions, with a short JSON payload describing a plausible sensor reading for that subject."
            }),
            json!({
                "type": "open_server",
                "port": 4222,
                "base_stack": "nats",
                "event_handlers": [{
                    "event_pattern": "nats_publish",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": script
                    }
                }]
            }),
            json!({
                "type": "open_server",
                "port": 4222,
                "base_stack": "nats",
                "event_handlers": [{
                    "event_pattern": "nats_subscribe",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "send_nats_message",
                            "subject": "welcome",
                            "sid": "1",
                            "payload": "subscribed"
                        }]
                    }
                }]
            }),
        )
    }
}

impl Server for NatsProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::server::nats::NatsServer;

            // Both parameters are optional, and both errors are propagated rather than
            // unwrapped: this JSON comes from the model or an MCP client, and a panic here
            // kills the request task before it can answer.
            let (server_name, max_payload, jetstream) = match &ctx.startup_params {
                Some(params) => {
                    let name = params.get_optional_string("server_name")?;
                    let payload = params.get_optional_u64("max_payload")?;
                    let jetstream = params.get_optional_bool("jetstream")?;
                    (name, payload, jetstream)
                }
                None => (None, None, None),
            };

            let max_payload = max_payload.unwrap_or(DEFAULT_MAX_PAYLOAD);
            if max_payload > MAX_PAYLOAD_CEILING {
                anyhow::bail!(
                    "max_payload {} is above this server's ceiling of {} bytes \
                     (nats-server's own default max_pending); refusing to start",
                    max_payload,
                    MAX_PAYLOAD_CEILING
                );
            }

            NatsServer::spawn_with_llm_actions(
                ctx.legacy_listen_addr(),
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.server_id,
                server_name.unwrap_or_else(|| "netget-nats".to_string()),
                max_payload,
                jetstream
                    .unwrap_or(DEFAULT_JETSTREAM)
                    .then(|| std::sync::Arc::new(super::jetstream::Shared::default())),
            )
            .await
        })
    }

    fn execute_action(&self, action: serde_json::Value) -> Result<ActionResult> {
        let action_type = action
            .get("type")
            .and_then(|v| v.as_str())
            .context("Missing 'type' field in action")?;

        if let Some(result) = super::jetstream::execute(&action) {
            return result;
        }
        match action_type {
            "send_nats_message" => execute_send_nats_message(&action),
            "send_nats_info" => execute_send_nats_info(&action),
            "send_ok" => Ok(ActionResult::Output(b"+OK\r\n".to_vec())),
            "send_err" => execute_send_err(&action),
            "send_ping" => Ok(ActionResult::Output(b"PING\r\n".to_vec())),
            "close_connection" => Ok(ActionResult::CloseConnection),
            _ => Err(anyhow::anyhow!("Unknown NATS action: {}", action_type)),
        }
    }
}

// ============================================================================
// Executors
// ============================================================================

/// A NATS control line is whitespace-delimited and CRLF-terminated, so any token the model
/// supplies that contains whitespace or a line break would forge a second frame.
///
/// Rejecting is the only safe answer: silently stripping would deliver a message on a
/// subject nobody asked for, which is worse than a failed action the operator can see.
pub(crate) fn check_token(value: &str, field: &str) -> Result<()> {
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
/// No sniffing: `"48656c6c6f"` is both valid text and valid hex, and only the sender knows
/// which it means. This mirrors `send_tcp_data`.
pub(crate) fn decode_payload(action: &serde_json::Value) -> Result<Vec<u8>> {
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
            "Invalid 'encoding' value {other:?}. Valid values are \"utf8\" (default) and \
             \"hex\"."
        )),
    }
}

/// Render the `headers` object as a NATS/1.0 header block.
///
/// Header values are free text in the protocol but must not contain CR or LF, which would
/// end the header block early; a name has the same problem plus `:`.
pub(crate) fn encode_headers(
    headers: &serde_json::Map<String, serde_json::Value>,
) -> Result<Vec<u8>> {
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

fn execute_send_nats_message(action: &serde_json::Value) -> Result<ActionResult> {
    let subject = action
        .get("subject")
        .and_then(|v| v.as_str())
        .context("Missing 'subject' parameter")?;
    check_token(subject, "subject")?;

    // `sid` is a string here because that is what the wire carries and what the
    // nats_subscribe event reports, but most clients (async-nats among them) parse it back
    // as an integer, so a non-numeric sid would be dropped on the floor by the client
    // rather than rejected here. The action description says so.
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

    let reply_to = action.get("reply_to").and_then(|v| v.as_str());
    if let Some(reply_to) = reply_to {
        check_token(reply_to, "reply_to")?;
    }

    let payload = decode_payload(action)?;
    let headers = match action.get("headers") {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::Object(map)) if map.is_empty() => None,
        Some(serde_json::Value::Object(map)) => Some(encode_headers(map)?),
        Some(other) => {
            return Err(anyhow::anyhow!(
                "'headers' must be an object of string values, got {other}"
            ))
        }
    };

    let mut frame = Vec::new();
    match &headers {
        // HMSG <subject> <sid> [reply-to] <#header bytes> <#total bytes>
        Some(header_block) => {
            let head = match reply_to {
                Some(reply) => format!(
                    "HMSG {} {} {} {} {}\r\n",
                    subject,
                    sid,
                    reply,
                    header_block.len(),
                    header_block.len() + payload.len()
                ),
                None => format!(
                    "HMSG {} {} {} {}\r\n",
                    subject,
                    sid,
                    header_block.len(),
                    header_block.len() + payload.len()
                ),
            };
            frame.extend_from_slice(head.as_bytes());
            frame.extend_from_slice(header_block);
        }
        // MSG <subject> <sid> [reply-to] <#bytes>
        None => {
            let head = match reply_to {
                Some(reply) => {
                    format!("MSG {} {} {} {}\r\n", subject, sid, reply, payload.len())
                }
                None => format!("MSG {} {} {}\r\n", subject, sid, payload.len()),
            };
            frame.extend_from_slice(head.as_bytes());
        }
    }
    frame.extend_from_slice(&payload);
    frame.extend_from_slice(b"\r\n");

    Ok(ActionResult::Output(frame))
}

fn execute_send_nats_info(action: &serde_json::Value) -> Result<ActionResult> {
    let server_name = action
        .get("server_name")
        .and_then(|v| v.as_str())
        .unwrap_or("netget-nats");
    let max_payload = action
        .get("max_payload")
        .and_then(|v| v.as_u64())
        .unwrap_or(DEFAULT_MAX_PAYLOAD);

    let jetstream = action
        .get("jetstream")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let info = build_info_json(server_name, max_payload, "0.0.0.0", 0, 0, "", jetstream);
    Ok(ActionResult::Output(
        format!("INFO {}\r\n", info).into_bytes(),
    ))
}

/// The `INFO` document sent on accept and by `send_nats_info`.
///
/// Every field `async-nats` deserialises is present and correctly typed. It is one place
/// rather than two so the greeting and the action cannot drift apart.
pub fn build_info_json(
    server_name: &str,
    max_payload: u64,
    host: &str,
    port: u16,
    client_id: u64,
    client_ip: &str,
    jetstream: bool,
) -> String {
    // `server_id` is opaque to clients; deriving it from the name keeps it stable for the
    // life of the server and free of anything host-identifying.
    let server_id = format!("NETGET-{}", server_name);
    json!({
        "server_id": server_id,
        "server_name": server_name,
        "version": ADVERTISED_VERSION,
        "proto": NATS_PROTO_VERSION,
        "go": "",
        "host": host,
        "port": port,
        "headers": true,
        "max_payload": max_payload,
        "client_id": client_id,
        "client_ip": client_ip,
        "auth_required": false,
        "tls_required": false,
        "jetstream": jetstream,
        "connect_urls": [],
    })
    .to_string()
}

fn execute_send_err(action: &serde_json::Value) -> Result<ActionResult> {
    let message = action
        .get("message")
        .and_then(|v| v.as_str())
        .unwrap_or("Unknown Protocol Operation");
    Ok(ActionResult::Output(
        format!("-ERR '{}'\r\n", sanitize_err_text(message)).into_bytes(),
    ))
}

/// `-ERR '<text>'` is a single-quoted, single-line field. A quote or a line break inside it
/// forges a frame boundary, so both are replaced rather than passed through.
pub fn sanitize_err_text(message: &str) -> String {
    let cleaned = crate::utils::sanitize::line_field(&message.replace('\'', "\""));
    crate::utils::truncate_for_log(cleaned.trim(), 200)
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
                      as hex, two digits per byte, so {\"payload\": \"48656c6c6f\", \
                      \"encoding\": \"hex\"} sends the 5 bytes 'Hello'. Echo back the \
                      'payload_encoding' of a nats_publish event to forward a payload \
                      unchanged. No other values are accepted"
            .to_string(),
        required: false,
    }
    .with_choices(["utf8", "hex"])
}

fn send_nats_message_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_nats_message".to_string(),
        description: "Deliver a message to one subscription on THIS connection - the MSG (or \
                      HMSG, when 'headers' is given) frame a NATS subscriber receives. The \
                      'sid' picks which subscription it lands in: use one from the \
                      'matching_subscriptions' list of a nats_publish event, or the 'sid' of a \
                      nats_subscribe event. Nothing is delivered automatically, so this action \
                      is the only way a subscriber ever hears anything"
            .to_string(),
        parameters: vec![
            Parameter {
                name: "subject".to_string(),
                type_hint: "string".to_string(),
                description: "Subject the message is delivered on, e.g. \"orders.eu\". Usually \
                              the subject the subscription was made on (wildcards are not \
                              allowed here - send the concrete subject)"
                    .to_string(),
                required: true,
            },
            Parameter {
                name: "sid".to_string(),
                type_hint: "string".to_string(),
                description: "Subscription id to deliver into, taken from a nats_subscribe \
                              event or from 'matching_subscriptions'. Clients parse it as a \
                              decimal number and silently ignore a message whose sid they do \
                              not know, so do not invent one"
                    .to_string(),
                required: true,
            },
            Parameter {
                name: "reply_to".to_string(),
                type_hint: "string".to_string(),
                description: "Optional reply subject. Set it to the 'reply_to' of a \
                              nats_publish event to answer a request/reply call"
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "payload".to_string(),
                type_hint: "string".to_string(),
                description: "Message body, interpreted according to 'encoding'. Omit for an \
                              empty message"
                    .to_string(),
                required: false,
            },
            encoding_parameter(),
            Parameter {
                name: "headers".to_string(),
                type_hint: "object".to_string(),
                description: "Optional NATS headers as a flat object of string values, e.g. \
                              {\"Nats-Msg-Id\": \"42\"}. When present the message is sent as \
                              HMSG; clients that negotiated the header protocol expose them on \
                              the received message"
                    .to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_nats_message",
            "subject": "orders.eu",
            "sid": "1",
            "payload": "{\"order\":42,\"status\":\"accepted\"}"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> NATS MSG {subject} sid={sid}")
                .with_debug(
                    "NATS send_nats_message: subject={subject} sid={sid} reply_to={reply_to}",
                )
                .with_trace("NATS MSG: {json_pretty(.)}"),
        ),
    }
}

fn send_nats_info_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_nats_info".to_string(),
        description: "Send another INFO document. The server already sends one on accept, so \
                      this is only needed to re-announce changed limits mid-connection; a \
                      client applies the new max_payload from it"
            .to_string(),
        parameters: vec![
            Parameter {
                name: "server_name".to_string(),
                type_hint: "string".to_string(),
                description: "Name to report (default \"netget-nats\")".to_string(),
                required: false,
            },
            Parameter {
                name: "max_payload".to_string(),
                type_hint: "number".to_string(),
                description: "Largest payload to advertise, in bytes (default 1048576). Note \
                              this only tells the client what to send; the limit the server \
                              enforces is the one set at startup"
                    .to_string(),
                required: false,
            },
        ],
        example: json!({"type": "send_nats_info", "server_name": "netget-nats"}),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> NATS INFO ({server_name})")
                .with_debug("NATS send_nats_info: server_name={server_name}"),
        ),
    }
}

fn send_ok_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_ok".to_string(),
        description: "Send +OK. Clients that connected with \"verbose\": true already get one \
                      per command from the server itself, so this is for acknowledging \
                      something out of band; a client in the default non-verbose mode ignores \
                      it"
        .to_string(),
        parameters: vec![],
        example: json!({"type": "send_ok"}),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> NATS +OK")
                .with_debug("NATS send_ok"),
        ),
    }
}

fn send_err_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_err".to_string(),
        description: "Send -ERR '<message>'. Use it to refuse something - an unauthorised \
                      subject, a publish you will not accept. Most clients treat -ERR as fatal \
                      and hang up, so do not use it for routine negative answers"
            .to_string(),
        parameters: vec![Parameter {
            name: "message".to_string(),
            type_hint: "string".to_string(),
            description: "Short reason, one line. Single quotes become double quotes and \
                          control characters become spaces, because the frame is single-quoted \
                          and CRLF-terminated"
                .to_string(),
            required: false,
        }],
        example: json!({
            "type": "send_err",
            "message": "Permissions Violation for Publish to orders.eu"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> NATS -ERR {message}")
                .with_debug("NATS send_err: {message}"),
        ),
    }
}

fn send_ping_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_ping".to_string(),
        description: "Send PING to the client. The server answers a client's PING with PONG by \
                      itself; this is the other direction, a liveness probe the client must \
                      answer with PONG"
            .to_string(),
        parameters: vec![],
        example: json!({"type": "send_ping"}),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> NATS PING")
                .with_debug("NATS send_ping"),
        ),
    }
}

fn close_connection_action() -> ActionDefinition {
    ActionDefinition {
        name: "close_connection".to_string(),
        description: "Close this NATS connection. Anything sent in the same answer is written \
                      first"
            .to_string(),
        parameters: vec![],
        example: json!({"type": "close_connection"}),
        log_template: Some(
            LogTemplate::new()
                .with_info("NATS connection closed")
                .with_debug("NATS close_connection"),
        ),
    }
}

// ============================================================================
// Events
// ============================================================================

/// Raised once per connection, when the client sends its `CONNECT` document.
///
/// The verbose-mode `+OK` and the `PING` that `async-nats` sends alongside `CONNECT` are
/// answered by the connection loop without asking, so a slow or parked answer here does not
/// break the client's connect.
pub static NATS_CONNECT_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "nats_connect",
        "A NATS client sent its CONNECT document",
        json!({"type": "send_ok"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "options".to_string(),
            type_hint: "object".to_string(),
            description: "The full CONNECT document as the client sent it (verbose, pedantic, \
                          protocol, headers, name, lang, version, and any credentials fields)"
                .to_string(),
            required: true,
        },
        Parameter {
            name: "client_name".to_string(),
            type_hint: "string".to_string(),
            description: "The client's self-reported name, empty if it sent none".to_string(),
            required: true,
        },
        Parameter {
            name: "lang".to_string(),
            type_hint: "string".to_string(),
            description: "Client language, e.g. \"rust\", \"go\", \"python3\"".to_string(),
            required: true,
        },
        Parameter {
            name: "verbose".to_string(),
            type_hint: "boolean".to_string(),
            description: "Whether the client asked for a +OK after every command. The server \
                          already sends those; this is here so you know it does"
                .to_string(),
            required: true,
        },
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("NATS CONNECT {client_name} ({lang})")
            .with_debug("NATS connect: name={client_name} lang={lang} verbose={verbose}")
            .with_trace("NATS connect: {json_pretty(.)}"),
    )
    .with_actions(vec![
        send_ok_action(),
        send_err_action(),
        send_nats_info_action(),
        send_nats_message_action(),
        close_connection_action(),
    ])
    .with_alternative_example(json!({
        "type": "send_err",
        "message": "Authorization Violation"
    }))
});

/// Raised for every `PUB`/`HPUB`. This is where the broker's real decision lives: which
/// subscriptions, if any, hear about it.
pub static NATS_PUBLISH_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "nats_publish",
        "A NATS client published a message",
        json!({
            "type": "send_nats_message",
            "subject": "orders.eu",
            "sid": "1",
            "payload": "{\"order\":42,\"status\":\"accepted\"}"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "subject".to_string(),
            type_hint: "string".to_string(),
            description: "Subject published to, e.g. \"orders.eu\"".to_string(),
            required: true,
        },
        Parameter {
            name: "reply_to".to_string(),
            type_hint: "string".to_string(),
            description: "Reply subject if this is a request, otherwise null. Pass it back as \
                          'reply_to' on send_nats_message to answer the requester"
                .to_string(),
            required: false,
        },
        Parameter {
            name: "payload".to_string(),
            type_hint: "string".to_string(),
            description: "The published body: the text itself when it is printable, otherwise \
                          hex. 'payload_encoding' says which"
                .to_string(),
            required: true,
        },
        Parameter {
            name: "payload_encoding".to_string(),
            type_hint: "string".to_string(),
            description: "\"utf8\" or \"hex\", describing 'payload'. Pass it through as \
                          'encoding' on send_nats_message to forward the bytes unchanged"
                .to_string(),
            required: true,
        },
        Parameter {
            name: "headers".to_string(),
            type_hint: "object".to_string(),
            description: "Headers from an HPUB as a flat object, empty for a plain PUB".to_string(),
            required: true,
        },
        Parameter {
            name: "matching_subscriptions".to_string(),
            type_hint: "array".to_string(),
            description: "The subscriptions on THIS connection whose subject filter matches, \
                          each {\"sid\", \"subject\", \"queue_group\"}. Nothing is delivered \
                          unless you answer with send_nats_message; the list is a hint, and you \
                          may deliver to any sid or to none"
                .to_string(),
            required: true,
        },
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("NATS PUB {subject} ({payload})")
            .with_debug(
                "NATS publish: subject={subject} reply_to={reply_to} encoding={payload_encoding}",
            )
            .with_trace("NATS publish: {json_pretty(.)}"),
    )
    .with_actions(vec![
        send_nats_message_action(),
        send_ok_action(),
        send_err_action(),
        send_ping_action(),
        close_connection_action(),
    ])
    .with_alternative_example(json!({
        "type": "send_err",
        "message": "Permissions Violation for Publish to orders.eu"
    }))
});

/// Raised for every `SUB`. Answering with `send_nats_message` on the new `sid` is how a
/// subscriber gets a retained/welcome message.
pub static NATS_SUBSCRIBE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "nats_subscribe",
        "A NATS client subscribed to a subject",
        json!({
            "type": "send_nats_message",
            "subject": "orders.eu",
            "sid": "1",
            "payload": "subscribed"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "subject".to_string(),
            type_hint: "string".to_string(),
            description: "Subject filter, which may contain the wildcards '*' (one token) and \
                          '>' (the rest), e.g. \"orders.*\" or \"orders.>\""
                .to_string(),
            required: true,
        },
        Parameter {
            name: "queue_group".to_string(),
            type_hint: "string".to_string(),
            description: "Queue group name, or null. Queue groups are recorded and reported, \
                          not load-balanced: you decide which member hears a message"
                .to_string(),
            required: false,
        },
        Parameter {
            name: "sid".to_string(),
            type_hint: "string".to_string(),
            description: "Subscription id chosen by the client. Deliver to this subscription \
                          by passing it as 'sid' on send_nats_message"
                .to_string(),
            required: true,
        },
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("NATS SUB {subject} sid={sid}")
            .with_debug("NATS subscribe: subject={subject} sid={sid} queue_group={queue_group}")
            .with_trace("NATS subscribe: {json_pretty(.)}"),
    )
    .with_actions(vec![
        send_nats_message_action(),
        send_ok_action(),
        send_err_action(),
        close_connection_action(),
    ])
    .with_alternative_example(json!({
        "type": "send_err",
        "message": "Permissions Violation for Subscription to orders.eu"
    }))
});

/// Raised for every `UNSUB`.
pub static NATS_UNSUBSCRIBE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "nats_unsubscribe",
        "A NATS client unsubscribed",
        json!({"type": "send_ok"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "sid".to_string(),
            type_hint: "string".to_string(),
            description: "Subscription id the client is cancelling".to_string(),
            required: true,
        },
        Parameter {
            name: "subject".to_string(),
            type_hint: "string".to_string(),
            description: "Subject that subscription was made on, or null if this connection \
                          never subscribed with that sid"
                .to_string(),
            required: false,
        },
        Parameter {
            name: "max_msgs".to_string(),
            type_hint: "number".to_string(),
            description: "Auto-unsubscribe threshold when the client sent one: it wants at most \
                          this many further messages on that sid. Deliveries are NOT counted \
                          for you - honour it yourself, or stop delivering to the sid"
                .to_string(),
            required: false,
        },
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("NATS UNSUB sid={sid}")
            .with_debug("NATS unsubscribe: sid={sid} subject={subject} max_msgs={max_msgs}")
            .with_trace("NATS unsubscribe: {json_pretty(.)}"),
    )
    .with_actions(vec![
        send_ok_action(),
        send_nats_message_action(),
        send_err_action(),
        close_connection_action(),
    ])
});

pub fn get_nats_event_types() -> Vec<EventType> {
    vec![
        NATS_CONNECT_EVENT.clone(),
        NATS_PUBLISH_EVENT.clone(),
        NATS_SUBSCRIBE_EVENT.clone(),
        NATS_UNSUBSCRIBE_EVENT.clone(),
    ]
}

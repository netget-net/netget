//! CoAP protocol actions.
//!
//! The model decides two things a constrained-device server actually decides: what a
//! resource *is* (its representation and media type) and which response code the request
//! deserves. Everything the transport determines — the message type of the reply, the
//! message id, the token — is reconstructed by `src/server/coap/mod.rs` from the request,
//! so the model can neither break reliability matching nor be asked to echo an
//! identifier it has no business handling.

use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter, ParameterDefinition,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::EventType;
use crate::state::app_state::AppState;
use anyhow::{Context, Result};
use serde_json::json;
use std::sync::LazyLock;

use super::codec;

/// Names carried by the [`ActionResult::Custom`] results this protocol produces.
pub const RESULT_RESPONSE: &str = "coap_response";
pub const RESULT_RESET: &str = "coap_reset";
pub const RESULT_IGNORE: &str = "coap_ignore";
pub const RESULT_NOTIFIED: &str = "coap_notified";

/// CoAP server protocol handler.
#[derive(Default)]
pub struct CoapProtocol;

impl CoapProtocol {
    pub fn new() -> Self {
        Self
    }
}

impl Protocol for CoapProtocol {
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        // The one thing a CoAP server says unasked: a notification to the observers of a
        // resource whose state changed (RFC 7641).
        vec![coap_notify_action()]
    }

    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            send_coap_response_action(),
            send_coap_reset_action(),
            ignore_coap_request_action(),
            coap_notify_action(),
        ]
    }

    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![ParameterDefinition {
            name: "notification_ack_timeout_ms".to_string(),
            type_hint: "number".to_string(),
            description: "Milliseconds to wait for the ACK of a Confirmable notification \
                 (coap_notify with confirmable: true) before resending it, doubling each \
                 time. After 4 unanswered resends the observer is presumed gone and its \
                 observation is removed (RFC 7641 §4.5). RFC 7252's ACK_TIMEOUT; 100-60000."
                .to_string(),
            required: false,
            example: json!(2000),
            default: Some(json!(super::DEFAULT_NOTIFICATION_ACK_TIMEOUT_MS)),
        }]
    }

    fn protocol_name(&self) -> &'static str {
        "CoAP"
    }

    fn get_event_types(&self) -> Vec<EventType> {
        get_coap_event_types()
    }

    fn stack_name(&self) -> &'static str {
        "ETH>IP>UDP>COAP"
    }

    fn keywords(&self) -> Vec<&'static str> {
        // "coap" and multi-word phrases only; nothing generic like "iot" or "sensor",
        // which would swallow requests meant for MQTT or Modbus.
        vec![
            "coap",
            "coap server",
            "constrained application protocol",
            "rfc 7252",
        ]
    }

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{
            DevelopmentState, PrivilegeRequirement, ProtocolMetadataV2,
        };

        ProtocolMetadataV2::builder()
            .connectionless()
            // Answers on failure: 5.03 Service Unavailable, never an invented 2.05.
            .answers_on_failure()
            // STABLE, set 16 September 2026 against the six conditions in the root CLAUDE.md,
            // each verified in that pass rather than inherited. Read `.e2e_testing` and
            // `.notes` below before quoting this: the rating is about the evidence for the
            // surface this server implements, and that surface is a subset of RFC 7252.
            //
            // One of the six was FALSE when the pass began and is worth knowing about, because
            // nothing in CI can catch it: `fuzz/fuzz_targets/coap_message.rs` had not compiled
            // since `0996d00f` made `encode` fallible, so "a fuzz target exists and has run
            // clean" was a claim about a file rather than an execution. `fuzz/` is its own
            // workspace and no job builds it. Rebuild it before trusting this line again.
            //
            // The line this replaces read "Not Stable: Stable additionally wants spec
            // compliance and scripting support reviewed" — a bar nobody had written down,
            // which is precisely how the three previous Stable ratings in this repository were
            // set and lost.
            .state(DevelopmentState::Stable)
            // 5683 is above 1023; declaring PrivilegedPort here could never fire.
            .privilege_requirement(PrivilegeRequirement::None)
            .well_known_udp_port(5683)
            .implementation(
                "Hand-rolled RFC 7252 codec (src/server/coap/codec.rs): 4-byte header, \
                 CON/NON/ACK/RST, tokens, option delta/length with both extension forms, \
                 payload marker, GET/POST/PUT/DELETE. Observe (RFC 7641, observe.rs): \
                 registration, deregistration, NON or CON notifications, RST and \
                 unacknowledged-CON removal. Block-wise (RFC 7959, blockwise.rs): Block2 \
                 served from one cached answer with ETag and Size2, Block1 reassembled with \
                 2.31 Continue, 4.08 and 4.13+Size1",
            )
            .llm_control(
                "Resource representations, media type and response code, whether a resource \
                 is observable, and when its observers are notified. Message type, message id, \
                 token echo, block slicing and reassembly are server-side",
            )
            .e2e_testing(
                "STABLE rests on all six conditions, each checked against source and by \
                 running it on 16 September 2026. (1) TWO independent clients, neither \
                 #[ignore]d and neither able to skip: libcoap 4.3.5's own `coap-client` \
                 binary -- C, a different project -- in real_client_test.rs, which FAILS \
                 rather than skips when libcoap is absent, asserting the exact 2.05 body \
                 libcoap parsed and printed, a POST payload echoed back in a 2.04, and a 4.04 \
                 reported as an error with no body; and the coap 0.27 UDP client over \
                 coap-lite 0.13, an unconditional dev-dependency, doing its own CON/ACK \
                 matching so a wrong message id or token is a timeout rather than a pass. \
                 (Those two crates are ONE family -- coap is built on coap-lite -- so they \
                 count as one independent peer, not two.) (2) The pcap oracle runs over every \
                 datagram in e2e_test::exchange and llm_failure_test::exchange, and hard-fails \
                 when tshark is missing. (3) fuzz/fuzz_targets/coap_message.rs: 292,391 runs \
                 in 91s, clean, no artefact. Its corpus has no depth bomb because the decoder \
                 has no recursion -- the equivalent blind spot is the option delta/length \
                 extension forms, and option_delta_ext13/ext14 seed those. (4) Every declared \
                 bound has a test in bounds_test.rs -- MAX_MESSAGE_LEN, MAX_TOKEN_LEN in both \
                 directions, MAX_OPTION_LEN, MAX_PAYLOAD_LEN -- each with an at-limit half and \
                 each verified by REMOVING the bound and recording what failed. (5) Both \
                 CLAUDE.md files were re-read against source in that pass; the corrections are \
                 in them. (6) No #[ignore] and no skip gate anywhere in tests/server/coap/. \
                 \
                 OBSERVE AND BLOCK-WISE, added October 2026, carry the same six conditions on \
                 their own surface (observe_blockwise_test.rs, observe_blockwise_bounds_test.rs): \
                 (1) libcoap's coap-client and aiocoap 0.4 (Python, its own codec) each \
                 register an observation and receive notifications NetGet pushed with \
                 coap_notify, fetch a 3000-byte representation as Block2 blocks and reassemble \
                 it byte for byte, and upload a 3000-byte body as Block1 blocks that reaches \
                 the model whole; both fail rather than skip when absent. (2) The pcap oracle \
                 reads every datagram of the Observe and block exchanges. (3) The fuzz target \
                 also reads Block1, Block2 and Observe from every decoded message. (4) \
                 MAX_OBSERVERS, MAX_OBSERVERS_PER_IP, OBSERVER_MAX_AGE, MAX_UPLOADS, \
                 MAX_UPLOADS_PER_IP, MAX_TRANSFERS, TRANSFER_SERVE_FACTOR, the Block2 TTL a \
                 hit does not renew, MAX_REPRESENTATION_LEN (both directions), out-of-order \
                 Block1, RST removal and the CON notification retransmission limit (including \
                 past the RECENT_NOTIFICATIONS window) each have a test. \
                 \
                 UNPROVEN, because none of it is implemented: DTLS/CoAPS on 5684, separate \
                 (non-piggybacked) responses, retransmission of Confirmable responses, \
                 message deduplication (there is no cache, so a retransmitted CON produces a \
                 second handler call) and multicast.",
            )
            .notes(
                "Stable means the evidence for the implemented surface is complete, NOT that \
                 RFC 7252 is. What is implemented: the 4-byte header, CON/NON/ACK/RST, tokens, \
                 option delta/length with both extension forms, the payload marker, \
                 GET/POST/PUT/DELETE, piggybacked responses, the ping->RST reply, RST for a \
                 malformed CON, 4.13 for a datagram over MAX_MESSAGE_LEN, Observe \
                 (RFC 7641) and Block-wise transfer in both directions (RFC 7959). Not \
                 implemented: separate responses, deduplication, DTLS, multicast. \
                 Two things a future reader should re-check rather than inherit: the fuzz \
                 target (fuzz/ is its own workspace, NO CI job builds it, and this target was \
                 found uncompilable-since-September in the pass that set this rating), and \
                 that coap-client is still on PATH wherever the suite runs, since its test \
                 hard-fails by design.",
            )
            // The bound on what a stranger can send, not on what this server writes.
            // `MAX_PAYLOAD_LEN` was declared here and governs the outbound direction only,
            // so the number named nothing the inbound path checked.
            .max_inbound_bytes(crate::server::coap::codec::MAX_MESSAGE_LEN)
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }

    fn description(&self) -> &'static str {
        "CoAP server impersonating a constrained IoT device (RFC 7252)"
    }

    fn example_prompt(&self) -> &'static str {
        "Pretend to be a soil moisture sensor via coap on port 5683; GET /sensors/moisture \
         returns JSON with a percentage, everything else is 4.04"
    }

    fn group_name(&self) -> &'static str {
        "Application"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;

        // Deterministic: answer every request with a fixed JSON sensor reading,
        // no LLM call.
        let script = r#"import json, sys
data = json.load(sys.stdin)
event = data["event"]
if data["event_type_id"] == "coap_request":
    actions = [{"type": "send_coap_response", "code": "2.05",
                "payload": '{"pct": 41.2}', "content_format": "application/json"}]
else:
    actions = []
print(json.dumps({"actions": actions}))"#;

        StartupExamples::new(
            // LLM mode: the model invents the resource tree and its representations.
            json!({
                "type": "open_server",
                "port": 5683,
                "base_stack": "coap",
                "instruction": "Act as a soil moisture sensor. GET /sensors/moisture returns \
                                2.05 with JSON like {\"pct\": 41.2}. GET /.well-known/core \
                                returns the link-format listing. Anything else is 4.04."
            }),
            // Script mode: deterministic routing, no LLM call per request.
            json!({
                "type": "open_server",
                "port": 5683,
                "base_stack": "coap",
                "event_handlers": [{
                    "event_pattern": "coap_request",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": script
                    }
                }]
            }),
            // Static mode: one fixed representation for every request.
            json!({
                "type": "open_server",
                "port": 5683,
                "base_stack": "coap",
                "event_handlers": [{
                    "event_pattern": "coap_request",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "send_coap_response",
                            "code": "2.05",
                            "payload": "{\"pct\": 41.2}",
                            "content_format": "application/json"
                        }]
                    }
                }]
            }),
        )
    }
}

impl Server for CoapProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            let ack_timeout_ms = ctx
                .startup_params
                .as_ref()
                .map(|p| p.get_optional_u64("notification_ack_timeout_ms"))
                .transpose()?
                .flatten()
                .unwrap_or(super::DEFAULT_NOTIFICATION_ACK_TIMEOUT_MS);
            if !(100..=60_000).contains(&ack_timeout_ms) {
                anyhow::bail!(
                    "notification_ack_timeout_ms must be between 100 and 60000, got \
                     {ack_timeout_ms}"
                );
            }
            let listen_addr = ctx.legacy_listen_addr();
            super::CoapServer::spawn_with_llm_actions(
                listen_addr,
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.server_id,
                std::time::Duration::from_millis(ack_timeout_ms),
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
            "send_coap_response" => {
                let code = response_code(&action, "send_coap_response")?;
                let payload = decode_payload(&action)?;
                let content_format = content_format(&action, &payload, "send_coap_response")?;

                let observable = match action.get("observable") {
                    None | Some(serde_json::Value::Null) => true,
                    Some(serde_json::Value::Bool(b)) => *b,
                    Some(other) => anyhow::bail!(
                        "send_coap_response 'observable' must be true or false, got {other}"
                    ),
                };

                Ok(ActionResult::Custom {
                    name: RESULT_RESPONSE.to_string(),
                    data: json!({
                        "code": code,
                        "payload_hex": hex::encode(&payload),
                        "content_format": content_format,
                        "observable": observable,
                    }),
                })
            }
            "coap_notify" => {
                // Validated here so a malformed one names its real problem, but it can only
                // run against the live server's observers.
                notification_from_action(&action)?;
                anyhow::bail!(
                    "coap_notify needs the running CoAP server's observers and must be \
                     dispatched through execute_action_with_state"
                )
            }
            "send_coap_reset" => Ok(ActionResult::Custom {
                name: RESULT_RESET.to_string(),
                data: json!({}),
            }),
            "ignore_coap_request" => Ok(ActionResult::Custom {
                name: RESULT_IGNORE.to_string(),
                data: json!({}),
            }),
            _ => Err(anyhow::anyhow!("Unknown CoAP action: {action_type}")),
        }
    }

    fn execute_action_with_state<'a>(
        &'a self,
        action: serde_json::Value,
        state: AppState,
        server_id: Option<crate::state::ServerId>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<ActionResult>> + Send + 'a>>
    {
        Box::pin(async move {
            if action.get("type").and_then(|v| v.as_str()) != Some("coap_notify") {
                return self.execute_action(action);
            }
            let (path, rep, confirmable) = notification_from_action(&action)?;
            let server_id =
                server_id.context("coap_notify needs a running CoAP server in context")?;
            let handle = state
                .server_handle::<super::CoapServerHandle>(server_id)
                .await
                .context("coap_notify: this server is not a running CoAP server")?;
            let report = handle.notify(&state, &path, rep, confirmable).await;
            Ok(ActionResult::Custom {
                name: RESULT_NOTIFIED.to_string(),
                data: json!({
                    "path": path,
                    "observers_notified": report.sent,
                    "observations_ended": report.ended,
                }),
            })
        })
    }
}

/// The `code` field: a CoAP response code written `class.detail`, class 2, 4 or 5.
fn response_code(action: &serde_json::Value, verb: &str) -> Result<u8> {
    let code_value = action
        .get("code")
        .with_context(|| format!("{verb} requires a 'code', e.g. \"2.05\" or \"4.04\""))?;

    let code = if let Some(s) = code_value.as_str() {
        codec::parse_code_string(s).ok_or_else(|| {
            anyhow::anyhow!(
                "{verb} 'code' {s:?} is not a CoAP response code. Write it as class.detail, \
                 e.g. \"2.05\" (Content), \"2.04\" (Changed), \"4.04\" (Not Found), \"5.03\" \
                 (Service Unavailable)."
            )
        })?
    } else {
        anyhow::bail!("{verb} 'code' must be a string such as \"2.05\", got {code_value}");
    };

    let class = codec::code_class(code);
    if !(2..=5).contains(&class) || class == 3 {
        anyhow::bail!(
            "{verb} 'code' {} is not a response code: class must be 2 (success), 4 (client \
             error) or 5 (server error). Class 0 is a request method, and 1/3/6/7 are reserved.",
            codec::code_to_string(code)
        );
    }
    Ok(code)
}

/// The `content_format` field. Explicit wins; otherwise text/plain when there is a payload at
/// all, so a client is never handed bytes with no media type. An empty string is "no media
/// type", which is what a model writes for a 4.04 with no body; it reads as absent rather
/// than as an unknown media type.
fn content_format(action: &serde_json::Value, payload: &[u8], verb: &str) -> Result<Option<u16>> {
    let default = if payload.is_empty() { None } else { Some(0) };
    Ok(match action.get("content_format") {
        Some(serde_json::Value::String(s)) if s.trim().is_empty() => default,
        Some(serde_json::Value::String(s)) => {
            Some(codec::content_format_id(s).ok_or_else(|| {
                anyhow::anyhow!(
                    "{verb} 'content_format' {s:?} is not a CoAP media type. Use \"text/plain\", \
                 \"application/json\", \"application/cbor\", \"application/xml\", \
                 \"application/octet-stream\" or \"application/link-format\", or the numeric \
                 identifier."
                )
            })?)
        }
        Some(serde_json::Value::Number(n)) => {
            let id = n.as_u64().unwrap_or(u64::MAX);
            if id > u16::MAX as u64 {
                anyhow::bail!(
                    "{verb} 'content_format' {id} is not a valid Content-Format identifier"
                );
            }
            Some(id as u16)
        }
        Some(serde_json::Value::Null) | None => default, // text/plain;charset=utf-8
        Some(other) => anyhow::bail!(
            "{verb} 'content_format' must be a media type string or a numeric identifier, got \
             {other}"
        ),
    })
}

/// A `coap_notify` action, read into the path, the representation and the message type.
fn notification_from_action(
    action: &serde_json::Value,
) -> Result<(String, super::blockwise::Representation, bool)> {
    let path = action
        .get("path")
        .and_then(|v| v.as_str())
        .context("coap_notify requires a 'path', the observed resource, e.g. \"/temperature\"")?;
    let path = if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    };
    let code = match action.get("code") {
        None | Some(serde_json::Value::Null) => codec::CODE_CONTENT,
        Some(_) => response_code(action, "coap_notify")?,
    };
    let payload = decode_payload(action)?;
    let content_format = content_format(action, &payload, "coap_notify")?;
    let confirmable = match action.get("confirmable") {
        None | Some(serde_json::Value::Null) => false,
        Some(serde_json::Value::Bool(b)) => *b,
        Some(other) => {
            anyhow::bail!("coap_notify 'confirmable' must be true or false, got {other}")
        }
    };
    Ok((
        path,
        super::blockwise::Representation::new(code, payload, content_format),
        confirmable,
    ))
}

/// Turn the action's `payload` into the exact bytes to put on the wire, honouring the
/// explicit `encoding` field.
///
/// There is deliberately no sniffing: `"48656c6c6f"` is both valid text and valid hex,
/// and only the sender knows which it means. A documented `encoding` that the executor
/// then ignores is the `send_tcp_data` bug; this function is the reason it cannot recur
/// here.
fn decode_payload(action: &serde_json::Value) -> Result<Vec<u8>> {
    let payload = match action.get("payload") {
        None | Some(serde_json::Value::Null) => return Ok(Vec::new()),
        Some(serde_json::Value::String(s)) => s.clone(),
        Some(other) => anyhow::bail!(
            "'payload' must be a string (use \"encoding\": \"hex\" for binary), got {other}"
        ),
    };

    let encoding = action
        .get("encoding")
        .and_then(|v| v.as_str())
        .unwrap_or("utf8");

    let bytes = decode_with_encoding(&payload, encoding)?;

    if bytes.len() > codec::MAX_REPRESENTATION_LEN {
        anyhow::bail!(
            "'payload' is {} bytes, over the {}-byte limit. A representation over {} bytes is \
             sent in Block-wise transfer blocks (RFC 7959), but every block is served from one \
             held copy, so the whole has a ceiling. Return a smaller representation - a \
             summary, fewer records, or a link to the detail.",
            bytes.len(),
            codec::MAX_REPRESENTATION_LEN,
            codec::MAX_PAYLOAD_LEN
        );
    }

    Ok(bytes)
}

/// Turn the `payload` string into bytes according to `encoding`, with no size opinion.
fn decode_with_encoding(payload: &str, encoding: &str) -> Result<Vec<u8>> {
    let payload = payload.to_string();
    match encoding {
        "utf8" => Ok(payload.into_bytes()),
        "hex" => {
            let cleaned: String = payload
                .chars()
                .filter(|c| !c.is_ascii_whitespace() && *c != ':')
                .collect();
            let cleaned = cleaned.strip_prefix("0x").unwrap_or(&cleaned);
            if cleaned.len() % 2 != 0 {
                anyhow::bail!(
                    "Invalid hex in 'payload': expected an even number of hex digits, got {} \
                     ({payload:?}). Each byte is two hex digits.",
                    cleaned.len()
                );
            }
            hex::decode(cleaned).map_err(|e| {
                anyhow::anyhow!(
                    "Invalid hex in 'payload' ({payload:?}): {e}. Use only 0-9/a-f, two digits \
                     per byte. To send this string as literal text, omit 'encoding' or set it \
                     to \"utf8\"."
                )
            })
        }
        other => anyhow::bail!(
            "Invalid 'encoding' value {other:?}. Valid values are \"utf8\" (default, send the \
             characters of 'payload' as-is) and \"hex\" (decode 'payload' as hex-encoded \
             bytes)."
        ),
    }
}

// ===========================================================================
// Action definitions
// ===========================================================================

fn send_coap_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_coap_response".to_string(),
        description: "Answer a CoAP request. You decide the resource's representation and which \
             response code it deserves: 2.05 Content for a successful GET, 2.01 Created / \
             2.04 Changed for a POST or PUT, 2.02 Deleted for a DELETE, 4.04 Not Found for a \
             resource this device does not have, 4.05 Method Not Allowed, 4.00 Bad Request, \
             5.03 Service Unavailable. A path your instructions do not give this device is \
             4.04 with no payload - never a representation invented for it. Where the \
             instructions leave a resource's value open, invent one that is plausible for the \
             device and keep it consistent across requests with set_memory. The example's \
             payload is a placeholder for the shape, never data. The message type of the reply \
             (ACK for a CON request, NON for a NON request), the message id and the token echo \
             are handled for you, and so is Block-wise transfer: a payload over 1024 bytes \
             (up to 64 KiB) is sent in blocks without you seeing the continuations. When the \
             request's 'observe' is \"register\", a 2.xx answer registers the client as an \
             observer of the path; push later states with coap_notify."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "code".to_string(),
                type_hint: "string".to_string(),
                description:
                    "CoAP response code written as class.detail, e.g. \"2.05\", \"2.04\", \
                     \"4.04\", \"5.03\". Class must be 2, 4 or 5."
                        .to_string(),
                required: true,
            },
            Parameter {
                name: "payload".to_string(),
                type_hint: "string".to_string(),
                description: "Representation to return. Interpreted according to 'encoding': by \
                     default the characters of this string are sent as UTF-8. Omit for a \
                     response with no body (a DELETE confirmation, a 4.04)."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "encoding".to_string(),
                type_hint: "string".to_string(),
                description:
                    "How to turn 'payload' into bytes. \"utf8\" (the default when omitted) \
                     sends the characters unchanged - use it for text, JSON and XML. \"hex\" \
                     decodes 'payload' as hex-encoded bytes, two hex digits per byte - use it \
                     for CBOR or any other binary representation, e.g. {\"payload\": \
                     \"a1636f6e f5\", \"encoding\": \"hex\"}. There is no auto-detection."
                        .to_string(),
                required: false,
            },
            Parameter {
                name: "content_format".to_string(),
                type_hint: "string".to_string(),
                description: "Media type of 'payload': \"text/plain\", \"application/json\", \
                     \"application/cbor\", \"application/xml\", \"application/octet-stream\", \
                     \"application/link-format\", or the numeric CoAP identifier. Defaults to \
                     text/plain when a payload is present and this is omitted."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "observable".to_string(),
                type_hint: "boolean".to_string(),
                description: "Only matters when the request's 'observe' is \"register\". \
                     Omitted or true, a 2.xx answer registers the client and it will receive \
                     your coap_notify updates for this path. false serves the representation \
                     once and tells the client the resource is not observable."
                    .to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_coap_response",
            "code": "2.05",
            "payload": "<the resource's representation>",
            "content_format": "text/plain"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> {code}")
                .with_debug("CoAP response {code} ({output_bytes}B)")
                .with_trace("CoAP response: {preview(payload,200)}"),
        ),
    }
}

fn send_coap_reset_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_coap_reset".to_string(),
        description:
            "Reject the message with a CoAP Reset (RST). Use this when the device cannot make \
             any sense of the request at all - not as a way to say 'not found', which is \
             4.04. A Reset tells the client to stop retransmitting and that no response is \
             coming."
                .to_string(),
        parameters: vec![],
        example: json!({ "type": "send_coap_reset" }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> RST")
                .with_debug("CoAP reset"),
        ),
    }
}

fn ignore_coap_request_action() -> ActionDefinition {
    ActionDefinition {
        name: "ignore_coap_request".to_string(),
        description:
            "Send nothing at all. Appropriate for a Non-confirmable request the device would \
             not answer, or to model a sleeping or unreachable node. A Confirmable client \
             will retransmit and eventually time out, which is the behaviour you are asking \
             for when you choose this."
                .to_string(),
        parameters: vec![],
        example: json!({ "type": "ignore_coap_request" }),
        log_template: Some(LogTemplate::new().with_debug("CoAP request deliberately unanswered")),
    }
}

fn coap_notify_action() -> ActionDefinition {
    ActionDefinition {
        name: "coap_notify".to_string(),
        description: "Push a resource's new state to every client observing it (RFC 7641). Use \
             it when the state your instructions describe changes - a reading moves, a PUT \
             changes a value others observe - including while answering another request. \
             Clients register by GETting the path with Observe; a path nobody observes \
             notifies nobody, which is not an error. A 2.xx code (the default 2.05) keeps \
             the observations; any 4.xx or 5.xx ends them, which is how you say the resource \
             is gone. A payload over 1024 bytes goes out as its first block and the client \
             fetches the rest."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "path".to_string(),
                type_hint: "string".to_string(),
                description: "The observed resource, e.g. \"/temperature\".".to_string(),
                required: true,
            },
            Parameter {
                name: "payload".to_string(),
                type_hint: "string".to_string(),
                description: "The resource's new representation, read according to \
                     'encoding' exactly as in send_coap_response."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "encoding".to_string(),
                type_hint: "string".to_string(),
                description: "\"utf8\" (default) or \"hex\", as in send_coap_response.".to_string(),
                required: false,
            },
            Parameter {
                name: "content_format".to_string(),
                type_hint: "string".to_string(),
                description: "Media type of 'payload', as in send_coap_response.".to_string(),
                required: false,
            },
            Parameter {
                name: "code".to_string(),
                type_hint: "string".to_string(),
                description: "Response code of the notification. Default \"2.05\"; a 4.xx \
                     or 5.xx ends every observation of the path."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "confirmable".to_string(),
                type_hint: "boolean".to_string(),
                description: "true sends a Confirmable notification the client must \
                     acknowledge; one that is never acknowledged ends the observation. Default \
                     false (Non-confirmable)."
                    .to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "coap_notify",
            "path": "/temperature",
            "payload": "<the resource's new representation>",
            "content_format": "text/plain"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> notify {path}")
                .with_debug("CoAP notify {path} ({output_bytes}B)")
                .with_trace("CoAP notify {path}: {preview(payload,200)}"),
        ),
    }
}

pub static COAP_NOTIFY_ACTION: LazyLock<ActionDefinition> = LazyLock::new(coap_notify_action);

pub static SEND_COAP_RESPONSE_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(send_coap_response_action);
pub static SEND_COAP_RESET_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(send_coap_reset_action);
pub static IGNORE_COAP_REQUEST_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(ignore_coap_request_action);

// ===========================================================================
// Event types
// ===========================================================================

/// A GET/POST/PUT/DELETE arrived. This is the only event this protocol declares, and
/// `src/server/coap/mod.rs` emits it for every well-formed request.
pub static COAP_REQUEST_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "coap_request",
        "A CoAP client is requesting a resource. Decide whether this device has a resource \
         at that path - only the resources your instructions give it exist - and answer with \
         its representation and a response code, or 4.04 when there is none. answer_with \
         says which, for this request.",
        json!({
            "type": "send_coap_response",
            "code": "2.05",
            "payload": "<the resource's representation>",
            "content_format": "text/plain"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "method".to_string(),
            type_hint: "string".to_string(),
            description: "GET, POST, PUT or DELETE".to_string(),
            required: true,
        },
        Parameter {
            name: "path".to_string(),
            type_hint: "string".to_string(),
            description: "Requested path assembled from the Uri-Path options, e.g. \
                 \"/sensors/moisture\". \"/\" when no Uri-Path option was sent."
                .to_string(),
            required: true,
        },
        Parameter {
            name: "path_segments".to_string(),
            type_hint: "array of strings".to_string(),
            description: "The Uri-Path options as individual segments".to_string(),
            required: true,
        },
        Parameter {
            name: "query".to_string(),
            type_hint: "string".to_string(),
            description:
                "Uri-Query options joined with '&', e.g. \"unit=C&since=60\". Absent when the \
                 request carried no query."
                    .to_string(),
            required: false,
        },
        Parameter {
            name: "message_type".to_string(),
            type_hint: "string".to_string(),
            description:
                "\"CON\" for a Confirmable request (the client expects an acknowledgement and \
                 will retransmit without one) or \"NON\" for a Non-confirmable one. The reply \
                 is matched to it automatically; you do not need to act on this."
                    .to_string(),
            required: true,
        },
        Parameter {
            name: "message_id".to_string(),
            type_hint: "integer".to_string(),
            description: "The client's message id. Echoed back automatically - informational only."
                .to_string(),
            required: true,
        },
        Parameter {
            name: "content_format".to_string(),
            type_hint: "string".to_string(),
            description: "Media type of the request payload, when the client declared one"
                .to_string(),
            required: false,
        },
        Parameter {
            name: "accept".to_string(),
            type_hint: "string".to_string(),
            description: "Media type the client asked for in the Accept option, when it sent one. \
                 Prefer it when you can represent the resource that way."
                .to_string(),
            required: false,
        },
        Parameter {
            name: "payload".to_string(),
            type_hint: "string".to_string(),
            description:
                "Request body, for POST and PUT. Read it according to 'payload_encoding'. \
                 Absent when the request carried no body. A body the client sent in Block1 \
                 blocks arrives here whole."
                    .to_string(),
            required: false,
        },
        Parameter {
            name: "payload_size".to_string(),
            type_hint: "integer".to_string(),
            description: "Length of the request body in bytes, when there is one.".to_string(),
            required: false,
        },
        Parameter {
            name: "blocks".to_string(),
            type_hint: "integer".to_string(),
            description: "How many Block1 blocks the body arrived in. Absent when it came in \
                 one message. Informational: the reassembly is done."
                .to_string(),
            required: false,
        },
        Parameter {
            name: "observe".to_string(),
            type_hint: "string".to_string(),
            description: "\"register\" when the client asks to observe this GET's resource: a \
                 2.xx answer registers it, and it will receive every coap_notify for the \
                 path. \"deregister\" when it asks to stop: it is already removed, answer the \
                 GET as usual. Absent for an ordinary request."
                .to_string(),
            required: false,
        },
        Parameter {
            name: "answer_with".to_string(),
            type_hint: "string".to_string(),
            description: "Which answer this request takes, by method and path: the success \
                 code when your instructions give this device the resource, 4.04 when they \
                 do not."
                .to_string(),
            required: true,
        },
        Parameter {
            name: "payload_encoding".to_string(),
            type_hint: "string".to_string(),
            description:
                "How to read 'payload': \"utf8\" means it is the received bytes as literal \
                 text, \"hex\" means it is the received bytes hex-encoded (used whenever they \
                 are not all printable)."
                    .to_string(),
            required: false,
        },
    ])
    .with_actions(vec![
        SEND_COAP_RESPONSE_ACTION.clone(),
        SEND_COAP_RESET_ACTION.clone(),
        IGNORE_COAP_REQUEST_ACTION.clone(),
        COAP_NOTIFY_ACTION.clone(),
    ])
    .with_alternative_example(json!({
        "type": "send_coap_response",
        "code": "4.04"
    }))
    .with_alternative_example(json!({ "type": "send_coap_reset" }))
    .with_log_template(
        LogTemplate::new()
            .with_info("{client_ip}:{client_port} {method} {path}")
            .with_debug("CoAP {message_type} {method} {path} mid={message_id}")
            .with_trace("CoAP request: {json_pretty(.)}"),
    )
});

/// The `answer_with` event field: the answer this request takes, by method and path.
///
/// The code table in `send_coap_response`'s description was not enough on its own: told "you
/// are a greenhouse sensor whose only resource is /temperature", llama3.1:8b answered a GET of
/// /humidity with an invented 2.05 `{"humidity": 41.2}` - the value lifted from the action's
/// example - five times in five. A small model reads the request in front of it, not a table,
/// so the request names both outcomes and the one that applies when the instructions are
/// silent about the path. It leads with the lookup and gives the 4.04 as the literal action:
/// a first version that named the success code first was still answered with an invented 2.05
/// in 2 runs of 5.
pub fn answer_with_for_request(method: &str, path: &str) -> String {
    let found = match method {
        "POST" => "send_coap_response with code \"2.04\" (\"2.01\" when the POST creates a \
                   resource)"
            .to_string(),
        "PUT" => "send_coap_response with code \"2.04\" (\"2.01\" when the PUT creates the \
                  resource)"
            .to_string(),
        "DELETE" => "send_coap_response with code \"2.02\" and no payload".to_string(),
        _ => format!(
            "send_coap_response with code \"2.05\" whose payload is exactly what they say \
             {path} returns, character for character - text stays text, never rewritten as \
             JSON"
        ),
    };
    format!(
        "first look in your instructions for a resource at {path}. If they give this device \
         none there - including when they say it has only other resources - answer exactly \
         {{\"type\": \"send_coap_response\", \"code\": \"4.04\"}} and nothing else; never \
         invent a resource they do not describe. If they do give one, {found}"
    )
}

/// All CoAP event types. The single entry is emitted for every well-formed request.
pub fn get_coap_event_types() -> Vec<EventType> {
    vec![COAP_REQUEST_EVENT.clone()]
}

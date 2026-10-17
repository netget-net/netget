//! GTP protocol actions — the vocabulary the model uses to play an SGSN/GGSN or SGW/PGW.
//!
//! The model decides the things a mobile core actually decides: **whether a subscriber's
//! session is created at all**, what IP address the UE is given, which DNS servers it is told
//! about, and which TEIDs this node will accept traffic on. Everything mechanical — the
//! header bits, the E/S/PN all-or-nothing rule, the fixed-vs-TLV information element split,
//! the sequence-number echo — is `codec.rs` and `mod.rs`.
//!
//! # Why `execute_action` returns structure, not bytes
//!
//! Every executor arm here validates and normalises, then returns an [`ActionResult::Custom`]
//! that `mod.rs` turns into a packet using the *request's* context. Two consequences, both
//! deliberate:
//!
//! * The registry's `GtpProtocol` is stateless and has no request in hand, so every declared
//!   `example` really executes — which is what `tests/executable_examples_test.rs` checks.
//! * A **static or script handler works**, because it does not have to echo a sequence number
//!   it cannot see: `sequence` and `teid` are optional overrides and `mod.rs` fills in the
//!   request's values when they are absent.
//!
//! # Fail closed
//!
//! Nothing in this file can synthesise an acceptance. `send_gtp_create_session_response`
//! requires an explicit cause, and an *accepting* cause additionally requires the address and
//! both TEIDs — a session cannot be granted by omission. The refusal `mod.rs` sends when the
//! model says nothing is built there, from a rejecting cause, and logged distinctly. See
//! `src/server/gtp/CLAUDE.md`.

use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::EventType;
use crate::state::app_state::AppState;
use anyhow::{Context, Result};
use serde_json::json;
use std::net::IpAddr;
use std::sync::LazyLock;

use super::codec;

/// Names carried by the [`ActionResult::Custom`] results this protocol produces. `mod.rs`
/// matches on these; they are not visible to the model.
pub const RESULT_ECHO_RESPONSE: &str = "gtp_echo_response";
pub const RESULT_CREATE_RESPONSE: &str = "gtp_create_session_response";
pub const RESULT_UPDATE_RESPONSE: &str = "gtp_update_context_response";
pub const RESULT_DELETE_RESPONSE: &str = "gtp_delete_session_response";
pub const RESULT_ERROR_INDICATION: &str = "gtp_error_indication";
pub const RESULT_GPDU: &str = "gtp_gpdu";
pub const RESULT_NO_RESPONSE: &str = "gtp_no_response";

/// GTP-C / GTP-U server protocol handler. Stateless: this server keeps **no PDP context
/// table**, by the "protocols must not implement storage" rule.
#[derive(Default)]
pub struct GtpProtocol;

impl GtpProtocol {
    pub fn new() -> Self {
        Self
    }
}

// ===========================================================================
// Parameter helpers
// ===========================================================================

/// Read an optional unsigned integer, accepting the string form models often produce.
fn optional_u32(action: &serde_json::Value, key: &str) -> Result<Option<u32>> {
    match action.get(key) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::Number(n)) => {
            let v = n
                .as_u64()
                .with_context(|| format!("'{key}' must be a non-negative integer, got {n}"))?;
            if v > u32::MAX as u64 {
                anyhow::bail!("'{key}' must fit in 32 bits, got {v}");
            }
            Ok(Some(v as u32))
        }
        Some(serde_json::Value::String(s)) => {
            let trimmed = s.trim();
            let parsed = if let Some(hex) = trimmed
                .strip_prefix("0x")
                .or_else(|| trimmed.strip_prefix("0X"))
            {
                u32::from_str_radix(hex, 16).ok()
            } else {
                trimmed.parse::<u32>().ok()
            };
            parsed
                .map(Some)
                .with_context(|| format!("'{key}' must be an integer, got {s:?}"))
        }
        Some(other) => anyhow::bail!("'{key}' must be an integer, got {other}"),
    }
}

fn optional_u8(action: &serde_json::Value, key: &str) -> Result<Option<u8>> {
    match optional_u32(action, key)? {
        None => Ok(None),
        Some(v) if v <= u8::MAX as u32 => Ok(Some(v as u8)),
        Some(v) => anyhow::bail!("'{key}' must be 0-255, got {v}"),
    }
}

fn optional_ip(action: &serde_json::Value, key: &str) -> Result<Option<IpAddr>> {
    match action.get(key) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::String(s)) => s.trim().parse::<IpAddr>().map(Some).map_err(|_| {
            anyhow::anyhow!(
                "'{key}' must be an IP address such as \"10.45.0.2\", got {s:?}. Write the \
                 address in dotted-quad or IPv6 form; this is the address the subscriber's \
                 device will use."
            )
        }),
        Some(other) => {
            anyhow::bail!("'{key}' must be an IP address written as a string, got {other}")
        }
    }
}

fn dns_servers(action: &serde_json::Value) -> Result<Vec<IpAddr>> {
    let Some(value) = action.get("dns_servers") else {
        return Ok(Vec::new());
    };
    if value.is_null() {
        return Ok(Vec::new());
    }
    let array = value.as_array().ok_or_else(|| {
        anyhow::anyhow!(
            "'dns_servers' must be an array of IP addresses, e.g. [\"8.8.8.8\", \"1.1.1.1\"], \
             got {value}"
        )
    })?;
    let mut out = Vec::with_capacity(array.len());
    for entry in array {
        let s = entry.as_str().ok_or_else(|| {
            anyhow::anyhow!("each entry of 'dns_servers' must be a string, got {entry}")
        })?;
        out.push(
            s.trim()
                .parse::<IpAddr>()
                .map_err(|_| anyhow::anyhow!("'dns_servers' entry {s:?} is not an IP address"))?,
        );
    }
    Ok(out)
}

/// Resolve the model's `cause` into something that can be rendered for either GTP version.
///
/// Returns `(json, accepts_for_v1, accepts_for_v2)`. A named cause carries both codes; a raw
/// number is used verbatim, and whether it accepts is then decided by the numeric ranges
/// TS 29.060 §7.7.1 and TS 29.274 §8.4 define.
fn resolve_cause(
    action: &serde_json::Value,
    action_name: &str,
) -> Result<(serde_json::Value, bool, bool)> {
    let value = action.get("cause").with_context(|| {
        format!(
            "{action_name} requires a 'cause'. Name one of: {}. There is deliberately no \
             default: a session must never be created because a field was left out.",
            codec::cause_names().join(", ")
        )
    })?;

    match value {
        serde_json::Value::String(s) => {
            let cause = codec::cause_by_name(s).ok_or_else(|| {
                anyhow::anyhow!(
                    "{action_name} 'cause' {s:?} is not a GTP cause. Use one of: {}. To send a \
                     value this list does not cover, pass the number from TS 29.060 Table 38 \
                     (GTPv1) or TS 29.274 Table 8.4-1 (GTPv2) instead.",
                    codec::cause_names().join(", ")
                )
            })?;
            Ok((
                json!({ "name": cause.name, "v1": cause.v1, "v2": cause.v2 }),
                cause.accepts,
                cause.accepts,
            ))
        }
        serde_json::Value::Number(n) => {
            let raw = n
                .as_u64()
                .filter(|v| *v <= 255)
                .with_context(|| format!("{action_name} 'cause' must be 0-255, got {n}"))?
                as u8;
            Ok((
                json!({ "name": serde_json::Value::Null, "v1": raw, "v2": raw }),
                codec::cause_accepts(codec::GtpVersion::V1, raw),
                codec::cause_accepts(codec::GtpVersion::V2, raw),
            ))
        }
        other => anyhow::bail!(
            "{action_name} 'cause' must be a name such as \"request_accepted\" or a numeric \
             cause value, got {other}"
        ),
    }
}

/// Turn a `payload` + `encoding` pair into wire bytes.
///
/// The encapsulated user packet is the one genuinely opaque field in this protocol, so it
/// gets an explicit `encoding` that is **really decoded** rather than sniffed —
/// `"48656c6c6f"` is simultaneously valid text and valid hex, and only the sender knows which
/// it meant. That is the `send_tcp_data` lesson (`d70bb5b5`) applied up front.
fn decode_payload(action: &serde_json::Value) -> Result<Vec<u8>> {
    let payload = match action.get("payload") {
        None | Some(serde_json::Value::Null) => return Ok(Vec::new()),
        Some(serde_json::Value::String(s)) => s.clone(),
        Some(other) => anyhow::bail!(
            "send_gtp_gpdu 'payload' must be a string (use \"encoding\": \"hex\" for binary), \
             got {other}"
        ),
    };

    let encoding = action
        .get("encoding")
        .and_then(|v| v.as_str())
        .unwrap_or("utf8");

    match encoding {
        "utf8" => Ok(payload.into_bytes()),
        "hex" => {
            let cleaned: String = payload
                .chars()
                .filter(|c| !c.is_ascii_whitespace() && *c != ':')
                .collect();
            let cleaned = cleaned.strip_prefix("0x").unwrap_or(&cleaned);
            if !cleaned.len().is_multiple_of(2) {
                anyhow::bail!(
                    "Invalid hex in 'payload': expected an even number of hex digits, got {} \
                     ({payload:?}). Each octet is two hex digits.",
                    cleaned.len()
                );
            }
            hex::decode(cleaned).map_err(|e| {
                anyhow::anyhow!(
                    "Invalid hex in 'payload' ({payload:?}): {e}. Use only 0-9/a-f, two digits \
                     per octet. To send this string as literal text, omit 'encoding' or set it \
                     to \"utf8\"."
                )
            })
        }
        other => anyhow::bail!(
            "Invalid 'encoding' value {other:?}. Valid values are \"utf8\" (default: send the \
             characters of 'payload' as-is) and \"hex\" (decode 'payload' as hex-encoded \
             octets)."
        ),
    }
}

/// Optional `sequence` / `teid` overrides shared by every response action.
fn overrides(action: &serde_json::Value) -> Result<serde_json::Value> {
    Ok(json!({
        "sequence": optional_u32(action, "sequence")?,
        "teid": optional_u32(action, "teid")?,
    }))
}

// ===========================================================================
// Protocol trait
// ===========================================================================

impl Protocol for GtpProtocol {
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        // A GTP node has nothing to say to a peer it has not heard from: every message this
        // server sends is a reply, an error indication for traffic that arrived, or a G-PDU
        // back down a tunnel a peer opened. Unsolicited traffic would need a peer table, and
        // this protocol deliberately keeps no state.
        vec![]
    }

    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            send_gtp_echo_response_action(),
            send_gtp_create_session_response_action(),
            send_gtp_update_context_response_action(),
            send_gtp_delete_session_response_action(),
            send_gtp_error_indication_action(),
            send_gtp_gpdu_action(),
            no_response_action(),
        ]
    }

    fn protocol_name(&self) -> &'static str {
        "GTP"
    }

    fn get_event_types(&self) -> Vec<EventType> {
        get_gtp_event_types()
    }

    fn stack_name(&self) -> &'static str {
        "ETH>IP>UDP>GTP"
    }

    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "gtp",
            "gtp-c",
            "gtp-u",
            "gtpv1",
            "gtpv2",
            "gprs tunnelling protocol",
            "mobile core",
            "epc",
            "ggsn",
            "sgsn",
            "pgw",
            "sgw",
        ]
    }

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{
            DevelopmentState, PrivilegeRequirement, ProtocolMetadataV2,
        };

        ProtocolMetadataV2::builder()
            .connectionless()
            // Answers on failure: a session-management request gets its response message with a
            // REFUSING cause (never an accepting one). Echo Requests and G-PDUs stay silent - an
            // Echo Response asserts this node is healthy, and the only user-plane reply (Error
            // Indication) asserts a tunnel does not exist, which tears the peer's session down.
            .answers_on_failure()
            // Experimental. The transport genuinely executes here — both ports are above
            // 1023, so the e2e suite binds real UDP sockets and drives real datagrams
            // through the real codec, which is more than most of this tier can say. What is
            // missing for Beta is the one thing that matters: no third-party GTP
            // implementation has ever accepted a packet this server produced. See notes.
            .state(DevelopmentState::Experimental)
            // 2123 and 2152 are both above 1023. Declaring PrivilegedPort here could never
            // fire and would read as protection that is dead code (the svn/3690 mistake).
            .privilege_requirement(PrivilegeRequirement::None)
            .well_known_udp_port(2123)
            .implementation(
                "Hand-rolled GTPv1-C/GTPv1-U (TS 29.060) and GTPv2-C (TS 29.274) codec in \
                 src/server/gtp/codec.rs: the E/S/PN all-or-nothing optional block, extension \
                 headers, the fixed-length (<128) vs TLV (>=128) GTPv1 IE split, GTPv2's \
                 conditional TEID and TLIV IEs, TBCD subscriber identifiers, labelled APNs, \
                 End User Address / PAA / F-TEID / PCO, and the inner IP header of a G-PDU",
            )
            .llm_control(
                "Whether a subscriber session is created and with which cause, the UE's \
                 assigned IP address, the DNS servers it is told about, the TEIDs this node \
                 will accept, and what to do with user-plane traffic. The header bits, the \
                 sequence-number echo and the IE encoding are server-side",
            )
            .e2e_testing(
                "Real UDP sockets on 127.0.0.1 driven by a hand-written peer in \
                 tests/server/gtp; codec pinned against literal RFC/3GPP-derived bytes. No \
                 third-party GTP implementation is involved",
            )
            .notes(
                "GTPv2-C (TS 29.274) IS implemented alongside GTPv1 and both are served on \
                 the control port: the first three bits select the version, and Echo, Create \
                 Session / Create PDP Context, Modify Bearer / Update PDP Context and Delete \
                 Session / Delete PDP Context are handled in each. Experimental, not Beta, \
                 for one reason: no independent GTP implementation has completed a session \
                 against it. The transport IS exercised - the e2e suite binds real UDP sockets \
                 on ephemeral ports and completes real exchanges - but its peer is hand-written \
                 inside the test, which the root CLAUDE.md classes as an independent reading of \
                 the specification rather than an independent implementation (the dhcp and \
                 usbip situation). The BYTES are third-party validated: Wireshark 4.x's gtp and \
                 gtpv2 dissectors parse this server's Create PDP Context Response, Create \
                 Session Response, Echo Response and a PN-only G-PDU with no expert warnings, \
                 naming every cause, IE, F-TEID interface type and PCO container correctly - \
                 which is validation of the encoding, not of a peer completing a session, so it \
                 raises confidence without earning Beta. Not implemented: the QoS Profile IE (fabricating a valid \
                 TS 24.008 profile would be inventing spec compliance we have not checked), \
                 GTP' charging (TS 32.295), GTPv0, secondary PDP contexts, MBMS, S1 handover \
                 signalling, and any retransmission or duplicate-detection timer. This server \
                 keeps NO PDP context table, so a Delete response echoes the request's header \
                 TEID unless the model supplies one - a real GGSN would look the peer's TEID \
                 up in state we deliberately do not hold. IMSI and MSISDN are subscriber \
                 identifiers: the model invents them and this server reads no real subscriber \
                 source of any kind",
            )
            .max_inbound_bytes(crate::server::gtp::codec::MAX_GPDU_PAYLOAD_LEN)
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }

    fn description(&self) -> &'static str {
        "GTP-C/GTP-U server playing a mobile-core node (GGSN/PGW): decides whether a \
         subscriber session is created and what address it gets"
    }

    fn example_prompt(&self) -> &'static str {
        "Act as a PGW on gtp port 2123: accept Create Session Requests whose APN is \
         \"internet\", assign addresses from 10.45.0.0/16 and hand out 8.8.8.8 for DNS; \
         refuse every other APN with missing_or_unknown_apn"
    }

    fn group_name(&self) -> &'static str {
        "Mobile"
    }

    fn get_startup_parameters(&self) -> Vec<crate::llm::actions::ParameterDefinition> {
        use crate::llm::actions::ParameterDefinition;
        vec![
            ParameterDefinition {
                name: "user_plane_port".to_string(),
                type_hint: "number".to_string(),
                description:
                    "UDP port for GTP-U (the user plane). When omitted the server uses 2152 if \
                     the control port is the standard 2123, and an ephemeral port otherwise, \
                     so a test on an ephemeral control port does not collide on a fixed one. \
                     Pass 0 to force an ephemeral port."
                        .to_string(),
                required: false,
                example: json!(2152),
                default: None,
            },
            ParameterDefinition {
                name: "enable_user_plane".to_string(),
                type_hint: "boolean".to_string(),
                description:
                    "Whether to bind the GTP-U socket at all. Default true. Set false for a \
                     control-plane-only node, which is what you want when the point is the \
                     session-management signalling and nothing will carry user traffic."
                        .to_string(),
                required: false,
                example: json!(true),
                default: None,
            },
        ]
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;

        let script = r#"import json, sys
data = json.load(sys.stdin)
event = data["event"]
if data["event_type_id"] == "gtp_create_session_request":
    if event.get("apn") == "internet":
        actions = [{"type": "send_gtp_create_session_response",
                    "cause": "request_accepted",
                    "sequence": event["sequence"],
                    "assigned_address": "10.45.0.2",
                    "control_teid": 1, "data_teid": 2,
                    "dns_servers": ["8.8.8.8"]}]
    else:
        actions = [{"type": "send_gtp_create_session_response",
                    "cause": "missing_or_unknown_apn",
                    "sequence": event["sequence"]}]
elif data["event_type_id"] == "gtp_echo_request":
    actions = [{"type": "send_gtp_echo_response", "sequence": event["sequence"]}]
else:
    actions = []
print(json.dumps({"actions": actions}))"#;

        StartupExamples::new(
            // LLM mode: the model plays the PGW and decides every session.
            json!({
                "type": "open_server",
                "port": 2123,
                "base_stack": "gtp",
                "startup_params": { "user_plane_port": 2152 },
                "instruction": "You are a PGW. Accept Create Session Requests for APN \
                                \"internet\", assigning addresses from 10.45.0.0/16 and DNS \
                                8.8.8.8. Refuse any other APN with missing_or_unknown_apn. \
                                Answer Echo Requests."
            }),
            // Script mode: deterministic admission, no LLM call per session.
            json!({
                "type": "open_server",
                "port": 2123,
                "base_stack": "gtp",
                "event_handlers": [{
                    "event_pattern": "gtp_*",
                    "handler": { "type": "script", "language": "python", "code": script }
                }]
            }),
            // Static mode: refuse every session, answer nothing else. A GTP node that is
            // administratively closed - and notably NOT the shape of an accept, because a
            // static accept would have to invent a per-session address.
            json!({
                "type": "open_server",
                "port": 2123,
                "base_stack": "gtp",
                "event_handlers": [{
                    "event_pattern": "gtp_create_session_request",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "send_gtp_create_session_response",
                            "cause": "no_resources_available"
                        }]
                    }
                }]
            }),
        )
    }
}

impl Server for GtpProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move { super::GtpServer::spawn_with_llm_actions(ctx).await })
    }

    fn execute_action(&self, action: serde_json::Value) -> Result<ActionResult> {
        let action_type = action
            .get("type")
            .and_then(|v| v.as_str())
            .context("Missing 'type' field in action")?;

        match action_type {
            "send_gtp_echo_response" => {
                let mut data = overrides(&action)?;
                data["recovery"] = json!(optional_u8(&action, "recovery")?.unwrap_or(0));
                Ok(ActionResult::Custom {
                    name: RESULT_ECHO_RESPONSE.to_string(),
                    data,
                })
            }

            "send_gtp_create_session_response" => {
                let (cause, accepts_v1, accepts_v2) =
                    resolve_cause(&action, "send_gtp_create_session_response")?;
                let assigned_address = optional_ip(&action, "assigned_address")?;
                let control_teid = optional_u32(&action, "control_teid")?;
                let data_teid = optional_u32(&action, "data_teid")?;

                // A grant must be complete. Answering "accepted" with no address and no
                // TEIDs would produce a response a real peer treats as a successful session
                // it can never use - the fail-open shape this protocol exists to avoid.
                if accepts_v1 || accepts_v2 {
                    if assigned_address.is_none() {
                        anyhow::bail!(
                            "send_gtp_create_session_response with an accepting cause requires \
                             'assigned_address': the address the subscriber's device will use, \
                             e.g. \"10.45.0.2\". To refuse instead, use a cause such as \
                             \"no_resources_available\" or \"missing_or_unknown_apn\"."
                        );
                    }
                    if control_teid.is_none() || data_teid.is_none() {
                        anyhow::bail!(
                            "send_gtp_create_session_response with an accepting cause requires \
                             both 'control_teid' and 'data_teid': the tunnel endpoint \
                             identifiers this node will accept for the session's signalling \
                             and its user traffic. Any non-zero 32-bit values will do; they \
                             are yours to choose."
                        );
                    }
                }

                let mut data = overrides(&action)?;
                data["cause"] = cause;
                data["assigned_address"] = json!(assigned_address.map(|a| a.to_string()));
                data["control_teid"] = json!(control_teid);
                data["data_teid"] = json!(data_teid);
                data["charging_id"] = json!(optional_u32(&action, "charging_id")?);
                data["recovery"] = json!(optional_u8(&action, "recovery")?);
                data["dns_servers"] = json!(dns_servers(&action)?
                    .into_iter()
                    .map(|a| a.to_string())
                    .collect::<Vec<_>>());
                Ok(ActionResult::Custom {
                    name: RESULT_CREATE_RESPONSE.to_string(),
                    data,
                })
            }

            "send_gtp_update_context_response" => {
                let (cause, _, _) = resolve_cause(&action, "send_gtp_update_context_response")?;
                let mut data = overrides(&action)?;
                data["cause"] = cause;
                data["control_teid"] = json!(optional_u32(&action, "control_teid")?);
                data["data_teid"] = json!(optional_u32(&action, "data_teid")?);
                data["assigned_address"] =
                    json!(optional_ip(&action, "assigned_address")?.map(|a| a.to_string()));
                data["charging_id"] = json!(optional_u32(&action, "charging_id")?);
                data["recovery"] = json!(optional_u8(&action, "recovery")?);
                Ok(ActionResult::Custom {
                    name: RESULT_UPDATE_RESPONSE.to_string(),
                    data,
                })
            }

            "send_gtp_delete_session_response" => {
                let (cause, _, _) = resolve_cause(&action, "send_gtp_delete_session_response")?;
                let mut data = overrides(&action)?;
                data["cause"] = cause;
                data["recovery"] = json!(optional_u8(&action, "recovery")?);
                Ok(ActionResult::Custom {
                    name: RESULT_DELETE_RESPONSE.to_string(),
                    data,
                })
            }

            "send_gtp_error_indication" => {
                let teid = optional_u32(&action, "teid")?.context(
                    "send_gtp_error_indication requires 'teid': the tunnel endpoint identifier \
                     from the G-PDU that had no context here. Sending it back is what tells \
                     the peer to tear that tunnel down.",
                )?;
                Ok(ActionResult::Custom {
                    name: RESULT_ERROR_INDICATION.to_string(),
                    data: json!({
                        "teid": teid,
                        "sequence": optional_u32(&action, "sequence")?,
                    }),
                })
            }

            "send_gtp_gpdu" => {
                let teid = optional_u32(&action, "teid")?.context(
                    "send_gtp_gpdu requires 'teid': the tunnel endpoint identifier the peer \
                     assigned for this session's user traffic. It is what tells the receiving \
                     node which subscriber the packet belongs to.",
                )?;
                let payload = decode_payload(&action)?;
                if payload.is_empty() {
                    anyhow::bail!(
                        "send_gtp_gpdu requires a non-empty 'payload': a G-PDU carries one \
                         encapsulated user IP packet, and an empty tunnel packet means nothing."
                    );
                }
                Ok(ActionResult::Custom {
                    name: RESULT_GPDU.to_string(),
                    data: json!({
                        "teid": teid,
                        "payload_hex": hex::encode(&payload),
                        "sequence": optional_u32(&action, "sequence")?,
                    }),
                })
            }

            "no_response" => Ok(ActionResult::Custom {
                name: RESULT_NO_RESPONSE.to_string(),
                data: json!({
                    "reason": action.get("reason").and_then(|v| v.as_str()).unwrap_or(""),
                }),
            }),

            _ => Err(anyhow::anyhow!("Unknown GTP action: {action_type}")),
        }
    }
}

// ===========================================================================
// Action definitions
// ===========================================================================

/// The `sequence` parameter, identical on every response action.
fn sequence_parameter() -> Parameter {
    Parameter {
        name: "sequence".to_string(),
        type_hint: "integer".to_string(),
        description:
            "Sequence number of the request being answered. A GTP peer matches a response to \
             its request by this number, so copy it from the event's 'sequence' field. If you \
             omit it the server echoes the request's own sequence, which is almost always what \
             you want - set it only when you deliberately mean a different one."
                .to_string(),
        required: false,
    }
}

/// The `teid` parameter, identical on every response action.
fn response_teid_parameter() -> Parameter {
    Parameter {
        name: "teid".to_string(),
        type_hint: "integer".to_string(),
        description:
            "Tunnel endpoint identifier to put in the response header - the value the PEER \
             gave you for its own control plane, so that it can route the answer. Omit it and \
             the server uses the one the request advertised. Do not confuse it with \
             'control_teid', which is the identifier YOU are assigning."
                .to_string(),
        required: false,
    }
}

fn cause_parameter(action_name: &str) -> Parameter {
    Parameter {
        name: "cause".to_string(),
        type_hint: "string".to_string(),
        description: format!(
            "Why {action_name} says what it says. One of: {}. \"request_accepted\" is the only \
             common acceptance and it commits this node to the session; every other value \
             refuses. A number from TS 29.060 Table 38 (GTPv1) or TS 29.274 Table 8.4-1 \
             (GTPv2) is also accepted for causes this list does not name. There is no default.",
            codec::cause_names().join(", ")
        ),
        required: true,
    }
}

fn send_gtp_echo_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_gtp_echo_response".to_string(),
        description: "Answer a GTP Echo Request, telling the peer this node is alive and the path \
             between you is usable. A peer that gets no answer to several echoes tears down \
             every tunnel it has with this node, so answer unless you are deliberately \
             modelling an unreachable GSN - for which use no_response."
            .to_string(),
        parameters: vec![
            sequence_parameter(),
            Parameter {
                name: "recovery".to_string(),
                type_hint: "integer".to_string(),
                description:
                    "Restart counter, 0-255. A peer that sees this value INCREASE concludes \
                     that this node restarted and that every tunnel it held is gone. Keep it \
                     stable (0 is fine) unless you are modelling a restart."
                        .to_string(),
                required: false,
            },
        ],
        example: json!({ "type": "send_gtp_echo_response", "sequence": 1, "recovery": 0 }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> Echo Response")
                .with_debug("GTP Echo Response seq={sequence} recovery={recovery}"),
        ),
    }
}

fn send_gtp_create_session_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_gtp_create_session_response".to_string(),
        description:
            "Decide whether this subscriber gets a session, and on what terms. This is the \
             central decision of a mobile core: you are the GGSN/PGW, and the answer either \
             admits the subscriber to the packet network or refuses them. Answers a Create \
             PDP Context Request (GTPv1) or a Create Session Request (GTPv2) - the server \
             sends whichever the peer asked in. To ACCEPT you must supply 'assigned_address', \
             'control_teid' and 'data_teid'; a session cannot be granted by leaving fields \
             out. To REFUSE, name a rejecting cause and omit the rest."
                .to_string(),
        parameters: vec![
            cause_parameter("this session decision"),
            Parameter {
                name: "assigned_address".to_string(),
                type_hint: "string".to_string(),
                description: "IP address assigned to the subscriber's device, e.g. \"10.45.0.2\". \
                     Required when accepting. Invent one from a private range and keep it \
                     consistent for the session (use set_memory if you need to remember it); \
                     this server holds no session table of its own."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "control_teid".to_string(),
                type_hint: "integer".to_string(),
                description: "Tunnel endpoint identifier THIS node will accept for the session's \
                     control-plane signalling. Required when accepting. Any non-zero 32-bit \
                     value; the peer will put it in the header of every later message about \
                     this session."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "data_teid".to_string(),
                type_hint: "integer".to_string(),
                description:
                    "Tunnel endpoint identifier THIS node will accept for the subscriber's \
                     user traffic on the GTP-U port. Required when accepting."
                        .to_string(),
                required: false,
            },
            Parameter {
                name: "dns_servers".to_string(),
                type_hint: "array of strings".to_string(),
                description:
                    "DNS resolvers to hand the device, e.g. [\"8.8.8.8\", \"1.1.1.1\"]. Sent \
                     inside Protocol Configuration Options. Omit to tell the device nothing, \
                     which is legitimate when it asked for nothing."
                        .to_string(),
                required: false,
            },
            Parameter {
                name: "charging_id".to_string(),
                type_hint: "integer".to_string(),
                description:
                    "Charging identifier for the session, if you want the peer to have one. \
                     GTPv1 only; ignored for a GTPv2 peer."
                        .to_string(),
                required: false,
            },
            Parameter {
                name: "recovery".to_string(),
                type_hint: "integer".to_string(),
                description: "Restart counter to include, 0-255. Omit unless you mean to \
                              advertise one."
                    .to_string(),
                required: false,
            },
            sequence_parameter(),
            response_teid_parameter(),
        ],
        example: json!({
            "type": "send_gtp_create_session_response",
            "cause": "request_accepted",
            "sequence": 1,
            "assigned_address": "10.45.0.2",
            "control_teid": 305419896,
            "data_teid": 305419897,
            "dns_servers": ["8.8.8.8", "1.1.1.1"]
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> session {cause}")
                .with_debug(
                    "GTP Create Session Response cause={cause} addr={assigned_address} \
                     seq={sequence}",
                )
                .with_trace("GTP Create Session Response: {json_pretty(.)}"),
        ),
    }
}

fn send_gtp_update_context_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_gtp_update_context_response".to_string(),
        description:
            "Answer an Update PDP Context Request (GTPv1) or a Modify Bearer Request (GTPv2). \
             The peer is telling you the subscriber moved, or that some parameter of an \
             existing session changed, and is asking you to keep it. Accepting confirms the \
             session continues; refusing tears it down. Supply 'control_teid' / 'data_teid' \
             only if you are changing the identifiers this node accepts."
                .to_string(),
        parameters: vec![
            cause_parameter("this update"),
            Parameter {
                name: "control_teid".to_string(),
                type_hint: "integer".to_string(),
                description: "New control-plane TEID this node will accept, if it changed."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "data_teid".to_string(),
                type_hint: "integer".to_string(),
                description: "New user-plane TEID this node will accept, if it changed."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "assigned_address".to_string(),
                type_hint: "string".to_string(),
                description: "The subscriber's address, if you are restating or changing it."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "charging_id".to_string(),
                type_hint: "integer".to_string(),
                description: "Charging identifier, GTPv1 only.".to_string(),
                required: false,
            },
            Parameter {
                name: "recovery".to_string(),
                type_hint: "integer".to_string(),
                description: "Restart counter to include, 0-255.".to_string(),
                required: false,
            },
            sequence_parameter(),
            response_teid_parameter(),
        ],
        example: json!({
            "type": "send_gtp_update_context_response",
            "cause": "request_accepted",
            "sequence": 2
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> update {cause}")
                .with_debug("GTP Update/Modify Response cause={cause} seq={sequence}"),
        ),
    }
}

fn send_gtp_delete_session_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_gtp_delete_session_response".to_string(),
        description:
            "Answer a Delete PDP Context Request (GTPv1) or a Delete Session Request (GTPv2). \
             The peer wants the subscriber's session torn down. \"request_accepted\" confirms \
             it is gone; \"context_not_found\" is the right answer when you have no record of \
             the session at all, and is not an error."
                .to_string(),
        parameters: vec![
            cause_parameter("this deletion"),
            Parameter {
                name: "recovery".to_string(),
                type_hint: "integer".to_string(),
                description: "Restart counter to include, 0-255.".to_string(),
                required: false,
            },
            sequence_parameter(),
            response_teid_parameter(),
        ],
        example: json!({
            "type": "send_gtp_delete_session_response",
            "cause": "request_accepted",
            "sequence": 3
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> delete {cause}")
                .with_debug("GTP Delete Session Response cause={cause} seq={sequence}"),
        ),
    }
}

fn send_gtp_error_indication_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_gtp_error_indication".to_string(),
        description:
            "Tell the peer that user traffic arrived for a tunnel this node knows nothing \
             about. This is the correct answer to a G-PDU whose TEID belongs to no session - \
             it makes the sender stop, rather than letting it keep pushing a subscriber's \
             packets into a hole. Do not use it for traffic you simply chose not to forward."
                .to_string(),
        parameters: vec![
            Parameter {
                name: "teid".to_string(),
                type_hint: "integer".to_string(),
                description: "The TEID from the G-PDU that had no context here. Copy it from the \
                     event's 'teid' field; it is what identifies the tunnel the peer must \
                     tear down."
                    .to_string(),
                required: true,
            },
            sequence_parameter(),
        ],
        example: json!({ "type": "send_gtp_error_indication", "teid": 305419896 }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> Error Indication teid={teid}")
                .with_debug("GTP Error Indication teid={teid}"),
        ),
    }
}

fn send_gtp_gpdu_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_gtp_gpdu".to_string(),
        description:
            "Send one encapsulated user packet back down a tunnel - what a PGW does when a \
             reply arrives from the internet for a subscriber. 'payload' is the complete \
             inner IP packet, and it is the one place in this protocol where you supply raw \
             octets, so say which encoding you used."
                .to_string(),
        parameters: vec![
            Parameter {
                name: "teid".to_string(),
                type_hint: "integer".to_string(),
                description:
                    "TEID the PEER assigned for this session's user traffic - the value it \
                     sent you when the session was created. It selects the subscriber at the \
                     other end."
                        .to_string(),
                required: true,
            },
            Parameter {
                name: "payload".to_string(),
                type_hint: "string".to_string(),
                description: "The inner packet, interpreted according to 'encoding'. A real G-PDU \
                     carries a complete IP packet, so this is normally a hex-encoded IPv4 or \
                     IPv6 datagram."
                    .to_string(),
                required: true,
            },
            Parameter {
                name: "encoding".to_string(),
                type_hint: "\"utf8\" | \"hex\"".to_string(),
                description:
                    "How to turn 'payload' into octets. \"hex\" decodes it as hex, two digits \
                     per octet - use this for a real IP packet. \"utf8\" (the default) sends \
                     the characters unchanged, which is only useful for a synthetic payload. \
                     There is no auto-detection: \"48656c6c6f\" is both valid text and valid \
                     hex, and only you know which you meant."
                        .to_string(),
                required: false,
            },
            Parameter {
                name: "sequence".to_string(),
                type_hint: "integer".to_string(),
                description:
                    "Optional GTP-U sequence number. Omit it and the packet carries none, \
                     which is what most user-plane traffic does."
                        .to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_gtp_gpdu",
            "teid": 305419896,
            // A 28-octet IPv4/UDP packet: 10.45.0.1:53 -> 10.45.0.2:1024, empty body.
            "payload": "450000\
        1c0001000040110000\
        0a2d00010a2d0002003504000008\
        0000",
            "encoding": "hex"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> G-PDU teid={teid}")
                .with_debug("GTP G-PDU teid={teid} ({output_bytes}B)"),
        ),
    }
}

fn no_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "no_response".to_string(),
        description:
            "Send nothing at all. A real, deliberate answer, and distinct from failing to \
             answer: use it for a node that is administratively silent, for user-plane \
             traffic you are simply absorbing, or to model a GSN the peer will conclude is \
             unreachable. Note the consequence for signalling - a peer whose Echo Requests \
             or Create Session Requests go unanswered will retransmit and then give up on \
             this node entirely."
                .to_string(),
        parameters: vec![Parameter {
            name: "reason".to_string(),
            type_hint: "string".to_string(),
            description: "Why nothing is being sent. Recorded in the log; never transmitted."
                .to_string(),
            required: false,
        }],
        example: json!({ "type": "no_response", "reason": "absorbing user-plane traffic" }),
        log_template: Some(LogTemplate::new().with_debug("GTP deliberately silent: {reason}")),
    }
}

pub static SEND_GTP_ECHO_RESPONSE_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(send_gtp_echo_response_action);
pub static SEND_GTP_CREATE_SESSION_RESPONSE_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(send_gtp_create_session_response_action);
pub static SEND_GTP_UPDATE_CONTEXT_RESPONSE_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(send_gtp_update_context_response_action);
pub static SEND_GTP_DELETE_SESSION_RESPONSE_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(send_gtp_delete_session_response_action);
pub static SEND_GTP_ERROR_INDICATION_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(send_gtp_error_indication_action);
pub static SEND_GTP_GPDU_ACTION: LazyLock<ActionDefinition> = LazyLock::new(send_gtp_gpdu_action);
pub static NO_RESPONSE_ACTION: LazyLock<ActionDefinition> = LazyLock::new(no_response_action);

// ===========================================================================
// Event types
// ===========================================================================

fn common_parameters() -> Vec<Parameter> {
    vec![
        Parameter {
            name: "version".to_string(),
            type_hint: "integer".to_string(),
            description:
                "1 for GTPv1 (TS 29.060, the 2G/3G packet core) or 2 for GTPv2-C (TS 29.274, \
                 the EPC). The server answers in whichever version the peer used; this is \
                 informational."
                    .to_string(),
            required: true,
        },
        Parameter {
            name: "message".to_string(),
            type_hint: "string".to_string(),
            description: "The 3GPP name of the message that arrived, e.g. \"Create Session \
                          Request\"."
                .to_string(),
            required: true,
        },
        Parameter {
            name: "sequence".to_string(),
            type_hint: "integer".to_string(),
            description:
                "The request's sequence number. Copy it into your response's 'sequence' so \
                 the peer can match the two."
                    .to_string(),
            required: true,
        },
        Parameter {
            name: "teid".to_string(),
            type_hint: "integer".to_string(),
            description: "Tunnel endpoint identifier in the request header. 0 on a first \
                          contact, since the peer has not been given one yet."
                .to_string(),
            required: true,
        },
        Parameter {
            name: "source_address".to_string(),
            type_hint: "string".to_string(),
            description: "IP address and port the datagram came from.".to_string(),
            required: true,
        },
    ]
}

/// A peer is checking that this node and the path to it are alive.
pub static GTP_ECHO_REQUEST_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    let mut parameters = common_parameters();
    parameters.push(Parameter {
        name: "plane".to_string(),
        type_hint: "\"control\" | \"user\"".to_string(),
        description:
            "Which socket it arrived on. Both planes run path management independently, so an \
             echo on the user plane is about the tunnel path, not the signalling one."
                .to_string(),
        required: true,
    });

    EventType::new(
        "gtp_echo_request",
        "A GTP peer is asking whether this node is alive. Answering keeps every tunnel \
         between you up; silence eventually makes the peer tear them all down.",
        json!({ "type": "send_gtp_echo_response", "sequence": 1 }),
    )
    .with_parameters(parameters)
    .with_actions(vec![
        SEND_GTP_ECHO_RESPONSE_ACTION.clone(),
        NO_RESPONSE_ACTION.clone(),
    ])
    .with_alternative_example(json!({ "type": "no_response", "reason": "node is down" }))
    .with_log_template(
        LogTemplate::new()
            .with_info("{source_address} Echo Request")
            .with_debug("GTP v{version} Echo Request seq={sequence} on the {plane} plane"),
    )
});

/// A peer wants a subscriber admitted to the packet network.
pub static GTP_CREATE_SESSION_REQUEST_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    let mut parameters = common_parameters();
    parameters.extend(vec![
        Parameter {
            name: "imsi".to_string(),
            type_hint: "string".to_string(),
            description:
                "International Mobile Subscriber Identity, as decimal digits: the identifier \
                 of the SIM asking for a session. The first 3 digits are the mobile country \
                 code and the next 2-3 the network code. Treat it as a subscriber identifier, \
                 not as a name you can look anything up by - nothing here has a real \
                 subscriber database."
                    .to_string(),
            required: false,
        },
        Parameter {
            name: "msisdn".to_string(),
            type_hint: "string".to_string(),
            description: "The subscriber's phone number in international format, when the peer \
                          sent one."
                .to_string(),
            required: false,
        },
        Parameter {
            name: "apn".to_string(),
            type_hint: "string".to_string(),
            description: "Access Point Name the device asked for, e.g. \"internet\" or \
                 \"ims.mnc001.mcc262.gprs\". This is the main thing to decide on: an APN this \
                 network does not serve should be refused with missing_or_unknown_apn."
                .to_string(),
            required: false,
        },
        Parameter {
            name: "control_teid".to_string(),
            type_hint: "integer".to_string(),
            description: "TEID the PEER will accept for this session's signalling. Put it in your \
                 response's 'teid' - though the server does that for you if you omit it."
                .to_string(),
            required: false,
        },
        Parameter {
            name: "data_teid".to_string(),
            type_hint: "integer".to_string(),
            description: "TEID the PEER will accept for this session's user traffic. It is \
                          what you would put in a later send_gtp_gpdu."
                .to_string(),
            required: false,
        },
        Parameter {
            name: "requested_address".to_string(),
            type_hint: "string".to_string(),
            description:
                "Address the device asked for, when it asked for a specific one. Absent means \
                 it wants whatever you assign, which is the normal case."
                    .to_string(),
            required: false,
        },
        Parameter {
            name: "pdp_type".to_string(),
            type_hint: "string".to_string(),
            description: "\"IPv4\", \"IPv6\" or \"IPv4v6\" - the kind of address the device \
                          can use."
                .to_string(),
            required: false,
        },
        Parameter {
            name: "rat_type".to_string(),
            type_hint: "string".to_string(),
            description: "Radio access technology, e.g. \"EUTRAN\", \"UTRAN\", \"NR\".".to_string(),
            required: false,
        },
        Parameter {
            name: "nsapi".to_string(),
            type_hint: "integer".to_string(),
            description: "GTPv1 NSAPI or GTPv2 EPS Bearer Identity: which bearer of this \
                          subscriber's the request is about."
                .to_string(),
            required: false,
        },
        Parameter {
            name: "peer_address".to_string(),
            type_hint: "string".to_string(),
            description: "Control-plane address the peer advertised for itself, from its GSN \
                          Address or F-TEID."
                .to_string(),
            required: false,
        },
        Parameter {
            name: "information_elements".to_string(),
            type_hint: "array of objects".to_string(),
            description:
                "Every information element in the request as {type, name, length} - a summary \
                 for elements this server does not decode into a named field. No octets."
                    .to_string(),
            required: false,
        },
    ]);

    EventType::new(
        "gtp_create_session_request",
        "A subscriber is asking to be admitted to the packet data network. You are the \
         GGSN/PGW: decide whether this IMSI gets a session on this APN, and if so what IP \
         address and DNS servers it is given. Refusing is a normal outcome - name the cause.",
        json!({
            "type": "send_gtp_create_session_response",
            "cause": "request_accepted",
            "sequence": 1,
            "assigned_address": "10.45.0.2",
            "control_teid": 305419896,
            "data_teid": 305419897,
            "dns_servers": ["8.8.8.8"]
        }),
    )
    .with_parameters(parameters)
    .with_actions(vec![
        SEND_GTP_CREATE_SESSION_RESPONSE_ACTION.clone(),
        NO_RESPONSE_ACTION.clone(),
    ])
    .with_alternative_example(json!({
        "type": "send_gtp_create_session_response",
        "cause": "missing_or_unknown_apn",
        "sequence": 1
    }))
    .with_log_template(
        LogTemplate::new()
            .with_info("{source_address} session request imsi={imsi} apn={apn}")
            .with_debug(
                "GTP v{version} {message} imsi={imsi} apn={apn} seq={sequence} rat={rat_type}",
            )
            .with_trace("GTP session request: {json_pretty(.)}"),
    )
});

/// A peer wants an existing session changed — a handover, or a parameter update.
pub static GTP_UPDATE_CONTEXT_REQUEST_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    let mut parameters = common_parameters();
    parameters.extend(vec![
        Parameter {
            name: "imsi".to_string(),
            type_hint: "string".to_string(),
            description: "Subscriber identity, when the peer restated it.".to_string(),
            required: false,
        },
        Parameter {
            name: "control_teid".to_string(),
            type_hint: "integer".to_string(),
            description: "Control-plane TEID the peer will now accept, when it changed."
                .to_string(),
            required: false,
        },
        Parameter {
            name: "data_teid".to_string(),
            type_hint: "integer".to_string(),
            description: "User-plane TEID the peer will now accept. This is the field a handover \
                 changes: traffic must go to the new one from now on."
                .to_string(),
            required: false,
        },
        Parameter {
            name: "nsapi".to_string(),
            type_hint: "integer".to_string(),
            description: "Which bearer is being updated.".to_string(),
            required: false,
        },
        Parameter {
            name: "rat_type".to_string(),
            type_hint: "string".to_string(),
            description: "Radio access technology after the change, when the peer sent one."
                .to_string(),
            required: false,
        },
        Parameter {
            name: "peer_address".to_string(),
            type_hint: "string".to_string(),
            description: "Address the peer advertised for itself.".to_string(),
            required: false,
        },
        Parameter {
            name: "information_elements".to_string(),
            type_hint: "array of objects".to_string(),
            description: "Every information element as {type, name, length}.".to_string(),
            required: false,
        },
    ]);

    EventType::new(
        "gtp_update_context_request",
        "A peer is asking to change an existing subscriber session - typically because the \
         device moved to another node and its user traffic must now go somewhere else. Accept \
         to keep the session, refuse to end it.",
        json!({
            "type": "send_gtp_update_context_response",
            "cause": "request_accepted",
            "sequence": 2
        }),
    )
    .with_parameters(parameters)
    .with_actions(vec![
        SEND_GTP_UPDATE_CONTEXT_RESPONSE_ACTION.clone(),
        NO_RESPONSE_ACTION.clone(),
    ])
    .with_alternative_example(json!({
        "type": "send_gtp_update_context_response",
        "cause": "context_not_found",
        "sequence": 2
    }))
    .with_log_template(
        LogTemplate::new()
            .with_info("{source_address} update teid={teid}")
            .with_debug("GTP v{version} {message} teid={teid} seq={sequence}"),
    )
});

/// A peer wants a session torn down.
pub static GTP_DELETE_SESSION_REQUEST_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    let mut parameters = common_parameters();
    parameters.extend(vec![
        Parameter {
            name: "nsapi".to_string(),
            type_hint: "integer".to_string(),
            description: "Which bearer is being deleted.".to_string(),
            required: false,
        },
        Parameter {
            name: "teardown_indicator".to_string(),
            type_hint: "boolean".to_string(),
            description:
                "True when the peer is asking for EVERY context of this subscriber to go, not \
                 just the named bearer. GTPv1 only."
                    .to_string(),
            required: false,
        },
        Parameter {
            name: "information_elements".to_string(),
            type_hint: "array of objects".to_string(),
            description: "Every information element as {type, name, length}.".to_string(),
            required: false,
        },
    ]);

    EventType::new(
        "gtp_delete_session_request",
        "A peer is ending a subscriber's session. Confirm it with request_accepted, or say \
         context_not_found if this node has no record of it - which is a normal answer, not \
         an error.",
        json!({
            "type": "send_gtp_delete_session_response",
            "cause": "request_accepted",
            "sequence": 3
        }),
    )
    .with_parameters(parameters)
    .with_actions(vec![
        SEND_GTP_DELETE_SESSION_RESPONSE_ACTION.clone(),
        NO_RESPONSE_ACTION.clone(),
    ])
    .with_alternative_example(json!({
        "type": "send_gtp_delete_session_response",
        "cause": "context_not_found",
        "sequence": 3
    }))
    .with_log_template(
        LogTemplate::new()
            .with_info("{source_address} delete teid={teid}")
            .with_debug("GTP v{version} {message} teid={teid} seq={sequence}"),
    )
});

/// Subscriber traffic arrived through a tunnel.
pub static GTP_GPDU_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "gtp_gpdu_received",
        "A subscriber's own IP packet arrived inside a GTP-U tunnel. You are the node at the \
         end of that tunnel: forward something back down it, tell the peer the tunnel does \
         not exist, or absorb it silently.",
        json!({ "type": "no_response", "reason": "absorbing user-plane traffic" }),
    )
    .with_parameters(vec![
        Parameter {
            name: "teid".to_string(),
            type_hint: "integer".to_string(),
            description:
                "Tunnel endpoint identifier the packet arrived on - which session it claims \
                 to belong to. A TEID you never assigned is what send_gtp_error_indication is \
                 for."
                    .to_string(),
            required: true,
        },
        Parameter {
            name: "sequence".to_string(),
            type_hint: "integer".to_string(),
            description: "GTP-U sequence number, when the packet carried one. Most do not."
                .to_string(),
            required: false,
        },
        Parameter {
            name: "source_address".to_string(),
            type_hint: "string".to_string(),
            description: "Address and port of the peer that sent the tunnel packet - the base \
                          station or serving gateway, not the subscriber."
                .to_string(),
            required: true,
        },
        Parameter {
            name: "inner_ip".to_string(),
            type_hint: "object".to_string(),
            description: "The subscriber's own packet, decoded: {version, source, destination, \
                 protocol, protocol_name, ttl, length, source_port, destination_port}. \
                 'source' is the address this network assigned the device; 'destination' is \
                 where on the internet it is trying to go. Absent when the tunnel carried \
                 something that is not IP."
                .to_string(),
            required: false,
        },
        Parameter {
            name: "payload".to_string(),
            type_hint: "string".to_string(),
            description: "The transport payload of the inner packet, read according to \
                 'payload_encoding'. Absent when there was none or it could not be located."
                .to_string(),
            required: false,
        },
        Parameter {
            name: "payload_encoding".to_string(),
            type_hint: "\"utf8\" | \"hex\"".to_string(),
            description: "How to read 'payload': \"utf8\" means it is the octets as literal text, \
                 \"hex\" means hex-encoded octets (used whenever they are not all printable)."
                .to_string(),
            required: false,
        },
    ])
    .with_actions(vec![
        SEND_GTP_GPDU_ACTION.clone(),
        SEND_GTP_ERROR_INDICATION_ACTION.clone(),
        NO_RESPONSE_ACTION.clone(),
    ])
    .with_alternative_example(json!({
        "type": "send_gtp_error_indication",
        "teid": 305419896
    }))
    .with_log_template(
        LogTemplate::new()
            .with_info("{source_address} G-PDU teid={teid}")
            .with_debug("GTP G-PDU teid={teid} from {source_address}")
            .with_trace("GTP G-PDU: {json_pretty(.)}"),
    )
});

/// Every GTP event type. All five are emitted by `src/server/gtp/mod.rs`.
pub fn get_gtp_event_types() -> Vec<EventType> {
    vec![
        GTP_ECHO_REQUEST_EVENT.clone(),
        GTP_CREATE_SESSION_REQUEST_EVENT.clone(),
        GTP_UPDATE_CONTEXT_REQUEST_EVENT.clone(),
        GTP_DELETE_SESSION_REQUEST_EVENT.clone(),
        GTP_GPDU_RECEIVED_EVENT.clone(),
    ]
}

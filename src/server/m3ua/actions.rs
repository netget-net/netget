//! M3UA protocol actions, events and metadata (RFC 4666).
//!
//! Every `send_m3ua_*` action validates its parameters here and returns the fully encoded
//! message as [`ActionResult::Output`]. Unlike BGP, nothing about an M3UA message's encoding
//! depends on the session, so there is no intent indirection: the octets an action produces
//! are the octets that go on the wire, whether they came from the model, a static handler or
//! the dashboard's "message this peer".
//!
//! The session reads back what it wrote with [`super::codec::peek_class_type`], so the ASP
//! state machine follows the octets rather than a parallel bookkeeping that could drift from
//! them.

use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::EventType;
use crate::state::app_state::AppState;
use anyhow::{bail, Context, Result};
use serde_json::json;
use std::sync::LazyLock;

use super::codec;

/// M3UA protocol action handler.
pub struct M3uaProtocol {
    /// Set on the instance the dashboard's peer command task runs: an SS7 dialogue intent needs
    /// the association's transaction table, which only the session holds, so there it is refused
    /// by name instead of being reported as executed with nothing sent.
    peer_commands: bool,
}

impl Default for M3uaProtocol {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Parameter parsing helpers
// ============================================================================

/// Named error codes, in the order RFC 4666 section 3.8.1 lists them.
///
/// The model is offered names rather than raw integers because `0x0d` means nothing to it and
/// `refused_management_blocking` means exactly what it says. Integers are still accepted, but
/// only the codes the RFC defines — an undefined code on the wire is a bug a peer cannot
/// interpret, so it is rejected here as a failed action naming the allowed set.
const ERROR_CODES: &[(&str, u32)] = &[
    ("invalid_version", codec::ERR_INVALID_VERSION),
    (
        "unsupported_message_class",
        codec::ERR_UNSUPPORTED_MESSAGE_CLASS,
    ),
    (
        "unsupported_message_type",
        codec::ERR_UNSUPPORTED_MESSAGE_TYPE,
    ),
    (
        "unsupported_traffic_mode",
        codec::ERR_UNSUPPORTED_TRAFFIC_MODE,
    ),
    ("unexpected_message", codec::ERR_UNEXPECTED_MESSAGE),
    ("protocol_error", codec::ERR_PROTOCOL_ERROR),
    (
        "invalid_stream_identifier",
        codec::ERR_INVALID_STREAM_IDENTIFIER,
    ),
    (
        "refused_management_blocking",
        codec::ERR_REFUSED_MANAGEMENT_BLOCKING,
    ),
    (
        "asp_identifier_required",
        codec::ERR_ASP_IDENTIFIER_REQUIRED,
    ),
    ("invalid_asp_identifier", codec::ERR_INVALID_ASP_IDENTIFIER),
    (
        "invalid_parameter_value",
        codec::ERR_INVALID_PARAMETER_VALUE,
    ),
    ("parameter_field_error", codec::ERR_PARAMETER_FIELD_ERROR),
    ("unexpected_parameter", codec::ERR_UNEXPECTED_PARAMETER),
    (
        "destination_status_unknown",
        codec::ERR_DESTINATION_STATUS_UNKNOWN,
    ),
    (
        "invalid_network_appearance",
        codec::ERR_INVALID_NETWORK_APPEARANCE,
    ),
    ("missing_parameter", codec::ERR_MISSING_PARAMETER),
    (
        "invalid_routing_context",
        codec::ERR_INVALID_ROUTING_CONTEXT,
    ),
    (
        "no_configured_as_for_asp",
        codec::ERR_NO_CONFIGURED_AS_FOR_ASP,
    ),
];

const TRAFFIC_MODES: &[(&str, u32)] = &[
    ("override", codec::TRAFFIC_MODE_OVERRIDE),
    ("loadshare", codec::TRAFFIC_MODE_LOADSHARE),
    ("broadcast", codec::TRAFFIC_MODE_BROADCAST),
];

const STATUS_TYPES: &[(&str, u16)] = &[
    ("as_state_change", codec::STATUS_TYPE_AS_STATE_CHANGE),
    ("other", codec::STATUS_TYPE_OTHER),
];

const AS_STATE_INFOS: &[(&str, u16)] = &[
    ("as_inactive", codec::STATUS_AS_INACTIVE),
    ("as_active", codec::STATUS_AS_ACTIVE),
    ("as_pending", codec::STATUS_AS_PENDING),
];

const OTHER_STATUS_INFOS: &[(&str, u16)] = &[
    (
        "insufficient_asp_resources",
        codec::STATUS_INSUFFICIENT_ASP_RESOURCES,
    ),
    ("alternate_asp_active", codec::STATUS_ALTERNATE_ASP_ACTIVE),
    ("asp_failure", codec::STATUS_ASP_FAILURE),
];

fn names(table: &[(&'static str, u32)]) -> String {
    table.iter().map(|(n, _)| *n).collect::<Vec<_>>().join(", ")
}

fn names16(table: &[(&'static str, u16)]) -> String {
    table.iter().map(|(n, _)| *n).collect::<Vec<_>>().join(", ")
}

/// Resolve a field that may be spelled as a name or as its numeric value.
fn lookup_u32(
    action: &serde_json::Value,
    field: &str,
    table: &[(&'static str, u32)],
) -> Result<Option<u32>> {
    match action.get(field) {
        None => Ok(None),
        Some(v) if v.is_null() => Ok(None),
        Some(v) if v.is_string() => {
            let s = v.as_str().unwrap_or_default().to_ascii_lowercase();
            table
                .iter()
                .find(|(n, _)| *n == s)
                .map(|(_, code)| Some(*code))
                .with_context(|| format!("{field} {s:?} is not one of: {}", names(table)))
        }
        Some(v) => {
            let n = v
                .as_u64()
                .with_context(|| format!("{field} must be a name or a number"))?;
            let n = u32::try_from(n).with_context(|| format!("{field} value {n} is too large"))?;
            if table.iter().any(|(_, code)| *code == n) {
                Ok(Some(n))
            } else {
                bail!(
                    "{field} {n} is not a value RFC 4666 defines; use one of: {}",
                    names(table)
                )
            }
        }
    }
}

fn lookup_u16(
    action: &serde_json::Value,
    field: &str,
    table: &[(&'static str, u16)],
) -> Result<Option<u16>> {
    let widened: Vec<(&'static str, u32)> = table.iter().map(|(n, v)| (*n, *v as u32)).collect();
    Ok(lookup_u32(action, field, &widened)?.map(|v| v as u16))
}

/// An unsigned field that must fit in `max`.
fn bounded_u32(action: &serde_json::Value, field: &str, max: u32, required: bool) -> Result<u32> {
    match action.get(field) {
        None if required => bail!("{field} is required"),
        Some(v) if v.is_null() && required => bail!("{field} is required"),
        None => Ok(0),
        Some(v) if v.is_null() => Ok(0),
        Some(v) => {
            let n = v
                .as_u64()
                .with_context(|| format!("{field} must be a non-negative number"))?;
            if n > max as u64 {
                bail!("{field} value {n} exceeds the maximum {max}");
            }
            Ok(n as u32)
        }
    }
}

fn optional_u32(action: &serde_json::Value, field: &str) -> Result<Option<u32>> {
    match action.get(field) {
        None => Ok(None),
        Some(v) if v.is_null() => Ok(None),
        Some(v) => {
            let n = v
                .as_u64()
                .with_context(|| format!("{field} must be a non-negative number"))?;
            Ok(Some(u32::try_from(n).with_context(|| {
                format!("{field} value {n} does not fit in 32 bits")
            })?))
        }
    }
}

fn optional_string(action: &serde_json::Value, field: &str) -> Result<Option<String>> {
    match action.get(field) {
        None => Ok(None),
        Some(v) if v.is_null() => Ok(None),
        Some(v) => Ok(Some(
            v.as_str()
                .with_context(|| format!("{field} must be a string"))?
                .to_string(),
        )),
    }
}

/// Decode the one legitimately opaque field in this protocol.
///
/// The SS7 user part (an ISUP IAM, an SCCP UDT) is binary that no model can be asked to render
/// as text, so `payload` carries an explicit `encoding`. It is **declared, never sniffed**:
/// `"48656c6c6f"` is simultaneously valid text and valid hex and only the sender knows which it
/// meant. This is the TCP `send_tcp_data` lesson — documenting hex and then calling
/// `as_bytes()` puts literal ASCII on the wire.
pub fn decode_payload(action: &serde_json::Value) -> Result<Vec<u8>> {
    let payload = action
        .get("payload")
        .and_then(|v| v.as_str())
        .context("send_m3ua_data requires payload (a string)")?;
    let encoding = action
        .get("encoding")
        .and_then(|v| v.as_str())
        .unwrap_or("utf8")
        .to_ascii_lowercase();
    let bytes = match encoding.as_str() {
        "utf8" | "utf-8" | "text" | "ascii" => payload.as_bytes().to_vec(),
        "hex" => hex::decode(payload)
            .with_context(|| format!("payload {payload:?} is declared hex but is not valid hex"))?,
        other => bail!("encoding must be \"utf8\" or \"hex\", got {other:?}"),
    };

    // Bounded on the encode side too, not just on decode. `Parameter::write_into` writes the
    // Parameter Length as a `u16`, so a user part this size or larger wrapped the field and
    // produced a message no SS7 peer could parse — and nothing anywhere would have said so.
    if bytes.len() > codec::MAX_USER_DATA_LEN {
        bail!(
            "payload is {} octets, over the {}-octet limit. M3UA's Parameter Length field is \
             16 bits and has to cover the Protocol Data header as well, so a larger user part \
             cannot be framed at all. For scale, a real SS7 MSU carries at most 272 octets of \
             user part — a payload this size almost certainly means the field has been \
             misunderstood.",
            bytes.len(),
            codec::MAX_USER_DATA_LEN
        );
    }

    Ok(bytes)
}

impl M3uaProtocol {
    pub fn new() -> Self {
        Self {
            peer_commands: false,
        }
    }

    /// The instance for the dashboard's "message this peer" (see `peer_commands`).
    pub fn for_peer_commands() -> Self {
        Self {
            peer_commands: true,
        }
    }

    fn execute_send_asp_up_ack(&self, action: serde_json::Value) -> Result<ActionResult> {
        let info = optional_string(&action, "info_string")?;
        Ok(ActionResult::Output(codec::aspup_ack(info.as_deref())?))
    }

    fn execute_send_asp_active_ack(&self, action: serde_json::Value) -> Result<ActionResult> {
        let traffic_mode = lookup_u32(&action, "traffic_mode", TRAFFIC_MODES)?;
        let routing_context = optional_u32(&action, "routing_context")?;
        let info = optional_string(&action, "info_string")?;
        Ok(ActionResult::Output(codec::aspac_ack(
            traffic_mode,
            routing_context,
            info.as_deref(),
        )?))
    }

    fn execute_send_data(&self, action: serde_json::Value) -> Result<ActionResult> {
        // Point codes occupy a 32-bit field but carry at most a 24-bit ANSI code; ITU codes are
        // 14 bits. Rejecting above 24 bits catches an ASN-sized number pasted into the wrong
        // field rather than silently routing an MSU to a destination that cannot exist.
        const MAX_POINT_CODE: u32 = 0x00FF_FFFF;
        let opc = bounded_u32(&action, "opc", MAX_POINT_CODE, true)?;
        let dpc = bounded_u32(&action, "dpc", MAX_POINT_CODE, true)?;
        let si = bounded_u32(&action, "si", 0xFF, true)? as u8;
        let ni = bounded_u32(&action, "ni", 0x03, false)? as u8;
        let mp = bounded_u32(&action, "mp", 0x0F, false)? as u8;
        let sls = bounded_u32(&action, "sls", 0xFF, false)? as u8;
        let payload = decode_payload(&action)?;

        let protocol_data = codec::ProtocolData {
            opc,
            dpc,
            si,
            ni,
            mp,
            sls,
            payload,
        };
        Ok(ActionResult::Output(codec::data(
            &protocol_data,
            optional_u32(&action, "network_appearance")?,
            optional_u32(&action, "routing_context")?,
            optional_u32(&action, "correlation_id")?,
        )?))
    }

    fn execute_send_error(&self, action: serde_json::Value) -> Result<ActionResult> {
        let code = lookup_u32(&action, "error_code", ERROR_CODES)?
            .context("send_m3ua_error requires error_code")?;
        Ok(ActionResult::Output(codec::error(
            code,
            optional_u32(&action, "routing_context")?,
        )?))
    }

    fn execute_send_notify(&self, action: serde_json::Value) -> Result<ActionResult> {
        let status_type = lookup_u16(&action, "status_type", STATUS_TYPES)?
            .context("send_m3ua_notify requires status_type")?;

        // The Status Information values are only meaningful under their own Status Type, so
        // they are validated against the type rather than against one flat list. A NTFY
        // carrying type 1 / info 3 ("AS-ACTIVE") and one carrying type 2 / info 3
        // ("ASP Failure") differ only here.
        let table: &[(&'static str, u16)] = if status_type == codec::STATUS_TYPE_AS_STATE_CHANGE {
            AS_STATE_INFOS
        } else {
            OTHER_STATUS_INFOS
        };
        let status_info = lookup_u16(&action, "status_info", table)?.with_context(|| {
            format!(
                "send_m3ua_notify requires status_info, one of: {}",
                names16(table)
            )
        })?;

        let info = optional_string(&action, "info_string")?;
        Ok(ActionResult::Output(codec::notify(
            status_type,
            status_info,
            optional_u32(&action, "asp_identifier")?,
            optional_u32(&action, "routing_context")?,
            info.as_deref(),
        )?))
    }
}

// ============================================================================
// Action definitions (shared between get_sync_actions() and every event type)
// ============================================================================

fn send_asp_up_ack_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_m3ua_asp_up_ack".to_string(),
        description: "Admit this ASP: acknowledge its ASPUP and move it to ASP-INACTIVE. This \
                      is the admission decision — returning it lets a signalling peer into the \
                      network, so return send_m3ua_error instead to refuse."
            .to_string(),
        parameters: vec![Parameter {
            name: "info_string".to_string(),
            type_hint: "string".to_string(),
            description: "Optional free text for the peer's log (INFO String parameter)."
                .to_string(),
            required: false,
        }],
        example: json!({ "type": "send_m3ua_asp_up_ack" }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> M3UA ASPUP ACK")
                .with_debug("M3UA send_m3ua_asp_up_ack info={info_string}"),
        ),
    }
}

fn send_asp_active_ack_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_m3ua_asp_active_ack".to_string(),
        description: "Activate this ASP: acknowledge its ASPAC and move it to ASP-ACTIVE, after \
                      which DATA may flow in both directions. Return send_m3ua_error to refuse."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "traffic_mode".to_string(),
                type_hint: "string".to_string(),
                description: "Traffic Mode Type granted: override, loadshare or broadcast. \
                              Omit to leave it unstated."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "routing_context".to_string(),
                type_hint: "number".to_string(),
                description: "Routing Context being activated. Echo the one the ASPAC carried."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "info_string".to_string(),
                type_hint: "string".to_string(),
                description: "Optional free text for the peer's log.".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_m3ua_asp_active_ack",
            "traffic_mode": "loadshare"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> M3UA ASPAC ACK mode={traffic_mode}")
                .with_debug("M3UA send_m3ua_asp_active_ack rc={routing_context}"),
        ),
    }
}

fn send_data_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_m3ua_data".to_string(),
        description: "Send an SS7 MSU to the ASP as an M3UA DATA message. The routing label is \
                      structured (opc, dpc, si, ni, mp, sls) and only the user part payload is \
                      opaque."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "opc".to_string(),
                type_hint: "number".to_string(),
                description: "Originating Point Code, 0-16777215. For a reply this is usually \
                              the dpc of the message being answered."
                    .to_string(),
                required: true,
            },
            Parameter {
                name: "dpc".to_string(),
                type_hint: "number".to_string(),
                description: "Destination Point Code, 0-16777215.".to_string(),
                required: true,
            },
            Parameter {
                name: "si".to_string(),
                type_hint: "number".to_string(),
                description: "Service Indicator: 3 SCCP, 4 TUP, 5 ISUP, 9 B-ISUP, 0 SNM."
                    .to_string(),
                required: true,
            },
            Parameter {
                name: "ni".to_string(),
                type_hint: "number".to_string(),
                description: "Network Indicator, 0-3: 0 international, 2 national.".to_string(),
                required: false,
            },
            Parameter {
                name: "mp".to_string(),
                type_hint: "number".to_string(),
                description: "Message Priority, 0-3 (0 unless the national network uses it)."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "sls".to_string(),
                type_hint: "number".to_string(),
                description: "Signalling Link Selection. Echo the request's sls to keep a \
                              transaction on one link."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "payload".to_string(),
                type_hint: "string".to_string(),
                description: "The user part message (an ISUP or SCCP MSU body), as text or as \
                              a hex string. Which one is decided by `encoding`, never guessed."
                    .to_string(),
                required: true,
            },
            Parameter {
                name: "encoding".to_string(),
                type_hint: "string".to_string(),
                description: "How to read `payload`: \"hex\" for real SS7 binary (the usual \
                              case), \"utf8\" for text. Defaults to \"utf8\"."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "routing_context".to_string(),
                type_hint: "number".to_string(),
                description: "Routing Context this MSU belongs to.".to_string(),
                required: false,
            },
            Parameter {
                name: "network_appearance".to_string(),
                type_hint: "number".to_string(),
                description: "Network Appearance, when the SGP fronts more than one network."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "correlation_id".to_string(),
                type_hint: "number".to_string(),
                description: "Correlation Id, for an ASP that correlates a reply to a request."
                    .to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_m3ua_data",
            "opc": 2002,
            "dpc": 1001,
            "si": 3,
            "ni": 2,
            "mp": 0,
            "sls": 5,
            "payload": "09810300",
            "encoding": "hex",
            "routing_context": 100
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> M3UA DATA opc={opc} dpc={dpc} si={si}")
                .with_debug("M3UA send_m3ua_data opc={opc} dpc={dpc} si={si} sls={sls}"),
        ),
    }
}

fn send_error_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_m3ua_error".to_string(),
        description: "Refuse: answer with an M3UA ERR carrying an error code. On an ASPUP or \
                      ASPAC event this is the explicit refusal to admit or activate the ASP, \
                      and it is the only thing that counts as one."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "error_code".to_string(),
                type_hint: "string".to_string(),
                description: "RFC 4666 error code, by name: refused_management_blocking, \
                              unexpected_message, protocol_error, invalid_routing_context, \
                              no_configured_as_for_asp, invalid_network_appearance, \
                              unsupported_traffic_mode, missing_parameter, \
                              parameter_field_error, invalid_parameter_value, \
                              invalid_asp_identifier, asp_identifier_required, \
                              destination_status_unknown, unexpected_parameter, \
                              unsupported_message_class, unsupported_message_type, \
                              invalid_stream_identifier, invalid_version. \
                              Use refused_management_blocking to deny an ASP by policy."
                    .to_string(),
                required: true,
            },
            Parameter {
                name: "routing_context".to_string(),
                type_hint: "number".to_string(),
                description: "Routing Context the error concerns, when it concerns one."
                    .to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_m3ua_error",
            "error_code": "refused_management_blocking"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> M3UA ERR {error_code}")
                .with_debug("M3UA send_m3ua_error code={error_code} rc={routing_context}"),
        ),
    }
}

fn send_notify_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_m3ua_notify".to_string(),
        description: "Tell the ASP about an Application Server state change or an AS-level \
                      condition with an M3UA NTFY. Informational: it changes nothing here."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "status_type".to_string(),
                type_hint: "string".to_string(),
                description: "as_state_change (an AS changed state) or other (an ASP-level \
                              condition)."
                    .to_string(),
                required: true,
            },
            Parameter {
                name: "status_info".to_string(),
                type_hint: "string".to_string(),
                description: "With as_state_change: as_inactive, as_active or as_pending. \
                              With other: insufficient_asp_resources, alternate_asp_active or \
                              asp_failure."
                    .to_string(),
                required: true,
            },
            Parameter {
                name: "asp_identifier".to_string(),
                type_hint: "number".to_string(),
                description: "ASP Identifier the notification concerns.".to_string(),
                required: false,
            },
            Parameter {
                name: "routing_context".to_string(),
                type_hint: "number".to_string(),
                description: "Routing Context the notification concerns.".to_string(),
                required: false,
            },
            Parameter {
                name: "info_string".to_string(),
                type_hint: "string".to_string(),
                description: "Optional free text for the peer's log.".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_m3ua_notify",
            "status_type": "as_state_change",
            "status_info": "as_active"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> M3UA NTFY {status_type}/{status_info}")
                .with_debug("M3UA send_m3ua_notify {status_type}/{status_info}"),
        ),
    }
}

fn wait_for_more_action() -> ActionDefinition {
    ActionDefinition {
        name: "wait_for_more".to_string(),
        description: "Send nothing and wait for the next M3UA message. On an ASPUP or ASPAC \
                      event this is NOT an admission: saying nothing leaves the ASP where it \
                      was and NetGet answers with ERR."
            .to_string(),
        parameters: vec![],
        example: json!({ "type": "wait_for_more" }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> M3UA wait for more")
                .with_debug("M3UA wait_for_more: awaiting the next message"),
        ),
    }
}

/// Actions any M3UA event may be answered with.
///
/// `call_llm` builds the model's tool list from `EventType::actions`, so every event carries
/// this list — an event that declared none would leave the model unable to answer at all.
fn m3ua_response_actions() -> Vec<ActionDefinition> {
    vec![
        send_asp_up_ack_action(),
        send_asp_active_ack_action(),
        send_data_action(),
        send_error_action(),
        send_notify_action(),
        wait_for_more_action(),
    ]
}

// ============================================================================
// Event types
// ============================================================================

pub static M3UA_ASP_UP_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "m3ua_asp_up_received",
        "An ASP sent ASPUP and wants to be admitted to this signalling gateway. Reply with \
         send_m3ua_asp_up_ack to admit it, or send_m3ua_error to refuse. Anything else — \
         including wait_for_more and no answer at all — leaves the ASP DOWN and NetGet answers \
         with ERR: admitting a signalling peer is never the default.",
        json!({ "type": "send_m3ua_asp_up_ack" }),
    )
    .with_alternative_example(json!({
        "type": "send_m3ua_error",
        "error_code": "refused_management_blocking"
    }))
    .with_actions(m3ua_response_actions())
    .with_log_template(
        LogTemplate::new()
            .with_info("M3UA ASPUP from {remote_addr} asp_id={asp_identifier}")
            .with_debug("M3UA ASPUP on {connection_id} asp_id={asp_identifier} info={info_string}")
            .with_trace("M3UA ASPUP: {json_pretty(.)}"),
    )
});

pub static M3UA_ASP_ACTIVE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "m3ua_asp_active_received",
        "An admitted ASP sent ASPAC and wants to carry traffic for a routing context. Reply \
         with send_m3ua_asp_active_ack to activate it, or send_m3ua_error to refuse. Saying \
         nothing leaves it INACTIVE and NetGet answers with ERR.",
        json!({
            "type": "send_m3ua_asp_active_ack",
            "traffic_mode": "loadshare"
        }),
    )
    .with_alternative_example(json!({
        "type": "send_m3ua_error",
        "error_code": "unsupported_traffic_mode"
    }))
    .with_actions(m3ua_response_actions())
    .with_log_template(
        LogTemplate::new()
            .with_info("M3UA ASPAC from {remote_addr} rc={routing_context}")
            .with_debug("M3UA ASPAC on {connection_id} rc={routing_context} mode={traffic_mode}")
            .with_trace("M3UA ASPAC: {json_pretty(.)}"),
    )
});

pub static M3UA_DATA_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "m3ua_data_received",
        "An active ASP sent an SS7 MSU. The routing label is decoded into opc, dpc, si, ni, mp \
         and sls; the user part is in payload, read according to encoding. Reply with \
         send_m3ua_data to answer the far end, or wait_for_more to send nothing.",
        json!({
            "type": "send_m3ua_data",
            "opc": 2002,
            "dpc": 1001,
            "si": 3,
            "ni": 2,
            "sls": 5,
            "payload": "09810300",
            "encoding": "hex"
        }),
    )
    .with_alternative_example(json!({ "type": "wait_for_more" }))
    .with_actions(m3ua_response_actions())
    .with_log_template(
        LogTemplate::new()
            .with_info("M3UA DATA opc={opc} dpc={dpc} si={si} ({si_name})")
            .with_debug("M3UA DATA on {connection_id} opc={opc} dpc={dpc} si={si} sls={sls}")
            .with_trace("M3UA DATA: {json_pretty(.)}"),
    )
});

pub static M3UA_ASP_DOWN_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "m3ua_asp_down_received",
        "An ASP sent ASPDN and is leaving service. NetGet has already acknowledged it and the \
         ASP is DOWN — taking a peer out of service needs no permission. This event is for \
         whatever should follow: send_m3ua_notify to tell it about the AS, or wait_for_more.",
        json!({ "type": "wait_for_more" }),
    )
    .with_alternative_example(json!({
        "type": "send_m3ua_notify",
        "status_type": "as_state_change",
        "status_info": "as_inactive"
    }))
    .with_actions(m3ua_response_actions())
    .with_log_template(
        LogTemplate::new()
            .with_info("M3UA ASPDN from {remote_addr}")
            .with_debug("M3UA ASPDN on {connection_id}, ASP returned to DOWN")
            .with_trace("M3UA ASPDN: {json_pretty(.)}"),
    )
});

pub static M3UA_ERROR_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "m3ua_error_received",
        "The ASP sent an M3UA ERR, reporting that something NetGet sent was unacceptable. \
         Observational: the error_code and error_name say what it objected to. Reply with \
         wait_for_more unless there is something to send in response.",
        json!({ "type": "wait_for_more" }),
    )
    .with_actions(m3ua_response_actions())
    .with_log_template(
        LogTemplate::new()
            .with_info("M3UA ERR from {remote_addr}: {error_name}")
            .with_debug("M3UA ERR on {connection_id} code={error_code} ({error_name})")
            .with_trace("M3UA ERR: {json_pretty(.)}"),
    )
});

// ============================================================================
// Protocol / Server traits
// ============================================================================

impl Protocol for M3uaProtocol {
    /// No user-triggered actions.
    ///
    /// Every M3UA verb is addressed to one association, and an async action carries no
    /// connection. The dashboard's "message this peer" reaches a live ASP through the peer
    /// command channel, which runs exactly the sync actions below.
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![]
    }

    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        let mut actions = m3ua_response_actions();
        actions.extend(super::ss7_actions::all_actions(
            super::ss7_actions::Role::Sgp,
        ));
        actions
    }

    fn protocol_name(&self) -> &'static str {
        "M3UA"
    }

    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            M3UA_ASP_UP_EVENT.clone(),
            M3UA_ASP_ACTIVE_EVENT.clone(),
            M3UA_DATA_EVENT.clone(),
            M3UA_ASP_DOWN_EVENT.clone(),
            M3UA_ERROR_EVENT.clone(),
            super::ss7_actions::SGP_MAP_EVENT.clone(),
            super::ss7_actions::SGP_CAP_EVENT.clone(),
        ]
    }

    fn stack_name(&self) -> &'static str {
        "ETH>IP>SCTP>M3UA"
    }

    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "m3ua", "sigtran", "ss7", "mtp3", "sgp", "asp", "sccp", "tcap", "map", "gsm map",
            "camel", "cap", "hlr", "ussd",
        ]
    }

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{
            DevelopmentState, PrivilegeRequirement, ProtocolMetadataV2,
        };

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            // M3UA's registered port is 2905, above 1023, so no privilege is required. SCTP
            // itself needs none either — it is a kernel protocol like TCP, not a raw socket.
            .privilege_requirement(PrivilegeRequirement::None)
            .well_known_sctp_port(2905)
            .implementation(
                "RFC 4666 common header, TLV parameters and ASP state machine, hand-written; \
                 SCTP transport via a socket2 SOCK_STREAM/IPPROTO_SCTP socket with sendmsg \
                 (PPID 3, management on stream 0, DATA on stream 1), plus a non-standard TCP \
                 transport for lab use. Above it, for service indicator 3: SCCP UDT/XUDT with \
                 point code, SSN and global title addressing, ITU TCAP (dialogue portion and \
                 components) over a hand-rolled bounded BER codec, and MAP and CAMEL operation \
                 mappings (src/server/m3ua/{sccp,tcap,ber,map,cap,ss7}.rs)",
            )
            .llm_control(
                "The model is the admission policy (may an ASP come up, go active) and the SS7 \
                 node behind the SGP: it answers decoded MAP invokes (sendRoutingInfoForSM, \
                 anyTimeInterrogation, processUnstructuredSS-Request, mo/mt-forwardSM, \
                 sendRoutingInfo, updateLocation) with structured results or MAP errors, and \
                 CAMEL initialDP / eventReportBCSM with connect, continue, releaseCall and \
                 requestReportBCSMEvent. Rust owns transaction and invoke ids, AARE, SCCP and \
                 MTP addressing; BEAT, ASPDN/ASPIA ACK, SCCP SST, CAP activityTest, every \
                 protocol-validity refusal (P-Abort, Reject, AARE reject) are answered with no \
                 LLM call",
            )
            .e2e_testing(
                "Restcomm jSS7 8.0.112 (an independent Java SS7 stack) over real SCTP on Linux \
                 drives MAP and CAMEL dialogues against the SGP and decodes the model's answers \
                 (tests/server/m3ua/real_peer_test.rs), also with osmo-stp (libosmo-sigtran, C) \
                 routing between them as an ASP of NetGet's SGP (osmo_stp_test.rs); a live \
                 capture is read by tshark's m3ua/sccp/tcap/gsm_map/camel dissectors. The codec \
                 suite requires NetGet's MAP answers to equal jSS7's own answers octet for octet \
                 for the same requests; RFC 4666 literal vectors for M3UA; mocked-model E2E over \
                 the lab transport",
            )
            .notes(
                "EXPERIMENTAL. Two independent peers exercise it over real SCTP (jSS7 for M3UA, \
                 SCCP, TCAP, MAP and CAP; osmo-stp for M3UA and MTP routing), but only on Linux \
                 and only in the protocol-pairs m3ua job, which has not yet run in CI, and the \
                 code has had no human review - so the Beta bar is not met yet. macOS has no \
                 SCTP: requesting the default transport there makes spawn() return an Err naming \
                 SCTP; transport=\"tcp\" is a NON-STANDARD lab framing. MAP and CAP are a \
                 subset (no sendAuthenticationInfo, insertSubscriberData, MAP v1 origination, \
                 CAP charging or SRF operations); SCCP segmentation, LUDT and the \
                 connection-oriented classes are refused, not implemented; there is no global \
                 title translation. Routing key management (RKM) is decoded and refused because \
                 a routing key table is storage. No MTP3 network management (SSNM) is generated.",
            )
            .max_inbound_bytes(crate::server::m3ua::codec::MAX_MESSAGE_LEN)
            .build()
    }

    fn description(&self) -> &'static str {
        "M3UA/SIGTRAN signalling gateway with SCCP, TCAP, MAP and CAMEL (SS7 over IP)"
    }

    fn example_prompt(&self) -> &'static str {
        "Start an M3UA signalling gateway on port 2905"
    }

    fn get_startup_parameters(&self) -> Vec<crate::llm::actions::ParameterDefinition> {
        use crate::llm::actions::ParameterDefinition;
        vec![
            ParameterDefinition {
                name: "transport".to_string(),
                type_hint: "string".to_string(),
                description: "\"sctp\" (default, the only transport RFC 4666 defines) or \
                              \"tcp\". TCP IS NON-STANDARD and exists for local protocol work \
                              only: no real SIGTRAN peer speaks M3UA over TCP, and a host with \
                              no SCTP stack (macOS has none) refuses to start with \"sctp\" \
                              rather than silently falling back."
                    .to_string(),
                required: false,
                example: json!("sctp"),
                default: None,
            },
            ParameterDefinition {
                name: "routing_context".to_string(),
                type_hint: "integer".to_string(),
                description: "If set, DATA and ASPAC carrying a different Routing Context are \
                              refused with ERR Invalid Routing Context before the model is \
                              consulted. Omit to accept any."
                    .to_string(),
                required: false,
                example: json!(100),
                default: None,
            },
            ParameterDefinition {
                name: "network_appearance".to_string(),
                type_hint: "integer".to_string(),
                description: "If set, DATA carrying a different Network Appearance is refused \
                              with ERR Invalid Network Appearance before the model is consulted. \
                              Omit to accept any."
                    .to_string(),
                required: false,
                example: json!(1),
                default: None,
            },
        ]
    }

    fn group_name(&self) -> &'static str {
        "Network"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;

        // Deterministic: admit and activate every ASP, echo nothing. No LLM call at all.
        let script = r#"import json, sys
data = json.load(sys.stdin)
event_id = data["event_type_id"]
if event_id == "m3ua_asp_up_received":
    actions = [{"type": "send_m3ua_asp_up_ack"}]
elif event_id == "m3ua_asp_active_received":
    actions = [{"type": "send_m3ua_asp_active_ack", "traffic_mode": "loadshare"}]
else:
    actions = []
print(json.dumps({"actions": actions}))"#;

        StartupExamples::new(
            // LLM mode: the model is the admission policy.
            json!({
                "type": "open_server",
                "port": 2905,
                "base_stack": "m3ua",
                "instruction": "Act as an SGP. Admit ASPs and activate routing context 100, \
                                and answer SCCP queries from point code 1001.",
                "startup_params": { "transport": "sctp", "routing_context": 100 }
            }),
            // Script mode.
            json!({
                "type": "open_server",
                "port": 2905,
                "base_stack": "m3ua",
                "startup_params": { "transport": "sctp" },
                "event_handlers": [{
                    // Patterns are an exact event id or "*" — there is no prefix glob, and
                    // "m3ua_*" would match nothing.
                    "event_pattern": "*",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": script
                    }
                }]
            }),
            // Static mode: admit and activate, nothing else.
            json!({
                "type": "open_server",
                "port": 2905,
                "base_stack": "m3ua",
                "startup_params": { "transport": "sctp" },
                "event_handlers": [
                    {
                        "event_pattern": "m3ua_asp_up_received",
                        "handler": {
                            "type": "static",
                            "actions": [{ "type": "send_m3ua_asp_up_ack" }]
                        }
                    },
                    {
                        "event_pattern": "m3ua_asp_active_received",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "send_m3ua_asp_active_ack",
                                "traffic_mode": "loadshare"
                            }]
                        }
                    }
                ]
            }),
        )
    }
}

impl Server for M3uaProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::server::m3ua::M3uaServer;
            M3uaServer::spawn_with_llm_actions(
                ctx.legacy_listen_addr(),
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.server_id,
                ctx.startup_params,
            )
            .await
        })
    }

    fn execute_action(&self, action: serde_json::Value) -> Result<ActionResult> {
        let action_type = action
            .get("type")
            .and_then(|v| v.as_str())
            .context("Missing action type")?;

        match action_type {
            "send_m3ua_asp_up_ack" => self.execute_send_asp_up_ack(action),
            "send_m3ua_asp_active_ack" => self.execute_send_asp_active_ack(action),
            "send_m3ua_data" => self.execute_send_data(action),
            "send_m3ua_error" => self.execute_send_error(action),
            "send_m3ua_notify" => self.execute_send_notify(action),
            name if super::ss7::INTENTS.contains(&name) => {
                if self.peer_commands {
                    anyhow::bail!(
                        "{name} answers a TCAP dialogue, which only the association's own \
                         handler can address; from the dashboard send M3UA messages \
                         (send_m3ua_data, send_m3ua_notify, send_m3ua_error)"
                    );
                }
                super::ss7::check_intent(&action).map_err(|e| anyhow::anyhow!(e))?;
                Ok(ActionResult::Custom {
                    name: super::ss7::SS7_INTENT.to_string(),
                    data: action,
                })
            }
            "wait_for_more" => Ok(ActionResult::WaitForMore),
            // Not offered to the model — refusing an ASP is send_m3ua_error, which keeps the
            // association up so the peer can retry. The dashboard's "disconnect this peer"
            // injects this to close the association itself.
            "close_connection" => Ok(ActionResult::CloseConnection),
            _ => Err(anyhow::anyhow!("Unknown M3UA action type: {}", action_type)),
        }
    }
}

//! NGAP AMF actions, events and metadata.
//!
//! Every `send_*` action validates its fields against the 38.413 constraints and returns the
//! fully encoded PDU as [`ActionResult::Output`]; the session reads the procedure and UE id back
//! off those octets to apply the fail-closed rule. Nothing about the encoding depends on session
//! state, so the same octets come out whether the model, a static handler or the dashboard's
//! "message this peer" asked for them.

use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::EventType;
use crate::state::app_state::AppState;
use anyhow::{anyhow, Context, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

use super::codec::{self, Cause};
use super::nas;
use super::sm;

pub struct NgapProtocol;

impl Default for NgapProtocol {
    fn default() -> Self {
        Self::new()
    }
}

impl NgapProtocol {
    pub fn new() -> Self {
        Self
    }
}

fn p(name: &str, type_hint: &str, description: &str, required: bool) -> Parameter {
    Parameter {
        name: name.to_string(),
        type_hint: type_hint.to_string(),
        description: description.to_string(),
        required,
    }
}

fn list<'a>(action: &'a Value, field: &str) -> Result<&'a Vec<Value>> {
    action
        .get(field)
        .and_then(Value::as_array)
        .with_context(|| format!("{field} must be a list"))
}

fn cause_field(action: &Value, field: &str, default: Option<&str>) -> Result<Cause> {
    match action.get(field) {
        Some(v) if !v.is_null() => Ok(Cause::from_json(v)?),
        _ => match default {
            Some(d) => Ok(Cause::from_json(&json!(d))?),
            None => Err(anyhow!(
                "{field} is required, e.g. \"misc/unknown-PLMN-or-SNPN\""
            )),
        },
    }
}

/// Encode the `nas` object of a downlink action into a NAS-PDU.
pub fn downlink_nas(action: &Value) -> Result<Vec<u8>> {
    let v = action.get("nas").context(
        "nas is required: {\"message\": \"registration_reject\", \"cause\": \"illegal_ue\"}",
    )?;
    nas::encode(v, nas::DOWNLINK_MESSAGES).map_err(|e| anyhow!(e))
}

impl NgapProtocol {
    fn ng_setup_response(&self, a: &Value) -> Result<ActionResult> {
        let name = a
            .get("amf_name")
            .and_then(Value::as_str)
            .context("amf_name is required")?;
        let capacity = codec::json_opt_u64(a, "relative_amf_capacity", 255)?.unwrap_or(255);
        Ok(ActionResult::Output(codec::ng_setup_response(
            name,
            list(a, "served_guami")?,
            capacity,
            list(a, "plmn_support")?,
        )?))
    }

    fn ng_setup_failure(&self, a: &Value) -> Result<ActionResult> {
        let cause = cause_field(a, "cause", None)?;
        let ttw = a.get("time_to_wait").and_then(|v| match v {
            Value::String(s) => Some(s.clone()),
            Value::Number(n) => Some(n.to_string()),
            _ => None,
        });
        Ok(ActionResult::Output(codec::ng_setup_failure(
            &cause,
            ttw.as_deref(),
        )?))
    }

    fn downlink_nas_transport(&self, a: &Value) -> Result<ActionResult> {
        let amf = codec::json_u64(a, "amf_ue_ngap_id", codec::MAX_AMF_UE_NGAP_ID)?;
        let ran = codec::json_u64(a, "ran_ue_ngap_id", codec::MAX_RAN_UE_NGAP_ID)?;
        let nas = downlink_nas(a)?;
        Ok(ActionResult::Output(codec::downlink_nas_transport(
            amf, ran, &nas,
        )?))
    }

    fn ue_context_release(&self, a: &Value) -> Result<ActionResult> {
        // A subscriber named by SUPI: the session finds its connection.
        if a.get("amf_ue_ngap_id").is_none_or(Value::is_null) && a.get("supi").is_some() {
            target_ue(a)?;
            cause_field(a, "cause", Some("nas/normal-release"))?;
            return Ok(ActionResult::Custom {
                name: UE_CONTEXT_RELEASE.into(),
                data: a.clone(),
            });
        }
        let amf = codec::json_u64(a, "amf_ue_ngap_id", codec::MAX_AMF_UE_NGAP_ID)?;
        let ran = codec::json_opt_u64(a, "ran_ue_ngap_id", codec::MAX_RAN_UE_NGAP_ID)?;
        let cause = cause_field(a, "cause", Some("nas/normal-release"))?;
        Ok(ActionResult::Output(codec::ue_context_release_command(
            amf, ran, &cause,
        )?))
    }

    fn error_indication(&self, a: &Value) -> Result<ActionResult> {
        let amf = codec::json_opt_u64(a, "amf_ue_ngap_id", codec::MAX_AMF_UE_NGAP_ID)?;
        let ran = codec::json_opt_u64(a, "ran_ue_ngap_id", codec::MAX_RAN_UE_NGAP_ID)?;
        let cause = match a.get("cause") {
            Some(v) if !v.is_null() => Some(Cause::from_json(v)?),
            _ => None,
        };
        Ok(ActionResult::Output(codec::error_indication(
            amf,
            ran,
            cause.as_ref(),
        )?))
    }

    fn ng_reset(&self, a: &Value) -> Result<ActionResult> {
        let cause = cause_field(a, "cause", Some("misc/om-intervention"))?;
        Ok(ActionResult::Output(codec::ng_reset(&cause, None)?))
    }

    /// Validated here, carried out by the session, which holds the UE's keys and counts.
    fn registration_accept(&self, a: &Value) -> Result<ActionResult> {
        codec::json_u64(a, "amf_ue_ngap_id", codec::MAX_AMF_UE_NGAP_ID)?;
        let slices = list(a, "allowed_nssai")?;
        anyhow::ensure!(
            (1..=8).contains(&slices.len()),
            "allowed_nssai must hold 1..8 slices"
        );
        for s in slices {
            nas::Snssai::from_json(s).map_err(|e| anyhow!(e))?;
        }
        if let Some(t) = a.get("tac_list").filter(|v| !v.is_null()) {
            let t = t.as_array().context("tac_list must be a list of TACs")?;
            anyhow::ensure!(
                (1..=nas::MAX_TAI_LIST).contains(&t.len()),
                "tac_list must hold 1..{} TACs",
                nas::MAX_TAI_LIST
            );
            anyhow::ensure!(
                t.iter()
                    .all(|x| x.as_u64().map(|v| v <= 0xFF_FFFF).unwrap_or(false)),
                "tac_list entries are 24-bit numbers"
            );
        }
        codec::json_opt_u64(a, "tmsi", u32::MAX as u64)?;
        Ok(ActionResult::Custom {
            name: REGISTRATION_ACCEPT.into(),
            data: a.clone(),
        })
    }

    fn pdu_session_accept(&self, a: &Value) -> Result<ActionResult> {
        codec::json_u64(a, "amf_ue_ngap_id", codec::MAX_AMF_UE_NGAP_ID)?;
        session_id(a)?;
        let kind = a
            .get("pdu_session_type")
            .and_then(Value::as_str)
            .map(str::to_ascii_lowercase);
        // Without a type the UE's request decides; check whatever addresses were given.
        let wants_v4 = matches!(kind.as_deref(), None | Some("ipv4") | Some("ipv4v6"));
        let wants_v6 = matches!(kind.as_deref(), Some("ipv6") | Some("ipv4v6"));
        anyhow::ensure!(
            kind.is_none() || wants_v4 || wants_v6,
            "pdu_session_type must be ipv4, ipv6 or ipv4v6"
        );
        if wants_v4 && (kind.is_some() || a.get("ue_ipv6_prefix").is_none()) {
            let ip: std::net::Ipv4Addr = a
                .get("ue_ipv4")
                .and_then(Value::as_str)
                .context("ue_ipv4 is required: the IPv4 address this AMF assigns the UE")?
                .parse()
                .context("ue_ipv4 must be an IPv4 address")?;
            anyhow::ensure!(
                !(ip.is_unspecified() || ip.is_broadcast() || ip.is_multicast()),
                "ue_ipv4 {ip} cannot be a UE's address"
            );
        }
        if wants_v6 || a.get("ue_ipv6_prefix").is_some() {
            super::amf::parse_prefix(a.get("ue_ipv6_prefix").and_then(Value::as_str).context(
                "ue_ipv6_prefix is required for an IPv6 session, e.g. 2001:db8:1:2::/64",
            )?)
            .map_err(|e| anyhow!(e))?;
        }
        if let Some(i) = a
            .get("ue_ipv6_interface_identifier")
            .and_then(Value::as_str)
        {
            sm::parse_iid(i).map_err(|e| anyhow!(e))?;
        }
        super::amf::parse_answering_addresses(a).map_err(|e| anyhow!(e))?;
        if let Some(s) = a.get("s_nssai").filter(|v| !v.is_null()) {
            nas::Snssai::from_json(s).map_err(|e| anyhow!(e))?;
        }
        if let Some(d) = a.get("dnn").and_then(Value::as_str) {
            crate::server::gtp::codec::encode_apn(d).map_err(|e| anyhow!("dnn: {e}"))?;
        }
        codec::json_opt_u64(a, "five_qi", 255)?;
        Ok(ActionResult::Custom {
            name: PDU_SESSION_ACCEPT.into(),
            data: a.clone(),
        })
    }

    fn pdu_session_reject(&self, a: &Value) -> Result<ActionResult> {
        codec::json_u64(a, "amf_ue_ngap_id", codec::MAX_AMF_UE_NGAP_ID)?;
        let psi = codec::json_u64(a, "pdu_session_id", 15)?;
        anyhow::ensure!(psi >= 1, "pdu_session_id must be 1..15");
        sm::parse_cause(a.get("cause").unwrap_or(&Value::Null)).map_err(|e| anyhow!(e))?;
        Ok(ActionResult::Custom {
            name: PDU_SESSION_REJECT.into(),
            data: a.clone(),
        })
    }
}

/// A UE named by `amf_ue_ngap_id` (connected) or `supi` (connected or idle).
fn target_ue(a: &Value) -> Result<()> {
    match (
        a.get("amf_ue_ngap_id").filter(|v| !v.is_null()),
        a.get("supi").filter(|v| !v.is_null()),
    ) {
        (Some(_), _) => {
            codec::json_u64(a, "amf_ue_ngap_id", codec::MAX_AMF_UE_NGAP_ID)?;
        }
        (None, Some(s)) => {
            let s = s
                .as_str()
                .context("supi must be a string, e.g. imsi-001010000000001")?;
            super::subscribers::supi_digits(s).map_err(|e| anyhow!(e))?;
        }
        (None, None) => {
            anyhow::bail!("give amf_ue_ngap_id (a connected UE) or supi (connected or idle)")
        }
    }
    Ok(())
}

fn session_id(a: &Value) -> Result<()> {
    let psi = codec::json_u64(a, "pdu_session_id", 15)?;
    anyhow::ensure!(psi >= 1, "pdu_session_id must be 1..15");
    Ok(())
}

impl NgapProtocol {
    fn pdu_session_release(&self, a: &Value) -> Result<ActionResult> {
        target_ue(a)?;
        session_id(a)?;
        if let Some(c) = a.get("cause").filter(|v| !v.is_null()) {
            sm::parse_cause(c).map_err(|e| anyhow!(e))?;
        }
        Ok(ActionResult::Custom {
            name: PDU_SESSION_RELEASE.into(),
            data: a.clone(),
        })
    }

    fn pdu_session_release_reject(&self, a: &Value) -> Result<ActionResult> {
        codec::json_u64(a, "amf_ue_ngap_id", codec::MAX_AMF_UE_NGAP_ID)?;
        session_id(a)?;
        sm::parse_cause(a.get("cause").unwrap_or(&Value::Null)).map_err(|e| anyhow!(e))?;
        Ok(ActionResult::Custom {
            name: PDU_SESSION_RELEASE_REJECT.into(),
            data: a.clone(),
        })
    }

    fn pdu_session_modification(&self, a: &Value) -> Result<ActionResult> {
        target_ue(a)?;
        session_id(a)?;
        let ambr = a.get("session_ambr").filter(|v| !v.is_null());
        if let Some(m) = ambr {
            for k in ["uplink_kbps", "downlink_kbps"] {
                m.get(k)
                    .and_then(Value::as_u64)
                    .with_context(|| format!("session_ambr.{k} must be a number of kbps"))?;
            }
        }
        let five_qi = codec::json_opt_u64(a, "five_qi", 255)?;
        anyhow::ensure!(five_qi != Some(0), "five_qi must be 1..255");
        anyhow::ensure!(
            ambr.is_some() || five_qi.is_some(),
            "a modification changes session_ambr, five_qi or both"
        );
        Ok(ActionResult::Custom {
            name: PDU_SESSION_MODIFICATION.into(),
            data: a.clone(),
        })
    }

    fn pdu_session_modification_reject(&self, a: &Value) -> Result<ActionResult> {
        codec::json_u64(a, "amf_ue_ngap_id", codec::MAX_AMF_UE_NGAP_ID)?;
        session_id(a)?;
        sm::parse_cause(a.get("cause").unwrap_or(&Value::Null)).map_err(|e| anyhow!(e))?;
        Ok(ActionResult::Custom {
            name: PDU_SESSION_MODIFICATION_REJECT.into(),
            data: a.clone(),
        })
    }

    fn paging(&self, a: &Value) -> Result<ActionResult> {
        let s = a
            .get("supi")
            .and_then(Value::as_str)
            .context("supi is required: the idle subscriber to page, e.g. imsi-001010000000001")?;
        super::subscribers::supi_digits(s).map_err(|e| anyhow!(e))?;
        Ok(ActionResult::Custom {
            name: PAGING.into(),
            data: a.clone(),
        })
    }
}

pub const PDU_SESSION_RELEASE: &str = "pdu_session_release";
pub const PDU_SESSION_RELEASE_REJECT: &str = "pdu_session_release_reject";
pub const PDU_SESSION_MODIFICATION: &str = "pdu_session_modification";
pub const PDU_SESSION_MODIFICATION_REJECT: &str = "pdu_session_modification_reject";
pub const PAGING: &str = "paging";
pub const UE_CONTEXT_RELEASE: &str = "ue_context_release";

fn pdu_session_release_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_pdu_session_release".into(),
        description: "Release a PDU session: the answer to ngap_pdu_session_release_request, or \
                      a network-requested release at any time. Rust sends the protected 5GSM \
                      PDU Session Release Command inside a PDU Session Resource Release Command \
                      and stops the session's GTP-U tunnel at once. Name the UE by \
                      amf_ue_ngap_id, or by supi — an idle UE is paged and the release runs \
                      when it comes back."
            .into(),
        parameters: vec![
            p(
                "amf_ue_ngap_id",
                "number",
                "The UE's AMF UE NGAP ID (a connected UE)",
                false,
            ),
            p(
                "supi",
                "string",
                "Or the subscriber, e.g. imsi-001010000000001 (connected or idle)",
                false,
            ),
            p(
                "pdu_session_id",
                "number",
                "The session to release (1-15)",
                true,
            ),
            p(
                "cause",
                "string",
                "5GSM cause, default regular_deactivation; e.g. insufficient_resources, \
                 network_failure, reactivation_requested",
                false,
            ),
        ],
        example: json!({
            "type": "send_pdu_session_release",
            "amf_ue_ngap_id": 1,
            "pdu_session_id": 1,
            "cause": "regular_deactivation"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> NGAP PDU session {pdu_session_id} release {cause}")
                .with_debug("NGAP send_pdu_session_release {pdu_session_id} {cause}"),
        ),
    }
}

fn pdu_session_release_reject_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_pdu_session_release_reject".into(),
        description: "Refuse a UE's request to release a session (5GSM PDU Session Release \
                      Reject, protected by Rust); the session stays."
            .into(),
        parameters: vec![
            p("amf_ue_ngap_id", "number", "The UE's AMF UE NGAP ID", true),
            p("pdu_session_id", "number", "The session (1-15)", true),
            p(
                "cause",
                "string",
                "5GSM cause, e.g. request_rejected_unspecified",
                true,
            ),
        ],
        example: json!({
            "type": "send_pdu_session_release_reject",
            "amf_ue_ngap_id": 1,
            "pdu_session_id": 1,
            "cause": "request_rejected_unspecified"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> NGAP PDU session {pdu_session_id} release refused {cause}")
                .with_debug("NGAP send_pdu_session_release_reject {pdu_session_id} {cause}"),
        ),
    }
}

fn pdu_session_modification_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_pdu_session_modification".into(),
        description: "Change a PDU session's QoS: the answer to \
                      ngap_pdu_session_modification_request, or a network-requested \
                      modification at any time. You choose the session AMBR and/or the 5QI of \
                      its default QoS flow (rule 1, QFI 1); Rust sends the protected 5GSM PDU \
                      Session Modification Command inside a PDU Session Resource Modify Request \
                      and applies the change when the UE completes it. Name the UE by \
                      amf_ue_ngap_id, or by supi — an idle UE is paged first."
            .into(),
        parameters: vec![
            p(
                "amf_ue_ngap_id",
                "number",
                "The UE's AMF UE NGAP ID (a connected UE)",
                false,
            ),
            p(
                "supi",
                "string",
                "Or the subscriber (connected or idle)",
                false,
            ),
            p("pdu_session_id", "number", "The session (1-15)", true),
            p(
                "session_ambr",
                "object",
                "New session AMBR {\"uplink_kbps\", \"downlink_kbps\"}",
                false,
            ),
            p(
                "five_qi",
                "number",
                "New standardised 5QI of the default flow (1-255)",
                false,
            ),
        ],
        example: json!({
            "type": "send_pdu_session_modification",
            "amf_ue_ngap_id": 1,
            "pdu_session_id": 1,
            "session_ambr": {"uplink_kbps": 50000, "downlink_kbps": 100000},
            "five_qi": 8
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> NGAP PDU session {pdu_session_id} modification")
                .with_debug(
                    "NGAP send_pdu_session_modification {pdu_session_id} {session_ambr} {five_qi}",
                ),
        ),
    }
}

fn pdu_session_modification_reject_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_pdu_session_modification_reject".into(),
        description: "Refuse a UE's modification request (5GSM PDU Session Modification \
                      Reject, protected by Rust); the session stays as it is."
            .into(),
        parameters: vec![
            p("amf_ue_ngap_id", "number", "The UE's AMF UE NGAP ID", true),
            p("pdu_session_id", "number", "The session (1-15)", true),
            p(
                "cause",
                "string",
                "5GSM cause, e.g. requested_service_option_not_subscribed, insufficient_resources",
                true,
            ),
        ],
        example: json!({
            "type": "send_pdu_session_modification_reject",
            "amf_ue_ngap_id": 1,
            "pdu_session_id": 1,
            "cause": "requested_service_option_not_subscribed"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> NGAP PDU session {pdu_session_id} modification refused {cause}")
                .with_debug("NGAP send_pdu_session_modification_reject {pdu_session_id} {cause}"),
        ),
    }
}

fn paging_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_paging".into(),
        description: "Page an idle subscriber (NGAP Paging with its 5G-S-TMSI in its last \
                      tracking area). It answers with a Service Request, which Rust verifies \
                      and accepts, setting its PDU sessions' user plane up again. A UE goes \
                      idle when its N2 context is released (send_ue_context_release_command, \
                      the inactivity timer, or the gNB)."
            .into(),
        parameters: vec![p(
            "supi",
            "string",
            "The idle subscriber, e.g. imsi-001010000000001",
            true,
        )],
        example: json!({"type": "send_paging", "supi": "imsi-001010000000001"}),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> NGAP Paging {supi}")
                .with_debug("NGAP send_paging {supi}"),
        ),
    }
}

pub static NGAP_PDU_SESSION_RELEASE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "ngap_pdu_session_release_request",
        "A registered UE asks to release one of its PDU sessions (5GSM PDU Session Release \
         Request, verified under NAS security). session describes it (type, address, DNN, \
         slice, 5QI, AMBR); cause is the UE's, usually regular_deactivation. Decide: \
         send_pdu_session_release (Rust releases it and stops its tunnel) or \
         send_pdu_session_release_reject with a 5GSM cause. No answer, or a failed model, \
         releases it: a release keeps nothing open.",
        pdu_session_release_action().example,
    )
    .with_alternative_example(pdu_session_release_reject_action().example)
    .with_actions(response_actions())
    .with_log_template(
        LogTemplate::new()
            .with_info("NGAP PDU session {pdu_session_id} release request ue={amf_ue_ngap_id}")
            .with_debug("NGAP PDU session release request {supi} {pdu_session_id} {cause}")
            .with_trace("NGAP PDU session release request: {json_pretty(.)}"),
    )
});

pub static NGAP_PDU_SESSION_MODIFICATION_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "ngap_pdu_session_modification_request",
        "A registered UE asks to modify one of its PDU sessions (5GSM PDU Session Modification \
         Request, verified under NAS security). requested_five_qi is the 5QI it asked for on its \
         default flow, if it named one; session is what it has now. Decide: \
         send_pdu_session_modification with the session_ambr and/or five_qi it gets, or \
         send_pdu_session_modification_reject with a 5GSM cause. No answer is a reject: \
         nothing changes by default.",
        pdu_session_modification_action().example,
    )
    .with_alternative_example(pdu_session_modification_reject_action().example)
    .with_actions(response_actions())
    .with_log_template(
        LogTemplate::new()
            .with_info("NGAP PDU session {pdu_session_id} modification request ue={amf_ue_ngap_id}")
            .with_debug(
                "NGAP PDU session modification request {supi} {pdu_session_id} {requested_five_qi}",
            )
            .with_trace("NGAP PDU session modification request: {json_pretty(.)}"),
    )
});

/// The names the session knows the stateful decisions by.
pub const REGISTRATION_ACCEPT: &str = "registration_accept";
pub const PDU_SESSION_ACCEPT: &str = "pdu_session_accept";
pub const PDU_SESSION_REJECT: &str = "pdu_session_reject";

// ============================================================================
// Action definitions
// ============================================================================

const PLMN_HELP: &str = "{\"mcc\": \"001\", \"mnc\": \"01\"} — digits as strings";

fn ng_setup_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_ng_setup_response".into(),
        description: "Admit this gNB: answer its NG Setup Request with an NG Setup Response \
                      naming this AMF, its GUAMIs and the PLMNs and slices it serves. This is the \
                      admission decision for N2 — return send_ng_setup_failure to refuse."
            .into(),
        parameters: vec![
            p("amf_name", "string", "This AMF's name, 1-150 PrintableString characters", true),
            p(
                "served_guami",
                "array",
                &format!("GUAMIs this AMF serves (1-256): [{{\"plmn\": {PLMN_HELP}, \"amf_region_id\": 0-255, \"amf_set_id\": 0-1023, \"amf_pointer\": 0-63}}]"),
                true,
            ),
            p(
                "plmn_support",
                "array",
                "PLMNs and slices supported (1-12): [{\"plmn\": {...}, \"slices\": [{\"sst\": 1, \"sd\": \"010203\"}]}] — sd is optional, six hex digits",
                true,
            ),
            p("relative_amf_capacity", "number", "0-255, default 255", false),
        ],
        example: json!({
            "type": "send_ng_setup_response",
            "amf_name": "netget-amf",
            "served_guami": [{"plmn": {"mcc": "001", "mnc": "01"}, "amf_region_id": 2, "amf_set_id": 1, "amf_pointer": 0}],
            "plmn_support": [{"plmn": {"mcc": "001", "mnc": "01"}, "slices": [{"sst": 1}]}],
            "relative_amf_capacity": 255
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> NGAP NG Setup Response {amf_name}")
                .with_debug("NGAP send_ng_setup_response {amf_name}"),
        ),
    }
}

fn ng_setup_failure_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_ng_setup_failure".into(),
        description: "Refuse this gNB with an NG Setup Failure carrying a cause. The explicit \
                      refusal of N2 setup."
            .into(),
        parameters: vec![
            p(
                "cause",
                "string",
                "group/value, e.g. misc/unknown-PLMN-or-SNPN, misc/control-processing-overload, \
                 misc/om-intervention, misc/unspecified, protocol/semantic-error",
                true,
            ),
            p(
                "time_to_wait",
                "string",
                "When the gNB may retry: v1s, v2s, v5s, v10s, v20s or v60s",
                false,
            ),
        ],
        example: json!({"type": "send_ng_setup_failure", "cause": "misc/unknown-PLMN-or-SNPN", "time_to_wait": "v10s"}),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> NGAP NG Setup Failure {cause}")
                .with_debug("NGAP send_ng_setup_failure cause={cause}"),
        ),
    }
}

fn downlink_nas_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_downlink_nas_transport".into(),
        description:
            "Send a NAS message to one UE in a Downlink NAS Transport. The NAS message is \
                      structured and Rust encodes it — and protects it, when the UE is under NAS \
                      security. Offered: registration_reject {cause}, identity_request \
                      {identity_type}, authentication_request {ngksi, rand?, autn? — 32 hex digits \
                      each, random when omitted; for a UE with no credentials on this AMF a real \
                      UE answers with authentication_failure mac_failure}, authentication_reject, \
                      service_reject {cause}, 5gmm_status {cause}. Subscribers with credentials \
                      are authenticated by Rust; you are asked only whether to register them \
                      (ngap_registration_request) and about their PDU sessions."
                .into(),
        parameters: vec![
            p(
                "amf_ue_ngap_id",
                "number",
                "The UE's AMF UE NGAP ID, from the event",
                true,
            ),
            p(
                "ran_ue_ngap_id",
                "number",
                "The UE's RAN UE NGAP ID, from the event",
                true,
            ),
            p(
                "nas",
                "object",
                "e.g. {\"message\": \"registration_reject\", \"cause\": \"illegal_ue\"} or \
                 {\"message\": \"identity_request\", \"identity_type\": \"suci\"}. 5GMM causes by \
                 name: illegal_ue, plmn_not_allowed, tracking_area_not_allowed, congestion, \
                 no_network_slices_available, protocol_error_unspecified, …",
                true,
            ),
        ],
        example: json!({
            "type": "send_downlink_nas_transport",
            "amf_ue_ngap_id": 1,
            "ran_ue_ngap_id": 1,
            "nas": {"message": "registration_reject", "cause": "illegal_ue"}
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> NGAP Downlink NAS Transport ue={amf_ue_ngap_id}")
                .with_debug("NGAP send_downlink_nas_transport ue={amf_ue_ngap_id} nas={nas}"),
        ),
    }
}

fn release_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_ue_context_release_command".into(),
        description: "Release one UE's N2 context (UE Context Release Command). The gNB answers \
                      with UE Context Release Complete, which NetGet handles. A registered \
                      subscriber goes to CM-IDLE: it keeps its registration, NAS security and \
                      PDU sessions, and comes back with a Service Request (or when paged with \
                      send_paging); use cause radioNetwork/user-inactivity for that. A UE that \
                      is not registered is simply gone."
            .into(),
        parameters: vec![
            p("amf_ue_ngap_id", "number", "The UE's AMF UE NGAP ID", false),
            p(
                "ran_ue_ngap_id",
                "number",
                "The UE's RAN UE NGAP ID (sends the pair form)",
                false,
            ),
            p(
                "supi",
                "string",
                "Or a registered subscriber connected on this association, e.g. imsi-001010000000001",
                false,
            ),
            p(
                "cause",
                "string",
                "group/value, default nas/normal-release",
                false,
            ),
        ],
        example: json!({"type": "send_ue_context_release_command", "amf_ue_ngap_id": 1, "ran_ue_ngap_id": 1, "cause": "nas/normal-release"}),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> NGAP UE Context Release Command ue={amf_ue_ngap_id}")
                .with_debug("NGAP send_ue_context_release_command cause={cause}"),
        ),
    }
}

fn error_indication_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_error_indication".into(),
        description: "Report an error to the gNB with an Error Indication, optionally naming a UE."
            .into(),
        parameters: vec![
            p(
                "cause",
                "string",
                "group/value, e.g. protocol/semantic-error",
                false,
            ),
            p(
                "amf_ue_ngap_id",
                "number",
                "The UE concerned, if any",
                false,
            ),
            p(
                "ran_ue_ngap_id",
                "number",
                "The UE concerned, if any",
                false,
            ),
        ],
        example: json!({"type": "send_error_indication", "cause": "protocol/semantic-error"}),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> NGAP Error Indication {cause}")
                .with_debug("NGAP send_error_indication cause={cause}"),
        ),
    }
}

fn ng_reset_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_ng_reset".into(),
        description: "Reset every UE context on this N2 interface (NG Reset, reset-all). The gNB \
                      acknowledges and NetGet clears its UE table."
            .into(),
        parameters: vec![p(
            "cause",
            "string",
            "group/value, default misc/om-intervention",
            false,
        )],
        example: json!({"type": "send_ng_reset", "cause": "misc/om-intervention"}),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> NGAP NG Reset {cause}")
                .with_debug("NGAP send_ng_reset cause={cause}"),
        ),
    }
}

fn registration_accept_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_registration_accept".into(),
        description: "Admit an authenticated subscriber (answer to ngap_registration_request): \
                      Rust allocates its 5G-GUTI under this AMF's GUAMI, sends the protected \
                      Registration Accept inside an Initial Context Setup with K_gNB, and \
                      completes registration. You choose the allowed slices and the tracking \
                      areas. To refuse instead, send_downlink_nas_transport with \
                      registration_reject (Rust protects it) and release the UE."
            .into(),
        parameters: vec![
            p("amf_ue_ngap_id", "number", "The UE's AMF UE NGAP ID, from the event", true),
            p(
                "allowed_nssai",
                "array",
                "The slices this UE may use (1-8): [{\"sst\": 1, \"sd\": \"010203\"}] — sd optional",
                true,
            ),
            p(
                "tac_list",
                "array",
                "Tracking area codes of its registration area (1-16), in the UE's PLMN; \
                 default: the tracking area it is in",
                false,
            ),
            p("tmsi", "number", "The 5G-TMSI to assign (32 bits); default random", false),
            p(
                "ue_ambr",
                "object",
                "UE aggregate maximum bit rate {\"uplink_kbps\", \"downlink_kbps\"}; default none",
                false,
            ),
        ],
        example: json!({
            "type": "send_registration_accept",
            "amf_ue_ngap_id": 1,
            "allowed_nssai": [{"sst": 1}]
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> NGAP Registration Accept ue={amf_ue_ngap_id}")
                .with_debug("NGAP send_registration_accept ue={amf_ue_ngap_id} nssai={allowed_nssai}"),
        ),
    }
}

fn pdu_session_accept_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_pdu_session_accept".into(),
        description: "Accept a PDU session (answer to ngap_pdu_session_establishment_request): \
                      Rust sends the protected PDU Session Establishment Accept with one default \
                      QoS rule and flow inside a PDU Session Resource Setup Request, and opens a \
                      GTP-U tunnel on this AMF's user plane. You choose the UE's address — an \
                      IPv4 address, an IPv6 /64 prefix and interface identifier, or both — and \
                      which addresses answer its ICMP/ICMPv6 echo through the tunnel; packets to \
                      anything else are dropped. An IPv6 UE gets its prefix in a Router \
                      Advertisement from the user plane."
            .into(),
        parameters: vec![
            p("amf_ue_ngap_id", "number", "The UE's AMF UE NGAP ID, from the event", true),
            p("pdu_session_id", "number", "The session's id, from the event (1-15)", true),
            p(
                "ue_ipv4",
                "string",
                "The IPv4 address assigned to the UE, e.g. 10.45.0.2 (ipv4 and ipv4v6 sessions)",
                false,
            ),
            p(
                "ue_ipv6_prefix",
                "string",
                "The UE's /64 prefix, e.g. 2001:db8:1:2::/64 (ipv6 and ipv4v6 sessions)",
                false,
            ),
            p(
                "ue_ipv6_interface_identifier",
                "string",
                "The UE's IPv6 interface identifier, e.g. ::2 (default ::1)",
                false,
            ),
            p(
                "reachable_addresses",
                "array",
                "IPv4 or IPv6 addresses that answer the UE's ping through the tunnel (0-16), e.g. [\"10.45.0.1\", \"2001:db8:1:2::1\"]",
                false,
            ),
            p("dnn", "string", "The DNN; default the one the UE asked for, else internet", false),
            p("s_nssai", "object", "The slice {\"sst\", \"sd\"?}; default the one the UE asked for", false),
            p("five_qi", "number", "Standardised 5QI of the session's flow (1-255), default 9", false),
            p(
                "session_ambr",
                "object",
                "{\"uplink_kbps\", \"downlink_kbps\"}, default 1000000 each",
                false,
            ),
            p(
                "pdu_session_type",
                "string",
                "ipv4, ipv6 or ipv4v6; default the type the UE asked for",
                false,
            ),
        ],
        example: json!({
            "type": "send_pdu_session_accept",
            "amf_ue_ngap_id": 1,
            "pdu_session_id": 1,
            "ue_ipv4": "10.45.0.2",
            "reachable_addresses": ["10.45.0.1"]
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> NGAP PDU session {pdu_session_id} accepted ue={amf_ue_ngap_id} ip={ue_ipv4}")
                .with_debug("NGAP send_pdu_session_accept {pdu_session_id} {ue_ipv4}"),
        ),
    }
}

fn pdu_session_reject_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_pdu_session_reject".into(),
        description: "Refuse a PDU session with a 5GSM cause (PDU Session Establishment Reject, \
                      protected by Rust)."
            .into(),
        parameters: vec![
            p("amf_ue_ngap_id", "number", "The UE's AMF UE NGAP ID", true),
            p("pdu_session_id", "number", "The session's id (1-15)", true),
            p(
                "cause",
                "string",
                "5GSM cause: missing_or_unknown_dnn, insufficient_resources, \
                 request_rejected_unspecified, requested_service_option_not_subscribed, …",
                true,
            ),
        ],
        example: json!({
            "type": "send_pdu_session_reject",
            "amf_ue_ngap_id": 1,
            "pdu_session_id": 1,
            "cause": "missing_or_unknown_dnn"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> NGAP PDU session {pdu_session_id} rejected {cause}")
                .with_debug("NGAP send_pdu_session_reject {pdu_session_id} {cause}"),
        ),
    }
}

fn wait_for_more_action() -> ActionDefinition {
    ActionDefinition {
        name: "wait_for_more".into(),
        description: "Send nothing. On an NG Setup Request or Initial UE Message this is NOT an \
                      admission: NetGet answers with a refusal."
            .into(),
        parameters: vec![],
        example: json!({"type": "wait_for_more"}),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> NGAP wait for more")
                .with_debug("NGAP wait_for_more"),
        ),
    }
}

fn response_actions() -> Vec<ActionDefinition> {
    vec![
        ng_setup_response_action(),
        ng_setup_failure_action(),
        downlink_nas_action(),
        release_action(),
        error_indication_action(),
        ng_reset_action(),
        registration_accept_action(),
        pdu_session_accept_action(),
        pdu_session_reject_action(),
        pdu_session_release_action(),
        pdu_session_release_reject_action(),
        pdu_session_modification_action(),
        pdu_session_modification_reject_action(),
        paging_action(),
        wait_for_more_action(),
    ]
}

// ============================================================================
// Events
// ============================================================================

pub static NGAP_NG_SETUP_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "ngap_ng_setup_request",
        "A gNB sent NG Setup Request and wants to set up N2 with this AMF. global_ran_node_id \
         names it (plmn, gnb_id), supported_ta_list lists its tracking areas with the PLMNs and \
         slices broadcast in each. Reply with send_ng_setup_response to admit it, or \
         send_ng_setup_failure to refuse. Anything else — wait_for_more, no answer, a failed \
         model — is answered by NetGet with NG Setup Failure: admitting a gNB is never the \
         default.",
        ng_setup_response_action().example,
    )
    .with_alternative_example(
        json!({"type": "send_ng_setup_failure", "cause": "misc/unknown-PLMN-or-SNPN"}),
    )
    .with_actions(response_actions())
    .with_log_template(
        LogTemplate::new()
            .with_info("NGAP NG Setup Request from {ran_node_name}")
            .with_debug("NGAP NG Setup Request {global_ran_node_id}")
            .with_trace("NGAP NG Setup Request: {json_pretty(.)}"),
    )
});

pub static NGAP_INITIAL_UE_MESSAGE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "ngap_initial_ue_message",
        "A UE's first NAS message arrived through the gNB (Initial UE Message). NetGet allocated \
         amf_ue_ngap_id; ran_ue_ngap_id is the gNB's. nas is the decoded 5GMM message — for a \
         registration_request: registration_type, ngksi and mobile_identity (a SUCI's plmn, \
         routing_indicator, protection_scheme and, for the null scheme, msin; or a 5G-GUTI). \
         Answer with send_downlink_nas_transport carrying identity_request, \
         authentication_request or registration_reject, optionally followed by \
         send_ue_context_release_command. Saying nothing makes NetGet reject the UE \
         (registration_reject protocol_error_unspecified) and release it.",
        downlink_nas_action().example,
    )
    .with_alternative_example(json!({
        "type": "send_downlink_nas_transport",
        "amf_ue_ngap_id": 1,
        "ran_ue_ngap_id": 1,
        "nas": {"message": "authentication_request", "ngksi": 0}
    }))
    .with_actions(response_actions())
    .with_log_template(
        LogTemplate::new()
            .with_info("NGAP Initial UE Message ue={amf_ue_ngap_id}")
            .with_debug("NGAP Initial UE Message ue={amf_ue_ngap_id} nas={nas}")
            .with_trace("NGAP Initial UE Message: {json_pretty(.)}"),
    )
});

pub static NGAP_UPLINK_NAS_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "ngap_uplink_nas_transport",
        "A UE answered through the gNB (Uplink NAS Transport). nas is the decoded 5GMM message — \
         e.g. identity_response with its mobile_identity, or authentication_failure with its \
         cause (mac_failure means the UE did not accept the AUTN). Answer with \
         send_downlink_nas_transport, send_ue_context_release_command, or wait_for_more.",
        json!({
            "type": "send_downlink_nas_transport",
            "amf_ue_ngap_id": 1,
            "ran_ue_ngap_id": 1,
            "nas": {"message": "registration_reject", "cause": "illegal_ue"}
        }),
    )
    .with_alternative_example(json!({"type": "wait_for_more"}))
    .with_actions(response_actions())
    .with_log_template(
        LogTemplate::new()
            .with_info("NGAP Uplink NAS Transport ue={amf_ue_ngap_id}")
            .with_debug("NGAP Uplink NAS Transport ue={amf_ue_ngap_id} nas={nas}")
            .with_trace("NGAP Uplink NAS Transport: {json_pretty(.)}"),
    )
});

pub static NGAP_REGISTRATION_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "ngap_registration_request",
        "A subscriber this AMF holds credentials for has completed 5G-AKA and NAS security is on \
         (Rust did both: the keys never leave it). supi is the authenticated identity; \
         requested_nssai the slices it asked for; user_location its cell and tracking area; \
         plmn_support what this AMF announced. Decide whether it may register: \
         send_registration_accept with the allowed slices, or send_downlink_nas_transport with \
         registration_reject and a 5GMM cause (then send_ue_context_release_command). No \
         answer, or a failed model, is a Registration Reject: registering is never the default.",
        registration_accept_action().example,
    )
    .with_alternative_example(json!({
        "type": "send_downlink_nas_transport",
        "amf_ue_ngap_id": 1,
        "ran_ue_ngap_id": 1,
        "nas": {"message": "registration_reject", "cause": "plmn_not_allowed"}
    }))
    .with_actions(response_actions())
    .with_log_template(
        LogTemplate::new()
            .with_info("NGAP registration decision ue={amf_ue_ngap_id} {supi}")
            .with_debug("NGAP registration request {supi} nssai={requested_nssai}")
            .with_trace("NGAP registration request: {json_pretty(.)}"),
    )
});

pub static NGAP_PDU_SESSION_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "ngap_pdu_session_establishment_request",
        "A registered UE asks for a PDU session (5GSM PDU Session Establishment Request, \
         delivered under NAS security). pdu_session_id, dnn, s_nssai and pdu_session_type are \
         what it asked for; user_plane_available says whether this AMF has a GTP-U user plane \
         (without one an accept is answered with insufficient_resources). Decide: \
         send_pdu_session_accept with the UE's IPv4 address and the addresses that answer its \
         ping, or send_pdu_session_reject with a 5GSM cause. No answer is a reject.",
        pdu_session_accept_action().example,
    )
    .with_alternative_example(pdu_session_reject_action().example)
    .with_actions(response_actions())
    .with_log_template(
        LogTemplate::new()
            .with_info("NGAP PDU session {pdu_session_id} request ue={amf_ue_ngap_id} dnn={dnn}")
            .with_debug("NGAP PDU session request {supi} {pdu_session_id} {dnn} {s_nssai}")
            .with_trace("NGAP PDU session request: {json_pretty(.)}"),
    )
});

pub static NGAP_ERROR_INDICATION_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "ngap_error_indication",
        "The gNB reported an error (Error Indication), with an optional cause and UE ids. \
         Observational: no answer is required. Release the UE with \
         send_ue_context_release_command if it names one, or wait_for_more.",
        json!({"type": "wait_for_more"}),
    )
    .with_alternative_example(
        json!({"type": "send_ue_context_release_command", "amf_ue_ngap_id": 1}),
    )
    .with_actions(response_actions())
    .with_log_template(
        LogTemplate::new()
            .with_info("NGAP Error Indication {cause}")
            .with_debug("NGAP Error Indication {cause} ue={amf_ue_ngap_id}")
            .with_trace("NGAP Error Indication: {json_pretty(.)}"),
    )
});

// ============================================================================

impl Protocol for NgapProtocol {
    /// Every NGAP verb is addressed to one association, so there are no async actions; the
    /// dashboard's "message this peer" runs the sync actions through the peer command channel.
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![]
    }

    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        response_actions()
    }

    fn protocol_name(&self) -> &'static str {
        "NGAP"
    }

    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            NGAP_NG_SETUP_EVENT.clone(),
            NGAP_INITIAL_UE_MESSAGE_EVENT.clone(),
            NGAP_UPLINK_NAS_EVENT.clone(),
            NGAP_REGISTRATION_EVENT.clone(),
            NGAP_PDU_SESSION_EVENT.clone(),
            NGAP_PDU_SESSION_RELEASE_EVENT.clone(),
            NGAP_PDU_SESSION_MODIFICATION_EVENT.clone(),
            NGAP_ERROR_INDICATION_EVENT.clone(),
        ]
    }

    fn stack_name(&self) -> &'static str {
        "ETH>IP>SCTP>NGAP"
    }

    fn keywords(&self) -> Vec<&'static str> {
        vec!["ngap", "n2", "amf", "5g core", "5gc", "38.413"]
    }

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{
            DevelopmentState, PrivilegeRequirement, ProtocolMetadataV2,
        };
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            // 38412 is above 1023 and SCTP is an ordinary kernel transport, not a raw socket.
            .privilege_requirement(PrivilegeRequirement::None)
            // TS 38.412 section 7; the same number as `codec::SCTP_PORT`, written as a literal so
            // the well-known-port ratchet can read it from source.
            .well_known_sctp_port(38412)
            .implementation(
                "TS 38.413 ALIGNED PER hand-written for the procedures implemented (NG Setup, \
                 Initial UE Message, Downlink/Uplink NAS Transport, Initial Context Setup, PDU \
                 Session Resource Setup, Release and Modify with their transfers, Paging, Error \
                 Indication, NG Reset, UE Context Release and its request), other IEs framed and \
                 skipped by length; 5GMM and 5GSM (TS 24.501) decoded and encoded, including \
                 Service Request/Accept and PDU session release and modification; NAS security \
                 in Rust: Milenage, the 5G-AKA key hierarchy (RES*, K_AUSF, K_SEAF, K_AMF, NAS \
                 keys, K_gNB), NIA1/NIA2/NIA3 and NEA0/NEA1/NEA2/NEA3 (SNOW 3G and ZUC written \
                 from the ETSI/SAGE specifications) by the operator's preference, per-direction \
                 COUNTs and replay refusal, SUCI deconcealment for ECIES Profiles A and B; \
                 CM-IDLE with a server-wide idle store, Service Request verified with the UE's \
                 context and its NAS message container deciphered, paging, an inactivity timer; \
                 a minimal GTP-U user plane that answers ICMP and ICMPv6 echo and Router \
                 Solicitation; SCTP via a socket2 one-to-one socket with PPID 60 and stream 0/1 \
                 selection, plus a non-standard length-prefixed TCP transport",
            )
            .llm_control(
                "The model admits or refuses gNBs (NG Setup Response/Failure), decides whether \
                 each authenticated subscriber may register and on which slices \
                 (send_registration_accept or a reject), decides each PDU session (IPv4 \
                 address, IPv6 prefix and interface identifier, DNN, slice, 5QI, AMBR and which \
                 addresses answer its ping, or a 5GSM reject), answers a UE's release and \
                 modification requests, and on its own releases or modifies sessions, idles \
                 UEs (send_ue_context_release_command) and pages them (send_paging). UEs \
                 without credentials stay model-driven pre-security. 5G-AKA, the security mode \
                 procedure, every MAC and COUNT, K_gNB, GUTI allocation, Service Request, \
                 deregistration, decoding, ID allocation, NG Reset and protocol refusals are \
                 Rust's; the keys never reach the model",
            )
            .e2e_testing(
                "UERANSIM v3.2.7's nr-gnb and nr-ue over real SCTP on Linux: a UE with an ECIES \
                 Profile A SUCI authenticates, registers, gets a PDU session, pings through its \
                 uesimtun and NetGet's GTP-U, and deregisters; UEs register under SNOW 3G \
                 (NIA1/NEA1) and ZUC (NIA3/NEA3) and ping; a UE releases its session (its \
                 uesimtun goes), is idled and answers NetGet's paging; another is challenged \
                 without credentials and rejected; tshark's ngap and nas-5gs dissectors read \
                 the live captures. In-process over the lab transport with a mocked model and \
                 scripted UEs: modification, UE- and network-requested release, CM-IDLE, \
                 Service Request (forged and unknown ones refused), paging with a queued \
                 decision, IPv6 and IPv4v6 sessions with ICMPv6 echo and Router Advertisement \
                 verified by tshark, forged MACs, replayed COUNTs, wrong RES*, MAC and synch \
                 failures, silent and failed models; Milenage, NIA1-3/NEA1-3 and SUCI against \
                 TS 35.208, TS 33.401 and ETSI/SAGE vectors",
            )
            .notes(
                "EXPERIMENTAL: one independent peer (UERANSIM) — condition 1 of the Stable bar \
                 needs two — and its evidence runs only where SCTP exists (Linux, the ngap pair \
                 job). macOS has no SCTP, so there only the non-standard transport=\"tcp\" \
                 runs. UERANSIM v3.2.7 cannot exercise three of the new procedures: its UE \
                 refuses to request an IPv6 or IPv4v6 session, implements no PDU session \
                 modification, and its gNB drops every Service Request (it selects an AMF by \
                 the slice of a Registration Request) — those rest on the lab tests and on \
                 NetGet's gNB against Open5GS. 5G-AKA only (no EAP-AKA'); one QoS flow per \
                 session; the user plane answers echo and Router Solicitation and routes \
                 nothing else. Not built: handover, AMF configuration update, N2 for several \
                 gNBs as one AMF beyond the shared idle store.",
            )
            .max_inbound_bytes(codec::MAX_PDU_LEN)
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }

    fn description(&self) -> &'static str {
        "NGAP (5G N2) AMF: NG Setup, 5G-AKA and NAS security, registration, PDU sessions and a GTP-U user plane"
    }

    fn example_prompt(&self) -> &'static str {
        "Start a 5G AMF for PLMN 001-01 that admits gNBs and rejects every UE as illegal"
    }

    fn get_startup_parameters(&self) -> Vec<crate::llm::actions::ParameterDefinition> {
        vec![
            crate::llm::actions::ParameterDefinition {
                name: "transport".into(),
                type_hint: "string".into(),
                description: "\"sctp\" (default — TS 38.412, PPID 60) or \"tcp\". TCP IS \
                          NON-STANDARD: a NetGet length-prefixed framing that no real gNB speaks, \
                          for local protocol work on hosts with no SCTP (macOS has none). A host \
                          without SCTP refuses \"sctp\" rather than falling back."
                    .into(),
                required: false,
                example: json!("sctp"),
                default: None,
            },
            crate::llm::actions::ParameterDefinition {
                name: "subscribers".into(),
                type_hint: "array".into(),
                description: "Subscriber credentials this AMF authenticates with 5G-AKA (it plays \
                          AUSF/UDM too): [{\"supi\": \"imsi-001010000000001\", \
                          \"subscriber_key\": K (32 hex), \"subscriber_opc\": OPc (32 hex) or \
                          \"subscriber_op\": OP, \"amf_field\": \"8000\", \"sqn\": the last SQN \
                          used (number or 12 hex)}]. A UE whose SUCI resolves to one of these is \
                          authenticated, secured (NIA2) and offered to the model once, already \
                          authenticated. Keys are redacted wherever parameters are shown and never \
                          reach an event. Without this, NAS security is not used."
                    .into(),
                required: false,
                example: json!([{"supi": "imsi-001010000000001",
                             "subscriber_key": "465B5CE8B199B49FAA5F0A2EE238A6BC",
                             "subscriber_opc": "E8ED289DEBA952E4283B54E88E6183CA",
                             "amf_field": "8000"}]),
                default: None,
            },
            crate::llm::actions::ParameterDefinition {
                name: "suci_keys".into(),
                type_hint: "array".into(),
                description: "Home network private keys for SUCI concealment (TS 33.501 Annex C): \
                          [{\"key_id\": 1, \"scheme\": \"profile_a\" | \"profile_b\", \
                          \"home_network_private_key\": 64 hex}]. A SUCI with an ECIES profile \
                          and no matching key is left to the model, unread."
                    .into(),
                required: false,
                example: json!([{"key_id": 1, "scheme": "profile_a",
                             "home_network_private_key": hex::encode(super::suci::TS_33_501_C_4_3_HOME_NETWORK_PRIVATE_KEY)}]),
                default: None,
            },
            crate::llm::actions::ParameterDefinition {
                name: "nas_ciphering".into(),
                type_hint: "string".into(),
                description: "NAS ciphering algorithms in order of preference, comma-separated: \
                          \"nea0\" (null ciphering, the protected NAS stays readable on the \
                          wire), \"nea1\" (SNOW 3G), \"nea2\" (AES-CTR), \"nea3\" (ZUC), e.g. \
                          \"nea3,nea2\". The first one the UE supports is selected; NEA0 when it \
                          supports none of them."
                    .into(),
                required: false,
                example: json!("nea2"),
                default: Some(json!(super::DEFAULT_NAS_CIPHERING)),
            },
            crate::llm::actions::ParameterDefinition {
                name: "nas_integrity".into(),
                type_hint: "string".into(),
                description: "NAS integrity algorithms in order of preference, comma-separated: \
                          \"nia1\" (SNOW 3G), \"nia2\" (AES-CMAC), \"nia3\" (ZUC), e.g. \
                          \"nia3,nia2\". The first one the UE supports is selected; a UE that \
                          supports none of them is refused with 5GMM cause #23. NIA0 is never \
                          offered."
                    .into(),
                required: false,
                example: json!("nia2,nia1"),
                default: Some(json!(super::DEFAULT_NAS_INTEGRITY)),
            },
            crate::llm::actions::ParameterDefinition {
                name: "ue_inactivity_timeout_secs".into(),
                type_hint: "number".into(),
                description:
                    "Release a registered UE to CM-IDLE after this many seconds with no NAS \
                          message and no user-plane packet from it (UE Context Release Command, \
                          radioNetwork/user-inactivity). It keeps its sessions and comes back \
                          with a Service Request. Omitted or 0: never; the model or the gNB \
                          idles UEs."
                        .into(),
                required: false,
                example: json!(30),
                default: None,
            },
            crate::llm::actions::ParameterDefinition {
                name: "user_plane_address".into(),
                type_hint: "string".into(),
                description:
                    "Run a GTP-U user plane on this address (UDP 2152, or IP:port) and put \
                          it in each accepted PDU session's uplink tunnel. It answers a UE's ICMP \
                          echo for the addresses the model chose for the session; nothing else is \
                          routed. Without it PDU sessions are refused with \
                          insufficient_resources."
                        .into(),
                required: false,
                example: json!("127.0.0.5"),
                default: None,
            },
        ]
    }

    fn group_name(&self) -> &'static str {
        "Routing"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let script = r#"import json, sys
data = json.load(sys.stdin)
event = data["event"]
if data["event_type_id"] == "ngap_ng_setup_request":
    plmn = event["global_ran_node_id"]["plmn"]
    actions = [{"type": "send_ng_setup_response", "amf_name": "netget-amf",
                "served_guami": [{"plmn": plmn, "amf_region_id": 2, "amf_set_id": 1, "amf_pointer": 0}],
                "plmn_support": [{"plmn": plmn, "slices": [{"sst": 1}]}]}]
elif data["event_type_id"] == "ngap_initial_ue_message":
    actions = [{"type": "send_downlink_nas_transport", "amf_ue_ngap_id": event["amf_ue_ngap_id"],
                "ran_ue_ngap_id": event["ran_ue_ngap_id"],
                "nas": {"message": "registration_reject", "cause": "illegal_ue"}}]
else:
    actions = []
print(json.dumps({"actions": actions}))"#;
        crate::llm::actions::StartupExamples::new(
            json!({
                "type": "open_server",
                "port": 38412,
                "base_stack": "ngap",
                "instruction": "Act as a 5G AMF for PLMN 001-01, slice SST 1. Admit gNBs that \
                                broadcast that PLMN; ask every registering UE for its identity, \
                                then reject it with illegal_ue.",
                "startup_params": {"transport": "sctp"}
            }),
            json!({
                "type": "open_server",
                "port": 38412,
                "base_stack": "ngap",
                "startup_params": {"transport": "sctp"},
                "event_handlers": [{
                    "event_pattern": "*",
                    "handler": {"type": "script", "language": "python", "code": script}
                }]
            }),
            json!({
                "type": "open_server",
                "port": 38412,
                "base_stack": "ngap",
                "startup_params": {"transport": "sctp"},
                "event_handlers": [{
                    "event_pattern": "ngap_ng_setup_request",
                    "handler": {"type": "static", "actions": [{
                        "type": "send_ng_setup_failure",
                        "cause": "misc/om-intervention",
                        "time_to_wait": "v60s"
                    }]}
                }]
            }),
        )
    }
}

impl Server for NgapProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            super::NgapServer::spawn_with_llm_actions(
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

    fn execute_action(&self, action: Value) -> Result<ActionResult> {
        let t = action
            .get("type")
            .and_then(Value::as_str)
            .context("Missing action type")?;
        match t {
            "send_ng_setup_response" => self.ng_setup_response(&action),
            "send_ng_setup_failure" => self.ng_setup_failure(&action),
            "send_downlink_nas_transport" => self.downlink_nas_transport(&action),
            "send_ue_context_release_command" => self.ue_context_release(&action),
            "send_error_indication" => self.error_indication(&action),
            "send_ng_reset" => self.ng_reset(&action),
            "send_registration_accept" => self.registration_accept(&action),
            "send_pdu_session_accept" => self.pdu_session_accept(&action),
            "send_pdu_session_reject" => self.pdu_session_reject(&action),
            "send_pdu_session_release" => self.pdu_session_release(&action),
            "send_pdu_session_release_reject" => self.pdu_session_release_reject(&action),
            "send_pdu_session_modification" => self.pdu_session_modification(&action),
            "send_pdu_session_modification_reject" => self.pdu_session_modification_reject(&action),
            "send_paging" => self.paging(&action),
            "wait_for_more" => Ok(ActionResult::WaitForMore),
            // Not offered to the model; the dashboard's "disconnect this peer" injects it.
            "close_connection" => Ok(ActionResult::CloseConnection),
            _ => Err(anyhow!("Unknown NGAP action type: {t}")),
        }
    }
}

//! 5GS session management (5GSM, TS 24.501 section 8.3): PDU Session Establishment, carried in a
//! 5GMM UL/DL NAS Transport. Shared by the AMF (which decodes the request for the model and
//! encodes its accept or reject) and the gNB's UE side (the reverse).
//!
//! A 5GSM message is the payload of a 5GMM container, never a container itself, so nothing here
//! calls back into the 5GMM decoder: the nesting is exactly one level and bounded by the
//! container's own length.

use super::nas::Snssai;
use serde_json::{json, Map, Value};
use std::net::Ipv4Addr;

pub const EPD_5GSM: u8 = 0x2e;

pub const PDU_SESSION_ESTABLISHMENT_REQUEST: u8 = 0xc1;
pub const PDU_SESSION_ESTABLISHMENT_ACCEPT: u8 = 0xc2;
pub const PDU_SESSION_ESTABLISHMENT_REJECT: u8 = 0xc3;
pub const PDU_SESSION_RELEASE_REQUEST: u8 = 0xd1;
pub const PDU_SESSION_RELEASE_COMMAND: u8 = 0xd3;
pub const PDU_SESSION_RELEASE_COMPLETE: u8 = 0xd4;
pub const FIVEGSM_STATUS: u8 = 0xd6;

pub fn message_name(t: u8) -> Option<&'static str> {
    Some(match t {
        0xc1 => "pdu_session_establishment_request",
        0xc2 => "pdu_session_establishment_accept",
        0xc3 => "pdu_session_establishment_reject",
        0xc5 => "pdu_session_authentication_command",
        0xc6 => "pdu_session_authentication_complete",
        0xc7 => "pdu_session_authentication_result",
        0xc9 => "pdu_session_modification_request",
        0xca => "pdu_session_modification_reject",
        0xcb => "pdu_session_modification_command",
        0xcc => "pdu_session_modification_complete",
        0xcd => "pdu_session_modification_command_reject",
        0xd1 => "pdu_session_release_request",
        0xd2 => "pdu_session_release_reject",
        0xd3 => "pdu_session_release_command",
        0xd4 => "pdu_session_release_complete",
        0xd6 => "5gsm_status",
        _ => return None,
    })
}

/// 5GSM causes (TS 24.501 9.11.4.2), by the names Annex B gives them.
pub const CAUSES: &[(&str, u8)] = &[
    ("operator_determined_barring", 8),
    ("insufficient_resources", 26),
    ("missing_or_unknown_dnn", 27),
    ("unknown_pdu_session_type", 28),
    ("user_authentication_or_authorization_failed", 29),
    ("request_rejected_unspecified", 31),
    ("service_option_not_supported", 32),
    ("requested_service_option_not_subscribed", 33),
    ("pti_already_in_use", 35),
    ("regular_deactivation", 36),
    ("network_failure", 38),
    ("reactivation_requested", 39),
    ("invalid_pdu_session_identity", 43),
    ("out_of_ladn_service_area", 46),
    ("pti_mismatch", 47),
    ("pdu_session_type_ipv4_only_allowed", 50),
    ("pdu_session_type_ipv6_only_allowed", 51),
    ("pdu_session_does_not_exist", 54),
    ("insufficient_resources_for_specific_slice_and_dnn", 67),
    ("not_supported_ssc_mode", 68),
    ("insufficient_resources_for_specific_slice", 69),
    ("missing_or_unknown_dnn_in_a_slice", 70),
    ("invalid_pti_value", 81),
    ("semantically_incorrect_message", 95),
    ("invalid_mandatory_information", 96),
    ("message_type_non_existent_or_not_implemented", 97),
    ("message_type_not_compatible_with_the_protocol_state", 98),
    ("information_element_non_existent_or_not_implemented", 99),
    ("conditional_ie_error", 100),
    ("message_not_compatible_with_the_protocol_state", 101),
    ("protocol_error_unspecified", 111),
];

pub const CAUSE_INSUFFICIENT_RESOURCES: u8 = 26;
pub const CAUSE_REQUEST_REJECTED_UNSPECIFIED: u8 = 31;
pub const CAUSE_NETWORK_FAILURE: u8 = 38;
pub const CAUSE_REGULAR_DEACTIVATION: u8 = 36;

pub fn cause_name(c: u8) -> String {
    CAUSES
        .iter()
        .find(|(_, v)| *v == c)
        .map(|(n, _)| n.to_string())
        .unwrap_or_else(|| format!("cause_{c}"))
}

/// A 5GSM cause by name or number; an undefined one is refused.
pub fn parse_cause(v: &Value) -> Result<u8, String> {
    match v {
        Value::Number(n) => {
            let n = n.as_u64().ok_or("cause must be a non-negative integer")?;
            CAUSES
                .iter()
                .find(|(_, c)| *c as u64 == n)
                .map(|(_, c)| *c)
                .ok_or_else(|| format!("5GSM cause {n} is not defined by TS 24.501"))
        }
        Value::String(s) => {
            let want = s.trim().to_ascii_lowercase().replace([' ', '-'], "_");
            CAUSES
                .iter()
                .find(|(n, _)| *n == want)
                .map(|(_, c)| *c)
                .ok_or_else(|| {
                    format!(
                        "5GSM cause {s:?} is not one of: {}",
                        CAUSES
                            .iter()
                            .map(|(n, _)| *n)
                            .collect::<Vec<_>>()
                            .join(", ")
                    )
                })
        }
        _ => Err("cause must be a 5GSM cause name such as \"missing_or_unknown_dnn\"".into()),
    }
}

pub const PDU_SESSION_TYPES: &[(&str, u8)] = &[
    ("ipv4", 1),
    ("ipv6", 2),
    ("ipv4v6", 3),
    ("unstructured", 4),
    ("ethernet", 5),
];

pub fn pdu_session_type_name(t: u8) -> &'static str {
    PDU_SESSION_TYPES
        .iter()
        .find(|(_, v)| *v == t)
        .map(|(n, _)| *n)
        .unwrap_or("reserved")
}

/// The header of any 5GSM message: `(psi, pti, message type)`.
pub fn header(b: &[u8]) -> Option<(u8, u8, u8)> {
    if b.len() < 4 || b[0] != EPD_5GSM {
        return None;
    }
    Some((b[1], b[2], b[3]))
}

/// PDU Session Establishment Request, the fields the AMF passes to the model.
#[derive(Debug, Clone)]
pub struct EstablishmentRequest {
    pub psi: u8,
    pub pti: u8,
    pub pdu_session_type: Option<u8>,
    pub ssc_mode: Option<u8>,
    pub integrity_max_rate: [u8; 2],
    pub optional_ies: Vec<String>,
}

pub fn parse_establishment_request(b: &[u8]) -> Result<EstablishmentRequest, String> {
    let (psi, pti, t) = header(b).ok_or("not a 5GSM message")?;
    if t != PDU_SESSION_ESTABLISHMENT_REQUEST {
        return Err(format!(
            "expected a PDU Session Establishment Request, got {}",
            message_name(t).unwrap_or("an unknown 5GSM message")
        ));
    }
    if b.len() < 6 {
        return Err("truncated integrity protection maximum data rate".into());
    }
    let mut r = EstablishmentRequest {
        psi,
        pti,
        pdu_session_type: None,
        ssc_mode: None,
        integrity_max_rate: [b[4], b[5]],
        optional_ies: Vec::new(),
    };
    let mut i = 6;
    let mut n = 0;
    while i < b.len() {
        n += 1;
        if n > 64 {
            return Err("more than 64 optional IEs".into());
        }
        let iei = b[i];
        i += 1;
        if iei & 0x80 != 0 {
            match iei >> 4 {
                0x9 => r.pdu_session_type = Some(iei & 0x07),
                0xA => r.ssc_mode = Some(iei & 0x07),
                0xB => r
                    .optional_ies
                    .push("always_on_pdu_session_requested".into()),
                _ => r.optional_ies.push(format!("iei_0x{:x}", iei >> 4)),
            }
            continue;
        }
        let len = match iei {
            // Maximum number of supported packet filters: TV, two octets of value.
            0x55 => 2,
            0x70..=0x7f => {
                let l = b.get(i..i + 2).ok_or("truncated TLV-E")?;
                i += 2;
                u16::from_be_bytes([l[0], l[1]]) as usize
            }
            _ => {
                let l = *b.get(i).ok_or("truncated TLV")? as usize;
                i += 1;
                l
            }
        };
        if b.len() - i < len {
            return Err(format!("IE 0x{iei:02x} declares {len} octets past the end"));
        }
        r.optional_ies.push(match iei {
            0x28 => "5gsm_capability".into(),
            0x55 => "maximum_number_of_supported_packet_filters".into(),
            0x39 => "sm_pdu_dn_request_container".into(),
            0x7b => "extended_protocol_configuration_options".into(),
            other => format!("iei_0x{other:02x}"),
        });
        i += len;
    }
    Ok(r)
}

/// PDU Session Establishment Request (UE side), IPv4, SSC mode 1.
pub fn establishment_request(psi: u8, pti: u8, pdu_session_type: u8, ssc_mode: u8) -> Vec<u8> {
    vec![
        EPD_5GSM,
        psi,
        pti,
        PDU_SESSION_ESTABLISHMENT_REQUEST,
        0xff,
        0xff,
        0x90 | (pdu_session_type & 0x07),
        0xA0 | (ssc_mode & 0x07),
    ]
}

/// Session-AMBR or a bit rate in kbps, encoded with the coarsest unit that keeps it in 16 bits
/// (TS 24.501 9.11.4.14: unit 1 = 1 kbps, each step ×4).
fn ambr_value(kbps: u64) -> (u8, u16) {
    let mut unit = 1u8;
    let mut v = kbps;
    while v > 0xFFFF && unit < 0x0B {
        v = v.div_ceil(4);
        unit += 1;
    }
    (unit, v.min(0xFFFF) as u16)
}

fn ambr_kbps(unit: u8, v: u16) -> u64 {
    if unit == 0 {
        return 0;
    }
    (v as u64) << (2 * (unit as u64 - 1).min(20))
}

/// What the AMF puts in a PDU Session Establishment Accept.
pub struct Accept {
    pub psi: u8,
    pub pti: u8,
    pub pdu_session_type: u8,
    pub ssc_mode: u8,
    pub qfi: u8,
    pub five_qi: u8,
    pub ambr_uplink_kbps: u64,
    pub ambr_downlink_kbps: u64,
    pub address: Ipv4Addr,
    pub s_nssai: Snssai,
    pub dnn: String,
}

/// PDU Session Establishment Accept (TS 24.501 8.3.2): one default QoS rule matching all
/// traffic on the session's QoS flow, its flow description with the 5QI, the session AMBR, the
/// IPv4 PDU address, the S-NSSAI and the DNN.
pub fn establishment_accept(a: &Accept) -> Result<Vec<u8>, String> {
    if a.qfi == 0 || a.qfi > 63 {
        return Err("qfi must be 1..63".into());
    }
    let mut out = vec![
        EPD_5GSM,
        a.psi,
        a.pti,
        PDU_SESSION_ESTABLISHMENT_ACCEPT,
        ((a.ssc_mode & 0x07) << 4) | (a.pdu_session_type & 0x07),
    ];
    // Authorized QoS rules: rule 1, create (001), DQR, one packet filter (bidirectional,
    // match-all), precedence 255, the flow's QFI.
    let rule = [0x31, 0x31, 0x01, 0x01, 0xff, a.qfi & 0x3F];
    let mut rules = vec![0x01];
    rules.extend_from_slice(&(rule.len() as u16).to_be_bytes());
    rules.extend_from_slice(&rule);
    out.extend_from_slice(&(rules.len() as u16).to_be_bytes());
    out.extend_from_slice(&rules);
    let (dl_unit, dl) = ambr_value(a.ambr_downlink_kbps);
    let (ul_unit, ul) = ambr_value(a.ambr_uplink_kbps);
    out.push(6);
    out.push(dl_unit);
    out.extend_from_slice(&dl.to_be_bytes());
    out.push(ul_unit);
    out.extend_from_slice(&ul.to_be_bytes());
    // PDU address: IPv4.
    out.extend_from_slice(&[0x29, 5, 0x01]);
    out.extend_from_slice(&a.address.octets());
    let sn = a.s_nssai.octets();
    out.push(0x22);
    out.push(sn.len() as u8);
    out.extend_from_slice(&sn);
    // Authorized QoS flow descriptions: QFI, create (001), E=1 with one parameter: 5QI.
    let fd = [a.qfi & 0x3F, 0x20, 0x41, 0x01, 0x01, a.five_qi];
    out.push(0x79);
    out.extend_from_slice(&(fd.len() as u16).to_be_bytes());
    out.extend_from_slice(&fd);
    let apn = crate::server::gtp::codec::encode_apn(&a.dnn).map_err(|e| e.to_string())?;
    if apn.is_empty() || apn.len() > 100 {
        return Err("dnn must encode to 1..100 octets".into());
    }
    out.push(0x25);
    out.push(apn.len() as u8);
    out.extend_from_slice(&apn);
    Ok(out)
}

pub fn establishment_reject(psi: u8, pti: u8, cause: u8) -> Vec<u8> {
    vec![EPD_5GSM, psi, pti, PDU_SESSION_ESTABLISHMENT_REJECT, cause]
}

/// The UE's reading of an accept.
#[derive(Debug, Clone)]
pub struct ParsedAccept {
    pub psi: u8,
    pub pti: u8,
    pub pdu_session_type: u8,
    pub ssc_mode: u8,
    pub address: Option<Ipv4Addr>,
    pub ambr_uplink_kbps: u64,
    pub ambr_downlink_kbps: u64,
    pub qfis: Vec<u8>,
    pub s_nssai: Option<Snssai>,
    pub dnn: Option<String>,
}

pub fn parse_establishment_accept(b: &[u8]) -> Result<ParsedAccept, String> {
    let (psi, pti, t) = header(b).ok_or("not a 5GSM message")?;
    if t != PDU_SESSION_ESTABLISHMENT_ACCEPT {
        return Err("not a PDU Session Establishment Accept".into());
    }
    let mut i = 4;
    let o = *b.get(i).ok_or("truncated")?;
    i += 1;
    let rl = b.get(i..i + 2).ok_or("truncated QoS rules length")?;
    let rules_len = u16::from_be_bytes([rl[0], rl[1]]) as usize;
    i += 2;
    let rules = b.get(i..i + rules_len).ok_or("QoS rules past the end")?;
    i += rules_len;
    // Each rule: id, 2-octet length, contents whose last octet carries the QFI.
    let mut qfis = Vec::new();
    let mut j = 0;
    while j + 3 <= rules.len() && qfis.len() < 16 {
        let len = u16::from_be_bytes([rules[j + 1], rules[j + 2]]) as usize;
        let Some(body) = rules.get(j + 3..j + 3 + len) else {
            break;
        };
        if let Some(q) = body.last() {
            qfis.push(q & 0x3F);
        }
        j += 3 + len;
    }
    let al = *b.get(i).ok_or("truncated session AMBR")? as usize;
    let ambr = b
        .get(i + 1..i + 1 + al)
        .ok_or("session AMBR past the end")?;
    i += 1 + al;
    let (dl, ul) = if ambr.len() >= 6 {
        (
            ambr_kbps(ambr[0], u16::from_be_bytes([ambr[1], ambr[2]])),
            ambr_kbps(ambr[3], u16::from_be_bytes([ambr[4], ambr[5]])),
        )
    } else {
        (0, 0)
    };
    let mut out = ParsedAccept {
        psi,
        pti,
        pdu_session_type: o & 0x07,
        ssc_mode: (o >> 4) & 0x07,
        address: None,
        ambr_uplink_kbps: ul,
        ambr_downlink_kbps: dl,
        qfis,
        s_nssai: None,
        dnn: None,
    };
    let mut n = 0;
    while i < b.len() {
        n += 1;
        if n > 64 {
            return Err("more than 64 optional IEs".into());
        }
        let iei = b[i];
        i += 1;
        if iei & 0x80 != 0 {
            continue;
        }
        let len = match iei {
            0x59 | 0x56 => 1,
            0x70..=0x7f => {
                let l = b.get(i..i + 2).ok_or("truncated TLV-E")?;
                i += 2;
                u16::from_be_bytes([l[0], l[1]]) as usize
            }
            _ => {
                let l = *b.get(i).ok_or("truncated TLV")? as usize;
                i += 1;
                l
            }
        };
        let v = b.get(i..i + len).ok_or("IE past the end")?;
        match iei {
            0x29 if v.len() == 5 && v[0] & 0x07 == 1 => {
                out.address = Some(Ipv4Addr::new(v[1], v[2], v[3], v[4]))
            }
            0x22 => out.s_nssai = Snssai::parse(v).ok(),
            0x25 => out.dnn = crate::server::gtp::codec::decode_apn(v),
            _ => {}
        }
        i += len;
    }
    Ok(out)
}

/// A 5GSM message for the model: the header and, for the messages NetGet acts on, their fields.
/// Never fails; what does not parse is reported with its reason.
pub fn decode(b: &[u8]) -> Value {
    let Some((psi, pti, t)) = header(b) else {
        return json!({"epd": "5gsm", "decoded": false, "error": "truncated 5GSM header", "length": b.len()});
    };
    let mut v = Map::new();
    v.insert("epd".into(), json!("5gsm"));
    v.insert("pdu_session_id".into(), json!(psi));
    v.insert("pti".into(), json!(pti));
    v.insert(
        "message".into(),
        json!(message_name(t)
            .map(str::to_string)
            .unwrap_or(format!("0x{t:02x}"))),
    );
    match t {
        PDU_SESSION_ESTABLISHMENT_REQUEST => match parse_establishment_request(b) {
            Ok(r) => {
                v.insert(
                    "pdu_session_type".into(),
                    json!(r.pdu_session_type.map(pdu_session_type_name)),
                );
                v.insert("ssc_mode".into(), json!(r.ssc_mode));
                v.insert("optional_ies".into(), json!(r.optional_ies));
            }
            Err(e) => {
                v.insert("error".into(), json!(e));
            }
        },
        PDU_SESSION_ESTABLISHMENT_ACCEPT => match parse_establishment_accept(b) {
            Ok(a) => {
                v.insert(
                    "pdu_session_type".into(),
                    json!(pdu_session_type_name(a.pdu_session_type)),
                );
                v.insert("ue_ipv4".into(), json!(a.address.map(|x| x.to_string())));
                v.insert("qfis".into(), json!(a.qfis));
                v.insert(
                    "session_ambr_kbps".into(),
                    json!({"uplink": a.ambr_uplink_kbps, "downlink": a.ambr_downlink_kbps}),
                );
                v.insert("s_nssai".into(), json!(a.s_nssai.map(|s| s.to_json())));
                v.insert("dnn".into(), json!(a.dnn));
            }
            Err(e) => {
                v.insert("error".into(), json!(e));
            }
        },
        PDU_SESSION_ESTABLISHMENT_REJECT | FIVEGSM_STATUS | PDU_SESSION_RELEASE_COMMAND => {
            if let Some(c) = b.get(4) {
                v.insert("cause".into(), json!({"value": c, "name": cause_name(*c)}));
            }
        }
        _ => {
            v.insert("body_length".into(), json!(b.len() - 4));
        }
    }
    Value::Object(v)
}

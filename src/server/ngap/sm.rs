//! 5GS session management (5GSM, TS 24.501 section 8.3): PDU Session Establishment,
//! Modification and Release, carried in a 5GMM UL/DL NAS Transport. Shared by the AMF (which
//! decodes the UE's requests for the model and encodes its answers) and the gNB's UE side (the
//! reverse).
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
pub const PDU_SESSION_MODIFICATION_REQUEST: u8 = 0xc9;
pub const PDU_SESSION_MODIFICATION_REJECT: u8 = 0xca;
pub const PDU_SESSION_MODIFICATION_COMMAND: u8 = 0xcb;
pub const PDU_SESSION_MODIFICATION_COMPLETE: u8 = 0xcc;
pub const PDU_SESSION_MODIFICATION_COMMAND_REJECT: u8 = 0xcd;
pub const PDU_SESSION_RELEASE_REQUEST: u8 = 0xd1;
pub const PDU_SESSION_RELEASE_REJECT: u8 = 0xd2;
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

/// The PDU address a session carries (TS 24.501 9.11.4.10): an IPv4 address, an IPv6 interface
/// identifier (the UE builds its link-local and global addresses from it; the prefix comes in a
/// Router Advertisement on the user plane), or both.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PduAddress {
    V4(Ipv4Addr),
    V6 { iid: [u8; 8] },
    V4V6 { iid: [u8; 8], v4: Ipv4Addr },
}

impl PduAddress {
    /// The PDU session type this address belongs to (1 IPv4, 2 IPv6, 3 IPv4v6).
    pub fn session_type(&self) -> u8 {
        match self {
            PduAddress::V4(_) => 1,
            PduAddress::V6 { .. } => 2,
            PduAddress::V4V6 { .. } => 3,
        }
    }

    pub fn ipv4(&self) -> Option<Ipv4Addr> {
        match self {
            PduAddress::V4(a) | PduAddress::V4V6 { v4: a, .. } => Some(*a),
            PduAddress::V6 { .. } => None,
        }
    }

    pub fn iid(&self) -> Option<[u8; 8]> {
        match self {
            PduAddress::V6 { iid } | PduAddress::V4V6 { iid, .. } => Some(*iid),
            PduAddress::V4(_) => None,
        }
    }

    /// The IE value: the type octet, then the IID and/or the IPv4 address.
    pub fn octets(&self) -> Vec<u8> {
        let mut v = vec![self.session_type()];
        if let Some(iid) = self.iid() {
            v.extend_from_slice(&iid);
        }
        if let Some(a) = self.ipv4() {
            v.extend_from_slice(&a.octets());
        }
        v
    }

    pub fn parse(v: &[u8]) -> Option<PduAddress> {
        let iid = |r: &[u8]| -> Option<[u8; 8]> { r.try_into().ok() };
        match (v.first().map(|t| t & 0x07), v.len()) {
            (Some(1), 5) => Some(PduAddress::V4(Ipv4Addr::new(v[1], v[2], v[3], v[4]))),
            (Some(2), 9) => Some(PduAddress::V6 { iid: iid(&v[1..9])? }),
            (Some(3), 13) => Some(PduAddress::V4V6 {
                iid: iid(&v[1..9])?,
                v4: Ipv4Addr::new(v[9], v[10], v[11], v[12]),
            }),
            _ => None,
        }
    }
}

/// An IPv6 interface identifier written as the low half of an IPv6 address (`"::2"`,
/// `"::1:2:3:4"`) or as 16 hex digits.
pub fn parse_iid(s: &str) -> Result<[u8; 8], String> {
    let s = s.trim();
    if s.len() == 16 && s.chars().all(|c| c.is_ascii_hexdigit()) {
        let raw = hex::decode(s).map_err(|_| "interface identifier must be hex".to_string())?;
        return raw
            .try_into()
            .map_err(|_| "interface identifier is 8 octets".to_string());
    }
    let full = if s.starts_with("::") {
        s.to_string()
    } else {
        format!("::{s}")
    };
    let a: std::net::Ipv6Addr = full.parse().map_err(|_| {
        format!("{s:?} is not an interface identifier (e.g. \"::2\" or 16 hex digits)")
    })?;
    if a.octets()[..8] != [0u8; 8] {
        return Err(format!(
            "{s:?} is longer than an interface identifier (64 bits)"
        ));
    }
    let mut iid = [0u8; 8];
    iid.copy_from_slice(&a.octets()[8..16]);
    Ok(iid)
}

/// An interface identifier as the low 64 bits of an IPv6 address: `::a:b:c:d`.
pub fn iid_string(iid: &[u8; 8]) -> String {
    let mut o = [0u8; 16];
    o[8..].copy_from_slice(iid);
    std::net::Ipv6Addr::from(o).to_string()
}

/// What the AMF puts in a PDU Session Establishment Accept.
pub struct Accept {
    pub psi: u8,
    pub pti: u8,
    pub ssc_mode: u8,
    pub qfi: u8,
    pub five_qi: u8,
    pub ambr_uplink_kbps: u64,
    pub ambr_downlink_kbps: u64,
    pub address: PduAddress,
    pub s_nssai: Snssai,
    pub dnn: String,
}

/// Session-AMBR (TS 24.501 9.11.4.14) as its six value octets.
fn ambr_octets(downlink_kbps: u64, uplink_kbps: u64) -> [u8; 6] {
    let (dl_unit, dl) = ambr_value(downlink_kbps);
    let (ul_unit, ul) = ambr_value(uplink_kbps);
    let dl = dl.to_be_bytes();
    let ul = ul.to_be_bytes();
    [dl_unit, dl[0], dl[1], ul_unit, ul[0], ul[1]]
}

/// QoS rule operation codes (TS 24.501 9.11.4.13, bits 8-6 of the rule's third octet).
const RULE_CREATE: u8 = 0b001;
const RULE_MODIFY_KEEP_FILTERS: u8 = 0b110;
/// QoS flow description operation codes (9.11.4.12, bits 8-6 of the second octet).
const FLOW_CREATE: u8 = 0b001;
const FLOW_MODIFY: u8 = 0b011;

/// The default QoS rule (rule 1, DQR) on `qfi`: created with one match-all packet filter, or
/// restated with its packet filters left as they are.
fn default_rule(op: u8, precedence: u8, qfi: u8) -> Vec<u8> {
    let body: Vec<u8> = if op == RULE_CREATE {
        // DQR, one packet filter: bidirectional (11), id 1, one component "match-all" (0x01).
        vec![(op << 5) | 0x10 | 0x01, 0x31, 0x01, 0x01, precedence, qfi & 0x3F]
    } else {
        vec![(op << 5) | 0x10, precedence, qfi & 0x3F]
    };
    let mut rules = vec![0x01];
    rules.extend_from_slice(&(body.len() as u16).to_be_bytes());
    rules.extend_from_slice(&body);
    rules
}

/// One QoS flow description carrying a 5QI (parameter identifier 1).
fn flow_description(op: u8, qfi: u8, five_qi: u8) -> [u8; 6] {
    [qfi & 0x3F, op << 5, 0x41, 0x01, 0x01, five_qi]
}

/// PDU Session Establishment Accept (TS 24.501 8.3.2): one default QoS rule matching all
/// traffic on the session's QoS flow, its flow description with the 5QI, the session AMBR, the
/// PDU address (IPv4, an IPv6 interface identifier, or both), the S-NSSAI and the DNN.
pub fn establishment_accept(a: &Accept) -> Result<Vec<u8>, String> {
    if a.qfi == 0 || a.qfi > 63 {
        return Err("qfi must be 1..63".into());
    }
    let mut out = vec![
        EPD_5GSM,
        a.psi,
        a.pti,
        PDU_SESSION_ESTABLISHMENT_ACCEPT,
        ((a.ssc_mode & 0x07) << 4) | a.address.session_type(),
    ];
    // Authorized QoS rules: rule 1, create, DQR, one bidirectional match-all packet filter,
    // precedence 255, the flow's QFI.
    let rules = default_rule(RULE_CREATE, 0xff, a.qfi);
    out.extend_from_slice(&(rules.len() as u16).to_be_bytes());
    out.extend_from_slice(&rules);
    out.push(6);
    out.extend_from_slice(&ambr_octets(a.ambr_downlink_kbps, a.ambr_uplink_kbps));
    let addr = a.address.octets();
    out.push(0x29);
    out.push(addr.len() as u8);
    out.extend_from_slice(&addr);
    let sn = a.s_nssai.octets();
    out.push(0x22);
    out.push(sn.len() as u8);
    out.extend_from_slice(&sn);
    // Authorized QoS flow descriptions: the flow, created, with its 5QI.
    let fd = flow_description(FLOW_CREATE, a.qfi, a.five_qi);
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

// ============================================================================
// Release (TS 24.501 8.3.12-8.3.15) and modification (8.3.7-8.3.11)
// ============================================================================

/// The optional 5GSM cause of a Release Request or Release Complete (IEI 0x59, TV).
const IEI_CAUSE: u8 = 0x59;
const IEI_SESSION_AMBR: u8 = 0x2a;
const IEI_QOS_RULES: u8 = 0x7a;
const IEI_QOS_FLOW_DESCRIPTIONS: u8 = 0x79;

/// PDU Session Release Request (UE): the optional cause the UE gives, usually #36 regular
/// deactivation.
pub fn release_request(psi: u8, pti: u8, cause: Option<u8>) -> Vec<u8> {
    let mut v = vec![EPD_5GSM, psi, pti, PDU_SESSION_RELEASE_REQUEST];
    if let Some(c) = cause {
        v.extend_from_slice(&[IEI_CAUSE, c]);
    }
    v
}

/// PDU Session Release Command (network), with its mandatory cause.
pub fn release_command(psi: u8, pti: u8, cause: u8) -> Vec<u8> {
    vec![EPD_5GSM, psi, pti, PDU_SESSION_RELEASE_COMMAND, cause]
}

/// PDU Session Release Reject (network): the UE's request refused with a cause.
pub fn release_reject(psi: u8, pti: u8, cause: u8) -> Vec<u8> {
    vec![EPD_5GSM, psi, pti, PDU_SESSION_RELEASE_REJECT, cause]
}

/// PDU Session Release Complete (UE).
pub fn release_complete(psi: u8, pti: u8) -> Vec<u8> {
    vec![EPD_5GSM, psi, pti, PDU_SESSION_RELEASE_COMPLETE]
}

/// PDU Session Modification Reject (network).
pub fn modification_reject(psi: u8, pti: u8, cause: u8) -> Vec<u8> {
    vec![EPD_5GSM, psi, pti, PDU_SESSION_MODIFICATION_REJECT, cause]
}

/// PDU Session Modification Complete (UE).
pub fn modification_complete(psi: u8, pti: u8) -> Vec<u8> {
    vec![EPD_5GSM, psi, pti, PDU_SESSION_MODIFICATION_COMPLETE]
}

/// PDU Session Modification Command Reject (UE).
pub fn modification_command_reject(psi: u8, pti: u8, cause: u8) -> Vec<u8> {
    vec![
        EPD_5GSM,
        psi,
        pti,
        PDU_SESSION_MODIFICATION_COMMAND_REJECT,
        cause,
    ]
}

/// PDU Session Modification Request (UE): what NetGet's UE asks for — a new 5QI for the session's
/// default flow, as a requested QoS flow description, and an optional cause.
pub fn modification_request(psi: u8, pti: u8, qfi: u8, five_qi: Option<u8>) -> Vec<u8> {
    let mut v = vec![EPD_5GSM, psi, pti, PDU_SESSION_MODIFICATION_REQUEST];
    if let Some(q) = five_qi {
        let fd = flow_description(FLOW_MODIFY, qfi, q);
        v.push(IEI_QOS_FLOW_DESCRIPTIONS);
        v.extend_from_slice(&(fd.len() as u16).to_be_bytes());
        v.extend_from_slice(&fd);
    }
    v
}

/// What the network changes in a PDU Session Modification Command: the session AMBR and/or the
/// default QoS rule's flow (its precedence restated, its 5QI changed).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Modification {
    pub ambr_uplink_kbps: Option<u64>,
    pub ambr_downlink_kbps: Option<u64>,
    /// `(QFI, 5QI)` of the default flow when its 5QI changes.
    pub flow_five_qi: Option<(u8, u8)>,
    pub cause: Option<u8>,
}

/// PDU Session Modification Command (network).
pub fn modification_command(psi: u8, pti: u8, m: &Modification) -> Result<Vec<u8>, String> {
    let mut v = vec![EPD_5GSM, psi, pti, PDU_SESSION_MODIFICATION_COMMAND];
    if let Some(c) = m.cause {
        v.extend_from_slice(&[IEI_CAUSE, c]);
    }
    match (m.ambr_downlink_kbps, m.ambr_uplink_kbps) {
        (Some(dl), Some(ul)) => {
            v.extend_from_slice(&[IEI_SESSION_AMBR, 6]);
            v.extend_from_slice(&ambr_octets(dl, ul));
        }
        (None, None) => {}
        _ => return Err("session AMBR needs both directions".into()),
    }
    if let Some((qfi, five_qi)) = m.flow_five_qi {
        if qfi == 0 || qfi > 63 {
            return Err("qfi must be 1..63".into());
        }
        let rules = default_rule(RULE_MODIFY_KEEP_FILTERS, 0xff, qfi);
        v.push(IEI_QOS_RULES);
        v.extend_from_slice(&(rules.len() as u16).to_be_bytes());
        v.extend_from_slice(&rules);
        let fd = flow_description(FLOW_MODIFY, qfi, five_qi);
        v.push(IEI_QOS_FLOW_DESCRIPTIONS);
        v.extend_from_slice(&(fd.len() as u16).to_be_bytes());
        v.extend_from_slice(&fd);
    }
    if v.len() == 4 {
        return Err("a modification command must change something".into());
    }
    Ok(v)
}

/// The fields of any 5GSM release or modification message NetGet reads: the header, the cause
/// (mandatory in the commands and rejects, optional elsewhere), and for modification the session
/// AMBR and 5QI the message names, plus the IEIs it carried.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SmProcedure {
    pub psi: u8,
    pub pti: u8,
    pub message_type: u8,
    pub cause: Option<u8>,
    pub ambr_uplink_kbps: Option<u64>,
    pub ambr_downlink_kbps: Option<u64>,
    /// `(QFI, 5QI)` from the first QoS flow description that carries a 5QI.
    pub flow_five_qi: Option<(u8, u8)>,
    pub optional_ies: Vec<String>,
}

/// Parse a release or modification message (any of 0xc9-0xcd, 0xd1-0xd4) with its optional IEs.
/// Bounded: at most 64 optional IEs, each by its own length.
pub fn parse_procedure(b: &[u8]) -> Result<SmProcedure, String> {
    let (psi, pti, t) = header(b).ok_or("not a 5GSM message")?;
    let mandatory_cause = matches!(
        t,
        PDU_SESSION_MODIFICATION_REJECT
            | PDU_SESSION_MODIFICATION_COMMAND_REJECT
            | PDU_SESSION_RELEASE_REJECT
            | PDU_SESSION_RELEASE_COMMAND
    );
    let optional_cause = matches!(
        t,
        PDU_SESSION_MODIFICATION_REQUEST
            | PDU_SESSION_MODIFICATION_COMMAND
            | PDU_SESSION_RELEASE_REQUEST
            | PDU_SESSION_RELEASE_COMPLETE
    );
    if !mandatory_cause && !optional_cause && t != PDU_SESSION_MODIFICATION_COMPLETE {
        return Err(format!(
            "{} is not a release or modification message",
            message_name(t).unwrap_or("an unknown 5GSM message")
        ));
    }
    let mut out = SmProcedure {
        psi,
        pti,
        message_type: t,
        ..Default::default()
    };
    let mut i = 4;
    if mandatory_cause {
        out.cause = Some(*b.get(4).ok_or("truncated 5GSM cause")?);
        i = 5;
    }
    let mut n = 0;
    while i < b.len() {
        n += 1;
        if n > 64 {
            return Err("more than 64 optional IEs".into());
        }
        let iei = b[i];
        i += 1;
        if iei & 0x80 != 0 {
            // Type 1 (half-octet) IEs: always-on indication and the like.
            out.optional_ies.push(format!("iei_0x{:x}", iei >> 4));
            continue;
        }
        let len = match iei {
            // TV, one octet of value.
            IEI_CAUSE | 0x56 | 0x61 => 1,
            // Maximum number of supported packet filters and integrity protection maximum data
            // rate: TV, two octets of value.
            0x55 | 0x13 => 2,
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
        let v = b
            .get(i..i + len)
            .ok_or_else(|| format!("IE 0x{iei:02x} declares {len} octets past the end"))?;
        match iei {
            IEI_CAUSE => out.cause = v.first().copied(),
            IEI_SESSION_AMBR if v.len() >= 6 => {
                out.ambr_downlink_kbps = Some(ambr_kbps(v[0], u16::from_be_bytes([v[1], v[2]])));
                out.ambr_uplink_kbps = Some(ambr_kbps(v[3], u16::from_be_bytes([v[4], v[5]])));
            }
            IEI_QOS_FLOW_DESCRIPTIONS if out.flow_five_qi.is_none() => {
                out.flow_five_qi = first_five_qi(v);
            }
            _ => {}
        }
        out.optional_ies.push(match iei {
            IEI_CAUSE => "5gsm_cause".into(),
            IEI_SESSION_AMBR => "session_ambr".into(),
            IEI_QOS_RULES => "qos_rules".into(),
            IEI_QOS_FLOW_DESCRIPTIONS => "qos_flow_descriptions".into(),
            0x28 => "5gsm_capability".into(),
            0x75 => "mapped_eps_bearer_contexts".into(),
            0x7b => "extended_protocol_configuration_options".into(),
            0x37 => "back_off_timer".into(),
            other => format!("iei_0x{other:02x}"),
        });
        i += len;
    }
    Ok(out)
}

/// The first `(QFI, 5QI)` in a QoS flow descriptions value: each description is QFI, operation
/// code, then E|number of parameters and that many `(id, length, value)` parameters. Bounded by
/// the value's own length; at most 64 descriptions and 16 parameters each are looked at.
fn first_five_qi(v: &[u8]) -> Option<(u8, u8)> {
    let mut i = 0;
    for _ in 0..64 {
        let qfi = *v.get(i)? & 0x3F;
        let count = (*v.get(i + 2)? & 0x3F) as usize;
        i += 3;
        for _ in 0..count.min(16) {
            let id = *v.get(i)?;
            let len = *v.get(i + 1)? as usize;
            let val = v.get(i + 2..i + 2 + len)?;
            if id == 0x01 && len == 1 {
                return Some((qfi, val[0]));
            }
            i += 2 + len;
        }
        if i >= v.len() {
            return None;
        }
    }
    None
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
    /// The IPv6 interface identifier of an IPv6 or IPv4v6 session.
    pub ipv6_iid: Option<[u8; 8]>,
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
        ipv6_iid: None,
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
            0x29 => {
                if let Some(a) = PduAddress::parse(v) {
                    out.address = a.ipv4();
                    out.ipv6_iid = a.iid();
                }
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
                v.insert(
                    "ue_ipv6_interface_identifier".into(),
                    json!(a.ipv6_iid.as_ref().map(iid_string)),
                );
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
        PDU_SESSION_ESTABLISHMENT_REJECT | FIVEGSM_STATUS => {
            if let Some(c) = b.get(4) {
                v.insert("cause".into(), json!({"value": c, "name": cause_name(*c)}));
            }
        }
        PDU_SESSION_MODIFICATION_REQUEST..=PDU_SESSION_MODIFICATION_COMMAND_REJECT
        | PDU_SESSION_RELEASE_REQUEST..=PDU_SESSION_RELEASE_COMPLETE => match parse_procedure(b) {
            Ok(p) => {
                if let Some(c) = p.cause {
                    v.insert("cause".into(), json!({"value": c, "name": cause_name(c)}));
                }
                if let (Some(ul), Some(dl)) = (p.ambr_uplink_kbps, p.ambr_downlink_kbps) {
                    v.insert(
                        "session_ambr_kbps".into(),
                        json!({"uplink": ul, "downlink": dl}),
                    );
                }
                if let Some((qfi, five_qi)) = p.flow_five_qi {
                    v.insert("qfi".into(), json!(qfi));
                    v.insert("five_qi".into(), json!(five_qi));
                }
                v.insert("optional_ies".into(), json!(p.optional_ies));
            }
            Err(e) => {
                v.insert("error".into(), json!(e));
            }
        },
        _ => {
            v.insert("body_length".into(), json!(b.len() - 4));
        }
    }
    Value::Object(v)
}

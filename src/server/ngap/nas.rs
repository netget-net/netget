//! 5GS mobility management (5GMM, TS 24.501) — the plain-NAS subset NGAP carries during initial
//! registration.
//!
//! NAS is opaque to NGAP: a NAS-PDU IE is just octets. NetGet decodes the 5GMM messages that cross
//! N2 before a NAS security context exists, so the model sees *what the UE asked for* —
//! registration type, the SUCI's PLMN, routing indicator and protection scheme, the 5GMM cause of
//! a failure — instead of a hex string, and answers with a structured action that Rust encodes.
//!
//! # What is out of scope, and why
//!
//! **NAS security.** 5G-AKA (deriving RES*, K_AUSF, K_SEAF, K_AMF), Security Mode Command and
//! integrity/ciphering of later messages are not implemented. Without them a UE accepts only the
//! messages TS 24.501 section 4.4.4.2 lists as processable before security is established —
//! Identity Request, Authentication Request/Reject, Registration Reject, Service Reject,
//! Deregistration Accept — which is exactly the set [`encode`] offers the AMF. An Authentication
//! Request NetGet sends carries a RAND and AUTN the model chooses (random by default); a real UE
//! computes the expected MAC from its own key, finds it does not match, and answers with
//! Authentication Failure #20 (MAC failure). That round trip is real and is what the tests prove;
//! a *successful* authentication is not available without the subscriber key and the AKA
//! derivations.
//!
//! A security-protected message is reported with its header fields; when it is integrity
//! protected but not ciphered, the plain message inside is decoded too, because its octets are in
//! the clear. The MAC is not verified — there is no key to verify it with — and the event says so.

use serde_json::{json, Map, Value};

/// Extended protocol discriminator for 5GMM (TS 24.007 section 11.2.3.1.1A).
pub const EPD_5GMM: u8 = 0x7e;
/// Extended protocol discriminator for 5GSM.
pub const EPD_5GSM: u8 = 0x2e;

pub const REGISTRATION_REQUEST: u8 = 0x41;
pub const REGISTRATION_ACCEPT: u8 = 0x42;
pub const REGISTRATION_COMPLETE: u8 = 0x43;
pub const REGISTRATION_REJECT: u8 = 0x44;
pub const DEREGISTRATION_REQUEST_UE_ORIGINATING: u8 = 0x45;
pub const DEREGISTRATION_ACCEPT_UE_ORIGINATING: u8 = 0x46;
pub const SERVICE_REQUEST: u8 = 0x4c;
pub const SERVICE_REJECT: u8 = 0x4d;
pub const AUTHENTICATION_REQUEST: u8 = 0x56;
pub const AUTHENTICATION_RESPONSE: u8 = 0x57;
pub const AUTHENTICATION_REJECT: u8 = 0x58;
pub const AUTHENTICATION_FAILURE: u8 = 0x59;
pub const IDENTITY_REQUEST: u8 = 0x5b;
pub const IDENTITY_RESPONSE: u8 = 0x5c;
pub const SECURITY_MODE_COMMAND: u8 = 0x5d;
pub const SECURITY_MODE_COMPLETE: u8 = 0x5e;
pub const SECURITY_MODE_REJECT: u8 = 0x5f;
pub const FIVEGMM_STATUS: u8 = 0x64;

pub fn message_name(t: u8) -> Option<&'static str> {
    Some(match t {
        0x41 => "registration_request",
        0x42 => "registration_accept",
        0x43 => "registration_complete",
        0x44 => "registration_reject",
        0x45 => "deregistration_request_ue_originating",
        0x46 => "deregistration_accept_ue_originating",
        0x47 => "deregistration_request_ue_terminated",
        0x48 => "deregistration_accept_ue_terminated",
        0x4c => "service_request",
        0x4d => "service_reject",
        0x4e => "service_accept",
        0x54 => "configuration_update_command",
        0x55 => "configuration_update_complete",
        0x56 => "authentication_request",
        0x57 => "authentication_response",
        0x58 => "authentication_reject",
        0x59 => "authentication_failure",
        0x5a => "authentication_result",
        0x5b => "identity_request",
        0x5c => "identity_response",
        0x5d => "security_mode_command",
        0x5e => "security_mode_complete",
        0x5f => "security_mode_reject",
        0x64 => "5gmm_status",
        0x65 => "notification",
        0x66 => "notification_response",
        0x67 => "ul_nas_transport",
        0x68 => "dl_nas_transport",
        _ => return None,
    })
}

/// 5GMM causes (TS 24.501 section 9.11.3.2), by the names Annex A gives them.
pub const CAUSES: &[(&str, u8)] = &[
    ("illegal_ue", 3),
    ("pei_not_accepted", 5),
    ("illegal_me", 6),
    ("5gs_services_not_allowed", 7),
    ("ue_identity_cannot_be_derived_by_the_network", 9),
    ("implicitly_deregistered", 10),
    ("plmn_not_allowed", 11),
    ("tracking_area_not_allowed", 12),
    ("roaming_not_allowed_in_this_tracking_area", 13),
    ("no_suitable_cells_in_tracking_area", 15),
    ("mac_failure", 20),
    ("synch_failure", 21),
    ("congestion", 22),
    ("ue_security_capabilities_mismatch", 23),
    ("security_mode_rejected_unspecified", 24),
    ("non_5g_authentication_unacceptable", 26),
    ("n1_mode_not_allowed", 27),
    ("restricted_service_area", 28),
    ("redirection_to_epc_required", 31),
    ("ladn_not_available", 43),
    ("no_network_slices_available", 62),
    ("maximum_number_of_pdu_sessions_reached", 65),
    ("insufficient_resources_for_specific_slice_and_dnn", 67),
    ("insufficient_resources_for_specific_slice", 69),
    ("ngksi_already_in_use", 71),
    ("non_3gpp_access_to_5gcn_not_allowed", 72),
    ("serving_network_not_authorized", 73),
    ("temporarily_not_authorized_for_this_snpn", 74),
    ("permanently_not_authorized_for_this_snpn", 75),
    (
        "not_authorized_for_this_cag_or_authorized_for_cag_cells_only",
        76,
    ),
    ("wireline_access_area_not_allowed", 77),
    ("payload_was_not_forwarded", 90),
    ("dnn_not_supported_or_not_subscribed_in_the_slice", 91),
    ("insufficient_user_plane_resources_for_the_pdu_session", 92),
    ("semantically_incorrect_message", 95),
    ("invalid_mandatory_information", 96),
    ("message_type_non_existent_or_not_implemented", 97),
    ("message_type_not_compatible_with_the_protocol_state", 98),
    ("information_element_non_existent_or_not_implemented", 99),
    ("conditional_ie_error", 100),
    ("message_not_compatible_with_the_protocol_state", 101),
    ("protocol_error_unspecified", 111),
];

pub const CAUSE_ILLEGAL_UE: u8 = 3;
pub const CAUSE_MAC_FAILURE: u8 = 20;
pub const CAUSE_CONGESTION: u8 = 22;
pub const CAUSE_PROTOCOL_ERROR_UNSPECIFIED: u8 = 111;

pub fn cause_name(c: u8) -> String {
    CAUSES
        .iter()
        .find(|(_, v)| *v == c)
        .map(|(n, _)| n.to_string())
        .unwrap_or_else(|| format!("cause_{c}"))
}

fn cause_json(c: u8) -> Value {
    json!({"value": c, "name": cause_name(c)})
}

/// A 5GMM cause by name or number. Undefined numbers are refused rather than put on the wire.
pub fn parse_cause(v: &Value) -> Result<u8, String> {
    // `{"name": …}` / `{"value": …}` is unwrapped once; a nested object is refused below.
    let v = match v {
        Value::Object(m) => m.get("name").or(m.get("value")).unwrap_or(&Value::Null),
        other => other,
    };
    match v {
        Value::Number(n) => {
            let n = n.as_u64().ok_or("cause must be a non-negative integer")?;
            CAUSES
                .iter()
                .find(|(_, c)| *c as u64 == n)
                .map(|(_, c)| *c)
                .ok_or_else(|| format!("5GMM cause {n} is not defined by TS 24.501"))
        }
        Value::String(s) => {
            let want = s.trim().to_ascii_lowercase().replace([' ', '-'], "_");
            CAUSES
                .iter()
                .find(|(n, _)| *n == want)
                .map(|(_, c)| *c)
                .ok_or_else(|| {
                    format!(
                        "5GMM cause {s:?} is not one of: {}",
                        CAUSES
                            .iter()
                            .map(|(n, _)| *n)
                            .collect::<Vec<_>>()
                            .join(", ")
                    )
                })
        }
        _ => Err("cause must be a 5GMM cause name such as \"illegal_ue\" or its number".into()),
    }
}

const IDENTITY_TYPES: &[(&str, u8)] = &[
    ("suci", 1),
    ("5g_guti", 2),
    ("imei", 3),
    ("5g_s_tmsi", 4),
    ("imeisv", 5),
    ("mac_address", 6),
    ("eui64", 7),
];

fn identity_type_name(t: u8) -> &'static str {
    IDENTITY_TYPES
        .iter()
        .find(|(_, v)| *v == t)
        .map(|(n, _)| *n)
        .unwrap_or("no_identity")
}

const REGISTRATION_TYPES: &[(&str, u8)] = &[
    ("initial", 1),
    ("mobility_updating", 2),
    ("periodic_updating", 3),
    ("emergency", 4),
    ("snpn_onboarding", 5),
    ("disaster_roaming_mobility_updating", 6),
    ("disaster_roaming_initial", 7),
];

/// Optional-IE names in a Registration Request (TS 24.501 Table 8.2.6.1.1), for the event.
fn registration_request_iei_name(iei: u8) -> Option<&'static str> {
    Some(match iei {
        0x10 => "5gmm_capability",
        0x2e => "ue_security_capability",
        0x2f => "requested_nssai",
        0x52 => "last_visited_registered_tai",
        0x17 => "s1_ue_network_capability",
        0x40 => "uplink_data_status",
        0x50 => "pdu_session_status",
        0x2b => "ue_status",
        0x77 => "additional_guti",
        0x25 => "allowed_pdu_session_status",
        0x18 => "ue_usage_setting",
        0x51 => "requested_drx_parameters",
        0x70 => "eps_nas_message_container",
        0x74 => "ladn_indication",
        0x7b => "payload_container",
        0x53 => "5gs_update_type",
        0x71 => "nas_message_container",
        0x60 => "eps_bearer_context_status",
        _ => match iei >> 4 {
            0xC => "non_current_native_nas_ksi",
            0xB => "mico_indication",
            0x8 => "payload_container_type",
            0x9 => "network_slicing_indication",
            _ => return None,
        },
    })
}

// ============================================================================
// Decoding
// ============================================================================

struct Cursor<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Cursor<'a> {
    fn u8(&mut self, what: &str) -> Result<u8, String> {
        let v = *self.b.get(self.i).ok_or(format!("{what}: truncated"))?;
        self.i += 1;
        Ok(v)
    }
    fn take(&mut self, n: usize, what: &str) -> Result<&'a [u8], String> {
        if self.b.len() - self.i < n {
            return Err(format!(
                "{what}: needs {n} octets, {} remain",
                self.b.len() - self.i
            ));
        }
        let s = &self.b[self.i..self.i + n];
        self.i += n;
        Ok(s)
    }
    fn lv(&mut self, what: &str) -> Result<&'a [u8], String> {
        let n = self.u8(what)? as usize;
        self.take(n, what)
    }
    fn lve(&mut self, what: &str) -> Result<&'a [u8], String> {
        let n = (self.u8(what)? as usize) << 8 | self.u8(what)? as usize;
        self.take(n, what)
    }
    fn done(&self) -> bool {
        self.i >= self.b.len()
    }
}

/// Optional IEs: 1-octet when the IEI's top bit is set, TLV-E for 0x7X, a fixed TV length where
/// `fixed` names one, TLV otherwise (TS 24.007 section 11.2.4, TS 24.501 section 9.11).
fn optional_ies<'a>(
    c: &mut Cursor<'a>,
    fixed: &[(u8, usize)],
) -> Result<Vec<(u8, &'a [u8])>, String> {
    let mut out = Vec::new();
    while !c.done() {
        if out.len() >= 64 {
            return Err("more than 64 optional IEs".into());
        }
        let iei = c.u8("IEI")?;
        if iei & 0x80 != 0 {
            out.push((iei, &c.b[c.i - 1..c.i]));
        } else if let Some((_, n)) = fixed.iter().find(|(i, _)| *i == iei) {
            out.push((iei, c.take(*n, "TV IE")?));
        } else if (0x70..=0x7f).contains(&iei) {
            out.push((iei, c.lve("TLV-E IE")?));
        } else {
            out.push((iei, c.lv("TLV IE")?));
        }
    }
    Ok(out)
}

fn bcd(octets: &[u8]) -> String {
    let mut s = String::new();
    for b in octets {
        for nib in [b & 0x0F, b >> 4] {
            if nib <= 9 {
                s.push((b'0' + nib) as char);
            }
        }
    }
    s
}

fn plmn(b: &[u8]) -> Value {
    match super::codec::Plmn::decode_octets(b) {
        Ok(p) => p.to_json(),
        Err(_) => json!(null),
    }
}

/// A 5GS mobile identity (TS 24.501 section 9.11.3.4).
pub fn decode_mobile_identity(b: &[u8]) -> Value {
    let Some(&first) = b.first() else {
        return json!({"type": "no_identity"});
    };
    let t = first & 0x07;
    match t {
        1 => {
            let supi_format = (first >> 4) & 0x07;
            if supi_format != 0 || b.len() < 8 {
                return json!({"type": "suci", "supi_format": if supi_format == 1 { "nai" } else { "other" }, "length": b.len()});
            }
            let scheme = b[6] & 0x0F;
            let output = &b[8..];
            let mut v = json!({
                "type": "suci",
                "supi_format": "imsi",
                "plmn": plmn(&b[1..4]),
                "routing_indicator": bcd(&b[4..6]),
                "protection_scheme": match scheme { 0 => "null", 1 => "profile_a", 2 => "profile_b", _ => "other" },
                "protection_scheme_id": scheme,
                "home_network_public_key_id": b[7],
            });
            if scheme == 0 {
                v["msin"] = json!(bcd(output));
            } else {
                v["scheme_output_length"] = json!(output.len());
            }
            v
        }
        2 if b.len() == 11 => json!({
            "type": "5g_guti",
            "plmn": plmn(&b[1..4]),
            "amf_region_id": b[4],
            "amf_set_id": ((b[5] as u16) << 2) | (b[6] >> 6) as u16,
            "amf_pointer": b[6] & 0x3F,
            "tmsi": u32::from_be_bytes([b[7], b[8], b[9], b[10]]),
        }),
        3 | 5 => {
            let mut digits = String::new();
            digits.push((b'0' + ((first >> 4) & 0x0F).min(9)) as char);
            digits.push_str(&bcd(&b[1..]));
            json!({"type": identity_type_name(t), "digits": digits})
        }
        4 if b.len() == 7 => json!({
            "type": "5g_s_tmsi",
            "amf_set_id": ((b[1] as u16) << 2) | (b[2] >> 6) as u16,
            "amf_pointer": b[2] & 0x3F,
            "tmsi": u32::from_be_bytes([b[3], b[4], b[5], b[6]]),
        }),
        _ => json!({"type": identity_type_name(t), "length": b.len()}),
    }
}

fn algorithms(byte: u8, prefix: &str) -> Vec<String> {
    (0..8)
        .filter(|i| byte & (0x80 >> i) != 0)
        .map(|i| format!("{prefix}{i}"))
        .collect()
}

fn decode_nssai(b: &[u8]) -> Value {
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() && out.len() < 16 {
        let n = b[i] as usize;
        let Some(s) = b.get(i + 1..i + 1 + n) else {
            break;
        };
        let mut v = json!({"sst": s.first().copied().unwrap_or(0)});
        if n >= 4 {
            v["sd"] = json!(hex::encode(&s[1..4]));
        }
        out.push(v);
        i += 1 + n;
    }
    json!(out)
}

/// Decode one NAS PDU for the model. Never fails: a PDU that does not parse is reported with
/// its length and the reason, because NAS is opaque to NGAP and a 5GMM message NetGet cannot read
/// is still a valid NGAP message.
pub fn decode(b: &[u8]) -> Value {
    decode_at(b, 0)
}

/// How many security headers may wrap a plain 5GMM message: one (TS 24.501 §9.1). A protected
/// message inside another is not valid NAS, and refusing it keeps the decoder from recursing.
pub const MAX_NAS_DEPTH: usize = 1;

fn decode_at(b: &[u8], depth: usize) -> Value {
    match decode_inner(b, depth) {
        Ok(v) => v,
        Err(e) => json!({"decoded": false, "error": e, "length": b.len()}),
    }
}

fn decode_inner(b: &[u8], depth: usize) -> Result<Value, String> {
    let mut c = Cursor { b, i: 0 };
    let epd = c.u8("extended protocol discriminator")?;
    if epd == EPD_5GSM {
        return Ok(json!({"epd": "5gsm", "length": b.len(), "decoded": false,
                         "error": "5GSM messages are not decoded by NetGet"}));
    }
    if epd != EPD_5GMM {
        return Err(format!(
            "extended protocol discriminator 0x{epd:02x} is not 5GMM"
        ));
    }
    let sht = c.u8("security header type")? & 0x0F;
    if sht != 0 {
        if depth >= MAX_NAS_DEPTH {
            return Err("a security-protected NAS message inside another is not valid NAS".into());
        }
        let mac = c.take(4, "message authentication code")?;
        let sqn = c.u8("sequence number")?;
        let mut v = json!({
            "epd": "5gmm",
            "security_header": match sht {
                1 => "integrity_protected",
                2 => "integrity_protected_and_ciphered",
                3 => "integrity_protected_with_new_security_context",
                4 => "integrity_protected_and_ciphered_with_new_security_context",
                _ => "reserved",
            },
            "mac": hex::encode(mac),
            "sequence_number": sqn,
            "mac_verified": false,
        });
        if sht == 1 || sht == 3 {
            v["inner"] = decode_at(&b[c.i..], depth + 1);
        } else {
            v["ciphered_length"] = json!(b.len() - c.i);
        }
        return Ok(v);
    }
    let t = c.u8("message type")?;
    let mut v = Map::new();
    v.insert("epd".into(), json!("5gmm"));
    v.insert("security_header".into(), json!("plain"));
    v.insert(
        "message".into(),
        json!(message_name(t)
            .map(str::to_string)
            .unwrap_or(format!("0x{t:02x}"))),
    );
    v.insert("message_type".into(), json!(t));
    match t {
        REGISTRATION_REQUEST => {
            let o = c.u8("5GS registration type")?;
            let rt = o & 0x07;
            v.insert(
                "registration_type".into(),
                json!(REGISTRATION_TYPES
                    .iter()
                    .find(|(_, x)| *x == rt)
                    .map(|(n, _)| *n)
                    .unwrap_or("reserved")),
            );
            v.insert("follow_on_request".into(), json!(o & 0x08 != 0));
            v.insert("ngksi".into(), json!((o >> 4) & 0x07));
            v.insert(
                "ngksi_tsc".into(),
                json!(if o & 0x80 != 0 { "mapped" } else { "native" }),
            );
            v.insert(
                "mobile_identity".into(),
                decode_mobile_identity(c.lve("5GS mobile identity")?),
            );
            let mut present = Vec::new();
            for (iei, val) in optional_ies(&mut c, &[(0x52, 6)])? {
                let name = registration_request_iei_name(iei)
                    .map(str::to_string)
                    .unwrap_or(format!("iei_0x{iei:02x}"));
                match iei {
                    0x2e if !val.is_empty() => {
                        let mut s = json!({"5g_ea": algorithms(val[0], "5G-EA")});
                        if val.len() > 1 {
                            s["5g_ia"] = json!(algorithms(val[1], "5G-IA"));
                        }
                        v.insert("ue_security_capability".into(), s);
                    }
                    0x2f => {
                        v.insert("requested_nssai".into(), decode_nssai(val));
                    }
                    _ => {}
                }
                present.push(json!(name));
            }
            v.insert("optional_ies".into(), json!(present));
        }
        REGISTRATION_REJECT | SERVICE_REJECT | FIVEGMM_STATUS | SECURITY_MODE_REJECT => {
            v.insert("cause".into(), cause_json(c.u8("5GMM cause")?));
        }
        AUTHENTICATION_FAILURE => {
            v.insert("cause".into(), cause_json(c.u8("5GMM cause")?));
            for (iei, val) in optional_ies(&mut c, &[])? {
                if iei == 0x30 {
                    v.insert("auts_length".into(), json!(val.len()));
                }
            }
        }
        AUTHENTICATION_REQUEST => {
            let o = c.u8("ngKSI")?;
            v.insert("ngksi".into(), json!(o & 0x07));
            v.insert("abba".into(), json!(hex::encode(c.lv("ABBA")?)));
            for (iei, val) in optional_ies(&mut c, &[(0x21, 16)])? {
                match iei {
                    0x21 => {
                        v.insert("rand".into(), json!(hex::encode(val)));
                    }
                    0x20 => {
                        v.insert("autn".into(), json!(hex::encode(val)));
                    }
                    _ => {}
                }
            }
        }
        AUTHENTICATION_RESPONSE => {
            for (iei, val) in optional_ies(&mut c, &[])? {
                if iei == 0x2d {
                    v.insert("res_star_length".into(), json!(val.len()));
                }
            }
        }
        IDENTITY_REQUEST => {
            let o = c.u8("identity type")? & 0x07;
            v.insert("identity_type".into(), json!(identity_type_name(o)));
        }
        IDENTITY_RESPONSE => {
            v.insert(
                "mobile_identity".into(),
                decode_mobile_identity(c.lve("mobile identity")?),
            );
        }
        DEREGISTRATION_REQUEST_UE_ORIGINATING => {
            let o = c.u8("de-registration type")?;
            v.insert("switch_off".into(), json!(o & 0x08 != 0));
            v.insert("ngksi".into(), json!((o >> 4) & 0x07));
            v.insert(
                "mobile_identity".into(),
                decode_mobile_identity(c.lve("mobile identity")?),
            );
        }
        SERVICE_REQUEST => {
            let o = c.u8("service type")?;
            v.insert("service_type".into(), json!(o & 0x0F));
            v.insert("ngksi".into(), json!((o >> 4) & 0x07));
            v.insert(
                "mobile_identity".into(),
                decode_mobile_identity(c.lve("5G-S-TMSI")?),
            );
        }
        _ => {
            v.insert("body_length".into(), json!(b.len() - c.i));
        }
    }
    Ok(Value::Object(v))
}

/// The plain 5GMM message type, looking through an integrity-protected (not ciphered) header.
pub fn message_type(b: &[u8]) -> Option<u8> {
    let mut b = b;
    for depth in 0..=MAX_NAS_DEPTH {
        if b.first() != Some(&EPD_5GMM) {
            return None;
        }
        match b.get(1)? & 0x0F {
            0 => return b.get(2).copied(),
            1 | 3 if depth < MAX_NAS_DEPTH => b = b.get(7..)?,
            _ => return None,
        }
    }
    None
}

// ============================================================================
// Encoding
// ============================================================================

fn hex_field(v: &Value, field: &str, len: usize) -> Result<Option<Vec<u8>>, String> {
    match v.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => {
            let b = hex::decode(s.trim()).map_err(|_| format!("{field} {s:?} is not hex"))?;
            if b.len() != len {
                return Err(format!(
                    "{field} must be {len} octets ({} hex digits)",
                    len * 2
                ));
            }
            Ok(Some(b))
        }
        _ => Err(format!("{field} must be a hex string")),
    }
}

fn u8_field(v: &Value, field: &str, max: u8, default: u8) -> Result<u8, String> {
    match v.get(field) {
        None | Some(Value::Null) => Ok(default),
        Some(x) => {
            let n = x.as_u64().ok_or(format!("{field} must be a number"))?;
            if n > max as u64 {
                return Err(format!("{field} {n} is above {max}"));
            }
            Ok(n as u8)
        }
    }
}

fn digits(v: &Value, field: &str, min: usize, max: usize) -> Result<String, String> {
    let s = v
        .get(field)
        .and_then(Value::as_str)
        .ok_or(format!("{field} must be a string of digits"))?
        .trim()
        .to_string();
    if s.len() < min || s.len() > max || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!("{field} {s:?} must be {min}..{max} decimal digits"));
    }
    Ok(s)
}

fn to_bcd(s: &str) -> Vec<u8> {
    let d: Vec<u8> = s.bytes().map(|b| b - b'0').collect();
    d.chunks(2)
        .map(|p| {
            if p.len() == 2 {
                p[1] << 4 | p[0]
            } else {
                0xF0 | p[0]
            }
        })
        .collect()
}

/// A 5GS mobile identity from `{"type": "suci", "mcc", "mnc", "routing_indicator", "msin"}` (null
/// scheme), `{"type": "5g_guti", "plmn", "amf_region_id", "amf_set_id", "amf_pointer", "tmsi"}`,
/// or `{"type": "imei" | "imeisv", "digits"}`.
pub fn encode_mobile_identity(v: &Value) -> Result<Vec<u8>, String> {
    let t = v.get("type").and_then(Value::as_str).unwrap_or("suci");
    match t {
        "suci" => {
            let plmn = super::codec::Plmn::from_json(v.get("plmn").unwrap_or(v))
                .map_err(|e| e.to_string())?;
            let ri = v
                .get("routing_indicator")
                .and_then(Value::as_str)
                .unwrap_or("0000");
            if ri.is_empty() || ri.len() > 4 || !ri.bytes().all(|b| b.is_ascii_digit()) {
                return Err(format!("routing_indicator {ri:?} must be 1..4 digits"));
            }
            let msin = digits(v, "msin", 5, 10)?;
            let key_id = u8_field(v, "home_network_public_key_id", 255, 0)?;
            if v.get("protection_scheme")
                .and_then(Value::as_str)
                .unwrap_or("null")
                != "null"
            {
                return Err(
                    "only the null protection scheme can be built from structured fields; \
                     ECIES profiles need the home network's public key"
                        .into(),
                );
            }
            let mut ri_padded = to_bcd(ri);
            ri_padded.resize(2, 0xFF);
            if ri.len() <= 2 {
                ri_padded[1] = 0xFF;
            }
            let mut out = vec![0x01];
            out.extend_from_slice(&plmn.octets());
            out.extend_from_slice(&ri_padded);
            out.push(0x00);
            out.push(key_id);
            out.extend_from_slice(&to_bcd(&msin));
            Ok(out)
        }
        "5g_guti" => {
            let plmn = super::codec::Plmn::from_json(v.get("plmn").unwrap_or(&Value::Null))
                .map_err(|e| e.to_string())?;
            let region = u8_field(v, "amf_region_id", 255, 0)?;
            let set = v.get("amf_set_id").and_then(Value::as_u64).unwrap_or(0);
            if set > 0x3FF {
                return Err("amf_set_id is 10 bits".into());
            }
            let pointer = u8_field(v, "amf_pointer", 63, 0)?;
            let tmsi = v.get("tmsi").and_then(Value::as_u64).unwrap_or(0);
            if tmsi > u32::MAX as u64 {
                return Err("tmsi is 32 bits".into());
            }
            let mut out = vec![0xF2];
            out.extend_from_slice(&plmn.octets());
            out.push(region);
            out.push((set >> 2) as u8);
            out.push(((set as u8 & 0x03) << 6) | pointer);
            out.extend_from_slice(&(tmsi as u32).to_be_bytes());
            Ok(out)
        }
        "imei" | "imeisv" => {
            let d = digits(v, "digits", 15, 16)?;
            let odd = d.len() % 2 == 1;
            let b: Vec<u8> = d.bytes().map(|x| x - b'0').collect();
            let mut out = vec![(b[0] << 4) | ((odd as u8) << 3) | if t == "imei" { 3 } else { 5 }];
            out.extend(to_bcd(
                std::str::from_utf8(&d.as_bytes()[1..]).unwrap_or(""),
            ));
            Ok(out)
        }
        other => Err(format!(
            "mobile_identity.type {other:?} must be suci, 5g_guti, imei or imeisv"
        )),
    }
}

fn lve(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&(b.len() as u16).to_be_bytes());
    out.extend_from_slice(b);
}

/// Messages the AMF may send before NAS security exists (TS 24.501 section 4.4.4.2).
pub const DOWNLINK_MESSAGES: &[&str] = &[
    "registration_reject",
    "authentication_request",
    "authentication_reject",
    "identity_request",
    "service_reject",
    "5gmm_status",
];

/// Messages a gNB's UE side sends during registration, before security.
pub const UPLINK_MESSAGES: &[&str] = &[
    "registration_request",
    "identity_response",
    "authentication_failure",
    "registration_complete",
    "deregistration_request_ue_originating",
    "security_mode_reject",
    "5gmm_status",
];

/// Encode one plain 5GMM message from the model's structured fields. `allowed` is the direction's
/// list ([`DOWNLINK_MESSAGES`] or [`UPLINK_MESSAGES`]).
pub fn encode(v: &Value, allowed: &[&str]) -> Result<Vec<u8>, String> {
    let name = v
        .get("message")
        .and_then(Value::as_str)
        .ok_or("nas.message is required, e.g. \"registration_reject\"")?;
    if !allowed.contains(&name) {
        return Err(format!(
            "nas.message {name:?} cannot be sent in this direction; one of: {}",
            allowed.join(", ")
        ));
    }
    let mut out = vec![EPD_5GMM, 0x00];
    match name {
        "registration_reject" | "service_reject" | "5gmm_status" | "security_mode_reject" => {
            out.push(match name {
                "registration_reject" => REGISTRATION_REJECT,
                "service_reject" => SERVICE_REJECT,
                "security_mode_reject" => SECURITY_MODE_REJECT,
                _ => FIVEGMM_STATUS,
            });
            out.push(parse_cause(v.get("cause").unwrap_or(&Value::Null))?);
        }
        "authentication_request" => {
            out.push(AUTHENTICATION_REQUEST);
            out.push(u8_field(v, "ngksi", 6, 0)?);
            let abba = match v.get("abba").and_then(Value::as_str) {
                Some(s) => hex::decode(s.trim()).map_err(|_| "abba must be hex".to_string())?,
                None => vec![0, 0],
            };
            if abba.len() < 2 || abba.len() > 16 {
                return Err("abba must be 2..16 octets".into());
            }
            out.push(abba.len() as u8);
            out.extend_from_slice(&abba);
            let rand =
                hex_field(v, "rand", 16)?.unwrap_or_else(|| rand::random::<[u8; 16]>().to_vec());
            let autn =
                hex_field(v, "autn", 16)?.unwrap_or_else(|| rand::random::<[u8; 16]>().to_vec());
            out.push(0x21);
            out.extend_from_slice(&rand);
            out.push(0x20);
            out.push(16);
            out.extend_from_slice(&autn);
        }
        "authentication_reject" => out.push(AUTHENTICATION_REJECT),
        "identity_request" => {
            out.push(IDENTITY_REQUEST);
            let t = v
                .get("identity_type")
                .and_then(Value::as_str)
                .unwrap_or("suci");
            let code = IDENTITY_TYPES
                .iter()
                .find(|(n, _)| *n == t)
                .map(|(_, c)| *c)
                .ok_or(format!(
                    "identity_type {t:?} must be one of suci, 5g_guti, imei, 5g_s_tmsi, imeisv, mac_address, eui64"
                ))?;
            out.push(code);
        }
        "registration_request" => {
            out.push(REGISTRATION_REQUEST);
            let rt_name = v
                .get("registration_type")
                .and_then(Value::as_str)
                .unwrap_or("initial");
            let rt = REGISTRATION_TYPES
                .iter()
                .find(|(n, _)| *n == rt_name)
                .map(|(_, c)| *c)
                .ok_or(format!("registration_type {rt_name:?} must be initial, mobility_updating, periodic_updating or emergency"))?;
            let for_bit = v
                .get("follow_on_request")
                .and_then(Value::as_bool)
                .unwrap_or(true);
            let ksi = u8_field(v, "ngksi", 7, 7)?;
            out.push((ksi << 4) | ((for_bit as u8) << 3) | rt);
            let id = encode_mobile_identity(
                v.get("mobile_identity")
                    .ok_or("mobile_identity is required")?,
            )?;
            lve(&mut out, &id);
            // UE security capability: 5G-EA0..3 and 5G-IA0..3 unless the model narrows it.
            let ea = u8_field(v, "ue_security_capability_ea", 255, 0xF0)?;
            let ia = u8_field(v, "ue_security_capability_ia", 255, 0xF0)?;
            out.extend_from_slice(&[0x2e, 2, ea, ia]);
        }
        "identity_response" => {
            out.push(IDENTITY_RESPONSE);
            let id = encode_mobile_identity(
                v.get("mobile_identity")
                    .ok_or("mobile_identity is required")?,
            )?;
            lve(&mut out, &id);
        }
        "authentication_failure" => {
            out.push(AUTHENTICATION_FAILURE);
            out.push(parse_cause(
                v.get("cause").unwrap_or(&json!("mac_failure")),
            )?);
        }
        "registration_complete" => out.push(REGISTRATION_COMPLETE),
        "deregistration_request_ue_originating" => {
            out.push(DEREGISTRATION_REQUEST_UE_ORIGINATING);
            let switch_off = v
                .get("switch_off")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let ksi = u8_field(v, "ngksi", 7, 7)?;
            // Access type 1: 3GPP access.
            out.push((ksi << 4) | ((switch_off as u8) << 3) | 0x01);
            let id = encode_mobile_identity(
                v.get("mobile_identity")
                    .ok_or("mobile_identity is required")?,
            )?;
            lve(&mut out, &id);
        }
        _ => return Err(format!("nas.message {name:?} is not encodable")),
    }
    Ok(out)
}

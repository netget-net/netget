//! 5GS mobility management (5GMM, TS 24.501) as NGAP carries it, in two layers.
//!
//! NAS is opaque to NGAP: a NAS-PDU IE is just octets. [`decode`] turns a plain 5GMM message (and
//! a 5GSM payload, through `sm`) into fields, so the model sees *what the UE asked for* —
//! registration type, the SUCI's PLMN, routing indicator and protection scheme, the 5GMM cause of
//! a failure — instead of a hex string, and [`encode`] builds what the model may say to a UE from
//! structured fields: the messages TS 24.501 section 4.4.4.2 lets a UE process before security,
//! which the session protects for it once security is on.
//!
//! The second layer, from "Structured 5GMM for the security procedures" down, is Rust's own:
//! the parsers and builders 5G-AKA, the security mode procedure, registration and the 5GSM NAS
//! transport need. Protection itself (MAC, COUNT, ciphering) is `security::NasContext`'s.
//!
//! A security-protected message given to [`decode`] directly is reported with its header fields
//! and, when not ciphered, the plain message inside, marked `mac_verified: false`: [`decode`] has
//! no key. The AMF and the gNB's UE decode only after `security` verified the MAC.

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
        return Ok(super::sm::decode(b));
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
        SECURITY_MODE_COMMAND => {
            let smc = parse_security_mode_command(b)?;
            v.insert(
                "selected_algorithms".into(),
                json!({"integrity": super::security::integrity_name(smc.ia),
                       "ciphering": super::security::ciphering_name(smc.ea)}),
            );
            v.insert("ngksi".into(), json!(smc.ngksi));
            v.insert("imeisv_request".into(), json!(smc.imeisv_request));
            v.insert("retransmit_initial_nas".into(), json!(smc.rinmr));
        }
        SECURITY_MODE_COMPLETE => {
            let smc = parse_security_mode_complete(b)?;
            v.insert("imeisv".into(), json!(smc.imeisv));
            v.insert(
                "nas_message_container_length".into(),
                json!(smc.nas_container.map(|c| c.len())),
            );
        }
        REGISTRATION_ACCEPT => {
            let a = parse_registration_accept(b)?;
            v.insert("guti".into(), json!(a.guti));
            v.insert("tai_list".into(), json!(a.tai_list));
            v.insert(
                "allowed_nssai".into(),
                json!(a
                    .allowed_nssai
                    .iter()
                    .map(Snssai::to_json)
                    .collect::<Vec<_>>()),
            );
        }
        UL_NAS_TRANSPORT | DL_NAS_TRANSPORT => {
            let t = parse_nas_transport_sm(b, t)?;
            v.insert("payload_container_type".into(), json!(t.payload_type));
            v.insert("pdu_session_id".into(), json!(t.pdu_session_id));
            v.insert("request_type".into(), json!(t.request_type));
            v.insert("s_nssai".into(), json!(t.s_nssai.map(|s| s.to_json())));
            v.insert("dnn".into(), json!(t.dnn));
            if t.payload_type == PAYLOAD_N1_SM {
                v.insert("payload".into(), super::sm::decode(&t.payload));
            } else {
                v.insert("payload_length".into(), json!(t.payload.len()));
            }
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

// ============================================================================
// Structured 5GMM for the security procedures (Rust's side, never the model's)
// ============================================================================
//
// These parse and build the messages 5G-AKA, the security mode procedure, registration and the
// NAS transport of 5GSM need. They work on plain 5GMM (header type 0); protection is
// `security::NasContext`'s job. Every parse is bounded by the octets it is given and refuses a
// truncated IE rather than guessing.

pub const UL_NAS_TRANSPORT: u8 = 0x67;
pub const DL_NAS_TRANSPORT: u8 = 0x68;
pub const SERVICE_ACCEPT: u8 = 0x4e;
pub const DEREGISTRATION_REQUEST_UE_TERMINATED: u8 = 0x47;

/// Payload container type N1 SM information (TS 24.501 9.11.3.40).
pub const PAYLOAD_N1_SM: u8 = 1;

/// One S-NSSAI (TS 24.501 9.11.2.8): an SST and an optional 24-bit SD.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Snssai {
    pub sst: u8,
    pub sd: Option<u32>,
}

impl Snssai {
    pub fn to_json(&self) -> Value {
        let mut v = json!({"sst": self.sst});
        if let Some(sd) = self.sd {
            v["sd"] = json!(format!("{sd:06x}"));
        }
        v
    }

    /// `{"sst": 1, "sd": "010203"}`; `sd` may be omitted, or a number.
    pub fn from_json(v: &Value) -> Result<Snssai, String> {
        let sst = v
            .get("sst")
            .and_then(Value::as_u64)
            .filter(|s| *s <= 255)
            .ok_or("s_nssai.sst must be 0..255")? as u8;
        let sd = match v.get("sd") {
            None | Some(Value::Null) => None,
            Some(Value::String(s)) => {
                let s = s.trim().trim_start_matches("0x");
                if s.len() != 6 {
                    return Err(format!("sd {s:?} must be six hex digits"));
                }
                Some(u32::from_str_radix(s, 16).map_err(|_| format!("sd {s:?} is not hex"))?)
            }
            Some(Value::Number(n)) => Some(
                n.as_u64()
                    .filter(|x| *x <= 0xFF_FFFF)
                    .ok_or("sd must be 24 bits")? as u32,
            ),
            Some(_) => return Err("sd must be six hex digits".into()),
        };
        Ok(Snssai { sst, sd })
    }

    /// The S-NSSAI IE contents (length octet not included).
    pub fn octets(&self) -> Vec<u8> {
        let mut out = vec![self.sst];
        if let Some(sd) = self.sd {
            out.extend_from_slice(&[(sd >> 16) as u8, (sd >> 8) as u8, sd as u8]);
        }
        out
    }

    pub fn parse(b: &[u8]) -> Result<Snssai, String> {
        match b.len() {
            1 | 2 => Ok(Snssai {
                sst: b[0],
                sd: None,
            }),
            4 | 5 | 8 => Ok(Snssai {
                sst: b[0],
                sd: Some(((b[1] as u32) << 16) | ((b[2] as u32) << 8) | b[3] as u32),
            }),
            n => Err(format!("an S-NSSAI of {n} octets")),
        }
    }
}

/// NSSAI contents (TS 24.501 9.11.3.37): a list of LV S-NSSAIs. At most 16 are read.
pub fn parse_nssai(b: &[u8]) -> Result<Vec<Snssai>, String> {
    let mut out = Vec::new();
    let mut c = Cursor { b, i: 0 };
    while !c.done() {
        if out.len() >= 16 {
            return Err("more than 16 S-NSSAIs".into());
        }
        out.push(Snssai::parse(c.lv("S-NSSAI")?)?);
    }
    Ok(out)
}

pub fn nssai_octets(list: &[Snssai]) -> Vec<u8> {
    let mut out = Vec::new();
    for s in list {
        let o = s.octets();
        out.push(o.len() as u8);
        out.extend_from_slice(&o);
    }
    out
}

/// A Registration Request's fields the AMF acts on.
#[derive(Debug, Clone)]
pub struct RegistrationRequest {
    pub registration_type: u8,
    pub ngksi: u8,
    pub mobile_identity: Vec<u8>,
    /// The UE security capability IE's contents, replayed verbatim in Security Mode Command.
    pub ue_security_capability: Option<Vec<u8>>,
    pub requested_nssai: Vec<Snssai>,
}

pub fn parse_registration_request(b: &[u8]) -> Result<RegistrationRequest, String> {
    let mut c = plain_header(b, REGISTRATION_REQUEST)?;
    let o = c.u8("registration type")?;
    let id = c.lve("5GS mobile identity")?.to_vec();
    let mut r = RegistrationRequest {
        registration_type: o & 0x07,
        ngksi: (o >> 4) & 0x07,
        mobile_identity: id,
        ue_security_capability: None,
        requested_nssai: Vec::new(),
    };
    for (iei, val) in optional_ies(&mut c, &[(0x52, 6)])? {
        match iei {
            0x2e => {
                if !(2..=8).contains(&val.len()) {
                    return Err("UE security capability must be 2..8 octets".into());
                }
                r.ue_security_capability = Some(val.to_vec());
            }
            0x2f => r.requested_nssai = parse_nssai(val)?,
            _ => {}
        }
    }
    Ok(r)
}

/// A SUCI with an IMSI-format SUPI (TS 24.501 figure 9.11.3.4.3).
#[derive(Debug, Clone)]
pub struct Suci {
    pub plmn: super::codec::Plmn,
    pub routing_indicator: String,
    pub protection_scheme: u8,
    pub home_network_public_key_id: u8,
    pub scheme_output: Vec<u8>,
}

pub fn parse_suci(b: &[u8]) -> Option<Suci> {
    if b.len() < 9 || b[0] & 0x07 != 1 || (b[0] >> 4) & 0x07 != 0 {
        return None;
    }
    Some(Suci {
        plmn: super::codec::Plmn::decode_octets(&b[1..4]).ok()?,
        routing_indicator: bcd(&b[4..6]),
        protection_scheme: b[6] & 0x0F,
        home_network_public_key_id: b[7],
        scheme_output: b[8..].to_vec(),
    })
}

/// MSIN digits from BCD scheme input (low nibble first, 0xF filler in the last nibble only).
pub fn msin_from_bcd(b: &[u8]) -> Option<String> {
    let mut s = String::new();
    for (i, x) in b.iter().enumerate() {
        for (j, nib) in [x & 0x0F, x >> 4].into_iter().enumerate() {
            match nib {
                0..=9 => s.push((b'0' + nib) as char),
                0xF if i == b.len() - 1 && j == 1 => {}
                _ => return None,
            }
        }
    }
    if (5..=10).contains(&s.len()) {
        Some(s)
    } else {
        None
    }
}

pub fn bcd_from_digits(s: &str) -> Vec<u8> {
    to_bcd(s)
}

/// A 5G-GUTI mobile identity (11 octets).
pub fn guti_octets(
    plmn: &super::codec::Plmn,
    region: u8,
    set: u16,
    pointer: u8,
    tmsi: u32,
) -> Vec<u8> {
    let mut out = vec![0xF2];
    out.extend_from_slice(&plmn.octets());
    out.push(region);
    out.push((set >> 2) as u8);
    out.push((((set & 0x03) as u8) << 6) | (pointer & 0x3F));
    out.extend_from_slice(&tmsi.to_be_bytes());
    out
}

fn tlv(out: &mut Vec<u8>, iei: u8, v: &[u8]) {
    out.push(iei);
    out.push(v.len() as u8);
    out.extend_from_slice(v);
}

fn tlve(out: &mut Vec<u8>, iei: u8, v: &[u8]) {
    out.push(iei);
    lve(out, v);
}

fn plain_header(b: &[u8], want: u8) -> Result<Cursor<'_>, String> {
    let mut c = Cursor { b, i: 0 };
    if c.u8("EPD")? != EPD_5GMM || c.u8("security header type")? & 0x0F != 0 {
        return Err("not a plain 5GMM message".into());
    }
    let t = c.u8("message type")?;
    if t != want {
        return Err(format!(
            "expected {}, got {}",
            message_name(want).unwrap_or("?"),
            message_name(t).unwrap_or("an unknown message")
        ));
    }
    Ok(c)
}

pub fn authentication_request(ngksi: u8, abba: &[u8], rand: &[u8; 16], autn: &[u8; 16]) -> Vec<u8> {
    let mut out = vec![EPD_5GMM, 0, AUTHENTICATION_REQUEST, ngksi & 0x0F];
    out.push(abba.len() as u8);
    out.extend_from_slice(abba);
    out.push(0x21);
    out.extend_from_slice(rand);
    tlv(&mut out, 0x20, autn);
    out
}

pub fn authentication_reject() -> Vec<u8> {
    vec![EPD_5GMM, 0, AUTHENTICATION_REJECT]
}

/// The pieces of an Authentication Request a UE needs.
pub struct AuthenticationRequest {
    pub ngksi: u8,
    pub abba: Vec<u8>,
    pub rand: [u8; 16],
    pub autn: [u8; 16],
}

pub fn parse_authentication_request(b: &[u8]) -> Result<AuthenticationRequest, String> {
    let mut c = plain_header(b, AUTHENTICATION_REQUEST)?;
    let ngksi = c.u8("ngKSI")? & 0x0F;
    let abba = c.lv("ABBA")?.to_vec();
    let mut rand = None;
    let mut autn = None;
    for (iei, val) in optional_ies(&mut c, &[(0x21, 16)])? {
        match iei {
            0x21 => rand = val.try_into().ok(),
            0x20 => autn = val.try_into().ok(),
            _ => {}
        }
    }
    Ok(AuthenticationRequest {
        ngksi,
        abba,
        rand: rand.ok_or("no 16-octet RAND (5G-AKA needs one)")?,
        autn: autn.ok_or("no 16-octet AUTN (5G-AKA needs one)")?,
    })
}

pub fn authentication_response(res_star: &[u8; 16]) -> Vec<u8> {
    let mut out = vec![EPD_5GMM, 0, AUTHENTICATION_RESPONSE];
    tlv(&mut out, 0x2d, res_star);
    out
}

/// RES* from an Authentication Response; `None` when the parameter is absent or not 16 octets.
pub fn parse_authentication_response(b: &[u8]) -> Result<Option<[u8; 16]>, String> {
    let mut c = plain_header(b, AUTHENTICATION_RESPONSE)?;
    for (iei, val) in optional_ies(&mut c, &[])? {
        if iei == 0x2d {
            return Ok(val.try_into().ok());
        }
    }
    Ok(None)
}

pub fn authentication_failure(cause: u8, auts: Option<&[u8; 14]>) -> Vec<u8> {
    let mut out = vec![EPD_5GMM, 0, AUTHENTICATION_FAILURE, cause];
    if let Some(a) = auts {
        tlv(&mut out, 0x30, a);
    }
    out
}

/// The cause and AUTS of an Authentication Failure.
pub fn parse_authentication_failure(b: &[u8]) -> Result<(u8, Option<Vec<u8>>), String> {
    let mut c = plain_header(b, AUTHENTICATION_FAILURE)?;
    let cause = c.u8("5GMM cause")?;
    let mut auts = None;
    for (iei, val) in optional_ies(&mut c, &[])? {
        if iei == 0x30 {
            auts = Some(val.to_vec());
        }
    }
    Ok((cause, auts))
}

/// Security Mode Command (TS 24.501 8.2.25).
pub fn security_mode_command(
    ia: u8,
    ea: u8,
    ngksi: u8,
    replayed_ue_security_capability: &[u8],
    imeisv_request: bool,
    rinmr: bool,
) -> Vec<u8> {
    let mut out = vec![
        EPD_5GMM,
        0,
        SECURITY_MODE_COMMAND,
        (ea << 4) | (ia & 0x0F),
        ngksi & 0x0F,
        replayed_ue_security_capability.len() as u8,
    ];
    out.extend_from_slice(replayed_ue_security_capability);
    if imeisv_request {
        out.push(0xE1);
    }
    if rinmr {
        // Additional 5G security information: RINMR (bit 2) set, HDP clear.
        tlv(&mut out, 0x36, &[0x02]);
    }
    out
}

pub struct SecurityModeCommand {
    pub ia: u8,
    pub ea: u8,
    pub ngksi: u8,
    pub replayed_ue_security_capability: Vec<u8>,
    pub imeisv_request: bool,
    pub rinmr: bool,
}

pub fn parse_security_mode_command(b: &[u8]) -> Result<SecurityModeCommand, String> {
    let mut c = plain_header(b, SECURITY_MODE_COMMAND)?;
    let algs = c.u8("selected NAS security algorithms")?;
    let ngksi = c.u8("ngKSI")? & 0x0F;
    let caps = c.lv("replayed UE security capabilities")?.to_vec();
    let mut smc = SecurityModeCommand {
        ia: algs & 0x0F,
        ea: algs >> 4,
        ngksi,
        replayed_ue_security_capability: caps,
        imeisv_request: false,
        rinmr: false,
    };
    for (iei, val) in optional_ies(&mut c, &[(0x57, 1)])? {
        match iei {
            x if x >> 4 == 0xE => smc.imeisv_request = x & 0x07 == 1,
            0x36 => smc.rinmr = val.first().map(|o| o & 0x02 != 0).unwrap_or(false),
            _ => {}
        }
    }
    Ok(smc)
}

/// Security Mode Complete (TS 24.501 8.2.26).
pub fn security_mode_complete(imeisv: Option<&[u8]>, nas_container: Option<&[u8]>) -> Vec<u8> {
    let mut out = vec![EPD_5GMM, 0, SECURITY_MODE_COMPLETE];
    if let Some(i) = imeisv {
        tlve(&mut out, 0x77, i);
    }
    if let Some(n) = nas_container {
        tlve(&mut out, 0x71, n);
    }
    out
}

pub struct SecurityModeComplete {
    pub imeisv: Option<Value>,
    pub nas_container: Option<Vec<u8>>,
}

pub fn parse_security_mode_complete(b: &[u8]) -> Result<SecurityModeComplete, String> {
    let mut c = plain_header(b, SECURITY_MODE_COMPLETE)?;
    let mut out = SecurityModeComplete {
        imeisv: None,
        nas_container: None,
    };
    for (iei, val) in optional_ies(&mut c, &[])? {
        match iei {
            0x77 => out.imeisv = Some(decode_mobile_identity(val)),
            0x71 => out.nas_container = Some(val.to_vec()),
            _ => {}
        }
    }
    Ok(out)
}

/// What the AMF puts in a Registration Accept.
pub struct RegistrationAccept {
    pub guti: Vec<u8>,
    /// One partial TAI list of type 00: one PLMN, these TACs.
    pub tai_plmn: super::codec::Plmn,
    pub tacs: Vec<u32>,
    pub allowed_nssai: Vec<Snssai>,
    /// T3512 as a GPRS timer 3 octet, if any.
    pub t3512: Option<u8>,
}

/// TACs in one partial TAI list (TS 24.501 9.11.3.9 allows 16).
pub const MAX_TAI_LIST: usize = 16;

/// Registration Accept (TS 24.501 8.2.7), 3GPP access.
pub fn registration_accept(a: &RegistrationAccept) -> Result<Vec<u8>, String> {
    if a.tacs.is_empty() || a.tacs.len() > MAX_TAI_LIST {
        return Err(format!("the TAI list must hold 1..{MAX_TAI_LIST} TACs"));
    }
    if a.allowed_nssai.is_empty() || a.allowed_nssai.len() > 8 {
        return Err("the allowed NSSAI must hold 1..8 S-NSSAIs".into());
    }
    let mut out = vec![EPD_5GMM, 0, REGISTRATION_ACCEPT, 1, 0x01];
    tlve(&mut out, 0x77, &a.guti);
    let mut tai = vec![(a.tacs.len() - 1) as u8];
    tai.extend_from_slice(&a.tai_plmn.octets());
    for t in &a.tacs {
        tai.extend_from_slice(&[(t >> 16) as u8, (t >> 8) as u8, *t as u8]);
    }
    tlv(&mut out, 0x54, &tai);
    tlv(&mut out, 0x15, &nssai_octets(&a.allowed_nssai));
    if let Some(t) = a.t3512 {
        tlv(&mut out, 0x5E, &[t]);
    }
    Ok(out)
}

/// What a UE takes from a Registration Accept.
pub struct ParsedRegistrationAccept {
    pub result: u8,
    pub guti: Option<Value>,
    pub tai_list: Vec<Value>,
    pub allowed_nssai: Vec<Snssai>,
}

pub fn parse_registration_accept(b: &[u8]) -> Result<ParsedRegistrationAccept, String> {
    let mut c = plain_header(b, REGISTRATION_ACCEPT)?;
    let result = c
        .lv("5GS registration result")?
        .first()
        .copied()
        .unwrap_or(0)
        & 0x07;
    let mut out = ParsedRegistrationAccept {
        result,
        guti: None,
        tai_list: Vec::new(),
        allowed_nssai: Vec::new(),
    };
    for (iei, val) in optional_ies(&mut c, &[])? {
        match iei {
            0x77 => out.guti = Some(decode_mobile_identity(val)),
            0x15 => out.allowed_nssai = parse_nssai(val)?,
            0x54 => out.tai_list = decode_tai_list(val),
            _ => {}
        }
    }
    Ok(out)
}

/// Partial TAI lists of types 00, 01 and 10 (TS 24.501 9.11.3.9). At most
/// [`MAX_TAI_LIST`] TAIs are reported.
fn decode_tai_list(b: &[u8]) -> Vec<Value> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() && out.len() < MAX_TAI_LIST {
        let t = (b[i] >> 5) & 0x03;
        let n = (b[i] & 0x1F) as usize + 1;
        i += 1;
        match t {
            0 => {
                let Some(p) = b.get(i..i + 3) else { break };
                let p = plmn(p);
                i += 3;
                for _ in 0..n {
                    let Some(tac) = b.get(i..i + 3) else {
                        return out;
                    };
                    out.push(
                        json!({"plmn": p, "tac": u32::from_be_bytes([0, tac[0], tac[1], tac[2]])}),
                    );
                    i += 3;
                    if out.len() >= MAX_TAI_LIST {
                        return out;
                    }
                }
            }
            1 => {
                let Some(p) = b.get(i..i + 6) else { break };
                let first = u32::from_be_bytes([0, p[3], p[4], p[5]]);
                for k in 0..n.min(MAX_TAI_LIST - out.len()) {
                    out.push(json!({"plmn": plmn(&p[0..3]), "tac": first + k as u32}));
                }
                i += 6;
            }
            2 => {
                // Type 10: n TAIs, each its own PLMN and TAC (Open5GS sends this one).
                for _ in 0..n {
                    let Some(p) = b.get(i..i + 6) else { return out };
                    out.push(json!({"plmn": plmn(&p[0..3]), "tac": u32::from_be_bytes([0, p[3], p[4], p[5]])}));
                    i += 6;
                    if out.len() >= MAX_TAI_LIST {
                        return out;
                    }
                }
            }
            _ => break,
        }
    }
    out
}

pub fn registration_complete() -> Vec<u8> {
    vec![EPD_5GMM, 0, REGISTRATION_COMPLETE]
}

pub fn registration_reject(cause: u8) -> Vec<u8> {
    vec![EPD_5GMM, 0, REGISTRATION_REJECT, cause]
}

pub fn deregistration_accept_ue_originating() -> Vec<u8> {
    vec![EPD_5GMM, 0, DEREGISTRATION_ACCEPT_UE_ORIGINATING]
}

/// `(switch_off, mobile identity)` of a UE-originating Deregistration Request.
pub fn parse_deregistration_request(b: &[u8]) -> Result<(bool, Vec<u8>), String> {
    let mut c = plain_header(b, DEREGISTRATION_REQUEST_UE_ORIGINATING)?;
    let o = c.u8("de-registration type")?;
    Ok(((o & 0x08) != 0, c.lve("5GS mobile identity")?.to_vec()))
}

/// A UE-originating Deregistration Request (UE side).
pub fn deregistration_request(ngksi: u8, switch_off: bool, identity: &[u8]) -> Vec<u8> {
    let mut out = vec![
        EPD_5GMM,
        0,
        DEREGISTRATION_REQUEST_UE_ORIGINATING,
        ((ngksi & 0x07) << 4) | ((switch_off as u8) << 3) | 0x01,
    ];
    lve(&mut out, identity);
    out
}

/// A 5GMM Status (either direction).
pub fn status(cause: u8) -> Vec<u8> {
    vec![EPD_5GMM, 0, FIVEGMM_STATUS, cause]
}

/// DL NAS Transport carrying N1 SM information for a PDU session (TS 24.501 8.2.11).
pub fn dl_nas_transport_sm(psi: u8, sm: &[u8]) -> Vec<u8> {
    let mut out = vec![EPD_5GMM, 0, DL_NAS_TRANSPORT, PAYLOAD_N1_SM];
    lve(&mut out, sm);
    out.push(0x12);
    out.push(psi);
    out
}

/// What a UL or DL NAS Transport carries for a PDU session (TS 24.501 8.2.10, 8.2.11).
#[derive(Debug, Clone)]
pub struct NasTransportSm {
    pub payload_type: u8,
    pub payload: Vec<u8>,
    pub pdu_session_id: Option<u8>,
    pub request_type: Option<u8>,
    pub s_nssai: Option<Snssai>,
    pub dnn: Option<String>,
}

pub fn parse_ul_nas_transport(b: &[u8]) -> Result<NasTransportSm, String> {
    parse_nas_transport_sm(b, UL_NAS_TRANSPORT)
}

pub fn parse_dl_nas_transport(b: &[u8]) -> Result<NasTransportSm, String> {
    parse_nas_transport_sm(b, DL_NAS_TRANSPORT)
}

fn parse_nas_transport_sm(b: &[u8], t: u8) -> Result<NasTransportSm, String> {
    let mut c = plain_header(b, t)?;
    let payload_type = c.u8("payload container type")? & 0x0F;
    let payload = c.lve("payload container")?.to_vec();
    let mut out = NasTransportSm {
        payload_type,
        payload,
        pdu_session_id: None,
        request_type: None,
        s_nssai: None,
        dnn: None,
    };
    for (iei, val) in optional_ies(&mut c, &[(0x12, 1), (0x59, 1), (0x58, 1)])? {
        match iei {
            0x12 => out.pdu_session_id = val.first().copied(),
            x if x >> 4 == 0x8 => out.request_type = Some(x & 0x07),
            0x22 => out.s_nssai = Some(Snssai::parse(val)?),
            0x25 => out.dnn = crate::server::gtp::codec::decode_apn(val),
            _ => {}
        }
    }
    Ok(out)
}

/// UL NAS Transport carrying a 5GSM message (UE side).
pub fn ul_nas_transport_sm(
    psi: u8,
    request_type: u8,
    s_nssai: Option<&Snssai>,
    dnn: Option<&str>,
    sm: &[u8],
) -> Result<Vec<u8>, String> {
    let mut out = vec![EPD_5GMM, 0, UL_NAS_TRANSPORT, PAYLOAD_N1_SM];
    lve(&mut out, sm);
    out.push(0x12);
    out.push(psi);
    out.push(0x80 | (request_type & 0x07));
    if let Some(s) = s_nssai {
        tlv(&mut out, 0x22, &s.octets());
    }
    if let Some(d) = dnn {
        let apn = crate::server::gtp::codec::encode_apn(d).map_err(|e| e.to_string())?;
        if apn.len() > 100 {
            return Err("the DNN is longer than 100 octets".into());
        }
        tlv(&mut out, 0x25, &apn);
    }
    Ok(out)
}

/// UE security capability octets to the NGAP UESecurityCapabilities bitmaps (NR encryption, NR
/// integrity, E-UTRA encryption, E-UTRA integrity): 16 bits each, whose first bit is algorithm 1.
pub fn ngap_security_capabilities(nas_caps: &[u8]) -> [u16; 4] {
    let get = |i: usize| nas_caps.get(i).copied().unwrap_or(0);
    // NAS: bit 8 of each octet is algorithm 0; NGAP leaves algorithm 0 out and starts at 1.
    let map = |o: u8| ((o << 1) as u16 & 0x00FE) << 8;
    [map(get(0)), map(get(1)), map(get(2)), map(get(3))]
}

//! The GSM encodings MAP and CAP carry inside their OCTET STRINGs: TBCD digit strings (TS 29.002
//! section 17.7.8), AddressString (its nature/plan octet), the GSM 7-bit default alphabet and its
//! packing (TS 23.038), SMS TPDUs (TS 23.040: SMS-SUBMIT and SMS-DELIVER), the ISUP number and
//! cause formats CAMEL borrows (Q.763, Q.850) and the cell global identity (TS 24.008).
//!
//! The model never sees any of these as octets. Each has a structured form — digits, nature,
//! text, mcc/mnc/lac/ci — and the conversion is done here, with every length the formats allow
//! checked on the way in.

use serde_json::{json, Value};

/// TS 29.002 limits: ISDN-AddressString is at most 9 octets (1 + 8, so 16 digits), AddressString
/// at most 20 (38 digits), IMSI 3..8 octets.
pub const MAX_ISDN_ADDRESS_DIGITS: usize = 16;
pub const MAX_ADDRESS_DIGITS: usize = 38;
pub const MAX_IMSI_DIGITS: usize = 15;
pub const MIN_IMSI_DIGITS: usize = 6;
/// USSD-String is at most 160 octets (TS 29.002 `maxUSSD-StringLength`).
pub const MAX_USSD_OCTETS: usize = 160;
/// One SMS TPDU's user data: 140 octets (160 septets).
pub const MAX_SMS_UD_OCTETS: usize = 140;

/// Errors from these conversions name the field and the rule; they go to the model as a failed
/// action or to the log, never onto the wire.
pub type GsmResult<T> = Result<T, String>;

// ---------------------------------------------------------------------------
// TBCD
// ---------------------------------------------------------------------------

fn tbcd_digit(c: char) -> GsmResult<u8> {
    Ok(match c {
        '0'..='9' => c as u8 - b'0',
        '*' => 0xa,
        '#' => 0xb,
        'a' | 'A' => 0xc,
        'b' | 'B' => 0xd,
        'c' | 'C' => 0xe,
        other => return Err(format!("{other:?} is not a TBCD digit (0-9 * # a b c)")),
    })
}

fn tbcd_char(n: u8) -> Option<char> {
    match n {
        0..=9 => Some((b'0' + n) as char),
        0xa => Some('*'),
        0xb => Some('#'),
        0xc => Some('a'),
        0xd => Some('b'),
        0xe => Some('c'),
        _ => None,
    }
}

/// TBCD: two digits an octet, the first in the low nibble, an odd count padded with 0xF.
pub fn tbcd_encode(digits: &str) -> GsmResult<Vec<u8>> {
    let nibbles: Vec<u8> = digits
        .chars()
        .map(tbcd_digit)
        .collect::<GsmResult<Vec<_>>>()?;
    Ok(nibbles
        .chunks(2)
        .map(|p| p[0] | (p.get(1).copied().unwrap_or(0xf) << 4))
        .collect())
}

/// Decode TBCD, stopping at the first filler nibble.
pub fn tbcd_decode(octets: &[u8]) -> String {
    let mut out = String::new();
    for b in octets {
        for n in [b & 0x0f, b >> 4] {
            match tbcd_char(n) {
                Some(c) => out.push(c),
                None => return out,
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// AddressString / ISDN-AddressString (TS 29.002 section 17.7.8)
// ---------------------------------------------------------------------------

pub const NATURES: &[(&str, u8)] = &[
    ("unknown", 0),
    ("international", 1),
    ("national", 2),
    ("network_specific", 3),
    ("subscriber", 4),
    ("abbreviated", 6),
];

pub const PLANS: &[(&str, u8)] = &[
    ("unknown", 0),
    ("isdn", 1),
    ("data", 3),
    ("telex", 4),
    ("land_mobile", 6),
    ("national", 8),
    ("private", 9),
];

fn name_of(table: &[(&'static str, u8)], v: u8) -> Value {
    table
        .iter()
        .find(|(_, n)| *n == v)
        .map(|(s, _)| json!(s))
        .unwrap_or_else(|| json!(v))
}

fn value_of(table: &[(&'static str, u8)], v: &Value, field: &str, max: u8) -> GsmResult<u8> {
    if let Some(n) = v.as_u64() {
        if n <= max as u64 {
            return Ok(n as u8);
        }
        return Err(format!("{field} {n} is above {max}"));
    }
    let s = v
        .as_str()
        .ok_or_else(|| format!("{field} must be a name or a number"))?;
    table
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(s))
        .map(|(_, v)| *v)
        .ok_or_else(|| {
            format!(
                "{field} {s:?} is not one of {}",
                table.iter().map(|(n, _)| *n).collect::<Vec<_>>().join(", ")
            )
        })
}

/// An AddressString in structured form.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Address {
    pub nature: u8,
    pub plan: u8,
    pub digits: String,
}

impl Address {
    pub fn international(digits: &str) -> Self {
        Address {
            nature: 1,
            plan: 1,
            digits: digits.to_string(),
        }
    }

    pub fn decode(octets: &[u8]) -> GsmResult<Self> {
        let Some((first, rest)) = octets.split_first() else {
            return Err("empty AddressString".into());
        };
        Ok(Address {
            nature: (first >> 4) & 0x07,
            plan: first & 0x0f,
            digits: tbcd_decode(rest),
        })
    }

    pub fn encode(&self, max_digits: usize) -> GsmResult<Vec<u8>> {
        if self.digits.is_empty() || self.digits.len() > max_digits {
            return Err(format!(
                "an address of {} digits (1..{max_digits} allowed)",
                self.digits.len()
            ));
        }
        let mut out = vec![0x80 | (self.nature & 0x07) << 4 | (self.plan & 0x0f)];
        out.extend(tbcd_encode(&self.digits)?);
        Ok(out)
    }

    pub fn to_json(&self) -> Value {
        json!({
            "digits": self.digits,
            "nature": name_of(NATURES, self.nature),
            "plan": name_of(PLANS, self.plan),
        })
    }

    /// Accept `"31628838002"`, `"+31628838002"` (both international/ISDN) or
    /// `{"digits", "nature", "plan"}`.
    pub fn from_json(v: &Value, field: &str) -> GsmResult<Self> {
        match v {
            Value::String(s) => {
                let digits = s.trim().trim_start_matches('+');
                Ok(Address::international(digits))
            }
            Value::Number(_) => Ok(Address::international(&v.to_string())),
            Value::Object(o) => {
                let digits = o
                    .get("digits")
                    .and_then(Value::as_str)
                    .ok_or_else(|| format!("{field}.digits is required"))?
                    .trim_start_matches('+')
                    .to_string();
                let nature = match o.get("nature") {
                    Some(n) => value_of(NATURES, n, &format!("{field}.nature"), 7)?,
                    None => 1,
                };
                let plan = match o.get("plan") {
                    Some(p) => value_of(PLANS, p, &format!("{field}.plan"), 15)?,
                    None => 1,
                };
                Ok(Address {
                    nature,
                    plan,
                    digits,
                })
            }
            _ => Err(format!(
                "{field} must be a digit string or {{\"digits\", \"nature\", \"plan\"}}"
            )),
        }
    }
}

/// IMSI: TBCD, 6..15 digits.
pub fn imsi_encode(digits: &str) -> GsmResult<Vec<u8>> {
    if !(MIN_IMSI_DIGITS..=MAX_IMSI_DIGITS).contains(&digits.len())
        || !digits.chars().all(|c| c.is_ascii_digit())
    {
        return Err(format!(
            "IMSI {digits:?} must be {MIN_IMSI_DIGITS}..{MAX_IMSI_DIGITS} decimal digits"
        ));
    }
    tbcd_encode(digits)
}

pub fn json_str<'a>(v: &'a Value, field: &str) -> GsmResult<&'a str> {
    v.get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{field} is required (a string)"))
}

// ---------------------------------------------------------------------------
// GSM 7-bit default alphabet (TS 23.038 section 6.2.1) and packing (section 6.1.2.1)
// ---------------------------------------------------------------------------

const GSM7_BASIC: [char; 128] = [
    '@', '£', '$', '¥', 'è', 'é', 'ù', 'ì', 'ò', 'Ç', '\n', 'Ø', 'ø', '\r', 'Å', 'å', 'Δ', '_',
    'Φ', 'Γ', 'Λ', 'Ω', 'Π', 'Ψ', 'Σ', 'Θ', 'Ξ', '\u{1b}', 'Æ', 'æ', 'ß', 'É', ' ', '!', '"', '#',
    '¤', '%', '&', '\'', '(', ')', '*', '+', ',', '-', '.', '/', '0', '1', '2', '3', '4', '5', '6',
    '7', '8', '9', ':', ';', '<', '=', '>', '?', '¡', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I',
    'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'Ä', 'Ö',
    'Ñ', 'Ü', '§', '¿', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o',
    'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'ä', 'ö', 'ñ', 'ü', 'à',
];

/// The extension table (escape 0x1B), section 6.2.1.1.
const GSM7_EXTENSION: &[(u8, char)] = &[
    (0x0a, '\u{0c}'),
    (0x14, '^'),
    (0x28, '{'),
    (0x29, '}'),
    (0x2f, '\\'),
    (0x3c, '['),
    (0x3d, '~'),
    (0x3e, ']'),
    (0x40, '|'),
    (0x65, '€'),
];

/// Text to septets, or `None` if a character is outside the default alphabet and its extension.
pub fn gsm7_septets(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len());
    for c in text.chars() {
        if c == '\u{1b}' {
            return None;
        }
        if let Some(i) = GSM7_BASIC.iter().position(|b| *b == c) {
            out.push(i as u8);
        } else if let Some((code, _)) = GSM7_EXTENSION.iter().find(|(_, e)| *e == c) {
            out.push(0x1b);
            out.push(*code);
        } else {
            return None;
        }
    }
    Some(out)
}

/// Septets to text. An escape followed by an unknown code reads as a space (section 6.2.1.1).
pub fn gsm7_text(septets: &[u8]) -> String {
    let mut out = String::new();
    let mut escape = false;
    for s in septets {
        let s = s & 0x7f;
        if escape {
            escape = false;
            out.push(
                GSM7_EXTENSION
                    .iter()
                    .find(|(code, _)| *code == s)
                    .map(|(_, c)| *c)
                    .unwrap_or(' '),
            );
        } else if s == 0x1b {
            escape = true;
        } else {
            out.push(GSM7_BASIC[s as usize]);
        }
    }
    out
}

/// Pack septets LSB-first, starting `fill_bits` into the first octet (used after a UDH).
pub fn pack_septets(septets: &[u8], fill_bits: usize) -> Vec<u8> {
    let total_bits = fill_bits + septets.len() * 7;
    let mut out = vec![0u8; total_bits.div_ceil(8)];
    for (i, s) in septets.iter().enumerate() {
        let bit = fill_bits + i * 7;
        let byte = bit / 8;
        let shift = bit % 8;
        let v = ((*s & 0x7f) as u16) << shift;
        out[byte] |= (v & 0xff) as u8;
        if shift > 1 {
            out[byte + 1] |= (v >> 8) as u8;
        }
    }
    out
}

/// Unpack `count` septets starting `fill_bits` into the octets.
pub fn unpack_septets(octets: &[u8], count: usize, fill_bits: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let bit = fill_bits + i * 7;
        let byte = bit / 8;
        let shift = bit % 8;
        let lo = *octets.get(byte).unwrap_or(&0) as u16;
        let hi = *octets.get(byte + 1).unwrap_or(&0) as u16;
        out.push((((hi << 8) | lo) >> shift) as u8 & 0x7f);
    }
    out
}

// ---------------------------------------------------------------------------
// USSD strings (TS 23.038 section 5, CBS data coding scheme; section 6.1.2.3.1 padding)
// ---------------------------------------------------------------------------

/// Whether a CBS data coding scheme means the GSM 7-bit default alphabet.
pub fn cbs_dcs_is_gsm7(dcs: u8) -> bool {
    matches!(dcs >> 4, 0x0 | 0x2 | 0x3)
        || dcs == 0x10
        || (dcs & 0xc0 == 0x40 && dcs & 0x0c == 0x00)
        || (dcs & 0xf0 == 0xf0 && dcs & 0x04 == 0)
}

/// Whether a CBS data coding scheme means UCS2.
pub fn cbs_dcs_is_ucs2(dcs: u8) -> bool {
    dcs == 0x11 || (dcs & 0xc0 == 0x40 && dcs & 0x0c == 0x08)
}

/// Decode a USSD-String under its data coding scheme. `None` when the scheme is one this does
/// not interpret (8-bit data, reserved groups).
pub fn ussd_decode(dcs: u8, octets: &[u8]) -> Option<String> {
    if cbs_dcs_is_gsm7(dcs) {
        let count = octets.len() * 8 / 7;
        let mut septets = unpack_septets(octets, count, 0);
        // Section 6.1.2.3.1: 7 spare bits at the end are filled with CR, which is not text.
        if count.is_multiple_of(8) && septets.last() == Some(&0x0d) {
            septets.pop();
        }
        Some(gsm7_text(&septets))
    } else if cbs_dcs_is_ucs2(dcs) {
        let body = if dcs == 0x11 && octets.len() >= 2 {
            &octets[2..]
        } else {
            octets
        };
        let units: Vec<u16> = body
            .chunks(2)
            .filter(|c| c.len() == 2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect();
        Some(String::from_utf16_lossy(&units))
    } else {
        None
    }
}

/// Encode USSD text: the GSM default alphabet (DCS 0x0F) where every character allows it,
/// otherwise UCS2 (DCS 0x48). Returns (dcs, octets).
pub fn ussd_encode(text: &str) -> GsmResult<(u8, Vec<u8>)> {
    let (dcs, octets) = match gsm7_septets(text) {
        Some(mut septets) => {
            // Section 6.1.2.3.1: when 7 spare bits would remain, they carry CR, not zeros (which
            // would read as a trailing '@').
            if septets.len() % 8 == 7 {
                septets.push(0x0d);
            }
            (0x0f, pack_septets(&septets, 0))
        }
        None => {
            let mut out = Vec::new();
            for u in text.encode_utf16() {
                out.extend_from_slice(&u.to_be_bytes());
            }
            (0x48, out)
        }
    };
    if octets.is_empty() || octets.len() > MAX_USSD_OCTETS {
        return Err(format!(
            "USSD text encodes to {} octets (1..{MAX_USSD_OCTETS} allowed)",
            octets.len()
        ));
    }
    Ok((dcs, octets))
}

// ---------------------------------------------------------------------------
// SMS TPDUs (TS 23.040 section 9.2)
// ---------------------------------------------------------------------------

/// TP-Address: length in digits, type of address, semi-octet digits.
fn tp_address_decode(octets: &[u8], pos: &mut usize) -> GsmResult<Value> {
    let digits = *octets.get(*pos).ok_or("TP address length missing")? as usize;
    let toa = *octets.get(*pos + 1).ok_or("TP address type missing")?;
    let n = digits.div_ceil(2);
    let body = octets
        .get(*pos + 2..*pos + 2 + n)
        .ok_or("TP address shorter than its length")?;
    *pos += 2 + n;
    let ton = (toa >> 4) & 0x07;
    let text = if ton == 5 {
        // Alphanumeric (section 9.1.2.5): GSM 7-bit packed in the semi-octets' space.
        gsm7_text(&unpack_septets(body, digits * 4 / 7, 0))
    } else {
        let mut d = tbcd_decode(body);
        d.truncate(digits);
        d
    };
    Ok(json!({
        "digits": text,
        "nature": name_of(NATURES, ton),
        "plan": name_of(PLANS, toa & 0x0f),
    }))
}

fn tp_address_encode(a: &Address) -> GsmResult<Vec<u8>> {
    if a.digits.is_empty() || a.digits.len() > 20 {
        return Err(format!(
            "a TP address of {} digits (1..20 allowed)",
            a.digits.len()
        ));
    }
    let mut out = vec![
        a.digits.len() as u8,
        0x80 | (a.nature & 0x07) << 4 | (a.plan & 0x0f),
    ];
    out.extend(tbcd_encode(&a.digits)?);
    Ok(out)
}

/// TP-User-Data under TP-DCS (section 4 of TS 23.038, the SMS data coding groups).
fn tp_user_data_decode(dcs: u8, udl: usize, ud: &[u8], udhi: bool) -> Value {
    let alphabet = match dcs >> 4 {
        0x0..=0x3 => (dcs >> 2) & 0x03,
        0xf => (dcs >> 2) & 0x01,
        _ => 3,
    };
    let header_len = if udhi {
        ud.first().map(|l| *l as usize + 1).unwrap_or(0)
    } else {
        0
    };
    let (text, encoding) = match alphabet {
        0 => {
            let fill = (7 - (header_len * 8) % 7) % 7;
            let header_septets = (header_len * 8 + fill) / 7;
            let septets = unpack_septets(
                ud.get(header_len..).unwrap_or(&[]),
                udl.saturating_sub(header_septets),
                fill,
            );
            (Some(gsm7_text(&septets)), "gsm7")
        }
        2 => {
            let body = ud.get(header_len..udl.min(ud.len())).unwrap_or(&[]);
            let units: Vec<u16> = body
                .chunks(2)
                .filter(|c| c.len() == 2)
                .map(|c| u16::from_be_bytes([c[0], c[1]]))
                .collect();
            (Some(String::from_utf16_lossy(&units)), "ucs2")
        }
        _ => (None, "8bit"),
    };
    json!({
        "text": text,
        "alphabet": encoding,
        "has_user_data_header": udhi,
        "data_coding_scheme": dcs,
    })
}

/// Encode text as TP-DCS, TP-UDL and TP-UD.
fn tp_user_data_encode(text: &str) -> GsmResult<(u8, u8, Vec<u8>)> {
    match gsm7_septets(text) {
        Some(septets) => {
            if septets.len() > 160 {
                return Err(format!(
                    "SMS text is {} septets; one message holds 160 (concatenation is not \
                     implemented)",
                    septets.len()
                ));
            }
            Ok((0x00, septets.len() as u8, pack_septets(&septets, 0)))
        }
        None => {
            let mut out = Vec::new();
            for u in text.encode_utf16() {
                out.extend_from_slice(&u.to_be_bytes());
            }
            if out.len() > MAX_SMS_UD_OCTETS {
                return Err(format!(
                    "SMS text is {} UCS2 octets; one message holds {MAX_SMS_UD_OCTETS}",
                    out.len()
                ));
            }
            Ok((0x08, out.len() as u8, out))
        }
    }
}

/// Decode an SMS TPDU from the MS-to-SC direction (SMS-SUBMIT) or SC-to-MS (SMS-DELIVER).
/// `mobile_originated` picks the direction, since the message type indicator values overlap.
pub fn sms_tpdu_decode(octets: &[u8], mobile_originated: bool) -> GsmResult<Value> {
    let first = *octets.first().ok_or("empty TPDU")?;
    let mti = first & 0x03;
    let udhi = first & 0x40 != 0;
    let mut pos = 1;
    match (mobile_originated, mti) {
        (true, 1) => {
            let vpf = (first >> 3) & 0x03;
            let mr = *octets.get(pos).ok_or("SMS-SUBMIT without TP-MR")?;
            pos += 1;
            let da = tp_address_decode(octets, &mut pos)?;
            let pid = *octets.get(pos).ok_or("SMS-SUBMIT without TP-PID")?;
            let dcs = *octets.get(pos + 1).ok_or("SMS-SUBMIT without TP-DCS")?;
            pos += 2;
            pos += match vpf {
                0 => 0,
                2 => 1,
                _ => 7,
            };
            let udl = *octets.get(pos).ok_or("SMS-SUBMIT without TP-UDL")? as usize;
            let ud = octets.get(pos + 1..).unwrap_or(&[]);
            Ok(json!({
                "tpdu": "sms_submit",
                "message_reference": mr,
                "destination": da,
                "protocol_identifier": pid,
                "status_report_requested": first & 0x20 != 0,
                "user_data": tp_user_data_decode(dcs, udl, ud, udhi),
            }))
        }
        (false, 0) => {
            let oa = tp_address_decode(octets, &mut pos)?;
            let pid = *octets.get(pos).ok_or("SMS-DELIVER without TP-PID")?;
            let dcs = *octets.get(pos + 1).ok_or("SMS-DELIVER without TP-DCS")?;
            pos += 2;
            let scts = octets
                .get(pos..pos + 7)
                .ok_or("SMS-DELIVER without TP-SCTS")?;
            pos += 7;
            let udl = *octets.get(pos).ok_or("SMS-DELIVER without TP-UDL")? as usize;
            let ud = octets.get(pos + 1..).unwrap_or(&[]);
            Ok(json!({
                "tpdu": "sms_deliver",
                "originator": oa,
                "protocol_identifier": pid,
                "more_messages_to_send": first & 0x04 == 0,
                "service_centre_timestamp": timestamp_decode(scts),
                "user_data": tp_user_data_decode(dcs, udl, ud, udhi),
            }))
        }
        (_, mti) => Ok(json!({
            "tpdu": format!("message_type_indicator_{mti}"),
            "note": "NetGet decodes SMS-SUBMIT (MS to SC) and SMS-DELIVER (SC to MS) only",
        })),
    }
}

/// Encode an SMS-SUBMIT from `{"destination", "text", "message_reference"}`.
pub fn sms_submit_encode(v: &Value) -> GsmResult<Vec<u8>> {
    let da = Address::from_json(
        v.get("destination").ok_or("sms.destination is required")?,
        "sms.destination",
    )?;
    let text = json_str(v, "text")?;
    let mr = v
        .get("message_reference")
        .and_then(Value::as_u64)
        .unwrap_or(0)
        .min(255) as u8;
    let (dcs, udl, ud) = tp_user_data_encode(text)?;
    // TP-MTI SMS-SUBMIT (01), TP-RD 0, TP-VPF none (00), TP-SRR 0, TP-UDHI 0, TP-RP 0.
    let mut out = vec![0x01, mr];
    out.extend(tp_address_encode(&da)?);
    out.extend([0x00, dcs, udl]);
    out.extend(ud);
    Ok(out)
}

/// Encode an SMS-DELIVER from `{"originator", "text", "timestamp"?}`.
pub fn sms_deliver_encode(v: &Value) -> GsmResult<Vec<u8>> {
    let oa = Address::from_json(
        v.get("originator").ok_or("sms.originator is required")?,
        "sms.originator",
    )?;
    let text = json_str(v, "text")?;
    let (dcs, udl, ud) = tp_user_data_encode(text)?;
    let scts = match v.get("timestamp").and_then(Value::as_str) {
        Some(t) => timestamp_encode(t)?,
        None => timestamp_encode("2026-01-01T00:00:00+00:00")?,
    };
    // TP-MTI SMS-DELIVER (00), TP-MMS 1 (no more messages), TP-SRI 0, TP-UDHI 0, TP-RP 0.
    let mut out = vec![0x04];
    out.extend(tp_address_encode(&oa)?);
    out.extend([0x00, dcs]);
    out.extend(scts);
    out.push(udl);
    out.extend(ud);
    Ok(out)
}

/// TP-SCTS: seven semi-octet fields, the last a signed quarter-hour time zone.
fn timestamp_decode(o: &[u8]) -> String {
    let d = |b: u8| (b & 0x0f) * 10 + (b >> 4);
    let tz_raw = o[6];
    let negative = tz_raw & 0x08 != 0;
    let quarters = ((tz_raw & 0x07) * 10 + (tz_raw >> 4)) as i32;
    let minutes = quarters * 15 * if negative { -1 } else { 1 };
    format!(
        "20{:02}-{:02}-{:02}T{:02}:{:02}:{:02}{}{:02}:{:02}",
        d(o[0]),
        d(o[1]),
        d(o[2]),
        d(o[3]),
        d(o[4]),
        d(o[5]),
        if minutes < 0 { '-' } else { '+' },
        minutes.abs() / 60,
        minutes.abs() % 60
    )
}

/// `YYYY-MM-DDThh:mm:ss±hh:mm` (years 2000..2099) to TP-SCTS.
fn timestamp_encode(t: &str) -> GsmResult<Vec<u8>> {
    let bad = || format!("timestamp {t:?} must be YYYY-MM-DDThh:mm:ss+hh:mm, year 2000-2099");
    let b = t.as_bytes();
    if b.len() != 25 || !t.starts_with("20") {
        return Err(bad());
    }
    let num = |s: &str| s.parse::<u8>().map_err(|_| bad());
    let fields = [
        num(&t[2..4])?,
        num(&t[5..7])?,
        num(&t[8..10])?,
        num(&t[11..13])?,
        num(&t[14..16])?,
        num(&t[17..19])?,
    ];
    let sign = b[19];
    let tz_minutes = num(&t[20..22])? as u32 * 60 + num(&t[23..25])? as u32;
    if sign != b'+' && sign != b'-' {
        return Err(bad());
    }
    let semi = |v: u8| (v % 10) << 4 | (v / 10);
    let mut out: Vec<u8> = fields.iter().map(|v| semi(*v)).collect();
    let q = (tz_minutes / 15) as u8;
    out.push(semi(q) | if sign == b'-' { 0x08 } else { 0 });
    Ok(out)
}

// ---------------------------------------------------------------------------
// Cell Global Identity (TS 24.008 section 10.5.1.3 layout, as MAP's 7-octet fixed length form)
// ---------------------------------------------------------------------------

/// MCC/MNC in the three-octet PLMN layout.
pub fn plmn_encode(mcc: &str, mnc: &str) -> GsmResult<[u8; 3]> {
    let d = |s: &str, f: &str| -> GsmResult<Vec<u8>> {
        s.chars()
            .map(|c| {
                c.to_digit(10)
                    .map(|v| v as u8)
                    .ok_or_else(|| format!("{f} {s:?} must be decimal digits"))
            })
            .collect()
    };
    let c = d(mcc, "mcc")?;
    let n = d(mnc, "mnc")?;
    if c.len() != 3 || !(2..=3).contains(&n.len()) {
        return Err(format!(
            "PLMN {mcc}-{mnc}: mcc must be 3 digits and mnc 2 or 3"
        ));
    }
    let mnc3 = if n.len() == 3 { n[2] } else { 0xf };
    Ok([c[1] << 4 | c[0], mnc3 << 4 | c[2], n[1] << 4 | n[0]])
}

pub fn plmn_decode(o: &[u8]) -> (String, String) {
    let n = |v: u8| char::from_digit((v & 0x0f) as u32, 10);
    let mut mcc = String::new();
    let mut mnc = String::new();
    for v in [o[0] & 0x0f, o[0] >> 4, o[1] & 0x0f] {
        if let Some(c) = n(v) {
            mcc.push(c);
        }
    }
    for v in [o[2] & 0x0f, o[2] >> 4, o[1] >> 4] {
        if let Some(c) = n(v) {
            if v <= 9 {
                mnc.push(c);
            }
        }
    }
    (mcc, mnc)
}

/// `{"mcc", "mnc", "lac", "cell_id"}` to the seven-octet CGI.
pub fn cgi_encode(v: &Value) -> GsmResult<Vec<u8>> {
    let mcc = json_str(v, "mcc")?;
    let mnc = json_str(v, "mnc")?;
    let num = |f: &str| -> GsmResult<u16> {
        v.get(f)
            .and_then(Value::as_u64)
            .filter(|n| *n <= 0xffff)
            .map(|n| n as u16)
            .ok_or_else(|| format!("cgi.{f} must be an integer 0..65535"))
    };
    let mut out = plmn_encode(mcc, mnc)?.to_vec();
    out.extend(num("lac")?.to_be_bytes());
    out.extend(num("cell_id")?.to_be_bytes());
    Ok(out)
}

pub fn cgi_decode(o: &[u8]) -> Value {
    if o.len() != 7 && o.len() != 5 {
        return json!({"octets": o.len(), "note": "not a 5- or 7-octet CGI/LAI"});
    }
    let (mcc, mnc) = plmn_decode(&o[..3]);
    let mut v = json!({"mcc": mcc, "mnc": mnc, "lac": u16::from_be_bytes([o[3], o[4]])});
    if o.len() == 7 {
        v["cell_id"] = json!(u16::from_be_bytes([o[5], o[6]]));
    }
    v
}

// ---------------------------------------------------------------------------
// ISUP numbers and cause (Q.763 sections 3.9 and 3.10; Q.850) as CAMEL carries them
// ---------------------------------------------------------------------------

/// Nature of address indicator values for ISUP numbers.
pub const ISUP_NATURES: &[(&str, u8)] = &[
    ("subscriber", 1),
    ("unknown", 2),
    ("national", 3),
    ("international", 4),
    ("network_specific", 5),
];

/// Called/calling party number. `calling` adds the presentation and screening indicators.
pub fn isup_number_encode(v: &Value, field: &str, calling: bool) -> GsmResult<Vec<u8>> {
    let (digits, nai) = match v {
        Value::String(s) => (s.trim_start_matches('+').to_string(), 4),
        Value::Object(o) => (
            o.get("digits")
                .and_then(Value::as_str)
                .ok_or_else(|| format!("{field}.digits is required"))?
                .trim_start_matches('+')
                .to_string(),
            match o.get("nature") {
                Some(n) => value_of(ISUP_NATURES, n, &format!("{field}.nature"), 127)?,
                None => 4,
            },
        ),
        _ => {
            return Err(format!(
                "{field} must be a digit string or {{\"digits\", \"nature\"}}"
            ))
        }
    };
    if digits.is_empty() || digits.len() > 20 || !digits.chars().all(|c| c.is_ascii_digit()) {
        return Err(format!("{field} must be 1..20 decimal digits"));
    }
    let odd = digits.len() % 2 == 1;
    // Octet 2: called: INN 0 (routing to internal network number allowed), NPI ISDN (001);
    // calling: NI complete (0), NPI ISDN, presentation allowed (00), user provided verified (01).
    let second = if calling { 0x11 } else { 0x10 };
    let mut out = vec![(odd as u8) << 7 | nai, second];
    let nibbles: Vec<u8> = digits.bytes().map(|b| b - b'0').collect();
    out.extend(
        nibbles
            .chunks(2)
            .map(|p| p[0] | p.get(1).copied().unwrap_or(0) << 4),
    );
    Ok(out)
}

pub fn isup_number_decode(o: &[u8]) -> Value {
    if o.len() < 2 {
        return json!({"note": "ISUP number shorter than 2 octets"});
    }
    let odd = o[0] & 0x80 != 0;
    let mut digits = String::new();
    for b in &o[2..] {
        for n in [b & 0x0f, b >> 4] {
            digits.push(match n {
                0..=9 => (b'0' + n) as char,
                0xb => '*',
                0xc => '#',
                _ => '?',
            });
        }
    }
    if odd {
        digits.pop();
    }
    json!({
        "digits": digits,
        "nature": name_of(ISUP_NATURES, o[0] & 0x7f),
        "numbering_plan": (o[1] >> 4) & 0x07,
    })
}

/// Q.850 cause values a model is likely to want by name.
pub const CAUSES: &[(&str, u8)] = &[
    ("unallocated_number", 1),
    ("no_route_to_destination", 3),
    ("normal_call_clearing", 16),
    ("user_busy", 17),
    ("no_user_responding", 18),
    ("no_answer", 19),
    ("subscriber_absent", 20),
    ("call_rejected", 21),
    ("number_changed", 22),
    ("destination_out_of_order", 27),
    ("invalid_number_format", 28),
    ("facility_rejected", 29),
    ("normal_unspecified", 31),
    ("no_circuit_available", 34),
    ("network_out_of_order", 38),
    ("temporary_failure", 41),
    ("switching_equipment_congestion", 42),
    ("resource_unavailable", 47),
    ("incoming_calls_barred_within_cug", 55),
    ("bearer_capability_not_authorized", 57),
    ("service_not_available", 63),
    ("interworking_unspecified", 127),
];

/// Q.850 cause: ITU-T coding standard, location "public network serving the local user".
pub fn cause_encode(v: &Value) -> GsmResult<Vec<u8>> {
    let value = value_of(CAUSES, v, "cause", 127)?;
    Ok(vec![0x82, 0x80 | value])
}

pub fn cause_decode(o: &[u8]) -> Value {
    if o.len() < 2 {
        return json!({"note": "cause shorter than 2 octets"});
    }
    // Octet 1 may carry an extension (octet 1a) when its high bit is clear.
    let value_octet = if o[0] & 0x80 == 0 { o.get(2) } else { o.get(1) };
    let value = value_octet.map(|b| b & 0x7f).unwrap_or(0);
    json!({
        "value": value,
        "name": name_of(CAUSES, value),
        "location": o[0] & 0x0f,
    })
}

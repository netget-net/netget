//! SCCP connectionless messages (ITU-T Q.713): UDT, XUDT and their service messages UDTS and
//! XUDTS, Called/Calling Party Addresses with point code, SSN and global title, and the SCMG
//! subsystem messages (section 5.3) an SS7 peer exchanges about subsystem status.
//!
//! This is the user part carried in an M3UA DATA whose Service Indicator is 3. Everything is in
//! the ITU format: 14-bit point codes in two octets little-endian, the address indicator's bit 7
//! the routing indicator, bits 6..3 the global title indicator.
//!
//! # What is refused
//!
//! - **Segmentation.** An XUDT carrying a Segmentation parameter that is not "first and only
//!   segment" would need a reassembly buffer keyed by the far end's local reference. NetGet
//!   refuses it (cause `segmentation not supported`, returned only if the sender asked for
//!   errors back) instead of buffering, so a peer cannot make it hold partial messages.
//! - **Long UDT (LUDT)** and the connection-oriented classes 2 and 3: answered by nothing, logged.
//! - **Data over 255 octets** cannot be expressed in UDT or XUDT (their length field is one
//!   octet); an outgoing TCAP message that does not fit is refused at encode time rather than
//!   segmented.

use super::gsm::tbcd_encode;
use serde_json::{json, Value};

pub const MSG_UDT: u8 = 0x09;
pub const MSG_UDTS: u8 = 0x0a;
pub const MSG_XUDT: u8 = 0x11;
pub const MSG_XUDTS: u8 = 0x12;
pub const MSG_LUDT: u8 = 0x13;
pub const MSG_LUDTS: u8 = 0x14;

/// Optional parameter codes (Q.713 section 3).
pub const PARAM_END_OF_OPTIONAL: u8 = 0x00;
pub const PARAM_SEGMENTATION: u8 = 0x10;
pub const PARAM_IMPORTANCE: u8 = 0x12;

/// Return causes (Q.713 section 3.12).
pub const CAUSE_NO_TRANSLATION_FOR_NATURE: u8 = 0x00;
pub const CAUSE_NO_TRANSLATION_FOR_ADDRESS: u8 = 0x01;
pub const CAUSE_SUBSYSTEM_FAILURE: u8 = 0x03;
pub const CAUSE_UNEQUIPPED_USER: u8 = 0x04;
pub const CAUSE_UNQUALIFIED: u8 = 0x07;
pub const CAUSE_ERROR_IN_LOCAL_PROCESSING: u8 = 0x09;
pub const CAUSE_SEGMENTATION_NOT_SUPPORTED: u8 = 0x0d;

/// SSN 1 is SCCP management itself.
pub const SSN_SCMG: u8 = 1;
/// SCMG format identifiers (Q.713 section 5.3).
pub const SCMG_SSA: u8 = 0x01;
pub const SCMG_SSP: u8 = 0x02;
pub const SCMG_SST: u8 = 0x03;

/// The largest data part a UDT or XUDT can carry: its length is a single octet.
pub const MAX_DATA_LEN: usize = 255;
/// Hop counter NetGet puts in the XUDTs it originates (Q.714 recommends 15 or below).
pub const DEFAULT_HOP_COUNTER: u8 = 15;

fn err<T>(msg: impl Into<String>) -> Result<T, String> {
    Err(msg.into())
}

/// A global title in structured form.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GlobalTitle {
    /// Global title indicator 1..4.
    pub gti: u8,
    pub translation_type: u8,
    /// Numbering plan (GTI 3 and 4); 1 is ISDN/telephony.
    pub numbering_plan: u8,
    /// Nature of address indicator (GTI 1 and 4); 4 is international.
    pub nature: u8,
    pub digits: String,
}

impl GlobalTitle {
    pub fn e164(digits: &str) -> Self {
        GlobalTitle {
            gti: 4,
            translation_type: 0,
            numbering_plan: 1,
            nature: 4,
            digits: digits.to_string(),
        }
    }
}

/// A Called or Calling Party Address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SccpAddress {
    /// Routing indicator: true routes on the global title, false on DPC + SSN.
    pub route_on_gt: bool,
    pub point_code: Option<u16>,
    pub ssn: Option<u8>,
    pub global_title: Option<GlobalTitle>,
    /// Bit 8 of the address indicator, reserved for national use; kept so a reply echoes it.
    pub national: bool,
}

impl SccpAddress {
    pub fn decode(o: &[u8]) -> Result<Self, String> {
        let Some((&ai, mut rest)) = o.split_first() else {
            return err("empty SCCP address");
        };
        let pc_present = ai & 0x01 != 0;
        let ssn_present = ai & 0x02 != 0;
        let gti = (ai >> 2) & 0x0f;
        let route_on_gt = ai & 0x40 == 0;
        let point_code = if pc_present {
            if rest.len() < 2 {
                return err("SCCP address indicates a point code but has no room for it");
            }
            let pc = u16::from_le_bytes([rest[0], rest[1]]) & 0x3fff;
            rest = &rest[2..];
            Some(pc)
        } else {
            None
        };
        let ssn = if ssn_present {
            let Some((&s, r)) = rest.split_first() else {
                return err("SCCP address indicates an SSN but has no room for it");
            };
            rest = r;
            Some(s)
        } else {
            None
        };
        let global_title = match gti {
            0 => None,
            1 => {
                let Some((&b, digits)) = rest.split_first() else {
                    return err("GTI 1 global title is empty");
                };
                let mut d = bcd_digits(digits);
                if b & 0x80 != 0 {
                    d.pop();
                }
                Some(GlobalTitle {
                    gti,
                    translation_type: 0,
                    numbering_plan: 0,
                    nature: b & 0x7f,
                    digits: d,
                })
            }
            2 => {
                let Some((&tt, digits)) = rest.split_first() else {
                    return err("GTI 2 global title is empty");
                };
                Some(GlobalTitle {
                    gti,
                    translation_type: tt,
                    numbering_plan: 0,
                    nature: 0,
                    digits: bcd_digits(digits),
                })
            }
            3 | 4 => {
                let need = if gti == 4 { 3 } else { 2 };
                if rest.len() < need {
                    return err(format!("GTI {gti} global title shorter than its header"));
                }
                let tt = rest[0];
                let np = rest[1] >> 4;
                let es = rest[1] & 0x0f;
                let nature = if gti == 4 { rest[2] & 0x7f } else { 0 };
                let digits = &rest[need..];
                let mut d = bcd_digits(digits);
                // Encoding scheme 1 is BCD with an odd number of digits: the last high nibble is
                // filler, whatever value the sender put there.
                if es == 1 && !d.is_empty() {
                    d.pop();
                } else if es != 1 && es != 2 {
                    return err(format!(
                        "GTI {gti} global title uses encoding scheme {es}; only BCD (1, 2) is \
                         implemented"
                    ));
                }
                Some(GlobalTitle {
                    gti,
                    translation_type: tt,
                    numbering_plan: np,
                    nature,
                    digits: d,
                })
            }
            other => return err(format!("global title indicator {other} is reserved")),
        };
        if route_on_gt && global_title.is_none() {
            return err("SCCP address routes on global title but carries none");
        }
        Ok(SccpAddress {
            route_on_gt,
            point_code,
            ssn,
            global_title,
            national: ai & 0x80 != 0,
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>, String> {
        let gti = self.global_title.as_ref().map(|g| g.gti).unwrap_or(0);
        let mut ai = (gti & 0x0f) << 2;
        if self.point_code.is_some() {
            ai |= 0x01;
        }
        if self.ssn.is_some() {
            ai |= 0x02;
        }
        if !self.route_on_gt {
            ai |= 0x40;
        }
        if self.national {
            ai |= 0x80;
        }
        if self.route_on_gt && self.global_title.is_none() {
            return err("an address that routes on global title needs one");
        }
        if !self.route_on_gt && self.ssn.is_none() {
            return err("an address that routes on SSN needs an ssn");
        }
        let mut out = vec![ai];
        if let Some(pc) = self.point_code {
            if pc > 0x3fff {
                return err(format!("point code {pc} does not fit 14 bits"));
            }
            out.extend(pc.to_le_bytes());
        }
        if let Some(ssn) = self.ssn {
            out.push(ssn);
        }
        if let Some(g) = &self.global_title {
            if g.digits.is_empty() || g.digits.len() > 32 {
                return err("a global title needs 1..32 digits");
            }
            let odd = g.digits.len() % 2 == 1;
            let digits = tbcd_encode(&g.digits)?;
            // Odd counts are filled with 0 in SCCP, not with TBCD's F.
            let digits: Vec<u8> = if odd {
                let mut d = digits;
                if let Some(last) = d.last_mut() {
                    *last &= 0x0f;
                }
                d
            } else {
                digits
            };
            match g.gti {
                1 => {
                    out.push((odd as u8) << 7 | (g.nature & 0x7f));
                }
                2 => out.push(g.translation_type),
                3 => {
                    out.push(g.translation_type);
                    out.push(g.numbering_plan << 4 | if odd { 1 } else { 2 });
                }
                4 => {
                    out.push(g.translation_type);
                    out.push(g.numbering_plan << 4 | if odd { 1 } else { 2 });
                    out.push(g.nature & 0x7f);
                }
                other => return err(format!("global title indicator {other} is not 1..4")),
            }
            out.extend(digits);
        }
        Ok(out)
    }

    pub fn to_json(&self) -> Value {
        let mut v = json!({
            "route_on": if self.route_on_gt { "gt" } else { "ssn" },
            "pc": self.point_code,
            "ssn": self.ssn,
        });
        if let Some(g) = &self.global_title {
            v["gt"] = json!({
                "digits": g.digits,
                "gti": g.gti,
                "tt": g.translation_type,
                "np": g.numbering_plan,
                "nai": g.nature,
            });
        }
        v
    }

    /// From `{"route_on": "gt"|"ssn", "pc", "ssn", "gt": "digits" | {"digits","tt","np","nai","gti"}}`.
    pub fn from_json(v: &Value, field: &str) -> Result<Self, String> {
        let o = v
            .as_object()
            .ok_or_else(|| format!("{field} must be an object {{route_on, pc, ssn, gt}}"))?;
        let num = |k: &str, max: u64| -> Result<Option<u64>, String> {
            match o.get(k) {
                None | Some(Value::Null) => Ok(None),
                Some(x) => x
                    .as_u64()
                    .filter(|n| *n <= max)
                    .map(Some)
                    .ok_or_else(|| format!("{field}.{k} must be an integer 0..{max}")),
            }
        };
        let global_title = match o.get("gt") {
            None | Some(Value::Null) => None,
            Some(Value::String(s)) => Some(GlobalTitle::e164(s.trim_start_matches('+'))),
            Some(Value::Object(g)) => {
                let get = |k: &str, d: u8, max: u8| -> Result<u8, String> {
                    match g.get(k) {
                        None => Ok(d),
                        Some(x) => x
                            .as_u64()
                            .filter(|n| *n <= max as u64)
                            .map(|n| n as u8)
                            .ok_or_else(|| format!("{field}.gt.{k} must be 0..{max}")),
                    }
                };
                Some(GlobalTitle {
                    gti: get("gti", 4, 4)?.max(1),
                    translation_type: get("tt", 0, 255)?,
                    numbering_plan: get("np", 1, 15)?,
                    nature: get("nai", 4, 127)?,
                    digits: g
                        .get("digits")
                        .and_then(Value::as_str)
                        .ok_or_else(|| format!("{field}.gt.digits is required"))?
                        .trim_start_matches('+')
                        .to_string(),
                })
            }
            Some(_) => return Err(format!("{field}.gt must be digits or an object")),
        };
        let route_on_gt = match o.get("route_on").and_then(Value::as_str) {
            Some("gt") => true,
            Some("ssn") => false,
            Some(other) => return Err(format!("{field}.route_on {other:?} is not gt or ssn")),
            None => global_title.is_some() && o.get("pc").is_none(),
        };
        let a = SccpAddress {
            route_on_gt,
            point_code: num("pc", 0x3fff)?.map(|n| n as u16),
            ssn: num("ssn", 255)?.map(|n| n as u8),
            global_title,
            national: false,
        };
        a.encode()?;
        Ok(a)
    }
}

/// BCD digits as SCCP writes them (filler 0 for odd counts is handled by the caller).
fn bcd_digits(o: &[u8]) -> String {
    let mut out = String::new();
    for b in o {
        for n in [b & 0x0f, b >> 4] {
            out.push(match n {
                0..=9 => (b'0' + n) as char,
                0xb => '*',
                0xc => '#',
                0xa => 'a',
                0xd => 'b',
                0xe => 'c',
                _ => 'f',
            });
        }
    }
    out
}

/// A Segmentation parameter (Q.713 section 3.17).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Segmentation {
    pub first: bool,
    pub remaining: u8,
    pub local_reference: u32,
}

impl Segmentation {
    /// "First segment, no more to come" carries the whole message and needs no reassembly.
    pub fn is_whole_message(&self) -> bool {
        self.first && self.remaining == 0
    }
}

/// A decoded connectionless SCCP message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Unitdata {
    pub message_type: u8,
    /// Protocol class 0 or 1 (low nibble of the protocol class octet).
    pub protocol_class: u8,
    /// Return-on-error: the sender wants a UDTS/XUDTS if delivery fails.
    pub return_on_error: bool,
    /// UDTS/XUDTS only.
    pub return_cause: Option<u8>,
    pub hop_counter: Option<u8>,
    pub called: SccpAddress,
    pub calling: SccpAddress,
    pub data: Vec<u8>,
    pub segmentation: Option<Segmentation>,
    pub importance: Option<u8>,
}

impl Unitdata {
    pub fn is_service_message(&self) -> bool {
        matches!(self.message_type, MSG_UDTS | MSG_XUDTS)
    }

    pub fn type_name(&self) -> &'static str {
        message_type_name(self.message_type)
    }
}

pub fn message_type_name(t: u8) -> &'static str {
    match t {
        MSG_UDT => "UDT",
        MSG_UDTS => "UDTS",
        MSG_XUDT => "XUDT",
        MSG_XUDTS => "XUDTS",
        MSG_LUDT => "LUDT",
        MSG_LUDTS => "LUDTS",
        0x01 => "CR",
        0x02 => "CC",
        0x03 => "CREF",
        0x04 => "RLSD",
        0x05 => "RLC",
        0x06 => "DT1",
        _ => "unknown",
    }
}

/// Follow a one-octet pointer at `at` to a length-prefixed field.
fn variable(o: &[u8], at: usize, name: &str) -> Result<Vec<u8>, String> {
    let ptr = *o
        .get(at)
        .ok_or_else(|| format!("SCCP message ends before the {name} pointer"))?
        as usize;
    if ptr == 0 {
        return err(format!("SCCP {name} pointer is zero"));
    }
    let start = at + ptr;
    let len = *o
        .get(start)
        .ok_or_else(|| format!("SCCP {name} pointer leads past the end"))? as usize;
    o.get(start + 1..start + 1 + len)
        .map(|s| s.to_vec())
        .ok_or_else(|| format!("SCCP {name} of {len} octets runs past the end"))
}

/// Decode a UDT, XUDT, UDTS or XUDTS. Other types are reported by name in the error.
pub fn decode(o: &[u8]) -> Result<Unitdata, String> {
    let Some(&mt) = o.first() else {
        return err("empty SCCP message");
    };
    let (class_octet, cause, hop, ptr_base, has_optional) = match mt {
        MSG_UDT => (
            Some(*o.get(1).ok_or("UDT without protocol class")?),
            None,
            None,
            2,
            false,
        ),
        MSG_UDTS => (
            None,
            Some(*o.get(1).ok_or("UDTS without return cause")?),
            None,
            2,
            false,
        ),
        MSG_XUDT => (
            Some(*o.get(1).ok_or("XUDT without protocol class")?),
            None,
            Some(*o.get(2).ok_or("XUDT without hop counter")?),
            3,
            true,
        ),
        MSG_XUDTS => (
            None,
            Some(*o.get(1).ok_or("XUDTS without return cause")?),
            Some(*o.get(2).ok_or("XUDTS without hop counter")?),
            3,
            true,
        ),
        other => {
            return err(format!(
                "SCCP {} (message type 0x{other:02x}) is not implemented; NetGet handles UDT, \
                 XUDT, UDTS and XUDTS",
                message_type_name(other)
            ))
        }
    };
    let called = SccpAddress::decode(&variable(o, ptr_base, "called party address")?)?;
    let calling = SccpAddress::decode(&variable(o, ptr_base + 1, "calling party address")?)?;
    let data = variable(o, ptr_base + 2, "data")?;
    let mut segmentation = None;
    let mut importance = None;
    if has_optional {
        let ptr = *o
            .get(ptr_base + 3)
            .ok_or("XUDT ends before its optional pointer")? as usize;
        if ptr != 0 {
            let mut pos = ptr_base + 3 + ptr;
            // At most a handful of optional parameters exist; bound the walk anyway.
            for _ in 0..16 {
                let Some(&code) = o.get(pos) else {
                    return err("XUDT optional part ends without end-of-optional-parameters");
                };
                if code == PARAM_END_OF_OPTIONAL {
                    break;
                }
                let len = *o
                    .get(pos + 1)
                    .ok_or("XUDT optional parameter without length")?
                    as usize;
                let v = o
                    .get(pos + 2..pos + 2 + len)
                    .ok_or("XUDT optional parameter runs past the end")?;
                match code {
                    PARAM_SEGMENTATION if len == 4 => {
                        segmentation = Some(Segmentation {
                            first: v[0] & 0x80 != 0,
                            remaining: v[0] & 0x0f,
                            local_reference: u32::from_be_bytes([0, v[1], v[2], v[3]]),
                        });
                    }
                    PARAM_IMPORTANCE if len == 1 => importance = Some(v[0] & 0x07),
                    _ => {}
                }
                pos += 2 + len;
            }
        }
    }
    let class = class_octet.unwrap_or(0);
    Ok(Unitdata {
        message_type: mt,
        protocol_class: class & 0x0f,
        return_on_error: class & 0x80 != 0,
        return_cause: cause,
        hop_counter: hop,
        called,
        calling,
        data,
        segmentation,
        importance,
    })
}

/// Encode a UDT (protocol class 0 or 1).
pub fn encode_udt(
    protocol_class: u8,
    return_on_error: bool,
    called: &SccpAddress,
    calling: &SccpAddress,
    data: &[u8],
) -> Result<Vec<u8>, String> {
    let class = (protocol_class & 0x01) | if return_on_error { 0x80 } else { 0 };
    encode_unitdata(MSG_UDT, &[class], called, calling, data, false)
}

/// Encode an XUDT with the given hop counter and no optional parameters.
pub fn encode_xudt(
    protocol_class: u8,
    return_on_error: bool,
    hop_counter: u8,
    called: &SccpAddress,
    calling: &SccpAddress,
    data: &[u8],
) -> Result<Vec<u8>, String> {
    let class = (protocol_class & 0x01) | if return_on_error { 0x80 } else { 0 };
    encode_unitdata(
        MSG_XUDT,
        &[class, hop_counter.clamp(1, 15)],
        called,
        calling,
        data,
        true,
    )
}

/// The service message answering `original` with `cause`: UDTS for a UDT, XUDTS for an XUDT.
/// Addresses are swapped, the data is returned (truncated to what fits).
pub fn encode_service(original: &Unitdata, cause: u8) -> Result<Vec<u8>, String> {
    let mut data = original.data.clone();
    data.truncate(MAX_DATA_LEN);
    match original.message_type {
        MSG_XUDT => encode_unitdata(
            MSG_XUDTS,
            &[cause, DEFAULT_HOP_COUNTER],
            &original.calling,
            &original.called,
            &data,
            true,
        ),
        _ => encode_unitdata(
            MSG_UDTS,
            &[cause],
            &original.calling,
            &original.called,
            &data,
            false,
        ),
    }
}

fn encode_unitdata(
    mt: u8,
    fixed: &[u8],
    called: &SccpAddress,
    calling: &SccpAddress,
    data: &[u8],
    optional_pointer: bool,
) -> Result<Vec<u8>, String> {
    if data.len() > MAX_DATA_LEN {
        return err(format!(
            "{} octets of data do not fit one {} ({MAX_DATA_LEN} at most); NetGet does not \
             segment",
            data.len(),
            message_type_name(mt)
        ));
    }
    let called = called.encode()?;
    let calling = calling.encode()?;
    let pointers = if optional_pointer { 4 } else { 3 };
    let mut out = vec![mt];
    out.extend_from_slice(fixed);
    // Each pointer counts from its own octet to the length octet of its field.
    let p_called = pointers;
    let p_calling = p_called - 1 + 1 + called.len();
    let p_data = p_calling - 1 + 1 + calling.len();
    for p in [p_called, p_calling, p_data] {
        if p > 255 {
            return err("SCCP addresses too long for one-octet pointers");
        }
    }
    out.push(p_called as u8);
    out.push(p_calling as u8);
    out.push(p_data as u8);
    if optional_pointer {
        out.push(0);
    }
    out.push(called.len() as u8);
    out.extend(called);
    out.push(calling.len() as u8);
    out.extend(calling);
    out.push(data.len() as u8);
    out.extend_from_slice(data);
    Ok(out)
}

/// A decoded SCMG message (Q.713 section 5.3), the data of a UDT to SSN 1.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Scmg {
    pub format: u8,
    pub affected_ssn: u8,
    pub affected_pc: u16,
    pub multiplicity: u8,
}

impl Scmg {
    pub fn decode(o: &[u8]) -> Result<Self, String> {
        if o.len() < 5 {
            return err(format!("SCMG message of {} octets (5 expected)", o.len()));
        }
        Ok(Scmg {
            format: o[0],
            affected_ssn: o[1],
            affected_pc: u16::from_le_bytes([o[2], o[3]]) & 0x3fff,
            multiplicity: o[4] & 0x03,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let pc = self.affected_pc.to_le_bytes();
        vec![
            self.format,
            self.affected_ssn,
            pc[0],
            pc[1],
            self.multiplicity,
        ]
    }

    pub fn name(&self) -> &'static str {
        match self.format {
            SCMG_SSA => "SSA",
            SCMG_SSP => "SSP",
            SCMG_SST => "SST",
            0x04 => "SOR",
            0x05 => "SOG",
            0x06 => "SSC",
            _ => "unknown",
        }
    }
}

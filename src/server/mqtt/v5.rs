//! MQTT 5.0 properties and reason codes (OASIS MQTT v5.0, §2.2.2 and §2.4).
//!
//! A v5 connection differs from a 3.1.1 one in two places, and this module holds both:
//!
//! - **Properties.** Every variable header except PINGREQ/PINGRESP gains a property block: a
//!   variable byte integer length, then `identifier, value` pairs whose value type is fixed by
//!   the identifier (§2.2.2.2). [`read_properties`] decodes one block into [`Properties`] and
//!   [`PropertyWriter`] encodes one.
//! - **Reason codes.** CONNACK's return code, SUBACK's granted QoS and the PUBACK / PUBREC /
//!   UNSUBACK / DISCONNECT acknowledgements carry a one-byte reason code from a table per
//!   packet (§2.4). 3.1.1's six CONNACK codes map onto v5's, which is what
//!   [`connack_v311_to_v5`] and [`connack_v5_to_v311`] do, so a handler written for one version
//!   still answers the other correctly.
//!
//! Binary properties (Correlation Data, Authentication Data) never reach the model as bytes:
//! they are rendered as text when they are UTF-8 and as hex otherwise, with a sibling
//! `<name>_encoding` saying which, and the actions take the same `encoding` field back — the
//! rule `send_tcp_data` taught this repository (AGENTS.md, "Action & event design rules").

use serde_json::{json, Map, Value};

// ---------------------------------------------------------------------------
// Property identifiers (§2.2.2.2)
// ---------------------------------------------------------------------------

pub const PAYLOAD_FORMAT_INDICATOR: u8 = 0x01;
pub const MESSAGE_EXPIRY_INTERVAL: u8 = 0x02;
pub const CONTENT_TYPE: u8 = 0x03;
pub const RESPONSE_TOPIC: u8 = 0x08;
pub const CORRELATION_DATA: u8 = 0x09;
pub const SUBSCRIPTION_IDENTIFIER: u8 = 0x0B;
pub const SESSION_EXPIRY_INTERVAL: u8 = 0x11;
pub const ASSIGNED_CLIENT_IDENTIFIER: u8 = 0x12;
pub const SERVER_KEEP_ALIVE: u8 = 0x13;
pub const AUTHENTICATION_METHOD: u8 = 0x15;
pub const AUTHENTICATION_DATA: u8 = 0x16;
pub const REQUEST_PROBLEM_INFORMATION: u8 = 0x17;
pub const WILL_DELAY_INTERVAL: u8 = 0x18;
pub const REQUEST_RESPONSE_INFORMATION: u8 = 0x19;
pub const RESPONSE_INFORMATION: u8 = 0x1A;
pub const SERVER_REFERENCE: u8 = 0x1C;
pub const REASON_STRING: u8 = 0x1F;
pub const RECEIVE_MAXIMUM: u8 = 0x21;
pub const TOPIC_ALIAS_MAXIMUM: u8 = 0x22;
pub const TOPIC_ALIAS: u8 = 0x23;
pub const MAXIMUM_QOS: u8 = 0x24;
pub const RETAIN_AVAILABLE: u8 = 0x25;
pub const USER_PROPERTY: u8 = 0x26;
pub const MAXIMUM_PACKET_SIZE: u8 = 0x27;
pub const WILDCARD_SUBSCRIPTION_AVAILABLE: u8 = 0x28;
pub const SUBSCRIPTION_IDENTIFIER_AVAILABLE: u8 = 0x29;
pub const SHARED_SUBSCRIPTION_AVAILABLE: u8 = 0x2A;

/// The value type an identifier carries. Fixed by the specification, so an identifier this
/// table does not know is a malformed packet rather than something to skip: there is no way
/// to know how many bytes its value occupies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Byte,
    U16,
    U32,
    Varint,
    Utf8,
    Binary,
    Pair,
}

/// Identifier → (snake_case name the model sees, value type).
fn describe(id: u8) -> Option<(&'static str, Kind)> {
    Some(match id {
        PAYLOAD_FORMAT_INDICATOR => ("payload_format_indicator", Kind::Byte),
        MESSAGE_EXPIRY_INTERVAL => ("message_expiry_interval", Kind::U32),
        CONTENT_TYPE => ("content_type", Kind::Utf8),
        RESPONSE_TOPIC => ("response_topic", Kind::Utf8),
        CORRELATION_DATA => ("correlation_data", Kind::Binary),
        SUBSCRIPTION_IDENTIFIER => ("subscription_identifier", Kind::Varint),
        SESSION_EXPIRY_INTERVAL => ("session_expiry_interval", Kind::U32),
        ASSIGNED_CLIENT_IDENTIFIER => ("assigned_client_identifier", Kind::Utf8),
        SERVER_KEEP_ALIVE => ("server_keep_alive", Kind::U16),
        AUTHENTICATION_METHOD => ("authentication_method", Kind::Utf8),
        AUTHENTICATION_DATA => ("authentication_data", Kind::Binary),
        REQUEST_PROBLEM_INFORMATION => ("request_problem_information", Kind::Byte),
        WILL_DELAY_INTERVAL => ("will_delay_interval", Kind::U32),
        REQUEST_RESPONSE_INFORMATION => ("request_response_information", Kind::Byte),
        RESPONSE_INFORMATION => ("response_information", Kind::Utf8),
        SERVER_REFERENCE => ("server_reference", Kind::Utf8),
        REASON_STRING => ("reason_string", Kind::Utf8),
        RECEIVE_MAXIMUM => ("receive_maximum", Kind::U16),
        TOPIC_ALIAS_MAXIMUM => ("topic_alias_maximum", Kind::U16),
        TOPIC_ALIAS => ("topic_alias", Kind::U16),
        MAXIMUM_QOS => ("maximum_qos", Kind::Byte),
        RETAIN_AVAILABLE => ("retain_available", Kind::Byte),
        USER_PROPERTY => ("user_properties", Kind::Pair),
        MAXIMUM_PACKET_SIZE => ("maximum_packet_size", Kind::U32),
        WILDCARD_SUBSCRIPTION_AVAILABLE => ("wildcard_subscription_available", Kind::Byte),
        SUBSCRIPTION_IDENTIFIER_AVAILABLE => ("subscription_identifier_available", Kind::Byte),
        SHARED_SUBSCRIPTION_AVAILABLE => ("shared_subscription_available", Kind::Byte),
        _ => return None,
    })
}

/// One decoded property value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PropValue {
    Int(u32),
    Text(String),
    Binary(Vec<u8>),
    Pair(String, String),
}

/// A decoded property block, in wire order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Properties {
    pub entries: Vec<(u8, PropValue)>,
}

impl Properties {
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn int(&self, id: u8) -> Option<u32> {
        self.entries.iter().find_map(|(i, v)| match v {
            PropValue::Int(n) if *i == id => Some(*n),
            _ => None,
        })
    }

    pub fn text(&self, id: u8) -> Option<&str> {
        self.entries.iter().find_map(|(i, v)| match v {
            PropValue::Text(s) if *i == id => Some(s.as_str()),
            _ => None,
        })
    }

    pub fn binary(&self, id: u8) -> Option<&[u8]> {
        self.entries.iter().find_map(|(i, v)| match v {
            PropValue::Binary(b) if *i == id => Some(b.as_slice()),
            _ => None,
        })
    }

    /// The block as the model sees it: one key per property, User Properties as a list of
    /// `[name, value]` pairs (names may repeat, §3.1.2.11.8), Subscription Identifiers as a
    /// list (a PUBLISH may carry several), binary values as text or hex.
    pub fn to_json(&self) -> Value {
        let mut out = Map::new();
        let mut pairs: Vec<Value> = Vec::new();
        let mut sub_ids: Vec<Value> = Vec::new();
        for (id, value) in &self.entries {
            let Some((name, _)) = describe(*id) else {
                continue;
            };
            match value {
                PropValue::Pair(k, v) => pairs.push(json!([k, v])),
                PropValue::Int(n) if *id == SUBSCRIPTION_IDENTIFIER => sub_ids.push(json!(n)),
                PropValue::Int(n) => {
                    out.insert(name.to_string(), json!(n));
                }
                PropValue::Text(s) => {
                    out.insert(name.to_string(), json!(s));
                }
                PropValue::Binary(b) => {
                    let (text, encoding) = binary_to_text(b);
                    out.insert(name.to_string(), json!(text));
                    out.insert(format!("{name}_encoding"), json!(encoding));
                }
            }
        }
        if !pairs.is_empty() {
            out.insert("user_properties".into(), Value::Array(pairs));
        }
        if !sub_ids.is_empty() {
            out.insert("subscription_identifiers".into(), Value::Array(sub_ids));
        }
        Value::Object(out)
    }
}

/// Render binary for the model: UTF-8 text when it is, hex otherwise.
pub fn binary_to_text(bytes: &[u8]) -> (String, &'static str) {
    match std::str::from_utf8(bytes) {
        Ok(s) if !crate::utils::sanitize::has_controls(s) => (s.to_string(), "utf8"),
        _ => (hex::encode(bytes), "hex"),
    }
}

/// The inverse of [`binary_to_text`], with the encoding named by the caller rather than
/// guessed: `"48656c6c6f"` is valid text and valid hex, and only the sender knows which.
pub fn text_to_binary(text: &str, encoding: Option<&str>) -> Result<Vec<u8>, String> {
    match encoding.unwrap_or("utf8") {
        "utf8" => Ok(text.as_bytes().to_vec()),
        "hex" => hex::decode(text).map_err(|e| format!("not valid hex: {e}")),
        other => Err(format!(
            "encoding must be \"utf8\" or \"hex\", not {other:?}"
        )),
    }
}

/// Decode a variable byte integer (§1.5.5) at `pos`, advancing it. At most four bytes.
pub fn read_varint(buf: &[u8], pos: &mut usize) -> Option<u32> {
    let mut value: u32 = 0;
    for i in 0..4 {
        let byte = *buf.get(*pos + i)?;
        value |= u32::from(byte & 0x7F) << (7 * i);
        if byte & 0x80 == 0 {
            *pos += i + 1;
            return Some(value);
        }
    }
    None
}

/// Encode a variable byte integer. Values above 268 435 455 are not representable and are
/// clamped by the caller's validation; this writes at most four bytes.
pub fn write_varint(out: &mut Vec<u8>, mut value: u32) {
    for _ in 0..4 {
        let mut byte = (value % 128) as u8;
        value /= 128;
        if value > 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
}

/// Largest value a variable byte integer can hold (§1.5.5).
pub const VARINT_MAX: u32 = 268_435_455;

fn read_u16(buf: &[u8], pos: &mut usize) -> Option<u16> {
    let b = buf.get(*pos..*pos + 2)?;
    *pos += 2;
    Some(u16::from_be_bytes([b[0], b[1]]))
}

fn read_bin(buf: &[u8], pos: &mut usize) -> Option<Vec<u8>> {
    let len = usize::from(read_u16(buf, pos)?);
    let end = pos.checked_add(len)?;
    let b = buf.get(*pos..end)?.to_vec();
    *pos = end;
    Some(b)
}

fn read_utf8(buf: &[u8], pos: &mut usize) -> Option<String> {
    // §1.5.4: a UTF-8 Encoded String that is not well-formed is a Malformed Packet.
    String::from_utf8(read_bin(buf, pos)?).ok()
}

/// Why a property block was rejected. Each maps to the reason code a v5 DISCONNECT carries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PropertyError {
    /// Truncated, an unknown identifier, an over-long varint or ill-formed UTF-8 (0x81).
    Malformed(String),
    /// A property that may appear once appeared twice (0x82, §2.2.2.2).
    Duplicate(&'static str),
}

impl std::fmt::Display for PropertyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PropertyError::Malformed(m) => write!(f, "malformed properties: {m}"),
            PropertyError::Duplicate(n) => write!(f, "property {n} appears more than once"),
        }
    }
}

/// Decode one property block at `pos` — its varint length, then exactly that many bytes of
/// properties — advancing `pos` past it.
pub fn read_properties(buf: &[u8], pos: &mut usize) -> Result<Properties, PropertyError> {
    let malformed = |m: &str| PropertyError::Malformed(m.to_string());
    let len = read_varint(buf, pos).ok_or_else(|| malformed("property length"))? as usize;
    let end = pos
        .checked_add(len)
        .filter(|e| *e <= buf.len())
        .ok_or_else(|| malformed("property length runs past the packet"))?;
    let block = &buf[*pos..end];
    let mut p = 0usize;
    let mut props = Properties::default();
    while p < block.len() {
        let id = read_varint(block, &mut p).ok_or_else(|| malformed("property identifier"))?;
        let id = u8::try_from(id).map_err(|_| malformed("property identifier out of range"))?;
        let (name, kind) =
            describe(id).ok_or_else(|| malformed(&format!("unknown property 0x{id:02x}")))?;
        let value = match kind {
            Kind::Byte => PropValue::Int(u32::from(*block.get(p).ok_or_else(|| malformed(name))?)),
            Kind::U16 => PropValue::Int(u32::from(
                read_u16(block, &mut p).ok_or_else(|| malformed(name))?,
            )),
            Kind::U32 => {
                let b = block.get(p..p + 4).ok_or_else(|| malformed(name))?;
                p += 4;
                PropValue::Int(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
            }
            Kind::Varint => {
                PropValue::Int(read_varint(block, &mut p).ok_or_else(|| malformed(name))?)
            }
            Kind::Utf8 => PropValue::Text(read_utf8(block, &mut p).ok_or_else(|| malformed(name))?),
            Kind::Binary => {
                PropValue::Binary(read_bin(block, &mut p).ok_or_else(|| malformed(name))?)
            }
            Kind::Pair => {
                let k = read_utf8(block, &mut p).ok_or_else(|| malformed(name))?;
                let v = read_utf8(block, &mut p).ok_or_else(|| malformed(name))?;
                PropValue::Pair(k, v)
            }
        };
        if kind == Kind::Byte {
            p += 1;
        }
        // User Property may repeat, and so may Subscription Identifier in a PUBLISH the
        // server sends; everything else is "a Protocol Error to include ... more than once".
        let repeatable = id == USER_PROPERTY || id == SUBSCRIPTION_IDENTIFIER;
        if !repeatable && props.entries.iter().any(|(i, _)| *i == id) {
            return Err(PropertyError::Duplicate(name));
        }
        props.entries.push((id, value));
    }
    *pos = end;
    Ok(props)
}

/// Builds one property block. [`PropertyWriter::finish`] prefixes the varint length.
#[derive(Default, Debug, Clone)]
pub struct PropertyWriter {
    body: Vec<u8>,
}

impl PropertyWriter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.body.is_empty()
    }

    pub fn byte(&mut self, id: u8, v: u8) -> &mut Self {
        self.body.extend_from_slice(&[id, v]);
        self
    }

    pub fn u16(&mut self, id: u8, v: u16) -> &mut Self {
        self.body.push(id);
        self.body.extend_from_slice(&v.to_be_bytes());
        self
    }

    pub fn u32(&mut self, id: u8, v: u32) -> &mut Self {
        self.body.push(id);
        self.body.extend_from_slice(&v.to_be_bytes());
        self
    }

    pub fn varint(&mut self, id: u8, v: u32) -> &mut Self {
        self.body.push(id);
        write_varint(&mut self.body, v);
        self
    }

    fn lp(&mut self, bytes: &[u8]) {
        // Callers bound every string and binary they write to u16::MAX; see `validate_*`.
        let len = bytes.len().min(usize::from(u16::MAX));
        self.body.extend_from_slice(&(len as u16).to_be_bytes());
        self.body.extend_from_slice(&bytes[..len]);
    }

    pub fn text(&mut self, id: u8, v: &str) -> &mut Self {
        self.body.push(id);
        self.lp(v.as_bytes());
        self
    }

    pub fn binary(&mut self, id: u8, v: &[u8]) -> &mut Self {
        self.body.push(id);
        self.lp(v);
        self
    }

    pub fn pair(&mut self, k: &str, v: &str) -> &mut Self {
        self.body.push(USER_PROPERTY);
        self.lp(k.as_bytes());
        self.lp(v.as_bytes());
        self
    }

    /// Append every entry of a decoded block (used to carry properties onward unchanged).
    pub fn extend(&mut self, props: &Properties) -> &mut Self {
        for (id, value) in &props.entries {
            match (describe(*id).map(|d| d.1), value) {
                (Some(Kind::Byte), PropValue::Int(n)) => self.byte(*id, *n as u8),
                (Some(Kind::U16), PropValue::Int(n)) => self.u16(*id, *n as u16),
                (Some(Kind::U32), PropValue::Int(n)) => self.u32(*id, *n),
                (Some(Kind::Varint), PropValue::Int(n)) => self.varint(*id, *n),
                (Some(Kind::Utf8), PropValue::Text(s)) => self.text(*id, s),
                (Some(Kind::Binary), PropValue::Binary(b)) => self.binary(*id, b),
                (Some(Kind::Pair), PropValue::Pair(k, v)) => self.pair(k, v),
                _ => self,
            };
        }
        self
    }

    /// Append another writer's properties after this one's.
    pub fn append(&mut self, other: &PropertyWriter) -> &mut Self {
        self.body.extend_from_slice(&other.body);
        self
    }

    /// The block as it goes on the wire: varint length, then the properties.
    pub fn finish(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.body.len() + 4);
        write_varint(&mut out, self.body.len() as u32);
        out.extend_from_slice(&self.body);
        out
    }
}

/// Read a model-supplied `user_properties` field: a list of `[name, value]` pairs (the shape
/// the events use, so a handler can echo one back) or an object of `name: value`.
pub fn user_properties_from_json(v: Option<&Value>) -> Result<Vec<(String, String)>, String> {
    let Some(v) = v else {
        return Ok(Vec::new());
    };
    let as_text = |x: &Value| -> Result<String, String> {
        match x {
            Value::String(s) => Ok(s.clone()),
            Value::Number(n) => Ok(n.to_string()),
            Value::Bool(b) => Ok(b.to_string()),
            other => Err(format!("user property values must be strings, not {other}")),
        }
    };
    let pairs = match v {
        Value::Null => Vec::new(),
        Value::Object(map) => map
            .iter()
            .map(|(k, x)| Ok((k.clone(), as_text(x)?)))
            .collect::<Result<Vec<_>, String>>()?,
        Value::Array(items) => items
            .iter()
            .map(|item| match item {
                Value::Array(kv) if kv.len() == 2 => Ok((as_text(&kv[0])?, as_text(&kv[1])?)),
                Value::Object(o) => match (o.get("name").or(o.get("key")), o.get("value")) {
                    (Some(k), Some(x)) => Ok((as_text(k)?, as_text(x)?)),
                    _ => Err("each user property object needs \"name\" and \"value\"".into()),
                },
                other => Err(format!(
                    "each user property is a [name, value] pair, not {other}"
                )),
            })
            .collect::<Result<Vec<_>, String>>()?,
        other => {
            return Err(format!(
                "user_properties is a list of [name, value] pairs or an object, not {other}"
            ))
        }
    };
    for (k, x) in &pairs {
        if k.len() > usize::from(u16::MAX) || x.len() > usize::from(u16::MAX) {
            return Err("a user property name or value is longer than 65535 bytes".into());
        }
    }
    Ok(pairs)
}

// ---------------------------------------------------------------------------
// Reason codes (§2.4)
// ---------------------------------------------------------------------------

/// CONNACK reason codes a server may send (§3.2.2.2).
pub const CONNACK_REASON_CODES: &[(u8, &str)] = &[
    (0x00, "success"),
    (0x80, "unspecified error"),
    (0x81, "malformed packet"),
    (0x82, "protocol error"),
    (0x83, "implementation specific error"),
    (0x84, "unsupported protocol version"),
    (0x85, "client identifier not valid"),
    (0x86, "bad user name or password"),
    (0x87, "not authorized"),
    (0x88, "server unavailable"),
    (0x89, "server busy"),
    (0x8A, "banned"),
    (0x8C, "bad authentication method"),
    (0x90, "topic name invalid"),
    (0x95, "packet too large"),
    (0x97, "quota exceeded"),
    (0x99, "payload format invalid"),
    (0x9A, "retain not supported"),
    (0x9B, "QoS not supported"),
    (0x9C, "use another server"),
    (0x9D, "server moved"),
    (0x9F, "connection rate exceeded"),
];

/// SUBACK reason codes (§3.9.3): the granted QoS, or a refusal.
pub const SUBACK_REASON_CODES: &[(u8, &str)] = &[
    (0x00, "granted QoS 0"),
    (0x01, "granted QoS 1"),
    (0x02, "granted QoS 2"),
    (0x80, "unspecified error"),
    (0x83, "implementation specific error"),
    (0x87, "not authorized"),
    (0x8F, "topic filter invalid"),
    (0x91, "packet identifier in use"),
    (0x97, "quota exceeded"),
    (0x9E, "shared subscriptions not supported"),
    (0xA1, "subscription identifiers not supported"),
    (0xA2, "wildcard subscriptions not supported"),
];

/// PUBACK and PUBREC reason codes (§3.4.2.1, §3.5.2.1).
pub const PUBACK_REASON_CODES: &[(u8, &str)] = &[
    (0x00, "success"),
    (0x10, "no matching subscribers"),
    (0x80, "unspecified error"),
    (0x83, "implementation specific error"),
    (0x87, "not authorized"),
    (0x90, "topic name invalid"),
    (0x91, "packet identifier in use"),
    (0x97, "quota exceeded"),
    (0x99, "payload format invalid"),
];

/// UNSUBACK reason codes (§3.11.3).
pub const UNSUBACK_REASON_CODES: &[(u8, &str)] = &[
    (0x00, "success"),
    (0x11, "no subscription existed"),
    (0x80, "unspecified error"),
    (0x83, "implementation specific error"),
    (0x87, "not authorized"),
    (0x8F, "topic filter invalid"),
    (0x91, "packet identifier in use"),
];

/// DISCONNECT reason codes a *server* may send (§3.14.2.1).
pub const DISCONNECT_REASON_CODES: &[(u8, &str)] = &[
    (0x00, "normal disconnection"),
    (0x80, "unspecified error"),
    (0x81, "malformed packet"),
    (0x82, "protocol error"),
    (0x83, "implementation specific error"),
    (0x87, "not authorized"),
    (0x89, "server busy"),
    (0x8B, "server shutting down"),
    (0x8D, "keep alive timeout"),
    (0x8E, "session taken over"),
    (0x8F, "topic filter invalid"),
    (0x90, "topic name invalid"),
    (0x93, "receive maximum exceeded"),
    (0x94, "topic alias invalid"),
    (0x95, "packet too large"),
    (0x96, "message rate too high"),
    (0x97, "quota exceeded"),
    (0x98, "administrative action"),
    (0x99, "payload format invalid"),
    (0x9A, "retain not supported"),
    (0x9B, "QoS not supported"),
    (0x9C, "use another server"),
    (0x9D, "server moved"),
    (0x9E, "shared subscriptions not supported"),
    (0x9F, "connection rate exceeded"),
    (0xA0, "maximum connect time"),
    (0xA1, "subscription identifiers not supported"),
    (0xA2, "wildcard subscriptions not supported"),
];

/// Check `code` against one of the tables above, naming the valid ones on refusal.
pub fn check_reason(code: u64, table: &[(u8, &str)], packet: &str) -> Result<u8, String> {
    if let Ok(c) = u8::try_from(code) {
        if table.iter().any(|(t, _)| *t == c) {
            return Ok(c);
        }
    }
    let valid: Vec<String> = table
        .iter()
        .map(|(c, n)| format!("{c} (0x{c:02x}, {n})"))
        .collect();
    Err(format!(
        "{code} is not an MQTT 5 {packet} reason code; use one of: {}",
        valid.join(", ")
    ))
}

/// The name of a reason code in a table, for logs.
pub fn reason_name(code: u8, table: &[(u8, &'static str)]) -> &'static str {
    table
        .iter()
        .find(|(c, _)| *c == code)
        .map(|(_, n)| *n)
        .unwrap_or("unknown")
}

/// A 3.1.1 CONNACK return code (0–5) as the v5 reason code that means the same thing.
pub fn connack_v311_to_v5(code: u8) -> u8 {
    match code {
        0 => 0x00,
        1 => 0x84,
        2 => 0x85,
        3 => 0x88,
        4 => 0x86,
        _ => 0x87,
    }
}

/// A v5 CONNACK reason code as the nearest 3.1.1 return code, for a handler that answered a
/// 3.1.1 client with a v5 code. Every refusal stays a refusal: the codes with no 3.1.1 twin
/// fall to 3 (server unavailable) when they describe the server's state and to 5 (not
/// authorized) when they describe the client.
pub fn connack_v5_to_v311(code: u8) -> u8 {
    match code {
        0x00 => 0,
        0x84 => 1,
        0x85 => 2,
        0x86 | 0x8C => 4,
        0x80 | 0x83 | 0x88 | 0x89 | 0x97 | 0x9C | 0x9D | 0x9F => 3,
        _ => 5,
    }
}

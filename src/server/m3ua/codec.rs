//! M3UA wire codec (RFC 4666).
//!
//! Pure functions over bytes: the common header, the TLV parameter encoding, the Protocol Data
//! field, and small builders for the messages an SGP sends. Nothing here touches a socket, the
//! LLM or `AppState`, so every rule below is pinned directly against literal bytes in
//! `tests/server/m3ua/codec_test.rs`.
//!
//! # The two rules that are usually got wrong
//!
//! **1. Parameter padding is not counted in the parameter length.** RFC 4666 section 3.2: the
//! Parameter Length covers Tag + Length + Value and *excludes* the padding that rounds the
//! parameter up to a 4-octet boundary. A parameter carrying the two octets `"ok"` therefore
//! declares length 6 and occupies 8 octets on the wire, the last two being zeros nobody counts.
//! Getting this backwards produces a stream that decodes correctly against itself and against
//! nothing else, which is why the codec tests assert octets rather than round-trips.
//!
//! **2. The Message Length in the common header is the whole message including the header.**
//! NetGet *includes* the parameters' padding octets in it, which is what the reference SIGTRAN
//! stacks do. A peer that excludes it produces a length that is not a multiple of four; the
//! reader in `mod.rs` reconciles that by consuming the alignment octets that must be on the
//! wire regardless (see `alignment_slack`).

use std::fmt;

/// M3UA protocol version (RFC 4666 section 3.1.1). Only version 1 exists.
pub const VERSION: u8 = 1;

/// Common header length: version, reserved, class, type, 32-bit length.
pub const HEADER_LEN: usize = 8;

/// Refuse to allocate for anything larger. M3UA has no stated ceiling, but an SS7 MSU is at
/// most 272 octets of user part, so this is generous by three orders of magnitude and still
/// bounds what an unauthenticated peer can make the server reserve.
pub const MAX_MESSAGE_LEN: usize = 65_535;

/// Largest SS7 user part this server will put inside a Protocol Data parameter, in octets.
///
/// `MAX_MESSAGE_LEN` bounds the **decode** side, where a hostile peer chooses the number.
/// This bounds the **encode** side, where the model does — and that side had no bound at
/// all: `Parameter::write_into` writes `declared_len()` as a `u16`, so a user part of 65520
/// octets or more wrapped the Parameter Length field and produced a message no SS7 peer
/// could parse.
///
/// The arithmetic, and **the padding rule is part of it**. A body is always a whole number of
/// 4-octet words — every parameter is padded up to one — so the largest body that fits under
/// [`MAX_MESSAGE_LEN`] is `((65535 − 8) / 4) * 4 = 65524`, not 65527. Take off the 4-octet
/// parameter header and Protocol Data's 12 fixed octets (OPC, DPC, SI, NI, MP, SLS) and 65508
/// is left. The earlier form of this constant subtracted the headers and forgot the padding,
/// which put it three octets too high — so a payload at exactly the documented limit produced
/// a 65536-octet message, one past the ceiling. That is the same "padding is not in the
/// length" trap this module's header warns about, met from the other side.
///
/// This is three orders of magnitude above anything real. A genuine MSU carries at most 272
/// octets of user part, which is why exceeding it means the model has misunderstood the
/// field rather than hit a legitimate ceiling. It is also a *per-parameter* guide: a DATA
/// message that also carries Network Appearance, Routing Context and Correlation ID has 24
/// fewer octets to spend, and [`Message::encode`] is what enforces the real ceiling.
pub const MAX_USER_DATA_LEN: usize = ((MAX_MESSAGE_LEN - HEADER_LEN) / 4) * 4 - 4 - 12;

// ---------------------------------------------------------------------------
// Message classes and types (RFC 4666 section 3.1.3 / 3.1.4)
// ---------------------------------------------------------------------------

pub const CLASS_MGMT: u8 = 0;
pub const CLASS_TRANSFER: u8 = 1;
pub const CLASS_SSNM: u8 = 2;
pub const CLASS_ASPSM: u8 = 3;
pub const CLASS_ASPTM: u8 = 4;
pub const CLASS_RKM: u8 = 9;

// MGMT (class 0)
pub const MGMT_ERR: u8 = 0;
pub const MGMT_NTFY: u8 = 1;

// Transfer (class 1)
pub const TRANSFER_DATA: u8 = 1;

// SSNM (class 2)
pub const SSNM_DUNA: u8 = 1;
pub const SSNM_DAVA: u8 = 2;
pub const SSNM_DAUD: u8 = 3;
pub const SSNM_SCON: u8 = 4;
pub const SSNM_DUPU: u8 = 5;
pub const SSNM_DRST: u8 = 6;

// ASPSM (class 3)
pub const ASPSM_ASPUP: u8 = 1;
pub const ASPSM_ASPDN: u8 = 2;
pub const ASPSM_BEAT: u8 = 3;
pub const ASPSM_ASPUP_ACK: u8 = 4;
pub const ASPSM_ASPDN_ACK: u8 = 5;
pub const ASPSM_BEAT_ACK: u8 = 6;

// ASPTM (class 4)
pub const ASPTM_ASPAC: u8 = 1;
pub const ASPTM_ASPIA: u8 = 2;
pub const ASPTM_ASPAC_ACK: u8 = 3;
pub const ASPTM_ASPIA_ACK: u8 = 4;

// RKM (class 9)
pub const RKM_REG_REQ: u8 = 1;
pub const RKM_REG_RSP: u8 = 2;
pub const RKM_DEREG_REQ: u8 = 3;
pub const RKM_DEREG_RSP: u8 = 4;

// ---------------------------------------------------------------------------
// Parameter tags (RFC 4666 section 3.2)
// ---------------------------------------------------------------------------

/// Common parameters, shared with the other SIGTRAN adaptation layers.
pub const TAG_INFO_STRING: u16 = 0x0004;
pub const TAG_ROUTING_CONTEXT: u16 = 0x0006;
pub const TAG_DIAGNOSTIC_INFO: u16 = 0x0007;
pub const TAG_HEARTBEAT_DATA: u16 = 0x0009;
pub const TAG_TRAFFIC_MODE_TYPE: u16 = 0x000b;
pub const TAG_ERROR_CODE: u16 = 0x000c;
pub const TAG_STATUS: u16 = 0x000d;
pub const TAG_ASP_IDENTIFIER: u16 = 0x0011;
pub const TAG_AFFECTED_POINT_CODE: u16 = 0x0012;
pub const TAG_CORRELATION_ID: u16 = 0x0013;

/// M3UA-specific parameters.
pub const TAG_NETWORK_APPEARANCE: u16 = 0x0200;
pub const TAG_USER_CAUSE: u16 = 0x0204;
pub const TAG_CONGESTION_INDICATIONS: u16 = 0x0205;
pub const TAG_CONCERNED_DESTINATION: u16 = 0x0206;
pub const TAG_ROUTING_KEY: u16 = 0x0207;
pub const TAG_REGISTRATION_RESULT: u16 = 0x0208;
pub const TAG_DEREGISTRATION_RESULT: u16 = 0x0209;
pub const TAG_LOCAL_ROUTING_KEY_ID: u16 = 0x020a;
pub const TAG_DESTINATION_POINT_CODE: u16 = 0x020b;
pub const TAG_SERVICE_INDICATORS: u16 = 0x020c;
pub const TAG_ORIGINATING_POINT_CODE_LIST: u16 = 0x020e;
pub const TAG_PROTOCOL_DATA: u16 = 0x0210;
pub const TAG_REGISTRATION_STATUS: u16 = 0x0212;
pub const TAG_DEREGISTRATION_STATUS: u16 = 0x0213;

// ---------------------------------------------------------------------------
// Error codes (RFC 4666 section 3.8.1), carried as a 32-bit Error Code parameter
// ---------------------------------------------------------------------------

pub const ERR_INVALID_VERSION: u32 = 0x01;
pub const ERR_UNSUPPORTED_MESSAGE_CLASS: u32 = 0x03;
pub const ERR_UNSUPPORTED_MESSAGE_TYPE: u32 = 0x04;
pub const ERR_UNSUPPORTED_TRAFFIC_MODE: u32 = 0x05;
pub const ERR_UNEXPECTED_MESSAGE: u32 = 0x06;
pub const ERR_PROTOCOL_ERROR: u32 = 0x07;
pub const ERR_INVALID_STREAM_IDENTIFIER: u32 = 0x09;
pub const ERR_REFUSED_MANAGEMENT_BLOCKING: u32 = 0x0d;
pub const ERR_ASP_IDENTIFIER_REQUIRED: u32 = 0x0e;
pub const ERR_INVALID_ASP_IDENTIFIER: u32 = 0x0f;
pub const ERR_INVALID_PARAMETER_VALUE: u32 = 0x11;
pub const ERR_PARAMETER_FIELD_ERROR: u32 = 0x12;
pub const ERR_UNEXPECTED_PARAMETER: u32 = 0x13;
pub const ERR_DESTINATION_STATUS_UNKNOWN: u32 = 0x14;
pub const ERR_INVALID_NETWORK_APPEARANCE: u32 = 0x15;
pub const ERR_MISSING_PARAMETER: u32 = 0x16;
pub const ERR_INVALID_ROUTING_CONTEXT: u32 = 0x19;
pub const ERR_NO_CONFIGURED_AS_FOR_ASP: u32 = 0x1a;

/// Traffic Mode Type values (RFC 4666 section 3.6.1).
pub const TRAFFIC_MODE_OVERRIDE: u32 = 1;
pub const TRAFFIC_MODE_LOADSHARE: u32 = 2;
pub const TRAFFIC_MODE_BROADCAST: u32 = 3;

/// Status Type values for NTFY (RFC 4666 section 3.8.2).
pub const STATUS_TYPE_AS_STATE_CHANGE: u16 = 1;
pub const STATUS_TYPE_OTHER: u16 = 2;

/// Status Information under Status Type 1.
pub const STATUS_AS_INACTIVE: u16 = 2;
pub const STATUS_AS_ACTIVE: u16 = 3;
pub const STATUS_AS_PENDING: u16 = 4;

/// Status Information under Status Type 2.
pub const STATUS_INSUFFICIENT_ASP_RESOURCES: u16 = 1;
pub const STATUS_ALTERNATE_ASP_ACTIVE: u16 = 2;
pub const STATUS_ASP_FAILURE: u16 = 3;

/// Human name for a message class, for logs and event data.
pub fn class_name(class: u8) -> &'static str {
    match class {
        CLASS_MGMT => "MGMT",
        CLASS_TRANSFER => "Transfer",
        CLASS_SSNM => "SSNM",
        CLASS_ASPSM => "ASPSM",
        CLASS_ASPTM => "ASPTM",
        5 => "RKM(reserved)",
        6 => "IIM",
        CLASS_RKM => "RKM",
        _ => "unknown",
    }
}

/// Human name for a (class, type) pair, for logs and event data.
pub fn message_name(class: u8, msg_type: u8) -> &'static str {
    match (class, msg_type) {
        (CLASS_MGMT, MGMT_ERR) => "ERR",
        (CLASS_MGMT, MGMT_NTFY) => "NTFY",
        (CLASS_TRANSFER, TRANSFER_DATA) => "DATA",
        (CLASS_SSNM, SSNM_DUNA) => "DUNA",
        (CLASS_SSNM, SSNM_DAVA) => "DAVA",
        (CLASS_SSNM, SSNM_DAUD) => "DAUD",
        (CLASS_SSNM, SSNM_SCON) => "SCON",
        (CLASS_SSNM, SSNM_DUPU) => "DUPU",
        (CLASS_SSNM, SSNM_DRST) => "DRST",
        (CLASS_ASPSM, ASPSM_ASPUP) => "ASPUP",
        (CLASS_ASPSM, ASPSM_ASPDN) => "ASPDN",
        (CLASS_ASPSM, ASPSM_BEAT) => "BEAT",
        (CLASS_ASPSM, ASPSM_ASPUP_ACK) => "ASPUP ACK",
        (CLASS_ASPSM, ASPSM_ASPDN_ACK) => "ASPDN ACK",
        (CLASS_ASPSM, ASPSM_BEAT_ACK) => "BEAT ACK",
        (CLASS_ASPTM, ASPTM_ASPAC) => "ASPAC",
        (CLASS_ASPTM, ASPTM_ASPIA) => "ASPIA",
        (CLASS_ASPTM, ASPTM_ASPAC_ACK) => "ASPAC ACK",
        (CLASS_ASPTM, ASPTM_ASPIA_ACK) => "ASPIA ACK",
        (CLASS_RKM, RKM_REG_REQ) => "REG REQ",
        (CLASS_RKM, RKM_REG_RSP) => "REG RSP",
        (CLASS_RKM, RKM_DEREG_REQ) => "DEREG REQ",
        (CLASS_RKM, RKM_DEREG_RSP) => "DEREG RSP",
        _ => "unknown",
    }
}

/// MTP3 Service Indicator names (ITU-T Q.704 table 1), for the DATA event.
///
/// Purely descriptive: the model reasons far better about `"si_name": "ISUP"` than about
/// `"si": 5`, and both are supplied so nothing has to be guessed from the name.
pub fn si_name(si: u8) -> &'static str {
    match si {
        0 => "SNM",
        1 => "MTP testing",
        2 => "special MTP testing",
        3 => "SCCP",
        4 => "TUP",
        5 => "ISUP",
        6 => "DUP (call and circuit related)",
        7 => "DUP (facility registration/cancellation)",
        8 => "MTP testing user part",
        9 => "B-ISUP",
        10 => "SAT-ISUP",
        _ => "unassigned",
    }
}

/// Name of an error code, for logs and for the `m3ua_error_received` event.
pub fn error_code_name(code: u32) -> &'static str {
    match code {
        ERR_INVALID_VERSION => "Invalid Version",
        ERR_UNSUPPORTED_MESSAGE_CLASS => "Unsupported Message Class",
        ERR_UNSUPPORTED_MESSAGE_TYPE => "Unsupported Message Type",
        ERR_UNSUPPORTED_TRAFFIC_MODE => "Unsupported Traffic Mode Type",
        ERR_UNEXPECTED_MESSAGE => "Unexpected Message",
        ERR_PROTOCOL_ERROR => "Protocol Error",
        ERR_INVALID_STREAM_IDENTIFIER => "Invalid Stream Identifier",
        ERR_REFUSED_MANAGEMENT_BLOCKING => "Refused - Management Blocking",
        ERR_ASP_IDENTIFIER_REQUIRED => "ASP Identifier Required",
        ERR_INVALID_ASP_IDENTIFIER => "Invalid ASP Identifier",
        ERR_INVALID_PARAMETER_VALUE => "Invalid Parameter Value",
        ERR_PARAMETER_FIELD_ERROR => "Parameter Field Error",
        ERR_UNEXPECTED_PARAMETER => "Unexpected Parameter",
        ERR_DESTINATION_STATUS_UNKNOWN => "Destination Status Unknown",
        ERR_INVALID_NETWORK_APPEARANCE => "Invalid Network Appearance",
        ERR_MISSING_PARAMETER => "Missing Parameter",
        ERR_INVALID_ROUTING_CONTEXT => "Invalid Routing Context",
        ERR_NO_CONFIGURED_AS_FOR_ASP => "No Configured AS for ASP",
        _ => "unassigned",
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// A decode failure, carrying the M3UA error code the peer earns for it.
///
/// `reason` is for the log only. It never reaches the peer: RFC 4666's ERR message carries a
/// numeric Error Code, and the optional Diagnostic Information parameter is left empty rather
/// than filled with an internal string.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WireError {
    pub error_code: u32,
    pub reason: String,
}

impl WireError {
    fn new(error_code: u32, reason: impl Into<String>) -> Self {
        Self {
            error_code,
            reason: reason.into(),
        }
    }
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} (error code 0x{:02x} {})",
            self.reason,
            self.error_code,
            error_code_name(self.error_code)
        )
    }
}

impl std::error::Error for WireError {}

// ---------------------------------------------------------------------------
// Common header
// ---------------------------------------------------------------------------

/// The 8-octet M3UA common header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommonHeader {
    pub version: u8,
    pub reserved: u8,
    pub class: u8,
    pub msg_type: u8,
    /// Total message length in octets, *including* these 8.
    pub length: u32,
}

/// Parse and validate the common header.
///
/// Everything is checked before the caller allocates the body, so a peer cannot choose the
/// size of a buffer and `length - HEADER_LEN` cannot underflow.
pub fn parse_header(bytes: &[u8]) -> Result<CommonHeader, WireError> {
    if bytes.len() < HEADER_LEN {
        return Err(WireError::new(
            ERR_PROTOCOL_ERROR,
            format!("common header truncated at {} octets", bytes.len()),
        ));
    }
    let version = bytes[0];
    if version != VERSION {
        return Err(WireError::new(
            ERR_INVALID_VERSION,
            format!("M3UA version {version} is not 1"),
        ));
    }
    let length = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    if (length as usize) < HEADER_LEN {
        return Err(WireError::new(
            ERR_PROTOCOL_ERROR,
            format!("message length {length} is shorter than the common header"),
        ));
    }
    if length as usize > MAX_MESSAGE_LEN {
        return Err(WireError::new(
            ERR_PROTOCOL_ERROR,
            format!("message length {length} exceeds the {MAX_MESSAGE_LEN}-octet ceiling"),
        ));
    }
    Ok(CommonHeader {
        version,
        reserved: bytes[1],
        class: bytes[2],
        msg_type: bytes[3],
        length,
    })
}

/// Octets of 4-byte alignment slack a declared message length implies.
///
/// NetGet includes parameter padding in the Message Length, so its own messages always yield
/// zero here. A peer that excludes the final parameter's padding declares a length that is not
/// a multiple of four while still writing the padding octets, per RFC 4666 section 3.2 ("the
/// sender pads the parameter"). The reader consumes this many octets after the declared body so
/// the next header starts where it should.
pub fn alignment_slack(length: u32) -> usize {
    padding_for(length as usize)
}

/// Octets needed to round `len` up to a 4-octet boundary.
pub fn padding_for(len: usize) -> usize {
    (4 - (len % 4)) % 4
}

// ---------------------------------------------------------------------------
// Parameters
// ---------------------------------------------------------------------------

/// One TLV parameter, without its padding — the padding is a property of the encoding, never
/// of the value, and folding it into `value` is how a decoder starts handing 3 stray zero
/// octets to a user part.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Parameter {
    pub tag: u16,
    pub value: Vec<u8>,
}

impl Parameter {
    pub fn new(tag: u16, value: impl Into<Vec<u8>>) -> Self {
        Self {
            tag,
            value: value.into(),
        }
    }

    /// A parameter whose whole value is one 32-bit field (routing context, error code, …).
    pub fn u32(tag: u16, value: u32) -> Self {
        Self::new(tag, value.to_be_bytes().to_vec())
    }

    /// The value of the Parameter Length field: 4 header octets plus the value, and **not**
    /// the padding (RFC 4666 section 3.2).
    pub fn declared_len(&self) -> usize {
        4 + self.value.len()
    }

    /// Octets this parameter occupies on the wire, padding included.
    pub fn wire_len(&self) -> usize {
        let declared = self.declared_len();
        declared + padding_for(declared)
    }

    /// Append the TLV, refusing a value whose Parameter Length would not fit the 16-bit field.
    ///
    /// The check comes before anything is written, so a refusal leaves `out` untouched: a
    /// partial TLV would corrupt every parameter after it just as surely as the wrong length
    /// did. The old `declared as u16` was worse than an oversize parameter — a 65532-octet
    /// value makes `declared` 65536, which narrows to **0**, below the 4-octet TLV header
    /// itself, so the parameter became unparseable and took every later parameter with it.
    /// Silent in release and silent in debug, because a cast does not overflow-check.
    pub fn write_into(&self, out: &mut Vec<u8>) -> Result<(), WireError> {
        let declared = self.declared_len();
        if declared > u16::MAX as usize {
            return Err(WireError::new(
                ERR_PROTOCOL_ERROR,
                format!(
                    "parameter 0x{:04x} declares {declared} octets, past the {} a 16-bit \
                     Parameter Length can carry",
                    self.tag,
                    u16::MAX
                ),
            ));
        }
        out.extend_from_slice(&self.tag.to_be_bytes());
        out.extend_from_slice(&(declared as u16).to_be_bytes());
        out.extend_from_slice(&self.value);
        out.resize(out.len() + padding_for(declared), 0);
        Ok(())
    }

    /// The value read as a 32-bit field, or `None` if it is not exactly four octets.
    pub fn as_u32(&self) -> Option<u32> {
        let bytes: [u8; 4] = self.value.as_slice().try_into().ok()?;
        Some(u32::from_be_bytes(bytes))
    }
}

/// Parse a message body into its parameters.
///
/// Tolerates a final parameter whose padding octets were not written, which is what a sender
/// that excludes padding from the Message Length produces at the end of a message.
pub fn parse_parameters(body: &[u8]) -> Result<Vec<Parameter>, WireError> {
    let mut out = Vec::new();
    let mut offset = 0usize;
    while offset < body.len() {
        let remaining = body.len() - offset;
        if remaining < 4 {
            // Fewer than four octets left. Trailing zeros are the previous parameter's padding;
            // anything else is a truncated parameter header.
            if body[offset..].iter().all(|b| *b == 0) {
                break;
            }
            return Err(WireError::new(
                ERR_PARAMETER_FIELD_ERROR,
                format!("{remaining} trailing octets are too short for a parameter header"),
            ));
        }
        let tag = u16::from_be_bytes([body[offset], body[offset + 1]]);
        let declared = u16::from_be_bytes([body[offset + 2], body[offset + 3]]) as usize;
        if declared < 4 {
            return Err(WireError::new(
                ERR_PARAMETER_FIELD_ERROR,
                format!("parameter 0x{tag:04x} declares length {declared}, below the 4-octet TLV header"),
            ));
        }
        let end = offset + declared;
        if end > body.len() {
            return Err(WireError::new(
                ERR_PARAMETER_FIELD_ERROR,
                format!(
                    "parameter 0x{tag:04x} declares {declared} octets but only {remaining} remain"
                ),
            ));
        }
        out.push(Parameter {
            tag,
            value: body[offset + 4..end].to_vec(),
        });
        // Padding is not in `declared`, so skip it explicitly; a final parameter may have had
        // its padding omitted, in which case we simply land on the end of the body.
        offset = (end + padding_for(declared)).min(body.len());
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

/// A whole M3UA message: class, type and its parameters in wire order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    pub class: u8,
    pub msg_type: u8,
    pub parameters: Vec<Parameter>,
}

impl Message {
    pub fn new(class: u8, msg_type: u8) -> Self {
        Self {
            class,
            msg_type,
            parameters: Vec::new(),
        }
    }

    pub fn with(mut self, parameter: Parameter) -> Self {
        self.parameters.push(parameter);
        self
    }

    /// Append `parameter` only when `value` is present. Every optional parameter in this file
    /// goes through here, so "omitted" and "present but zero" stay distinguishable.
    pub fn with_opt_u32(self, tag: u16, value: Option<u32>) -> Self {
        match value {
            Some(v) => self.with(Parameter::u32(tag, v)),
            None => self,
        }
    }

    pub fn with_opt(self, tag: u16, value: Option<Vec<u8>>) -> Self {
        match value {
            Some(v) => self.with(Parameter::new(tag, v)),
            None => self,
        }
    }

    /// Encode to the wire. The Message Length includes the common header and every parameter's
    /// padding.
    ///
    /// Refuses anything [`parse_header`] would reject, which is the asymmetry this whole class
    /// of finding is named after: `MAX_MESSAGE_LEN` bounded the **decode** side, against a
    /// hostile peer, and nothing bounded the **encode** side, against the model. A message
    /// whose parameters ran past the ceiling encoded happily and was then rejected by this
    /// codec's own parser at the far end.
    pub fn encode(&self) -> Result<Vec<u8>, WireError> {
        let body_len: usize = self.parameters.iter().map(|p| p.wire_len()).sum();
        let total = HEADER_LEN + body_len;
        if total > MAX_MESSAGE_LEN {
            return Err(WireError::new(
                ERR_PROTOCOL_ERROR,
                format!(
                    "message of {} parameter(s) encodes to {total} octets, past the \
                     {MAX_MESSAGE_LEN}-octet ceiling this codec's own parser enforces",
                    self.parameters.len()
                ),
            ));
        }
        let mut out = Vec::with_capacity(total);
        out.push(VERSION);
        out.push(0); // Reserved
        out.push(self.class);
        out.push(self.msg_type);
        // Bounded above, so the cast cannot lose a bit.
        out.extend_from_slice(&(total as u32).to_be_bytes());
        for parameter in &self.parameters {
            parameter.write_into(&mut out)?;
        }
        Ok(out)
    }

    /// Decode a complete message: the common header followed by exactly `length - 8` body
    /// octets. `full` must be the declared length, which is what `mod.rs`'s reader supplies.
    pub fn parse(full: &[u8]) -> Result<Message, WireError> {
        let header = parse_header(full)?;
        let declared = header.length as usize;
        if full.len() < declared {
            return Err(WireError::new(
                ERR_PROTOCOL_ERROR,
                format!(
                    "message declares {declared} octets but only {} were supplied",
                    full.len()
                ),
            ));
        }
        let parameters = parse_parameters(&full[HEADER_LEN..declared])?;
        Ok(Message {
            class: header.class,
            msg_type: header.msg_type,
            parameters,
        })
    }

    pub fn param(&self, tag: u16) -> Option<&Parameter> {
        self.parameters.iter().find(|p| p.tag == tag)
    }

    pub fn param_u32(&self, tag: u16) -> Option<u32> {
        self.param(tag).and_then(|p| p.as_u32())
    }

    pub fn name(&self) -> &'static str {
        message_name(self.class, self.msg_type)
    }
}

/// The (class, type) of an already-encoded message, without decoding it.
///
/// The session uses this to learn what a handler's actions actually put on the wire — an
/// ASPUP ACK is what moves the ASP out of Down, and reading it back off the encoded bytes
/// means the state machine follows the octets rather than a parallel bookkeeping the actions
/// could drift from.
pub fn peek_class_type(bytes: &[u8]) -> Option<(u8, u8)> {
    if bytes.len() < HEADER_LEN || bytes[0] != VERSION {
        return None;
    }
    Some((bytes[2], bytes[3]))
}

// ---------------------------------------------------------------------------
// Protocol Data (RFC 4666 section 3.3.1)
// ---------------------------------------------------------------------------

/// Fixed part of the Protocol Data value: OPC, DPC, SI, NI, MP, SLS.
pub const PROTOCOL_DATA_FIXED_LEN: usize = 12;

/// The SS7 routing label plus the user part payload, as structured fields.
///
/// Surfacing these separately rather than as one opaque blob is the whole point: a model can
/// reason about "ISUP from point code 1001 to 2002" and cannot reason about 40 octets of hex.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtocolData {
    pub opc: u32,
    pub dpc: u32,
    pub si: u8,
    pub ni: u8,
    pub mp: u8,
    pub sls: u8,
    pub payload: Vec<u8>,
}

impl ProtocolData {
    pub fn parse(value: &[u8]) -> Result<Self, WireError> {
        if value.len() < PROTOCOL_DATA_FIXED_LEN {
            return Err(WireError::new(
                ERR_PARAMETER_FIELD_ERROR,
                format!(
                    "Protocol Data is {} octets, below the {PROTOCOL_DATA_FIXED_LEN}-octet \
                     routing label",
                    value.len()
                ),
            ));
        }
        Ok(Self {
            opc: u32::from_be_bytes([value[0], value[1], value[2], value[3]]),
            dpc: u32::from_be_bytes([value[4], value[5], value[6], value[7]]),
            si: value[8],
            ni: value[9],
            mp: value[10],
            sls: value[11],
            payload: value[PROTOCOL_DATA_FIXED_LEN..].to_vec(),
        })
    }

    /// The Protocol Data parameter *value* — tag, length and padding are added by `Parameter`.
    pub fn to_value(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(PROTOCOL_DATA_FIXED_LEN + self.payload.len());
        out.extend_from_slice(&self.opc.to_be_bytes());
        out.extend_from_slice(&self.dpc.to_be_bytes());
        out.push(self.si);
        out.push(self.ni);
        out.push(self.mp);
        out.push(self.sls);
        out.extend_from_slice(&self.payload);
        out
    }
}

// ---------------------------------------------------------------------------
// Builders for the messages an SGP sends
// ---------------------------------------------------------------------------

/// ASPUP ACK (RFC 4666 section 3.5.4).
pub fn aspup_ack(info_string: Option<&str>) -> Result<Vec<u8>, WireError> {
    Message::new(CLASS_ASPSM, ASPSM_ASPUP_ACK)
        .with_opt(TAG_INFO_STRING, info_string.map(|s| s.as_bytes().to_vec()))
        .encode()
}

/// ASPDN ACK (RFC 4666 section 3.5.5).
pub fn aspdn_ack() -> Result<Vec<u8>, WireError> {
    Message::new(CLASS_ASPSM, ASPSM_ASPDN_ACK).encode()
}

/// BEAT ACK (RFC 4666 section 3.5.6). The Heartbeat Data is echoed verbatim, which is the
/// entire point of the parameter: the ASP matches its own opaque token.
pub fn beat_ack(heartbeat_data: Option<&[u8]>) -> Result<Vec<u8>, WireError> {
    Message::new(CLASS_ASPSM, ASPSM_BEAT_ACK)
        .with_opt(TAG_HEARTBEAT_DATA, heartbeat_data.map(|d| d.to_vec()))
        .encode()
}

/// ASPAC ACK (RFC 4666 section 3.7.3).
pub fn aspac_ack(
    traffic_mode: Option<u32>,
    routing_context: Option<u32>,
    info_string: Option<&str>,
) -> Result<Vec<u8>, WireError> {
    Message::new(CLASS_ASPTM, ASPTM_ASPAC_ACK)
        .with_opt_u32(TAG_TRAFFIC_MODE_TYPE, traffic_mode)
        .with_opt_u32(TAG_ROUTING_CONTEXT, routing_context)
        .with_opt(TAG_INFO_STRING, info_string.map(|s| s.as_bytes().to_vec()))
        .encode()
}

/// ASPIA ACK (RFC 4666 section 3.7.4).
pub fn aspia_ack(routing_context: Option<u32>) -> Result<Vec<u8>, WireError> {
    Message::new(CLASS_ASPTM, ASPTM_ASPIA_ACK)
        .with_opt_u32(TAG_ROUTING_CONTEXT, routing_context)
        .encode()
}

/// ERR (RFC 4666 section 3.8.1).
///
/// The Diagnostic Information parameter is deliberately never populated. It is the one field
/// in M3UA where an internal error string could reach a peer, and the rule in
/// `crate::utils::wire_failure` is that the peer gets a category and the log gets the error.
pub fn error(error_code: u32, routing_context: Option<u32>) -> Result<Vec<u8>, WireError> {
    Message::new(CLASS_MGMT, MGMT_ERR)
        .with(Parameter::u32(TAG_ERROR_CODE, error_code))
        .with_opt_u32(TAG_ROUTING_CONTEXT, routing_context)
        .encode()
}

/// NTFY (RFC 4666 section 3.8.2). Status is one 32-bit field: type in the high half, info in
/// the low half.
pub fn notify(
    status_type: u16,
    status_info: u16,
    asp_identifier: Option<u32>,
    routing_context: Option<u32>,
    info_string: Option<&str>,
) -> Result<Vec<u8>, WireError> {
    let status = ((status_type as u32) << 16) | status_info as u32;
    Message::new(CLASS_MGMT, MGMT_NTFY)
        .with(Parameter::u32(TAG_STATUS, status))
        .with_opt_u32(TAG_ASP_IDENTIFIER, asp_identifier)
        .with_opt_u32(TAG_ROUTING_CONTEXT, routing_context)
        .with_opt(TAG_INFO_STRING, info_string.map(|s| s.as_bytes().to_vec()))
        .encode()
}

/// DATA (RFC 4666 section 3.3.1), parameters in the order the RFC lists them.
pub fn data(
    protocol_data: &ProtocolData,
    network_appearance: Option<u32>,
    routing_context: Option<u32>,
    correlation_id: Option<u32>,
) -> Result<Vec<u8>, WireError> {
    Message::new(CLASS_TRANSFER, TRANSFER_DATA)
        .with_opt_u32(TAG_NETWORK_APPEARANCE, network_appearance)
        .with_opt_u32(TAG_ROUTING_CONTEXT, routing_context)
        .with(Parameter::new(TAG_PROTOCOL_DATA, protocol_data.to_value()))
        .with_opt_u32(TAG_CORRELATION_ID, correlation_id)
        .encode()
}

// ---------------------------------------------------------------------------
// Builders for the messages an ASP sends (the NetGet M3UA client)
// ---------------------------------------------------------------------------

/// ASPUP (RFC 4666 section 3.5.1).
pub fn aspup(asp_identifier: Option<u32>, info_string: Option<&str>) -> Result<Vec<u8>, WireError> {
    Message::new(CLASS_ASPSM, ASPSM_ASPUP)
        .with_opt_u32(TAG_ASP_IDENTIFIER, asp_identifier)
        .with_opt(TAG_INFO_STRING, info_string.map(|s| s.as_bytes().to_vec()))
        .encode()
}

/// ASPDN (RFC 4666 section 3.5.2).
pub fn aspdn() -> Result<Vec<u8>, WireError> {
    Message::new(CLASS_ASPSM, ASPSM_ASPDN).encode()
}

/// ASPAC (RFC 4666 section 3.7.1).
pub fn aspac(
    traffic_mode: Option<u32>,
    routing_context: Option<u32>,
) -> Result<Vec<u8>, WireError> {
    Message::new(CLASS_ASPTM, ASPTM_ASPAC)
        .with_opt_u32(TAG_TRAFFIC_MODE_TYPE, traffic_mode)
        .with_opt_u32(TAG_ROUTING_CONTEXT, routing_context)
        .encode()
}

/// BEAT (RFC 4666 section 3.5.5).
pub fn beat(heartbeat_data: &[u8]) -> Result<Vec<u8>, WireError> {
    Message::new(CLASS_ASPSM, ASPSM_BEAT)
        .with(Parameter::new(TAG_HEARTBEAT_DATA, heartbeat_data.to_vec()))
        .encode()
}

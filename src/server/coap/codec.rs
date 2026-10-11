//! CoAP (RFC 7252) message codec.
//!
//! Hand-rolled on purpose: the server's encoder and the `coap` / `coap-lite` crates used
//! as the test peer are then genuinely independent implementations, so a round trip
//! through them is evidence rather than a tautology.
//!
//! Covers the 4-byte binary header, the four message types, tokens, the option
//! delta/length encoding with both extension forms, the payload marker, and the
//! request/response code space, and the option values Observe (RFC 7641) and Block-wise
//! transfer (RFC 7959) carry: [`BlockValue`] and the Observe sequence. What those options
//! *mean* — registrations, reassembly, the transfer cache — is `observe.rs` and
//! `blockwise.rs`; this file only reads and writes them. Not covered: DTLS.

use std::fmt;

/// Fixed CoAP header length: Ver/T/TKL, Code, Message ID.
pub const HEADER_LEN: usize = 4;

/// Marks the start of the payload, after any options.
pub const PAYLOAD_MARKER: u8 = 0xFF;

/// Largest **inbound** datagram this server will process, in bytes.
///
/// RFC 7252 §4.6 names this number: an endpoint that does not know the path MTU assumes
/// `MAX_MESSAGE_SIZE` of 1152 bytes, and a constrained endpoint is entitled to refuse
/// anything larger. The legal way for a peer to send more is Block1 (RFC 7959), whose largest
/// block is 1024 bytes and fits, so a bigger datagram is either a client that ignored the
/// specification or somebody probing for a buffer to grow.
///
/// Enforced in `mod.rs::handle_datagram`, **before** the message is decoded and before any
/// model call, and answered in CoAP's own vocabulary with 4.13 Request Entity Too Large
/// (RFC 7252 §5.9.2.9). This is the number `ProtocolMetadataV2::max_inbound_bytes`
/// declares.
///
/// It used to declare [`MAX_PAYLOAD_LEN`] instead, which is the bound on what the server
/// *writes*. Nothing inbound was bounded at all: the receive buffer was the only ceiling
/// and a 2000-byte request was decoded and handed to the model. A declaration naming a
/// number the inbound path never checks is the exact shape
/// `max_inbound_bytes`' own doc comment warns about — "the number must be the one the code
/// enforces, at the point the length is decided".
pub const MAX_MESSAGE_LEN: usize = 1152;

/// Largest payload this server will put in **one message**, in bytes — the largest Block2
/// block (SZX 6).
///
/// RFC 7252 §4.6: absent any knowledge of the path MTU, a CoAP endpoint must assume
/// `MAX_MESSAGE_SIZE` of 1152 bytes, "leading to a maximum payload size of 1024 bytes". A
/// representation larger than this is split with Block2 (RFC 7959) rather than sent whole;
/// the bound on the representation itself is [`MAX_REPRESENTATION_LEN`].
pub const MAX_PAYLOAD_LEN: usize = 1024;

/// Largest representation the model may return, in bytes — and the largest request body a
/// Block1 upload may reassemble to.
///
/// Over [`MAX_PAYLOAD_LEN`] a representation goes out as Block2 blocks, so this is not a
/// datagram limit but a memory one: every block of a transfer is served from one cached copy
/// (`blockwise::Transfers`), and every upload is held until its last block arrives. 64 KiB is
/// sixty-four blocks — far past anything a constrained device serves — and with the table
/// caps in `blockwise.rs` bounds what one server holds to a few MiB.
///
/// Enforced on the model's side in `actions.rs::decode_payload`, so an oversize answer is a
/// legible error the model can act on rather than an `EMSGSIZE` the peer never hears about,
/// and on the peer's side in `blockwise::Uploads`, which answers 4.13 with Size1.
pub const MAX_REPRESENTATION_LEN: usize = 64 * 1024;

/// CoAP version implemented here.
pub const VERSION: u8 = 1;

/// Longest token a message may carry, in octets (RFC 7252 §3).
///
/// TKL is four bits and 9-15 are reserved, so this is a format limit. It is stated once and
/// enforced in **both** directions: `decode` refuses `tkl > 8` from a peer, and `encode`
/// refuses an over-long token from the caller. The encoder used to cut instead, which is the
/// worst available outcome on this protocol — CoAP's entire request/response matching *is*
/// token equality, so a truncated token produces a reply that is discarded silently at the
/// client with no error at either end.
pub const MAX_TOKEN_LEN: usize = 8;

/// Longest value a single option may carry, in octets.
///
/// The extended length form is `269 + a big-endian u16`, but `read_extended` saturates that
/// addition at `u16::MAX`, so 65535 is the largest length this codec can read back — and an
/// encoder must not produce a length its own decoder cannot. Stated so the encoder refuses
/// rather than narrowing an option length with an `as u16`.
pub const MAX_OPTION_LEN: usize = u16::MAX as usize;

// ---------------------------------------------------------------------------
// Option numbers (RFC 7252 §5.10, §12.2)
// ---------------------------------------------------------------------------

pub const OPT_IF_MATCH: u16 = 1;
pub const OPT_URI_HOST: u16 = 3;
pub const OPT_ETAG: u16 = 4;
pub const OPT_IF_NONE_MATCH: u16 = 5;
/// Observe (RFC 7641 §2): 0 registers, 1 deregisters, and in a notification it is the
/// sequence number.
pub const OPT_OBSERVE: u16 = 6;
pub const OPT_URI_PORT: u16 = 7;
pub const OPT_LOCATION_PATH: u16 = 8;
pub const OPT_URI_PATH: u16 = 11;
pub const OPT_CONTENT_FORMAT: u16 = 12;
pub const OPT_MAX_AGE: u16 = 14;
pub const OPT_URI_QUERY: u16 = 15;
pub const OPT_ACCEPT: u16 = 17;
pub const OPT_LOCATION_QUERY: u16 = 20;
/// Block2 (RFC 7959 §2.1): which block of the *response* this is, or which one is wanted.
pub const OPT_BLOCK2: u16 = 23;
/// Block1 (RFC 7959 §2.1): which block of the *request* body this is.
pub const OPT_BLOCK1: u16 = 27;
/// Size2 (RFC 7959 §4): the whole representation's length.
pub const OPT_SIZE2: u16 = 28;
/// Size1 (RFC 7252 §5.10.9, RFC 7959 §4): the whole request body's length, or in a 4.13
/// the largest one the server will take.
pub const OPT_SIZE1: u16 = 60;

/// A CoAP unsigned integer option value: minimum-length big-endian (RFC 7252 §3.2), so zero
/// is the empty string rather than a zero byte.
pub fn uint_option(value: u32) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    let first = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    bytes[first..].to_vec()
}

// ---------------------------------------------------------------------------
// Codes
// ---------------------------------------------------------------------------

/// The empty code, 0.00 — used by ACK and RST, and by a CoAP ping.
pub const CODE_EMPTY: u8 = 0x00;
pub const CODE_GET: u8 = 0x01;
pub const CODE_POST: u8 = 0x02;
pub const CODE_PUT: u8 = 0x03;
pub const CODE_DELETE: u8 = 0x04;

/// Build a code byte from the human `class.detail` pair, e.g. `2.05` -> `code(2, 5)`.
pub const fn code(class: u8, detail: u8) -> u8 {
    (class << 5) | (detail & 0x1F)
}

pub const CODE_CONTENT: u8 = code(2, 5); // 2.05
pub const CODE_CONTINUE: u8 = code(2, 31); // 2.31 (RFC 7959 §2.9.1)
pub const CODE_BAD_REQUEST: u8 = code(4, 0); // 4.00
pub const CODE_BAD_OPTION: u8 = code(4, 2); // 4.02
pub const CODE_NOT_FOUND: u8 = code(4, 4); // 4.04
pub const CODE_METHOD_NOT_ALLOWED: u8 = code(4, 5); // 4.05
pub const CODE_REQUEST_ENTITY_INCOMPLETE: u8 = code(4, 8); // 4.08 (RFC 7959 §2.9.2)
pub const CODE_REQUEST_ENTITY_TOO_LARGE: u8 = code(4, 13); // 4.13
pub const CODE_INTERNAL_SERVER_ERROR: u8 = code(5, 0); // 5.00
pub const CODE_SERVICE_UNAVAILABLE: u8 = code(5, 3); // 5.03

/// Class portion of a code byte (the digit before the dot).
pub const fn code_class(code: u8) -> u8 {
    code >> 5
}

/// Detail portion of a code byte (the two digits after the dot).
pub const fn code_detail(code: u8) -> u8 {
    code & 0x1F
}

/// Render a code byte in the conventional `c.dd` notation.
pub fn code_to_string(code: u8) -> String {
    format!("{}.{:02}", code_class(code), code_detail(code))
}

/// Parse `"2.05"` (or `"2.05 Content"`) into a code byte.
pub fn parse_code_string(s: &str) -> Option<u8> {
    let token = s.split_whitespace().next()?;
    let (class, detail) = token.split_once('.')?;
    let class: u8 = class.trim().parse().ok()?;
    let detail: u8 = detail.trim().parse().ok()?;
    if class > 7 || detail > 31 {
        return None;
    }
    Some(code(class, detail))
}

/// Method name for a request code, or `None` if this is not a request code.
pub fn method_name(code: u8) -> Option<&'static str> {
    match code {
        CODE_GET => Some("GET"),
        CODE_POST => Some("POST"),
        CODE_PUT => Some("PUT"),
        CODE_DELETE => Some("DELETE"),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Content formats (RFC 7252 §12.3)
// ---------------------------------------------------------------------------

/// Media type name for a Content-Format identifier.
pub fn content_format_name(id: u16) -> Option<&'static str> {
    match id {
        0 => Some("text/plain"),
        40 => Some("application/link-format"),
        41 => Some("application/xml"),
        42 => Some("application/octet-stream"),
        47 => Some("application/exi"),
        50 => Some("application/json"),
        60 => Some("application/cbor"),
        _ => None,
    }
}

/// Content-Format identifier for a media type name.
pub fn content_format_id(name: &str) -> Option<u16> {
    let n = name.trim().to_ascii_lowercase();
    // Tolerate the charset parameter clients and models both like to add.
    let n = n.split(';').next().unwrap_or(&n).trim().to_string();
    match n.as_str() {
        "text/plain" | "text" | "plain" => Some(0),
        "application/link-format" | "link-format" => Some(40),
        "application/xml" | "xml" => Some(41),
        "application/octet-stream" | "octet-stream" | "binary" => Some(42),
        "application/exi" | "exi" => Some(47),
        "application/json" | "json" => Some(50),
        "application/cbor" | "cbor" => Some(60),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Message
// ---------------------------------------------------------------------------

/// CoAP message type (the `T` field).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    Confirmable,
    NonConfirmable,
    Acknowledgement,
    Reset,
}

impl MessageType {
    pub fn from_bits(bits: u8) -> MessageType {
        match bits & 0x03 {
            0 => MessageType::Confirmable,
            1 => MessageType::NonConfirmable,
            2 => MessageType::Acknowledgement,
            _ => MessageType::Reset,
        }
    }

    pub fn to_bits(self) -> u8 {
        match self {
            MessageType::Confirmable => 0,
            MessageType::NonConfirmable => 1,
            MessageType::Acknowledgement => 2,
            MessageType::Reset => 3,
        }
    }

    /// Short name used in event data and logs.
    pub fn as_str(self) -> &'static str {
        match self {
            MessageType::Confirmable => "CON",
            MessageType::NonConfirmable => "NON",
            MessageType::Acknowledgement => "ACK",
            MessageType::Reset => "RST",
        }
    }
}

/// A decoded CoAP message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoapMessage {
    pub mtype: MessageType,
    pub code: u8,
    pub message_id: u16,
    pub token: Vec<u8>,
    /// Options as `(number, value)`, in ascending order of number, repeats allowed.
    pub options: Vec<(u16, Vec<u8>)>,
    pub payload: Vec<u8>,
}

/// Why a datagram is not a CoAP message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    TooShort {
        len: usize,
    },
    BadVersion {
        version: u8,
    },
    BadTokenLength {
        tkl: u8,
    },
    Truncated {
        what: &'static str,
    },
    /// Option delta or length nibble 15, which is reserved (0xFF is the payload marker).
    ReservedOptionNibble,
    /// A payload marker with nothing after it (RFC 7252 §3: this is a format error).
    EmptyPayloadAfterMarker,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecodeError::TooShort { len } => {
                write!(
                    f,
                    "datagram of {len} bytes is shorter than the 4-byte CoAP header"
                )
            }
            DecodeError::BadVersion { version } => {
                write!(f, "CoAP version {version} is not supported (expected 1)")
            }
            DecodeError::BadTokenLength { tkl } => {
                write!(f, "token length {tkl} is reserved (must be 0-8)")
            }
            DecodeError::Truncated { what } => write!(f, "message truncated inside {what}"),
            DecodeError::ReservedOptionNibble => {
                write!(f, "option delta/length nibble 15 is reserved")
            }
            DecodeError::EmptyPayloadAfterMarker => {
                write!(f, "payload marker present but payload is empty")
            }
        }
    }
}

impl std::error::Error for DecodeError {}

/// Why a message cannot be put on the wire.
///
/// The decode side above is bounded against a hostile peer; this is the same bound stated
/// against the *caller*, which is the direction that had none. Both refusals are total: a
/// message this codec would not accept back is never written in a shortened form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncodeError {
    /// A token longer than the 4-bit TKL field can describe (RFC 7252 §3: 0-8 octets).
    TokenTooLong { len: usize },
    /// An option value longer than the extended length form can describe.
    OptionTooLong { number: u16, len: usize },
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EncodeError::TokenTooLong { len } => write!(
                f,
                "token is {len} octets; RFC 7252 §3 allows 0-{MAX_TOKEN_LEN}, and CoAP matches \
                 a response to its request by token equality, so a shortened one matches nothing"
            ),
            EncodeError::OptionTooLong { number, len } => write!(
                f,
                "option {number} carries {len} octets; the option length field tops out at \
                 {MAX_OPTION_LEN}"
            ),
        }
    }
}

impl std::error::Error for EncodeError {}

impl CoapMessage {
    /// Decode a datagram.
    pub fn decode(buf: &[u8]) -> Result<CoapMessage, DecodeError> {
        if buf.len() < HEADER_LEN {
            return Err(DecodeError::TooShort { len: buf.len() });
        }

        let version = buf[0] >> 6;
        if version != VERSION {
            return Err(DecodeError::BadVersion { version });
        }
        let mtype = MessageType::from_bits(buf[0] >> 4);
        let tkl = buf[0] & 0x0F;
        if tkl > 8 {
            return Err(DecodeError::BadTokenLength { tkl });
        }
        let code = buf[1];
        let message_id = u16::from_be_bytes([buf[2], buf[3]]);

        let mut pos = HEADER_LEN;
        if buf.len() < pos + tkl as usize {
            return Err(DecodeError::Truncated { what: "token" });
        }
        let token = buf[pos..pos + tkl as usize].to_vec();
        pos += tkl as usize;

        let mut options: Vec<(u16, Vec<u8>)> = Vec::new();
        let mut current_number: u16 = 0;
        let mut payload = Vec::new();

        while pos < buf.len() {
            if buf[pos] == PAYLOAD_MARKER {
                pos += 1;
                if pos >= buf.len() {
                    return Err(DecodeError::EmptyPayloadAfterMarker);
                }
                payload = buf[pos..].to_vec();
                break;
            }

            let delta_nibble = buf[pos] >> 4;
            let length_nibble = buf[pos] & 0x0F;
            pos += 1;

            let delta = read_extended(buf, &mut pos, delta_nibble)?;
            let length = read_extended(buf, &mut pos, length_nibble)?;

            if buf.len() < pos + length as usize {
                return Err(DecodeError::Truncated {
                    what: "option value",
                });
            }
            current_number = current_number.saturating_add(delta);
            options.push((current_number, buf[pos..pos + length as usize].to_vec()));
            pos += length as usize;
        }

        Ok(CoapMessage {
            mtype,
            code,
            message_id,
            token,
            options,
            payload,
        })
    }

    /// Encode to a datagram.
    ///
    /// Refuses anything `decode` would not accept back, rather than shortening it to fit. See
    /// [`MAX_TOKEN_LEN`] for why truncating a token is the worst outcome available here.
    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        if self.token.len() > MAX_TOKEN_LEN {
            return Err(EncodeError::TokenTooLong {
                len: self.token.len(),
            });
        }
        for (number, value) in &self.options {
            if value.len() > MAX_OPTION_LEN {
                return Err(EncodeError::OptionTooLong {
                    number: *number,
                    len: value.len(),
                });
            }
        }

        let mut out = Vec::with_capacity(HEADER_LEN + self.token.len() + self.payload.len() + 16);
        let tkl = self.token.len() as u8;
        out.push((VERSION << 6) | (self.mtype.to_bits() << 4) | tkl);
        out.push(self.code);
        out.extend_from_slice(&self.message_id.to_be_bytes());
        out.extend_from_slice(&self.token);

        let mut sorted = self.options.clone();
        // Options must be emitted in ascending order; `sort_by_key` is stable, so
        // repeated options (Uri-Path segments) keep the order they were given in.
        sorted.sort_by_key(|(n, _)| *n);

        let mut last: u16 = 0;
        for (number, value) in &sorted {
            let delta = number.saturating_sub(last);
            last = *number;

            // Range-checked above, so neither cast can lose a bit.
            let (delta_nibble, delta_ext) = split_extended(delta);
            let (length_nibble, length_ext) = split_extended(value.len() as u16);

            out.push((delta_nibble << 4) | length_nibble);
            out.extend_from_slice(&delta_ext);
            out.extend_from_slice(&length_ext);
            out.extend_from_slice(value);
        }

        if !self.payload.is_empty() {
            out.push(PAYLOAD_MARKER);
            out.extend_from_slice(&self.payload);
        }

        Ok(out)
    }

    /// Values of every occurrence of an option, in order.
    pub fn option_values(&self, number: u16) -> Vec<&[u8]> {
        self.options
            .iter()
            .filter(|(n, _)| *n == number)
            .map(|(_, v)| v.as_slice())
            .collect()
    }

    /// First value of an option, decoded as a big-endian unsigned integer.
    pub fn option_uint(&self, number: u16) -> Option<u32> {
        self.option_values(number)
            .first()
            .map(|v| v.iter().take(4).fold(0u32, |acc, b| (acc << 8) | *b as u32))
    }

    /// Request path assembled from the Uri-Path options, always leading-slashed.
    pub fn uri_path(&self) -> String {
        let segments: Vec<String> = self
            .option_values(OPT_URI_PATH)
            .iter()
            .map(|v| String::from_utf8_lossy(v).to_string())
            .collect();
        if segments.is_empty() {
            "/".to_string()
        } else {
            format!("/{}", segments.join("/"))
        }
    }

    /// Uri-Path options as individual segments.
    pub fn path_segments(&self) -> Vec<String> {
        self.option_values(OPT_URI_PATH)
            .iter()
            .map(|v| String::from_utf8_lossy(v).to_string())
            .collect()
    }

    /// Query string assembled from the Uri-Query options, `&`-joined, or `None`.
    pub fn uri_query(&self) -> Option<String> {
        let parts: Vec<String> = self
            .option_values(OPT_URI_QUERY)
            .iter()
            .map(|v| String::from_utf8_lossy(v).to_string())
            .collect();
        if parts.is_empty() {
            None
        } else {
            Some(parts.join("&"))
        }
    }

    /// True when this message is empty (code 0.00 and no token, options or payload).
    pub fn is_empty_message(&self) -> bool {
        self.code == CODE_EMPTY
    }

    /// True when the code is one of the four defined request methods.
    pub fn is_request(&self) -> bool {
        method_name(self.code).is_some()
    }
}

/// A Block1 or Block2 option value: `NUM << 4 | M << 3 | SZX` (RFC 7959 §2.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockValue {
    /// Block number, 0-based. At most 20 bits.
    pub num: u32,
    /// More blocks follow.
    pub more: bool,
    /// Size exponent: the block is `2^(szx + 4)` bytes, 16 to 1024.
    pub szx: u8,
}

/// Largest block number a three-byte option value can carry.
pub const MAX_BLOCK_NUM: u32 = (1 << 20) - 1;

/// The largest size exponent: SZX 6 is 1024 bytes. 7 is reserved (BERT, CoAP over TCP only).
pub const MAX_SZX: u8 = 6;

impl BlockValue {
    /// Read an option value. `None` for more than three bytes or the reserved SZX 7.
    pub fn parse(value: &[u8]) -> Option<BlockValue> {
        if value.len() > 3 {
            return None;
        }
        let v = value.iter().fold(0u32, |acc, b| (acc << 8) | u32::from(*b));
        let szx = (v & 0x07) as u8;
        if szx > MAX_SZX {
            return None;
        }
        Some(BlockValue {
            num: v >> 4,
            more: v & 0x08 != 0,
            szx,
        })
    }

    /// The option value, minimum-length big-endian. `num` is masked to 20 bits.
    pub fn encode(self) -> Vec<u8> {
        let v = ((self.num & MAX_BLOCK_NUM) << 4)
            | if self.more { 0x08 } else { 0 }
            | u32::from(self.szx.min(MAX_SZX));
        let bytes = v.to_be_bytes();
        let first = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
        bytes[first..].to_vec()
    }

    /// Block size in bytes.
    pub fn size(self) -> usize {
        szx_size(self.szx)
    }

    /// Byte offset of this block in the whole body.
    pub fn offset(self) -> usize {
        self.num as usize * self.size()
    }
}

/// Block size for a size exponent, `2^(szx + 4)`, clamped to SZX 6.
pub const fn szx_size(szx: u8) -> usize {
    let szx = if szx > MAX_SZX { MAX_SZX } else { szx };
    1 << (szx as u32 + 4)
}

impl CoapMessage {
    /// The Block1 option, if present and readable. `Some(None)` when present but malformed.
    pub fn block1(&self) -> Option<Option<BlockValue>> {
        self.option_values(OPT_BLOCK1)
            .first()
            .map(|v| BlockValue::parse(v))
    }

    /// The Block2 option, if present and readable. `Some(None)` when present but malformed.
    pub fn block2(&self) -> Option<Option<BlockValue>> {
        self.option_values(OPT_BLOCK2)
            .first()
            .map(|v| BlockValue::parse(v))
    }

    /// The Observe option's value, if present. Values are at most three bytes (24 bits).
    pub fn observe(&self) -> Option<u32> {
        self.option_values(OPT_OBSERVE)
            .first()
            .filter(|v| v.len() <= 3)
            .map(|v| v.iter().fold(0u32, |acc, b| (acc << 8) | u32::from(*b)))
    }
}

/// The part of a message that lives at fixed offsets: the header and the token.
///
/// Everything here can be read without walking a single option, which is what makes it
/// usable for a datagram the server has decided **not** to parse. A refusal still has to
/// carry the request's message id and token or the client discards it as unsolicited and
/// the refusal is indistinguishable from silence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessagePrefix {
    pub mtype: MessageType,
    pub code: u8,
    pub message_id: u16,
    pub token: Vec<u8>,
}

/// Read the header and token of a datagram without touching its options or payload.
///
/// `None` when the bytes are not a CoAP message at all by the parts this reads — too
/// short, wrong version, a reserved token length, or a token that runs off the end. In
/// that case there is nothing to echo and no reply can be matched to anything.
pub fn message_prefix(buf: &[u8]) -> Option<MessagePrefix> {
    if buf.len() < HEADER_LEN || buf[0] >> 6 != VERSION {
        return None;
    }
    let tkl = (buf[0] & 0x0F) as usize;
    if tkl > MAX_TOKEN_LEN || buf.len() < HEADER_LEN + tkl {
        return None;
    }
    Some(MessagePrefix {
        mtype: MessageType::from_bits(buf[0] >> 4),
        code: buf[1],
        message_id: u16::from_be_bytes([buf[2], buf[3]]),
        token: buf[HEADER_LEN..HEADER_LEN + tkl].to_vec(),
    })
}

/// Build the piggybacked/separate response shell for a request.
///
/// The message id and token are taken from the request, which is why the model never
/// sees or supplies them: reliability matching is the transport's job, not a decision.
/// A Confirmable request is answered with an Acknowledgement carrying the same message
/// id (RFC 7252 §5.2.1); a Non-confirmable request is answered with a Non-confirmable
/// message carrying a fresh message id.
pub fn response_to(request: &CoapMessage, fresh_message_id: u16, code: u8) -> CoapMessage {
    response_shell(
        request.mtype,
        request.message_id,
        request.token.clone(),
        fresh_message_id,
        code,
    )
}

/// The same shell, built from a [`MessagePrefix`] — for a datagram that was refused
/// before it was decoded, which therefore has no [`CoapMessage`] to answer from.
pub fn response_to_prefix(prefix: &MessagePrefix, fresh_message_id: u16, code: u8) -> CoapMessage {
    response_shell(
        prefix.mtype,
        prefix.message_id,
        prefix.token.clone(),
        fresh_message_id,
        code,
    )
}

fn response_shell(
    request_type: MessageType,
    request_message_id: u16,
    token: Vec<u8>,
    fresh_message_id: u16,
    code: u8,
) -> CoapMessage {
    let (mtype, message_id) = match request_type {
        MessageType::Confirmable => (MessageType::Acknowledgement, request_message_id),
        _ => (MessageType::NonConfirmable, fresh_message_id),
    };
    CoapMessage {
        mtype,
        code,
        message_id,
        token,
        options: Vec::new(),
        payload: Vec::new(),
    }
}

/// An empty Reset for the given message id (RFC 7252 §4.2).
pub fn reset_for(message_id: u16) -> CoapMessage {
    CoapMessage {
        mtype: MessageType::Reset,
        code: CODE_EMPTY,
        message_id,
        token: Vec::new(),
        options: Vec::new(),
        payload: Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// Option delta/length extension encoding
// ---------------------------------------------------------------------------

/// Read the extended value that a nibble of 13 or 14 introduces.
fn read_extended(buf: &[u8], pos: &mut usize, nibble: u8) -> Result<u16, DecodeError> {
    match nibble {
        0..=12 => Ok(nibble as u16),
        13 => {
            let b = *buf.get(*pos).ok_or(DecodeError::Truncated {
                what: "option extension byte",
            })?;
            *pos += 1;
            Ok(b as u16 + 13)
        }
        14 => {
            if buf.len() < *pos + 2 {
                return Err(DecodeError::Truncated {
                    what: "option extension bytes",
                });
            }
            let v = u16::from_be_bytes([buf[*pos], buf[*pos + 1]]);
            *pos += 2;
            Ok(v.saturating_add(269))
        }
        _ => Err(DecodeError::ReservedOptionNibble),
    }
}

/// Split a delta or length into its nibble and extension bytes.
fn split_extended(value: u16) -> (u8, Vec<u8>) {
    if value < 13 {
        (value as u8, Vec::new())
    } else if value < 269 {
        (13, vec![(value - 13) as u8])
    } else {
        (14, (value - 269).to_be_bytes().to_vec())
    }
}

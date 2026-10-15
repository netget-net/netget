//! OpenFlow 1.3 (wire version 0x04) framing and message codec, written by hand from the
//! OpenFlow Switch Specification 1.3.5 (ONF TS-023). Shared by the controller
//! (`src/server/openflow/`) and the switch (`src/client/openflow/`). Pure: no sockets here.
//!
//! Every length on the wire is a peer's claim, so every one is checked against the bytes that
//! are actually there before it is used, and every list a peer controls is bounded:
//!
//! - a message is at most [`MAX_MESSAGE_LEN`] bytes, which the 16-bit length field already
//!   enforces, and at least the 8-byte header;
//! - a match carries at most [`MAX_OXMS`] OXM TLVs, an action list at most [`MAX_ACTIONS`]
//!   actions, an instruction list at most [`MAX_INSTRUCTIONS`] instructions;
//! - a HELLO carries at most [`MAX_HELLO_ELEMENTS`] elements;
//! - a multipart reply carries at most [`MAX_MULTIPART_ENTRIES`] entries per part.
//!
//! Nothing here recurses: an instruction holds an action list and a set-field action holds one
//! OXM, and neither can hold the other, so nesting is two levels by construction.
use anyhow::{anyhow, bail, ensure, Result};
use tokio::io::{AsyncRead, AsyncReadExt};

/// The only version this implementation speaks. A peer offering 1.4 or 1.5 in its HELLO
/// bitmap negotiates down to it; a peer offering only 1.0–1.2 is refused with HELLO_FAILED.
pub const VERSION_1_3: u8 = 0x04;
/// `ofp_header`: version, type, length, xid.
pub const HEADER_LEN: usize = 8;
/// The 16-bit length field is the whole bound: no OpenFlow message is longer.
pub const MAX_MESSAGE_LEN: usize = u16::MAX as usize;
/// OXM TLVs in one match. OpenFlow 1.3 defines 40 basic fields and a field may appear once.
pub const MAX_OXMS: usize = 64;
/// Actions in one action list or action set.
pub const MAX_ACTIONS: usize = 64;
/// Instructions in one flow entry. The six instruction types may each appear once.
pub const MAX_INSTRUCTIONS: usize = 8;
/// Elements in one HELLO.
pub const MAX_HELLO_ELEMENTS: usize = 16;
/// Entries decoded from one multipart part (flows, ports, tables).
pub const MAX_MULTIPART_ENTRIES: usize = 1024;
/// `OFP_NO_BUFFER`: the packet is carried whole rather than buffered at the switch.
pub const NO_BUFFER: u32 = 0xffff_ffff;
/// `OFPCML_NO_BUFFER`: send the whole packet to the controller.
pub const CML_NO_BUFFER: u16 = 0xffff;
/// `OFPTT_ALL`.
pub const TABLE_ALL: u8 = 0xff;
/// `OFPG_ANY`.
pub const GROUP_ANY: u32 = 0xffff_ffff;
/// The OXM class every basic field lives in.
pub const OXM_CLASS_BASIC: u16 = 0x8000;
pub const OXM_CLASS_EXPERIMENTER: u16 = 0xffff;
/// `OFPVID_PRESENT`: set in an OXM VLAN_VID when a tag is present.
pub const VID_PRESENT: u16 = 0x1000;

/// Message types (`ofp_type`).
pub mod msg {
    pub const HELLO: u8 = 0;
    pub const ERROR: u8 = 1;
    pub const ECHO_REQUEST: u8 = 2;
    pub const ECHO_REPLY: u8 = 3;
    pub const EXPERIMENTER: u8 = 4;
    pub const FEATURES_REQUEST: u8 = 5;
    pub const FEATURES_REPLY: u8 = 6;
    pub const GET_CONFIG_REQUEST: u8 = 7;
    pub const GET_CONFIG_REPLY: u8 = 8;
    pub const SET_CONFIG: u8 = 9;
    pub const PACKET_IN: u8 = 10;
    pub const FLOW_REMOVED: u8 = 11;
    pub const PORT_STATUS: u8 = 12;
    pub const PACKET_OUT: u8 = 13;
    pub const FLOW_MOD: u8 = 14;
    pub const GROUP_MOD: u8 = 15;
    pub const PORT_MOD: u8 = 16;
    pub const TABLE_MOD: u8 = 17;
    pub const MULTIPART_REQUEST: u8 = 18;
    pub const MULTIPART_REPLY: u8 = 19;
    pub const BARRIER_REQUEST: u8 = 20;
    pub const BARRIER_REPLY: u8 = 21;
    pub const QUEUE_GET_CONFIG_REQUEST: u8 = 22;
    pub const QUEUE_GET_CONFIG_REPLY: u8 = 23;
    pub const ROLE_REQUEST: u8 = 24;
    pub const ROLE_REPLY: u8 = 25;
    pub const GET_ASYNC_REQUEST: u8 = 26;
    pub const GET_ASYNC_REPLY: u8 = 27;
    pub const SET_ASYNC: u8 = 28;
    pub const METER_MOD: u8 = 29;
}

pub fn msg_name(t: u8) -> &'static str {
    const NAMES: [&str; 30] = [
        "HELLO",
        "ERROR",
        "ECHO_REQUEST",
        "ECHO_REPLY",
        "EXPERIMENTER",
        "FEATURES_REQUEST",
        "FEATURES_REPLY",
        "GET_CONFIG_REQUEST",
        "GET_CONFIG_REPLY",
        "SET_CONFIG",
        "PACKET_IN",
        "FLOW_REMOVED",
        "PORT_STATUS",
        "PACKET_OUT",
        "FLOW_MOD",
        "GROUP_MOD",
        "PORT_MOD",
        "TABLE_MOD",
        "MULTIPART_REQUEST",
        "MULTIPART_REPLY",
        "BARRIER_REQUEST",
        "BARRIER_REPLY",
        "QUEUE_GET_CONFIG_REQUEST",
        "QUEUE_GET_CONFIG_REPLY",
        "ROLE_REQUEST",
        "ROLE_REPLY",
        "GET_ASYNC_REQUEST",
        "GET_ASYNC_REPLY",
        "SET_ASYNC",
        "METER_MOD",
    ];
    NAMES.get(t as usize).copied().unwrap_or("UNKNOWN")
}

/// Error types (`ofp_error_type`) and the codes this implementation sends.
pub mod err {
    pub const HELLO_FAILED: u16 = 0;
    pub const BAD_REQUEST: u16 = 1;
    pub const BAD_ACTION: u16 = 2;
    pub const BAD_INSTRUCTION: u16 = 3;
    pub const BAD_MATCH: u16 = 4;
    pub const FLOW_MOD_FAILED: u16 = 5;
    pub const GROUP_MOD_FAILED: u16 = 6;
    pub const PORT_MOD_FAILED: u16 = 7;
    pub const TABLE_MOD_FAILED: u16 = 8;
    pub const QUEUE_OP_FAILED: u16 = 9;
    pub const SWITCH_CONFIG_FAILED: u16 = 10;
    pub const ROLE_REQUEST_FAILED: u16 = 11;
    pub const METER_MOD_FAILED: u16 = 12;
    pub const TABLE_FEATURES_FAILED: u16 = 13;
    pub const EXPERIMENTER: u16 = 0xffff;

    pub const HELLO_INCOMPATIBLE: u16 = 0;

    pub const BAD_REQUEST_BAD_VERSION: u16 = 0;
    pub const BAD_REQUEST_BAD_TYPE: u16 = 1;
    pub const BAD_REQUEST_BAD_MULTIPART: u16 = 2;
    pub const BAD_REQUEST_BAD_EXPERIMENTER: u16 = 3;
    pub const BAD_REQUEST_BAD_LEN: u16 = 6;
    pub const BAD_REQUEST_BUFFER_UNKNOWN: u16 = 8;
    pub const BAD_REQUEST_BAD_PORT: u16 = 11;
    pub const BAD_REQUEST_BAD_PACKET: u16 = 12;
    pub const BAD_REQUEST_MULTIPART_BUFFER_OVERFLOW: u16 = 13;

    pub const BAD_ACTION_BAD_TYPE: u16 = 0;
    pub const BAD_ACTION_BAD_LEN: u16 = 1;
    pub const BAD_ACTION_BAD_OUT_PORT: u16 = 4;
    pub const BAD_ACTION_BAD_ARGUMENT: u16 = 5;
    pub const BAD_ACTION_TOO_MANY: u16 = 7;
    pub const BAD_ACTION_BAD_SET_TYPE: u16 = 13;
    pub const BAD_ACTION_BAD_SET_LEN: u16 = 14;
    pub const BAD_ACTION_BAD_SET_ARGUMENT: u16 = 15;

    pub const BAD_INSTRUCTION_UNKNOWN_INST: u16 = 0;
    pub const BAD_INSTRUCTION_BAD_LEN: u16 = 7;

    pub const BAD_MATCH_BAD_TYPE: u16 = 0;
    pub const BAD_MATCH_BAD_LEN: u16 = 1;
    pub const BAD_MATCH_BAD_FIELD: u16 = 6;
    pub const BAD_MATCH_BAD_VALUE: u16 = 7;
    pub const BAD_MATCH_BAD_MASK: u16 = 8;
    pub const BAD_MATCH_BAD_PREREQ: u16 = 9;
    pub const BAD_MATCH_DUP_FIELD: u16 = 10;

    pub const FLOW_MOD_FAILED_UNKNOWN: u16 = 0;
    pub const FLOW_MOD_FAILED_TABLE_FULL: u16 = 1;
    pub const FLOW_MOD_FAILED_BAD_TABLE_ID: u16 = 2;
    pub const FLOW_MOD_FAILED_OVERLAP: u16 = 3;
    pub const FLOW_MOD_FAILED_BAD_COMMAND: u16 = 6;
}

pub fn error_type_name(t: u16) -> &'static str {
    match t {
        err::HELLO_FAILED => "HELLO_FAILED",
        err::BAD_REQUEST => "BAD_REQUEST",
        err::BAD_ACTION => "BAD_ACTION",
        err::BAD_INSTRUCTION => "BAD_INSTRUCTION",
        err::BAD_MATCH => "BAD_MATCH",
        err::FLOW_MOD_FAILED => "FLOW_MOD_FAILED",
        err::GROUP_MOD_FAILED => "GROUP_MOD_FAILED",
        err::PORT_MOD_FAILED => "PORT_MOD_FAILED",
        err::TABLE_MOD_FAILED => "TABLE_MOD_FAILED",
        err::QUEUE_OP_FAILED => "QUEUE_OP_FAILED",
        err::SWITCH_CONFIG_FAILED => "SWITCH_CONFIG_FAILED",
        err::ROLE_REQUEST_FAILED => "ROLE_REQUEST_FAILED",
        err::METER_MOD_FAILED => "METER_MOD_FAILED",
        err::TABLE_FEATURES_FAILED => "TABLE_FEATURES_FAILED",
        err::EXPERIMENTER => "EXPERIMENTER",
        _ => "UNKNOWN",
    }
}

/// The spec's name for an error code, where this implementation knows it.
pub fn error_code_name(t: u16, c: u16) -> &'static str {
    let table: &[&str] = match t {
        err::HELLO_FAILED => &["INCOMPATIBLE", "EPERM"],
        err::BAD_REQUEST => &[
            "BAD_VERSION",
            "BAD_TYPE",
            "BAD_MULTIPART",
            "BAD_EXPERIMENTER",
            "BAD_EXP_TYPE",
            "EPERM",
            "BAD_LEN",
            "BUFFER_EMPTY",
            "BUFFER_UNKNOWN",
            "BAD_TABLE_ID",
            "IS_SLAVE",
            "BAD_PORT",
            "BAD_PACKET",
            "MULTIPART_BUFFER_OVERFLOW",
        ],
        err::BAD_ACTION => &[
            "BAD_TYPE",
            "BAD_LEN",
            "BAD_EXPERIMENTER",
            "BAD_EXP_TYPE",
            "BAD_OUT_PORT",
            "BAD_ARGUMENT",
            "EPERM",
            "TOO_MANY",
            "BAD_QUEUE",
            "BAD_OUT_GROUP",
            "MATCH_INCONSISTENT",
            "UNSUPPORTED_ORDER",
            "BAD_TAG",
            "BAD_SET_TYPE",
            "BAD_SET_LEN",
            "BAD_SET_ARGUMENT",
        ],
        err::BAD_INSTRUCTION => &[
            "UNKNOWN_INST",
            "UNSUP_INST",
            "BAD_TABLE_ID",
            "UNSUP_METADATA",
            "UNSUP_METADATA_MASK",
            "BAD_EXPERIMENTER",
            "BAD_EXP_TYPE",
            "BAD_LEN",
            "EPERM",
        ],
        err::BAD_MATCH => &[
            "BAD_TYPE",
            "BAD_LEN",
            "BAD_TAG",
            "BAD_DL_ADDR_MASK",
            "BAD_NW_ADDR_MASK",
            "BAD_WILDCARDS",
            "BAD_FIELD",
            "BAD_VALUE",
            "BAD_MASK",
            "BAD_PREREQ",
            "DUP_FIELD",
            "EPERM",
        ],
        err::FLOW_MOD_FAILED => &[
            "UNKNOWN",
            "TABLE_FULL",
            "BAD_TABLE_ID",
            "OVERLAP",
            "EPERM",
            "BAD_TIMEOUT",
            "BAD_COMMAND",
            "BAD_FLAGS",
        ],
        err::GROUP_MOD_FAILED => &[
            "GROUP_EXISTS",
            "INVALID_GROUP",
            "WEIGHT_UNSUPPORTED",
            "OUT_OF_GROUPS",
            "OUT_OF_BUCKETS",
            "CHAINING_UNSUPPORTED",
            "WATCH_UNSUPPORTED",
            "LOOP",
            "UNKNOWN_GROUP",
            "CHAINED_GROUP",
            "BAD_TYPE",
            "BAD_COMMAND",
            "BAD_BUCKET",
            "BAD_WATCH",
            "EPERM",
        ],
        err::PORT_MOD_FAILED => &[
            "BAD_PORT",
            "BAD_HW_ADDR",
            "BAD_CONFIG",
            "BAD_ADVERTISE",
            "EPERM",
        ],
        err::SWITCH_CONFIG_FAILED => &["BAD_FLAGS", "BAD_LEN", "EPERM"],
        err::ROLE_REQUEST_FAILED => &["STALE", "UNSUP", "BAD_ROLE"],
        _ => &[],
    };
    table.get(c as usize).copied().unwrap_or("UNKNOWN")
}

/// Reserved port numbers (`ofp_port_no`).
pub mod port {
    pub const MAX: u32 = 0xffff_ff00;
    pub const IN_PORT: u32 = 0xffff_fff8;
    pub const TABLE: u32 = 0xffff_fff9;
    pub const NORMAL: u32 = 0xffff_fffa;
    pub const FLOOD: u32 = 0xffff_fffb;
    pub const ALL: u32 = 0xffff_fffc;
    pub const CONTROLLER: u32 = 0xffff_fffd;
    pub const LOCAL: u32 = 0xffff_fffe;
    pub const ANY: u32 = 0xffff_ffff;

    pub const RESERVED: [(&str, u32); 8] = [
        ("in_port", IN_PORT),
        ("table", TABLE),
        ("normal", NORMAL),
        ("flood", FLOOD),
        ("all", ALL),
        ("controller", CONTROLLER),
        ("local", LOCAL),
        ("any", ANY),
    ];

    /// The name of a reserved port, or `None` for a physical or logical one.
    pub fn reserved_name(p: u32) -> Option<&'static str> {
        RESERVED.iter().find(|(_, v)| *v == p).map(|(n, _)| *n)
    }

    pub fn by_name(name: &str) -> Option<u32> {
        let n = name.trim().to_ascii_lowercase();
        RESERVED.iter().find(|(k, _)| *k == n).map(|(_, v)| *v)
    }
}

/// A big-endian reader over a byte slice whose every read is checked.
pub struct Rd<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Rd<'a> {
    pub fn new(b: &'a [u8]) -> Self {
        Self { b, pos: 0 }
    }
    pub fn remaining(&self) -> usize {
        self.b.len() - self.pos
    }
    pub fn pos(&self) -> usize {
        self.pos
    }
    pub fn take(&mut self, n: usize, what: &str) -> Result<&'a [u8]> {
        ensure!(
            n <= self.remaining(),
            "{what}: {n} bytes needed, {} left",
            self.remaining()
        );
        let s = &self.b[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    pub fn skip(&mut self, n: usize, what: &str) -> Result<()> {
        self.take(n, what).map(|_| ())
    }
    pub fn u8(&mut self, what: &str) -> Result<u8> {
        Ok(self.take(1, what)?[0])
    }
    pub fn u16(&mut self, what: &str) -> Result<u16> {
        let s = self.take(2, what)?;
        Ok(u16::from_be_bytes([s[0], s[1]]))
    }
    pub fn u32(&mut self, what: &str) -> Result<u32> {
        let s = self.take(4, what)?;
        Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    }
    pub fn u64(&mut self, what: &str) -> Result<u64> {
        let s = self.take(8, what)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(s);
        Ok(u64::from_be_bytes(a))
    }
    pub fn rest(&mut self) -> &'a [u8] {
        let s = &self.b[self.pos..];
        self.pos = self.b.len();
        s
    }
}

fn pad8(len: usize) -> usize {
    (8 - len % 8) % 8
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub version: u8,
    pub msg_type: u8,
    pub length: u16,
    pub xid: u32,
}

impl Header {
    pub fn parse(b: &[u8; HEADER_LEN]) -> Header {
        Header {
            version: b[0],
            msg_type: b[1],
            length: u16::from_be_bytes([b[2], b[3]]),
            xid: u32::from_be_bytes([b[4], b[5], b[6], b[7]]),
        }
    }
}

/// One whole message: header fields and the bytes after the header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub header: Header,
    pub body: Vec<u8>,
}

impl Message {
    /// The message re-encoded as it arrived, for an ERROR's data field.
    pub fn raw(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + self.body.len());
        out.push(self.header.version);
        out.push(self.header.msg_type);
        out.extend_from_slice(&self.header.length.to_be_bytes());
        out.extend_from_slice(&self.header.xid.to_be_bytes());
        out.extend_from_slice(&self.body);
        out
    }
}

/// Frame a message. Fails only when the body does not fit the 16-bit length.
pub fn encode(version: u8, msg_type: u8, xid: u32, body: &[u8]) -> Result<Vec<u8>> {
    let len = HEADER_LEN + body.len();
    ensure!(
        len <= MAX_MESSAGE_LEN,
        "a {} message of {len} bytes is longer than OpenFlow's {MAX_MESSAGE_LEN}-byte limit",
        msg_name(msg_type)
    );
    let mut out = Vec::with_capacity(len);
    out.push(version);
    out.push(msg_type);
    out.extend_from_slice(&(len as u16).to_be_bytes());
    out.extend_from_slice(&xid.to_be_bytes());
    out.extend_from_slice(body);
    Ok(out)
}

#[derive(Debug)]
pub enum ReadError {
    Io(std::io::Error),
    /// The header claimed fewer than its own eight bytes.
    BadLength(u16),
}

impl std::fmt::Display for ReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReadError::Io(e) => write!(f, "{e}"),
            ReadError::BadLength(n) => {
                write!(
                    f,
                    "a message length of {n} is shorter than the 8-byte header"
                )
            }
        }
    }
}

impl From<std::io::Error> for ReadError {
    fn from(e: std::io::Error) -> Self {
        ReadError::Io(e)
    }
}

/// Read one message. The header's length is validated before anything is allocated for the
/// body, and the body can never be larger than 65,527 bytes because the field is 16 bits.
pub async fn read_message<R: AsyncRead + Unpin>(r: &mut R) -> Result<Message, ReadError> {
    let mut h = [0u8; HEADER_LEN];
    r.read_exact(&mut h).await?;
    let header = Header::parse(&h);
    if (header.length as usize) < HEADER_LEN {
        return Err(ReadError::BadLength(header.length));
    }
    let mut body = vec![0u8; header.length as usize - HEADER_LEN];
    r.read_exact(&mut body).await?;
    Ok(Message { header, body })
}

// ---- HELLO ---------------------------------------------------------------------------------

const HELLO_ELEM_VERSIONBITMAP: u16 = 1;

/// A HELLO body offering exactly `versions` in a version bitmap element.
pub fn hello_body(versions: &[u8]) -> Vec<u8> {
    let mut bitmap = 0u32;
    for v in versions {
        if *v < 32 {
            bitmap |= 1 << v;
        }
    }
    let mut out = Vec::new();
    out.extend_from_slice(&HELLO_ELEM_VERSIONBITMAP.to_be_bytes());
    out.extend_from_slice(&8u16.to_be_bytes());
    out.extend_from_slice(&bitmap.to_be_bytes());
    out
}

/// The versions a HELLO's bitmap offers, if it carried one.
pub fn parse_hello_bitmap(body: &[u8]) -> Result<Option<Vec<u32>>> {
    let mut rd = Rd::new(body);
    let mut elements = 0usize;
    let mut bitmap = None;
    while rd.remaining() >= 4 {
        elements += 1;
        ensure!(
            elements <= MAX_HELLO_ELEMENTS,
            "a HELLO with more than {MAX_HELLO_ELEMENTS} elements"
        );
        let etype = rd.u16("hello element type")?;
        let len = rd.u16("hello element length")? as usize;
        ensure!(len >= 4, "a HELLO element of length {len}");
        let data = rd.take(len - 4, "hello element")?;
        let padding = pad8(len).min(rd.remaining());
        rd.skip(padding, "hello element padding")?;
        if etype == HELLO_ELEM_VERSIONBITMAP {
            ensure!(
                data.len() % 4 == 0,
                "a version bitmap that is not whole words"
            );
            bitmap = Some(
                data.chunks_exact(4)
                    .map(|c| u32::from_be_bytes([c[0], c[1], c[2], c[3]]))
                    .collect(),
            );
        }
    }
    Ok(bitmap)
}

/// The version both sides speak, per the spec's negotiation rules: with both bitmaps, the
/// highest version both offer; without the peer's bitmap, the lower of the two header versions
/// — which must then be one we speak.
pub fn negotiate(peer_header_version: u8, peer_bitmap: Option<&[u32]>) -> Option<u8> {
    match peer_bitmap {
        Some(words) => {
            let word = (VERSION_1_3 / 32) as usize;
            let bit = VERSION_1_3 % 32;
            words
                .get(word)
                .is_some_and(|w| w & (1 << bit) != 0)
                .then_some(VERSION_1_3)
        }
        None => (peer_header_version >= VERSION_1_3).then_some(VERSION_1_3),
    }
}

/// Every version a bitmap offers, for logging.
pub fn bitmap_versions(words: &[u32]) -> Vec<u8> {
    let mut out = Vec::new();
    for (i, w) in words.iter().enumerate().take(8) {
        for bit in 0..32u8 {
            if w & (1 << bit) != 0 {
                out.push((i as u8) * 32 + bit);
            }
        }
    }
    out
}

pub fn version_name(v: u8) -> String {
    match v {
        1 => "1.0".into(),
        2 => "1.1".into(),
        3 => "1.2".into(),
        4 => "1.3".into(),
        5 => "1.4".into(),
        6 => "1.5".into(),
        other => format!("wire version {other}"),
    }
}

// ---- ERROR ---------------------------------------------------------------------------------

/// The first bytes of the offending request an ERROR carries (the spec says at least 64).
pub const ERROR_DATA_BYTES: usize = 64;

pub fn error_body(etype: u16, code: u16, offending: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + ERROR_DATA_BYTES);
    out.extend_from_slice(&etype.to_be_bytes());
    out.extend_from_slice(&code.to_be_bytes());
    out.extend_from_slice(&offending[..offending.len().min(ERROR_DATA_BYTES)]);
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorMsg {
    pub etype: u16,
    pub code: u16,
    /// For an experimenter error, the experimenter id.
    pub experimenter: Option<u32>,
    pub data: Vec<u8>,
}

impl ErrorMsg {
    pub fn parse(body: &[u8]) -> Result<ErrorMsg> {
        let mut rd = Rd::new(body);
        let etype = rd.u16("error type")?;
        let code = rd.u16("error code")?;
        let experimenter = if etype == err::EXPERIMENTER {
            Some(rd.u32("experimenter")?)
        } else {
            None
        };
        Ok(ErrorMsg {
            etype,
            code,
            experimenter,
            data: rd.rest().to_vec(),
        })
    }

    /// The type and xid of the request this error is about, read from its data.
    pub fn offending(&self) -> Option<(u8, u32)> {
        (self.data.len() >= HEADER_LEN).then(|| {
            (
                self.data[1],
                u32::from_be_bytes([self.data[4], self.data[5], self.data[6], self.data[7]]),
            )
        })
    }
}

// ---- FEATURES, CONFIG, ROLE, ASYNC --------------------------------------------------------

pub mod capability {
    pub const ALL: [(&str, u32); 7] = [
        ("flow_stats", 1),
        ("table_stats", 2),
        ("port_stats", 4),
        ("group_stats", 8),
        ("ip_reasm", 32),
        ("queue_stats", 64),
        ("port_blocked", 256),
    ];
}

pub fn capability_names(bits: u32) -> Vec<&'static str> {
    capability::ALL
        .iter()
        .filter(|(_, b)| bits & b != 0)
        .map(|(n, _)| *n)
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Features {
    pub datapath_id: u64,
    pub n_buffers: u32,
    pub n_tables: u8,
    pub auxiliary_id: u8,
    pub capabilities: u32,
}

impl Features {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(24);
        out.extend_from_slice(&self.datapath_id.to_be_bytes());
        out.extend_from_slice(&self.n_buffers.to_be_bytes());
        out.push(self.n_tables);
        out.push(self.auxiliary_id);
        out.extend_from_slice(&[0, 0]);
        out.extend_from_slice(&self.capabilities.to_be_bytes());
        out.extend_from_slice(&0u32.to_be_bytes());
        out
    }
    pub fn parse(body: &[u8]) -> Result<Features> {
        let mut rd = Rd::new(body);
        let datapath_id = rd.u64("datapath_id")?;
        let n_buffers = rd.u32("n_buffers")?;
        let n_tables = rd.u8("n_tables")?;
        let auxiliary_id = rd.u8("auxiliary_id")?;
        rd.skip(2, "pad")?;
        let capabilities = rd.u32("capabilities")?;
        Ok(Features {
            datapath_id,
            n_buffers,
            n_tables,
            auxiliary_id,
            capabilities,
        })
    }
}

pub fn datapath_id_str(dpid: u64) -> String {
    format!("{dpid:016x}")
}

/// `ofp_switch_config`: flags and miss_send_len.
pub fn config_body(flags: u16, miss_send_len: u16) -> Vec<u8> {
    let mut out = flags.to_be_bytes().to_vec();
    out.extend_from_slice(&miss_send_len.to_be_bytes());
    out
}

pub fn parse_config(body: &[u8]) -> Result<(u16, u16)> {
    let mut rd = Rd::new(body);
    Ok((rd.u16("flags")?, rd.u16("miss_send_len")?))
}

pub fn role_body(role: u32, generation_id: u64) -> Vec<u8> {
    let mut out = role.to_be_bytes().to_vec();
    out.extend_from_slice(&[0; 4]);
    out.extend_from_slice(&generation_id.to_be_bytes());
    out
}

pub fn parse_role(body: &[u8]) -> Result<(u32, u64)> {
    let mut rd = Rd::new(body);
    let role = rd.u32("role")?;
    rd.skip(4, "pad")?;
    Ok((role, rd.u64("generation_id")?))
}

/// GET_ASYNC_REPLY with the spec's defaults for a master: every packet-in reason, every
/// port-status reason, every flow-removed reason.
pub fn default_async_body() -> Vec<u8> {
    let mut out = Vec::with_capacity(24);
    for (master, slave) in [(0b111u32, 0u32), (0b111, 0b111), (0b1111, 0)] {
        out.extend_from_slice(&master.to_be_bytes());
        out.extend_from_slice(&slave.to_be_bytes());
    }
    out
}

// ---- Ports -------------------------------------------------------------------------------

pub const PORT_LEN: usize = 64;
pub const PORT_NAME_LEN: usize = 16;
pub const PORT_CONFIG_DOWN: u32 = 1;
pub const PORT_STATE_LINK_DOWN: u32 = 1;
pub const PORT_STATE_LIVE: u32 = 4;
/// `OFPPF_10GB_FD | OFPPF_COPPER`, what a virtual port usually reports.
pub const PORT_FEATURES_DEFAULT: u32 = (1 << 6) | (1 << 11);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Port {
    pub port_no: u32,
    pub hw_addr: [u8; 6],
    pub name: String,
    pub config: u32,
    pub state: u32,
    pub curr: u32,
    pub advertised: u32,
    pub supported: u32,
    pub peer: u32,
    pub curr_speed: u32,
    pub max_speed: u32,
}

impl Port {
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.port_no.to_be_bytes());
        out.extend_from_slice(&[0; 4]);
        out.extend_from_slice(&self.hw_addr);
        out.extend_from_slice(&[0; 2]);
        let mut name = [0u8; PORT_NAME_LEN];
        let bytes = self.name.as_bytes();
        let n = bytes.len().min(PORT_NAME_LEN - 1);
        name[..n].copy_from_slice(&bytes[..n]);
        out.extend_from_slice(&name);
        for v in [
            self.config,
            self.state,
            self.curr,
            self.advertised,
            self.supported,
            self.peer,
            self.curr_speed,
            self.max_speed,
        ] {
            out.extend_from_slice(&v.to_be_bytes());
        }
    }

    pub fn parse(rd: &mut Rd) -> Result<Port> {
        let port_no = rd.u32("port_no")?;
        rd.skip(4, "pad")?;
        let mut hw_addr = [0u8; 6];
        hw_addr.copy_from_slice(rd.take(6, "hw_addr")?);
        rd.skip(2, "pad")?;
        let raw = rd.take(PORT_NAME_LEN, "port name")?;
        let end = raw.iter().position(|b| *b == 0).unwrap_or(raw.len());
        let name = crate::utils::sanitize::line_field(&String::from_utf8_lossy(&raw[..end]));
        Ok(Port {
            port_no,
            hw_addr,
            name,
            config: rd.u32("config")?,
            state: rd.u32("state")?,
            curr: rd.u32("curr")?,
            advertised: rd.u32("advertised")?,
            supported: rd.u32("supported")?,
            peer: rd.u32("peer")?,
            curr_speed: rd.u32("curr_speed")?,
            max_speed: rd.u32("max_speed")?,
        })
    }
}

pub fn port_status_body(reason: u8, port: &Port) -> Vec<u8> {
    let mut out = vec![reason, 0, 0, 0, 0, 0, 0, 0];
    port.encode(&mut out);
    out
}

pub fn parse_port_status(body: &[u8]) -> Result<(u8, Port)> {
    let mut rd = Rd::new(body);
    let reason = rd.u8("reason")?;
    rd.skip(7, "pad")?;
    Ok((reason, Port::parse(&mut rd)?))
}

// ---- Match (OXM) ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Oxm {
    pub class: u16,
    pub field: u8,
    pub value: Vec<u8>,
    pub mask: Option<Vec<u8>>,
}

impl Oxm {
    pub fn basic(field: u8, value: Vec<u8>) -> Oxm {
        Oxm {
            class: OXM_CLASS_BASIC,
            field,
            value,
            mask: None,
        }
    }

    pub fn encoded_len(&self) -> usize {
        4 + self.value.len() + self.mask.as_ref().map_or(0, |m| m.len())
    }

    pub fn encode(&self, out: &mut Vec<u8>) {
        let payload = self.value.len() + self.mask.as_ref().map_or(0, |m| m.len());
        out.extend_from_slice(&self.class.to_be_bytes());
        out.push((self.field << 1) | u8::from(self.mask.is_some()));
        out.push(payload as u8);
        out.extend_from_slice(&self.value);
        if let Some(m) = &self.mask {
            out.extend_from_slice(m);
        }
    }

    pub fn parse(rd: &mut Rd) -> Result<Oxm> {
        let class = rd.u16("oxm class")?;
        let fh = rd.u8("oxm field")?;
        let len = rd.u8("oxm length")? as usize;
        let payload = rd.take(len, "oxm payload")?;
        let field = fh >> 1;
        let has_mask = fh & 1 == 1;
        if has_mask {
            ensure!(
                len % 2 == 0 && len > 0,
                "a masked OXM with an odd payload length {len}"
            );
            let half = len / 2;
            Ok(Oxm {
                class,
                field,
                value: payload[..half].to_vec(),
                mask: Some(payload[half..].to_vec()),
            })
        } else {
            Ok(Oxm {
                class,
                field,
                value: payload.to_vec(),
                mask: None,
            })
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Match {
    pub oxms: Vec<Oxm>,
}

const MATCH_TYPE_OXM: u16 = 1;

impl Match {
    /// `ofp_match` with OXM type, padded to a multiple of eight.
    pub fn encode(&self, out: &mut Vec<u8>) {
        let len = 4 + self.oxms.iter().map(Oxm::encoded_len).sum::<usize>();
        out.extend_from_slice(&MATCH_TYPE_OXM.to_be_bytes());
        out.extend_from_slice(&(len as u16).to_be_bytes());
        for o in &self.oxms {
            o.encode(out);
        }
        out.extend(std::iter::repeat_n(0u8, pad8(len)));
    }

    pub fn encoded_len(&self) -> usize {
        let len = 4 + self.oxms.iter().map(Oxm::encoded_len).sum::<usize>();
        len + pad8(len)
    }

    /// Parse an `ofp_match` and its padding. The error names the `BAD_MATCH` code a switch
    /// answers with.
    pub fn parse(rd: &mut Rd) -> Result<Match, (u16, String)> {
        let bad_len = |e: anyhow::Error| (err::BAD_MATCH_BAD_LEN, e.to_string());
        let mtype = rd.u16("match type").map_err(bad_len)?;
        let len = rd.u16("match length").map_err(bad_len)? as usize;
        if mtype != MATCH_TYPE_OXM {
            return Err((
                err::BAD_MATCH_BAD_TYPE,
                format!("match type {mtype} is not OXM (1)"),
            ));
        }
        if len < 4 {
            return Err((err::BAD_MATCH_BAD_LEN, format!("a match length of {len}")));
        }
        let body = rd.take(len - 4, "match fields").map_err(bad_len)?;
        let padding = pad8(len);
        rd.skip(padding.min(rd.remaining()), "match padding")
            .map_err(bad_len)?;
        let mut inner = Rd::new(body);
        let mut oxms = Vec::new();
        while inner.remaining() > 0 {
            if oxms.len() >= MAX_OXMS {
                return Err((
                    err::BAD_MATCH_BAD_LEN,
                    format!("a match with more than {MAX_OXMS} fields"),
                ));
            }
            let o = Oxm::parse(&mut inner).map_err(bad_len)?;
            if oxms
                .iter()
                .any(|p: &Oxm| p.class == o.class && p.field == o.field)
            {
                return Err((
                    err::BAD_MATCH_DUP_FIELD,
                    format!("field {} appears twice", o.field),
                ));
            }
            oxms.push(o);
        }
        Ok(Match { oxms })
    }

    pub fn get(&self, field: u8) -> Option<&Oxm> {
        self.oxms
            .iter()
            .find(|o| o.class == OXM_CLASS_BASIC && o.field == field)
    }
}

// ---- Actions and instructions -------------------------------------------------------------

pub mod act {
    pub const OUTPUT: u16 = 0;
    pub const COPY_TTL_OUT: u16 = 11;
    pub const COPY_TTL_IN: u16 = 12;
    pub const SET_MPLS_TTL: u16 = 15;
    pub const DEC_MPLS_TTL: u16 = 16;
    pub const PUSH_VLAN: u16 = 17;
    pub const POP_VLAN: u16 = 18;
    pub const PUSH_MPLS: u16 = 19;
    pub const POP_MPLS: u16 = 20;
    pub const SET_QUEUE: u16 = 21;
    pub const GROUP: u16 = 22;
    pub const SET_NW_TTL: u16 = 23;
    pub const DEC_NW_TTL: u16 = 24;
    pub const SET_FIELD: u16 = 25;
    pub const PUSH_PBB: u16 = 26;
    pub const POP_PBB: u16 = 27;
    pub const EXPERIMENTER: u16 = 0xffff;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Output {
        port: u32,
        max_len: u16,
    },
    CopyTtlOut,
    CopyTtlIn,
    SetMplsTtl(u8),
    DecMplsTtl,
    PushVlan(u16),
    PopVlan,
    PushMpls(u16),
    PopMpls(u16),
    SetQueue(u32),
    Group(u32),
    SetNwTtl(u8),
    DecNwTtl,
    SetField(Oxm),
    PushPbb(u16),
    PopPbb,
    /// An experimenter or unknown action, kept so it can be reported.
    Other {
        atype: u16,
        len: usize,
    },
}

impl Action {
    pub fn encode(&self, out: &mut Vec<u8>) {
        let start = out.len();
        let header = |out: &mut Vec<u8>, t: u16, len: u16| {
            out.extend_from_slice(&t.to_be_bytes());
            out.extend_from_slice(&len.to_be_bytes());
        };
        match self {
            Action::Output { port, max_len } => {
                header(out, act::OUTPUT, 16);
                out.extend_from_slice(&port.to_be_bytes());
                out.extend_from_slice(&max_len.to_be_bytes());
                out.extend_from_slice(&[0; 6]);
            }
            Action::CopyTtlOut
            | Action::CopyTtlIn
            | Action::DecMplsTtl
            | Action::PopVlan
            | Action::DecNwTtl
            | Action::PopPbb => {
                let t = match self {
                    Action::CopyTtlOut => act::COPY_TTL_OUT,
                    Action::CopyTtlIn => act::COPY_TTL_IN,
                    Action::DecMplsTtl => act::DEC_MPLS_TTL,
                    Action::PopVlan => act::POP_VLAN,
                    Action::DecNwTtl => act::DEC_NW_TTL,
                    _ => act::POP_PBB,
                };
                header(out, t, 8);
                out.extend_from_slice(&[0; 4]);
            }
            Action::SetMplsTtl(ttl) | Action::SetNwTtl(ttl) => {
                let t = if matches!(self, Action::SetMplsTtl(_)) {
                    act::SET_MPLS_TTL
                } else {
                    act::SET_NW_TTL
                };
                header(out, t, 8);
                out.extend_from_slice(&[*ttl, 0, 0, 0]);
            }
            Action::PushVlan(et)
            | Action::PushMpls(et)
            | Action::PopMpls(et)
            | Action::PushPbb(et) => {
                let t = match self {
                    Action::PushVlan(_) => act::PUSH_VLAN,
                    Action::PushMpls(_) => act::PUSH_MPLS,
                    Action::PopMpls(_) => act::POP_MPLS,
                    _ => act::PUSH_PBB,
                };
                header(out, t, 8);
                out.extend_from_slice(&et.to_be_bytes());
                out.extend_from_slice(&[0; 2]);
            }
            Action::SetQueue(id) | Action::Group(id) => {
                let t = if matches!(self, Action::SetQueue(_)) {
                    act::SET_QUEUE
                } else {
                    act::GROUP
                };
                header(out, t, 8);
                out.extend_from_slice(&id.to_be_bytes());
            }
            Action::SetField(oxm) => {
                let len = 4 + oxm.encoded_len();
                let total = len + pad8(len);
                header(out, act::SET_FIELD, total as u16);
                oxm.encode(out);
                out.extend(std::iter::repeat_n(0u8, pad8(len)));
            }
            Action::Other { .. } => {}
        }
        debug_assert_eq!((out.len() - start) % 8, 0);
    }

    pub fn parse(rd: &mut Rd) -> Result<Action, (u16, String)> {
        let bad_len = |e: anyhow::Error| (err::BAD_ACTION_BAD_LEN, e.to_string());
        let atype = rd.u16("action type").map_err(bad_len)?;
        let len = rd.u16("action length").map_err(bad_len)? as usize;
        if len < 8 || len % 8 != 0 {
            return Err((
                err::BAD_ACTION_BAD_LEN,
                format!("an action length of {len} (must be a multiple of 8, at least 8)"),
            ));
        }
        let body = rd.take(len - 4, "action body").map_err(bad_len)?;
        let mut b = Rd::new(body);
        let fixed = |want: usize| -> Result<(), (u16, String)> {
            if len != want {
                Err((
                    err::BAD_ACTION_BAD_LEN,
                    format!("action type {atype} has length {len}, not {want}"),
                ))
            } else {
                Ok(())
            }
        };
        let a = match atype {
            act::OUTPUT => {
                fixed(16)?;
                Action::Output {
                    port: b.u32("port").map_err(bad_len)?,
                    max_len: b.u16("max_len").map_err(bad_len)?,
                }
            }
            act::COPY_TTL_OUT => fixed(8).map(|_| Action::CopyTtlOut)?,
            act::COPY_TTL_IN => fixed(8).map(|_| Action::CopyTtlIn)?,
            act::DEC_MPLS_TTL => fixed(8).map(|_| Action::DecMplsTtl)?,
            act::POP_VLAN => fixed(8).map(|_| Action::PopVlan)?,
            act::DEC_NW_TTL => fixed(8).map(|_| Action::DecNwTtl)?,
            act::POP_PBB => fixed(8).map(|_| Action::PopPbb)?,
            act::SET_MPLS_TTL => {
                fixed(8)?;
                Action::SetMplsTtl(b.u8("ttl").map_err(bad_len)?)
            }
            act::SET_NW_TTL => {
                fixed(8)?;
                Action::SetNwTtl(b.u8("ttl").map_err(bad_len)?)
            }
            act::PUSH_VLAN | act::PUSH_MPLS | act::POP_MPLS | act::PUSH_PBB => {
                fixed(8)?;
                let et = b.u16("ethertype").map_err(bad_len)?;
                match atype {
                    act::PUSH_VLAN => Action::PushVlan(et),
                    act::PUSH_MPLS => Action::PushMpls(et),
                    act::POP_MPLS => Action::PopMpls(et),
                    _ => Action::PushPbb(et),
                }
            }
            act::SET_QUEUE => {
                fixed(8)?;
                Action::SetQueue(b.u32("queue_id").map_err(bad_len)?)
            }
            act::GROUP => {
                fixed(8)?;
                Action::Group(b.u32("group_id").map_err(bad_len)?)
            }
            act::SET_FIELD => {
                let oxm =
                    Oxm::parse(&mut b).map_err(|e| (err::BAD_ACTION_BAD_SET_LEN, e.to_string()))?;
                if oxm.mask.is_some() {
                    return Err((
                        err::BAD_ACTION_BAD_SET_ARGUMENT,
                        "a set-field action with a mask".into(),
                    ));
                }
                if b.rest().iter().any(|x| *x != 0) {
                    return Err((
                        err::BAD_ACTION_BAD_SET_LEN,
                        "a set-field action with bytes after its field".into(),
                    ));
                }
                Action::SetField(oxm)
            }
            other => Action::Other { atype: other, len },
        };
        Ok(a)
    }
}

/// An action list of exactly `len` bytes.
pub fn parse_actions(rd: &mut Rd, len: usize) -> Result<Vec<Action>, (u16, String)> {
    let body = rd
        .take(len, "action list")
        .map_err(|e| (err::BAD_ACTION_BAD_LEN, e.to_string()))?;
    let mut inner = Rd::new(body);
    let mut out = Vec::new();
    while inner.remaining() > 0 {
        if out.len() >= MAX_ACTIONS {
            return Err((
                err::BAD_ACTION_TOO_MANY,
                format!("more than {MAX_ACTIONS} actions in one list"),
            ));
        }
        out.push(Action::parse(&mut inner)?);
    }
    Ok(out)
}

pub fn encode_actions(actions: &[Action]) -> Vec<u8> {
    let mut out = Vec::new();
    for a in actions {
        a.encode(&mut out);
    }
    out
}

pub mod inst {
    pub const GOTO_TABLE: u16 = 1;
    pub const WRITE_METADATA: u16 = 2;
    pub const WRITE_ACTIONS: u16 = 3;
    pub const APPLY_ACTIONS: u16 = 4;
    pub const CLEAR_ACTIONS: u16 = 5;
    pub const METER: u16 = 6;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Instruction {
    GotoTable(u8),
    WriteMetadata { metadata: u64, mask: u64 },
    WriteActions(Vec<Action>),
    ApplyActions(Vec<Action>),
    ClearActions,
    Meter(u32),
    Other { itype: u16, len: usize },
}

impl Instruction {
    pub fn kind(&self) -> u16 {
        match self {
            Instruction::GotoTable(_) => inst::GOTO_TABLE,
            Instruction::WriteMetadata { .. } => inst::WRITE_METADATA,
            Instruction::WriteActions(_) => inst::WRITE_ACTIONS,
            Instruction::ApplyActions(_) => inst::APPLY_ACTIONS,
            Instruction::ClearActions => inst::CLEAR_ACTIONS,
            Instruction::Meter(_) => inst::METER,
            Instruction::Other { itype, .. } => *itype,
        }
    }

    pub fn encode(&self, out: &mut Vec<u8>) {
        let header = |out: &mut Vec<u8>, t: u16, len: usize| {
            out.extend_from_slice(&t.to_be_bytes());
            out.extend_from_slice(&(len as u16).to_be_bytes());
        };
        match self {
            Instruction::GotoTable(t) => {
                header(out, inst::GOTO_TABLE, 8);
                out.extend_from_slice(&[*t, 0, 0, 0]);
            }
            Instruction::WriteMetadata { metadata, mask } => {
                header(out, inst::WRITE_METADATA, 24);
                out.extend_from_slice(&[0; 4]);
                out.extend_from_slice(&metadata.to_be_bytes());
                out.extend_from_slice(&mask.to_be_bytes());
            }
            Instruction::WriteActions(a) | Instruction::ApplyActions(a) => {
                let body = encode_actions(a);
                header(out, self.kind(), 8 + body.len());
                out.extend_from_slice(&[0; 4]);
                out.extend_from_slice(&body);
            }
            Instruction::ClearActions => {
                header(out, inst::CLEAR_ACTIONS, 8);
                out.extend_from_slice(&[0; 4]);
            }
            Instruction::Meter(id) => {
                header(out, inst::METER, 8);
                out.extend_from_slice(&id.to_be_bytes());
            }
            Instruction::Other { .. } => {}
        }
    }

    pub fn parse(rd: &mut Rd) -> Result<Instruction, (u16, u16, String)> {
        let bad = |e: anyhow::Error| {
            (
                err::BAD_INSTRUCTION,
                err::BAD_INSTRUCTION_BAD_LEN,
                e.to_string(),
            )
        };
        let itype = rd.u16("instruction type").map_err(bad)?;
        let len = rd.u16("instruction length").map_err(bad)? as usize;
        if len < 8 || len % 8 != 0 {
            return Err((
                err::BAD_INSTRUCTION,
                err::BAD_INSTRUCTION_BAD_LEN,
                format!("an instruction length of {len}"),
            ));
        }
        let body = rd.take(len - 4, "instruction body").map_err(bad)?;
        let mut b = Rd::new(body);
        let i = match itype {
            inst::GOTO_TABLE => Instruction::GotoTable(b.u8("table_id").map_err(bad)?),
            inst::WRITE_METADATA => {
                b.skip(4, "pad").map_err(bad)?;
                Instruction::WriteMetadata {
                    metadata: b.u64("metadata").map_err(bad)?,
                    mask: b.u64("metadata mask").map_err(bad)?,
                }
            }
            inst::WRITE_ACTIONS | inst::APPLY_ACTIONS => {
                b.skip(4, "pad").map_err(bad)?;
                let n = b.remaining();
                let actions = parse_actions(&mut b, n).map_err(|(c, m)| (err::BAD_ACTION, c, m))?;
                if itype == inst::WRITE_ACTIONS {
                    Instruction::WriteActions(actions)
                } else {
                    Instruction::ApplyActions(actions)
                }
            }
            inst::CLEAR_ACTIONS => Instruction::ClearActions,
            inst::METER => Instruction::Meter(b.u32("meter_id").map_err(bad)?),
            other => Instruction::Other { itype: other, len },
        };
        Ok(i)
    }
}

/// Every instruction in the remaining bytes. Each type may appear once.
pub fn parse_instructions(rd: &mut Rd) -> Result<Vec<Instruction>, (u16, u16, String)> {
    let mut out: Vec<Instruction> = Vec::new();
    while rd.remaining() > 0 {
        if out.len() >= MAX_INSTRUCTIONS {
            return Err((
                err::BAD_INSTRUCTION,
                err::BAD_INSTRUCTION_BAD_LEN,
                format!("more than {MAX_INSTRUCTIONS} instructions"),
            ));
        }
        let i = Instruction::parse(rd)?;
        if out.iter().any(|p| p.kind() == i.kind()) {
            return Err((
                err::BAD_INSTRUCTION,
                err::BAD_INSTRUCTION_UNKNOWN_INST,
                format!("instruction type {} appears twice", i.kind()),
            ));
        }
        out.push(i);
    }
    Ok(out)
}

pub fn encode_instructions(list: &[Instruction]) -> Vec<u8> {
    let mut out = Vec::new();
    for i in list {
        i.encode(&mut out);
    }
    out
}

// ---- PACKET_IN / PACKET_OUT ---------------------------------------------------------------

pub mod packet_in_reason {
    pub const NO_MATCH: u8 = 0;
    pub const ACTION: u8 = 1;
    pub const INVALID_TTL: u8 = 2;
    pub fn name(r: u8) -> &'static str {
        match r {
            NO_MATCH => "no_match",
            ACTION => "action",
            INVALID_TTL => "invalid_ttl",
            _ => "unknown",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketIn {
    pub buffer_id: u32,
    pub total_len: u16,
    pub reason: u8,
    pub table_id: u8,
    pub cookie: u64,
    pub matched: Match,
    pub data: Vec<u8>,
}

impl PacketIn {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + self.data.len());
        out.extend_from_slice(&self.buffer_id.to_be_bytes());
        out.extend_from_slice(&self.total_len.to_be_bytes());
        out.push(self.reason);
        out.push(self.table_id);
        out.extend_from_slice(&self.cookie.to_be_bytes());
        self.matched.encode(&mut out);
        out.extend_from_slice(&[0, 0]);
        out.extend_from_slice(&self.data);
        out
    }

    pub fn parse(body: &[u8]) -> Result<PacketIn> {
        let mut rd = Rd::new(body);
        let buffer_id = rd.u32("buffer_id")?;
        let total_len = rd.u16("total_len")?;
        let reason = rd.u8("reason")?;
        let table_id = rd.u8("table_id")?;
        let cookie = rd.u64("cookie")?;
        let matched = Match::parse(&mut rd).map_err(|(_, m)| anyhow!(m))?;
        rd.skip(2, "pad")?;
        Ok(PacketIn {
            buffer_id,
            total_len,
            reason,
            table_id,
            cookie,
            matched,
            data: rd.rest().to_vec(),
        })
    }

    pub fn in_port(&self) -> Option<u32> {
        self.matched
            .get(fields::IN_PORT)
            .filter(|o| o.value.len() == 4)
            .map(|o| u32::from_be_bytes([o.value[0], o.value[1], o.value[2], o.value[3]]))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketOut {
    pub buffer_id: u32,
    pub in_port: u32,
    pub actions: Vec<Action>,
    pub data: Vec<u8>,
}

impl PacketOut {
    pub fn encode(&self) -> Vec<u8> {
        let actions = encode_actions(&self.actions);
        let mut out = Vec::with_capacity(16 + actions.len() + self.data.len());
        out.extend_from_slice(&self.buffer_id.to_be_bytes());
        out.extend_from_slice(&self.in_port.to_be_bytes());
        out.extend_from_slice(&(actions.len() as u16).to_be_bytes());
        out.extend_from_slice(&[0; 6]);
        out.extend_from_slice(&actions);
        out.extend_from_slice(&self.data);
        out
    }

    pub fn parse(body: &[u8]) -> Result<PacketOut, (u16, u16, String)> {
        let bad = |e: anyhow::Error| (err::BAD_REQUEST, err::BAD_REQUEST_BAD_LEN, e.to_string());
        let mut rd = Rd::new(body);
        let buffer_id = rd.u32("buffer_id").map_err(bad)?;
        let in_port = rd.u32("in_port").map_err(bad)?;
        let actions_len = rd.u16("actions_len").map_err(bad)? as usize;
        rd.skip(6, "pad").map_err(bad)?;
        let actions =
            parse_actions(&mut rd, actions_len).map_err(|(c, m)| (err::BAD_ACTION, c, m))?;
        Ok(PacketOut {
            buffer_id,
            in_port,
            actions,
            data: rd.rest().to_vec(),
        })
    }
}

// ---- FLOW_MOD / FLOW_REMOVED --------------------------------------------------------------

pub mod flow_cmd {
    pub const ADD: u8 = 0;
    pub const MODIFY: u8 = 1;
    pub const MODIFY_STRICT: u8 = 2;
    pub const DELETE: u8 = 3;
    pub const DELETE_STRICT: u8 = 4;
    pub const NAMES: [&str; 5] = ["add", "modify", "modify_strict", "delete", "delete_strict"];
}

pub mod flow_flag {
    pub const ALL: [(&str, u16); 5] = [
        ("send_flow_rem", 1),
        ("check_overlap", 2),
        ("reset_counts", 4),
        ("no_pkt_counts", 8),
        ("no_byt_counts", 16),
    ];
}

pub fn flow_flag_names(bits: u16) -> Vec<&'static str> {
    flow_flag::ALL
        .iter()
        .filter(|(_, b)| bits & b != 0)
        .map(|(n, _)| *n)
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowMod {
    pub cookie: u64,
    pub cookie_mask: u64,
    pub table_id: u8,
    pub command: u8,
    pub idle_timeout: u16,
    pub hard_timeout: u16,
    pub priority: u16,
    pub buffer_id: u32,
    pub out_port: u32,
    pub out_group: u32,
    pub flags: u16,
    pub matched: Match,
    pub instructions: Vec<Instruction>,
}

impl FlowMod {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64);
        out.extend_from_slice(&self.cookie.to_be_bytes());
        out.extend_from_slice(&self.cookie_mask.to_be_bytes());
        out.push(self.table_id);
        out.push(self.command);
        out.extend_from_slice(&self.idle_timeout.to_be_bytes());
        out.extend_from_slice(&self.hard_timeout.to_be_bytes());
        out.extend_from_slice(&self.priority.to_be_bytes());
        out.extend_from_slice(&self.buffer_id.to_be_bytes());
        out.extend_from_slice(&self.out_port.to_be_bytes());
        out.extend_from_slice(&self.out_group.to_be_bytes());
        out.extend_from_slice(&self.flags.to_be_bytes());
        out.extend_from_slice(&[0, 0]);
        self.matched.encode(&mut out);
        out.extend_from_slice(&encode_instructions(&self.instructions));
        out
    }

    /// Parse a FLOW_MOD body; the error carries the ERROR type and code a switch answers.
    pub fn parse(body: &[u8]) -> Result<FlowMod, (u16, u16, String)> {
        let bad = |e: anyhow::Error| (err::BAD_REQUEST, err::BAD_REQUEST_BAD_LEN, e.to_string());
        let mut rd = Rd::new(body);
        let cookie = rd.u64("cookie").map_err(bad)?;
        let cookie_mask = rd.u64("cookie_mask").map_err(bad)?;
        let table_id = rd.u8("table_id").map_err(bad)?;
        let command = rd.u8("command").map_err(bad)?;
        let idle_timeout = rd.u16("idle_timeout").map_err(bad)?;
        let hard_timeout = rd.u16("hard_timeout").map_err(bad)?;
        let priority = rd.u16("priority").map_err(bad)?;
        let buffer_id = rd.u32("buffer_id").map_err(bad)?;
        let out_port = rd.u32("out_port").map_err(bad)?;
        let out_group = rd.u32("out_group").map_err(bad)?;
        let flags = rd.u16("flags").map_err(bad)?;
        rd.skip(2, "pad").map_err(bad)?;
        let matched = Match::parse(&mut rd).map_err(|(c, m)| (err::BAD_MATCH, c, m))?;
        let instructions = parse_instructions(&mut rd)?;
        Ok(FlowMod {
            cookie,
            cookie_mask,
            table_id,
            command,
            idle_timeout,
            hard_timeout,
            priority,
            buffer_id,
            out_port,
            out_group,
            flags,
            matched,
            instructions,
        })
    }
}

pub mod removed_reason {
    pub const NAMES: [&str; 4] = ["idle_timeout", "hard_timeout", "delete", "group_delete"];
    pub fn name(r: u8) -> &'static str {
        NAMES.get(r as usize).copied().unwrap_or("unknown")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowRemoved {
    pub cookie: u64,
    pub priority: u16,
    pub reason: u8,
    pub table_id: u8,
    pub duration_sec: u32,
    pub duration_nsec: u32,
    pub idle_timeout: u16,
    pub hard_timeout: u16,
    pub packet_count: u64,
    pub byte_count: u64,
    pub matched: Match,
}

impl FlowRemoved {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(48);
        out.extend_from_slice(&self.cookie.to_be_bytes());
        out.extend_from_slice(&self.priority.to_be_bytes());
        out.push(self.reason);
        out.push(self.table_id);
        out.extend_from_slice(&self.duration_sec.to_be_bytes());
        out.extend_from_slice(&self.duration_nsec.to_be_bytes());
        out.extend_from_slice(&self.idle_timeout.to_be_bytes());
        out.extend_from_slice(&self.hard_timeout.to_be_bytes());
        out.extend_from_slice(&self.packet_count.to_be_bytes());
        out.extend_from_slice(&self.byte_count.to_be_bytes());
        self.matched.encode(&mut out);
        out
    }

    pub fn parse(body: &[u8]) -> Result<FlowRemoved> {
        let mut rd = Rd::new(body);
        Ok(FlowRemoved {
            cookie: rd.u64("cookie")?,
            priority: rd.u16("priority")?,
            reason: rd.u8("reason")?,
            table_id: rd.u8("table_id")?,
            duration_sec: rd.u32("duration_sec")?,
            duration_nsec: rd.u32("duration_nsec")?,
            idle_timeout: rd.u16("idle_timeout")?,
            hard_timeout: rd.u16("hard_timeout")?,
            packet_count: rd.u64("packet_count")?,
            byte_count: rd.u64("byte_count")?,
            matched: Match::parse(&mut rd).map_err(|(_, m)| anyhow!(m))?,
        })
    }
}

// ---- Multipart -----------------------------------------------------------------------------

pub mod mp {
    pub const DESC: u16 = 0;
    pub const FLOW: u16 = 1;
    pub const AGGREGATE: u16 = 2;
    pub const TABLE: u16 = 3;
    pub const PORT_STATS: u16 = 4;
    pub const QUEUE: u16 = 5;
    pub const GROUP: u16 = 6;
    pub const GROUP_DESC: u16 = 7;
    pub const GROUP_FEATURES: u16 = 8;
    pub const METER: u16 = 9;
    pub const METER_CONFIG: u16 = 10;
    pub const METER_FEATURES: u16 = 11;
    pub const TABLE_FEATURES: u16 = 12;
    pub const PORT_DESC: u16 = 13;
    pub const EXPERIMENTER: u16 = 0xffff;
    /// `OFPMPF_REQ_MORE` / `OFPMPF_REPLY_MORE`.
    pub const MORE: u16 = 1;

    pub fn name(t: u16) -> &'static str {
        match t {
            DESC => "desc",
            FLOW => "flow",
            AGGREGATE => "aggregate",
            TABLE => "table",
            PORT_STATS => "port",
            QUEUE => "queue",
            GROUP => "group",
            GROUP_DESC => "group_desc",
            GROUP_FEATURES => "group_features",
            METER => "meter",
            METER_CONFIG => "meter_config",
            METER_FEATURES => "meter_features",
            TABLE_FEATURES => "table_features",
            PORT_DESC => "port_desc",
            EXPERIMENTER => "experimenter",
            _ => "unknown",
        }
    }
}

pub fn multipart_body(mtype: u16, flags: u16, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + body.len());
    out.extend_from_slice(&mtype.to_be_bytes());
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&[0; 4]);
    out.extend_from_slice(body);
    out
}

/// (type, flags, body) of a multipart request or reply.
pub fn parse_multipart(body: &[u8]) -> Result<(u16, u16, &[u8])> {
    let mut rd = Rd::new(body);
    let mtype = rd.u16("multipart type")?;
    let flags = rd.u16("multipart flags")?;
    rd.skip(4, "pad")?;
    Ok((mtype, flags, rd.rest()))
}

/// The request body for FLOW and AGGREGATE statistics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowStatsRequest {
    pub table_id: u8,
    pub out_port: u32,
    pub out_group: u32,
    pub cookie: u64,
    pub cookie_mask: u64,
    pub matched: Match,
}

impl FlowStatsRequest {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(48);
        out.push(self.table_id);
        out.extend_from_slice(&[0; 3]);
        out.extend_from_slice(&self.out_port.to_be_bytes());
        out.extend_from_slice(&self.out_group.to_be_bytes());
        out.extend_from_slice(&[0; 4]);
        out.extend_from_slice(&self.cookie.to_be_bytes());
        out.extend_from_slice(&self.cookie_mask.to_be_bytes());
        self.matched.encode(&mut out);
        out
    }

    pub fn parse(body: &[u8]) -> Result<FlowStatsRequest, (u16, u16, String)> {
        let bad = |e: anyhow::Error| (err::BAD_REQUEST, err::BAD_REQUEST_BAD_LEN, e.to_string());
        let mut rd = Rd::new(body);
        let table_id = rd.u8("table_id").map_err(bad)?;
        rd.skip(3, "pad").map_err(bad)?;
        let out_port = rd.u32("out_port").map_err(bad)?;
        let out_group = rd.u32("out_group").map_err(bad)?;
        rd.skip(4, "pad").map_err(bad)?;
        let cookie = rd.u64("cookie").map_err(bad)?;
        let cookie_mask = rd.u64("cookie_mask").map_err(bad)?;
        let matched = Match::parse(&mut rd).map_err(|(c, m)| (err::BAD_MATCH, c, m))?;
        Ok(FlowStatsRequest {
            table_id,
            out_port,
            out_group,
            cookie,
            cookie_mask,
            matched,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowStats {
    pub table_id: u8,
    pub duration_sec: u32,
    pub duration_nsec: u32,
    pub priority: u16,
    pub idle_timeout: u16,
    pub hard_timeout: u16,
    pub flags: u16,
    pub cookie: u64,
    pub packet_count: u64,
    pub byte_count: u64,
    pub matched: Match,
    pub instructions: Vec<Instruction>,
}

impl FlowStats {
    pub fn encode(&self, out: &mut Vec<u8>) {
        let mut body = Vec::with_capacity(64);
        body.push(self.table_id);
        body.push(0);
        body.extend_from_slice(&self.duration_sec.to_be_bytes());
        body.extend_from_slice(&self.duration_nsec.to_be_bytes());
        body.extend_from_slice(&self.priority.to_be_bytes());
        body.extend_from_slice(&self.idle_timeout.to_be_bytes());
        body.extend_from_slice(&self.hard_timeout.to_be_bytes());
        body.extend_from_slice(&self.flags.to_be_bytes());
        body.extend_from_slice(&[0; 4]);
        body.extend_from_slice(&self.cookie.to_be_bytes());
        body.extend_from_slice(&self.packet_count.to_be_bytes());
        body.extend_from_slice(&self.byte_count.to_be_bytes());
        self.matched.encode(&mut body);
        body.extend_from_slice(&encode_instructions(&self.instructions));
        out.extend_from_slice(&((body.len() + 2) as u16).to_be_bytes());
        out.extend_from_slice(&body);
    }

    pub fn encoded_len(&self) -> usize {
        let mut v = Vec::new();
        self.encode(&mut v);
        v.len()
    }

    pub fn parse_all(body: &[u8]) -> Result<Vec<FlowStats>> {
        let mut rd = Rd::new(body);
        let mut out = Vec::new();
        while rd.remaining() > 0 {
            ensure!(
                out.len() < MAX_MULTIPART_ENTRIES,
                "more than {MAX_MULTIPART_ENTRIES} flow entries in one part"
            );
            let len = rd.u16("flow stats length")? as usize;
            ensure!(len >= 56, "a flow stats entry of length {len}");
            let entry = rd.take(len - 2, "flow stats entry")?;
            let mut e = Rd::new(entry);
            let table_id = e.u8("table_id")?;
            e.skip(1, "pad")?;
            let duration_sec = e.u32("duration_sec")?;
            let duration_nsec = e.u32("duration_nsec")?;
            let priority = e.u16("priority")?;
            let idle_timeout = e.u16("idle_timeout")?;
            let hard_timeout = e.u16("hard_timeout")?;
            let flags = e.u16("flags")?;
            e.skip(4, "pad")?;
            let cookie = e.u64("cookie")?;
            let packet_count = e.u64("packet_count")?;
            let byte_count = e.u64("byte_count")?;
            let matched = Match::parse(&mut e).map_err(|(_, m)| anyhow!(m))?;
            let instructions = parse_instructions(&mut e).map_err(|(_, _, m)| anyhow!(m))?;
            out.push(FlowStats {
                table_id,
                duration_sec,
                duration_nsec,
                priority,
                idle_timeout,
                hard_timeout,
                flags,
                cookie,
                packet_count,
                byte_count,
                matched,
                instructions,
            });
        }
        Ok(out)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TableStats {
    pub table_id: u8,
    pub active_count: u32,
    pub lookup_count: u64,
    pub matched_count: u64,
}

impl TableStats {
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.push(self.table_id);
        out.extend_from_slice(&[0; 3]);
        out.extend_from_slice(&self.active_count.to_be_bytes());
        out.extend_from_slice(&self.lookup_count.to_be_bytes());
        out.extend_from_slice(&self.matched_count.to_be_bytes());
    }

    pub fn parse_all(body: &[u8]) -> Result<Vec<TableStats>> {
        ensure!(body.len() % 24 == 0, "table stats not in 24-byte entries");
        ensure!(
            body.len() / 24 <= MAX_MULTIPART_ENTRIES,
            "more than {MAX_MULTIPART_ENTRIES} table entries in one part"
        );
        let mut rd = Rd::new(body);
        let mut out = Vec::new();
        while rd.remaining() > 0 {
            let table_id = rd.u8("table_id")?;
            rd.skip(3, "pad")?;
            out.push(TableStats {
                table_id,
                active_count: rd.u32("active_count")?,
                lookup_count: rd.u64("lookup_count")?,
                matched_count: rd.u64("matched_count")?,
            });
        }
        Ok(out)
    }
}

/// `ofp_port_stats`: 112 bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PortStats {
    pub port_no: u32,
    /// rx_packets, tx_packets, rx_bytes, tx_bytes, rx_dropped, tx_dropped, rx_errors,
    /// tx_errors, rx_frame_err, rx_over_err, rx_crc_err, collisions.
    pub counters: [u64; 12],
    pub duration_sec: u32,
    pub duration_nsec: u32,
}

pub const PORT_STATS_COUNTERS: [&str; 12] = [
    "rx_packets",
    "tx_packets",
    "rx_bytes",
    "tx_bytes",
    "rx_dropped",
    "tx_dropped",
    "rx_errors",
    "tx_errors",
    "rx_frame_err",
    "rx_over_err",
    "rx_crc_err",
    "collisions",
];

impl PortStats {
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.port_no.to_be_bytes());
        out.extend_from_slice(&[0; 4]);
        for c in self.counters {
            out.extend_from_slice(&c.to_be_bytes());
        }
        out.extend_from_slice(&self.duration_sec.to_be_bytes());
        out.extend_from_slice(&self.duration_nsec.to_be_bytes());
    }

    pub fn parse_all(body: &[u8]) -> Result<Vec<PortStats>> {
        ensure!(body.len() % 112 == 0, "port stats not in 112-byte entries");
        ensure!(
            body.len() / 112 <= MAX_MULTIPART_ENTRIES,
            "more than {MAX_MULTIPART_ENTRIES} port entries in one part"
        );
        let mut rd = Rd::new(body);
        let mut out = Vec::new();
        while rd.remaining() > 0 {
            let port_no = rd.u32("port_no")?;
            rd.skip(4, "pad")?;
            let mut counters = [0u64; 12];
            for c in counters.iter_mut() {
                *c = rd.u64("counter")?;
            }
            out.push(PortStats {
                port_no,
                counters,
                duration_sec: rd.u32("duration_sec")?,
                duration_nsec: rd.u32("duration_nsec")?,
            });
        }
        Ok(out)
    }
}

pub fn parse_ports(body: &[u8]) -> Result<Vec<Port>> {
    ensure!(
        body.len() % PORT_LEN == 0,
        "port descriptions not in 64-byte entries"
    );
    ensure!(
        body.len() / PORT_LEN <= MAX_MULTIPART_ENTRIES,
        "more than {MAX_MULTIPART_ENTRIES} ports in one part"
    );
    let mut rd = Rd::new(body);
    let mut out = Vec::new();
    while rd.remaining() > 0 {
        out.push(Port::parse(&mut rd)?);
    }
    Ok(out)
}

/// `ofp_desc`: five fixed-width strings.
pub const DESC_FIELDS: [(&str, usize); 5] = [
    ("mfr_desc", 256),
    ("hw_desc", 256),
    ("sw_desc", 256),
    ("serial_num", 32),
    ("dp_desc", 256),
];

pub fn desc_body(values: [&str; 5]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1056);
    for ((_, width), v) in DESC_FIELDS.iter().zip(values) {
        let mut field = vec![0u8; *width];
        let b = v.as_bytes();
        let n = b.len().min(width - 1);
        field[..n].copy_from_slice(&b[..n]);
        out.extend_from_slice(&field);
    }
    out
}

pub fn parse_desc(body: &[u8]) -> Result<Vec<(&'static str, String)>> {
    let mut rd = Rd::new(body);
    let mut out = Vec::new();
    for (name, width) in DESC_FIELDS {
        let raw = rd.take(width, name)?;
        let end = raw.iter().position(|b| *b == 0).unwrap_or(raw.len());
        out.push((
            name,
            crate::utils::sanitize::line_field(&String::from_utf8_lossy(&raw[..end])),
        ));
    }
    Ok(out)
}

/// AGGREGATE reply: packet_count, byte_count, flow_count.
pub fn parse_aggregate(body: &[u8]) -> Result<(u64, u64, u32)> {
    let mut rd = Rd::new(body);
    Ok((
        rd.u64("packet_count")?,
        rd.u64("byte_count")?,
        rd.u32("flow_count")?,
    ))
}

pub fn aggregate_body(packets: u64, bytes: u64, flows: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(24);
    out.extend_from_slice(&packets.to_be_bytes());
    out.extend_from_slice(&bytes.to_be_bytes());
    out.extend_from_slice(&flows.to_be_bytes());
    out.extend_from_slice(&[0; 4]);
    out
}

/// Field ids of the basic OXM class this crate refers to by name.
pub mod fields {
    pub const IN_PORT: u8 = 0;
    pub const IN_PHY_PORT: u8 = 1;
    pub const ETH_TYPE: u8 = 5;
    pub const VLAN_VID: u8 = 6;
}

/// A message's type, refused with `BAD_REQUEST/BAD_TYPE` by anything that does not handle it.
pub fn bad_type(m: &Message) -> Vec<u8> {
    error_body(err::BAD_REQUEST, err::BAD_REQUEST_BAD_TYPE, &m.raw())
}

/// Shorthand used by both roles: a protocol error with the offending message.
pub fn protocol_error(etype: u16, code: u16, m: &Message) -> Vec<u8> {
    error_body(etype, code, &m.raw())
}

/// Refuse anything that is not a message of the negotiated version.
pub fn check_version(m: &Message, version: u8) -> Result<()> {
    if m.header.version != version {
        bail!(
            "a {} of wire version {} on a {} connection",
            msg_name(m.header.msg_type),
            m.header.version,
            version_name(version)
        );
    }
    Ok(())
}

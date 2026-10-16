//! DSI — the Data Stream Interface that carries AFP over TCP (AFP 3.x reference, "AFP over
//! TCP"). Every message is a 16-byte header followed by `length` bytes:
//!
//! ```text
//! flags(1) command(1) request_id(2) error_code_or_write_offset(4) length(4) reserved(4)
//! ```
//!
//! `flags` is 0 for a request and 1 for a reply. A reply carries the request's id and the AFP
//! result code in the 4-byte field; a `DSIWrite` request uses the same field for the length of
//! the AFP command that precedes the data to write. Pure functions, shared by the server and
//! the client and fuzzed without a socket (`fuzz/fuzz_targets/afp_dsi.rs`).
use anyhow::{bail, Result};

/// The header every DSI message starts with.
pub const HEADER_LEN: usize = 16;

/// `flags`.
pub const FLAG_REQUEST: u8 = 0x00;
pub const FLAG_REPLY: u8 = 0x01;

/// `command`.
pub mod command {
    pub const CLOSE_SESSION: u8 = 1;
    pub const COMMAND: u8 = 2;
    pub const GET_STATUS: u8 = 3;
    pub const OPEN_SESSION: u8 = 4;
    pub const TICKLE: u8 = 5;
    pub const WRITE: u8 = 6;
    pub const ATTENTION: u8 = 8;
}

/// DSIOpenSession option types.
pub mod option {
    /// Server to client: the largest request the server accepts (4 bytes).
    pub const SERVER_REQUEST_QUANTUM: u8 = 0x00;
    /// Client to server: the largest attention the client accepts (4 bytes).
    pub const ATTENTION_QUANTUM: u8 = 0x01;
    /// Server to client: replay cache size (4 bytes).
    pub const SERVER_REPLAY_CACHE_SIZE: u8 = 0x02;
}

/// The request quantum NetGet advertises: the most AFP data one request may carry (a write's
/// data), and the most one reply carries (a read's data). 128 KiB: a client splits larger
/// writes into several, and every write's data reaches the model, so one chunk stays small.
pub const REQUEST_QUANTUM: u32 = 128 * 1024;

/// The longest AFP command block (everything before a write's data) NetGet reads. netatalk
/// uses the same 8 KiB (`DSI_CMDSIZ`); no AFP command NetGet implements comes near it.
pub const MAX_COMMAND_LEN: usize = 8 * 1024;

/// The most bytes one DSI message may declare: a command block plus a quantum of data. Larger
/// is refused before a byte of the payload is read.
pub const MAX_PAYLOAD_LEN: usize = MAX_COMMAND_LEN + REQUEST_QUANTUM as usize;

/// The largest whole message: header plus [`MAX_PAYLOAD_LEN`].
pub const MAX_MESSAGE_LEN: usize = HEADER_LEN + MAX_PAYLOAD_LEN;

/// One DSI header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub flags: u8,
    pub command: u8,
    pub request_id: u16,
    /// The AFP result code of a reply, or a `DSIWrite` request's command length.
    pub code: u32,
    pub length: u32,
    pub reserved: u32,
}

impl Header {
    pub fn parse(b: &[u8; HEADER_LEN]) -> Header {
        Header {
            flags: b[0],
            command: b[1],
            request_id: u16::from_be_bytes([b[2], b[3]]),
            code: u32::from_be_bytes([b[4], b[5], b[6], b[7]]),
            length: u32::from_be_bytes([b[8], b[9], b[10], b[11]]),
            reserved: u32::from_be_bytes([b[12], b[13], b[14], b[15]]),
        }
    }

    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let mut b = [0u8; HEADER_LEN];
        b[0] = self.flags;
        b[1] = self.command;
        b[2..4].copy_from_slice(&self.request_id.to_be_bytes());
        b[4..8].copy_from_slice(&self.code.to_be_bytes());
        b[8..12].copy_from_slice(&self.length.to_be_bytes());
        b[12..16].copy_from_slice(&self.reserved.to_be_bytes());
        b
    }

    /// The AFP result code a reply carries, as the signed number the spec names (-5000 …).
    pub fn result(&self) -> i32 {
        self.code as i32
    }

    /// Whether the declared payload is one NetGet will read.
    pub fn check_length(&self) -> Result<usize> {
        let len = self.length as usize;
        if len > MAX_PAYLOAD_LEN {
            bail!(
                "DSI {} declares {len} payload bytes; the most one message may carry is \
                 {MAX_PAYLOAD_LEN}",
                command_name(self.command)
            );
        }
        Ok(len)
    }
}

pub fn command_name(c: u8) -> &'static str {
    match c {
        command::CLOSE_SESSION => "DSICloseSession",
        command::COMMAND => "DSICommand",
        command::GET_STATUS => "DSIGetStatus",
        command::OPEN_SESSION => "DSIOpenSession",
        command::TICKLE => "DSITickle",
        command::WRITE => "DSIWrite",
        command::ATTENTION => "DSIAttention",
        _ => "unknown DSI command",
    }
}

/// A whole message: header with `length` set to the payload's, then the payload.
pub fn message(flags: u8, command: u8, request_id: u16, code: u32, payload: &[u8]) -> Vec<u8> {
    let header = Header {
        flags,
        command,
        request_id,
        code,
        length: payload.len() as u32,
        reserved: 0,
    };
    let mut out = Vec::with_capacity(HEADER_LEN + payload.len());
    out.extend_from_slice(&header.encode());
    out.extend_from_slice(payload);
    out
}

/// A reply to `request` carrying `result` (an AFP code, 0 for success) and `payload`.
pub fn reply(request: &Header, result: i32, payload: &[u8]) -> Vec<u8> {
    message(
        FLAG_REPLY,
        request.command,
        request.request_id,
        result as u32,
        payload,
    )
}

/// A DSIWrite request's split: the AFP command block and the data after it.
pub fn split_write(header: &Header, payload: &[u8]) -> Result<(usize, usize)> {
    let cmd_len = header.code as usize;
    if cmd_len > payload.len() {
        bail!(
            "DSIWrite says its command is {cmd_len} bytes but the message carries only {}",
            payload.len()
        );
    }
    if cmd_len > MAX_COMMAND_LEN {
        bail!("DSIWrite command block of {cmd_len} bytes exceeds {MAX_COMMAND_LEN}");
    }
    Ok((cmd_len, payload.len() - cmd_len))
}

/// DSIOpenSession options: `(type, value)` pairs, each `type(1) length(1) value`.
pub fn parse_options(payload: &[u8]) -> Result<Vec<(u8, Vec<u8>)>> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < payload.len() {
        if out.len() >= 16 {
            bail!("more than 16 DSIOpenSession options");
        }
        if i + 2 > payload.len() {
            bail!("a DSIOpenSession option is cut short");
        }
        let kind = payload[i];
        let len = payload[i + 1] as usize;
        let start = i + 2;
        if start + len > payload.len() {
            bail!("DSIOpenSession option {kind:#04x} declares {len} bytes past the end");
        }
        out.push((kind, payload[start..start + len].to_vec()));
        i = start + len;
    }
    Ok(out)
}

/// Encode DSIOpenSession options.
pub fn encode_options(options: &[(u8, Vec<u8>)]) -> Vec<u8> {
    let mut out = Vec::new();
    for (kind, value) in options {
        out.push(*kind);
        out.push(value.len().min(255) as u8);
        out.extend_from_slice(&value[..value.len().min(255)]);
    }
    out
}

/// The 4-byte value of a quantum option, when present and well formed.
pub fn quantum_option(options: &[(u8, Vec<u8>)], kind: u8) -> Option<u32> {
    options.iter().find_map(|(k, v)| {
        (*k == kind && v.len() == 4).then(|| u32::from_be_bytes([v[0], v[1], v[2], v[3]]))
    })
}

//! DRDA / DDM wire codec for the Db2 server.
//!
//! DRDA (Distributed Relational Database Architecture) frames every message in a
//! **DSS** (Data Stream Structure) envelope carrying one or more **DDM**
//! (Distributed Data Management) objects. There is essentially no maintained Rust
//! crate for the server side of DRDA, so this is hand-rolled against the public
//! DRDA specification (the same code points Apache Derby's `org.apache.derby.impl.drda`
//! and IBM's Db2 documentation use).
//!
//! ## DSS envelope (6-byte header)
//!
//! ```text
//! +--------+--------+--------+--------+--------+--------+
//! | length (u16 BE) | 0xD0   | format | correlator (u16)|
//! +--------+--------+--------+--------+--------+--------+
//! ```
//! `length` counts the whole DSS including the header. `0xD0` is the DDM magic.
//! `format` low nibble is the DSS type (1=RQSDSS request, 2=RPYDSS reply,
//! 3=OBJDSS object); the high nibble carries chaining flags. `correlator` ties a
//! reply to its request.
//!
//! ## DDM object (4-byte header)
//!
//! ```text
//! +--------+--------+--------+--------+ ...
//! | length (u16 BE) | code point (u16) | data (length-4 bytes)
//! +--------+--------+--------+--------+ ...
//! ```
//! The `data` region may itself be a sequence of nested code-pointed objects
//! (parameters).
//!
//! ## What this codec covers
//!
//! Enough of the object layer for the connection handshake
//! (EXCSAT/ACCSEC/SECCHK/ACCRDB) and the `EXCSQLIMM` → `SQLCARD` basic-query path.
//! DDM character fields (user id, RDB name) are IBM037 EBCDIC, decoded best-effort
//! here; SQL text is FD:OCA data in the requester's declared CCSID (`decode_sqlstt`).
//! See `mod.rs`/`AGENTS.md` for what is deliberately not implemented (SELECT
//! result-set retrieval: OPNQRY/QRYDSC/QRYDTA).

/// DDM magic byte that opens every DSS.
pub const DSS_MAGIC: u8 = 0xD0;

/// DSS format low-nibble types.
pub const DSSFMT_RQSDSS: u8 = 0x01;
pub const DSSFMT_RPYDSS: u8 = 0x02;
pub const DSSFMT_OBJDSS: u8 = 0x03;

/// DRDA/DDM code points used by the handshake and basic query path.
pub mod cp {
    // Commands (RQSDSS)
    pub const EXCSAT: u16 = 0x1041; // Exchange Server Attributes
    pub const ACCSEC: u16 = 0x106D; // Access Security
    pub const SECCHK: u16 = 0x106E; // Security Check
    pub const ACCRDB: u16 = 0x2001; // Access RDB
    pub const EXCSQLIMM: u16 = 0x200A; // Execute Immediate SQL
    pub const EXCSQLSTT: u16 = 0x200B; // Execute SQL Statement
    pub const EXCSQLSET: u16 = 0x2014; // Set SQL environment (special registers)
    pub const RDBCMM: u16 = 0x200E; // Commit unit of work
    pub const RDBRLLBCK: u16 = 0x200F; // Roll back unit of work

    // Reply objects / messages (RPYDSS / OBJDSS)
    pub const EXCSATRD: u16 = 0x1443; // EXCSAT reply data
    pub const ACCSECRD: u16 = 0x14AC; // Access Security reply data
    pub const SECCHKRM: u16 = 0x1219; // Security Check reply message
    pub const ACCRDBRM: u16 = 0x2201; // Access RDB reply message
    pub const SQLCARD: u16 = 0x2408; // SQL Communications Area Reply Data
    pub const CMDNSPRM: u16 = 0x1250; // Command Not Supported reply message
    pub const ENDUOWRM: u16 = 0x220C; // End unit of work reply message
    pub const RDBATHRM: u16 = 0x22CB; // Not authorized to RDB reply message

    // Scalar parameters
    pub const EXTNAM: u16 = 0x115E; // External name
    pub const SRVNAM: u16 = 0x116D; // Server name
    pub const SRVRLSLV: u16 = 0x115A; // Server product release level
    pub const SRVCLSNM: u16 = 0x1147; // Server class name
    pub const MGRLVLLS: u16 = 0x1404; // Manager-level list
    pub const SECMEC: u16 = 0x11A2; // Security mechanism
    pub const SECCHKCD: u16 = 0x11A4; // Security-check code
    pub const SVRCOD: u16 = 0x1149; // Severity code
    pub const RDBNAM: u16 = 0x2110; // Relational database name
    pub const USRID: u16 = 0x11A0; // User id
    pub const PASSWORD: u16 = 0x11A1; // Password
    pub const PRDID: u16 = 0x112E; // Product-specific identifier
    pub const TYPDEFNAM: u16 = 0x002F; // Data-type-definition name
    pub const TYPDEFOVR: u16 = 0x0035; // TYPDEF overrides
    pub const SQLSTT: u16 = 0x2414; // SQL statement
    pub const SQLSTTGRP: u16 = 0x2214; // SQL statement group (mixed/single byte)
    pub const UOWDSP: u16 = 0x2115; // Unit of work disposition
    pub const CCSIDSBC: u16 = 0x119C; // CCSID of single-byte characters
    pub const CCSIDMBC: u16 = 0x119E; // CCSID of mixed-byte characters
}

/// SVRCOD severity levels.
pub mod svrcod {
    pub const INFO: u16 = 0;
    pub const WARNING: u16 = 4;
    pub const ERROR: u16 = 8;
    pub const SEVERE: u16 = 16;
}

/// SECCHKCD security-check outcome codes (subset).
pub mod secchkcd {
    pub const SUCCESS: u8 = 0x00; // authentication succeeded
    pub const PASSWORD_INVALID: u8 = 0x0F; // userid known, password invalid
    pub const USERID_MISSING: u8 = 0x12; // userid missing
    pub const USERID_UNKNOWN: u8 = 0x10; // userid not known
}

/// Encode a DDM object: `length(u16) | codepoint(u16) | data`.
pub fn encode_object(codepoint: u16, data: &[u8]) -> Vec<u8> {
    let len = (data.len() + 4) as u16;
    let mut out = Vec::with_capacity(data.len() + 4);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&codepoint.to_be_bytes());
    out.extend_from_slice(data);
    out
}

/// Encode a scalar parameter (same wire shape as an object).
pub fn encode_scalar(codepoint: u16, data: &[u8]) -> Vec<u8> {
    encode_object(codepoint, data)
}

/// Encode a scalar parameter whose value is EBCDIC-encoded ASCII text.
pub fn encode_scalar_str(codepoint: u16, text: &str) -> Vec<u8> {
    encode_object(codepoint, &ascii_to_ebcdic(text))
}

/// Wrap a DDM object (or concatenation of them) in a DSS envelope.
///
/// * `dss_type` — one of `DSSFMT_RQSDSS` / `DSSFMT_RPYDSS` / `DSSFMT_OBJDSS`.
/// * `chained` — set the "chained, same correlator" flags (0x40 | 0x10) so the
///   peer expects another DSS with the same correlator to follow.
pub fn encode_dss(dss_type: u8, chained: bool, correlator: u16, ddm: &[u8]) -> Vec<u8> {
    let total = (ddm.len() + 6) as u16;
    let format = if chained {
        // 0x40 = DSSCHAIN (chained to next), 0x10 = next DSS has same correlator.
        0x40 | 0x10 | (dss_type & 0x0F)
    } else {
        dss_type & 0x0F
    };
    let mut out = Vec::with_capacity(ddm.len() + 6);
    out.extend_from_slice(&total.to_be_bytes());
    out.push(DSS_MAGIC);
    out.push(format);
    out.extend_from_slice(&correlator.to_be_bytes());
    out.extend_from_slice(ddm);
    out
}

/// A parsed DSS carrying its top-level DDM command/object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedDss {
    /// Raw format byte (chaining flags + DSS type).
    pub format: u8,
    /// Low nibble of `format`: the DSS type.
    pub dss_type: u8,
    /// Request/reply correlator.
    pub correlator: u16,
    /// Top-level DDM code point (the command, e.g. EXCSAT).
    pub codepoint: u16,
    /// The top-level object's data region (nested parameters live here).
    pub body: Vec<u8>,
}

/// Errors the DRDA parser can produce. All are recoverable at the connection
/// level (the server logs and drops the connection) — none panic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DrdaError {
    /// Fewer bytes than a DSS/DDM header requires.
    Truncated,
    /// The DDM magic byte (0xD0) was not where a DSS header requires it.
    BadMagic(u8),
    /// A declared length field was impossible (smaller than its own header).
    BadLength(u16),
}

impl std::fmt::Display for DrdaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DrdaError::Truncated => write!(f, "truncated DRDA frame"),
            DrdaError::BadMagic(b) => write!(f, "bad DDM magic 0x{:02X} (expected 0xD0)", b),
            DrdaError::BadLength(l) => write!(f, "impossible DRDA length {}", l),
        }
    }
}

impl std::error::Error for DrdaError {}

/// The declared total length of the DSS at the front of `buf`, if the 2-byte
/// length prefix is present. Used by the read loop to know how many bytes make a
/// full frame before parsing it.
pub fn dss_declared_len(buf: &[u8]) -> Option<usize> {
    if buf.len() < 2 {
        return None;
    }
    Some(u16::from_be_bytes([buf[0], buf[1]]) as usize)
}

/// Parse a single DSS from the front of `buf`, returning the parsed command and
/// the number of bytes consumed.
pub fn parse_dss(buf: &[u8]) -> Result<(ParsedDss, usize), DrdaError> {
    if buf.len() < 6 {
        return Err(DrdaError::Truncated);
    }
    let total = u16::from_be_bytes([buf[0], buf[1]]) as usize;
    if total < 6 {
        return Err(DrdaError::BadLength(total as u16));
    }
    if buf[2] != DSS_MAGIC {
        return Err(DrdaError::BadMagic(buf[2]));
    }
    let format = buf[3];
    let correlator = u16::from_be_bytes([buf[4], buf[5]]);
    if buf.len() < total {
        return Err(DrdaError::Truncated);
    }
    let ddm = &buf[6..total];
    // Top-level DDM object header.
    if ddm.len() < 4 {
        return Err(DrdaError::Truncated);
    }
    let obj_len = u16::from_be_bytes([ddm[0], ddm[1]]) as usize;
    if obj_len < 4 {
        return Err(DrdaError::BadLength(obj_len as u16));
    }
    let codepoint = u16::from_be_bytes([ddm[2], ddm[3]]);
    let end = obj_len.min(ddm.len());
    let body = ddm[4..end].to_vec();
    Ok((
        ParsedDss {
            format,
            dss_type: format & 0x0F,
            correlator,
            codepoint,
            body,
        },
        total,
    ))
}

/// Parse a flat list of code-pointed parameters from an object body.
///
/// Stops at the first malformed length rather than looping forever. Nested groups
/// are returned as raw bytes (the caller descends into the ones it cares about).
pub fn parse_params(body: &[u8]) -> Vec<(u16, Vec<u8>)> {
    let mut out = Vec::new();
    let mut i = 0;
    while i + 4 <= body.len() {
        let len = u16::from_be_bytes([body[i], body[i + 1]]) as usize;
        let cp = u16::from_be_bytes([body[i + 2], body[i + 3]]);
        if len < 4 || i + len > body.len() {
            break;
        }
        out.push((cp, body[i + 4..i + len].to_vec()));
        i += len;
    }
    out
}

/// Find the first parameter with `codepoint` in an object body.
pub fn find_param(body: &[u8], codepoint: u16) -> Option<Vec<u8>> {
    parse_params(body)
        .into_iter()
        .find(|(cp, _)| *cp == codepoint)
        .map(|(_, v)| v)
}

// ============================================================================
// SQLCARD (SQL Communications Area Reply Data)
// ============================================================================

/// A success SQLCARD: an SQLCAGRP with the FDOCA NULL indicator (0xFF), which the
/// driver reads as SQLCODE 0. This is the complete reply a real Db2 server sends
/// after a successful `EXCSQLIMM` of a non-query statement.
pub fn sqlcard_success() -> Vec<u8> {
    encode_object(cp::SQLCARD, &[0xFF])
}

/// An error/warning SQLCARD: SQLCODE and SQLSTATE in a complete SQLAM 7 SQLCA.
pub fn sqlcard_error(sqlcode: i32, sqlstate: &str) -> Vec<u8> {
    sqlcard(sqlcode, sqlstate, 0)
}

/// A complete SQLAM 7 SQLCARD: the SQLCAGRP with its SQLCAXGRP present (so SQLERRD3 can
/// carry the rows a statement affected) and its SQLDIAGGRP null. Character fields are in
/// the single-byte CCSID ACCRDBRM declares (UTF-8, so plain ASCII here). Byte layout:
///
/// ```text
/// 0x00                       SQLCAGRP present
/// SQLCODE    i32 BE          4 bytes
/// SQLSTATE   5 chars         padded with blanks
/// SQLERRPROC 8 chars         "NETGET  "
/// 0x00                       SQLCAXGRP present
///   SQLERRD1..6  6 x i32     SQLERRD3 = rows affected, the rest 0
///   SQLWARN0..A  11 chars    blanks
///   SQLRDBNAME   u16 0       empty VCS
///   SQLERRMSG_m  u16 0       empty VCM
///   SQLERRMSG_s  u16 0       empty VCS
/// 0xFF                       SQLDIAGGRP null
/// ```
///
/// SQLDIAGGRP's null indicator is not optional at SQLAM 7: a driver reads it after the
/// SQLCAXGRP whether or not anything is in it.
pub fn sqlcard(sqlcode: i32, sqlstate: &str, rows: i32) -> Vec<u8> {
    let mut data = Vec::with_capacity(64);
    data.push(0x00);
    data.extend_from_slice(&sqlcode.to_be_bytes());
    let mut state = [b' '; 5];
    for (i, b) in sqlstate
        .bytes()
        .filter(u8::is_ascii_alphanumeric)
        .take(5)
        .enumerate()
    {
        state[i] = b;
    }
    data.extend_from_slice(&state);
    data.extend_from_slice(b"NETGET  ");
    data.push(0x00);
    for errd in [0, 0, rows, 0, 0, 0] {
        data.extend_from_slice(&errd.to_be_bytes());
    }
    data.extend_from_slice(&[b' '; 11]);
    data.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    data.push(0xFF);
    encode_object(cp::SQLCARD, &data)
}

/// Set the chaining flags of a reply to one request DSS.
///
/// DRDA replies to a request chain with a reply chain: every reply DSS but the very last one
/// of the chain says "chained", and says "same correlator" when the next reply DSS carries the
/// same correlator. `reply` holds the DSSes answering one request; `request_chained` is that
/// request's own chained flag, which says whether more replies follow after these. A driver
/// that sends EXCSAT chained to ACCSEC rejects an unchained EXCSATRD as a syntax error.
pub fn chain_reply(mut reply: Vec<u8>, request_chained: bool) -> Vec<u8> {
    let mut starts = Vec::new();
    let mut pos = 0;
    while pos + 6 <= reply.len() {
        let len = u16::from_be_bytes([reply[pos], reply[pos + 1]]) as usize;
        if len < 6 || len & 0x8000 != 0 || pos + len > reply.len() {
            return reply;
        }
        starts.push(pos);
        pos += len;
    }
    for (i, &at) in starts.iter().enumerate() {
        let next = starts.get(i + 1);
        let chained = next.is_some() || request_chained;
        let same = next.is_some_and(|&n| reply[n + 4..n + 6] == reply[at + 4..at + 6]);
        let mut format = reply[at + 3] & 0x0F;
        if chained {
            format |= 0x40;
            if same {
                format |= 0x10;
            }
        }
        reply[at + 3] = format;
    }
    reply
}

/// The SQL text in an SQLSTT body.
///
/// DRDA carries it as FD:OCA data: a nullable mixed-character string with a 4-byte length
/// (`0x00 | len | bytes`), then a nullable single-byte one, of which one is null. The text is
/// in the CCSID the requester declared, which every driver here declares as UTF-8. A body
/// that is not shaped like that is read as bare EBCDIC, the encoding this server's own
/// byte-literal tests use.
pub fn decode_sqlstt(body: &[u8]) -> String {
    let field = |b: &[u8]| -> Option<(Option<Vec<u8>>, usize)> {
        match b.first()? {
            0xFF => Some((None, 1)),
            0x00 if b.len() >= 5 => {
                let n = u32::from_be_bytes([b[1], b[2], b[3], b[4]]) as usize;
                let end = 5usize.checked_add(n)?;
                (end <= b.len()).then(|| (Some(b[5..end].to_vec()), end))
            }
            _ => None,
        }
    };
    if let Some((mixed, used)) = field(body) {
        let single = field(&body[used..]);
        if let Some((single, used2)) = single {
            if used + used2 == body.len() {
                if let Some(text) = mixed.or(single) {
                    return String::from_utf8_lossy(&text).trim_end().to_string();
                }
            }
        }
    }
    ebcdic_to_ascii(body)
}

// ============================================================================
// IBM037 (CP037) EBCDIC <-> ASCII, range-based for the printable set.
// ============================================================================

/// Convert one ASCII byte to its IBM037 EBCDIC equivalent. Characters outside the
/// mapped printable set become 0x6F (EBCDIC '?').
pub fn ascii_byte_to_ebcdic(c: u8) -> u8 {
    match c {
        b'A'..=b'I' => 0xC1 + (c - b'A'),
        b'J'..=b'R' => 0xD1 + (c - b'J'),
        b'S'..=b'Z' => 0xE2 + (c - b'S'),
        b'a'..=b'i' => 0x81 + (c - b'a'),
        b'j'..=b'r' => 0x91 + (c - b'j'),
        b's'..=b'z' => 0xA2 + (c - b's'),
        b'0'..=b'9' => 0xF0 + (c - b'0'),
        b' ' => 0x40,
        b'.' => 0x4B,
        b'<' => 0x4C,
        b'(' => 0x4D,
        b'+' => 0x4E,
        b'|' => 0x4F,
        b'&' => 0x50,
        b'!' => 0x5A,
        b'$' => 0x5B,
        b'*' => 0x5C,
        b')' => 0x5D,
        b';' => 0x5E,
        b'-' => 0x60,
        b'/' => 0x61,
        b',' => 0x6B,
        b'%' => 0x6C,
        b'_' => 0x6D,
        b'>' => 0x6E,
        b'?' => 0x6F,
        b'`' => 0x79,
        b':' => 0x7A,
        b'#' => 0x7B,
        b'@' => 0x7C,
        b'\'' => 0x7D,
        b'=' => 0x7E,
        b'"' => 0x7F,
        b'~' => 0xA1,
        b'[' => 0xBA,
        b']' => 0xBB,
        b'{' => 0xC0,
        b'}' => 0xD0,
        b'\\' => 0xE0,
        b'^' => 0xB0,
        _ => 0x6F,
    }
}

/// Convert one IBM037 EBCDIC byte to ASCII. Unmapped bytes become b'?'.
pub fn ebcdic_byte_to_ascii(e: u8) -> u8 {
    match e {
        0xC1..=0xC9 => b'A' + (e - 0xC1),
        0xD1..=0xD9 => b'J' + (e - 0xD1),
        0xE2..=0xE9 => b'S' + (e - 0xE2),
        0x81..=0x89 => b'a' + (e - 0x81),
        0x91..=0x99 => b'j' + (e - 0x91),
        0xA2..=0xA9 => b's' + (e - 0xA2),
        0xF0..=0xF9 => b'0' + (e - 0xF0),
        0x40 => b' ',
        0x4B => b'.',
        0x4C => b'<',
        0x4D => b'(',
        0x4E => b'+',
        0x4F => b'|',
        0x50 => b'&',
        0x5A => b'!',
        0x5B => b'$',
        0x5C => b'*',
        0x5D => b')',
        0x5E => b';',
        0x60 => b'-',
        0x61 => b'/',
        0x6B => b',',
        0x6C => b'%',
        0x6D => b'_',
        0x6E => b'>',
        0x6F => b'?',
        0x79 => b'`',
        0x7A => b':',
        0x7B => b'#',
        0x7C => b'@',
        0x7D => b'\'',
        0x7E => b'=',
        0x7F => b'"',
        0xA1 => b'~',
        0xBA => b'[',
        0xBB => b']',
        0xC0 => b'{',
        0xD0 => b'}',
        0xE0 => b'\\',
        0xB0 => b'^',
        _ => b'?',
    }
}

/// EBCDIC-encode an ASCII string.
pub fn ascii_to_ebcdic(s: &str) -> Vec<u8> {
    s.bytes().map(ascii_byte_to_ebcdic).collect()
}

/// EBCDIC-encode a byte slice already known to be ASCII.
pub fn ascii_to_ebcdic_bytes(b: &[u8]) -> Vec<u8> {
    b.iter().map(|&c| ascii_byte_to_ebcdic(c)).collect()
}

/// Decode EBCDIC bytes to an ASCII string, trimming trailing spaces.
pub fn ebcdic_to_ascii(bytes: &[u8]) -> String {
    let s: String = bytes
        .iter()
        .map(|&e| ebcdic_byte_to_ascii(e) as char)
        .collect();
    s.trim_end().to_string()
}

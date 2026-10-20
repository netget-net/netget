//! NVMe/TCP PDU framing (NVMe/TCP Transport Specification 1.0, §3.6): the 8-byte common header
//! (type, flags, HLEN, PDO, PLEN), the PDU-specific header, the optional CRC32C header digest,
//! padding up to the data offset the receiver's alignment asks for, the data, and the optional
//! CRC32C data digest. Shared by the target and the host (`src/client/nvme_tcp`).
//!
//! Every length here comes from the peer, so [`check_header`] decides a PDU from its eight-byte
//! common header — type, HLEN, PDO, PLEN and the digest flags against what was negotiated, and
//! the data length against the bound for that PDU type — before anything is read or allocated
//! for the rest. A PDU that fails it is a fatal transport error with the Fatal Error Status the
//! specification names, answered with a TermReq and the connection closed.
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt};

/// The common header every PDU starts with.
pub const CH_LEN: usize = 8;
/// ICReq and ICResp are 128 bytes, header only.
pub const IC_LEN: usize = 128;
/// The capsule command header: common header plus a 64-byte submission queue entry.
pub const CAPSULE_CMD_HLEN: usize = 72;
/// Every other PDU header (CapsuleResp, H2CData, C2HData, R2T, TermReq) is 24 bytes.
pub const SHORT_HLEN: usize = 24;
/// A TermReq carries at most 128 bytes of the PDU header that caused it (PLEN ≤ 152).
pub const TERM_REQ_MAX_DATA: usize = 128;
/// The largest padding a PDU data alignment of (31 + 1) × 4 bytes can call for.
pub const MAX_PAD: usize = 128;
/// The data digest and header digest are four bytes each.
pub const DIGEST_LEN: usize = 4;

/// PDU types (§3.6.1). Host to controller: ICReq, H2CTermReq, CapsuleCmd, H2CData; controller
/// to host: ICResp, C2HTermReq, CapsuleResp, C2HData, R2T.
pub mod kind {
    pub const IC_REQ: u8 = 0x00;
    pub const IC_RESP: u8 = 0x01;
    pub const H2C_TERM_REQ: u8 = 0x02;
    pub const C2H_TERM_REQ: u8 = 0x03;
    pub const CAPSULE_CMD: u8 = 0x04;
    pub const CAPSULE_RESP: u8 = 0x05;
    pub const H2C_DATA: u8 = 0x06;
    pub const C2H_DATA: u8 = 0x07;
    pub const R2T: u8 = 0x09;

    pub fn name(k: u8) -> &'static str {
        match k {
            IC_REQ => "ICReq",
            IC_RESP => "ICResp",
            H2C_TERM_REQ => "H2CTermReq",
            C2H_TERM_REQ => "C2HTermReq",
            CAPSULE_CMD => "CapsuleCmd",
            CAPSULE_RESP => "CapsuleResp",
            H2C_DATA => "H2CData",
            C2H_DATA => "C2HData",
            R2T => "R2T",
            _ => "unknown PDU type",
        }
    }

    /// The fixed header length of a PDU type.
    pub fn hlen(k: u8) -> Option<usize> {
        match k {
            IC_REQ | IC_RESP => Some(super::IC_LEN),
            CAPSULE_CMD => Some(super::CAPSULE_CMD_HLEN),
            H2C_TERM_REQ | C2H_TERM_REQ | CAPSULE_RESP | H2C_DATA | C2H_DATA | R2T => {
                Some(super::SHORT_HLEN)
            }
            _ => None,
        }
    }

    /// Whether this type carries the negotiated digests. ICReq/ICResp precede negotiation and a
    /// TermReq never carries them (the Linux host says as much when it reads one).
    pub fn digested(k: u8) -> bool {
        !matches!(k, IC_REQ | IC_RESP | H2C_TERM_REQ | C2H_TERM_REQ)
    }

    /// Whether this type may carry data.
    pub fn carries_data(k: u8) -> bool {
        matches!(
            k,
            CAPSULE_CMD | H2C_DATA | C2H_DATA | H2C_TERM_REQ | C2H_TERM_REQ
        )
    }
}

/// Common header flags (§3.6.2).
pub mod flag {
    pub const HDGSTF: u8 = 0x01;
    pub const DDGSTF: u8 = 0x02;
    /// H2CData / C2HData: the last PDU of the transfer (of the R2T, for H2CData).
    pub const LAST_PDU: u8 = 0x04;
    /// C2HData only: the command completed successfully and no CapsuleResp follows. Allowed
    /// only when submission queue flow control is disabled.
    pub const SUCCESS: u8 = 0x08;
}

/// Fatal Error Status of a TermReq (§3.6.2.9).
pub mod fes {
    pub const INVALID_PDU_HEADER_FIELD: u16 = 0x01;
    pub const PDU_SEQUENCE_ERROR: u16 = 0x02;
    pub const HEADER_DIGEST_ERROR: u16 = 0x03;
    pub const DATA_TRANSFER_OUT_OF_RANGE: u16 = 0x04;
    pub const DATA_TRANSFER_LIMIT_EXCEEDED: u16 = 0x05;
    pub const UNSUPPORTED_PARAMETER: u16 = 0x06;

    pub fn name(f: u16) -> &'static str {
        match f {
            INVALID_PDU_HEADER_FIELD => "invalid PDU header field",
            PDU_SEQUENCE_ERROR => "PDU sequence error",
            HEADER_DIGEST_ERROR => "header digest error",
            DATA_TRANSFER_OUT_OF_RANGE => "data transfer out of range",
            DATA_TRANSFER_LIMIT_EXCEEDED => "data transfer limit exceeded",
            UNSUPPORTED_PARAMETER => "unsupported parameter",
            _ => "unknown fatal error status",
        }
    }
}

/// Byte offsets of the common header fields, for a TermReq's Fatal Error Information.
pub mod offset {
    pub const PDU_TYPE: u32 = 0;
    pub const FLAGS: u32 = 1;
    pub const HLEN: u32 = 2;
    pub const PDO: u32 = 3;
    pub const PLEN: u32 = 4;
}

/// Which digests a connection uses, once ICReq/ICResp have settled them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Digests {
    pub header: bool,
    pub data: bool,
}

/// A PDU: its whole header (common header and PDU-specific header, HLEN bytes) and its data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pdu {
    pub header: Vec<u8>,
    pub data: Vec<u8>,
}

impl Pdu {
    /// A PDU of a type, its header zeroed at the type's length.
    pub fn new(k: u8) -> Self {
        let hlen = kind::hlen(k).unwrap_or(SHORT_HLEN);
        let mut header = vec![0u8; hlen];
        header[0] = k;
        header[2] = hlen as u8;
        Self {
            header,
            data: Vec::new(),
        }
    }
    pub fn kind(&self) -> u8 {
        self.header[0]
    }
    pub fn flags(&self) -> u8 {
        self.header[1]
    }
    pub fn set_flags(&mut self, f: u8) {
        self.header[1] = f;
    }
    pub fn u8_at(&self, at: usize) -> u8 {
        self.header[at]
    }
    pub fn u16_at(&self, at: usize) -> u16 {
        u16::from_le_bytes([self.header[at], self.header[at + 1]])
    }
    pub fn u32_at(&self, at: usize) -> u32 {
        u32::from_le_bytes(self.header[at..at + 4].try_into().expect("4 bytes"))
    }
    pub fn u64_at(&self, at: usize) -> u64 {
        u64::from_le_bytes(self.header[at..at + 8].try_into().expect("8 bytes"))
    }
    pub fn set_u16(&mut self, at: usize, v: u16) {
        self.header[at..at + 2].copy_from_slice(&v.to_le_bytes());
    }
    pub fn set_u32(&mut self, at: usize, v: u32) {
        self.header[at..at + 4].copy_from_slice(&v.to_le_bytes());
    }
    pub fn set_u64(&mut self, at: usize, v: u64) {
        self.header[at..at + 8].copy_from_slice(&v.to_le_bytes());
    }

    /// The PDU as wire bytes: PDO and PLEN filled in, the digest flags set for what is in use,
    /// the data placed at the alignment `pda` asks for ((pda + 1) × 4 bytes, the receiver's
    /// HPDA or CPDA).
    pub fn encode(&self, digests: Digests, pda: u8) -> Vec<u8> {
        let k = self.kind();
        let hlen = self.header.len();
        let hdgst = digests.header && kind::digested(k);
        let has_data = !self.data.is_empty();
        let ddgst = digests.data && has_data && kind::digested(k);
        let mut header = self.header.clone();
        header[2] = hlen as u8;
        let mut flags = header[1] & !(flag::HDGSTF | flag::DDGSTF);
        if hdgst {
            flags |= flag::HDGSTF;
        }
        if ddgst {
            flags |= flag::DDGSTF;
        }
        header[1] = flags;
        let after_header = hlen + if hdgst { DIGEST_LEN } else { 0 };
        // A TermReq's data follows its header directly (PDO 0), as SPDK sends it.
        let pdo = if !has_data {
            0
        } else if matches!(k, kind::H2C_TERM_REQ | kind::C2H_TERM_REQ) {
            after_header
        } else {
            let align = (pda as usize % 32 + 1) * 4;
            after_header.div_ceil(align) * align
        };
        let plen = if has_data {
            pdo + self.data.len() + if ddgst { DIGEST_LEN } else { 0 }
        } else {
            after_header
        };
        header[3] = if has_data && !matches!(k, kind::H2C_TERM_REQ | kind::C2H_TERM_REQ) {
            pdo as u8
        } else {
            0
        };
        header[4..8].copy_from_slice(&(plen as u32).to_le_bytes());
        let mut out = Vec::with_capacity(plen);
        out.extend(&header);
        if hdgst {
            out.extend(crc32c(&header).to_le_bytes());
        }
        if has_data {
            out.resize(pdo, 0);
            out.extend(&self.data);
            if ddgst {
                out.extend(crc32c(&self.data).to_le_bytes());
            }
        }
        out
    }
}

/// CRC32C (Castagnoli), the digest the specification names, sent least significant byte
/// first as the Linux and SPDK implementations put it on the wire.
pub fn crc32c(bytes: &[u8]) -> u32 {
    crc32c::crc32c(bytes)
}

/// What a receiver accepts: the PDU types legal in its direction at this point, the digests
/// negotiated, and the most data each data-bearing type may carry.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Bit `n` set: PDU type `n` is accepted.
    pub accepted: u32,
    pub digests: Digests,
    /// In-capsule data in a CapsuleCmd.
    pub max_capsule_data: usize,
    /// Data in one H2CData or C2HData PDU.
    pub max_data_pdu: usize,
}

impl Limits {
    pub fn types(types: &[u8]) -> u32 {
        types.iter().fold(0, |m, t| m | (1 << t))
    }
    fn max_data(&self, k: u8) -> usize {
        match k {
            kind::CAPSULE_CMD => self.max_capsule_data,
            kind::H2C_DATA | kind::C2H_DATA => self.max_data_pdu,
            kind::H2C_TERM_REQ | kind::C2H_TERM_REQ => TERM_REQ_MAX_DATA,
            _ => 0,
        }
    }
}

/// Where a PDU's parts lie, from its common header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Layout {
    pub kind: u8,
    pub hlen: usize,
    pub hdgst: bool,
    pub ddgst: bool,
    /// Where the data starts (0 when there is none).
    pub pdo: usize,
    pub data_len: usize,
    pub plen: usize,
}

/// A fatal transport error: the TermReq status and information, and what was wrong.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fatal {
    pub fes: u16,
    pub fei: u32,
    pub reason: String,
}

fn fatal(fes: u16, fei: u32, reason: impl Into<String>) -> Fatal {
    Fatal {
        fes,
        fei,
        reason: reason.into(),
    }
}

/// Decide a PDU from its common header alone, before anything else is read.
pub fn check_header(ch: &[u8; CH_LEN], limits: &Limits) -> Result<Layout, Fatal> {
    let k = ch[0];
    let flags = ch[1];
    let hlen = ch[2] as usize;
    let pdo = ch[3] as usize;
    let plen = u32::from_le_bytes(ch[4..8].try_into().expect("4 bytes")) as usize;
    if k >= 32 || limits.accepted & (1 << k) == 0 {
        return Err(fatal(
            if kind::hlen(k).is_some() {
                fes::PDU_SEQUENCE_ERROR
            } else {
                fes::INVALID_PDU_HEADER_FIELD
            },
            offset::PDU_TYPE,
            format!("a {} PDU (type 0x{k:02x}) here", kind::name(k)),
        ));
    }
    let want = kind::hlen(k).expect("an accepted type has a length");
    if hlen != want {
        return Err(fatal(
            fes::INVALID_PDU_HEADER_FIELD,
            offset::HLEN,
            format!("HLEN {hlen} for a {} (must be {want})", kind::name(k)),
        ));
    }
    let digested = kind::digested(k);
    let hdgst = digested && limits.digests.header;
    if digested && (flags & flag::HDGSTF != 0) != limits.digests.header {
        return Err(fatal(
            fes::INVALID_PDU_HEADER_FIELD,
            offset::FLAGS,
            "the header digest flag disagrees with what was negotiated",
        ));
    }
    let after_header = hlen + if hdgst { DIGEST_LEN } else { 0 };
    if matches!(k, kind::IC_REQ | kind::IC_RESP) && plen != IC_LEN {
        return Err(fatal(
            fes::INVALID_PDU_HEADER_FIELD,
            offset::PLEN,
            format!("PLEN {plen} for a {} (must be 128)", kind::name(k)),
        ));
    }
    if plen < after_header {
        return Err(fatal(
            fes::INVALID_PDU_HEADER_FIELD,
            offset::PLEN,
            format!("PLEN {plen} is shorter than the header ({after_header})"),
        ));
    }
    if plen == after_header {
        // No data. A PDO naming where data would start is tolerated; nothing follows it.
        if pdo != 0 && pdo != after_header {
            return Err(fatal(
                fes::INVALID_PDU_HEADER_FIELD,
                offset::PDO,
                format!("PDO {pdo} on a PDU without data"),
            ));
        }
        if digested && flags & flag::DDGSTF != 0 {
            return Err(fatal(
                fes::INVALID_PDU_HEADER_FIELD,
                offset::FLAGS,
                "a data digest flag on a PDU without data",
            ));
        }
        return Ok(Layout {
            kind: k,
            hlen,
            hdgst,
            ddgst: false,
            pdo: 0,
            data_len: 0,
            plen,
        });
    }
    if !kind::carries_data(k) {
        return Err(fatal(
            fes::INVALID_PDU_HEADER_FIELD,
            offset::PLEN,
            format!(
                "PLEN {plen} gives a {} data, which it cannot carry",
                kind::name(k)
            ),
        ));
    }
    let ddgst = digested && limits.digests.data;
    if digested && (flags & flag::DDGSTF != 0) != limits.digests.data {
        return Err(fatal(
            fes::INVALID_PDU_HEADER_FIELD,
            offset::FLAGS,
            "the data digest flag disagrees with what was negotiated",
        ));
    }
    // A TermReq's data follows its header; it has no PDO.
    let pdo = if matches!(k, kind::H2C_TERM_REQ | kind::C2H_TERM_REQ) {
        after_header
    } else {
        if pdo < after_header || pdo - after_header >= MAX_PAD {
            return Err(fatal(
                fes::INVALID_PDU_HEADER_FIELD,
                offset::PDO,
                format!("PDO {pdo} (the header ends at {after_header})"),
            ));
        }
        pdo
    };
    let tail = if ddgst { DIGEST_LEN } else { 0 };
    if plen < pdo + tail + 1 {
        return Err(fatal(
            fes::INVALID_PDU_HEADER_FIELD,
            offset::PLEN,
            format!("PLEN {plen} leaves no room for data after PDO {pdo}"),
        ));
    }
    let data_len = plen - pdo - tail;
    let max = limits.max_data(k);
    if data_len > max {
        return Err(fatal(
            if matches!(k, kind::H2C_DATA | kind::C2H_DATA) {
                fes::DATA_TRANSFER_LIMIT_EXCEEDED
            } else {
                fes::INVALID_PDU_HEADER_FIELD
            },
            offset::PLEN,
            format!(
                "a {} carrying {data_len} bytes, over the {max} this side accepts",
                kind::name(k)
            ),
        ));
    }
    Ok(Layout {
        kind: k,
        hlen,
        hdgst,
        ddgst,
        pdo,
        data_len,
        plen,
    })
}

/// Why a PDU could not be read.
#[derive(Debug)]
pub enum ReadError {
    /// The peer closed the connection before a PDU began.
    Closed,
    Io(std::io::Error),
    /// The rest of a PDU did not arrive within the deadline after its first byte.
    Stalled,
    /// A fatal transport error, and the header bytes read so far (for the TermReq).
    Fatal(Fatal, Vec<u8>),
    /// The data digest did not match. The PDU was read whole, so the stream is in step.
    DataDigest(Box<Pdu>),
}

impl std::fmt::Display for ReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Closed => write!(f, "the peer closed the connection"),
            Self::Io(e) => write!(f, "{e}"),
            Self::Stalled => write!(f, "a PDU stalled part-way"),
            Self::Fatal(e, _) => write!(f, "{} ({})", e.reason, fes::name(e.fes)),
            Self::DataDigest(_) => write!(f, "data digest mismatch"),
        }
    }
}

impl std::error::Error for ReadError {}

/// The rest of a PDU whose first byte has arrived, read within `deadline`.
pub async fn read_rest<R: AsyncRead + Unpin>(
    r: &mut R,
    first: u8,
    limits: &Limits,
    deadline: Duration,
) -> Result<Pdu, ReadError> {
    let rest = async {
        let mut ch = [0u8; CH_LEN];
        ch[0] = first;
        r.read_exact(&mut ch[1..]).await.map_err(ReadError::Io)?;
        let layout = check_header(&ch, limits).map_err(|e| ReadError::Fatal(e, ch.to_vec()))?;
        let mut header = vec![0u8; layout.hlen];
        header[..CH_LEN].copy_from_slice(&ch);
        r.read_exact(&mut header[CH_LEN..])
            .await
            .map_err(ReadError::Io)?;
        if layout.hdgst {
            let mut d = [0u8; DIGEST_LEN];
            r.read_exact(&mut d).await.map_err(ReadError::Io)?;
            if crc32c(&header) != u32::from_le_bytes(d) {
                return Err(ReadError::Fatal(
                    fatal(fes::HEADER_DIGEST_ERROR, 0, "header digest mismatch"),
                    header,
                ));
            }
        }
        let mut data = Vec::new();
        if layout.data_len > 0 {
            let pad = layout.pdo - layout.hlen - if layout.hdgst { DIGEST_LEN } else { 0 };
            let mut skip = [0u8; MAX_PAD];
            r.read_exact(&mut skip[..pad])
                .await
                .map_err(ReadError::Io)?;
            data = vec![0u8; layout.data_len];
            r.read_exact(&mut data).await.map_err(ReadError::Io)?;
            if layout.ddgst {
                let mut d = [0u8; DIGEST_LEN];
                r.read_exact(&mut d).await.map_err(ReadError::Io)?;
                if crc32c(&data) != u32::from_le_bytes(d) {
                    return Err(ReadError::DataDigest(Box::new(Pdu { header, data })));
                }
            }
        }
        Ok(Pdu { header, data })
    };
    tokio::time::timeout(deadline, rest)
        .await
        .map_err(|_| ReadError::Stalled)?
}

/// Read one PDU. Waiting for its first byte has no deadline (an idle queue is normal); once it
/// has begun, the rest must arrive within `deadline`.
pub async fn read_pdu<R: AsyncRead + Unpin>(
    r: &mut R,
    limits: &Limits,
    deadline: Duration,
) -> Result<Pdu, ReadError> {
    let mut first = [0u8; 1];
    let n = r.read(&mut first).await.map_err(ReadError::Io)?;
    if n == 0 {
        return Err(ReadError::Closed);
    }
    read_rest(r, first[0], limits, deadline).await
}

/// One PDU from the front of a buffer, with the checks [`read_pdu`] makes. `Ok(None)` means the
/// buffer holds less than a whole PDU; otherwise the PDU and the bytes it took. For the fuzz
/// target and for anything holding bytes already read.
pub fn decode(buf: &[u8], limits: &Limits) -> Result<Option<(Pdu, usize)>, ReadError> {
    let Some(ch) = buf.get(..CH_LEN) else {
        return Ok(None);
    };
    let ch: [u8; CH_LEN] = ch.try_into().expect("8 bytes");
    let layout = check_header(&ch, limits).map_err(|e| ReadError::Fatal(e, ch.to_vec()))?;
    if buf.len() < layout.plen {
        return Ok(None);
    }
    let header = buf[..layout.hlen].to_vec();
    if layout.hdgst {
        let d = &buf[layout.hlen..layout.hlen + DIGEST_LEN];
        if crc32c(&header) != u32::from_le_bytes(d.try_into().expect("4 bytes")) {
            return Err(ReadError::Fatal(
                fatal(fes::HEADER_DIGEST_ERROR, 0, "header digest mismatch"),
                header,
            ));
        }
    }
    let mut data = Vec::new();
    if layout.data_len > 0 {
        data = buf[layout.pdo..layout.pdo + layout.data_len].to_vec();
        if layout.ddgst {
            let at = layout.pdo + layout.data_len;
            let d = &buf[at..at + DIGEST_LEN];
            if crc32c(&data) != u32::from_le_bytes(d.try_into().expect("4 bytes")) {
                return Err(ReadError::DataDigest(Box::new(Pdu { header, data })));
            }
        }
    }
    Ok(Some((Pdu { header, data }, layout.plen)))
}

/// A TermReq (H2C or C2H) carrying a fatal error and up to 128 bytes of the offending header.
pub fn term_req(k: u8, e: &Fatal, offending: &[u8]) -> Pdu {
    let mut p = Pdu::new(k);
    p.set_u16(8, e.fes);
    if matches!(
        e.fes,
        fes::INVALID_PDU_HEADER_FIELD | fes::UNSUPPORTED_PARAMETER
    ) {
        p.set_u32(10, e.fei);
    }
    p.data = offending[..offending.len().min(TERM_REQ_MAX_DATA)].to_vec();
    p
}

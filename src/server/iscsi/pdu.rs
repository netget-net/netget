//! iSCSI PDU framing (RFC 7143 §11): the 48-byte Basic Header Segment, additional header
//! segments, the data segment padded to four bytes, and the optional CRC32C header and data
//! digests. Shared by the target and the initiator (`src/client/iscsi`).
//!
//! Every length here comes from the peer, so [`read_pdu`] decides a PDU from its header before
//! it allocates for it: a data segment longer than the receiver declared in
//! MaxRecvDataSegmentLength is refused unread, and the AHS can hold at most 255 words.
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt};

pub const BHS_LEN: usize = 48;
/// The ITT and TTT value meaning "none".
pub const RESERVED_TAG: u32 = 0xFFFF_FFFF;
/// The data segment any receiver accepts before negotiation (RFC 7143 §13.12).
pub const DEFAULT_MAX_RECV_DATA_SEGMENT: usize = 8192;
/// The 24-bit DataSegmentLength field's ceiling.
pub const MAX_DATA_SEGMENT_FIELD: usize = (1 << 24) - 1;

/// Opcodes. Initiator opcodes are below 0x20, target opcodes from 0x20.
pub mod op {
    pub const NOP_OUT: u8 = 0x00;
    pub const SCSI_COMMAND: u8 = 0x01;
    pub const TASK_MGMT_REQUEST: u8 = 0x02;
    pub const LOGIN_REQUEST: u8 = 0x03;
    pub const TEXT_REQUEST: u8 = 0x04;
    pub const DATA_OUT: u8 = 0x05;
    pub const LOGOUT_REQUEST: u8 = 0x06;
    pub const SNACK_REQUEST: u8 = 0x10;
    pub const NOP_IN: u8 = 0x20;
    pub const SCSI_RESPONSE: u8 = 0x21;
    pub const TASK_MGMT_RESPONSE: u8 = 0x22;
    pub const LOGIN_RESPONSE: u8 = 0x23;
    pub const TEXT_RESPONSE: u8 = 0x24;
    pub const DATA_IN: u8 = 0x25;
    pub const LOGOUT_RESPONSE: u8 = 0x26;
    pub const R2T: u8 = 0x31;
    pub const ASYNC_MESSAGE: u8 = 0x32;
    pub const REJECT: u8 = 0x3F;

    pub fn name(op: u8) -> &'static str {
        match op {
            NOP_OUT => "NOP-Out",
            SCSI_COMMAND => "SCSI Command",
            TASK_MGMT_REQUEST => "Task Management Request",
            LOGIN_REQUEST => "Login Request",
            TEXT_REQUEST => "Text Request",
            DATA_OUT => "SCSI Data-Out",
            LOGOUT_REQUEST => "Logout Request",
            SNACK_REQUEST => "SNACK Request",
            NOP_IN => "NOP-In",
            SCSI_RESPONSE => "SCSI Response",
            TASK_MGMT_RESPONSE => "Task Management Response",
            LOGIN_RESPONSE => "Login Response",
            TEXT_RESPONSE => "Text Response",
            DATA_IN => "SCSI Data-In",
            LOGOUT_RESPONSE => "Logout Response",
            R2T => "Ready To Transfer",
            ASYNC_MESSAGE => "Asynchronous Message",
            REJECT => "Reject",
            _ => "unknown opcode",
        }
    }
}

/// Reject reasons (RFC 7143 §11.17.1).
pub mod reject {
    pub const DATA_DIGEST_ERROR: u8 = 0x02;
    pub const SNACK_REJECT: u8 = 0x03;
    pub const PROTOCOL_ERROR: u8 = 0x04;
    pub const COMMAND_NOT_SUPPORTED: u8 = 0x05;
    pub const INVALID_PDU_FIELD: u8 = 0x09;
}

/// Login status class and detail (RFC 7143 §11.13.5), as the 16-bit pair.
pub mod login_status {
    pub const SUCCESS: u16 = 0x0000;
    pub const INITIATOR_ERROR: u16 = 0x0200;
    pub const AUTHENTICATION_FAILURE: u16 = 0x0201;
    pub const AUTHORIZATION_FAILURE: u16 = 0x0202;
    pub const NOT_FOUND: u16 = 0x0203;
    pub const TARGET_REMOVED: u16 = 0x0204;
    pub const UNSUPPORTED_VERSION: u16 = 0x0205;
    pub const MISSING_PARAMETER: u16 = 0x0207;
    pub const SESSION_TYPE_NOT_SUPPORTED: u16 = 0x0209;
    pub const SESSION_DOES_NOT_EXIST: u16 = 0x020A;
    pub const INVALID_DURING_LOGIN: u16 = 0x020B;
    pub const TARGET_ERROR: u16 = 0x0300;
    pub const SERVICE_UNAVAILABLE: u16 = 0x0301;
    pub const OUT_OF_RESOURCES: u16 = 0x0302;

    pub fn describe(code: u16) -> &'static str {
        match code {
            SUCCESS => "success",
            0x0101 => "target moved temporarily",
            0x0102 => "target moved permanently",
            INITIATOR_ERROR => "initiator error",
            AUTHENTICATION_FAILURE => "authentication failure",
            AUTHORIZATION_FAILURE => "authorization failure",
            NOT_FOUND => "target not found",
            TARGET_REMOVED => "target removed",
            UNSUPPORTED_VERSION => "unsupported version",
            0x0206 => "too many connections",
            MISSING_PARAMETER => "missing parameter",
            0x0208 => "cannot include in session",
            SESSION_TYPE_NOT_SUPPORTED => "session type not supported",
            SESSION_DOES_NOT_EXIST => "session does not exist",
            INVALID_DURING_LOGIN => "invalid request during login",
            TARGET_ERROR => "target error",
            SERVICE_UNAVAILABLE => "service unavailable",
            OUT_OF_RESOURCES => "out of resources",
            _ => "unknown status",
        }
    }
}

/// Login stages (CSG/NSG).
pub mod stage {
    pub const SECURITY: u8 = 0;
    pub const OPERATIONAL: u8 = 1;
    pub const FULL_FEATURE: u8 = 3;
}

/// Which digests a connection uses, once negotiated. Login PDUs never carry them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Digests {
    pub header: bool,
    pub data: bool,
}

/// A PDU: the BHS as bytes, the AHS and the data segment (unpadded).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pdu {
    pub bhs: [u8; BHS_LEN],
    pub ahs: Vec<u8>,
    pub data: Vec<u8>,
}

impl Pdu {
    pub fn new(opcode: u8) -> Self {
        let mut bhs = [0u8; BHS_LEN];
        bhs[0] = opcode & 0x3F;
        Self {
            bhs,
            ahs: Vec::new(),
            data: Vec::new(),
        }
    }
    pub fn opcode(&self) -> u8 {
        self.bhs[0] & 0x3F
    }
    pub fn immediate(&self) -> bool {
        self.bhs[0] & 0x40 != 0
    }
    pub fn set_immediate(&mut self) {
        self.bhs[0] |= 0x40;
    }
    pub fn flags(&self) -> u8 {
        self.bhs[1]
    }
    pub fn set_flags(&mut self, f: u8) {
        self.bhs[1] = f;
    }
    pub fn final_bit(&self) -> bool {
        self.bhs[1] & 0x80 != 0
    }
    pub fn u16_at(&self, at: usize) -> u16 {
        u16::from_be_bytes([self.bhs[at], self.bhs[at + 1]])
    }
    pub fn u32_at(&self, at: usize) -> u32 {
        u32::from_be_bytes(self.bhs[at..at + 4].try_into().expect("4 bytes"))
    }
    pub fn set_u16(&mut self, at: usize, v: u16) {
        self.bhs[at..at + 2].copy_from_slice(&v.to_be_bytes());
    }
    pub fn set_u32(&mut self, at: usize, v: u32) {
        self.bhs[at..at + 4].copy_from_slice(&v.to_be_bytes());
    }
    pub fn lun(&self) -> [u8; 8] {
        self.bhs[8..16].try_into().expect("8 bytes")
    }
    pub fn set_lun(&mut self, lun: [u8; 8]) {
        self.bhs[8..16].copy_from_slice(&lun);
    }
    pub fn itt(&self) -> u32 {
        self.u32_at(16)
    }
    pub fn set_itt(&mut self, itt: u32) {
        self.set_u32(16, itt);
    }
    /// Header lengths as the BHS declares them: (AHS bytes, data segment bytes).
    pub fn declared_lengths(bhs: &[u8; BHS_LEN]) -> (usize, usize) {
        let ahs = bhs[4] as usize * 4;
        let dsl = ((bhs[5] as usize) << 16) | ((bhs[6] as usize) << 8) | bhs[7] as usize;
        (ahs, dsl)
    }

    /// The PDU as wire bytes, with lengths filled in, padding and the digests in use.
    pub fn encode(&self, digests: Digests) -> Vec<u8> {
        let mut bhs = self.bhs;
        bhs[4] = (self.ahs.len() / 4) as u8;
        let dsl = self.data.len().min(MAX_DATA_SEGMENT_FIELD) as u32;
        bhs[5..8].copy_from_slice(&dsl.to_be_bytes()[1..]);
        let mut out = Vec::with_capacity(BHS_LEN + self.ahs.len() + self.data.len() + 12);
        out.extend(bhs);
        out.extend(&self.ahs);
        if digests.header {
            let d = crc32c(&out);
            out.extend(d.to_le_bytes());
        }
        if !self.data.is_empty() {
            let start = out.len();
            out.extend(&self.data);
            out.resize(start + padded(self.data.len()), 0);
            if digests.data {
                let d = crc32c(&out[start..]);
                out.extend(d.to_le_bytes());
            }
        }
        out
    }
}

/// A length rounded up to a whole number of four-byte words.
pub fn padded(n: usize) -> usize {
    n.div_ceil(4) * 4
}

/// CRC32C (Castagnoli), the digest RFC 7143 §13.1 names. It is sent least significant byte
/// first, which is how the Linux, libiscsi and tgt implementations put it on the wire.
pub fn crc32c(bytes: &[u8]) -> u32 {
    crc32c::crc32c(bytes)
}

/// Why a PDU could not be read.
#[derive(Debug)]
pub enum ReadError {
    /// The peer closed the connection before a PDU began.
    Closed,
    Io(std::io::Error),
    /// The rest of a PDU did not arrive within the deadline after its first byte.
    Stalled,
    /// The data segment declared is longer than this side accepts; nothing past the header
    /// was read.
    Oversize { declared: usize, limit: usize },
    /// The header digest did not match: the stream can no longer be trusted.
    HeaderDigest,
    /// The data digest did not match. The PDU was read whole, so the stream is still in step.
    DataDigest(Box<Pdu>),
}

impl std::fmt::Display for ReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Closed => write!(f, "the peer closed the connection"),
            Self::Io(e) => write!(f, "{e}"),
            Self::Stalled => write!(f, "a PDU stalled part-way"),
            Self::Oversize { declared, limit } => write!(
                f,
                "a data segment of {declared} bytes, over the {limit} this side accepts"
            ),
            Self::HeaderDigest => write!(f, "header digest mismatch"),
            Self::DataDigest(_) => write!(f, "data digest mismatch"),
        }
    }
}

impl std::error::Error for ReadError {}

/// Read one PDU. Waiting for its first byte has no deadline (an idle session is normal); once
/// it has begun, the rest must arrive within `deadline`. A data segment over `max_data` is
/// refused before it is read.
pub async fn read_pdu<R: AsyncRead + Unpin>(
    r: &mut R,
    digests: Digests,
    max_data: usize,
    deadline: Duration,
) -> Result<Pdu, ReadError> {
    let mut bhs = [0u8; BHS_LEN];
    let n = r.read(&mut bhs[..1]).await.map_err(ReadError::Io)?;
    if n == 0 {
        return Err(ReadError::Closed);
    }
    let rest = async {
        r.read_exact(&mut bhs[1..]).await.map_err(ReadError::Io)?;
        let (ahs_len, dsl) = Pdu::declared_lengths(&bhs);
        if dsl > max_data {
            return Err(ReadError::Oversize {
                declared: dsl,
                limit: max_data,
            });
        }
        let mut ahs = vec![0u8; ahs_len];
        r.read_exact(&mut ahs).await.map_err(ReadError::Io)?;
        if digests.header {
            let mut d = [0u8; 4];
            r.read_exact(&mut d).await.map_err(ReadError::Io)?;
            let mut covered = bhs.to_vec();
            covered.extend(&ahs);
            if crc32c(&covered) != u32::from_le_bytes(d) {
                return Err(ReadError::HeaderDigest);
            }
        }
        let mut data = vec![0u8; padded(dsl)];
        let mut data_ok = true;
        if dsl > 0 {
            r.read_exact(&mut data).await.map_err(ReadError::Io)?;
            if digests.data {
                let mut d = [0u8; 4];
                r.read_exact(&mut d).await.map_err(ReadError::Io)?;
                data_ok = crc32c(&data) == u32::from_le_bytes(d);
            }
        }
        data.truncate(dsl);
        let pdu = Pdu { bhs, ahs, data };
        if data_ok {
            Ok(pdu)
        } else {
            Err(ReadError::DataDigest(Box::new(pdu)))
        }
    };
    tokio::time::timeout(deadline, rest)
        .await
        .map_err(|_| ReadError::Stalled)?
}

/// Serial number comparison (RFC 1982, 32-bit), which CmdSN, StatSN and DataSN use: whether
/// `a` is before `b`.
pub fn sn_lt(a: u32, b: u32) -> bool {
    a != b && ((a < b && b - a < 1 << 31) || (a > b && a - b > 1 << 31))
}

/// Whether `a` is at or before `b` in serial number order.
pub fn sn_le(a: u32, b: u32) -> bool {
    a == b || sn_lt(a, b)
}

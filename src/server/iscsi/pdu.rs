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
    pub const TASK_IN_PROGRESS: u8 = 0x07;
    pub const INVALID_DATA_ACK: u8 = 0x08;
    pub const INVALID_PDU_FIELD: u8 = 0x09;
}

/// Task management functions (RFC 7143 §11.5.1; 9-12 from RFC 7144) and responses (§11.6.1).
pub mod tmf {
    pub const ABORT_TASK: u8 = 1;
    pub const ABORT_TASK_SET: u8 = 2;
    pub const CLEAR_ACA: u8 = 3;
    pub const CLEAR_TASK_SET: u8 = 4;
    pub const LOGICAL_UNIT_RESET: u8 = 5;
    pub const TARGET_WARM_RESET: u8 = 6;
    pub const TARGET_COLD_RESET: u8 = 7;
    pub const TASK_REASSIGN: u8 = 8;
    pub const QUERY_TASK: u8 = 9;
    pub const QUERY_ASYNC_EVENT: u8 = 12;

    pub const FUNCTION_COMPLETE: u8 = 0;
    pub const TASK_DOES_NOT_EXIST: u8 = 1;
    pub const LUN_DOES_NOT_EXIST: u8 = 2;
    pub const TASK_STILL_ALLEGIANT: u8 = 3;
    pub const REASSIGNMENT_NOT_SUPPORTED: u8 = 4;
    pub const NOT_SUPPORTED: u8 = 5;
    pub const AUTHORIZATION_FAILED: u8 = 6;
    pub const REJECTED: u8 = 255;

    /// The function's name in events and logs.
    pub fn name(f: u8) -> &'static str {
        match f {
            ABORT_TASK => "abort_task",
            ABORT_TASK_SET => "abort_task_set",
            CLEAR_ACA => "clear_aca",
            CLEAR_TASK_SET => "clear_task_set",
            LOGICAL_UNIT_RESET => "logical_unit_reset",
            TARGET_WARM_RESET => "target_warm_reset",
            TARGET_COLD_RESET => "target_cold_reset",
            TASK_REASSIGN => "task_reassign",
            QUERY_TASK => "query_task",
            10 => "query_task_set",
            11 => "i_t_nexus_reset",
            QUERY_ASYNC_EVENT => "query_async_event",
            _ => "unassigned",
        }
    }

    /// A function by its name, for the initiator's actions.
    pub fn by_name(name: &str) -> Option<u8> {
        (1..=12).find(|f| self::name(*f) == name)
    }

    pub fn response_name(r: u8) -> &'static str {
        match r {
            FUNCTION_COMPLETE => "function_complete",
            TASK_DOES_NOT_EXIST => "task_does_not_exist",
            LUN_DOES_NOT_EXIST => "lun_does_not_exist",
            TASK_STILL_ALLEGIANT => "task_still_allegiant",
            REASSIGNMENT_NOT_SUPPORTED => "task_allegiance_reassignment_not_supported",
            NOT_SUPPORTED => "function_not_supported",
            AUTHORIZATION_FAILED => "function_authorization_failed",
            REJECTED => "function_rejected",
            _ => "unknown_response",
        }
    }
}

/// SNACK types (RFC 7143 §11.16.1).
pub mod snack {
    pub const DATA_R2T: u8 = 0;
    pub const STATUS: u8 = 1;
    pub const DATA_ACK: u8 = 2;
    pub const R_DATA: u8 = 3;
}

/// Logout reasons (§11.14.1) and responses (§11.15.1).
pub mod logout {
    pub const CLOSE_SESSION: u8 = 0;
    pub const CLOSE_CONNECTION: u8 = 1;
    pub const REMOVE_FOR_RECOVERY: u8 = 2;

    pub const CLOSED: u8 = 0;
    pub const CID_NOT_FOUND: u8 = 1;
    pub const RECOVERY_NOT_SUPPORTED: u8 = 2;
    pub const CLEANUP_FAILED: u8 = 3;
}

/// A Task Management Function Request's fields (RFC 7143 §11.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TmfRequest {
    pub function: u8,
    pub lun: [u8; 8],
    pub itt: u32,
    pub referenced: u32,
    pub cmd_sn: u32,
    pub ref_cmd_sn: u32,
    pub exp_data_sn: u32,
    pub immediate: bool,
}

impl TmfRequest {
    pub fn decode(p: &Pdu) -> Self {
        Self {
            function: p.flags() & 0x7F,
            lun: p.lun(),
            itt: p.itt(),
            referenced: p.u32_at(20),
            cmd_sn: p.u32_at(24),
            ref_cmd_sn: p.u32_at(32),
            exp_data_sn: p.u32_at(36),
            immediate: p.immediate(),
        }
    }
}

/// A SNACK Request's fields (RFC 7143 §11.16).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SnackRequest {
    pub kind: u8,
    pub lun: [u8; 8],
    pub itt: u32,
    /// The Target Transfer Tag (DataACK) or SNACK Tag (R-Data SNACK).
    pub tag: u32,
    pub beg_run: u32,
    pub run_length: u32,
}

impl SnackRequest {
    pub fn decode(p: &Pdu) -> Self {
        Self {
            kind: p.flags() & 0x0F,
            lun: p.lun(),
            itt: p.itt(),
            tag: p.u32_at(20),
            beg_run: p.u32_at(40),
            run_length: p.u32_at(44),
        }
    }

    /// The sequence numbers a run asks for, of the `sent` numbered PDUs (0..sent) the first
    /// `acked` of which the initiator has already acknowledged: `Err` when it names one that was
    /// never sent or is acknowledged (RFC 7143 §11.16: a Protocol Error Reject). BegRun 0 with
    /// RunLength 0 means every unacknowledged one; RunLength 0 alone, all from BegRun.
    pub fn run(&self, sent: u32, acked: u32) -> Result<std::ops::Range<u32>, ()> {
        if self.beg_run == 0 && self.run_length == 0 {
            return Ok(acked.min(sent)..sent);
        }
        let end = if self.run_length == 0 {
            sent
        } else {
            self.beg_run.checked_add(self.run_length).ok_or(())?
        };
        if self.beg_run < acked || end > sent || self.beg_run >= end {
            return Err(());
        }
        Ok(self.beg_run..end)
    }
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
    pub const TOO_MANY_CONNECTIONS: u16 = 0x0206;
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
            TOO_MANY_CONNECTIONS => "too many connections",
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
    Oversize {
        declared: usize,
        limit: usize,
    },
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

/// The bytes a whole PDU occupies on the wire, from its header and the digests in use.
pub fn frame_length(bhs: &[u8; BHS_LEN], digests: Digests) -> usize {
    let (ahs, dsl) = Pdu::declared_lengths(bhs);
    let mut n = BHS_LEN + ahs + if digests.header { 4 } else { 0 };
    if dsl > 0 {
        n += padded(dsl) + if digests.data { 4 } else { 0 };
    }
    n
}

/// Reads whole PDUs off a stream, keeping what has arrived between calls, so that
/// [`PduReader::next`] can be dropped part-way (in a `select!`) without losing bytes: it only
/// ever waits in `read`, which takes nothing from the stream unless it completes. Holds at most
/// one PDU's bytes, bounded by the data segment limit before anything past the header is read.
pub struct PduReader {
    buf: Vec<u8>,
    /// When the PDU now arriving began, for the deadline on its rest.
    started: Option<tokio::time::Instant>,
}

impl Default for PduReader {
    fn default() -> Self {
        Self::new()
    }
}

impl PduReader {
    pub fn new() -> Self {
        Self {
            buf: Vec::new(),
            started: None,
        }
    }

    /// The next PDU: the same checks and errors as [`read_pdu`]. Waiting for a PDU's first
    /// byte has no deadline; its rest must arrive within `deadline` of that byte.
    pub async fn next<R: AsyncRead + Unpin>(
        &mut self,
        r: &mut R,
        digests: Digests,
        max_data: usize,
        deadline: Duration,
    ) -> Result<Pdu, ReadError> {
        loop {
            let mut need = BHS_LEN;
            if self.buf.len() >= BHS_LEN {
                let bhs: [u8; BHS_LEN] = self.buf[..BHS_LEN].try_into().expect("48 bytes");
                let (_, dsl) = Pdu::declared_lengths(&bhs);
                if dsl > max_data {
                    self.buf.clear();
                    self.started = None;
                    return Err(ReadError::Oversize {
                        declared: dsl,
                        limit: max_data,
                    });
                }
                need = frame_length(&bhs, digests);
                if self.buf.len() >= need {
                    let result = decode(&self.buf[..need], digests, max_data);
                    self.buf.drain(..need);
                    self.started = if self.buf.is_empty() {
                        None
                    } else {
                        Some(tokio::time::Instant::now())
                    };
                    return match result {
                        Ok(Some((p, _))) => Ok(p),
                        Ok(None) => Err(ReadError::Stalled),
                        Err(e) => Err(e),
                    };
                }
            }
            let mut chunk = vec![0u8; (need - self.buf.len()).min(64 * 1024)];
            let n = match self.started {
                None => r.read(&mut chunk).await.map_err(ReadError::Io)?,
                Some(at) => tokio::time::timeout_at(at + deadline, r.read(&mut chunk))
                    .await
                    .map_err(|_| ReadError::Stalled)?
                    .map_err(ReadError::Io)?,
            };
            if n == 0 {
                return Err(if self.buf.is_empty() {
                    ReadError::Closed
                } else {
                    ReadError::Io(std::io::ErrorKind::UnexpectedEof.into())
                });
            }
            if self.started.is_none() {
                self.started = Some(tokio::time::Instant::now());
            }
            self.buf.extend_from_slice(&chunk[..n]);
        }
    }
}

/// One PDU from the front of a buffer, with the same checks [`read_pdu`] makes: the data
/// segment bounded before anything else is believed, then the digests. `Ok(None)` means the
/// buffer holds less than a whole PDU; otherwise the PDU and the bytes it took. For the fuzz
/// target and for anything holding bytes already read.
pub fn decode(
    buf: &[u8],
    digests: Digests,
    max_data: usize,
) -> Result<Option<(Pdu, usize)>, ReadError> {
    let Some(head) = buf.get(..BHS_LEN) else {
        return Ok(None);
    };
    let bhs: [u8; BHS_LEN] = head.try_into().expect("48 bytes");
    let (ahs_len, dsl) = Pdu::declared_lengths(&bhs);
    if dsl > max_data {
        return Err(ReadError::Oversize {
            declared: dsl,
            limit: max_data,
        });
    }
    let mut at = BHS_LEN + ahs_len;
    let Some(ahs) = buf.get(BHS_LEN..at) else {
        return Ok(None);
    };
    if digests.header {
        let Some(d) = buf.get(at..at + 4) else {
            return Ok(None);
        };
        if crc32c(&buf[..at]) != u32::from_le_bytes(d.try_into().expect("4 bytes")) {
            return Err(ReadError::HeaderDigest);
        }
        at += 4;
    }
    let mut data_ok = true;
    let mut data = Vec::new();
    if dsl > 0 {
        let end = at + padded(dsl);
        let Some(seg) = buf.get(at..end) else {
            return Ok(None);
        };
        data = seg[..dsl].to_vec();
        at = end;
        if digests.data {
            let Some(d) = buf.get(at..at + 4) else {
                return Ok(None);
            };
            data_ok = crc32c(seg) == u32::from_le_bytes(d.try_into().expect("4 bytes"));
            at += 4;
        }
    }
    let pdu = Pdu {
        bhs,
        ahs: ahs.to_vec(),
        data,
    };
    if data_ok {
        Ok(Some((pdu, at)))
    } else {
        Err(ReadError::DataDigest(Box::new(pdu)))
    }
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

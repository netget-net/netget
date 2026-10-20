//! The NVMe and NVMe over Fabrics vocabulary both roles speak inside the capsules: the 64-byte
//! submission queue entry, the 16-byte completion, status codes, opcodes, properties, the SGL
//! descriptors NVMe/TCP uses, and the data structures a host reads (Identify Controller and
//! Namespace, the active namespace list, namespace identification descriptors, the discovery
//! log page and the SMART / Health log). Encoders for the target, decoders for the host; the
//! fuzz target runs every decoder.
/// The well-known NQN of a discovery service.
pub const DISCOVERY_NQN: &str = "nqn.2014-08.org.nvmexpress.discovery";
/// NQNs are at most 223 bytes in a 256-byte field.
pub const MAX_NQN: usize = 223;
pub const NQN_FIELD: usize = 256;
/// Every Identify data structure, and the logs that are a page, are 4096 bytes.
pub const IDENTIFY_LEN: usize = 4096;
/// The Connect command's data.
pub const CONNECT_DATA_LEN: usize = 1024;
/// A discovery log page header and each entry are 1024 bytes.
pub const DISCOVERY_RECORD_LEN: usize = 1024;
/// The dynamic-controller CNTLID a host puts in an admin queue Connect.
pub const CNTLID_DYNAMIC: u16 = 0xFFFF;

/// Admin command opcodes.
pub mod admin {
    pub const GET_LOG_PAGE: u8 = 0x02;
    pub const IDENTIFY: u8 = 0x06;
    pub const ABORT: u8 = 0x08;
    pub const SET_FEATURES: u8 = 0x09;
    pub const GET_FEATURES: u8 = 0x0A;
    pub const ASYNC_EVENT_REQUEST: u8 = 0x0C;
    pub const KEEP_ALIVE: u8 = 0x18;
    pub const FABRICS: u8 = 0x7F;
}

/// NVM command set opcodes.
pub mod io {
    pub const FLUSH: u8 = 0x00;
    pub const WRITE: u8 = 0x01;
    pub const READ: u8 = 0x02;
    pub const WRITE_ZEROES: u8 = 0x08;
    pub const DATASET_MANAGEMENT: u8 = 0x09;
}

/// Fabrics command types (FCTYPE, byte 4 of a Fabrics command).
pub mod fctype {
    pub const PROPERTY_SET: u8 = 0x00;
    pub const CONNECT: u8 = 0x01;
    pub const PROPERTY_GET: u8 = 0x04;
    pub const AUTH_SEND: u8 = 0x05;
    pub const AUTH_RECEIVE: u8 = 0x06;
    pub const DISCONNECT: u8 = 0x08;
}

/// Property offsets.
pub mod prop {
    pub const CAP: u32 = 0x00;
    pub const VS: u32 = 0x08;
    pub const CC: u32 = 0x14;
    pub const CSTS: u32 = 0x1C;
    pub const NSSR: u32 = 0x20;
}

/// Identify CNS values.
pub mod cns {
    pub const NAMESPACE: u8 = 0x00;
    pub const CONTROLLER: u8 = 0x01;
    pub const ACTIVE_NAMESPACES: u8 = 0x02;
    pub const NAMESPACE_DESCRIPTORS: u8 = 0x03;
}

/// Log page identifiers.
pub mod log {
    pub const ERROR: u8 = 0x01;
    pub const SMART: u8 = 0x02;
    pub const FIRMWARE_SLOT: u8 = 0x03;
    pub const CHANGED_NAMESPACES: u8 = 0x04;
    pub const DISCOVERY: u8 = 0x70;
}

/// Feature identifiers.
pub mod feature {
    pub const ARBITRATION: u8 = 0x01;
    pub const POWER_MANAGEMENT: u8 = 0x02;
    pub const TEMPERATURE_THRESHOLD: u8 = 0x04;
    pub const ERROR_RECOVERY: u8 = 0x05;
    pub const VOLATILE_WRITE_CACHE: u8 = 0x06;
    pub const NUMBER_OF_QUEUES: u8 = 0x07;
    pub const WRITE_ATOMICITY: u8 = 0x0A;
    pub const ASYNC_EVENT_CONFIG: u8 = 0x0B;
    pub const KEEP_ALIVE_TIMER: u8 = 0x0F;
}

/// SGL descriptor types as NVMe/TCP uses them (the descriptor's byte 15).
pub mod sgl {
    /// Data Block, Offset subtype: the data is in the capsule, at `address`.
    pub const IN_CAPSULE: u8 = 0x01;
    /// Transport SGL Data Block, transport-specific subtype: the data moves in C2HData, or in
    /// H2CData PDUs the controller asks for with R2T.
    pub const TRANSPORT: u8 = 0x5A;
}

/// A completion status: status code type, status code and Do Not Retry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Status {
    pub sct: u8,
    pub sc: u8,
    pub dnr: bool,
}

impl Status {
    pub const fn generic(sc: u8) -> Self {
        Self {
            sct: 0,
            sc,
            dnr: true,
        }
    }
    pub const fn specific(sc: u8) -> Self {
        Self {
            sct: 1,
            sc,
            dnr: true,
        }
    }
    pub const fn media(sc: u8) -> Self {
        Self {
            sct: 2,
            sc,
            dnr: true,
        }
    }
    pub const fn retry(mut self) -> Self {
        self.dnr = false;
        self
    }
    pub const SUCCESS: Status = Status {
        sct: 0,
        sc: 0,
        dnr: false,
    };
    pub const INVALID_OPCODE: Status = Status::generic(0x01);
    pub const INVALID_FIELD: Status = Status::generic(0x02);
    pub const CID_CONFLICT: Status = Status::generic(0x03);
    pub const DATA_TRANSFER_ERROR: Status = Status::generic(0x04);
    pub const INTERNAL_ERROR: Status = Status::generic(0x06);
    pub const INVALID_NAMESPACE: Status = Status::generic(0x0B);
    pub const COMMAND_SEQUENCE_ERROR: Status = Status::generic(0x0C);
    pub const SGL_LENGTH_INVALID: Status = Status::generic(0x0F);
    pub const SGL_TYPE_INVALID: Status = Status::generic(0x11);
    pub const NAMESPACE_WRITE_PROTECTED: Status = Status::generic(0x20);
    pub const TRANSIENT_TRANSPORT_ERROR: Status = Status::generic(0x22).retry();
    pub const LBA_OUT_OF_RANGE: Status = Status::generic(0x80);
    pub const CAPACITY_EXCEEDED: Status = Status::generic(0x81);
    pub const INVALID_QUEUE_IDENTIFIER: Status = Status::specific(0x01);
    pub const AER_LIMIT_EXCEEDED: Status = Status::specific(0x05);
    pub const INVALID_LOG_PAGE: Status = Status::specific(0x09);
    pub const FEATURE_NOT_SAVEABLE: Status = Status::specific(0x0D);
    pub const CONNECT_INCOMPATIBLE_FORMAT: Status = Status::specific(0x80);
    pub const CONNECT_CONTROLLER_BUSY: Status = Status::specific(0x81).retry();
    pub const CONNECT_INVALID_PARAMETERS: Status = Status::specific(0x82);
    pub const CONNECT_INVALID_HOST: Status = Status::specific(0x84);
    pub const WRITE_FAULT: Status = Status::media(0x80);
    pub const UNRECOVERED_READ_ERROR: Status = Status::media(0x81);

    /// The 16-bit status field of a completion (phase tag 0).
    pub fn field(self) -> u16 {
        ((self.sc as u16) << 1) | (((self.sct & 7) as u16) << 9) | if self.dnr { 0x8000 } else { 0 }
    }
    pub fn from_field(f: u16) -> Self {
        Self {
            sc: (f >> 1) as u8,
            sct: ((f >> 9) & 7) as u8,
            dnr: f & 0x8000 != 0,
        }
    }
    pub fn is_success(self) -> bool {
        self.sct == 0 && self.sc == 0
    }

    /// The status as NVMe names it.
    pub fn describe(self) -> String {
        let name = match (self.sct, self.sc) {
            (0, 0x00) => "SUCCESS",
            (0, 0x01) => "INVALID COMMAND OPCODE",
            (0, 0x02) => "INVALID FIELD IN COMMAND",
            (0, 0x03) => "COMMAND ID CONFLICT",
            (0, 0x04) => "DATA TRANSFER ERROR",
            (0, 0x06) => "INTERNAL ERROR",
            (0, 0x07) => "COMMAND ABORT REQUESTED",
            (0, 0x0B) => "INVALID NAMESPACE OR FORMAT",
            (0, 0x0C) => "COMMAND SEQUENCE ERROR",
            (0, 0x0F) => "DATA SGL LENGTH INVALID",
            (0, 0x11) => "SGL DESCRIPTOR TYPE INVALID",
            (0, 0x20) => "NAMESPACE IS WRITE PROTECTED",
            (0, 0x22) => "TRANSIENT TRANSPORT ERROR",
            (0, 0x80) => "LBA OUT OF RANGE",
            (0, 0x81) => "CAPACITY EXCEEDED",
            (0, 0x82) => "NAMESPACE NOT READY",
            (1, 0x01) => "INVALID QUEUE IDENTIFIER",
            (1, 0x02) => "INVALID QUEUE SIZE",
            (1, 0x05) => "ASYNCHRONOUS EVENT REQUEST LIMIT EXCEEDED",
            (1, 0x09) => "INVALID LOG PAGE",
            (1, 0x0D) => "FEATURE IDENTIFIER NOT SAVEABLE",
            (1, 0x80) => "CONNECT INCOMPATIBLE FORMAT",
            (1, 0x81) => "CONNECT CONTROLLER BUSY",
            (1, 0x82) => "CONNECT INVALID PARAMETERS",
            (1, 0x83) => "CONNECT RESTART DISCOVERY",
            (1, 0x84) => "CONNECT INVALID HOST",
            (1, 0x91) => "AUTHENTICATION REQUIRED",
            (2, 0x80) => "WRITE FAULT",
            (2, 0x81) => "UNRECOVERED READ ERROR",
            (2, 0x86) => "ACCESS DENIED",
            _ => "",
        };
        if name.is_empty() {
            format!("STATUS TYPE {:#x} CODE {:#04x}", self.sct, self.sc)
        } else {
            name.to_string()
        }
    }
}

/// A 64-byte submission queue entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sqe(pub [u8; 64]);

impl Default for Sqe {
    fn default() -> Self {
        Self([0u8; 64])
    }
}

impl Sqe {
    pub fn new(opcode: u8, cid: u16) -> Self {
        let mut s = Self::default();
        s.0[0] = opcode;
        // PSDT: SGLs for data and metadata (NVMe over Fabrics requires SGLs).
        s.0[1] = 0x40;
        s.set_u16(2, cid);
        s
    }
    pub fn opcode(&self) -> u8 {
        self.0[0]
    }
    /// PSDT, bits 7:6 of byte 1: 0 is PRPs, which no fabric uses.
    pub fn psdt(&self) -> u8 {
        self.0[1] >> 6
    }
    pub fn fuse(&self) -> u8 {
        self.0[1] & 0x03
    }
    pub fn cid(&self) -> u16 {
        self.u16(2)
    }
    pub fn nsid(&self) -> u32 {
        self.u32(4)
    }
    pub fn set_nsid(&mut self, v: u32) {
        self.set_u32(4, v);
    }
    /// The Fabrics command type.
    pub fn fctype(&self) -> u8 {
        self.0[4]
    }
    pub fn cdw(&self, n: usize) -> u32 {
        self.u32(n * 4)
    }
    pub fn set_cdw(&mut self, n: usize, v: u32) {
        self.set_u32(n * 4, v);
    }
    pub fn u16(&self, at: usize) -> u16 {
        u16::from_le_bytes([self.0[at], self.0[at + 1]])
    }
    pub fn u32(&self, at: usize) -> u32 {
        u32::from_le_bytes(self.0[at..at + 4].try_into().expect("4 bytes"))
    }
    pub fn u64(&self, at: usize) -> u64 {
        u64::from_le_bytes(self.0[at..at + 8].try_into().expect("8 bytes"))
    }
    pub fn set_u16(&mut self, at: usize, v: u16) {
        self.0[at..at + 2].copy_from_slice(&v.to_le_bytes());
    }
    pub fn set_u32(&mut self, at: usize, v: u32) {
        self.0[at..at + 4].copy_from_slice(&v.to_le_bytes());
    }
    pub fn set_u64(&mut self, at: usize, v: u64) {
        self.0[at..at + 8].copy_from_slice(&v.to_le_bytes());
    }
    /// SGL1: (address, length, descriptor type byte).
    pub fn sgl(&self) -> (u64, u32, u8) {
        (self.u64(24), self.u32(32), self.0[39])
    }
    pub fn set_sgl(&mut self, address: u64, length: u32, kind: u8) {
        self.set_u64(24, address);
        self.set_u32(32, length);
        self.0[36..39].fill(0);
        self.0[39] = kind;
    }
    /// Starting LBA and block count (NLB + 1) of a Read, Write or Write Zeroes.
    pub fn lba_range(&self) -> (u64, u64) {
        (self.u64(40), (self.cdw(12) & 0xFFFF) as u64 + 1)
    }
}

/// A 16-byte completion queue entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cqe {
    pub dw0: u32,
    pub dw1: u32,
    pub sqhd: u16,
    pub sqid: u16,
    pub cid: u16,
    pub status: u16,
}

impl Cqe {
    pub fn encode(&self) -> [u8; 16] {
        let mut b = [0u8; 16];
        b[0..4].copy_from_slice(&self.dw0.to_le_bytes());
        b[4..8].copy_from_slice(&self.dw1.to_le_bytes());
        b[8..10].copy_from_slice(&self.sqhd.to_le_bytes());
        b[10..12].copy_from_slice(&self.sqid.to_le_bytes());
        b[12..14].copy_from_slice(&self.cid.to_le_bytes());
        b[14..16].copy_from_slice(&self.status.to_le_bytes());
        b
    }
    pub fn decode(b: &[u8]) -> Option<Self> {
        let b = b.get(..16)?;
        let u16_at = |at: usize| u16::from_le_bytes([b[at], b[at + 1]]);
        let u32_at = |at: usize| u32::from_le_bytes(b[at..at + 4].try_into().expect("4 bytes"));
        Some(Self {
            dw0: u32_at(0),
            dw1: u32_at(4),
            sqhd: u16_at(8),
            sqid: u16_at(10),
            cid: u16_at(12),
            status: u16_at(14),
        })
    }
    pub fn status(&self) -> Status {
        Status::from_field(self.status)
    }
    /// A 64-bit result (Property Get of an 8-byte property).
    pub fn result64(&self) -> u64 {
        self.dw0 as u64 | (self.dw1 as u64) << 32
    }
}

/// DW0 of a Connect completion refused with Connect Invalid Parameters: the byte offset of the
/// offending field, and bit 16 set when it is in the Connect data rather than the command.
pub fn invalid_parameter(offset: u16, in_data: bool) -> u32 {
    offset as u32 | if in_data { 1 << 16 } else { 0 }
}

/// Connect command offsets (in the SQE) and Connect data offsets.
pub mod connect {
    pub const RECFMT: u16 = 40;
    pub const QID: u16 = 42;
    pub const SQSIZE: u16 = 44;
    pub const CATTR: u16 = 46;
    pub const KATO: u16 = 48;
    pub const DATA_HOSTID: u16 = 0;
    pub const DATA_CNTLID: u16 = 16;
    pub const DATA_SUBNQN: u16 = 256;
    pub const DATA_HOSTNQN: u16 = 512;
    /// CATTR bit 2: the host asks for submission queue flow control to be disabled.
    pub const CATTR_DISABLE_SQ_FLOW: u8 = 0x04;
}

/// A Connect command and its data, decoded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectRequest {
    pub recfmt: u16,
    pub qid: u16,
    pub sqsize: u16,
    pub cattr: u8,
    pub kato_ms: u32,
    pub hostid: [u8; 16],
    pub cntlid: u16,
    /// `Err(offset)` when the field is not a NUL-terminated printable string.
    pub subnqn: Result<String, u16>,
    pub hostnqn: Result<String, u16>,
}

/// A NUL-terminated string field of `len` bytes, printable ASCII without spaces.
pub fn nqn_field(b: &[u8]) -> Option<String> {
    let end = b.iter().position(|c| *c == 0)?;
    let s = &b[..end];
    (!s.is_empty() && s.len() <= MAX_NQN && s.iter().all(|c| (0x21..0x7F).contains(c)))
        .then(|| String::from_utf8_lossy(s).into_owned())
}

/// Whether a string is an NVMe Qualified Name this side accepts: `nqn.` form, printable ASCII
/// without spaces, at most 223 bytes.
pub fn valid_nqn(nqn: &str) -> bool {
    nqn.len() > 4
        && nqn.len() <= MAX_NQN
        && nqn.starts_with("nqn.")
        && nqn.bytes().all(|c| (0x21..0x7F).contains(&c))
}

impl ConnectRequest {
    pub fn decode(sqe: &Sqe, data: &[u8]) -> Option<Self> {
        if data.len() < CONNECT_DATA_LEN {
            return None;
        }
        let field = |at: usize, offset: u16| {
            nqn_field(&data[at..at + NQN_FIELD])
                .filter(|s| valid_nqn(s))
                .ok_or(offset)
        };
        Some(Self {
            recfmt: sqe.u16(connect::RECFMT as usize),
            qid: sqe.u16(connect::QID as usize),
            sqsize: sqe.u16(connect::SQSIZE as usize),
            cattr: sqe.0[connect::CATTR as usize],
            kato_ms: sqe.u32(connect::KATO as usize),
            hostid: data[0..16].try_into().expect("16 bytes"),
            cntlid: u16::from_le_bytes([data[16], data[17]]),
            subnqn: field(256, connect::DATA_SUBNQN),
            hostnqn: field(512, connect::DATA_HOSTNQN),
        })
    }
}

/// The Connect data a host sends.
pub fn connect_data(hostid: &[u8; 16], cntlid: u16, subnqn: &str, hostnqn: &str) -> Vec<u8> {
    let mut d = vec![0u8; CONNECT_DATA_LEN];
    d[0..16].copy_from_slice(hostid);
    d[16..18].copy_from_slice(&cntlid.to_le_bytes());
    let n = subnqn.len().min(NQN_FIELD - 1);
    d[256..256 + n].copy_from_slice(&subnqn.as_bytes()[..n]);
    let n = hostnqn.len().min(NQN_FIELD - 1);
    d[512..512 + n].copy_from_slice(&hostnqn.as_bytes()[..n]);
    d
}

/// A host identifier as the UUID text form.
pub fn uuid_text(b: &[u8; 16]) -> String {
    let h = hex::encode(b);
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

/// ASCII, space padded to `len` (SN, MN, FR, and the discovery entry's address fields).
pub fn put_padded(out: &mut [u8], s: &str) {
    out.fill(b' ');
    let n = s.len().min(out.len());
    out[..n].copy_from_slice(&s.as_bytes()[..n]);
}

/// NUL padded (NQN fields).
pub fn put_nul_padded(out: &mut [u8], s: &str) {
    out.fill(0);
    let n = s.len().min(out.len().saturating_sub(1));
    out[..n].copy_from_slice(&s.as_bytes()[..n]);
}

/// A space- or NUL-padded ASCII field as text, controls replaced.
pub fn text_field(b: &[u8]) -> String {
    let end = b.iter().position(|c| *c == 0).unwrap_or(b.len());
    crate::utils::sanitize::line_field(&String::from_utf8_lossy(&b[..end]))
        .trim()
        .to_string()
}

/// The NVMe version this target reports (VS and Identify Controller VER): 1.4.0.
pub const VERSION: u32 = 0x0001_0400;

pub fn version_text(vs: u32) -> String {
    let (major, minor, ter) = (vs >> 16, (vs >> 8) & 0xFF, vs & 0xFF);
    format!("{major}.{minor}.{ter}")
}

// ---------------------------------------------------------------- discovery log

/// One discovery log page entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiscoveryEntry {
    pub trtype: u8,
    pub adrfam: u8,
    pub subtype: u8,
    pub treq: u8,
    pub portid: u16,
    pub cntlid: u16,
    pub asqsz: u16,
    pub trsvcid: String,
    pub subnqn: String,
    pub traddr: String,
    pub sectype: u8,
}

pub const TRTYPE_TCP: u8 = 3;
pub const ADRFAM_IPV4: u8 = 1;
pub const ADRFAM_IPV6: u8 = 2;
pub const SUBTYPE_REFERRAL: u8 = 1;
pub const SUBTYPE_NVME: u8 = 2;
pub const SUBTYPE_CURRENT_DISCOVERY: u8 = 3;
/// TREQ: secure channel not required.
pub const TREQ_NOT_REQUIRED: u8 = 0x02;

impl DiscoveryEntry {
    pub fn encode(&self) -> [u8; DISCOVERY_RECORD_LEN] {
        let mut e = [0u8; DISCOVERY_RECORD_LEN];
        e[0] = self.trtype;
        e[1] = self.adrfam;
        e[2] = self.subtype;
        e[3] = self.treq;
        e[4..6].copy_from_slice(&self.portid.to_le_bytes());
        e[6..8].copy_from_slice(&self.cntlid.to_le_bytes());
        e[8..10].copy_from_slice(&self.asqsz.to_le_bytes());
        put_padded(&mut e[32..64], &self.trsvcid);
        put_nul_padded(&mut e[256..512], &self.subnqn);
        put_padded(&mut e[512..768], &self.traddr);
        e[768] = self.sectype;
        e
    }
    pub fn decode(e: &[u8]) -> Option<Self> {
        let e = e.get(..DISCOVERY_RECORD_LEN)?;
        Some(Self {
            trtype: e[0],
            adrfam: e[1],
            subtype: e[2],
            treq: e[3],
            portid: u16::from_le_bytes([e[4], e[5]]),
            cntlid: u16::from_le_bytes([e[6], e[7]]),
            asqsz: u16::from_le_bytes([e[8], e[9]]),
            trsvcid: text_field(&e[32..64]),
            subnqn: text_field(&e[256..512]),
            traddr: text_field(&e[512..768]),
            sectype: e[768],
        })
    }
    pub fn trtype_name(&self) -> &'static str {
        match self.trtype {
            1 => "rdma",
            2 => "fc",
            3 => "tcp",
            254 => "loop",
            _ => "unknown",
        }
    }
    pub fn adrfam_name(&self) -> &'static str {
        match self.adrfam {
            1 => "ipv4",
            2 => "ipv6",
            3 => "ib",
            4 => "fc",
            254 => "loop",
            _ => "unknown",
        }
    }
    pub fn subtype_name(&self) -> &'static str {
        match self.subtype {
            1 => "referral",
            2 => "nvme subsystem",
            3 => "current discovery subsystem",
            _ => "unknown",
        }
    }
}

/// A discovery log page: the 1024-byte header (generation counter, record count, format) and
/// the entries.
pub fn discovery_log(genctr: u64, entries: &[DiscoveryEntry]) -> Vec<u8> {
    let mut out = vec![0u8; DISCOVERY_RECORD_LEN * (1 + entries.len())];
    out[0..8].copy_from_slice(&genctr.to_le_bytes());
    out[8..16].copy_from_slice(&(entries.len() as u64).to_le_bytes());
    for (i, e) in entries.iter().enumerate() {
        let at = DISCOVERY_RECORD_LEN * (i + 1);
        out[at..at + DISCOVERY_RECORD_LEN].copy_from_slice(&e.encode());
    }
    out
}

/// A discovery log page header: (generation counter, number of records, record format).
pub fn discovery_header(b: &[u8]) -> Option<(u64, u64, u16)> {
    let b = b.get(..18)?;
    Some((
        u64::from_le_bytes(b[0..8].try_into().expect("8 bytes")),
        u64::from_le_bytes(b[8..16].try_into().expect("8 bytes")),
        u16::from_le_bytes([b[16], b[17]]),
    ))
}

// ------------------------------------------------------------- identify decoders

/// What a host reports of Identify Controller.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ControllerInfo {
    pub vid: u16,
    pub serial: String,
    pub model: String,
    pub firmware: String,
    pub mdts: u8,
    pub cntlid: u16,
    pub version: u32,
    pub cntrltype: u8,
    pub kas: u16,
    pub sgls: u32,
    pub maxcmd: u16,
    pub nn: u32,
    pub oncs: u16,
    pub vwc: u8,
    pub subnqn: String,
    pub ioccsz: u32,
    pub iorcsz: u32,
    pub icdoff: u16,
    pub aerl: u8,
    pub lpa: u8,
}

impl ControllerInfo {
    pub fn decode(b: &[u8]) -> Option<Self> {
        let b = b.get(..IDENTIFY_LEN)?;
        let u16_at = |at: usize| u16::from_le_bytes([b[at], b[at + 1]]);
        let u32_at = |at: usize| u32::from_le_bytes(b[at..at + 4].try_into().expect("4 bytes"));
        Some(Self {
            vid: u16_at(0),
            serial: text_field(&b[4..24]),
            model: text_field(&b[24..64]),
            firmware: text_field(&b[64..72]),
            mdts: b[77],
            cntlid: u16_at(78),
            version: u32_at(80),
            cntrltype: b[111],
            aerl: b[259],
            lpa: b[261],
            kas: u16_at(320),
            maxcmd: u16_at(514),
            nn: u32_at(516),
            oncs: u16_at(520),
            vwc: b[525],
            sgls: u32_at(536),
            subnqn: text_field(&b[768..1024]),
            ioccsz: u32_at(1792),
            iorcsz: u32_at(1796),
            icdoff: u16_at(1800),
        })
    }
    pub fn controller_type(&self) -> &'static str {
        match self.cntrltype {
            1 => "io",
            2 => "discovery",
            3 => "administrative",
            _ => "not reported",
        }
    }
}

/// What a host reports of Identify Namespace.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NamespaceInfo {
    pub nsze: u64,
    pub ncap: u64,
    pub nuse: u64,
    pub block_size: u64,
    pub write_protected: bool,
    pub shared: bool,
    pub nguid: [u8; 16],
    pub eui64: [u8; 8],
}

impl NamespaceInfo {
    pub fn decode(b: &[u8]) -> Option<Self> {
        let b = b.get(..IDENTIFY_LEN)?;
        let u64_at = |at: usize| u64::from_le_bytes(b[at..at + 8].try_into().expect("8 bytes"));
        let format = (b[26] & 0x0F) as usize;
        let lbaf = &b[128 + format * 4..128 + format * 4 + 4];
        let lbads = lbaf[2];
        Some(Self {
            nsze: u64_at(0),
            ncap: u64_at(8),
            nuse: u64_at(16),
            // A data size below 2^9 is not a valid format; report it as given (0 when absent).
            block_size: if (9..=31).contains(&lbads) {
                1u64 << lbads
            } else {
                0
            },
            write_protected: b[99] & 1 != 0,
            shared: b[30] & 1 != 0,
            nguid: b[104..120].try_into().expect("16 bytes"),
            eui64: b[120..128].try_into().expect("8 bytes"),
        })
    }
}

/// The namespace IDs of an active namespace list (zero-terminated, at most 1024).
pub fn parse_ns_list(b: &[u8]) -> Vec<u32> {
    b.chunks_exact(4)
        .take(1024)
        .map(|c| u32::from_le_bytes(c.try_into().expect("4 bytes")))
        .take_while(|n| *n != 0)
        .collect()
}

/// Namespace identification descriptors: (type name, value as text). The walk is a loop over
/// a bounded buffer, never a recursion, and stops at a zero type or a length past the end.
pub fn parse_ns_descriptors(b: &[u8]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut at = 0;
    while at + 4 <= b.len() && out.len() < 64 {
        let (t, len) = (b[at], b[at + 1] as usize);
        if t == 0 || len == 0 || at + 4 + len > b.len() {
            break;
        }
        let v = &b[at + 4..at + 4 + len];
        let (name, value) = match t {
            1 => ("eui64", hex::encode(v)),
            2 => ("nguid", hex::encode(v)),
            3 if v.len() == 16 => ("uuid", uuid_text(v.try_into().expect("16 bytes"))),
            4 => ("csi", format!("{}", v[0])),
            _ => ("unknown", hex::encode(v)),
        };
        out.push((name.to_string(), value));
        at += 4 + len;
    }
    out
}

/// The SMART / Health Information log, the fields a person reads.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Smart {
    pub critical_warning: u8,
    pub temperature_kelvin: u16,
    pub available_spare: u8,
    pub percentage_used: u8,
    pub data_units_read: u128,
    pub data_units_written: u128,
    pub host_read_commands: u128,
    pub host_write_commands: u128,
    pub power_on_hours: u128,
    pub media_errors: u128,
}

impl Smart {
    pub fn encode(&self) -> Vec<u8> {
        let mut b = vec![0u8; 512];
        b[0] = self.critical_warning;
        b[1..3].copy_from_slice(&self.temperature_kelvin.to_le_bytes());
        b[3] = self.available_spare;
        b[4] = 10; // available spare threshold
        b[5] = self.percentage_used;
        b[32..48].copy_from_slice(&self.data_units_read.to_le_bytes());
        b[48..64].copy_from_slice(&self.data_units_written.to_le_bytes());
        b[64..80].copy_from_slice(&self.host_read_commands.to_le_bytes());
        b[80..96].copy_from_slice(&self.host_write_commands.to_le_bytes());
        b[128..144].copy_from_slice(&self.power_on_hours.to_le_bytes());
        b[160..176].copy_from_slice(&self.media_errors.to_le_bytes());
        b
    }
    pub fn decode(b: &[u8]) -> Option<Self> {
        let b = b.get(..512)?;
        let u128_at = |at: usize| u128::from_le_bytes(b[at..at + 16].try_into().expect("16 bytes"));
        Some(Self {
            critical_warning: b[0],
            temperature_kelvin: u16::from_le_bytes([b[1], b[2]]),
            available_spare: b[3],
            percentage_used: b[5],
            data_units_read: u128_at(32),
            data_units_written: u128_at(48),
            host_read_commands: u128_at(64),
            host_write_commands: u128_at(80),
            power_on_hours: u128_at(128),
            media_errors: u128_at(160),
        })
    }
}

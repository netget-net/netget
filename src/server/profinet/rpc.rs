//! Connectionless DCE/RPC (the "dg" protocol, UDP) as PROFINET IO uses it — the pure codec.
//!
//! Every PNIO-CM operation (Connect, Release, Read, Write, Control, ReadImplicit) is one RPC
//! request and one response on UDP port 34964. The datagram is an 80-octet header followed by
//! the body:
//!
//! ```text
//! rpc_vers(1)=4 ptype(1) flags1(1) flags2(1) drep(3) serial_hi(1)
//! object(16) interface(16) activity(16)
//! server_boot(4) if_vers(4) seqnum(4) opnum(2) ihint(2) ahint(2)
//! len(2) fragnum(2) auth_proto(1) serial_lo(1)
//! ```
//!
//! `drep[0]`'s high nibble says how the header's integers (and the UUIDs' first three fields)
//! are ordered: `0x10` little-endian, `0x00` big-endian. The PNIO body starts with an NDR
//! header in the same order — for a request ArgsMaximum, ArgsLength, MaximumCount, Offset,
//! ActualCount; for a response PNIOStatus, ArgsLength, MaximumCount, Offset, ActualCount — and
//! then the PNIO blocks, which are **always** big-endian whatever drep says.
//!
//! Fragmentation is not implemented in either direction: a PNIO Connect for the layouts this
//! module accepts fits one datagram, and a fragmented request is refused rather than buffered.
use anyhow::{ensure, Context, Result};

pub const RPC_PORT: u16 = 34964;
pub const HEADER_LEN: usize = 80;
/// The largest RPC body accepted or produced: one UDP datagram on an Ethernet link, less the
/// IP (20), UDP (8) and RPC (80) headers.
pub const MAX_BODY_LEN: usize = 1500 - 20 - 8 - HEADER_LEN;
/// The NDR header in front of the PNIO blocks (five 32-bit words).
pub const NDR_HEADER_LEN: usize = 20;

pub mod ptype {
    pub const REQUEST: u8 = 0;
    pub const PING: u8 = 1;
    pub const RESPONSE: u8 = 2;
    pub const FAULT: u8 = 3;
    pub const WORKING: u8 = 4;
    pub const NOCALL: u8 = 5;
    pub const REJECT: u8 = 6;
    pub const ACK: u8 = 7;
    pub const CL_CANCEL: u8 = 8;
    pub const FACK: u8 = 9;
    pub const CANCEL_ACK: u8 = 10;
}

pub mod flags1 {
    pub const LAST_FRAGMENT: u8 = 0x02;
    pub const FRAGMENT: u8 = 0x04;
    pub const NO_FACK: u8 = 0x08;
    pub const MAYBE: u8 = 0x10;
    pub const IDEMPOTENT: u8 = 0x20;
    pub const BROADCAST: u8 = 0x40;
}

pub mod opnum {
    pub const CONNECT: u16 = 0;
    pub const RELEASE: u16 = 1;
    pub const READ: u16 = 2;
    pub const WRITE: u16 = 3;
    pub const CONTROL: u16 = 4;
    pub const READ_IMPLICIT: u16 = 5;

    pub fn name(op: u16) -> &'static str {
        match op {
            CONNECT => "Connect",
            RELEASE => "Release",
            READ => "Read",
            WRITE => "Write",
            CONTROL => "Control",
            READ_IMPLICIT => "ReadImplicit",
            _ => "unknown",
        }
    }
}

/// `nca_s_op_rng_error`: the opnum is outside the interface.
pub const NCA_OP_RANGE_ERROR: u32 = 0x1c01_0002;
/// `nca_s_unk_if`: the interface UUID is not one this server exports.
pub const NCA_UNKNOWN_INTERFACE: u32 = 0x1c01_0003;
/// `nca_s_proto_error`: what a fragmented request is refused with.
pub const NCA_PROTO_ERROR: u32 = 0x1c01_000b;

/// A UUID in its canonical (string-order, big-endian) byte layout.
pub type Uuid = [u8; 16];

const fn pnio_uuid(first: u32) -> Uuid {
    let f = first.to_be_bytes();
    [
        f[0], f[1], f[2], f[3], 0x6c, 0x97, 0x11, 0xd1, 0x82, 0x71, 0x00, 0xa0, 0x24, 0x42, 0xdf,
        0x7d,
    ]
}

/// PNIO IO-device interface (`DEA00001-6C97-11D1-8271-00A02442DF7D`).
pub const IF_DEVICE: Uuid = pnio_uuid(0xdea0_0001);
/// PNIO IO-controller interface (`DEA00002-…`), the target of a device's CControl request.
pub const IF_CONTROLLER: Uuid = pnio_uuid(0xdea0_0002);

/// A PNIO object UUID: `DEA00000-6C97-11D1-8271-<instance><device id><vendor id>`.
pub fn object_uuid(instance: u16, device_id: u16, vendor_id: u16) -> Uuid {
    let mut u = pnio_uuid(0xdea0_0000);
    u[10..12].copy_from_slice(&instance.to_be_bytes());
    u[12..14].copy_from_slice(&device_id.to_be_bytes());
    u[14..16].copy_from_slice(&vendor_id.to_be_bytes());
    u
}

pub fn format_uuid(u: &Uuid) -> String {
    let h: Vec<String> = u.iter().map(|b| format!("{b:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        h[0..4].concat(),
        h[4..6].concat(),
        h[6..8].concat(),
        h[8..10].concat(),
        h[10..16].concat()
    )
}

pub fn parse_uuid(text: &str) -> Result<Uuid> {
    let hex: String = text.chars().filter(|c| *c != '-').collect();
    ensure!(hex.len() == 32, "UUID {text:?} must have 32 hex digits");
    let mut u = [0u8; 16];
    for (i, b) in u.iter_mut().enumerate() {
        *b = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .with_context(|| format!("UUID {text:?} is not hex"))?;
    }
    Ok(u)
}

/// A fresh random (version 4) UUID.
pub fn random_uuid() -> Uuid {
    *uuid::Uuid::new_v4().as_bytes()
}

/// The 80-octet connectionless RPC header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub ptype: u8,
    pub flags1: u8,
    pub flags2: u8,
    /// True when drep says little-endian (`drep[0] & 0xf0 == 0x10`).
    pub little_endian: bool,
    pub serial_hi: u8,
    pub object: Uuid,
    pub interface: Uuid,
    pub activity: Uuid,
    pub server_boot: u32,
    pub if_version: u32,
    pub seqnum: u32,
    pub opnum: u16,
    pub ihint: u16,
    pub ahint: u16,
    pub body_len: u16,
    pub fragnum: u16,
    pub auth_proto: u8,
    pub serial_lo: u8,
}

impl Header {
    pub fn request(object: Uuid, interface: Uuid, activity: Uuid, seqnum: u32, op: u16) -> Self {
        Self {
            ptype: ptype::REQUEST,
            flags1: flags1::IDEMPOTENT,
            flags2: 0,
            little_endian: false,
            serial_hi: 0,
            object,
            interface,
            activity,
            server_boot: 0,
            if_version: 1,
            seqnum,
            opnum: op,
            ihint: 0xffff,
            ahint: 0xffff,
            body_len: 0,
            fragnum: 0,
            auth_proto: 0,
            serial_lo: 0,
        }
    }

    /// The header of the response to this request: same object, interface, activity,
    /// sequence number and opnum; big-endian; one unfragmented PDU.
    pub fn response_to(&self, ptype_value: u8, server_boot: u32) -> Self {
        Self {
            ptype: ptype_value,
            flags1: flags1::NO_FACK | flags1::IDEMPOTENT,
            flags2: 0,
            little_endian: false,
            serial_hi: 0,
            object: self.object,
            interface: self.interface,
            activity: self.activity,
            server_boot,
            if_version: self.if_version,
            seqnum: self.seqnum,
            opnum: self.opnum,
            ihint: 0xffff,
            ahint: 0xffff,
            body_len: 0,
            fragnum: 0,
            auth_proto: 0,
            serial_lo: 0,
        }
    }

    pub fn is_fragmented(&self) -> bool {
        self.flags1 & flags1::FRAGMENT != 0 || self.fragnum != 0
    }
}

fn put_u16(out: &mut Vec<u8>, le: bool, v: u16) {
    out.extend_from_slice(&if le { v.to_le_bytes() } else { v.to_be_bytes() });
}

fn put_u32(out: &mut Vec<u8>, le: bool, v: u32) {
    out.extend_from_slice(&if le { v.to_le_bytes() } else { v.to_be_bytes() });
}

fn put_uuid(out: &mut Vec<u8>, le: bool, u: &Uuid) {
    if le {
        out.extend_from_slice(&[u[3], u[2], u[1], u[0], u[5], u[4], u[7], u[6]]);
        out.extend_from_slice(&u[8..]);
    } else {
        out.extend_from_slice(u);
    }
}

fn get_u16(b: &[u8], le: bool) -> u16 {
    let a = [b[0], b[1]];
    if le {
        u16::from_le_bytes(a)
    } else {
        u16::from_be_bytes(a)
    }
}

fn get_u32(b: &[u8], le: bool) -> u32 {
    let a = [b[0], b[1], b[2], b[3]];
    if le {
        u32::from_le_bytes(a)
    } else {
        u32::from_be_bytes(a)
    }
}

fn get_uuid(b: &[u8], le: bool) -> Uuid {
    let mut u = [0u8; 16];
    u.copy_from_slice(&b[..16]);
    if le {
        u[0..4].reverse();
        u[4..6].reverse();
        u[6..8].reverse();
    }
    u
}

/// Encode a datagram: the header (its `body_len` set from `body`) and the body.
pub fn encode(header: &Header, body: &[u8]) -> Result<Vec<u8>> {
    ensure!(
        body.len() <= MAX_BODY_LEN,
        "RPC body of {} octets exceeds the {MAX_BODY_LEN} one datagram carries",
        body.len()
    );
    let le = header.little_endian;
    let mut out = Vec::with_capacity(HEADER_LEN + body.len());
    out.push(4);
    out.push(header.ptype);
    out.push(header.flags1);
    out.push(header.flags2);
    out.extend_from_slice(&[if le { 0x10 } else { 0x00 }, 0x00, 0x00]);
    out.push(header.serial_hi);
    put_uuid(&mut out, le, &header.object);
    put_uuid(&mut out, le, &header.interface);
    put_uuid(&mut out, le, &header.activity);
    put_u32(&mut out, le, header.server_boot);
    put_u32(&mut out, le, header.if_version);
    put_u32(&mut out, le, header.seqnum);
    put_u16(&mut out, le, header.opnum);
    put_u16(&mut out, le, header.ihint);
    put_u16(&mut out, le, header.ahint);
    put_u16(&mut out, le, body.len() as u16);
    put_u16(&mut out, le, header.fragnum);
    out.push(header.auth_proto);
    out.push(header.serial_lo);
    out.extend_from_slice(body);
    Ok(out)
}

/// Parse a datagram into its header and body. The body is exactly `len` octets; a datagram
/// shorter than that is refused, longer is trimmed.
pub fn parse(datagram: &[u8]) -> Result<(Header, &[u8])> {
    ensure!(
        datagram.len() >= HEADER_LEN,
        "RPC datagram of {} octets is shorter than the 80-octet header",
        datagram.len()
    );
    ensure!(
        datagram[0] == 4,
        "RPC version {} is not connectionless DCE/RPC (4)",
        datagram[0]
    );
    let le = datagram[4] & 0xf0 == 0x10;
    let body_len = get_u16(&datagram[74..], le);
    ensure!(
        body_len as usize <= MAX_BODY_LEN,
        "RPC body length {body_len} exceeds the {MAX_BODY_LEN} one datagram carries"
    );
    let body = datagram
        .get(HEADER_LEN..HEADER_LEN + body_len as usize)
        .with_context(|| {
            format!(
                "RPC header declares a {body_len}-octet body but {} octets follow it",
                datagram.len() - HEADER_LEN
            )
        })?;
    Ok((
        Header {
            ptype: datagram[1],
            flags1: datagram[2],
            flags2: datagram[3],
            little_endian: le,
            serial_hi: datagram[7],
            object: get_uuid(&datagram[8..], le),
            interface: get_uuid(&datagram[24..], le),
            activity: get_uuid(&datagram[40..], le),
            server_boot: get_u32(&datagram[56..], le),
            if_version: get_u32(&datagram[60..], le),
            seqnum: get_u32(&datagram[64..], le),
            opnum: get_u16(&datagram[68..], le),
            ihint: get_u16(&datagram[70..], le),
            ahint: get_u16(&datagram[72..], le),
            body_len,
            fragnum: get_u16(&datagram[76..], le),
            auth_proto: datagram[78],
            serial_lo: datagram[79],
        },
        body,
    ))
}

/// PNIOStatus: ErrorCode, ErrorDecode, ErrorCode1, ErrorCode2. All zero is success.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PnioStatus {
    pub code: u8,
    pub decode: u8,
    pub code1: u8,
    pub code2: u8,
}

impl PnioStatus {
    pub const OK: PnioStatus = PnioStatus {
        code: 0,
        decode: 0,
        code1: 0,
        code2: 0,
    };

    pub const fn new(code: u8, decode: u8, code1: u8, code2: u8) -> Self {
        Self {
            code,
            decode,
            code1,
            code2,
        }
    }

    pub fn is_ok(&self) -> bool {
        *self == Self::OK
    }

    pub fn to_u32(self) -> u32 {
        u32::from_be_bytes([self.code, self.decode, self.code1, self.code2])
    }

    pub fn from_u32(v: u32) -> Self {
        let [code, decode, code1, code2] = v.to_be_bytes();
        Self {
            code,
            decode,
            code1,
            code2,
        }
    }

    pub fn describe(&self) -> String {
        format!(
            "{:02X}{:02X}{:02X}{:02X} ({})",
            self.code,
            self.decode,
            self.code1,
            self.code2,
            status_text(*self)
        )
    }
}

/// ErrorCode values (which service failed).
pub mod error_code {
    pub const RTA_ERROR: u8 = 0xcf;
    pub const ALARM_ACK: u8 = 0xda;
    pub const CONNECT: u8 = 0xdb;
    pub const RELEASE: u8 = 0xdc;
    pub const CONTROL: u8 = 0xdd;
    pub const READ: u8 = 0xde;
    pub const WRITE: u8 = 0xdf;
}

/// ErrorDecode values.
pub mod error_decode {
    /// Record services (Read/Write): ErrorCode1 is an IODReadRes/IODWriteRes error class.
    pub const PNIORW: u8 = 0x80;
    /// Connection services: ErrorCode1 names the block (or the CM state machine) at fault.
    pub const PNIO: u8 = 0x81;
}

/// ErrorCode1 values with ErrorDecode PNIO (0x81): the block or machine that refused.
pub mod connect_error {
    pub const AR_BLOCK_REQ: u8 = 0x01;
    pub const IOCR_BLOCK_REQ: u8 = 0x02;
    pub const EXPECTED_SUBMODULE_BLOCK_REQ: u8 = 0x03;
    pub const ALARM_CR_BLOCK_REQ: u8 = 0x04;
    pub const CONTROL_BLOCK: u8 = 0x08;
    pub const RELEASE_BLOCK: u8 = 0x09;
    pub const READ_WRITE_HEADER: u8 = 0x0c;
    /// "CMRPC": the RPC layer itself (ErrorCode2 4 = out of AR resources, 5 = AR UUID unknown).
    pub const CMRPC: u8 = 0x3d;
    /// "RMPM": the responder's AR protocol machine — the code a device answers with when it
    /// (here: the model) declines an otherwise well-formed Connect.
    pub const RMPM: u8 = 0x40;
    pub const CMDEV: u8 = 0x3f;
}

/// ErrorCode1 values with ErrorDecode PNIORW (0x80), high nibble class, low nibble code.
pub mod rw_error {
    /// Application: read error.
    pub const APP_READ_ERROR: u8 = 0xa0;
    /// Application: write error.
    pub const APP_WRITE_ERROR: u8 = 0xa1;
    /// Access: invalid index.
    pub const ACCESS_INVALID_INDEX: u8 = 0xb0;
    /// Access: write length error.
    pub const ACCESS_WRITE_LENGTH: u8 = 0xb1;
    /// Access: invalid slot/subslot.
    pub const ACCESS_INVALID_SLOT: u8 = 0xb2;
    /// Access: access denied.
    pub const ACCESS_DENIED: u8 = 0xb6;
    /// Access: invalid range (a value the device will not take).
    pub const ACCESS_INVALID_RANGE: u8 = 0xb7;
    /// Resource: resource unavailable (the answer when nobody decided).
    pub const RESOURCE_UNAVAILABLE: u8 = 0xc3;
}

pub fn status_text(s: PnioStatus) -> &'static str {
    if s.is_ok() {
        return "ok";
    }
    match (s.decode, s.code1) {
        (error_decode::PNIORW, rw_error::APP_READ_ERROR) => "application read error",
        (error_decode::PNIORW, rw_error::APP_WRITE_ERROR) => "application write error",
        (error_decode::PNIORW, rw_error::ACCESS_INVALID_INDEX) => "invalid index",
        (error_decode::PNIORW, rw_error::ACCESS_WRITE_LENGTH) => "write length error",
        (error_decode::PNIORW, rw_error::ACCESS_INVALID_SLOT) => "invalid slot/subslot",
        (error_decode::PNIORW, rw_error::ACCESS_DENIED) => "access denied",
        (error_decode::PNIORW, rw_error::ACCESS_INVALID_RANGE) => "invalid range",
        (error_decode::PNIORW, rw_error::RESOURCE_UNAVAILABLE) => "resource unavailable",
        (error_decode::PNIO, connect_error::AR_BLOCK_REQ) => "faulty ARBlockReq",
        (error_decode::PNIO, connect_error::IOCR_BLOCK_REQ) => "faulty IOCRBlockReq",
        (error_decode::PNIO, connect_error::EXPECTED_SUBMODULE_BLOCK_REQ) => {
            "faulty ExpectedSubmoduleBlockReq"
        }
        (error_decode::PNIO, connect_error::ALARM_CR_BLOCK_REQ) => "faulty AlarmCRBlockReq",
        (error_decode::PNIO, connect_error::CONTROL_BLOCK) => "faulty IODControlReq",
        (error_decode::PNIO, connect_error::RELEASE_BLOCK) => "faulty IODReleaseReq",
        (error_decode::PNIO, connect_error::CMRPC) => "CMRPC refused (resources or unknown AR)",
        (error_decode::PNIO, connect_error::RMPM) => "RMPM refused the AR",
        (error_decode::PNIO, connect_error::CMDEV) => "CMDEV state conflict",
        _ => "error",
    }
}

/// The NDR header in front of a request's blocks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NdrRequest {
    pub args_maximum: u32,
    pub args_length: u32,
    pub maximum_count: u32,
    pub offset: u32,
    pub actual_count: u32,
}

/// Wrap request blocks in the NDR header, big-endian (the drep [`Header::request`] uses).
pub fn ndr_request(args_maximum: u32, blocks: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(NDR_HEADER_LEN + blocks.len());
    let len = blocks.len() as u32;
    for v in [args_maximum.max(len), len, args_maximum.max(len), 0, len] {
        out.extend_from_slice(&v.to_be_bytes());
    }
    out.extend_from_slice(blocks);
    out
}

/// Split a request body into its NDR header and the blocks. ArgsLength and ActualCount must
/// agree with each other and with what is present; ArgsMaximum bounds the response.
pub fn parse_ndr_request(body: &[u8], le: bool) -> Result<(NdrRequest, &[u8])> {
    ensure!(
        body.len() >= NDR_HEADER_LEN,
        "PNIO request body of {} octets is shorter than its 20-octet NDR header",
        body.len()
    );
    let w = |i: usize| get_u32(&body[i * 4..], le);
    let ndr = NdrRequest {
        args_maximum: w(0),
        args_length: w(1),
        maximum_count: w(2),
        offset: w(3),
        actual_count: w(4),
    };
    ensure!(
        ndr.offset == 0,
        "NDR array offset {} is not 0, which PNIO never sends",
        ndr.offset
    );
    ensure!(
        ndr.actual_count == ndr.args_length,
        "NDR ActualCount {} disagrees with ArgsLength {}",
        ndr.actual_count,
        ndr.args_length
    );
    ensure!(
        ndr.args_length <= ndr.args_maximum && ndr.actual_count <= ndr.maximum_count,
        "NDR ArgsLength {} exceeds ArgsMaximum {} or MaximumCount {}",
        ndr.args_length,
        ndr.args_maximum,
        ndr.maximum_count
    );
    let blocks = body
        .get(NDR_HEADER_LEN..NDR_HEADER_LEN + ndr.args_length as usize)
        .with_context(|| {
            format!(
                "NDR ArgsLength {} runs past the {} octets of the body",
                ndr.args_length,
                body.len() - NDR_HEADER_LEN
            )
        })?;
    Ok((ndr, blocks))
}

/// A response body: PNIOStatus, the NDR array header, the blocks — big-endian.
pub fn ndr_response(status: PnioStatus, args_maximum: u32, blocks: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(NDR_HEADER_LEN + blocks.len());
    let len = blocks.len() as u32;
    for v in [status.to_u32(), len, args_maximum.max(len), 0, len] {
        out.extend_from_slice(&v.to_be_bytes());
    }
    out.extend_from_slice(blocks);
    out
}

/// Split a response body into PNIOStatus and its blocks.
pub fn parse_ndr_response(body: &[u8], le: bool) -> Result<(PnioStatus, &[u8])> {
    ensure!(
        body.len() >= NDR_HEADER_LEN,
        "PNIO response body of {} octets is shorter than its 20-octet NDR header",
        body.len()
    );
    let status = PnioStatus::from_u32(get_u32(body, le));
    let args_length = get_u32(&body[4..], le) as usize;
    let maximum_count = get_u32(&body[8..], le) as usize;
    let offset = get_u32(&body[12..], le);
    let actual_count = get_u32(&body[16..], le) as usize;
    ensure!(
        offset == 0 && actual_count == args_length && args_length <= maximum_count,
        "NDR response header disagrees with itself: ArgsLength {args_length}, MaximumCount \
         {maximum_count}, Offset {offset}, ActualCount {actual_count}"
    );
    let blocks = body
        .get(NDR_HEADER_LEN..NDR_HEADER_LEN + args_length)
        .with_context(|| {
            format!(
                "NDR ArgsLength {args_length} runs past the {} octets of the response",
                body.len() - NDR_HEADER_LEN
            )
        })?;
    Ok((status, blocks))
}

/// The body of a FAULT or REJECT PDU: one NCA status code in the header's byte order.
pub fn fault_body(status: u32) -> Vec<u8> {
    status.to_be_bytes().to_vec()
}

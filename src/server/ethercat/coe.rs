//! The mailbox and CoE (CANopen over EtherCAT, ETG.1000.6 §5.6): the 6-octet mailbox header,
//! the 2-octet CoE header, and the SDO services — expedited, normal and segmented upload and
//! download, and the abort — in both directions (a slave answers requests, a master builds
//! them and reads the answers).
//!
//! ```text
//! mailbox header  u16 length (of what follows) | u16 address | u8 channel:6 priority:2 |
//!                 u8 type:4 counter:3 reserved:1
//! CoE header      u16 number:9 reserved:3 service:4   (service 2 = SDO request, 3 = response)
//! SDO             u8 command | u16 index | u8 subindex | 4 octets (data, or the complete size)
//! SDO segment     u8 command | up to mailbox-size − 9 octets of data (at least 7, padded)
//! ```
use anyhow::{bail, ensure, Result};

pub const HEADER_LEN: usize = 6;
pub const COE_HEADER_LEN: usize = 2;
/// CoE header + SDO command, index, subindex and four data octets.
pub const SDO_LEN: usize = 10;
/// Mailbox types.
pub mod mbx_type {
    pub const ERROR: u8 = 0x00;
    pub const AOE: u8 = 0x01;
    pub const EOE: u8 = 0x02;
    pub const COE: u8 = 0x03;
    pub const FOE: u8 = 0x04;
    pub const SOE: u8 = 0x05;
    pub const VOE: u8 = 0x0F;
}
/// CoE services.
pub mod service {
    pub const EMERGENCY: u8 = 1;
    pub const SDO_REQUEST: u8 = 2;
    pub const SDO_RESPONSE: u8 = 3;
    pub const SDO_INFO: u8 = 8;
}
/// Mailbox error details (a type-0 reply).
pub mod mbx_error {
    pub const SYNTAX: u16 = 0x0001;
    pub const UNSUPPORTED_PROTOCOL: u16 = 0x0002;
    pub const SERVICE_NOT_SUPPORTED: u16 = 0x0004;
    pub const INVALID_HEADER: u16 = 0x0005;
    pub const SIZE_TOO_SHORT: u16 = 0x0006;
    pub const INVALID_SIZE: u16 = 0x0008;
}

/// The objects NetGet's slaves keep their process data in: inputs at 0x6000:1.., outputs at
/// 0x7000:1.., mapped by PDOs 0x1A00 and 0x1600.
pub const INPUT_OBJECT: u16 = 0x6000;
pub const OUTPUT_OBJECT: u16 = 0x7000;
pub const TXPDO_MAPPING: u16 = 0x1A00;
pub const RXPDO_MAPPING: u16 = 0x1600;
/// The largest value an SDO transfer carries in either direction.
pub const MAX_SDO_BYTES: usize = 512;

/// SDO abort codes (ETG.1000.6 Table 41) the model may name.
pub mod abort {
    pub const TOGGLE: u32 = 0x0503_0000;
    pub const TIMEOUT: u32 = 0x0504_0000;
    pub const COMMAND: u32 = 0x0504_0001;
    pub const OUT_OF_MEMORY: u32 = 0x0504_0005;
    pub const UNSUPPORTED_ACCESS: u32 = 0x0601_0000;
    pub const WRITE_ONLY: u32 = 0x0601_0001;
    pub const READ_ONLY: u32 = 0x0601_0002;
    pub const NO_OBJECT: u32 = 0x0602_0000;
    pub const HARDWARE: u32 = 0x0606_0000;
    pub const TYPE_LENGTH: u32 = 0x0607_0010;
    pub const TOO_LONG: u32 = 0x0607_0012;
    pub const TOO_SHORT: u32 = 0x0607_0013;
    pub const NO_SUBINDEX: u32 = 0x0609_0011;
    pub const VALUE_RANGE: u32 = 0x0609_0030;
    pub const VALUE_HIGH: u32 = 0x0609_0031;
    pub const VALUE_LOW: u32 = 0x0609_0032;
    pub const GENERAL: u32 = 0x0800_0000;
    pub const TRANSFER: u32 = 0x0800_0020;
    pub const LOCAL_CONTROL: u32 = 0x0800_0021;
    pub const DEVICE_STATE: u32 = 0x0800_0022;
    pub const NO_DICTIONARY: u32 = 0x0800_0023;

    /// The names the model uses, with their codes.
    pub const NAMES: &[(&str, u32)] = &[
        ("object_does_not_exist", NO_OBJECT),
        ("subindex_does_not_exist", NO_SUBINDEX),
        ("read_only", READ_ONLY),
        ("write_only", WRITE_ONLY),
        ("value_range_exceeded", VALUE_RANGE),
        ("value_too_high", VALUE_HIGH),
        ("value_too_low", VALUE_LOW),
        ("type_mismatch", TYPE_LENGTH),
        ("hardware_error", HARDWARE),
        ("device_state", DEVICE_STATE),
        ("local_control", LOCAL_CONTROL),
        ("cannot_transfer", TRANSFER),
        ("general_error", GENERAL),
        ("unsupported_access", UNSUPPORTED_ACCESS),
    ];

    pub fn name(code: u32) -> &'static str {
        match code {
            TOGGLE => "toggle bit not alternated",
            TIMEOUT => "SDO protocol timed out",
            COMMAND => "client/server command specifier not valid or unknown",
            OUT_OF_MEMORY => "out of memory",
            UNSUPPORTED_ACCESS => "unsupported access to an object",
            WRITE_ONLY => "attempt to read a write-only object",
            READ_ONLY => "attempt to write a read-only object",
            NO_OBJECT => "the object does not exist in the object dictionary",
            HARDWARE => "access failed due to a hardware error",
            TYPE_LENGTH => "data type does not match, length of service parameter does not match",
            TOO_LONG => "data type does not match, length too high",
            TOO_SHORT => "data type does not match, length too low",
            NO_SUBINDEX => "subindex does not exist",
            VALUE_RANGE => "value range of parameter exceeded",
            VALUE_HIGH => "value of parameter written too high",
            VALUE_LOW => "value of parameter written too low",
            GENERAL => "general error",
            TRANSFER => "data cannot be transferred or stored to the application",
            LOCAL_CONTROL => "data cannot be transferred because of local control",
            DEVICE_STATE => "data cannot be transferred in the present device state",
            NO_DICTIONARY => "no object dictionary is present",
            _ => "unknown abort code",
        }
    }
}

/// A mailbox: its header fields and the data after it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mailbox {
    pub address: u16,
    pub channel: u8,
    pub priority: u8,
    pub mbx_type: u8,
    pub counter: u8,
    pub data: Vec<u8>,
}

impl Mailbox {
    /// Parse the mailbox in a SyncManager area. The declared length must fit the area.
    pub fn parse(area: &[u8]) -> Result<Self> {
        ensure!(area.len() >= HEADER_LEN, "a mailbox is at least 6 octets");
        let len = u16::from_le_bytes([area[0], area[1]]) as usize;
        ensure!(
            HEADER_LEN + len <= area.len(),
            "the mailbox header declares {len} octets, the mailbox holds {}",
            area.len() - HEADER_LEN
        );
        Ok(Mailbox {
            address: u16::from_le_bytes([area[2], area[3]]),
            channel: area[4] & 0x3F,
            priority: area[4] >> 6,
            mbx_type: area[5] & 0x0F,
            counter: (area[5] >> 4) & 0x07,
            data: area[HEADER_LEN..HEADER_LEN + len].to_vec(),
        })
    }

    /// Encode, padded with zeros to `size` (the SyncManager's length).
    pub fn encode(&self, size: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(size.max(HEADER_LEN + self.data.len()));
        out.extend_from_slice(&(self.data.len() as u16).to_le_bytes());
        out.extend_from_slice(&self.address.to_le_bytes());
        out.push(self.channel & 0x3F | (self.priority & 3) << 6);
        out.push(self.mbx_type & 0x0F | (self.counter & 7) << 4);
        out.extend_from_slice(&self.data);
        if out.len() < size {
            out.resize(size, 0);
        }
        out
    }
}

/// The next mailbox counter: 1..=7, wrapping past 0 (0 is reserved for "not counted").
pub fn next_counter(c: u8) -> u8 {
    if c >= 7 {
        1
    } else {
        c + 1
    }
}

/// A mailbox error reply (type 0) with a detail code.
pub fn error_reply(counter: u8, detail: u16) -> Mailbox {
    let mut data = Vec::with_capacity(4);
    data.extend_from_slice(&0x0001u16.to_le_bytes()); // type: mailbox command
    data.extend_from_slice(&detail.to_le_bytes());
    Mailbox {
        address: 0,
        channel: 0,
        priority: 0,
        mbx_type: mbx_type::ERROR,
        counter,
        data,
    }
}

fn coe_header(service: u8) -> [u8; 2] {
    ((service as u16) << 12).to_le_bytes()
}

/// The CoE service of a CoE mailbox's data.
pub fn coe_service(data: &[u8]) -> Option<u8> {
    (data.len() >= COE_HEADER_LEN).then(|| data[1] >> 4)
}

/// What a master asked of a slave's SDO server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SdoRequest {
    /// Initiate upload (read). `complete_access` reads every subindex at once.
    Upload {
        index: u16,
        subindex: u8,
        complete_access: bool,
    },
    /// The next segment of an upload in progress.
    UploadSegment {
        toggle: bool,
    },
    /// Initiate download (write): expedited or normal, the data complete when `size` octets are
    /// in it, otherwise followed by segments.
    Download {
        index: u16,
        subindex: u8,
        complete_access: bool,
        size: usize,
        data: Vec<u8>,
    },
    DownloadSegment {
        toggle: bool,
        last: bool,
        data: Vec<u8>,
    },
    Abort {
        index: u16,
        subindex: u8,
        code: u32,
    },
}

/// Parse the data of a CoE mailbox carrying an SDO request.
pub fn parse_request(data: &[u8]) -> Result<SdoRequest> {
    ensure!(
        data.len() >= SDO_LEN,
        "an SDO request is at least 10 octets, got {}",
        data.len()
    );
    ensure!(
        coe_service(data) == Some(service::SDO_REQUEST),
        "not an SDO request"
    );
    let c = data[2];
    let index = u16::from_le_bytes([data[3], data[4]]);
    let subindex = data[5];
    let ca = c & 0x10 != 0;
    Ok(match c >> 5 {
        // Initiate download
        1 => {
            let expedited = c & 0x02 != 0;
            let size_indicated = c & 0x01 != 0;
            if expedited {
                let n = if size_indicated {
                    4 - ((c >> 2) & 3) as usize
                } else {
                    4
                };
                SdoRequest::Download {
                    index,
                    subindex,
                    complete_access: ca,
                    size: n,
                    data: data[6..6 + n].to_vec(),
                }
            } else {
                let size = u32::from_le_bytes([data[6], data[7], data[8], data[9]]) as usize;
                ensure!(
                    size <= MAX_SDO_BYTES,
                    "an SDO download of {size} octets, more than {MAX_SDO_BYTES}"
                );
                let here = (data.len() - SDO_LEN).min(size);
                SdoRequest::Download {
                    index,
                    subindex,
                    complete_access: ca,
                    size,
                    data: data[SDO_LEN..SDO_LEN + here].to_vec(),
                }
            }
        }
        // Initiate upload
        2 => SdoRequest::Upload {
            index,
            subindex,
            complete_access: ca,
        },
        // Upload segment
        3 => SdoRequest::UploadSegment {
            toggle: c & 0x10 != 0,
        },
        // Download segment
        0 => {
            let last = c & 0x01 != 0;
            let seg = &data[3..];
            let unused = ((c >> 1) & 7) as usize;
            let n = if seg.len() <= 7 {
                7usize.saturating_sub(unused).min(seg.len())
            } else {
                seg.len()
            };
            SdoRequest::DownloadSegment {
                toggle: c & 0x10 != 0,
                last,
                data: seg[..n].to_vec(),
            }
        }
        4 => SdoRequest::Abort {
            index,
            subindex,
            code: u32::from_le_bytes([data[6], data[7], data[8], data[9]]),
        },
        other => bail!("SDO command specifier {other} is not a request"),
    })
}

fn sdo(cmd: u8, index: u16, subindex: u8, tail: &[u8]) -> Vec<u8> {
    let mut d = Vec::with_capacity(SDO_LEN + tail.len().saturating_sub(4));
    d.extend_from_slice(&coe_header(service::SDO_RESPONSE));
    d.push(cmd);
    d.extend_from_slice(&index.to_le_bytes());
    d.push(subindex);
    d.extend_from_slice(tail);
    if d.len() < SDO_LEN {
        d.resize(SDO_LEN, 0);
    }
    d
}

/// The CoE data answering an upload with `value`, and what is left for upload segments when the
/// value does not fit the mailbox (`mailbox` is the SyncManager length).
pub fn upload_response(
    index: u16,
    subindex: u8,
    value: &[u8],
    mailbox: usize,
) -> (Vec<u8>, Vec<u8>) {
    if !value.is_empty() && value.len() <= 4 {
        let n = (4 - value.len()) as u8;
        let mut tail = value.to_vec();
        tail.resize(4, 0);
        return (sdo(0x43 | n << 2, index, subindex, &tail), Vec::new());
    }
    let room = mailbox.saturating_sub(HEADER_LEN + SDO_LEN);
    let here = value.len().min(room);
    let mut tail = (value.len() as u32).to_le_bytes().to_vec();
    tail.extend_from_slice(&value[..here]);
    (sdo(0x41, index, subindex, &tail), value[here..].to_vec())
}

/// One upload segment from `rest`; returns the CoE data and what remains.
pub fn upload_segment(toggle: bool, rest: &[u8], mailbox: usize) -> (Vec<u8>, Vec<u8>) {
    let room = mailbox
        .saturating_sub(HEADER_LEN + COE_HEADER_LEN + 1)
        .max(7);
    let here = rest.len().min(room);
    let last = here == rest.len();
    let mut cmd = (toggle as u8) << 4 | last as u8;
    let mut d = coe_header(service::SDO_RESPONSE).to_vec();
    if here < 7 {
        cmd |= ((7 - here) as u8) << 1;
    }
    d.push(cmd);
    d.extend_from_slice(&rest[..here]);
    if d.len() < SDO_LEN {
        d.resize(SDO_LEN, 0);
    }
    (d, rest[here..].to_vec())
}

pub fn download_response(index: u16, subindex: u8) -> Vec<u8> {
    sdo(0x60, index, subindex, &[0; 4])
}

pub fn download_segment_response(toggle: bool) -> Vec<u8> {
    sdo(0x20 | (toggle as u8) << 4, 0, 0, &[0; 4])
}

pub fn abort_response(index: u16, subindex: u8, code: u32) -> Vec<u8> {
    let mut d = coe_header(service::SDO_REQUEST).to_vec();
    d.push(0x80);
    d.extend_from_slice(&index.to_le_bytes());
    d.push(subindex);
    d.extend_from_slice(&code.to_le_bytes());
    d
}

// ------------------------------------------------------------------ the master's side

fn request(cmd: u8, index: u16, subindex: u8, tail: &[u8]) -> Vec<u8> {
    let mut d = coe_header(service::SDO_REQUEST).to_vec();
    d.push(cmd);
    d.extend_from_slice(&index.to_le_bytes());
    d.push(subindex);
    d.extend_from_slice(tail);
    if d.len() < SDO_LEN {
        d.resize(SDO_LEN, 0);
    }
    d
}

pub fn upload_request(index: u16, subindex: u8) -> Vec<u8> {
    request(0x40, index, subindex, &[0; 4])
}

pub fn upload_segment_request(toggle: bool) -> Vec<u8> {
    request(0x60 | (toggle as u8) << 4, 0, 0, &[0; 4])
}

/// A download request: expedited when it fits four octets, otherwise normal with as much as
/// the mailbox holds; returns the CoE data and what is left for segments.
pub fn download_request(
    index: u16,
    subindex: u8,
    value: &[u8],
    mailbox: usize,
) -> (Vec<u8>, Vec<u8>) {
    if !value.is_empty() && value.len() <= 4 {
        let n = (4 - value.len()) as u8;
        let mut tail = value.to_vec();
        tail.resize(4, 0);
        return (request(0x23 | n << 2, index, subindex, &tail), Vec::new());
    }
    let room = mailbox.saturating_sub(HEADER_LEN + SDO_LEN);
    let here = value.len().min(room);
    let mut tail = (value.len() as u32).to_le_bytes().to_vec();
    tail.extend_from_slice(&value[..here]);
    (
        request(0x21, index, subindex, &tail),
        value[here..].to_vec(),
    )
}

pub fn download_segment_request(toggle: bool, rest: &[u8], mailbox: usize) -> (Vec<u8>, Vec<u8>) {
    let room = mailbox
        .saturating_sub(HEADER_LEN + COE_HEADER_LEN + 1)
        .max(7);
    let here = rest.len().min(room);
    let last = here == rest.len();
    let mut cmd = (toggle as u8) << 4 | last as u8;
    let mut d = coe_header(service::SDO_REQUEST).to_vec();
    if here < 7 {
        cmd |= ((7 - here) as u8) << 1;
    }
    d.push(cmd);
    d.extend_from_slice(&rest[..here]);
    if d.len() < SDO_LEN {
        d.resize(SDO_LEN, 0);
    }
    (d, rest[here..].to_vec())
}

/// What a slave answered an SDO request with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SdoResponse {
    /// Upload data: complete when `size` octets have arrived.
    Upload {
        size: usize,
        data: Vec<u8>,
    },
    UploadSegment {
        last: bool,
        data: Vec<u8>,
    },
    Download,
    DownloadSegment,
    Abort {
        code: u32,
    },
}

/// Parse the data of a CoE mailbox a slave sent.
pub fn parse_response(data: &[u8]) -> Result<SdoResponse> {
    ensure!(
        data.len() >= SDO_LEN,
        "an SDO response is at least 10 octets"
    );
    let svc = coe_service(data);
    let c = data[2];
    if c >> 5 == 4 {
        return Ok(SdoResponse::Abort {
            code: u32::from_le_bytes([data[6], data[7], data[8], data[9]]),
        });
    }
    ensure!(
        svc == Some(service::SDO_RESPONSE),
        "CoE service {svc:?} is not an SDO response"
    );
    Ok(match c >> 5 {
        2 => {
            if c & 0x02 != 0 {
                let n = if c & 0x01 != 0 {
                    4 - ((c >> 2) & 3) as usize
                } else {
                    4
                };
                SdoResponse::Upload {
                    size: n,
                    data: data[6..6 + n].to_vec(),
                }
            } else {
                let size = u32::from_le_bytes([data[6], data[7], data[8], data[9]]) as usize;
                ensure!(
                    size <= MAX_SDO_BYTES,
                    "an SDO upload of {size} octets, more than {MAX_SDO_BYTES}"
                );
                let here = (data.len() - SDO_LEN).min(size);
                SdoResponse::Upload {
                    size,
                    data: data[SDO_LEN..SDO_LEN + here].to_vec(),
                }
            }
        }
        0 => {
            let seg = &data[3..];
            let unused = ((c >> 1) & 7) as usize;
            let n = if seg.len() <= 7 {
                7usize.saturating_sub(unused).min(seg.len())
            } else {
                seg.len()
            };
            SdoResponse::UploadSegment {
                last: c & 0x01 != 0,
                data: seg[..n].to_vec(),
            }
        }
        3 => SdoResponse::Download,
        1 => SdoResponse::DownloadSegment,
        other => bail!("SDO command specifier {other} is not a response"),
    })
}

/// The CoE mailbox wrapping SDO data.
pub fn coe_mailbox(counter: u8, data: Vec<u8>) -> Mailbox {
    Mailbox {
        address: 0,
        channel: 0,
        priority: 0,
        mbx_type: mbx_type::COE,
        counter,
        data,
    }
}

/// An abort code given by name or number.
pub fn abort_code(v: Option<&serde_json::Value>) -> Result<u32> {
    use serde_json::Value;
    Ok(match v {
        None | Some(Value::Null) => abort::GENERAL,
        Some(Value::String(s)) => {
            if let Some((_, c)) = abort::NAMES.iter().find(|(n, _)| n.eq_ignore_ascii_case(s)) {
                *c
            } else {
                let n = super::device::parse_int_text(s).map_err(|_| {
                    anyhow::anyhow!(
                        "abort {s:?} is one of {} or a number",
                        abort::NAMES
                            .iter()
                            .map(|(n, _)| *n)
                            .collect::<Vec<_>>()
                            .join(", ")
                    )
                })?;
                u32::try_from(n).map_err(|_| anyhow::anyhow!("abort code {n} is not 32-bit"))?
            }
        }
        Some(Value::Number(n)) => n
            .as_u64()
            .and_then(|n| u32::try_from(n).ok())
            .ok_or_else(|| anyhow::anyhow!("abort code must be 0..=0xFFFFFFFF"))?,
        Some(other) => bail!("abort is a name or a number, got {other}"),
    })
}

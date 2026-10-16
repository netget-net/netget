//! EtherCAT frames and datagrams (IEC 61158-4-12 / ETG.1000.4 §5): the 2-octet frame header,
//! the datagrams it carries, and the two ways a frame travels — as the payload of an Ethernet
//! frame with EtherType 0x88A4, or as the payload of a UDP datagram to port 0x88A4 (34980).
//!
//! A datagram is processed *in place*: a slave changes its data and its working counter as the
//! frame passes and nothing else, so the codec hands out offsets into the caller's buffer
//! rather than owned copies, and the frame that goes back has exactly the length that came in.
//!
//! Layouts (all little-endian):
//!
//! ```text
//! frame header   u16   bits 0-10 length of the datagrams, bit 11 reserved, bits 12-15 type (1)
//! datagram       u8 cmd | u8 idx | u32 address | u16 len (bits 0-10 length, 14 circulating,
//!                15 more follows) | u16 irq | data[len] | u16 working counter
//! ```
//!
//! The address is ADP (u16, position or station address) then ADO (u16, register offset) for
//! the physical commands and one u32 for the logical ones.

/// EtherType of EtherCAT frames.
pub const ETHERTYPE: u16 = 0x88A4;
/// UDP port of EtherCAT-in-UDP (ETG.1000.4: the same number as the EtherType).
pub const UDP_PORT: u16 = 0x88A4;
/// Frame type 1: EtherCAT commands (DLPDUs). 4 and 5 (network variables, mailbox gateway)
/// are other traffic and are not processed.
pub const FRAME_TYPE_COMMANDS: u8 = 1;
pub const HEADER_LEN: usize = 2;
/// Datagram header (10) plus working counter (2).
pub const DATAGRAM_OVERHEAD: usize = 12;
/// The longest EtherCAT payload one Ethernet frame carries: 1500 minus the frame header.
pub const MAX_PAYLOAD: usize = 1498;
/// The most data one datagram can carry inside one frame.
pub const MAX_DATAGRAM_DATA: usize = MAX_PAYLOAD - DATAGRAM_OVERHEAD;
/// Datagrams processed in one frame. A legal frame of empty datagrams could hold 124; a
/// frame claiming more than this is refused whole rather than worked through.
pub const MAX_DATAGRAMS: usize = 64;
/// The largest Ethernet frame accepted (1500 payload, 14 header, one 802.1Q tag, 4 spare).
pub const MAX_ETHERNET_FRAME: usize = 1522;
/// Ethernet frames shorter than this are padded (60 octets without the FCS).
pub const MIN_ETHERNET_FRAME: usize = 60;

pub mod cmd {
    pub const NOP: u8 = 0;
    pub const APRD: u8 = 1;
    pub const APWR: u8 = 2;
    pub const APRW: u8 = 3;
    pub const FPRD: u8 = 4;
    pub const FPWR: u8 = 5;
    pub const FPRW: u8 = 6;
    pub const BRD: u8 = 7;
    pub const BWR: u8 = 8;
    pub const BRW: u8 = 9;
    pub const LRD: u8 = 10;
    pub const LWR: u8 = 11;
    pub const LRW: u8 = 12;
    pub const ARMW: u8 = 13;
    pub const FRMW: u8 = 14;

    pub fn name(c: u8) -> &'static str {
        match c {
            NOP => "NOP",
            APRD => "APRD",
            APWR => "APWR",
            APRW => "APRW",
            FPRD => "FPRD",
            FPWR => "FPWR",
            FPRW => "FPRW",
            BRD => "BRD",
            BWR => "BWR",
            BRW => "BRW",
            LRD => "LRD",
            LWR => "LWR",
            LRW => "LRW",
            ARMW => "ARMW",
            FRMW => "FRMW",
            _ => "unknown",
        }
    }
}

/// Why a frame was not processed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameError {
    TooShort,
    TooLong(usize),
    NotCommands(u8),
    LengthBeyondPayload { declared: usize, available: usize },
    DatagramBeyondFrame { index: usize },
    TooManyDatagrams,
    NoDatagrams,
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FrameError::TooShort => write!(f, "shorter than an EtherCAT header and one datagram"),
            FrameError::TooLong(n) => write!(f, "{n} octets, more than {MAX_PAYLOAD}"),
            FrameError::NotCommands(t) => write!(f, "frame type {t}, not EtherCAT commands"),
            FrameError::LengthBeyondPayload {
                declared,
                available,
            } => write!(
                f,
                "header declares {declared} octets of datagrams, {available} present"
            ),
            FrameError::DatagramBeyondFrame { index } => {
                write!(f, "datagram {index} runs past the declared frame length")
            }
            FrameError::TooManyDatagrams => write!(f, "more than {MAX_DATAGRAMS} datagrams"),
            FrameError::NoDatagrams => write!(f, "no datagram"),
        }
    }
}

impl std::error::Error for FrameError {}

/// Where one datagram sits in a frame buffer (offsets are from the start of the EtherCAT
/// payload, i.e. the frame header is at 0).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DatagramAt {
    pub cmd: u8,
    pub idx: u8,
    /// Offset of the datagram header.
    pub offset: usize,
    /// Offset and length of the data.
    pub data: usize,
    pub len: usize,
    pub circulating: bool,
}

impl DatagramAt {
    pub fn adp(&self, buf: &[u8]) -> u16 {
        u16::from_le_bytes([buf[self.offset + 2], buf[self.offset + 3]])
    }
    pub fn set_adp(&self, buf: &mut [u8], v: u16) {
        buf[self.offset + 2..self.offset + 4].copy_from_slice(&v.to_le_bytes());
    }
    pub fn ado(&self, buf: &[u8]) -> u16 {
        u16::from_le_bytes([buf[self.offset + 4], buf[self.offset + 5]])
    }
    pub fn logical(&self, buf: &[u8]) -> u32 {
        u32::from_le_bytes([
            buf[self.offset + 2],
            buf[self.offset + 3],
            buf[self.offset + 4],
            buf[self.offset + 5],
        ])
    }
    pub fn wkc_offset(&self) -> usize {
        self.data + self.len
    }
    pub fn wkc(&self, buf: &[u8]) -> u16 {
        let o = self.wkc_offset();
        u16::from_le_bytes([buf[o], buf[o + 1]])
    }
    pub fn set_wkc(&self, buf: &mut [u8], v: u16) {
        let o = self.wkc_offset();
        buf[o..o + 2].copy_from_slice(&v.to_le_bytes());
    }
}

/// The datagrams of an EtherCAT payload (frame header first). Octets after the declared
/// length — Ethernet padding — are left alone.
pub fn parse(buf: &[u8]) -> Result<Vec<DatagramAt>, FrameError> {
    if buf.len() < HEADER_LEN + DATAGRAM_OVERHEAD {
        return Err(FrameError::TooShort);
    }
    if buf.len() > MAX_PAYLOAD + HEADER_LEN + 64 {
        // A UDP datagram or Ethernet payload larger than any EtherCAT frame plus padding.
        return Err(FrameError::TooLong(buf.len()));
    }
    let h = u16::from_le_bytes([buf[0], buf[1]]);
    let declared = (h & 0x07FF) as usize;
    let ftype = (h >> 12) as u8;
    if ftype != FRAME_TYPE_COMMANDS {
        return Err(FrameError::NotCommands(ftype));
    }
    if declared > MAX_PAYLOAD {
        return Err(FrameError::TooLong(declared));
    }
    let available = buf.len() - HEADER_LEN;
    if declared > available {
        return Err(FrameError::LengthBeyondPayload {
            declared,
            available,
        });
    }
    let end = HEADER_LEN + declared;
    let mut out = Vec::new();
    let mut pos = HEADER_LEN;
    loop {
        if out.len() >= MAX_DATAGRAMS {
            return Err(FrameError::TooManyDatagrams);
        }
        if pos + 10 > end {
            return Err(if out.is_empty() {
                FrameError::NoDatagrams
            } else {
                FrameError::DatagramBeyondFrame { index: out.len() }
            });
        }
        let lf = u16::from_le_bytes([buf[pos + 6], buf[pos + 7]]);
        let len = (lf & 0x07FF) as usize;
        let data = pos + 10;
        if data + len + 2 > end {
            return Err(FrameError::DatagramBeyondFrame { index: out.len() });
        }
        out.push(DatagramAt {
            cmd: buf[pos],
            idx: buf[pos + 1],
            offset: pos,
            data,
            len,
            circulating: lf & 0x4000 != 0,
        });
        pos = data + len + 2;
        if lf & 0x8000 == 0 {
            break;
        }
    }
    Ok(out)
}

/// One datagram a master builds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Datagram {
    pub cmd: u8,
    pub idx: u8,
    /// ADP | ADO << 16 for physical commands; the logical address for LRD/LWR/LRW.
    pub address: u32,
    pub data: Vec<u8>,
    pub wkc: u16,
}

impl Datagram {
    pub fn physical(cmd: u8, adp: u16, ado: u16, data: Vec<u8>) -> Self {
        Self {
            cmd,
            idx: 0,
            address: adp as u32 | (ado as u32) << 16,
            data,
            wkc: 0,
        }
    }
    pub fn logical(cmd: u8, address: u32, data: Vec<u8>) -> Self {
        Self {
            cmd,
            idx: 0,
            address,
            data,
            wkc: 0,
        }
    }
}

/// Encode datagrams into an EtherCAT payload (frame header first).
pub fn encode(datagrams: &[Datagram]) -> Result<Vec<u8>, FrameError> {
    if datagrams.is_empty() {
        return Err(FrameError::NoDatagrams);
    }
    if datagrams.len() > MAX_DATAGRAMS {
        return Err(FrameError::TooManyDatagrams);
    }
    let body: usize = datagrams
        .iter()
        .map(|d| d.data.len() + DATAGRAM_OVERHEAD)
        .sum();
    if body > MAX_PAYLOAD {
        return Err(FrameError::TooLong(body));
    }
    let mut out = Vec::with_capacity(HEADER_LEN + body);
    out.extend_from_slice(&((body as u16) | (FRAME_TYPE_COMMANDS as u16) << 12).to_le_bytes());
    for (i, d) in datagrams.iter().enumerate() {
        out.push(d.cmd);
        out.push(d.idx);
        out.extend_from_slice(&d.address.to_le_bytes());
        let more = if i + 1 < datagrams.len() { 0x8000 } else { 0 };
        out.extend_from_slice(&((d.data.len() as u16) | more).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&d.data);
        out.extend_from_slice(&d.wkc.to_le_bytes());
    }
    Ok(out)
}

/// The datagrams of a returned frame, as owned values.
pub fn decode(buf: &[u8]) -> Result<Vec<Datagram>, FrameError> {
    Ok(parse(buf)?
        .into_iter()
        .map(|d| Datagram {
            cmd: d.cmd,
            idx: d.idx,
            address: d.logical(buf),
            data: buf[d.data..d.data + d.len].to_vec(),
            wkc: d.wkc(buf),
        })
        .collect())
}

/// An Ethernet frame around an EtherCAT payload, padded to the 60-octet minimum.
pub fn ethernet(dst: [u8; 6], src: [u8; 6], payload: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity((14 + payload.len()).max(MIN_ETHERNET_FRAME));
    f.extend_from_slice(&dst);
    f.extend_from_slice(&src);
    f.extend_from_slice(&ETHERTYPE.to_be_bytes());
    f.extend_from_slice(payload);
    if f.len() < MIN_ETHERNET_FRAME {
        f.resize(MIN_ETHERNET_FRAME, 0);
    }
    f
}

/// Where the EtherCAT payload starts in an Ethernet frame (after any 802.1Q tags), when the
/// frame carries EtherType 0x88A4.
pub fn ethernet_payload_offset(frame: &[u8]) -> Option<usize> {
    if frame.len() < 14 || frame.len() > MAX_ETHERNET_FRAME {
        return None;
    }
    let mut pos = 12;
    for _ in 0..2 {
        let t = u16::from_be_bytes([frame[pos], frame[pos + 1]]);
        if t == 0x8100 || t == 0x88A8 {
            pos += 4;
            if pos + 2 > frame.len() {
                return None;
            }
            continue;
        }
        return (t == ETHERTYPE).then_some(pos + 2);
    }
    let t = u16::from_be_bytes([frame[pos], frame[pos + 1]]);
    (t == ETHERTYPE).then_some(pos + 2)
}

/// The source address an ESC writes when a frame passes it: the locally administered bit
/// (bit 1 of the first octet) set. A master recognises a frame that has been through at least
/// one slave by it (ethercrab drops the ones that have not).
pub fn processed_source(src: [u8; 6]) -> [u8; 6] {
    let mut s = src;
    s[0] |= 0x02;
    s
}

/// A short, printable account of a frame, for the log.
pub fn summary(buf: &[u8]) -> String {
    match parse(buf) {
        Ok(ds) => ds
            .iter()
            .map(|d| {
                format!(
                    "{}#{} {}B wkc {}",
                    cmd::name(d.cmd),
                    d.idx,
                    d.len,
                    d.wkc(buf)
                )
            })
            .collect::<Vec<_>>()
            .join(", "),
        Err(e) => format!("unparsable ({e})"),
    }
}

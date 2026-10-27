//! TI's Monitor and Test (MT) framing, the host link of a Z-Stack network co-processor (ZNP):
//! `SOF (0xFE) | Length | Cmd0 | Cmd1 | Data[Length] | FCS`, where Cmd0 carries the command
//! type in its top three bits and the subsystem in the low five, Cmd1 is the command id, and
//! the FCS is the XOR of every byte from Length through the last data byte.
//!
//! There is no escaping, acknowledgement or retransmission: a frame either arrives whole with a
//! good FCS or is dropped, as Z-Stack's NPI drops it. `Length` above [`MAX_DATA`] is not a
//! frame (zigpy-znp, zigbee-herdsman and Z-Stack all refuse it); the deframer skips that SOF and
//! hunts for the next, so it never holds more than one maximal frame.

/// Start of frame.
pub const SOF: u8 = 0xFE;
/// The most data one frame carries (Z-Stack's `MT_RPC_DATA_MAX`).
pub const MAX_DATA: usize = 250;
/// A whole frame: SOF, length, two command bytes, the data and the FCS.
pub const MAX_FRAME: usize = MAX_DATA + 5;

/// Command types (Cmd0 bits 7..5).
pub mod kind {
    pub const POLL: u8 = 0;
    pub const SREQ: u8 = 1;
    pub const AREQ: u8 = 2;
    pub const SRSP: u8 = 3;
}

/// Subsystems (Cmd0 bits 4..0).
pub mod subsystem {
    pub const RPC_ERROR: u8 = 0x00;
    pub const SYS: u8 = 0x01;
    pub const MAC: u8 = 0x02;
    pub const NWK: u8 = 0x03;
    pub const AF: u8 = 0x04;
    pub const ZDO: u8 = 0x05;
    pub const SAPI: u8 = 0x06;
    pub const UTIL: u8 = 0x07;
    pub const DEBUG: u8 = 0x08;
    pub const APP: u8 = 0x09;
    pub const APP_CNF: u8 = 0x0F;
    pub const GP: u8 = 0x15;
}

/// `MT_RPC_ERR_*`: why an SREQ was not executed, in the RPC error SRSP.
pub mod rpc_error {
    pub const INVALID_SUBSYSTEM: u8 = 0x01;
    pub const INVALID_COMMAND_ID: u8 = 0x02;
    pub const INVALID_PARAMETER: u8 = 0x03;
    pub const INVALID_LENGTH: u8 = 0x04;
}

/// One MT frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// The command type, `kind::*`.
    pub kind: u8,
    /// The subsystem, `subsystem::*`.
    pub subsystem: u8,
    /// Cmd1.
    pub id: u8,
    pub data: Vec<u8>,
}

impl Frame {
    pub fn new(kind: u8, subsystem: u8, id: u8, data: Vec<u8>) -> Self {
        Self {
            kind: kind & 0x07,
            subsystem: subsystem & 0x1F,
            id,
            data,
        }
    }

    pub fn srsp(subsystem: u8, id: u8, data: Vec<u8>) -> Self {
        Self::new(kind::SRSP, subsystem, id, data)
    }

    pub fn areq(subsystem: u8, id: u8, data: Vec<u8>) -> Self {
        Self::new(kind::AREQ, subsystem, id, data)
    }

    pub fn cmd0(&self) -> u8 {
        (self.kind << 5) | self.subsystem
    }

    /// The bytes on the wire. A frame is never built with more than [`MAX_DATA`] bytes of
    /// data; if one were, its data is cut at the bound rather than sent with a length byte
    /// that lies.
    pub fn encode(&self) -> Vec<u8> {
        let data = &self.data[..self.data.len().min(MAX_DATA)];
        let mut out = Vec::with_capacity(data.len() + 5);
        out.push(SOF);
        out.push(data.len() as u8);
        out.push(self.cmd0());
        out.push(self.id);
        out.extend_from_slice(data);
        out.push(fcs(&out[1..]));
        out
    }

    /// Decode one whole frame, SOF through FCS.
    pub fn decode(raw: &[u8]) -> Result<Frame, Bad> {
        if raw.len() < 5 || raw[0] != SOF {
            return Err(Bad::Short);
        }
        let len = raw[1] as usize;
        if len > MAX_DATA {
            return Err(Bad::TooLong(raw[1]));
        }
        if raw.len() != len + 5 {
            return Err(Bad::Short);
        }
        let want = raw[len + 4];
        if fcs(&raw[1..len + 4]) != want {
            return Err(Bad::Fcs);
        }
        Ok(Frame {
            kind: raw[2] >> 5,
            subsystem: raw[2] & 0x1F,
            id: raw[3],
            data: raw[4..4 + len].to_vec(),
        })
    }

    /// The RPC error SRSP a Z-Stack co-processor answers an SREQ it does not execute with:
    /// `[ErrorCode, Cmd0, Cmd1]` of the request, in subsystem 0.
    pub fn rpc_error(error: u8, request: &Frame) -> Frame {
        Frame::srsp(
            subsystem::RPC_ERROR,
            0x00,
            vec![error, request.cmd0(), request.id],
        )
    }
}

/// The frame check sequence: the XOR of every byte given.
pub fn fcs(bytes: &[u8]) -> u8 {
    bytes.iter().fold(0u8, |a, b| a ^ b)
}

/// Why bytes on the link were not a frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bad {
    /// Fewer bytes than the length promised.
    Short,
    /// A length byte above [`MAX_DATA`].
    TooLong(u8),
    /// The FCS did not match.
    Fcs,
}

/// What the deframer found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Deframed {
    Frame(Frame),
    /// A whole frame whose FCS was wrong: dropped, never executed.
    BadFcs {
        cmd0: u8,
        cmd1: u8,
    },
    /// An SOF followed by a length above [`MAX_DATA`]: not a frame, skipped.
    TooLong(u8),
    /// Bytes before an SOF (a bootloader-skip byte, line noise): how many were dropped.
    Skipped(usize),
}

/// Reassembles frames from a byte stream, holding at most one maximal frame.
#[derive(Debug, Default)]
pub struct Deframer {
    buf: Vec<u8>,
}

impl Deframer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Bytes held waiting for the rest of a frame.
    pub fn held(&self) -> usize {
        self.buf.len()
    }

    pub fn push(&mut self, bytes: &[u8], out: &mut Vec<Deframed>) {
        let mut skipped = 0usize;
        for &b in bytes {
            if self.buf.is_empty() {
                if b == SOF {
                    self.buf.push(b);
                } else {
                    skipped += 1;
                }
                continue;
            }
            if self.buf.len() == 1 && b as usize > MAX_DATA {
                // Not a length a frame can have: this SOF was not a frame's.
                if skipped > 0 {
                    out.push(Deframed::Skipped(skipped));
                    skipped = 0;
                }
                out.push(Deframed::TooLong(b));
                self.buf.clear();
                if b == SOF {
                    self.buf.push(b);
                }
                continue;
            }
            self.buf.push(b);
            let len = self.buf[1] as usize;
            if self.buf.len() == len + 5 {
                if skipped > 0 {
                    out.push(Deframed::Skipped(skipped));
                    skipped = 0;
                }
                let raw = std::mem::take(&mut self.buf);
                out.push(match Frame::decode(&raw) {
                    Ok(f) => Deframed::Frame(f),
                    Err(_) => Deframed::BadFcs {
                        cmd0: raw[2],
                        cmd1: raw[3],
                    },
                });
            }
        }
        if skipped > 0 {
            out.push(Deframed::Skipped(skipped));
        }
    }
}

/// A reader over command data that refuses to read past the end.
pub struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

/// The data ended before the command's fields did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Truncated;

impl std::fmt::Display for Truncated {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the command's data ended early")
    }
}

impl std::error::Error for Truncated {}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }
    pub fn bytes(&mut self, n: usize) -> Result<&'a [u8], Truncated> {
        if self.data.len() - self.pos < n {
            return Err(Truncated);
        }
        let s = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    pub fn u8(&mut self) -> Result<u8, Truncated> {
        Ok(self.bytes(1)?[0])
    }
    pub fn u16(&mut self) -> Result<u16, Truncated> {
        let b = self.bytes(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }
    pub fn u32(&mut self) -> Result<u32, Truncated> {
        let b = self.bytes(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
    pub fn eui64(&mut self) -> Result<u64, Truncated> {
        let b = self.bytes(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Ok(u64::from_le_bytes(a))
    }
    /// A one-byte length and that many bytes.
    pub fn lv(&mut self) -> Result<&'a [u8], Truncated> {
        let n = self.u8()? as usize;
        self.bytes(n)
    }
    /// A list of `n` little-endian 16-bit values, the count in one byte first.
    pub fn u16_list(&mut self) -> Result<Vec<u16>, Truncated> {
        let n = self.u8()? as usize;
        let mut v = Vec::with_capacity(n);
        for _ in 0..n {
            v.push(self.u16()?);
        }
        Ok(v)
    }
    pub fn rest(&mut self) -> &'a [u8] {
        let s = &self.data[self.pos..];
        self.pos = self.data.len();
        s
    }
    pub fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }
}

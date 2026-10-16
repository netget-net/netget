//! M-Bus link layer (EN 13757-2): the four telegram formats, their checksums, the control
//! field, primary addresses and secondary-address selection.
//!
//! An M-Bus/IP gateway forwards these bytes unchanged between TCP and the two-wire bus, so this
//! is the whole framing on both the slave (`src/server/mbus`) and master (`src/client/mbus`)
//! side:
//!
//! | Format         | Bytes                                         |
//! |----------------|-----------------------------------------------|
//! | single char    | `E5`                                          |
//! | short frame    | `10 C A CS 16`                                |
//! | control frame  | `68 03 03 68 C A CI CS 16`                    |
//! | long frame     | `68 L L 68 C A CI data… CS 16`, L = 3 + data  |
//!
//! CS is the arithmetic sum, modulo 256, of every byte from C up to the last data byte. L is one
//! byte, so a long frame carries at most 252 bytes of user data and is at most 261 bytes long.
use anyhow::{bail, ensure, Result};

pub const ACK: u8 = 0xE5;
pub const START_SHORT: u8 = 0x10;
pub const START_LONG: u8 = 0x68;
pub const STOP: u8 = 0x16;

/// The largest L field: C, A, CI and 252 bytes of user data.
pub const MAX_L: usize = 255;
/// The most user data (after CI) a long frame carries.
pub const MAX_USER_DATA: usize = MAX_L - 3;
/// The longest frame on the wire: `68 L L 68`, L bytes, CS, `16`.
pub const MAX_FRAME_LEN: usize = MAX_L + 6;

/// Control field (C) values and bits.
pub mod c {
    /// Link reset (master to slave). Answered with E5.
    pub const SND_NKE: u8 = 0x40;
    /// Send user data (master to slave), FCV set. Answered with E5.
    pub const SND_UD: u8 = 0x53;
    /// Request class 2 data (master to slave), FCV set. Answered with RSP_UD.
    pub const REQ_UD2: u8 = 0x5B;
    /// Request class 1 (alarm) data (master to slave), FCV set.
    pub const REQ_UD1: u8 = 0x5A;
    /// Respond with user data (slave to master).
    pub const RSP_UD: u8 = 0x08;
    /// Frame count bit (master to slave): toggled on every successful transaction.
    pub const FCB: u8 = 0x20;
    /// Frame count bit valid (master to slave).
    pub const FCV: u8 = 0x10;
    /// Access demand (slave to master): the slave has class 1 data.
    pub const ACD: u8 = 0x20;
    /// Data flow control (slave to master): the slave cannot take more data.
    pub const DFC: u8 = 0x10;
    /// Direction bit: set master to slave.
    pub const DIR_M2S: u8 = 0x40;
    /// The function part of the C field, FCB and FCV removed.
    pub const fn function(c: u8) -> u8 {
        c & !(FCB | FCV)
    }
}

/// Control information (CI) values used here.
pub mod ci {
    /// Application reset (EN 13757-3), optionally followed by a subcode byte.
    pub const APPLICATION_RESET: u8 = 0x50;
    /// Data send: variable data records, master to slave.
    pub const DATA_SEND: u8 = 0x51;
    /// Slave select for secondary addressing (mode 1, little-endian ID).
    pub const SELECT: u8 = 0x52;
    /// Slave select, mode 2 (big-endian ID) — refused here, see `SecondaryAddress::matches`.
    pub const SELECT_MODE2: u8 = 0x56;
    /// Variable data respond, long header (ID, manufacturer, version, medium, access, status,
    /// signature), little-endian.
    pub const RSP_VARIABLE: u8 = 0x72;
    /// Fixed data respond (EN 1434-3 legacy).
    pub const RSP_FIXED: u8 = 0x73;
    /// Application error from slave.
    pub const RSP_ERROR: u8 = 0x70;
    /// Set baud rate: 0xB8 (300) to 0xBF (38400).
    pub const BAUD_FIRST: u8 = 0xB8;
    pub const BAUD_LAST: u8 = 0xBF;
    pub fn name(ci: u8) -> String {
        match ci {
            APPLICATION_RESET => "application_reset".into(),
            DATA_SEND => "data_send".into(),
            SELECT => "select".into(),
            SELECT_MODE2 => "select_mode2".into(),
            RSP_VARIABLE => "rsp_variable".into(),
            RSP_FIXED => "rsp_fixed".into(),
            RSP_ERROR => "application_error".into(),
            BAUD_FIRST..=BAUD_LAST => "set_baud_rate".into(),
            other => format!("ci_{other:#04x}"),
        }
    }
}

/// Primary addresses with a meaning of their own.
pub mod addr {
    /// The highest address a slave may have.
    pub const MAX_PRIMARY: u8 = 250;
    /// Addresses the slave selected by secondary addressing.
    pub const NETWORK_LAYER: u8 = 253;
    /// Every slave answers (a collision if there is more than one).
    pub const BROADCAST_REPLY: u8 = 254;
    /// Every slave listens and none answers.
    pub const BROADCAST_NO_REPLY: u8 = 255;
}

/// One telegram.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    /// The single character E5: acknowledgement.
    Ack,
    Short {
        c: u8,
        a: u8,
    },
    /// A long frame with no user data (L = 3).
    Control {
        c: u8,
        a: u8,
        ci: u8,
    },
    Long {
        c: u8,
        a: u8,
        ci: u8,
        data: Vec<u8>,
    },
}

pub fn checksum(bytes: &[u8]) -> u8 {
    bytes.iter().fold(0u8, |s, b| s.wrapping_add(*b))
}

impl Frame {
    /// A long frame, or a control frame when there is no user data.
    pub fn long(c: u8, a: u8, ci: u8, data: Vec<u8>) -> Frame {
        if data.is_empty() {
            Frame::Control { c, a, ci }
        } else {
            Frame::Long { c, a, ci, data }
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        Ok(match self {
            Frame::Ack => vec![ACK],
            Frame::Short { c, a } => vec![START_SHORT, *c, *a, c.wrapping_add(*a), STOP],
            Frame::Control { c, a, ci } => Self::encode_long(*c, *a, *ci, &[])?,
            Frame::Long { c, a, ci, data } => Self::encode_long(*c, *a, *ci, data)?,
        })
    }

    fn encode_long(c: u8, a: u8, ci: u8, data: &[u8]) -> Result<Vec<u8>> {
        ensure!(
            data.len() <= MAX_USER_DATA,
            "{} bytes of user data do not fit one M-Bus telegram (at most {MAX_USER_DATA})",
            data.len()
        );
        let l = (3 + data.len()) as u8;
        let mut out = Vec::with_capacity(data.len() + 9);
        out.extend_from_slice(&[START_LONG, l, l, START_LONG, c, a, ci]);
        out.extend_from_slice(data);
        out.push(checksum(&out[4..]));
        out.push(STOP);
        Ok(out)
    }

    pub fn c(&self) -> Option<u8> {
        match self {
            Frame::Ack => None,
            Frame::Short { c, .. } | Frame::Control { c, .. } | Frame::Long { c, .. } => Some(*c),
        }
    }

    pub fn a(&self) -> Option<u8> {
        match self {
            Frame::Ack => None,
            Frame::Short { a, .. } | Frame::Control { a, .. } | Frame::Long { a, .. } => Some(*a),
        }
    }

    pub fn ci(&self) -> Option<u8> {
        match self {
            Frame::Control { ci, .. } | Frame::Long { ci, .. } => Some(*ci),
            _ => None,
        }
    }

    pub fn data(&self) -> &[u8] {
        match self {
            Frame::Long { data, .. } => data,
            _ => &[],
        }
    }

    /// What this frame is, for logs and events: `REQ_UD2`, `SND_UD select`, `RSP_UD`, `ACK`.
    pub fn describe(&self) -> String {
        let Some(c) = self.c() else {
            return "ACK".into();
        };
        let name = match c::function(c) {
            f if f == c::function(c::SND_NKE) => "SND_NKE",
            f if f == c::function(c::SND_UD) => "SND_UD",
            f if f == c::function(c::REQ_UD2) => "REQ_UD2",
            f if f == c::function(c::REQ_UD1) => "REQ_UD1",
            f if f == c::function(c::RSP_UD) => "RSP_UD",
            _ => "unknown",
        };
        match self.ci() {
            Some(ci) => format!("{name} ({})", ci::name(ci)),
            None => name.into(),
        }
    }
}

/// What the front of a byte buffer holds.
#[derive(Debug, PartialEq, Eq)]
pub enum Parsed {
    /// Not enough bytes yet; at least this many more are needed.
    Incomplete(usize),
    /// A whole telegram, and how many bytes it took.
    Frame(Frame, usize),
    /// The first byte cannot begin a valid telegram (or the telegram it begins is broken):
    /// discard `skip` bytes and look again. A slave ignores such a telegram — a garbled one
    /// must not be answered — and a master reports it.
    Invalid { skip: usize, reason: String },
}

/// Parse the telegram at the front of `buf`.
///
/// A broken long frame (length bytes that disagree, a bad checksum, a missing stop byte) is
/// discarded whole once all of it has arrived, so a master's garbage never turns into a second
/// frame read from the middle of the first. A byte that cannot start any frame is skipped
/// alone. The buffer a caller keeps therefore never holds more than one frame's worth of
/// bytes beyond what it has already parsed: [`MAX_FRAME_LEN`].
pub fn parse(buf: &[u8]) -> Parsed {
    let Some(&first) = buf.first() else {
        return Parsed::Incomplete(1);
    };
    match first {
        ACK => Parsed::Frame(Frame::Ack, 1),
        START_SHORT => {
            if buf.len() < 5 {
                return Parsed::Incomplete(5 - buf.len());
            }
            let (c, a, cs, stop) = (buf[1], buf[2], buf[3], buf[4]);
            if stop != STOP {
                return Parsed::Invalid {
                    skip: 5,
                    reason: format!("short frame ends with {stop:#04x}, not the stop byte 0x16"),
                };
            }
            if c.wrapping_add(a) != cs {
                return Parsed::Invalid {
                    skip: 5,
                    reason: format!(
                        "short frame checksum {cs:#04x}, expected {:#04x}",
                        c.wrapping_add(a)
                    ),
                };
            }
            Parsed::Frame(Frame::Short { c, a }, 5)
        }
        START_LONG => {
            if buf.len() < 4 {
                return Parsed::Incomplete(4 - buf.len());
            }
            let (l1, l2) = (buf[1] as usize, buf[2] as usize);
            if l1 != l2 || buf[3] != START_LONG || l1 < 3 {
                return Parsed::Invalid {
                    skip: 1,
                    reason: format!(
                        "long frame header 68 {:02x} {:02x} {:02x} is not 68 L L 68 with L >= 3",
                        buf[1], buf[2], buf[3]
                    ),
                };
            }
            let total = l1 + 6;
            if buf.len() < total {
                return Parsed::Incomplete(total - buf.len());
            }
            let body = &buf[4..4 + l1];
            let cs = buf[4 + l1];
            let stop = buf[5 + l1];
            if stop != STOP {
                return Parsed::Invalid {
                    skip: total,
                    reason: format!("long frame ends with {stop:#04x}, not the stop byte 0x16"),
                };
            }
            let want = checksum(body);
            if cs != want {
                return Parsed::Invalid {
                    skip: total,
                    reason: format!("long frame checksum {cs:#04x}, expected {want:#04x}"),
                };
            }
            let (c, a, ci) = (body[0], body[1], body[2]);
            let frame = if l1 == 3 {
                Frame::Control { c, a, ci }
            } else {
                Frame::Long {
                    c,
                    a,
                    ci,
                    data: body[3..].to_vec(),
                }
            };
            Parsed::Frame(frame, total)
        }
        other => Parsed::Invalid {
            skip: 1,
            reason: format!("{other:#04x} does not start an M-Bus telegram"),
        },
    }
}

/// Every whole frame in `bytes`, in order, and every reason a stretch was discarded.
pub fn parse_all(mut bytes: &[u8]) -> (Vec<Frame>, Vec<String>) {
    let mut frames = Vec::new();
    let mut errors = Vec::new();
    loop {
        match parse(bytes) {
            Parsed::Incomplete(_) => {
                if !bytes.is_empty() {
                    errors.push(format!(
                        "{} trailing bytes are not a whole telegram",
                        bytes.len()
                    ));
                }
                return (frames, errors);
            }
            Parsed::Frame(f, n) => {
                frames.push(f);
                bytes = &bytes[n..];
            }
            Parsed::Invalid { skip, reason } => {
                errors.push(reason);
                bytes = &bytes[skip.min(bytes.len())..];
            }
        }
    }
}

/// Medium codes (EN 13757-3 table 3).
pub const MEDIA: &[(u8, &str)] = &[
    (0x00, "other"),
    (0x01, "oil"),
    (0x02, "electricity"),
    (0x03, "gas"),
    (0x04, "heat"),
    (0x05, "steam"),
    (0x06, "warm_water"),
    (0x07, "water"),
    (0x08, "heat_cost_allocator"),
    (0x09, "compressed_air"),
    (0x0A, "cooling_outlet"),
    (0x0B, "cooling_inlet"),
    (0x0C, "heat_inlet"),
    (0x0D, "heat_cooling"),
    (0x0E, "bus_system"),
    (0x0F, "unknown"),
    (0x15, "hot_water"),
    (0x16, "cold_water"),
    (0x17, "dual_water"),
    (0x18, "pressure"),
    (0x19, "ad_converter"),
];

pub fn medium_name(code: u8) -> String {
    MEDIA
        .iter()
        .find(|(c, _)| *c == code)
        .map(|(_, n)| (*n).to_string())
        .unwrap_or_else(|| format!("reserved_{code:#04x}"))
}

pub fn medium_from_name(name: &str) -> Result<u8> {
    let n = name.trim().to_ascii_lowercase().replace([' ', '-'], "_");
    if let Some((c, _)) = MEDIA.iter().find(|(_, m)| *m == n) {
        return Ok(*c);
    }
    if let Some(hex) = n.strip_prefix("0x") {
        return Ok(u8::from_str_radix(hex, 16)?);
    }
    bail!(
        "medium {name:?} is one of {}, or a code such as \"0x07\"",
        MEDIA.iter().map(|(_, m)| *m).collect::<Vec<_>>().join(", ")
    )
}

/// The three-letter manufacturer code (FLAG association): each letter A-Z is five bits,
/// `((c1 - 64) << 10) | ((c2 - 64) << 5) | (c3 - 64)`, sent little-endian.
pub fn manufacturer_code(letters: &str) -> Result<u16> {
    let b = letters.trim().as_bytes();
    ensure!(
        b.len() == 3 && b.iter().all(|c| c.is_ascii_uppercase()),
        "manufacturer {letters:?} is three capital letters A-Z (the FLAG code, e.g. \"KAM\")"
    );
    Ok(((b[0] as u16 - 64) << 10) | ((b[1] as u16 - 64) << 5) | (b[2] as u16 - 64))
}

pub fn manufacturer_letters(code: u16) -> String {
    let letter = |shift: u16| -> char {
        let v = ((code >> shift) & 0x1F) as u8;
        if (1..=26).contains(&v) {
            (v + 64) as char
        } else {
            '?'
        }
    };
    [letter(10), letter(5), letter(0)].iter().collect()
}

/// Pack a decimal identification number (at most 8 digits) as 4 BCD bytes, little-endian.
pub fn id_to_bcd(id: u32) -> Result<[u8; 4]> {
    ensure!(
        id <= 99_999_999,
        "an M-Bus identification number has at most 8 digits"
    );
    let mut out = [0u8; 4];
    let mut v = id;
    for byte in out.iter_mut() {
        let lo = (v % 10) as u8;
        v /= 10;
        let hi = (v % 10) as u8;
        v /= 10;
        *byte = (hi << 4) | lo;
    }
    Ok(out)
}

/// The identification number of 4 BCD bytes, little-endian, as its 8 hexadecimal nibbles —
/// the form libmbus prints. A digit outside 0-9 stays visible rather than being mis-read.
pub fn id_hex(bytes: &[u8]) -> String {
    bytes.iter().rev().map(|b| format!("{b:02X}")).collect()
}

/// A meter's secondary address: identification number, manufacturer, version and medium.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecondaryAddress {
    /// BCD-packed little-endian identification number.
    pub id: [u8; 4],
    pub manufacturer: u16,
    pub version: u8,
    pub medium: u8,
}

impl SecondaryAddress {
    pub fn bytes(&self) -> [u8; 8] {
        let m = self.manufacturer.to_le_bytes();
        [
            self.id[0],
            self.id[1],
            self.id[2],
            self.id[3],
            m[0],
            m[1],
            self.version,
            self.medium,
        ]
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        ensure!(
            b.len() >= 8,
            "a secondary address is 8 bytes, got {}",
            b.len()
        );
        Ok(Self {
            id: [b[0], b[1], b[2], b[3]],
            manufacturer: u16::from_le_bytes([b[4], b[5]]),
            version: b[6],
            medium: b[7],
        })
    }

    /// The 16-character form libmbus and most tools use: the identification number's eight
    /// digits, then the manufacturer, version and medium bytes in hex, the manufacturer's two
    /// bytes in wire order (`12345678` `2D2C` `01` `07` for KAM).
    pub fn to_hex(&self) -> String {
        let b = self.bytes();
        format!(
            "{}{:02X}{:02X}{:02X}{:02X}",
            id_hex(&self.id),
            b[4],
            b[5],
            b[6],
            b[7]
        )
    }

    /// Whether a selection mask (the 8 data bytes of a CI 0x52 SND_UD) selects this meter.
    ///
    /// Each nibble of the mask that is `F` matches anything. EN 13757-3 defines the wildcard
    /// per BCD digit for the identification number and per byte (`FF`) for the other fields;
    /// matching per nibble everywhere accepts both, and accepts the per-nibble masks libmbus's
    /// collision search sends for the manufacturer, version and medium positions.
    pub fn matches(&self, mask: &[u8; 8]) -> bool {
        self.bytes().iter().zip(mask.iter()).all(|(have, m)| {
            let hi_ok = m & 0xF0 == 0xF0 || (m & 0xF0) == (have & 0xF0);
            let lo_ok = m & 0x0F == 0x0F || (m & 0x0F) == (have & 0x0F);
            hi_ok && lo_ok
        })
    }
}

/// A secondary-address mask from its 16-character form, `F` (either case) as a wildcard
/// nibble anywhere. The identification digits are BCD, so a digit outside 0-9 other than `F`
/// is refused.
pub fn mask_from_hex(s: &str) -> Result<[u8; 8]> {
    let s = s.trim();
    ensure!(
        s.len() == 16 && s.chars().all(|c| c.is_ascii_hexdigit()),
        "a secondary address is 16 hex characters: 8 identification digits, then manufacturer, \
         version and medium bytes (e.g. \"123456782D2C0107\"; F is a wildcard), not {s:?}"
    );
    let nib = |i: usize| -> u8 { (s.as_bytes()[i] as char).to_digit(16).unwrap_or(0) as u8 };
    let mut out = [0u8; 8];
    // The identification digits, most significant first, into little-endian BCD.
    for (k, byte) in out.iter_mut().take(4).enumerate() {
        let hi = nib(6 - 2 * k);
        let lo = nib(7 - 2 * k);
        ensure!(
            (hi <= 9 || hi == 0xF) && (lo <= 9 || lo == 0xF),
            "identification digits are 0-9 or the wildcard F, not {s:?}"
        );
        *byte = (hi << 4) | lo;
    }
    for (k, byte) in out.iter_mut().skip(4).enumerate() {
        *byte = (nib(8 + 2 * k) << 4) | nib(9 + 2 * k);
    }
    Ok(out)
}

/// The 16-character form of a mask (the inverse of [`mask_from_hex`]).
pub fn mask_to_hex(mask: &[u8; 8]) -> String {
    format!(
        "{}{:02X}{:02X}{:02X}{:02X}",
        id_hex(&mask[..4]),
        mask[4],
        mask[5],
        mask[6],
        mask[7]
    )
}

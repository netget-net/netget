//! TPKT (RFC 1006) framing and the Q.931 message envelope H.225.0 call signalling uses.
//!
//! H.225.0 clause 7 profiles Q.931: protocol discriminator 0x08, a two-octet call reference,
//! one message type octet, then information elements. Every IE NetGet reads or writes is
//! listed in [`ie`]; any other is kept by id and stepped over by its length. The User-user IE
//! is the one exception to Q.931's one-octet IE length — H.225.0 7.2.2.1 gives it two — and it
//! carries the PER-encoded `H323-UserInformation` after a protocol discriminator of 0x05.
//!
//! Bounds: a TPKT may declare at most [`MAX_TPKT`] octets (its own 16-bit field allows 65535;
//! no H.225.0 message NetGet speaks comes near 8 KiB) and a message at most [`MAX_IES`] IEs.

use anyhow::{anyhow, bail, Result};
use tokio::io::{AsyncRead, AsyncReadExt};

/// Largest TPKT (header included) NetGet reads.
pub const MAX_TPKT: usize = 16_384;
/// Most information elements one message may carry.
pub const MAX_IES: usize = 64;

pub mod msg {
    pub const ALERTING: u8 = 0x01;
    pub const CALL_PROCEEDING: u8 = 0x02;
    pub const PROGRESS: u8 = 0x03;
    pub const SETUP: u8 = 0x05;
    pub const CONNECT: u8 = 0x07;
    pub const SETUP_ACKNOWLEDGE: u8 = 0x0D;
    pub const RELEASE_COMPLETE: u8 = 0x5A;
    pub const FACILITY: u8 = 0x62;
    pub const NOTIFY: u8 = 0x6E;
    pub const STATUS_ENQUIRY: u8 = 0x75;
    pub const INFORMATION: u8 = 0x7B;
    pub const STATUS: u8 = 0x7D;
}

pub mod ie {
    pub const BEARER_CAPABILITY: u8 = 0x04;
    pub const CAUSE: u8 = 0x08;
    pub const CALL_STATE: u8 = 0x14;
    pub const PROGRESS_INDICATOR: u8 = 0x1E;
    pub const DISPLAY: u8 = 0x28;
    pub const KEYPAD: u8 = 0x2C;
    pub const SIGNAL: u8 = 0x34;
    pub const CALLING_PARTY_NUMBER: u8 = 0x6C;
    pub const CALLED_PARTY_NUMBER: u8 = 0x70;
    pub const USER_USER: u8 = 0x7E;
}

pub fn message_name(t: u8) -> &'static str {
    match t {
        msg::ALERTING => "Alerting",
        msg::CALL_PROCEEDING => "CallProceeding",
        msg::PROGRESS => "Progress",
        msg::SETUP => "Setup",
        msg::CONNECT => "Connect",
        msg::SETUP_ACKNOWLEDGE => "SetupAcknowledge",
        msg::RELEASE_COMPLETE => "ReleaseComplete",
        msg::FACILITY => "Facility",
        msg::NOTIFY => "Notify",
        msg::STATUS_ENQUIRY => "StatusEnquiry",
        msg::INFORMATION => "Information",
        msg::STATUS => "Status",
        _ => "Unknown",
    }
}

/// One Q.931 message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Q931 {
    /// The call reference value (15 bits).
    pub crv: u16,
    /// The call reference flag: set on messages sent by the side that did *not* allocate the
    /// call reference (the called side).
    pub from_destination: bool,
    pub message_type: u8,
    /// Information elements in order: (id, contents). Single-octet IEs have empty contents
    /// and their whole octet as the id.
    pub ies: Vec<(u8, Vec<u8>)>,
}

impl Q931 {
    pub fn new(message_type: u8, crv: u16, from_destination: bool) -> Self {
        Self {
            crv: crv & 0x7FFF,
            from_destination,
            message_type,
            ies: Vec::new(),
        }
    }

    pub fn ie(&self, id: u8) -> Option<&[u8]> {
        self.ies
            .iter()
            .find(|(i, _)| *i == id)
            .map(|(_, v)| v.as_slice())
    }

    pub fn with_ie(mut self, id: u8, contents: Vec<u8>) -> Self {
        self.ies.push((id, contents));
        self
    }

    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 3 {
            bail!("Q.931 message of {} octets", data.len());
        }
        if data[0] != 0x08 {
            bail!(
                "protocol discriminator {:#04x} is not Q.931's 0x08",
                data[0]
            );
        }
        let crl = (data[1] & 0x0F) as usize;
        if crl > 2 {
            bail!("call reference length {crl} (H.225.0 uses 2)");
        }
        if data.len() < 3 + crl {
            bail!("Q.931 message truncated in its call reference");
        }
        let (crv, flag) = match crl {
            0 => (0u16, false),
            1 => ((data[2] & 0x7F) as u16, data[2] & 0x80 != 0),
            _ => (
                (((data[2] & 0x7F) as u16) << 8) | data[3] as u16,
                data[2] & 0x80 != 0,
            ),
        };
        let mut pos = 2 + crl;
        let message_type = data[pos] & 0x7F;
        pos += 1;
        let mut ies = Vec::new();
        while pos < data.len() {
            if ies.len() >= MAX_IES {
                bail!("more than {MAX_IES} information elements");
            }
            let id = data[pos];
            pos += 1;
            if id & 0x80 != 0 {
                ies.push((id, Vec::new()));
                continue;
            }
            let len = if id == ie::USER_USER {
                if pos + 2 > data.len() {
                    bail!("User-user IE truncated in its length");
                }
                let l = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
                pos += 2;
                l
            } else {
                if pos >= data.len() {
                    bail!("IE {id:#04x} truncated in its length");
                }
                let l = data[pos] as usize;
                pos += 1;
                l
            };
            if pos + len > data.len() {
                bail!(
                    "IE {id:#04x} declares {len} octets, {} remain",
                    data.len() - pos
                );
            }
            ies.push((id, data[pos..pos + len].to_vec()));
            pos += len;
        }
        Ok(Self {
            crv,
            from_destination: flag,
            message_type,
            ies,
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = vec![
            0x08,
            0x02,
            ((self.crv >> 8) as u8 & 0x7F) | if self.from_destination { 0x80 } else { 0 },
            self.crv as u8,
            self.message_type & 0x7F,
        ];
        for (id, contents) in &self.ies {
            if id & 0x80 != 0 {
                out.push(*id);
                continue;
            }
            out.push(*id);
            if *id == ie::USER_USER {
                let len = u16::try_from(contents.len())
                    .map_err(|_| anyhow!("User-user IE of {} octets", contents.len()))?;
                out.extend_from_slice(&len.to_be_bytes());
            } else {
                let len = u8::try_from(contents.len())
                    .map_err(|_| anyhow!("IE {id:#04x} of {} octets", contents.len()))?;
                out.push(len);
            }
            out.extend_from_slice(contents);
        }
        Ok(out)
    }

    /// The PER-encoded `H323-UserInformation` inside the User-user IE, if there is one.
    pub fn user_user(&self) -> Result<Option<&[u8]>> {
        let Some(uu) = self.ie(ie::USER_USER) else {
            return Ok(None);
        };
        match uu.split_first() {
            Some((0x05, rest)) if !rest.is_empty() => Ok(Some(rest)),
            Some((pd, _)) => {
                bail!("User-user protocol discriminator {pd:#04x}, not X.208/X.209's 0x05")
            }
            None => bail!("empty User-user IE"),
        }
    }

    pub fn with_user_user(self, per: &[u8]) -> Self {
        let mut contents = Vec::with_capacity(per.len() + 1);
        contents.push(0x05);
        contents.extend_from_slice(per);
        self.with_ie(ie::USER_USER, contents)
    }

    /// The Q.850 cause value, if a Cause IE is present.
    pub fn cause(&self) -> Option<u8> {
        let c = self.ie(ie::CAUSE)?;
        // Octet 3 (coding standard, location), optional 3a when its extension bit is clear,
        // then octet 4 with the cause value.
        let idx = if c.first()? & 0x80 != 0 { 1 } else { 2 };
        c.get(idx).map(|b| b & 0x7F)
    }

    /// Digits of a called/calling party number IE.
    pub fn number(&self, id: u8) -> Option<String> {
        let c = self.ie(id)?;
        let first = *c.first()?;
        let skip = if first & 0x80 != 0 { 1 } else { 2 };
        let digits: String = c
            .get(skip..)?
            .iter()
            .filter(|b| b.is_ascii_digit() || **b == b'*' || **b == b'#')
            .map(|b| *b as char)
            .collect();
        Some(digits)
    }

    pub fn display(&self) -> Option<String> {
        let c = self.ie(ie::DISPLAY)?;
        Some(crate::utils::sanitize::strip_controls(
            &String::from_utf8_lossy(c),
        ))
    }
}

/// Q.850 cause IE contents (ITU-T coding, location "user").
pub fn cause_ie(cause: u8) -> Vec<u8> {
    vec![0x80, 0x80 | (cause & 0x7F)]
}

/// A party-number IE: type unknown, ISDN/telephony numbering plan, IA5 digits.
pub fn number_ie(digits: &str) -> Vec<u8> {
    let mut v = vec![0x81];
    v.extend(digits.bytes());
    v
}

/// The Bearer capability H.225.0 Setup carries: ITU-T coding, unrestricted digital
/// information, circuit mode 64 kbit/s, user information layer 1 Rec. H.221 and H.242.
pub fn bearer_capability() -> Vec<u8> {
    vec![0x88, 0x90, 0xA5]
}

/// Wrap one message in a TPKT.
pub fn tpkt(payload: &[u8]) -> Result<Vec<u8>> {
    let total = payload.len() + 4;
    if total > MAX_TPKT {
        bail!("TPKT of {total} octets exceeds {MAX_TPKT}");
    }
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&[3, 0, (total >> 8) as u8, total as u8]);
    out.extend_from_slice(payload);
    Ok(out)
}

/// Read one TPKT's payload. `Ok(None)` at a clean end of stream. A TPKT with no payload (some
/// stacks send one as a keep-alive) comes back as an empty vector.
pub async fn read_tpkt<R: AsyncRead + Unpin>(r: &mut R) -> Result<Option<Vec<u8>>> {
    let mut header = [0u8; 4];
    match r.read_exact(&mut header[..1]).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    r.read_exact(&mut header[1..]).await?;
    if header[0] != 3 {
        bail!("TPKT version {} (expected 3)", header[0]);
    }
    let total = u16::from_be_bytes([header[2], header[3]]) as usize;
    if total < 4 {
        bail!("TPKT length {total} is shorter than its header");
    }
    if total > MAX_TPKT {
        bail!("TPKT declares {total} octets, more than {MAX_TPKT}");
    }
    let mut payload = vec![0u8; total - 4];
    r.read_exact(&mut payload).await?;
    Ok(Some(payload))
}

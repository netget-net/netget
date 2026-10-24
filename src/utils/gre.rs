//! GRE (RFC 2784) with RFC 2890's key and sequence number: the header codec shared by the
//! `vxlan` protocol's GRE-in-UDP mode (RFC 8086, a Linux gretap over fou) and the `gre`
//! protocol on IP protocol 47. Pure: no sockets, and nothing about what the payload carries.
//!
//! [`decode`] refuses, before anything reads the payload:
//!
//! - a version other than 0 (1 is PPTP's enhanced GRE);
//! - RFC 1701's routing, strict-source-route or recursion bits, which RFC 2784 receivers
//!   discard;
//! - a packet that ends inside any field its flags announce (checksum, key, sequence number);
//! - a checksum that does not verify over the GRE header and payload.
//!
//! The protocol type is returned, not checked: each caller accepts its own.
use anyhow::{ensure, Result};

/// GRE's IP protocol number.
pub const IP_PROTOCOL: u8 = 47;
/// Protocol type for an Ethernet payload (Transparent Ethernet Bridging: a Linux `gretap`).
pub const PROTO_TEB: u16 = 0x6558;
/// Protocol type for an IPv4 payload (a Linux `gre` link, Cisco's `tunnel mode gre ip`).
pub const PROTO_IPV4: u16 = 0x0800;
/// The protocol type of a Cisco-style keepalive's inner GRE header, which carries nothing.
pub const PROTO_KEEPALIVE: u16 = 0x0000;

/// Flag bits in the first header byte (RFC 2784 section 2.1, RFC 2890 section 2).
const FLAG_CHECKSUM: u8 = 0x80;
const FLAG_KEY: u8 = 0x20;
const FLAG_SEQUENCE: u8 = 0x10;
/// RFC 2784's "bits 1-5", less RFC 2890's K and S: RFC 1701's Routing Present (0x40), Strict
/// Source Route (0x08) and the top bit of Recursion Control (0x04). A receiver discards a
/// packet with any of them set.
const RFC1701_ONLY: u8 = 0x40 | 0x08 | 0x04;

/// What a GRE header says besides the payload it carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Header {
    /// The payload's protocol type (an EtherType).
    pub protocol: u16,
    /// The key, when the K bit is set.
    pub key: Option<u32>,
    /// A checksum is present. On input it has been verified.
    pub checksum: bool,
    /// The sequence number, when the S bit is set.
    pub sequence: Option<u32>,
}

/// The header and the payload of one GRE packet (the bytes after the outer IP header, or the
/// UDP payload for GRE-in-UDP). Each optional field is length-checked before it is read, and a
/// present checksum must verify over the header and the payload.
pub fn decode(b: &[u8]) -> Result<(Header, &[u8])> {
    ensure!(b.len() >= 4, "a {}-byte packet has no GRE header", b.len());
    let version = b[1] & 0x07;
    ensure!(
        version == 0,
        "GRE version {version} (1 is PPTP's enhanced GRE)"
    );
    ensure!(
        b[0] & RFC1701_ONLY == 0,
        "GRE flags {:#04x}: RFC 1701 routing, strict source route or recursion bits are set",
        b[0]
    );
    let protocol = u16::from_be_bytes([b[2], b[3]]);
    let checksum = b[0] & FLAG_CHECKSUM != 0;
    let mut at = 4;
    let mut field = |present: bool, what: &str| -> Result<Option<u32>> {
        if !present {
            return Ok(None);
        }
        ensure!(
            b.len() >= at + 4,
            "a {}-byte packet ends inside the GRE {what}",
            b.len()
        );
        let v = u32::from_be_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]]);
        at += 4;
        Ok(Some(v))
    };
    field(checksum, "checksum")?;
    let key = field(b[0] & FLAG_KEY != 0, "key")?;
    let sequence = field(b[0] & FLAG_SEQUENCE != 0, "sequence number")?;
    // RFC 2784: the checksum covers the GRE header and the payload, so a correct one sums the
    // whole packet, checksum field included, to zero.
    ensure!(
        !checksum || internet_checksum(&[b]) == 0,
        "bad GRE checksum"
    );
    Ok((
        Header {
            protocol,
            key,
            checksum,
            sequence,
        },
        &b[at..],
    ))
}

/// A GRE packet: the header with each field it has, then the payload. The checksum, when the
/// header has one, is computed over both.
pub fn encode(header: &Header, payload: &[u8]) -> Vec<u8> {
    let flags = if header.checksum { FLAG_CHECKSUM } else { 0 }
        | if header.key.is_some() { FLAG_KEY } else { 0 }
        | if header.sequence.is_some() {
            FLAG_SEQUENCE
        } else {
            0
        };
    let mut out = Vec::with_capacity(16 + payload.len());
    out.extend_from_slice(&[flags, 0]);
    out.extend_from_slice(&header.protocol.to_be_bytes());
    if header.checksum {
        out.extend_from_slice(&[0; 4]);
    }
    if let Some(k) = header.key {
        out.extend_from_slice(&k.to_be_bytes());
    }
    if let Some(s) = header.sequence {
        out.extend_from_slice(&s.to_be_bytes());
    }
    out.extend_from_slice(payload);
    if header.checksum {
        let sum = internet_checksum(&[&out]);
        out[4..6].copy_from_slice(&sum.to_be_bytes());
    }
    out
}

/// Write `sequence` into a GRE packet that carries a sequence number, and redo its checksum
/// when it has one, so the number can be given at the moment of sending: a peer that checks
/// sequence numbers (a Linux `gre`/`gretap` with `iseq`) drops one that goes backwards. False,
/// with nothing changed, for a packet that carries none.
pub fn stamp_sequence(packet: &mut [u8], sequence: u32) -> bool {
    if packet.len() < 4 || packet[0] & FLAG_SEQUENCE == 0 {
        return false;
    }
    let has_checksum = packet[0] & FLAG_CHECKSUM != 0;
    let at = 4 + 4 * usize::from(has_checksum) + 4 * usize::from(packet[0] & FLAG_KEY != 0);
    if packet.len() < at + 4 {
        return false;
    }
    packet[at..at + 4].copy_from_slice(&sequence.to_be_bytes());
    if has_checksum {
        packet[4..6].copy_from_slice(&[0, 0]);
        let sum = internet_checksum(&[packet]);
        packet[4..6].copy_from_slice(&sum.to_be_bytes());
    }
    true
}

/// The Internet checksum (RFC 1071) over the parts in order, as if concatenated.
pub fn internet_checksum(parts: &[&[u8]]) -> u16 {
    let mut sum: u32 = 0;
    let mut odd: Option<u8> = None;
    for part in parts {
        for &b in *part {
            match odd.take() {
                Some(hi) => sum += u32::from(u16::from_be_bytes([hi, b])),
                None => odd = Some(b),
            }
        }
    }
    if let Some(hi) = odd {
        sum += u32::from(u16::from_be_bytes([hi, 0]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

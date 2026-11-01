//! The bytes of a classic pcap file, and the IP/TCP/UDP headers NetGet synthesises around
//! what its sockets carried.
//!
//! Pure functions, no I/O. NetGet never sees a packet — it sees what `read()` returned and
//! what `write()` accepted — so every header here is fabricated from the connection's real
//! 4-tuple, with checksums computed so a dissector has nothing to complain about.
//!
//! The link type is `LINKTYPE_RAW` (101): each record is a bare IPv4 or IPv6 packet, the
//! version nibble saying which, so one file holds both families without an invented
//! Ethernet header.

use std::net::{IpAddr, Ipv6Addr, SocketAddr};

/// `LINKTYPE_RAW`: the record is an IP packet, version in its first nibble.
pub const LINKTYPE_RAW: u32 = 101;
/// Classic pcap, microsecond timestamps, written little-endian.
pub const PCAP_MAGIC_MICROS: u32 = 0xa1b2_c3d4;
/// The global header's length.
pub const GLOBAL_HEADER_LEN: usize = 24;
/// A record header's length.
pub const RECORD_HEADER_LEN: usize = 16;
/// The snapshot length the header declares. Every record is written whole, so this only
/// has to be at least the largest packet [`tcp_packet`] or [`udp_packet`] builds.
pub const SNAPLEN: u32 = 262_144;
/// The most payload one synthesised TCP segment carries. A single `write()` can accept more
/// than an IP packet can hold, so larger chunks are split into consecutive segments.
pub const MAX_SEGMENT_PAYLOAD: usize = 65_000;

/// TCP flag bits.
pub const FIN: u8 = 0x01;
pub const SYN: u8 = 0x02;
pub const PSH: u8 = 0x08;
pub const ACK: u8 = 0x10;

const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;

/// The 24-byte global header.
pub fn global_header() -> [u8; GLOBAL_HEADER_LEN] {
    let mut h = [0u8; GLOBAL_HEADER_LEN];
    h[0..4].copy_from_slice(&PCAP_MAGIC_MICROS.to_le_bytes());
    h[4..6].copy_from_slice(&2u16.to_le_bytes());
    h[6..8].copy_from_slice(&4u16.to_le_bytes());
    // thiszone and sigfigs stay zero.
    h[16..20].copy_from_slice(&SNAPLEN.to_le_bytes());
    h[20..24].copy_from_slice(&LINKTYPE_RAW.to_le_bytes());
    h
}

/// Whether `header` is the global header of a classic pcap this module could append to:
/// microsecond magic in either byte order is a pcap, but only our own little-endian
/// `LINKTYPE_RAW` layout can take more records without rewriting the file.
pub fn header_kind(header: &[u8]) -> HeaderKind {
    if header.len() < 4 {
        return HeaderKind::NotPcap;
    }
    let magic_le = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
    let magic_be = u32::from_be_bytes([header[0], header[1], header[2], header[3]]);
    let is_pcap = [0xa1b2_c3d4, 0xa1b2_3c4d].contains(&magic_le)
        || [0xa1b2_c3d4, 0xa1b2_3c4d].contains(&magic_be)
        // pcapng's section header block.
        || magic_le == 0x0a0d_0d0a;
    if !is_pcap {
        return HeaderKind::NotPcap;
    }
    if header.len() >= GLOBAL_HEADER_LEN
        && magic_le == PCAP_MAGIC_MICROS
        && u32::from_le_bytes([header[20], header[21], header[22], header[23]]) == LINKTYPE_RAW
    {
        HeaderKind::Appendable
    } else {
        HeaderKind::OtherPcap
    }
}

/// What [`header_kind`] found at the start of an existing file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderKind {
    /// Not a capture at all — NetGet refuses to overwrite it.
    NotPcap,
    /// A capture, but not one this writer can extend in place.
    OtherPcap,
    /// One of NetGet's own captures.
    Appendable,
}

/// A record header for a packet of `len` bytes at `micros` since the epoch.
pub fn record_header(micros: u64, len: usize) -> [u8; RECORD_HEADER_LEN] {
    let mut h = [0u8; RECORD_HEADER_LEN];
    let secs = (micros / 1_000_000) as u32;
    let usecs = (micros % 1_000_000) as u32;
    h[0..4].copy_from_slice(&secs.to_le_bytes());
    h[4..8].copy_from_slice(&usecs.to_le_bytes());
    h[8..12].copy_from_slice(&(len as u32).to_le_bytes());
    h[12..16].copy_from_slice(&(len as u32).to_le_bytes());
    h
}

/// One TCP segment as an IP packet.
#[allow(clippy::too_many_arguments)]
pub fn tcp_packet(
    src: SocketAddr,
    dst: SocketAddr,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: &[u8],
    ip_id: u16,
) -> Vec<u8> {
    let (src_ip, dst_ip) = same_family(src.ip(), dst.ip());
    let mut seg = Vec::with_capacity(20 + payload.len());
    seg.extend_from_slice(&src.port().to_be_bytes());
    seg.extend_from_slice(&dst.port().to_be_bytes());
    seg.extend_from_slice(&seq.to_be_bytes());
    let ack_value = if flags & ACK != 0 { ack } else { 0 };
    seg.extend_from_slice(&ack_value.to_be_bytes());
    seg.push(5 << 4);
    seg.push(flags);
    seg.extend_from_slice(&65_535u16.to_be_bytes());
    seg.extend_from_slice(&[0, 0, 0, 0]);
    seg.extend_from_slice(payload);
    let sum = transport_checksum(src_ip, dst_ip, PROTO_TCP, &seg);
    seg[16..18].copy_from_slice(&sum.to_be_bytes());
    ip_packet(src_ip, dst_ip, PROTO_TCP, &seg, ip_id)
}

/// One UDP datagram as an IP packet. A payload too large for one IP packet is cut to fit;
/// no real datagram is that large, so it never happens with bytes a socket carried.
pub fn udp_packet(src: SocketAddr, dst: SocketAddr, payload: &[u8], ip_id: u16) -> Vec<u8> {
    let (src_ip, dst_ip) = same_family(src.ip(), dst.ip());
    let max = match src_ip {
        IpAddr::V4(_) => 65_535 - 20 - 8,
        IpAddr::V6(_) => 65_535 - 8,
    };
    let payload = &payload[..payload.len().min(max)];
    let len = (8 + payload.len()) as u16;
    let mut dgram = Vec::with_capacity(len as usize);
    dgram.extend_from_slice(&src.port().to_be_bytes());
    dgram.extend_from_slice(&dst.port().to_be_bytes());
    dgram.extend_from_slice(&len.to_be_bytes());
    dgram.extend_from_slice(&[0, 0]);
    dgram.extend_from_slice(payload);
    let mut sum = transport_checksum(src_ip, dst_ip, PROTO_UDP, &dgram);
    if sum == 0 {
        // RFC 768: a computed zero is sent as all ones; zero means "no checksum".
        sum = 0xffff;
    }
    dgram[6..8].copy_from_slice(&sum.to_be_bytes());
    ip_packet(src_ip, dst_ip, PROTO_UDP, &dgram, ip_id)
}

/// Both addresses in one family: IPv4 when both are IPv4 (an IPv4-mapped IPv6 address
/// counts), IPv6 otherwise.
fn same_family(a: IpAddr, b: IpAddr) -> (IpAddr, IpAddr) {
    let a = unmap(a);
    let b = unmap(b);
    match (a, b) {
        (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_)) => (a, b),
        _ => (IpAddr::V6(to_v6(a)), IpAddr::V6(to_v6(b))),
    }
}

fn unmap(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        v4 => v4,
    }
}

fn to_v6(ip: IpAddr) -> Ipv6Addr {
    match ip {
        IpAddr::V4(v4) => v4.to_ipv6_mapped(),
        IpAddr::V6(v6) => v6,
    }
}

fn ip_packet(src: IpAddr, dst: IpAddr, proto: u8, payload: &[u8], ip_id: u16) -> Vec<u8> {
    match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            let total = (20 + payload.len()) as u16;
            let mut p = Vec::with_capacity(total as usize);
            p.push(0x45);
            p.push(0);
            p.extend_from_slice(&total.to_be_bytes());
            p.extend_from_slice(&ip_id.to_be_bytes());
            // Don't Fragment: these packets are never fragments.
            p.extend_from_slice(&0x4000u16.to_be_bytes());
            p.push(64);
            p.push(proto);
            p.extend_from_slice(&[0, 0]);
            p.extend_from_slice(&s.octets());
            p.extend_from_slice(&d.octets());
            let sum = ones_complement(&p[..20]);
            p[10..12].copy_from_slice(&sum.to_be_bytes());
            p.extend_from_slice(payload);
            p
        }
        (s, d) => {
            let (s, d) = (to_v6(s), to_v6(d));
            let mut p = Vec::with_capacity(40 + payload.len());
            p.extend_from_slice(&[0x60, 0, 0, 0]);
            p.extend_from_slice(&(payload.len() as u16).to_be_bytes());
            p.push(proto);
            p.push(64);
            p.extend_from_slice(&s.octets());
            p.extend_from_slice(&d.octets());
            p.extend_from_slice(payload);
            p
        }
    }
}

fn transport_checksum(src: IpAddr, dst: IpAddr, proto: u8, segment: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(40 + segment.len());
    match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            pseudo.extend_from_slice(&s.octets());
            pseudo.extend_from_slice(&d.octets());
            pseudo.push(0);
            pseudo.push(proto);
            pseudo.extend_from_slice(&(segment.len() as u16).to_be_bytes());
        }
        (s, d) => {
            pseudo.extend_from_slice(&to_v6(s).octets());
            pseudo.extend_from_slice(&to_v6(d).octets());
            pseudo.extend_from_slice(&(segment.len() as u32).to_be_bytes());
            pseudo.extend_from_slice(&[0, 0, 0, proto]);
        }
    }
    pseudo.extend_from_slice(segment);
    ones_complement(&pseudo)
}

fn ones_complement(bytes: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for chunk in bytes.chunks(2) {
        let word = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]])
        } else {
            u16::from_be_bytes([chunk[0], 0])
        };
        sum += word as u32;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

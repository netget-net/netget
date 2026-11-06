//! Link types, IPv4/TCP crafting and frame decoding for the DataLink client and server.
//!
//! **Nothing in this file performs I/O**, so all of it is testable against literal bytes with
//! no capture access (`tests/client/datalink/packet_test.rs`).
//!
//! # Why the link type matters
//!
//! libpcap hands back, and accepts, frames in the interface's *link-layer* format, which is
//! not always Ethernet. macOS `lo0` — the DataLink server's default interface — is `DLT_NULL`:
//! every frame starts with a 4-byte address family in host byte order, not 14 bytes of MACs
//! and an EtherType. Treating it as Ethernet put garbage on the wire for a structured
//! `inject_frame` and decoded garbage `dst_mac` / `src_mac` / `ethertype` out of every
//! captured frame. [`LinkType`] is read from the open handle (`pcap_datalink`) and every
//! builder and decoder here takes it.
//!
//! | `link_type` | DLT | Header | Built from |
//! |---|---|---|---|
//! | `EN10MB` | 1 | 14 bytes: dst MAC, src MAC, EtherType | `dst_mac`, `src_mac`, `ethertype` |
//! | `NULL` | 0 | 4 bytes: address family, **host** byte order | `ethertype` ipv4/ipv6 |
//! | `LOOP` | 108 | 4 bytes: address family, **network** byte order | `ethertype` ipv4/ipv6 |
//! | `RAW` / `IPV4` / `IPV6` | 12, 14, 101 / 228 / 229 | none: the frame is the IP packet | nothing |
//! | `LINUX_SLL` | 113 | 16-byte cooked header | decoded only; cannot be injected |
//!
//! # Crafting
//!
//! [`build_ipv4_tcp`] turns a structured description — addresses, ports, flag names, sequence
//! numbers, and TCP options as a list of objects including MPTCP `mp_capable` — into an IPv4
//! packet with both checksums computed, and [`link_header`] prepends whatever the link needs.
//! The model never writes header bytes.
//!
//! # Decoding
//!
//! [`decode_frame`] reads the link header for the link type it is told, then IPv4 and
//! TCP / UDP / ICMP, including every TCP option (MPTCP subtypes by name). TCP options are
//! decoded in the same spelling [`encode_tcp_options`] accepts, so a captured option list can
//! be handed straight back.

use anyhow::{bail, Context, Result};
use serde_json::{json, Map, Value};
use std::net::{IpAddr, Ipv4Addr};

use crate::server::tuntap::packet::{
    checksum16, icmpv4_type_name, ip_protocol_name, tcp_flag_bits, tcp_flag_names, TCP_FLAG_NAMES,
};

// ---------------------------------------------------------------------------
// Link types
// ---------------------------------------------------------------------------

/// The link-layer format of a pcap handle, as `pcap_datalink` reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LinkType {
    /// `DLT_EN10MB`: Ethernet.
    #[default]
    Ethernet,
    /// `DLT_NULL`: BSD loopback, a 4-byte address family in host byte order.
    Null,
    /// `DLT_LOOP`: OpenBSD loopback, a 4-byte address family in network byte order.
    Loop,
    /// `DLT_RAW`: the frame is an IPv4 or IPv6 packet with no link header.
    Raw,
    /// `LINKTYPE_IPV4`: IPv4 only, no link header.
    Ipv4,
    /// `LINKTYPE_IPV6`: IPv6 only, no link header.
    Ipv6,
    /// `DLT_LINUX_SLL`: Linux cooked capture (the `any` device). Decoded, never injected.
    LinuxSll,
    /// Anything else. Frames are passed through whole; nothing is built or decoded.
    Other(i32),
}

impl LinkType {
    /// From the DLT value `pcap_datalink` returns.
    ///
    /// `DLT_RAW` is 12 on most platforms and 14 on OpenBSD, and some libpcaps report the
    /// `LINKTYPE_RAW` value 101 — all three mean the same thing.
    pub fn from_dlt(dlt: i32) -> Self {
        match dlt {
            0 => Self::Null,
            1 => Self::Ethernet,
            12 | 14 | 101 => Self::Raw,
            108 => Self::Loop,
            113 => Self::LinuxSll,
            228 => Self::Ipv4,
            229 => Self::Ipv6,
            other => Self::Other(other),
        }
    }

    /// The name events report as `link_type` — libpcap's own (`pcap_datalink_val_to_name`).
    pub fn name(&self) -> String {
        match self {
            Self::Ethernet => "EN10MB".to_string(),
            Self::Null => "NULL".to_string(),
            Self::Loop => "LOOP".to_string(),
            Self::Raw => "RAW".to_string(),
            Self::Ipv4 => "IPV4".to_string(),
            Self::Ipv6 => "IPV6".to_string(),
            Self::LinuxSll => "LINUX_SLL".to_string(),
            Self::Other(n) => format!("DLT_{n}"),
        }
    }

    /// Bytes of link header in front of the network-layer packet; `None` when unknown.
    pub fn header_len(&self) -> Option<usize> {
        match self {
            Self::Ethernet => Some(14),
            Self::Null | Self::Loop => Some(4),
            Self::Raw | Self::Ipv4 | Self::Ipv6 => Some(0),
            Self::LinuxSll => Some(16),
            Self::Other(_) => None,
        }
    }

    /// Whether this link carries MAC addresses at all.
    pub fn has_macs(&self) -> bool {
        matches!(self, Self::Ethernet)
    }
}

/// `AF_INET`, which is 2 on every platform that has a loopback link header.
pub const AF_INET: u32 = 2;

/// `AF_INET6` on this platform — what a built `NULL` / `LOOP` header carries for IPv6.
#[cfg(any(target_os = "macos", target_os = "ios"))]
pub const AF_INET6: u32 = 30;
/// `AF_INET6` on this platform — what a built `NULL` / `LOOP` header carries for IPv6.
#[cfg(any(target_os = "freebsd", target_os = "dragonfly"))]
pub const AF_INET6: u32 = 28;
/// `AF_INET6` on this platform — what a built `NULL` / `LOOP` header carries for IPv6.
#[cfg(any(target_os = "openbsd", target_os = "netbsd"))]
pub const AF_INET6: u32 = 24;
/// `AF_INET6` on this platform — what a built `NULL` / `LOOP` header carries for IPv6.
#[cfg(not(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "dragonfly",
    target_os = "openbsd",
    target_os = "netbsd"
)))]
pub const AF_INET6: u32 = 10;

/// The address family a loopback header carries, as the name events report as `family`.
///
/// Every BSD's `AF_INET6` value is accepted when decoding (24, 28, 30), as libpcap's own
/// documentation for `DLT_NULL` says a reader must, because a capture file can come from any
/// of them.
pub fn family_name(af: u32) -> Option<&'static str> {
    match af {
        AF_INET => Some("AF_INET"),
        24 | 28 | 30 => Some("AF_INET6"),
        n if n == AF_INET6 => Some("AF_INET6"),
        _ => None,
    }
}

fn family_for_ethertype(ethertype: u16, link: LinkType) -> Result<u32> {
    match ethertype {
        0x0800 => Ok(AF_INET),
        0x86dd => Ok(AF_INET6),
        other => bail!(
            "this interface's link type is {} (a 4-byte address-family header, not Ethernet), \
             which can carry only IPv4 or IPv6; 'ethertype' 0x{other:04x} cannot be expressed \
             in it. Use \"ipv4\" or \"ipv6\".",
            link.name()
        ),
    }
}

/// The link-layer header for one frame on `link`.
///
/// `macs` is `(dst, src)` and is required on Ethernet and refused everywhere else: a loopback
/// or raw-IP link has no MAC addresses, and silently dropping the ones the caller gave would
/// hide a misunderstanding about which interface they are on.
pub fn link_header(
    link: LinkType,
    ethertype: u16,
    macs: Option<([u8; 6], [u8; 6])>,
) -> Result<Vec<u8>> {
    match link {
        LinkType::Ethernet => {
            let Some((dst, src)) = macs else {
                bail!(
                    "this interface is Ethernet (link_type EN10MB): give 'dst_mac' and \
                     'src_mac' — the next hop's MAC and this interface's"
                );
            };
            let mut h = Vec::with_capacity(14);
            h.extend_from_slice(&dst);
            h.extend_from_slice(&src);
            h.extend_from_slice(&ethertype.to_be_bytes());
            Ok(h)
        }
        LinkType::Null | LinkType::Loop => {
            refuse_macs(link, macs.is_some())?;
            let af = family_for_ethertype(ethertype, link)?;
            Ok(if link == LinkType::Null {
                af.to_ne_bytes().to_vec()
            } else {
                af.to_be_bytes().to_vec()
            })
        }
        LinkType::Raw | LinkType::Ipv4 | LinkType::Ipv6 => {
            refuse_macs(link, macs.is_some())?;
            let ok = match link {
                LinkType::Ipv4 => ethertype == 0x0800,
                LinkType::Ipv6 => ethertype == 0x86dd,
                _ => ethertype == 0x0800 || ethertype == 0x86dd,
            };
            if !ok {
                bail!(
                    "this interface's link type is {} (no link header: the frame is the IP \
                     packet itself); 'ethertype' 0x{ethertype:04x} cannot be carried on it",
                    link.name()
                );
            }
            Ok(Vec::new())
        }
        LinkType::LinuxSll => bail!(
            "this capture is Linux cooked mode (link_type LINUX_SLL, the 'any' device), which \
             libpcap cannot inject into. Open a real interface such as 'eth0' or 'lo'."
        ),
        LinkType::Other(n) => bail!(
            "this interface's link type is DLT_{n}, which NetGet does not know how to frame; \
             pass the whole frame as 'frame_hex' instead"
        ),
    }
}

fn refuse_macs(link: LinkType, given: bool) -> Result<()> {
    if given {
        bail!(
            "this interface's link type is {} — it has no MAC addresses, so 'dst_mac' / \
             'src_mac' cannot apply. Leave them out; give 'ethertype' (\"ipv4\" or \"ipv6\") \
             and the header is built for this link.",
            link.name()
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// remote_addr
// ---------------------------------------------------------------------------

/// The host and optional port a DataLink client's `remote_addr` names, if it names one.
///
/// `"127.0.0.1:3333"`, `"10.0.0.2"`, `"[::1]:80"` and `"localhost:80"` are targets; an
/// interface name (`"eth0"`, which the startup examples pass) is not, and gives `None`.
/// Port 0 is treated as no port.
pub fn parse_target(remote_addr: &str) -> Option<(IpAddr, Option<u16>)> {
    let s = remote_addr.trim();
    if let Ok(sa) = s.parse::<std::net::SocketAddr>() {
        return Some((sa.ip(), (sa.port() != 0).then_some(sa.port())));
    }
    if let Ok(ip) = s
        .trim_start_matches('[')
        .trim_end_matches(']')
        .parse::<IpAddr>()
    {
        return Some((ip, None));
    }
    let (host, port) = s.rsplit_once(':')?;
    let port: u16 = port.parse().ok()?;
    let ip = match host {
        "localhost" => IpAddr::V4(Ipv4Addr::LOCALHOST),
        _ => return None,
    };
    Some((ip, (port != 0).then_some(port)))
}

/// The capture filter a target implies: `host X and port Y`, or `host X` without a port.
pub fn target_filter(ip: IpAddr, port: Option<u16>) -> String {
    match port {
        Some(p) => format!("host {ip} and port {p}"),
        None => format!("host {ip}"),
    }
}

// ---------------------------------------------------------------------------
// Field parsing
// ---------------------------------------------------------------------------

fn get_uint(v: &Value, key: &str, max: u64) -> Result<Option<u64>> {
    let Some(raw) = v.get(key) else {
        return Ok(None);
    };
    if raw.is_null() {
        return Ok(None);
    }
    let n = if let Some(n) = raw.as_u64() {
        n
    } else if let Some(s) = raw.as_str().and_then(|s| s.trim().strip_prefix("0x")) {
        u64::from_str_radix(s, 16)
            .with_context(|| format!("'{key}' {raw} is not a 0x-prefixed hex number"))?
    } else {
        bail!("'{key}' must be a non-negative number (or a 0x-prefixed hex string); got {raw}");
    };
    if n > max {
        bail!("'{key}' is {n}, which does not fit: the maximum is {max}");
    }
    Ok(Some(n))
}

fn get_ipv4(v: &Value, key: &str) -> Result<Option<Ipv4Addr>> {
    match v.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => match s.trim().parse::<IpAddr>() {
            Ok(IpAddr::V4(a)) => Ok(Some(a)),
            Ok(IpAddr::V6(_)) => {
                bail!("'{key}' {s:?} is IPv6; this action builds IPv4 packets only")
            }
            Err(_) => bail!("'{key}' {s:?} is not an IPv4 address, e.g. \"127.0.0.1\""),
        },
        Some(other) => bail!("'{key}' must be an IPv4 address string; got {other}"),
    }
}

fn parse_flags(v: Option<&Value>) -> Result<u8> {
    let names: Vec<String> = match v {
        None | Some(Value::Null) => return Ok(0x02),
        Some(Value::Array(items)) => items
            .iter()
            .map(|i| {
                i.as_str()
                    .map(|s| s.to_string())
                    .with_context(|| format!("'flags' entries must be names; got {i}"))
            })
            .collect::<Result<_>>()?,
        Some(Value::String(s)) => s
            .split(|c: char| c == ',' || c == '|' || c == '+' || c.is_whitespace())
            .filter(|p| !p.is_empty())
            .map(|p| p.to_string())
            .collect(),
        Some(other) => bail!(
            "'flags' must be a list of names such as [\"syn\"] or [\"syn\", \"ack\"]; got {other}"
        ),
    };
    tcp_flag_bits(&names).map_err(|e| anyhow::anyhow!("{}", e.0))
}

/// TCP payload bytes from `payload` + its required `payload_encoding` (`hex` / `utf8`).
fn parse_l4_payload(v: &Value) -> Result<Vec<u8>> {
    let Some(payload) = v.get("payload").and_then(|p| p.as_str()) else {
        return Ok(Vec::new());
    };
    match v.get("payload_encoding").and_then(|e| e.as_str()) {
        Some("utf8") => Ok(payload.as_bytes().to_vec()),
        Some("hex") => decode_hex_loose(payload).context("invalid hex in 'payload'"),
        Some(other) => bail!("'payload_encoding' {other:?} is not \"hex\" or \"utf8\""),
        None => bail!(
            "'payload' was given without 'payload_encoding'. Say \"utf8\" (send its characters) \
             or \"hex\" (decode it) — nothing is guessed."
        ),
    }
}

/// Hex with the separators a model copying a dump writes (`:`, `-`, `.`, whitespace) removed.
pub fn decode_hex_loose(s: &str) -> Result<Vec<u8>> {
    let cleaned: String = s
        .chars()
        .filter(|c| !matches!(c, ' ' | ':' | '-' | '.' | '\n' | '\r' | '\t'))
        .collect();
    let cleaned = cleaned.strip_prefix("0x").unwrap_or(&cleaned);
    Ok(hex::decode(cleaned)?)
}

// ---------------------------------------------------------------------------
// TCP options
// ---------------------------------------------------------------------------

/// MP_CAPABLE flag bits (RFC 8684 §3.1), named as the decoder reports them.
pub const MP_CAPABLE_FLAG_NAMES: [(u8, &str); 4] = [
    (0x80, "checksum_required"),
    (0x40, "extensibility"),
    (0x20, "no_new_subflows_to_source"),
    (0x01, "hmac_sha256"),
];

/// MPTCP option subtypes (RFC 8684 §3, IANA "MPTCP Option Subtypes").
pub fn mptcp_subtype_name(subtype: u8) -> &'static str {
    match subtype {
        0 => "mp_capable",
        1 => "mp_join",
        2 => "dss",
        3 => "add_addr",
        4 => "remove_addr",
        5 => "mp_prio",
        6 => "mp_fail",
        7 => "mp_fastclose",
        8 => "mp_tcprst",
        _ => "unknown",
    }
}

/// The TCP option kind names [`encode_tcp_options`] accepts.
pub const TCP_OPTION_KINDS: &[&str] = &[
    "eol",
    "nop",
    "mss",
    "wscale",
    "sack_perm",
    "sack",
    "timestamps",
    "mp_capable",
    "mptcp",
];

/// The most TCP option bytes a header can carry (data offset 15 words − 5).
pub const MAX_TCP_OPTION_BYTES: usize = 40;

fn mp_capable_flags(v: Option<&Value>) -> Result<u8> {
    match v {
        None | Some(Value::Null) => Ok(0x01),
        Some(Value::Array(items)) => {
            let mut bits = 0u8;
            for item in items {
                let name = item.as_str().with_context(|| {
                    format!("mp_capable 'flags' entries must be names; got {item}")
                })?;
                let Some((bit, _)) = MP_CAPABLE_FLAG_NAMES
                    .iter()
                    .find(|(_, n)| *n == name.trim().to_ascii_lowercase())
                else {
                    bail!(
                        "unknown mp_capable flag {name:?}; known: {} (or give the byte as a \
                         number, e.g. 1)",
                        MP_CAPABLE_FLAG_NAMES
                            .iter()
                            .map(|(_, n)| *n)
                            .collect::<Vec<_>>()
                            .join(", ")
                    );
                };
                bits |= bit;
            }
            Ok(bits)
        }
        Some(_) => Ok(get_uint(&json!({"flags": v}), "flags", 0xff)?.unwrap_or(0) as u8),
    }
}

/// Encode a structured option list, padded with EOL to a 4-byte boundary.
///
/// Each entry is an object with a `kind`:
///
/// - `{"kind":"mss","value":1460}`, `{"kind":"wscale","shift":7}`, `{"kind":"sack_perm"}`,
///   `{"kind":"timestamps","tsval":1,"tsecr":0}`, `{"kind":"nop"}`, `{"kind":"eol"}`,
///   `{"kind":"sack","blocks":[[left,right], …]}`
/// - `{"kind":"mp_capable","version":1,"flags":1}` — MPTCP MP_CAPABLE (option 30, subtype
///   0). `flags` is the byte or a list of names from [`MP_CAPABLE_FLAG_NAMES`] (default
///   `0x01`, HMAC-SHA256); optional `sender_key` / `receiver_key` (64-bit, a number or a
///   `0x` string), `data_level_length` and `checksum` for the third-ACK forms.
/// - escape hatch: `{"kind": 254, "data_hex": "…"}` — any kind number, with the bytes after
///   the kind and length octets; `{"kind":"mptcp","data_hex":"…"}` for an MPTCP subtype this
///   builder has no fields for.
pub fn encode_tcp_options(options: &[Value]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    for (i, opt) in options.iter().enumerate() {
        let kind = opt
            .get("kind")
            .with_context(|| format!("TCP option {i} has no 'kind': {opt}"))?;
        if let Some(n) = kind.as_u64() {
            let n = u8::try_from(n).with_context(|| format!("TCP option kind {n} is over 255"))?;
            let data = match opt.get("data_hex").and_then(|d| d.as_str()) {
                Some(h) => {
                    decode_hex_loose(h).with_context(|| format!("TCP option {i} 'data_hex'"))?
                }
                None => Vec::new(),
            };
            if n <= 1 {
                if !data.is_empty() {
                    bail!("TCP option kind {n} is a single byte and carries no data");
                }
                out.push(n);
            } else {
                push_option(&mut out, n, &data)?;
            }
            continue;
        }
        let name = kind
            .as_str()
            .with_context(|| format!("TCP option {i} 'kind' must be a name or a number: {kind}"))?
            .trim()
            .to_ascii_lowercase();
        match name.as_str() {
            "eol" => out.push(0),
            "nop" => out.push(1),
            "mss" => {
                let v = get_uint(opt, "value", 0xffff)?
                    .context("mss needs 'value', e.g. {\"kind\":\"mss\",\"value\":1460}")?;
                push_option(&mut out, 2, &(v as u16).to_be_bytes())?;
            }
            "wscale" => {
                let s = get_uint(opt, "shift", 14)?.context(
                    "wscale needs 'shift' (0-14), e.g. {\"kind\":\"wscale\",\"shift\":7}",
                )?;
                push_option(&mut out, 3, &[s as u8])?;
            }
            "sack_perm" => push_option(&mut out, 4, &[])?,
            "sack" => {
                let blocks = opt
                    .get("blocks")
                    .and_then(|b| b.as_array())
                    .context("sack needs 'blocks': [[left, right], …]")?;
                let mut data = Vec::new();
                for b in blocks {
                    let pair = b
                        .as_array()
                        .filter(|p| p.len() == 2)
                        .with_context(|| format!("each sack block is [left, right]; got {b}"))?;
                    for edge in pair {
                        let e = edge
                            .as_u64()
                            .filter(|e| *e <= u32::MAX as u64)
                            .with_context(|| format!("sack edge {edge} is not a 32-bit number"))?;
                        data.extend_from_slice(&(e as u32).to_be_bytes());
                    }
                }
                push_option(&mut out, 5, &data)?;
            }
            "timestamps" => {
                let tsval = get_uint(opt, "tsval", u32::MAX as u64)?.unwrap_or(0) as u32;
                let tsecr = get_uint(opt, "tsecr", u32::MAX as u64)?.unwrap_or(0) as u32;
                let mut data = tsval.to_be_bytes().to_vec();
                data.extend_from_slice(&tsecr.to_be_bytes());
                push_option(&mut out, 8, &data)?;
            }
            "mp_capable" => {
                let version = get_uint(opt, "version", 15)?.unwrap_or(1) as u8;
                let flags = mp_capable_flags(opt.get("flags"))?;
                let mut data = vec![version & 0x0f, flags];
                let sender = get_uint(opt, "sender_key", u64::MAX)?;
                let receiver = get_uint(opt, "receiver_key", u64::MAX)?;
                if receiver.is_some() && sender.is_none() {
                    bail!("mp_capable 'receiver_key' needs 'sender_key' before it (RFC 8684 §3.1)");
                }
                if let Some(k) = sender {
                    data.extend_from_slice(&k.to_be_bytes());
                }
                if let Some(k) = receiver {
                    data.extend_from_slice(&k.to_be_bytes());
                }
                if let Some(l) = get_uint(opt, "data_level_length", 0xffff)? {
                    data.extend_from_slice(&(l as u16).to_be_bytes());
                    if let Some(c) = get_uint(opt, "checksum", 0xffff)? {
                        data.extend_from_slice(&(c as u16).to_be_bytes());
                    }
                }
                push_option(&mut out, 30, &data)?;
            }
            "mptcp" => {
                let data = opt
                    .get("data_hex")
                    .and_then(|d| d.as_str())
                    .context("an 'mptcp' option needs 'data_hex' (subtype byte onward); for MP_CAPABLE use kind \"mp_capable\"")?;
                push_option(&mut out, 30, &decode_hex_loose(data)?)?;
            }
            other => bail!(
                "unknown TCP option kind {other:?}; known: {} — or give a number with 'data_hex'",
                TCP_OPTION_KINDS.join(", ")
            ),
        }
    }
    while out.len() % 4 != 0 {
        out.push(0);
    }
    if out.len() > MAX_TCP_OPTION_BYTES {
        bail!(
            "the TCP options come to {} bytes; a TCP header has room for {MAX_TCP_OPTION_BYTES}",
            out.len()
        );
    }
    Ok(out)
}

fn push_option(out: &mut Vec<u8>, kind: u8, data: &[u8]) -> Result<()> {
    let len = data.len() + 2;
    if len > MAX_TCP_OPTION_BYTES {
        bail!("TCP option kind {kind} would be {len} bytes; options have {MAX_TCP_OPTION_BYTES} in all");
    }
    out.push(kind);
    out.push(len as u8);
    out.extend_from_slice(data);
    Ok(())
}

fn key_hex(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

/// Decode TCP option bytes into the structured list [`encode_tcp_options`] accepts.
///
/// EOL ends the list and is not reported (it is padding). An option whose length octet is
/// impossible is reported as `{"kind": n, "malformed": true}` and ends decoding.
pub fn decode_tcp_options(bytes: &[u8]) -> Vec<Value> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let kind = bytes[i];
        match kind {
            0 => break,
            1 => {
                out.push(json!({"kind": "nop"}));
                i += 1;
                continue;
            }
            _ => {}
        }
        let Some(&len) = bytes.get(i + 1) else {
            out.push(json!({"kind": kind, "malformed": true}));
            break;
        };
        let len = len as usize;
        if len < 2 || i + len > bytes.len() {
            out.push(json!({"kind": kind, "malformed": true}));
            break;
        }
        let d = &bytes[i + 2..i + len];
        let decoded = match (kind, d.len()) {
            (2, 2) => json!({"kind": "mss", "value": u16::from_be_bytes([d[0], d[1]])}),
            (3, 1) => json!({"kind": "wscale", "shift": d[0]}),
            (4, 0) => json!({"kind": "sack_perm"}),
            (5, n) if n % 8 == 0 => json!({
                "kind": "sack",
                "blocks": d.chunks(8).map(|c| json!([
                    u32::from_be_bytes([c[0], c[1], c[2], c[3]]),
                    u32::from_be_bytes([c[4], c[5], c[6], c[7]]),
                ])).collect::<Vec<_>>()
            }),
            (8, 8) => json!({
                "kind": "timestamps",
                "tsval": u32::from_be_bytes([d[0], d[1], d[2], d[3]]),
                "tsecr": u32::from_be_bytes([d[4], d[5], d[6], d[7]]),
            }),
            (30, n) if n >= 2 => decode_mptcp(d),
            _ => json!({"kind": kind, "data_hex": hex::encode(d)}),
        };
        out.push(decoded);
        i += len;
    }
    out
}

fn decode_mptcp(d: &[u8]) -> Value {
    let subtype = d[0] >> 4;
    if subtype == 0 {
        let flags = d[1];
        let mut o = Map::new();
        o.insert("kind".into(), json!("mp_capable"));
        o.insert("version".into(), json!(d[0] & 0x0f));
        o.insert("flags".into(), json!(flags));
        o.insert(
            "flag_names".into(),
            json!(MP_CAPABLE_FLAG_NAMES
                .iter()
                .filter(|(b, _)| flags & b != 0)
                .map(|(_, n)| *n)
                .collect::<Vec<_>>()),
        );
        let rest = &d[2..];
        if rest.len() >= 8 {
            o.insert("sender_key".into(), json!(key_hex(&rest[..8])));
        }
        if rest.len() >= 16 {
            o.insert("receiver_key".into(), json!(key_hex(&rest[8..16])));
        }
        let tail = if rest.len() >= 16 {
            &rest[16..]
        } else if rest.len() >= 8 {
            &rest[8..]
        } else {
            rest
        };
        if tail.len() >= 2 {
            o.insert(
                "data_level_length".into(),
                json!(u16::from_be_bytes([tail[0], tail[1]])),
            );
        }
        if tail.len() >= 4 {
            o.insert(
                "checksum".into(),
                json!(u16::from_be_bytes([tail[2], tail[3]])),
            );
        }
        return Value::Object(o);
    }
    json!({
        "kind": "mptcp",
        "subtype": mptcp_subtype_name(subtype),
        "subtype_number": subtype,
        "data_hex": hex::encode(d),
    })
}

// ---------------------------------------------------------------------------
// IPv4 + TCP building
// ---------------------------------------------------------------------------

/// Where a built packet defaults its destination from: the client's `remote_addr`.
#[derive(Debug, Clone, Copy, Default)]
pub struct BuildDefaults {
    /// Destination address when the action names none.
    pub dst_ip: Option<Ipv4Addr>,
    /// Destination port when the action names none.
    pub dst_port: Option<u16>,
}

/// One TCP flow, from the sender's side.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TcpFlow {
    /// Source address.
    pub src_ip: Ipv4Addr,
    /// Destination address.
    pub dst_ip: Ipv4Addr,
    /// Source port.
    pub src_port: u16,
    /// Destination port.
    pub dst_port: u16,
}

impl TcpFlow {
    /// The capture filter that matches the far end's answers on this flow: TCP from the
    /// destination back to the source, plus ICMP addressed to the source (an unreachable or
    /// time-exceeded about it).
    pub fn reply_filter(&self) -> String {
        format!(
            "(tcp and src host {} and src port {} and dst host {} and dst port {}) or \
             (icmp and dst host {})",
            self.dst_ip, self.dst_port, self.src_ip, self.src_port, self.src_ip
        )
    }
}

/// An IPv4 packet carrying one TCP segment, built from structured fields.
#[derive(Debug, Clone)]
pub struct BuiltTcpPacket {
    /// The IPv4 packet: header, TCP header, options, payload. No link header.
    pub packet: Vec<u8>,
    /// The flow it belongs to.
    pub flow: TcpFlow,
}

/// Build an IPv4 + TCP packet from an action's structured fields, both checksums computed.
///
/// Fields (all optional except where a default cannot exist):
/// `src_ip`, `dst_ip` (IPv4; `dst_ip` defaults from `remote_addr`, `src_ip` to `dst_ip` when
/// that is loopback), `src_port` (default a random ephemeral port), `dst_port` (default from
/// `remote_addr`), `flags` (names, default `["syn"]`), `seq` (default random), `ack` (0),
/// `window` (65535), `urgent` (0), `options` (see [`encode_tcp_options`]), `ttl` (64),
/// `ip_id` (random), `dont_fragment` (true), `tos` (0), and a `payload` with its required
/// `payload_encoding`.
pub fn build_ipv4_tcp(v: &Value, defaults: &BuildDefaults) -> Result<BuiltTcpPacket> {
    use rand::Rng;
    let mut rng = rand::thread_rng();

    let dst_ip = match get_ipv4(v, "dst_ip")? {
        Some(a) => a,
        None => defaults.dst_ip.context(
            "missing 'dst_ip': name the destination IPv4 address (the client's remote_addr \
             names none to default from)",
        )?,
    };
    let src_ip = match get_ipv4(v, "src_ip")? {
        Some(a) => a,
        None if dst_ip.is_loopback() => dst_ip,
        None => bail!(
            "missing 'src_ip': this interface's own IPv4 address (it defaults only for a \
             loopback destination)"
        ),
    };
    let dst_port = match get_uint(v, "dst_port", 0xffff)? {
        Some(p) => p as u16,
        None => defaults.dst_port.context(
            "missing 'dst_port' (the client's remote_addr names no port to default from)",
        )?,
    };
    let src_port = get_uint(v, "src_port", 0xffff)?
        .map(|p| p as u16)
        .unwrap_or_else(|| rng.gen_range(49152..=65535));
    let seq = get_uint(v, "seq", u32::MAX as u64)?
        .map(|s| s as u32)
        .unwrap_or_else(|| rng.gen());
    let ack = get_uint(v, "ack", u32::MAX as u64)?.unwrap_or(0) as u32;
    let window = get_uint(v, "window", 0xffff)?.unwrap_or(65535) as u16;
    let urgent = get_uint(v, "urgent", 0xffff)?.unwrap_or(0) as u16;
    let ttl = get_uint(v, "ttl", 255)?.unwrap_or(64) as u8;
    let ip_id = get_uint(v, "ip_id", 0xffff)?
        .map(|i| i as u16)
        .unwrap_or_else(|| rng.gen());
    let tos = get_uint(v, "tos", 255)?.unwrap_or(0) as u8;
    let df = match v.get("dont_fragment") {
        None | Some(Value::Null) => true,
        Some(Value::Bool(b)) => *b,
        Some(other) => bail!("'dont_fragment' must be true or false; got {other}"),
    };
    let flags = parse_flags(v.get("flags"))?;
    let options = match v.get("options") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(items)) => encode_tcp_options(items)?,
        Some(other) => bail!(
            "'options' must be a list such as [{{\"kind\":\"mss\",\"value\":1460}}, \
             {{\"kind\":\"mp_capable\",\"version\":1,\"flags\":1}}]; got {other}"
        ),
    };
    let payload = parse_l4_payload(v)?;

    let tcp_len = 20 + options.len() + payload.len();
    let total = 20 + tcp_len;
    if total > 65535 {
        bail!("the packet would be {total} bytes; an IPv4 packet is at most 65535");
    }

    let mut tcp = Vec::with_capacity(tcp_len);
    tcp.extend_from_slice(&src_port.to_be_bytes());
    tcp.extend_from_slice(&dst_port.to_be_bytes());
    tcp.extend_from_slice(&seq.to_be_bytes());
    tcp.extend_from_slice(&ack.to_be_bytes());
    tcp.push((((20 + options.len()) / 4) as u8) << 4);
    tcp.push(flags);
    tcp.extend_from_slice(&window.to_be_bytes());
    tcp.extend_from_slice(&[0, 0]);
    tcp.extend_from_slice(&urgent.to_be_bytes());
    tcp.extend_from_slice(&options);
    tcp.extend_from_slice(&payload);
    let c = tcp_checksum_ipv4(src_ip, dst_ip, &tcp);
    tcp[16..18].copy_from_slice(&c.to_be_bytes());

    let mut ip = Vec::with_capacity(total);
    ip.push(0x45);
    ip.push(tos);
    ip.extend_from_slice(&(total as u16).to_be_bytes());
    ip.extend_from_slice(&ip_id.to_be_bytes());
    ip.extend_from_slice(&(if df { 0x4000u16 } else { 0 }).to_be_bytes());
    ip.push(ttl);
    ip.push(6);
    ip.extend_from_slice(&[0, 0]);
    ip.extend_from_slice(&src_ip.octets());
    ip.extend_from_slice(&dst_ip.octets());
    let hc = checksum16(&ip);
    ip[10..12].copy_from_slice(&hc.to_be_bytes());
    ip.extend_from_slice(&tcp);

    Ok(BuiltTcpPacket {
        packet: ip,
        flow: TcpFlow {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
        },
    })
}

/// The TCP checksum over the IPv4 pseudo-header and `segment` (whose checksum field must be
/// zero, or the result is the verification sum: 0 for a correct segment).
pub fn tcp_checksum_ipv4(src: Ipv4Addr, dst: Ipv4Addr, segment: &[u8]) -> u16 {
    l4_checksum_ipv4(src, dst, 6, segment)
}

fn l4_checksum_ipv4(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, segment: &[u8]) -> u16 {
    let mut buf = Vec::with_capacity(12 + segment.len());
    buf.extend_from_slice(&src.octets());
    buf.extend_from_slice(&dst.octets());
    buf.push(0);
    buf.push(proto);
    buf.extend_from_slice(&(segment.len() as u16).to_be_bytes());
    buf.extend_from_slice(segment);
    checksum16(&buf)
}

/// The IPv4 header checksum of `header` (checksum field zeroed, or 0 back for a correct one).
pub fn ipv4_header_checksum(header: &[u8]) -> u16 {
    checksum16(header)
}

// ---------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------

/// The link header of one frame, read for its link type.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LinkFields {
    /// Destination MAC, Ethernet only.
    pub dst_mac: Option<String>,
    /// Source MAC, Ethernet only.
    pub src_mac: Option<String>,
    /// EtherType as `0x0800`; on a loopback link, the one the family implies.
    pub ethertype: Option<String>,
    /// `AF_INET` / `AF_INET6` (or the number) on a `NULL` / `LOOP` link.
    pub family: Option<Value>,
    /// Where the network-layer packet starts, if the header was readable.
    pub l3_offset: Option<usize>,
}

fn format_mac(b: &[u8]) -> String {
    crate::server::tuntap::packet::format_mac(b)
}

/// Read the link header of `frame` for `link`.
pub fn decode_link(frame: &[u8], link: LinkType) -> LinkFields {
    let mut f = LinkFields::default();
    match link {
        LinkType::Ethernet => {
            if frame.len() >= 14 {
                f.dst_mac = Some(format_mac(&frame[0..6]));
                f.src_mac = Some(format_mac(&frame[6..12]));
                let et = u16::from_be_bytes([frame[12], frame[13]]);
                f.ethertype = Some(format!("0x{et:04x}"));
                // One 802.1Q tag is stepped over so the IP inside is still decoded.
                if et == 0x8100 && frame.len() >= 18 {
                    let inner = u16::from_be_bytes([frame[16], frame[17]]);
                    if inner == 0x0800 {
                        f.l3_offset = Some(18);
                    }
                } else if et == 0x0800 {
                    f.l3_offset = Some(14);
                }
            }
        }
        LinkType::Null | LinkType::Loop => {
            if frame.len() >= 4 {
                let raw = [frame[0], frame[1], frame[2], frame[3]];
                let af = if link == LinkType::Null {
                    u32::from_ne_bytes(raw)
                } else {
                    u32::from_be_bytes(raw)
                };
                match family_name(af) {
                    Some(name) => {
                        f.family = Some(json!(name));
                        let v6 = name == "AF_INET6";
                        f.ethertype = Some(if v6 { "0x86dd" } else { "0x0800" }.to_string());
                        if !v6 {
                            f.l3_offset = Some(4);
                        }
                    }
                    None => f.family = Some(json!(af)),
                }
            }
        }
        LinkType::Raw | LinkType::Ipv4 | LinkType::Ipv6 => {
            if let Some(b) = frame.first() {
                match b >> 4 {
                    4 => {
                        f.ethertype = Some("0x0800".into());
                        f.l3_offset = Some(0);
                    }
                    6 => f.ethertype = Some("0x86dd".into()),
                    _ => {}
                }
            }
        }
        LinkType::LinuxSll => {
            if frame.len() >= 16 {
                let et = u16::from_be_bytes([frame[14], frame[15]]);
                f.ethertype = Some(format!("0x{et:04x}"));
                if et == 0x0800 {
                    f.l3_offset = Some(16);
                }
            }
        }
        LinkType::Other(_) => {}
    }
    f
}

const LOOPBACK_ZERO_NOTE: &str = "checksum is 0x0000 on a loopback interface: the kernel left it \
     for checksum offload and never computed it, because loopback traffic never crosses a wire. \
     Not a malformed packet.";
const OFFLOAD_NOTE: &str = "does not verify. On a frame this host sent, that is usually \
     transmit checksum offload (the NIC fills it in after the capture point); on a frame it \
     received, the packet is corrupt.";

fn checksum_verdict(
    obj: &mut Map<String, Value>,
    stored: u16,
    verifies: Option<bool>,
    loopback: bool,
) {
    obj.insert("checksum".into(), json!(format!("0x{stored:04x}")));
    match verifies {
        None => {
            obj.insert("checksum_ok".into(), Value::Null);
            obj.insert(
                "checksum_note".into(),
                json!("not verified: the captured bytes do not cover the whole segment"),
            );
        }
        Some(true) => {
            obj.insert("checksum_ok".into(), json!(true));
        }
        Some(false) if stored == 0 && loopback => {
            obj.insert("checksum_ok".into(), Value::Null);
            obj.insert("checksum_note".into(), json!(LOOPBACK_ZERO_NOTE));
        }
        Some(false) => {
            obj.insert("checksum_ok".into(), json!(false));
            obj.insert(
                "checksum_note".into(),
                json!(if loopback {
                    "does not verify on a loopback interface, where the kernel routinely \
                     leaves a partial (pseudo-header only) checksum for offload"
                } else {
                    OFFLOAD_NOTE
                }),
            );
        }
    }
}

fn payload_fields(obj: &mut Map<String, Value>, data: &[u8]) {
    obj.insert("payload_length".into(), json!(data.len()));
    if data.is_empty() {
        return;
    }
    let shown = &data[..data.len().min(512)];
    if shown
        .iter()
        .all(|&b| b.is_ascii_graphic() || b.is_ascii_whitespace())
    {
        obj.insert("payload".into(), json!(String::from_utf8_lossy(shown)));
        obj.insert("payload_encoding".into(), json!("utf8"));
    } else {
        obj.insert("payload".into(), json!(hex::encode(shown)));
        obj.insert("payload_encoding".into(), json!("hex"));
    }
    if shown.len() < data.len() {
        obj.insert("payload_truncated".into(), json!(true));
    }
}

/// Decode an IPv4 packet and its TCP / UDP / ICMP payload.
///
/// `full_length` is the frame's real length (it may be longer than `packet` when the capture
/// was cut), so a checksum is only verified over bytes that are all there. `loopback` turns a
/// zero checksum into the offload note rather than a failure.
///
/// Returns `(ip, transport_key, transport)`: `transport_key` is `"tcp"`, `"udp"` or `"icmp"`.
pub fn decode_ipv4(
    packet: &[u8],
    loopback: bool,
) -> Option<(Value, Option<(&'static str, Value)>)> {
    if packet.len() < 20 || packet[0] >> 4 != 4 {
        return None;
    }
    let ihl = ((packet[0] & 0x0f) as usize) * 4;
    if ihl < 20 || packet.len() < ihl {
        return None;
    }
    let total_length = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    let frag = u16::from_be_bytes([packet[6], packet[7]]);
    let proto = packet[9];
    let src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    let stored = u16::from_be_bytes([packet[10], packet[11]]);

    let mut ip = Map::new();
    ip.insert("version".into(), json!(4));
    ip.insert("src".into(), json!(src.to_string()));
    ip.insert("dst".into(), json!(dst.to_string()));
    ip.insert("protocol".into(), json!(ip_protocol_name(proto)));
    ip.insert("protocol_number".into(), json!(proto));
    ip.insert("ttl".into(), json!(packet[8]));
    ip.insert(
        "id".into(),
        json!(u16::from_be_bytes([packet[4], packet[5]])),
    );
    ip.insert("tos".into(), json!(packet[1]));
    ip.insert("dont_fragment".into(), json!(frag & 0x4000 != 0));
    ip.insert("more_fragments".into(), json!(frag & 0x2000 != 0));
    ip.insert("fragment_offset".into(), json!((frag & 0x1fff) * 8));
    ip.insert("header_length".into(), json!(ihl));
    ip.insert("total_length".into(), json!(total_length));
    checksum_verdict(
        &mut ip,
        stored,
        Some(checksum16(&packet[..ihl]) == 0),
        loopback,
    );

    // Only the first fragment carries the transport header.
    if frag & 0x1fff != 0 {
        return Some((Value::Object(ip), None));
    }
    let end = total_length.clamp(ihl, packet.len());
    let whole = total_length <= packet.len() && total_length >= ihl;
    let seg = &packet[ihl..end];

    let transport = match proto {
        6 if seg.len() >= 20 => {
            let off = ((seg[12] >> 4) as usize) * 4;
            let mut t = Map::new();
            t.insert(
                "src_port".into(),
                json!(u16::from_be_bytes([seg[0], seg[1]])),
            );
            t.insert(
                "dst_port".into(),
                json!(u16::from_be_bytes([seg[2], seg[3]])),
            );
            t.insert(
                "seq".into(),
                json!(u32::from_be_bytes([seg[4], seg[5], seg[6], seg[7]])),
            );
            t.insert(
                "ack".into(),
                json!(u32::from_be_bytes([seg[8], seg[9], seg[10], seg[11]])),
            );
            t.insert("flags".into(), json!(tcp_flag_names(seg[13])));
            t.insert(
                "window".into(),
                json!(u16::from_be_bytes([seg[14], seg[15]])),
            );
            t.insert(
                "urgent".into(),
                json!(u16::from_be_bytes([seg[18], seg[19]])),
            );
            t.insert("header_length".into(), json!(off));
            let opts_end = off.clamp(20, seg.len());
            t.insert(
                "options".into(),
                json!(decode_tcp_options(&seg[20..opts_end])),
            );
            let stored = u16::from_be_bytes([seg[16], seg[17]]);
            let verifies = whole.then(|| tcp_checksum_ipv4(src, dst, seg) == 0);
            checksum_verdict(&mut t, stored, verifies, loopback);
            payload_fields(&mut t, seg.get(opts_end..).unwrap_or(&[]));
            Some(("tcp", Value::Object(t)))
        }
        17 if seg.len() >= 8 => {
            let mut u = Map::new();
            u.insert(
                "src_port".into(),
                json!(u16::from_be_bytes([seg[0], seg[1]])),
            );
            u.insert(
                "dst_port".into(),
                json!(u16::from_be_bytes([seg[2], seg[3]])),
            );
            u.insert("length".into(), json!(u16::from_be_bytes([seg[4], seg[5]])));
            let stored = u16::from_be_bytes([seg[6], seg[7]]);
            if stored == 0 {
                u.insert("checksum".into(), json!("0x0000"));
                u.insert("checksum_ok".into(), Value::Null);
                u.insert(
                    "checksum_note".into(),
                    json!(if loopback {
                        LOOPBACK_ZERO_NOTE
                    } else {
                        "0x0000: the sender computed no checksum, which IPv4 UDP allows"
                    }),
                );
            } else {
                let verifies = whole.then(|| l4_checksum_ipv4(src, dst, 17, seg) == 0);
                checksum_verdict(&mut u, stored, verifies, loopback);
            }
            payload_fields(&mut u, &seg[8..]);
            Some(("udp", Value::Object(u)))
        }
        1 if seg.len() >= 4 => {
            let mut c = Map::new();
            c.insert("type".into(), json!(seg[0]));
            c.insert("type_name".into(), json!(icmpv4_type_name(seg[0])));
            c.insert("code".into(), json!(seg[1]));
            // An error quotes the IP header and 8 bytes of the packet it is about.
            if matches!(seg[0], 3 | 4 | 5 | 11 | 12) && seg.len() >= 8 + 20 {
                if let Some((quoted, qt)) = decode_ipv4(&seg[8..], loopback) {
                    let mut about = Map::new();
                    about.insert("src".into(), quoted["src"].clone());
                    about.insert("dst".into(), quoted["dst"].clone());
                    about.insert("protocol".into(), quoted["protocol"].clone());
                    if let Some((_, t)) = qt {
                        about.insert("src_port".into(), t["src_port"].clone());
                        about.insert("dst_port".into(), t["dst_port"].clone());
                    } else {
                        let qihl = ((seg[8] & 0x0f) as usize) * 4;
                        if let Some(p) = seg.get(8 + qihl..8 + qihl + 4) {
                            about
                                .insert("src_port".into(), json!(u16::from_be_bytes([p[0], p[1]])));
                            about
                                .insert("dst_port".into(), json!(u16::from_be_bytes([p[2], p[3]])));
                        }
                    }
                    c.insert("about".into(), Value::Object(about));
                }
            }
            Some(("icmp", Value::Object(c)))
        }
        _ => None,
    };
    Some((Value::Object(ip), transport))
}

/// Every decoded field of one frame, for an event: `link_type`, the link header fields for
/// that link (`dst_mac` / `src_mac` are `null` where the link has no MACs, and `family` is set
/// on `NULL` / `LOOP`), and `ip` plus `tcp` / `udp` / `icmp` when the frame carries IPv4.
///
/// `ip` and the transport keys are **absent** when the frame does not carry them.
pub fn decode_frame(frame: &[u8], link: LinkType, loopback: bool) -> Map<String, Value> {
    let lf = decode_link(frame, link);
    let mut m = Map::new();
    m.insert("link_type".into(), json!(link.name()));
    m.insert("dst_mac".into(), json!(lf.dst_mac));
    m.insert("src_mac".into(), json!(lf.src_mac));
    m.insert("ethertype".into(), json!(lf.ethertype));
    if matches!(link, LinkType::Null | LinkType::Loop) {
        m.insert("family".into(), lf.family.clone().unwrap_or(Value::Null));
    }
    if let Some(off) = lf.l3_offset {
        if let Some((ip, transport)) = decode_ipv4(&frame[off.min(frame.len())..], loopback) {
            m.insert("ip".into(), ip);
            if let Some((key, t)) = transport {
                m.insert(key.into(), t);
            }
        }
    }
    m
}

/// A one-line reading of a decoded frame, e.g.
/// `"tcp 127.0.0.1:3333 -> 127.0.0.1:40000 [syn, ack] options: mss, mp_capable"`.
pub fn summarize(decoded: &Map<String, Value>) -> String {
    let Some(ip) = decoded.get("ip") else {
        return format!(
            "{} frame, ethertype {}",
            decoded
                .get("link_type")
                .and_then(|v| v.as_str())
                .unwrap_or("?"),
            decoded
                .get("ethertype")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
        );
    };
    let s = ip["src"].as_str().unwrap_or("?");
    let d = ip["dst"].as_str().unwrap_or("?");
    if let Some(t) = decoded.get("tcp") {
        let flags: Vec<&str> = t["flags"]
            .as_array()
            .map(|a| a.iter().filter_map(|f| f.as_str()).collect())
            .unwrap_or_default();
        let opts: Vec<String> = t["options"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter(|o| o["kind"] != "nop")
                    .map(|o| match &o["kind"] {
                        Value::String(k) => k.clone(),
                        other => other.to_string(),
                    })
                    .collect()
            })
            .unwrap_or_default();
        return format!(
            "tcp {s}:{} -> {d}:{} [{}]{}",
            t["src_port"],
            t["dst_port"],
            flags.join(", "),
            if opts.is_empty() {
                String::new()
            } else {
                format!(" options: {}", opts.join(", "))
            }
        );
    }
    if let Some(u) = decoded.get("udp") {
        return format!("udp {s}:{} -> {d}:{}", u["src_port"], u["dst_port"]);
    }
    if let Some(c) = decoded.get("icmp") {
        return format!(
            "icmp {s} -> {d} {} code {}",
            c["type_name"].as_str().unwrap_or("?"),
            c["code"]
        );
    }
    format!("ipv4 {s} -> {d} protocol {}", ip["protocol"])
}

/// Which of `sent`'s TCP option kinds a reply's options carry back, and which it does not.
pub fn echoed_options(sent: &[Value], reply: &[Value]) -> (Vec<String>, Vec<String>) {
    let kind = |o: &Value| match &o["kind"] {
        Value::String(k) => k.clone(),
        other => other.to_string(),
    };
    let reply_kinds: Vec<String> = reply.iter().map(kind).collect();
    let mut echoed = Vec::new();
    let mut missing = Vec::new();
    for k in sent.iter().map(kind) {
        if k == "nop" || echoed.contains(&k) || missing.contains(&k) {
            continue;
        }
        if reply_kinds.contains(&k) {
            echoed.push(k);
        } else {
            missing.push(k);
        }
    }
    (echoed, missing)
}

/// The TCP flag names, for documentation strings.
pub fn tcp_flag_list() -> String {
    TCP_FLAG_NAMES
        .iter()
        .map(|(_, n)| *n)
        .collect::<Vec<_>>()
        .join(", ")
}

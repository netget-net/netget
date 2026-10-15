//! The packets a PACKET_IN carries and a PACKET_OUT or an injected PACKET_IN sends, as
//! structured JSON: Ethernet (with up to [`MAX_VLAN_TAGS`] VLAN tags), ARP, IPv4, IPv6 (with a
//! bounded walk of its extension headers), TCP, UDP, SCTP, ICMP and ICMPv6.
//!
//! [`describe`] never fails: a truncated or odd frame is described as far as it goes and says
//! where it stopped, because a controller has to decide about the packet it was given, not the
//! one it wishes it had been given. Checksums are not verified there for the same reason.
//! [`build`] is the reverse for the model's description, with every checksum computed here.
//! The RFC 1071 checksum and the ICMP echo and Ethernet builders are VXLAN's
//! (`crate::server::vxlan::frame`); its frame *parser* refuses IPv6, TCP and bad checksums, so
//! it is not reused here.
use crate::server::vxlan::frame::{checksum, ethernet, icmp_echo};
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Map, Value};
use std::net::{Ipv4Addr, Ipv6Addr};

use super::fields::{mac_str, number, parse_mac};

/// VLAN tags walked before the frame is described as tagged deeper than that.
pub const MAX_VLAN_TAGS: usize = 2;
/// IPv6 extension headers walked before the walk stops.
pub const MAX_IPV6_EXT_HEADERS: usize = 8;
/// Characters of a printable payload shown to the model.
pub const MAX_PAYLOAD_PREVIEW: usize = 256;
/// The longest payload text the model may put in a packet it builds.
pub const MAX_BUILT_PAYLOAD: usize = 1400;
/// Ethernet's minimum frame without the FCS; a built frame is padded to it.
pub const MIN_FRAME: usize = 60;

const ETH_IPV4: u16 = 0x0800;
const ETH_ARP: u16 = 0x0806;
const ETH_IPV6: u16 = 0x86dd;
const ETH_VLAN: u16 = 0x8100;

fn u16_at(b: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(i)?, *b.get(i + 1)?]))
}

fn u32_at(b: &[u8], i: usize) -> Option<u32> {
    Some(u32::from_be_bytes([
        *b.get(i)?,
        *b.get(i + 1)?,
        *b.get(i + 2)?,
        *b.get(i + 3)?,
    ]))
}

fn ipv4_at(b: &[u8], i: usize) -> Option<String> {
    let s = b.get(i..i + 4)?;
    Some(Ipv4Addr::new(s[0], s[1], s[2], s[3]).to_string())
}

fn ipv6_at(b: &[u8], i: usize) -> Option<String> {
    let s = b.get(i..i + 16)?;
    let mut a = [0u8; 16];
    a.copy_from_slice(s);
    Some(Ipv6Addr::from(a).to_string())
}

/// Describe a frame for the model.
pub fn describe(frame: &[u8]) -> Value {
    let mut out = Map::new();
    out.insert("length".into(), json!(frame.len()));
    if frame.len() < 14 {
        out.insert("truncated".into(), json!("shorter than an Ethernet header"));
        return Value::Object(out);
    }
    out.insert("eth_dst".into(), json!(mac_str(&frame[0..6])));
    out.insert("eth_src".into(), json!(mac_str(&frame[6..12])));
    let mut et = u16_at(frame, 12).unwrap_or(0);
    let mut pos = 14;
    let mut vlans = Vec::new();
    while matches!(et, 0x8100 | 0x88a8 | 0x9100) {
        if vlans.len() >= MAX_VLAN_TAGS {
            out.insert(
                "truncated".into(),
                json!(format!("more than {MAX_VLAN_TAGS} VLAN tags")),
            );
            out.insert("vlans".into(), json!(vlans));
            return Value::Object(out);
        }
        let (Some(tci), Some(next)) = (u16_at(frame, pos), u16_at(frame, pos + 2)) else {
            out.insert("truncated".into(), json!("in a VLAN tag"));
            out.insert("vlans".into(), json!(vlans));
            return Value::Object(out);
        };
        vlans.push(json!({
            "tpid": format!("{et:#06x}"),
            "vid": tci & 0x0fff,
            "pcp": tci >> 13,
        }));
        et = next;
        pos += 4;
    }
    if !vlans.is_empty() {
        out.insert("vlans".into(), json!(vlans));
    }
    out.insert("eth_type".into(), json!(format!("{et:#06x}")));
    let body = &frame[pos..];
    match et {
        ETH_ARP => describe_arp(body, &mut out),
        ETH_IPV4 => describe_ipv4(body, &mut out),
        ETH_IPV6 => describe_ipv6(body, &mut out),
        0x8847 | 0x8848 => {
            if let Some(word) = u32_at(body, 0) {
                out.insert(
                    "mpls".into(),
                    json!({"label": word >> 12, "tc": (word >> 9) & 7, "bos": (word >> 8) & 1, "ttl": word & 0xff}),
                );
            }
        }
        0x88cc => {
            out.insert("lldp".into(), json!(true));
        }
        _ => payload(body, &mut out),
    }
    Value::Object(out)
}

fn describe_arp(b: &[u8], out: &mut Map<String, Value>) {
    if b.len() < 28 || b[0..6] != [0, 1, 8, 0, 6, 4] {
        out.insert("truncated".into(), json!("not an Ethernet/IPv4 ARP packet"));
        return;
    }
    let op = u16_at(b, 6).unwrap_or(0);
    out.insert(
        "arp".into(),
        json!({
            "op": match op { 1 => json!("request"), 2 => json!("reply"), n => json!(n) },
            "sha": mac_str(&b[8..14]),
            "spa": ipv4_at(b, 14),
            "tha": mac_str(&b[18..24]),
            "tpa": ipv4_at(b, 24),
        }),
    );
}

fn describe_ipv4(b: &[u8], out: &mut Map<String, Value>) {
    if b.len() < 20 || b[0] >> 4 != 4 {
        out.insert("truncated".into(), json!("not a whole IPv4 header"));
        return;
    }
    let ihl = (b[0] & 0x0f) as usize * 4;
    let total = u16_at(b, 2).unwrap_or(0) as usize;
    let flags_frag = u16_at(b, 6).unwrap_or(0);
    let proto = b[9];
    let mut ip = json!({
        "src": ipv4_at(b, 12),
        "dst": ipv4_at(b, 16),
        "ttl": b[8],
        "protocol": proto,
        "dscp": b[1] >> 2,
        "ecn": b[1] & 3,
        "total_length": total,
    });
    let fragment = flags_frag & 0x1fff != 0 || flags_frag & 0x2000 != 0;
    if fragment {
        ip["fragment"] = json!({"offset": (flags_frag & 0x1fff) * 8, "more_fragments": flags_frag & 0x2000 != 0});
    }
    out.insert("ipv4".into(), ip);
    if ihl < 20 || b.len() < ihl {
        out.insert("truncated".into(), json!("IPv4 options"));
        return;
    }
    let end = total.clamp(ihl, b.len());
    if flags_frag & 0x1fff != 0 {
        payload(&b[ihl..end], out);
        return;
    }
    describe_l4(proto, &b[ihl..end], out);
}

fn describe_ipv6(b: &[u8], out: &mut Map<String, Value>) {
    if b.len() < 40 || b[0] >> 4 != 6 {
        out.insert("truncated".into(), json!("not a whole IPv6 header"));
        return;
    }
    let word = u32_at(b, 0).unwrap_or(0);
    let plen = u16_at(b, 4).unwrap_or(0) as usize;
    let mut next = b[6];
    let mut ip = json!({
        "src": ipv6_at(b, 8),
        "dst": ipv6_at(b, 24),
        "hop_limit": b[7],
        "flow_label": word & 0xf_ffff,
        "traffic_class": (word >> 20) & 0xff,
        "payload_length": plen,
    });
    let end = (40 + plen).min(b.len());
    let mut pos = 40;
    let mut ext = Vec::new();
    while matches!(next, 0 | 43 | 44 | 51 | 60) {
        if ext.len() >= MAX_IPV6_EXT_HEADERS {
            ip["extension_headers"] = json!(ext);
            out.insert("ipv6".into(), ip);
            out.insert(
                "truncated".into(),
                json!(format!(
                    "more than {MAX_IPV6_EXT_HEADERS} extension headers"
                )),
            );
            return;
        }
        let (Some(&nh), Some(&hl)) = (b.get(pos), b.get(pos + 1)) else {
            ip["extension_headers"] = json!(ext);
            out.insert("ipv6".into(), ip);
            out.insert("truncated".into(), json!("in an extension header"));
            return;
        };
        let len = match next {
            44 => 8,
            51 => (hl as usize + 2) * 4,
            _ => (hl as usize + 1) * 8,
        };
        ext.push(json!(match next {
            0 => "hop_by_hop",
            43 => "routing",
            44 => "fragment",
            51 => "authentication",
            _ => "destination_options",
        }));
        if next == 44 {
            let off = u16_at(b, pos + 2).unwrap_or(0) >> 3;
            if off != 0 {
                ip["extension_headers"] = json!(ext);
                ip["next_header"] = json!(nh);
                out.insert("ipv6".into(), ip);
                return;
            }
        }
        next = nh;
        pos += len;
    }
    if !ext.is_empty() {
        ip["extension_headers"] = json!(ext);
    }
    ip["next_header"] = json!(next);
    out.insert("ipv6".into(), ip);
    if pos > end {
        out.insert("truncated".into(), json!("in an extension header"));
        return;
    }
    describe_l4(next, &b[pos..end], out);
}

const TCP_FLAGS: [(&str, u8); 8] = [
    ("fin", 0x01),
    ("syn", 0x02),
    ("rst", 0x04),
    ("psh", 0x08),
    ("ack", 0x10),
    ("urg", 0x20),
    ("ece", 0x40),
    ("cwr", 0x80),
];

fn describe_l4(proto: u8, b: &[u8], out: &mut Map<String, Value>) {
    match proto {
        6 => {
            if b.len() < 20 {
                out.insert("truncated".into(), json!("in the TCP header"));
                return;
            }
            let off = ((b[12] >> 4) as usize * 4).clamp(20, b.len());
            let flags: Vec<&str> = TCP_FLAGS
                .iter()
                .filter(|(_, bit)| b[13] & bit != 0)
                .map(|(n, _)| *n)
                .collect();
            out.insert(
                "tcp".into(),
                json!({
                    "src_port": u16_at(b, 0), "dst_port": u16_at(b, 2),
                    "seq": u32_at(b, 4), "ack": u32_at(b, 8),
                    "flags": flags, "window": u16_at(b, 14),
                }),
            );
            payload(&b[off..], out);
        }
        17 => {
            if b.len() < 8 {
                out.insert("truncated".into(), json!("in the UDP header"));
                return;
            }
            out.insert(
                "udp".into(),
                json!({"src_port": u16_at(b, 0), "dst_port": u16_at(b, 2), "length": u16_at(b, 4)}),
            );
            payload(&b[8..], out);
        }
        132 => {
            if b.len() < 12 {
                out.insert("truncated".into(), json!("in the SCTP header"));
                return;
            }
            out.insert(
                "sctp".into(),
                json!({"src_port": u16_at(b, 0), "dst_port": u16_at(b, 2)}),
            );
        }
        1 | 58 => {
            if b.len() < 4 {
                out.insert("truncated".into(), json!("in the ICMP header"));
                return;
            }
            let (t, code) = (b[0], b[1]);
            let mut icmp = json!({"type": t, "code": code});
            let echo = if proto == 1 {
                t == 0 || t == 8
            } else {
                t == 128 || t == 129
            };
            if echo && b.len() >= 8 {
                icmp["id"] = json!(u16_at(b, 4));
                icmp["seq"] = json!(u16_at(b, 6));
                payload(&b[8..], out);
            }
            if proto == 58 && (t == 135 || t == 136) && b.len() >= 24 {
                icmp["nd_target"] = json!(ipv6_at(b, 8));
            }
            if let Some(name) = icmp_name(proto, t) {
                icmp["name"] = json!(name);
            }
            out.insert(if proto == 1 { "icmp" } else { "icmpv6" }.into(), icmp);
        }
        _ => payload(b, out),
    }
}

fn icmp_name(proto: u8, t: u8) -> Option<&'static str> {
    Some(match (proto, t) {
        (1, 0) => "echo_reply",
        (1, 3) => "destination_unreachable",
        (1, 8) => "echo_request",
        (1, 11) => "time_exceeded",
        (58, 1) => "destination_unreachable",
        (58, 3) => "time_exceeded",
        (58, 128) => "echo_request",
        (58, 129) => "echo_reply",
        (58, 133) => "router_solicitation",
        (58, 134) => "router_advertisement",
        (58, 135) => "neighbor_solicitation",
        (58, 136) => "neighbor_advertisement",
        _ => return None,
    })
}

/// The payload's length, and its text when it is text. Never the bytes themselves.
fn payload(b: &[u8], out: &mut Map<String, Value>) {
    out.insert("payload_length".into(), json!(b.len()));
    if b.is_empty() {
        return;
    }
    if let Ok(s) = std::str::from_utf8(b) {
        let flat = s.replace(['\n', '\r', '\t'], "");
        if !crate::utils::sanitize::has_controls(&flat) {
            let text = crate::utils::sanitize::multiline(s);
            let shown: String = text.chars().take(MAX_PAYLOAD_PREVIEW).collect();
            out.insert("payload_text".into(), json!(shown));
            if text.chars().count() > MAX_PAYLOAD_PREVIEW {
                out.insert("payload_text_truncated".into(), json!(true));
            }
        }
    }
}

// ---- Building ------------------------------------------------------------------------------

fn opt_u64(v: &Value, key: &str, default: u64, max: u64) -> Result<u64> {
    match v.get(key) {
        None | Some(Value::Null) => Ok(default),
        Some(x) => {
            let n = number(x, key)?;
            ensure!(n <= max, "{key} is {n}, above {max}");
            Ok(n)
        }
    }
}

fn req_str<'a>(v: &'a Value, key: &str, ctx: &str) -> Result<&'a str> {
    v.get(key)
        .and_then(Value::as_str)
        .with_context(|| format!("{ctx} needs \"{key}\""))
}

fn ipv4(v: &Value, key: &str, ctx: &str) -> Result<Ipv4Addr> {
    req_str(v, key, ctx)?
        .trim()
        .parse()
        .with_context(|| format!("{ctx} {key} is not an IPv4 address"))
}

fn ipv6(v: &Value, key: &str, ctx: &str) -> Result<Ipv6Addr> {
    req_str(v, key, ctx)?
        .trim()
        .parse()
        .with_context(|| format!("{ctx} {key} is not an IPv6 address"))
}

fn payload_bytes(spec: &Value) -> Result<Vec<u8>> {
    match spec.get("payload_text") {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::String(s)) => {
            ensure!(
                s.len() <= MAX_BUILT_PAYLOAD,
                "payload_text is {} bytes; at most {MAX_BUILT_PAYLOAD}",
                s.len()
            );
            Ok(s.as_bytes().to_vec())
        }
        Some(other) => bail!("payload_text must be a string, not {other}"),
    }
}

enum L3 {
    V4(Ipv4Addr, Ipv4Addr),
    V6(Ipv6Addr, Ipv6Addr),
}

fn pseudo_sum(l3: &L3, proto: u8, segment: &[u8]) -> u16 {
    let mut p = Vec::with_capacity(40);
    match l3 {
        L3::V4(s, d) => {
            p.extend_from_slice(&s.octets());
            p.extend_from_slice(&d.octets());
            p.extend_from_slice(&[0, proto]);
            p.extend_from_slice(&(segment.len() as u16).to_be_bytes());
        }
        L3::V6(s, d) => {
            p.extend_from_slice(&s.octets());
            p.extend_from_slice(&d.octets());
            p.extend_from_slice(&(segment.len() as u32).to_be_bytes());
            p.extend_from_slice(&[0, 0, 0, proto]);
        }
    }
    checksum(&[&p, segment])
}

/// The transport segment the spec describes, and its IP protocol number.
fn build_l4(spec: &Value, l3: &L3, data: &[u8]) -> Result<Option<(u8, Vec<u8>)>> {
    let v6 = matches!(l3, L3::V6(..));
    if let Some(u) = spec.get("udp").filter(|x| !x.is_null()) {
        let src = opt_u64(u, "src_port", 0, 0xffff)? as u16;
        let dst = opt_u64(u, "dst_port", 0, 0xffff)? as u16;
        let mut seg = Vec::with_capacity(8 + data.len());
        seg.extend_from_slice(&src.to_be_bytes());
        seg.extend_from_slice(&dst.to_be_bytes());
        seg.extend_from_slice(&((8 + data.len()) as u16).to_be_bytes());
        seg.extend_from_slice(&[0, 0]);
        seg.extend_from_slice(data);
        let mut sum = pseudo_sum(l3, 17, &seg);
        if sum == 0 {
            sum = 0xffff;
        }
        seg[6..8].copy_from_slice(&sum.to_be_bytes());
        return Ok(Some((17, seg)));
    }
    if let Some(t) = spec.get("tcp").filter(|x| !x.is_null()) {
        let src = opt_u64(t, "src_port", 0, 0xffff)? as u16;
        let dst = opt_u64(t, "dst_port", 0, 0xffff)? as u16;
        let seq = opt_u64(t, "seq", 0, u32::MAX as u64)? as u32;
        let ack = opt_u64(t, "ack", 0, u32::MAX as u64)? as u32;
        let window = opt_u64(t, "window", 65535, 0xffff)? as u16;
        let mut flags = 0u8;
        if let Some(list) = t.get("flags").and_then(Value::as_array) {
            for f in list {
                let name = f.as_str().context("a TCP flag is a name like syn")?;
                let (_, bit) = TCP_FLAGS
                    .iter()
                    .find(|(n, _)| name.eq_ignore_ascii_case(n))
                    .with_context(|| format!("unknown TCP flag {name:?}"))?;
                flags |= bit;
            }
        }
        let mut seg = Vec::with_capacity(20 + data.len());
        seg.extend_from_slice(&src.to_be_bytes());
        seg.extend_from_slice(&dst.to_be_bytes());
        seg.extend_from_slice(&seq.to_be_bytes());
        seg.extend_from_slice(&ack.to_be_bytes());
        seg.extend_from_slice(&[5 << 4, flags]);
        seg.extend_from_slice(&window.to_be_bytes());
        seg.extend_from_slice(&[0, 0, 0, 0]);
        seg.extend_from_slice(data);
        let sum = pseudo_sum(l3, 6, &seg);
        seg[16..18].copy_from_slice(&sum.to_be_bytes());
        return Ok(Some((6, seg)));
    }
    let icmp_key = if v6 { "icmpv6" } else { "icmp" };
    if let Some(i) = spec.get(icmp_key).filter(|x| !x.is_null()) {
        let default_type = if v6 { 128 } else { 8 };
        let t = opt_u64(i, "type", default_type, 255)? as u8;
        let code = opt_u64(i, "code", 0, 255)? as u8;
        let id = opt_u64(i, "id", 0, 0xffff)? as u16;
        let seq = opt_u64(i, "seq", 0, 0xffff)? as u16;
        if v6 {
            let mut m = vec![t, code, 0, 0];
            if t == 135 || t == 136 {
                // Neighbor solicitation/advertisement: flags (solicited+override on an
                // advertisement), the target, no options.
                let target = ipv6(i, "nd_target", "an icmpv6 neighbor message")?;
                let flags: u32 = if t == 136 { 0x6000_0000 } else { 0 };
                m.extend_from_slice(&flags.to_be_bytes());
                m.extend_from_slice(&target.octets());
            } else {
                m.extend_from_slice(&id.to_be_bytes());
                m.extend_from_slice(&seq.to_be_bytes());
                m.extend_from_slice(data);
            }
            let sum = pseudo_sum(l3, 58, &m);
            m[2..4].copy_from_slice(&sum.to_be_bytes());
            return Ok(Some((58, m)));
        }
        let m = if (t == 8 || t == 0) && code == 0 {
            icmp_echo(t == 8, id, seq, data)
        } else {
            let mut m = vec![t, code, 0, 0, 0, 0, 0, 0];
            m.extend_from_slice(data);
            let sum = checksum(&[&m]);
            m[2..4].copy_from_slice(&sum.to_be_bytes());
            m
        };
        return Ok(Some((1, m)));
    }
    Ok(None)
}

/// Build a frame from the model's description.
pub fn build(spec: &Value) -> Result<Vec<u8>> {
    ensure!(
        spec.is_object(),
        "a packet is an object describing its headers"
    );
    let src = parse_mac(req_str(spec, "eth_src", "a packet")?).context("eth_src")?;
    let dst = match spec.get("eth_dst").and_then(Value::as_str) {
        Some(s) => parse_mac(s).context("eth_dst")?,
        None => [0xff; 6],
    };
    let data = payload_bytes(spec)?;
    let (ethertype, l3_bytes) = if let Some(a) = spec.get("arp").filter(|x| !x.is_null()) {
        let op = match a.get("op") {
            None => 1u16,
            Some(Value::String(s)) if s == "request" => 1,
            Some(Value::String(s)) if s == "reply" => 2,
            Some(other) => {
                let n = number(other, "arp op")?;
                ensure!(n == 1 || n == 2, "arp op is request (1) or reply (2)");
                n as u16
            }
        };
        let sha = match a.get("sha").and_then(Value::as_str) {
            Some(s) => parse_mac(s).context("arp sha")?,
            None => src,
        };
        let tha = match a.get("tha").and_then(Value::as_str) {
            Some(s) => parse_mac(s).context("arp tha")?,
            None if op == 2 => dst,
            None => [0; 6],
        };
        let spa = ipv4(a, "spa", "an arp packet")?;
        let tpa = ipv4(a, "tpa", "an arp packet")?;
        let mut b = vec![0, 1, 8, 0, 6, 4];
        b.extend_from_slice(&op.to_be_bytes());
        b.extend_from_slice(&sha);
        b.extend_from_slice(&spa.octets());
        b.extend_from_slice(&tha);
        b.extend_from_slice(&tpa.octets());
        (ETH_ARP, b)
    } else if let Some(ip) = spec.get("ipv4").filter(|x| !x.is_null()) {
        let s = ipv4(ip, "src", "an ipv4 header")?;
        let d = ipv4(ip, "dst", "an ipv4 header")?;
        let ttl = opt_u64(ip, "ttl", 64, 255)? as u8;
        let dscp = opt_u64(ip, "dscp", 0, 63)? as u8;
        let id = opt_u64(ip, "id", 0, 0xffff)? as u16;
        let l3 = L3::V4(s, d);
        let (proto, seg) = match build_l4(spec, &l3, &data)? {
            Some(x) => x,
            None => (opt_u64(ip, "protocol", 253, 255)? as u8, data.clone()),
        };
        let total = 20 + seg.len();
        ensure!(total <= 0xffff, "the IPv4 packet is too long");
        let mut h = vec![0x45, dscp << 2];
        h.extend_from_slice(&(total as u16).to_be_bytes());
        h.extend_from_slice(&id.to_be_bytes());
        h.extend_from_slice(&[0x40, 0, ttl, proto, 0, 0]);
        h.extend_from_slice(&s.octets());
        h.extend_from_slice(&d.octets());
        let sum = checksum(&[&h]);
        h[10..12].copy_from_slice(&sum.to_be_bytes());
        h.extend_from_slice(&seg);
        (ETH_IPV4, h)
    } else if let Some(ip) = spec.get("ipv6").filter(|x| !x.is_null()) {
        let s = ipv6(ip, "src", "an ipv6 header")?;
        let d = ipv6(ip, "dst", "an ipv6 header")?;
        let hop = opt_u64(ip, "hop_limit", 64, 255)? as u8;
        let flow = opt_u64(ip, "flow_label", 0, 0xf_ffff)? as u32;
        let l3 = L3::V6(s, d);
        let (proto, seg) = match build_l4(spec, &l3, &data)? {
            Some(x) => x,
            None => (opt_u64(ip, "next_header", 59, 255)? as u8, data.clone()),
        };
        let mut h = (0x6000_0000u32 | flow).to_be_bytes().to_vec();
        h.extend_from_slice(&(seg.len() as u16).to_be_bytes());
        h.extend_from_slice(&[proto, hop]);
        h.extend_from_slice(&s.octets());
        h.extend_from_slice(&d.octets());
        h.extend_from_slice(&seg);
        (ETH_IPV6, h)
    } else {
        let et = match spec.get("eth_type") {
            Some(v) => number(v, "eth_type")?,
            None => bail!(
                "a packet needs \"arp\", \"ipv4\" or \"ipv6\", or an \"eth_type\" with \
                 \"payload_text\""
            ),
        };
        ensure!(
            (0x0600..=0xffff).contains(&et),
            "eth_type {et:#x} is not an EtherType"
        );
        (et as u16, data.clone())
    };
    let mut frame = match spec.get("vlan").filter(|x| !x.is_null()) {
        Some(v) => {
            let vid = opt_u64(v, "vid", 0, 0xfff)? as u16;
            let pcp = opt_u64(v, "pcp", 0, 7)? as u16;
            let mut inner = ((pcp << 13) | vid).to_be_bytes().to_vec();
            inner.extend_from_slice(&ethertype.to_be_bytes());
            inner.extend_from_slice(&l3_bytes);
            ethernet(dst, src, ETH_VLAN, &inner)
        }
        None => ethernet(dst, src, ethertype, &l3_bytes),
    };
    if frame.len() < MIN_FRAME {
        frame.resize(MIN_FRAME, 0);
    }
    Ok(frame)
}

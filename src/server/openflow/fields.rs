//! Structured JSON for OpenFlow 1.3 matches, actions and instructions, in both directions.
//!
//! The model never writes or reads an OXM TLV. It writes `{"in_port": 1, "eth_type": "0x0800",
//! "ipv4_dst": "10.0.0.0/8"}` and `[{"type": "output", "port": "flood"}]`; this module turns
//! those into the wire structures in `wire.rs` (refusing anything malformed with a message the
//! model can act on), and turns what a peer sent back into the same vocabulary.
use super::wire::{self, Action, Instruction, Match, Oxm, OXM_CLASS_BASIC, VID_PRESENT};
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Map, Value};
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Port,
    U8,
    U16,
    U24,
    U32,
    U64,
    Mac,
    Ipv4,
    Ipv6,
    /// VLAN_VID: a 12-bit id with `OFPVID_PRESENT`, or `"none"`.
    VlanVid,
    /// ETH_TYPE, written as a hex string.
    EtherType,
}

impl Kind {
    pub fn len(self) -> usize {
        match self {
            Kind::U8 => 1,
            Kind::U16 | Kind::VlanVid | Kind::EtherType => 2,
            Kind::U24 => 3,
            Kind::Port | Kind::U32 | Kind::Ipv4 => 4,
            Kind::Mac => 6,
            Kind::U64 => 8,
            Kind::Ipv6 => 16,
        }
    }
}

pub struct FieldInfo {
    pub id: u8,
    pub name: &'static str,
    pub kind: Kind,
    pub maskable: bool,
    /// The largest value the field holds, where it is narrower than its bytes.
    pub max: Option<u64>,
}

const fn f(id: u8, name: &'static str, kind: Kind, maskable: bool, max: Option<u64>) -> FieldInfo {
    FieldInfo {
        id,
        name,
        kind,
        maskable,
        max,
    }
}

/// OpenFlow 1.3's basic OXM fields (Table 11), in field-id order.
pub const FIELDS: &[FieldInfo] = &[
    f(0, "in_port", Kind::Port, false, None),
    f(1, "in_phy_port", Kind::Port, false, None),
    f(2, "metadata", Kind::U64, true, None),
    f(3, "eth_dst", Kind::Mac, true, None),
    f(4, "eth_src", Kind::Mac, true, None),
    f(5, "eth_type", Kind::EtherType, false, None),
    f(6, "vlan_vid", Kind::VlanVid, true, None),
    f(7, "vlan_pcp", Kind::U8, false, Some(7)),
    f(8, "ip_dscp", Kind::U8, false, Some(63)),
    f(9, "ip_ecn", Kind::U8, false, Some(3)),
    f(10, "ip_proto", Kind::U8, false, None),
    f(11, "ipv4_src", Kind::Ipv4, true, None),
    f(12, "ipv4_dst", Kind::Ipv4, true, None),
    f(13, "tcp_src", Kind::U16, false, None),
    f(14, "tcp_dst", Kind::U16, false, None),
    f(15, "udp_src", Kind::U16, false, None),
    f(16, "udp_dst", Kind::U16, false, None),
    f(17, "sctp_src", Kind::U16, false, None),
    f(18, "sctp_dst", Kind::U16, false, None),
    f(19, "icmpv4_type", Kind::U8, false, None),
    f(20, "icmpv4_code", Kind::U8, false, None),
    f(21, "arp_op", Kind::U16, false, None),
    f(22, "arp_spa", Kind::Ipv4, true, None),
    f(23, "arp_tpa", Kind::Ipv4, true, None),
    f(24, "arp_sha", Kind::Mac, true, None),
    f(25, "arp_tha", Kind::Mac, true, None),
    f(26, "ipv6_src", Kind::Ipv6, true, None),
    f(27, "ipv6_dst", Kind::Ipv6, true, None),
    f(28, "ipv6_flabel", Kind::U32, true, Some(0xf_ffff)),
    f(29, "icmpv6_type", Kind::U8, false, None),
    f(30, "icmpv6_code", Kind::U8, false, None),
    f(31, "ipv6_nd_target", Kind::Ipv6, false, None),
    f(32, "ipv6_nd_sll", Kind::Mac, false, None),
    f(33, "ipv6_nd_tll", Kind::Mac, false, None),
    f(34, "mpls_label", Kind::U32, false, Some(0xf_ffff)),
    f(35, "mpls_tc", Kind::U8, false, Some(7)),
    f(36, "mpls_bos", Kind::U8, false, Some(1)),
    f(37, "pbb_isid", Kind::U24, true, None),
    f(38, "tunnel_id", Kind::U64, true, None),
    f(39, "ipv6_exthdr", Kind::U16, true, Some(0x1ff)),
];

pub fn field_by_name(name: &str) -> Option<&'static FieldInfo> {
    FIELDS.iter().find(|f| f.name == name)
}

pub fn field_by_id(id: u8) -> Option<&'static FieldInfo> {
    FIELDS.iter().find(|f| f.id == id)
}

pub fn field_names() -> String {
    FIELDS.iter().map(|f| f.name).collect::<Vec<_>>().join(", ")
}

pub fn mac_str(m: &[u8]) -> String {
    m.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

pub fn parse_mac(s: &str) -> Result<[u8; 6]> {
    let parts: Vec<&str> = s.trim().split([':', '-']).collect();
    ensure!(
        parts.len() == 6,
        "{s:?} is not a MAC address like 02:00:00:00:00:01"
    );
    let mut mac = [0u8; 6];
    for (i, p) in parts.iter().enumerate() {
        ensure!(p.len() <= 2 && !p.is_empty(), "{s:?} is not a MAC address");
        mac[i] =
            u8::from_str_radix(p, 16).with_context(|| format!("{s:?} is not a MAC address"))?;
    }
    Ok(mac)
}

/// A number from JSON: an integer, or a string in decimal or `0x` hex.
pub fn number(v: &Value, what: &str) -> Result<u64> {
    match v {
        Value::Number(n) => n
            .as_u64()
            .with_context(|| format!("{what} must be a non-negative integer, not {n}")),
        Value::String(s) => {
            let t = s.trim();
            let parsed = if let Some(h) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
                u64::from_str_radix(h, 16)
            } else {
                t.parse::<u64>()
            };
            parsed.with_context(|| format!("{what} must be a number, not {s:?}"))
        }
        other => bail!("{what} must be a number, not {other}"),
    }
}

fn ranged(v: &Value, what: &str, max: u64) -> Result<u64> {
    let n = number(v, what)?;
    ensure!(n <= max, "{what} is {n}, above its maximum {max}");
    Ok(n)
}

/// A port number or a reserved port name (`controller`, `flood`, `all`, `in_port`, `local`,
/// `normal`, `table`, `any`).
pub fn port_from_json(v: &Value, what: &str) -> Result<u32> {
    if let Value::String(s) = v {
        if let Some(p) = wire::port::by_name(s) {
            return Ok(p);
        }
    }
    let n = number(v, what).with_context(|| {
        format!(
            "{what} is a port number or one of {}",
            wire::port::RESERVED
                .iter()
                .map(|(n, _)| *n)
                .collect::<Vec<_>>()
                .join(", ")
        )
    })?;
    ensure!(n <= u32::MAX as u64, "{what} {n} does not fit 32 bits");
    let p = n as u32;
    ensure!(
        p < wire::port::MAX || wire::port::reserved_name(p).is_some(),
        "{what} {p:#x} is in the reserved range but is not a reserved port"
    );
    Ok(p)
}

pub fn port_to_json(p: u32) -> Value {
    match wire::port::reserved_name(p) {
        Some(n) => json!(n),
        None => json!(p),
    }
}

fn be(n: u64, len: usize) -> Vec<u8> {
    n.to_be_bytes()[8 - len..].to_vec()
}

fn from_be(b: &[u8]) -> u64 {
    b.iter().fold(0u64, |acc, x| (acc << 8) | u64::from(*x))
}

/// The value bytes of one field from JSON.
fn value_bytes(info: &FieldInfo, v: &Value) -> Result<Vec<u8>> {
    let what = info.name;
    Ok(match info.kind {
        Kind::Port => port_from_json(v, what)?.to_be_bytes().to_vec(),
        Kind::Mac => parse_mac(
            v.as_str()
                .with_context(|| format!("{what} is a MAC string"))?,
        )
        .with_context(|| format!("invalid {what}"))?
        .to_vec(),
        Kind::Ipv4 => v
            .as_str()
            .with_context(|| format!("{what} is an IPv4 address string"))?
            .trim()
            .parse::<Ipv4Addr>()
            .with_context(|| format!("{what} is not an IPv4 address"))?
            .octets()
            .to_vec(),
        Kind::Ipv6 => v
            .as_str()
            .with_context(|| format!("{what} is an IPv6 address string"))?
            .trim()
            .parse::<Ipv6Addr>()
            .with_context(|| format!("{what} is not an IPv6 address"))?
            .octets()
            .to_vec(),
        Kind::VlanVid => {
            if v.as_str().is_some_and(|s| s.eq_ignore_ascii_case("none")) {
                vec![0, 0]
            } else {
                let vid = ranged(v, what, 0xfff)? as u16;
                (vid | VID_PRESENT).to_be_bytes().to_vec()
            }
        }
        Kind::EtherType => be(ranged(v, what, 0xffff)?, 2),
        Kind::U8 | Kind::U16 | Kind::U24 | Kind::U32 | Kind::U64 => {
            let len = info.kind.len();
            let width_max = if len == 8 {
                u64::MAX
            } else {
                (1u64 << (len * 8)) - 1
            };
            be(ranged(v, what, info.max.unwrap_or(width_max))?, len)
        }
    })
}

fn prefix_mask(bits: u32, len: usize) -> Vec<u8> {
    let mut m = vec![0u8; len];
    for (i, byte) in m.iter_mut().enumerate() {
        let lo = (i * 8) as u32;
        if bits >= lo + 8 {
            *byte = 0xff;
        } else if bits > lo {
            *byte = 0xffu8 << (8 - (bits - lo));
        }
    }
    m
}

/// One field's OXM from JSON: a bare value, a CIDR string for an address, or
/// `{"value": …, "mask": …}`.
fn oxm_from_json(info: &FieldInfo, v: &Value) -> Result<Oxm> {
    let what = info.name;
    let (value, mask) = match v {
        Value::Object(o) if o.contains_key("value") => {
            let value = value_bytes(info, &o["value"])?;
            let mask = match o.get("mask") {
                None | Some(Value::Null) => None,
                Some(m) => {
                    ensure!(info.maskable, "{what} cannot be masked");
                    let mut mb = match info.kind {
                        Kind::VlanVid => be(ranged(m, "vlan_vid mask", 0x1fff)?, 2),
                        _ => value_bytes(info, m)?,
                    };
                    if info.kind == Kind::Port {
                        mb.truncate(4);
                    }
                    Some(mb)
                }
            };
            (value, mask)
        }
        Value::String(s) if matches!(info.kind, Kind::Ipv4 | Kind::Ipv6) && s.contains('/') => {
            let (addr, bits) = s.split_once('/').unwrap_or((s, ""));
            let value = value_bytes(info, &json!(addr))?;
            let max_bits = (value.len() * 8) as u32;
            let bits: u32 = bits
                .trim()
                .parse()
                .with_context(|| format!("{what} {s:?} has no prefix length"))?;
            ensure!(
                bits <= max_bits,
                "{what} prefix /{bits} is longer than {max_bits}"
            );
            if bits == max_bits {
                (value, None)
            } else {
                ensure!(info.maskable, "{what} cannot be masked");
                (value, Some(prefix_mask(bits, info.kind.len())))
            }
        }
        Value::String(s) if info.kind == Kind::VlanVid && s.eq_ignore_ascii_case("present") => (
            VID_PRESENT.to_be_bytes().to_vec(),
            Some(VID_PRESENT.to_be_bytes().to_vec()),
        ),
        other => (value_bytes(info, other)?, None),
    };
    let mut value = value;
    if let Some(m) = &mask {
        ensure!(
            m.len() == value.len(),
            "{what} mask is not as wide as the field"
        );
        // A value bit outside its mask can never match; the spec calls that BAD_WILDCARDS, so
        // clear it rather than send something a switch refuses.
        for (b, mb) in value.iter_mut().zip(m) {
            *b &= *mb;
        }
    }
    Ok(Oxm {
        class: OXM_CLASS_BASIC,
        field: info.id,
        value,
        mask,
    })
}

/// A match from a JSON object, with the prerequisites the fields themselves imply completed
/// (`ipv4_dst` implies `eth_type` 0x0800, `tcp_dst` implies `ip_proto` 6) and sorted into
/// field-id order, which puts every prerequisite before what depends on it. A prerequisite
/// that cannot be implied (a TCP port with no IP version) or that the match contradicts is an
/// error naming the field to add.
pub fn match_from_json(v: &Value) -> Result<Match> {
    let obj = match v {
        Value::Null => return Ok(Match::default()),
        Value::Object(o) => o,
        other => bail!("match must be an object of field names to values, not {other}"),
    };
    ensure!(
        obj.len() <= wire::MAX_OXMS,
        "a match with more than {} fields",
        wire::MAX_OXMS
    );
    let mut oxms: Vec<Oxm> = Vec::new();
    for (k, val) in obj {
        let info = field_by_name(k).with_context(|| {
            format!(
                "unknown match field {k:?}; the fields are {}",
                field_names()
            )
        })?;
        oxms.push(oxm_from_json(info, val)?);
    }
    complete_prerequisites(&mut oxms)?;
    oxms.sort_by_key(|o| o.field);
    let m = Match { oxms };
    check_prerequisites(&m).map_err(|(_, msg)| anyhow::anyhow!(msg))?;
    Ok(m)
}

const ETH_IPV4: u16 = 0x0800;
const ETH_ARP: u16 = 0x0806;
const ETH_IPV6: u16 = 0x86dd;
const ETH_PBB: u16 = 0x88e7;

fn exact_u64(m: &[Oxm], field: u8) -> Option<u64> {
    m.iter()
        .find(|o| o.class == OXM_CLASS_BASIC && o.field == field && o.mask.is_none())
        .map(|o| from_be(&o.value))
}

fn complete_prerequisites(oxms: &mut Vec<Oxm>) -> Result<()> {
    let has = |oxms: &Vec<Oxm>, ids: &[u8]| oxms.iter().any(|o| ids.contains(&o.field));
    // ip_proto implied by a transport field.
    let proto = if has(oxms, &[13, 14]) {
        Some(6u8)
    } else if has(oxms, &[15, 16]) {
        Some(17)
    } else if has(oxms, &[17, 18]) {
        Some(132)
    } else if has(oxms, &[19, 20]) {
        Some(1)
    } else if has(oxms, &[29, 30, 31, 32, 33]) {
        Some(58)
    } else {
        None
    };
    if let Some(p) = proto {
        match exact_u64(oxms, 10) {
            None if !has(oxms, &[10]) => oxms.push(Oxm::basic(10, vec![p])),
            Some(given) if given == u64::from(p) => {}
            _ => bail!("the match's ip_proto contradicts its transport fields (they need {p})"),
        }
    }
    // eth_type implied by an address family.
    let eth = if has(oxms, &[11, 12, 19, 20]) {
        Some(ETH_IPV4)
    } else if has(oxms, &[21, 22, 23, 24, 25]) {
        Some(ETH_ARP)
    } else if has(oxms, &[26, 27, 28, 29, 30, 31, 32, 33, 39]) {
        Some(ETH_IPV6)
    } else if has(oxms, &[37]) {
        Some(ETH_PBB)
    } else {
        None
    };
    if let Some(e) = eth {
        match exact_u64(oxms, 5) {
            None if !has(oxms, &[5]) => oxms.push(Oxm::basic(5, e.to_be_bytes().to_vec())),
            Some(given) if given == u64::from(e) => {}
            _ => bail!("the match's eth_type contradicts its fields (they need {e:#06x})"),
        }
    }
    Ok(())
}

/// OpenFlow 1.3's prerequisite rules (Table 12). The error is a `BAD_MATCH` code and a reason.
pub fn check_prerequisites(m: &Match) -> Result<(), (u16, String)> {
    let get = |id: u8| exact_u64(&m.oxms, id);
    let present = |id: u8| m.get(id).is_some();
    let eth = get(5);
    let proto = get(10);
    let need = |cond: bool, field: &str, what: &str| -> Result<(), (u16, String)> {
        if cond {
            Ok(())
        } else {
            Err((
                wire::err::BAD_MATCH_BAD_PREREQ,
                format!("{field} needs {what} in the match"),
            ))
        }
    };
    for o in &m.oxms {
        if o.class != OXM_CLASS_BASIC {
            continue;
        }
        let name = field_by_id(o.field).map(|f| f.name).unwrap_or("field");
        match o.field {
            1 => need(present(0), name, "in_port")?,
            7 => need(
                m.get(6).is_some_and(|v| v.value != [0, 0]),
                name,
                "a vlan_vid other than none",
            )?,
            8..=10 => need(
                eth == Some(u64::from(ETH_IPV4)) || eth == Some(u64::from(ETH_IPV6)),
                name,
                "eth_type 0x0800 (IPv4) or 0x86dd (IPv6)",
            )?,
            11 | 12 => need(eth == Some(u64::from(ETH_IPV4)), name, "eth_type 0x0800")?,
            13 | 14 => need(proto == Some(6), name, "ip_proto 6 (TCP)")?,
            15 | 16 => need(proto == Some(17), name, "ip_proto 17 (UDP)")?,
            17 | 18 => need(proto == Some(132), name, "ip_proto 132 (SCTP)")?,
            19 | 20 => need(proto == Some(1), name, "ip_proto 1 (ICMP)")?,
            21..=25 => need(eth == Some(u64::from(ETH_ARP)), name, "eth_type 0x0806")?,
            26..=28 | 39 => need(eth == Some(u64::from(ETH_IPV6)), name, "eth_type 0x86dd")?,
            29 | 30 => need(proto == Some(58), name, "ip_proto 58 (ICMPv6)")?,
            31 => need(
                matches!(get(29), Some(135) | Some(136)),
                name,
                "icmpv6_type 135 or 136",
            )?,
            32 => need(get(29) == Some(135), name, "icmpv6_type 135")?,
            33 => need(get(29) == Some(136), name, "icmpv6_type 136")?,
            34..=36 => need(
                eth == Some(0x8847) || eth == Some(0x8848),
                name,
                "eth_type 0x8847 or 0x8848 (MPLS)",
            )?,
            37 => need(eth == Some(u64::from(ETH_PBB)), name, "eth_type 0x88e7")?,
            _ => {}
        }
        // Plain value checks a switch makes too.
        if let Some(info) = field_by_id(o.field) {
            if o.value.len() != info.kind.len() {
                return Err((
                    wire::err::BAD_MATCH_BAD_LEN,
                    format!("{name} is {} bytes, not {}", o.value.len(), info.kind.len()),
                ));
            }
            if o.mask.is_some() && !info.maskable {
                return Err((
                    wire::err::BAD_MATCH_BAD_MASK,
                    format!("{name} cannot be masked"),
                ));
            }
        }
    }
    Ok(())
}

/// One OXM's value (and mask) as JSON.
pub fn oxm_value_json(o: &Oxm) -> (String, Value) {
    if o.class != OXM_CLASS_BASIC {
        return (
            format!("oxm_class_{:#06x}_field_{}", o.class, o.field),
            json!(hex_string(&o.value)),
        );
    }
    let Some(info) = field_by_id(o.field) else {
        return (
            format!("oxm_field_{}", o.field),
            json!(hex_string(&o.value)),
        );
    };
    let render = |b: &[u8]| -> Value {
        if b.len() != info.kind.len() {
            return json!(hex_string(b));
        }
        match info.kind {
            Kind::Port => port_to_json(from_be(b) as u32),
            Kind::Mac => json!(mac_str(b)),
            Kind::Ipv4 => json!(Ipv4Addr::new(b[0], b[1], b[2], b[3]).to_string()),
            Kind::Ipv6 => {
                let mut a = [0u8; 16];
                a.copy_from_slice(b);
                json!(Ipv6Addr::from(a).to_string())
            }
            Kind::EtherType => json!(format!("{:#06x}", from_be(b))),
            Kind::VlanVid => {
                let v = from_be(b) as u16;
                if v == 0 {
                    json!("none")
                } else {
                    json!(v & 0x0fff)
                }
            }
            _ => json!(from_be(b)),
        }
    };
    let value = render(&o.value);
    let v = match &o.mask {
        None => value,
        Some(m) => {
            let prefix = matches!(info.kind, Kind::Ipv4 | Kind::Ipv6)
                .then(|| prefix_len(m))
                .flatten();
            match (prefix, &value) {
                (Some(bits), Value::String(s)) => json!(format!("{s}/{bits}")),
                _ if info.kind == Kind::VlanVid => {
                    json!({"value": from_be(&o.value) & 0xfff, "mask": format!("{:#06x}", from_be(m)), "present": from_be(&o.value) & u64::from(VID_PRESENT) != 0})
                }
                _ => json!({"value": value, "mask": render(m)}),
            }
        }
    };
    (info.name.to_string(), v)
}

fn prefix_len(mask: &[u8]) -> Option<u32> {
    let bits: u32 = mask.iter().map(|b| b.count_ones()).sum();
    (prefix_mask(bits, mask.len()) == mask).then_some(bits)
}

pub fn hex_string(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn match_to_json(m: &Match) -> Value {
    let mut out = Map::new();
    for o in &m.oxms {
        let (k, v) = oxm_value_json(o);
        out.insert(k, v);
    }
    Value::Object(out)
}

// ---- Actions -------------------------------------------------------------------------------

pub const ACTION_TYPES: &str = "output, set_field, push_vlan, pop_vlan, push_mpls, pop_mpls, \
     set_mpls_ttl, dec_mpls_ttl, set_nw_ttl, dec_nw_ttl, copy_ttl_out, copy_ttl_in, group, \
     set_queue";

fn u8_field(o: &Value, key: &str) -> Result<u8> {
    Ok(ranged(
        o.get(key).with_context(|| format!("missing {key:?}"))?,
        key,
        255,
    )? as u8)
}

fn u32_field(o: &Value, key: &str) -> Result<u32> {
    Ok(ranged(
        o.get(key).with_context(|| format!("missing {key:?}"))?,
        key,
        u32::MAX as u64,
    )? as u32)
}

fn ethertype_field(o: &Value, key: &str, default: Option<u16>) -> Result<u16> {
    match o.get(key) {
        Some(v) => Ok(ranged(v, key, 0xffff)? as u16),
        None => default.with_context(|| format!("missing {key:?}")),
    }
}

pub fn action_from_json(v: &Value) -> Result<Action> {
    let t = v
        .get("type")
        .and_then(Value::as_str)
        .with_context(|| format!("an action needs a \"type\" (one of {ACTION_TYPES})"))?;
    Ok(match t {
        "output" => {
            let port = port_from_json(
                v.get("port").context("output needs a \"port\"")?,
                "output port",
            )?;
            ensure!(port != wire::port::ANY, "output to port any is not allowed");
            let max_len = match v.get("max_len") {
                Some(m) => ranged(m, "max_len", 0xffff)? as u16,
                None => wire::CML_NO_BUFFER,
            };
            Action::Output { port, max_len }
        }
        "set_field" => {
            let field = v
                .get("field")
                .and_then(Value::as_str)
                .context("set_field needs a \"field\" naming a match field")?;
            let info = field_by_name(field)
                .with_context(|| format!("unknown set_field field {field:?}"))?;
            ensure!(
                !matches!(info.id, 0..=2),
                "{field} cannot be set by an action"
            );
            let value = v.get("value").context("set_field needs a \"value\"")?;
            let mut value = value_bytes(info, value)?;
            if info.kind == Kind::VlanVid {
                // Set-field on VLAN_VID always carries OFPVID_PRESENT.
                value[0] |= (VID_PRESENT >> 8) as u8;
            }
            Action::SetField(Oxm::basic(info.id, value))
        }
        "push_vlan" => {
            let et = ethertype_field(v, "ethertype", Some(0x8100))?;
            ensure!(
                et == 0x8100 || et == 0x88a8,
                "push_vlan ethertype is 0x8100 or 0x88a8"
            );
            Action::PushVlan(et)
        }
        "pop_vlan" => Action::PopVlan,
        "push_mpls" => {
            let et = ethertype_field(v, "ethertype", Some(0x8847))?;
            ensure!(
                et == 0x8847 || et == 0x8848,
                "push_mpls ethertype is 0x8847 or 0x8848"
            );
            Action::PushMpls(et)
        }
        "pop_mpls" => Action::PopMpls(ethertype_field(v, "ethertype", None)?),
        "push_pbb" => Action::PushPbb(ethertype_field(v, "ethertype", Some(ETH_PBB))?),
        "pop_pbb" => Action::PopPbb,
        "set_mpls_ttl" => Action::SetMplsTtl(u8_field(v, "ttl")?),
        "dec_mpls_ttl" => Action::DecMplsTtl,
        "set_nw_ttl" => Action::SetNwTtl(u8_field(v, "ttl")?),
        "dec_nw_ttl" => Action::DecNwTtl,
        "copy_ttl_out" => Action::CopyTtlOut,
        "copy_ttl_in" => Action::CopyTtlIn,
        "group" => Action::Group(u32_field(v, "group_id")?),
        "set_queue" => Action::SetQueue(u32_field(v, "queue_id")?),
        other => bail!("unknown action type {other:?}; the types are {ACTION_TYPES}"),
    })
}

pub fn actions_from_json(v: &Value) -> Result<Vec<Action>> {
    let list = match v {
        Value::Null => return Ok(Vec::new()),
        Value::Array(a) => a,
        other => bail!("actions must be an array, not {other}"),
    };
    ensure!(
        list.len() <= wire::MAX_ACTIONS,
        "more than {} actions",
        wire::MAX_ACTIONS
    );
    list.iter()
        .enumerate()
        .map(|(i, a)| action_from_json(a).with_context(|| format!("action {i}")))
        .collect()
}

pub fn action_to_json(a: &Action) -> Value {
    match a {
        Action::Output { port, max_len } => {
            let mut v = json!({"type": "output", "port": port_to_json(*port)});
            if *port == wire::port::CONTROLLER {
                v["max_len"] = json!(max_len);
            }
            v
        }
        Action::SetField(o) => {
            let (k, val) = oxm_value_json(o);
            json!({"type": "set_field", "field": k, "value": val})
        }
        Action::PushVlan(e) => json!({"type": "push_vlan", "ethertype": format!("{e:#06x}")}),
        Action::PopVlan => json!({"type": "pop_vlan"}),
        Action::PushMpls(e) => json!({"type": "push_mpls", "ethertype": format!("{e:#06x}")}),
        Action::PopMpls(e) => json!({"type": "pop_mpls", "ethertype": format!("{e:#06x}")}),
        Action::PushPbb(e) => json!({"type": "push_pbb", "ethertype": format!("{e:#06x}")}),
        Action::PopPbb => json!({"type": "pop_pbb"}),
        Action::SetMplsTtl(t) => json!({"type": "set_mpls_ttl", "ttl": t}),
        Action::DecMplsTtl => json!({"type": "dec_mpls_ttl"}),
        Action::SetNwTtl(t) => json!({"type": "set_nw_ttl", "ttl": t}),
        Action::DecNwTtl => json!({"type": "dec_nw_ttl"}),
        Action::CopyTtlOut => json!({"type": "copy_ttl_out"}),
        Action::CopyTtlIn => json!({"type": "copy_ttl_in"}),
        Action::Group(g) => json!({"type": "group", "group_id": g}),
        Action::SetQueue(q) => json!({"type": "set_queue", "queue_id": q}),
        Action::Other { atype, len } => {
            json!({"type": "unknown", "action_type": atype, "length": len})
        }
    }
}

pub fn actions_to_json(list: &[Action]) -> Value {
    Value::Array(list.iter().map(action_to_json).collect())
}

// ---- Instructions --------------------------------------------------------------------------

pub const INSTRUCTION_TYPES: &str =
    "apply_actions, write_actions, clear_actions, goto_table, write_metadata, meter";

pub fn instruction_from_json(v: &Value) -> Result<Instruction> {
    let t = v
        .get("type")
        .and_then(Value::as_str)
        .with_context(|| format!("an instruction needs a \"type\" (one of {INSTRUCTION_TYPES})"))?;
    Ok(match t {
        "apply_actions" => {
            Instruction::ApplyActions(actions_from_json(v.get("actions").unwrap_or(&Value::Null))?)
        }
        "write_actions" => {
            Instruction::WriteActions(actions_from_json(v.get("actions").unwrap_or(&Value::Null))?)
        }
        "clear_actions" => Instruction::ClearActions,
        "goto_table" => {
            let t = u8_field(v, "table_id")?;
            ensure!(t < wire::TABLE_ALL, "goto_table table_id must be below 255");
            Instruction::GotoTable(t)
        }
        "write_metadata" => Instruction::WriteMetadata {
            metadata: number(
                v.get("metadata").context("missing \"metadata\"")?,
                "metadata",
            )?,
            mask: match v.get("mask") {
                Some(m) => number(m, "mask")?,
                None => u64::MAX,
            },
        },
        "meter" => Instruction::Meter(u32_field(v, "meter_id")?),
        other => bail!("unknown instruction type {other:?}; the types are {INSTRUCTION_TYPES}"),
    })
}

/// Instructions from `instructions`, or from a bare `actions` list (shorthand for one
/// `apply_actions`). Each instruction type may appear once.
pub fn instructions_from_action(v: &Value) -> Result<Vec<Instruction>> {
    let mut out: Vec<Instruction> = Vec::new();
    if let Some(list) = v.get("instructions").filter(|x| !x.is_null()) {
        let list = list.as_array().context("instructions must be an array")?;
        ensure!(
            list.len() <= wire::MAX_INSTRUCTIONS,
            "more than {} instructions",
            wire::MAX_INSTRUCTIONS
        );
        for (i, item) in list.iter().enumerate() {
            let ins = instruction_from_json(item).with_context(|| format!("instruction {i}"))?;
            ensure!(
                !out.iter().any(|p| p.kind() == ins.kind()),
                "instruction type {} appears twice",
                item["type"]
            );
            out.push(ins);
        }
    }
    if let Some(actions) = v.get("actions").filter(|x| !x.is_null()) {
        ensure!(
            !out.iter().any(|p| p.kind() == wire::inst::APPLY_ACTIONS),
            "give \"actions\" or an apply_actions instruction, not both"
        );
        out.push(Instruction::ApplyActions(actions_from_json(actions)?));
    }
    Ok(out)
}

pub fn instruction_to_json(i: &Instruction) -> Value {
    match i {
        Instruction::GotoTable(t) => json!({"type": "goto_table", "table_id": t}),
        Instruction::WriteMetadata { metadata, mask } => json!({
            "type": "write_metadata",
            "metadata": format!("{metadata:#x}"),
            "mask": format!("{mask:#x}"),
        }),
        Instruction::WriteActions(a) => {
            json!({"type": "write_actions", "actions": actions_to_json(a)})
        }
        Instruction::ApplyActions(a) => {
            json!({"type": "apply_actions", "actions": actions_to_json(a)})
        }
        Instruction::ClearActions => json!({"type": "clear_actions"}),
        Instruction::Meter(m) => json!({"type": "meter", "meter_id": m}),
        Instruction::Other { itype, len } => {
            json!({"type": "unknown", "instruction_type": itype, "length": len})
        }
    }
}

pub fn instructions_to_json(list: &[Instruction]) -> Value {
    Value::Array(list.iter().map(instruction_to_json).collect())
}

/// Flow-mod flags from a list of names.
pub fn flow_flags_from_json(v: Option<&Value>) -> Result<u16> {
    let Some(v) = v.filter(|v| !v.is_null()) else {
        return Ok(0);
    };
    let list = v.as_array().context("flags must be an array of names")?;
    let mut bits = 0u16;
    for item in list {
        let name = item.as_str().context("a flag is a name")?;
        let (_, b) = wire::flow_flag::ALL
            .iter()
            .find(|(n, _)| *n == name)
            .with_context(|| {
                format!(
                    "unknown flag {name:?}; flags are {}",
                    wire::flow_flag::ALL
                        .iter()
                        .map(|(n, _)| *n)
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            })?;
        bits |= b;
    }
    Ok(bits)
}

/// A datapath id from JSON: a number, `0x` hex, 16 hex digits, or eight colon-separated
/// octets as `ovs-ofctl` prints it.
pub fn datapath_id_from_json(v: &Value) -> Result<u64> {
    if let Value::String(s) = v {
        let t = s.trim();
        if t.contains(':') {
            let hex: String = t.split(':').collect();
            ensure!(hex.len() == 16, "datapath_id {s:?} is not eight octets");
            return u64::from_str_radix(&hex, 16).with_context(|| format!("datapath_id {s:?}"));
        }
        if t.len() == 16 && !t.starts_with("0x") {
            return u64::from_str_radix(t, 16).with_context(|| format!("datapath_id {s:?}"));
        }
    }
    number(v, "datapath_id")
}

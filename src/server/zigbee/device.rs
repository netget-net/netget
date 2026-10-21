//! The simulated Zigbee devices behind the co-processor: each is described once — IEEE and
//! NWK address, device type, endpoints, clusters and attribute values — and the ZDO and ZCL
//! requests a host sends it are answered from that description in Rust where the description
//! covers them (descriptors, address requests, attribute reads, discovery, reporting
//! configuration). Cluster commands, attribute writes and manufacturer-specific frames are the
//! model's to answer; `mod.rs` asks it and builds the device's reply with the helpers here.
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;

/// Devices one network holds, joined or waiting to join.
pub const MAX_DEVICES: usize = 32;
pub const MAX_ENDPOINTS: usize = 8;
pub const MAX_CLUSTERS: usize = 32;
pub const MAX_ATTRIBUTES: usize = 64;
/// String and octet-string attribute values, in bytes.
pub const MAX_STRING: usize = 64;
/// The largest APS payload an unfragmented Zigbee frame carries with NWK security; a host
/// message longer than this is refused the way the stack refuses it, and a device reply is
/// cut to it (a Read Attributes Response carries the records that fit).
pub const MAX_APS_PAYLOAD: usize = 82;
pub const NAME_CHARS: usize = 64;

pub const PROFILE_ZDO: u16 = 0x0000;
pub const PROFILE_HA: u16 = 0x0104;

/// ZDO status codes.
pub mod zdo_status {
    pub const SUCCESS: u8 = 0x00;
    pub const INVALID_EP: u8 = 0x82;
    pub const NOT_ACTIVE: u8 = 0x83;
    pub const NOT_SUPPORTED: u8 = 0x84;
    pub const DEVICE_NOT_FOUND: u8 = 0x81;
}

/// ZCL status codes.
pub mod zcl_status {
    pub const SUCCESS: u8 = 0x00;
    pub const FAILURE: u8 = 0x01;
    pub const NOT_AUTHORIZED: u8 = 0x7E;
    pub const MALFORMED_COMMAND: u8 = 0x80;
    pub const UNSUP_CLUSTER_COMMAND: u8 = 0x81;
    pub const UNSUP_GENERAL_COMMAND: u8 = 0x82;
    pub const UNSUP_MANUF_CLUSTER_COMMAND: u8 = 0x83;
    pub const UNSUP_MANUF_GENERAL_COMMAND: u8 = 0x84;
    pub const INVALID_FIELD: u8 = 0x85;
    pub const UNSUPPORTED_ATTRIBUTE: u8 = 0x86;
    pub const INVALID_VALUE: u8 = 0x87;
    pub const READ_ONLY: u8 = 0x88;
    pub const INSUFFICIENT_SPACE: u8 = 0x89;
    pub const NOT_FOUND: u8 = 0x8B;
    pub const INVALID_DATA_TYPE: u8 = 0x8D;
    pub const TIMEOUT: u8 = 0x94;
    pub const UNSUPPORTED_CLUSTER: u8 = 0xC3;

    pub const NAMES: &[(&str, u8)] = &[
        ("success", SUCCESS),
        ("failure", FAILURE),
        ("not_authorized", NOT_AUTHORIZED),
        ("malformed_command", MALFORMED_COMMAND),
        ("unsup_cluster_command", UNSUP_CLUSTER_COMMAND),
        ("unsup_general_command", UNSUP_GENERAL_COMMAND),
        ("invalid_field", INVALID_FIELD),
        ("unsupported_attribute", UNSUPPORTED_ATTRIBUTE),
        ("invalid_value", INVALID_VALUE),
        ("read_only", READ_ONLY),
        ("insufficient_space", INSUFFICIENT_SPACE),
        ("not_found", NOT_FOUND),
        ("invalid_data_type", INVALID_DATA_TYPE),
        ("timeout", TIMEOUT),
        ("unsupported_cluster", UNSUPPORTED_CLUSTER),
    ];

    pub fn parse(v: &serde_json::Value) -> anyhow::Result<u8> {
        if let Some(n) = v.as_u64() {
            anyhow::ensure!(n <= 0xFF, "a ZCL status is one byte");
            return Ok(n as u8);
        }
        let s = v
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("status is a name such as success or a number"))?;
        NAMES
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(s))
            .map(|(_, c)| *c)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "unknown ZCL status {s:?}; one of {}",
                    NAMES.iter().map(|(n, _)| *n).collect::<Vec<_>>().join(", ")
                )
            })
    }
}

/// Device types a description names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Router,
    EndDevice,
    SleepyEndDevice,
}

impl Kind {
    pub fn name(self) -> &'static str {
        match self {
            Kind::Router => "router",
            Kind::EndDevice => "end_device",
            Kind::SleepyEndDevice => "sleepy_end_device",
        }
    }
    /// `EmberNodeType`.
    pub fn ember_node_type(self) -> u8 {
        match self {
            Kind::Router => 0x02,
            Kind::EndDevice => 0x03,
            Kind::SleepyEndDevice => 0x04,
        }
    }
    /// A child of the coordinator (end devices join it directly here).
    pub fn is_child(self) -> bool {
        !matches!(self, Kind::Router)
    }
}

/// A ZCL attribute value, typed.
#[derive(Debug, Clone, PartialEq)]
pub enum AttrValue {
    Bool(bool),
    Uint(u64),
    Int(i64),
    Float(f32),
    Str(String),
    Octets(Vec<u8>),
}

/// ZCL data types the descriptions use: name, type id, width in bytes (0 for strings).
pub const TYPES: &[(&str, u8, usize)] = &[
    ("bool", 0x10, 1),
    ("map8", 0x18, 1),
    ("map16", 0x19, 2),
    ("map32", 0x1B, 4),
    ("uint8", 0x20, 1),
    ("uint16", 0x21, 2),
    ("uint24", 0x22, 3),
    ("uint32", 0x23, 4),
    ("int8", 0x28, 1),
    ("int16", 0x29, 2),
    ("int24", 0x2A, 3),
    ("int32", 0x2B, 4),
    ("enum8", 0x30, 1),
    ("enum16", 0x31, 2),
    ("single", 0x39, 4),
    ("octets", 0x41, 0),
    ("string", 0x42, 0),
];

pub fn type_name(id: u8) -> String {
    TYPES
        .iter()
        .find(|(_, t, _)| *t == id)
        .map(|(n, _, _)| n.to_string())
        .unwrap_or_else(|| format!("0x{id:02x}"))
}

fn type_by_name(name: &str) -> Result<u8> {
    TYPES
        .iter()
        .find(|(n, _, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, t, _)| *t)
        .with_context(|| {
            format!(
                "unknown attribute type {name:?}; one of {}",
                TYPES
                    .iter()
                    .map(|(n, _, _)| *n)
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        })
}

fn width(ty: u8) -> Option<usize> {
    TYPES.iter().find(|(_, t, _)| *t == ty).map(|(_, _, w)| *w)
}

/// One attribute of one cluster on one endpoint.
#[derive(Debug, Clone, PartialEq)]
pub struct Attribute {
    pub ty: u8,
    pub value: AttrValue,
}

impl Attribute {
    /// Read a value the model or a description wrote, checked against its type.
    pub fn from_json(ty: u8, v: &Value) -> Result<Self> {
        let value = match ty {
            0x10 => AttrValue::Bool(match v {
                Value::Bool(b) => *b,
                Value::Number(n) if n.as_u64() == Some(0) || n.as_u64() == Some(1) => {
                    n.as_u64() == Some(1)
                }
                _ => bail!("a bool attribute takes true or false"),
            }),
            0x18..=0x1B | 0x20..=0x23 | 0x30 | 0x31 => {
                let n = v.as_u64().context("an unsigned attribute takes a number")?;
                let w = width(ty).unwrap_or(4);
                ensure!(
                    w >= 8 || n < (1u64 << (8 * w)),
                    "{n} does not fit {} ({w} bytes)",
                    type_name(ty)
                );
                AttrValue::Uint(n)
            }
            0x28..=0x2B => {
                let n = v.as_i64().context("a signed attribute takes a number")?;
                let w = width(ty).unwrap_or(4) as u32;
                let lim = 1i64 << (8 * w - 1);
                ensure!(
                    (-lim..lim).contains(&n),
                    "{n} does not fit {}",
                    type_name(ty)
                );
                AttrValue::Int(n)
            }
            0x39 => {
                AttrValue::Float(v.as_f64().context("a single attribute takes a number")? as f32)
            }
            0x42 => {
                let s = v.as_str().context("a string attribute takes a string")?;
                ensure!(
                    s.len() <= MAX_STRING,
                    "a string attribute is at most {MAX_STRING} bytes"
                );
                ensure!(
                    !crate::utils::sanitize::has_controls(s),
                    "a string attribute holds no control characters"
                );
                AttrValue::Str(s.to_string())
            }
            0x41 => {
                let s = v.as_str().context("an octets attribute takes hex digits")?;
                let b = hex::decode(s).context("an octets attribute takes hex digits")?;
                ensure!(
                    b.len() <= MAX_STRING,
                    "an octets attribute is at most {MAX_STRING} bytes"
                );
                AttrValue::Octets(b)
            }
            _ => bail!("attribute type 0x{ty:02x} is not one NetGet encodes"),
        };
        Ok(Self { ty, value })
    }

    pub fn to_json(&self) -> Value {
        match &self.value {
            AttrValue::Bool(b) => json!(b),
            AttrValue::Uint(n) => json!(n),
            AttrValue::Int(n) => json!(n),
            AttrValue::Float(f) => json!(f),
            AttrValue::Str(s) => json!(s),
            AttrValue::Octets(b) => json!(hex::encode(b)),
        }
    }

    /// The value's encoding without its type byte.
    pub fn encode(&self) -> Vec<u8> {
        match &self.value {
            AttrValue::Bool(b) => vec![*b as u8],
            AttrValue::Uint(n) => n.to_le_bytes()[..width(self.ty).unwrap_or(4)].to_vec(),
            AttrValue::Int(n) => n.to_le_bytes()[..width(self.ty).unwrap_or(4)].to_vec(),
            AttrValue::Float(f) => f.to_le_bytes().to_vec(),
            AttrValue::Str(s) => {
                let mut v = vec![s.len() as u8];
                v.extend_from_slice(s.as_bytes());
                v
            }
            AttrValue::Octets(b) => {
                let mut v = vec![b.len() as u8];
                v.extend_from_slice(b);
                v
            }
        }
    }

    /// Decode a typed value from a ZCL frame (a Write Attributes record), for the model's
    /// event. `None` when the type is not one NetGet decodes or the bytes run out.
    pub fn decode(ty: u8, data: &[u8]) -> Option<(Self, usize)> {
        let w = width(ty)?;
        let value = match ty {
            0x10 => AttrValue::Bool(*data.first()? != 0),
            0x41 | 0x42 => {
                let n = *data.first()? as usize;
                if n == 0xFF {
                    return Some((
                        Self {
                            ty,
                            value: if ty == 0x42 {
                                AttrValue::Str(String::new())
                            } else {
                                AttrValue::Octets(Vec::new())
                            },
                        },
                        1,
                    ));
                }
                let b = data.get(1..1 + n)?;
                let value = if ty == 0x42 {
                    AttrValue::Str(crate::utils::sanitize::strip_controls(
                        &String::from_utf8_lossy(b),
                    ))
                } else {
                    AttrValue::Octets(b.to_vec())
                };
                return Some((Self { ty, value }, 1 + n));
            }
            0x39 => {
                let b = data.get(..4)?;
                AttrValue::Float(f32::from_le_bytes([b[0], b[1], b[2], b[3]]))
            }
            0x28..=0x2B => {
                let b = data.get(..w)?;
                let mut a = [0u8; 8];
                a[..w].copy_from_slice(b);
                let raw = u64::from_le_bytes(a);
                let shift = 64 - 8 * w as u32;
                AttrValue::Int(((raw << shift) as i64) >> shift)
            }
            _ => {
                let b = data.get(..w)?;
                let mut a = [0u8; 8];
                a[..w].copy_from_slice(b);
                AttrValue::Uint(u64::from_le_bytes(a))
            }
        };
        Some((Self { ty, value }, w))
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Endpoint {
    pub id: u8,
    pub profile: u16,
    pub device_type: u16,
    pub version: u8,
    pub in_clusters: Vec<u16>,
    pub out_clusters: Vec<u16>,
    /// (cluster, attribute) → value, server-side attributes of the in clusters.
    pub attributes: BTreeMap<(u16, u16), Attribute>,
}

impl Endpoint {
    /// `SimpleDescriptor` bytes.
    pub fn simple_descriptor(&self) -> Vec<u8> {
        let mut v = vec![self.id];
        v.extend_from_slice(&self.profile.to_le_bytes());
        v.extend_from_slice(&self.device_type.to_le_bytes());
        v.push(self.version & 0x0F);
        v.push(self.in_clusters.len() as u8);
        for c in &self.in_clusters {
            v.extend_from_slice(&c.to_le_bytes());
        }
        v.push(self.out_clusters.len() as u8);
        for c in &self.out_clusters {
            v.extend_from_slice(&c.to_le_bytes());
        }
        v
    }
}

/// One simulated device.
#[derive(Debug, Clone, PartialEq)]
pub struct Device {
    pub name: String,
    pub ieee: u64,
    pub nwk: u16,
    pub kind: Kind,
    pub manufacturer_code: u16,
    pub mains_powered: bool,
    pub endpoints: Vec<Endpoint>,
    /// The device's own ZCL transaction counter, for reports and commands it originates.
    pub zcl_tsn: u8,
    /// The device's APS counter.
    pub aps_counter: u8,
}

pub fn eui_display(e: u64) -> String {
    let b = e.to_be_bytes();
    b.iter()
        .map(|x| format!("{x:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// An EUI-64 written most significant byte first, with or without colons, as zigpy, ZHA and
/// Zigbee2MQTT ("0x00124b…") print it.
pub fn parse_eui(s: &str) -> Result<u64> {
    let t = s.trim();
    let t = t.strip_prefix("0x").unwrap_or(t);
    let hex: String = t.chars().filter(|c| *c != ':' && *c != '-').collect();
    ensure!(
        hex.len() == 16 && hex.chars().all(|c| c.is_ascii_hexdigit()),
        "an EUI-64 is 16 hex digits, most significant first (\"00:12:4b:00:01:02:03:04\")"
    );
    Ok(u64::from_str_radix(&hex, 16)?)
}

/// A 16-bit value as a number or a hex string ("0x1a62").
pub fn parse_u16(v: &Value, what: &str) -> Result<u16> {
    if let Some(n) = v.as_u64() {
        ensure!(n <= 0xFFFF, "{what} is 16 bits");
        return Ok(n as u16);
    }
    let s = v
        .as_str()
        .with_context(|| format!("{what} is a number or a hex string"))?;
    let t = s.trim();
    let t = t
        .strip_prefix("0x")
        .or_else(|| t.strip_prefix("0X"))
        .unwrap_or(t);
    u16::from_str_radix(t, 16).with_context(|| format!("{what} {s:?} is not 16-bit hex"))
}

/// Cluster names an event shows and a description or action may use.
pub const CLUSTERS: &[(&str, u16)] = &[
    ("basic", 0x0000),
    ("power_configuration", 0x0001),
    ("identify", 0x0003),
    ("groups", 0x0004),
    ("scenes", 0x0005),
    ("on_off", 0x0006),
    ("level_control", 0x0008),
    ("time", 0x000A),
    ("ota", 0x0019),
    ("poll_control", 0x0020),
    ("window_covering", 0x0102),
    ("thermostat", 0x0201),
    ("color_control", 0x0300),
    ("illuminance_measurement", 0x0400),
    ("temperature_measurement", 0x0402),
    ("pressure_measurement", 0x0403),
    ("relative_humidity", 0x0405),
    ("occupancy_sensing", 0x0406),
    ("ias_zone", 0x0500),
    ("metering", 0x0702),
    ("electrical_measurement", 0x0B04),
];

pub fn cluster_name(id: u16) -> String {
    CLUSTERS
        .iter()
        .find(|(_, c)| *c == id)
        .map(|(n, _)| n.to_string())
        .unwrap_or_else(|| format!("0x{id:04x}"))
}

pub fn parse_cluster(v: &Value) -> Result<u16> {
    if let Some(s) = v.as_str() {
        if let Some((_, c)) = CLUSTERS.iter().find(|(n, _)| n.eq_ignore_ascii_case(s)) {
            return Ok(*c);
        }
    }
    parse_u16(v, "cluster")
}

/// Cluster command names, client to server, where an event names the command and an action
/// may name one.
pub const COMMANDS: &[(u16, &str, u8)] = &[
    (0x0003, "identify", 0x00),
    (0x0003, "identify_query", 0x01),
    (0x0006, "off", 0x00),
    (0x0006, "on", 0x01),
    (0x0006, "toggle", 0x02),
    (0x0006, "off_with_effect", 0x40),
    (0x0006, "on_with_recall_global_scene", 0x41),
    (0x0006, "on_with_timed_off", 0x42),
    (0x0008, "move_to_level", 0x00),
    (0x0008, "move", 0x01),
    (0x0008, "step", 0x02),
    (0x0008, "stop", 0x03),
    (0x0008, "move_to_level_with_on_off", 0x04),
    (0x0008, "move_with_on_off", 0x05),
    (0x0008, "step_with_on_off", 0x06),
    (0x0008, "stop_with_on_off", 0x07),
    (0x0300, "move_to_hue", 0x00),
    (0x0300, "move_to_saturation", 0x03),
    (0x0300, "move_to_color", 0x07),
    (0x0300, "move_to_color_temp", 0x0A),
];

pub fn command_name(cluster: u16, id: u8) -> String {
    COMMANDS
        .iter()
        .find(|(c, _, i)| *c == cluster && *i == id)
        .map(|(_, n, _)| n.to_string())
        .unwrap_or_else(|| format!("0x{id:02x}"))
}

pub fn parse_command(cluster: u16, v: &Value) -> Result<u8> {
    if let Some(n) = v.as_u64() {
        ensure!(n <= 0xFF, "a command id is one byte");
        return Ok(n as u8);
    }
    let s = v.as_str().context("command is a name or a number")?;
    COMMANDS
        .iter()
        .find(|(c, n, _)| *c == cluster && n.eq_ignore_ascii_case(s))
        .map(|(_, _, i)| *i)
        .with_context(|| {
            format!(
                "{s:?} is not a command of cluster {} NetGet knows by name; give its number",
                cluster_name(cluster)
            )
        })
}

/// A device NetGet derives a NWK address for when the description names none.
fn derived_nwk(ieee: u64, taken: &[u16]) -> u16 {
    let mut n = ((ieee ^ (ieee >> 16) ^ (ieee >> 32)) as u16 & 0xFFF7).max(0x0001);
    while taken.contains(&n) || n == 0x0000 || n >= 0xFFF8 {
        n = n.wrapping_add(0x0101) & 0xFFF7;
        if n == 0 {
            n = 1;
        }
    }
    n
}

fn u8_of(v: &Value, key: &str, default: Option<u8>) -> Result<u8> {
    match v.get(key) {
        None | Some(Value::Null) => default.with_context(|| format!("{key} is required")),
        Some(x) => {
            let n = x.as_u64().with_context(|| format!("{key} is a number"))?;
            ensure!(n <= 0xFF, "{key} is one byte");
            Ok(n as u8)
        }
    }
}

fn clusters_of(v: &Value, key: &str) -> Result<Vec<u16>> {
    let Some(list) = v.get(key).filter(|x| !x.is_null()) else {
        return Ok(Vec::new());
    };
    let list = list
        .as_array()
        .with_context(|| format!("{key} is a list of cluster ids"))?;
    ensure!(
        list.len() <= MAX_CLUSTERS,
        "{key} holds at most {MAX_CLUSTERS} clusters"
    );
    let mut out = Vec::new();
    for c in list {
        let id = parse_cluster(c)?;
        if !out.contains(&id) {
            out.push(id);
        }
    }
    Ok(out)
}

/// Read one device description. `taken` are NWK addresses already in use.
pub fn parse_device(v: &Value, taken: &[u16]) -> Result<Device> {
    let o = v
        .as_object()
        .context("a device is an object with ieee, endpoints and optionally name, nwk, type")?;
    let ieee = parse_eui(
        o.get("ieee")
            .and_then(Value::as_str)
            .context("ieee is the device's EUI-64")?,
    )?;
    ensure!(
        ieee != 0 && ieee != u64::MAX,
        "ieee 00…00 and ff…ff are not device addresses"
    );
    let name = match o.get("name").and_then(Value::as_str) {
        Some(n) => {
            let n = crate::utils::sanitize::token(n, NAME_CHARS);
            ensure!(!n.is_empty(), "name is not empty");
            n
        }
        None => eui_display(ieee),
    };
    let nwk = match o.get("nwk").filter(|x| !x.is_null()) {
        Some(n) => {
            let n = parse_u16(n, "nwk")?;
            ensure!(
                n != 0x0000 && n < 0xFFF8,
                "nwk 0x0000 is the coordinator and 0xfff8 and above are broadcast addresses"
            );
            ensure!(!taken.contains(&n), "nwk 0x{n:04x} is already in use");
            n
        }
        None => derived_nwk(ieee, taken),
    };
    let kind = match o.get("type").and_then(Value::as_str).unwrap_or("router") {
        "router" => Kind::Router,
        "end_device" => Kind::EndDevice,
        "sleepy_end_device" => Kind::SleepyEndDevice,
        other => bail!("type {other:?} is router, end_device or sleepy_end_device"),
    };
    let mains_powered = match o.get("power_source").and_then(Value::as_str) {
        None => kind == Kind::Router,
        Some("mains") => true,
        Some("battery") => false,
        Some(other) => bail!("power_source {other:?} is mains or battery"),
    };
    let manufacturer_code = match o.get("manufacturer_code").filter(|x| !x.is_null()) {
        Some(m) => parse_u16(m, "manufacturer_code")?,
        None => 0x0000,
    };
    let manufacturer = o.get("manufacturer").and_then(Value::as_str);
    let model = o.get("model").and_then(Value::as_str);
    let eps = o.get("endpoints").and_then(Value::as_array).context(
        "endpoints is a list of {id, profile, device_type, in_clusters, out_clusters, attributes}",
    )?;
    ensure!(
        !eps.is_empty() && eps.len() <= MAX_ENDPOINTS,
        "a device has 1 to {MAX_ENDPOINTS} endpoints"
    );
    let mut endpoints = Vec::new();
    for e in eps {
        let id = u8_of(e, "id", None)?;
        ensure!(
            (1..=240).contains(&id),
            "endpoint {id} is not an application endpoint (1..240)"
        );
        ensure!(
            !endpoints.iter().any(|x: &Endpoint| x.id == id),
            "endpoint {id} is described twice"
        );
        let profile = match e.get("profile").filter(|x| !x.is_null()) {
            Some(p) => parse_u16(p, "profile")?,
            None => PROFILE_HA,
        };
        let device_type = match e.get("device_type").filter(|x| !x.is_null()) {
            Some(d) => parse_u16(d, "device_type")?,
            None => 0x0100,
        };
        let version = u8_of(e, "version", Some(1))?;
        let in_clusters = clusters_of(e, "in_clusters")?;
        let out_clusters = clusters_of(e, "out_clusters")?;
        let mut attributes = BTreeMap::new();
        if in_clusters.contains(&0x0000) {
            attributes.insert(
                (0x0000, 0x0000),
                Attribute {
                    ty: 0x20,
                    value: AttrValue::Uint(8),
                },
            );
            attributes.insert(
                (0x0000, 0x0007),
                Attribute {
                    ty: 0x30,
                    value: AttrValue::Uint(if mains_powered { 0x01 } else { 0x03 }),
                },
            );
            for (attr, text) in [(0x0004u16, manufacturer), (0x0005, model)] {
                if let Some(t) = text {
                    attributes.insert((0x0000, attr), Attribute::from_json(0x42, &json!(t))?);
                }
            }
        }
        if let Some(list) = e.get("attributes").filter(|x| !x.is_null()) {
            let list = list
                .as_array()
                .context("attributes is a list of {cluster, attribute, type, value}")?;
            ensure!(
                list.len() <= MAX_ATTRIBUTES,
                "an endpoint has at most {MAX_ATTRIBUTES} attributes"
            );
            for a in list {
                let cluster =
                    parse_cluster(a.get("cluster").context("an attribute names its cluster")?)?;
                ensure!(
                    in_clusters.contains(&cluster),
                    "attribute of cluster {} on endpoint {id}, which does not serve it (in_clusters)",
                    cluster_name(cluster)
                );
                let attr = parse_u16(
                    a.get("attribute")
                        .context("an attribute has an id (attribute)")?,
                    "attribute",
                )?;
                let ty = type_by_name(
                    a.get("type")
                        .and_then(Value::as_str)
                        .context("an attribute has a type (bool, uint8, string, …)")?,
                )?;
                let value = Attribute::from_json(ty, a.get("value").unwrap_or(&Value::Null))
                    .with_context(|| {
                        format!("attribute 0x{attr:04x} of {}", cluster_name(cluster))
                    })?;
                attributes.insert((cluster, attr), value);
            }
        }
        ensure!(
            attributes.len() <= MAX_ATTRIBUTES + 4,
            "an endpoint has at most {MAX_ATTRIBUTES} attributes"
        );
        endpoints.push(Endpoint {
            id,
            profile,
            device_type,
            version,
            in_clusters,
            out_clusters,
            attributes,
        });
    }
    Ok(Device {
        name,
        ieee,
        nwk,
        kind,
        manufacturer_code,
        mains_powered,
        endpoints,
        zcl_tsn: 0,
        aps_counter: 0,
    })
}

impl Device {
    pub fn endpoint(&self, id: u8) -> Option<&Endpoint> {
        self.endpoints.iter().find(|e| e.id == id)
    }

    pub fn endpoint_mut(&mut self, id: u8) -> Option<&mut Endpoint> {
        self.endpoints.iter_mut().find(|e| e.id == id)
    }

    /// MAC capability flags as a device announces them.
    pub fn capability(&self) -> u8 {
        let mut c = 0x80; // allocate address
        if self.kind == Kind::Router {
            c |= 0x02;
        }
        if self.mains_powered {
            c |= 0x04;
        }
        if self.kind != Kind::SleepyEndDevice {
            c |= 0x08;
        }
        c
    }

    /// The 13-byte Node Descriptor.
    pub fn node_descriptor(&self) -> Vec<u8> {
        let logical = match self.kind {
            Kind::Router => 1,
            _ => 2,
        };
        let mut v = vec![logical, 0x40, self.capability()];
        v.extend_from_slice(&self.manufacturer_code.to_le_bytes());
        v.push(0x52);
        v.extend_from_slice(&0x0052u16.to_le_bytes());
        // Server mask: stack compliance revision 22, no server roles.
        v.extend_from_slice(&0x2C00u16.to_le_bytes());
        v.extend_from_slice(&0x0052u16.to_le_bytes());
        v.push(0x00);
        v
    }

    pub fn summary(&self) -> Value {
        json!({
            "name": self.name,
            "ieee": eui_display(self.ieee),
            "nwk": format!("0x{:04x}", self.nwk),
            "type": self.kind.name(),
            "endpoints": self.endpoints.iter().map(|e| json!({
                "id": e.id,
                "profile": format!("0x{:04x}", e.profile),
                "in_clusters": e.in_clusters.iter().map(|c| cluster_name(*c)).collect::<Vec<_>>(),
                "out_clusters": e.out_clusters.iter().map(|c| cluster_name(*c)).collect::<Vec<_>>(),
            })).collect::<Vec<_>>(),
        })
    }

    /// The current values of one cluster's attributes, for an event.
    pub fn cluster_values(&self, ep: u8, cluster: u16) -> Value {
        let mut m = Map::new();
        if let Some(e) = self.endpoint(ep) {
            for ((c, a), v) in &e.attributes {
                if *c == cluster {
                    m.insert(
                        format!("0x{a:04x}"),
                        json!({"type": type_name(v.ty), "value": v.to_json()}),
                    );
                }
            }
        }
        Value::Object(m)
    }

    pub fn next_zcl_tsn(&mut self) -> u8 {
        self.zcl_tsn = self.zcl_tsn.wrapping_add(1);
        self.zcl_tsn
    }

    pub fn next_aps(&mut self) -> u8 {
        self.aps_counter = self.aps_counter.wrapping_add(1);
        self.aps_counter
    }
}

/// A ZDO request answered: response cluster and payload, and whether the device leaves after.
pub struct ZdoReply {
    pub cluster: u16,
    pub payload: Vec<u8>,
    pub leave_after: bool,
}

/// Answer a ZDO request a device received. `None` for ZDO responses and broadcasts the device
/// does not answer.
pub fn zdo(dev: &Device, cluster: u16, payload: &[u8], broadcast: bool) -> Option<ZdoReply> {
    if cluster & 0x8000 != 0 {
        return None;
    }
    let tsn = *payload.first()?;
    let body = &payload[1..];
    let rsp = cluster | 0x8000;
    let reply = |p: Vec<u8>| {
        Some(ZdoReply {
            cluster: rsp,
            payload: p,
            leave_after: false,
        })
    };
    let nwk = dev.nwk.to_le_bytes();
    let ieee = dev.ieee.to_le_bytes();
    let of_interest = || -> Option<u16> {
        let b = body.get(..2)?;
        Some(u16::from_le_bytes([b[0], b[1]]))
    };
    match cluster {
        // NWK_addr_req: answered by the device whose IEEE it names, broadcast or not.
        0x0000 => {
            let b = body.get(..8)?;
            let mut a = [0u8; 8];
            a.copy_from_slice(b);
            if u64::from_le_bytes(a) != dev.ieee {
                return None;
            }
            let mut p = vec![tsn, zdo_status::SUCCESS];
            p.extend_from_slice(&ieee);
            p.extend_from_slice(&nwk);
            if body.get(8) == Some(&1) {
                p.extend_from_slice(&[0, 0]);
            }
            reply(p)
        }
        _ if broadcast => None,
        0x0001 => {
            let mut p = vec![tsn, zdo_status::SUCCESS];
            p.extend_from_slice(&ieee);
            p.extend_from_slice(&nwk);
            if body.get(2) == Some(&1) {
                p.extend_from_slice(&[0, 0]);
            }
            reply(p)
        }
        0x0002 => {
            let _ = of_interest()?;
            let mut p = vec![tsn, zdo_status::SUCCESS];
            p.extend_from_slice(&nwk);
            p.extend_from_slice(&dev.node_descriptor());
            reply(p)
        }
        0x0003 => {
            let _ = of_interest()?;
            let mut p = vec![tsn, zdo_status::SUCCESS];
            p.extend_from_slice(&nwk);
            if dev.mains_powered {
                p.extend_from_slice(&[0x10, 0xC1]);
            } else {
                p.extend_from_slice(&[0x40, 0xC4]);
            }
            reply(p)
        }
        0x0004 => {
            let ep = *body.get(2)?;
            let mut p = vec![tsn];
            match dev.endpoint(ep) {
                // 241–254 are reserved, not invalid: 242 is Green Power's.
                _ if ep == 0 || ep == 0xFF => {
                    p.push(zdo_status::INVALID_EP);
                    p.extend_from_slice(&nwk);
                    p.push(0);
                }
                None => {
                    p.push(zdo_status::NOT_ACTIVE);
                    p.extend_from_slice(&nwk);
                    p.push(0);
                }
                Some(e) => {
                    let d = e.simple_descriptor();
                    p.push(zdo_status::SUCCESS);
                    p.extend_from_slice(&nwk);
                    p.push(d.len() as u8);
                    p.extend_from_slice(&d);
                }
            }
            reply(p)
        }
        0x0005 => {
            let _ = of_interest()?;
            let mut p = vec![tsn, zdo_status::SUCCESS];
            p.extend_from_slice(&nwk);
            p.push(dev.endpoints.len() as u8);
            p.extend(dev.endpoints.iter().map(|e| e.id));
            reply(p)
        }
        0x0006 => {
            let profile = u16::from_le_bytes([*body.get(2)?, *body.get(3)?]);
            let n_in = *body.get(4)? as usize;
            let ins: Vec<u16> = (0..n_in)
                .map(|i| {
                    Some(u16::from_le_bytes([
                        *body.get(5 + 2 * i)?,
                        *body.get(6 + 2 * i)?,
                    ]))
                })
                .collect::<Option<_>>()?;
            let at = 5 + 2 * n_in;
            let n_out = *body.get(at)? as usize;
            let outs: Vec<u16> = (0..n_out)
                .map(|i| {
                    Some(u16::from_le_bytes([
                        *body.get(at + 1 + 2 * i)?,
                        *body.get(at + 2 + 2 * i)?,
                    ]))
                })
                .collect::<Option<_>>()?;
            let eps: Vec<u8> = dev
                .endpoints
                .iter()
                .filter(|e| {
                    (e.profile == profile || profile == 0xFFFF)
                        && (ins.iter().any(|c| e.in_clusters.contains(c))
                            || outs.iter().any(|c| e.out_clusters.contains(c)))
                })
                .map(|e| e.id)
                .collect();
            let mut p = vec![tsn, zdo_status::SUCCESS];
            p.extend_from_slice(&nwk);
            p.push(eps.len() as u8);
            p.extend(eps);
            reply(p)
        }
        // Bind_req / Unbind_req: the source must be this device and serve the cluster.
        0x0021 | 0x0022 => {
            let src = body.get(..8)?;
            let ep = *body.get(8)?;
            let c = u16::from_le_bytes([*body.get(9)?, *body.get(10)?]);
            let ok = src == ieee
                && dev
                    .endpoint(ep)
                    .is_some_and(|e| e.in_clusters.contains(&c) || e.out_clusters.contains(&c));
            let status = if ok {
                zdo_status::SUCCESS
            } else if dev.endpoint(ep).is_none() {
                zdo_status::INVALID_EP
            } else {
                zdo_status::NOT_SUPPORTED
            };
            reply(vec![tsn, status])
        }
        // Mgmt_Lqi_req / Mgmt_Rtg_req: an empty table.
        0x0031 | 0x0032 => {
            let start = body.first().copied().unwrap_or(0);
            reply(vec![tsn, zdo_status::SUCCESS, 0, start, 0])
        }
        0x0034 => Some(ZdoReply {
            cluster: rsp,
            payload: vec![tsn, zdo_status::SUCCESS],
            leave_after: true,
        }),
        0x0036 => reply(vec![tsn, zdo_status::SUCCESS]),
        _ => reply(vec![tsn, zdo_status::NOT_SUPPORTED]),
    }
}

/// A ZCL frame header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZclHeader {
    pub frame_control: u8,
    pub manufacturer: Option<u16>,
    pub tsn: u8,
    pub command: u8,
}

impl ZclHeader {
    pub fn parse(data: &[u8]) -> Option<(Self, &[u8])> {
        let fc = *data.first()?;
        let (manufacturer, rest) = if fc & 0x04 != 0 {
            (
                Some(u16::from_le_bytes([*data.get(1)?, *data.get(2)?])),
                data.get(3..)?,
            )
        } else {
            (None, data.get(1..)?)
        };
        let tsn = *rest.first()?;
        let command = *rest.get(1)?;
        Some((
            Self {
                frame_control: fc,
                manufacturer,
                tsn,
                command,
            },
            &rest[2..],
        ))
    }
    pub fn cluster_specific(&self) -> bool {
        self.frame_control & 0x03 == 0x01
    }
    pub fn server_to_client(&self) -> bool {
        self.frame_control & 0x08 != 0
    }
    pub fn default_response_disabled(&self) -> bool {
        self.frame_control & 0x10 != 0
    }
}

/// A reply frame to a request: same frame type unless `global`, opposite direction, default
/// response disabled, manufacturer code mirrored.
pub fn reply_frame(req: &ZclHeader, global: bool, command: u8, payload: &[u8]) -> Vec<u8> {
    let mut fc = if global {
        0x00
    } else {
        req.frame_control & 0x03
    };
    if !req.server_to_client() {
        fc |= 0x08;
    }
    fc |= 0x10;
    let mut v = Vec::with_capacity(payload.len() + 5);
    if let Some(m) = req.manufacturer {
        fc |= 0x04;
        v.push(fc);
        v.extend_from_slice(&m.to_le_bytes());
    } else {
        v.push(fc);
    }
    v.push(req.tsn);
    v.push(command);
    v.extend_from_slice(payload);
    v
}

/// A Default Response; `None` when the request disabled it and the status is success.
pub fn default_response(req: &ZclHeader, status: u8) -> Option<Vec<u8>> {
    if status == zcl_status::SUCCESS && req.default_response_disabled() {
        return None;
    }
    Some(reply_frame(req, true, 0x0B, &[req.command, status]))
}

/// What the device does with a ZCL frame.
#[derive(Debug)]
pub enum ZclOutcome {
    /// Answered from the description.
    Reply(Vec<u8>),
    /// The model decides.
    Ask(ZclRequest),
    /// Nothing to answer (a response or report from the host, a broadcast).
    Nothing,
}

/// A ZCL request the model answers, with what NetGet decoded of it.
#[derive(Debug, Clone)]
pub struct ZclRequest {
    pub header: ZclHeader,
    pub endpoint: u8,
    pub cluster: u16,
    pub payload: Vec<u8>,
    /// Decoded fields (attribute writes, known command arguments).
    pub fields: Value,
    pub kind: RequestKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestKind {
    ClusterCommand,
    WriteAttributes { undivided: bool, no_response: bool },
    ManufacturerGlobal,
}

/// Answer a ZCL frame addressed to one of the device's endpoints.
pub fn zcl(dev: &Device, ep: u8, cluster: u16, data: &[u8]) -> ZclOutcome {
    let Some((h, body)) = ZclHeader::parse(data) else {
        // Too short to carry a sequence number: nothing a reply could be matched to.
        return ZclOutcome::Nothing;
    };
    if h.server_to_client() {
        // A response, report or command from the host acting as a server: the device's
        // stack takes it without a reply.
        return ZclOutcome::Nothing;
    }
    let Some(endpoint) = dev.endpoint(ep) else {
        return ZclOutcome::Nothing;
    };
    if !endpoint.in_clusters.contains(&cluster) {
        return match default_response(&h, zcl_status::UNSUPPORTED_CLUSTER) {
            Some(r) => ZclOutcome::Reply(r),
            None => ZclOutcome::Nothing,
        };
    }
    if h.cluster_specific() || h.manufacturer.is_some() {
        let kind = if h.cluster_specific() {
            RequestKind::ClusterCommand
        } else {
            RequestKind::ManufacturerGlobal
        };
        return ZclOutcome::Ask(ZclRequest {
            header: h,
            endpoint: ep,
            cluster,
            payload: body.to_vec(),
            fields: command_fields(cluster, &h, body),
            kind,
        });
    }
    let reply = |cmd: u8, p: &[u8]| ZclOutcome::Reply(reply_frame(&h, true, cmd, p));
    let fail = |status: u8| match default_response(&h, status) {
        Some(r) => ZclOutcome::Reply(r),
        None => ZclOutcome::Nothing,
    };
    match h.command {
        // Read Attributes.
        0x00 => {
            if body.len() % 2 != 0 || body.is_empty() {
                return fail(zcl_status::MALFORMED_COMMAND);
            }
            let mut p = Vec::new();
            for id in body
                .as_chunks::<2>()
                .0
                .iter()
                .map(|c| u16::from_le_bytes(*c))
            {
                let mut rec = id.to_le_bytes().to_vec();
                match endpoint.attributes.get(&(cluster, id)) {
                    Some(a) => {
                        rec.push(zcl_status::SUCCESS);
                        rec.push(a.ty);
                        rec.extend(a.encode());
                    }
                    None => rec.push(zcl_status::UNSUPPORTED_ATTRIBUTE),
                }
                // A response that would not fit one frame carries the records that do.
                if p.len() + rec.len() + 3 > MAX_APS_PAYLOAD {
                    break;
                }
                p.extend(rec);
            }
            reply(0x01, &p)
        }
        // Write Attributes, undivided, no response: the model decides.
        0x02 | 0x03 | 0x05 => {
            let mut writes = Vec::new();
            let mut rest = body;
            while !rest.is_empty() {
                let (Some(lo), Some(hi), Some(ty)) = (rest.first(), rest.get(1), rest.get(2))
                else {
                    return fail(zcl_status::MALFORMED_COMMAND);
                };
                let attr = u16::from_le_bytes([*lo, *hi]);
                let Some((value, used)) = Attribute::decode(*ty, &rest[3..]) else {
                    return fail(zcl_status::INVALID_DATA_TYPE);
                };
                writes.push(json!({
                    "attribute": format!("0x{attr:04x}"),
                    "type": type_name(*ty),
                    "value": value.to_json(),
                    "described": endpoint.attributes.contains_key(&(cluster, attr)),
                }));
                rest = &rest[3 + used..];
                if writes.len() > MAX_ATTRIBUTES {
                    return fail(zcl_status::INSUFFICIENT_SPACE);
                }
            }
            ZclOutcome::Ask(ZclRequest {
                header: h,
                endpoint: ep,
                cluster,
                payload: body.to_vec(),
                fields: json!({"writes": writes}),
                kind: RequestKind::WriteAttributes {
                    undivided: h.command == 0x03,
                    no_response: h.command == 0x05,
                },
            })
        }
        // Configure Reporting: accepted for every described attribute.
        0x06 => {
            let mut statuses = Vec::new();
            let mut rest = body;
            while !rest.is_empty() {
                let dir = rest[0];
                let Some(id) = rest.get(1..3).map(|b| u16::from_le_bytes([b[0], b[1]])) else {
                    return fail(zcl_status::MALFORMED_COMMAND);
                };
                let used = if dir == 0x00 {
                    let Some(ty) = rest.get(3).copied() else {
                        return fail(zcl_status::MALFORMED_COMMAND);
                    };
                    let analog = matches!(ty, 0x20..=0x2F | 0x38..=0x3A | 0xE0..=0xE2);
                    let change = if analog { width(ty).unwrap_or(0) } else { 0 };
                    if analog && change == 0 {
                        return fail(zcl_status::INVALID_DATA_TYPE);
                    }
                    8 + change
                } else if dir == 0x01 {
                    5
                } else {
                    return fail(zcl_status::INVALID_FIELD);
                };
                if rest.len() < used {
                    return fail(zcl_status::MALFORMED_COMMAND);
                }
                let st = if endpoint.attributes.contains_key(&(cluster, id)) {
                    zcl_status::SUCCESS
                } else {
                    zcl_status::UNSUPPORTED_ATTRIBUTE
                };
                statuses.push((st, dir, id));
                rest = &rest[used..];
                if statuses.len() > MAX_ATTRIBUTES {
                    return fail(zcl_status::INSUFFICIENT_SPACE);
                }
            }
            if statuses.iter().all(|(s, _, _)| *s == zcl_status::SUCCESS) {
                return reply(0x07, &[zcl_status::SUCCESS]);
            }
            let mut p = Vec::new();
            for (s, d, id) in statuses
                .iter()
                .filter(|(s, _, _)| *s != zcl_status::SUCCESS)
            {
                p.push(*s);
                p.push(*d);
                p.extend_from_slice(&id.to_le_bytes());
            }
            reply(0x07, &p)
        }
        // Discover Attributes.
        0x0C => {
            let (Some(lo), Some(hi), Some(max)) = (body.first(), body.get(1), body.get(2)) else {
                return fail(zcl_status::MALFORMED_COMMAND);
            };
            let start = u16::from_le_bytes([*lo, *hi]);
            let all: Vec<(u16, u8)> = endpoint
                .attributes
                .iter()
                .filter(|((c, a), _)| *c == cluster && *a >= start)
                .map(|((_, a), v)| (*a, v.ty))
                .collect();
            let fit = ((MAX_APS_PAYLOAD - 4) / 3).min(*max as usize);
            let complete = all.len() <= fit;
            let mut p = vec![complete as u8];
            for (a, t) in all.into_iter().take(fit) {
                p.extend_from_slice(&a.to_le_bytes());
                p.push(t);
            }
            reply(0x0D, &p)
        }
        // A Default Response or a report from the host needs nothing back.
        0x0B | 0x0A | 0x01 | 0x04 | 0x07 => ZclOutcome::Nothing,
        _ => fail(zcl_status::UNSUP_GENERAL_COMMAND),
    }
}

/// What NetGet can read of a cluster command's arguments.
fn command_fields(cluster: u16, h: &ZclHeader, body: &[u8]) -> Value {
    if !h.cluster_specific() || h.manufacturer.is_some() {
        return json!({});
    }
    let u16_at = |i: usize| body.get(i..i + 2).map(|b| u16::from_le_bytes([b[0], b[1]]));
    match (cluster, h.command) {
        (0x0003, 0x00) => json!({"identify_time_secs": u16_at(0)}),
        (0x0008, 0x00) | (0x0008, 0x04) => {
            json!({"level": body.first(), "transition_tenths": u16_at(1)})
        }
        (0x0008, 0x01) | (0x0008, 0x05) => {
            json!({"move_mode": body.first(), "rate": body.get(1)})
        }
        (0x0008, 0x02) | (0x0008, 0x06) => {
            json!({"step_mode": body.first(), "step_size": body.get(1), "transition_tenths": u16_at(2)})
        }
        (0x0300, 0x0A) => {
            json!({"color_temp_mireds": u16_at(0), "transition_tenths": u16_at(2)})
        }
        (0x0300, 0x07) => {
            json!({"color_x": u16_at(0), "color_y": u16_at(2), "transition_tenths": u16_at(4)})
        }
        (0x0006, 0x42) => {
            json!({"on_off_control": body.first(), "on_time_tenths": u16_at(1), "off_wait_time_tenths": u16_at(3)})
        }
        _ => json!({}),
    }
}

/// Attribute updates the model gave, applied to the description; returns the records written
/// (for a report) in order.
pub fn apply_attributes(
    dev: &mut Device,
    ep: u8,
    default_cluster: Option<u16>,
    list: &[Value],
) -> Result<Vec<(u16, u16, Attribute)>> {
    ensure!(
        list.len() <= MAX_ATTRIBUTES,
        "at most {MAX_ATTRIBUTES} attributes at once"
    );
    let endpoint = dev
        .endpoint_mut(ep)
        .with_context(|| format!("the device has no endpoint {ep}"))?;
    let mut planned = Vec::new();
    for a in list {
        let cluster = match a.get("cluster").filter(|x| !x.is_null()) {
            Some(c) => parse_cluster(c)?,
            None => default_cluster.context("each attribute names its cluster")?,
        };
        ensure!(
            endpoint.in_clusters.contains(&cluster),
            "endpoint {ep} does not serve cluster {}",
            cluster_name(cluster)
        );
        let attr = parse_u16(
            a.get("attribute")
                .context("each attribute has an id (attribute)")?,
            "attribute",
        )?;
        let ty = match a.get("type").and_then(Value::as_str) {
            Some(t) => type_by_name(t)?,
            None => endpoint
                .attributes
                .get(&(cluster, attr))
                .map(|x| x.ty)
                .with_context(|| {
                    format!(
                        "attribute 0x{attr:04x} of {} is not described; give its type",
                        cluster_name(cluster)
                    )
                })?,
        };
        let value = Attribute::from_json(ty, a.get("value").unwrap_or(&Value::Null))?;
        planned.push((cluster, attr, value));
    }
    for (c, a, v) in &planned {
        endpoint.attributes.insert((*c, *a), v.clone());
    }
    ensure!(
        endpoint.attributes.len() <= MAX_ATTRIBUTES + 4,
        "an endpoint has at most {MAX_ATTRIBUTES} attributes"
    );
    Ok(planned)
}

/// A Report Attributes frame from the device (server to client, default response disabled),
/// cut to the records that fit one frame.
pub fn report_frame(tsn: u8, records: &[(u16, Attribute)]) -> Vec<u8> {
    let mut v = vec![0x18, tsn, 0x0A];
    for (id, a) in records {
        let mut rec = id.to_le_bytes().to_vec();
        rec.push(a.ty);
        rec.extend(a.encode());
        if v.len() + rec.len() > MAX_APS_PAYLOAD {
            break;
        }
        v.extend(rec);
    }
    v
}

/// A cluster command the device sends as a client (a button press), default response enabled.
pub fn command_frame(tsn: u8, command: u8, payload: &[u8]) -> Vec<u8> {
    let mut v = vec![0x01, tsn, command];
    v.extend_from_slice(payload);
    v
}

/// A Device_annce the device broadcasts after joining.
pub fn device_announce(dev: &Device, tsn: u8) -> Vec<u8> {
    let mut v = vec![tsn];
    v.extend_from_slice(&dev.nwk.to_le_bytes());
    v.extend_from_slice(&dev.ieee.to_le_bytes());
    v.push(dev.capability());
    v
}

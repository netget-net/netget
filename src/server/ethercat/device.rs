//! What an emulated slave is: its identity, its process data (named, typed entries packed
//! little-endian at bit offsets, as EtherCAT lays them out), and its object dictionary.
//!
//! The model never sees octets: inputs and outputs are `{name: value}` maps and SDO values are
//! typed numbers, booleans or strings, converted here.
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Map, Value};

/// Entries per direction (inputs or outputs) of one slave.
pub const MAX_ENTRIES: usize = 32;
/// Process data octets per direction of one slave (each 3-buffer SyncManager occupies three
/// times this in ESC memory).
pub const MAX_PD_BYTES: usize = 128;
/// Declared dictionary objects (index/subindex pairs) of one slave.
pub const MAX_OBJECTS: usize = 128;
/// Longest string an SDO value or a device name may be.
pub const MAX_STRING: usize = 64;
/// Emulated slaves on one segment.
pub const MAX_SLAVES: usize = 8;

/// CoE data types (ETG.1000.6 Table 64).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataType {
    Bool,
    I8,
    I16,
    I32,
    I64,
    U8,
    U16,
    U32,
    U64,
    F32,
    F64,
    /// VISIBLE_STRING; only in the dictionary, never in process data.
    String,
}

impl DataType {
    pub fn parse(s: &str) -> Result<Self> {
        Ok(match s.trim().to_ascii_lowercase().as_str() {
            "bool" | "boolean" => DataType::Bool,
            "i8" | "int8" | "sint" => DataType::I8,
            "i16" | "int16" | "int" => DataType::I16,
            "i32" | "int32" | "dint" => DataType::I32,
            "i64" | "int64" | "lint" => DataType::I64,
            "u8" | "uint8" | "usint" | "byte" => DataType::U8,
            "u16" | "uint16" | "uint" | "word" => DataType::U16,
            "u32" | "uint32" | "udint" | "dword" => DataType::U32,
            "u64" | "uint64" | "ulint" => DataType::U64,
            "f32" | "real" | "real32" => DataType::F32,
            "f64" | "lreal" | "real64" => DataType::F64,
            "string" | "visible_string" => DataType::String,
            other => bail!(
                "type {other:?} is one of bool, i8, i16, i32, i64, u8, u16, u32, u64, f32, f64, \
                 string"
            ),
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            DataType::Bool => "bool",
            DataType::I8 => "i8",
            DataType::I16 => "i16",
            DataType::I32 => "i32",
            DataType::I64 => "i64",
            DataType::U8 => "u8",
            DataType::U16 => "u16",
            DataType::U32 => "u32",
            DataType::U64 => "u64",
            DataType::F32 => "f32",
            DataType::F64 => "f64",
            DataType::String => "string",
        }
    }

    /// The CoE data type code (SII PDO entries and object descriptions carry it).
    pub fn code(self) -> u16 {
        match self {
            DataType::Bool => 0x0001,
            DataType::I8 => 0x0002,
            DataType::I16 => 0x0003,
            DataType::I32 => 0x0004,
            DataType::U8 => 0x0005,
            DataType::U16 => 0x0006,
            DataType::U32 => 0x0007,
            DataType::F32 => 0x0008,
            DataType::String => 0x0009,
            DataType::F64 => 0x0011,
            DataType::I64 => 0x0015,
            DataType::U64 => 0x001B,
        }
    }

    pub fn from_code(code: u16) -> Option<Self> {
        Some(match code {
            0x0001 => DataType::Bool,
            0x0002 => DataType::I8,
            0x0003 => DataType::I16,
            0x0004 => DataType::I32,
            0x0005 => DataType::U8,
            0x0006 => DataType::U16,
            0x0007 => DataType::U32,
            0x0008 => DataType::F32,
            0x0009 => DataType::String,
            0x0011 => DataType::F64,
            0x0015 => DataType::I64,
            0x001B => DataType::U64,
            _ => return None,
        })
    }

    /// Size in bits (a string has none fixed).
    pub fn bits(self) -> usize {
        match self {
            DataType::Bool => 1,
            DataType::I8 | DataType::U8 => 8,
            DataType::I16 | DataType::U16 => 16,
            DataType::I32 | DataType::U32 | DataType::F32 => 32,
            DataType::I64 | DataType::U64 | DataType::F64 => 64,
            DataType::String => 0,
        }
    }

    /// The octets of a value of this type (little-endian). Strings are their UTF-8 bytes.
    pub fn encode(self, v: &Value) -> Result<Vec<u8>> {
        let int = |min: i128, max: i128| -> Result<i128> {
            let n: i128 = match v {
                Value::Number(n) => {
                    if let Some(i) = n.as_i64() {
                        i as i128
                    } else if let Some(u) = n.as_u64() {
                        u as i128
                    } else {
                        let f = n.as_f64().unwrap_or(f64::NAN);
                        ensure!(f.fract() == 0.0, "{f} is not a whole number");
                        f as i128
                    }
                }
                Value::Bool(b) => *b as i128,
                Value::String(s) => parse_int_text(s)?,
                other => bail!("{other} is not a number"),
            };
            ensure!(
                (min..=max).contains(&n),
                "{n} does not fit a {} ({min}..={max})",
                self.name()
            );
            Ok(n)
        };
        let float = || -> Result<f64> {
            match v {
                Value::Number(n) => n.as_f64().context("not a number"),
                Value::String(s) => s.trim().parse().context("not a number"),
                other => bail!("{other} is not a number"),
            }
        };
        Ok(match self {
            DataType::Bool => match v {
                Value::Bool(b) => vec![*b as u8],
                _ => vec![int(0, 1)? as u8],
            },
            DataType::I8 => (int(i8::MIN as i128, i8::MAX as i128)? as i8)
                .to_le_bytes()
                .to_vec(),
            DataType::U8 => vec![int(0, u8::MAX as i128)? as u8],
            DataType::I16 => (int(i16::MIN as i128, i16::MAX as i128)? as i16)
                .to_le_bytes()
                .to_vec(),
            DataType::U16 => (int(0, u16::MAX as i128)? as u16).to_le_bytes().to_vec(),
            DataType::I32 => (int(i32::MIN as i128, i32::MAX as i128)? as i32)
                .to_le_bytes()
                .to_vec(),
            DataType::U32 => (int(0, u32::MAX as i128)? as u32).to_le_bytes().to_vec(),
            DataType::I64 => (int(i64::MIN as i128, i64::MAX as i128)? as i64)
                .to_le_bytes()
                .to_vec(),
            DataType::U64 => (int(0, u64::MAX as i128)? as u64).to_le_bytes().to_vec(),
            DataType::F32 => (float()? as f32).to_le_bytes().to_vec(),
            DataType::F64 => float()?.to_le_bytes().to_vec(),
            DataType::String => {
                let s = v.as_str().context("a string value is required")?;
                ensure!(
                    s.len() <= MAX_STRING,
                    "the string is {} octets, at most {MAX_STRING}",
                    s.len()
                );
                s.as_bytes().to_vec()
            }
        })
    }

    /// A value of this type from its octets. `None` when the length is wrong.
    pub fn decode(self, b: &[u8]) -> Option<Value> {
        let fixed = self.bits().div_ceil(8);
        if self != DataType::String && b.len() != fixed {
            return None;
        }
        Some(match self {
            DataType::Bool => json!(b[0] & 1 != 0),
            DataType::I8 => json!(b[0] as i8),
            DataType::U8 => json!(b[0]),
            DataType::I16 => json!(i16::from_le_bytes([b[0], b[1]])),
            DataType::U16 => json!(u16::from_le_bytes([b[0], b[1]])),
            DataType::I32 => json!(i32::from_le_bytes(b.try_into().ok()?)),
            DataType::U32 => json!(u32::from_le_bytes(b.try_into().ok()?)),
            DataType::I64 => json!(i64::from_le_bytes(b.try_into().ok()?)),
            DataType::U64 => json!(u64::from_le_bytes(b.try_into().ok()?)),
            DataType::F32 => {
                let f = f32::from_le_bytes(b.try_into().ok()?);
                if f.is_finite() {
                    json!(f)
                } else {
                    json!(f.to_string())
                }
            }
            DataType::F64 => {
                let f = f64::from_le_bytes(b.try_into().ok()?);
                if f.is_finite() {
                    json!(f)
                } else {
                    json!(f.to_string())
                }
            }
            DataType::String => {
                let end = b.iter().position(|c| *c == 0).unwrap_or(b.len());
                json!(crate::utils::sanitize::line_field(
                    &String::from_utf8_lossy(&b[..end])
                ))
            }
        })
    }
}

/// "0x1A", "26", "-3".
pub fn parse_int_text(s: &str) -> Result<i128> {
    let t = s.trim();
    let (neg, t) = match t.strip_prefix('-') {
        Some(r) => (true, r),
        None => (false, t),
    };
    let n = match t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        Some(h) => i128::from_str_radix(h, 16),
        None => t.parse::<i128>(),
    }
    .with_context(|| format!("{s:?} is not a number"))?;
    Ok(if neg { -n } else { n })
}

/// A number (or "0x…" text) in a JSON field.
pub fn number_field(v: Option<&Value>, what: &str, max: u64) -> Result<u64> {
    let n = match v {
        Some(Value::Number(n)) => {
            n.as_u64()
                .with_context(|| format!("{what} must be a whole number ≥ 0"))? as i128
        }
        Some(Value::String(s)) => parse_int_text(s)?,
        None | Some(Value::Null) => bail!("{what} is required"),
        Some(other) => bail!("{what} must be a number, got {other}"),
    };
    ensure!(
        (0..=max as i128).contains(&n),
        "{what} must be 0..={max:#x}, got {n}"
    );
    Ok(n as u64)
}

/// One process data entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub name: String,
    pub ty: DataType,
    /// Bit offset inside the direction's image.
    pub bit_offset: usize,
}

/// One direction of process data: entries packed in order, little-endian, no gaps.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Image {
    pub entries: Vec<Entry>,
    pub bits: usize,
}

impl Image {
    pub fn parse(v: Option<&Value>, what: &str) -> Result<Self> {
        let list = match v {
            None | Some(Value::Null) => return Ok(Image::default()),
            Some(Value::Array(a)) => a,
            Some(other) => bail!("{what} is a list of {{name, type}}, got {other}"),
        };
        ensure!(
            list.len() <= MAX_ENTRIES,
            "{what} has {} entries, at most {MAX_ENTRIES}",
            list.len()
        );
        let mut img = Image::default();
        for (i, e) in list.iter().enumerate() {
            let name = e
                .get("name")
                .and_then(Value::as_str)
                .with_context(|| format!("{what}[{i}] needs a name"))?
                .trim()
                .to_string();
            ensure!(
                !name.is_empty()
                    && name.len() <= 32
                    && name
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-'),
                "{what}[{i}] name {name:?}: 1-32 letters, digits, '_' or '-'"
            );
            ensure!(
                !img.entries.iter().any(|x| x.name == name),
                "{what} names {name:?} twice"
            );
            let ty = DataType::parse(
                e.get("type")
                    .and_then(Value::as_str)
                    .with_context(|| format!("{what}[{i}] needs a type"))?,
            )?;
            ensure!(
                ty != DataType::String,
                "{what}[{i}]: strings cannot be process data"
            );
            img.entries.push(Entry {
                name,
                ty,
                bit_offset: img.bits,
            });
            img.bits += ty.bits();
        }
        ensure!(
            img.bytes() <= MAX_PD_BYTES,
            "{what} is {} octets, at most {MAX_PD_BYTES}",
            img.bytes()
        );
        Ok(img)
    }

    pub fn bytes(&self) -> usize {
        self.bits.div_ceil(8)
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Write `values` (a subset of the entries, by name) into `buf`.
    pub fn encode_into(&self, values: &Map<String, Value>, buf: &mut [u8]) -> Result<()> {
        ensure!(buf.len() >= self.bytes(), "image buffer too short");
        for (k, v) in values {
            let e = self
                .entries
                .iter()
                .find(|e| &e.name == k)
                .with_context(|| {
                    format!(
                        "no entry named {k:?} (have: {})",
                        self.entries
                            .iter()
                            .map(|e| e.name.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    )
                })?;
            let octets =
                e.ty.encode(v)
                    .with_context(|| format!("{k} ({})", e.ty.name()))?;
            put_bits(buf, e.bit_offset, e.ty.bits(), &octets);
        }
        Ok(())
    }

    /// Every entry's value, from `buf`.
    pub fn decode(&self, buf: &[u8]) -> Map<String, Value> {
        let mut m = Map::new();
        for e in &self.entries {
            let octets = get_bits(buf, e.bit_offset, e.ty.bits());
            if let Some(v) = e.ty.decode(&octets) {
                m.insert(e.name.clone(), v);
            }
        }
        m
    }

    pub fn describe(&self) -> Value {
        Value::Array(
            self.entries
                .iter()
                .map(|e| json!({"name": e.name, "type": e.ty.name()}))
                .collect(),
        )
    }
}

/// Copy `bits` bits of `src` (LSB first) into `dst` at bit `at`.
pub fn put_bits(dst: &mut [u8], at: usize, bits: usize, src: &[u8]) {
    for i in 0..bits {
        let bit = src.get(i / 8).is_some_and(|b| b >> (i % 8) & 1 != 0);
        let d = at + i;
        if let Some(byte) = dst.get_mut(d / 8) {
            if bit {
                *byte |= 1 << (d % 8);
            } else {
                *byte &= !(1 << (d % 8));
            }
        }
    }
}

/// `bits` bits of `src` from bit `at`, LSB first, in whole octets.
pub fn get_bits(src: &[u8], at: usize, bits: usize) -> Vec<u8> {
    let mut out = vec![0u8; bits.div_ceil(8)];
    for i in 0..bits {
        let s = at + i;
        if src.get(s / 8).is_some_and(|b| b >> (s % 8) & 1 != 0) {
            out[i / 8] |= 1 << (i % 8);
        }
    }
    out
}

/// Who may touch a dictionary object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    ReadOnly,
    ReadWrite,
    WriteOnly,
}

impl Access {
    pub fn parse(v: Option<&str>) -> Result<Self> {
        Ok(match v.map(str::to_ascii_lowercase).as_deref() {
            None | Some("rw") => Access::ReadWrite,
            Some("ro") => Access::ReadOnly,
            Some("wo") => Access::WriteOnly,
            Some(other) => bail!("access is ro, rw or wo, not {other:?}"),
        })
    }
    pub fn name(self) -> &'static str {
        match self {
            Access::ReadOnly => "ro",
            Access::ReadWrite => "rw",
            Access::WriteOnly => "wo",
        }
    }
}

/// A dictionary object the model answers for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Object {
    pub index: u16,
    pub subindex: u8,
    pub name: String,
    pub ty: DataType,
    pub access: Access,
}

/// One emulated slave.
#[derive(Debug, Clone, PartialEq)]
pub struct DeviceSpec {
    pub name: String,
    pub vendor_id: u32,
    pub product_code: u32,
    pub revision: u32,
    pub serial: u32,
    /// CoE 0x1000 (the device profile; 0 = none).
    pub device_type: u32,
    pub hardware_version: Option<String>,
    pub software_version: Option<String>,
    pub alias: u16,
    pub inputs: Image,
    pub outputs: Image,
    pub objects: Vec<Object>,
}

/// The default slave: one u8 input `inputs`, one u8 output `outputs`. Its vendor ID is 0, which
/// is not an ETG assignment: set it to the device being described.
pub fn default_device(position: usize) -> DeviceSpec {
    DeviceSpec {
        name: if position == 0 {
            "NetGet EtherCAT slave".into()
        } else {
            format!("NetGet EtherCAT slave {}", position + 1)
        },
        vendor_id: 0,
        product_code: 1,
        revision: 1,
        serial: position as u32 + 1,
        device_type: 0,
        hardware_version: None,
        software_version: None,
        alias: 0,
        inputs: Image::parse(Some(&json!([{"name": "inputs", "type": "u8"}])), "inputs")
            .expect("default inputs"),
        outputs: Image::parse(Some(&json!([{"name": "outputs", "type": "u8"}])), "outputs")
            .expect("default outputs"),
        objects: Vec::new(),
    }
}

fn text(v: Option<&Value>, what: &str) -> Result<Option<String>> {
    match v {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => {
            ensure!(
                s.len() <= MAX_STRING,
                "{what} is {} octets, at most {MAX_STRING}",
                s.len()
            );
            ensure!(
                !crate::utils::sanitize::has_controls(s),
                "{what} must be printable text"
            );
            Ok(Some(s.clone()))
        }
        Some(other) => bail!("{what} must be text, got {other}"),
    }
}

/// Indices Rust answers itself (identity, PDO mapping and assignment, SM types, the process
/// data objects). A declared object may not take one.
pub fn is_structural(index: u16) -> bool {
    matches!(
        index,
        0x1000 | 0x1008 | 0x1009 | 0x100A | 0x1018 | 0x1600 | 0x1A00 | 0x1C00 | 0x1C12 | 0x1C13
    ) || index == super::coe::INPUT_OBJECT
        || index == super::coe::OUTPUT_OBJECT
}

impl DeviceSpec {
    pub fn parse(v: &Value, position: usize) -> Result<Self> {
        let d = default_device(position);
        let o = v
            .as_object()
            .context("each slave is an object {name, vendor_id, product_code, …}")?;
        let known = [
            "name",
            "vendor_id",
            "product_code",
            "revision",
            "serial",
            "device_type",
            "hardware_version",
            "software_version",
            "alias",
            "inputs",
            "outputs",
            "objects",
        ];
        if let Some(k) = o.keys().find(|k| !known.contains(&k.as_str())) {
            bail!("unknown slave field {k:?} (known: {})", known.join(", "));
        }
        let num = |k: &str, default: u32| -> Result<u32> {
            match o.get(k) {
                None | Some(Value::Null) => Ok(default),
                some => Ok(number_field(some, k, u32::MAX as u64)? as u32),
            }
        };
        let name = text(o.get("name"), "name")?.unwrap_or(d.name);
        ensure!(!name.is_empty(), "name must not be empty");
        let inputs = match o.get("inputs") {
            None => d.inputs,
            some => Image::parse(some, "inputs")?,
        };
        let outputs = match o.get("outputs") {
            None => d.outputs,
            some => Image::parse(some, "outputs")?,
        };
        let mut objects: Vec<Object> = Vec::new();
        if let Some(list) = o.get("objects").filter(|x| !x.is_null()) {
            let list = list
                .as_array()
                .context("objects is a list of {index, subindex, name, type, access}")?;
            ensure!(
                list.len() <= MAX_OBJECTS,
                "objects has {} entries, at most {MAX_OBJECTS}",
                list.len()
            );
            for (i, ob) in list.iter().enumerate() {
                let index = number_field(ob.get("index"), "objects[].index", 0xFFFF)? as u16;
                ensure!(
                    (0x2000..=0x5FFF).contains(&index) || (0x8000..=0xFFFF).contains(&index),
                    "objects[{i}]: index {index:#06x} is outside the manufacturer (0x2000-0x5FFF) \
                     and device (0x8000-0xFFFF) areas"
                );
                ensure!(
                    !is_structural(index),
                    "objects[{i}]: index {index:#06x} is answered by NetGet itself"
                );
                let subindex = match ob.get("subindex") {
                    None | Some(Value::Null) => 0,
                    some => number_field(some, "objects[].subindex", 0xFF)? as u8,
                };
                ensure!(
                    !objects
                        .iter()
                        .any(|x| x.index == index && x.subindex == subindex),
                    "objects[{i}]: {index:#06x}:{subindex} is declared twice"
                );
                let ty = DataType::parse(
                    ob.get("type")
                        .and_then(Value::as_str)
                        .with_context(|| format!("objects[{i}] needs a type"))?,
                )?;
                let name = text(ob.get("name"), "objects[].name")?
                    .unwrap_or_else(|| format!("Object {index:#06x}:{subindex}"));
                objects.push(Object {
                    index,
                    subindex,
                    name,
                    ty,
                    access: Access::parse(ob.get("access").and_then(Value::as_str))?,
                });
            }
        }
        Ok(DeviceSpec {
            name,
            vendor_id: num("vendor_id", d.vendor_id)?,
            product_code: num("product_code", d.product_code)?,
            revision: num("revision", d.revision)?,
            serial: num("serial", d.serial)?,
            device_type: num("device_type", d.device_type)?,
            hardware_version: text(o.get("hardware_version"), "hardware_version")?,
            software_version: text(o.get("software_version"), "software_version")?,
            alias: num("alias", 0)?
                .try_into()
                .context("alias must be 0..=0xFFFF")?,
            inputs,
            outputs,
            objects,
        })
    }

    /// The JSON the model sees for this slave.
    pub fn describe(&self, position: usize, station: u16) -> Value {
        json!({
            "position": position,
            "station_address": station,
            "name": self.name,
            "vendor_id": self.vendor_id,
            "product_code": self.product_code,
            "inputs": self.inputs.describe(),
            "outputs": self.outputs.describe(),
        })
    }
}

/// The segment a `slaves` startup parameter describes, or one default slave.
pub fn segment_from_params(v: Option<&Value>) -> Result<Vec<DeviceSpec>> {
    match v {
        None | Some(Value::Null) => Ok(vec![default_device(0)]),
        Some(Value::Array(list)) => {
            ensure!(!list.is_empty(), "slaves must name at least one slave");
            ensure!(
                list.len() <= MAX_SLAVES,
                "slaves has {} entries, at most {MAX_SLAVES}",
                list.len()
            );
            list.iter()
                .enumerate()
                .map(|(i, s)| DeviceSpec::parse(s, i).with_context(|| format!("slaves[{i}]")))
                .collect()
        }
        Some(other) => bail!("slaves is a list of slave descriptions, got {other}"),
    }
}

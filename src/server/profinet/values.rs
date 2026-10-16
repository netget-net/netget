//! Typed IO values and the module/submodule layout both roles describe.
//!
//! A submodule's cyclic data is a run of octets; what they mean is the GSDML's business, and a
//! model cannot be expected to write bytes. So a layout names each submodule's fields — `u8`,
//! `i16`, `f32`, `bool`, … in order — and Rust encodes the model's `{"name": value}` objects to
//! big-endian octets (PROFINET's order) and decodes the peer's octets back to the same
//! objects. The octets never appear in an event or an action.
use super::blocks::{self, ExpectedSubmodule, MAX_C_SDU, MAX_SUBMODULES};
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Map, Value};

/// Fields in one direction of one submodule.
pub const MAX_FIELDS: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldType {
    Bool,
    U8,
    I8,
    U16,
    I16,
    U32,
    I32,
    F32,
}

impl FieldType {
    pub fn parse(s: &str) -> Result<Self> {
        Ok(match s {
            "bool" => FieldType::Bool,
            "u8" => FieldType::U8,
            "i8" => FieldType::I8,
            "u16" => FieldType::U16,
            "i16" => FieldType::I16,
            "u32" => FieldType::U32,
            "i32" => FieldType::I32,
            "f32" => FieldType::F32,
            other => {
                bail!("field type {other:?} is not one of bool, u8, i8, u16, i16, u32, i32, f32")
            }
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            FieldType::Bool => "bool",
            FieldType::U8 => "u8",
            FieldType::I8 => "i8",
            FieldType::U16 => "u16",
            FieldType::I16 => "i16",
            FieldType::U32 => "u32",
            FieldType::I32 => "i32",
            FieldType::F32 => "f32",
        }
    }

    pub fn size(self) -> usize {
        match self {
            FieldType::Bool | FieldType::U8 | FieldType::I8 => 1,
            FieldType::U16 | FieldType::I16 => 2,
            FieldType::U32 | FieldType::I32 | FieldType::F32 => 4,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Field {
    pub name: String,
    pub ty: FieldType,
}

pub fn fields_len(fields: &[Field]) -> usize {
    fields.iter().map(|f| f.ty.size()).sum()
}

/// Parse a field list: `[{"name": "temp", "type": "i16"}, …]`.
pub fn parse_fields(v: Option<&Value>, what: &str) -> Result<Vec<Field>> {
    let Some(v) = v.filter(|v| !v.is_null()) else {
        return Ok(Vec::new());
    };
    let arr = v
        .as_array()
        .with_context(|| format!("{what} must be an array of {{name, type}} objects"))?;
    ensure!(
        arr.len() <= MAX_FIELDS,
        "{what} has {} fields, at most {MAX_FIELDS}",
        arr.len()
    );
    let mut out: Vec<Field> = Vec::with_capacity(arr.len());
    for (i, f) in arr.iter().enumerate() {
        let name = f
            .get("name")
            .and_then(Value::as_str)
            .with_context(|| format!("{what}[{i}] needs a \"name\""))?;
        ensure!(
            !name.is_empty()
                && name.len() <= 64
                && name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-'),
            "{what}[{i}] name {name:?} must be 1-64 of letters, digits, '_' or '-'"
        );
        ensure!(
            !out.iter().any(|o| o.name == name),
            "{what} names {name:?} twice"
        );
        let ty = FieldType::parse(
            f.get("type")
                .and_then(Value::as_str)
                .with_context(|| format!("{what}[{i}] ({name}) needs a \"type\""))?,
        )?;
        out.push(Field {
            name: name.to_string(),
            ty,
        });
    }
    ensure!(
        fields_len(&out) <= MAX_C_SDU as usize,
        "{what} is {} octets, more than one frame carries",
        fields_len(&out)
    );
    Ok(out)
}

pub fn fields_json(fields: &[Field]) -> Value {
    Value::Array(
        fields
            .iter()
            .map(|f| json!({"name": f.name, "type": f.ty.name()}))
            .collect(),
    )
}

/// Write the named values into `buf` (whose length is the fields' total), leaving fields the
/// object does not name as they were. An unknown name, a wrong type or an out-of-range
/// number is an error naming the field — never a silent truncation.
pub fn encode_into(fields: &[Field], values: &Map<String, Value>, buf: &mut [u8]) -> Result<()> {
    ensure!(
        buf.len() == fields_len(fields),
        "buffer of {} octets for {} octets of fields",
        buf.len(),
        fields_len(fields)
    );
    for name in values.keys() {
        ensure!(
            fields.iter().any(|f| &f.name == name),
            "no field named {name:?} (fields: {})",
            fields
                .iter()
                .map(|f| f.name.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    let mut off = 0;
    for f in fields {
        let size = f.ty.size();
        if let Some(v) = values.get(&f.name) {
            let dst = &mut buf[off..off + size];
            encode_one(f, v, dst)?;
        }
        off += size;
    }
    Ok(())
}

fn int(f: &Field, v: &Value, min: i64, max: i64) -> Result<i64> {
    let n = v
        .as_i64()
        .or_else(|| v.as_u64().and_then(|u| i64::try_from(u).ok()))
        .or_else(|| v.as_bool().map(i64::from))
        .with_context(|| format!("{} ({}) must be an integer, got {v}", f.name, f.ty.name()))?;
    ensure!(
        (min..=max).contains(&n),
        "{} ({}) is {n}, outside {min}..={max}",
        f.name,
        f.ty.name()
    );
    Ok(n)
}

fn encode_one(f: &Field, v: &Value, dst: &mut [u8]) -> Result<()> {
    match f.ty {
        FieldType::Bool => {
            let b = match v {
                Value::Bool(b) => *b,
                Value::Number(_) => int(f, v, 0, 1)? == 1,
                _ => bail!("{} (bool) must be true or false, got {v}", f.name),
            };
            dst[0] = u8::from(b);
        }
        FieldType::U8 => dst[0] = int(f, v, 0, u8::MAX as i64)? as u8,
        FieldType::I8 => dst[0] = (int(f, v, i8::MIN as i64, i8::MAX as i64)? as i8) as u8,
        FieldType::U16 => {
            dst.copy_from_slice(&(int(f, v, 0, u16::MAX as i64)? as u16).to_be_bytes())
        }
        FieldType::I16 => dst
            .copy_from_slice(&(int(f, v, i16::MIN as i64, i16::MAX as i64)? as i16).to_be_bytes()),
        FieldType::U32 => {
            dst.copy_from_slice(&(int(f, v, 0, u32::MAX as i64)? as u32).to_be_bytes())
        }
        FieldType::I32 => dst
            .copy_from_slice(&(int(f, v, i32::MIN as i64, i32::MAX as i64)? as i32).to_be_bytes()),
        FieldType::F32 => {
            let x = v
                .as_f64()
                .with_context(|| format!("{} (f32) must be a number, got {v}", f.name))?;
            ensure!(
                x.is_finite() && x.abs() <= f32::MAX as f64,
                "{} (f32) is {x}, not a finite 32-bit float",
                f.name
            );
            dst.copy_from_slice(&(x as f32).to_be_bytes());
        }
    }
    Ok(())
}

/// Decode a submodule's octets to `{"name": value}`.
pub fn decode(fields: &[Field], data: &[u8]) -> Map<String, Value> {
    let mut out = Map::new();
    let mut off = 0;
    for f in fields {
        let size = f.ty.size();
        let Some(b) = data.get(off..off + size) else {
            break;
        };
        let v = match f.ty {
            FieldType::Bool => json!(b[0] != 0),
            FieldType::U8 => json!(b[0]),
            FieldType::I8 => json!(b[0] as i8),
            FieldType::U16 => json!(u16::from_be_bytes([b[0], b[1]])),
            FieldType::I16 => json!(i16::from_be_bytes([b[0], b[1]])),
            FieldType::U32 => json!(u32::from_be_bytes([b[0], b[1], b[2], b[3]])),
            FieldType::I32 => json!(i32::from_be_bytes([b[0], b[1], b[2], b[3]])),
            FieldType::F32 => {
                let x = f32::from_be_bytes([b[0], b[1], b[2], b[3]]);
                if x.is_finite() {
                    json!(x)
                } else {
                    // JSON has no NaN or infinity; say what it was.
                    json!(format!("{x}"))
                }
            }
        };
        out.insert(f.name.clone(), v);
        off += size;
    }
    out
}

/// Fields for `n` octets that nobody described: `byte0` … `byte{n-1}`, each `u8`.
pub fn anonymous_fields(n: usize) -> Vec<Field> {
    (0..n)
        .map(|i| Field {
            name: format!("byte{i}"),
            ty: FieldType::U8,
        })
        .collect()
}

/// One submodule: where it sits, what it is, and the fields of its cyclic data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubmoduleSpec {
    pub api: u32,
    pub slot: u16,
    pub subslot: u16,
    pub module_ident: u32,
    pub submodule_ident: u32,
    pub inputs: Vec<Field>,
    pub outputs: Vec<Field>,
}

impl SubmoduleSpec {
    pub fn input_len(&self) -> usize {
        fields_len(&self.inputs)
    }

    pub fn output_len(&self) -> usize {
        fields_len(&self.outputs)
    }

    pub fn kind(&self) -> u16 {
        match (self.input_len() > 0, self.output_len() > 0) {
            (false, false) => blocks::submodule_kind::NO_IO,
            (true, false) => blocks::submodule_kind::INPUT,
            (false, true) => blocks::submodule_kind::OUTPUT,
            (true, true) => blocks::submodule_kind::INPUT_OUTPUT,
        }
    }

    pub fn to_expected(&self) -> ExpectedSubmodule {
        ExpectedSubmodule {
            api: self.api,
            slot: self.slot,
            module_ident: self.module_ident,
            module_properties: 0,
            subslot: self.subslot,
            submodule_ident: self.submodule_ident,
            submodule_properties: self.kind(),
            input_length: self.input_len() as u16,
            output_length: self.output_len() as u16,
        }
    }

    pub fn to_json(&self) -> Value {
        json!({
            "slot": self.slot,
            "subslot": self.subslot,
            "module_ident": format!("{:#010x}", self.module_ident),
            "submodule_ident": format!("{:#010x}", self.submodule_ident),
            "inputs": fields_json(&self.inputs),
            "outputs": fields_json(&self.outputs),
        })
    }
}

/// An identifier given as a number or as a hex/decimal string ("0x32", "50").
pub fn ident(v: Option<&Value>, what: &str) -> Result<u32> {
    match v {
        Some(Value::Number(n)) => n
            .as_u64()
            .and_then(|n| u32::try_from(n).ok())
            .with_context(|| format!("{what} must be 0..=0xFFFFFFFF")),
        Some(Value::String(s)) => {
            let t = s.trim();
            let parsed = match t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
                Some(h) => u32::from_str_radix(h, 16),
                None => t.parse::<u32>(),
            };
            parsed.with_context(|| format!("{what} {s:?} is not a 32-bit number"))
        }
        _ => bail!("{what} is required (a number or a hex string such as \"0x32\")"),
    }
}

fn number_u16(v: Option<&Value>, what: &str) -> Result<u16> {
    v.and_then(Value::as_u64)
        .and_then(|n| u16::try_from(n).ok())
        .with_context(|| format!("{what} must be a number 0..=65535"))
}

/// Parse a layout: `[{"slot", "subslot", "module_ident", "submodule_ident", "inputs",
/// "outputs"}, …]`. Every submodule of one slot must name the same module.
pub fn parse_layout(v: &Value) -> Result<Vec<SubmoduleSpec>> {
    let arr = v
        .as_array()
        .context("the layout must be an array of submodule objects")?;
    ensure!(!arr.is_empty(), "the layout names no submodules");
    ensure!(
        arr.len() <= MAX_SUBMODULES,
        "the layout has {} submodules, at most {MAX_SUBMODULES}",
        arr.len()
    );
    let mut out: Vec<SubmoduleSpec> = Vec::new();
    for (i, s) in arr.iter().enumerate() {
        let slot = number_u16(s.get("slot"), &format!("submodule {i} slot"))?;
        let subslot = number_u16(s.get("subslot"), &format!("submodule {i} subslot"))?;
        ensure!(subslot != 0, "submodule {i}: subslot 0 is not a submodule");
        let module_ident = ident(
            s.get("module_ident"),
            &format!("submodule {i} module_ident"),
        )?;
        let submodule_ident = ident(
            s.get("submodule_ident"),
            &format!("submodule {i} submodule_ident"),
        )?;
        let spec = SubmoduleSpec {
            api: 0,
            slot,
            subslot,
            module_ident,
            submodule_ident,
            inputs: parse_fields(s.get("inputs"), &format!("slot {slot}/{subslot} inputs"))?,
            outputs: parse_fields(s.get("outputs"), &format!("slot {slot}/{subslot} outputs"))?,
        };
        if let Some(other) = out
            .iter()
            .find(|o| o.slot == slot && o.module_ident != module_ident)
        {
            bail!(
                "slot {slot} is module {:#x} in one entry and {:#x} in another",
                other.module_ident,
                module_ident
            );
        }
        ensure!(
            !out.iter().any(|o| o.slot == slot && o.subslot == subslot),
            "slot {slot} subslot {subslot} is listed twice"
        );
        out.push(spec);
    }
    Ok(out)
}

/// The layout a device has when the operator gives none: the access point (slot 0 — the
/// device itself, its interface and its port, none with cyclic data) and one digital
/// input/output module in slot 1 carrying an 8-bit input and an 8-bit output.
pub fn default_layout() -> Vec<SubmoduleSpec> {
    let dap = |subslot: u16, ident: u32| SubmoduleSpec {
        api: 0,
        slot: 0,
        subslot,
        module_ident: 0x0000_0001,
        submodule_ident: ident,
        inputs: Vec::new(),
        outputs: Vec::new(),
    };
    vec![
        dap(1, 0x0000_0001),
        dap(0x8000, 0x0000_8000),
        dap(0x8001, 0x0000_8001),
        SubmoduleSpec {
            api: 0,
            slot: 1,
            subslot: 1,
            module_ident: 0x0000_0032,
            submodule_ident: 0x0000_0132,
            inputs: vec![Field {
                name: "inputs".into(),
                ty: FieldType::U8,
            }],
            outputs: vec![Field {
                name: "outputs".into(),
                ty: FieldType::U8,
            }],
        },
    ]
}

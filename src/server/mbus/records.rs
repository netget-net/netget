//! M-Bus application layer (EN 13757-3): the variable data structure.
//!
//! A RSP_UD with CI 0x72 carries a 12-byte header — identification number (BCD), manufacturer,
//! version, medium, access number, status, signature — and then data records. Each record is a
//! DIB (DIF and up to ten DIFEs: data field coding, function, storage number, tariff, subunit),
//! a VIB (VIF and up to ten VIFEs: what is measured, in which unit, at which power of ten) and
//! the value in the coding the DIF names: 8- to 64-bit signed integers, 2- to 12-digit BCD,
//! 32-bit IEEE real, or a variable-length field.
//!
//! The model never sees these bytes. It writes a record as `{"quantity": "energy", "unit":
//! "kWh", "value": 12.345}` and [`encode_record`] picks the VIF whose power of ten carries the
//! value exactly; [`decode_records`] turns bytes back into the same shape, with the value in the
//! quantity's base unit and the mantissa and exponent beside it so nothing is lost to a float.
use super::frame::{self, MAX_USER_DATA};
use anyhow::{anyhow, bail, ensure, Context, Result};
use serde_json::{json, Map, Value};

/// The most DIFEs (and, separately, VIFEs) one record may chain, per EN 13757-3.
pub const MAX_EXTENSIONS: usize = 10;
/// The most data records one telegram may carry, in either direction. 252 bytes of user data
/// hold at most 84 one-byte-valued records, so this binds before the frame does.
pub const MAX_RECORDS_PER_TELEGRAM: usize = 64;
/// The most telegrams one readout spans (each but the last ends with DIF 0x1F, "more records
/// follow").
pub const MAX_TELEGRAMS: usize = 16;
/// The most records the model may give for one readout.
pub const MAX_RECORDS_PER_READOUT: usize = MAX_RECORDS_PER_TELEGRAM * 4;
/// Variable-length (LVAR) text is at most this many characters (EN 13757-3: 0x00-0xBF).
pub const MAX_LVAR_TEXT: usize = 0xBF;

/// The fixed header of a variable data response.
pub const HEADER_LEN: usize = 12;

/// DIF data field codes.
pub mod df {
    pub const NONE: u8 = 0x0;
    pub const INT8: u8 = 0x1;
    pub const INT16: u8 = 0x2;
    pub const INT24: u8 = 0x3;
    pub const INT32: u8 = 0x4;
    pub const REAL32: u8 = 0x5;
    pub const INT48: u8 = 0x6;
    pub const INT64: u8 = 0x7;
    pub const SELECTION: u8 = 0x8;
    pub const BCD2: u8 = 0x9;
    pub const BCD4: u8 = 0xA;
    pub const BCD6: u8 = 0xB;
    pub const BCD8: u8 = 0xC;
    pub const LVAR: u8 = 0xD;
    pub const BCD12: u8 = 0xE;
    pub const SPECIAL: u8 = 0xF;
}

/// DIF 0x0F: manufacturer-specific data follows to the end of the telegram.
pub const DIF_MANUFACTURER: u8 = 0x0F;
/// DIF 0x1F: as 0x0F, and more records follow in the next telegram.
pub const DIF_MORE_RECORDS: u8 = 0x1F;
/// DIF 0x2F: an idle filler byte.
pub const DIF_IDLE: u8 = 0x2F;
/// DIF 0x7F: global readout request (master to slave).
pub const DIF_GLOBAL_READOUT: u8 = 0x7F;

/// The fixed header of a CI 0x72 telegram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub address: frame::SecondaryAddress,
    pub access_number: u8,
    pub status: u8,
    pub signature: u16,
}

impl Header {
    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let a = self.address.bytes();
        let s = self.signature.to_le_bytes();
        [
            a[0],
            a[1],
            a[2],
            a[3],
            a[4],
            a[5],
            a[6],
            a[7],
            self.access_number,
            self.status,
            s[0],
            s[1],
        ]
    }

    pub fn decode(b: &[u8]) -> Result<Header> {
        ensure!(
            b.len() >= HEADER_LEN,
            "a variable data header is {HEADER_LEN} bytes, the telegram has {}",
            b.len()
        );
        Ok(Header {
            address: frame::SecondaryAddress::from_bytes(&b[..8])?,
            access_number: b[8],
            status: b[9],
            signature: u16::from_le_bytes([b[10], b[11]]),
        })
    }
}

/// The status byte's flags (EN 13757-3 table 9).
pub mod status {
    /// Bits 0-1: 00 no error, 01 application busy, 10 any application error, 11 abnormal.
    pub const APPLICATION_MASK: u8 = 0x03;
    pub const APPLICATION_BUSY: u8 = 0x01;
    pub const APPLICATION_ERROR: u8 = 0x02;
    pub const ABNORMAL: u8 = 0x03;
    pub const POWER_LOW: u8 = 0x04;
    pub const PERMANENT_ERROR: u8 = 0x08;
    pub const TEMPORARY_ERROR: u8 = 0x10;

    pub const FLAGS: &[(&str, u8)] = &[
        ("application_busy", APPLICATION_BUSY),
        ("application_error", APPLICATION_ERROR),
        ("abnormal_situation", ABNORMAL),
        ("power_low", POWER_LOW),
        ("permanent_error", PERMANENT_ERROR),
        ("temporary_error", TEMPORARY_ERROR),
    ];

    /// The flags a status byte sets, by name.
    pub fn names(s: u8) -> Vec<&'static str> {
        let mut out = Vec::new();
        match s & APPLICATION_MASK {
            APPLICATION_BUSY => out.push("application_busy"),
            APPLICATION_ERROR => out.push("application_error"),
            ABNORMAL => out.push("abnormal_situation"),
            _ => {}
        }
        for (name, bit) in &FLAGS[3..] {
            if s & bit != 0 {
                out.push(name);
            }
        }
        if s & 0xE0 != 0 {
            out.push("manufacturer_specific");
        }
        out
    }
}

/// The status byte from the model's flag names.
pub fn status_from_json(v: Option<&Value>) -> Result<u8> {
    let Some(v) = v.filter(|v| !v.is_null()) else {
        return Ok(0);
    };
    let list = v
        .as_array()
        .context("status is a list of flag names, e.g. [\"power_low\"]")?;
    let mut out = 0u8;
    for item in list {
        let name = item.as_str().context("status flags are strings")?;
        let bit = status::FLAGS
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, b)| *b)
            .with_context(|| {
                format!(
                    "status flag {name:?} is one of {}",
                    status::FLAGS
                        .iter()
                        .map(|(n, _)| *n)
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            })?;
        if bit & status::APPLICATION_MASK != 0 {
            ensure!(
                out & status::APPLICATION_MASK == 0,
                "give at most one of application_busy, application_error, abnormal_situation"
            );
        }
        out |= bit;
    }
    Ok(out)
}

/// A value-information family: one row of the VIF table that varies by a power of ten.
struct Family {
    quantity: &'static str,
    /// The unit the exponent is relative to.
    base_unit: &'static str,
    /// 0 for the primary table, or the extension prefix (0xFD, 0xFB).
    prefix: u8,
    code: u8,
    /// How many low bits carry the exponent.
    bits: u8,
    /// The exponent of code + 0.
    offset: i32,
    /// Accepted unit spellings and their power of ten relative to `base_unit`.
    units: &'static [(&'static str, i32)],
}

impl Family {
    fn min_exp(&self) -> i32 {
        self.offset
    }
    fn max_exp(&self) -> i32 {
        self.offset + (1 << self.bits) - 1
    }
}

const WH: &[(&str, i32)] = &[("Wh", 0), ("kWh", 3), ("MWh", 6), ("GWh", 9)];
const J: &[(&str, i32)] = &[("J", 0), ("kJ", 3), ("MJ", 6), ("GJ", 9)];
const M3: &[(&str, i32)] = &[
    ("m3", 0),
    ("m^3", 0),
    ("m³", 0),
    ("l", -3),
    ("L", -3),
    ("litre", -3),
    ("liter", -3),
    ("dm3", -3),
];
const KG: &[(&str, i32)] = &[("kg", 0), ("g", -3), ("t", 3)];
const W: &[(&str, i32)] = &[("W", 0), ("kW", 3), ("MW", 6)];
const JH: &[(&str, i32)] = &[("J/h", 0), ("kJ/h", 3), ("MJ/h", 6), ("GJ/h", 9)];
const M3H: &[(&str, i32)] = &[("m3/h", 0), ("m^3/h", 0), ("m³/h", 0), ("l/h", -3)];
const M3MIN: &[(&str, i32)] = &[("m3/min", 0), ("m^3/min", 0), ("m³/min", 0), ("l/min", -3)];
const M3S: &[(&str, i32)] = &[("m3/s", 0), ("m^3/s", 0), ("m³/s", 0), ("l/s", -3)];
const KGH: &[(&str, i32)] = &[("kg/h", 0), ("g/h", -3), ("t/h", 3)];
const DEGC: &[(&str, i32)] = &[("°C", 0), ("C", 0), ("degC", 0), ("celsius", 0)];
const KELVIN: &[(&str, i32)] = &[("K", 0), ("mK", -3)];
const BAR: &[(&str, i32)] = &[("bar", 0), ("mbar", -3)];
const VOLT: &[(&str, i32)] = &[("V", 0), ("mV", -3), ("kV", 3)];
const AMP: &[(&str, i32)] = &[("A", 0), ("mA", -3)];

const FAMILIES: &[Family] = &[
    Family {
        quantity: "energy",
        base_unit: "Wh",
        prefix: 0,
        code: 0x00,
        bits: 3,
        offset: -3,
        units: WH,
    },
    Family {
        quantity: "energy",
        base_unit: "J",
        prefix: 0,
        code: 0x08,
        bits: 3,
        offset: 0,
        units: J,
    },
    Family {
        quantity: "volume",
        base_unit: "m3",
        prefix: 0,
        code: 0x10,
        bits: 3,
        offset: -6,
        units: M3,
    },
    Family {
        quantity: "mass",
        base_unit: "kg",
        prefix: 0,
        code: 0x18,
        bits: 3,
        offset: -3,
        units: KG,
    },
    Family {
        quantity: "power",
        base_unit: "W",
        prefix: 0,
        code: 0x28,
        bits: 3,
        offset: -3,
        units: W,
    },
    Family {
        quantity: "power",
        base_unit: "J/h",
        prefix: 0,
        code: 0x30,
        bits: 3,
        offset: 0,
        units: JH,
    },
    Family {
        quantity: "volume_flow",
        base_unit: "m3/h",
        prefix: 0,
        code: 0x38,
        bits: 3,
        offset: -6,
        units: M3H,
    },
    Family {
        quantity: "volume_flow",
        base_unit: "m3/min",
        prefix: 0,
        code: 0x40,
        bits: 3,
        offset: -7,
        units: M3MIN,
    },
    Family {
        quantity: "volume_flow",
        base_unit: "m3/s",
        prefix: 0,
        code: 0x48,
        bits: 3,
        offset: -9,
        units: M3S,
    },
    Family {
        quantity: "mass_flow",
        base_unit: "kg/h",
        prefix: 0,
        code: 0x50,
        bits: 3,
        offset: -3,
        units: KGH,
    },
    Family {
        quantity: "flow_temperature",
        base_unit: "°C",
        prefix: 0,
        code: 0x58,
        bits: 2,
        offset: -3,
        units: DEGC,
    },
    Family {
        quantity: "return_temperature",
        base_unit: "°C",
        prefix: 0,
        code: 0x5C,
        bits: 2,
        offset: -3,
        units: DEGC,
    },
    Family {
        quantity: "temperature_difference",
        base_unit: "K",
        prefix: 0,
        code: 0x60,
        bits: 2,
        offset: -3,
        units: KELVIN,
    },
    Family {
        quantity: "external_temperature",
        base_unit: "°C",
        prefix: 0,
        code: 0x64,
        bits: 2,
        offset: -3,
        units: DEGC,
    },
    Family {
        quantity: "pressure",
        base_unit: "bar",
        prefix: 0,
        code: 0x68,
        bits: 2,
        offset: -3,
        units: BAR,
    },
    Family {
        quantity: "voltage",
        base_unit: "V",
        prefix: 0xFD,
        code: 0x40,
        bits: 4,
        offset: -9,
        units: VOLT,
    },
    Family {
        quantity: "current",
        base_unit: "A",
        prefix: 0xFD,
        code: 0x50,
        bits: 4,
        offset: -12,
        units: AMP,
    },
];

/// Durations: the low two bits name the unit rather than a power of ten.
const DURATIONS: &[(&str, u8)] = &[
    ("on_time", 0x20),
    ("operating_time", 0x24),
    ("averaging_duration", 0x70),
    ("actuality_duration", 0x74),
];
const DURATION_UNITS: &[&str] = &["s", "min", "h", "d"];

/// Dimensionless primary VIFs.
const PLAIN: &[(&str, u8)] = &[
    ("hca_units", 0x6E),
    ("fabrication_number", 0x78),
    ("enhanced_identification", 0x79),
    ("bus_address", 0x7A),
];

const VIF_DATE: u8 = 0x6C;
const VIF_DATETIME: u8 = 0x6D;

/// Every quantity the model may name.
pub fn quantity_names() -> String {
    let mut names: Vec<&str> = FAMILIES.iter().map(|f| f.quantity).collect();
    names.dedup();
    names.extend(DURATIONS.iter().map(|(n, _)| *n));
    names.extend(PLAIN.iter().map(|(n, _)| *n));
    names.extend(["date", "datetime"]);
    names.join(", ")
}

/// A decimal number read exactly from its JSON text: `mantissa * 10^exp`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decimal {
    pub mantissa: i128,
    pub exp: i32,
}

impl Decimal {
    /// Parse a JSON number's text (`12.345`, `-4`, `1.5e3`) without passing through a float.
    pub fn parse(text: &str) -> Result<Decimal> {
        let t = text.trim();
        let (num, e) = match t.find(['e', 'E']) {
            Some(i) => (&t[..i], t[i + 1..].parse::<i32>()?),
            None => (t, 0),
        };
        let neg = num.starts_with('-');
        let num = num.trim_start_matches(['-', '+']);
        let (int, frac) = num.split_once('.').unwrap_or((num, ""));
        ensure!(
            !(int.is_empty() && frac.is_empty())
                && int.chars().chain(frac.chars()).all(|c| c.is_ascii_digit()),
            "{text:?} is not a number"
        );
        let digits = format!("{int}{frac}");
        let digits = digits.trim_start_matches('0');
        ensure!(digits.len() <= 30, "{text:?} has too many digits");
        let mut m: i128 = if digits.is_empty() {
            0
        } else {
            digits.parse()?
        };
        if neg {
            m = -m;
        }
        ensure!(e.abs() <= 60, "{text:?} is out of range");
        Ok(Decimal {
            mantissa: m,
            exp: e - frac.len() as i32,
        }
        .normalized())
    }

    fn normalized(mut self) -> Self {
        if self.mantissa == 0 {
            self.exp = 0;
            return self;
        }
        while self.mantissa % 10 == 0 {
            self.mantissa /= 10;
            self.exp += 1;
        }
        self
    }

    /// The mantissa at exponent `x`, when the value is a whole multiple of 10^x.
    fn at(&self, x: i32) -> Option<i128> {
        if self.mantissa == 0 {
            return Some(0);
        }
        if self.exp < x {
            return None;
        }
        let shift = (self.exp - x) as u32;
        if shift > 38 {
            return None;
        }
        self.mantissa.checked_mul(10i128.checked_pow(shift)?)
    }

    pub fn to_f64(self) -> f64 {
        format!("{}e{}", self.mantissa, self.exp)
            .parse()
            .unwrap_or(f64::NAN)
    }
}

/// `mantissa * 10^exp` as a JSON number, printed through its decimal text so 12345 * 10^-3 is
/// 12.345 and not the nearest binary fraction's longest form.
pub fn number(mantissa: i128, exp: i32) -> Value {
    if exp >= 0 && exp <= 18 {
        if let Some(v) = mantissa
            .checked_mul(10i128.pow(exp as u32))
            .and_then(|v| i64::try_from(v).ok())
        {
            return json!(v);
        }
    }
    let f: f64 = format!("{mantissa}e{exp}").parse().unwrap_or(f64::NAN);
    json!(f)
}

/// How the value is coded on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Coding {
    Int(usize),
    Bcd(usize),
    Real32,
}

impl Coding {
    pub fn df(self) -> u8 {
        match self {
            Coding::Int(1) => df::INT8,
            Coding::Int(2) => df::INT16,
            Coding::Int(3) => df::INT24,
            Coding::Int(4) => df::INT32,
            Coding::Int(6) => df::INT48,
            Coding::Int(_) => df::INT64,
            Coding::Bcd(1) => df::BCD2,
            Coding::Bcd(2) => df::BCD4,
            Coding::Bcd(3) => df::BCD6,
            Coding::Bcd(4) => df::BCD8,
            Coding::Bcd(_) => df::BCD12,
            Coding::Real32 => df::REAL32,
        }
    }

    pub fn name(self) -> String {
        match self {
            Coding::Int(n) => format!("int{}", n * 8),
            Coding::Bcd(n) => format!("bcd{}", n * 2),
            Coding::Real32 => "real32".into(),
        }
    }

    fn fits(self, v: i128) -> bool {
        match self {
            Coding::Int(n) => {
                let bits = n as u32 * 8;
                let lo = -(1i128 << (bits - 1));
                let hi = (1i128 << (bits - 1)) - 1;
                (lo..=hi).contains(&v)
            }
            Coding::Bcd(n) => {
                let digits = n as u32 * 2;
                // A negative BCD value gives its top digit to the sign nibble F.
                if v < 0 {
                    -v < 10i128.pow(digits - 1)
                } else {
                    v < 10i128.pow(digits)
                }
            }
            Coding::Real32 => true,
        }
    }

    const INTS: [Coding; 6] = [
        Coding::Int(1),
        Coding::Int(2),
        Coding::Int(3),
        Coding::Int(4),
        Coding::Int(6),
        Coding::Int(8),
    ];
    const BCDS: [Coding; 5] = [
        Coding::Bcd(1),
        Coding::Bcd(2),
        Coding::Bcd(3),
        Coding::Bcd(4),
        Coding::Bcd(6),
    ];

    fn parse(name: &str) -> Result<Option<Coding>> {
        Ok(Some(match name {
            "int" | "bcd" | "auto" => return Ok(None),
            "int8" => Coding::Int(1),
            "int16" => Coding::Int(2),
            "int24" => Coding::Int(3),
            "int32" => Coding::Int(4),
            "int48" => Coding::Int(6),
            "int64" => Coding::Int(8),
            "bcd2" => Coding::Bcd(1),
            "bcd4" => Coding::Bcd(2),
            "bcd6" => Coding::Bcd(3),
            "bcd8" => Coding::Bcd(4),
            "bcd12" => Coding::Bcd(6),
            "real" | "real32" => Coding::Real32,
            other => bail!(
                "encoding {other:?} is int (the smallest that fits), bcd, real, or one of \
                 int8/16/24/32/48/64, bcd2/4/6/8/12, real32"
            ),
        }))
    }

    fn encode(self, v: i128, real: f64) -> Result<Vec<u8>> {
        ensure!(
            self.fits(v),
            "{v} does not fit {} (pick a wider encoding)",
            self.name()
        );
        Ok(match self {
            Coding::Int(n) => (v as i64).to_le_bytes()[..n].to_vec(),
            Coding::Bcd(n) => {
                let mut out = vec![0u8; n];
                let mut a = v.unsigned_abs();
                for (i, byte) in out.iter_mut().enumerate() {
                    let lo = (a % 10) as u8;
                    a /= 10;
                    let hi = (a % 10) as u8;
                    a /= 10;
                    *byte = (hi << 4) | lo;
                    if v < 0 && i == n - 1 {
                        *byte = 0xF0 | lo;
                    }
                }
                out
            }
            Coding::Real32 => (real as f32).to_le_bytes().to_vec(),
        })
    }
}

/// DIF function field.
const FUNCTIONS: &[(&str, u8)] = &[
    ("instantaneous", 0),
    ("maximum", 1),
    ("minimum", 2),
    ("error", 3),
];

fn opt_u64(v: &Value, key: &str, max: u64) -> Result<u64> {
    match v.get(key) {
        None | Some(Value::Null) => Ok(0),
        Some(x) => {
            let n = x
                .as_u64()
                .with_context(|| format!("{key} is a whole number, not {x}"))?;
            ensure!(n <= max, "{key} is {n}, above {max}");
            Ok(n)
        }
    }
}

/// The DIB for a record: DIF and the DIFEs that storage number, tariff and subunit need.
fn encode_dib(data_field: u8, v: &Value) -> Result<Vec<u8>> {
    let function = match v.get("function").and_then(Value::as_str) {
        None => 0,
        Some(f) => FUNCTIONS
            .iter()
            .find(|(n, _)| *n == f)
            .map(|(_, c)| *c)
            .with_context(|| {
                format!("function {f:?} is instantaneous, maximum, minimum or error")
            })?,
    };
    // One storage bit in the DIF, four per DIFE; two tariff bits and one subunit bit per DIFE.
    let storage = opt_u64(v, "storage", (1u64 << (1 + 4 * MAX_EXTENSIONS)) - 1)?;
    let tariff = opt_u64(v, "tariff", (1u64 << (2 * MAX_EXTENSIONS)) - 1)?;
    let subunit = opt_u64(v, "subunit", (1u64 << MAX_EXTENSIONS) - 1)?;
    let mut dif = data_field | (function << 4) | (((storage & 1) as u8) << 6);
    let mut rest_storage = storage >> 1;
    let mut rest_tariff = tariff;
    let mut rest_subunit = subunit;
    let mut difes = Vec::new();
    while rest_storage != 0 || rest_tariff != 0 || rest_subunit != 0 {
        ensure!(
            difes.len() < MAX_EXTENSIONS,
            "storage, tariff and subunit need more than {MAX_EXTENSIONS} DIFEs"
        );
        difes.push(
            (rest_storage & 0x0F) as u8
                | (((rest_tariff & 0x03) as u8) << 4)
                | (((rest_subunit & 1) as u8) << 6),
        );
        rest_storage >>= 4;
        rest_tariff >>= 2;
        rest_subunit >>= 1;
    }
    let mut out = Vec::with_capacity(1 + difes.len());
    if !difes.is_empty() {
        dif |= 0x80;
    }
    out.push(dif);
    let n = difes.len();
    for (i, d) in difes.into_iter().enumerate() {
        out.push(if i + 1 < n { d | 0x80 } else { d });
    }
    Ok(out)
}

fn decimal_value(v: &Value) -> Result<Decimal> {
    match v.get("value") {
        Some(Value::Number(n)) => Decimal::parse(&n.to_string()),
        Some(Value::String(s)) => Decimal::parse(s).with_context(|| {
            format!("value {s:?} is a number (a string is accepted only if it is one)")
        }),
        Some(other) => bail!("value is a number, not {other}"),
        None => bail!("a record needs a \"value\""),
    }
}

fn choose_coding(
    v: &Value,
    mantissa: i128,
    real: f64,
    default_bcd: bool,
) -> Result<(Coding, Vec<u8>)> {
    let named = v.get("encoding").and_then(Value::as_str).unwrap_or("auto");
    let coding = match Coding::parse(named)? {
        Some(c) => c,
        None => {
            let bcd = named == "bcd" || (named == "auto" && default_bcd);
            let list: &[Coding] = if bcd { &Coding::BCDS } else { &Coding::INTS };
            *list.iter().find(|c| c.fits(mantissa)).with_context(|| {
                format!(
                    "{mantissa} is too large for any {} coding",
                    if bcd { "BCD" } else { "integer" }
                )
            })?
        }
    };
    let bytes = coding.encode(mantissa, real)?;
    Ok((coding, bytes))
}

/// One data record from the model's description, as bytes (DIB, VIB, value).
///
/// The model names a quantity, a unit and a value; this picks the VIF whose power of ten
/// carries the value exactly — the coarsest one at which it is still a whole number, so 12000
/// Wh travels as 12 at 10^3 Wh — or the one `resolution` names (a power of ten in the given
/// unit, the meter's own step: `0.01` for a meter counting hundredths of m³). A value finer
/// than the finest step the VIF table has is refused rather than rounded.
pub fn encode_record(v: &Value) -> Result<Vec<u8>> {
    ensure!(
        v.is_object(),
        "a record is an object such as {{\"quantity\":\"energy\",\"unit\":\"Wh\",\"value\":12345}}"
    );
    let quantity = v
        .get("quantity")
        .and_then(Value::as_str)
        .context("a record needs a \"quantity\"")?;
    let unit = v.get("unit").and_then(Value::as_str).unwrap_or("");

    // Durations: the unit is part of the VIF and the value is a count of it.
    if let Some((_, code)) = DURATIONS.iter().find(|(n, _)| *n == quantity) {
        let nn = DURATION_UNITS
            .iter()
            .position(|u| *u == unit)
            .with_context(|| format!("{quantity} takes unit s, min, h or d, not {unit:?}"))?;
        let d = decimal_value(v)?;
        let m = d
            .at(0)
            .with_context(|| format!("{quantity} is a whole number of {unit}"))?;
        let (coding, bytes) = choose_coding(v, m, m as f64, false)?;
        let mut out = encode_dib(coding.df(), v)?;
        out.push(code | nn as u8);
        out.extend(bytes);
        return Ok(out);
    }
    if let Some((_, code)) = PLAIN.iter().find(|(n, _)| *n == quantity) {
        let d = decimal_value(v)?;
        let m = d
            .at(0)
            .with_context(|| format!("{quantity} is a whole number"))?;
        let (coding, bytes) = choose_coding(v, m, m as f64, quantity == "fabrication_number")?;
        let mut out = encode_dib(coding.df(), v)?;
        out.push(*code);
        out.extend(bytes);
        return Ok(out);
    }
    if quantity == "date" || quantity == "datetime" {
        let text = v
            .get("value")
            .and_then(Value::as_str)
            .context("a date is a string: \"2026-10-16\" or \"2026-10-16T12:30\"")?;
        let (vif, bytes) = encode_date(quantity == "datetime", text)?;
        let mut out = encode_dib(
            if vif == VIF_DATE {
                df::INT16
            } else {
                df::INT32
            },
            v,
        )?;
        out.push(vif);
        out.extend(bytes);
        return Ok(out);
    }

    let candidates: Vec<&Family> = FAMILIES.iter().filter(|f| f.quantity == quantity).collect();
    ensure!(
        !candidates.is_empty(),
        "quantity {quantity:?} is one of {}",
        quantity_names()
    );
    let (family, scale) = candidates
        .iter()
        .find_map(|f| {
            f.units
                .iter()
                .find(|(u, _)| *u == unit)
                .map(|(_, s)| (*f, *s))
        })
        .with_context(|| {
            format!(
                "{quantity} takes unit {}, not {unit:?}",
                candidates
                    .iter()
                    .flat_map(|f| f.units.iter().map(|(u, _)| *u))
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        })?;
    let d = decimal_value(v)?;
    // The value in the family's base unit: mantissa * 10^(exp + scale).
    let base = Decimal {
        mantissa: d.mantissa,
        exp: d.exp + scale,
    };
    let real = matches!(
        v.get("encoding").and_then(Value::as_str),
        Some("real") | Some("real32")
    );
    let x = if real {
        scale.clamp(family.min_exp(), family.max_exp())
    } else if let Some(r) = v.get("resolution").filter(|r| !r.is_null()) {
        let r = Decimal::parse(&r.to_string())?;
        ensure!(
            r.mantissa == 1,
            "resolution is a power of ten in the given unit (1, 0.1, 0.01, 1000 ...)"
        );
        let x = r.exp + scale;
        ensure!(
            (family.min_exp()..=family.max_exp()).contains(&x),
            "a resolution of 10^{} {unit} is outside what M-Bus can express for {quantity} \
             (10^{} to 10^{} {})",
            r.exp,
            family.min_exp(),
            family.max_exp(),
            family.base_unit
        );
        x
    } else if base.mantissa == 0 {
        family.min_exp().max(scale.min(family.max_exp()))
    } else if base.exp < family.min_exp() {
        bail!(
            "{} {unit} is finer than the smallest step M-Bus has for {quantity} (10^{} {})",
            v["value"],
            family.min_exp(),
            family.base_unit
        )
    } else {
        base.exp.min(family.max_exp())
    };
    let (coding, bytes) = if real {
        let f = Decimal {
            mantissa: base.mantissa,
            exp: base.exp - x,
        }
        .to_f64();
        (Coding::Real32, Coding::Real32.encode(0, f)?)
    } else {
        let m = base.at(x).with_context(|| {
            format!(
                "{} {unit} is not a whole number of the resolution's steps",
                v["value"]
            )
        })?;
        choose_coding(v, m, m as f64, false)?
    };
    let mut out = encode_dib(coding.df(), v)?;
    if family.prefix != 0 {
        out.push(family.prefix);
    }
    out.push(family.code | (x - family.offset) as u8);
    out.extend(bytes);
    Ok(out)
}

fn encode_date(with_time: bool, text: &str) -> Result<(u8, Vec<u8>)> {
    let bad = || {
        anyhow!(
            "date {text:?} is \"YYYY-MM-DD\" (date) or \"YYYY-MM-DDTHH:MM\" (datetime), year \
             2000-2099"
        )
    };
    let (date, time) = match text.split_once(['T', ' ']) {
        Some((d, t)) => (d, Some(t)),
        None => (text, None),
    };
    let mut parts = date.split('-');
    let year: u32 = parts.next().and_then(|s| s.parse().ok()).ok_or_else(bad)?;
    let month: u32 = parts.next().and_then(|s| s.parse().ok()).ok_or_else(bad)?;
    let day: u32 = parts.next().and_then(|s| s.parse().ok()).ok_or_else(bad)?;
    ensure!(
        (2000..=2099).contains(&year) && (1..=12).contains(&month) && (1..=31).contains(&day),
        bad()
    );
    let y = year - 2000;
    let b_day = (day as u8) | (((y & 0x07) as u8) << 5);
    let b_month = (month as u8) | (((y >> 3) as u8 & 0x0F) << 4);
    if !with_time {
        ensure!(
            time.is_none(),
            "quantity date carries no time; use datetime"
        );
        return Ok((VIF_DATE, vec![b_day, b_month]));
    }
    let time = time.ok_or_else(bad)?;
    let mut t = time.split(':');
    let hour: u8 = t.next().and_then(|s| s.parse().ok()).ok_or_else(bad)?;
    let minute: u8 = t.next().and_then(|s| s.parse().ok()).ok_or_else(bad)?;
    ensure!(hour < 24 && minute < 60, bad());
    Ok((VIF_DATETIME, vec![minute, hour, b_day, b_month]))
}

fn decode_date(b: &[u8]) -> Option<String> {
    let (day_b, month_b) = match b.len() {
        2 => (b[0], b[1]),
        4 => (b[2], b[3]),
        // Type I (EN 13757-3:2013): seconds, minutes, hours, then day and month as type F.
        6 => (b[3], b[4]),
        _ => return None,
    };
    let day = day_b & 0x1F;
    let month = month_b & 0x0F;
    let year = 2000 + (((day_b & 0xE0) >> 5) | ((month_b & 0xF0) >> 1)) as u32;
    let date = format!("{year:04}-{month:02}-{day:02}");
    if b.len() == 2 {
        return Some(date);
    }
    if b.len() == 6 {
        return Some(format!(
            "{date}T{:02}:{:02}:{:02}",
            b[2] & 0x1F,
            b[1] & 0x3F,
            b[0] & 0x3F
        ));
    }
    if b[0] & 0x80 != 0 {
        return Some(format!("{date} (marked invalid)"));
    }
    Some(format!("{date}T{:02}:{:02}", b[1] & 0x1F, b[0] & 0x3F))
}

/// The user data of the telegrams one readout takes: each is CI 0x72's header (with the access
/// number counting up from `first_access`) and as many whole records as fit, every telegram but
/// the last closed with DIF 0x1F.
pub fn pack_telegrams(
    address: frame::SecondaryAddress,
    first_access: u8,
    status: u8,
    records: &[Vec<u8>],
) -> Result<Vec<Vec<u8>>> {
    // Every telegram: header, records, and (all but the last) the 0x1F byte.
    let room = MAX_USER_DATA - HEADER_LEN;
    let mut telegrams: Vec<Vec<Vec<u8>>> = vec![Vec::new()];
    let mut used = 0usize;
    for r in records {
        ensure!(
            r.len() < room,
            "a record of {} bytes does not fit a telegram",
            r.len()
        );
        let current = telegrams.last().map(|t| t.len()).unwrap_or(0);
        // Leave one byte for the 0x1F that ends a telegram with more to follow.
        if used + r.len() + 1 > room || current >= MAX_RECORDS_PER_TELEGRAM {
            telegrams.push(Vec::new());
            used = 0;
        }
        used += r.len();
        if let Some(t) = telegrams.last_mut() {
            t.push(r.clone());
        }
    }
    ensure!(
        telegrams.len() <= MAX_TELEGRAMS,
        "the records need {} telegrams; at most {MAX_TELEGRAMS} make one readout",
        telegrams.len()
    );
    let n = telegrams.len();
    Ok(telegrams
        .into_iter()
        .enumerate()
        .map(|(i, recs)| {
            let mut out = Header {
                address,
                access_number: first_access.wrapping_add(i as u8),
                status,
                signature: 0,
            }
            .encode()
            .to_vec();
            for r in recs {
                out.extend(r);
            }
            if i + 1 < n {
                out.push(DIF_MORE_RECORDS);
            }
            out
        })
        .collect())
}

/// What a telegram's data records decode to.
#[derive(Debug, Clone, Default)]
pub struct Decoded {
    pub records: Vec<Value>,
    /// The telegram ended with DIF 0x1F.
    pub more_records_follow: bool,
    /// Bytes of manufacturer-specific data after DIF 0x0F/0x1F (reported by count only).
    pub manufacturer_specific_bytes: usize,
    /// DIF 0x7F: the master asked for a global readout.
    pub global_readout: bool,
}

fn function_name(f: u8) -> &'static str {
    FUNCTIONS
        .iter()
        .find(|(_, c)| *c == f)
        .map(|(n, _)| *n)
        .unwrap_or("instantaneous")
}

/// The value-information of a VIF (with its extension prefix, if any): quantity, base unit and
/// exponent.
struct Vi {
    quantity: String,
    unit: String,
    exponent: i32,
    date: bool,
}

fn describe_vif(prefix: u8, code: u8) -> Vi {
    let vi = |q: &str, u: &str, e: i32| Vi {
        quantity: q.into(),
        unit: u.into(),
        exponent: e,
        date: false,
    };
    for f in FAMILIES.iter().filter(|f| f.prefix == prefix) {
        let mask = !((1u8 << f.bits) - 1);
        if code & mask == f.code {
            return vi(f.quantity, f.base_unit, f.offset + (code & !mask) as i32);
        }
    }
    if prefix == 0 {
        for (name, base) in DURATIONS {
            if code & 0xFC == *base {
                return vi(name, DURATION_UNITS[(code & 0x03) as usize], 0);
            }
        }
        for (name, c) in PLAIN {
            if code == *c {
                return vi(name, "", 0);
            }
        }
        if code == VIF_DATE || code == VIF_DATETIME {
            return Vi {
                quantity: if code == VIF_DATE { "date" } else { "datetime" }.into(),
                unit: String::new(),
                exponent: 0,
                date: true,
            };
        }
        if code == 0x7E {
            return vi("any", "", 0);
        }
    }
    if prefix == 0xFB {
        match code {
            0x00 | 0x01 => return vi("energy", "Wh", 5 + code as i32),
            0x08 | 0x09 => return vi("energy", "J", 8 + (code & 1) as i32),
            0x10 | 0x11 => return vi("volume", "m3", 2 + (code & 1) as i32),
            0x18 | 0x19 => return vi("mass", "kg", 5 + (code & 1) as i32),
            0x28 | 0x29 => return vi("power", "W", 5 + (code & 1) as i32),
            0x30 | 0x31 => return vi("power", "J/h", 8 + (code & 1) as i32),
            _ => {}
        }
    }
    if prefix == 0xFD {
        let named = match code {
            0x08 => Some("access_number"),
            0x09 => Some("medium"),
            0x0A => Some("manufacturer"),
            0x0B => Some("parameter_set_id"),
            0x0C => Some("model_version"),
            0x0D => Some("hardware_version"),
            0x0E => Some("firmware_version"),
            0x0F => Some("software_version"),
            0x10 => Some("customer_location"),
            0x11 => Some("customer"),
            0x16 => Some("password"),
            0x17 => Some("error_flags"),
            0x1A => Some("digital_output"),
            0x1B => Some("digital_input"),
            0x1C => Some("baud_rate"),
            0x60 => Some("reset_counter"),
            0x61 => Some("cumulation_counter"),
            _ => None,
        };
        if let Some(n) = named {
            return vi(n, "", 0);
        }
    }
    vi("unknown", "", 0)
}

fn take<'a>(data: &'a [u8], at: &mut usize, n: usize, what: &str) -> Result<&'a [u8]> {
    let end = at
        .checked_add(n)
        .filter(|e| *e <= data.len())
        .with_context(|| {
            format!(
                "{what} needs {n} bytes at offset {}, only {} remain",
                *at,
                data.len().saturating_sub(*at)
            )
        })?;
    let s = &data[*at..end];
    *at = end;
    Ok(s)
}

fn bcd_value(b: &[u8]) -> Result<i128> {
    let mut v: i128 = 0;
    let negative = b.last().is_some_and(|last| last >> 4 == 0xF);
    for (i, byte) in b.iter().enumerate().rev() {
        let hi = byte >> 4;
        let lo = byte & 0x0F;
        let hi = if i == b.len() - 1 && negative { 0 } else { hi };
        ensure!(
            hi <= 9 && lo <= 9,
            "BCD byte {byte:#04x} holds a digit above 9"
        );
        v = v * 100 + (hi as i128) * 10 + lo as i128;
    }
    Ok(if negative { -v } else { v })
}

/// A BCD field's nibbles as the meter stores them, most significant first.
fn id_digits(b: &[u8]) -> String {
    b.iter().rev().map(|x| format!("{x:02X}")).collect()
}

fn int_value(b: &[u8]) -> i128 {
    let mut buf = [0u8; 8];
    buf[..b.len()].copy_from_slice(b);
    let unsigned = u64::from_le_bytes(buf);
    let bits = b.len() as u32 * 8;
    if bits == 64 {
        return unsigned as i64 as i128;
    }
    let sign = 1u64 << (bits - 1);
    if unsigned & sign != 0 {
        unsigned as i128 - (1i128 << bits)
    } else {
        unsigned as i128
    }
}

/// Decode the data records of a telegram (the bytes after the 12-byte header).
pub fn decode_records(data: &[u8]) -> Result<Decoded> {
    let mut out = Decoded::default();
    let mut at = 0usize;
    while at < data.len() {
        let dif = data[at];
        at += 1;
        if dif == DIF_IDLE {
            continue;
        }
        if dif == DIF_MANUFACTURER || dif == DIF_MORE_RECORDS {
            out.more_records_follow = dif == DIF_MORE_RECORDS;
            out.manufacturer_specific_bytes = data.len() - at;
            break;
        }
        if dif == DIF_GLOBAL_READOUT {
            out.global_readout = true;
            continue;
        }
        ensure!(
            out.records.len() < MAX_RECORDS_PER_TELEGRAM,
            "more than {MAX_RECORDS_PER_TELEGRAM} records in one telegram"
        );
        let data_field = dif & 0x0F;
        let function = (dif >> 4) & 0x03;
        let mut storage: u64 = ((dif >> 6) & 1) as u64;
        let mut tariff: u64 = 0;
        let mut subunit: u64 = 0;
        let mut ext = dif & 0x80 != 0;
        let mut n = 0usize;
        while ext {
            ensure!(
                n < MAX_EXTENSIONS,
                "a record chains more than {MAX_EXTENSIONS} DIFEs"
            );
            let dife = take(data, &mut at, 1, "a DIFE")?[0];
            storage |= ((dife & 0x0F) as u64) << (1 + 4 * n);
            tariff |= (((dife >> 4) & 0x03) as u64) << (2 * n);
            subunit |= (((dife >> 6) & 1) as u64) << n;
            ext = dife & 0x80 != 0;
            n += 1;
        }
        let mut vif = take(data, &mut at, 1, "a VIF")?[0];
        let mut prefix = 0u8;
        let mut plain_unit: Option<String> = None;
        let mut vifes: Vec<String> = Vec::new();
        let mut manufacturer_vif = false;
        if vif == 0xFB || vif == 0xFD {
            prefix = vif;
            vif = take(data, &mut at, 1, "an extended VIF")?[0];
        } else if vif & 0x7F == 0x7C {
            // Plain-text unit: a length byte and the characters, last first.
            let len = take(data, &mut at, 1, "a plain-text VIF length")?[0] as usize;
            let chars = take(data, &mut at, len, "plain-text VIF characters")?;
            plain_unit = Some(chars.iter().rev().map(|c| *c as char).collect());
        } else if vif & 0x7F == 0x7F {
            manufacturer_vif = true;
        }
        let mut ext = vif & 0x80 != 0;
        let mut n = 0usize;
        while ext {
            ensure!(
                n < MAX_EXTENSIONS,
                "a record chains more than {MAX_EXTENSIONS} VIFEs"
            );
            let vife = take(data, &mut at, 1, "a VIFE")?[0];
            vifes.push(format!("{:#04x}", vife & 0x7F));
            ext = vife & 0x80 != 0;
            n += 1;
        }
        let code = vif & 0x7F;
        let vi = if let Some(u) = &plain_unit {
            Vi {
                quantity: "plain_text_unit".into(),
                unit: u.clone(),
                exponent: 0,
                date: false,
            }
        } else if manufacturer_vif {
            Vi {
                quantity: "manufacturer_specific".into(),
                unit: String::new(),
                exponent: 0,
                date: false,
            }
        } else {
            describe_vif(prefix, code)
        };
        let mut rec = Map::new();
        rec.insert("quantity".into(), json!(vi.quantity));
        if !vi.unit.is_empty() {
            rec.insert("unit".into(), json!(vi.unit));
        }
        let (value, coding, raw): (Value, String, Option<i128>) = match data_field {
            df::NONE => (Value::Null, "none".into(), None),
            df::SELECTION => (Value::Null, "selection".into(), None),
            df::INT8 | df::INT16 | df::INT24 | df::INT32 | df::INT48 | df::INT64 => {
                let len = [0, 1, 2, 3, 4, 0, 6, 8][data_field as usize];
                let b = take(data, &mut at, len, "an integer value")?;
                if vi.date {
                    let d = decode_date(b)
                        .with_context(|| format!("a {len}-byte value is not a date"))?;
                    (json!(d), format!("int{}", len * 8), None)
                } else {
                    let m = int_value(b);
                    (number(m, vi.exponent), format!("int{}", len * 8), Some(m))
                }
            }
            df::REAL32 => {
                let b = take(data, &mut at, 4, "a real value")?;
                let f = f32::from_le_bytes([b[0], b[1], b[2], b[3]]) as f64;
                let scaled: f64 = format!("{f}e{}", vi.exponent).parse().unwrap_or(f64::NAN);
                (
                    if scaled.is_finite() {
                        json!(scaled)
                    } else {
                        json!(scaled.to_string())
                    },
                    "real32".into(),
                    None,
                )
            }
            df::BCD2 | df::BCD4 | df::BCD6 | df::BCD8 | df::BCD12 => {
                let len = match data_field {
                    df::BCD2 => 1,
                    df::BCD4 => 2,
                    df::BCD6 => 3,
                    df::BCD8 => 4,
                    _ => 6,
                };
                let b = take(data, &mut at, len, "a BCD value")?;
                match bcd_value(b) {
                    Ok(m) => (number(m, vi.exponent), format!("bcd{}", len * 2), Some(m)),
                    Err(_) => {
                        // Meters put A-F nibbles in a BCD field to say the value is not
                        // available (often with function "error"). There is no number to
                        // report; the digits are what the meter's display would show.
                        rec.insert("bcd_digits".into(), json!(id_digits(b)));
                        rec.insert(
                            "invalid".into(),
                            json!("BCD field holds digits above 9: no value"),
                        );
                        (Value::Null, format!("bcd{}", len * 2), None)
                    }
                }
            }
            df::LVAR => {
                let lvar = take(data, &mut at, 1, "an LVAR length")?[0];
                match lvar {
                    0x00..=0xBF => {
                        let b = take(data, &mut at, lvar as usize, "LVAR text")?;
                        let text: String = b
                            .iter()
                            .rev()
                            .map(|c| {
                                if c.is_ascii_graphic() || *c == b' ' {
                                    *c as char
                                } else {
                                    '.'
                                }
                            })
                            .collect();
                        (json!(text), "text".into(), None)
                    }
                    0xC0..=0xC9 | 0xD0..=0xD9 => {
                        let len = (lvar & 0x0F) as usize;
                        let b = take(data, &mut at, len, "LVAR BCD")?;
                        let mut m = bcd_value(b)?;
                        if lvar >= 0xD0 {
                            m = -m;
                        }
                        (number(m, vi.exponent), "lvar_bcd".into(), Some(m))
                    }
                    0xE0..=0xEF => {
                        let len = (lvar & 0x0F) as usize;
                        let b = take(data, &mut at, len, "LVAR binary")?;
                        if len <= 8 && len > 0 {
                            let m = int_value(b);
                            (number(m, vi.exponent), "lvar_binary".into(), Some(m))
                        } else {
                            (Value::Null, format!("lvar_binary_{len}_bytes"), None)
                        }
                    }
                    0xF0..=0xF4 => {
                        // EN 13757-3: 4 * (LVAR - 0xEC) bytes of binary number.
                        let len = 4 * (lvar as usize - 0xEC);
                        take(data, &mut at, len, "LVAR long binary")?;
                        (Value::Null, format!("lvar_binary_{len}_bytes"), None)
                    }
                    other => bail!("LVAR {other:#04x} is reserved"),
                }
            }
            _ => bail!("DIF {dif:#04x} has a reserved data field"),
        };
        rec.insert("value".into(), value);
        if let Some(m) = raw {
            if vi.exponent != 0 {
                rec.insert("raw_value".into(), json!(m as i64));
                rec.insert("exponent".into(), json!(vi.exponent));
            }
        }
        rec.insert("encoding".into(), json!(coding));
        rec.insert("function".into(), json!(function_name(function)));
        rec.insert("storage".into(), json!(storage));
        if tariff != 0 {
            rec.insert("tariff".into(), json!(tariff));
        }
        if subunit != 0 {
            rec.insert("subunit".into(), json!(subunit));
        }
        if prefix != 0 || vi.quantity == "unknown" {
            rec.insert(
                "vif".into(),
                json!(if prefix != 0 {
                    format!("{prefix:#04x} {code:#04x}")
                } else {
                    format!("{code:#04x}")
                }),
            );
        }
        if !vifes.is_empty() {
            rec.insert("vife".into(), json!(vifes));
        }
        out.records.push(Value::Object(rec));
    }
    Ok(out)
}

/// A whole RSP_UD's user data (CI 0x72): the header as the model reads it and the records.
pub fn decode_response(ci: u8, data: &[u8]) -> Result<(Header, Decoded)> {
    ensure!(
        ci == frame::ci::RSP_VARIABLE,
        "CI {ci:#04x} is not a variable data response (0x72); only CI 0x72 is decoded"
    );
    let header = Header::decode(data)?;
    let decoded = decode_records(&data[HEADER_LEN..])?;
    Ok((header, decoded))
}

/// The header as the model reads it.
pub fn header_json(h: &Header) -> Value {
    json!({
        "secondary_address": h.address.to_hex(),
        "id": frame::id_hex(&h.address.id),
        "manufacturer": frame::manufacturer_letters(h.address.manufacturer),
        "version": h.address.version,
        "medium": frame::medium_name(h.address.medium),
        "access_number": h.access_number,
        "status": status::names(h.status),
    })
}

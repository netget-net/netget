//! A bounded decoder for the parameter block of `COM_STMT_EXECUTE`, written here because
//! `opensrv-mysql`'s own cannot be called safely.
//!
//! # Why not `ParamParser`
//!
//! `opensrv-mysql` 0.7.0 hands `on_execute` a `ParamParser` whose iterator
//! (`src/params.rs`, `impl Iterator for Params`) trusts every length the peer sent:
//!
//! | line | what panics | the peer sends |
//! |---|---|---|
//! | 81 | `self.input.split_at(nullmap_len)` | fewer bytes than the NULL bitmap needs |
//! | 86 | `rest[1..].split_at(2 * self.params)` | the new-params-bound flag set, then fewer than `2 × n` type bytes |
//! | 90–91 | `panic!("bad column type 0x{:x}: {}", …)` | any type byte `ColumnType::try_from` does not know — one client-chosen byte |
//! | 103 | `&self.bound_types[self.col]` | the new-params-bound flag clear on a statement's first execute, so no types were ever bound |
//! | 127 | `Value::parse_from(…).unwrap()` | a value shorter than its type (an `INT` with two bytes left, a string whose length-encoded size runs past the packet), or a type `parse_from` refuses (`src/value/decode.rs:175`) |
//!
//! Every one of those is a panic inside the connection task, from bytes sent after a handshake
//! that verifies nothing. So `on_execute` never iterates `ParamParser`, and the raw bytes it
//! would have read reach this module through [`super::command_tap`], which copies each
//! `COM_STMT_EXECUTE` as it passes beneath the crate.
//!
//! # What this decoder promises
//!
//! It never panics and never allocates in proportion to a number the peer declared: every
//! length is compared with the bytes actually remaining before it is used, as a `u64`, so a
//! length-encoded `0xFE` size of 2⁶⁴−1 is a refusal rather than an overflow. Values are borrowed
//! from the packet, not copied. Anything it does not understand is an [`ExecuteError`], which
//! the server answers with ERR 1835 `ER_MALFORMED_PACKET` — the session continues.
//!
//! It is strict where `mysqld` is lenient, deliberately: trailing bytes after the last value,
//! a temporal value whose length byte is not one the format defines, and a type byte outside
//! the binary protocol's parameter types are all refused rather than guessed at, because the
//! decoded values go to a model that will answer as though they were what the client meant.
//!
//! The wire format (no `CLIENT_QUERY_ATTRIBUTES`, which `opensrv-mysql` does not advertise):
//!
//! ```text
//! stmt_id u32 · flags u8 · iteration_count u32
//! if n > 0:  null_bitmap[(n+7)/8] · new_params_bound u8
//!            if new_params_bound != 0: n × (type u8, flags u8)   — flags 0x80 = unsigned
//!            values, in order, for every parameter that is neither NULL nor sent as long data
//! ```

use std::collections::HashMap;

/// The parameter flag bit marking an integer as unsigned.
const UNSIGNED_FLAG: u8 = 0x80;

/// Longest prefix of a string or blob value shown to the model, in bytes.
///
/// The model needs to read the value, not receive it whole: a 16 MiB blob in a prompt helps
/// nobody and the event is rendered into the model's context. The full length is always
/// reported beside a truncated prefix.
pub const MAX_RENDERED_VALUE_BYTES: usize = 512;

/// A parameter's declared type as the client bound it: the type byte and the unsigned flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParamType {
    pub code: u8,
    pub unsigned: bool,
}

/// What a `COM_STMT_SEND_LONG_DATA` sequence delivered for one parameter.
///
/// Only a prefix is kept — enough to show the model — with the total length beside it. Long
/// data is how a client sends a value larger than one packet, so keeping all of it would make
/// the peer decide how much this process holds.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LongData {
    /// The first [`MAX_RENDERED_VALUE_BYTES`] bytes (or a few more, to finish a character).
    pub prefix: Vec<u8>,
    /// Total bytes received across every chunk.
    pub total_len: u64,
}

impl LongData {
    /// Append one chunk, of which `chunk_prefix` is the start (or all) and `chunk_len` the
    /// full length, keeping the stored prefix bounded.
    pub fn append(&mut self, chunk_prefix: &[u8], chunk_len: u64) {
        // A few spare bytes so a multi-byte character cut at the limit can still be decoded.
        // Only extend while nothing has been dropped yet: once the stored prefix is short of
        // the total, a later chunk is not contiguous with it.
        if self.prefix.len() as u64 == self.total_len {
            let keep = (MAX_RENDERED_VALUE_BYTES + 4).saturating_sub(self.prefix.len());
            self.prefix
                .extend_from_slice(&chunk_prefix[..chunk_prefix.len().min(keep)]);
        }
        self.total_len = self.total_len.saturating_add(chunk_len);
    }
}

/// One decoded parameter value. Borrowed from the packet; nothing is copied.
#[derive(Debug, Clone, PartialEq)]
pub enum ParamValue<'a> {
    Null,
    Int(i64),
    UInt(u64),
    Float(f32),
    Double(f64),
    /// A length-encoded string: every string, blob, decimal, enum, set, bit, JSON and geometry
    /// type. Decimals arrive as their decimal text, which is how they are shown.
    Bytes(&'a [u8]),
    /// DATE / DATETIME / TIMESTAMP. `len` is the length byte the client sent, which says how
    /// many fields are present: 0 (zero date), 4 (date), 7 (date and time) or 11 (with
    /// microseconds).
    DateTime {
        len: u8,
        year: u16,
        month: u8,
        day: u8,
        hour: u8,
        minute: u8,
        second: u8,
        micros: u32,
    },
    /// TIME: a signed duration of days, hours, minutes, seconds and microseconds. `len` is 0,
    /// 8 or 12.
    Time {
        len: u8,
        negative: bool,
        days: u32,
        hour: u8,
        minute: u8,
        second: u8,
        micros: u32,
    },
    /// The value arrived through `COM_STMT_SEND_LONG_DATA` rather than in this packet.
    LongData(&'a LongData),
}

/// One parameter: its declared type and its value.
#[derive(Debug, Clone, PartialEq)]
pub struct DecodedParam<'a> {
    pub ty: ParamType,
    /// Whether the NULL bitmap marked this parameter. Kept beside `value` because a parameter
    /// can be bitmap-NULL and have long data (long data wins, as in `mysqld`).
    pub null_bit: bool,
    pub value: ParamValue<'a>,
}

/// A decoded `COM_STMT_EXECUTE`.
#[derive(Debug, Clone, PartialEq)]
pub struct ExecuteRequest<'a> {
    pub stmt_id: u32,
    pub flags: u8,
    pub iteration_count: u32,
    /// The types this packet bound, when its new-params-bound flag was set. The caller keeps
    /// them: a later execute of the same statement may clear the flag and reuse them.
    pub new_types: Option<Vec<ParamType>>,
    /// The raw new-params-bound byte, kept so a re-encoder can reproduce the packet exactly.
    pub new_params_bound: u8,
    pub params: Vec<DecodedParam<'a>>,
}

/// Why a `COM_STMT_EXECUTE` was refused. Written to the log, never to the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecuteError {
    /// Fewer bytes remained than the named field needs.
    Truncated {
        field: &'static str,
        needed: u64,
        remaining: usize,
    },
    /// A length-encoded integer began with `0xFB` or `0xFF`, which are not lengths.
    BadLengthPrefix { param: usize, byte: u8 },
    /// The new-params-bound flag was clear and no earlier execute had bound types.
    NoBoundTypes,
    /// A type byte the binary protocol does not define for a parameter.
    UnsupportedType { param: usize, code: u8 },
    /// A temporal value's length byte is not one its format defines.
    BadTemporalLength { param: usize, code: u8, len: u8 },
    /// Bytes remained after the last value.
    TrailingBytes { count: usize },
    /// More parameters than the decoder will take (the server caps placeholders lower still).
    TooManyParams { count: usize },
}

impl std::fmt::Display for ExecuteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated {
                field,
                needed,
                remaining,
            } => write!(
                f,
                "truncated at {field}: needs {needed} bytes, {remaining} remain"
            ),
            Self::BadLengthPrefix { param, byte } => write!(
                f,
                "parameter {} has length prefix 0x{byte:02x}, which is not a length",
                param + 1
            ),
            Self::NoBoundTypes => write!(
                f,
                "new-params-bound flag is clear but no earlier execute bound any types"
            ),
            Self::UnsupportedType { param, code } => {
                write!(
                    f,
                    "parameter {} has unsupported type 0x{code:02x}",
                    param + 1
                )
            }
            Self::BadTemporalLength { param, code, len } => write!(
                f,
                "parameter {} ({}) has temporal length {len}, which the format does not define",
                param + 1,
                type_name(*code)
            ),
            Self::TrailingBytes { count } => {
                write!(f, "{count} unexpected bytes after the last parameter")
            }
            Self::TooManyParams { count } => write!(f, "{count} parameters is more than allowed"),
        }
    }
}

impl std::error::Error for ExecuteError {}

/// Most parameters [`parse_execute`] will decode. MySQL's own ceiling; the server's
/// `MAX_PLACEHOLDERS` is lower, so this only matters to a caller that is not the server.
pub const MAX_PARAMS: usize = 65_535;

/// A cursor over the packet that refuses instead of panicking.
struct Cursor<'a> {
    bytes: &'a [u8],
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: u64, field: &'static str) -> Result<&'a [u8], ExecuteError> {
        if n > self.bytes.len() as u64 {
            return Err(ExecuteError::Truncated {
                field,
                needed: n,
                remaining: self.bytes.len(),
            });
        }
        let (head, rest) = self.bytes.split_at(n as usize);
        self.bytes = rest;
        Ok(head)
    }

    fn u8(&mut self, field: &'static str) -> Result<u8, ExecuteError> {
        Ok(self.take(1, field)?[0])
    }

    fn array<const N: usize>(&mut self, field: &'static str) -> Result<[u8; N], ExecuteError> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.take(N as u64, field)?);
        Ok(out)
    }

    fn u16(&mut self, field: &'static str) -> Result<u16, ExecuteError> {
        Ok(u16::from_le_bytes(self.array(field)?))
    }

    fn u32(&mut self, field: &'static str) -> Result<u32, ExecuteError> {
        Ok(u32::from_le_bytes(self.array(field)?))
    }

    fn u64(&mut self, field: &'static str) -> Result<u64, ExecuteError> {
        Ok(u64::from_le_bytes(self.array(field)?))
    }

    /// A length-encoded integer. `0xFB` (NULL in a row) and `0xFF` (an ERR marker) are not
    /// lengths, and a parameter value never uses them.
    fn lenenc(&mut self, param: usize) -> Result<u64, ExecuteError> {
        let first = self.u8("length prefix")?;
        match first {
            0x00..=0xFA => Ok(u64::from(first)),
            0xFC => Ok(u64::from(self.u16("2-byte length")?)),
            0xFD => {
                let b = self.array::<3>("3-byte length")?;
                Ok(u64::from(u32::from_le_bytes([b[0], b[1], b[2], 0])))
            }
            0xFE => self.u64("8-byte length"),
            byte => Err(ExecuteError::BadLengthPrefix { param, byte }),
        }
    }
}

/// MySQL's name for a type byte, as it appears in the event the model reads.
pub fn type_name(code: u8) -> &'static str {
    match code {
        0x00 => "DECIMAL",
        0x01 => "TINY",
        0x02 => "SHORT",
        0x03 => "LONG",
        0x04 => "FLOAT",
        0x05 => "DOUBLE",
        0x06 => "NULL",
        0x07 => "TIMESTAMP",
        0x08 => "LONGLONG",
        0x09 => "INT24",
        0x0A => "DATE",
        0x0B => "TIME",
        0x0C => "DATETIME",
        0x0D => "YEAR",
        0x0F => "VARCHAR",
        0x10 => "BIT",
        0xF5 => "JSON",
        0xF6 => "NEWDECIMAL",
        0xF7 => "ENUM",
        0xF8 => "SET",
        0xF9 => "TINY_BLOB",
        0xFA => "MEDIUM_BLOB",
        0xFB => "LONG_BLOB",
        0xFC => "BLOB",
        0xFD => "VAR_STRING",
        0xFE => "STRING",
        0xFF => "GEOMETRY",
        _ => "UNKNOWN",
    }
}

/// Whether `code` is a type whose value is a length-encoded string.
fn is_lenenc_type(code: u8) -> bool {
    matches!(code, 0x00 | 0x0F | 0x10 | 0xF5..=0xFF)
}

/// Decode one non-NULL value of type `ty` from `cur`.
fn decode_value<'a>(
    cur: &mut Cursor<'a>,
    ty: ParamType,
    param: usize,
) -> Result<ParamValue<'a>, ExecuteError> {
    let code = ty.code;
    let v = match code {
        0x06 => ParamValue::Null,
        0x01 => {
            let b = cur.u8("TINY value")?;
            if ty.unsigned {
                ParamValue::UInt(u64::from(b))
            } else {
                ParamValue::Int(i64::from(b as i8))
            }
        }
        0x02 | 0x0D => {
            let b = cur.u16("SHORT value")?;
            if ty.unsigned {
                ParamValue::UInt(u64::from(b))
            } else {
                ParamValue::Int(i64::from(b as i16))
            }
        }
        0x03 | 0x09 => {
            let b = cur.u32("LONG value")?;
            if ty.unsigned {
                ParamValue::UInt(u64::from(b))
            } else {
                ParamValue::Int(i64::from(b as i32))
            }
        }
        0x08 => {
            let b = cur.u64("LONGLONG value")?;
            if ty.unsigned {
                ParamValue::UInt(b)
            } else {
                ParamValue::Int(b as i64)
            }
        }
        0x04 => ParamValue::Float(f32::from_le_bytes(cur.array("FLOAT value")?)),
        0x05 => ParamValue::Double(f64::from_le_bytes(cur.array("DOUBLE value")?)),
        0x07 | 0x0A | 0x0C => {
            let len = cur.u8("date length")?;
            if !matches!(len, 0 | 4 | 7 | 11) {
                return Err(ExecuteError::BadTemporalLength { param, code, len });
            }
            let mut c = Cursor {
                bytes: cur.take(u64::from(len), "date value")?,
            };
            let (mut year, mut month, mut day) = (0, 0, 0);
            let (mut hour, mut minute, mut second, mut micros) = (0, 0, 0, 0);
            if len >= 4 {
                year = c.u16("year")?;
                month = c.u8("month")?;
                day = c.u8("day")?;
            }
            if len >= 7 {
                hour = c.u8("hour")?;
                minute = c.u8("minute")?;
                second = c.u8("second")?;
            }
            if len >= 11 {
                micros = c.u32("microseconds")?;
            }
            ParamValue::DateTime {
                len,
                year,
                month,
                day,
                hour,
                minute,
                second,
                micros,
            }
        }
        0x0B => {
            let len = cur.u8("time length")?;
            if !matches!(len, 0 | 8 | 12) {
                return Err(ExecuteError::BadTemporalLength { param, code, len });
            }
            let mut c = Cursor {
                bytes: cur.take(u64::from(len), "time value")?,
            };
            let (mut negative, mut days, mut hour, mut minute, mut second, mut micros) =
                (false, 0, 0, 0, 0, 0);
            if len >= 8 {
                negative = c.u8("sign")? != 0;
                days = c.u32("days")?;
                hour = c.u8("hour")?;
                minute = c.u8("minute")?;
                second = c.u8("second")?;
            }
            if len >= 12 {
                micros = c.u32("microseconds")?;
            }
            ParamValue::Time {
                len,
                negative,
                days,
                hour,
                minute,
                second,
                micros,
            }
        }
        c if is_lenenc_type(c) => {
            let n = cur.lenenc(param)?;
            ParamValue::Bytes(cur.take(n, "string value")?)
        }
        _ => return Err(ExecuteError::UnsupportedType { param, code }),
    };
    Ok(v)
}

/// Decode the payload of a `COM_STMT_EXECUTE` — everything after the `0x17` command byte.
///
/// - `param_count` is what the server told the client at PREPARE; the client frames the packet
///   by it, so it is the only count that can be trusted.
/// - `previous_types` are the types an earlier execute of this statement bound, used when this
///   packet's new-params-bound flag is clear.
/// - `long_data` holds what `COM_STMT_SEND_LONG_DATA` delivered since the last execute, keyed
///   by parameter index. Those parameters carry no bytes in this packet.
pub fn parse_execute<'a>(
    payload: &'a [u8],
    param_count: usize,
    previous_types: Option<&[ParamType]>,
    long_data: &'a HashMap<u16, LongData>,
) -> Result<ExecuteRequest<'a>, ExecuteError> {
    if param_count > MAX_PARAMS {
        return Err(ExecuteError::TooManyParams { count: param_count });
    }
    let mut cur = Cursor { bytes: payload };
    let stmt_id = cur.u32("statement id")?;
    let flags = cur.u8("flags")?;
    let iteration_count = cur.u32("iteration count")?;

    let mut params = Vec::new();
    let mut new_types = None;
    let mut new_params_bound = 0;

    if param_count > 0 {
        let bitmap = cur.take(param_count.div_ceil(8) as u64, "NULL bitmap")?;
        new_params_bound = cur.u8("new-params-bound flag")?;

        let types: Vec<ParamType> = if new_params_bound != 0 {
            let raw = cur.take(2 * param_count as u64, "parameter types")?;
            let types: Vec<ParamType> = raw
                .chunks_exact(2)
                .map(|pair| ParamType {
                    code: pair[0],
                    unsigned: pair[1] & UNSIGNED_FLAG != 0,
                })
                .collect();
            new_types = Some(types.clone());
            types
        } else {
            match previous_types {
                Some(t) if t.len() == param_count => t.to_vec(),
                _ => return Err(ExecuteError::NoBoundTypes),
            }
        };

        // Every type is checked before any value is read, so a refusal names the type rather
        // than whatever misreading of the bytes after it would have produced.
        for (i, ty) in types.iter().enumerate() {
            if type_name(ty.code) == "UNKNOWN" {
                return Err(ExecuteError::UnsupportedType {
                    param: i,
                    code: ty.code,
                });
            }
        }

        params.reserve(param_count);
        for (i, ty) in types.into_iter().enumerate() {
            let null_bit = bitmap[i / 8] & (1 << (i % 8)) != 0;
            // `mysqld` checks long data first: a parameter that received it takes that value
            // whatever the bitmap says, and carries no bytes here.
            let value = if let Some(ld) = u16::try_from(i).ok().and_then(|k| long_data.get(&k)) {
                ParamValue::LongData(ld)
            } else if null_bit {
                ParamValue::Null
            } else {
                decode_value(&mut cur, ty, i)?
            };
            params.push(DecodedParam {
                ty,
                null_bit,
                value,
            });
        }
    }

    if !cur.bytes.is_empty() {
        return Err(ExecuteError::TrailingBytes {
            count: cur.bytes.len(),
        });
    }

    Ok(ExecuteRequest {
        stmt_id,
        flags,
        iteration_count,
        new_types,
        new_params_bound,
        params,
    })
}

/// Text for a string value as the model sees it: at most [`MAX_RENDERED_VALUE_BYTES`], cut on
/// a character boundary, with whether it was cut and whether the bytes were UTF-8 at all.
struct RenderedText {
    text: String,
    truncated: bool,
    utf8: bool,
}

fn render_text(bytes: &[u8], total_len: u64) -> RenderedText {
    let prefix = &bytes[..bytes.len().min(MAX_RENDERED_VALUE_BYTES + 4)];
    let (text, utf8) = match std::str::from_utf8(prefix) {
        Ok(s) => (s.to_string(), true),
        // An error with no `error_len` is a character cut at the end of the prefix — the bytes
        // are UTF-8, the prefix just stopped inside one.
        Err(e) if e.error_len().is_none() => (
            String::from_utf8_lossy(&prefix[..e.valid_up_to()]).into_owned(),
            true,
        ),
        Err(_) => (String::from_utf8_lossy(prefix).into_owned(), false),
    };
    let cut = crate::utils::truncate::truncate_str(&text, MAX_RENDERED_VALUE_BYTES).to_string();
    let truncated = (cut.len() as u64) < total_len;
    RenderedText {
        text: cut,
        truncated,
        utf8,
    }
}

fn two(n: u8) -> String {
    format!("{n:02}")
}

/// A temporal value in MySQL's own literal form, `YYYY-MM-DD[ HH:MM:SS[.ffffff]]`.
fn render_temporal(v: &ParamValue<'_>) -> Option<String> {
    match *v {
        ParamValue::DateTime {
            len,
            year,
            month,
            day,
            hour,
            minute,
            second,
            micros,
        } => {
            let date = format!("{year:04}-{}-{}", two(month), two(day));
            Some(match len {
                0 => "0000-00-00".to_string(),
                4 => date,
                7 => format!("{date} {}:{}:{}", two(hour), two(minute), two(second)),
                _ => format!(
                    "{date} {}:{}:{}.{micros:06}",
                    two(hour),
                    two(minute),
                    two(second)
                ),
            })
        }
        ParamValue::Time {
            len,
            negative,
            days,
            hour,
            minute,
            second,
            micros,
        } => {
            let hours = u64::from(days) * 24 + u64::from(hour);
            let sign = if negative { "-" } else { "" };
            Some(match len {
                0 => "00:00:00".to_string(),
                8 => format!("{sign}{hours:02}:{}:{}", two(minute), two(second)),
                _ => format!(
                    "{sign}{hours:02}:{}:{}.{micros:06}",
                    two(minute),
                    two(second)
                ),
            })
        }
        _ => None,
    }
}

/// A float as JSON: a number when it is finite, its name as a string when it is not (JSON has
/// no NaN or infinity).
fn float_json(f: f64) -> serde_json::Value {
    serde_json::Number::from_f64(f)
        .map(serde_json::Value::Number)
        .unwrap_or_else(|| serde_json::Value::String(f.to_string()))
}

/// One parameter as the model sees it in the event's `params` array.
///
/// `{"index": 1, "type": "LONGLONG", "value": 42}` — `index` counts from 1, in placeholder
/// order. String values carry `"truncated": true` and `"byte_length"` when only a prefix is
/// shown, and `"not_utf8": true` when the bytes were not text (the value is then a lossy
/// rendering, never the bytes themselves). `"long_data": true` marks a value that arrived via
/// `COM_STMT_SEND_LONG_DATA`.
pub fn param_json(index: usize, p: &DecodedParam<'_>) -> serde_json::Value {
    let mut obj = serde_json::Map::new();
    obj.insert("index".into(), serde_json::json!(index + 1));
    obj.insert("type".into(), serde_json::json!(type_name(p.ty.code)));
    if p.ty.unsigned {
        obj.insert("unsigned".into(), serde_json::json!(true));
    }
    fn text(bytes: &[u8], total: u64, obj: &mut serde_json::Map<String, serde_json::Value>) {
        let r = render_text(bytes, total);
        obj.insert("value".into(), serde_json::json!(r.text));
        if r.truncated {
            obj.insert("truncated".into(), serde_json::json!(true));
            obj.insert("byte_length".into(), serde_json::json!(total));
        }
        if !r.utf8 {
            obj.insert("not_utf8".into(), serde_json::json!(true));
        }
    }
    match &p.value {
        ParamValue::Null => {
            obj.insert("value".into(), serde_json::Value::Null);
        }
        ParamValue::Int(n) => {
            obj.insert("value".into(), serde_json::json!(n));
        }
        ParamValue::UInt(n) => {
            obj.insert("value".into(), serde_json::json!(n));
        }
        ParamValue::Float(f) => {
            // Through its own shortest decimal form, so 0.1f32 reads as 0.1 rather than as
            // the f64 widening 0.10000000149011612.
            let widened = f.to_string().parse::<f64>().unwrap_or(f64::from(*f));
            obj.insert("value".into(), float_json(widened));
        }
        ParamValue::Double(f) => {
            obj.insert("value".into(), float_json(*f));
        }
        ParamValue::Bytes(b) => text(b, b.len() as u64, &mut obj),
        ParamValue::LongData(ld) => {
            obj.insert("long_data".into(), serde_json::json!(true));
            text(&ld.prefix, ld.total_len, &mut obj);
        }
        v @ (ParamValue::DateTime { .. } | ParamValue::Time { .. }) => {
            obj.insert(
                "value".into(),
                serde_json::json!(render_temporal(v).unwrap_or_default()),
            );
        }
    }
    serde_json::Value::Object(obj)
}

/// Every parameter as the event's `params` array.
pub fn params_json(req: &ExecuteRequest<'_>) -> serde_json::Value {
    serde_json::Value::Array(
        req.params
            .iter()
            .enumerate()
            .map(|(i, p)| param_json(i, p))
            .collect(),
    )
}

/// The opening and closing marks around a rendered value in [`render_query`].
///
/// U+27E8 / U+27E9 (mathematical angle brackets) are not SQL syntax in any dialect, so a
/// rendering can never be mistaken for, or pasted back as, the statement the client sent.
pub const RENDER_OPEN: char = '⟨';
pub const RENDER_CLOSE: char = '⟩';

/// One value for [`render_query`]: `NULL`, a number, or a JSON string literal.
fn render_inline(p: &DecodedParam<'_>) -> String {
    let quoted = |s: &str| {
        // A JSON string literal, with the two marks escaped so a value cannot close its own
        // bracket and make the text after it read as part of the statement.
        serde_json::to_string(s)
            .unwrap_or_default()
            .replace(RENDER_OPEN, "\\u27e8")
            .replace(RENDER_CLOSE, "\\u27e9")
    };
    match &p.value {
        ParamValue::Null => "NULL".to_string(),
        ParamValue::Int(n) => n.to_string(),
        ParamValue::UInt(n) => n.to_string(),
        ParamValue::Float(f) => f.to_string(),
        ParamValue::Double(f) => f.to_string(),
        ParamValue::Bytes(b) => {
            let r = render_text(b, b.len() as u64);
            let mut s = quoted(&r.text);
            if r.truncated {
                s.push('…');
            }
            s
        }
        ParamValue::LongData(ld) => {
            let r = render_text(&ld.prefix, ld.total_len);
            let mut s = quoted(&r.text);
            if r.truncated {
                s.push('…');
            }
            s
        }
        v => quoted(&render_temporal(v).unwrap_or_default()),
    }
}

/// The statement text with each `?` placeholder replaced by `⟨value⟩`, for **reading only**.
///
/// It is not SQL and never will be: values sit inside [`RENDER_OPEN`]/[`RENDER_CLOSE`], strings
/// and dates are JSON string literals (so an embedded quote is `\"`, not SQL's `''`), and a
/// truncated string ends `"…"…`. The event's `params` array is the authoritative form; this
/// exists so a model reading `WHERE id = ⟨42⟩` does not have to count question marks.
///
/// `placeholder_offsets` are the byte offsets of each `?` in `sql`, from
/// `super::placeholder_offsets`. When their number does not match the parameters (it always
/// does — the count told to the client at PREPARE came from the same function), the
/// placeholders beyond the shorter list are left as `?`.
pub fn render_query(sql: &str, placeholder_offsets: &[usize], req: &ExecuteRequest<'_>) -> String {
    let mut out = String::with_capacity(sql.len() + 16 * req.params.len());
    let mut last = 0usize;
    for (offset, p) in placeholder_offsets.iter().zip(req.params.iter()) {
        let offset = *offset;
        if offset < last || offset >= sql.len() || !sql.is_char_boundary(offset) {
            continue;
        }
        out.push_str(&sql[last..offset]);
        out.push(RENDER_OPEN);
        out.push_str(&render_inline(p));
        out.push(RENDER_CLOSE);
        last = offset + 1;
    }
    out.push_str(&sql[last..]);
    out
}

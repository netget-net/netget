//! A query response's `data`, decoded into what the model is shown.
//!
//! Snowflake types a result twice: `rowtype` gives each column's **logical** type (FIXED with a
//! scale, REAL, TEXT, BOOLEAN, DATE, TIME, TIMESTAMP_NTZ/LTZ/TZ, VARIANT/OBJECT/ARRAY, BINARY),
//! and the cells come either as JSON strings (`rowset`) whose meaning depends on that type —
//! a DATE is a day count, a TIMESTAMP is `seconds.fraction` — or as an Arrow stream
//! (`rowsetBase64`) whose physical type is one of a few encodings of it. Both are turned into
//! the same JSON values here:
//!
//! | logical type | the model sees |
//! |---|---|
//! | FIXED, scale 0 | a JSON number (a string beyond 64 bits) |
//! | FIXED, scale > 0 | an exact decimal string, `"123.45"` |
//! | REAL | a JSON number (`"NaN"`, `"inf"` as strings) |
//! | TEXT | a string, cut at [`MAX_CELL_BYTES`] |
//! | BOOLEAN | `true` / `false` |
//! | DATE | `"2026-10-14"` |
//! | TIME | `"12:34:56"` plus the column's scale of fraction digits |
//! | TIMESTAMP_NTZ | `"2026-10-14T12:34:56.123456"`, no zone |
//! | TIMESTAMP_LTZ | the instant in UTC, `"…Z"` |
//! | TIMESTAMP_TZ | the wall time with its offset, `"…+02:00"` |
//! | VARIANT, OBJECT, ARRAY | the JSON value itself, if it nests no deeper than [`MAX_VARIANT_DEPTH`] |
//! | BINARY | `{"binary_length": n}` — never the bytes |
//! | NULL | `null` |
//!
//! A cell that does not read as its column's type is **not** guessed at: the model gets the
//! server's text as it came, and `decode_warnings` names the column and why. That is what
//! keeps a server's bug visible instead of turning it into a plausible wrong value.

use anyhow::{bail, ensure, Context, Result};
use chrono::{DateTime, Duration as ChronoDuration, FixedOffset, NaiveDate};
use serde_json::{json, Map, Value};

use super::arrow::{self, ArrowType, Cell};

/// Columns in one result.
pub const MAX_COLUMNS: usize = 1024;
/// A text cell longer than this many bytes is cut, and counted in `truncated_cells`.
pub const MAX_CELL_BYTES: usize = 16 * 1024;
/// How deep a VARIANT/OBJECT/ARRAY value may nest before it is handed on as text instead.
pub const MAX_VARIANT_DEPTH: usize = 64;
/// Decode warnings kept per result; the rest are only counted.
pub const MAX_DECODE_WARNINGS: usize = 16;

/// A column's logical type.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Kind {
    Fixed,
    Real,
    Text,
    Boolean,
    Date,
    Time,
    TimestampNtz,
    TimestampLtz,
    TimestampTz,
    Variant,
    Binary,
    Other,
}

impl Kind {
    pub fn from_type(name: &str) -> Kind {
        match name.to_ascii_lowercase().as_str() {
            "fixed" | "number" | "decimal" | "numeric" | "int" | "integer" | "bigint" => {
                Kind::Fixed
            }
            "real" | "float" | "double" => Kind::Real,
            "text" | "varchar" | "string" | "char" => Kind::Text,
            "boolean" => Kind::Boolean,
            "date" => Kind::Date,
            "time" => Kind::Time,
            "timestamp_ntz" | "timestamp" | "datetime" => Kind::TimestampNtz,
            "timestamp_ltz" => Kind::TimestampLtz,
            "timestamp_tz" => Kind::TimestampTz,
            "variant" | "object" | "array" => Kind::Variant,
            "binary" => Kind::Binary,
            _ => Kind::Other,
        }
    }
}

/// One column of `rowtype`.
#[derive(Debug, Clone)]
pub struct Column {
    pub name: String,
    pub type_name: String,
    pub kind: Kind,
    pub nullable: bool,
    pub precision: Option<i64>,
    pub scale: u32,
}

impl Column {
    pub fn from_rowtype(v: &Value) -> Result<Column> {
        let name = v
            .get("name")
            .and_then(Value::as_str)
            .context("a rowtype column has no name")?
            .to_string();
        let type_name = v
            .get("type")
            .and_then(Value::as_str)
            .with_context(|| format!("rowtype column {name:?} has no type"))?
            .to_ascii_lowercase();
        let scale = match v.get("scale") {
            None | Some(Value::Null) => None,
            Some(s) => Some(
                s.as_u64()
                    .filter(|s| *s <= 38)
                    .with_context(|| format!("column {name:?} has scale {s}"))?,
            ),
        };
        let kind = Kind::from_type(&type_name);
        // A time's scale defaults to nanoseconds, as Snowflake's does; a number's to 0.
        let default_scale = match kind {
            Kind::Time | Kind::TimestampNtz | Kind::TimestampLtz | Kind::TimestampTz => 9,
            _ => 0,
        };
        let scale = scale.unwrap_or(default_scale) as u32;
        if matches!(
            kind,
            Kind::Time | Kind::TimestampNtz | Kind::TimestampLtz | Kind::TimestampTz
        ) {
            ensure!(scale <= 9, "column {name:?}: a time scale of {scale}");
        }
        Ok(Column {
            name,
            type_name,
            kind,
            nullable: v.get("nullable").and_then(Value::as_bool).unwrap_or(true),
            precision: v.get("precision").and_then(Value::as_i64),
            scale,
        })
    }

    pub fn to_json(&self) -> Value {
        json!({
            "name": self.name,
            "type": self.type_name,
            "nullable": self.nullable,
            "precision": self.precision,
            "scale": self.scale,
        })
    }
}

/// What decoding found wrong, and what it cut.
#[derive(Default)]
struct Notes {
    warnings: Vec<Value>,
    warning_count: usize,
    truncated_cells: usize,
}

impl Notes {
    fn warn(&mut self, column: &Column, reason: String) {
        self.warning_count += 1;
        if self.warnings.len() < MAX_DECODE_WARNINGS {
            self.warnings.push(json!({
                "column": column.name,
                "type": column.type_name,
                "reason": reason,
            }));
        }
    }
    fn text(&mut self, s: &str) -> Value {
        if s.len() > MAX_CELL_BYTES {
            self.truncated_cells += 1;
            Value::String(crate::utils::truncate::truncate_with_suffix(
                s,
                MAX_CELL_BYTES,
                "...",
            ))
        } else {
            Value::String(s.to_string())
        }
    }
}

/// The deepest nesting of brackets in a JSON text, outside its strings. Iterative.
pub fn json_depth(text: &str) -> usize {
    let (mut depth, mut max, mut in_string, mut escaped) = (0usize, 0usize, false, false);
    for b in text.bytes() {
        if in_string {
            match (escaped, b) {
                (true, _) => escaped = false,
                (false, b'\\') => escaped = true,
                (false, b'"') => in_string = false,
                _ => {}
            }
            continue;
        }
        match b {
            b'"' => in_string = true,
            b'[' | b'{' => {
                depth += 1;
                max = max.max(depth);
            }
            b']' | b'}' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    max
}

/// `units` of 10^-scale, as an exact decimal string.
pub fn decimal_string(units: i128, scale: u32) -> String {
    if scale == 0 {
        return units.to_string();
    }
    let digits = units.unsigned_abs().to_string();
    let scale = scale as usize;
    let padded = if digits.len() <= scale {
        format!("{}{}", "0".repeat(scale + 1 - digits.len()), digits)
    } else {
        digits
    };
    let (int, frac) = padded.split_at(padded.len() - scale);
    format!("{}{int}.{frac}", if units < 0 { "-" } else { "" })
}

/// A whole number as JSON: a number when it fits 64 bits, otherwise its decimal string.
fn integer(units: i128) -> Value {
    match i64::try_from(units) {
        Ok(v) => json!(v),
        Err(_) => Value::String(units.to_string()),
    }
}

/// `"seconds[.fraction]"` as nanoseconds since the epoch, exactly.
pub fn parse_seconds(text: &str) -> Result<i128> {
    let (neg, body) = match text.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, text),
    };
    let (int, frac) = body.split_once('.').unwrap_or((body, ""));
    ensure!(
        !int.is_empty()
            && int.bytes().all(|b| b.is_ascii_digit())
            && frac.bytes().all(|b| b.is_ascii_digit())
            && frac.len() <= 9
            && int.len() <= 18,
        "{text:?} is not seconds with up to nine fraction digits"
    );
    let int: i128 = int.parse()?;
    let frac: i128 = if frac.is_empty() {
        0
    } else {
        format!("{frac:0<9}").parse()?
    };
    let nanos = int * 1_000_000_000 + frac;
    Ok(if neg { -nanos } else { nanos })
}

fn fraction(nanos: u32, scale: u32) -> String {
    if scale == 0 {
        return String::new();
    }
    format!(".{}", &format!("{nanos:09}")[..scale as usize])
}

fn split_nanos(nanos: i128) -> Result<(i64, u32)> {
    let secs = i64::try_from(nanos.div_euclid(1_000_000_000)).context("time out of range")?;
    Ok((secs, nanos.rem_euclid(1_000_000_000) as u32))
}

pub fn date_from_days(days: i64) -> Result<String> {
    let epoch = NaiveDate::from_ymd_opt(1970, 1, 1).context("epoch")?;
    let date = epoch
        .checked_add_signed(ChronoDuration::try_days(days).context("date out of range")?)
        .context("date out of range")?;
    Ok(date.format("%Y-%m-%d").to_string())
}

pub fn time_from_nanos(nanos: i128, scale: u32) -> Result<String> {
    ensure!(
        (0..86_400 * 1_000_000_000).contains(&nanos),
        "a time of day outside 00:00:00..24:00:00"
    );
    let (secs, frac) = split_nanos(nanos)?;
    Ok(format!(
        "{:02}:{:02}:{:02}{}",
        secs / 3600,
        secs / 60 % 60,
        secs % 60,
        fraction(frac, scale)
    ))
}

/// `nanos` since the epoch, with `offset_minutes` east of UTC where the column has a zone.
pub fn timestamp(
    nanos: i128,
    scale: u32,
    kind: Kind,
    offset_minutes: Option<i32>,
) -> Result<String> {
    let (secs, frac) = split_nanos(nanos)?;
    let utc = DateTime::from_timestamp(secs, frac).context("timestamp out of range")?;
    let base = |t: chrono::NaiveDateTime| {
        format!("{}{}", t.format("%Y-%m-%dT%H:%M:%S"), fraction(frac, scale))
    };
    Ok(match kind {
        Kind::TimestampNtz => base(utc.naive_utc()),
        Kind::TimestampLtz => format!("{}Z", base(utc.naive_utc())),
        _ => {
            let minutes = offset_minutes.context("TIMESTAMP_TZ without an offset")?;
            let offset = FixedOffset::east_opt(minutes * 60)
                .with_context(|| format!("a zone offset of {minutes} minutes"))?;
            let local = utc.with_timezone(&offset);
            format!("{}{}", base(local.naive_local()), local.format("%:z"))
        }
    })
}

/// Snowflake piggybacks a TIMESTAMP_TZ's zone as minutes east of UTC plus 1440.
fn zone(encoded: i128) -> Result<i32> {
    let minutes = i32::try_from(encoded - 1440).context("zone out of range")?;
    ensure!(
        (-1440..=1440).contains(&minutes),
        "a zone offset of {minutes} minutes"
    );
    Ok(minutes)
}

fn variant(text: &str, notes: &mut Notes, column: &Column) -> Value {
    if json_depth(text) > MAX_VARIANT_DEPTH {
        notes.warn(
            column,
            format!("nests deeper than {MAX_VARIANT_DEPTH}; given as text"),
        );
        return notes.text(text);
    }
    match serde_json::from_str::<Value>(text) {
        Ok(v) if text.len() <= MAX_CELL_BYTES => v,
        Ok(_) => notes.text(text),
        Err(e) => {
            notes.warn(column, format!("not JSON: {e}"));
            notes.text(text)
        }
    }
}

/// One JSON-format cell (a string or null) as its column's type.
fn json_cell(raw: &Value, column: &Column, notes: &mut Notes) -> Value {
    let text = match raw {
        Value::Null => return Value::Null,
        Value::String(s) => s.as_str(),
        other => {
            notes.warn(column, "a JSON rowset cell that is not a string".into());
            return other.clone();
        }
    };
    let decoded: Result<Value> = (|| {
        Ok(match column.kind {
            Kind::Text | Kind::Other => notes.text(text),
            Kind::Variant => variant(text, notes, column),
            Kind::Fixed => {
                if column.scale == 0 {
                    let v: i128 = text
                        .parse()
                        .with_context(|| format!("{text:?} is not a whole number"))?;
                    integer(v)
                } else {
                    let (int, frac) = text.split_once('.').unwrap_or((text, ""));
                    let int = int.strip_prefix('-').unwrap_or(int);
                    ensure!(
                        !int.is_empty()
                            && int.bytes().all(|b| b.is_ascii_digit())
                            && frac.bytes().all(|b| b.is_ascii_digit())
                            && frac.len() <= column.scale as usize,
                        "{text:?} is not a number of scale {}",
                        column.scale
                    );
                    Value::String(text.to_string())
                }
            }
            Kind::Real => {
                let v: f64 = text
                    .parse()
                    .with_context(|| format!("{text:?} is not a number"))?;
                if v.is_finite() {
                    json!(v)
                } else {
                    Value::String(text.to_string())
                }
            }
            Kind::Boolean => match text {
                "1" | "TRUE" | "true" | "True" => Value::Bool(true),
                "0" | "FALSE" | "false" | "False" => Value::Bool(false),
                _ => bail!("{text:?} is not a boolean"),
            },
            Kind::Date => Value::String(date_from_days(
                text.parse()
                    .with_context(|| format!("{text:?} is not a day count"))?,
            )?),
            Kind::Time => Value::String(time_from_nanos(parse_seconds(text)?, column.scale)?),
            Kind::TimestampNtz | Kind::TimestampLtz => Value::String(timestamp(
                parse_seconds(text)?,
                column.scale,
                column.kind,
                None,
            )?),
            Kind::TimestampTz => {
                let (value, tz) = text
                    .split_once(' ')
                    .with_context(|| format!("{text:?} carries no zone"))?;
                let tz: i128 = tz.parse().with_context(|| format!("zone {tz:?}"))?;
                Value::String(timestamp(
                    parse_seconds(value)?,
                    column.scale,
                    column.kind,
                    Some(zone(tz)?),
                )?)
            }
            Kind::Binary => {
                ensure!(
                    text.len().is_multiple_of(2) && text.bytes().all(|b| b.is_ascii_hexdigit()),
                    "{} characters that are not hex",
                    text.len()
                );
                json!({"binary_length": text.len() / 2})
            }
        })
    })();
    match decoded {
        Ok(v) => v,
        Err(e) => {
            notes.warn(column, format!("{e:#}"));
            notes.text(text)
        }
    }
}

fn scaled(units: i128, scale: u32) -> Result<i128> {
    let factor = 10i128
        .checked_pow(9u32.checked_sub(scale).context("a scale above 9")?)
        .context("scale")?;
    units.checked_mul(factor).context("time out of range")
}

/// The raw value of an Arrow cell, for a warning's fallback.
fn raw_arrow(cell: &Cell) -> Value {
    match cell {
        Cell::Null => Value::Null,
        Cell::Int(v) => integer(*v),
        Cell::Float(f) => json!(f),
        Cell::Bool(b) => json!(b),
        Cell::Text(s) => json!(s),
        Cell::Bytes(n) => json!({ "binary_length": n }),
        Cell::Struct(c) => Value::Array(c.iter().map(raw_arrow).collect()),
    }
}

/// One Arrow cell as its column's type. `field` is the cell's Arrow field.
fn arrow_cell(cell: &Cell, field: &arrow::Field, column: &Column, notes: &mut Notes) -> Value {
    if *cell == Cell::Null {
        return Value::Null;
    }
    // fakesnow marks a NULL timestamp in the struct's children rather than on the struct;
    // a struct whose every child is null is that NULL.
    if let Cell::Struct(parts) = cell {
        if !parts.is_empty() && parts.iter().all(|c| *c == Cell::Null) {
            return Value::Null;
        }
    }
    let decoded: Result<Value> = (|| {
        Ok(match (column.kind, cell, &field.data_type) {
            (Kind::Fixed, Cell::Int(v), ArrowType::Decimal { scale, .. }) => {
                ensure!(*scale >= 0, "a negative decimal scale");
                if *scale == 0 {
                    integer(*v)
                } else {
                    Value::String(decimal_string(*v, *scale as u32))
                }
            }
            (Kind::Fixed, Cell::Int(v), ArrowType::Int { .. }) => {
                if column.scale == 0 {
                    integer(*v)
                } else {
                    Value::String(decimal_string(*v, column.scale))
                }
            }
            (Kind::Fixed | Kind::Real, Cell::Float(f), _) => {
                if f.is_finite() {
                    json!(f)
                } else {
                    Value::String(f.to_string())
                }
            }
            (Kind::Real, Cell::Int(v), ArrowType::Int { .. }) => integer(*v),
            (Kind::Text | Kind::Other, Cell::Text(s), _) => notes.text(s),
            (Kind::Variant, Cell::Text(s), _) => variant(s, notes, column),
            (Kind::Boolean, Cell::Bool(b), _) => Value::Bool(*b),
            (Kind::Binary, Cell::Bytes(n), _) => json!({ "binary_length": n }),
            (Kind::Date, Cell::Int(v), ArrowType::Date { day: true }) => {
                Value::String(date_from_days(i64::try_from(*v)?)?)
            }
            (Kind::Date, Cell::Int(v), ArrowType::Date { day: false }) => {
                Value::String(date_from_days(i64::try_from(v.div_euclid(86_400_000))?)?)
            }
            (Kind::Time, Cell::Int(v), ArrowType::Int { .. }) => {
                Value::String(time_from_nanos(scaled(*v, column.scale)?, column.scale)?)
            }
            (Kind::Time, Cell::Int(v), ArrowType::Time { scale, .. }) => {
                Value::String(time_from_nanos(scaled(*v, *scale)?, column.scale)?)
            }
            (
                Kind::TimestampNtz | Kind::TimestampLtz | Kind::TimestampTz,
                Cell::Int(v),
                ArrowType::Int { .. },
            ) => {
                ensure!(
                    column.kind != Kind::TimestampTz,
                    "TIMESTAMP_TZ as a bare integer carries no zone"
                );
                Value::String(timestamp(
                    scaled(*v, column.scale)?,
                    column.scale,
                    column.kind,
                    None,
                )?)
            }
            (
                Kind::TimestampNtz | Kind::TimestampLtz,
                Cell::Int(v),
                ArrowType::Timestamp { scale, .. },
            ) => Value::String(timestamp(
                scaled(*v, *scale)?,
                column.scale,
                column.kind,
                None,
            )?),
            (
                Kind::TimestampNtz | Kind::TimestampLtz | Kind::TimestampTz,
                Cell::Struct(parts),
                ArrowType::Struct,
            ) => {
                let get = |name: &str| -> Option<i128> {
                    field
                        .children
                        .iter()
                        .position(|c| c.name == name)
                        .and_then(|i| match parts.get(i) {
                            Some(Cell::Int(v)) => Some(*v),
                            _ => None,
                        })
                };
                let epoch = get("epoch").context("a timestamp struct with no epoch")?;
                let nanos = match get("fraction") {
                    // {epoch seconds, fraction nanoseconds[, timezone]}
                    Some(fraction) => epoch
                        .checked_mul(1_000_000_000)
                        .and_then(|e| e.checked_add(fraction))
                        .context("timestamp out of range")?,
                    // {epoch in units of the column's scale, timezone}
                    None => scaled(epoch, column.scale)?,
                };
                let offset = match column.kind {
                    Kind::TimestampTz => Some(zone(
                        get("timezone").context("a TIMESTAMP_TZ struct with no timezone")?,
                    )?),
                    _ => None,
                };
                Value::String(timestamp(nanos, column.scale, column.kind, offset)?)
            }
            (kind, _, physical) => bail!("a {kind:?} column sent as Arrow {physical:?}"),
        })
    })();
    match decoded {
        Ok(v) => v,
        Err(e) => {
            notes.warn(column, format!("{e:#}"));
            raw_arrow(cell)
        }
    }
}

/// Column names as object keys: a repeated name gets `_2`, `_3`, ...
fn keys(columns: &[Column]) -> Vec<String> {
    let mut seen: Vec<String> = Vec::with_capacity(columns.len());
    for c in columns {
        let mut key = c.name.clone();
        let mut n = 1;
        while seen.contains(&key) {
            n += 1;
            key = format!("{}_{n}", c.name);
        }
        seen.push(key);
    }
    seen
}

/// Statement type ids of DML, whose result row counts the rows it changed.
fn is_dml(statement_type_id: Option<i64>) -> bool {
    statement_type_id.is_some_and(|id| (0x3000..0x4000).contains(&id))
}

/// Decode a successful query response's `data` into the `snowflake_query_result` fields.
pub fn decode(data: &Value, max_rows: usize) -> Result<Value> {
    let rowtype = match data.get("rowtype") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(a)) => a.clone(),
        Some(_) => bail!("rowtype is not an array"),
    };
    ensure!(
        rowtype.len() <= MAX_COLUMNS,
        "the result has {} columns; at most {MAX_COLUMNS} are read",
        rowtype.len()
    );
    let columns: Vec<Column> = rowtype
        .iter()
        .map(Column::from_rowtype)
        .collect::<Result<_>>()?;
    let names = keys(&columns);
    let mut notes = Notes::default();
    let format = data
        .get("queryResultFormat")
        .and_then(Value::as_str)
        .unwrap_or("json")
        .to_ascii_lowercase();

    let mut rows: Vec<Value> = Vec::new();
    let available: u64;
    match format.as_str() {
        "json" => {
            let rowset = match data.get("rowset") {
                None | Some(Value::Null) => Vec::new(),
                Some(Value::Array(a)) => a.clone(),
                Some(_) => bail!("rowset is not an array"),
            };
            available = rowset.len() as u64;
            for raw in rowset.iter().take(max_rows) {
                let cells = raw.as_array().context("a rowset row is not an array")?;
                ensure!(
                    cells.len() == columns.len(),
                    "a row has {} cells where rowtype has {} columns",
                    cells.len(),
                    columns.len()
                );
                let mut row = Map::new();
                for ((cell, column), key) in cells.iter().zip(&columns).zip(&names) {
                    row.insert(key.clone(), json_cell(cell, column, &mut notes));
                }
                rows.push(Value::Object(row));
            }
        }
        "arrow" => {
            let encoded = data
                .get("rowsetBase64")
                .and_then(Value::as_str)
                .unwrap_or("");
            if encoded.is_empty() {
                available = 0;
            } else {
                use base64::Engine as _;
                let stream = base64::engine::general_purpose::STANDARD
                    .decode(encoded.trim())
                    .context("rowsetBase64 is not base64")?;
                let decoded = arrow::decode_stream(&stream, max_rows)?;
                ensure!(
                    decoded.fields.len() == columns.len(),
                    "the Arrow schema has {} columns where rowtype has {}",
                    decoded.fields.len(),
                    columns.len()
                );
                available = decoded.total_rows;
                for cells in &decoded.rows {
                    let mut row = Map::new();
                    for (((cell, field), column), key) in
                        cells.iter().zip(&decoded.fields).zip(&columns).zip(&names)
                    {
                        row.insert(key.clone(), arrow_cell(cell, field, column, &mut notes));
                    }
                    rows.push(Value::Object(row));
                }
            }
        }
        other => bail!("result format {other:?} is neither json nor arrow"),
    }

    // Large results continue in `chunks` at presigned URLs, which name another host (cloud
    // storage). This client fetches nothing from anywhere but its target, so they are counted
    // and reported, never followed.
    let chunks = data
        .get("chunks")
        .and_then(Value::as_array)
        .map(|c| c.len())
        .unwrap_or(0);
    let chunk_rows: u64 = data
        .get("chunks")
        .and_then(Value::as_array)
        .map(|c| {
            c.iter()
                .filter_map(|c| c.get("rowCount").and_then(Value::as_u64))
                .sum()
        })
        .unwrap_or(0);
    let total = data.get("total").and_then(Value::as_u64);
    let statement_type_id = data.get("statementTypeId").and_then(Value::as_i64);

    // DML answers with one row of "number of rows inserted/updated/deleted" columns.
    let mut rows_affected: Option<i128> = None;
    if is_dml(statement_type_id) || columns.iter().any(|c| c.name.starts_with("number of rows")) {
        if let Some(Value::Object(first)) = rows.first() {
            for (column, key) in columns.iter().zip(&names) {
                if column.name.starts_with("number of rows")
                    || column.name.starts_with("number of multi-joined rows")
                {
                    if let Some(n) = first.get(key).and_then(Value::as_i64) {
                        rows_affected = Some(rows_affected.unwrap_or(0) + n as i128);
                    }
                }
            }
        }
    }

    let delivered = rows.len() as u64;
    let truncated = delivered < available || chunks > 0;
    Ok(json!({
        "query_id": data.get("queryId").and_then(Value::as_str).unwrap_or(""),
        "statement_type_id": statement_type_id,
        "result_format": format,
        "columns": columns.iter().map(Column::to_json).collect::<Vec<_>>(),
        "row_count": delivered,
        "rows": rows,
        "total": total,
        "rows_affected": rows_affected.map(|n| n as i64),
        "truncated": truncated,
        "chunks_not_fetched": chunks,
        "rows_in_chunks": chunk_rows,
        "decode_warnings": notes.warnings,
        "decode_warning_count": notes.warning_count,
        "truncated_cells": notes.truncated_cells,
    }))
}

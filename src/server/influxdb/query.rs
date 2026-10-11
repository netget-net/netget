//! Queries: Flux at `POST /api/v2/query` and InfluxQL at the v1-compatible `/query`.
//!
//! The server holds no time series — the project's rule is that protocols implement no
//! storage — so a query reaches the model (or a configured handler) as an `influx_query` event
//! and the answer comes back as structured tables. This module reads the request in each
//! dialect's own shape and renders the model's tables in each dialect's own wire format:
//!
//! - **Flux** answers in annotated CSV (`#datatype`, `#group`, `#default`, then a header and
//!   rows), the format every official client parses; each table is its own annotated block.
//! - **InfluxQL** answers in the v1 JSON shape, `{"results": [{"statement_id", "series": [{"name",
//!   "tags", "columns", "values"}]}]}`, with times as RFC 3339 or, when the client sends
//!   `epoch`, integers in that unit.
//!
//! Every value is checked against its column's declared type before anything is written, so a
//! model that says `long` and writes `0.5` is refused rather than putting a lie on the wire.

use anyhow::{bail, ensure, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;

/// Longest query text accepted, Flux or InfluxQL.
pub const MAX_QUERY_BYTES: usize = 16 * 1024;
/// Statements in one InfluxQL request.
pub const MAX_STATEMENTS: usize = 16;
/// Tables in one answer, all statements together.
pub const MAX_RESULT_TABLES: usize = 64;
/// Columns in one table, and tags on one table (Flux renders each tag as a column too).
pub const MAX_RESULT_COLUMNS: usize = 64;
/// Rows in one answer, all tables together.
pub const MAX_RESULT_ROWS: usize = 10_000;
/// Longest string a cell, tag or name may hold.
pub const MAX_CELL_BYTES: usize = 64 * 1024;
/// The rendered answer, whichever dialect.
pub const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

/// The query dialect.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Language {
    Flux,
    Influxql,
}

/// A query as the event reports it.
#[derive(Clone, Debug, Serialize)]
pub struct QueryRequest {
    pub language: Language,
    pub query: String,
    /// InfluxQL only: the statements, split on `;` outside quotes.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub statements: Vec<String>,
    /// Flux: the org; InfluxQL: absent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub org: Option<String>,
    /// InfluxQL: the database (`db`), and retention policy (`rp`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub db: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rp: Option<String>,
    /// InfluxQL: the unit the client asked times in, `ns`/`u`/`ms`/`s`/`m`/`h`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epoch: Option<String>,
    /// The credential, never reported: compared against the configured token.
    #[serde(skip)]
    pub v1_password: Option<String>,
}

fn decode_pairs(text: &str) -> Result<BTreeMap<String, String>> {
    let mut out = BTreeMap::new();
    for field in text.split('&').filter(|f| !f.is_empty()) {
        let (k, v) = field.split_once('=').unwrap_or((field, ""));
        let k = super::query_piece(k)?;
        let v = super::query_piece(v)?;
        ensure!(out.insert(k, v).is_none(), "duplicate query parameter");
    }
    Ok(out)
}

fn bounded(text: String, what: &str) -> Result<String> {
    ensure!(
        text.len() <= MAX_QUERY_BYTES,
        "{what} is {} bytes; at most {MAX_QUERY_BYTES}",
        text.len()
    );
    ensure!(!text.trim().is_empty(), "{what} is empty");
    Ok(text)
}

/// `POST /api/v2/query?org=…`: a JSON body `{"query": …, "type": "flux"}` (what every official
/// client sends) or a raw `application/vnd.flux` body.
pub fn parse_flux(
    uri_query: Option<&str>,
    content_type: Option<&str>,
    body: &[u8],
) -> Result<QueryRequest> {
    let params = decode_pairs(uri_query.unwrap_or(""))?;
    let org = params.get("org").or_else(|| params.get("orgID")).cloned();
    let mime = content_type
        .and_then(|c| c.split(';').next())
        .map(|c| c.trim().to_ascii_lowercase())
        .unwrap_or_else(|| "application/json".into());
    let query = match mime.as_str() {
        "application/vnd.flux" => String::from_utf8(body.to_vec()).context("Flux is not UTF-8")?,
        "application/json" => {
            let v: Value = serde_json::from_slice(body).context("query body is not JSON")?;
            if let Some(t) = v.get("type").and_then(|t| t.as_str()) {
                ensure!(
                    t == "flux",
                    "only Flux is served at /api/v2/query, not {t:?}"
                );
            }
            v.get("query")
                .and_then(|q| q.as_str())
                .context("the JSON body needs a 'query'")?
                .to_string()
        }
        other => bail!("unsupported query content type {other}"),
    };
    Ok(QueryRequest {
        language: Language::Flux,
        query: bounded(query, "the Flux query")?,
        statements: Vec::new(),
        org,
        db: None,
        rp: None,
        epoch: None,
        v1_password: None,
    })
}

/// Split InfluxQL on `;` outside single and double quotes.
pub fn split_statements(q: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for c in q.chars() {
        if escaped {
            current.push(c);
            escaped = false;
            continue;
        }
        match (c, quote) {
            ('\\', Some(_)) => {
                escaped = true;
                current.push(c);
            }
            ('\'' | '"', None) => {
                quote = Some(c);
                current.push(c);
            }
            (c2, Some(q2)) if c2 == q2 => {
                quote = None;
                current.push(c);
            }
            (';', None) => {
                if !current.trim().is_empty() {
                    out.push(current.trim().to_string());
                }
                current.clear();
            }
            _ => current.push(c),
        }
    }
    if !current.trim().is_empty() {
        out.push(current.trim().to_string());
    }
    out
}

/// `GET|POST /query?db=…&q=…`: InfluxQL, its parameters in the query string or, for a POST, in
/// a form-encoded body (both v1 client libraries do one or the other).
pub fn parse_influxql(
    uri_query: Option<&str>,
    content_type: Option<&str>,
    body: &[u8],
) -> Result<QueryRequest> {
    let mut params = decode_pairs(uri_query.unwrap_or(""))?;
    let form = content_type
        .and_then(|c| c.split(';').next())
        .is_some_and(|c| {
            c.trim()
                .eq_ignore_ascii_case("application/x-www-form-urlencoded")
        });
    if form && !body.is_empty() {
        for (k, v) in decode_pairs(std::str::from_utf8(body).context("form body is not UTF-8")?)? {
            ensure!(params.insert(k, v).is_none(), "duplicate query parameter");
        }
    }
    if params.get("chunked").is_some_and(|c| c == "true") {
        bail!("chunked responses are not served");
    }
    let query = bounded(
        params
            .remove("q")
            .context("q (the InfluxQL query) is required")?,
        "q",
    )?;
    let statements = split_statements(&query);
    ensure!(!statements.is_empty(), "q holds no statement");
    ensure!(
        statements.len() <= MAX_STATEMENTS,
        "q holds {} statements; at most {MAX_STATEMENTS}",
        statements.len()
    );
    // An empty `epoch` is RFC 3339, as InfluxDB reads it: node-influx sends `epoch=` whenever
    // no precision was asked for.
    let epoch = params.remove("epoch").filter(|e| !e.is_empty());
    if let Some(e) = &epoch {
        ensure!(
            ["ns", "n", "u", "µ", "ms", "s", "m", "h"].contains(&e.as_str()),
            "epoch must be ns, u, ms, s, m or h"
        );
    }
    Ok(QueryRequest {
        language: Language::Influxql,
        query,
        statements,
        org: None,
        db: params.remove("db"),
        rp: params.remove("rp"),
        epoch,
        v1_password: params.remove("p"),
    })
}

/// A column's type, in Flux's annotation vocabulary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ColumnType {
    String,
    Long,
    UnsignedLong,
    Double,
    Boolean,
    DateTime,
}

impl ColumnType {
    fn parse(s: &str) -> Result<ColumnType> {
        Ok(match s {
            "string" => ColumnType::String,
            "long" => ColumnType::Long,
            "unsignedLong" => ColumnType::UnsignedLong,
            "double" => ColumnType::Double,
            "boolean" => ColumnType::Boolean,
            "dateTime:RFC3339" | "dateTime" | "time" => ColumnType::DateTime,
            other => bail!(
                "column type {other:?} is not one of string, long, unsignedLong, double, \
                 boolean, dateTime:RFC3339"
            ),
        })
    }

    fn annotation(self) -> &'static str {
        match self {
            ColumnType::String => "string",
            ColumnType::Long => "long",
            ColumnType::UnsignedLong => "unsignedLong",
            ColumnType::Double => "double",
            ColumnType::Boolean => "boolean",
            ColumnType::DateTime => "dateTime:RFC3339",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Column {
    pub name: String,
    pub kind: ColumnType,
    pub group: bool,
}

/// A cell, checked against its column's type.
#[derive(Clone, Debug)]
pub enum Cell {
    Null,
    Text(String),
    Long(i64),
    Unsigned(u64),
    Double(f64),
    Bool(bool),
    /// Nanoseconds since the epoch, and the text the model wrote.
    Time(i64, String),
}

#[derive(Clone, Debug)]
pub struct Table {
    pub measurement: Option<String>,
    pub tags: BTreeMap<String, String>,
    pub columns: Vec<Column>,
    pub rows: Vec<Vec<Cell>>,
}

/// One InfluxQL statement's answer.
#[derive(Clone, Debug)]
pub enum StatementResult {
    Tables(Vec<Table>),
    Error(String),
}

fn short(text: &str, what: &str) -> Result<String> {
    ensure!(
        text.len() <= MAX_CELL_BYTES,
        "{what} is {} bytes; at most {MAX_CELL_BYTES}",
        text.len()
    );
    Ok(text.to_string())
}

fn parse_time(text: &str) -> Result<i64> {
    let t = chrono::DateTime::parse_from_rfc3339(text)
        .with_context(|| format!("{text:?} is not an RFC 3339 time"))?;
    t.timestamp_nanos_opt()
        .with_context(|| format!("{text:?} is outside the nanosecond range"))
}

fn cell(v: &Value, kind: ColumnType, where_: &str) -> Result<Cell> {
    if v.is_null() {
        return Ok(Cell::Null);
    }
    Ok(match kind {
        ColumnType::String => Cell::Text(short(
            v.as_str()
                .with_context(|| format!("{where_}: a string column holds {v}"))?,
            where_,
        )?),
        ColumnType::Long => Cell::Long(
            v.as_i64()
                .with_context(|| format!("{where_}: a long column holds {v}"))?,
        ),
        ColumnType::UnsignedLong => Cell::Unsigned(
            v.as_u64()
                .with_context(|| format!("{where_}: an unsignedLong column holds {v}"))?,
        ),
        ColumnType::Double => {
            let f = v
                .as_f64()
                .with_context(|| format!("{where_}: a double column holds {v}"))?;
            ensure!(f.is_finite(), "{where_}: a double must be finite");
            Cell::Double(f)
        }
        ColumnType::Boolean => Cell::Bool(
            v.as_bool()
                .with_context(|| format!("{where_}: a boolean column holds {v}"))?,
        ),
        ColumnType::DateTime => {
            let text = v
                .as_str()
                .with_context(|| format!("{where_}: a dateTime column holds {v}"))?;
            Cell::Time(parse_time(text)?, text.to_string())
        }
    })
}

/// Read the model's tables, checking every bound and every cell's type.
pub fn tables_from_json(
    v: &Value,
    rows_so_far: &mut usize,
    tables_so_far: &mut usize,
) -> Result<Vec<Table>> {
    let items = v.as_array().context("'tables' must be an array")?;
    let mut out = Vec::with_capacity(items.len());
    for (ti, t) in items.iter().enumerate() {
        *tables_so_far += 1;
        ensure!(
            *tables_so_far <= MAX_RESULT_TABLES,
            "more than {MAX_RESULT_TABLES} tables"
        );
        let measurement = t
            .get("measurement")
            .and_then(|m| m.as_str())
            .map(|m| short(m, "measurement"))
            .transpose()?;
        let mut tags = BTreeMap::new();
        if let Some(obj) = t.get("tags").and_then(|t| t.as_object()) {
            ensure!(
                obj.len() <= MAX_RESULT_COLUMNS,
                "tables[{ti}] has {} tags; at most {MAX_RESULT_COLUMNS}",
                obj.len()
            );
            for (k, v) in obj {
                let v = v
                    .as_str()
                    .with_context(|| format!("tables[{ti}].tags.{k} must be a string"))?;
                tags.insert(short(k, "tag key")?, short(v, "tag value")?);
            }
        }
        let cols = t
            .get("columns")
            .and_then(|c| c.as_array())
            .with_context(|| format!("tables[{ti}] needs 'columns'"))?;
        ensure!(
            !cols.is_empty() && cols.len() <= MAX_RESULT_COLUMNS,
            "tables[{ti}] has {} columns; 1 to {MAX_RESULT_COLUMNS}",
            cols.len()
        );
        let columns = cols
            .iter()
            .enumerate()
            .map(|(ci, c)| {
                let name = c
                    .get("name")
                    .and_then(|n| n.as_str())
                    .with_context(|| format!("tables[{ti}].columns[{ci}] needs 'name'"))?;
                let kind =
                    ColumnType::parse(c.get("type").and_then(|k| k.as_str()).unwrap_or("string"))?;
                Ok(Column {
                    name: short(name, "column name")?,
                    kind,
                    group: c.get("group").and_then(|g| g.as_bool()).unwrap_or(false),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let rows_json = t
            .get("rows")
            .and_then(|r| r.as_array())
            .with_context(|| format!("tables[{ti}] needs 'rows', an array of arrays"))?;
        let mut rows = Vec::with_capacity(rows_json.len());
        for (ri, r) in rows_json.iter().enumerate() {
            *rows_so_far += 1;
            ensure!(
                *rows_so_far <= MAX_RESULT_ROWS,
                "more than {MAX_RESULT_ROWS} rows"
            );
            let r = r
                .as_array()
                .with_context(|| format!("tables[{ti}].rows[{ri}] must be an array"))?;
            ensure!(
                r.len() == columns.len(),
                "tables[{ti}].rows[{ri}] has {} values for {} columns",
                r.len(),
                columns.len()
            );
            rows.push(
                r.iter()
                    .zip(&columns)
                    .map(|(v, c)| cell(v, c.kind, &format!("tables[{ti}].rows[{ri}].{}", c.name)))
                    .collect::<Result<Vec<_>>>()?,
            );
        }
        out.push(Table {
            measurement,
            tags,
            columns,
            rows,
        });
    }
    Ok(out)
}

/// The InfluxQL statements' answers from a `send_influx_query_result` action: `statements`
/// when given, else `tables` as the one statement's answer.
pub fn statements_from_json(action: &Value) -> Result<Vec<StatementResult>> {
    let mut rows = 0;
    let mut tables = 0;
    if let Some(list) = action.get("statements").and_then(|s| s.as_array()) {
        ensure!(
            list.len() <= MAX_STATEMENTS,
            "more than {MAX_STATEMENTS} statements"
        );
        return list
            .iter()
            .map(|s| {
                if let Some(err) = s.get("error").and_then(|e| e.as_str()) {
                    Ok(StatementResult::Error(short(err, "error")?))
                } else {
                    Ok(StatementResult::Tables(tables_from_json(
                        s.get("tables").unwrap_or(&json!([])),
                        &mut rows,
                        &mut tables,
                    )?))
                }
            })
            .collect();
    }
    Ok(vec![StatementResult::Tables(tables_from_json(
        action
            .get("tables")
            .context("needs 'tables' (or 'statements')")?,
        &mut rows,
        &mut tables,
    )?)])
}

fn csv_field(s: &str) -> String {
    if s.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

fn cell_text(c: &Cell) -> String {
    match c {
        Cell::Null => String::new(),
        Cell::Text(s) => s.clone(),
        Cell::Long(n) => n.to_string(),
        Cell::Unsigned(n) => n.to_string(),
        Cell::Double(f) => {
            let s = f.to_string();
            if s.contains(['.', 'e', 'E']) || s.contains("inf") || s.contains("NaN") {
                s
            } else {
                format!("{s}.0")
            }
        }
        Cell::Bool(b) => b.to_string(),
        Cell::Time(_, text) => text.clone(),
    }
}

/// Flux's annotated CSV (RFC 4180 rows under `#datatype`, `#group`, `#default`). Each table
/// is a block of its own, separated by an empty line, with its index in the `table` column.
/// Tags become string columns in the group key, and the measurement `_measurement`.
///
/// Every line is measured before it is appended, so the answer is refused at the line that
/// would take it past [`MAX_RESPONSE_BYTES`] and never grows beyond it.
pub fn render_flux(tables: &[Table]) -> Result<String> {
    let mut out = String::new();
    let line = |out: &mut String, first: &str, a: &str, b: &str, rest: Vec<String>| {
        let len = first.len()
            + a.len()
            + b.len()
            + 2
            + rest.iter().map(|r| r.len() + 1).sum::<usize>()
            + 2;
        ensure!(
            out.len() + len <= MAX_RESPONSE_BYTES,
            "the answer passes {MAX_RESPONSE_BYTES} bytes"
        );
        out.push_str(first);
        out.push(',');
        out.push_str(a);
        out.push(',');
        out.push_str(b);
        for r in rest {
            out.push(',');
            out.push_str(&r);
        }
        out.push_str("\r\n");
        Ok(())
    };
    for (index, t) in tables.iter().enumerate() {
        let mut columns = t.columns.clone();
        let mut constants: Vec<String> = Vec::new();
        if let Some(m) = &t.measurement {
            columns.push(Column {
                name: "_measurement".into(),
                kind: ColumnType::String,
                group: true,
            });
            constants.push(csv_field(m));
        }
        for (k, v) in &t.tags {
            columns.push(Column {
                name: k.clone(),
                kind: ColumnType::String,
                group: true,
            });
            constants.push(csv_field(v));
        }
        if index > 0 {
            ensure!(
                out.len() + 2 <= MAX_RESPONSE_BYTES,
                "the answer passes {MAX_RESPONSE_BYTES} bytes"
            );
            out.push_str("\r\n");
        }
        line(
            &mut out,
            "#datatype",
            "string",
            "long",
            columns
                .iter()
                .map(|c| c.kind.annotation().to_string())
                .collect(),
        )?;
        line(
            &mut out,
            "#group",
            "false",
            "false",
            columns.iter().map(|c| c.group.to_string()).collect(),
        )?;
        line(
            &mut out,
            "#default",
            "_result",
            "",
            columns.iter().map(|_| String::new()).collect(),
        )?;
        line(
            &mut out,
            "",
            "result",
            "table",
            columns.iter().map(|c| csv_field(&c.name)).collect(),
        )?;
        let table = index.to_string();
        for row in &t.rows {
            let mut cells: Vec<String> = row.iter().map(|c| csv_field(&cell_text(c))).collect();
            cells.extend(constants.iter().cloned());
            line(&mut out, "", "", &table, cells)?;
        }
    }
    if out.is_empty() {
        // No tables: an empty result is an empty body with the CSV content type.
        out.push_str("\r\n");
    }
    Ok(out)
}

fn epoch_value(ns: i64, epoch: &str) -> i64 {
    match epoch {
        "u" | "µ" => ns / 1_000,
        "ms" => ns / 1_000_000,
        "s" => ns / 1_000_000_000,
        "m" => ns / 60_000_000_000,
        "h" => ns / 3_600_000_000_000,
        _ => ns,
    }
}

fn cell_json(c: &Cell, epoch: Option<&str>) -> Value {
    match c {
        Cell::Null => Value::Null,
        Cell::Text(s) => json!(s),
        Cell::Long(n) => json!(n),
        Cell::Unsigned(n) => json!(n),
        Cell::Double(f) => json!(f),
        Cell::Bool(b) => json!(b),
        Cell::Time(ns, text) => match epoch {
            Some(e) => json!(epoch_value(*ns, e)),
            None => json!(text),
        },
    }
}

/// InfluxQL's v1 JSON: one result per statement, one series per table.
pub fn render_influxql(results: &[StatementResult], epoch: Option<&str>) -> Result<Vec<u8>> {
    let results: Vec<Value> = results
        .iter()
        .enumerate()
        .map(|(i, r)| match r {
            StatementResult::Error(e) => json!({"statement_id": i, "error": e}),
            StatementResult::Tables(tables) if tables.is_empty() => json!({"statement_id": i}),
            StatementResult::Tables(tables) => {
                let series: Vec<Value> = tables
                    .iter()
                    .map(|t| {
                        let mut s = json!({
                            "name": t.measurement.clone().unwrap_or_else(|| "result".into()),
                            "columns": t.columns.iter().map(|c| c.name.clone()).collect::<Vec<_>>(),
                            "values": t.rows.iter().map(|row| row.iter().map(|c| cell_json(c, epoch)).collect::<Vec<_>>()).collect::<Vec<_>>(),
                        });
                        if !t.tags.is_empty() {
                            s["tags"] = json!(t.tags);
                        }
                        s
                    })
                    .collect();
                json!({"statement_id": i, "series": series})
            }
        })
        .collect();
    let body = serde_json::to_vec(&json!({ "results": results }))?;
    ensure!(
        body.len() <= MAX_RESPONSE_BYTES,
        "the answer passes {MAX_RESPONSE_BYTES} bytes"
    );
    Ok(body)
}

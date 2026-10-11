//! Queries: Flux at `POST /api/v2/query` (annotated CSV back) and InfluxQL at the
//! v1-compatible `GET /query` (v1 JSON back), read into structured tables for the model.
//!
//! The model never sees CSV. A Flux answer is split into its annotated blocks, each row into
//! fields (RFC 4180 quoting), each field converted by its `#datatype` annotation and `#default`
//! — so a `long` is a JSON integer, a `boolean` a JSON boolean, and an empty cell is the
//! column's default or `null`. Rows are grouped into tables by the `table` column, which is
//! how a Flux result says which table a row belongs to. An InfluxQL answer is already JSON,
//! and is bounded and passed through series by series.
//!
//! An event carries at most [`MAX_REPORTED_ROWS`] rows, and says how many it left out.
use super::transport::{query as percent, Origin};
use anyhow::{bail, ensure, Context, Result};
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::{
    client::conn::http1,
    header::{ACCEPT, AUTHORIZATION, CONNECTION, CONTENT_ENCODING, CONTENT_TYPE, HOST},
    Request,
};
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::time::Duration;

/// A whole query exchange, connect to last byte.
pub const QUERY_TIMEOUT: Duration = Duration::from_secs(30);
/// The answer body, either dialect.
pub const MAX_QUERY_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
/// Longest query text sent.
pub const MAX_QUERY_BYTES: usize = 16 * 1024;
/// Rows an event reports, all tables or series together.
pub const MAX_REPORTED_ROWS: usize = 1000;
/// Tables (Flux) or series (InfluxQL) an event reports.
pub const MAX_REPORTED_TABLES: usize = 64;
/// Columns in one table.
pub const MAX_COLUMNS: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Language {
    Flux,
    Influxql,
}

/// A query as the model asked it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QuerySpec {
    pub language: Language,
    pub query: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rp: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epoch: Option<String>,
}

impl QuerySpec {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.query.trim().is_empty() && self.query.len() <= MAX_QUERY_BYTES,
            "query must be 1 to {MAX_QUERY_BYTES} bytes"
        );
        match self.language {
            Language::Flux => {
                let org = self.org.as_deref().context("a Flux query needs 'org'")?;
                ensure!(
                    !org.is_empty() && org.len() <= 1024,
                    "org must be 1 to 1024 bytes"
                );
            }
            Language::Influxql => {
                for value in [&self.db, &self.rp].into_iter().flatten() {
                    ensure!(value.len() <= 1024, "db and rp are at most 1024 bytes");
                }
                if let Some(e) = &self.epoch {
                    ensure!(
                        ["ns", "u", "ms", "s", "m", "h"].contains(&e.as_str()),
                        "epoch must be ns, u, ms, s, m or h"
                    );
                }
            }
        }
        Ok(())
    }

    fn request(&self, origin: &Origin, token: &Option<String>) -> Result<Request<Full<Bytes>>> {
        let mut builder = Request::builder()
            .header(HOST, &origin.authority)
            .header(CONNECTION, "close");
        if let Some(token) = token {
            builder = builder.header(AUTHORIZATION, format!("Token {token}"));
        }
        Ok(match self.language {
            Language::Flux => builder
                .method("POST")
                .uri(format!(
                    "/api/v2/query?org={}",
                    percent(self.org.as_deref().unwrap_or_default())
                ))
                .header(CONTENT_TYPE, "application/json")
                .header(ACCEPT, "application/csv")
                .body(Full::new(Bytes::from(serde_json::to_vec(&json!({
                    "query": self.query,
                    "type": "flux",
                    "dialect": {
                        "header": true,
                        "delimiter": ",",
                        "annotations": ["datatype", "group", "default"],
                        "commentPrefix": "#",
                        "dateTimeFormat": "RFC3339",
                    },
                }))?)))?,
            Language::Influxql => {
                let mut target = format!("/query?q={}", percent(&self.query));
                for (key, value) in [("db", &self.db), ("rp", &self.rp), ("epoch", &self.epoch)] {
                    if let Some(value) = value {
                        target.push_str(&format!("&{key}={}", percent(value)));
                    }
                }
                builder
                    .method("GET")
                    .uri(target)
                    .header(ACCEPT, "application/json")
                    .body(Full::new(Bytes::new()))?
            }
        })
    }
}

/// What a query exchange reports to the model.
#[derive(Clone, Debug, Serialize)]
pub struct QueryResponse {
    pub language: Language,
    pub query: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub org: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub db: Option<String>,
    pub status: u16,
    /// Flux: the result tables.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tables: Option<Vec<Value>>,
    /// InfluxQL: one entry per statement, `{statement_id, series}` or `{statement_id, error}`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub statements: Option<Vec<Value>>,
    /// Rows in the answer, and how many of them this event carries.
    pub row_count: usize,
    pub reported_rows: usize,
    pub truncated: bool,
    /// Non-2xx answers: the server's own message, and its code where the dialect has one.
    pub error: Option<Value>,
}

pub async fn query(
    origin: Origin,
    token: Option<String>,
    spec: QuerySpec,
) -> Result<QueryResponse> {
    let request = spec.request(&origin, &token)?;
    let (status, content_type, body) = tokio::time::timeout(QUERY_TIMEOUT, async move {
        let socket = tokio::net::TcpStream::connect(&origin.connect_addr).await?;
        let (mut sender, connection) = http1::Builder::new()
            .max_headers(64)
            .max_buf_size(32 * 1024)
            .handshake(TokioIo::new(socket))
            .await?;
        let exchange = async {
            let response = sender.send_request(request).await?;
            let (parts, body) = response.into_parts();
            ensure!(
                parts
                    .headers
                    .get(CONTENT_ENCODING)
                    .map(|v| v.as_bytes() == b"identity")
                    .unwrap_or(true),
                "compressed HTTP responses unsupported"
            );
            let content_type = parts
                .headers
                .get(CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.split(';').next())
                .map(|v| v.trim().to_ascii_lowercase())
                .unwrap_or_default();
            let bytes = Limited::new(body, MAX_QUERY_RESPONSE_BYTES)
                .collect()
                .await
                .map_err(|_| {
                    anyhow::anyhow!(
                        "query answer passes {MAX_QUERY_RESPONSE_BYTES} bytes or is cut short"
                    )
                })?
                .to_bytes();
            Ok::<_, anyhow::Error>((parts.status.as_u16(), content_type, bytes))
        };
        tokio::pin!(connection);
        tokio::pin!(exchange);
        tokio::select! {
            result = &mut exchange => result,
            result = &mut connection => {
                result.context("HTTP driver failed")?;
                exchange.await
            }
        }
    })
    .await
    .context("InfluxDB query deadline exceeded")??;
    let mut response = QueryResponse {
        language: spec.language,
        query: spec.query,
        org: spec.org,
        db: spec.db,
        status,
        tables: None,
        statements: None,
        row_count: 0,
        reported_rows: 0,
        truncated: false,
        error: None,
    };
    if !(200..300).contains(&status) {
        response.error = Some(error_body(&body));
        return Ok(response);
    }
    // A 2xx answer the client cannot read — or a Flux failure reported in-band, after the
    // status line was already sent — is reported to the model as an error, not as tables,
    // and the session carries on.
    if let Err(e) = read_answer(&mut response, spec.language, &content_type, &body) {
        response.error = Some(json!({"code": "unreadable_answer", "message": e.to_string()}));
    }
    Ok(response)
}

fn read_answer(
    response: &mut QueryResponse,
    language: Language,
    content_type: &str,
    body: &[u8],
) -> Result<()> {
    let text = std::str::from_utf8(body).context("the answer is not UTF-8")?;
    let mut budget = Budget::default();
    match language {
        Language::Flux => {
            ensure!(
                content_type.is_empty()
                    || content_type == "text/csv"
                    || content_type == "application/csv",
                "a Flux answer must be CSV, not {content_type}"
            );
            let tables = read_flux(text)?;
            response.tables = Some(budget.tables(tables));
        }
        Language::Influxql => {
            let value: Value =
                serde_json::from_str(text).context("the InfluxQL answer is not JSON")?;
            response.statements = Some(budget.statements(&value)?);
        }
    }
    budget.finish(response);
    Ok(())
}

/// An error body as the model sees it: v2's `{code, message}`, v1's `{error}` as
/// `{message}`, or the text itself (bounded) when it is neither.
fn error_body(body: &[u8]) -> Value {
    let text = String::from_utf8_lossy(body);
    match serde_json::from_str::<Value>(&text) {
        Ok(v) if v.get("message").is_some() => {
            json!({"code": v.get("code").cloned().unwrap_or(Value::Null), "message": v["message"]})
        }
        Ok(v) if v.get("error").is_some() => json!({"code": Value::Null, "message": v["error"]}),
        _ => {
            json!({"code": Value::Null, "message": crate::utils::truncate_for_log(text.trim(), 1024)})
        }
    }
}

#[derive(Default)]
struct Budget {
    rows: usize,
    reported: usize,
    tables: usize,
    truncated: bool,
}

impl Budget {
    fn take(&mut self, rows: Vec<Value>) -> Vec<Value> {
        self.rows += rows.len();
        let room = MAX_REPORTED_ROWS - self.reported;
        if rows.len() > room {
            self.truncated = true;
        }
        let kept: Vec<Value> = rows.into_iter().take(room).collect();
        self.reported += kept.len();
        kept
    }

    fn table_room(&mut self) -> bool {
        self.tables += 1;
        if self.tables > MAX_REPORTED_TABLES {
            self.truncated = true;
            return false;
        }
        true
    }

    fn tables(&mut self, tables: Vec<FluxTable>) -> Vec<Value> {
        let mut out = Vec::new();
        for t in tables {
            if !self.table_room() {
                self.rows += t.rows.len();
                continue;
            }
            let rows = self.take(t.rows);
            out.push(json!({
                "result": t.result,
                "table": t.table,
                "columns": t.columns,
                "rows": rows,
            }));
        }
        out
    }

    fn statements(&mut self, value: &Value) -> Result<Vec<Value>> {
        let results = value
            .get("results")
            .and_then(|r| r.as_array())
            .context("InfluxQL answer has no 'results'")?;
        let mut out = Vec::new();
        for r in results {
            let id = r.get("statement_id").cloned().unwrap_or(Value::Null);
            if let Some(e) = r.get("error") {
                out.push(json!({"statement_id": id, "error": e}));
                continue;
            }
            let mut series = Vec::new();
            for s in r
                .get("series")
                .and_then(|s| s.as_array())
                .into_iter()
                .flatten()
            {
                let values = s
                    .get("values")
                    .and_then(|v| v.as_array())
                    .cloned()
                    .unwrap_or_default();
                if !self.table_room() {
                    self.rows += values.len();
                    continue;
                }
                let columns = s
                    .get("columns")
                    .and_then(|c| c.as_array())
                    .context("a series has no columns")?;
                ensure!(
                    columns.len() <= MAX_COLUMNS,
                    "a series has more than {MAX_COLUMNS} columns"
                );
                let mut entry = Map::new();
                entry.insert("name".into(), s.get("name").cloned().unwrap_or(Value::Null));
                if let Some(tags) = s.get("tags") {
                    entry.insert("tags".into(), tags.clone());
                }
                entry.insert("columns".into(), Value::Array(columns.clone()));
                entry.insert("values".into(), Value::Array(self.take(values)));
                series.push(Value::Object(entry));
            }
            out.push(json!({"statement_id": id, "series": series}));
        }
        Ok(out)
    }

    fn finish(self, response: &mut QueryResponse) {
        response.row_count = self.rows;
        response.reported_rows = self.reported;
        response.truncated = self.truncated;
    }
}

/// One Flux table: its columns (name, datatype, whether in the group key) and typed rows.
#[derive(Debug)]
pub struct FluxTable {
    pub result: String,
    pub table: i64,
    pub columns: Vec<Value>,
    pub rows: Vec<Value>,
}

/// Split a CSV document into records, RFC 4180: quoted fields may hold commas, doubled quotes
/// and line breaks; a record ends at CRLF or LF; an empty line is an empty record.
pub fn csv_records(text: &str) -> Result<Vec<Vec<String>>> {
    let mut records = Vec::new();
    let mut record = Vec::new();
    let mut field = String::new();
    let mut quoted = false;
    let mut chars = text.chars().peekable();
    let mut empty_line = true;
    while let Some(c) = chars.next() {
        if quoted {
            if c == '"' {
                if chars.peek() == Some(&'"') {
                    field.push('"');
                    chars.next();
                } else {
                    quoted = false;
                }
            } else {
                field.push(c);
            }
            continue;
        }
        match c {
            '"' => {
                quoted = true;
                empty_line = false;
            }
            ',' => {
                record.push(std::mem::take(&mut field));
                empty_line = false;
            }
            '\r' if chars.peek() == Some(&'\n') => {}
            '\n' => {
                if empty_line && record.is_empty() && field.is_empty() {
                    records.push(Vec::new());
                } else {
                    record.push(std::mem::take(&mut field));
                    records.push(std::mem::take(&mut record));
                }
                empty_line = true;
            }
            c => {
                field.push(c);
                empty_line = false;
            }
        }
    }
    ensure!(!quoted, "unterminated quoted CSV field");
    if !empty_line || !record.is_empty() || !field.is_empty() {
        record.push(field);
        records.push(record);
    }
    Ok(records)
}

fn typed(text: &str, datatype: &str) -> Result<Value> {
    Ok(match datatype {
        "long" => json!(text
            .parse::<i64>()
            .with_context(|| format!("{text:?} is not a long"))?),
        "unsignedLong" => json!(text
            .parse::<u64>()
            .with_context(|| format!("{text:?} is not an unsignedLong"))?),
        "double" => match text {
            "+Inf" | "Inf" => json!("+Inf"),
            "-Inf" => json!("-Inf"),
            "NaN" => json!("NaN"),
            _ => json!(text
                .parse::<f64>()
                .with_context(|| format!("{text:?} is not a double"))?),
        },
        "boolean" => match text {
            "true" => json!(true),
            "false" => json!(false),
            _ => bail!("{text:?} is not a boolean"),
        },
        // string, dateTime:RFC3339, duration, base64Binary: the text is the value.
        _ => json!(text),
    })
}

/// Read Flux's annotated CSV into tables. A block is a run of annotation rows, a header, and
/// data rows, ending at an empty line or the next annotation. A block whose header has an
/// `error` column is Flux reporting a failure mid-stream, and is returned as an error.
pub fn read_flux(text: &str) -> Result<Vec<FluxTable>> {
    let mut tables: Vec<FluxTable> = Vec::new();
    let mut datatypes: Vec<String> = Vec::new();
    let mut groups: Vec<String> = Vec::new();
    let mut defaults: Vec<String> = Vec::new();
    let mut header: Option<Vec<String>> = None;
    for record in csv_records(text)? {
        if record.is_empty() || record.iter().all(|f| f.is_empty()) {
            header = None;
            continue;
        }
        match record[0].as_str() {
            "#datatype" => {
                header = None;
                datatypes = record;
                continue;
            }
            "#group" => {
                groups = record;
                continue;
            }
            "#default" => {
                defaults = record;
                continue;
            }
            _ => {}
        }
        let Some(names) = &header else {
            ensure!(
                record.len() <= MAX_COLUMNS + 1,
                "more than {MAX_COLUMNS} columns"
            );
            if record.iter().any(|n| n == "error") && !record.iter().any(|n| n == "table") {
                header = Some(record);
                continue;
            }
            ensure!(
                datatypes.len() == record.len(),
                "a Flux header without a matching #datatype annotation"
            );
            header = Some(record);
            continue;
        };
        ensure!(
            record.len() == names.len(),
            "a Flux row has {} fields for {} columns",
            record.len(),
            names.len()
        );
        if let Some(at) = names.iter().position(|n| n == "error") {
            if !names.iter().any(|n| n == "table") {
                bail!("the query failed: {}", record[at]);
            }
        }
        let mut result = String::from("_result");
        let mut table = 0i64;
        let mut columns = Vec::new();
        let mut row = Vec::new();
        for (i, name) in names.iter().enumerate().skip(1) {
            let datatype = datatypes.get(i).map(String::as_str).unwrap_or("string");
            let text = if record[i].is_empty() {
                defaults.get(i).cloned().unwrap_or_default()
            } else {
                record[i].clone()
            };
            match name.as_str() {
                "result" => result = text,
                "table" => table = text.parse().context("the table column is not a long")?,
                _ => {
                    columns.push(json!({
                        "name": name,
                        "type": datatype,
                        "group": groups.get(i).is_some_and(|g| g == "true"),
                    }));
                    row.push(if text.is_empty() && datatype != "string" {
                        Value::Null
                    } else {
                        typed(&text, datatype)?
                    });
                }
            }
        }
        match tables.last_mut() {
            Some(t) if t.table == table && t.result == result && t.columns == columns => {
                t.rows.push(Value::Array(row))
            }
            _ => tables.push(FluxTable {
                result,
                table,
                columns,
                rows: vec![Value::Array(row)],
            }),
        }
    }
    Ok(tables)
}

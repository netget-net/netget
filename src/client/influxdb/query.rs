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
//! An event carries at most [`MAX_REPORTED_ROWS`] rows in at most [`MAX_REPORTED_TABLES`]
//! tables, and says how many it left out. The Flux reader holds no more than that while it
//! reads: rows and tables past the bounds are validated and counted, never stored, each
//! header's column descriptors are built once and shared by its rows, and a header or
//! annotation row is refused past [`MAX_HEADER_BYTES`]. Error text from the server reaches
//! the model cut to [`MAX_ERROR_TEXT_BYTES`].
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
use std::sync::Arc;
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
/// Bytes in one Flux header row's column names, and in one annotation row's fields. Column
/// descriptors and `#default` values are copied into what an event carries, so their size is
/// bounded where they are read.
pub const MAX_HEADER_BYTES: usize = 16 * 1024;
/// Server-supplied error text, as the model sees it: a v1/v2 error body's message, an
/// in-band Flux error, or why a 2xx answer could not be read.
pub const MAX_ERROR_TEXT_BYTES: usize = 1024;

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
        response.error = Some(json!({
            "code": "unreadable_answer",
            "message": crate::utils::truncate_for_log(&e.to_string(), MAX_ERROR_TEXT_BYTES),
        }));
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
            let answer = read_flux(text)?;
            response.tables = Some(budget.flux(answer));
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
/// `{message}`, or the text itself when it is neither — each cut to [`MAX_ERROR_TEXT_BYTES`].
fn error_body(body: &[u8]) -> Value {
    let text = String::from_utf8_lossy(body);
    match serde_json::from_str::<Value>(&text) {
        Ok(v) if v.get("message").is_some() => json!({
            "code": v.get("code").map_or(Value::Null, bounded),
            "message": bounded(&v["message"]),
        }),
        Ok(v) if v.get("error").is_some() => {
            json!({"code": Value::Null, "message": bounded(&v["error"])})
        }
        _ => json!({
            "code": Value::Null,
            "message": crate::utils::truncate_for_log(text.trim(), MAX_ERROR_TEXT_BYTES),
        }),
    }
}

/// A server-supplied JSON value bounded for the model: a string cut on a char boundary to
/// [`MAX_ERROR_TEXT_BYTES`]; an array or object whose JSON text passes that becomes its
/// text, cut the same way.
fn bounded(value: &Value) -> Value {
    match value {
        Value::String(s) => Value::String(crate::utils::truncate_for_log(s, MAX_ERROR_TEXT_BYTES)),
        Value::Array(_) | Value::Object(_) => {
            let text = value.to_string();
            if text.len() <= MAX_ERROR_TEXT_BYTES {
                value.clone()
            } else {
                Value::String(crate::utils::truncate_for_log(&text, MAX_ERROR_TEXT_BYTES))
            }
        }
        _ => value.clone(),
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

    /// The tables `read_flux` kept, with the counts of everything it did not.
    fn flux(&mut self, answer: FluxAnswer) -> Vec<Value> {
        let mut out = Vec::new();
        for t in answer.tables {
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
        // `take` counted only the rows the reader kept; the reader counted them all.
        self.rows = answer.row_count;
        if answer.table_count > MAX_REPORTED_TABLES || answer.row_count > self.reported {
            self.truncated = true;
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
                out.push(json!({"statement_id": id, "error": bounded(e)}));
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

/// A Flux answer as read: the first [`MAX_REPORTED_TABLES`] tables, holding the first
/// [`MAX_REPORTED_ROWS`] rows between them, and how many of each the answer had in all.
#[derive(Debug)]
pub struct FluxAnswer {
    pub tables: Vec<FluxTable>,
    /// Tables in the answer, kept or not.
    pub table_count: usize,
    /// Rows in the answer, kept or not.
    pub row_count: usize,
}

/// Split a CSV document into records, RFC 4180: quoted fields may hold commas, doubled quotes
/// and line breaks; a record ends at CRLF or LF; an empty line is an empty record.
pub fn csv_records(text: &str) -> Result<Vec<Vec<String>>> {
    CsvRecords::new(text, usize::MAX).collect()
}

/// [`csv_records`] one record at a time, so a reader holds one record rather than the whole
/// document. A record with more than `max_fields` fields is an error, raised at the comma that
/// passes the bound rather than after the record is held whole.
pub struct CsvRecords<'a> {
    chars: std::iter::Peekable<std::str::Chars<'a>>,
    max_fields: usize,
    done: bool,
}

impl<'a> CsvRecords<'a> {
    pub fn new(text: &'a str, max_fields: usize) -> Self {
        CsvRecords {
            chars: text.chars().peekable(),
            max_fields,
            done: false,
        }
    }
}

impl Iterator for CsvRecords<'_> {
    type Item = Result<Vec<String>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        let mut record = Vec::new();
        let mut field = String::new();
        let mut quoted = false;
        let mut empty_line = true;
        while let Some(c) = self.chars.next() {
            if quoted {
                if c == '"' {
                    if self.chars.peek() == Some(&'"') {
                        field.push('"');
                        self.chars.next();
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
                    // At least one more field follows this comma.
                    if record.len() >= self.max_fields {
                        self.done = true;
                        return Some(Err(anyhow::anyhow!(
                            "a CSV record has more than {} fields",
                            self.max_fields
                        )));
                    }
                }
                '\r' if self.chars.peek() == Some(&'\n') => {}
                '\n' => {
                    if empty_line && record.is_empty() && field.is_empty() {
                        return Some(Ok(Vec::new()));
                    }
                    record.push(field);
                    return Some(Ok(record));
                }
                c => {
                    field.push(c);
                    empty_line = false;
                }
            }
        }
        self.done = true;
        if quoted {
            return Some(Err(anyhow::anyhow!("unterminated quoted CSV field")));
        }
        if !empty_line || !record.is_empty() || !field.is_empty() {
            record.push(field);
            return Some(Ok(record));
        }
        None
    }
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

/// The header row of the current block, read once.
struct Header {
    names: Vec<String>,
    /// The descriptor of every column but `result` and `table`, built once per header and
    /// shared by every table it starts.
    columns: Arc<Vec<Value>>,
    /// Which header this is: rows under the same header have the same columns.
    generation: usize,
    /// A header with an `error` column and no `table` column is Flux reporting a failure.
    error_at: Option<usize>,
}

impl Header {
    fn new(names: Vec<String>, datatypes: &[String], groups: &[String], generation: usize) -> Self {
        let error_at = if names.iter().any(|n| n == "table") {
            None
        } else {
            names.iter().position(|n| n == "error")
        };
        let columns = Arc::new(Self::columns(&names, datatypes, groups));
        Header {
            names,
            columns,
            generation,
            error_at,
        }
    }

    fn columns(names: &[String], datatypes: &[String], groups: &[String]) -> Vec<Value> {
        names
            .iter()
            .enumerate()
            .skip(1)
            .filter(|(_, name)| *name != "result" && *name != "table")
            .map(|(i, name)| {
                json!({
                    "name": name,
                    "type": datatypes.get(i).map(String::as_str).unwrap_or("string"),
                    "group": groups.get(i).is_some_and(|g| g == "true"),
                })
            })
            .collect()
    }

    /// The last column named `name`, as a row reads it.
    fn last(&self, name: &str) -> Option<usize> {
        self.names
            .iter()
            .enumerate()
            .skip(1)
            .filter(|(_, n)| *n == name)
            .map(|(i, _)| i)
            .last()
    }
}

/// The table the last row belonged to, whether or not it was kept.
struct Current {
    result: String,
    table: i64,
    generation: usize,
    columns: Arc<Vec<Value>>,
    kept: bool,
}

fn record_bytes(record: &[String]) -> usize {
    record.iter().map(String::len).sum()
}

/// Field `i` of a row, or the column's `#default` when it is empty. Borrowed: nothing is
/// copied until a row is kept.
fn cell<'a>(record: &'a [String], defaults: &'a [String], i: usize) -> &'a str {
    if record[i].is_empty() {
        defaults.get(i).map_or("", String::as_str)
    } else {
        &record[i]
    }
}

/// Read Flux's annotated CSV into tables. A block is a run of annotation rows, a header, and
/// data rows, ending at an empty line or the next annotation. A block whose header has an
/// `error` column is Flux reporting a failure mid-stream, and is returned as an error.
///
/// Every row is checked against its header and datatypes, but only the first
/// [`MAX_REPORTED_TABLES`] tables and the first [`MAX_REPORTED_ROWS`] rows are stored; the
/// rest are counted. A header or annotation row past [`MAX_HEADER_BYTES`] is an error.
pub fn read_flux(text: &str) -> Result<FluxAnswer> {
    let mut answer = FluxAnswer {
        tables: Vec::new(),
        table_count: 0,
        row_count: 0,
    };
    let mut kept_rows = 0usize;
    let mut datatypes: Vec<String> = Vec::new();
    let mut groups: Vec<String> = Vec::new();
    let mut defaults: Vec<String> = Vec::new();
    let mut header: Option<Header> = None;
    let mut generation = 0usize;
    let mut current: Option<Current> = None;
    for record in CsvRecords::new(text, MAX_COLUMNS + 1) {
        let record = record?;
        if record.is_empty() || record.iter().all(|f| f.is_empty()) {
            header = None;
            continue;
        }
        if matches!(record[0].as_str(), "#datatype" | "#group" | "#default") {
            ensure!(
                record_bytes(&record) <= MAX_HEADER_BYTES,
                "a Flux annotation row passes {MAX_HEADER_BYTES} bytes"
            );
        }
        match record[0].as_str() {
            "#datatype" => {
                header = None;
                datatypes = record;
                continue;
            }
            "#group" => {
                groups = record;
                // A #group row after the header changes the columns of the rows after it.
                if let Some(h) = header.as_mut() {
                    generation += 1;
                    h.columns = Arc::new(Header::columns(&h.names, &datatypes, &groups));
                    h.generation = generation;
                }
                continue;
            }
            "#default" => {
                defaults = record;
                continue;
            }
            _ => {}
        }
        let Some(h) = &header else {
            ensure!(
                record.len() <= MAX_COLUMNS + 1,
                "more than {MAX_COLUMNS} columns"
            );
            ensure!(
                record_bytes(&record) <= MAX_HEADER_BYTES,
                "a Flux header passes {MAX_HEADER_BYTES} bytes of column names"
            );
            let reports_error =
                record.iter().any(|n| n == "error") && !record.iter().any(|n| n == "table");
            if !reports_error {
                ensure!(
                    datatypes.len() == record.len(),
                    "a Flux header without a matching #datatype annotation"
                );
            }
            generation += 1;
            header = Some(Header::new(record, &datatypes, &groups, generation));
            continue;
        };
        ensure!(
            record.len() == h.names.len(),
            "a Flux row has {} fields for {} columns",
            record.len(),
            h.names.len()
        );
        if let Some(at) = h.error_at {
            bail!(
                "the query failed: {}",
                crate::utils::truncate_for_log(&record[at], MAX_ERROR_TEXT_BYTES)
            );
        }
        let result = h
            .last("result")
            .map_or("_result", |i| cell(&record, &defaults, i));
        let table: i64 = match h.last("table") {
            Some(i) => cell(&record, &defaults, i)
                .parse()
                .context("the table column is not a long")?,
            None => 0,
        };

        let same = current.as_ref().is_some_and(|c| {
            c.table == table
                && c.result == result
                && (c.generation == h.generation || c.columns == h.columns)
        });
        if same {
            if let Some(c) = current.as_mut() {
                c.generation = h.generation;
            }
        } else {
            answer.table_count += 1;
            let kept = answer.tables.len() < MAX_REPORTED_TABLES;
            if kept {
                answer.tables.push(FluxTable {
                    result: result.to_string(),
                    table,
                    columns: h.columns.as_ref().clone(),
                    rows: Vec::new(),
                });
            }
            current = Some(Current {
                result: result.to_string(),
                table,
                generation: h.generation,
                columns: h.columns.clone(),
                kept,
            });
        }
        answer.row_count += 1;
        let keep = current.as_ref().is_some_and(|c| c.kept) && kept_rows < MAX_REPORTED_ROWS;

        let mut row = Vec::new();
        for (i, name) in h.names.iter().enumerate().skip(1) {
            if name == "result" || name == "table" {
                continue;
            }
            let datatype = datatypes.get(i).map(String::as_str).unwrap_or("string");
            let text = cell(&record, &defaults, i);
            let value = if text.is_empty() && datatype != "string" {
                Value::Null
            } else {
                typed(text, datatype)?
            };
            if keep {
                row.push(value);
            }
        }
        if keep {
            if let Some(t) = answer.tables.last_mut() {
                t.rows.push(Value::Array(row));
                kept_rows += 1;
            }
        }
    }
    Ok(answer)
}

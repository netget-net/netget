//! Bounded RFC 2229 framing and structured dictionary responses.
use crate::server::dict::wire;
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};
use std::time::Duration;
use tokio::io::{AsyncBufRead, AsyncBufReadExt};
pub const DEADLINE: Duration = Duration::from_secs(30);
pub const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
pub const MAX_ENTRIES: usize = 4096;
pub const MAX_RESPONSE_LINE: usize = 65536;
/// Model-originated requests that may follow one another: an answer to the event at this depth
/// is not sent, so a model that answers every response with another request stops here.
pub const MAX_FOLLOWUPS: u8 = 4;
#[derive(Debug)]
pub struct Request {
    pub operation: String,
    pub bytes: Vec<u8>,
}
impl Request {
    pub fn from_action(v: &Value) -> Result<Self> {
        let operation = v["operation"].as_str().context("Missing operation")?;
        let text = |key: &str, default: Option<&str>| -> Result<String> {
            let s = v
                .get(key)
                .map(|v| v.as_str().context("Expected string"))
                .unwrap_or_else(|| default.context("Missing parameter"))?;
            ensure!(
                !crate::utils::sanitize::has_controls(&s),
                "DICT parameters cannot contain control characters"
            );
            Ok(wire::quoted(s))
        };
        let database = || text("database", Some("*"));
        let line = match operation {
            "define" => format!("DEFINE {} {}", database()?, text("word", None)?),
            "match" => format!(
                "MATCH {} {} {}",
                database()?,
                text("strategy", Some("."))?,
                text("word", None)?
            ),
            "databases" => "SHOW DB".into(),
            "strategies" => "SHOW STRAT".into(),
            "info" => format!("SHOW INFO {}", text("database", None)?),
            "server" => "SHOW SERVER".into(),
            "status" => "STATUS".into(),
            "help" => "HELP".into(),
            "client" => format!("CLIENT {}", text("name", None)?),
            "quit" => "QUIT".into(),
            _ => bail!("Unsupported DICT operation"),
        };
        ensure!(
            line.len() + 2 <= wire::MAX_LINE_BYTES,
            "DICT command exceeds client 1024-byte bound"
        );
        Ok(Self {
            operation: operation.into(),
            bytes: format!("{line}\r\n").into_bytes(),
        })
    }
}
pub async fn line<R: AsyncBufRead + Unpin>(reader: &mut R, budget: &mut usize) -> Result<String> {
    let mut result = Vec::new();
    loop {
        let chunk = reader.fill_buf().await?;
        ensure!(!chunk.is_empty(), "Truncated DICT response");
        let n = chunk
            .iter()
            .position(|b| *b == b'\n')
            .map(|n| n + 1)
            .unwrap_or(chunk.len());
        ensure!(
            result.len() + n <= MAX_RESPONSE_LINE,
            "DICT response line too large"
        );
        ensure!(
            *budget + n <= MAX_RESPONSE_BYTES,
            "DICT response exceeds limit"
        );
        result.extend_from_slice(&chunk[..n]);
        reader.consume(n);
        *budget += n;
        if result.ends_with(b"\n") {
            ensure!(result.ends_with(b"\r\n"), "DICT requires CRLF");
            result.truncate(result.len() - 2);
            return Ok(String::from_utf8(result)?);
        }
    }
}
fn status(line: &str) -> Result<(u16, &str)> {
    let bytes = line.as_bytes();
    ensure!(
        bytes.len() >= 3
            && bytes[..3].iter().all(u8::is_ascii_digit)
            && (bytes.len() == 3 || bytes[3] == b' '),
        "Malformed DICT status"
    );
    Ok((line[..3].parse()?, line.get(4..).unwrap_or("")))
}
async fn block<R: AsyncBufRead + Unpin>(reader: &mut R, budget: &mut usize) -> Result<Vec<String>> {
    let mut lines = Vec::new();
    loop {
        let line = line(reader, budget).await?;
        if line == "." {
            return Ok(lines);
        }
        ensure!(
            lines.len() < MAX_ENTRIES,
            "DICT text/list has too many lines"
        );
        lines.push(
            line.strip_prefix("..")
                .map(|s| format!(".{s}"))
                .unwrap_or(line),
        );
    }
}
// Only the first three 151 fields have quoting syntax. Explanatory text can
// contain apostrophes or quotes and is not another protocol parameter.
fn definition_fields(text: &str) -> Result<Vec<String>> {
    let mut quote = None;
    let mut escaped = false;
    let mut in_token = false;
    let mut fields = 0;
    let mut end = text.len();
    for (i, c) in text.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if c == '\\' {
            escaped = true;
            in_token = true;
            continue;
        }
        if let Some(q) = quote {
            if c == q {
                quote = None;
            }
            continue;
        }
        if c == '\"' || c == '\'' {
            quote = Some(c);
            in_token = true;
            continue;
        }
        if c == ' ' || c == '\t' {
            if in_token {
                fields += 1;
                in_token = false;
                if fields == 3 {
                    end = i;
                    break;
                }
            }
        } else {
            in_token = true;
        }
    }
    wire::split_args(&text[..end]).map_err(|_| anyhow::anyhow!("Invalid definition fields"))
}
async fn finish<R: AsyncBufRead + Unpin>(reader: &mut R, budget: &mut usize) -> Result<()> {
    let s = line(reader, budget).await?;
    ensure!(status(&s)?.0 == 250, "DICT response missing final 250");
    Ok(())
}
pub async fn greeting<R: AsyncBufRead + Unpin>(reader: &mut R) -> Result<Value> {
    tokio::time::timeout(DEADLINE, async {
        let mut budget = 0;
        let s = line(reader, &mut budget).await?;
        let (code, message) = status(&s)?;
        ensure!(
            code == 220,
            "DICT server refused connection: {code} {message}"
        );
        Ok(json!({"greeting":message}))
    })
    .await
    .context("DICT greeting deadline exceeded")?
}
pub async fn response<R: AsyncBufRead + Unpin>(reader: &mut R, request: &Request) -> Result<Value> {
    tokio::time::timeout(DEADLINE, read_response(reader, request))
        .await
        .context("DICT response deadline exceeded")?
}
async fn read_response<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    request: &Request,
) -> Result<Value> {
    let mut budget = 0;
    let first = line(reader, &mut budget).await?;
    let (code, message) = status(&first)?;
    if (400..600).contains(&code) {
        return Ok(json!({"code":code,"error":message}));
    }
    match request.operation.as_str() {
        "define" => {
            ensure!(code == 150, "Expected DICT definition header");
            let count = message
                .split_whitespace()
                .next()
                .context("Missing definition count")?
                .parse::<usize>()?;
            ensure!(count <= MAX_ENTRIES, "Too many definitions");
            let mut entries = Vec::new();
            for _ in 0..count {
                let header = line(reader, &mut budget).await?;
                let (code, text) = status(&header)?;
                ensure!(code == 151, "Expected definition preface");
                let fields = definition_fields(text)?;
                ensure!(fields.len() >= 3, "Invalid definition preface");
                let text = block(reader, &mut budget).await?.join("\n");
                entries.push(json!({"word":fields[0],"database":fields[1],"database_description":fields[2],"text":text}));
            }
            finish(reader, &mut budget).await?;
            Ok(json!({"code":150,"definitions":entries}))
        }
        "match" | "databases" | "strategies" => {
            let expected = match request.operation.as_str() {
                "match" => 152,
                "databases" => 110,
                _ => 111,
            };
            ensure!(code == expected, "Unexpected DICT listing status");
            let count = message
                .split_whitespace()
                .next()
                .context("Missing list count")?
                .parse::<usize>()?;
            ensure!(count <= MAX_ENTRIES, "Too many list entries");
            let lines = block(reader, &mut budget).await?;
            ensure!(lines.len() == count, "DICT list count mismatch");
            let mut entries = Vec::new();
            for line in lines {
                let fields = wire::split_args(&line)
                    .map_err(|_| anyhow::anyhow!("Invalid listing fields"))?;
                ensure!(fields.len() == 2, "Invalid listing row");
                entries.push(if request.operation == "match" {
                    json!({"database":fields[0],"word":fields[1]})
                } else {
                    json!({"name":fields[0],"description":fields[1]})
                });
            }
            finish(reader, &mut budget).await?;
            Ok(json!({"code":code,"entries":entries}))
        }
        "info" | "server" | "help" => {
            ensure!(
                code == match request.operation.as_str() {
                    "info" => 112,
                    "help" => 113,
                    _ => 114,
                },
                "Unexpected DICT text status"
            );
            let text = block(reader, &mut budget).await?.join("\n");
            finish(reader, &mut budget).await?;
            Ok(json!({"code":code,"text":text}))
        }
        "client" => {
            ensure!(code == 250, "Unexpected CLIENT reply");
            Ok(json!({"code":code,"message":message}))
        }
        "status" => {
            ensure!(code == 210, "Unexpected STATUS reply");
            Ok(json!({"code":code,"message":message}))
        }
        "quit" => {
            ensure!(code == 221, "Unexpected QUIT reply");
            Ok(json!({"code":code,"message":message}))
        }
        _ => bail!("Unsupported DICT response"),
    }
}

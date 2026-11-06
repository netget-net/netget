//! Structured Beanstalkd requests and bounded, correlated responses.
use crate::server::beanstalkd::wire::{self, Command};
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};
use std::time::Duration;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt};
pub const DEADLINE: Duration = Duration::from_secs(30);
pub const MAX_REPLY_BYTES: usize = 1024 * 1024;
/// Model-originated requests that may follow one another: an answer to the event at this depth
/// is not sent, so a model that answers every response with another request stops here.
pub const MAX_FOLLOWUPS: u8 = 4;
#[derive(Debug)]
pub struct Request {
    pub command: Command,
    pub bytes: Vec<u8>,
}
impl Request {
    pub fn from_action(v: &Value) -> Result<Self> {
        let op = v["operation"].as_str().context("Missing operation")?;
        let number = |key: &str, default: Option<u64>| -> Result<u64> {
            v.get(key)
                .map(|v| {
                    v.as_u64()
                        .with_context(|| format!("{key} must be an unsigned integer"))
                })
                .unwrap_or_else(|| default.with_context(|| format!("Missing {key}")))
        };
        let tube = || -> Result<&str> {
            let tube = v["tube"].as_str().context("Missing tube")?;
            ensure!(wire::valid_tube_name(tube), "Invalid tube name");
            Ok(tube)
        };
        let id = || -> Result<u64> {
            let id = number("id", None)?;
            ensure!(id > 0, "Job id must be positive");
            Ok(id)
        };
        let priority = || number("priority", Some(1024));
        let delay = || number("delay", Some(0));
        let mut body = None;
        let line = match op {
            "put" => {
                let text = v["body"].as_str().context("Missing text body")?;
                ensure!(
                    text.len() <= wire::MAX_JOB_BYTES,
                    "Job body exceeds 65535 bytes"
                );
                body = Some(text);
                format!(
                    "put {} {} {} {}",
                    priority()?,
                    delay()?,
                    number("ttr", Some(60))?,
                    text.len()
                )
            }
            "use" | "watch" | "ignore" => format!("{op} {}", tube()?),
            "reserve" => {
                let seconds = number("timeout_secs", Some(0))?;
                ensure!(seconds <= 25, "Reservation timeout must be 0..=25 seconds");
                format!("reserve-with-timeout {seconds}")
            }
            "reserve_job" | "delete" | "touch" | "peek" | "kick_job" | "stats_job" => {
                format!("{} {}", op.replace('_', "-"), id()?)
            }
            "release" => format!("release {} {} {}", id()?, priority()?, delay()?),
            "bury" => format!("bury {} {}", id()?, priority()?),
            "kick" => format!("kick {}", number("count", Some(1))?),
            "stats_tube" => format!("stats-tube {}", tube()?),
            "pause_tube" => format!("pause-tube {} {}", tube()?, delay()?),
            "stats" | "list_tubes" | "list_tube_used" | "list_tubes_watched" | "peek_ready"
            | "peek_delayed" | "peek_buried" | "quit" => op.replace('_', "-"),
            _ => bail!("Unsupported Beanstalkd operation"),
        };
        ensure!(
            line.len() + 2 <= wire::MAX_LINE_BYTES,
            "Command header too long"
        );
        let command = wire::parse_command(&line);
        ensure!(
            !matches!(command, Command::BadFormat | Command::Unknown),
            "Invalid command arguments or numeric range"
        );
        let mut bytes = format!("{line}\r\n").into_bytes();
        if let Some(body) = body {
            bytes.extend_from_slice(body.as_bytes());
            bytes.extend_from_slice(b"\r\n");
        }
        Ok(Self { command, bytes })
    }
}
fn unsigned(text: &str) -> Result<u64> {
    ensure!(
        !text.is_empty() && text.bytes().all(|c| c.is_ascii_digit()),
        "Invalid unsigned response number"
    );
    Ok(text.parse()?)
}
fn job_id(text: &str) -> Result<u64> {
    let id = unsigned(text)?;
    ensure!(id > 0, "Job ID must be positive");
    Ok(id)
}
async fn line<R: AsyncBufRead + Unpin>(r: &mut R) -> Result<String> {
    let mut bytes = Vec::new();
    loop {
        let chunk = r.fill_buf().await?;
        ensure!(!chunk.is_empty(), "Truncated Beanstalkd response");
        let n = chunk
            .iter()
            .position(|b| *b == b'\n')
            .map(|n| n + 1)
            .unwrap_or(chunk.len());
        ensure!(
            bytes.len() + n <= wire::MAX_LINE_BYTES,
            "Beanstalkd response header too long"
        );
        bytes.extend_from_slice(&chunk[..n]);
        r.consume(n);
        if bytes.ends_with(b"\n") {
            ensure!(bytes.ends_with(b"\r\n"), "Beanstalkd requires CRLF");
            bytes.truncate(bytes.len() - 2);
            return Ok(String::from_utf8(bytes)?);
        }
    }
}
pub async fn response<R: AsyncBufRead + Unpin>(reader: &mut R, request: &Request) -> Result<Value> {
    tokio::time::timeout(DEADLINE, async {
        let header = line(reader).await?;
        let args: Vec<&str> = header.split(' ').collect();
        let status = args.first().copied().context("Missing status")?;
        let mut wire = format!("{header}\r\n").into_bytes();
        let mut payload = None;
        if matches!(status, "RESERVED" | "FOUND" | "OK") {
            ensure!(
                args.len() == if status == "OK" { 2 } else { 3 },
                "Malformed byte-counted response header"
            );
            let length = usize::try_from(unsigned(args.last().context("Missing byte count")?)?)?;
            ensure!(
                length <= MAX_REPLY_BYTES,
                "Beanstalkd reply body exceeds limit"
            );
            if status != "OK" {
                ensure!(
                    length <= wire::MAX_JOB_BYTES,
                    "Beanstalkd job exceeds limit"
                );
            }
            let mut body = vec![0; length];
            reader.read_exact(&mut body).await?;
            let mut ending = [0; 2];
            reader.read_exact(&mut ending).await?;
            ensure!(ending == *b"\r\n", "Body missing CRLF");
            wire.extend_from_slice(&body);
            wire.extend_from_slice(&ending);
            payload = Some(
                String::from_utf8(body)
                    .context("Non-UTF8 jobs are outside this client's text payload scope")?,
            );
        }
        let global_error = matches!(
            status,
            "OUT_OF_MEMORY"
                | "INTERNAL_ERROR"
                | "BAD_FORMAT"
                | "UNKNOWN_COMMAND"
                | "JOB_TOO_BIG"
                | "EXPECTED_CRLF"
        ) && args.len() == 1;
        let fits = match &request.command {
            Command::Use(tube) => args == vec!["USING", tube.as_str()],
            Command::Watch(_) => status == "WATCHING" && args.len() == 2,
            Command::Ignore(_) => {
                status == "NOT_IGNORED" && args.len() == 1
                    || status == "WATCHING" && args.len() == 2
            }
            Command::ListTubeUsed => {
                status == "USING" && args.len() == 2 && wire::valid_tube_name(args[1])
            }
            Command::ListTubesWatched => status == "OK" && args.len() == 2,
            _ => wire::reply_fits(&request.command, &wire),
        };
        ensure!(
            global_error || fits,
            "Unexpected Beanstalkd response for request"
        );
        let mut result = json!({"status":status});
        if status == "OK" {
            let value = parse_yaml(
                payload.as_deref().context("Missing YAML payload")?,
                matches!(
                    request.command,
                    Command::ListTubes | Command::ListTubesWatched
                ),
            )?;
            match request.command {
                Command::ListTubes | Command::ListTubesWatched => ensure!(
                    value
                        .as_array()
                        .is_some_and(|v| v.iter().all(Value::is_string)),
                    "Expected tube-name list"
                ),
                _ => ensure!(value.is_object(), "Expected stats mapping"),
            }
            result["data"] = value;
        } else if matches!(status, "RESERVED" | "FOUND") {
            ensure!(args.len() == 3, "Malformed job response");
            let id = job_id(args[1])?;
            if let Command::Peek(expected) | Command::ReserveJob(expected) = request.command {
                ensure!(id == expected, "Reply job ID does not match request");
            }
            result["id"] = json!(id);
            result["body"] = json!(payload);
        } else if args.len() == 2 {
            match status {
                "USING" => result["tube"] = json!(args[1]),
                "WATCHING" | "KICKED" => {
                    let count = unsigned(args[1])?;
                    ensure!(
                        status != "WATCHING" || count > 0,
                        "Empty watch set is invalid"
                    );
                    result["count"] = json!(count);
                }
                "INSERTED" | "BURIED" => result["id"] = json!(job_id(args[1])?),
                _ => bail!("Unknown status arguments"),
            }
        }
        Ok(result)
    })
    .await
    .context("Beanstalkd response deadline exceeded")?
}

/// Deserialize scalar values without ever visiting a sequence/map's children.
/// Deserializing into Value first would allocate nested graphs before rejecting them.
struct Scalar(Value);
impl<'de> serde::Deserialize<'de> for Scalar {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        struct ScalarVisitor;
        impl<'de> serde::de::Visitor<'de> for ScalarVisitor {
            type Value = Scalar;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a flat YAML scalar")
            }
            fn visit_bool<E: serde::de::Error>(self, v: bool) -> std::result::Result<Scalar, E> {
                Ok(Scalar(json!(v)))
            }
            fn visit_i64<E: serde::de::Error>(self, v: i64) -> std::result::Result<Scalar, E> {
                Ok(Scalar(json!(v)))
            }
            fn visit_u64<E: serde::de::Error>(self, v: u64) -> std::result::Result<Scalar, E> {
                Ok(Scalar(json!(v)))
            }
            fn visit_f64<E: serde::de::Error>(self, v: f64) -> std::result::Result<Scalar, E> {
                serde_json::Number::from_f64(v)
                    .map(|n| Scalar(Value::Number(n)))
                    .ok_or_else(|| E::custom("Nonfinite YAML number"))
            }
            fn visit_str<E: serde::de::Error>(self, v: &str) -> std::result::Result<Scalar, E> {
                Ok(Scalar(json!(v)))
            }
            fn visit_string<E: serde::de::Error>(
                self,
                v: String,
            ) -> std::result::Result<Scalar, E> {
                Ok(Scalar(Value::String(v)))
            }
            fn visit_unit<E: serde::de::Error>(self) -> std::result::Result<Scalar, E> {
                Ok(Scalar(Value::Null))
            }
            // The default visit_seq, visit_map and visit_enum reject immediately.
        }
        deserializer.deserialize_any(ScalarVisitor)
    }
}

/// Beanstalkd's YAML payload is a flat list or scalar mapping. Parse each scalar
/// independently so aliases/anchors cannot expand across records.
pub fn parse_yaml(text: &str, list: bool) -> Result<Value> {
    let text = text
        .strip_prefix("---\n")
        .context("Missing YAML document marker")?;
    let rows: Vec<&str> = text.lines().collect();
    ensure!(
        rows.len() <= wire::MAX_YAML_ENTRIES,
        "Too many YAML entries"
    );
    if list {
        let mut out = Vec::new();
        for row in rows {
            if row.trim().is_empty() {
                continue;
            }
            let text = row.strip_prefix("- ").context("Expected flat tube list")?;
            let value = if wire::valid_tube_name(text) {
                json!(text)
            } else {
                let Scalar(value) = serde_yaml::from_str(text)?;
                value
            };
            let name = value.as_str().context("Tube name must be text")?;
            ensure!(wire::valid_tube_name(name), "Invalid tube name in list");
            out.push(value);
        }
        Ok(Value::Array(out))
    } else {
        let mut out = serde_json::Map::new();
        for row in rows {
            if row.trim().is_empty() {
                continue;
            }
            let (key, text) = row
                .split_once(": ")
                .context("Expected flat stats mapping")?;
            ensure!(
                !key.is_empty()
                    && key
                        .bytes()
                        .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_'),
                "Invalid stats key"
            );
            // v1.12 emits uname fields without YAML quoting: os starts with '#'
            // on Linux and contains ': ' on Darwin. Treat only these protocol text
            // fields as opaque strings, never deserialize arbitrary nested values.
            let value = if matches!(key, "hostname" | "os" | "platform")
                && !text.starts_with(['\"', '\''])
            {
                json!(text)
            } else if matches!(key, "tube" | "name") && wire::valid_tube_name(text) {
                json!(text)
            } else {
                let Scalar(value) = serde_yaml::from_str(text)?;
                value
            };
            ensure!(
                out.insert(key.into(), value).is_none(),
                "Duplicate stats key"
            );
        }
        Ok(Value::Object(out))
    }
}

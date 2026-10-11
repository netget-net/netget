//! Server-sent events (WHATWG HTML §9.2, `text/event-stream`): encoding for the server and the
//! event-stream parser the client uses. Shared so both roles agree on the format byte for byte.
use anyhow::{ensure, Result};

/// A line the parser will hold before giving up on the stream.
pub const MAX_LINE_BYTES: usize = 64 * 1024;
/// One event's data at most.
pub const MAX_EVENT_BYTES: usize = 1024 * 1024;

fn single_line(field: &str, value: &str) -> Result<()> {
    ensure!(
        !value.contains(['\r', '\n']),
        "{field} is one line: it may not contain CR or LF"
    );
    Ok(())
}

/// One event: `event:`, `id:`, `retry:` and a `data:` line per line of `data`, then a blank line.
pub fn encode_event(
    event: Option<&str>,
    id: Option<&str>,
    data: &str,
    retry_ms: Option<u64>,
) -> Result<Vec<u8>> {
    ensure!(
        data.len() <= MAX_EVENT_BYTES,
        "data is at most {MAX_EVENT_BYTES} bytes"
    );
    let mut out = String::with_capacity(data.len() + 64);
    if let Some(event) = event.filter(|e| !e.is_empty()) {
        single_line("event", event)?;
        out.push_str("event: ");
        out.push_str(event);
        out.push('\n');
    }
    if let Some(id) = id {
        single_line("id", id)?;
        ensure!(
            !id.contains('\0'),
            "id may not contain NUL (the client would ignore it)"
        );
        out.push_str("id: ");
        out.push_str(id);
        out.push('\n');
    }
    if let Some(retry) = retry_ms {
        out.push_str(&format!("retry: {retry}\n"));
    }
    for line in data.split("\r\n").flat_map(|l| l.split(['\r', '\n'])) {
        out.push_str("data: ");
        out.push_str(line);
        out.push('\n');
    }
    out.push('\n');
    Ok(out.into_bytes())
}

/// A comment line (`: text`), which clients ignore; servers send it to keep a stream alive.
pub fn encode_comment(text: &str) -> Result<Vec<u8>> {
    single_line("comment", text)?;
    Ok(format!(": {text}\n\n").into_bytes())
}

/// A `retry:` field on its own, telling the client how long to wait before reconnecting.
pub fn encode_retry(retry_ms: u64) -> Vec<u8> {
    format!("retry: {retry_ms}\n\n").into_bytes()
}

/// One dispatched event.
#[derive(Debug, Clone, PartialEq)]
pub struct Event {
    /// The event type (`message` when the stream named none).
    pub event: String,
    pub data: String,
    /// The last event ID buffer after this event, which a reconnect sends as `Last-Event-ID`.
    pub last_event_id: String,
}

/// The WHATWG event-stream interpretation, fed bytes as they arrive.
#[derive(Default)]
pub struct Parser {
    pending: Vec<u8>,
    started: bool,
    skip_lf: bool,
    event: String,
    data: String,
    has_data: bool,
    pub last_event_id: String,
    /// The most recent valid `retry:` value.
    pub retry_ms: Option<u64>,
}

impl Parser {
    pub fn with_last_event_id(id: &str) -> Self {
        Self {
            last_event_id: id.to_string(),
            ..Self::default()
        }
    }

    /// Start a new connection's stream (the last event ID and retry carry over).
    pub fn reset_stream(&mut self) {
        self.pending.clear();
        self.started = false;
        self.skip_lf = false;
        self.event.clear();
        self.data.clear();
        self.has_data = false;
    }

    /// Feed bytes; returns the events they completed. Fails on a line or event over its bound.
    pub fn feed(&mut self, bytes: &[u8]) -> Result<Vec<Event>> {
        let mut out = Vec::new();
        for &b in bytes {
            if self.skip_lf {
                self.skip_lf = false;
                if b == b'\n' {
                    continue;
                }
            }
            match b {
                b'\r' | b'\n' => {
                    self.skip_lf = b == b'\r';
                    let line = std::mem::take(&mut self.pending);
                    if let Some(e) = self.line(&line)? {
                        out.push(e);
                    }
                }
                _ => {
                    ensure!(
                        self.pending.len() < MAX_LINE_BYTES,
                        "an event-stream line longer than {MAX_LINE_BYTES} bytes"
                    );
                    self.pending.push(b);
                }
            }
        }
        Ok(out)
    }

    fn line(&mut self, raw: &[u8]) -> Result<Option<Event>> {
        let mut line = String::from_utf8_lossy(raw).into_owned();
        if !self.started {
            self.started = true;
            if let Some(rest) = line.strip_prefix('\u{feff}') {
                line = rest.to_string();
            }
        }
        if line.is_empty() {
            return Ok(self.dispatch());
        }
        if line.starts_with(':') {
            return Ok(None);
        }
        let (field, value) = match line.split_once(':') {
            Some((f, v)) => (f.to_string(), v.strip_prefix(' ').unwrap_or(v).to_string()),
            None => (line.clone(), String::new()),
        };
        match field.as_str() {
            "event" => self.event = value,
            "data" => {
                ensure!(
                    self.data.len() + value.len() < MAX_EVENT_BYTES,
                    "an event's data over {MAX_EVENT_BYTES} bytes"
                );
                self.data.push_str(&value);
                self.data.push('\n');
                self.has_data = true;
            }
            "id" if !value.contains('\0') => self.last_event_id = value,
            "retry" if !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()) => {
                self.retry_ms = value.parse().ok();
            }
            _ => {}
        }
        Ok(None)
    }

    fn dispatch(&mut self) -> Option<Event> {
        let event = std::mem::take(&mut self.event);
        if !self.has_data {
            return None;
        }
        self.has_data = false;
        let mut data = std::mem::take(&mut self.data);
        data.pop();
        Some(Event {
            event: if event.is_empty() {
                "message".into()
            } else {
                event
            },
            data,
            last_event_id: self.last_event_id.clone(),
        })
    }
}

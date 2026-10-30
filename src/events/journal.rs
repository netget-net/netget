//! Bounded, process-local event history shared by MCP poll, streams and channels.
//! Notifications are observations: reading them never claims or resolves work.

use serde_json::{json, Map, Value};
use std::collections::VecDeque;
use std::sync::Mutex;
use tokio::sync::watch;

pub const LLM_PENDING: &str = "llm.request.pending";
pub const INTERCEPT_PENDING: &str = "intercept.pending";
pub const ACCESS_RECORDED: &str = "access_log.recorded";
pub const EVENT_HISTORY_LIMIT: usize = 1024;

struct Occurrence {
    sequence: u64,
    unix_ms: u64,
    value: Value,
}

struct History {
    sequence: u64,
    entries: VecDeque<Occurrence>,
}

pub struct EventJournal {
    epoch: String,
    history: Mutex<History>,
    changed: watch::Sender<u64>,
}

pub struct EventBatch {
    pub events: Vec<Value>,
    pub start_cursor: String,
    pub cursor: String,
    pub truncated: bool,
    pub has_more: bool,
}

impl Default for EventJournal {
    fn default() -> Self {
        Self {
            epoch: format!("{:016x}", rand::random::<u64>()),
            history: Mutex::new(History {
                sequence: 0,
                entries: VecDeque::new(),
            }),
            changed: watch::channel(0).0,
        }
    }
}

impl EventJournal {
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.changed.subscribe()
    }

    fn cursor(&self, sequence: u64) -> String {
        format!("{}:{sequence}", self.epoch)
    }

    pub fn current_cursor(&self) -> String {
        self.cursor(
            self.history
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .sequence,
        )
    }

    /// Payloads contain bounded identifiers and deadlines, never wire bodies or prompts.
    pub fn publish(&self, name: &'static str, data: Value) {
        let now = chrono::Utc::now();
        let mut history = self.history.lock().unwrap_or_else(|e| e.into_inner());
        history.sequence += 1;
        let sequence = history.sequence;
        history.entries.push_back(Occurrence {
            sequence,
            unix_ms: now.timestamp_millis().max(0) as u64,
            value: json!({
                "eventId": format!("{}:{sequence}", self.epoch), "name": name,
                "timestamp": now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                "data": data,
            }),
        });
        while history.entries.len() > EVENT_HISTORY_LIMIT {
            history.entries.pop_front();
        }
        self.changed.send_replace(sequence);
    }

    /// A null cursor starts at now. Foreign/restarted cursors reset to now with a gap.
    pub fn read(
        &self,
        name: &str,
        arguments: &Map<String, Value>,
        cursor: Option<&str>,
        max_age_ms: Option<u64>,
        limit: usize,
    ) -> Result<EventBatch, &'static str> {
        let history = self.history.lock().unwrap_or_else(|e| e.into_inner());
        let tail = history.sequence;
        let (mut position, mut truncated) = match cursor {
            None => (tail, false),
            Some(cursor) => {
                let (epoch, sequence) = cursor.split_once(':').ok_or("invalid event cursor")?;
                let sequence = sequence
                    .parse::<u64>()
                    .map_err(|_| "invalid event cursor")?;
                if epoch != self.epoch || sequence > tail {
                    (tail, true)
                } else {
                    (sequence, false)
                }
            }
        };
        let oldest = history
            .entries
            .front()
            .map_or(tail, |e| e.sequence.saturating_sub(1));
        if position < oldest {
            position = oldest;
            truncated = true;
        }
        if cursor.is_some() {
            if let Some(age) = max_age_ms {
                let floor =
                    (chrono::Utc::now().timestamp_millis().max(0) as u64).saturating_sub(age);
                let initial_position = position;
                for event in history
                    .entries
                    .iter()
                    .filter(|e| e.sequence > initial_position && e.unix_ms < floor)
                {
                    // Publication order is authoritative even if the wall clock moves.
                    position = position.max(event.sequence);
                    truncated = true;
                }
            }
        }
        let start_cursor = self.cursor(position);
        let mut events = Vec::new();
        let mut has_more = false;
        for event in history.entries.iter().filter(|e| e.sequence > position) {
            let matches = (name == "*" || event.value["name"] == name)
                && arguments
                    .iter()
                    .all(|(key, value)| event.value["data"].get(key) == Some(value));
            if matches {
                if events.len() == limit {
                    has_more = true;
                    break;
                }
                let mut value = event.value.clone();
                value["cursor"] = json!(self.cursor(event.sequence));
                events.push(value);
            }
        }
        let end = if has_more {
            events
                .last()
                .and_then(|e| e["cursor"].as_str())
                .unwrap_or(&start_cursor)
                .to_owned()
        } else {
            self.cursor(tail)
        };
        Ok(EventBatch {
            events,
            start_cursor,
            cursor: end,
            truncated,
            has_more,
        })
    }
}

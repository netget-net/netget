//! What has already happened on one connection, kept so the model can be shown it.
//!
//! Every network event used to reach the model alone, so a telnet peer asking "what did I
//! just say?" was answered from a prompt holding only that question. An [`ExchangeHistory`]
//! records each event on a connection together with whatever answered it — the model, a
//! script, a static rule, a person at the dashboard — and each action an operator sent down
//! the connection unprompted. [`crate::state::app_state::AppState::record_access_log`] is the
//! one place every one of those passes, so that is where entries are written; the two LLM
//! entry points render them ahead of the event being answered.
//!
//! Bounded three ways, because a long session must not grow a prompt without limit:
//! - each entry is cut to [`HISTORY_ENTRY_MAX_CHARS`] when it is recorded;
//! - a connection keeps at most the instance's entry limit ([`crate::protocol::metadata::HistoryMode`]);
//! - the rendered block stops at [`HISTORY_PROMPT_BUDGET_CHARS`], newest entries kept.
//!
//! An exchange carrying credentials is recorded as a placeholder that says so and nothing else,
//! so a password typed once is not repeated into every later prompt on the connection.
//!
//! The rendered block deliberately contains no line beginning `Event ID:` or `Event:` and no
//! `Context data:` / `Data:` label: those mark the *current* trigger, and both the prompt's
//! reader and the test mock find the event by them.

use std::collections::VecDeque;

use serde_json::Value;

/// The most characters the rendered history block may add to one prompt.
pub const HISTORY_PROMPT_BUDGET_CHARS: usize = 4096;

/// The most characters one recorded entry keeps; longer exchanges are cut with a marker.
pub const HISTORY_ENTRY_MAX_CHARS: usize = 600;

/// The access-log response recorded for an event a batch answered together with a later one
/// (see `call_llm_batch`), so history says so instead of "answered with: nothing".
pub const ANSWERED_WITH_NEXT: &str = "answered_together_with_next";

/// Event type recorded for an action an operator sent down the connection by hand
/// (`send_to_peer`, `send_to_client`, the dashboard's `[ send ]`).
pub const INJECTED_ACTION_EVENT: &str = "injected_action";

/// Event type recorded for a client's first model call, the one that acts on its instruction
/// before any event has arrived. Without it the first thing a client did was in nobody's
/// history, and every later event was answered by a model that could not see it had already
/// started the script.
pub const CLIENT_STARTED_EVENT: &str = "client_started";

/// What separates an event from its answer inside one recorded entry. It begins with a real
/// newline, which compact JSON can never contain, so it marks our own text and nothing a peer
/// sent; [`ExchangeHistory::render_for_client`] relies on that to reword it.
const ANSWERED_WITH: &str = "\n   answered with: ";

/// The client wording of [`ANSWERED_WITH`]: on a client the "answer" is what the client
/// itself did next.
const CLIENT_DID: &str = "\n   you did: ";

/// One exchange rendered as a history entry, ready to append.
///
/// Rendering redacts and serialises the event and its answer, which is most of what recording
/// costs, so `AppState::record_access_log` renders before it takes the state lock and only
/// appends under it.
#[derive(Debug, Clone)]
pub struct RenderedEntry(String);

impl RenderedEntry {
    pub fn new(event_type: &str, request: &Value, response: &[Value]) -> Self {
        Self(render_entry(event_type, request, response))
    }
}

#[derive(Debug, Clone)]
struct HistoryEntry {
    /// 1-based position of this entry among everything ever recorded on the connection.
    seq: u64,
    text: String,
}

/// The recorded exchange on one connection (one client, on the client side).
#[derive(Debug, Clone, Default)]
pub struct ExchangeHistory {
    entries: VecDeque<HistoryEntry>,
    recorded: u64,
}

impl ExchangeHistory {
    pub fn new() -> Self {
        Self::default()
    }

    /// How many entries are currently kept.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// How many entries have ever been recorded on this connection, kept or not.
    pub fn recorded(&self) -> u64 {
        self.recorded
    }

    /// Record one exchange, keeping at most `limit` entries. A `limit` of 0 records nothing.
    pub fn record(&mut self, event_type: &str, request: &Value, response: &[Value], limit: u16) {
        if limit == 0 {
            return;
        }
        self.record_rendered(RenderedEntry::new(event_type, request, response), limit);
    }

    /// [`Self::record`] for an exchange already rendered with [`RenderedEntry::new`].
    pub fn record_rendered(&mut self, entry: RenderedEntry, limit: u16) {
        if limit == 0 {
            return;
        }
        self.recorded += 1;
        self.entries.push_back(HistoryEntry {
            seq: self.recorded,
            text: entry.0,
        });
        self.trim(limit);
    }

    /// Drop the oldest entries beyond `limit` (used when an instance's limit is lowered).
    pub fn trim(&mut self, limit: u16) {
        while self.entries.len() > limit as usize {
            self.entries.pop_front();
        }
    }

    /// The block shown to the model ahead of the current event, or `None` when there is
    /// nothing earlier to show. At most `limit` entries, newest kept, within
    /// [`HISTORY_PROMPT_BUDGET_CHARS`].
    pub fn render(&self, limit: u16) -> Option<String> {
        self.render_with(limit, Perspective::Server)
    }

    /// [`Self::render`] for a client, which reads its history as progress through its own
    /// instruction rather than as requests it answered.
    ///
    /// A client's instruction is a script ("send PING, then GET mykey, then stop") and the
    /// model is asked again on every reply, so its record is worded as what the client did and
    /// the header says all of it is done. That is the accurate wording, not a cure: llama3.1:8b
    /// re-sends the script on replies with or without it (6 of 8 seeded runs before, 6 of 8
    /// after, 31 October 2026), with both commands listed as already sent directly above the
    /// reply it was answering. What stops the restart is structural and lives elsewhere:
    /// [`crate::client::restart_check`] asks before an answer that repeats the opening is sent.
    pub fn render_for_client(&self, limit: u16) -> Option<String> {
        self.render_with(limit, Perspective::Client)
    }

    fn render_with(&self, limit: u16, perspective: Perspective) -> Option<String> {
        if limit == 0 || self.entries.is_empty() {
            return None;
        }
        let mut chosen: Vec<&HistoryEntry> = Vec::new();
        let mut used = 0usize;
        for entry in self.entries.iter().rev().take(limit as usize) {
            let cost = entry.text.len() + 8;
            if used + cost > HISTORY_PROMPT_BUDGET_CHARS && !chosen.is_empty() {
                break;
            }
            used += cost;
            chosen.push(entry);
        }
        chosen.reverse();

        let omitted = self.recorded - chosen.len() as u64;
        let mut out = String::from(match perspective {
            Perspective::Server => "Earlier on this connection, oldest first",
            Perspective::Client => {
                "Earlier in this session, oldest first: everything that arrived and what you did"
            }
        });
        if omitted > 0 {
            out.push_str(&format!(
                " ({} shown; {} earlier not shown — keep anything that must outlive this in memory)",
                chosen.len(),
                omitted
            ));
        }
        out.push_str(match perspective {
            Perspective::Server => {
                ". These were already handled and are shown for context only; do not answer \
                 them again.\n"
            }
            Perspective::Client => {
                ". All of it is done: every action listed was already sent, so do not send it \
                 again. Your instruction is the plan for the whole session, not a new request \
                 on each event: continue it from where this leaves off, and once every step of \
                 it is done answer with no actions (or disconnect, if it says to finish).\n"
            }
        });
        for entry in chosen {
            let text = match perspective {
                Perspective::Server => entry.text.clone(),
                Perspective::Client => entry.text.replace(ANSWERED_WITH, CLIENT_DID),
            };
            out.push_str(&format!("#{} {}\n", entry.seq, text));
        }
        Some(out)
    }
}

/// Whose history is being rendered; see [`ExchangeHistory::render_for_client`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Perspective {
    Server,
    Client,
}

fn render_entry(event_type: &str, request: &Value, response: &[Value]) -> String {
    let private = crate::utils::redact::contains_credentials(request)
        || response.iter().any(|action| {
            action.get("type").and_then(Value::as_str) == Some("private_handler_result")
        });
    if private {
        return format!(
            "{} — carried credentials; its content is not repeated here",
            event_type
        );
    }

    let text = if event_type == INJECTED_ACTION_EVENT {
        // The request is the action the operator sent; the response is its outcome.
        format!("operator sent {}", render_action(request))
    } else if event_type == CLIENT_STARTED_EVENT {
        // No event arrived; the client acted on its instruction alone.
        let answers: Vec<String> = response.iter().map(render_action).collect();
        format!(
            "{} (no event yet: acting on the instruction){}{}",
            event_type,
            ANSWERED_WITH,
            if answers.is_empty() {
                "nothing".to_string()
            } else {
                answers.join("; ")
            }
        )
    } else if response.iter().any(|action| {
        action
            .get("type")
            .and_then(Value::as_str)
            .is_some_and(|t| t.starts_with("FAILED"))
    }) {
        // A failed event is recorded with a `FAILED: …` envelope carrying the backend error.
        // Shown as answered, under a header saying everything was handled, it told the model
        // the peer had been answered — and leaked the error text into the prompt.
        format!(
            "{} {}\n   not answered: handling it failed",
            event_type,
            compact(&crate::utils::redact::redact_sensitive(request))
        )
    } else if response.len() == 1
        && response[0].get("type").and_then(Value::as_str) == Some(ANSWERED_WITH_NEXT)
    {
        format!(
            "{} {}\n   answered together with the next",
            event_type,
            compact(&crate::utils::redact::redact_sensitive(request))
        )
    } else {
        let answers: Vec<String> = response.iter().map(render_action).collect();
        let answered = if answers.is_empty() {
            "nothing".to_string()
        } else {
            answers.join("; ")
        };
        format!(
            "{} {}{}{}",
            event_type,
            compact(&crate::utils::redact::redact_sensitive(request)),
            ANSWERED_WITH,
            answered
        )
    };
    crate::utils::truncate::truncate_with_suffix(&text, HISTORY_ENTRY_MAX_CHARS, " …(cut)")
}

/// `send_telnet_message {"message":"hi"}` — the action's name, then its other fields.
fn render_action(action: &Value) -> String {
    let action = crate::utils::redact::redact_sensitive(action);
    match action.as_object() {
        Some(fields) => {
            let name = fields
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or("action")
                .to_string();
            let rest: serde_json::Map<String, Value> = fields
                .iter()
                .filter(|(key, _)| key.as_str() != "type")
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect();
            if rest.is_empty() {
                name
            } else {
                format!("{} {}", name, compact(&Value::Object(rest)))
            }
        }
        None => compact(&action),
    }
}

fn compact(value: &Value) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| value.to_string())
}

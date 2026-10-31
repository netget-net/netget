//! Reusing the model's answers: what memoisation and `export_rules` share.
//!
//! Two features answer an event the model has already answered, without asking it again:
//!
//! - **Memoisation** ([`Memo`]): an opt-in per-instance cache. An event whose type and data
//!   (less its per-request fields) match one the model answered within the TTL is answered
//!   with the same actions, re-rendered for this event, and recorded as answered by `cache`.
//! - **Record → rules** (`crate::llm::rule_export`): turns the model-authored answers in the
//!   access log into `event_handlers`, so the same traffic replays with no model at all.
//!
//! Both have to know which parts of an event are *per request* — a DNS `query_id`, a JSON-RPC
//! `id`, an IMAP `tag`, the client's source port — because those differ on every request
//! without changing what the answer should be, and the answer usually has to carry them back.
//! [`PER_REQUEST_FIELDS`] names them. They are only ever **top-level** event fields: a nested
//! `id` inside a request body is the body's data, and treating it as noise would make two
//! requests for different resources look identical. Where a per-request field's value appears
//! in an answer it is replaced by a `{{event.<field>}}` reference
//! ([`template_per_request_echoes`]), so a replay echoes the new request's value instead of
//! the recorded one.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Top-level event fields that identify one request rather than describe it: correlation
/// ids the answer echoes, and the peer's ephemeral port. Never part of a memo key or a rule's
/// `match`; echoed into answers by reference.
///
/// Deliberately a short, exact list. A name that is not here is treated as describing the
/// request, which costs at worst a cache miss or a more specific rule. A name wrongly here
/// would make two different requests share an answer.
pub const PER_REQUEST_FIELDS: &[&str] = &[
    "id",
    "xid",
    "txid",
    "tag",
    "nonce",
    "seq",
    "query_id",
    "request_id",
    "transaction_id",
    "message_id",
    "msg_id",
    "invoke_id",
    "correlation_id",
    "stream_id",
    "packet_id",
    "connection_id",
    "client_port",
    "remote_port",
    "source_port",
    "src_port",
    "peer_port",
];

/// Whether a top-level event field identifies one request (see [`PER_REQUEST_FIELDS`]).
pub fn is_per_request_field(name: &str) -> bool {
    PER_REQUEST_FIELDS.contains(&name)
}

/// Top-level event fields naming who sent the request rather than what it asks. A rule
/// conditions on one only where the recorded answers actually differed by it.
pub const PEER_ADDRESS_FIELDS: &[&str] = &[
    "client_ip",
    "client_addr",
    "remote_ip",
    "remote_addr",
    "source_ip",
    "source_addr",
    "src_ip",
    "src_addr",
    "peer_ip",
    "peer_addr",
    "peer",
    "local_addr",
];

/// Whether a top-level event field names the peer (see [`PEER_ADDRESS_FIELDS`]).
pub fn is_peer_address_field(name: &str) -> bool {
    PEER_ADDRESS_FIELDS.contains(&name)
}

/// Whether `key` can be written in a `{{event.…}}` reference or a `match` path: no `.`,
/// no braces, no surrounding whitespace, not empty, not all digits (that reads as an index).
pub fn is_addressable_key(key: &str) -> bool {
    !key.is_empty()
        && key.trim() == key
        && !key.contains(['.', '{', '}'])
        && !key.chars().all(|c| c.is_ascii_digit())
}

/// The value a per-request field may be echoed as: a non-empty string or a number. Booleans,
/// nulls and empty strings are far too common to be read as an echo.
fn echoable(value: &Value) -> bool {
    match value {
        Value::String(text) => !text.is_empty(),
        Value::Number(_) => true,
        _ => false,
    }
}

/// Whether a value is unlikely to appear in an answer by coincidence: a number of magnitude
/// 1000 or more, or a string of six characters or more. A JSON-RPC `id` of `1` beside a
/// `"result": 1` is the case this keeps apart.
fn distinctive(value: &Value) -> bool {
    match value {
        Value::Number(n) => n.as_f64().is_some_and(|f| f.abs() >= 1000.0),
        Value::String(text) => text.chars().count() >= 6,
        _ => false,
    }
}

/// How sure an echo has to be before a recorded value is replaced by a reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EchoEvidence {
    /// One answer is all there is: replace a leaf only where its key names the field
    /// (`"query_id": 4660` for `query_id`) or the value is [`distinctive`].
    SingleAnswer,
    /// The caller has several answers and checks them against each other afterwards: any
    /// equal leaf is a candidate.
    Corroborated,
}

/// Replace, anywhere in `actions`, a string or number leaf equal to the value of one of
/// `fields` (top-level fields of `request`) with a whole-string `{{event.<field>}}` reference.
/// A whole-string reference keeps the type, so a numeric `query_id` is rendered back as a
/// number. Only exact leaf equality counts; a value inside a longer string is left alone, and
/// an action's `type` is never touched. `evidence` decides how sure a match must be.
///
/// Where two fields carry the same value the first in `fields` order wins.
pub fn template_fields(
    request: &Value,
    actions: &[Value],
    fields: &[String],
    evidence: EchoEvidence,
) -> Vec<Value> {
    let Some(map) = request.as_object() else {
        return actions.to_vec();
    };
    let candidates: Vec<(&str, &Value, String)> = fields
        .iter()
        .filter(|field| is_addressable_key(field))
        .filter_map(|field| {
            map.get(field.as_str())
                .filter(|value| echoable(value))
                .map(|value| (field.as_str(), value, format!("{{{{event.{field}}}}}")))
        })
        .collect();
    if candidates.is_empty() {
        return actions.to_vec();
    }
    actions
        .iter()
        .map(|action| replace_leaves(action, None, &candidates, evidence))
        .collect()
}

fn replace_leaves(
    value: &Value,
    key: Option<&str>,
    candidates: &[(&str, &Value, String)],
    evidence: EchoEvidence,
) -> Value {
    match value {
        Value::String(_) | Value::Number(_) => candidates
            .iter()
            .find(|(field, candidate, _)| {
                *candidate == value
                    && (evidence == EchoEvidence::Corroborated
                        || key == Some(*field)
                        || distinctive(value))
            })
            .map(|(_, _, reference)| Value::String(reference.clone()))
            .unwrap_or_else(|| value.clone()),
        Value::Array(items) => Value::Array(
            items
                .iter()
                .map(|item| replace_leaves(item, None, candidates, evidence))
                .collect(),
        ),
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(name, item)| {
                    // The action's own name is never an echo.
                    if name == "type" {
                        (name.clone(), item.clone())
                    } else {
                        (
                            name.clone(),
                            replace_leaves(item, Some(name), candidates, evidence),
                        )
                    }
                })
                .collect(),
        ),
        other => other.clone(),
    }
}

/// The request's top-level per-request fields, in a stable order.
pub fn per_request_fields_of(request: &Value) -> Vec<String> {
    let mut fields: Vec<String> = request
        .as_object()
        .map(|map| {
            map.keys()
                .filter(|key| is_per_request_field(key))
                .cloned()
                .collect()
        })
        .unwrap_or_default();
    fields.sort_by_key(|field| {
        PER_REQUEST_FIELDS
            .iter()
            .position(|known| known == field)
            .unwrap_or(usize::MAX)
    });
    fields
}

/// [`template_fields`] over the request's per-request fields, for a single answer.
pub fn template_per_request_echoes(request: &Value, actions: &[Value]) -> Vec<Value> {
    template_fields(
        request,
        actions,
        &per_request_fields_of(request),
        EchoEvidence::SingleAnswer,
    )
}

/// Canonical JSON: object keys sorted at every level, so two events that differ only in key
/// order produce the same text whatever map ordering serde_json was built with.
pub fn canonical_json(value: &Value) -> String {
    let mut out = String::new();
    write_canonical(value, &mut out);
    out
}

fn write_canonical(value: &Value, out: &mut String) {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push('{');
            for (i, key) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(key).unwrap_or_default());
                out.push(':');
                write_canonical(&map[*key], out);
            }
            out.push('}');
        }
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(item, out);
            }
            out.push(']');
        }
        other => out.push_str(&other.to_string()),
    }
}

/// Whether an answer may be replayed: it names at least one action, every action is the
/// protocol's own or `show_message`, and nothing in it carries a credential. Memory writes,
/// scheduled tasks, logs and instance management are side effects of *answering once*; a
/// replay that repeated them would be doing more than answering.
pub fn replayable_answer(actions: &[Value]) -> bool {
    !actions.is_empty() && replayable_actions(actions)
}

/// [`replayable_answer`] without the non-empty requirement: an answer of no actions at all is
/// a deterministic "say nothing", which a rule can state even though a cache should not
/// assume it.
pub fn replayable_actions(actions: &[Value]) -> bool {
    actions.iter().all(|action| {
        let name = action.get("type").and_then(Value::as_str).unwrap_or("");
        !name.is_empty()
            && !name.starts_with(crate::llm::actions::executor::FAILED_ACTION_TYPE_PREFIX)
            && (name == "show_message"
                || !crate::events::handler::common_action_names().contains(&name))
    }) && !actions
        .iter()
        .any(crate::utils::redact::contains_credentials)
}

// ---------------------------------------------------------------------------
// Memoisation
// ---------------------------------------------------------------------------

/// The longest a memoised answer may be kept.
pub const MAX_MEMO_TTL_SECS: u64 = 86_400;

/// How many answers one instance's cache keeps; the oldest is dropped beyond it.
pub const MEMO_CAPACITY: usize = 256;

/// The largest canonical event a cache key is built from. A bigger event is answered by the
/// model every time rather than hashed into a key the size of a request body.
pub const MAX_MEMO_KEY_BYTES: usize = 64 * 1024;

/// An instance's memoisation setting. Off unless set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoSettings {
    /// How long a model answer is replayed for, in seconds.
    pub ttl_secs: u64,
    /// Replay an answer on a connection other than the one it was given on even though the
    /// instance shows the model the connection's history. Without it, an instance with
    /// history on keeps one cache per connection; with history off the answer cannot depend
    /// on the connection and is shared regardless.
    #[serde(default)]
    pub across_connections: bool,
}

/// Work out an instance's memoisation from what a form asked for and what it has now.
///
/// `ttl_secs`: `Some(0)` turns it off, `Some(n)` turns it on for `n` seconds, `None` leaves the
/// TTL as it is. `across_connections` changes only that flag and needs memoisation on.
/// Returns `None` when nothing was asked, `Some(new setting)` otherwise.
pub fn resolve_memo_settings(
    ttl_secs: Option<u64>,
    across_connections: Option<bool>,
    current: Option<MemoSettings>,
) -> anyhow::Result<Option<Option<MemoSettings>>> {
    match (ttl_secs, across_connections) {
        (None, None) => Ok(None),
        (Some(0), _) => Ok(Some(None)),
        (Some(ttl), _) if ttl > MAX_MEMO_TTL_SECS => anyhow::bail!(
            "memoize_ttl_secs {} is more than the {} seconds an answer may be memoised for",
            ttl,
            MAX_MEMO_TTL_SECS
        ),
        (Some(ttl), across) => Ok(Some(Some(MemoSettings {
            ttl_secs: ttl,
            across_connections: across
                .or(current.map(|c| c.across_connections))
                .unwrap_or(false),
        }))),
        (None, Some(across)) => match current {
            Some(current) => Ok(Some(Some(MemoSettings {
                across_connections: across,
                ..current
            }))),
            None => anyhow::bail!(
                "memoize_across_connections needs memoisation on: pass memoize_ttl_secs too"
            ),
        },
    }
}

struct MemoEntry {
    /// The answer with per-request echoes replaced by `{{event.…}}` references.
    actions: Vec<Value>,
    stored: crate::utils::clock::Instant,
}

#[derive(Default)]
struct MemoCache {
    entries: HashMap<String, MemoEntry>,
    order: VecDeque<String>,
}

/// An instance's memoisation: its setting and its cache. Cloning shares the cache, so every
/// copy of the instance `AppState` hands out reads and writes the same answers.
#[derive(Clone, Default)]
pub struct Memo {
    settings: Option<MemoSettings>,
    cache: Arc<Mutex<MemoCache>>,
}

impl std::fmt::Debug for Memo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Memo")
            .field("settings", &self.settings)
            .field("entries", &self.len())
            .finish()
    }
}

impl Memo {
    /// A memo with this setting and an empty cache.
    pub fn new(settings: Option<MemoSettings>) -> Self {
        Self {
            settings,
            cache: Arc::default(),
        }
    }

    pub fn settings(&self) -> Option<MemoSettings> {
        self.settings
    }

    /// How many answers the cache holds.
    pub fn len(&self) -> usize {
        self.cache.lock().map(|c| c.entries.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The cache key for this event, or `None` when it must not be memoised: memoisation is
    /// off, the event carries credentials, or it is too large.
    ///
    /// `context` is everything outside the event the answer may depend on — the instance's
    /// instruction and memory, a per-event handler instruction — and `connection_id` scopes
    /// the key to one connection unless the answer cannot depend on it (`history_entries`
    /// is 0, or the operator opted in with `across_connections`).
    pub fn key_for(
        &self,
        event_type: &str,
        event_data: &Value,
        connection_id: Option<u32>,
        history_entries: u16,
        context: &str,
    ) -> Option<String> {
        let settings = self.settings?;
        if crate::utils::redact::contains_credentials(event_data) {
            return None;
        }
        let data = match event_data {
            Value::Object(map) => Value::Object(
                map.iter()
                    .filter(|(key, _)| !is_per_request_field(key))
                    .map(|(key, value)| (key.clone(), value.clone()))
                    .collect(),
            ),
            other => other.clone(),
        };
        let canonical = canonical_json(&data);
        if canonical.len() > MAX_MEMO_KEY_BYTES {
            return None;
        }
        let scope = match connection_id {
            Some(conn) if history_entries > 0 && !settings.across_connections => {
                format!("conn:{conn}")
            }
            _ => "*".to_string(),
        };
        Some(format!(
            "{scope}\u{1f}{event_type}\u{1f}{}\u{1f}{canonical}",
            context_digest(context)
        ))
    }

    /// The memoised answer for `key`, rendered for `event_data`, if one is fresh. An expired
    /// entry, or one that no longer renders against this event, is dropped.
    pub fn get(&self, key: &str, event_data: &Value) -> Option<Vec<Value>> {
        let settings = self.settings?;
        let mut cache = self.cache.lock().ok()?;
        let entry = cache.entries.get(key)?;
        if entry.stored.elapsed().as_secs() >= settings.ttl_secs {
            cache.entries.remove(key);
            cache.order.retain(|k| k != key);
            return None;
        }
        match crate::scripting::event_handler::interpolate_actions(&entry.actions, Some(event_data))
        {
            Ok(actions) => Some(actions),
            Err(_) => {
                cache.entries.remove(key);
                cache.order.retain(|k| k != key);
                None
            }
        }
    }

    /// Keep the model's answer to the event under `key`, if it is replayable
    /// ([`replayable_answer`]). Per-request echoes are stored as references.
    pub fn put(&self, key: String, event_data: &Value, actions: &[Value]) {
        if self.settings.is_none() || !replayable_answer(actions) {
            return;
        }
        let templated = template_per_request_echoes(event_data, actions);
        let Ok(mut cache) = self.cache.lock() else {
            return;
        };
        if cache.entries.contains_key(&key) {
            cache.order.retain(|k| *k != key);
        }
        cache.order.push_back(key.clone());
        cache.entries.insert(
            key,
            MemoEntry {
                actions: templated,
                stored: crate::utils::clock::Instant::now(),
            },
        );
        while cache.order.len() > MEMO_CAPACITY {
            if let Some(oldest) = cache.order.pop_front() {
                cache.entries.remove(&oldest);
            }
        }
    }

    /// Drop the answer under `key` (a replay of it failed).
    pub fn forget(&self, key: &str) {
        if let Ok(mut cache) = self.cache.lock() {
            cache.entries.remove(key);
            cache.order.retain(|k| k != key);
        }
    }
}

/// A short, stable digest of the context an answer depends on.
fn context_digest(context: &str) -> String {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    context.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

/// What an instance's memo needs from `AppState` to build a key: the memo itself, the
/// instance's history setting, and the context its answers depend on.
#[derive(Debug, Clone)]
pub struct MemoHandle {
    pub memo: Memo,
    pub history_entries: u16,
    /// The instance's instruction and memory, joined.
    pub context: String,
}

impl MemoHandle {
    /// [`Memo::key_for`] with this instance's history and context, plus a per-event handler
    /// instruction if one applies.
    pub fn key_for(
        &self,
        event_type: &str,
        event_data: &Value,
        connection_id: Option<u32>,
        handler_instruction: Option<&str>,
    ) -> Option<String> {
        let context = format!(
            "{}\u{1f}{}",
            self.context,
            handler_instruction.unwrap_or_default()
        );
        self.memo.key_for(
            event_type,
            event_data,
            connection_id,
            self.history_entries,
            &context,
        )
    }
}

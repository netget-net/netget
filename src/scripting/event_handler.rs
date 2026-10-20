//! Event handler configuration system
//!
//! This module defines how events are handled - either by LLM, script, or static responses.
//!
//! # Static handler event interpolation
//!
//! A [`EventHandlerType::Static`] handler emits its configured actions without calling
//! the LLM. To let those actions echo values from the event that triggered them —
//! correlation ids such as a DNS `query_id`, a DHCP/BOOTP `xid`, an SNMP `request-id`,
//! a STUN transaction id — action JSON may contain references of the form:
//!
//! ```text
//! {{event.<field>}}          e.g. {{event.query_id}}
//! {{event.<a>.<b>}}          e.g. {{event.headers.host}}
//! {{event.<list>.<index>}}   e.g. {{event.questions.0.name}}
//! {{event}}                  the whole event payload
//! ```
//!
//! Substitution is performed by [`interpolate_actions`] immediately before the actions
//! are executed. Three rules define it:
//!
//! 1. **Whole-string reference preserves type.** A JSON string whose *entire* value is
//!    one reference is replaced by the referenced JSON value itself, so
//!    `"query_id": "{{event.query_id}}"` yields a *number*, not `"4660"`. Objects,
//!    arrays, booleans and null survive equally.
//! 2. **Embedded reference interpolates text.** `"reply to {{event.domain}}"` produces a
//!    string; non-string values are rendered in their JSON form (`null`, `true`, `42`,
//!    `{"a":1}`).
//! 3. **Everything else is byte-identical.** Only `{{` … `}}` groups whose contents are
//!    `event` or begin with `event.` are touched. Any other braces — Handlebars snippets
//!    in a served template, `{{ msg }}` in a Vue page, `{` in a JSON body or a regex —
//!    pass through unchanged, so handlers written before this feature keep working.
//!
//! An unresolvable reference is a hard error naming the reference and listing the fields
//! the event actually carries; it is never silently rendered as `null` or the empty
//! string, because a static handler with a typo'd field name must not appear to work.
//!
//! ## Why not Handlebars
//!
//! Handlebars is already a dependency (`src/llm/template_engine.rs`) and lends the
//! familiar `{{…}}` spelling, but it is the wrong engine for this path: it renders to a
//! `String`, so rule 1 would require re-parsing the output and would turn the string
//! `"007"` into the number `7`; it HTML-escapes `{{…}}` by default, corrupting JSON and
//! URL payloads unless every reference uses the triple-stash; and it claims the whole
//! `{{…}}` namespace, so a handler that serves a Handlebars/Vue template, or that
//! contains `{{#if}}`/`{{!--`/`{{>` text, would be rewritten or rejected. The resolver
//! below is ~150 lines, borrows only the spelling, and leaves every non-`event`
//! reference alone.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Pattern for matching events
///
/// On the wire a pattern is the string the operator wrote: an event id, or `"*"` for every
/// event. Serde is implemented by hand so the two directions agree: a derived `untagged`
/// encoding writes the wildcard as `null` and reads `"*"` back as an event literally named
/// `*`, so a configuration sent through JSON and back (a restart, the dashboard's driver
/// swap, status output) would change meaning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventPattern {
    /// Match a specific event type ID
    Specific(String),
    /// Match all events
    Wildcard,
}

impl EventPattern {
    /// Check if this pattern matches the given event type ID
    pub fn matches(&self, event_type_id: &str) -> bool {
        match self {
            EventPattern::Specific(pattern) => pattern == event_type_id,
            EventPattern::Wildcard => true,
        }
    }

    /// Create a wildcard pattern
    pub fn wildcard() -> Self {
        EventPattern::Wildcard
    }

    /// Create a specific pattern
    pub fn specific(event_type_id: impl Into<String>) -> Self {
        EventPattern::Specific(event_type_id.into())
    }
}

impl Serialize for EventPattern {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            EventPattern::Specific(id) => serializer.serialize_str(id),
            EventPattern::Wildcard => serializer.serialize_str("*"),
        }
    }
}

impl<'de> Deserialize<'de> for EventPattern {
    /// `"*"` and `"all"` are the wildcard, as in [`From<&str>`]; so is `null`, matching
    /// `parse_event_handlers`, where a rule without a pattern matches every event.
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(match Option::<String>::deserialize(deserializer)? {
            Some(pattern) => EventPattern::from(pattern),
            None => EventPattern::Wildcard,
        })
    }
}

impl From<String> for EventPattern {
    fn from(s: String) -> Self {
        if s == "*" || s == "all" {
            EventPattern::Wildcard
        } else {
            EventPattern::Specific(s)
        }
    }
}

impl From<&str> for EventPattern {
    fn from(s: &str) -> Self {
        if s == "*" || s == "all" {
            EventPattern::Wildcard
        } else {
            EventPattern::Specific(s.to_string())
        }
    }
}

/// Handler type for an event
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum EventHandlerType {
    /// Handle with LLM (default behavior)
    Llm {
        /// Instruction for how the LLM should handle this event
        instruction: String,
    },

    /// Handle with inline script
    Script {
        /// Scripting language (python, javascript, go, perl)
        language: String,
        /// Inline script code
        code: String,
        /// Run the script as a **resident** process: spawned once per scope and
        /// driven with one event per stdin line, keeping in-process state
        /// between events. Opt-in; defaults to `false` (the stateless per-event
        /// path). A resident script defines `handle(event_type, event, message)`
        /// instead of reading stdin itself. See `src/scripting/resident.rs`.
        #[serde(default)]
        resident: bool,
        /// Resident scope: `"server"` (default — one process shared by all the
        /// server's connections) or `"connection"` (one process per
        /// connection). Ignored unless `resident` is `true`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        scope: Option<String>,
    },

    /// Handle with static response (actions array)
    ///
    /// Action JSON may reference the triggering event with `{{event.field}}`; see the
    /// [module docs](self#static-handler-event-interpolation) for the substitution rules.
    Static {
        /// Actions to execute (actual JSON values, not strings)
        actions: Vec<serde_json::Value>,
    },

    /// Handled by a human at the dashboard.
    ///
    /// The event parks as a pending question (`AppState::park_intercept`) and the
    /// connection waits, exactly as it would for a slow model. Whatever actions the
    /// operator composes are executed as the answer; `{{event.field}}` references work
    /// the same as in a static handler. If nobody answers within `timeout_secs`, the
    /// handler **fails closed** — the dispatch errors and the protocol's LLM-failure
    /// branch answers the peer with a category, never with an invented success.
    Manual {
        /// Seconds to wait for the operator before failing closed.
        #[serde(default = "default_manual_timeout_secs")]
        timeout_secs: u64,
    },
}

/// How long a manual handler waits for the operator by default.
///
/// Generous on purpose: the whole point is that a human reads the event and composes an
/// answer, and most protocol peers apply their own (shorter) timeout anyway. It exists so
/// an unattended dashboard eventually fails closed instead of parking connections forever.
pub const DEFAULT_MANUAL_TIMEOUT_SECS: u64 = 300;

fn default_manual_timeout_secs() -> u64 {
    DEFAULT_MANUAL_TIMEOUT_SECS
}

impl EventHandlerType {
    /// Create a per-event (stateless) script handler.
    pub fn script(language: impl Into<String>, code: impl Into<String>) -> Self {
        EventHandlerType::Script {
            language: language.into(),
            code: code.into(),
            resident: false,
            scope: None,
        }
    }

    /// Create a resident (persistent) script handler with the given scope
    /// (`"server"` or `"connection"`; `None` defaults to server scope).
    pub fn script_resident(
        language: impl Into<String>,
        code: impl Into<String>,
        scope: Option<String>,
    ) -> Self {
        EventHandlerType::Script {
            language: language.into(),
            code: code.into(),
            resident: true,
            scope,
        }
    }

    /// Create a static handler
    pub fn static_response(actions: Vec<serde_json::Value>) -> Self {
        EventHandlerType::Static { actions }
    }

    /// Create an LLM handler
    pub fn llm(instruction: impl Into<String>) -> Self {
        EventHandlerType::Llm {
            instruction: instruction.into(),
        }
    }

    /// Create a manual (human-answered) handler.
    pub fn manual(timeout_secs: u64) -> Self {
        EventHandlerType::Manual { timeout_secs }
    }

    /// Validate the handler's `{{event.…}}` references *without* an event.
    ///
    /// This is the parse-time half of the check: it catches malformed references
    /// (`{{event.}}`, `{{event..x}}`, an opening `{{event.` that is never closed), which
    /// are wrong regardless of which event arrives. Whether a *well-formed* reference
    /// resolves depends on the event payload and can only be decided at dispatch time by
    /// [`interpolate_actions`].
    ///
    /// Callers that parse handler configuration (e.g. `EventHandler::parse_event_handlers`
    /// in `src/events/handler.rs`) should call this so a typo is reported to the MCP
    /// caller at `start_server` time rather than silently at the first packet.
    pub fn validate(&self) -> Result<(), InterpolationError> {
        if let EventHandlerType::Script { code, .. } = self {
            if code.len() > super::types::ScriptSource::MAX_CODE_BYTES {
                return Err(budget_error());
            }
        }
        match self {
            EventHandlerType::Static { actions } => {
                for action in actions {
                    validate_event_references(action)?;
                }
                Ok(())
            }
            // A script's contract depends on `resident`, and getting it wrong fails
            // silently: a resident script defines `handle(event_type, event, message)`
            // while a non-resident one reads stdin and prints its own output. Define
            // `handle` without `resident: true` and the script produces nothing, the
            // handler yields no actions, and the server fails closed -- which the peer
            // sees as a generic protocol error with no hint of the real cause.
            EventHandlerType::Script {
                language,
                code,
                resident,
                ..
            } if !*resident && defines_handle(language, code) => {
                Err(InterpolationError::script_contract(language.clone()))
            }
            _ => Ok(()),
        }
    }
}

/// Event handler configuration - maps event patterns to handlers
///
/// `deny_unknown_fields` is load-bearing. There are exactly two keys here, and there is no
/// data-based matching: a rule matches on the event id alone. An `event_data_contains` key
/// -- an entirely reasonable thing to assume exists, and something an LLM writing handlers
/// will invent -- used to be accepted and silently ignored, so every rule registered
/// against one event id matched every occurrence and first-match-wins picked the first.
/// The config looked like it discriminated between requests and simply did not.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventHandler {
    /// Pattern to match events
    pub event_pattern: EventPattern,

    /// Handler to use for matched events
    pub handler: EventHandlerType,
}

impl EventHandler {
    /// Create a new event handler
    pub fn new(event_pattern: EventPattern, handler: EventHandlerType) -> Self {
        Self {
            event_pattern,
            handler,
        }
    }

    /// Check if this handler matches the given event type ID
    pub fn matches(&self, event_type_id: &str) -> bool {
        self.event_pattern.matches(event_type_id)
    }
}

/// Configuration for all event handlers
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EventHandlerConfig {
    /// List of event handlers (processed in order, first match wins)
    pub handlers: Vec<EventHandler>,
}

impl EventHandlerConfig {
    /// Create a new empty configuration
    pub fn new() -> Self {
        Self {
            handlers: Vec::new(),
        }
    }

    /// Add a handler to the configuration
    pub fn add_handler(&mut self, handler: EventHandler) {
        self.handlers.push(handler);
    }

    /// Find the first handler that matches the given event type ID
    pub fn find_handler(&self, event_type_id: &str) -> Option<&EventHandlerType> {
        self.handlers
            .iter()
            .find(|h| h.matches(event_type_id))
            .map(|h| &h.handler)
    }

    /// Check if any handlers are configured
    pub fn is_empty(&self) -> bool {
        self.handlers.is_empty()
    }

    /// Get the number of handlers
    pub fn len(&self) -> usize {
        self.handlers.len()
    }
}

// ---------------------------------------------------------------------------
// Static handler event interpolation
// ---------------------------------------------------------------------------

/// Opening delimiter of a reference.
const REF_OPEN: &str = "{{";
/// Closing delimiter of a reference.
const REF_CLOSE: &str = "}}";
/// The only root identifier that is substituted. `{{anything.else}}` is left alone.
const REF_ROOT: &str = "event";
/// `REF_ROOT` followed by the path separator.
const REF_ROOT_DOT: &str = "event.";

/// A `{{event.…}}` reference in a static handler action could not be resolved.
///
/// Carries the offending reference verbatim plus a human-readable reason that names the
/// missing field and lists what the event actually offers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterpolationError {
    /// The reference exactly as it appeared, e.g. `{{event.headers.hsot}}`, or the
    /// script's language when `kind` is [`ErrorKind::ScriptContract`].
    pub reference: String,
    /// Why it could not be resolved, including the available alternatives
    pub detail: String,
    /// Which validation failed, so the message reads correctly for each.
    pub kind: ErrorKind,
}

/// What `EventHandlerType::validate` rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    /// A `{{event.…}}` reference in a static handler could not be resolved.
    Interpolation,
    /// A script's entry point contradicts its `resident` flag.
    ScriptContract,
}

impl InterpolationError {
    fn new(reference: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            reference: reference.into(),
            detail: detail.into(),
            kind: ErrorKind::Interpolation,
        }
    }

    /// A script defines `handle(...)` but is not marked `resident` (or vice versa).
    fn script_contract(language: impl Into<String>) -> Self {
        Self {
            reference: language.into(),
            detail: String::new(),
            kind: ErrorKind::ScriptContract,
        }
    }
}

impl std::fmt::Display for InterpolationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.kind {
            ErrorKind::Interpolation => write!(
                f,
                "static handler reference `{}` could not be resolved: {}",
                self.reference, self.detail
            ),
            ErrorKind::ScriptContract => write!(
                f,
                "this {} script defines `handle(...)`, which is the RESIDENT entry point, \
                 but the handler is not marked `resident: true`. As written the script \
                 reads nothing from stdin and prints nothing, so the handler produces no \
                 actions and the server fails closed -- with no hint of why. Add \
                 `\"resident\": true`, or rewrite the script to read the event from stdin \
                 and print its actions.",
                self.reference
            ),
        }
    }
}

impl std::error::Error for InterpolationError {}

/// A located reference inside a string.
struct FoundRef<'a> {
    /// Byte offset of the opening `{{`
    start: usize,
    /// Byte offset just past the closing `}}`
    end: usize,
    /// The reference including delimiters, for error messages
    raw: &'a str,
    /// The trimmed contents between the delimiters (`event` or `event.…`)
    inner: &'a str,
}

/// Find the next `{{event…}}` reference at or after byte offset `from`.
///
/// `{{` groups whose contents are not rooted at `event` are skipped, not consumed, so a
/// Handlebars/Vue template embedded in a handler is left untouched. The scan advances one
/// byte at a time on a miss, so `{{{event.x}}}` still finds the inner reference.
fn find_reference(s: &str, from: usize) -> Option<FoundRef<'_>> {
    let mut cursor = from;
    while cursor < s.len() {
        let open = cursor + s[cursor..].find(REF_OPEN)?;
        let after_open = open + REF_OPEN.len();
        let Some(rel_close) = s[after_open..].find(REF_CLOSE) else {
            // No closing delimiter anywhere after this point: nothing left to find.
            return None;
        };
        let close = after_open + rel_close;
        let inner = s[after_open..close].trim();
        if inner == REF_ROOT || inner.starts_with(REF_ROOT_DOT) {
            return Some(FoundRef {
                start: open,
                end: close + REF_CLOSE.len(),
                raw: &s[open..close + REF_CLOSE.len()],
                inner,
            });
        }
        cursor = open + 1;
    }
    None
}

/// Split a reference's contents into path segments. `{{event}}` yields an empty path.
fn parse_path<'a>(found: &FoundRef<'a>) -> Result<Vec<&'a str>, InterpolationError> {
    if found.inner == REF_ROOT {
        return Ok(Vec::new());
    }
    let rest = &found.inner[REF_ROOT_DOT.len()..];
    if rest.is_empty() {
        return Err(InterpolationError::new(
            found.raw,
            format!(
                "the path after `{}.` is empty; write `{{{{event.field}}}}` or `{{{{event}}}}` for the whole payload",
                REF_ROOT
            ),
        ));
    }
    let mut segments = Vec::new();
    for segment in rest.split('.') {
        let segment = segment.trim();
        if segment.is_empty() {
            return Err(InterpolationError::new(
                found.raw,
                "it contains an empty path segment (a doubled or trailing `.`)",
            ));
        }
        segments.push(segment);
    }
    Ok(segments)
}

/// Describe what can be reached from `value`, for the "available:" half of an error.
fn describe_available(value: &Value) -> String {
    match value {
        Value::Object(map) if map.is_empty() => "this object is empty".to_string(),
        Value::Object(map) => format!(
            "available fields: {}",
            map.keys()
                .take(16)
                .map(|key| key.chars().take(64).collect::<String>())
                .collect::<Vec<_>>()
                .join(", ")
        ),
        Value::Array(items) if items.is_empty() => "this array is empty".to_string(),
        Value::Array(items) => format!("available indices: 0..{}", items.len() - 1),
        other => format!("it is a {} and has no fields", json_type_name(other)),
    }
}

fn json_type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// Walk `segments` through the event payload.
fn resolve<'a>(
    event: &'a Value,
    segments: &[&str],
    raw: &str,
) -> Result<&'a Value, InterpolationError> {
    let mut current = event;
    let mut walked = REF_ROOT.to_string();
    for segment in segments {
        let next = match current {
            Value::Object(map) => map.get(*segment),
            Value::Array(items) => segment.parse::<usize>().ok().and_then(|i| items.get(i)),
            _ => None,
        };
        current = next.ok_or_else(|| {
            InterpolationError::new(
                raw,
                format!(
                    "`{}` has no `{}` ({})",
                    walked,
                    segment,
                    describe_available(current)
                ),
            )
        })?;
        walked.push('.');
        walked.push_str(segment);
    }
    Ok(current)
}

/// Maximum resources for one static action expansion (including all actions).
pub const MAX_INTERPOLATION_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_INTERPOLATION_NODES: usize = 65_536;
pub const MAX_INTERPOLATION_DEPTH: usize = 64;

fn budget_error() -> InterpolationError {
    InterpolationError::new(
        "event",
        "static handler exceeds the 8 MiB, 65536-node or 64-level interpolation budget",
    )
}

fn check_tree(value: &Value) -> Result<(), InterpolationError> {
    if crate::utils::json_budget::within_budget(
        value,
        MAX_INTERPOLATION_BYTES,
        MAX_INTERPOLATION_NODES,
        MAX_INTERPOLATION_DEPTH,
    ) {
        Ok(())
    } else {
        Err(budget_error())
    }
}

/// A shared serialization budget bounds expansion before any large intermediate
/// String is allocated. It also catches JSON escaping expansion.
struct ExpansionBudget {
    bytes: usize,
    nodes: usize,
}
impl ExpansionBudget {
    fn append(&mut self, out: &mut String, text: &str) -> Result<(), InterpolationError> {
        if text.len() > MAX_INTERPOLATION_BYTES.saturating_sub(self.bytes) {
            return Err(budget_error());
        }
        self.bytes += text.len();
        out.push_str(text);
        Ok(())
    }
    fn visit(&mut self) -> Result<(), InterpolationError> {
        self.nodes += 1;
        if self.nodes > MAX_INTERPOLATION_NODES {
            return Err(budget_error());
        }
        Ok(())
    }
}

fn bounded_display(
    value: &Value,
    budget: &mut ExpansionBudget,
) -> Result<String, InterpolationError> {
    check_tree(value)?;
    if let Value::String(text) = value {
        let mut result = String::new();
        budget.append(&mut result, text)?;
        return Ok(result);
    }
    struct Writer<'a> {
        data: Vec<u8>,
        budget: &'a mut ExpansionBudget,
    }
    impl std::io::Write for Writer<'_> {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if bytes.len() > MAX_INTERPOLATION_BYTES.saturating_sub(self.budget.bytes) {
                return Err(std::io::Error::other("interpolation byte cap"));
            }
            self.budget.bytes += bytes.len();
            self.data.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut writer = Writer {
        data: Vec::new(),
        budget,
    };
    serde_json::to_writer(&mut writer, value).map_err(|_| budget_error())?;
    String::from_utf8(writer.data).map_err(|_| budget_error())
}

fn clone_bounded(value: &Value, budget: &mut ExpansionBudget) -> Result<Value, InterpolationError> {
    check_tree(value)?;
    fn copy(value: &Value, budget: &mut ExpansionBudget) -> Result<Value, InterpolationError> {
        budget.visit()?;
        match value {
            Value::String(text) => {
                let mut out = String::new();
                budget.append(&mut out, text)?;
                Ok(Value::String(out))
            }
            Value::Array(items) => items
                .iter()
                .map(|v| copy(v, budget))
                .collect::<Result<Vec<_>, _>>()
                .map(Value::Array),
            Value::Object(map) => {
                let mut out = serde_json::Map::new();
                for (key, value) in map {
                    let mut owned = String::new();
                    budget.append(&mut owned, key)?;
                    out.insert(owned, copy(value, budget)?);
                }
                Ok(Value::Object(out))
            }
            other => Ok(other.clone()),
        }
    }
    copy(value, budget)
}

/// The event payload was absent, but a reference needed it.
fn missing_event_error(raw: &str) -> InterpolationError {
    InterpolationError::new(
        raw,
        "this event carries no structured data, so nothing can be substituted",
    )
}

/// Interpolate one string, returning a `Value` so a whole-string reference keeps its type.
fn interpolate_string(
    s: &str,
    event: Option<&Value>,
    budget: &mut ExpansionBudget,
) -> Result<Value, InterpolationError> {
    let Some(first) = find_reference(s, 0) else {
        // No reference at all: byte-identical pass-through.
        let mut out = String::new();
        budget.append(&mut out, s)?;
        return Ok(Value::String(out));
    };

    // Rule 1: the string is exactly one reference -> substitute the JSON value itself.
    if first.start == 0 && first.end == s.len() {
        let segments = parse_path(&first)?;
        let event = event.ok_or_else(|| missing_event_error(first.raw))?;
        return clone_bounded(resolve(event, &segments, first.raw)?, budget);
    }

    // Rule 2: one or more references embedded in surrounding text -> string splice.
    let mut out = String::new();
    let mut cursor = 0usize;
    let mut found = Some(first);
    while let Some(f) = found {
        budget.append(&mut out, &s[cursor..f.start])?;
        let segments = parse_path(&f)?;
        let event = event.ok_or_else(|| missing_event_error(f.raw))?;
        out.push_str(&bounded_display(resolve(event, &segments, f.raw)?, budget)?);
        cursor = f.end;
        found = find_reference(s, cursor);
    }
    budget.append(&mut out, &s[cursor..])?;
    Ok(Value::String(out))
}

/// Substitute every `{{event.…}}` reference in a JSON value tree.
///
/// Object keys are interpolated too, always as text (a JSON key must be a string).
/// Values with no references are returned unchanged.
pub fn interpolate_value(
    value: &Value,
    event_data: Option<&Value>,
) -> Result<Value, InterpolationError> {
    check_tree(value)?;
    let result = interpolate_inner(
        value,
        event_data,
        &mut ExpansionBudget { bytes: 0, nodes: 0 },
    )?;
    if check_tree(&result).is_err() {
        crate::utils::json_budget::drop_iteratively(result);
        return Err(budget_error());
    }
    Ok(result)
}

fn interpolate_inner(
    value: &Value,
    event_data: Option<&Value>,
    budget: &mut ExpansionBudget,
) -> Result<Value, InterpolationError> {
    budget.visit()?;
    match value {
        Value::String(s) => interpolate_string(s, event_data, budget),
        Value::Array(items) => items
            .iter()
            .map(|item| interpolate_inner(item, event_data, budget))
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Array),
        Value::Object(map) => {
            let mut out = serde_json::Map::new();
            for (key, val) in map {
                let key = match interpolate_string(key, event_data, budget)? {
                    Value::String(s) => s,
                    other => bounded_display(&other, budget)?,
                };
                if out.contains_key(&key) {
                    return Err(InterpolationError::new(key, "interpolated keys collide"));
                }
                out.insert(key, interpolate_inner(val, event_data, budget)?);
            }
            Ok(Value::Object(out))
        }
        other => Ok(other.clone()),
    }
}

/// Expand all actions under one shared byte/node budget.
pub fn interpolate_actions(
    actions: &[Value],
    event_data: Option<&Value>,
) -> Result<Vec<Value>, InterpolationError> {
    if actions.len() > MAX_INTERPOLATION_NODES {
        return Err(budget_error());
    }
    let mut budget = ExpansionBudget { bytes: 0, nodes: 0 };
    let expanded = actions
        .iter()
        .map(|action| {
            check_tree(action)?;
            interpolate_inner(action, event_data, &mut budget)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let combined = Value::Array(expanded);
    if check_tree(&combined).is_err() {
        crate::utils::json_budget::drop_iteratively(combined);
        return Err(budget_error());
    }
    let Value::Array(expanded) = combined else {
        unreachable!()
    };
    Ok(expanded)
}

/// Iterative inspection is also safe for programmatically constructed JSON.
pub fn contains_event_reference(value: &Value) -> bool {
    if check_tree(value).is_err() {
        return false;
    }
    let mut pending = vec![value];
    while let Some(value) = pending.pop() {
        match value {
            Value::String(s) if find_reference(s, 0).is_some() => return true,
            Value::Array(items) => pending.extend(items),
            Value::Object(map) => {
                if map.keys().any(|key| find_reference(key, 0).is_some()) {
                    return true;
                }
                pending.extend(map.values());
            }
            _ => {}
        }
    }
    false
}

/// Whether a script defines the resident entry point `handle(...)`.
///
/// Deliberately syntactic and conservative: it looks for a definition, not a call, so a
/// script that merely mentions the word is not flagged.
fn defines_handle(language: &str, code: &str) -> bool {
    let language = language.to_ascii_lowercase();
    let python = matches!(language.as_str(), "python" | "python3");
    let perl = language == "perl";
    let javascript = matches!(language.as_str(), "javascript" | "js" | "node");
    if !python && !perl && !javascript && language != "go" {
        return false;
    }
    // Ignore comments and string literals using each language's delimiters.
    // Tokenization makes whitespace/newlines irrelevant without executing code.
    let bytes = code.as_bytes();
    let mut tokens: Vec<&str> = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_whitespace() {
            i += 1;
            continue;
        }
        if ((python || perl) && bytes[i] == b'#')
            || (!python && !perl && bytes[i..].starts_with(b"//"))
        {
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        if !python && !perl && bytes[i..].starts_with(b"/*") {
            i += 2;
            while i < bytes.len() && !bytes[i..].starts_with(b"*/") {
                i += 1;
            }
            i = (i + 2).min(bytes.len());
            continue;
        }
        // Perl's q/qq/qw/qx/qr operators are strings/regexes too, not code.
        if perl && bytes[i] == b'q' {
            let mut delimiter = i + 1;
            if bytes
                .get(delimiter)
                .is_some_and(|b| matches!(*b, b'q' | b'w' | b'x' | b'r'))
            {
                delimiter += 1;
            }
            while bytes.get(delimiter).is_some_and(u8::is_ascii_whitespace) {
                delimiter += 1;
            }
            if let Some(&open) = bytes
                .get(delimiter)
                .filter(|b| !b.is_ascii_alphanumeric() && **b != b'_')
            {
                let close = match open {
                    b'{' => b'}',
                    b'[' => b']',
                    b'(' => b')',
                    b'<' => b'>',
                    other => other,
                };
                let mut depth = 1;
                i = delimiter + 1;
                while i < bytes.len() && depth > 0 {
                    if bytes[i] == b'\\' {
                        i = (i + 2).min(bytes.len());
                        continue;
                    }
                    if bytes[i] == close {
                        depth -= 1;
                    } else if open != close && bytes[i] == open {
                        depth += 1;
                    }
                    i += 1;
                }
                tokens.push("<literal>");
                continue;
            }
        }
        if matches!(bytes[i], b'\'' | b'"' | b'`') {
            let quote = bytes[i];
            let triple = python && bytes[i..].starts_with(&[quote; 3]);
            let size = if triple { 3 } else { 1 };
            i += size;
            while i < bytes.len() {
                if bytes[i] == b'\\' {
                    i = (i + 2).min(bytes.len());
                    continue;
                }
                if bytes[i] == quote && (!triple || bytes[i..].starts_with(&[quote; 3])) {
                    i += size;
                    break;
                }
                i += 1;
            }
            // Keep a boundary so tokens on either side cannot form a declaration.
            tokens.push("<literal>");
            continue;
        }
        // Regex literals can contain text resembling a function declaration.
        if javascript
            && bytes[i] == b'/'
            && tokens
                .last()
                .is_none_or(|t| matches!(*t, "=" | "(" | "," | ":" | "return"))
        {
            i += 1;
            let mut class = false;
            while i < bytes.len() {
                match bytes[i] {
                    b'\\' => {
                        i = (i + 2).min(bytes.len());
                        continue;
                    }
                    b'[' => class = true,
                    b']' => class = false,
                    b'/' if !class => {
                        i += 1;
                        break;
                    }
                    b'\n' => break,
                    _ => {}
                }
                i += 1;
            }
            tokens.push("<literal>");
            continue;
        }
        let start = i;
        if bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_' || bytes[i] == b'$' {
            i += 1;
            while i < bytes.len()
                && (bytes[i].is_ascii_alphanumeric() || matches!(bytes[i], b'_' | b'$'))
            {
                i += 1;
            }
        } else {
            // Advance by a complete UTF-8 character before slicing.
            i += code[i..].chars().next().unwrap().len_utf8();
        }
        tokens.push(&code[start..i]);
    }
    for (index, token) in tokens.iter().enumerate() {
        if *token != "handle" {
            continue;
        }
        let before = index.checked_sub(1).and_then(|n| tokens.get(n)).copied();
        let after = tokens.get(index + 1).copied();
        if python && before == Some("def") && after == Some("(") {
            return true;
        }
        if perl && before == Some("sub") && matches!(after, Some("{" | "(" | ":")) {
            return true;
        }
        if language == "go" && before == Some("func") && after == Some("(") {
            return true;
        }
        if javascript {
            if before == Some("function") && after == Some("(") {
                return true;
            }
            if after != Some("=") {
                continue;
            }
            let mut next = index + 2;
            if tokens.get(next) == Some(&"async") {
                next += 1;
            }
            if tokens.get(next) == Some(&"function") {
                return true;
            }
            if tokens.get(next) == Some(&"(") {
                let mut depth = 0;
                while let Some(token) = tokens.get(next) {
                    match *token {
                        "(" => depth += 1,
                        ")" => depth -= 1,
                        _ => {}
                    }
                    next += 1;
                    if depth == 0 {
                        break;
                    }
                }
            } else {
                next += 1;
            } // one unparenthesized arrow parameter
            if tokens.get(next..next.saturating_add(2)) == Some(&["=", ">"][..]) {
                return true;
            }
        }
    }
    false
}

/// Check every reference in a value tree for syntactic validity, without an event.
///
/// Catches malformed paths (`{{event.}}`, `{{event..x}}`) that are wrong for any event.
/// Field existence is deliberately *not* checked here: it depends on the payload.
pub fn validate_event_references(value: &Value) -> Result<(), InterpolationError> {
    check_tree(value)?;
    fn check_string(s: &str) -> Result<(), InterpolationError> {
        let mut cursor = 0;
        while let Some(found) = find_reference(s, cursor) {
            parse_path(&found)?;
            cursor = found.end;
        }
        Ok(())
    }
    let mut pending = vec![value];
    while let Some(value) = pending.pop() {
        match value {
            Value::String(s) => check_string(s)?,
            Value::Array(items) => pending.extend(items),
            Value::Object(map) => {
                for key in map.keys() {
                    check_string(key)?;
                }
                pending.extend(map.values());
            }
            _ => {}
        }
    }
    Ok(())
}

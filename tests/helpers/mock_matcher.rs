//! Mock matcher trait and implementations
//!
//! Defines the MockMatcher trait for matching LLM call contexts against rules.

use serde::{Deserialize, Serialize};

/// What kind of LLM request the prompt represents.
///
/// NetGet renders a different Handlebars template per situation, and the
/// template's own task text is the only reliable signal for which one it is —
/// prompt *bodies* routinely mention protocol and event names (protocol
/// documentation is literally a list of them), so keyword sniffing over the
/// whole prompt cannot tell a network event from a startup request.
///
/// See `prompts/network_request/task.hbs` vs `prompts/user_input/task.hbs`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RequestKind {
    /// Rendered from `prompts/network_request/**` (server) or the client
    /// network loop in `src/llm/action_helper.rs::call_llm_for_client`.
    /// A real protocol event is being handled — `event_type` is meaningful.
    NetworkEvent,

    /// Rendered from `prompts/user_input/**`. A user command such as
    /// "listen on port N via http" — there is no network event, so
    /// `event_type` must stay `None`.
    UserInput,

    /// A scheduled task firing (`src/cli/tasks.rs` sends the fixed user
    /// message "Execute the task."). Timer-driven, so there is no event id —
    /// what identifies the run sits in the system prompt's `Trigger:` block.
    ScheduledTask,

    /// Some other template (feedback) or a prompt with no
    /// recognisable marker. Classification falls back to legacy best-effort
    /// extraction.
    Unknown,
}

impl RequestKind {
    /// Whether an `event_type` may legitimately be extracted for this kind.
    pub fn carries_network_event(&self) -> bool {
        matches!(self, RequestKind::NetworkEvent | RequestKind::Unknown)
    }
}

/// Context passed to matchers when LLM is called
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct LlmContext {
    /// Event type (e.g., "tcp_connection_opened", "http_request")
    pub event_type: Option<String>,

    /// Server/client instruction
    pub instruction: String,

    /// Event data (request details, structured JSON)
    pub event_data: serde_json::Value,

    /// Iteration number for this context (for multi-turn conversations)
    pub iteration: usize,

    /// Message role (user/assistant) for user commands
    pub message_role: Option<String>,

    /// Full prompt text sent to LLM
    pub prompt: String,

    /// Which prompt template produced this request
    #[serde(default = "default_request_kind")]
    pub request_kind: RequestKind,
}

fn default_request_kind() -> RequestKind {
    RequestKind::Unknown
}

impl LlmContext {
    /// Create a new LLM context
    pub fn new(prompt: String) -> Self {
        Self {
            event_type: None,
            instruction: String::new(),
            event_data: serde_json::json!({}),
            iteration: 1,
            message_role: None,
            prompt,
            request_kind: RequestKind::Unknown,
        }
    }

    /// Set the request kind
    pub fn with_request_kind(mut self, kind: RequestKind) -> Self {
        self.request_kind = kind;
        self
    }

    /// Set event type
    pub fn with_event_type(mut self, event_type: impl Into<String>) -> Self {
        self.event_type = Some(event_type.into());
        self
    }

    /// Set instruction
    pub fn with_instruction(mut self, instruction: impl Into<String>) -> Self {
        self.instruction = instruction.into();
        self
    }

    /// Set event data
    pub fn with_event_data(mut self, data: serde_json::Value) -> Self {
        self.event_data = data;
        self
    }

    /// Set iteration
    pub fn with_iteration(mut self, iteration: usize) -> Self {
        self.iteration = iteration;
        self
    }

    /// Set message role
    pub fn with_message_role(mut self, role: impl Into<String>) -> Self {
        self.message_role = Some(role.into());
        self
    }
}

/// Trait for matching LLM call contexts
pub trait MockMatcher: Send + Sync {
    /// Check if context matches this matcher's criteria
    fn matches(&self, context: &LlmContext) -> bool;

    /// Get human-readable description of matching criteria
    fn describe(&self) -> String;
}

/// Matcher for event type
pub struct EventTypeMatcher {
    event_type: String,
}

impl EventTypeMatcher {
    pub fn new(event_type: impl Into<String>) -> Self {
        Self {
            event_type: event_type.into(),
        }
    }
}

impl MockMatcher for EventTypeMatcher {
    fn matches(&self, context: &LlmContext) -> bool {
        // `"*"` is a catch-all for any network event.
        //
        // It used to be compared literally, so a rule written as `.on_event("*")` matched
        // nothing at all. That reads as a deliberate catch-all and silently was not one --
        // the rule never fired, and a test relying on it asserted nothing about the event
        // path. Same shape as the other "cannot fail" tests found this week, except here it
        // was the harness itself.
        //
        // Note it matches only when an event is present: a user-input turn carries
        // `event_type: None` and must not be swallowed by an event rule.
        if self.event_type == "*" {
            return context.event_type.is_some();
        }
        context.event_type.as_ref() == Some(&self.event_type)
    }

    fn describe(&self) -> String {
        if self.event_type == "*" {
            return "event_type=* (any network event)".to_string();
        }
        format!("event_type={}", self.event_type)
    }
}

/// Matcher for instruction substring
pub struct InstructionContainsMatcher {
    substring: String,
}

impl InstructionContainsMatcher {
    pub fn new(substring: impl Into<String>) -> Self {
        Self {
            substring: substring.into(),
        }
    }
}

impl MockMatcher for InstructionContainsMatcher {
    fn matches(&self, context: &LlmContext) -> bool {
        context.instruction.contains(&self.substring)
    }

    fn describe(&self) -> String {
        format!("instruction contains '{}'", self.substring)
    }
}

/// Matcher for instruction regex
pub struct InstructionRegexMatcher {
    regex: regex::Regex,
    pattern: String,
}

impl InstructionRegexMatcher {
    pub fn new(pattern: impl Into<String>) -> Self {
        let pattern = pattern.into();
        let regex = regex::Regex::new(&pattern).expect("Invalid regex pattern");
        Self { regex, pattern }
    }
}

impl MockMatcher for InstructionRegexMatcher {
    fn matches(&self, context: &LlmContext) -> bool {
        self.regex.is_match(&context.instruction)
    }

    fn describe(&self) -> String {
        format!("instruction matches /{}/", self.pattern)
    }
}

/// Matcher for full prompt substring
pub struct PromptContainsMatcher {
    substring: String,
}

impl PromptContainsMatcher {
    pub fn new(substring: impl Into<String>) -> Self {
        Self {
            substring: substring.into(),
        }
    }
}

impl MockMatcher for PromptContainsMatcher {
    fn matches(&self, context: &LlmContext) -> bool {
        context.prompt.contains(&self.substring)
    }

    fn describe(&self) -> String {
        format!("prompt contains '{}'", self.substring)
    }
}

/// Matcher for event data field
pub struct EventDataMatcher {
    key: String,
    value: String,
}

impl EventDataMatcher {
    pub fn new(key: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            value: value.into(),
        }
    }
}

impl MockMatcher for EventDataMatcher {
    fn matches(&self, context: &LlmContext) -> bool {
        if let Some(field_value) = context.event_data.get(&self.key) {
            // Handle both string and numeric values
            let field_str = if let Some(s) = field_value.as_str() {
                s.to_string()
            } else if let Some(n) = field_value.as_i64() {
                n.to_string()
            } else if let Some(n) = field_value.as_u64() {
                n.to_string()
            } else if let Some(n) = field_value.as_f64() {
                n.to_string()
            } else {
                // For other types (bool, null, array, object), use JSON representation
                field_value.to_string()
            };
            field_str.contains(&self.value)
        } else {
            false
        }
    }

    fn describe(&self) -> String {
        format!("event_data[{}] contains '{}'", self.key, self.value)
    }
}

/// Matcher for iteration number
pub struct IterationMatcher {
    iteration: usize,
}

impl IterationMatcher {
    pub fn new(iteration: usize) -> Self {
        Self { iteration }
    }
}

impl MockMatcher for IterationMatcher {
    fn matches(&self, context: &LlmContext) -> bool {
        context.iteration == self.iteration
    }

    fn describe(&self) -> String {
        format!("iteration={}", self.iteration)
    }
}

/// Matcher for message role
pub struct MessageRoleMatcher {
    role: String,
}

impl MessageRoleMatcher {
    pub fn new(role: impl Into<String>) -> Self {
        Self { role: role.into() }
    }
}

impl MockMatcher for MessageRoleMatcher {
    fn matches(&self, context: &LlmContext) -> bool {
        context.message_role.as_ref() == Some(&self.role)
    }

    fn describe(&self) -> String {
        format!("message_role={}", self.role)
    }
}

/// Matcher for custom function
pub struct CustomMatcher<F>
where
    F: Fn(&LlmContext) -> bool + Send + Sync,
{
    matcher_fn: F,
}

impl<F> CustomMatcher<F>
where
    F: Fn(&LlmContext) -> bool + Send + Sync,
{
    pub fn new(matcher_fn: F) -> Self {
        Self { matcher_fn }
    }
}

impl<F> MockMatcher for CustomMatcher<F>
where
    F: Fn(&LlmContext) -> bool + Send + Sync,
{
    fn matches(&self, context: &LlmContext) -> bool {
        (self.matcher_fn)(context)
    }

    fn describe(&self) -> String {
        "custom matcher".to_string()
    }
}

/// Matcher that matches everything (fallback)
pub struct AnyMatcher;

impl MockMatcher for AnyMatcher {
    fn matches(&self, _context: &LlmContext) -> bool {
        true
    }

    fn describe(&self) -> String {
        "match any".to_string()
    }
}

/// Combined matcher (all must match)
pub struct CombinedMatcher {
    matchers: Vec<Box<dyn MockMatcher>>,
}

impl CombinedMatcher {
    pub fn new(matchers: Vec<Box<dyn MockMatcher>>) -> Self {
        Self { matchers }
    }

    pub fn add(&mut self, matcher: Box<dyn MockMatcher>) {
        self.matchers.push(matcher);
    }
}

impl MockMatcher for CombinedMatcher {
    fn matches(&self, context: &LlmContext) -> bool {
        self.matchers.iter().all(|m| m.matches(context))
    }

    fn describe(&self) -> String {
        let descriptions: Vec<String> = self.matchers.iter().map(|m| m.describe()).collect();
        descriptions.join(" AND ")
    }
}

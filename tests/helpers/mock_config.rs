//! Mock LLM configuration types
//!
//! Defines the data structures for configuring mock LLM responses in tests.

use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::Mutex;

use super::mock_matcher::{LlmContext, MockMatcher};

/// Function that generates mock actions dynamically from event data
///
/// This enables protocol-correct responses for correlation IDs (DNS query_id, STUN transaction_id, etc.)
/// The closure receives event data extracted from the LLM prompt and returns actions.
pub type ResponseGenerator =
    Arc<dyn Fn(&serde_json::Value) -> Vec<serde_json::Value> + Send + Sync>;

/// Complete mock LLM configuration
#[derive(Serialize, Deserialize)]
pub struct MockLlmConfig {
    /// Rules to match against LLM calls (evaluated in order)
    #[serde(skip)]
    pub rules: Vec<MockRule>,

    /// Serialized rules (for passing via environment variable)
    #[serde(default)]
    pub serialized_rules: Vec<SerializedMockRule>,

    /// Whether verify() was called
    #[serde(skip)]
    pub was_verified: Arc<AtomicBool>,

    /// History of all LLM calls (for debugging)
    #[serde(skip)]
    pub call_history: Arc<Mutex<Vec<MockCallRecord>>>,

    /// Problems the mock harness itself detected while serving requests
    /// (misrouted rules, response-shaped answers to startup calls, ...).
    ///
    /// These are surfaced by `verify_calls()` and by the startup helper so a
    /// misroute never degrades into an opaque "No servers or clients started".
    #[serde(skip)]
    pub harness_diagnostics: Arc<Mutex<Vec<String>>>,
}

impl Clone for MockLlmConfig {
    fn clone(&self) -> Self {
        Self {
            rules: self.rules.iter().map(|r| r.shallow_clone()).collect(),
            serialized_rules: self.serialized_rules.clone(),
            was_verified: Arc::clone(&self.was_verified),
            call_history: Arc::clone(&self.call_history),
            harness_diagnostics: Arc::clone(&self.harness_diagnostics),
        }
    }
}

impl MockLlmConfig {
    /// Create a new mock configuration
    pub fn new(rules: Vec<MockRule>) -> Self {
        // Serialize rules for environment variable passing
        let serialized_rules = rules.iter().map(|r| r.to_serialized()).collect();

        Self {
            rules,
            serialized_rules,
            was_verified: Arc::new(AtomicBool::new(false)),
            call_history: Arc::new(Mutex::new(Vec::new())),
            harness_diagnostics: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Create from serialized format (from environment variable)
    pub fn from_serialized(serialized: Vec<SerializedMockRule>) -> Self {
        let rules = serialized
            .iter()
            .map(|s| MockRule::from_serialized(s.clone()))
            .collect();

        Self {
            rules,
            serialized_rules: serialized,
            was_verified: Arc::new(AtomicBool::new(false)),
            call_history: Arc::new(Mutex::new(Vec::new())),
            harness_diagnostics: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Find matching response for the given context (synchronous version)
    ///
    /// This version does NOT record to call_history to avoid holding locks across await points.
    /// Returns (idx, response, rule_description) if matched.
    pub fn find_match_sync(&self, context: &LlmContext) -> Option<(usize, MockResponse, String)> {
        for (idx, rule) in self.rules.iter().enumerate() {
            if rule.matches(context) {
                // Increment call count
                rule.actual_calls.fetch_add(1, Ordering::SeqCst);

                return Some((idx, rule.response.clone(), rule.describe()));
            }
        }

        None
    }

    /// Record a matched call to history (separate method to avoid holding config lock)
    pub async fn record_call(
        &self,
        context: LlmContext,
        matched_rule_idx: usize,
        rule_description: String,
    ) {
        let mut history = self.call_history.lock().await;
        history.push(MockCallRecord {
            context,
            matched_rule_idx,
            rule_description,
        });
    }

    /// Find matching response for the given context
    ///
    /// DEPRECATED: Use find_match_sync() + record_call() to avoid holding locks across await.
    pub async fn find_match(&self, context: &LlmContext) -> Option<(usize, MockResponse)> {
        if let Some((idx, response, description)) = self.find_match_sync(context) {
            self.record_call(context.clone(), idx, description).await;
            Some((idx, response))
        } else {
            None
        }
    }

    /// Record a problem the harness itself detected (not a rule mismatch).
    ///
    /// Also echoed to stderr immediately: a misroute usually kills the test
    /// long before `verify_mocks()` is reached.
    pub async fn record_harness_diagnostic(&self, message: String) {
        eprintln!("🚨 MOCK HARNESS: {}", message);
        self.harness_diagnostics.lock().await.push(message);
    }

    /// All problems the harness detected, formatted for a failure message.
    /// Returns `None` when nothing went wrong.
    pub async fn harness_diagnostics_report(&self) -> Option<String> {
        let diagnostics = self.harness_diagnostics.lock().await;
        if diagnostics.is_empty() {
            return None;
        }

        let mut report = String::from("Mock harness detected inconsistent LLM routing:\n");
        for (idx, diagnostic) in diagnostics.iter().enumerate() {
            report.push_str(&format!("  {}. {}\n", idx + 1, diagnostic));
        }
        Some(report)
    }

    /// Mark as verified
    pub fn mark_verified(&self) {
        self.was_verified.store(true, Ordering::SeqCst);
    }

    /// Check if verified
    pub fn is_verified(&self) -> bool {
        self.was_verified.load(Ordering::SeqCst)
    }
}

/// A single mock rule with matching criteria and response
pub struct MockRule {
    /// Matcher for this rule (trait object, not serializable).
    ///
    /// `Arc`, not `Box`, because `shallow_clone` has to carry it: the config is cloned once on
    /// its way to the in-process mock server, and dropping the matcher there is what made
    /// `.on_custom()` predicates unreachable.
    matcher: Option<Arc<dyn MockMatcher>>,

    /// Serialized matcher data
    serialized_matcher: SerializedMatcher,

    /// Response to return
    pub response: MockResponse,

    /// Expected exact number of invocations (None = any number)
    pub expected_calls: Option<usize>,

    /// Minimum number of invocations
    pub min_calls: Option<usize>,

    /// Maximum number of invocations
    pub max_calls: Option<usize>,

    /// Actual number of invocations (tracked at runtime)
    pub actual_calls: Arc<AtomicUsize>,

    /// How long the mock takes to answer when this rule matches.
    ///
    /// A mock answers in microseconds and a real model in seconds, and a client or harness
    /// that gives up in between passes every mocked test. `tests/eval/probe_check.rs` uses
    /// this to stand in for a model call.
    pub delay: Option<std::time::Duration>,

    /// Held until the test releases it, when set: the call is recorded, then the answer waits.
    ///
    /// For a test whose premise is "this happened while the model was still answering". A
    /// delay only makes that likely, and under load the premise fails without the code under
    /// test doing anything wrong; a gate makes it true by construction.
    pub gate: Option<MockGate>,
}

/// A gate a mock rule's answer waits on until the test calls [`MockGate::release`].
///
/// Released once, open for good: every call held on it, and every later one, proceeds. A
/// release before the call arrives is not lost.
#[derive(Clone)]
pub struct MockGate(Arc<tokio::sync::Semaphore>);

impl MockGate {
    pub fn new() -> Self {
        Self(Arc::new(tokio::sync::Semaphore::new(0)))
    }

    /// Let every held answer, and every later one, go.
    pub fn release(&self) {
        // A closed semaphore fails every pending and future `acquire`, which is the open state.
        self.0.close();
    }

    /// Wait until [`Self::release`] has been called.
    pub async fn wait(&self) {
        let _ = self.0.acquire().await;
    }
}

impl Default for MockGate {
    fn default() -> Self {
        Self::new()
    }
}

impl MockRule {
    /// Create a new mock rule
    pub fn new(
        matcher: Box<dyn MockMatcher>,
        serialized_matcher: SerializedMatcher,
        response: MockResponse,
    ) -> Self {
        Self {
            matcher: Some(Arc::from(matcher)),
            serialized_matcher,
            response,
            expected_calls: None,
            min_calls: None,
            max_calls: None,
            actual_calls: Arc::new(AtomicUsize::new(0)),
            delay: None,
            gate: None,
        }
    }

    /// Check if context matches this rule
    pub fn matches(&self, context: &LlmContext) -> bool {
        // A closure cannot be serialized, so `on_custom` stores `match_any = true` in the
        // serialized matcher as a placeholder. Consulting only the serialized matcher therefore
        // turned every `.on_custom(pred)` into `.on_any()` - the predicate was never called, and
        // seven call sites in the grpc/http2/quic suites were relying on it to filter.
        if self.serialized_matcher.has_custom_predicate {
            return match self.matcher.as_ref() {
                Some(matcher) => matcher.matches(context),
                // Fail closed. Reaching here means the rule survived a round trip through
                // `NETGET_MOCK_LLM_CONFIG` that dropped the closure; matching everything would
                // silently restore exactly the bug this branch exists to fix.
                None => false,
            };
        }
        self.serialized_matcher.matches(context)
    }

    /// Get description of this rule
    pub fn describe(&self) -> String {
        if self.serialized_matcher.has_custom_predicate {
            return match self.matcher.as_ref() {
                Some(matcher) => matcher.describe(),
                None => "custom predicate (lost in serialization - matches nothing)".to_string(),
            };
        }
        self.serialized_matcher.describe()
    }

    /// The `event_type` this rule requires, if it is an `on_event(...)` rule.
    ///
    /// Used by the mock server to detect a misroute: an event rule matching a
    /// request that is not a network event at all.
    pub fn matcher_event_type(&self) -> Option<&str> {
        self.serialized_matcher.event_type.as_deref()
    }

    /// Convert to serialized format
    pub fn to_serialized(&self) -> SerializedMockRule {
        SerializedMockRule {
            matcher: self.serialized_matcher.clone(),
            response: self.response.clone(),
            expected_calls: self.expected_calls,
            min_calls: self.min_calls,
            max_calls: self.max_calls,
            delay_ms: self.delay.map(|d| d.as_millis() as u64),
        }
    }

    /// Create from serialized format
    pub fn from_serialized(s: SerializedMockRule) -> Self {
        Self {
            matcher: None, // Matcher not needed for deserialized rules
            serialized_matcher: s.matcher,
            response: s.response,
            expected_calls: s.expected_calls,
            min_calls: s.min_calls,
            max_calls: s.max_calls,
            actual_calls: Arc::new(AtomicUsize::new(0)),
            delay: s.delay_ms.map(std::time::Duration::from_millis),
            // A gate is an in-process handle; a rule that crossed a process boundary has none.
            gate: None,
        }
    }

    /// Shallow clone (clones Arc references, not underlying data)
    pub fn shallow_clone(&self) -> Self {
        Self {
            // Keep the matcher. `MockLlmConfig::clone()` is on the path from the test's builder
            // to the in-process mock server, so dropping it here disabled custom predicates.
            matcher: self.matcher.clone(),
            serialized_matcher: self.serialized_matcher.clone(),
            response: self.response.clone(),
            expected_calls: self.expected_calls,
            min_calls: self.min_calls,
            max_calls: self.max_calls,
            actual_calls: Arc::clone(&self.actual_calls),
            delay: self.delay,
            gate: self.gate.clone(),
        }
    }
}

/// Serializable mock rule (for environment variable passing)
#[derive(Clone, Serialize, Deserialize)]
pub struct SerializedMockRule {
    pub matcher: SerializedMatcher,
    pub response: MockResponse,
    pub expected_calls: Option<usize>,
    pub min_calls: Option<usize>,
    pub max_calls: Option<usize>,
    #[serde(default)]
    pub delay_ms: Option<u64>,
}

/// Serializable matcher (combines all matching criteria)
#[derive(Clone, Serialize, Deserialize)]
pub struct SerializedMatcher {
    /// Event type exact match
    pub event_type: Option<String>,

    /// Instruction substring match
    pub instruction_contains: Vec<String>,

    /// Instruction regex match
    pub instruction_regex: Option<String>,

    /// Event data field matches (key -> value substring)
    pub event_data_contains: Vec<(String, String)>,

    /// Iteration number
    pub iteration: Option<usize>,

    /// Message role
    pub message_role: Option<String>,

    /// Prompt substring match
    pub prompt_contains: Vec<String>,

    /// Match any (fallback)
    pub match_any: bool,

    /// This rule carries an `on_custom(...)` predicate, which lives in `MockRule::matcher` and
    /// cannot be serialized. `match_any` is set alongside it purely as a placeholder, so
    /// `MockRule::matches` must consult the real matcher instead of this struct.
    #[serde(default)]
    pub has_custom_predicate: bool,
}

impl SerializedMatcher {
    /// Create a new serialized matcher
    pub fn new() -> Self {
        Self {
            event_type: None,
            instruction_contains: Vec::new(),
            instruction_regex: None,
            event_data_contains: Vec::new(),
            iteration: None,
            message_role: None,
            prompt_contains: Vec::new(),
            match_any: false,
            has_custom_predicate: false,
        }
    }

    /// Check if context matches all criteria
    pub fn matches(&self, context: &LlmContext) -> bool {
        // Match any (fallback)
        if self.match_any {
            return true;
        }

        // Event type
        if let Some(ref event_type) = self.event_type {
            if context.event_type.as_ref() != Some(event_type) {
                return false;
            }
        }

        // CRITICAL FIX: Instruction-based matching should only match user input, not network events
        // If this rule uses instruction matching but the context has an event_type,
        // it means this is a network event (not user input), so skip instruction matching
        let has_instruction_criteria =
            !self.instruction_contains.is_empty() || self.instruction_regex.is_some();
        let is_network_event = context.event_type.is_some();

        if has_instruction_criteria && is_network_event && self.event_type.is_none() {
            // This rule is instruction-based (meant for user input) but context is a network event
            // Don't match unless the rule explicitly specifies an event_type
            return false;
        }

        // Instruction contains (all must match)
        for substring in &self.instruction_contains {
            if !context.instruction.contains(substring) {
                return false;
            }
        }

        // Instruction regex
        if let Some(ref regex_str) = self.instruction_regex {
            if let Ok(regex) = regex::Regex::new(regex_str) {
                if !regex.is_match(&context.instruction) {
                    return false;
                }
            } else {
                return false;
            }
        }

        // Event data contains
        for (key, value) in &self.event_data_contains {
            if let Some(field_value) = context.event_data.get(key) {
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
                if !field_str.contains(value) {
                    return false;
                }
            } else {
                return false;
            }
        }

        // Iteration
        if let Some(expected_iter) = self.iteration {
            if context.iteration != expected_iter {
                return false;
            }
        }

        // Message role
        if let Some(ref role) = self.message_role {
            if context.message_role.as_ref() != Some(role) {
                return false;
            }
        }

        // Prompt contains
        for substring in &self.prompt_contains {
            if !context.prompt.contains(substring) {
                return false;
            }
        }

        true
    }

    /// Get description of matching criteria
    pub fn describe(&self) -> String {
        if self.match_any {
            return "match any".to_string();
        }

        let mut parts = Vec::new();

        if let Some(ref event_type) = self.event_type {
            parts.push(format!("event={}", event_type));
        }

        if !self.instruction_contains.is_empty() {
            parts.push(format!(
                "instruction contains {:?}",
                self.instruction_contains
            ));
        }

        if let Some(ref regex) = self.instruction_regex {
            parts.push(format!("instruction matches /{}/", regex));
        }

        if !self.event_data_contains.is_empty() {
            parts.push(format!("event_data {:?}", self.event_data_contains));
        }

        if let Some(iter) = self.iteration {
            parts.push(format!("iteration={}", iter));
        }

        if let Some(ref role) = self.message_role {
            parts.push(format!("role={}", role));
        }

        if !self.prompt_contains.is_empty() {
            parts.push(format!("prompt contains {:?}", self.prompt_contains));
        }

        if parts.is_empty() {
            "no criteria".to_string()
        } else {
            parts.join(", ")
        }
    }
}

impl Default for SerializedMatcher {
    fn default() -> Self {
        Self::new()
    }
}

/// Response types
pub enum MockResponse {
    /// Valid action response (parsed as JSON)
    Actions { actions: Vec<serde_json::Value> },

    /// Dynamic actions generated from event data (not serializable)
    ///
    /// This variant allows mock responses to access event data at runtime,
    /// enabling protocol-correct responses for correlation IDs.
    /// Cannot be serialized to environment variables.
    DynamicActions { generator: ResponseGenerator },

    /// Raw string (for testing LLM failures/malformed responses)
    Raw { content: String },
}

impl MockResponse {
    /// Convert to string for LLM response
    ///
    /// # Arguments
    /// * `event_data` - Event data from LLM context (for dynamic responses)
    pub fn to_response_string(&self, event_data: Option<&serde_json::Value>) -> String {
        match self {
            MockResponse::Actions { actions } => {
                // Wrap actions in ActionResponse format
                serde_json::json!({
                    "actions": actions
                })
                .to_string()
            }

            MockResponse::DynamicActions { generator } => {
                let empty_obj = serde_json::json!({});
                let event_data = event_data.unwrap_or(&empty_obj);
                let actions = generator(event_data);
                serde_json::json!({
                    "actions": actions
                })
                .to_string()
            }

            MockResponse::Raw { content } => content.clone(),
        }
    }
}

// Manual Clone implementation (can't derive due to DynamicActions)
impl Clone for MockResponse {
    fn clone(&self) -> Self {
        match self {
            MockResponse::Actions { actions } => MockResponse::Actions {
                actions: actions.clone(),
            },
            MockResponse::DynamicActions { generator } => MockResponse::DynamicActions {
                generator: Arc::clone(generator),
            },
            MockResponse::Raw { content } => MockResponse::Raw {
                content: content.clone(),
            },
        }
    }
}

// Manual Serialize implementation (DynamicActions cannot be serialized)
impl Serialize for MockResponse {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;

        match self {
            MockResponse::Actions { actions } => {
                let mut state = serializer.serialize_struct("MockResponse", 2)?;
                state.serialize_field("type", "actions")?;
                state.serialize_field("actions", actions)?;
                state.end()
            }
            MockResponse::DynamicActions { .. } => Err(serde::ser::Error::custom(
                "DynamicActions cannot be serialized. \
                     Dynamic mocks require MOCK_OLLAMA_BASE_URL (in-process mock server), \
                     not NETGET_MOCK_LLM_CONFIG (environment variable serialization).",
            )),
            MockResponse::Raw { content } => {
                let mut state = serializer.serialize_struct("MockResponse", 2)?;
                state.serialize_field("type", "raw")?;
                state.serialize_field("content", content)?;
                state.end()
            }
        }
    }
}

// Manual Deserialize implementation (DynamicActions intentionally not deserializable)
impl<'de> Deserialize<'de> for MockResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(tag = "type", rename_all = "snake_case")]
        enum MockResponseHelper {
            Actions { actions: Vec<serde_json::Value> },
            Raw { content: String },
            // DynamicActions intentionally not deserializable
        }

        let helper = MockResponseHelper::deserialize(deserializer)?;
        Ok(match helper {
            MockResponseHelper::Actions { actions } => MockResponse::Actions { actions },
            MockResponseHelper::Raw { content } => MockResponse::Raw { content },
        })
    }
}

/// Backstop for a test that configured mocks and never called `verify_mocks()`.
///
/// This used to `eprintln!` a warning. At `--test-threads=100` nobody has ever read it, and 24
/// test files had drifted into asserting nothing about LLM interaction while still counting as
/// coverage. A warning that is never read is not a guard, so this now **fails the test** — but
/// only when there is something real to check:
///
/// * a config whose rules carry no `expect_calls` / `expect_at_least` / `expect_at_most` has no
///   expectation to break, so it only warns. Requiring `verify_mocks()` there would be noise.
/// * if the thread is already panicking, panicking again in `Drop` aborts the process and
///   destroys the real failure message, so we print instead.
///
/// Call `verify_mocks().await?` at the end of the test to satisfy it.
pub fn report_unverified_on_drop(kind: &str, mock_config: &MockLlmConfig) {
    let mut unmet = Vec::new();
    let mut has_expectations = false;

    for (idx, rule) in mock_config.rules.iter().enumerate() {
        let actual = rule.actual_calls.load(Ordering::SeqCst);
        if rule.expected_calls.is_none() && rule.min_calls.is_none() && rule.max_calls.is_none() {
            continue;
        }
        has_expectations = true;

        let broken = rule.expected_calls.is_some_and(|e| actual != e)
            || rule.min_calls.is_some_and(|m| actual < m)
            || rule.max_calls.is_some_and(|m| actual > m);
        if broken {
            unmet.push(format!(
                "   Rule #{}: expected {}{}{}, got {} - {}",
                idx,
                rule.expected_calls
                    .map(|e| format!("exactly {e}"))
                    .unwrap_or_default(),
                rule.min_calls
                    .map(|m| format!("at least {m}"))
                    .unwrap_or_default(),
                rule.max_calls
                    .map(|m| format!("at most {m}"))
                    .unwrap_or_default(),
                actual,
                rule.describe()
            ));
        }
    }

    let mut message = format!(
        "{} dropped without calling .verify_mocks(), so this test asserted nothing about LLM \
         interaction.\n   Add `{}.verify_mocks().await?;` before the end of the test.",
        if kind == "server" { "Server" } else { "Client" },
        kind
    );
    if !unmet.is_empty() {
        message.push_str("\n   Unmet expectations already visible:\n");
        message.push_str(&unmet.join("\n"));
    }

    // Panic only when something is actually unmet.
    //
    // A test that returns `Err` early -- typically because an EARLIER
    // `verify_mocks()?` on the other end failed -- drops this config without
    // reaching its own `verify_mocks`. That is not a panic, so the guard below
    // does not see it, and panicking here replaces the real error with "you
    // forgot to call verify_mocks". That is exactly backwards: the test did
    // call it, on the half that failed. A cassandra client test lost its
    // server-side failure message this way and read as a harness complaint.
    //
    // When every expectation is met, the mocks did assert what they were there
    // to assert, so a missing `verify_mocks()` is worth a warning and nothing
    // more. When something is unmet the panic still fires, carrying the list.
    if has_expectations && !unmet.is_empty() && !std::thread::panicking() {
        panic!("{message}");
    }

    eprintln!("⚠️  WARNING: {message}");
}

/// Sentinel `matched_rule_idx` for calls the mock harness answered itself
/// (currently only the forced `open_server` documentation retry). Such calls
/// consume no rule and count against no `expect_calls`.
pub const HARNESS_ANSWERED_RULE_IDX: usize = usize::MAX;

/// Record of a mock LLM call
#[derive(Clone)]
pub struct MockCallRecord {
    /// Context of the call
    pub context: LlmContext,
    /// Index of matched rule
    pub matched_rule_idx: usize,
    /// Description of matched rule
    pub rule_description: String,
}

impl MockCallRecord {
    /// Human-readable label for what answered this call.
    pub fn rule_label(&self) -> String {
        if self.matched_rule_idx == HARNESS_ANSWERED_RULE_IDX {
            "<harness>".to_string()
        } else {
            format!("rule #{}", self.matched_rule_idx)
        }
    }

    /// One-line summary for failure output.
    pub fn describe(&self) -> String {
        format!(
            "kind={:?} event={} -> {} ({})",
            self.context.request_kind,
            self.context.event_type.as_deref().unwrap_or("(none)"),
            self.rule_label(),
            self.rule_description
        )
    }
}

/// Poll until every expectation in `config` is satisfied, or `timeout_secs` elapses.
///
/// "Satisfied" means each rule has reached its `expect_calls` / `expect_at_least` floor;
/// `expect_at_most` needs no waiting, since exceeding it cannot be cured by waiting longer.
/// Returns quietly either way — the caller's `verify_mocks` is what asserts, and it names
/// the rule that fell short. This exists only so a test stops racing the exchange it is
/// testing.
pub async fn wait_for_mock_expectations(config: &MockLlmConfig, timeout_secs: u64) {
    let start = std::time::Instant::now();
    let deadline = std::time::Duration::from_secs(timeout_secs);
    loop {
        let satisfied = config.rules.iter().all(|rule| {
            let actual = rule.actual_calls.load(std::sync::atomic::Ordering::SeqCst);
            let floor = rule.expected_calls.or(rule.min_calls).unwrap_or(0);
            actual >= floor
        });
        if satisfied || start.elapsed() >= deadline {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}

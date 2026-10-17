//! Mock Ollama HTTP server for E2E testing
//!
//! This server mimics Ollama's HTTP API and allows tests to provide
//! mock responses without needing a real Ollama instance.
//!
//! Key benefits:
//! - Call counting works (server tracks calls in same process as test)
//! - No subprocess memory isolation issues
//! - True E2E testing (netget subprocess makes real HTTP calls)
//! - Easy debugging (server can log all requests)

use super::common::E2EResult;
use super::mock_config::{MockLlmConfig, HARNESS_ANSWERED_RULE_IDX};
use super::mock_matcher::{LlmContext, RequestKind};
use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::{oneshot, Mutex};
use tracing::{debug, info, warn};

/// Mock Ollama server that responds with configured mock responses
pub struct MockOllamaServer {
    /// Port the server is listening on
    pub port: u16,
    /// Mock configuration (shared with handler)
    config: Arc<Mutex<MockLlmConfig>>,
    /// `/api/tags` hits (shared with the handler)
    tags_hits: Arc<AtomicUsize>,
    /// Top-level request fields other than the prompt/messages, per request, in order.
    request_fields: RecordedFields,
    /// Shutdown signal
    _shutdown_tx: oneshot::Sender<()>,
}

/// Ollama chat request format
#[derive(Debug, Deserialize)]
struct OllamaChatRequest {
    model: String,
    messages: Vec<OllamaMessage>,
    #[serde(default)]
    #[allow(dead_code)]
    stream: bool,
    #[serde(default)]
    #[allow(dead_code)]
    format: Option<serde_json::Value>,
    /// Every other top-level field (`options`, `tools`, …), kept verbatim so a test can
    /// assert what NetGet put on the wire. See [`MockOllamaServer::recorded_request_fields`].
    #[serde(flatten)]
    extra: serde_json::Map<String, serde_json::Value>,
}

/// Ollama message format
#[derive(Debug, Deserialize)]
struct OllamaMessage {
    role: String,
    content: String,
}

/// Ollama chat response format
#[derive(Debug, Serialize)]
struct OllamaChatResponse {
    model: String,
    created_at: String,
    message: OllamaResponseMessage,
    done: bool,
}

/// Ollama response message
#[derive(Debug, Serialize)]
struct OllamaResponseMessage {
    role: String,
    content: String,
}

/// Ollama generate request format
#[derive(Debug, Deserialize)]
struct OllamaGenerateRequest {
    model: String,
    prompt: String,
    #[serde(default)]
    #[allow(dead_code)]
    stream: bool,
    #[serde(default)]
    #[allow(dead_code)]
    format: Option<serde_json::Value>,
    /// Every other top-level field (`options`, `tools`, …), kept verbatim so a test can
    /// assert what NetGet put on the wire. See [`MockOllamaServer::recorded_request_fields`].
    #[serde(flatten)]
    extra: serde_json::Map<String, serde_json::Value>,
}

/// Ollama generate response format
#[derive(Debug, Serialize)]
struct OllamaGenerateResponse {
    model: String,
    created_at: String,
    response: String,
    done: bool,
}

/// Ollama tags/models response
#[derive(Debug, Serialize)]
struct OllamaTagsResponse {
    models: Vec<OllamaModel>,
}

#[derive(Debug, Serialize)]
struct OllamaModel {
    name: String,
    modified_at: String,
    size: u64,
}

/// Shared state for axum handlers
#[derive(Clone)]
struct ServerState {
    config: Arc<Mutex<MockLlmConfig>>,
    /// How many `/api/tags` requests this endpoint has received.
    ///
    /// Model auto-selection is a `GET /api/tags`, not a chat call, so it is invisible to
    /// `call_history`. Counting it separately is what distinguishes "asked this endpoint and
    /// it had nothing" from "asked a different endpoint entirely" — the shape of the bug
    /// `tests/model_selection_endpoint_test.rs` pins.
    tags_hits: Arc<AtomicUsize>,
    /// `(endpoint, fields)` for every `/api/chat` and `/api/generate` request.
    request_fields: RecordedFields,
}

/// `(endpoint, top-level fields other than the prompt/messages)` per request.
type RecordedFields = Arc<std::sync::Mutex<Vec<(String, serde_json::Value)>>>;

fn record_request_fields(
    state: &ServerState,
    endpoint: &str,
    stream: bool,
    format: &Option<serde_json::Value>,
    extra: &serde_json::Map<String, serde_json::Value>,
) {
    let mut fields = extra.clone();
    fields.insert("stream".to_string(), serde_json::json!(stream));
    if let Some(format) = format {
        fields.insert("format".to_string(), format.clone());
    }
    state
        .request_fields
        .lock()
        .expect("request_fields poisoned")
        .push((endpoint.to_string(), serde_json::Value::Object(fields)));
}

// ============================================================================
// Request classification
// ============================================================================
//
// NetGet renders a *different prompt template* per situation. That template
// choice — not the prompt's wording — is what distinguishes a live network
// event from a user command, and it is the only signal that cannot rot as
// protocol text changes:
//
//   * `prompts/network_request/**`  -> handling a network event on a running server
//   * `prompts/user_input/**`       -> interpreting a user command (e.g. "listen on port N")
//   * `src/llm/action_helper.rs`    -> `call_llm_for_client` builds the client-side
//                                      network-event prompt inline (no template)
//
// Sniffing the prompt *body* for protocol/event names does not work, and used
// to be the bug this module carried: `open_server` forces a
// `DocumentationRequired` retry whose message embeds the protocol's own
// documentation, and that documentation lists every event as
// `### Event: http_request`. The old extractor picked that line up and
// reported `event_type: Some("http_request")` for the **startup** call, so an
// `on_event("http_request")` rule answered it with `send_http_response`, the
// startup path rejected the unknown action, and no server ever started.

/// Marker sentences emitted only by network-event prompts.
///
/// Sources (all read-only from this crate's point of view):
/// - `prompts/network_request/task.hbs`
/// - `prompts/network_request/partials/instructions.hbs`
/// - `src/llm/action_helper.rs::call_llm_for_client` (client system prompt)
/// - `prompts/easy_request/main.hbs` (easy mode, still a network request)
const NETWORK_EVENT_TEMPLATE_MARKERS: &[&str] = &[
    "You are being invoked in response to a network event",
    "## Network Event Instructions",
    "You are controlling a network client",
    "## Network Request Received",
];

/// Marker sentences emitted only by `prompts/user_input/task.hbs`.
const USER_INPUT_TEMPLATE_MARKERS: &[&str] = &[
    "You are an API that interprets user commands",
    "The user wants to start servers, connect clients",
];

/// Phrases from `ActionExecutionError::DocumentationRequired`
/// (`src/events/errors.rs`) — the forced read-the-docs retry before the first
/// `open_server` / `open_client` is allowed through.
const DOCUMENTATION_RETRY_MARKERS: &[&str] = &[
    "you must first read the documentation",
    "you must provide the action again",
];

/// The literal user message a scheduled-task run sends
/// (`src/cli/tasks.rs`). Everything that identifies the task lives in
/// the system prompt, which ends with `\n\nTrigger: Scheduled task '<name>' …`.
const SCHEDULED_TASK_TRIGGER_MESSAGE: &str = "Execute the task.";

/// Marker introducing the trigger block at the end of a task system prompt
/// (`PromptBuilder::build_task_execution_prompt`).
const TASK_TRIGGER_MARKER: &str = "\n\nTrigger: ";

fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|n| haystack.contains(n))
}

/// Classify a request from the template text (system prompt / whole prompt)
/// and the latest turn addressed to the model.
fn classify_request(template_text: &str, latest_message: &str) -> RequestKind {
    // Checked first: a server-scoped task renders `network_request/main` too,
    // but it is triggered by a timer, not by a packet.
    if latest_message.trim() == SCHEDULED_TASK_TRIGGER_MESSAGE
        && template_text.contains(TASK_TRIGGER_MARKER)
    {
        return RequestKind::ScheduledTask;
    }

    if contains_any(template_text, NETWORK_EVENT_TEMPLATE_MARKERS) {
        return RequestKind::NetworkEvent;
    }

    let latest_lower = latest_message.to_lowercase();
    if DOCUMENTATION_RETRY_MARKERS
        .iter()
        .all(|m| latest_lower.contains(m))
    {
        return RequestKind::DocumentationRetry;
    }

    if contains_any(template_text, USER_INPUT_TEMPLATE_MARKERS) {
        return RequestKind::UserInput;
    }

    RequestKind::Unknown
}

/// The current event's trigger: from the **last** line that opens one to the end of the prompt.
///
/// A prompt can carry earlier exchanges on the same connection ahead of the event being
/// answered (`src/state/exchange_history.rs`), so the first trigger-looking text is not
/// necessarily the current one. The server trigger opens with `Event ID:`, the client one with
/// `Event:`; only a line that *starts* with the label counts, which history entries and
/// pretty-printed event data never do.
fn current_trigger(text: &str) -> &str {
    let mut offset = 0usize;
    let mut event_id_at = None;
    let mut event_at = None;
    for line in text.split_inclusive('\n') {
        let trimmed = line.trim_start();
        if trimmed.starts_with("Event ID:") {
            event_id_at = Some(offset);
        } else if trimmed.starts_with("Event:") {
            event_at = Some(offset);
        }
        offset += line.len();
    }
    match event_id_at.or(event_at) {
        Some(at) => &text[at..],
        None => text,
    }
}

/// Extract the event id from a network-event trigger message.
///
/// Only ever called for requests classified as network events, so the
/// `Event:` fallback cannot latch onto a `### Event: <id>` heading inside
/// embedded protocol documentation.
fn extract_event_type(text: &str) -> Option<String> {
    let text = current_trigger(text);
    // Preferred: "Event ID: <id>" (PromptBuilder::build_event_trigger_message_with_id)
    if let Some(event_id_line) = text.lines().find(|line| line.contains("Event ID:")) {
        if let Some(event_id) = event_id_line.split("Event ID:").nth(1) {
            let event_id = event_id.trim();
            if !event_id.is_empty() {
                debug!("🔧 Extracted event type from Event ID: '{}'", event_id);
                return Some(event_id.to_string());
            }
        }
    }

    // Legacy: "Event: <description>" (PromptBuilder::build_event_trigger_message)
    if let Some(event_line) = text.lines().find(|line| line.contains("Event:")) {
        if let Some(event_type) = event_line.split("Event:").nth(1) {
            let event_type = event_type.trim().split_whitespace().next().unwrap_or("");
            if !event_type.is_empty() {
                debug!("🔧 Extracted event type from Event: '{}'", event_type);
                return Some(event_type.to_string());
            }
        }
    }

    None
}

/// Action name prefixes/suffixes that only make sense as a reply on the wire.
/// Seeing one of these answer a *startup* call means a rule was misrouted.
fn response_shaped_action_names(response_text: &str) -> Vec<String> {
    let parsed: serde_json::Value = match serde_json::from_str(response_text) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };

    parsed
        .get("actions")
        .and_then(|a| a.as_array())
        .map(|actions| {
            actions
                .iter()
                .filter_map(|a| a.get("type").and_then(|t| t.as_str()))
                .filter(|name| {
                    name.starts_with("send_")
                        || name.starts_with("respond_")
                        || name.ends_with("_response")
                })
                .map(|name| name.to_string())
                .collect()
        })
        .unwrap_or_default()
}

/// The last assistant turn that carries an `{"actions": [...]}` payload.
///
/// Used to satisfy the documentation gate: the retry literally asks the model
/// to "provide the action again", so replaying its own previous answer is the
/// correct response and needs no per-test mock rule.
fn last_assistant_action_payload(messages: &[OllamaMessage]) -> Option<String> {
    messages.iter().rev().find_map(|m| {
        if m.role != "assistant" {
            return None;
        }
        let content = m.content.trim();
        let parsed: serde_json::Value = serde_json::from_str(content).ok()?;
        let actions = parsed.get("actions")?.as_array()?;
        if actions.is_empty() {
            None
        } else {
            Some(content.to_string())
        }
    })
}

impl MockOllamaServer {
    /// Start a mock Ollama server on a random available port
    ///
    /// The server will:
    /// 1. Listen on 127.0.0.1 with OS-assigned port
    /// 2. Implement `/api/chat` and `/api/tags` endpoints
    /// 3. Use provided mock config to generate responses
    /// 4. Track call counts for verification
    pub async fn start(config: MockLlmConfig) -> E2EResult<Self> {
        let config = Arc::new(Mutex::new(config));
        let tags_hits = Arc::new(AtomicUsize::new(0));
        let request_fields: RecordedFields = Default::default();
        let state = ServerState {
            config: config.clone(),
            tags_hits: tags_hits.clone(),
            request_fields: request_fields.clone(),
        };

        // Build router with Ollama-compatible endpoints
        let app = Router::new()
            .route("/api/chat", post(handle_chat))
            .route("/api/generate", post(handle_generate))
            .route("/api/tags", get(handle_tags))
            .route("/api/version", get(handle_version))
            .with_state(state);

        // Bind to random port
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|e| format!("Failed to bind mock Ollama server: {}", e))?;

        let port = listener
            .local_addr()
            .map_err(|e| format!("Failed to get local addr: {}", e))?
            .port();

        info!("🔧 Mock Ollama server starting on port {}", port);

        // Create shutdown channel
        let (_shutdown_tx, shutdown_rx) = oneshot::channel();

        // Spawn server in background
        tokio::spawn(async move {
            let server = axum::serve(listener, app).with_graceful_shutdown(async {
                shutdown_rx.await.ok();
            });

            if let Err(e) = server.await {
                warn!("Mock Ollama server error: {}", e);
            }
        });

        // Give server a moment to start
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        info!("✅ Mock Ollama server ready on port {}", port);

        Ok(Self {
            port,
            config,
            tags_hits,
            request_fields,
            _shutdown_tx,
        })
    }

    /// Get the base URL for this server
    pub fn base_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    /// How many `/api/tags` requests reached this endpoint.
    ///
    /// Model auto-selection lands here rather than in `recorded_calls()`, so this is how a
    /// test proves NetGet asked *this* endpoint which models it has.
    pub fn tags_request_count(&self) -> usize {
        self.tags_hits.load(Ordering::SeqCst)
    }

    /// For every `/api/chat` and `/api/generate` request, in order: the endpoint and every
    /// top-level field except the prompt, the messages and the model — `options`, `tools`,
    /// `stream`, `format`. This is the wire, not NetGet's idea of it, so it is how a test
    /// proves which sampling options were (or were not) sent.
    pub fn recorded_request_fields(&self) -> Vec<(String, serde_json::Value)> {
        self.request_fields
            .lock()
            .expect("request_fields poisoned")
            .clone()
    }

    /// Every call the model actually received, in order.
    ///
    /// `verify_calls` asserts against *rule expectations*; this answers the blunter question
    /// "was the model consulted at all?", which is what a test of deterministic routing needs.
    /// A handler that is supposed to answer without a round-trip is proven only by a zero here
    /// — and only alongside a control that shows a non-zero, or the zero proves nothing.
    pub async fn recorded_calls(&self) -> Vec<super::mock_config::MockCallRecord> {
        let config = self.config.lock().await;
        let history = config.call_history.lock().await;
        history.clone()
    }

    /// How many LLM calls reached the model.
    pub async fn call_count(&self) -> usize {
        self.recorded_calls().await.len()
    }

    /// Verify that all mock expectations were met
    pub async fn verify_calls(&self) -> E2EResult<()> {
        // Add timeout to prevent deadlock on lock acquisition
        let config = tokio::time::timeout(std::time::Duration::from_secs(10), self.config.lock())
            .await
            .map_err(|_| "Timeout acquiring mock config lock (deadlock detected)")?;

        config.mark_verified();

        let mut errors = Vec::new();

        for (idx, rule) in config.rules.iter().enumerate() {
            let actual = rule.actual_calls.load(std::sync::atomic::Ordering::SeqCst);

            // Check exact count
            if let Some(expected) = rule.expected_calls {
                if actual != expected {
                    errors.push(format!(
                        "Rule #{} ({}): Expected {} calls, got {}",
                        idx,
                        rule.describe(),
                        expected,
                        actual
                    ));
                }
            }

            // Check minimum
            if let Some(min) = rule.min_calls {
                if actual < min {
                    errors.push(format!(
                        "Rule #{} ({}): Expected at least {} calls, got {}",
                        idx,
                        rule.describe(),
                        min,
                        actual
                    ));
                }
            }

            // Check maximum
            if let Some(max) = rule.max_calls {
                if actual > max {
                    errors.push(format!(
                        "Rule #{} ({}): Expected at most {} calls, got {}",
                        idx,
                        rule.describe(),
                        max,
                        actual
                    ));
                }
            }
        }

        // Informational: they explain why counts are off, but never fail a run
        // that otherwise met its expectations.
        let harness_report = config.harness_diagnostics_report().await;

        if !errors.is_empty() {
            let mut error_msg = String::from("Mock verification failed:\n");
            for error in &errors {
                error_msg.push_str("  ");
                error_msg.push_str(error);
                error_msg.push('\n');
            }

            if let Some(ref report) = harness_report {
                error_msg.push('\n');
                error_msg.push_str(report);
            }

            // Get call history for debugging (with timeout to prevent deadlock)
            let history = tokio::time::timeout(
                std::time::Duration::from_secs(10),
                config.call_history.lock(),
            )
            .await
            .map_err(|_| "Timeout acquiring call history lock (deadlock detected)")?;
            if !history.is_empty() {
                error_msg.push_str("\nAll LLM call history:\n");
                for (idx, call) in history.iter().enumerate() {
                    error_msg.push_str(&format!("  Call #{}: ", idx + 1));
                    error_msg.push_str(&format!("kind={:?} ", call.context.request_kind));
                    error_msg.push_str(&format!("instruction=\"{}\" ", call.context.instruction));
                    if let Some(ref event_type) = call.context.event_type {
                        error_msg.push_str(&format!("event_type=\"{}\" ", event_type));
                    }
                    error_msg.push_str(&format!("-> {}", call.rule_description));
                    error_msg.push('\n');
                }
            }

            return Err(error_msg.into());
        }

        Ok(())
    }

    /// Problems the harness detected while serving requests, if any.
    ///
    /// Exposed so startup failures can explain themselves before a test ever
    /// reaches `verify_mocks()`.
    pub async fn harness_diagnostics_report(&self) -> Option<String> {
        let config = tokio::time::timeout(std::time::Duration::from_secs(10), self.config.lock())
            .await
            .ok()?;
        config.harness_diagnostics_report().await
    }
}

/// Handle POST /api/chat
async fn handle_chat(
    State(state): State<ServerState>,
    Json(request): Json<OllamaChatRequest>,
) -> Response {
    record_request_fields(
        &state,
        "/api/chat",
        request.stream,
        &request.format,
        &request.extra,
    );
    debug!(
        "🔧 Mock Ollama received chat request: model={}, messages={}",
        request.model,
        request.messages.len()
    );

    // Extract context from request
    let context = extract_context(&request);

    // DEBUG: Log extracted context [FIX v2]
    eprintln!("🔍🔍🔍 Mock context extracted:");
    eprintln!("  request_kind: {:?}", context.request_kind);
    eprintln!("  event_type: {:?}", context.event_type);
    let instruction_preview: String = context.instruction.chars().take(200).collect();
    eprintln!("  instruction: {}", instruction_preview);
    let prompt_preview: String = context.prompt.chars().take(500).collect();
    eprintln!("  prompt preview: {}", prompt_preview);

    // The documentation gate (src/events/handler.rs) forces one extra LLM turn
    // before the first open_server/open_client succeeds. It is harness
    // plumbing, not a decision any test models, so answer it centrally by
    // replaying the model's own previous action — exactly what the retry asks
    // for ("please confirm your open_server action by providing it again").
    // No rule is consumed, so per-test `expect_calls` counts stay honest.
    if context.request_kind == RequestKind::DocumentationRetry {
        match last_assistant_action_payload(&request.messages) {
            Some(payload) => {
                eprintln!(
                    "📚 Documentation gate detected — replaying previous action (no rule consumed)"
                );
                state
                    .config
                    .lock()
                    .await
                    .record_call(
                        context.clone(),
                        HARNESS_ANSWERED_RULE_IDX,
                        "<harness> documentation gate replay (no rule consumed)".to_string(),
                    )
                    .await;

                let response = OllamaChatResponse {
                    model: request.model,
                    created_at: chrono::Utc::now().to_rfc3339(),
                    message: OllamaResponseMessage {
                        role: "assistant".to_string(),
                        content: payload,
                    },
                    done: true,
                };
                return Json(response).into_response();
            }
            None => {
                state
                    .config
                    .lock()
                    .await
                    .record_harness_diagnostic(
                        "open_server documentation gate fired but no previous assistant action \
                         was found to replay; falling back to rule matching. The startup call \
                         will most likely be answered with the wrong action."
                            .to_string(),
                    )
                    .await;
            }
        }
    }

    // Get mock response (using synchronous matching to avoid holding lock across await)
    let (match_result, matched_rule_event_type) = {
        let config = state.config.lock().await;

        // DEBUG: Log all rules and their match status
        eprintln!("🔍 Checking {} mock rules:", config.rules.len());
        for (idx, rule) in config.rules.iter().enumerate() {
            let matches = rule.matches(&context);
            eprintln!(
                "  Rule #{}: {} -> {}",
                idx,
                rule.describe(),
                if matches { "✅ MATCH" } else { "❌ no match" }
            );
        }

        let result = config.find_match_sync(&context);
        let event_type = result.as_ref().and_then(|(idx, _, _)| {
            config
                .rules
                .get(*idx)
                .and_then(|r| r.matcher_event_type().map(|e| e.to_string()))
        });
        (result, event_type)
    }; // Lock is dropped here!

    // Record call history AFTER releasing config lock
    let mock_response = match match_result {
        Some((idx, response, description)) => {
            eprintln!("✅ Using matched rule #{}", idx);
            // Rendered ONCE and reused. `to_response_string` runs the rule's response
            // generator, so rendering here for the diagnostics and again below for the
            // reply invoked the closure twice per request. A generator carrying state
            // between calls -- "the first GET finds the key, the one after the delete
            // does not" -- advanced twice and answered the first request with the second
            // answer.
            let rendered = response.to_response_string(Some(&context.event_data));
            report_routing_inconsistencies(
                &state,
                &context,
                idx,
                &description,
                matched_rule_event_type.as_deref(),
                &rendered,
            )
            .await;
            // Record call in separate lock acquisition
            state
                .config
                .lock()
                .await
                .record_call(context.clone(), idx, description)
                .await;
            let delay = state
                .config
                .lock()
                .await
                .rules
                .get(idx)
                .and_then(|r| r.delay);
            if let Some(delay) = delay {
                tokio::time::sleep(delay).await;
            }
            rendered
        }
        None => {
            eprintln!("❌ NO RULE MATCHED!");
            warn!("🔧 No mock rule matched, returning default error");
            state
                .config
                .lock()
                .await
                .record_harness_diagnostic(format!(
                    "No mock rule matched a {:?} request (event_type={:?}, instruction=\"{}\"). \
                     NetGet will report an LLM failure for this turn.",
                    context.request_kind,
                    context.event_type,
                    context.instruction.chars().take(120).collect::<String>()
                ))
                .await;
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "No mock rule matched this request"
                })),
            )
                .into_response();
        }
    };

    debug!("🔧 Mock Ollama returning response");

    // Format as Ollama chat response
    let response = OllamaChatResponse {
        model: request.model,
        created_at: chrono::Utc::now().to_rfc3339(),
        message: OllamaResponseMessage {
            role: "assistant".to_string(),
            content: mock_response,
        },
        done: true,
    };

    Json(response).into_response()
}

/// Flag a match whose classification looks inconsistent.
///
/// Two shapes matter, and both used to fail silently as
/// "No servers or clients started":
/// 1. an `on_event(...)` rule answering a request that is not a network event
/// 2. a wire-response action (`send_*` / `*_response`) answering a startup or
///    documentation turn, which NetGet rejects as an unknown action
async fn report_routing_inconsistencies(
    state: &ServerState,
    context: &LlmContext,
    rule_idx: usize,
    rule_description: &str,
    rule_event_type: Option<&str>,
    response_text: &str,
) {
    if context.request_kind.carries_network_event() {
        return;
    }

    if let Some(event_type) = rule_event_type {
        state
            .config
            .lock()
            .await
            .record_harness_diagnostic(format!(
                "Rule #{} ({}) matched a {:?} request. An on_event(\"{}\") rule must only match \
                 network events; matching a startup/documentation turn means the request was \
                 misclassified.",
                rule_idx, rule_description, context.request_kind, event_type
            ))
            .await;
    }

    let response_shaped = response_shaped_action_names(response_text);
    if !response_shaped.is_empty() {
        state
            .config
            .lock()
            .await
            .record_harness_diagnostic(format!(
                "Rule #{} ({}) answered a {:?} request with wire-response action(s) {:?}. \
                 NetGet only accepts open_server/open_client/tool actions here, will reject these \
                 as unknown actions, and no server will start.",
                rule_idx, rule_description, context.request_kind, response_shaped
            ))
            .await;
    }
}

/// Handle POST /api/generate
async fn handle_generate(
    State(state): State<ServerState>,
    Json(request): Json<OllamaGenerateRequest>,
) -> Response {
    record_request_fields(
        &state,
        "/api/generate",
        request.stream,
        &request.format,
        &request.extra,
    );
    debug!(
        "🔧 Mock Ollama received generate request: model={}, prompt_len={}",
        request.model,
        request.prompt.len()
    );

    // Extract context from prompt
    let context = extract_context_from_prompt(&request.prompt);

    // DEBUG: Log extracted context
    eprintln!("🔍🔍🔍 Mock generate context extracted:");
    eprintln!("  request_kind: {:?}", context.request_kind);
    eprintln!("  event_type: {:?}", context.event_type);
    // Use chars().take() to avoid splitting UTF-8 characters
    let instruction_preview: String = context.instruction.chars().take(200).collect();
    eprintln!("  instruction: {}", instruction_preview);
    eprintln!("  prompt length: {} chars", request.prompt.len());
    let first_500: String = request.prompt.chars().take(500).collect();
    eprintln!("  prompt first 500 chars: {}", first_500);
    // For last 500 chars, skip first N chars and take remaining
    let skip_count = request.prompt.chars().count().saturating_sub(500);
    let last_500: String = request.prompt.chars().skip(skip_count).collect();
    eprintln!("  prompt last 500 chars: {}", last_500);

    // Get mock response (using synchronous matching to avoid holding lock across await)
    let (match_result, matched_rule_event_type) = {
        let config = state.config.lock().await;

        // DEBUG: Log all rules and their match status
        eprintln!("🔍 Checking {} mock rules:", config.rules.len());
        for (idx, rule) in config.rules.iter().enumerate() {
            let matches = rule.matches(&context);
            eprintln!(
                "  Rule #{}: {} -> {}",
                idx,
                rule.describe(),
                if matches { "✅ MATCH" } else { "❌ no match" }
            );
        }

        let result = config.find_match_sync(&context);
        let event_type = result.as_ref().and_then(|(idx, _, _)| {
            config
                .rules
                .get(*idx)
                .and_then(|r| r.matcher_event_type().map(|e| e.to_string()))
        });
        (result, event_type)
    }; // Lock is dropped here!

    // Record call history AFTER releasing config lock
    let mock_response = match match_result {
        Some((idx, response, description)) => {
            eprintln!("✅ Using matched rule #{}", idx);
            // Rendered ONCE and reused. `to_response_string` runs the rule's response
            // generator, so rendering here for the diagnostics and again below for the
            // reply invoked the closure twice per request. A generator carrying state
            // between calls -- "the first GET finds the key, the one after the delete
            // does not" -- advanced twice and answered the first request with the second
            // answer.
            let rendered = response.to_response_string(Some(&context.event_data));
            report_routing_inconsistencies(
                &state,
                &context,
                idx,
                &description,
                matched_rule_event_type.as_deref(),
                &rendered,
            )
            .await;
            // Record call in separate lock acquisition
            state
                .config
                .lock()
                .await
                .record_call(context.clone(), idx, description)
                .await;
            let delay = state
                .config
                .lock()
                .await
                .rules
                .get(idx)
                .and_then(|r| r.delay);
            if let Some(delay) = delay {
                tokio::time::sleep(delay).await;
            }
            rendered
        }
        None => {
            eprintln!("❌ NO RULE MATCHED!");
            warn!("🔧 No mock rule matched generate request, returning default error");
            state
                .config
                .lock()
                .await
                .record_harness_diagnostic(format!(
                    "No mock rule matched a {:?} generate request (event_type={:?}, \
                     instruction=\"{}\"). NetGet will report an LLM failure for this turn.",
                    context.request_kind,
                    context.event_type,
                    context.instruction.chars().take(120).collect::<String>()
                ))
                .await;
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "No mock rule matched this request"
                })),
            )
                .into_response();
        }
    };

    debug!("🔧 Mock Ollama returning generate response");

    // Format as Ollama generate response
    let response = OllamaGenerateResponse {
        model: request.model,
        created_at: chrono::Utc::now().to_rfc3339(),
        response: mock_response,
        done: true,
    };

    Json(response).into_response()
}

/// Handle GET /api/tags (list models)
async fn handle_tags(State(state): State<ServerState>) -> Response {
    debug!("🔧 Mock Ollama received tags request");
    state.tags_hits.fetch_add(1, Ordering::SeqCst);

    // Must advertise every model name tests configure: netget validates
    // --model against this list at startup and refuses to run otherwise.
    // "qwen3.8:27b-mlx" is the test-helper default (tests/helpers/netget.rs);
    // "qwen3-coder:30b" is kept for tests that pass it explicitly.
    let response = OllamaTagsResponse {
        models: ["qwen3.8:27b-mlx", "qwen3-coder:30b"]
            .into_iter()
            .map(|name| OllamaModel {
                name: name.to_string(),
                modified_at: chrono::Utc::now().to_rfc3339(),
                size: 1000000,
            })
            .collect(),
    };

    Json(response).into_response()
}

/// Handle GET /api/version
async fn handle_version() -> Response {
    debug!("🔧 Mock Ollama received version request");
    Json(serde_json::json!({"version": "0.0.1-mock"})).into_response()
}

/// Extract LLM context from Ollama request
/// This must match the logic in src/llm/ollama_client.rs::extract_llm_context()
fn extract_context(request: &OllamaChatRequest) -> LlmContext {
    // Get the last user message (the prompt)
    let prompt = request
        .messages
        .iter()
        .rev()
        .find(|m| m.role == "user")
        .map(|m| m.content.as_str())
        .unwrap_or("");

    // Classify on the template that produced this request, not on the wording
    // of the message body. The system message carries the template's task text.
    let template_text = request
        .messages
        .iter()
        .filter(|m| m.role == "system")
        .map(|m| m.content.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    let request_kind = classify_request(&template_text, prompt);

    // A scheduled task's user message is the fixed string "Execute the task.";
    // everything identifying the run (the `Trigger: Scheduled task '<name>' …`
    // block and the task instruction) lives in the system prompt. Match on
    // that instead, or every task run looks identical.
    if request_kind == RequestKind::ScheduledTask {
        let mut context = LlmContext::new(template_text.clone()).with_request_kind(request_kind);
        context.instruction = match template_text.rfind(TASK_TRIGGER_MARKER) {
            Some(idx) => template_text[idx..].trim().to_string(),
            None => template_text.clone(),
        };
        context.iteration = request
            .messages
            .iter()
            .filter(|m| m.role == "assistant")
            .count();
        debug!(
            "🔧 Scheduled task request, instruction from system prompt: '{}'",
            context.instruction.chars().take(120).collect::<String>()
        );
        return context;
    }

    let mut context = LlmContext::new(prompt.to_string()).with_request_kind(request_kind);

    // Only network-event requests carry an event type. Startup and
    // documentation turns embed protocol docs full of `### Event: <id>`
    // headings, which must never be mistaken for a live event.
    if request_kind.carries_network_event() {
        context.event_type = extract_event_type(prompt);
    }

    // For a user command there is nothing to guess: the latest user message
    // *is* the instruction, verbatim. Line-sniffing here used to shred
    // multi-line prompts down to their last line, so a rule written as
    // `instruction contains "listen on port"` missed a prompt that opens with
    // exactly that phrase.
    if request_kind == RequestKind::UserInput {
        context.instruction = prompt.trim().to_string();
        debug!(
            "🔧 Instruction = full user message ({} chars)",
            context.instruction.len()
        );
    } else if let Some(instruction_line) = prompt
        .lines()
        .find(|line| line.contains("Your instruction:") || line.contains("instruction:"))
    {
        if let Some(instruction) = instruction_line
            .split("instruction:")
            .nth(1)
            .or_else(|| instruction_line.split("Your instruction:").nth(1))
        {
            let instruction_trimmed = instruction.trim();
            debug!("🔧 Extracted instruction: '{}'", instruction_trimmed);
            context.instruction = instruction_trimmed.to_string();
        }
    } else {
        debug!("🔧 Instruction extraction: no 'instruction:' line found, trying fallback");
        // Fallback: Look for the last substantial non-empty line (likely the user message)
        let lines: Vec<&str> = prompt.lines().collect();
        for line in lines.iter().rev() {
            let trimmed = line.trim();
            // Skip empty lines, very short lines, and lines that look like headers or system text
            if !trimmed.is_empty()
                && trimmed.len() > 5
                && !trimmed.starts_with('#')
                && !trimmed.starts_with("You ")
                && !trimmed.starts_with("Your ")
                && !trimmed.starts_with("Please ")
                && !trimmed.contains("```")
                && !trimmed.starts_with("Use `/")
            {
                debug!("🔧 Extracted instruction (fallback): '{}'", trimmed);
                context.instruction = trimmed.to_string();
                break;
            }
        }
    }

    // Try to extract event data (JSON after "Context data:", "Event data:", or "Data:")
    if let Some(data_start_idx) = prompt
        .find("Context data:")
        .or_else(|| prompt.find("Event data:"))
        .or_else(|| prompt.find("Data:"))
    {
        let after_data = &prompt[data_start_idx..];

        // Try to find JSON object
        if let Some(json_start) = after_data.find('{') {
            let json_str = &after_data[json_start..];

            // Try to parse as JSON using streaming parser (stops at first complete JSON value)
            use serde_json::Deserializer;
            let mut deserializer =
                Deserializer::from_str(json_str).into_iter::<serde_json::Value>();
            if let Some(Ok(json)) = deserializer.next() {
                debug!("🔧 Successfully parsed event data: {}", json);
                context.event_data = json;
            }
        }
    }

    // Determine iteration (how many assistant messages so far)
    context.iteration = request
        .messages
        .iter()
        .filter(|m| m.role == "assistant")
        .count();

    context
}

/// Extract LLM context from a generate request prompt
fn extract_context_from_prompt(prompt: &str) -> LlmContext {
    // /api/generate collapses system prompt and trigger into one blob, so the
    // template markers and the trigger live in the same string.
    let request_kind = classify_request(prompt, prompt);

    let mut context = LlmContext::new(prompt.to_string()).with_request_kind(request_kind);

    if request_kind.carries_network_event() {
        context.event_type = extract_event_type(prompt);
    }

    // Try to extract instruction - look for patterns
    // First, try to find the user input section at the end of the prompt
    // User input typically appears after system capabilities or markers like "## System Capabilities"
    let has_user_message = if let Some(cap_idx) = prompt
        .find("## System Capabilities")
        .or_else(|| prompt.find("# Current State"))
    {
        // Extract everything after the capabilities section
        let after_cap = &prompt[cap_idx..];

        // Try to find the end of the capabilities section using various markers
        let end_marker_and_len = [
            (
                "DataLink protocol unavailable",
                "DataLink protocol unavailable".len(),
            ),
            (
                "- **Raw socket access**: ✓ Available",
                "- **Raw socket access**: ✓ Available".len(),
            ),
            (
                "- **Raw socket access**: ✗ Unavailable",
                "- **Raw socket access**: ✗ Unavailable".len(),
            ),
            (
                "- **Privileged ports (<1024)**: ✓ Available",
                "- **Privileged ports (<1024)**: ✓ Available".len(),
            ),
        ];

        let mut after_system = None;
        for (marker, len) in &end_marker_and_len {
            if let Some(end_idx) = after_cap.find(marker) {
                after_system = Some(&after_cap[end_idx + len..]);
                debug!("🔧 Found capabilities end marker: '{}'", marker);
                break;
            }
        }

        if let Some(after_system) = after_system {
            // Collect ALL non-empty lines after the system section as the instruction
            // (not just the first line, to support multi-line instructions)
            let instruction_text = after_system
                .lines()
                .skip_while(|line| line.trim().is_empty())
                .collect::<Vec<&str>>()
                .join("\n")
                .trim()
                .to_string();

            if !instruction_text.is_empty() {
                debug!(
                    "🔧 Extracted instruction from end of prompt (first 200 chars): '{}'",
                    &instruction_text[..instruction_text.len().min(200)]
                );
                context.instruction = instruction_text;
                true
            } else {
                false
            }
        } else {
            false
        }
    } else {
        // Fallback: check for [user] message pattern
        if let Some(user_line) = prompt.lines().find(|line| {
            line.starts_with("[user]") || line.contains("Message") && line.contains("[user]")
        }) {
            // Extract text after [user]
            if let Some(after_user) = user_line.split("[user]").nth(1) {
                let instruction_trimmed = after_user.trim();
                if !instruction_trimmed.is_empty() {
                    debug!(
                        "🔧 Extracted instruction from [user] message: '{}'",
                        instruction_trimmed
                    );
                    context.instruction = instruction_trimmed.to_string();
                    true
                } else {
                    false
                }
            } else {
                false
            }
        } else {
            false
        }
    };

    // If no [user] message found, try traditional instruction markers
    if !has_user_message {
        if let Some(instruction_line) = prompt
            .lines()
            .find(|line| line.contains("Your instruction:") || line.contains("instruction:"))
        {
            if let Some(instruction) = instruction_line
                .split("instruction:")
                .nth(1)
                .or_else(|| instruction_line.split("Your instruction:").nth(1))
            {
                let instruction_trimmed = instruction.trim();
                debug!("🔧 Extracted instruction: '{}'", instruction_trimmed);
                context.instruction = instruction_trimmed.to_string();
            }
        } else {
            debug!("🔧 Instruction extraction: no markers found, trying fallback");
            // Fallback: User input is typically at the END of the prompt (after all system instructions)
            // Look for the LAST substantial non-empty line as the user input
            let lines: Vec<&str> = prompt.lines().collect();
            let mut found = false;

            // Search from the end backwards to find the user input
            for line in lines.iter().rev() {
                let trimmed = line.trim();
                if !trimmed.is_empty()
                    && trimmed.len() > 5
                    && !trimmed.starts_with('#')
                    && !trimmed.starts_with('-')
                    && !trimmed.starts_with("You ")
                    && !trimmed.starts_with("Your ")
                    && !trimmed.starts_with("Please ")
                    && !trimmed.contains("```")
                    && !trimmed.starts_with("Use `/")
                    && !trimmed.ends_with(":")
                    && !trimmed.contains("CRITICAL:")
                    && !trimmed.contains("**")
                {
                    debug!("🔧 Extracted instruction from end of prompt: '{}'", trimmed);
                    context.instruction = trimmed.to_string();
                    found = true;
                    break;
                }
            }

            // If still not found, try the old forward search as last resort
            if !found {
                for line in lines.iter() {
                    let trimmed = line.trim();
                    let lower = trimmed.to_lowercase();
                    if !trimmed.is_empty()
                        && trimmed.len() > 5
                        && !trimmed.starts_with('#')
                        && !trimmed.starts_with("You ")
                        && !trimmed.starts_with("Your ")
                        && !trimmed.starts_with("Please ")
                        && !trimmed.contains("```")
                        && !trimmed.starts_with("Use `/")
                        && (lower.starts_with("listen")
                            || lower.starts_with("start")
                            || lower.starts_with("create")
                            || lower.starts_with("open")
                            || lower.starts_with("run")
                            || lower.starts_with("spawn")
                            || lower.starts_with("connect"))
                    {
                        debug!("🔧 Extracted instruction (forward fallback): '{}'", trimmed);
                        context.instruction = trimmed.to_string();
                        break;
                    }
                }
            }
        }
    }

    // Try to extract event data — from the current trigger, not from an earlier exchange
    // rendered ahead of it.
    let trigger = if request_kind.carries_network_event() {
        current_trigger(prompt)
    } else {
        prompt
    };
    if let Some(data_start_idx) = trigger
        .find("Context data:")
        .or_else(|| trigger.find("Event data:"))
        .or_else(|| trigger.find("Data:"))
    {
        let after_data = &trigger[data_start_idx..];
        if let Some(json_start) = after_data.find('{') {
            let json_str = &after_data[json_start..];
            use serde_json::Deserializer;
            let mut deserializer =
                Deserializer::from_str(json_str).into_iter::<serde_json::Value>();
            if let Some(Ok(json)) = deserializer.next() {
                debug!("🔧 Successfully parsed event data: {}", json);
                context.event_data = json;
            }
        }
    }

    context
}

impl MockOllamaServer {
    /// Wait until every expectation this server's rules declare is satisfied, or
    /// `timeout_secs` elapses. Returns quietly either way; `verify_calls` asserts.
    pub async fn wait_for_expectations(&self, timeout_secs: u64) {
        let start = std::time::Instant::now();
        let deadline = std::time::Duration::from_secs(timeout_secs);
        loop {
            {
                let config = self.config.lock().await;
                let satisfied = config.rules.iter().all(|rule| {
                    let actual = rule.actual_calls.load(std::sync::atomic::Ordering::SeqCst);
                    let floor = rule.expected_calls.or(rule.min_calls).unwrap_or(0);
                    actual >= floor
                });
                if satisfied {
                    return;
                }
            }
            if start.elapsed() >= deadline {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    }
}

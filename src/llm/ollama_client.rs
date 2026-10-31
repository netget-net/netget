//! LLM client supporting Ollama and OpenAI-compatible endpoints

use std::collections::HashMap;

use crate::llm::actions::ActionResponse;
use crate::llm::circuit_breaker::{is_transport_failure, BreakerStatus, CircuitBreaker};
use crate::logging::emit::Log;
use anyhow::{Context, Result};
use bytes::Bytes;
#[cfg(not(target_arch = "wasm32"))]
use ollama_rs::Ollama;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tracing::{debug, error, info, trace, warn};

/// Internal backend implementation for LLM communication
#[derive(Clone)]
enum LlmBackend {
    /// Ollama HTTP API via ollama-rs.
    ///
    /// The second field is the HTTP client used for the two endpoints `ollama-rs` does not
    /// cover (`/api/generate` with a raw body, and `/api/chat` with tools). Both used to call
    /// `reqwest::Client::new()` **per request**, which is the defect the root CLAUDE.md
    /// describes: building a client sets up the rustls stack and loads the platform root
    /// store, on macOS through Security.framework, synchronously. Doing that on every LLM
    /// call parks a runtime worker every time. It is built once, here, with the same
    /// literal-IP resolver short-circuit as the `ollama-rs` client.
    #[cfg(not(target_arch = "wasm32"))]
    Ollama(Ollama, reqwest::Client),
    /// OpenAI-compatible API via reqwest
    #[cfg(not(target_arch = "wasm32"))]
    OpenAI {
        client: reqwest::Client,
        base_url: String,
        api_key: String,
    },
    /// No model: enqueue each request and await an answer from the calling MCP
    /// agent (see `crate::llm::agent_queue`). MCP `--llm-agent` mode only.
    Queue {
        queue: std::sync::Arc<crate::llm::agent_queue::LlmRequestQueue>,
        /// How long to wait for the agent's answer before erroring.
        timeout: std::time::Duration,
    },
    /// No HTTP at all: each request is handed to whoever drains the bridge — the browser
    /// page in the wasm build (WebLLM, a local Ollama it forwards to, or the person at the
    /// keyboard) — and its answer is used as the model's. See `crate::llm::bridge`.
    Bridge {
        bridge: std::sync::Arc<crate::llm::bridge::LlmBridge>,
        /// How long to wait for the host's answer before erroring.
        timeout: std::time::Duration,
    },
}

/// The backend's own error text out of an error response body: Ollama's `{"error": "…"}`,
/// OpenAI's `{"error": {"message": "…"}}`, or the body itself when it is neither.
#[cfg(not(target_arch = "wasm32"))]
fn backend_error_text(body: &str) -> String {
    let parsed = serde_json::from_str::<serde_json::Value>(body).ok();
    let text = parsed.as_ref().and_then(|v| {
        v.pointer("/error/message")
            .or_else(|| v.get("error"))
            .and_then(|e| e.as_str())
            .map(str::to_string)
    });
    let text = text.unwrap_or_else(|| body.trim().to_string());
    if text.is_empty() {
        "no error text".to_string()
    } else {
        crate::utils::truncate_for_log(&text, 300).to_string()
    }
}

/// Classify a non-success HTTP answer from the backend.
///
/// Ollama answers 404 on `/api/generate` and `/api/chat` for exactly one reason, a model it
/// does not have (`model "x" not found, try pulling it first`). An OpenAI-compatible server
/// can answer 404 for a wrong path too, so there it counts as a missing model only when the
/// backend's text says so.
#[cfg(not(target_arch = "wasm32"))]
fn backend_status_error(
    backend: &'static str,
    endpoint: &str,
    model: &str,
    status: u16,
    detail: String,
) -> crate::llm::LlmBackendError {
    use crate::llm::BackendFailureKind as K;
    let lower = detail.to_lowercase();
    let model_missing = if backend == crate::llm::backend_error::OLLAMA {
        status == 404 || (lower.contains("model") && lower.contains("not found"))
    } else {
        (status == 404 || status == 400)
            && lower.contains("model")
            && (lower.contains("not found")
                || lower.contains("does not exist")
                || lower.contains("model_not_found"))
    };
    let kind = if model_missing {
        K::ModelNotInstalled
    } else {
        match status {
            401 | 403 => K::AuthRejected,
            429 => K::RateLimited,
            status => K::Refused { status },
        }
    };
    crate::llm::LlmBackendError::new(kind, backend, endpoint, model, detail)
}

/// Read an error response and classify it. A body that cannot be read still yields the status.
#[cfg(not(target_arch = "wasm32"))]
async fn backend_response_error(
    backend: &'static str,
    endpoint: &str,
    model: &str,
    response: reqwest::Response,
) -> crate::llm::LlmBackendError {
    let status = response.status().as_u16();
    let detail = match crate::client::http_fetch::read_response_text(response, 1024 * 1024).await {
        Ok(body) => backend_error_text(&body),
        Err(e) => format!("(error body unreadable: {e})"),
    };
    backend_status_error(backend, endpoint, model, status, detail)
}

/// A request that produced no HTTP response at all.
#[cfg(not(target_arch = "wasm32"))]
fn backend_send_error(
    backend: &'static str,
    endpoint: &str,
    model: &str,
    error: reqwest::Error,
) -> crate::llm::LlmBackendError {
    use std::error::Error as _;
    // reqwest's Display is "error sending request for url (…)"; the reason is in the source.
    let mut detail = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        detail.push_str(": ");
        detail.push_str(&cause.to_string());
        source = cause.source();
    }
    crate::llm::LlmBackendError::new(
        crate::llm::BackendFailureKind::Unreachable,
        backend,
        endpoint,
        model,
        detail,
    )
}

/// A request that got no answer within the request timeout.
#[cfg(not(target_arch = "wasm32"))]
fn backend_timeout_error(
    backend: &'static str,
    endpoint: &str,
    model: &str,
    timeout: std::time::Duration,
) -> crate::llm::LlmBackendError {
    crate::llm::LlmBackendError::new(
        crate::llm::BackendFailureKind::TimedOut,
        backend,
        endpoint,
        model,
        format!("{:?}", timeout),
    )
}

/// Strip markdown code fences (```json ... ``` or ``` ... ```) from text
/// This helps handle cases where the LLM wraps JSON responses in markdown formatting
/// Handles multiple trailing backticks (e.g., ```\n```)
/// Pull the outermost JSON object out of a response that carries prose around
/// it.
///
/// A **reasoning** model answers with its thinking first and the JSON after
/// (`<reasoning>…</reasoning>\n{"actions": [...]}`), and prose that happens to
/// contain an angle bracket or an unbalanced tag defeats the XML-reference
/// stripping that runs before validation. The answer is then correct and
/// rejected, which surfaces as "LLM failed to provide valid format after
/// retry" — a hard failure over formatting, not content.
///
/// Braces are matched over `char_indices` so the slice lands on a character
/// boundary: a model writing an em dash inside a string would otherwise
/// truncate the object mid-character.
fn extract_embedded_json_object(text: &str) -> Option<&str> {
    let start = text.find('{')?;
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for (offset, c) in text[start..].char_indices() {
        if in_string {
            match c {
                _ if escaped => escaped = false,
                '\\' => escaped = true,
                '"' => in_string = false,
                _ => {}
            }
            continue;
        }
        match c {
            '"' => in_string = true,
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(&text[start..=start + offset]);
                }
            }
            _ => {}
        }
    }
    None
}

fn strip_markdown_fences(text: &str) -> String {
    let mut result = text.trim();

    // Remove opening fence (```json or ```)
    result = result
        .strip_prefix("```json")
        .or_else(|| result.strip_prefix("```"))
        .unwrap_or(result)
        .trim();

    // Remove ALL trailing backticks (loop until no more)
    // Handles cases like: {...}\n```\n```
    while let Some(stripped) = result.strip_suffix("```") {
        result = stripped.trim();
    }

    result.to_string()
}

// ============================================================================
// Streaming (NDJSON) response handling
// ============================================================================
//
// Both Ollama endpoints support `"stream": true`, in which case the HTTP body is
// NDJSON — one JSON object per line, each carrying an incremental delta — ending
// with a `{"done": true}` object that also holds the final token counts. When
// `stream` is false (and, importantly, what the in-process test mock always
// returns) the body is a SINGLE JSON object. The accumulator below handles BOTH
// shapes: it feeds the body line by line, and a single-object body is simply the
// degenerate case of "one line", so the mock harness keeps working unchanged.
//
// The `thinking` field (gemma/qwen "thinking" models, `message.thinking` for chat
// and top-level `thinking` for generate) is the chain-of-thought. It is forwarded
// to the status/log stream AS IT ARRIVES so the reasoning appears live in both the
// TUI and the non-interactive stdout forwarder; `content` is only accumulated (it
// is the actual answer — typically the JSON action body — and streaming it to the
// TUI would just reproduce the response dump the logging split deliberately keeps
// file-only).

/// Which Ollama endpoint produced a streamed body — decides which JSON fields
/// carry the content and the reasoning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OllamaResponseKind {
    /// `/api/chat`: content at `message.content`, reasoning at `message.thinking`,
    /// tool calls at `message.tool_calls`.
    Chat,
    /// `/api/generate`: content at `response`, reasoning at `thinking`.
    Generate,
}

/// The complete result of accumulating a (possibly streamed) Ollama response.
///
/// After the last line is processed this holds the same full text the old
/// single-shot path produced, so all downstream `ActionResponse` parsing is
/// unchanged.
#[derive(Debug, Clone, Default)]
pub struct StreamAccumulation {
    /// Full concatenated assistant content (the answer).
    pub content: String,
    /// Full concatenated chain-of-thought, if the model emitted any.
    pub thinking: String,
    /// `message.tool_calls` from the last chunk that carried a non-empty array.
    pub tool_calls: Option<serde_json::Value>,
    /// Prompt (input) token count from the final chunk, if reported.
    pub prompt_eval_count: u64,
    /// Completion (output) token count from the final chunk, if reported.
    pub eval_count: u64,
    /// An `{"error": "..."}` object seen anywhere in the body.
    pub error: Option<String>,
}

/// Force a partial reasoning line onto the status stream once it reaches this many
/// characters without a newline, so a model that streams a long unbroken thought
/// still appears live rather than in one lump at the end.
const REASONING_FLUSH_CHARS: usize = 160;

/// TUI/stdout prefix marking a streamed reasoning line. Deliberately NOT one of
/// the five `logging::emit::Log` level prefixes: reasoning is its own recognizable
/// kind (like `[USER]`/`[SERVER]`), it renders inline in the TUI and the
/// non-interactive forwarder prints it verbatim, and it is not mistaken for an
/// action. It also stays clear of the `llm_log_prefix_guard` test, which only
/// guards the five level prefixes.
const REASONING_PREFIX: &str = "[REASONING] ";

/// Coalesces reasoning deltas and forwards them to the status channel line by line.
///
/// Coalescing choice: flush on every newline, and additionally force-flush once the
/// pending buffer reaches [`REASONING_FLUSH_CHARS`]. This yields roughly
/// line-granular updates instead of one channel send per token — the maintainer
/// wants to *see* the reasoning, and the status channel is unbounded with no
/// backpressure, so per-token sends would be needless flooding.
struct ReasoningForwarder<'a> {
    status_tx: Option<&'a mpsc::UnboundedSender<String>>,
    buf: String,
}

impl<'a> ReasoningForwarder<'a> {
    fn new(status_tx: Option<&'a mpsc::UnboundedSender<String>>) -> Self {
        Self {
            status_tx,
            buf: String::new(),
        }
    }

    /// Append a reasoning delta and emit any complete/over-long lines.
    fn push(&mut self, delta: &str) {
        // No channel bound (e.g. unit tests without a receiver, or headless with no
        // consumer): nothing to forward, and `content`/`thinking` accumulation is
        // handled by the caller regardless.
        if self.status_tx.is_none() || delta.is_empty() {
            return;
        }
        self.buf.push_str(delta);

        while let Some(pos) = self.buf.find('\n') {
            let line: String = self.buf.drain(..=pos).collect();
            self.emit(line.trim_end_matches(['\n', '\r']));
        }

        // Force-flush an over-long unbroken buffer, cutting on a char boundary.
        while self.buf.chars().count() >= REASONING_FLUSH_CHARS {
            let cut = self
                .buf
                .char_indices()
                .nth(REASONING_FLUSH_CHARS)
                .map(|(i, _)| i)
                .unwrap_or(self.buf.len());
            let seg: String = self.buf.drain(..cut).collect();
            self.emit(&seg);
        }
    }

    fn emit(&self, line: &str) {
        let line = line.trim();
        if line.is_empty() {
            return;
        }
        if let Some(tx) = self.status_tx {
            let _ = tx.send(format!("{}{}", REASONING_PREFIX, line));
        }
    }

    /// Flush any buffered remainder (called once at end of stream).
    fn flush(&mut self) {
        let rest = std::mem::take(&mut self.buf);
        self.emit(&rest);
    }
}

/// Process a single NDJSON line: accumulate its deltas into `acc` and forward any
/// reasoning to `fwd`. Blank lines and non-JSON keepalives are ignored.
fn process_stream_line(
    line: &str,
    kind: OllamaResponseKind,
    acc: &mut StreamAccumulation,
    fwd: &mut ReasoningForwarder,
) {
    let line = line.trim();
    if line.is_empty() {
        return;
    }
    let v: serde_json::Value = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(_) => return,
    };

    if let Some(err) = v.get("error").and_then(|e| e.as_str()) {
        acc.error = Some(err.to_string());
    }

    let (content, thinking, tool_calls) = match kind {
        OllamaResponseKind::Chat => {
            let msg = v.get("message");
            let tool_calls = msg
                .and_then(|m| m.get("tool_calls"))
                .filter(|tc| tc.as_array().map(|a| !a.is_empty()).unwrap_or(false))
                .cloned();
            (
                msg.and_then(|m| m.get("content")).and_then(|c| c.as_str()),
                msg.and_then(|m| m.get("thinking")).and_then(|c| c.as_str()),
                tool_calls,
            )
        }
        OllamaResponseKind::Generate => (
            v.get("response").and_then(|c| c.as_str()),
            v.get("thinking").and_then(|c| c.as_str()),
            None,
        ),
    };

    if let Some(c) = content {
        acc.content.push_str(c);
    }
    if let Some(t) = thinking {
        acc.thinking.push_str(t);
        fwd.push(t);
    }
    if let Some(tc) = tool_calls {
        acc.tool_calls = Some(tc);
    }
    if let Some(n) = v.get("prompt_eval_count").and_then(|x| x.as_u64()) {
        acc.prompt_eval_count = n;
    }
    if let Some(n) = v.get("eval_count").and_then(|x| x.as_u64()) {
        acc.eval_count = n;
    }
}

/// Accumulate a complete Ollama response `body` (NDJSON stream OR single object)
/// into a [`StreamAccumulation`], forwarding reasoning deltas to `status_tx` line
/// by line exactly as the live streaming path does.
///
/// This is the synchronous core shared by the async transport reader and the unit
/// tests: feeding a whole body here is equivalent to receiving it in one network
/// chunk, so a test can assert both the accumulated text and the forwarded deltas
/// without a live model.
pub fn accumulate_ollama_stream(
    body: &str,
    kind: OllamaResponseKind,
    status_tx: Option<&mpsc::UnboundedSender<String>>,
) -> StreamAccumulation {
    let mut acc = StreamAccumulation::default();
    let mut fwd = ReasoningForwarder::new(status_tx);
    for line in body.split('\n') {
        process_stream_line(line, kind, &mut acc, &mut fwd);
    }
    fwd.flush();
    acc
}

// --- OpenAI (`/v1/chat/completions`) streaming ---
//
// OpenAI's stream is Server-Sent Events: each event is a `data: {json}` line,
// terminated by `data: [DONE]`. Unlike Ollama's NDJSON, tool calls arrive as
// fragments (an `index`, then `id`/`function.name`/`function.arguments` streamed
// piecewise), so they must be merged by index. The same processor also handles a
// non-SSE single-object body (the test mock and any non-streaming backend), where
// each field arrives whole — merging into an empty accumulator yields the value.

#[derive(Default, Clone)]
struct OpenAiToolCallAcc {
    id: String,
    name: String,
    arguments: String,
}

/// Accumulated OpenAI chat result (from an SSE stream or a single object).
#[derive(Default)]
pub struct OpenAiStreamAcc {
    pub content: String,
    pub reasoning: String,
    tool_calls: std::collections::BTreeMap<u64, OpenAiToolCallAcc>,
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    pub total_tokens: u64,
    pub error: Option<String>,
}

impl OpenAiStreamAcc {
    /// Finalize the merged tool-call fragments into `ToolCall`s, dropping any that
    /// never received a function name and defaulting unparseable arguments to `{}`.
    pub fn into_tool_calls(&self) -> Vec<ToolCall> {
        self.tool_calls
            .values()
            .filter(|t| !t.name.is_empty())
            .map(|t| ToolCall {
                id: t.id.clone(),
                function_name: t.name.clone(),
                arguments: serde_json::from_str(&t.arguments)
                    .unwrap_or_else(|_| serde_json::json!({})),
            })
            .collect()
    }

    pub fn token_usage(&self) -> TokenUsage {
        TokenUsage {
            prompt_tokens: self.prompt_tokens,
            completion_tokens: self.completion_tokens,
            total_tokens: if self.total_tokens > 0 {
                self.total_tokens
            } else {
                self.prompt_tokens + self.completion_tokens
            },
        }
    }
}

fn apply_openai_usage(acc: &mut OpenAiStreamAcc, usage: &serde_json::Value) {
    if let Some(n) = usage.get("prompt_tokens").and_then(|v| v.as_u64()) {
        acc.prompt_tokens = n;
    }
    if let Some(n) = usage.get("completion_tokens").and_then(|v| v.as_u64()) {
        acc.completion_tokens = n;
    }
    if let Some(n) = usage.get("total_tokens").and_then(|v| v.as_u64()) {
        acc.total_tokens = n;
    }
}

/// Merge one `choices[0].delta` (streaming) or `choices[0].message` (single
/// object) node into the accumulator, forwarding any reasoning delta.
fn merge_openai_choice(
    acc: &mut OpenAiStreamAcc,
    node: &serde_json::Value,
    fwd: &mut ReasoningForwarder,
) {
    if let Some(c) = node.get("content").and_then(|v| v.as_str()) {
        acc.content.push_str(c);
    }
    // OpenAI reasoning models expose chain-of-thought as `reasoning` or, on some
    // OpenAI-compatible endpoints, `reasoning_content`.
    for key in ["reasoning", "reasoning_content"] {
        if let Some(r) = node.get(key).and_then(|v| v.as_str()) {
            acc.reasoning.push_str(r);
            fwd.push(r);
        }
    }
    if let Some(tcs) = node.get("tool_calls").and_then(|v| v.as_array()) {
        for (i, tc) in tcs.iter().enumerate() {
            let idx = tc.get("index").and_then(|v| v.as_u64()).unwrap_or(i as u64);
            let e = acc.tool_calls.entry(idx).or_default();
            if let Some(id) = tc.get("id").and_then(|v| v.as_str()) {
                if !id.is_empty() {
                    e.id = id.to_string();
                }
            }
            if let Some(f) = tc.get("function") {
                if let Some(n) = f.get("name").and_then(|v| v.as_str()) {
                    e.name.push_str(n);
                }
                if let Some(a) = f.get("arguments").and_then(|v| v.as_str()) {
                    e.arguments.push_str(a);
                }
            }
        }
    }
}

/// Process one line of an OpenAI response. Returns `true` if the line was an SSE
/// `data:` frame (so the caller knows the body is a real stream, not a single
/// object). `[DONE]` and unparseable frames count as frames but add nothing.
fn process_openai_sse_line(
    line: &str,
    acc: &mut OpenAiStreamAcc,
    fwd: &mut ReasoningForwarder,
) -> bool {
    let line = line.trim();
    let data = match line.strip_prefix("data:") {
        Some(d) => d.trim(),
        None => return false,
    };
    if data == "[DONE]" {
        return true;
    }
    let v: serde_json::Value = match serde_json::from_str(data) {
        Ok(v) => v,
        Err(_) => return true,
    };
    if let Some(err) = v.pointer("/error/message").and_then(|e| e.as_str()) {
        acc.error = Some(err.to_string());
    }
    if let Some(u) = v.get("usage").filter(|u| u.is_object()) {
        apply_openai_usage(acc, u);
    }
    if let Some(delta) = v.pointer("/choices/0/delta") {
        merge_openai_choice(acc, delta, fwd);
    }
    true
}

/// Accumulate a whole OpenAI body — an SSE stream OR a single completion object —
/// forwarding reasoning line by line. The synchronous core shared by the async
/// reader and unit tests.
pub fn accumulate_openai_stream(
    body: &str,
    status_tx: Option<&mpsc::UnboundedSender<String>>,
) -> OpenAiStreamAcc {
    let mut acc = OpenAiStreamAcc::default();
    let mut fwd = ReasoningForwarder::new(status_tx);
    let mut saw_sse = false;
    for line in body.split('\n') {
        if process_openai_sse_line(line, &mut acc, &mut fwd) {
            saw_sse = true;
        }
    }
    // Non-SSE single object (mock / non-streaming backend): parse the whole body
    // and merge choices[0].message, which carries every field whole.
    if !saw_sse {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(body.trim()) {
            if let Some(err) = v.pointer("/error/message").and_then(|e| e.as_str()) {
                acc.error = Some(err.to_string());
            }
            if let Some(u) = v.get("usage").filter(|u| u.is_object()) {
                apply_openai_usage(&mut acc, u);
            }
            if let Some(msg) = v.pointer("/choices/0/message") {
                merge_openai_choice(&mut acc, msg, &mut fwd);
            }
        }
    }
    fwd.flush();
    acc
}

/// Message in a conversation with role (system/user/assistant/tool)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub role: String,
    pub content: String,
    /// Tool call ID for tool result messages (role="tool")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
}

/// Token usage statistics from an LLM response
#[derive(Debug, Clone, Copy, Default)]
pub struct TokenUsage {
    /// Number of tokens in the prompt (input)
    pub prompt_tokens: u64,
    /// Number of tokens in the response (output)
    pub completion_tokens: u64,
    /// Total tokens (prompt + completion)
    pub total_tokens: u64,
}

impl TokenUsage {
    /// Create from ollama-rs GenerationResponse
    #[cfg(not(target_arch = "wasm32"))]
    pub fn from_response(response: &ollama_rs::generation::completion::GenerationResponse) -> Self {
        let prompt_tokens = response.prompt_eval_count.unwrap_or(0) as u64;
        let completion_tokens = response.eval_count.unwrap_or(0) as u64;

        Self {
            prompt_tokens,
            completion_tokens,
            total_tokens: prompt_tokens + completion_tokens,
        }
    }
}

/// Response from generate_with_format including token usage
#[derive(Debug, Clone)]
pub struct GenerateResponse {
    /// The generated text
    pub text: String,
    /// Token usage statistics
    pub token_usage: TokenUsage,
}

/// Request for chat_with_tools - structured messages with native tool definitions
#[derive(Debug, Clone)]
pub struct ChatRequest {
    /// Conversation messages (system, user, assistant, tool)
    pub messages: Vec<Message>,
    /// Tool schemas in OpenAI/Ollama format (from ActionDefinition::to_tool_schema())
    pub tools: Vec<serde_json::Value>,
    /// Model name (e.g., "qwen3-coder:30b")
    pub model: String,
    /// The actions the prompt offers. Bridge and agent-queue backends send these
    /// as structured catalogs; native Ollama/OpenAI HTTP requests ignore this field.
    pub offered_actions: Vec<crate::llm::actions::ActionDefinition>,
}

/// Response from chat_with_tools - may contain text and/or tool calls
#[derive(Debug, Clone)]
pub struct ChatResponse {
    /// Text content of the response (may be None if only tool calls)
    pub content: Option<String>,
    /// Native tool calls requested by the LLM
    pub tool_calls: Vec<ToolCall>,
    /// Token usage statistics
    pub token_usage: TokenUsage,
}

/// A native tool call from the LLM
#[derive(Debug, Clone)]
pub struct ToolCall {
    /// Unique ID for this tool call (used to match tool results)
    pub id: String,
    /// Name of the function/tool to call
    pub function_name: String,
    /// Arguments as a JSON object
    pub arguments: serde_json::Value,
}

impl Message {
    /// Create a system message
    pub fn system(content: impl Into<String>) -> Self {
        Self {
            role: "system".to_string(),
            content: content.into(),
            tool_call_id: None,
        }
    }

    /// Create a user message
    pub fn user(content: impl Into<String>) -> Self {
        Self {
            role: "user".to_string(),
            content: content.into(),
            tool_call_id: None,
        }
    }

    /// Create an assistant message
    pub fn assistant(content: impl Into<String>) -> Self {
        Self {
            role: "assistant".to_string(),
            content: content.into(),
            tool_call_id: None,
        }
    }

    /// Create a tool message (legacy, without tool_call_id)
    pub fn tool(content: impl Into<String>) -> Self {
        Self {
            role: "tool".to_string(),
            content: content.into(),
            tool_call_id: None,
        }
    }

    /// Create a tool result message with tool_call_id for native tool calling
    pub fn tool_result(tool_call_id: String, content: impl Into<String>) -> Self {
        Self {
            role: "tool".to_string(),
            content: content.into(),
            tool_call_id: Some(tool_call_id),
        }
    }
}

/// Structured response from the LLM
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct LlmResponse {
    /// Data to send over the connection (None = no output)
    #[serde(default)]
    pub output: Option<String>,

    /// Whether to close this specific connection
    #[serde(default)]
    pub close_connection: bool,

    /// Whether to wait for more data before responding
    #[serde(default)]
    pub wait_for_more: bool,

    /// Whether to shut down the entire server
    #[serde(default)]
    pub shutdown_server: bool,

    /// Optional log message for debugging
    #[serde(default)]
    pub log_message: Option<String>,

    /// Update memory - completely replace existing memory
    #[serde(default)]
    pub set_memory: Option<String>,

    /// Append to memory (added to end with newline separator)
    #[serde(default)]
    pub append_memory: Option<String>,
}

impl LlmResponse {
    /// Parse from JSON string with fallback to legacy text format
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Result<Self> {
        let trimmed = s.trim();

        // Try to parse as JSON first
        if let Ok(response) = serde_json::from_str::<LlmResponse>(trimmed) {
            return Ok(response);
        }

        // Fallback: handle legacy text responses
        match trimmed {
            "NO_RESPONSE" => Ok(Self::default()),
            "CLOSE_CONNECTION" => Ok(Self {
                close_connection: true,
                ..Default::default()
            }),
            "WAIT_FOR_MORE" => Ok(Self {
                wait_for_more: true,
                ..Default::default()
            }),
            _ => {
                // Treat as raw output text
                Ok(Self {
                    output: Some(trimmed.to_string()),
                    ..Default::default()
                })
            }
        }
    }
}

/// Structured HTTP response from the LLM
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HttpLlmResponse {
    /// HTTP status code
    pub status: u16,

    /// Response headers
    #[serde(default)]
    pub headers: HashMap<String, String>,

    /// Response body
    pub body: String,

    /// Optional log message for debugging
    #[serde(default)]
    pub log_message: Option<String>,

    /// Update memory - completely replace existing memory
    #[serde(default)]
    pub set_memory: Option<String>,

    /// Append to memory (added to end with newline separator)
    #[serde(default)]
    pub append_memory: Option<String>,
}

impl Default for HttpLlmResponse {
    fn default() -> Self {
        Self {
            status: 200,
            headers: HashMap::new(),
            body: String::new(),
            log_message: None,
            set_memory: None,
            append_memory: None,
        }
    }
}

impl std::str::FromStr for LlmResponse {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        LlmResponse::from_str(s)
    }
}

impl HttpLlmResponse {
    /// Parse from JSON string
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Result<Self> {
        let trimmed = s.trim();
        serde_json::from_str::<HttpLlmResponse>(trimmed)
            .context("Failed to parse HTTP LLM response as JSON")
    }

    /// Convert to event HttpResponse
    pub fn to_event_response(self) -> crate::events::types::HttpResponse {
        crate::events::types::HttpResponse {
            status: self.status,
            headers: self.headers,
            body: Bytes::from(self.body),
        }
    }
}

impl std::str::FromStr for HttpLlmResponse {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        HttpLlmResponse::from_str(s)
    }
}

/// Action types for command interpretation
///
/// WARNING: If you modify this enum, you MUST also update the corresponding
/// The schema file is used for Ollama's structured output feature.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CommandAction {
    UpdateInstruction {
        instruction: String,
    },
    OpenServer {
        port: u16,
        base_stack: String,
        #[serde(default)]
        send_first: bool,
        #[serde(default)]
        initial_memory: Option<String>,
        /// The instruction prompt for handling network events
        instruction: String,
    },
    CloseServer {
        #[serde(default)]
        server_id: Option<u32>,
    },
    OpenClient {
        address: String,
        base_stack: String,
    },
    CloseConnection {
        #[serde(default)]
        connection_id: Option<String>,
    },
    ShowMessage {
        message: String,
    },
    ChangeModel {
        model: String,
    },
}

/// Structured response for command interpretation
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CommandInterpretation {
    /// List of actions to take
    #[serde(default)]
    pub actions: Vec<CommandAction>,

    /// Optional message to display to user
    #[serde(default)]
    pub message: Option<String>,
}

impl CommandInterpretation {
    /// Parse from JSON string
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Result<Self> {
        let trimmed = s.trim();
        serde_json::from_str::<CommandInterpretation>(trimmed)
            .context("Failed to parse command interpretation as JSON")
    }
}

impl std::str::FromStr for CommandInterpretation {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        CommandInterpretation::from_str(s)
    }
}

/// Default per-request wall-clock bound for a backend call.
///
/// 300s, raised from 120s. 120 was not a safety margin, it was a coin flip: a locally
/// served 31B reasoning model answering a realistic NetGet request — ~15k characters of
/// system prompt after stripping, plus the 27 tool schemas a default build advertises —
/// was measured at **79 seconds on an otherwise idle machine**. That is two thirds of the
/// old budget spent on a *good* run, so anything else touching the same GPU (a second
/// model loaded, a test suite, another netget) pushed it over, and the user saw
/// `LLM request (attempt 1/2)` and then nothing for two minutes.
///
/// Reasoning models are what changed the arithmetic: the thinking block and the answer are
/// generated serially, so latency scales with tool count and prompt size far more steeply
/// than it did for a non-reasoning model of the same size.
///
/// This is a backstop against a hung backend, not a performance target — a request that
/// legitimately needs four minutes should get four minutes, and one that is never coming
/// back is equally dead at 120s or 300s. Override with `--llm-request-timeout`.
pub const DEFAULT_REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

/// The bare host from anything callers hand us: `127.0.0.1`, `http://127.0.0.1`,
/// `http://127.0.0.1:11434`, `http://127.0.0.1:11434/v1`, `http://[::1]:11434`.
///
/// Written out because the first version of this only stripped the scheme, so
/// `http://127.0.0.1:54321` reduced to `127.0.0.1:54321` — which does not parse as an
/// `IpAddr`, so the override silently did not apply and the very call it was meant to fix
/// (`/api/tags`, on a 5-second budget) kept spending all five seconds in `getaddrinfo`. A
/// short-circuit that quietly fails to engage is worse than none, because the symptom is
/// unchanged; hence `host_of_extracts_the_bare_host` in tests/.
pub fn host_of(url_or_host: &str) -> &str {
    let after_scheme = url_or_host
        .rsplit_once("//")
        .map(|(_, h)| h)
        .unwrap_or(url_or_host);
    let authority = after_scheme.split('/').next().unwrap_or(after_scheme);
    // IPv6 literals are bracketed, and their own colons must not be read as a port separator.
    if let Some(rest) = authority.strip_prefix('[') {
        return rest.split(']').next().unwrap_or(rest);
    }
    match authority.rsplit_once(':') {
        Some((h, port)) if !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) => h,
        _ => authority,
    }
}

/// Add a resolver override when `host` is a **literal IP address**, so the request never
/// consults the system name resolver.
///
/// Asking the resolver about `127.0.0.1` is never meaningful — a dotted quad already *is* the
/// answer — but `reqwest` hands the URL host to its resolver unconditionally, and
/// `hyper-util`'s `GaiResolver` does not special-case one. That becomes a real
/// `getaddrinfo()` call, which on macOS goes through libinfo to mDNSResponder: a single
/// system-wide daemon, and a serialisation point under concurrency. It was measured blocking
/// for **8.25 seconds** with ~100 processes asking at once (see `src/server/doh/AGENTS.md`),
/// which is long enough to expire a request timeout against a server that is up and idle.
///
/// A hostname is left alone: resolving `localhost` or a real name is the resolver's job, and
/// `/etc/hosts` or split-horizon DNS may legitimately point it somewhere unexpected. Only the
/// case where resolution has exactly one correct answer is short-circuited.
#[cfg(not(target_arch = "wasm32"))]
fn without_dns_for_literal_ip(
    builder: reqwest::ClientBuilder,
    host: &str,
) -> reqwest::ClientBuilder {
    let bare = host_of(host);
    match bare.parse::<std::net::IpAddr>() {
        // The port is irrelevant: hyper overwrites it with the one from the URL, so a single
        // override serves every port this client is later pointed at.
        Ok(ip) => builder.resolve(bare, std::net::SocketAddr::new(ip, 0)),
        Err(_) => builder,
    }
}

/// Whether `host` (anything [`host_of`] accepts) names this machine.
///
/// `127.0.0.0/8`, `::1` and the literal name `localhost`. Nothing else: a LAN address
/// is somebody's network and its proxy configuration is their business.
#[cfg(not(target_arch = "wasm32"))]
pub fn is_loopback_endpoint(url_or_host: &str) -> bool {
    let bare = host_of(url_or_host);
    if bare.eq_ignore_ascii_case("localhost") {
        return true;
    }
    bare.parse::<std::net::IpAddr>()
        .map(|ip| ip.is_loopback())
        .unwrap_or(false)
}

/// Skip the **system proxy probe** when the endpoint is on this machine.
///
/// This is the same shape of defect as [`without_dns_for_literal_ip`] and cost more.
/// `reqwest`'s `system-proxy` feature is on by default, so every
/// `Client::builder().build()` calls `hyper_util`'s `Matcher::from_system()`, which on
/// macOS opens an `SCDynamicStore` session — a connection to **configd**, one
/// system-wide daemon, exactly like `getaddrinfo`'s mDNSResponder. It is paid whether or
/// not a proxy is configured, and it serialises across processes: measured here at
/// **0.056 ms alone and 657 ms (p50, 726 ms max) with 100 processes building at once**,
/// against 0.090 ms for the same build with `.no_proxy()` at the same concurrency. The
/// e2e suite runs a netget process per test, so that is the suite's normal condition.
///
/// It is **not** a per-client cost, which is the trap: the first build in a process pays
/// it and every later one costs ~0.3 ms, so caching clients per endpoint would save
/// nothing. The TLS backend is irrelevant too — `use_rustls_tls()` measured the same
/// 699 ms, and `tls_built_in_root_certs(false)` made no difference, because neither
/// backend loads a root store at build time.
///
/// Gating on loopback is also the **correct** behaviour rather than merely the cheap one.
/// `hyper_util`'s macOS reader takes `kSCPropNetProxiesHTTPEnable`/`Proxy`/`Port` and never
/// reads `kSCPropNetProxiesExceptionsList`, so with a system proxy configured it would send
/// a request for `http://127.0.0.1:11434` to that proxy — ignoring the exceptions list macOS
/// itself ships, which excludes local addresses. A loopback request must never leave the
/// machine.
///
/// A non-loopback endpoint keeps full system/env proxy behaviour: reaching a remote model
/// through a corporate proxy is a real deployment, and this must not break it.
#[cfg(not(target_arch = "wasm32"))]
fn without_proxy_for_loopback(
    builder: reqwest::ClientBuilder,
    host: &str,
) -> reqwest::ClientBuilder {
    if is_loopback_endpoint(host) {
        builder.no_proxy()
    } else {
        builder
    }
}

/// Both endpoint short-circuits in one place, so no constructor can acquire one and miss
/// the other. Every client NetGet builds from a configured URL goes through here.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn configured_for_endpoint(
    builder: reqwest::ClientBuilder,
    base_url: &str,
) -> reqwest::ClientBuilder {
    without_proxy_for_loopback(without_dns_for_literal_ip(builder, base_url), base_url)
}

/// An HTTP client for a NetGet-configured endpoint, with no request timeout.
///
/// Use this instead of `reqwest::Client::new()` anywhere the URL comes from configuration
/// (`--ollama-url`, `--openai-url`). It applies [`without_dns_for_literal_ip`] and
/// [`without_proxy_for_loopback`], and building it once per endpoint rather than once per
/// request is the other half of the same lesson — see the note on [`LlmBackend::Ollama`].
#[cfg(not(target_arch = "wasm32"))]
pub fn client_for_endpoint(base_url: &str) -> reqwest::Client {
    configured_for_endpoint(reqwest::Client::builder(), base_url)
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

/// As [`client_for_endpoint`], bounded by `timeout`.
#[cfg(not(target_arch = "wasm32"))]
pub fn client_for_endpoint_with_timeout(
    base_url: &str,
    timeout: std::time::Duration,
) -> reqwest::Client {
    configured_for_endpoint(reqwest::Client::builder().timeout(timeout), base_url)
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

/// The HTTP client used for OpenAI-compatible backends, bounded by `timeout`.
///
/// One constructor so the reqwest-level bound and [`OllamaClient::request_timeout`] cannot
/// disagree; see [`OllamaClient::with_request_timeout`] for what that disagreement cost.
#[cfg(not(target_arch = "wasm32"))]
fn openai_http_client(timeout: std::time::Duration, base_url: &str) -> reqwest::Client {
    configured_for_endpoint(reqwest::Client::builder().timeout(timeout), base_url)
        .build()
        .expect("Failed to build HTTP client")
}

/// The browser's `fetch()` does its own name resolution and offers no timeout knob, so on
/// wasm32 both constructors are a plain client. Nothing in the web build contacts an LLM
/// over HTTP anyway (see `LlmBackend::Bridge`); these exist for `model_selection`.
#[cfg(target_arch = "wasm32")]
pub fn client_for_endpoint(_base_url: &str) -> reqwest::Client {
    reqwest::Client::new()
}

#[cfg(target_arch = "wasm32")]
pub fn client_for_endpoint_with_timeout(
    _base_url: &str,
    _timeout: std::time::Duration,
) -> reqwest::Client {
    reqwest::Client::new()
}

/// Default completion-token budget for one backend call.
///
/// This is a **runaway guard**, not a working budget: it exists to stop a
/// model that has started generating without end, and should sit far above any
/// legitimate answer so it never truncates one. The wall-clock
/// `--llm-request-timeout` is the primary backstop; this is the secondary.
///
/// It used to be 2048, which is inside the range of ordinary answers. A
/// **reasoning** model spends the budget twice — once on its thinking block and
/// once on the answer — so a 27B model was observed emitting a full
/// `<reasoning>` section followed by a JSON action list truncated mid-object.
/// That surfaces as an unparseable (or empty) response, never as an obvious
/// limit, which is the worst way for a cap to fail. Override with
/// `--llm-max-tokens`.
pub const DEFAULT_MAX_TOKENS: u32 = 32768;

/// Sampling overrides sent to the backend with every request.
///
/// Both fields are `None` unless the operator set them, and a `None` field is **absent from
/// the request body** — not sent as a default — so a run without `--llm-seed` or
/// `--llm-temperature` puts exactly the bytes on the wire it always did and the model's own
/// Modelfile decides. `tests/llm_sampling_options_test.rs` pins both halves.
///
/// Ollama reads them from the `options` object of `/api/generate` and `/api/chat`; the
/// OpenAI-compatible API takes them as top-level `seed` and `temperature`.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct SamplingOptions {
    /// Sampler seed. With a fixed seed and an identical prompt, Ollama's sampler draws the
    /// same tokens; a prompt that differs (a new port, a new query id) still diverges.
    pub seed: Option<u64>,
    /// Sampling temperature. `0.0` is greedy decoding.
    pub temperature: Option<f32>,
}

impl SamplingOptions {
    /// Whether any override is set.
    pub fn is_empty(&self) -> bool {
        self.seed.is_none() && self.temperature.is_none()
    }

    /// Write the set fields into `target` (an Ollama `options` object or an OpenAI body).
    fn apply_to(&self, target: &mut serde_json::Value) {
        if let Some(seed) = self.seed {
            target["seed"] = serde_json::json!(seed);
        }
        if let Some(temperature) = self.temperature {
            target["temperature"] = serde_json::json!(temperature);
        }
    }
}

/// LLM API client supporting Ollama and OpenAI-compatible backends
#[derive(Clone)]
pub struct OllamaClient {
    backend: LlmBackend,
    status_tx: Option<mpsc::UnboundedSender<String>>,
    mock_config_file: Option<std::path::PathBuf>,
    app_state: Option<crate::state::AppState>,
    /// Shared across clones, so every caller sees the same backend health.
    breaker: std::sync::Arc<CircuitBreaker>,
    /// Wall-clock bound on a single backend call.
    request_timeout: std::time::Duration,
    /// Completion-token budget for a single backend call.
    max_tokens: u32,
    /// Sampling overrides (`--llm-seed`, `--llm-temperature`). Empty by default, and
    /// an empty value adds nothing to any request body.
    sampling: SamplingOptions,
}

impl OllamaClient {
    /// Create a new Ollama client
    #[cfg(not(target_arch = "wasm32"))]
    pub fn new(base_url: impl Into<String>) -> Self {
        let url_str = base_url.into();

        // Parse the URL to extract host and port
        // URL format: "http://host:port" or "http://host" (default port 11434)
        let (host, port) = if let Some(port_start) = url_str.rfind(':') {
            // Check if this is a port (not the :// in http://)
            if port_start > 6 && !url_str[port_start..].contains('/') {
                // Extract port number
                if let Ok(port_num) = url_str[port_start + 1..].parse::<u16>() {
                    // Valid port found - split host and port
                    (&url_str[..port_start], port_num)
                } else {
                    // Invalid port - use whole URL as host with default port
                    (url_str.as_str(), 11434)
                }
            } else {
                // No port in URL - use default
                (url_str.as_str(), 11434)
            }
        } else {
            // No colon found - use default port
            (url_str.as_str(), 11434)
        };

        // Built here rather than left to `Ollama::new`, which makes its own default client,
        // so a literal-IP host skips the system resolver and a loopback one skips the system
        // proxy probe. See `without_dns_for_literal_ip` and `without_proxy_for_loopback`.
        let http = configured_for_endpoint(reqwest::Client::builder(), host)
            .build()
            .expect("Failed to build Ollama HTTP client");
        let ollama = Ollama::new_with_client(host, port, http.clone());
        Self {
            backend: LlmBackend::Ollama(ollama, http),
            status_tx: None,
            mock_config_file: None,
            app_state: None,
            breaker: std::sync::Arc::new(CircuitBreaker::default()),
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            max_tokens: DEFAULT_MAX_TOKENS,
            sampling: SamplingOptions::default(),
        }
    }

    /// Create a default client pointing to localhost
    ///
    /// `ollama-rs`'s own default points at `http://127.0.0.1:11434`, so the HTTP client for
    /// the two endpoints it does not cover is built for that endpoint rather than with
    /// `reqwest::Client::new()` — which would take the system resolver and the system proxy
    /// probe this module exists to avoid.
    #[allow(clippy::should_implement_trait)]
    #[cfg(not(target_arch = "wasm32"))]
    pub fn default() -> Self {
        let http = client_for_endpoint("http://127.0.0.1:11434");
        let ollama = Ollama::new_with_client("http://127.0.0.1", 11434, http.clone());
        Self {
            backend: LlmBackend::Ollama(ollama, http),
            status_tx: None,
            mock_config_file: None,
            app_state: None,
            breaker: std::sync::Arc::new(CircuitBreaker::default()),
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            max_tokens: DEFAULT_MAX_TOKENS,
            sampling: SamplingOptions::default(),
        }
    }

    /// Create a new client for an OpenAI-compatible API endpoint
    #[cfg(not(target_arch = "wasm32"))]
    pub fn new_openai(base_url: impl Into<String>, api_key: impl Into<String>) -> Self {
        let base_url = base_url.into().trim_end_matches('/').to_string();
        let client = openai_http_client(DEFAULT_REQUEST_TIMEOUT, &base_url);
        Self {
            backend: LlmBackend::OpenAI {
                client,
                base_url,
                api_key: api_key.into(),
            },
            status_tx: None,
            mock_config_file: None,
            app_state: None,
            breaker: std::sync::Arc::new(CircuitBreaker::default()),
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            max_tokens: DEFAULT_MAX_TOKENS,
            sampling: SamplingOptions::default(),
        }
    }

    /// Create a client that queues LLM requests for the calling MCP agent to answer.
    /// No model is contacted; each request waits up to `timeout` for an answer.
    pub fn new_queue(
        queue: std::sync::Arc<crate::llm::agent_queue::LlmRequestQueue>,
        timeout: std::time::Duration,
    ) -> Self {
        Self {
            backend: LlmBackend::Queue { queue, timeout },
            status_tx: None,
            mock_config_file: None,
            app_state: None,
            breaker: std::sync::Arc::new(CircuitBreaker::default()),
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            max_tokens: DEFAULT_MAX_TOKENS,
            sampling: SamplingOptions::default(),
        }
    }

    /// Create a client whose every request is answered by whoever drains `bridge` — the
    /// browser page, in the wasm build. No model is contacted by NetGet itself.
    pub fn new_bridge(
        bridge: std::sync::Arc<crate::llm::bridge::LlmBridge>,
        timeout: std::time::Duration,
    ) -> Self {
        Self {
            backend: LlmBackend::Bridge { bridge, timeout },
            status_tx: None,
            mock_config_file: None,
            app_state: None,
            breaker: std::sync::Arc::new(CircuitBreaker::default()),
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            max_tokens: DEFAULT_MAX_TOKENS,
            sampling: SamplingOptions::default(),
        }
    }

    /// Returns the backend type as a string ("ollama", "openai", "agent" or "bridge")
    pub fn backend_type(&self) -> &str {
        match &self.backend {
            #[cfg(not(target_arch = "wasm32"))]
            LlmBackend::Ollama(..) => "ollama",
            #[cfg(not(target_arch = "wasm32"))]
            LlmBackend::OpenAI { .. } => "openai",
            LlmBackend::Queue { .. } => "agent",
            LlmBackend::Bridge { .. } => "bridge",
        }
    }

    /// Returns the base URL of the current backend
    pub fn backend_url(&self) -> String {
        match &self.backend {
            #[cfg(not(target_arch = "wasm32"))]
            // The whole URL — scheme, host and port. `Ollama::uri()` is the host alone, which
            // cannot be queried and names the wrong thing when two Ollamas share a host.
            LlmBackend::Ollama(ollama, _) => ollama.url_str().trim_end_matches('/').to_string(),
            #[cfg(not(target_arch = "wasm32"))]
            LlmBackend::OpenAI { base_url, .. } => base_url.clone(),
            LlmBackend::Queue { .. } => "(calling agent)".to_string(),
            LlmBackend::Bridge { .. } => "(host bridge)".to_string(),
        }
    }

    /// Set the status channel for sending trace logs to TUI
    pub fn with_status_tx(mut self, status_tx: mpsc::UnboundedSender<String>) -> Self {
        self.status_tx = Some(status_tx);
        self
    }

    /// The TUI status channel this client narrates to, if any.
    ///
    /// Exposed so the event-logging path (`action_helper::call_llm`) can route
    /// templated event lifecycle lines to the same TUI stream the transport
    /// uses, instead of always passing `None` to the template renderer.
    pub fn status_tx(&self) -> Option<&mpsc::UnboundedSender<String>> {
        self.status_tx.as_ref()
    }

    /// Dual-sink log facade bound to this client's status channel.
    ///
    /// The transport layer owns **wire facts** (model, sizes, tokens) which are
    /// `DEBUG`/`TRACE` and therefore file-only through the facade's defaults; it
    /// narrates to the TUI only for `WARN`/`ERROR`. The conversation layer is the
    /// one that narrates the round-trip to the TUI. This split is what removes the
    /// request/response double-logging.
    fn log(&self) -> Log<'_> {
        Log::new(self.status_tx.as_ref())
    }

    /// Forward the reasoning a bridge host sent with its answer (`BridgeReply::reasoning`)
    /// the way a streamed Ollama `thinking` or OpenAI `reasoning` is forwarded: as
    /// `[REASONING]` lines on the status channel, plus the file-only summary and payload.
    /// The host has already shown it live on its own side; here it arrives whole, with the
    /// answer, because the bridge carries one reply per request.
    fn forward_host_reasoning(&self, reasoning: Option<&str>, private_payloads: bool) {
        if private_payloads {
            return;
        }
        let Some(reasoning) = reasoning.filter(|r| !r.trim().is_empty()) else {
            return;
        };
        let mut fwd = ReasoningForwarder::new(self.status_tx.as_ref());
        fwd.push(reasoning);
        fwd.flush();
        let log = self.log();
        log.debug(format!(
            "LLM reasoning: {} chars from the host",
            reasoning.len()
        ));
        log.payload("Full LLM reasoning", reasoning, usize::MAX);
    }

    /// Read an Ollama HTTP response body — NDJSON stream or single object — into a
    /// [`StreamAccumulation`], forwarding reasoning deltas to this client's status
    /// channel as each line arrives.
    ///
    /// Uses `Response::chunk()` (no extra reqwest feature) and splits on `\n`, so
    /// the reasoning appears live rather than after the whole body is buffered. A
    /// non-streaming single-object body (the test mock, any `stream:false` backend)
    /// simply arrives as one trailing line with no newline and is handled the same.
    #[cfg(not(target_arch = "wasm32"))]
    async fn read_ollama_stream(
        &self,
        mut http_response: reqwest::Response,
        kind: OllamaResponseKind,
        private_payloads: bool,
    ) -> Result<StreamAccumulation> {
        let mut acc = StreamAccumulation::default();
        let mut fwd = ReasoningForwarder::new(if private_payloads {
            None
        } else {
            self.status_tx.as_ref()
        });
        let mut buf: Vec<u8> = Vec::new();

        // Bound the whole body read by the same wall-clock budget as the request, so
        // a hung stream mid-body cannot block forever.
        let read = async {
            while let Some(chunk) = http_response
                .chunk()
                .await
                .context("reading Ollama streaming response body")?
            {
                buf.extend_from_slice(&chunk);
                // A '\n' byte never occurs inside a UTF-8 multibyte sequence, so each
                // drained line is a complete, valid-UTF-8 logical line.
                while let Some(pos) = buf.iter().position(|&b| b == b'\n') {
                    let line: Vec<u8> = buf.drain(..=pos).collect();
                    if let Ok(s) = std::str::from_utf8(&line) {
                        process_stream_line(s, kind, &mut acc, &mut fwd);
                    }
                }
            }
            // Trailing line without a newline — notably the single-object mock body.
            if !buf.is_empty() {
                if let Ok(s) = std::str::from_utf8(&buf) {
                    process_stream_line(s, kind, &mut acc, &mut fwd);
                }
            }
            fwd.flush();
            Ok::<(), anyhow::Error>(())
        };

        tokio::time::timeout(self.request_timeout, read)
            .await
            .with_context(|| {
                format!(
                    "Ollama streaming response body timed out after {:?}",
                    self.request_timeout
                )
            })??;

        // Wire facts: reasoning recorded to the FILE (DEBUG summary + TRACE payload),
        // never streamed to the TUI here — the TUI already received the live
        // [REASONING] lines. This is a new output, not a duplicate of the response log.
        if !acc.thinking.is_empty() {
            let log = self.log().with_payloads(!private_payloads);
            log.debug(format!(
                "LLM reasoning: {} chars streamed",
                acc.thinking.len()
            ));
            log.payload("Full LLM reasoning", &acc.thinking, usize::MAX);
        }

        Ok(acc)
    }

    /// Read an OpenAI `/v1/chat/completions` response — an SSE stream or a single
    /// completion object — into an [`OpenAiStreamAcc`], forwarding reasoning deltas
    /// to this client's status channel as each `data:` frame arrives.
    ///
    /// Like the Ollama reader it uses `Response::chunk()` and splits on `\n`, so
    /// reasoning appears live. It also buffers the raw body: if no SSE frame was
    /// seen (a non-streaming backend, or the single-object test mock), the whole
    /// body is parsed once as a completion object.
    #[cfg(not(target_arch = "wasm32"))]
    async fn read_openai_stream(
        &self,
        mut http_response: reqwest::Response,
        private_payloads: bool,
    ) -> Result<OpenAiStreamAcc> {
        let mut acc = OpenAiStreamAcc::default();
        let mut fwd = ReasoningForwarder::new(if private_payloads {
            None
        } else {
            self.status_tx.as_ref()
        });
        let mut buf: Vec<u8> = Vec::new();
        let mut raw = String::new();
        let mut saw_sse = false;

        let read = async {
            while let Some(chunk) = http_response
                .chunk()
                .await
                .context("reading OpenAI streaming response body")?
            {
                buf.extend_from_slice(&chunk);
                while let Some(pos) = buf.iter().position(|&b| b == b'\n') {
                    let line: Vec<u8> = buf.drain(..=pos).collect();
                    if let Ok(s) = std::str::from_utf8(&line) {
                        raw.push_str(s);
                        if process_openai_sse_line(s, &mut acc, &mut fwd) {
                            saw_sse = true;
                        }
                    }
                }
            }
            if !buf.is_empty() {
                if let Ok(s) = std::str::from_utf8(&buf) {
                    raw.push_str(s);
                    if process_openai_sse_line(s, &mut acc, &mut fwd) {
                        saw_sse = true;
                    }
                }
            }
            Ok::<(), anyhow::Error>(())
        };

        tokio::time::timeout(self.request_timeout, read)
            .await
            .with_context(|| {
                format!(
                    "OpenAI streaming response body timed out after {:?}",
                    self.request_timeout
                )
            })??;

        // Non-SSE single object (mock / non-streaming backend): parse the whole
        // buffered body as a completion and merge choices[0].message.
        if !saw_sse {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(raw.trim()) {
                if let Some(err) = v.pointer("/error/message").and_then(|e| e.as_str()) {
                    acc.error = Some(err.to_string());
                }
                if let Some(u) = v.get("usage").filter(|u| u.is_object()) {
                    apply_openai_usage(&mut acc, u);
                }
                if let Some(msg) = v.pointer("/choices/0/message") {
                    merge_openai_choice(&mut acc, msg, &mut fwd);
                }
            }
        }

        fwd.flush();
        Ok(acc)
    }

    /// Set the mock configuration file path (for testing)
    pub fn with_mock_config_file(mut self, path: Option<std::path::PathBuf>) -> Self {
        self.mock_config_file = path;
        self
    }

    /// Set the app state for token tracking
    pub fn with_app_state(mut self, state: crate::state::AppState) -> Self {
        self.app_state = Some(state);
        self
    }

    /// Override the wall-clock bound on a single backend call
    /// (default [`DEFAULT_REQUEST_TIMEOUT`]).
    ///
    /// For the OpenAI backend this **rebuilds the HTTP client**, because reqwest enforces its
    /// own timeout underneath the `tokio::time::timeout` this field drives. That client was
    /// built with a hardcoded 120s, so whichever bound was shorter won — and raising
    /// `--llm-request-timeout` past 120s moved only the outer one. The flag appeared to work
    /// and the call still died at two minutes, reported as a transport failure rather than a
    /// timeout the user had asked for.
    pub fn with_request_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.request_timeout = timeout;
        #[cfg(not(target_arch = "wasm32"))]
        {
            if let LlmBackend::OpenAI {
                client, base_url, ..
            } = &mut self.backend
            {
                *client = openai_http_client(timeout, base_url);
            }
        }
        self
    }

    /// Override the completion-token budget for a single backend call
    /// (default [`DEFAULT_MAX_TOKENS`]). Reasoning models need more than the
    /// default, because their thinking block is spent from the same budget as
    /// the answer.
    pub fn with_max_tokens(mut self, max_tokens: u32) -> Self {
        self.max_tokens = max_tokens;
        self
    }

    /// Set the sampling overrides sent with every request. See [`SamplingOptions`].
    pub fn with_sampling(mut self, sampling: SamplingOptions) -> Self {
        self.sampling = sampling;
        self
    }

    /// The sampling overrides this client sends.
    pub fn sampling(&self) -> SamplingOptions {
        self.sampling
    }

    /// Replace the circuit breaker (thresholds are per-breaker; see
    /// [`crate::llm::circuit_breaker`]).
    ///
    /// The breaker is shared by every clone of this client, so one backend outage is
    /// observed once rather than rediscovered by each connection.
    pub fn with_circuit_breaker(mut self, breaker: std::sync::Arc<CircuitBreaker>) -> Self {
        self.breaker = breaker;
        self
    }

    /// The shared circuit breaker guarding this client's backend.
    pub fn circuit_breaker(&self) -> &std::sync::Arc<CircuitBreaker> {
        &self.breaker
    }

    /// Snapshot of backend health — a server whose breaker has tripped should say so.
    pub fn circuit_breaker_status(&self) -> BreakerStatus {
        self.breaker.status()
    }

    /// Whether the breaker guards this backend.
    ///
    /// The agent-queue backend is excluded: its "timeouts" mean the calling MCP agent has
    /// not answered yet, which is not a transport fault, and tripping on a slow human-driven
    /// agent would break the `--llm-agent` flow outright.
    fn breaker_applies(&self) -> bool {
        match self.backend {
            #[cfg(not(target_arch = "wasm32"))]
            LlmBackend::Ollama(..) | LlmBackend::OpenAI { .. } => true,
            // A queued or bridged request waits on an agent or a person, not a transport.
            LlmBackend::Queue { .. } | LlmBackend::Bridge { .. } => false,
        }
    }

    /// Fail fast if the backend is known to be down.
    fn breaker_guard(&self) -> Result<Option<crate::llm::circuit_breaker::BreakerPermit<'_>>> {
        if !self.breaker_applies() {
            return Ok(None);
        }
        match self.breaker.acquire() {
            Ok(permit) => Ok(Some(permit)),
            Err(open) => {
                debug!("Short-circuiting LLM request: {}", open);
                self.log().warn(self.breaker.status().summary());
                Err(anyhow::Error::new(open))
            }
        }
    }

    /// Say a backend refusal out loud where it happens: ERROR to the log and the status
    /// stream, and onto [`crate::state::AppState`] so `get_status` can show it. A missing
    /// model is answered in milliseconds, so without this the only trace was a per-request
    /// failure entry that did not say why.
    #[cfg(not(target_arch = "wasm32"))]
    fn report_backend_failure(&self, failure: crate::llm::LlmBackendError) -> anyhow::Error {
        self.log()
            .error(format!("LLM backend failure: {}", failure));
        if let Some(state) = &self.app_state {
            state.note_llm_backend_failure(failure.to_string());
        }
        anyhow::Error::new(failure)
    }

    /// Feed the original outcome into its request permit, then hide private diagnostics.
    fn record_backend_outcome<T>(
        &self,
        permit: Option<crate::llm::circuit_breaker::BreakerPermit<'_>>,
        result: Result<T>,
        private_payloads: bool,
    ) -> Result<T> {
        let hide_error = |e: anyhow::Error| {
            if !private_payloads {
                e
            } else if let Some(backend) = crate::llm::LlmBackendError::find(&e) {
                // Kind, model and endpoint are not the request's to hide; the backend's own
                // words might echo it.
                anyhow::Error::new(backend.without_detail())
            } else if is_transport_failure(&e) {
                anyhow::anyhow!(
                    "LLM connection failure for credential-bearing request; details hidden"
                )
            } else {
                anyhow::anyhow!("LLM backend rejected credential-bearing request; details hidden")
            }
        };
        let Some(permit) = permit else {
            return result.map_err(hide_error);
        };

        if result.is_ok() {
            if let Some(state) = &self.app_state {
                state.clear_llm_backend_failure();
            }
        }
        match &result {
            Ok(_) => permit.record_success(),
            Err(e) if is_transport_failure(e) => {
                let summary = if private_payloads {
                    "LLM connection failure for credential-bearing request; details hidden"
                        .to_string()
                } else {
                    format!("{e:#}")
                };
                if permit.record_failure(&summary) {
                    self.log().error(self.breaker.status().summary());
                } else {
                    warn!(
                        "LLM transport failure {}/{} before the circuit breaker opens: {}",
                        self.breaker.status().consecutive_failures,
                        self.breaker.failure_threshold(),
                        crate::utils::truncate_for_log(&summary, 200)
                    );
                }
            }
            // The backend answered, it just answered with an error. Transport is fine.
            Err(_) => permit.record_success(),
        }

        result.map_err(hide_error)
    }

    /// Generate a completion from the model with optional JSON schema
    ///
    /// IMPORTANT: This method is crate-private. Use `action_helper::call_llm_with_actions()`
    /// instead for all LLM calls. The action helper provides a unified interface with
    /// proper prompt building, response parsing, and action execution.
    ///
    /// Only use this directly in:
    /// - action_helper module (the primary consumer)
    /// - handler for user input commands
    pub(crate) async fn generate(&self, model: &str, prompt: &str) -> Result<GenerateResponse> {
        self.generate_with_format(model, prompt, None).await
    }

    /// Generate a completion with a specific JSON schema format
    ///
    /// IMPORTANT: This method is crate-private. Use `action_helper::call_llm_with_actions()`
    /// for network event handling, or the specialized methods like generate_command_interpretation()
    /// for user command interpretation.
    pub(crate) async fn generate_with_format(
        &self,
        model: &str,
        prompt: &str,
        format: Option<serde_json::Value>,
    ) -> Result<GenerateResponse> {
        self.generate_offering(model, prompt, format, &[], false)
            .await
    }

    /// [`Self::generate_with_format`] for a prompt that offers actions. `offered` is the
    /// list the prompt describes; bridge and agent-queue backends pass it on as
    /// structured metadata, and the HTTP backends send exactly what
    /// `generate_with_format` sends. `private_payloads` also covers credentials
    /// retained in earlier conversation turns when the offered list is narrowed.
    pub(crate) async fn generate_offering(
        &self,
        model: &str,
        prompt: &str,
        format: Option<serde_json::Value>,
        offered: &[crate::llm::actions::ActionDefinition],
        private_payloads: bool,
    ) -> Result<GenerateResponse> {
        self.generate_offering_with_event(model, prompt, format, offered, None, private_payloads)
            .await
    }

    /// The event metadata is for bridge hosts only; native model requests are unchanged.
    pub(crate) async fn generate_offering_with_event(
        &self,
        model: &str,
        prompt: &str,
        format: Option<serde_json::Value>,
        offered: &[crate::llm::actions::ActionDefinition],
        event: Option<&crate::llm::bridge::BridgeEventContext>,
        private_payloads: bool,
    ) -> Result<GenerateResponse> {
        // Fail immediately if the backend is already known to be down, rather than paying
        // another full request timeout to rediscover it. See `crate::llm::circuit_breaker`.
        let private_payloads =
            private_payloads || crate::utils::redact::actions_have_credentials(offered);
        let permit = self.breaker_guard()?;
        let result = self
            .generate_with_format_inner(model, prompt, format, offered, event, private_payloads)
            .await;
        self.record_backend_outcome(permit, result, private_payloads)
    }

    async fn generate_with_format_inner(
        &self,
        model: &str,
        prompt: &str,
        format: Option<serde_json::Value>,
        offered: &[crate::llm::actions::ActionDefinition],
        event: Option<&crate::llm::bridge::BridgeEventContext>,
        private_payloads: bool,
    ) -> Result<GenerateResponse> {
        // Transport owns wire facts: DEBUG summary + TRACE payload, both file-only.
        // The conversation layer is the one that narrates the round-trip to the TUI.
        let log = self.log().with_payloads(!private_payloads);
        log.debug(format!(
            "LLM request: model={}, prompt_len={} chars, format={}",
            model,
            prompt.len(),
            if format.is_some() { "JSON" } else { "text" }
        ));
        log.payload("Full LLM prompt", prompt, usize::MAX);
        if let Some(ref schema) = format {
            log.trace(format!(
                "JSON schema:\n{}",
                serde_json::to_string_pretty(schema).unwrap_or_else(|_| "invalid".to_string())
            ));
        }

        // Dispatch to the appropriate backend
        let (response_text, token_usage) = match &self.backend {
            #[cfg(not(target_arch = "wasm32"))]
            LlmBackend::Ollama(ollama, http_client) => {
                // Streamed `/api/generate`: `stream: true` returns NDJSON deltas we
                // forward live (reasoning) while accumulating the full response. Called
                // via reqwest rather than ollama-rs because ollama-rs's high-level
                // `generate()` buffers the whole reply, defeating live streaming.
                let mut body = serde_json::json!({
                    "model": model,
                    "prompt": prompt,
                    "stream": true,
                    // num_predict allows longer responses (esp. binary protocol
                    // data, and reasoning models that think before answering).
                    "options": { "num_predict": self.max_tokens },
                });
                self.sampling.apply_to(&mut body["options"]);
                if format.is_some() {
                    body["format"] = serde_json::json!("json");
                }

                let endpoint = ollama.url_str().trim_end_matches('/').to_string();
                let url = format!("{}/api/generate", endpoint);
                let http_client = http_client.clone();
                let backend = crate::llm::backend_error::OLLAMA;

                let http_response = tokio::time::timeout(
                    self.request_timeout,
                    http_client.post(&url).json(&body).send(),
                )
                .await
                .map_err(|_| {
                    backend_timeout_error(backend, &endpoint, model, self.request_timeout)
                })?
                .map_err(|e| backend_send_error(backend, &endpoint, model, e))?;

                if !http_response.status().is_success() {
                    let failure =
                        backend_response_error(backend, &endpoint, model, http_response).await;
                    return Err(self.report_backend_failure(failure));
                }

                let acc = self
                    .read_ollama_stream(
                        http_response,
                        OllamaResponseKind::Generate,
                        private_payloads,
                    )
                    .await?;
                if let Some(err) = acc.error {
                    anyhow::bail!("✗  Ollama request failed: {}", err);
                }

                let usage = TokenUsage {
                    prompt_tokens: acc.prompt_eval_count,
                    completion_tokens: acc.eval_count,
                    total_tokens: acc.prompt_eval_count + acc.eval_count,
                };
                (acc.content, usage)
            }

            #[cfg(not(target_arch = "wasm32"))]
            LlmBackend::OpenAI {
                client,
                base_url,
                api_key,
            } => {
                let mut body = serde_json::json!({
                    "model": model,
                    "messages": [{ "role": "user", "content": prompt }],
                    "max_tokens": self.max_tokens,
                    // Stream so reasoning appears live; ask for usage in the final frame.
                    "stream": true,
                    "stream_options": { "include_usage": true },
                });
                self.sampling.apply_to(&mut body);

                if format.is_some() {
                    body["response_format"] = serde_json::json!({ "type": "json_object" });
                }

                let url = format!("{}/v1/chat/completions", base_url);

                let http_response = tokio::time::timeout(
                    self.request_timeout,
                    client
                        .post(&url)
                        .header("Authorization", format!("Bearer {}", api_key))
                        .header("Content-Type", "application/json")
                        .json(&body)
                        .send(),
                )
                .await
                .map_err(|_| {
                    backend_timeout_error(
                        crate::llm::backend_error::OPENAI,
                        base_url,
                        model,
                        self.request_timeout,
                    )
                })?
                .map_err(|e| {
                    backend_send_error(crate::llm::backend_error::OPENAI, base_url, model, e)
                })?;

                if !http_response.status().is_success() {
                    // Error responses are a single JSON object, not an SSE stream.
                    let failure = backend_response_error(
                        crate::llm::backend_error::OPENAI,
                        base_url,
                        model,
                        http_response,
                    )
                    .await;
                    return Err(self.report_backend_failure(failure));
                }

                let acc = self
                    .read_openai_stream(http_response, private_payloads)
                    .await?;
                if let Some(err) = &acc.error {
                    anyhow::bail!("✗  OpenAI API error: {}", err);
                }
                (acc.content.clone(), acc.token_usage())
            }

            LlmBackend::Bridge { bridge, timeout } => {
                // No model here: the host answers. The prompt goes over as one user message,
                // the way the OpenAI arm sends it.
                let (id, rx) = bridge.submit_with_event(
                    crate::llm::bridge::BridgeRequestKind::Generate,
                    model.to_string(),
                    vec![Message::user(prompt)],
                    Vec::new(),
                    offered,
                    event.cloned(),
                );
                let reply = await_bridge_reply(id, rx, *timeout).await?;
                self.forward_host_reasoning(reply.reasoning.as_deref(), private_payloads);
                let usage = TokenUsage {
                    prompt_tokens: reply.prompt_tokens,
                    completion_tokens: reply.completion_tokens,
                    total_tokens: reply.prompt_tokens + reply.completion_tokens,
                };
                // A host that answered a prompt with native tool calls (a model that
                // prefers them) is folded into the action envelope the text path parses.
                let text = match reply.content {
                    Some(content) if !content.trim().is_empty() => content,
                    _ if !reply.tool_calls.is_empty() => {
                        let actions: Vec<serde_json::Value> = reply
                            .tool_calls
                            .into_iter()
                            .map(|call| {
                                let mut action = call.arguments;
                                if !action.is_object() {
                                    action = serde_json::json!({});
                                }
                                action["type"] = serde_json::Value::String(call.name);
                                action
                            })
                            .collect();
                        serde_json::json!({ "actions": actions }).to_string()
                    }
                    _ => String::new(),
                };
                (text, usage)
            }

            LlmBackend::Queue { queue, timeout } => {
                // No model: enqueue the prompt and await the agent's action JSON.
                let (id, rx) = queue.submit_with_context(
                    model.to_string(),
                    vec![Message::user(prompt)],
                    Vec::new(),
                    offered
                        .iter()
                        .map(crate::llm::bridge::offered_action)
                        .collect(),
                    event.map(|event| serde_json::json!({"event":event})),
                    Some(*timeout),
                );
                let _cleanup = queue.guard(id);
                let actions = match tokio::time::timeout(*timeout, rx).await {
                    Ok(Ok(actions)) => actions,
                    Ok(Err(_)) => {
                        queue.expire(id);
                        anyhow::bail!(
                            "agent-queue: LLM request #{} was dropped before it was answered",
                            id
                        );
                    }
                    Err(_) => {
                        queue.expire(id);
                        anyhow::bail!(
                            "agent-queue: LLM request #{} timed out after {:?} without an agent answer",
                            id,
                            timeout
                        );
                    }
                };
                let text = serde_json::json!({ "actions": actions }).to_string();
                (text, TokenUsage::default())
            }
        };

        // Record tokens in app state if available (for /usage command)
        if let Some(ref state) = self.app_state {
            state
                .record_llm_tokens(token_usage.prompt_tokens, token_usage.completion_tokens)
                .await;
        }

        // Wire fact: response size + tokens. DEBUG, file-only.
        log.debug(format!(
            "LLM response: response_len={} chars, tokens={}i/{}o/{}t",
            response_text.len(),
            token_usage.prompt_tokens,
            token_usage.completion_tokens,
            token_usage.total_tokens
        ));

        // Check for empty response (model may be incompatible with JSON format).
        // This is a real failure the peer will feel, so it reaches the TUI (ERROR).
        if response_text.is_empty() || response_text.trim().is_empty() {
            let error_msg = format!(
                "Model '{}' returned empty response (used {} completion tokens).",
                model, token_usage.completion_tokens
            );
            log.error(&error_msg);
            return Err(anyhow::anyhow!(error_msg));
        }

        // TRACE: full payload, file-only (pretty-printed JSON when possible).
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&response_text) {
            let pretty =
                serde_json::to_string_pretty(&json).unwrap_or_else(|_| response_text.clone());
            log.payload("Full LLM response (JSON)", &pretty, usize::MAX);
        } else {
            log.payload("Full LLM response (text)", &response_text, usize::MAX);
        }

        Ok(GenerateResponse {
            text: response_text,
            token_usage,
        })
    }

    /// Chat with native tool calling support
    ///
    /// Sends structured messages with tool definitions to the LLM backend.
    /// The LLM can respond with text content and/or tool calls.
    ///
    /// This is the preferred method for the chat completions migration.
    /// For Ollama: uses /api/chat with tools parameter
    /// For OpenAI: uses /v1/chat/completions with tools parameter
    ///
    /// # Arguments
    /// * `request` - Chat request with messages, tools, and model
    ///
    /// # Returns
    /// * `Ok(ChatResponse)` - Response with optional content and tool calls
    pub(crate) async fn chat_with_tools(
        &self,
        request: &ChatRequest,
        private_payloads: bool,
    ) -> Result<ChatResponse> {
        // See `generate_with_format`: fail fast while the backend is known to be down.
        let private_payloads = private_payloads
            || crate::utils::redact::actions_have_credentials(&request.offered_actions);
        let permit = self.breaker_guard()?;
        let result = self.chat_with_tools_inner(request, private_payloads).await;
        self.record_backend_outcome(permit, result, private_payloads)
    }

    async fn chat_with_tools_inner(
        &self,
        request: &ChatRequest,
        private_payloads: bool,
    ) -> Result<ChatResponse> {
        // Transport wire facts: file-only through the facade defaults.
        let log = self.log().with_payloads(!private_payloads);
        log.debug(format!(
            "Chat request: model={}, messages={}, tools={}",
            request.model,
            request.messages.len(),
            request.tools.len()
        ));

        log.trace(format!(
            "Chat messages: {:?}",
            request
                .messages
                .iter()
                .map(|m| {
                    format!(
                        "[{}] {}",
                        m.role,
                        crate::utils::truncate_for_log(&m.content, 100)
                    )
                })
                .collect::<Vec<_>>()
        ));

        let chat_response = match &self.backend {
            #[cfg(not(target_arch = "wasm32"))]
            LlmBackend::Ollama(ollama, http_client) => {
                self.chat_with_tools_ollama(ollama, http_client, request, private_payloads)
                    .await?
            }
            #[cfg(not(target_arch = "wasm32"))]
            LlmBackend::OpenAI {
                client,
                base_url,
                api_key,
            } => {
                self.chat_with_tools_openai(client, base_url, api_key, request, private_payloads)
                    .await?
            }
            LlmBackend::Queue { queue, timeout } => {
                self.chat_with_tools_queue(queue.clone(), *timeout, request)
                    .await?
            }
            LlmBackend::Bridge { bridge, timeout } => {
                let (id, rx) = bridge.submit(
                    crate::llm::bridge::BridgeRequestKind::Chat,
                    request.model.clone(),
                    request.messages.clone(),
                    request.tools.clone(),
                    &request.offered_actions,
                );
                let reply = await_bridge_reply(id, rx, *timeout).await?;
                self.forward_host_reasoning(reply.reasoning.as_deref(), private_payloads);
                let tool_calls = reply
                    .tool_calls
                    .into_iter()
                    .enumerate()
                    .map(|(i, call)| ToolCall {
                        id: call.id.unwrap_or_else(|| format!("bridge-{}-{}", id, i)),
                        function_name: call.name,
                        arguments: call.arguments,
                    })
                    .collect();
                ChatResponse {
                    content: reply.content,
                    tool_calls,
                    token_usage: TokenUsage {
                        prompt_tokens: reply.prompt_tokens,
                        completion_tokens: reply.completion_tokens,
                        total_tokens: reply.prompt_tokens + reply.completion_tokens,
                    },
                }
            }
        };

        // Record tokens in app state if available
        if let Some(ref state) = self.app_state {
            state
                .record_llm_tokens(
                    chat_response.token_usage.prompt_tokens,
                    chat_response.token_usage.completion_tokens,
                )
                .await;
        }

        log.debug(format!(
            "Chat response: content_len={}, tool_calls={}, tokens={}i/{}o/{}t",
            chat_response.content.as_ref().map(|c| c.len()).unwrap_or(0),
            chat_response.tool_calls.len(),
            chat_response.token_usage.prompt_tokens,
            chat_response.token_usage.completion_tokens,
            chat_response.token_usage.total_tokens
        ));

        Ok(chat_response)
    }

    /// Send explicit event context and the offered action catalog to an external agent.
    pub(crate) async fn generate_agent_request(
        &self,
        model: &str,
        messages: Vec<Message>,
        offered: &[crate::llm::actions::ActionDefinition],
        context: Option<serde_json::Value>,
    ) -> Result<GenerateResponse> {
        let LlmBackend::Queue { queue, timeout } = &self.backend else {
            anyhow::bail!("agent backend is not selected");
        };
        let (id, rx) = queue.submit_with_context(
            model.to_string(),
            messages,
            Vec::new(),
            offered
                .iter()
                .map(crate::llm::bridge::offered_action)
                .collect(),
            context,
            Some(*timeout),
        );
        let _cleanup = queue.guard(id);
        let actions = match tokio::time::timeout(*timeout, rx).await {
            Ok(Ok(actions)) => actions,
            Ok(Err(_)) => {
                queue.expire(id);
                anyhow::bail!("agent-queue: request #{id} was dropped");
            }
            Err(_) => {
                queue.expire(id);
                anyhow::bail!("agent-queue: request #{id} timed out after {timeout:?}");
            }
        };
        Ok(GenerateResponse {
            text: serde_json::json!({"actions":actions}).to_string(),
            token_usage: TokenUsage::default(),
        })
    }

    /// Native-tool agent requests retain their messages, tools and offered action
    /// catalog. Answered action objects become tool calls for the normal validator.
    async fn chat_with_tools_queue(
        &self,
        queue: std::sync::Arc<crate::llm::agent_queue::LlmRequestQueue>,
        timeout: std::time::Duration,
        request: &ChatRequest,
    ) -> Result<ChatResponse> {
        let (id, rx) = queue.submit_with_context(
            request.model.clone(),
            request.messages.clone(),
            request.tools.clone(),
            request
                .offered_actions
                .iter()
                .map(crate::llm::bridge::offered_action)
                .collect(),
            None,
            Some(timeout),
        );
        let _cleanup = queue.guard(id);
        self.log().debug(format!(
            "agent-queue: enqueued LLM request #{} ({} tools), awaiting agent answer (timeout {:?})",
            id,
            request.tools.len(),
            timeout
        ));

        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(actions)) => {
                // The native-tools pipeline (ConversationHandler) reads tool_calls, not
                // content: turn each answered action into a ToolCall whose function name
                // is the action `type` and whose arguments are the remaining fields.
                let tool_calls = actions
                    .into_iter()
                    .enumerate()
                    .map(|(i, mut action)| {
                        let function_name = action
                            .get("type")
                            .and_then(|v| v.as_str())
                            .unwrap_or_default()
                            .to_string();
                        if let Some(map) = action.as_object_mut() {
                            map.remove("type");
                        }
                        ToolCall {
                            id: format!("agent-{}", i),
                            function_name,
                            arguments: action,
                        }
                    })
                    .collect();
                Ok(ChatResponse {
                    content: None,
                    tool_calls,
                    token_usage: TokenUsage::default(),
                })
            }
            Ok(Err(_)) => {
                queue.expire(id);
                anyhow::bail!(
                    "agent-queue: LLM request #{} was dropped before it was answered",
                    id
                )
            }
            Err(_) => {
                queue.expire(id);
                anyhow::bail!(
                    "agent-queue: LLM request #{} timed out after {:?} without an agent answer",
                    id,
                    timeout
                )
            }
        }
    }

    /// Ollama backend: /api/chat with tools
    #[cfg(not(target_arch = "wasm32"))]
    async fn chat_with_tools_ollama(
        &self,
        ollama: &Ollama,
        http_client: &reqwest::Client,
        request: &ChatRequest,
        private_payloads: bool,
    ) -> Result<ChatResponse> {
        // Build the request body manually since ollama-rs may not support tools natively
        let messages: Vec<serde_json::Value> = request
            .messages
            .iter()
            .map(|m| {
                let mut msg = serde_json::json!({
                    "role": m.role,
                    "content": m.content,
                });
                if let Some(ref tool_call_id) = m.tool_call_id {
                    // This message is a tool result - it's not a standard Ollama field,
                    // but some Ollama models support it. For now, embed in content.
                    msg["tool_call_id"] = serde_json::json!(tool_call_id);
                }
                msg
            })
            .collect();

        let mut body = serde_json::json!({
            "model": request.model,
            "messages": messages,
            // Stream so reasoning (`message.thinking`) is forwarded live; the
            // accumulator reassembles the full content/tool_calls, and the test mock's
            // single-object body is handled as the one-line degenerate case.
            "stream": true,
        });
        // No `options` object at all unless an override is set: this path never sent one.
        if !self.sampling.is_empty() {
            body["options"] = serde_json::json!({});
            self.sampling.apply_to(&mut body["options"]);
        }

        // Add tools if any
        if !request.tools.is_empty() {
            body["tools"] = serde_json::Value::Array(request.tools.clone());
        }

        // ollama-rs doesn't expose a chat-with-tools API, so we call the endpoint via reqwest.
        // Preserve the client's full base URL (scheme, host, port, path prefix).
        let endpoint = ollama.url_str().trim_end_matches('/').to_string();
        let url = format!("{}/api/chat", endpoint);
        let backend = crate::llm::backend_error::OLLAMA;

        let http_client = http_client.clone();
        let http_response = tokio::time::timeout(
            self.request_timeout,
            http_client.post(&url).json(&body).send(),
        )
        .await
        .map_err(|_| {
            backend_timeout_error(backend, &endpoint, &request.model, self.request_timeout)
        })?
        .map_err(|e| backend_send_error(backend, &endpoint, &request.model, e))?;

        if !http_response.status().is_success() {
            let failure =
                backend_response_error(backend, &endpoint, &request.model, http_response).await;
            return Err(self.report_backend_failure(failure));
        }

        let acc = self
            .read_ollama_stream(http_response, OllamaResponseKind::Chat, private_payloads)
            .await?;
        if let Some(err) = acc.error {
            anyhow::bail!("Ollama chat API error: {}", err);
        }

        // Parse accumulated response
        let content = Some(acc.content).filter(|s| !s.is_empty());

        let tool_calls = acc
            .tool_calls
            .as_ref()
            .and_then(|v| v.as_array())
            .map(|calls| {
                calls
                    .iter()
                    .enumerate()
                    .filter_map(|(i, tc)| {
                        let function = tc.get("function")?;
                        let name = function["name"].as_str()?.to_string();
                        let arguments = function.get("arguments").cloned().unwrap_or_default();
                        Some(ToolCall {
                            id: format!("call_{}", i),
                            function_name: name,
                            arguments,
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();

        let token_usage = TokenUsage {
            prompt_tokens: acc.prompt_eval_count,
            completion_tokens: acc.eval_count,
            total_tokens: acc.prompt_eval_count + acc.eval_count,
        };

        Ok(ChatResponse {
            content,
            tool_calls,
            token_usage,
        })
    }

    /// OpenAI backend: /v1/chat/completions with tools
    #[cfg(not(target_arch = "wasm32"))]
    async fn chat_with_tools_openai(
        &self,
        client: &reqwest::Client,
        base_url: &str,
        api_key: &str,
        request: &ChatRequest,
        private_payloads: bool,
    ) -> Result<ChatResponse> {
        let messages: Vec<serde_json::Value> = request
            .messages
            .iter()
            .map(|m| {
                if let Some(ref tool_call_id) = m.tool_call_id {
                    serde_json::json!({
                        "role": "tool",
                        "content": m.content,
                        "tool_call_id": tool_call_id,
                    })
                } else {
                    serde_json::json!({
                        "role": m.role,
                        "content": m.content,
                    })
                }
            })
            .collect();

        let mut body = serde_json::json!({
            "model": request.model,
            "messages": messages,
            "max_tokens": 4096,
            // Stream so reasoning appears live; ask for usage in the final frame.
            "stream": true,
            "stream_options": { "include_usage": true },
        });
        self.sampling.apply_to(&mut body);

        if !request.tools.is_empty() {
            body["tools"] = serde_json::Value::Array(request.tools.clone());
            body["tool_choice"] = serde_json::json!("auto");
        }

        let url = format!("{}/v1/chat/completions", base_url);

        let http_response = tokio::time::timeout(
            self.request_timeout,
            client
                .post(&url)
                .header("Authorization", format!("Bearer {}", api_key))
                .header("Content-Type", "application/json")
                .json(&body)
                .send(),
        )
        .await
        .map_err(|_| {
            backend_timeout_error(
                crate::llm::backend_error::OPENAI,
                base_url,
                &request.model,
                self.request_timeout,
            )
        })?
        .map_err(|e| {
            backend_send_error(
                crate::llm::backend_error::OPENAI,
                base_url,
                &request.model,
                e,
            )
        })?;

        if !http_response.status().is_success() {
            // Error responses are a single JSON object, not an SSE stream.
            let failure = backend_response_error(
                crate::llm::backend_error::OPENAI,
                base_url,
                &request.model,
                http_response,
            )
            .await;
            return Err(self.report_backend_failure(failure));
        }

        let acc = self
            .read_openai_stream(http_response, private_payloads)
            .await?;
        if let Some(err) = &acc.error {
            anyhow::bail!("OpenAI chat API error: {}", err);
        }

        Ok(ChatResponse {
            content: Some(acc.content.clone()).filter(|s| !s.is_empty()),
            tool_calls: acc.into_tool_calls(),
            token_usage: acc.token_usage(),
        })
    }

    /// Generate with automatic retry on parse errors (for legacy protocols)
    ///
    /// This is a simpler retry wrapper for protocols that don't use the action system.
    /// It retries if the response doesn't parse as ActionResponse.
    ///
    /// # Arguments
    /// * `model` - Model name
    /// * `prompt` - The prompt string
    /// * `expected_format` - Description of expected format for error message
    /// * `max_retries` - Maximum number of retries (0 = no retries, just one attempt)
    ///
    /// # Returns
    /// * `Ok(String)` - The LLM response (may be after retry)
    pub async fn generate_with_retry(
        &self,
        model: &str,
        prompt: &str,
        expected_format: &str,
        max_retries: usize,
    ) -> Result<String> {
        // Make prompt owned so we can update it for retries
        let mut current_prompt = prompt.to_string();

        for attempt in 1..=max_retries + 1 {
            debug!("Generate attempt {}/{}", attempt, max_retries + 1);
            trace!(
                "Retry loop: attempt={}, prompt_len={}",
                attempt,
                current_prompt.len()
            );

            // Generate response
            let generate_response = self.generate(model, &current_prompt).await?;

            // Extract XML references BEFORE validating JSON format
            // This allows LLM to use <script001> tags without causing "trailing characters" errors
            let (json_only, _refs) =
                crate::llm::reference_parser::extract_references(&generate_response.text)
                    .unwrap_or_else(|_| {
                        (
                            generate_response.text.clone(),
                            std::collections::HashMap::new(),
                        )
                    });

            // Strip markdown code fences if present (```json ... ``` or ``` ... ```)
            // LLMs sometimes wrap JSON in markdown formatting which causes parse errors
            let json_cleaned = strip_markdown_fences(&json_only);

            // A reasoning model puts its thinking before the JSON, so accept an
            // answer that is embedded in prose rather than failing it for
            // formatting. Strict parsing is still tried first.
            let json_cleaned = match ActionResponse::from_str(&json_cleaned) {
                Ok(_) => json_cleaned,
                Err(_) => match extract_embedded_json_object(&json_cleaned) {
                    Some(embedded) if ActionResponse::from_str(embedded).is_ok() => {
                        debug!(
                            "Recovered the action JSON from a response that wrapped it in prose \
                             ({} chars of surrounding text)",
                            json_cleaned.len().saturating_sub(embedded.len())
                        );
                        embedded.to_string()
                    }
                    _ => json_cleaned,
                },
            };

            // Try to parse cleaned JSON as ActionResponse to check format
            match ActionResponse::from_str(&json_cleaned) {
                // A tools-only answer parses, but this path has no tool loop —
                // `generate_with_retry` is the one-shot generate used by git,
                // mercurial and the event-case harness, so a tool call here is
                // a request the caller can never satisfy and returning it hands
                // them an empty action list. Retry with the correction below,
                // which tells the model to answer directly instead.
                Ok(parsed) if parsed.actions.is_empty() && !parsed.tools.is_empty() => {
                    warn!(
                        "Model asked to call {} tool(s) on a path that has none; \
                         retrying with a direct-answer correction",
                        parsed.tools.len()
                    );
                    if attempt > max_retries {
                        return Err(anyhow::anyhow!(
                            "LLM asked to call tools, which are not available on this \
                             path, and did not answer directly when asked again. \
                             Response began: {}",
                            crate::utils::truncate_for_log(&json_cleaned, 400)
                        ));
                    }
                    current_prompt = format!(
                        "{}\n\n---\n\nYour previous response asked to call a tool. Tools are \
                         not available for this request: answer directly instead, using only \
                         the actions listed above, and supply any value you would have asked \
                         a tool for yourself.\n\nRequired format: {}",
                        current_prompt, expected_format
                    );
                    continue;
                }
                Ok(_) => {
                    // Valid format!
                    if attempt > 1 {
                        info!("Retry successful on attempt {}", attempt);
                    }
                    trace!("Parse succeeded on attempt {}", attempt);
                    return Ok(generate_response.text);
                }
                Err(e) => {
                    if attempt <= max_retries {
                        // We have retries left
                        warn!("Parse error on attempt {}: {}", attempt, e);
                        warn!(
                            "Malformed response (after XML extraction and markdown stripping): {}",
                            crate::utils::truncate_for_log(&json_cleaned, 500)
                        );
                        trace!(
                            "Will retry with corrective feedback (attempt {}/{})",
                            attempt,
                            max_retries + 1
                        );

                        current_prompt = format!(
                            "{}\n\n---\n\nYour previous response was invalid and could not be parsed.\n\nError: {}\n\nRequired format: {}\n\nPlease provide your response again in the correct format.",
                            current_prompt,
                            e,
                            expected_format
                        );

                        info!(
                            "Retrying with corrective feedback (attempt {}/{})",
                            attempt + 1,
                            max_retries + 1
                        );
                        // Continue to next loop iteration with updated prompt
                    } else {
                        // No more retries
                        error!("Failed to get valid response after {} attempts", attempt);
                        trace!("Max retries exhausted, returning error");
                        // Carry a slice of what was actually returned: without
                        // it the operator sees only that parsing failed, and
                        // the difference between a truncated answer, a refusal
                        // and a model that ignored the format is invisible.
                        return Err(e).context(format!(
                            "LLM failed to provide valid format after retry. Response began: {}",
                            crate::utils::truncate_for_log(&json_cleaned, 400)
                        ));
                    }
                }
            }
        }

        unreachable!("Loop should always return or error")
    }

    /// Check if the LLM backend is available
    ///
    /// This is a probe, not a guard: it costs a round trip and races with the next real
    /// request. Callers wanting "do not attempt a doomed request" want the circuit breaker
    /// ([`Self::circuit_breaker_status`]), which is fed by the requests themselves.
    pub async fn is_available(&self) -> bool {
        self.list_models().await.is_ok()
    }

    /// List available models from the backend
    pub async fn list_models(&self) -> Result<Vec<String>> {
        match &self.backend {
            LlmBackend::Bridge { bridge, .. } => Ok(bridge.models()),
            #[cfg(not(target_arch = "wasm32"))]
            LlmBackend::Ollama(ollama, _) => {
                // ollama-rs applies no timeout of its own, so an unreachable host that
                // silently drops packets would hang this call — and `is_available()` with it
                // — indefinitely.
                let models = tokio::time::timeout(self.request_timeout, ollama.list_local_models())
                    .await
                    .with_context(|| {
                        format!(
                            "Listing Ollama models timed out after {:?}",
                            self.request_timeout
                        )
                    })?
                    .map_err(|e| anyhow::anyhow!("Failed to list models: {}", e))?;
                Ok(models.into_iter().map(|m| m.name).collect())
            }
            #[cfg(not(target_arch = "wasm32"))]
            LlmBackend::OpenAI {
                client,
                base_url,
                api_key,
            } => {
                let url = format!("{}/v1/models", base_url);
                let response = client
                    .get(&url)
                    .header("Authorization", format!("Bearer {}", api_key))
                    .timeout(std::time::Duration::from_secs(5))
                    .send()
                    .await
                    .context("Failed to connect to OpenAI-compatible API")?;

                if !response.status().is_success() {
                    anyhow::bail!("OpenAI API returned error status: {}", response.status());
                }

                let body: serde_json::Value =
                    crate::client::http_fetch::read_response_json(response, 8 * 1024 * 1024)
                        .await
                        .context("Failed to parse model list response")?;

                let models = body["data"]
                    .as_array()
                    .unwrap_or(&vec![])
                    .iter()
                    .filter_map(|m| m["id"].as_str().map(|s| s.to_string()))
                    .collect();
                Ok(models)
            }
            LlmBackend::Queue { .. } => Ok(vec!["agent".to_string()]),
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl Default for OllamaClient {
    fn default() -> Self {
        OllamaClient::default()
    }
}

/// Await the host's answer to a bridge request, bounded by `timeout`.
///
/// The three failure shapes are kept distinct in the message: the host said no (its own
/// text, which the page chose to show), the host dropped the request, and the host never
/// answered. Only the first is the model's doing.
async fn await_bridge_reply(
    id: u64,
    rx: tokio::sync::oneshot::Receiver<Result<crate::llm::bridge::BridgeReply, String>>,
    timeout: std::time::Duration,
) -> Result<crate::llm::bridge::BridgeReply> {
    match tokio::time::timeout(timeout, rx).await {
        Ok(Ok(Ok(reply))) => Ok(reply),
        Ok(Ok(Err(message))) => anyhow::bail!("✗  The model host reported an error: {}", message),
        Ok(Err(_)) => anyhow::bail!(
            "bridge: LLM request #{} was dropped before it was answered",
            id
        ),
        Err(_) => anyhow::bail!(
            "bridge: LLM request #{} timed out after {:?} without an answer",
            id,
            timeout
        ),
    }
}

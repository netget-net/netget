//! An LLM backend that asks the host to answer.
//!
//! The browser build has no HTTP client it could point at Ollama and no model of its own;
//! what it has is a page. The page may run a model in-browser (the browser's built-in model,
//! or WebLLM over WebGPU), or show the request to the person at the keyboard and let *them*
//! be the model. NetGet does not need to know which: every request
//! `OllamaClient` would have sent over HTTP becomes a [`BridgeRequest`] on a channel, and
//! whoever drains the channel answers it with a [`BridgeReply`].
//!
//! The request carries everything the wire request would have: the model name, the full
//! message list (system prompt included) and the tool schemas. That is deliberate: the demo
//! page shows all of it, so a visitor sees exactly what NetGet says to a model and what comes
//! back. Nothing here is browser-specific; a native test can drain the same channel, which is
//! how the mapping from request to `ChatResponse` is verified.
//!
//! It also carries what no wire request does: the actions the prompt offers, as structured
//! data ([`BridgeRequest::actions`]). A network event's request has no native tool schemas —
//! the action list is prose inside the prompt — and a person answering by hand needs the
//! names, the parameters and a working example in a form a page can turn into a form.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, oneshot};

use crate::llm::actions::ActionDefinition;
use crate::llm::ollama_client::Message;

/// Which client entry point produced the request. The host may treat them alike (both are
/// "here are messages, give me a completion"); the distinction is kept because the two
/// paths parse the answer differently.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BridgeRequestKind {
    /// `generate_with_format`: one flattened prompt, the answer is parsed from its text.
    /// Every network event goes this way.
    Generate,
    /// `chat_with_tools`: structured messages plus tool schemas; the answer may carry
    /// native tool calls. User chat input and scheduled tasks go this way.
    Chat,
}

/// The network event behind a model request. The token identifies one event conversation,
/// so a host can attach deterministic state once even when the model answer is retried.
/// This is bridge metadata only; native model backends keep their existing wire format.
#[derive(Debug, Clone, Serialize)]
pub struct BridgeEventContext {
    pub token: String,
    pub server_id: u32,
    pub connection_id: Option<u32>,
    pub protocol: String,
    pub event_type: String,
    pub data: serde_json::Value,
}

/// One LLM request, as the host sees it.
#[derive(Debug, Serialize)]
pub struct BridgeRequest {
    pub id: u64,
    pub kind: BridgeRequestKind,
    pub model: String,
    /// The full prompt. For `Generate` this is a single `user` message holding the
    /// flattened prompt; for `Chat` it is the conversation, system message first.
    pub messages: Vec<Message>,
    /// Tool schemas in OpenAI function-tool format; empty for `Generate`.
    pub tools: Vec<serde_json::Value>,
    /// Every action the prompt offers for this request, in the shape [`offered_action`]
    /// documents — the same list the model is shown, whether it is shown as prose (every
    /// network event) or as native tools. Empty for a request that offers no actions.
    /// Nothing on the native Ollama/OpenAI wire carries it.
    pub actions: Vec<serde_json::Value>,
    /// Present for server event conversations; unchanged across retries of that event.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event: Option<BridgeEventContext>,
    /// Where the answer goes. Dropping it without answering fails the request.
    #[serde(skip)]
    pub reply: oneshot::Sender<Result<BridgeReply, String>>,
}

/// A native tool call in the host's answer.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BridgeToolCall {
    #[serde(default)]
    pub id: Option<String>,
    /// Accepts either spelling so a host can pass an OpenAI `function.name` through
    /// untouched.
    #[serde(default, alias = "function_name")]
    pub name: String,
    #[serde(default)]
    pub arguments: serde_json::Value,
}

/// The host's answer.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BridgeReply {
    /// The answer: the action envelope, or plain text. Only this is parsed.
    #[serde(default)]
    pub content: Option<String>,
    #[serde(default)]
    pub tool_calls: Vec<BridgeToolCall>,
    /// The reasoning a model that thinks natively wrote before this answer — the demo page
    /// sends Qwen3's `<think>` block here and the text after it as `content`. It is never
    /// parsed as part of the answer. It reaches the status channel as `[REASONING]` lines,
    /// exactly as an Ollama `thinking` stream or an OpenAI `reasoning`/`reasoning_content`
    /// stream does, so the dashboard shows it the same way.
    #[serde(default, alias = "reasoning_content", alias = "thinking")]
    pub reasoning: Option<String>,
    #[serde(default)]
    pub prompt_tokens: u64,
    #[serde(default)]
    pub completion_tokens: u64,
}

/// The channel between `OllamaClient` and the host.
pub struct LlmBridge {
    tx: mpsc::UnboundedSender<BridgeRequest>,
    next_id: AtomicU64,
    models: Mutex<Vec<String>>,
}

impl LlmBridge {
    /// Create a bridge and the receiver the host drains.
    pub fn new() -> (Arc<Self>, mpsc::UnboundedReceiver<BridgeRequest>) {
        let (tx, rx) = mpsc::unbounded_channel();
        (
            Arc::new(Self {
                tx,
                next_id: AtomicU64::new(1),
                models: Mutex::new(Vec::new()),
            }),
            rx,
        )
    }

    /// Hand a request to the host. The returned receiver yields the answer; an `Err` inside
    /// it is the host's own error text, an `Err` on the receive is the host dropping the
    /// request unanswered.
    pub fn submit(
        &self,
        kind: BridgeRequestKind,
        model: String,
        messages: Vec<Message>,
        tools: Vec<serde_json::Value>,
        offered: &[ActionDefinition],
    ) -> (u64, oneshot::Receiver<Result<BridgeReply, String>>) {
        self.submit_with_event(kind, model, messages, tools, offered, None)
    }

    /// Submit an event request without requiring the host to parse event data out of prose.
    pub(crate) fn submit_with_event(
        &self,
        kind: BridgeRequestKind,
        model: String,
        messages: Vec<Message>,
        tools: Vec<serde_json::Value>,
        offered: &[ActionDefinition],
        event: Option<BridgeEventContext>,
    ) -> (u64, oneshot::Receiver<Result<BridgeReply, String>>) {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let (reply, rx) = oneshot::channel();
        let request = BridgeRequest {
            id,
            kind,
            model,
            messages,
            tools,
            actions: offered.iter().map(offered_action).collect(),
            event,
            reply,
        };
        // A closed receiver means no host; the request's reply sender is dropped with it,
        // which the caller sees as an unanswered request.
        let _ = self.tx.send(request);
        (id, rx)
    }

    /// What `list_models` reports. The host sets this to whatever it can run.
    pub fn set_models(&self, models: Vec<String>) {
        *self.models.lock().expect("bridge model list") = models;
    }

    pub fn models(&self) -> Vec<String> {
        self.models.lock().expect("bridge model list").clone()
    }
}

/// The names [`offered_action`] marks `generic`.
static GENERIC_ACTIONS: std::sync::LazyLock<std::collections::HashSet<String>> =
    std::sync::LazyLock::new(|| {
        let mut names: std::collections::HashSet<String> =
            crate::llm::actions::common::get_network_event_common_actions()
                .into_iter()
                .map(|a| a.name)
                .collect();
        names.insert(crate::llm::actions::common::provide_feedback_action().name);
        names.insert(crate::llm::actions::common::set_connection_memory_action().name);
        names.insert(crate::llm::actions::common::append_connection_memory_action().name);
        names
    });

/// One offered action as the host sees it:
///
/// ```json
/// {"name": "send_tcp_data", "description": "...", "tool": false, "generic": false,
///  "parameters": [{"name": "encoding", "type": "\"utf8\" | \"hex\"", "description": "...",
///                  "required": false, "choices": ["utf8", "hex"]}],
///  "example": {"type": "send_tcp_data", "data": "hi"},
///  "schema": {"type": "object", "properties": {...}, "required": [...]}}
/// ```
///
/// - `type` is the declared type hint verbatim (`"string"`, `"number | string"`,
///   `"array"`…); `choices` is present only for a closed value set (`Parameter::choices`).
/// - `example` is the action's own example, which its executor accepts
///   (`tests/executable_examples_test.rs`), so a host can prefill a form from it.
/// - `tool` is true for a tool (`read_file`, `web_search`, …): the model is asked again with
///   its result, and in the JSON envelope it goes under `"tools"` rather than `"actions"`.
/// - `generic` is true for the bookkeeping actions every network event offers whatever the
///   protocol (`set_memory`, `notify_operator`, `provide_feedback`, …), so a host can put the
///   protocol's own answer first.
/// - `schema` is the JSON Schema of the parameters, the one a native tool schema carries.
pub fn offered_action(action: &ActionDefinition) -> serde_json::Value {
    let parameters: Vec<serde_json::Value> = action
        .parameters
        .iter()
        .map(|p| {
            let mut v = serde_json::json!({
                "name": p.name,
                "type": p.type_hint,
                "description": p.description,
                "required": p.required,
            });
            if let Some(choices) = p.choices() {
                v["choices"] = serde_json::json!(choices);
            }
            v
        })
        .collect();
    let schema = action
        .to_tool_schema()
        .pointer("/function/parameters")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    serde_json::json!({
        "name": action.name,
        "description": action.description,
        "tool": action.is_tool(),
        "generic": GENERIC_ACTIONS.contains(action.name.as_str()),
        "parameters": parameters,
        "example": action.example,
        "schema": schema,
    })
}

//! Conversation-based LLM interaction with tool calling and retry logic
//!
//! This module provides a unified conversation handler that:
//! 1. Maintains conversation history (system, user, assistant messages)
//! 2. Handles multi-turn tool calling automatically
//! 3. Retries malformed responses with corrective feedback
//! 4. Works for both user input and network events

use crate::llm::actions::{execute_tool, ActionDefinition, ActionResponse, ToolAction, ToolResult};
use crate::llm::conversation_state::ConversationState;
use crate::llm::ollama_client::{ChatRequest, ChatResponse, Message, OllamaClient};
use crate::llm::{RateLimiter, RequestSource};
use crate::logging::emit::Log;
use crate::state::app_state::{AppState, ConversationSource, WebApprovalRequest, WebSearchMode};
use anyhow::{Context, Result};
use std::sync::{Arc, Mutex};
use tracing::{debug, error, info, trace, warn};

/// Extract reasoning from LLM response and return (reasoning, cleaned_response)
///
/// Looks for `<reasoning>...</reasoning>` tags in the response, extracts the content,
/// and returns a cleaned response with the tags removed.
///
/// # Arguments
/// * `response` - The raw LLM response text
///
/// # Returns
/// * `(Option<String>, String)` - Reasoning content (if found) and cleaned response
/// Whether any value in this action still points at a tool result rather than
/// carrying one.
///
/// Models write these unprompted — `"block_hex": "{{tools[0].result}}"`,
/// `"token": "{{tool_results[1]}}"` — reasoning that the tool call they issued in
/// the same response will be substituted in. Nothing substitutes it:
/// `reference_parser` resolves `<tagname>` XML references, and there is no
/// `{{...}}` mechanism on the LLM path at all. The placeholder would reach the
/// wire as literal text.
///
/// Deliberately narrow. It matches only `{{…}}` whose body mentions a tool, so
/// `{{event.field}}` — which *is* substituted, later and elsewhere, inside static
/// event-handler definitions — is left alone.
fn action_references_tool_result(action: &serde_json::Value) -> bool {
    fn mentions_tool_placeholder(text: &str) -> bool {
        let mut rest = text;
        while let Some(open) = rest.find("{{") {
            let after = &rest[open + 2..];
            let Some(close) = after.find("}}") else { break };
            if after[..close].to_lowercase().contains("tool") {
                return true;
            }
            rest = &after[close + 2..];
        }
        false
    }

    match action {
        serde_json::Value::String(s) => mentions_tool_placeholder(s),
        serde_json::Value::Array(items) => items.iter().any(action_references_tool_result),
        serde_json::Value::Object(map) => map.values().any(action_references_tool_result),
        _ => false,
    }
}

fn extract_reasoning(response: &str) -> (Option<String>, String) {
    let reasoning_start = response.find("<reasoning>");
    let reasoning_end = response.find("</reasoning>");

    match (reasoning_start, reasoning_end) {
        (Some(start), Some(end)) if end > start => {
            // Extract reasoning content (between tags)
            let reasoning_content = response[start + 11..end].trim().to_string();

            // Remove the entire reasoning tag (including tags themselves)
            let before = &response[..start];
            let after = &response[end + 12..];
            let cleaned = format!("{}{}", before, after).trim().to_string();

            (Some(reasoning_content), cleaned)
        }
        _ => (None, response.to_string()),
    }
}

/// Default cap on the number of messages kept in the in-flight conversation.
///
/// A legitimate run is bounded by `max_tool_iterations` (5), each iteration contributing at
/// most an assistant response, an action acknowledgement and a tool-results message — 15,
/// plus the system message and the initial trigger. 24 leaves room for a couple of
/// corrections on top of a full-length legitimate run and clips only pathological ones.
pub const DEFAULT_MAX_HISTORY_MESSAGES: usize = 24;

/// Default cap on the total characters of the non-system messages sent to the model.
///
/// Roughly 8k tokens. `format_tool_results` already caps each tool result at 2000 chars, so
/// this holds a full 5-iteration run's worth of tool output plus the surrounding turns. It
/// is deliberately larger than `ConversationState`'s 8000-char cross-*call* window, which
/// bounds a different structure and never bounded what is actually sent.
pub const DEFAULT_MAX_HISTORY_CHARS: usize = 32_000;

/// Stand-in message left in place of history dropped by [`ConversationHandler::trim_history`].
const TRIM_NOTICE: &str = "[Earlier turns of this conversation were omitted to bound the prompt size. The system message and the original request above are intact.]";

/// Conversation handler for multi-turn LLM interactions
pub struct ConversationHandler {
    /// Unique conversation ID for tracking
    conversation_id: String,

    /// Conversation messages (system, user, assistant, tool)
    messages: Vec<Message>,

    /// Conversation state for history tracking with token limits
    conversation_state: Arc<Mutex<ConversationState>>,

    /// Ollama client for chat API calls
    client: Arc<OllamaClient>,

    /// Model name (e.g., "qwen3-coder:30b")
    model: String,

    /// Maximum number of retries for malformed responses
    max_retries: usize,

    /// Maximum tool calling iterations
    max_tool_iterations: usize,

    /// Status channel for user-visible logs
    status_tx: Option<tokio::sync::mpsc::UnboundedSender<String>>,

    /// Index of last logged message (to avoid re-logging entire conversation)
    last_logged_index: usize,

    /// Whether protocol documentation has been read in this conversation (enables open_server and open_client)
    protocol_docs_read: bool,

    /// Whether server documentation has been read in this conversation (enables open_server)
    _server_docs_read: bool,

    /// Whether client documentation has been read in this conversation (enables open_client)
    _client_docs_read: bool,

    /// Application state (for conversation tracking)
    state: Option<AppState>,

    /// Source of this conversation (for UI display)
    source: Option<ConversationSource>,

    /// Details text for UI display
    details: Option<String>,

    /// Whether this conversation has been registered (to avoid duplicate registration)
    registered: bool,

    /// Rate limiter for controlling LLM call frequency and token usage
    rate_limiter: RateLimiter,

    /// Source of the request (User or Network) for rate limiting behavior
    request_source: RequestSource,

    /// Native tool schemas for chat_with_tools() API (empty = use prompt-based fallback)
    tool_schemas: Vec<serde_json::Value>,

    /// Whether to use native tool calling (chat_with_tools) vs prompt-based (generate_with_format)
    use_native_tools: bool,

    /// The actions the current `generate_with_tools_and_retry` call offers. Handed to the
    /// client with every request so a bridge host can show them as structured data.
    offered_actions: Vec<ActionDefinition>,

    /// Structured metadata for a single network event, retained across all retries.
    bridge_event: Option<crate::llm::bridge::BridgeEventContext>,
    agent_context: Option<serde_json::Value>,

    /// Conversation-local policy retained once credential parameters are offered.
    private_payloads: bool,

    /// Cap on `messages.len()` — see [`DEFAULT_MAX_HISTORY_MESSAGES`]
    max_history_messages: usize,

    /// Cap on the total characters of the non-system messages — see [`DEFAULT_MAX_HISTORY_CHARS`]
    max_history_chars: usize,

    /// Bumped every time [`Self::trim_history`] actually removes messages.
    ///
    /// Trimming shifts every index after the protected prefix, so code holding a message
    /// index across a possible trim compares this first and gives up on a mismatch rather
    /// than draining the wrong range.
    trim_generation: u64,
}

impl ConversationHandler {
    /// Create a new conversation handler with a system message
    pub fn new(
        system_message: String,
        client: Arc<OllamaClient>,
        model: String,
        rate_limiter: RateLimiter,
        request_source: RequestSource,
    ) -> Self {
        let messages = vec![Message::system(system_message)];

        // Generate unique conversation ID using timestamp and random bytes
        let conversation_id = Self::generate_conversation_id();

        // Create conversation state with default token limit (8000 characters)
        // This can be made configurable later
        let conversation_state = Arc::new(Mutex::new(ConversationState::new(8000)));

        Self {
            conversation_id,
            messages,
            conversation_state,
            client,
            model,
            max_retries: 1,
            max_tool_iterations: 5,
            status_tx: None,
            last_logged_index: 0, // No messages logged yet
            protocol_docs_read: false,
            _server_docs_read: false,
            _client_docs_read: false,
            state: None,
            source: None,
            details: None,
            registered: false,
            rate_limiter,
            request_source,
            tool_schemas: Vec::new(),
            use_native_tools: false,
            offered_actions: Vec::new(),
            bridge_event: None,
            agent_context: None,
            private_payloads: false,
            max_history_messages: DEFAULT_MAX_HISTORY_MESSAGES,
            max_history_chars: DEFAULT_MAX_HISTORY_CHARS,
            trim_generation: 0,
        }
    }

    /// Explicit network context for agent consumers; native model prompts are unchanged.
    pub fn with_agent_context(mut self, mut context: serde_json::Value) -> Self {
        context["event_token"] = serde_json::json!(self.conversation_id);
        self.agent_context = Some(context);
        self
    }

    /// Attach the event for a bridge host without making it recover context from prompt text.
    pub fn with_bridge_event(
        mut self,
        server_id: crate::state::ServerId,
        connection_id: Option<crate::server::connection::ConnectionId>,
        protocol: &str,
        event: &crate::protocol::Event,
    ) -> Self {
        // Native transports already render event data into the prompt and never consume
        // this metadata. Avoid another potentially large clone for every native request.
        if self.client.backend_type() != "bridge" {
            return self;
        }
        self.bridge_event = Some(crate::llm::bridge::BridgeEventContext {
            token: self.conversation_id.clone(),
            server_id: server_id.as_u32(),
            connection_id: connection_id.map(|id| id.as_u32()),
            protocol: protocol.to_string(),
            event_type: event.id().to_string(),
            data: event.data.clone(),
        });
        self
    }

    /// Override the conversation-history caps (see [`DEFAULT_MAX_HISTORY_MESSAGES`] and
    /// [`DEFAULT_MAX_HISTORY_CHARS`]).
    pub fn with_history_limits(mut self, max_messages: usize, max_chars: usize) -> Self {
        self.max_history_messages = max_messages.max(3);
        self.max_history_chars = max_chars;
        self
    }

    /// Dual-sink log facade bound to this conversation's status channel.
    ///
    /// The conversation layer owns the *semantic* narration of a round-trip — which
    /// attempt, that a response arrived, the outcome — and is the only layer that
    /// narrates it to the TUI. Wire facts (sizes, tokens) belong to the transport
    /// (`OllamaClient`) and stay file-only. Full payloads are TRACE/file-only.
    fn log(&self) -> Log<'_> {
        Log::new(self.status_tx.as_ref()).with_payloads(!self.private_payloads)
    }

    fn display_payload(&self, text: &str) -> String {
        if self.private_payloads {
            crate::utils::redact::REDACTED.into()
        } else {
            text.into()
        }
    }

    /// Total characters of everything but the system message.
    fn history_chars(&self) -> usize {
        self.messages.iter().skip(1).map(|m| m.content.len()).sum()
    }

    /// Whether the conversation exceeds either history cap.
    fn over_history_budget(&self) -> bool {
        self.messages.len() > self.max_history_messages
            || self.history_chars() > self.max_history_chars
    }

    /// Bound the conversation that is actually sent to the model.
    ///
    /// Without this, `messages` only ever grows: five tool iterations each append an
    /// assistant response, an acknowledgement and a tool-results block, and every failed
    /// attempt leaves its response plus a correction behind for the rest of the
    /// conversation. `ConversationState`'s 8000-char window is a different structure and
    /// bounds only cross-call history, never the request.
    ///
    /// The system message and the first user message — the instruction and the request the
    /// whole conversation is about — are never dropped, nor are the two most recent
    /// messages. Everything between is dropped oldest-first and replaced by a single
    /// [`TRIM_NOTICE`], so the model is told its history was cut rather than left to
    /// reference turns that silently vanished.
    ///
    /// Called before every request; public so the bound is directly assertable.
    pub fn trim_history(&mut self) {
        if !self.over_history_budget() {
            return;
        }

        let protected = if self.messages.len() > 1 && self.messages[1].role == "user" {
            2
        } else {
            1
        };
        // Keep at least the two most recent messages after the protected prefix.
        let min_len = protected + 2;

        let mut dropped_messages = 0usize;
        let mut dropped_chars = 0usize;
        let mut removed_any = false;
        while self.messages.len() > min_len && self.over_history_budget() {
            let removed = self.messages.remove(protected);
            removed_any = true;
            // A notice left by an earlier trim is replaced, not counted as lost content.
            if removed.content != TRIM_NOTICE {
                dropped_messages += 1;
                dropped_chars += removed.content.len();
            }
        }

        if !removed_any {
            return;
        }

        // Any removal shifts every index after the protected prefix.
        self.trim_generation += 1;
        self.messages
            .insert(protected, Message::user(TRIM_NOTICE.to_string()));
        // The notice itself counts against the message cap.
        if self.messages.len() > self.max_history_messages && self.messages.len() > min_len + 1 {
            let removed = self.messages.remove(protected + 1);
            dropped_messages += 1;
            dropped_chars += removed.content.len();
        }

        // Trimming is a DEBUG summary — file-only, off the TUI stream.
        self.log().debug(format!(
            "Trimmed conversation history: dropped {} message(s) / {} chars, {} message(s) and \
             {} chars remain (caps: {} messages, {} chars)",
            dropped_messages,
            dropped_chars,
            self.messages.len(),
            self.history_chars(),
            self.max_history_messages,
            self.max_history_chars
        ));
    }

    /// Generate a unique conversation ID
    fn generate_conversation_id() -> String {
        use crate::utils::clock::SystemTime;
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let random: u32 = rand::random();
        format!("conv-{}-{:x}", timestamp, random)
    }

    /// Hide incidental payload/error diagnostics when structured request input
    /// contains credentials. Sticky only within this conversation's history.
    pub fn with_private_payloads(mut self, private: bool) -> Self {
        self.private_payloads |= private;
        self
    }

    /// Set the status channel for user-visible logs
    pub fn with_status_tx(mut self, tx: tokio::sync::mpsc::UnboundedSender<String>) -> Self {
        self.status_tx = Some(tx);
        self
    }

    /// Set an existing conversation state
    pub fn with_conversation_state(mut self, state: Arc<Mutex<ConversationState>>) -> Self {
        self.conversation_state = state;
        self
    }

    /// Set conversation tracking information
    pub fn with_tracking(
        mut self,
        state: AppState,
        source: ConversationSource,
        details: String,
    ) -> Self {
        self.state = Some(state);
        self.source = Some(source);
        self.details = Some(details);
        self
    }

    /// Enable native tool calling with the given action definitions
    ///
    /// When set, `generate_with_retry()` will use `chat_with_tools()` instead of
    /// `generate_with_format()`, sending structured messages and tool schemas.
    /// The response is converted back to ActionResponse text format so the existing
    /// tool calling loop in `generate_with_tools_and_retry()` works unchanged.
    ///
    /// Also strips redundant action/tool descriptions and JSON format instructions from
    /// the system message to reduce token usage (these are now handled by native tool schemas).
    pub fn with_native_tools(mut self, actions: &[ActionDefinition]) -> Self {
        self.tool_schemas = actions.iter().map(|a| a.to_tool_schema()).collect();
        self.use_native_tools = !self.tool_schemas.is_empty();

        // Strip redundant sections from system message when native tools are active
        if self.use_native_tools && !self.messages.is_empty() && self.messages[0].role == "system" {
            let content = &self.messages[0].content;
            let mut cleaned = content.clone();

            // Remove "# Available Tools" section (text descriptions of tools)
            if let Some(start) = cleaned.find("# Available Tools") {
                if let Some(next_section) = cleaned[start + 1..].find("\n# ") {
                    cleaned = format!(
                        "{}{}",
                        &cleaned[..start],
                        &cleaned[start + 1 + next_section..]
                    );
                }
            }

            // Remove "# Available Actions" section (text descriptions of actions)
            if let Some(start) = cleaned.find("# Available Actions") {
                if let Some(next_section) = cleaned[start + 1..].find("\n# ") {
                    cleaned = format!(
                        "{}{}",
                        &cleaned[..start],
                        &cleaned[start + 1 + next_section..]
                    );
                }
            }

            // Remove "# Response Format" section (JSON format instructions)
            if let Some(start) = cleaned.find("# Response Format") {
                if let Some(next_section) = cleaned[start + 1..].find("\n# ") {
                    cleaned = format!(
                        "{}{}",
                        &cleaned[..start],
                        &cleaned[start + 1 + next_section..]
                    );
                }
            }

            // Remove the "CRITICAL - READ THIS FIRST" JSON format block from task.hbs
            if let Some(start) = cleaned.find("**⚠️  CRITICAL - READ THIS FIRST ⚠️**") {
                // Find the end of this block (next "---" or "## ")
                if let Some(end_marker) = cleaned[start..].find("\n---\n") {
                    let end = start + end_marker + 5; // include the "---\n"
                    cleaned = format!("{}{}", &cleaned[..start], &cleaned[end..]);
                }
            }

            if cleaned.len() < content.len() {
                debug!(
                    "Stripped {} chars of redundant action/format descriptions from system message (native tools active)",
                    content.len() - cleaned.len()
                );
                self.messages[0] = Message::system(cleaned);
            }
        }

        self
    }

    /// Update the native tool schemas (e.g., after documentation is read and new tools are enabled)
    pub fn update_tool_schemas(&mut self, actions: &[ActionDefinition]) {
        self.tool_schemas = actions.iter().map(|a| a.to_tool_schema()).collect();
        self.use_native_tools = !self.tool_schemas.is_empty();
    }

    /// Convert a ChatResponse (native tool calls) into ActionResponse-compatible text
    ///
    /// This bridges native tool calling with the existing text-based parsing pipeline.
    /// Each tool_call is converted to a JSON object with "type" field matching the function name,
    /// then separated into tools vs actions arrays.
    fn chat_response_to_action_text(response: &ChatResponse) -> String {
        let mut tools = Vec::new();
        let mut actions = Vec::new();

        for tc in &response.tool_calls {
            // Build action JSON: merge function_name as "type" with arguments
            let obj = if let Some(map) = tc.arguments.as_object() {
                let mut new_map = serde_json::Map::new();
                new_map.insert(
                    "type".to_string(),
                    serde_json::Value::String(tc.function_name.clone()),
                );
                for (k, v) in map {
                    new_map.insert(k.clone(), v.clone());
                }
                serde_json::Value::Object(new_map)
            } else {
                serde_json::json!({"type": tc.function_name})
            };

            // Separate into tools vs actions using existing classification
            if ToolAction::is_tool_action(&obj) {
                tools.push(obj);
            } else {
                actions.push(obj);
            }
        }

        // If there's text content and no tool calls, convert to show_message
        if let Some(content) = &response.content {
            if !content.is_empty() && tools.is_empty() && actions.is_empty() {
                actions.push(serde_json::json!({"type": "show_message", "message": content}));
            }
        }

        serde_json::to_string(&serde_json::json!({
            "tools": tools,
            "actions": actions
        }))
        .unwrap_or_default()
    }

    /// Manually end conversation tracking (for error paths where generate_with_tools_and_retry doesn't complete)
    pub async fn end_tracking(&self) {
        if let Some(state) = &self.state {
            state.end_conversation(&self.conversation_id).await;
        }
    }

    /// Check if protocol documentation has been read in this conversation
    pub fn is_protocol_docs_read(&self) -> bool {
        self.protocol_docs_read
    }

    /// Mark protocol documentation as read in this conversation (enables open_server and open_client)
    /// This also updates the system message to enable the open_server and open_client actions
    fn mark_protocol_docs_read(&mut self, available_actions: &[ActionDefinition]) {
        self.protocol_docs_read = true;
        debug!("Protocol documentation read in conversation - open_server and open_client actions are now enabled");

        // Enable open_server and open_client in the available actions
        // by filtering out the disabled versions and regenerating them with enabled flag
        let mut enabled_actions = Vec::new();

        for action in available_actions {
            // Skip the disabled open_server and open_client actions - we'll add enabled versions
            if action.name == "open_server" && action.parameters.is_empty() {
                // This is the disabled version - skip it
                continue;
            }
            if action.name == "open_client" && action.parameters.is_empty() {
                // This is the disabled version - skip it
                continue;
            }
            enabled_actions.push(action.clone());
        }

        // We need to regenerate the enabled actions, but since we don't have access to the
        // state/env here, we'll add placeholder descriptions in the actions.
        // The real solution would be to pass state/env to this function, but that's more invasive.
        // For now, let's just update the existing disabled ones to be enabled by replacing them
        // with newly built ones that have full parameters.

        // Since we can't easily regenerate here without state/env, let's just pass the
        // existing actions. The update_actions_section function will render them as-is.
        // The actions will remain disabled in this iteration, but the next iteration will
        // have them enabled because the conversation will have a new set of actions built
        // with the enabled flags.

        // Rebuild the actions section in the system prompt
        self.update_actions_section(available_actions);
    }

    /// Mark server documentation as read in this conversation (enables open_server)
    #[allow(dead_code)]
    fn _mark_server_docs_read(&mut self, available_actions: &[ActionDefinition]) {
        self._server_docs_read = true;
        debug!("Server documentation read in conversation - open_server action is now enabled");

        // Rebuild the actions section in the system prompt
        self.update_actions_section(available_actions);
    }

    /// Mark client documentation as read in this conversation (enables open_client)
    #[allow(dead_code)]
    fn _mark_client_docs_read(&mut self, available_actions: &[ActionDefinition]) {
        self._client_docs_read = true;
        debug!("Client documentation read in conversation - open_client action is now enabled");

        // Rebuild the actions section in the system prompt
        self.update_actions_section(available_actions);
    }

    /// Update the "Available Actions" section in the system message
    ///
    /// This is used after read_base_stack_docs is called to enable the open_server action.
    fn update_actions_section(&mut self, available_actions: &[ActionDefinition]) {
        use crate::llm::prompt::PromptBuilder;

        if self.messages.is_empty() {
            warn!("Cannot update actions section: no system message found");
            return;
        }

        // Get the system message (first message)
        let system_msg = &self.messages[0];
        if system_msg.role != "system" {
            warn!("First message is not a system message, cannot update actions section");
            return;
        }

        let old_content = &system_msg.content;

        // Find the "# Available Tools" or "# Available Actions" section
        let section_start = if let Some(pos) = old_content.find("# Available Tools") {
            Some(pos)
        } else {
            old_content.find("# Available Actions")
        };

        if let Some(start_pos) = section_start {
            // Find where this section ends (next "# " or "---" or end of string)
            let content_after_section = &old_content[start_pos..];

            // Find the next major section marker
            let mut end_pos = start_pos;
            let mut found_end = false;

            // Skip past the section header
            if let Some(first_newline) = content_after_section.find('\n') {
                let search_start = start_pos + first_newline + 1;
                let remaining = &old_content[search_start..];

                // Look for next section (starts with "# " at line start or "---")
                if let Some(next_section) = remaining.find("\n# ") {
                    end_pos = search_start + next_section;
                    found_end = true;
                } else if let Some(divider) = remaining.find("\n---") {
                    end_pos = search_start + divider;
                    found_end = true;
                }
            }

            if !found_end {
                end_pos = old_content.len();
            }

            // Build new actions section using PromptBuilder
            let new_actions_section =
                PromptBuilder::build_actions_section_public(available_actions);

            // Replace the old actions section with the new one
            let mut new_content = String::new();
            new_content.push_str(&old_content[..start_pos]);
            new_content.push_str(&new_actions_section);
            if end_pos < old_content.len() {
                new_content.push_str(&old_content[end_pos..]);
            }

            // Update the system message
            self.messages[0] = Message::system(new_content);

            debug!("Updated Available Actions section in system message with open_server enabled");
        } else {
            warn!("Could not find '# Available Tools' or '# Available Actions' section in system message");
        }
    }

    /// Add a user message to the conversation
    pub fn add_user_message(&mut self, content: String) {
        // Track in conversation state
        if let Ok(mut state) = self.conversation_state.lock() {
            state.add_user_input(content.clone());
        }

        self.messages.push(Message::user(content));
    }

    /// Generate response with tool calling and retry logic
    ///
    /// This is the main entry point that handles:
    /// 1. Multi-turn tool calling loop
    /// 2. Automatic retry on parse/validation errors
    /// 3. Tool execution with result feedback
    ///
    /// # Arguments
    /// * `approval_tx` - Optional channel for web search approval
    /// * `web_search_mode` - Web search configuration
    /// * `available_actions` - List of actions available in this context
    ///
    /// # Returns
    /// * `Ok(Vec<serde_json::Value>)` - Array of non-tool actions to execute
    pub async fn generate_with_tools_and_retry(
        &mut self,
        approval_tx: Option<tokio::sync::mpsc::UnboundedSender<WebApprovalRequest>>,
        web_search_mode: WebSearchMode,
        available_actions: Vec<ActionDefinition>,
    ) -> Result<Vec<serde_json::Value>> {
        self.private_payloads |= crate::utils::redact::actions_have_credentials(&available_actions);
        // This handle belongs to this generation, including its tool/retry loop.
        // Dropping the future (e.g. stopping a server) also clears its activity.
        let _activity = self
            .state
            .as_ref()
            .zip(self.source.as_ref())
            .map(|(state, source)| {
                state.llm_activity.begin(
                    source.clone(),
                    self.display_payload(self.details.as_deref().unwrap_or_default()),
                )
            });
        let result = self
            .generate_until_final_response(approval_tx, web_search_mode, available_actions)
            .await;
        if result.is_err() {
            // Rejected/exhausted responses must not leave a live conversation in the UI.
            self.end_tracking().await;
        }
        result
    }

    async fn generate_until_final_response(
        &mut self,
        approval_tx: Option<tokio::sync::mpsc::UnboundedSender<WebApprovalRequest>>,
        web_search_mode: WebSearchMode,
        available_actions: Vec<ActionDefinition>,
    ) -> Result<Vec<serde_json::Value>> {
        // Register conversation if tracking is enabled and not already registered
        if !self.registered {
            if let (Some(state), Some(source), Some(details)) =
                (&self.state, &self.source, &self.details)
            {
                state
                    .register_conversation(
                        self.conversation_id.clone(),
                        source.clone(),
                        details.clone(),
                    )
                    .await;
                self.registered = true;
            }
        }

        let mut final_actions = None;
        let mut tool_results = Vec::new();
        // Index of the oldest rejected assistant response not yet superseded by a valid one.
        // Everything from there up to the current response is dropped once the model gets it
        // right, so a correction round-trip does not stay in the prompt for the rest of the
        // conversation.
        let mut rejected_block_start: Option<(usize, u64)> = None;
        let mut consecutive_tool_failures = 0;
        let mut unknown_action_retries = 0;
        let mut malformed_action_retries = 0;
        const MAX_CONSECUTIVE_FAILURES: usize = 2;
        const MAX_UNKNOWN_ACTION_RETRIES: usize = 2;
        const MAX_MALFORMED_ACTION_RETRIES: usize = 2;

        // Build set of valid action names for validation (mutable to allow updates after docs read)
        let mut valid_action_names: std::collections::HashSet<String> =
            available_actions.iter().map(|a| a.name.clone()).collect();
        let mut valid_action_names_list: Vec<String> =
            available_actions.iter().map(|a| a.name.clone()).collect();
        // History can retain a credential after the currently offered actions are narrowed.
        self.private_payloads |= crate::utils::redact::actions_have_credentials(&available_actions);
        self.offered_actions = available_actions.clone();

        for iteration in 1..=self.max_tool_iterations {
            debug!(
                "Conversation iteration {}/{}",
                iteration, self.max_tool_iterations
            );

            // Generate response from LLM
            let (original_response, cleaned_response) = self
                .generate_with_retry()
                .await
                .context("✗  LLM failed to generate valid response after retries.")?;

            // Add assistant's response to conversation history (with reasoning preserved)
            let assistant_idx = self.messages.len();
            self.messages
                .push(Message::assistant(original_response.clone()));

            // Extract XML references from response (scripts, configs, large content)
            let (json_only, references) =
                crate::llm::reference_parser::extract_references(&cleaned_response)
                    .context("Failed to extract XML references from response")?;

            if !references.is_empty() && !self.private_payloads {
                debug!(
                    "Extracted {} XML references from LLM response",
                    references.len()
                );
                for (tag_name, content) in &references {
                    trace!("  Reference <{}>: {} chars", tag_name, content.len());
                }
            }

            // Parse as action response (using JSON-only portion)
            let action_response = ActionResponse::from_str(&json_only)
                .context("Failed to parse action response (should not happen after retry)")?;

            // Resolve references in both tools and actions (replace <tagname> placeholders with actual content)
            let resolve_refs = |item: serde_json::Value| {
                let mut resolved_item = item;
                // Convert to JSON string, resolve references, parse back
                if let Ok(item_json) = serde_json::to_string(&resolved_item) {
                    if crate::llm::reference_parser::contains_references(&item_json) {
                        let resolved_json = crate::llm::reference_parser::resolve_references(
                            &item_json,
                            &references,
                        );
                        if let Ok(new_item) = serde_json::from_str(&resolved_json) {
                            resolved_item = new_item;
                        }
                    }
                }
                resolved_item
            };

            let tools_with_refs: Vec<_> = action_response
                .tools
                .into_iter()
                .map(&resolve_refs)
                .collect();

            let actions_with_refs: Vec<_> = action_response
                .actions
                .into_iter()
                .map(&resolve_refs)
                .collect();

            // Create new action response with resolved references
            let action_response = ActionResponse {
                tools: tools_with_refs,
                actions: actions_with_refs,
            };

            // Validate action names against available actions
            let unknown_actions: Vec<String> = action_response
                .actions
                .iter()
                .chain(action_response.tools.iter())
                .filter_map(|action| {
                    let Some(action_type) = action.get("type").and_then(|v| v.as_str()) else {
                        return Some("(missing or non-string action type)".to_string());
                    };
                    // Check if action exists in valid actions
                    if !valid_action_names.contains(action_type) {
                        Some(action_type.to_string())
                    } else {
                        None
                    }
                })
                .collect();

            if !unknown_actions.is_empty() {
                unknown_action_retries += 1;
                let shown_unknown_actions = if self.private_payloads {
                    vec![crate::utils::redact::REDACTED.to_string(); unknown_actions.len()]
                } else {
                    unknown_actions.clone()
                };

                // Log warning with the actual response
                warn!(
                    "LLM returned unknown action(s): {:?}. Response was: {}",
                    shown_unknown_actions,
                    self.display_payload(&crate::utils::truncate_for_log(&cleaned_response, 500))
                );

                if let Some(ref tx) = self.status_tx {
                    let _ = tx.send(format!(
                        "[WARN] LLM returned unknown action(s): {:?}",
                        shown_unknown_actions
                    ));
                }

                if unknown_action_retries >= MAX_UNKNOWN_ACTION_RETRIES {
                    // All retries exhausted - log error
                    error!(
                        "LLM failed to use valid actions after {} retries. Unknown actions: {:?}",
                        unknown_action_retries, shown_unknown_actions
                    );
                    if let Some(ref tx) = self.status_tx {
                        let _ = tx.send(format!(
                            "[ERROR] LLM failed to use valid actions after {} retries",
                            unknown_action_retries
                        ));
                    }
                    // Return error instead of silently continuing
                    anyhow::bail!(
                        "LLM returned unknown action(s) after {} retries: {:?}",
                        unknown_action_retries,
                        shown_unknown_actions
                    );
                }

                // Build retry prompt for unknown actions
                let correction =
                    crate::llm::prompt::PromptBuilder::build_unknown_action_retry_prompt(
                        &unknown_actions,
                        &valid_action_names_list,
                    );

                // Log the correction before adding to messages
                trace!(
                    "→ Sending unknown action correction and retrying (attempt {})...",
                    unknown_action_retries + 1
                );
                if let Some(ref tx) = self.status_tx {
                    let _ = tx.send(
                        "[TRACE] → Sending correction to LLM for unknown action...".to_string(),
                    );
                    // Show the correction message being sent (indented and dimmed)
                    for line in crate::llm::format_indented_dimmed_lines(
                        &self.display_payload(&correction),
                        8,
                    ) {
                        let _ = tx.send(format!("[TRACE] {}", line));
                    }
                }

                // The rejected response is already in `messages` (pushed above); pushing it a
                // second time only made the model read its own mistake twice.
                rejected_block_start.get_or_insert((assistant_idx, self.trim_generation));

                // Add correction as user message
                self.messages.push(Message::user(correction));

                // Continue to next iteration to retry
                continue;
            }

            // Get tool calls and regular actions from separate fields
            // Note: action_response.tools and action_response.actions are already separated
            // by the parsing logic (with backward compatibility for old format)
            let tools = action_response.tools;
            let regular = action_response.actions;

            // Validate regular actions by trying to parse them as CommonAction
            // This catches missing required parameters before execution
            let mut malformed_actions: Vec<(serde_json::Value, String)> = Vec::new();
            let mut valid_regular: Vec<serde_json::Value> = Vec::new();

            for action in regular {
                let action_type = action
                    .get("type")
                    .and_then(|t| t.as_str())
                    .unwrap_or("unknown");

                // Every CommonAction variant is checked here, so a malformed one gets the retry
                // instead of failing silently in the executor. Protocol-specific actions are
                // validated later by their own executors.
                let is_common_action = matches!(
                    action_type,
                    "open_server"
                        | "open_client"
                        | "close_server"
                        | "close_client"
                        | "close_all_servers"
                        | "close_all_clients"
                        | "update_instruction"
                        | "change_model"
                        | "set_memory"
                        | "append_memory"
                        | "append_to_log"
                        | "provide_feedback"
                        | "update_server"
                        | "update_client"
                        | "create_database"
                        | "delete_database"
                        | "schedule_task"
                        | "cancel_task"
                        | "show_message"
                        | "close_connection_by_id"
                        | "reconnect_client"
                        | "update_client_instruction"
                );

                if is_common_action {
                    // Try to parse as CommonAction to validate
                    match crate::llm::actions::common::CommonAction::from_json(&action) {
                        Ok(_) => valid_regular.push(action),
                        Err(e) => {
                            let error = if self.private_payloads {
                                "invalid credential-bearing action".into()
                            } else {
                                e.to_string()
                            };
                            malformed_actions.push((action, error));
                        }
                    }
                } else {
                    // Non-common actions pass through without validation here
                    valid_regular.push(action);
                }
            }

            // If we have malformed actions, trigger retry
            if !malformed_actions.is_empty() {
                malformed_action_retries += 1;

                // Log error with the actual malformed actions
                for (action_json, error) in &malformed_actions {
                    error!(
                        "LLM returned malformed action: {}. Error: {}. JSON: {}",
                        action_json
                            .get("type")
                            .and_then(|t| t.as_str())
                            .unwrap_or("unknown"),
                        error,
                        self.display_payload(
                            &serde_json::to_string(action_json)
                                .unwrap_or_else(|_| action_json.to_string())
                        )
                    );
                }

                if let Some(ref tx) = self.status_tx {
                    for (action_json, error) in &malformed_actions {
                        let action_type = action_json
                            .get("type")
                            .and_then(|t| t.as_str())
                            .unwrap_or("unknown");
                        let _ = tx.send(format!(
                            "[ERROR] Malformed action '{}': {}",
                            action_type, error
                        ));
                        // Show the actual JSON that was returned
                        let _ = tx.send(format!(
                            "[ERROR]   JSON: {}",
                            self.display_payload(
                                &serde_json::to_string(action_json)
                                    .unwrap_or_else(|_| action_json.to_string())
                            )
                        ));
                    }
                }

                if malformed_action_retries >= MAX_MALFORMED_ACTION_RETRIES {
                    // All retries exhausted - return error
                    let action_types: Vec<_> = malformed_actions
                        .iter()
                        .map(|(a, _)| a.get("type").and_then(|t| t.as_str()).unwrap_or("unknown"))
                        .collect();
                    error!(
                        "LLM failed to provide valid actions after {} retries. Malformed: {:?}",
                        malformed_action_retries, action_types
                    );
                    if let Some(ref tx) = self.status_tx {
                        let _ = tx.send(format!(
                            "[ERROR] LLM failed to provide valid actions after {} retries",
                            malformed_action_retries
                        ));
                    }
                    anyhow::bail!(
                        "LLM returned malformed action(s) after {} retries: {:?}",
                        malformed_action_retries,
                        action_types
                    );
                }

                // Build retry prompt for malformed actions
                let correction =
                    crate::llm::prompt::PromptBuilder::build_malformed_action_retry_prompt(
                        &malformed_actions,
                    );

                trace!(
                    "→ Sending malformed action correction and retrying (attempt {})...",
                    malformed_action_retries + 1
                );
                if let Some(ref tx) = self.status_tx {
                    let _ = tx.send(format!(
                        "[INFO] → Retrying due to malformed action(s) (attempt {}/{})...",
                        malformed_action_retries, MAX_MALFORMED_ACTION_RETRIES
                    ));
                }

                // The rejected response is already in `messages` (pushed above); pushing it a
                // second time only made the model read its own mistake twice.
                rejected_block_start.get_or_insert((assistant_idx, self.trim_generation));

                // Add correction as user message
                self.messages.push(Message::user(correction));

                // Continue to next iteration to retry
                continue;
            }

            // This response passed validation, so the rejected ones before it are superseded:
            // drop them and their corrections instead of re-sending them every iteration.
            if let Some((start, generation)) = rejected_block_start.take() {
                // A trim between the rejection and now would have shifted every index.
                if generation == self.trim_generation
                    && assistant_idx > start
                    && assistant_idx <= self.messages.len()
                {
                    let dropped = assistant_idx - start;
                    self.messages.drain(start..assistant_idx);
                    self.last_logged_index = self.last_logged_index.min(self.messages.len());
                    debug!(
                        "Dropped {} superseded message(s) from rejected action attempt(s)",
                        dropped
                    );
                }
            }

            // An action may not reference a tool result it has not been given yet.
            //
            // A model that emits a tool call and, in the *same* response, an action
            // whose parameter is `{{tools[0].result}}` is describing a substitution
            // nothing here performs: `reference_parser` resolves `<tagname>` XML
            // references, not `{{...}}`, so the placeholder survives verbatim. Without
            // this check the action was collected below, the tools ran, and the literal
            // string `{{tools[0].result}}` went out on the wire as if it were the value
            // — a BitTorrent `send_piece` whose block_hex is that text, a session token
            // that is that text. Silently wrong in the worst way: the action looked
            // well-formed at every layer that inspected it.
            //
            // The recovery is the one the model expects anyway: run the tools, hand it
            // the results, and let it re-emit the action with the real value. Nothing is
            // collected from this response, so the placeholder never reaches execution.
            let (deferred, ready): (Vec<_>, Vec<_>) = valid_regular
                .into_iter()
                .partition(|action| action_references_tool_result(action));

            if !deferred.is_empty() {
                let names: Vec<&str> = deferred
                    .iter()
                    .filter_map(|a| a.get("type").and_then(|t| t.as_str()))
                    .collect();
                // Dual-logged through the facade rather than a hand-written level
                // prefix; `tests/llm_log_prefix_guard_test.rs` fails the build on any
                // new one of those in src/llm/. (That guard counts substrings without
                // parsing, so even naming the pattern in a comment trips it.)
                Log::new(self.status_tx.as_ref())
                    .with_payloads(!self.private_payloads)
                    .warn(format!(
                        "LLM action(s) {:?} reference a tool result that has not been produced \
                     yet; holding them back until the tool(s) have run",
                        names
                    ));

                if tools.is_empty() {
                    // No tool call to wait for: the placeholder can never be filled in,
                    // so this is simply a malformed action. Ask for a literal value.
                    self.messages.push(Message::user(format!(
                        "The action(s) {:?} contain a placeholder like \
                         \"{{{{tools[0].result}}}}\". Placeholders are never substituted: \
                         whatever you write is used literally. You did not call any tool \
                         in that response either. Re-send the action with the actual \
                         value written out in full.",
                        names
                    )));
                    rejected_block_start.get_or_insert((assistant_idx, self.trim_generation));
                    continue;
                }

                // Tools are pending; they run below and their results are appended as a
                // user message, after which the model re-emits the action for real.
                self.messages.push(Message::user(format!(
                    "Hold on: the action(s) {:?} referenced a tool result with a \
                     placeholder, but placeholders are never substituted — whatever you \
                     write is sent literally. Your tool call(s) are running now. Wait for \
                     the results below, then re-send those action(s) with the actual \
                     values written out in full.",
                    names
                )));
            }

            // Only a final response commits actions. An intermediate tool round can
            // contain a draft answer, which the next response may repeat or replace.
            // Keeping it would execute both drafts (for example, two IMAP greetings).
            if tools.is_empty() {
                final_actions = Some(ready);
                debug!("No tool calls in response, finishing conversation");
                break;
            }

            if !ready.is_empty() {
                self.messages.push(Message::user(
                    "Actions in a response with tool calls are drafts and have not been executed. \
                     After reading the tool results, return all actions to execute in one \
                     final response with no tool calls."
                        .to_string(),
                ));
            }

            // If this is the last iteration, warn about unused tool calls
            if iteration == self.max_tool_iterations {
                warn!(
                    "Maximum iterations reached with {} pending tool calls",
                    tools.len()
                );
                if let Some(ref tx) = self.status_tx {
                    let _ = tx.send(format!(
                        "[WARN] Maximum iterations ({}) reached with {} pending tool call(s)",
                        self.max_tool_iterations,
                        tools.len()
                    ));
                }
                anyhow::bail!("Tool iteration limit reached before a final action response");
            }

            // Execute tool calls
            debug!("Executing {} tool calls", tools.len());
            if let Some(ref tx) = self.status_tx {
                let _ = tx.send(format!("[INFO] Executing {} tool call(s)...", tools.len()));
            }
            tool_results.clear();

            for tool_json in tools {
                match ToolAction::from_json(&tool_json) {
                    Ok(tool_action) => {
                        info!(
                            "→ Executing tool: {}",
                            self.display_payload(&tool_action.describe())
                        );
                        if let Some(ref tx) = self.status_tx {
                            let _ = tx.send(format!(
                                "[INFO] → Executing tool: {}",
                                self.display_payload(&tool_action.describe())
                            ));
                        }

                        // Track tool call in conversation state
                        if let Ok(mut state) = self.conversation_state.lock() {
                            let tool_name = match &tool_action {
                                ToolAction::ReadFile { .. } => "read_file",
                                ToolAction::WebSearch { .. } => "web_search",
                                ToolAction::ReadBaseStackDocs { .. } => "read_base_stack_docs",
                                ToolAction::ReadServerDocumentation { .. } => {
                                    "read_server_documentation"
                                }
                                ToolAction::ReadClientDocumentation { .. } => {
                                    "read_client_documentation"
                                }
                                ToolAction::ReadDocumentation { .. } => "read_documentation",
                                ToolAction::ListModels => "list_models",
                                ToolAction::GenerateRandom { .. } => "generate_random",
                                ToolAction::ListTasks => "list_tasks",
                                #[cfg(feature = "sqlite")]
                                ToolAction::ExecuteSql { .. } => "execute_sql",
                                #[cfg(feature = "sqlite")]
                                ToolAction::ListDatabases => "list_databases",
                            };
                            state.add_tool_call(
                                tool_name.to_string(),
                                self.display_payload(&tool_action.describe()),
                            );
                        }

                        // Check if this is a doc reading tool
                        let is_read_server_docs =
                            matches!(tool_action, ToolAction::ReadServerDocumentation { .. });
                        let is_read_client_docs =
                            matches!(tool_action, ToolAction::ReadClientDocumentation { .. });
                        let is_read_base_docs =
                            matches!(tool_action, ToolAction::ReadBaseStackDocs { .. });
                        let is_read_docs =
                            matches!(tool_action, ToolAction::ReadDocumentation { .. });

                        let execution =
                            execute_tool(&tool_action, approval_tx.as_ref(), web_search_mode, None);
                        let result = if self.private_payloads {
                            use tracing::instrument::WithSubscriber;
                            execution
                                .with_subscriber(tracing::subscriber::NoSubscriber::default())
                                .await
                        } else {
                            execution.await
                        };
                        info!("  Result: {}", self.display_payload(&result.summary()));
                        if let Some(ref tx) = self.status_tx {
                            let status = if result.success { "✓" } else { "✗" };
                            let _ = tx.send(format!(
                                "[INFO]   {} {}",
                                status,
                                self.display_payload(&result.summary())
                            ));
                        }

                        // Mark protocol docs as read if the tool succeeded
                        // This will update the system prompt to enable open_server/open_client actions
                        if result.success {
                            if is_read_server_docs {
                                self.mark_protocol_docs_read(&available_actions);
                                // Extract protocols and update AppState and ConversationState
                                if let ToolAction::ReadServerDocumentation {
                                    protocols,
                                    protocol,
                                } = &tool_action
                                {
                                    let mut all_protocols = protocols.clone();
                                    if let Some(p) = protocol {
                                        if !all_protocols.contains(p) {
                                            all_protocols.push(p.clone());
                                        }
                                    }
                                    // Update ConversationState to persist documented protocols
                                    if let Ok(mut conv_state) = self.conversation_state.lock() {
                                        conv_state.mark_server_protocols_documented(&all_protocols);
                                    }
                                    // Update AppState (global persistence)
                                    if let Some(ref state) = self.state {
                                        let state_clone = state.clone();
                                        let protocols_clone = all_protocols.clone();
                                        tokio::spawn(async move {
                                            state_clone
                                                .mark_server_protocols_documented(&protocols_clone)
                                                .await;
                                        });
                                    }
                                }
                                // Enable open_server in valid actions
                                if !valid_action_names.contains("open_server") {
                                    valid_action_names.insert("open_server".to_string());
                                    valid_action_names_list.push("open_server".to_string());
                                }
                            }
                            if is_read_client_docs {
                                self.mark_protocol_docs_read(&available_actions);
                                // Extract protocols and update AppState and ConversationState
                                if let ToolAction::ReadClientDocumentation {
                                    protocols,
                                    protocol,
                                } = &tool_action
                                {
                                    let mut all_protocols = protocols.clone();
                                    if let Some(p) = protocol {
                                        if !all_protocols.contains(p) {
                                            all_protocols.push(p.clone());
                                        }
                                    }
                                    // Update ConversationState to persist documented protocols
                                    if let Ok(mut conv_state) = self.conversation_state.lock() {
                                        conv_state.mark_client_protocols_documented(&all_protocols);
                                    }
                                    // Update AppState (global persistence)
                                    if let Some(ref state) = self.state {
                                        let state_clone = state.clone();
                                        let protocols_clone = all_protocols.clone();
                                        tokio::spawn(async move {
                                            state_clone
                                                .mark_client_protocols_documented(&protocols_clone)
                                                .await;
                                        });
                                    }
                                }
                                // Enable open_client in valid actions
                                if !valid_action_names.contains("open_client") {
                                    valid_action_names.insert("open_client".to_string());
                                    valid_action_names_list.push("open_client".to_string());
                                }
                            }
                            if is_read_base_docs {
                                self.mark_protocol_docs_read(&available_actions);
                                // Enable both open_server and open_client in valid actions
                                if !valid_action_names.contains("open_server") {
                                    valid_action_names.insert("open_server".to_string());
                                    valid_action_names_list.push("open_server".to_string());
                                }
                                if !valid_action_names.contains("open_client") {
                                    valid_action_names.insert("open_client".to_string());
                                    valid_action_names_list.push("open_client".to_string());
                                }
                            }
                            // Handle unified read_documentation tool
                            if is_read_docs {
                                self.mark_protocol_docs_read(&available_actions);
                                // Extract protocols and update both server and client state
                                if let ToolAction::ReadDocumentation {
                                    protocols,
                                    protocol,
                                } = &tool_action
                                {
                                    let mut all_protocols = protocols.clone();
                                    if let Some(p) = protocol {
                                        if !all_protocols.contains(p) {
                                            all_protocols.push(p.clone());
                                        }
                                    }
                                    // Update ConversationState to persist documented protocols (both server and client)
                                    if let Ok(mut conv_state) = self.conversation_state.lock() {
                                        conv_state.mark_server_protocols_documented(&all_protocols);
                                        conv_state.mark_client_protocols_documented(&all_protocols);
                                    }
                                    // Update AppState (global persistence for both server and client)
                                    if let Some(ref state) = self.state {
                                        let state_clone = state.clone();
                                        let protocols_clone = all_protocols.clone();
                                        tokio::spawn(async move {
                                            state_clone
                                                .mark_server_protocols_documented(&protocols_clone)
                                                .await;
                                            state_clone
                                                .mark_client_protocols_documented(&protocols_clone)
                                                .await;
                                        });
                                    }
                                }
                                // CRITICAL: Enable open_server and open_client in valid actions
                                // so the LLM can use them in subsequent iterations
                                if !valid_action_names.contains("open_server") {
                                    valid_action_names.insert("open_server".to_string());
                                    valid_action_names_list.push("open_server".to_string());
                                    debug!(
                                        "Enabled open_server action after reading documentation"
                                    );
                                }
                                if !valid_action_names.contains("open_client") {
                                    valid_action_names.insert("open_client".to_string());
                                    valid_action_names_list.push("open_client".to_string());
                                    debug!(
                                        "Enabled open_client action after reading documentation"
                                    );
                                }
                            }
                        }

                        tool_results.push(result);
                    }
                    Err(e) => {
                        let error = if self.private_payloads {
                            "invalid credential-bearing tool action".to_string()
                        } else {
                            e.to_string()
                        };
                        error!("Failed to parse tool action: {}", error);
                        if let Some(ref tx) = self.status_tx {
                            let _ =
                                tx.send(format!("[ERROR] Failed to parse tool action: {}", error));
                        }
                        tool_results.push(ToolResult::error(
                            "unknown",
                            "parse_error",
                            format!("Failed to parse tool action: {}", error),
                        ));
                    }
                }
            }

            // Check if all tools failed
            let all_failed = !tool_results.is_empty() && tool_results.iter().all(|r| !r.success);
            if all_failed {
                consecutive_tool_failures += 1;
                warn!(
                    "All {} tool calls failed (consecutive failures: {})",
                    tool_results.len(),
                    consecutive_tool_failures
                );
                if let Some(ref tx) = self.status_tx {
                    let _ = tx.send(format!(
                        "[WARN] All {} tool calls failed (consecutive failures: {})",
                        tool_results.len(),
                        consecutive_tool_failures
                    ));
                }

                if consecutive_tool_failures >= MAX_CONSECUTIVE_FAILURES {
                    error!(
                        "Breaking tool calling loop after {} consecutive failures",
                        consecutive_tool_failures
                    );
                    if let Some(ref tx) = self.status_tx {
                        let _ = tx.send(format!(
                            "[ERROR] Breaking tool loop after {} consecutive failures",
                            consecutive_tool_failures
                        ));
                    }
                    // Add a final message explaining the issue
                    self.messages.push(Message::user(
                        "CRITICAL: All tool calls are failing. Stop calling tools and respond with regular actions instead.".to_string()
                    ));
                    break;
                }
            } else {
                // Reset counter if at least one tool succeeded
                consecutive_tool_failures = 0;
            }

            // Add tool results as a user message for the next iteration
            if !tool_results.is_empty() {
                let tool_results_text = self.format_tool_results(&tool_results);
                self.messages.push(Message::user(tool_results_text));
            }

            debug!(
                "Completed iteration {}/{}, {} tool results provided for next iteration",
                iteration,
                self.max_tool_iterations,
                tool_results.len()
            );
            if let Some(ref tx) = self.status_tx {
                let _ = tx.send(format!(
                    "[TRACE] Iteration {}/{} complete, continuing with {} tool result(s)...",
                    iteration,
                    self.max_tool_iterations,
                    tool_results.len()
                ));
            }
        }

        let all_actions = final_actions.context(
            "Conversation ended without a final action response; no draft actions executed",
        )?;

        // Log details for each action (validation already happened above)
        for action in &all_actions {
            let action_type = action
                .get("type")
                .and_then(|t| t.as_str())
                .unwrap_or("unknown");

            // Build action details string based on action type
            let details = match action_type {
                "open_server" => {
                    let port = action.get("port").and_then(|p| p.as_u64());
                    let base_stack = action.get("base_stack").and_then(|b| b.as_str());
                    format!(
                        "port={}, base_stack={}",
                        port.map(|p| p.to_string())
                            .unwrap_or_else(|| "auto".to_string()),
                        base_stack.unwrap_or("?")
                    )
                }
                "open_client" => {
                    let protocol = action.get("protocol").and_then(|p| p.as_str());
                    let remote_addr = action.get("remote_addr").and_then(|r| r.as_str());
                    format!(
                        "protocol={}, remote_addr={}",
                        protocol.unwrap_or("?"),
                        remote_addr.unwrap_or("?")
                    )
                }
                "close_server" => {
                    let server_id = action.get("server_id").and_then(|p| p.as_u64());
                    format!(
                        "server_id={}",
                        server_id
                            .map(|p| p.to_string())
                            .unwrap_or_else(|| "?".to_string())
                    )
                }
                "update_instruction" => {
                    let instruction = action.get("instruction").and_then(|i| i.as_str());
                    format!(
                        "instruction={}",
                        instruction
                            .map(|i| {
                                let preview: String = i.chars().take(30).collect();
                                if i.len() > 30 {
                                    format!("\"{}...\"", preview)
                                } else {
                                    format!("\"{}\"", i)
                                }
                            })
                            .unwrap_or_else(|| "?".to_string())
                    )
                }
                "show_message" => {
                    let message = action.get("message").and_then(|m| m.as_str()).unwrap_or("");
                    let preview: String = message.chars().take(50).collect();
                    if message.len() > 50 {
                        format!("\"{}...\"", preview)
                    } else {
                        format!("\"{}\"", preview)
                    }
                }
                _ => {
                    // For other actions, show first few keys
                    let keys: Vec<&str> = action
                        .as_object()
                        .map(|obj| {
                            obj.keys()
                                .filter(|k| *k != "type")
                                .take(3)
                                .map(|s| s.as_str())
                                .collect()
                        })
                        .unwrap_or_default();
                    if keys.is_empty() {
                        String::new()
                    } else {
                        format!("keys=[{}]", keys.join(", "))
                    }
                }
            };

            let details = self.display_payload(&details);
            let log_msg = if details.is_empty() {
                format!("[INFO]   → {}", action_type)
            } else {
                format!("[INFO]   → {} ({})", action_type, details)
            };

            info!("Action: {} {}", action_type, details);
            if let Some(ref tx) = self.status_tx {
                let _ = tx.send(log_msg);
            }
        }

        info!(
            "Conversation complete: {} total actions collected",
            all_actions.len()
        );
        if let Some(ref tx) = self.status_tx {
            let _ = tx.send(format!(
                "[INFO] ✓ Conversation complete: {} action(s)",
                all_actions.len()
            ));
        }

        // End conversation tracking if enabled
        if let Some(state) = &self.state {
            state.end_conversation(&self.conversation_id).await;
        }

        Ok(all_actions)
    }

    /// Generate a response with automatic retry on parse errors
    ///
    /// Attempts to get a valid ActionResponse from the LLM. If parsing fails,
    /// sends a corrective message and retries once.
    ///
    /// Returns (original_response, cleaned_response):
    /// - original_response: Response with reasoning tags (for conversation history)
    /// - cleaned_response: Response with reasoning stripped (for JSON parsing)
    async fn generate_with_retry(&mut self) -> Result<(String, String)> {
        // Where this call's messages start. A parse failure appends the unparseable response
        // and a correction; once a valid response supersedes them they are pure noise that
        // would otherwise be re-sent for the rest of the conversation, so they are dropped.
        let attempt_block_start = self.messages.len();
        let attempt_block_generation = self.trim_generation;

        for attempt in 1..=self.max_retries + 1 {
            // Bound what is actually sent before building the request.
            self.trim_history();

            // ONE semantic line per request attempt, to BOTH channels. The transport
            // (OllamaClient) separately logs the wire facts (model, sizes) file-only, so
            // the round-trip is no longer announced twice per layer to each channel.
            self.log().info(format!(
                "LLM request (attempt {}/{})",
                attempt,
                self.max_retries + 1
            ));

            // Message-count summary and the per-message payload dump are DEBUG/TRACE:
            // file-only, never streamed to the unbounded TUI channel.
            let new_message_count = self.messages.len().saturating_sub(self.last_logged_index);
            self.log().debug(format!(
                "Conversation state: {} messages, {} new since last call",
                self.messages.len(),
                new_message_count
            ));

            if new_message_count > 0 {
                let log = self.log();
                log.trace("New messages:");
                for (idx, msg) in self
                    .messages
                    .iter()
                    .enumerate()
                    .skip(self.last_logged_index)
                {
                    log.trace(format!(
                        "  Message {}: [{}] {}",
                        idx + 1,
                        msg.role,
                        crate::utils::truncate_for_log(&msg.content, 200)
                    ));
                }
            }

            // Update the last logged index (track what's been sent, don't re-log)
            self.last_logged_index = self.messages.len();

            // Acquire rate limiter permit (waits for user requests, discards network requests if limited)
            let permit = self
                .rate_limiter
                .acquire_permit(self.request_source)
                .await
                .context("Rate limit exceeded")?;

            // Choose between native tool calling (chat API) and prompt-based (generate API)
            let response_text = if self.use_native_tools {
                // Native tool calling path: send structured messages with tool schemas
                let chat_request = ChatRequest {
                    messages: self.messages.clone(),
                    tools: self.tool_schemas.clone(),
                    model: self.model.clone(),
                    offered_actions: self.offered_actions.clone(),
                };

                let chat_response = self
                    .client
                    .chat_with_tools(&chat_request, self.private_payloads)
                    .await
                    .context("Chat API call failed")?;

                // Record token usage
                permit
                    .record_usage(
                        chat_response.token_usage.prompt_tokens,
                        chat_response.token_usage.completion_tokens,
                    )
                    .await;

                // Convert native tool_calls to ActionResponse text format
                // so the existing parsing/validation pipeline works unchanged
                if !chat_response.tool_calls.is_empty() {
                    debug!(
                        "Native tool calling: {} tool_calls received",
                        chat_response.tool_calls.len()
                    );
                    Self::chat_response_to_action_text(&chat_response)
                } else if let Some(ref content) = chat_response.content {
                    // No tool calls, just text - try to use it as-is
                    // (may be JSON actions from prompt-based models that ignore tools param)
                    content.clone()
                } else {
                    // Empty response
                    "{}".to_string()
                }
            } else {
                // Call generate API with concatenated prompt
                // We rely on prompt engineering for JSON responses rather than format enforcement,
                // as some models (e.g., gpt-oss) don't support Ollama's JSON format mode
                let generate_response = if self.client.backend_type() == "agent" {
                    self.client
                        .generate_agent_request(
                            &self.model,
                            self.messages.clone(),
                            &self.offered_actions,
                            self.agent_context.clone(),
                        )
                        .await
                } else {
                    // Prompt-based fallback: concatenate messages into single prompt
                    let mut full_prompt = String::new();
                    for msg in &self.messages {
                        match msg.role.as_str() {
                            "system" => {
                                full_prompt.push_str(&msg.content);
                                full_prompt.push_str("\n\n");
                            }
                            "user" => {
                                full_prompt.push_str(&msg.content);
                                full_prompt.push_str("\n\n");
                            }
                            "assistant" => {
                                // Neutral on purpose. On a network event the earlier turns are replies
                                // that were rejected — nothing in them ran — and the old "Actions you
                                // have executed" told the model its rejected action had already gone
                                // out, contradicting the retry message that follows. Where tools are
                                // offered an earlier turn may have run tools, so "rejected" would be
                                // just as wrong; the message after each turn says which it was.
                                full_prompt.push_str("Your previous response:\n");
                                full_prompt.push_str(&msg.content);
                                full_prompt.push_str("\n\n");
                            }
                            _ => {}
                        }
                    }

                    self.client
                        .generate_offering_with_event(
                            &self.model,
                            &full_prompt,
                            None,
                            &self.offered_actions,
                            self.bridge_event.as_ref(),
                            self.private_payloads,
                        )
                        .await
                }
                .context("Generate API call failed")?;

                // Record token usage
                permit
                    .record_usage(
                        generate_response.token_usage.prompt_tokens,
                        generate_response.token_usage.completion_tokens,
                    )
                    .await;

                generate_response.text
            };

            // ONE semantic line that a response arrived, to BOTH channels (the result
            // half of the round-trip). The transport already logged response size/tokens
            // file-only, and the full body goes to the file at TRACE below — it is never
            // streamed to the TUI.
            self.log().info(format!(
                "LLM response received (attempt {}): {} chars",
                attempt,
                response_text.len(),
            ));

            // Extract reasoning if present (before normalization to preserve formatting)
            let (reasoning, cleaned_response) = extract_reasoning(&response_text);

            // Reasoning is a full payload: TRACE, file-only.
            if let Some(ref reasoning_text) = reasoning {
                self.log()
                    .trace(format!("LLM Reasoning: {}", reasoning_text));
            }

            // Normalize the cleaned response: collapse whitespace and remove extra newlines
            // This handles cases where LLM returns formatted JSON with lots of whitespace
            let normalized_response = cleaned_response
                .lines()
                .map(|line| line.trim())
                .collect::<Vec<_>>()
                .join("");

            // Normalized-response preview is a DEBUG summary and the full body a TRACE
            // payload — both file-only. The full normalized body used to be pushed to the
            // TUI here, duplicating the transport's own body dump; that is removed.
            let log = self.log();
            log.debug(format!(
                "Response (normalized): {}",
                crate::utils::truncate_for_log(&normalized_response, 200)
            ));
            log.payload(
                "LLM response (normalized)",
                &normalized_response,
                usize::MAX,
            );

            // Try to parse as ActionResponse (use normalized version for better compatibility)
            match ActionResponse::from_str(&normalized_response) {
                Ok(action_response) => {
                    // Valid response!
                    // Track in conversation state
                    if let Ok(mut state) = self.conversation_state.lock() {
                        state.add_llm_response(
                            normalized_response.clone(),
                            Some(serde_json::json!(action_response)),
                        );
                    }

                    if attempt > 1 {
                        info!(
                            "✓ Retry successful! LLM provided valid format on attempt {}",
                            attempt
                        );
                        if let Some(ref tx) = self.status_tx {
                            let _ = tx
                                .send(format!("[INFO] ✓ Retry successful on attempt {}", attempt));
                        }
                        // This response supersedes the failed attempts: drop them and their
                        // corrections rather than carrying them for the rest of the
                        // conversation. Nothing was appended on the success path, so the
                        // block is exactly what the failed attempts added.
                        if self.trim_generation == attempt_block_generation
                            && self.messages.len() > attempt_block_start
                        {
                            let dropped = self.messages.len() - attempt_block_start;
                            self.messages.truncate(attempt_block_start);
                            self.last_logged_index =
                                self.last_logged_index.min(self.messages.len());
                            debug!(
                                "Dropped {} superseded message(s) from {} failed parse attempt(s)",
                                dropped,
                                attempt - 1
                            );
                        }
                    } else {
                        info!("✓ Valid response format on first attempt");
                    }
                    // Return both original (with reasoning) and normalized (for parsing)
                    return Ok((response_text.clone(), normalized_response));
                }
                Err(e) => {
                    let e = if self.private_payloads {
                        anyhow::anyhow!("invalid credential-bearing model response")
                    } else {
                        e
                    };
                    if attempt <= self.max_retries {
                        // We have retries left, send corrective feedback
                        warn!("✗ Parse error on attempt {}: {}", attempt, e);
                        warn!(
                            "Malformed response (raw): {}",
                            if response_text.is_empty() {
                                "(empty response)".to_string()
                            } else {
                                self.display_payload(&crate::utils::truncate_for_log(
                                    &response_text,
                                    500,
                                ))
                            }
                        );

                        if let Some(ref tx) = self.status_tx {
                            let error_preview = if normalized_response.is_empty() {
                                "(empty)".to_string()
                            } else {
                                self.display_payload(&crate::utils::truncate_for_log(
                                    &normalized_response,
                                    100,
                                ))
                            };
                            let _ = tx.send(format!(
                                "[WARN] ✗ Invalid format (attempt {}): {}. Response: {}",
                                attempt, e, error_preview
                            ));
                        }

                        // Add the malformed response as an assistant message (use normalized for conversation)
                        self.messages
                            .push(Message::assistant(normalized_response.clone()));

                        // Track invalid response in conversation state
                        if let Ok(mut state) = self.conversation_state.lock() {
                            state.add_llm_response(normalized_response.clone(), None);
                        }

                        // Build corrective user message using minimal retry prompt
                        let correction =
                            crate::llm::prompt::PromptBuilder::build_retry_prompt(&e.to_string());
                        debug!(
                            "Correction message preview: {}",
                            crate::utils::truncate_for_log(&correction, 200)
                        );

                        // Track retry instruction in conversation state
                        if let Ok(mut state) = self.conversation_state.lock() {
                            state.add_retry_instruction(correction.clone());
                        }

                        info!(
                            "→ Sending correction and retrying (attempt {})...",
                            attempt + 1
                        );
                        if let Some(ref tx) = self.status_tx {
                            let _ = tx.send("[INFO] → Sending correction to LLM...".to_string());
                            // Show the correction message being sent (indented and dimmed)
                            for line in crate::llm::format_indented_dimmed_lines(
                                &self.display_payload(&correction),
                                8,
                            ) {
                                let _ = tx.send(format!("[INFO] {}", line));
                            }
                        }

                        self.messages.push(Message::user(correction));
                    } else {
                        // No more retries
                        error!("✗ Failed to get valid response after {} attempts", attempt);
                        if let Some(ref tx) = self.status_tx {
                            let _ = tx.send(format!(
                                "[ERROR] ✗ Failed after {} attempts: {}",
                                attempt, e
                            ));
                        }
                        return Err(e).context("LLM failed to provide valid format after retry");
                    }
                }
            }
        }

        unreachable!("Loop should always return or error")
    }

    /// Format tool results for inclusion in the next message
    fn format_tool_results(&self, results: &[ToolResult]) -> String {
        let mut formatted = String::from("Tool execution results:\n\n");

        for (i, result) in results.iter().enumerate() {
            formatted.push_str(&format!("{}. {}\n", i + 1, result.summary()));
            formatted.push_str(&format!(
                "Status: {}\n",
                if result.success { "Success" } else { "Error" }
            ));

            // Truncate very long results on a char boundary, telling the model
            // explicitly how much was omitted so it can narrow its next request.
            let result_text = &result.result;
            formatted.push_str(&format!(
                "Result: {}\n",
                crate::utils::truncate_with_notice(result_text, 2000)
            ));

            formatted.push('\n');
        }

        formatted
    }

    /// Get the current conversation messages (for debugging)
    pub fn messages(&self) -> &[Message] {
        &self.messages
    }

    /// Get the number of messages in the conversation
    pub fn message_count(&self) -> usize {
        self.messages.len()
    }

    /// Get the conversation ID
    pub fn conversation_id(&self) -> &str {
        &self.conversation_id
    }

    /// Mark this conversation as already registered (to prevent duplicate registration)
    pub fn mark_registered(&mut self) {
        self.registered = true;
    }

    /// Update the "Current State" section in the system message
    ///
    /// This is used after actions like `open_server` that modify application state.
    /// The system message is rebuilt with updated state so subsequent tool calls
    /// see the current state.
    ///
    /// # Arguments
    /// * `state` - Application state
    /// * `server_id` - Optional server context
    pub async fn update_current_state(
        &mut self,
        state: &crate::state::app_state::AppState,
        server_id: Option<crate::state::ServerId>,
    ) {
        use crate::llm::prompt::PromptBuilder;

        if self.messages.is_empty() {
            warn!("Cannot update current state: no system message found");
            return;
        }

        // Get the system message (first message)
        let system_msg = &self.messages[0];
        if system_msg.role != "system" {
            warn!("First message is not a system message, cannot update current state");
            return;
        }

        let old_content = &system_msg.content;

        // Find the "# Current State" section
        if let Some(state_start) = old_content.find("# Current State") {
            // Find the next section (starts with "# ")
            let state_content_start = state_start;
            let state_end = old_content[state_content_start..]
                .find("\n# ")
                .map(|pos| state_content_start + pos)
                .unwrap_or(old_content.len());

            // Build new current state section
            let new_state_section =
                PromptBuilder::build_current_state_section_public(state, server_id).await;

            // Replace the old state section with the new one
            let mut new_content = String::new();
            new_content.push_str(&old_content[..state_start]);
            new_content.push_str(&new_state_section);
            // Don't include the newline before next section, it's already in new_state_section
            if state_end < old_content.len() {
                new_content.push_str(&old_content[state_end..]);
            }

            // Update the system message
            self.messages[0] = Message::system(new_content);

            debug!("Updated Current State section in system message");
        } else {
            warn!("Could not find '# Current State' section in system message");
        }
    }
}

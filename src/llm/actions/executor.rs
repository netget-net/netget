//! Action executor
//!
//! This module executes arrays of actions returned by the LLM.
//! It handles both common actions and protocol-specific actions.

use super::{
    common::CommonAction,
    protocol_trait::{ActionResult, Server},
};
use crate::protocol::log_action_result;
use crate::state::app_state::AppState;
use anyhow::Result;
use tracing::{debug, error, warn};

/// Prefix used for the synthetic `type` of a failed action in the access log.
///
/// The access-log viewer (`list_access_logs`) summarises an entry by the `type` of each
/// recorded action, so the failure has to live in that field to be visible at a glance.
/// A successful `send_tcp_data` is recorded as `send_tcp_data`; a failed one as
/// `FAILED: send_tcp_data`.
pub const FAILED_ACTION_TYPE_PREFIX: &str = "FAILED: ";

/// Cap on a server's `memory` string.
///
/// Memory is injected verbatim into the "Current State" section of *every* prompt for that
/// server, so it is paid for on every LLM call for the life of the server. `append_memory`
/// had no bound at all: a protocol that appends a line per request grows the prompt without
/// limit until the model's context is exhausted and every call starts failing.
///
/// 8000 characters is roughly 2k tokens — the same order as the conversation-history window,
/// large enough for the running notes memory is meant to hold, and small enough that it
/// cannot dominate the prompt.
pub const MAX_SERVER_MEMORY_CHARS: usize = 8000;

/// Notice prefixed to memory that had to be trimmed, so the model is not left believing it
/// still remembers something that was dropped.
const MEMORY_TRIMMED_NOTICE: &str = "[older memory dropped: over the size limit]";

/// Bound a server's memory to [`MAX_SERVER_MEMORY_CHARS`], keeping the **newest** content.
///
/// Memory accumulates chronologically (`append_memory` joins with a newline), so the tail is
/// the recent state and the head is the stalest. Whole lines are dropped from the front, and
/// the result is marked so the model can tell that history was lost. A single line longer
/// than the cap is truncated char-safely rather than dropped entirely.
pub fn bound_server_memory(memory: String) -> String {
    if memory.len() <= MAX_SERVER_MEMORY_CHARS {
        return memory;
    }

    // Budget for the notice plus its newline.
    let budget = MAX_SERVER_MEMORY_CHARS.saturating_sub(MEMORY_TRIMMED_NOTICE.len() + 1);

    let mut kept: Vec<&str> = Vec::new();
    let mut size = 0usize;
    for line in memory.lines().rev() {
        // +1 for the newline that will rejoin this line.
        let cost = line.len() + 1;
        if size + cost > budget {
            break;
        }
        size += cost;
        kept.push(line);
    }
    kept.reverse();

    if kept.is_empty() {
        // One oversized line: keep its tail, which is the newest text.
        let start = memory.len().saturating_sub(budget);
        let start = memory
            .char_indices()
            .map(|(i, _)| i)
            .find(|i| *i >= start)
            .unwrap_or(memory.len());
        return format!("{}\n{}", MEMORY_TRIMMED_NOTICE, &memory[start..]);
    }

    format!("{}\n{}", MEMORY_TRIMMED_NOTICE, kept.join("\n"))
}

/// One action from a batch that could not be executed.
///
/// Recorded rather than discarded so the failure reaches the access log and the caller
/// instead of being visible only as "the peer got the protocol default".
#[derive(Clone, Debug, serde::Serialize)]
pub struct ActionFailure {
    /// Position of the action in the submitted batch (indexes `ExecutionResult::raw_actions`)
    pub index: usize,
    /// The action's `type` field, or `unknown` when it had none
    pub action: String,
    /// Why it failed, as reported by the protocol executor
    pub error: String,
}

/// Result of executing all actions
pub struct ExecutionResult {
    /// Messages to display to the user
    pub messages: Vec<String>,

    /// Protocol-specific action results
    pub protocol_results: Vec<ActionResult>,

    /// The action name that produced each entry of `protocol_results`, index for index.
    ///
    /// A protocol that owes exactly one reply per request uses it to pick *the* reply when a
    /// batch carries several (see [`ExecutionResult::chosen_reply`]).
    pub protocol_result_actions: Vec<String>,

    /// Raw action JSON (for protocols that need to manually process actions)
    /// This is used by protocols like mDNS and NFS that have special manual processing
    pub raw_actions: Vec<serde_json::Value>,

    /// Actions in this batch that failed to execute, in submission order.
    ///
    /// Empty on a fully successful batch. A non-empty list does **not** mean the batch
    /// was aborted: execution continues past a failed action (see `execute_actions`).
    pub failures: Vec<ActionFailure>,
}

impl Default for ExecutionResult {
    fn default() -> Self {
        Self::new()
    }
}

impl ExecutionResult {
    pub fn new() -> Self {
        Self {
            messages: Vec::new(),
            protocol_results: Vec::new(),
            protocol_result_actions: Vec::new(),
            raw_actions: Vec::new(),
            failures: Vec::new(),
        }
    }

    pub fn add_message(&mut self, message: String) {
        self.messages.push(message);
    }

    /// Append another result after this one, as if both had come from one call — what a
    /// batch that fell back to answering its events one by one hands its protocol.
    pub fn extend(&mut self, other: ExecutionResult) {
        self.messages.extend(other.messages);
        self.protocol_results.extend(other.protocol_results);
        self.protocol_result_actions
            .extend(other.protocol_result_actions);
        self.raw_actions.extend(other.raw_actions);
        self.failures.extend(other.failures);
    }

    pub fn add_protocol_result(&mut self, result: ActionResult) {
        self.add_named_protocol_result(String::new(), result);
    }

    /// Record a protocol result together with the name of the action that produced it.
    pub fn add_named_protocol_result(&mut self, action_name: String, result: ActionResult) {
        self.protocol_results.push(result);
        self.protocol_result_actions.push(action_name);
    }

    /// Which entry of `protocol_results` is *the* reply, for a protocol that owes exactly one
    /// per request: the first that writes bytes and was produced by an action in `preferred`,
    /// otherwise the first that writes bytes at all. `None` when nothing writes.
    ///
    /// Why not simply the first: a small model often answers with a generic acknowledgement
    /// and *then* the answer the request needed - `+OK` then the `STAT` line, measured in the
    /// real-model eval - and the specific answer is the one the client is waiting for.
    pub fn chosen_reply(&self, preferred: &[&str]) -> Option<usize> {
        let writes = |i: &usize| !self.protocol_results[*i].get_all_output().is_empty();
        (0..self.protocol_results.len())
            .filter(writes)
            .find(|i| {
                self.protocol_result_actions
                    .get(*i)
                    .is_some_and(|name| preferred.contains(&name.as_str()))
            })
            .or_else(|| (0..self.protocol_results.len()).find(writes))
    }

    /// Record an action that could not be executed.
    pub fn add_failure(
        &mut self,
        index: usize,
        action: impl Into<String>,
        error: impl Into<String>,
    ) {
        self.failures.push(ActionFailure {
            index,
            action: action.into(),
            error: error.into(),
        });
    }

    /// Whether any action in the batch failed.
    pub fn has_failures(&self) -> bool {
        !self.failures.is_empty()
    }

    /// One-line summary of the failures, or `None` if the batch was clean.
    pub fn failure_summary(&self) -> Option<String> {
        if self.failures.is_empty() {
            return None;
        }
        let parts: Vec<String> = self
            .failures
            .iter()
            .map(|f| format!("{} ({})", f.action, f.error))
            .collect();
        Some(parts.join("; "))
    }

    /// The action array to record in the access log.
    ///
    /// Successful actions are recorded verbatim. A failed action keeps its original JSON
    /// under `action` but is wrapped in an envelope whose `type` is
    /// `FAILED: <action name>` and which carries the executor's error, so
    /// `list_access_logs` cannot show a failed action as though it had run.
    pub fn access_log_actions(&self) -> Vec<serde_json::Value> {
        if self.failures.is_empty() {
            return self.raw_actions.clone();
        }
        let mut out = self.raw_actions.clone();
        for failure in &self.failures {
            let original = out
                .get(failure.index)
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            let envelope = serde_json::json!({
                "type": format!("{}{}", FAILED_ACTION_TYPE_PREFIX, failure.action),
                "error": failure.error,
                "action": original,
            });
            if let Some(slot) = out.get_mut(failure.index) {
                *slot = envelope;
            } else {
                out.push(envelope);
            }
        }
        out
    }
}

/// Execute an array of actions from LLM response
///
/// # Arguments
/// * `actions` - Array of action JSON objects from LLM
/// * `state` - Application state
/// * `protocol` - Optional protocol for protocol-specific actions
/// * `server_id` - Optional server ID for context (used for feedback, memory, etc.)
/// * `client_id` - Optional client ID for context (used for client feedback)
///
/// # Failure handling
///
/// A failing action does **not** abort the batch. Each failure is logged at `error!`
/// and recorded in `ExecutionResult::failures`, and execution continues with the next
/// action. Aborting would suppress the *valid* actions that follow a bad one — dropping
/// the `close_this_connection` that was meant to terminate a request whose body already
/// went out, for example — and would convert a single malformed action into a lost
/// connection in protocols that today recover by falling back to their default response.
/// The defect this addresses is that failures were invisible, not that they were
/// tolerated, so they are now surfaced (access log, `error!`) rather than made fatal.
///
/// # Returns
/// * `Ok(ExecutionResult)` - Results of execution; check `failures` for per-action errors
/// * `Err(_)` - If execution failed critically
pub async fn execute_actions(
    actions: Vec<serde_json::Value>,
    state: &AppState,
    protocol: Option<&dyn Server>,
    server_id: Option<crate::state::ServerId>,
    client_id: Option<crate::state::ClientId>,
) -> Result<ExecutionResult> {
    // Static interpolation and parsed JSON have budgets, but manual answers and
    // direct callers can construct arbitrarily nested Values. Check the whole
    // batch before cloning, logging, parsing or recursively destroying anything.
    if !crate::utils::json_budget::within_values_budget(
        &actions,
        crate::scripting::event_handler::MAX_INTERPOLATION_BYTES,
        crate::scripting::event_handler::MAX_INTERPOLATION_NODES,
        crate::scripting::event_handler::MAX_INTERPOLATION_DEPTH,
    ) {
        for action in actions {
            crate::utils::json_budget::drop_iteratively(action);
        }
        anyhow::bail!("action batch exceeds the shared JSON budget");
    }
    let mut result = ExecutionResult::new();

    // Store raw actions for protocols that need manual processing (mDNS, NFS, etc.)
    result.raw_actions = actions.clone();

    for (i, action) in actions.iter().enumerate() {
        debug!(
            "Executing action {}: {:?}",
            i,
            crate::utils::redact::redact_sensitive(action)
        );

        let action_name = action
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();

        // Pipe wiring actions (create_pipe / remove_pipe): the LLM or an operator can
        // wire one instance's events into another. Handled here rather than as a
        // CommonAction variant so the enum and its many exhaustive matches stay
        // untouched. The executor already holds `state` and the server context.
        if action_name == "create_pipe" || action_name == "remove_pipe" {
            if let Err(e) =
                crate::pipe::execute_pipe_action(&action_name, action, state, server_id).await
            {
                warn!(
                    "Pipe action '{}' failed: {} (action: {})",
                    action_name, e, action
                );
                result.add_failure(i, action_name, e.to_string());
            }
            continue;
        }

        // Try to parse as common action first
        if let Ok(common_action) = CommonAction::from_json(action) {
            if let Err(e) =
                execute_common_action(common_action, state, &mut result, server_id, client_id).await
            {
                error!(
                    "Action {} '{}' failed: {} (action: {})",
                    i, action_name, e, action
                );
                result.add_failure(i, action_name, e.to_string());
            }
            continue;
        }

        // Try protocol-specific action
        if let Some(proto) = protocol {
            match proto
                .execute_action_with_state(action.clone(), state.clone(), server_id)
                .await
            {
                Ok(action_result) => {
                    // Find action definition to get log template
                    let action_def = proto
                        .get_sync_actions()
                        .into_iter()
                        .chain(proto.get_async_actions(state).into_iter())
                        .find(|a| a.name == action_name);

                    // Log action result with template if available
                    log_action_result(
                        &action_name,
                        action,
                        &action_result,
                        action_def
                            .as_ref()
                            .and_then(|def| def.log_template.as_ref()),
                        None, // No TUI output from executor (event-level logging handles TUI)
                    );

                    result.add_named_protocol_result(action_name.clone(), action_result);
                    continue;
                }
                Err(e) => {
                    // The peer will now receive the protocol's default (an empty 200 for
                    // HTTP, nothing at all for TCP). Say so loudly and record it, rather
                    // than letting the batch look successful.
                    error!(
                        "Action {} '{}' failed on protocol {}: {} — the peer receives the \
                         protocol default instead (action: {})",
                        i,
                        action_name,
                        proto.protocol_name(),
                        e,
                        action
                    );
                    result.add_failure(i, action_name, e.to_string());
                    // Continue with the rest of the batch; see the fn-level docs.
                    continue;
                }
            }
        }

        // Not a common action, and there is no protocol in context to try it against.
        let detail = "unknown action type and no protocol in context".to_string();
        error!(
            "Action {} '{}' skipped: {} ({})",
            i, action_name, detail, action
        );
        result.add_failure(i, action_name, detail);
    }

    if let Some(summary) = result.failure_summary() {
        error!(
            "{} of {} action(s) failed: {}",
            result.failures.len(),
            actions.len(),
            summary
        );
    }

    Ok(result)
}

/// Execute a common action
async fn execute_common_action(
    action: CommonAction,
    state: &AppState,
    result: &mut ExecutionResult,
    server_id: Option<crate::state::ServerId>,
    client_id: Option<crate::state::ClientId>,
) -> Result<()> {
    match action {
        CommonAction::ShowMessage { message } => {
            // The operator, feedback and non-interactive paths answer show_message themselves
            // and never reach here; a network event does. This arm used to do nothing, and
            // nothing filled `messages`, so a server's model could call show_message and the
            // operator saw nothing. Each server logs `result.messages` to the status stream.
            result.add_message(message);
        }

        CommonAction::OpenServer { .. } => {
            // This should be handled by the caller (user command handler)
            // because it requires spawning a new server task
            warn!("open_server action cannot be executed by action executor - must be handled by caller");
        }

        CommonAction::CloseServer { .. } => {
            // This should be handled by the caller
            warn!("close_server action cannot be executed by action executor - must be handled by caller");
        }

        CommonAction::CloseAllServers => {
            // This should be handled by the caller
            warn!("close_all_servers action cannot be executed by action executor - must be handled by caller");
        }

        CommonAction::UpdateInstruction { .. } => {
            // This should be handled by the caller
            warn!("update_instruction action cannot be executed by action executor - must be handled by caller");
        }

        CommonAction::ChangeModel { .. } => {
            // This should be handled by the caller
            warn!("change_model action cannot be executed by action executor - must be handled by caller");
        }

        CommonAction::SetMemory { value } => {
            // A client's memory belongs to that client. Falling through to
            // `get_first_server_id()` in a client context wrote it into whichever server
            // happened to be first — an unrelated server's prompt, silently corrupted, while
            // the client's own memory stayed empty.
            if server_id.is_none() {
                if let Some(cid) = client_id {
                    let bounded = bound_server_memory(value);
                    debug!(
                        "Client #{} memory set ({} chars)",
                        cid.as_u32(),
                        bounded.len()
                    );
                    state
                        .with_client_mut(cid, |client| client.memory = bounded)
                        .await;
                    return Ok(());
                }
            }
            let sid = match server_id {
                Some(id) => Some(id),
                None => state.get_first_server_id().await,
            };
            if let Some(server_id) = sid {
                // Memory is injected into every prompt for this server, so it is bounded
                // here rather than trusted to stay small.
                let bounded = bound_server_memory(value);
                debug!(
                    "Server #{} memory set ({} chars)",
                    server_id.as_u32(),
                    bounded.len()
                );
                state.set_memory(server_id, bounded).await;
            }
        }

        CommonAction::AppendMemory { value } => {
            // See `SetMemory`: a client context must not fall through to the first server.
            if server_id.is_none() {
                if let Some(cid) = client_id {
                    let bounded = state
                        .with_client_mut(cid, |client| {
                            let combined = if client.memory.is_empty() {
                                value
                            } else {
                                format!("{}\n{}", client.memory, value)
                            };
                            client.memory = bound_server_memory(combined);
                            client.memory.len()
                        })
                        .await;
                    if let Some(len) = bounded {
                        debug!("Client #{} memory appended ({} chars)", cid.as_u32(), len);
                    }
                    return Ok(());
                }
            }
            let sid = match server_id {
                Some(id) => Some(id),
                None => state.get_first_server_id().await,
            };
            if let Some(server_id) = sid {
                let current = state.get_memory(server_id).await.unwrap_or_default();
                let new_memory = if current.is_empty() {
                    value
                } else {
                    format!("{}\n{}", current, value)
                };
                let bounded = bound_server_memory(new_memory);
                debug!(
                    "Server #{} memory appended ({} chars)",
                    server_id.as_u32(),
                    bounded.len()
                );
                state.set_memory(server_id, bounded).await;
            }
        }

        CommonAction::AppendToLog {
            output_name,
            content,
        } => {
            let sid = match server_id {
                Some(id) => Some(id),
                None => state.get_first_server_id().await,
            };
            if let Some(server_id) = sid {
                // Get or create the log file path
                let log_path = state
                    .with_server_mut(server_id, |server| {
                        server.get_or_create_log_path(&output_name)
                    })
                    .await;
                let log_path = match log_path {
                    Some(Ok(path)) => Some(path),
                    Some(Err(e)) => {
                        // Refused, not rewritten: the name is model-authored and would
                        // have become part of a path.
                        warn!("append_to_log refused: {e}");
                        None
                    }
                    None => None,
                };

                if let Some(log_path) = log_path {
                    // Append content to the log file
                    match tokio::fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(&log_path)
                        .await
                    {
                        Ok(mut file) => {
                            use tokio::io::AsyncWriteExt;
                            let log_line = format!("{}\n", content);
                            if let Err(e) = file.write_all(log_line.as_bytes()).await {
                                warn!("Failed to write to log file {:?}: {}", log_path, e);
                            } else {
                                debug!("Appended to log file {:?}", log_path);
                            }
                        }
                        Err(e) => {
                            warn!("Failed to open log file {:?}: {}", log_path, e);
                        }
                    }
                } else {
                    warn!("No server found to append log for");
                }
            }
        }
        CommonAction::ScheduleTask { .. } | CommonAction::CancelTask { .. } => {
            // Task scheduling handled by event handler, not executor
        }

        CommonAction::OpenClient { .. }
        | CommonAction::CloseClient { .. }
        | CommonAction::CloseAllClients
        | CommonAction::CloseConnectionById { .. }
        | CommonAction::ReconnectClient { .. }
        | CommonAction::UpdateClientInstruction { .. } => {
            // Client and connection management handled by event handler, not executor
        }

        CommonAction::UpdateServer { .. } | CommonAction::UpdateClient { .. } => {
            // Update handled by the event handler (execute_server_management_action),
            // not the executor - it needs to spawn/restart instances.
            warn!("update_server/update_client action must be handled by caller");
        }

        CommonAction::ProvideFeedback { feedback } => {
            // Accumulate feedback for later processing (debounced + LLM invocation)
            if let Some(sid) = server_id {
                state
                    .add_server_feedback(sid, feedback)
                    .await
                    .unwrap_or_else(|e| {
                        warn!("Failed to add server feedback: {}", e);
                    });
                debug!("Server #{} feedback accumulated", sid.as_u32());
            } else if let Some(cid) = client_id {
                state
                    .add_client_feedback(cid, feedback)
                    .await
                    .unwrap_or_else(|e| {
                        warn!("Failed to add client feedback: {}", e);
                    });
                debug!("Client #{} feedback accumulated", cid.as_u32());
            } else {
                warn!("provide_feedback action called without server_id or client_id context");
            }
        }

        #[cfg(feature = "sqlite")]
        CommonAction::CreateDatabase { .. } | CommonAction::DeleteDatabase { .. } => {
            // SQLite operations handled by event handler, not executor
        }
    }

    Ok(())
}

/// Extract server management actions that need special handling
///
/// These actions cannot be executed directly by the executor and must
/// be handled by the caller (usually the user command handler in main.rs)
pub fn extract_server_management_actions(actions: &[serde_json::Value]) -> Vec<CommonAction> {
    actions
        .iter()
        .filter_map(|action| {
            if let Ok(common_action) = CommonAction::from_json(action) {
                match common_action {
                    CommonAction::OpenServer { .. }
                    | CommonAction::CloseServer { .. }
                    | CommonAction::UpdateInstruction { .. }
                    | CommonAction::ChangeModel { .. } => Some(common_action),
                    _ => None,
                }
            } else {
                None
            }
        })
        .collect()
}

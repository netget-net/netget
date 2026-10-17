//! LLM action helper - simplified API for action-based LLM calls
//!
//! This module provides a centralized helper for all LLM interactions.
//! It encapsulates the common pattern of:
//! 1. Building prompt with actions
//! 2. Calling LLM
//! 3. Parsing action response
//! 4. Executing actions
//!
//! USE THIS HELPER FOR ALL LLM CALLS. Do not call OllamaClient.generate() directly.

use crate::llm::actions::{
    executor::{execute_actions, ExecutionResult},
    get_network_event_common_actions,
    protocol_trait::Server,
    ActionDefinition,
};
use crate::llm::ollama_client::OllamaClient;
use crate::llm::prompt::PromptBuilder;
use crate::protocol::{Event, EventLogContext};
use crate::state::app_state::AppState;
use crate::state::ServerId;
use anyhow::{Context as AnyhowContext, Result};
use std::sync::Arc;
use tracing::{debug, error, warn};

/// Call LLM with action-based framework
///
/// This is the PRIMARY way to interact with the LLM. It handles:
/// - Multi-turn conversation with tool calling
/// - Prompt building with action definitions
/// - LLM API call with message history
/// - Response parsing
/// - Action execution
///
/// # Arguments
/// * `llm_client` - Ollama client instance
/// * `state` - Application state for context
/// * `server_id` - Server ID for context
/// * `connection_id` - Optional connection ID for context (for scripts)
/// * `event_description` - High-level description of the event (e.g., "NFS lookup requested")
/// * `context_json` - Structured context data for the prompt
/// * `protocol` - Optional protocol for protocol-specific sync actions
/// * `custom_actions` - Additional custom actions specific to this call
/// * `event_data` - Optional structured event data for scripts
///
/// # Returns
/// * `Ok(ExecutionResult)` - Results containing messages and protocol-specific results
/// * `Err(_)` - If LLM call or action execution failed
///
/// # Example
/// ```rust,ignore
/// // NFS lookup example
/// let params = json!({
///     "operation": "lookup",
///     "path": "/home/user/file.txt",
///     "parent_id": 1
/// });
///
/// let result = call_llm_with_actions(
///     &llm_client,
///     &state,
///     server_id,
///     "NFS lookup operation requested",
///     params,
///     Some(&nfs_protocol),
///     vec![],
/// ).await?;
/// ```
#[allow(clippy::too_many_arguments)]
pub async fn call_llm_with_actions(
    llm_client: &OllamaClient,
    state: &AppState,
    server_id: ServerId,
    connection_id: Option<crate::server::connection::ConnectionId>,
    event_description: &str,
    context_json: serde_json::Value,
    protocol: Option<&dyn Server>,
    custom_actions: Vec<ActionDefinition>,
    event_data: Option<serde_json::Value>,
) -> Result<ExecutionResult> {
    // NOTE: Easy protocol handling is done in call_llm() since it requires an Event object
    // This function (call_llm_with_actions) is for legacy code paths that don't have Event objects

    // TRY EVENT HANDLER FIRST if configured
    let event_type_id = crate::scripting::ScriptManager::extract_context_type(event_description);

    let handler_instruction: Option<String>;
    match crate::llm::event_handler_executor::try_execute_event_handler(
        state,
        server_id,
        connection_id,
        &event_type_id,
        event_description,
        event_data.clone(),
        protocol,
    )
    .await?
    {
        crate::llm::event_handler_executor::EventHandlerResult::Handled(result) => {
            // Handler executed successfully (script or static)
            return Ok(result);
        }
        crate::llm::event_handler_executor::EventHandlerResult::FallbackToLlm { instruction } => {
            // No handler, or an explicit `{"type":"llm","instruction":"…"}` handler whose
            // instruction must be added to this event's prompt.
            handler_instruction = instruction;
        }
    }

    // FALLBACK TO LLM (normal path if no handler or handler requested fallback)

    // Get model from state, auto-select if not set
    let model = crate::llm::ensure_model_selected(
        state.get_ollama_model().await,
        &state.get_ollama_url().await,
    )
    .await
    .context("Failed to ensure model is selected")?;

    // Collect all actions: common + protocol sync + custom
    let mut all_actions = get_network_event_common_actions();

    // Add provide_feedback action only if server has feedback_instructions configured
    let has_feedback_instructions = state
        .with_server_mut(server_id, |server| server.feedback_instructions.is_some())
        .await
        .unwrap_or(false);

    if has_feedback_instructions {
        all_actions.push(crate::llm::actions::common::provide_feedback_action());
    }

    // Add protocol sync actions if provided
    if let Some(proto) = protocol {
        all_actions.extend(proto.get_sync_actions());
    }

    // Add custom actions (these can override or augment the standard actions)
    all_actions.extend(custom_actions);

    debug!(
        "LLM call for event: {} (server #{}, {} actions available)",
        event_description,
        server_id.as_u32(),
        all_actions.len()
    );

    // Build system prompt using action system (NO trigger - that goes in user message).
    //
    // The builder returns the list it advertised: it removes tools and drops
    // the script actions the current scripting mode disallows. Validating against the
    // pre-adjustment `all_actions` accepted `update_script` with scripting Off and withheld
    // native schemas for tools the prompt offered, so the advertised list is used from here on.
    let (system_prompt, advertised_actions) =
        PromptBuilder::build_network_event_action_prompt_for_server_with_actions(
            state,
            server_id,
            all_actions,
        )
        .await;

    // Create conversation handler for network event with tracking
    let truncated_desc = format!(
        "LLM \"{}\"",
        crate::utils::truncate_for_log(event_description, 27)
    );

    // Get rate limiter for network events (discards if rate limited)
    let rate_limiter = state.get_rate_limiter().await;

    let mut conversation = crate::llm::ConversationHandler::new(
        system_prompt,
        std::sync::Arc::new(llm_client.clone()),
        model,
        rate_limiter,
        crate::llm::RequestSource::Network, // Network events are discarded if rate limited
    )
    // Deliberately NO `.with_native_tools(...)`; guarded by
    // tests/llm_native_tools_test.rs, which explains why in full.
    // Short version: native schemas gave the model a second way to answer
    // alongside the JSON action envelope this prompt teaches, and it took it —
    // 6 of 6 failing protocol cases pass once they are removed. Network events use only
    // protocol/common actions; operator conversations retain their tool loop.
    .with_tracking(
        state.clone(),
        crate::state::app_state::ConversationSource::Network {
            server_id,
            connection_id,
        },
        truncated_desc,
    );

    // Add event trigger as a user message
    let event_trigger =
        PromptBuilder::build_event_trigger_message(event_description, context_json.clone());
    conversation.add_user_message(apply_handler_instruction(
        event_trigger,
        handler_instruction.as_deref(),
    ));

    // Get web search mode and approval channel
    let web_search_mode = state.get_web_search_mode().await;
    let approval_tx = state.get_web_approval_channel().await;

    // Generate actions with tool calling and retry
    let action_values = conversation
        .generate_with_tools_and_retry(approval_tx, web_search_mode, advertised_actions)
        .await
        .context("LLM generate with tools failed")?;

    if action_values.is_empty() {
        warn!(
            "LLM returned empty actions array for event: {}",
            event_description
        );
    }

    // Execute all collected actions with server context
    let result = execute_actions(action_values, state, protocol, Some(server_id), None)
        .await
        .context("Failed to execute actions")?;

    debug!(
        "LLM call completed: {} messages, {} protocol results",
        result.messages.len(),
        result.protocol_results.len()
    );

    Ok(result)
}

/// Simplified variant when no custom actions or context needed
///
/// This is useful when you just want to use the standard protocol actions
/// without adding any custom behavior or structured context.
pub async fn call_llm_with_protocol(
    llm_client: &OllamaClient,
    state: &AppState,
    server_id: ServerId,
    connection_id: Option<crate::server::connection::ConnectionId>,
    event_description: &str,
    protocol: &dyn Server,
) -> Result<ExecutionResult> {
    call_llm_with_actions(
        llm_client,
        state,
        server_id,
        connection_id,
        event_description,
        serde_json::json!({}), // Empty context
        Some(protocol),
        Vec::new(), // No custom actions
        None,       // No custom event data
    )
    .await
}

/// Simplified variant for custom actions only (no protocol or context)
///
/// This is useful for special cases like authentication decisions
/// where you need a custom action but no protocol-specific actions.
pub async fn call_llm_with_custom_actions(
    llm_client: &OllamaClient,
    state: &AppState,
    server_id: ServerId,
    connection_id: Option<crate::server::connection::ConnectionId>,
    event_description: &str,
    custom_actions: Vec<ActionDefinition>,
) -> Result<ExecutionResult> {
    call_llm_with_actions(
        llm_client,
        state,
        server_id,
        connection_id,
        event_description,
        serde_json::json!({}), // Empty context
        None,
        custom_actions,
        None, // No custom event data
    )
    .await
}

/// NEW EVENT-DRIVEN API: Call LLM with Event
///
/// This is the PREFERRED way to call the LLM for protocol events.
/// You pass an Event which combines:
/// - EventType reference (event ID, description, available actions)
/// - Event data (actual context like username, path, command)
///
/// # Arguments
/// * `llm_client` - Ollama client instance
/// * `state` - Application state for context
/// * `server_id` - Server ID for context
/// * `connection_id` - Optional connection ID for context (for scripts)
/// * `event` - The Event instance (EventType + data)
/// * `protocol` - Protocol for executing protocol-specific actions
///
/// # Returns
/// * `Ok(ExecutionResult)` - Results containing messages and protocol-specific results
/// * `Err(_)` - If LLM call or action execution failed
///
/// # Example
/// ```rust,ignore
/// let event = Event::new(
///     &HTTP_REQUEST_EVENT,
///     json!({
///         "method": "GET",
///         "path": "/api/users"
///     })
/// );
///
/// let result = call_llm(
///     &llm_client,
///     &state,
///     server_id,
///     Some(connection_id),
///     &event,
///     &http_protocol,
/// ).await?;
/// ```
/// Record a request/response access-log entry for a handled network event.
///
/// The request is the structured event data; the response is the action JSON
/// (e.g. `send_http_response`) the LLM or handler produced. Surfaced via the
/// `list_access_logs` / `get_access_log` MCP tools.
///
/// Ordinary failures are recorded as `FAILED: <action>` carrying the executor's
/// error. Credential-bearing input instead keeps only response action/failure counts
/// to avoid untyped reflection; the original input and executed results stay intact. See
/// [`ExecutionResult::access_log_actions`].
async fn record_event_access_log(
    state: &AppState,
    server_id: ServerId,
    connection_id: Option<crate::server::connection::ConnectionId>,
    protocol: &dyn Server,
    event: &Event,
    result: &ExecutionResult,
) {
    if let Some(summary) = result.failure_summary() {
        error!(
            "{} action(s) failed while handling '{}' on server #{} ({}): {}",
            result.failures.len(),
            event.id(),
            server_id.as_u32(),
            protocol.protocol_name(),
            summary
        );
    }

    state
        .record_access_log(
            crate::state::AccessLogOwner::Server(server_id.as_u32()),
            protocol.protocol_name(),
            connection_id.map(|c| c.as_u32()),
            event.id(),
            event.data.clone(),
            if crate::utils::redact::contains_credentials(&event.data) {
                // The original actions/results remain available to the protocol executor.
                vec![serde_json::json!({"type":"private_handler_result", "action_count":result.raw_actions.len(), "failed_actions":result.failures.len()})]
            } else { result.access_log_actions() },
        )
        .await;
}

/// Record a request whose handling failed, so it is still visible.
///
/// The response slot carries the error rather than actions. Without this an
/// unreachable model, a timeout or a failed action made the request vanish
/// from `list_access_logs` — the request pane went empty precisely when
/// something had gone wrong.
async fn record_failed_event_access_log(
    state: &AppState,
    server_id: ServerId,
    connection_id: Option<crate::server::connection::ConnectionId>,
    protocol: &dyn Server,
    event: &Event,
    error: &anyhow::Error,
) {
    state
        .record_access_log(
            crate::state::AccessLogOwner::Server(server_id.as_u32()),
            protocol.protocol_name(),
            connection_id.map(|c| c.as_u32()),
            event.id(),
            event.data.clone(),
            vec![serde_json::json!({
                "type": format!("FAILED: {}", event.id()),
                "error": if crate::utils::redact::contains_credentials(&event.data) { "credential-bearing event failed; diagnostics hidden".to_string() } else { error.to_string() },
            })],
        )
        .await;
}

pub async fn call_llm(
    llm_client: &OllamaClient,
    state: &AppState,
    server_id: ServerId,
    connection_id: Option<crate::server::connection::ConnectionId>,
    event: &Event,
    protocol: &dyn Server,
) -> Result<ExecutionResult> {
    call_llm_with_earlier(
        llm_client,
        state,
        server_id,
        connection_id,
        event,
        &[],
        protocol,
    )
    .await
}

/// Answer several events from one connection — the ones that arrived while the model was
/// still answering an earlier one — in a single model call, when the instance batches.
///
/// The newest event is the trigger, exactly as for [`call_llm`]; the earlier ones are listed
/// above it as arrived and not yet answered, and the model may answer each, some or none. One
/// [`ExecutionResult`] covers the lot, its actions in the order the model gave them.
///
/// Falls back to answering the events one by one, in arrival order, and returns their results
/// concatenated, when the instance has batching off or when any of them is routed somewhere
/// other than the model: a script, static or manual rule decides its event on its own, and
/// folding such an event into a model call would hand the model a decision that was not its.
pub async fn call_llm_batch(
    llm_client: &OllamaClient,
    state: &AppState,
    server_id: ServerId,
    connection_id: Option<crate::server::connection::ConnectionId>,
    events: &[Event],
    protocol: &dyn Server,
) -> Result<ExecutionResult> {
    let Some((last, earlier)) = events.split_last() else {
        return Ok(ExecutionResult::new());
    };
    if earlier.is_empty() || !batch_goes_to_the_model(state, server_id, events).await {
        let mut combined = ExecutionResult::new();
        for event in events {
            combined.extend(
                call_llm(llm_client, state, server_id, connection_id, event, protocol).await?,
            );
        }
        return Ok(combined);
    }
    call_llm_with_earlier(
        llm_client,
        state,
        server_id,
        connection_id,
        last,
        earlier,
        protocol,
    )
    .await
}

/// Whether a batch may be answered by one model call: the instance batches, it is not driven
/// by an easy-protocol layer, and no event in it matches a rule other than an `llm` one with
/// the same instruction as the rest.
async fn batch_goes_to_the_model(state: &AppState, server_id: ServerId, events: &[Event]) -> bool {
    let batching = state
        .server_conversation_settings(server_id)
        .await
        .is_some_and(|(_, batching)| batching);
    if !batching || state.get_easy_for_server(server_id).await.is_some() {
        return false;
    }
    let Some(config) = state.get_event_handler_config(server_id).await else {
        return true;
    };
    let mut instruction: Option<Option<String>> = None;
    for event in events {
        let this = match config.find_handler(event.id()) {
            None => None,
            Some(crate::scripting::EventHandlerType::Llm { instruction }) => {
                Some(instruction.clone())
            }
            Some(_) => return false,
        };
        match &instruction {
            None => instruction = Some(this),
            Some(first) if *first != this => return false,
            Some(_) => {}
        }
    }
    true
}

async fn call_llm_with_earlier(
    llm_client: &OllamaClient,
    state: &AppState,
    server_id: ServerId,
    connection_id: Option<crate::server::connection::ConnectionId>,
    event: &Event,
    earlier: &[Event],
    protocol: &dyn Server,
) -> Result<ExecutionResult> {
    anyhow::ensure!(
        crate::utils::json_budget::within_budget(
            &event.data,
            crate::scripting::event_handler::MAX_INTERPOLATION_BYTES,
            crate::scripting::event_handler::MAX_INTERPOLATION_NODES,
            crate::scripting::event_handler::MAX_INTERPOLATION_DEPTH
        ),
        "event exceeds the shared JSON budget"
    );
    for earlier_event in earlier {
        anyhow::ensure!(
            crate::utils::json_budget::within_budget(
                &earlier_event.data,
                crate::scripting::event_handler::MAX_INTERPOLATION_BYTES,
                crate::scripting::event_handler::MAX_INTERPOLATION_NODES,
                crate::scripting::event_handler::MAX_INTERPOLATION_DEPTH
            ),
            "event exceeds the shared JSON budget"
        );
    }
    let private = crate::utils::redact::contains_credentials(&event.data)
        || earlier
            .iter()
            .any(|e| crate::utils::redact::contains_credentials(&e.data));
    let run = call_llm_inner(
        llm_client,
        state,
        server_id,
        connection_id,
        event,
        earlier,
        protocol,
        private,
    );
    let outcome = if private {
        use tracing::instrument::WithSubscriber;
        // Protocol/static execution can reflect an input value in an untyped diagnostic.
        // Suppress that request's tracing, preserving execution and typed access-log input.
        run.with_subscriber(tracing::subscriber::NoSubscriber::default())
            .await
            .map_err(crate::utils::redact::hide_error_details)
    } else {
        run.await
    };

    if let Err(e) = &outcome {
        for earlier_event in earlier {
            record_failed_event_access_log(
                state,
                server_id,
                connection_id,
                protocol,
                earlier_event,
                e,
            )
            .await;
        }
        record_failed_event_access_log(state, server_id, connection_id, protocol, event, e).await;
    }
    outcome
}

#[allow(clippy::too_many_arguments)]
async fn call_llm_inner(
    llm_client: &OllamaClient,
    state: &AppState,
    server_id: ServerId,
    connection_id: Option<crate::server::connection::ConnectionId>,
    event: &Event,
    earlier: &[Event],
    protocol: &dyn Server,
    private_payloads: bool,
) -> Result<ExecutionResult> {
    // Create event log context for lifecycle logging
    // Get client address from connection state if available
    let client_addr = if let Some(conn_id) = connection_id {
        state
            .with_server_mut(server_id, |server| {
                server.connections.get(&conn_id).map(|c| c.remote_addr)
            })
            .await
            .flatten()
    } else {
        None
    };

    let log_ctx = EventLogContext::new(
        event,
        server_id,
        connection_id,
        client_addr,
        protocol.protocol_name(),
    );

    // The event template renderer dual-logs (file + TUI) when given a status channel;
    // it was always called with `None`, so the 1600+ defined event templates reached the
    // file and never the TUI. Route them to whatever TUI stream this client narrates to
    // (the same channel the transport/conversation layers use). This is `None` wherever the
    // client was built without a status channel, in which case behaviour is unchanged.
    let event_status_tx = llm_client.status_tx();

    // Log event start (DEBUG level)
    if !private_payloads {
        log_ctx.log_start(event_status_tx);
    }

    // PIPE TAP: forward this event into any wired sink instances, deterministically
    // and before any handler runs, so a pipe fires regardless of how this server
    // answers its own peer (and even if the LLM call below fails). Delivery is
    // spawned under a bounded semaphore inside `dispatch_pipes`, so this does not
    // block the response path.
    crate::pipe::dispatch_pipes(state, server_id, event).await;

    // TRY EASY PROTOCOL HANDLER FIRST if this server is managed by an easy protocol
    if let Some(easy_id) = state.get_easy_for_server(server_id).await {
        use crate::protocol::EASY_REGISTRY;
        if let Some(easy_instance) = state.get_easy_instance(easy_id).await {
            if let Some(easy_protocol) = EASY_REGISTRY.get_by_name(&easy_instance.protocol_name) {
                // Call Easy protocol handler
                let actions = easy_protocol
                    .handle_event(
                        event.clone(),
                        easy_instance.user_instruction.clone(),
                        Arc::new(llm_client.clone()),
                        Arc::new(state.clone()),
                    )
                    .await
                    .context("Easy protocol handler failed")?;

                // Execute actions and return result
                let result = crate::llm::execute_actions(
                    actions,
                    state,
                    Some(protocol),
                    Some(server_id),
                    None, // client_id
                )
                .await?;

                // Log event completion
                if !private_payloads {
                    log_ctx.log_complete(event_status_tx, &result.protocol_results);
                }
                record_event_access_log(state, server_id, connection_id, protocol, event, &result)
                    .await;
                return Ok(result);
            }
        }
    }

    // TRY EVENT HANDLER FIRST if configured (includes scripts and static responses)
    let handler_instruction: Option<String>;
    match crate::llm::event_handler_executor::try_execute_event_handler(
        state,
        server_id,
        connection_id,
        &event.event_type.id,
        &event.event_type.description,
        Some(event.data.clone()),
        Some(protocol),
    )
    .await?
    {
        crate::llm::event_handler_executor::EventHandlerResult::Handled(result) => {
            // Handler executed successfully (script or static)
            if !private_payloads {
                log_ctx.log_complete(event_status_tx, &result.protocol_results);
            }
            record_event_access_log(state, server_id, connection_id, protocol, event, &result)
                .await;
            return Ok(result);
        }
        crate::llm::event_handler_executor::EventHandlerResult::FallbackToLlm { instruction } => {
            // No handler, or an explicit `{"type":"llm","instruction":"…"}` handler whose
            // instruction must be added to this event's prompt.
            handler_instruction = instruction;
        }
    }

    // FALLBACK TO LLM (normal path if no script or script failed/requested fallback)

    // Get model from state, auto-select if not set
    let model = crate::llm::ensure_model_selected(
        state.get_ollama_model().await,
        &state.get_ollama_url().await,
    )
    .await
    .context("Failed to ensure model is selected")?;

    // Collect all actions: common + event-specific actions
    let mut all_actions = get_network_event_common_actions();

    // Add provide_feedback action only if server has feedback_instructions configured
    let has_feedback_instructions = state
        .with_server_mut(server_id, |server| server.feedback_instructions.is_some())
        .await
        .unwrap_or(false);

    if has_feedback_instructions {
        all_actions.push(crate::llm::actions::common::provide_feedback_action());
    }

    // Add event-specific actions (these are the actions available for this event type).
    //
    // The event's own list is authoritative and is deliberately narrower than the protocol's
    // full set: SSH's `ssh_auth` accepts `ssh_auth_decision` and nothing else, and unioning in
    // `get_sync_actions()` would offer the model `sftp_error` as a way to answer an
    // authentication request. So a narrowing is preserved wherever a protocol expressed one.
    //
    // What is never intended is an *empty* list on a protocol that declares sync actions: the
    // model is then handed only set_memory/append_memory/show_message/append_to_log, and every
    // protocol action it returns is rejected as unknown, retried twice, and fails. That shape
    // silently disabled sixteen protocols, so it is reported and repaired instead of shipped.
    //
    // This path deliberately does NOT assert. It runs once per connection inside a tokio task,
    // where a `debug_assert!` panic is swallowed by the task and leaves the server still
    // reporting `Running` — the quietest possible way to be loud, and an NFS reviewer hit
    // exactly that. The loud, attributable failure lives in
    // `crate::llm::actions::protocol_trait::audit_event_action_declarations`, which is checked
    // over the whole registry by `tests/event_action_declarations_test.rs` and is meant to be
    // called once per protocol at startup in `src/cli/server_startup.rs`. Here: ERROR and
    // recover, so the connection is served rather than dropped.
    if event.event_type.has_no_usable_actions() {
        let fallback = protocol.get_sync_actions();
        if !fallback.is_empty() {
            error!(
                "BUG: event '{}' of protocol '{}' declares no actions of its own, so the model \
                 would be offered none of the protocol's {} sync action(s) and anything \
                 protocol-specific it returned would be rejected as an unknown action. Falling \
                 back to the full sync action set. Fix by adding .with_actions(...) to the event \
                 type, or .with_no_actions() if it genuinely needs none.",
                event.id(),
                protocol.protocol_name(),
                fallback.len()
            );
            all_actions.extend(fallback);
        }
    } else {
        all_actions.extend(event.event_type.actions.clone());
    }
    // A batch may hold events of other types; each one's own answers are on offer too.
    for earlier_event in earlier {
        for action in &earlier_event.event_type.actions {
            if !all_actions.iter().any(|a| a.name == action.name) {
                all_actions.push(action.clone());
            }
        }
    }

    debug!(
        "LLM call for event '{}' (server #{}, {} actions available)",
        event.id(),
        server_id.as_u32(),
        all_actions.len()
    );

    // Use the event's prompt description
    let event_description = event.to_prompt_description();

    // Build system prompt using action system (NO trigger - that goes in user message).
    // `advertised_actions` is what the prompt actually offered (tools added, script actions
    // filtered by scripting mode); everything downstream validates against that list.
    let (system_prompt, advertised_actions) =
        PromptBuilder::build_network_event_action_prompt_for_server_with_actions(
            state,
            server_id,
            all_actions,
        )
        .await;

    // Create conversation handler for network event with tracking
    // Note: Network events don't use tools (immediate response), but get retry logic
    let truncated_desc = if private_payloads {
        "LLM credential-bearing event".to_string()
    } else {
        format!(
            "LLM \"{}\"",
            crate::utils::truncate_for_log(&event_description, 27)
        )
    };

    // Get rate limiter for network events (discards if rate limited)
    let rate_limiter = state.get_rate_limiter().await;

    let mut conversation = crate::llm::ConversationHandler::new(
        system_prompt,
        std::sync::Arc::new(llm_client.clone()),
        model,
        rate_limiter,
        crate::llm::RequestSource::Network, // Network events are discarded if rate limited
    )
    .with_bridge_event(server_id, connection_id, protocol.protocol_name(), event)
    // Deliberately NO `.with_native_tools(...)`; guarded by
    // tests/llm_native_tools_test.rs, which explains why in full.
    // Short version: native schemas gave the model a second way to answer
    // alongside the JSON action envelope this prompt teaches, and it took it —
    // 6 of 6 failing protocol cases pass once they are removed. Network events use only
    // protocol/common actions; operator conversations retain their tool loop.
    .with_private_payloads(private_payloads)
    .with_tracking(
        state.clone(),
        crate::state::app_state::ConversationSource::Network {
            server_id,
            connection_id,
        },
        truncated_desc,
    );

    // Add event trigger as a user message (include event ID for mock testing compatibility)
    let event_trigger = PromptBuilder::build_event_trigger_message_with_id(
        event.id(),
        &event_description,
        event.data.clone(),
    );
    // What has already happened on this connection, ahead of the event being answered. The
    // block carries no `Event ID:` / `Context data:` labels, so the trigger stays the last —
    // and only — event in the prompt. Credentials were dropped when the history was recorded.
    let event_trigger = if earlier.is_empty() {
        event_trigger
    } else {
        format!("{}\n{}", render_unanswered(earlier, event), event_trigger)
    };
    let event_trigger = match state.render_server_history(server_id, connection_id).await {
        Some(history) => format!("{}\n{}", history, event_trigger),
        None => event_trigger,
    };
    conversation.add_user_message(apply_handler_instruction(
        event_trigger,
        handler_instruction.as_deref(),
    ));

    // Generate response with retry (no tool calling for network events)
    let actions = conversation
        .generate_with_tools_and_retry(
            None,                                        // No web approval for network events
            crate::state::app_state::WebSearchMode::Off, // No web search for network events
            advertised_actions,
        )
        .await
        .context("✗  LLM failed to generate valid response after retries.")?;

    if actions.is_empty() {
        warn!("LLM returned empty actions array for event: {}", event.id());
    }

    // Execute actions with server context
    let result = execute_actions(actions, state, Some(protocol), Some(server_id), None)
        .await
        .context("Failed to execute actions")?;

    debug!(
        "LLM call completed: {} messages, {} protocol results",
        result.messages.len(),
        result.protocol_results.len()
    );

    // Log event completion with timing and results
    if !private_payloads {
        log_ctx.log_complete(event_status_tx, &result.protocol_results);
    }
    // A batch is recorded event by event, so the access log and the connection's history
    // show each one arriving; the answer sits with the last, the others say they were
    // answered together with it.
    for earlier_event in earlier {
        state
            .record_access_log(
                crate::state::AccessLogOwner::Server(server_id.as_u32()),
                protocol.protocol_name(),
                connection_id.map(|c| c.as_u32()),
                earlier_event.id(),
                earlier_event.data.clone(),
                vec![serde_json::json!({
                    "type": crate::state::exchange_history::ANSWERED_WITH_NEXT
                })],
            )
            .await;
    }
    record_event_access_log(state, server_id, connection_id, protocol, event, &result).await;

    Ok(result)
}

/// The block listing a batch's earlier events above its trigger. It carries none of the
/// trigger's labels (`Event ID:`, `Event:`, `Context data:`), so the newest event stays the
/// one the prompt — and the test mock — reads as current.
fn render_unanswered(earlier: &[Event], last: &Event) -> String {
    let mut out = format!(
        "{} more arrived on this connection while you were answering, before the event below \
         and not yet answered. Your reply answers all {} together: answer each, some or none, \
         in the order the actions should happen.\n",
        earlier.len(),
        earlier.len() + 1
    );
    for (i, event) in earlier.iter().enumerate() {
        out.push_str(&format!(
            "({}) {} {}\n",
            i + 1,
            event.id(),
            serde_json::to_string(&event.data).unwrap_or_default()
        ));
    }
    out.push_str(&format!(
        "({}) is the event below ({}).\n",
        earlier.len() + 1,
        last.id()
    ));
    out
}

/// Call LLM for client protocol events (simplified version for MVP)
/// Result from client LLM call
#[derive(Debug, Clone)]
pub struct ClientLlmResult {
    pub actions: Vec<serde_json::Value>,
    pub memory_updates: Option<String>,
}

/// Call LLM for client protocol events (simplified version for MVP)
///
/// This is a simplified version of call_llm for client protocols.
/// Unlike servers, clients don't have complex scripting or connection tracking.
#[allow(clippy::too_many_arguments)]
pub async fn call_llm_for_client(
    llm_client: &OllamaClient,
    state: &AppState,
    client_id: String,
    instruction: &str,
    memory: &str,
    event: Option<&Event>,
    protocol: &dyn crate::llm::actions::client_trait::Client,
    status_tx: &tokio::sync::mpsc::UnboundedSender<String>,
) -> Result<ClientLlmResult> {
    if let Some(event) = event {
        anyhow::ensure!(
            crate::utils::json_budget::within_budget(
                &event.data,
                crate::scripting::event_handler::MAX_INTERPOLATION_BYTES,
                crate::scripting::event_handler::MAX_INTERPOLATION_NODES,
                crate::scripting::event_handler::MAX_INTERPOLATION_DEPTH,
            ),
            "event exceeds the shared JSON budget"
        );
    }
    let private_payloads = event
        .is_some_and(|event| crate::utils::redact::contains_credentials(&event.data))
        || crate::utils::redact::actions_have_credentials(
            &crate::llm::actions::client_trait::client_llm_action_set(protocol, state, event),
        );
    let run = call_llm_for_client_inner(
        llm_client,
        state,
        client_id,
        instruction,
        memory,
        event,
        protocol,
        status_tx,
        private_payloads,
    );
    if private_payloads {
        use tracing::instrument::WithSubscriber;
        run.with_subscriber(tracing::subscriber::NoSubscriber::default())
            .await
            .map_err(crate::utils::redact::hide_error_details)
    } else {
        run.await
    }
}

#[allow(clippy::too_many_arguments)]
async fn call_llm_for_client_inner(
    llm_client: &OllamaClient,
    state: &AppState,
    client_id: String,
    instruction: &str,
    memory: &str,
    event: Option<&Event>,
    protocol: &dyn crate::llm::actions::client_trait::Client,
    status_tx: &tokio::sync::mpsc::UnboundedSender<String>,
    private_payloads: bool,
) -> Result<ClientLlmResult> {
    // Get client actions.
    //
    // This used to be `protocol.get_async_actions(state)` and nothing else — not
    // `get_sync_actions()`, not `event.event_type.actions`. Any action declared only as sync,
    // or only attached to an event, was advertised nowhere and then rejected as an unknown
    // action if the model guessed it, which broke 53 of the 91 client protocols; TFTP's
    // sync-only `send_ack` stalled every transfer at block 1. `client_llm_action_set` is the
    // union, and `audit_client_action_declarations` (run over the whole client registry by
    // `tests/event_action_declarations_test.rs`) fails the build if the two ever diverge again.
    // See that function for why the client path unions where the server path narrows.
    let mut all_actions =
        crate::llm::actions::client_trait::client_llm_action_set(protocol, state, event);

    // A client has a memory — `ClientInstance::memory`, prefixed to every message below — but
    // no way to write it, so anything it learned across events was lost. Both actions are in
    // `CLIENT_COMMON_ACTION_NAMES`, so they are executed here rather than handed to a
    // `Client::execute_action` that has never heard of them.
    all_actions.push(crate::llm::actions::common::set_memory_action());
    all_actions.push(crate::llm::actions::common::append_memory_action());

    // A client's only way to say anything to the user. Without it, a model that had nothing
    // to send on the wire but something to report had no action it was allowed to use, and
    // reaching for `show_message` — the most obvious name there is — cost two retries and
    // then failed the whole event.
    all_actions.push(crate::llm::actions::common::show_message_action());

    // Add provide_feedback action only if client has feedback_instructions configured
    // Parse client_id from string format "client-123"
    if let Some(cid) = crate::state::ClientId::from_string(&client_id) {
        let has_feedback_instructions = state
            .with_client_mut(cid, |client| client.feedback_instructions.is_some())
            .await
            .unwrap_or(false);

        if has_feedback_instructions {
            all_actions.push(crate::llm::actions::common::provide_feedback_action());
        }
    }

    // Build simple prompt for client
    let system_prompt =
        format!(
        "You are controlling a network client ({}). Your instruction: {}\n\nAvailable actions:\n{}",
        protocol.protocol_name(),
        instruction,
        all_actions.iter().map(|a| a.to_prompt_text()).collect::<Vec<_>>().join("\n\n")
    );

    // Build user message
    let user_message = if let Some(ev) = event {
        format!(
            "Event: {}\nData: {}",
            ev.id(),
            serde_json::to_string_pretty(&ev.data).unwrap_or_default()
        )
    } else {
        "Waiting for instructions".to_string()
    };

    // What has already happened on this client's session, ahead of what it is answering now.
    // Rendered with no `Event:`/`Data:` labels, so the current event stays the only one.
    let user_message = match crate::state::ClientId::from_string(&client_id) {
        Some(cid) => match state.render_client_history(cid).await {
            Some(history) => format!("{}\n{}", history, user_message),
            None => user_message,
        },
        None => user_message,
    };

    // Add memory context if present
    let full_message = if !memory.is_empty() {
        format!("Memory: {}\n\n{}", memory, user_message)
    } else {
        user_message
    };

    // Get current model from state, auto-select if not set
    let current_model = state.get_ollama_model().await;
    let model =
        crate::llm::ensure_model_selected(current_model.clone(), &state.get_ollama_url().await)
            .await
            .context("Failed to ensure model is selected")?;

    // If model was auto-selected (wasn't set before), notify via status_tx
    if current_model.is_none() {
        let _ = status_tx.send(format!(
            "⚠  Auto-selected model: {} (no model was configured)",
            model
        ));
    }

    // Get rate limiter for client calls (network-like, discards if rate limited)
    let rate_limiter = state.get_rate_limiter().await;

    // Create conversation with correct parameter order
    let mut conversation = crate::llm::ConversationHandler::new(
        system_prompt,
        std::sync::Arc::new(llm_client.clone()),
        model,
        rate_limiter,
        crate::llm::RequestSource::Network, // Client calls are network-initiated, discarded if rate limited
    )
    // Same reasoning as the two server network-event paths above, and the same
    // construction — see tests/llm_native_tools_test.rs. Not separately measured:
    // the 6/6 evidence comes from server protocols, and this is inferred from the
    // paths being identical rather than from a client A/B.
    .with_status_tx(status_tx.clone())
    .with_private_payloads(private_payloads);

    if let Some(client_id) = crate::state::ClientId::from_string(&client_id) {
        conversation = conversation.with_tracking(
            state.clone(),
            crate::state::app_state::ConversationSource::Client { client_id },
            event
                .map(|ev| ev.id().to_string())
                .unwrap_or_else(|| "Client instructions".into()),
        );
    }

    // Add user message
    conversation.add_user_message(full_message);

    // Generate response with actions (no web approval or tools for clients)
    let actions = conversation
        .generate_with_tools_and_retry(
            None,
            crate::state::app_state::WebSearchMode::Off,
            all_actions,
        )
        .await?;

    // Execute the *common* actions this function advertised, and hand back only the ones a
    // client protocol can run.
    //
    // Every client dispatches `ClientLlmResult::actions` straight into its own
    // `Client::execute_action`, which knows only its protocol's vocabulary. `provide_feedback`
    // is not in any of them — it is injected into the tool list above, from
    // `common::provide_feedback_action()` — so a model that used the tool it was offered had
    // its call rejected as an unknown action, retried, and ultimately dropped. That is the
    // fail-open shape one level up: advertise a tool that cannot work.
    //
    // The server path does not have this problem because `executor::execute_actions` tries
    // `CommonAction::from_json` before the protocol. Clients never reach that executor, so the
    // split happens here — in the one place that advertises the action.
    let (common_actions, protocol_actions) = split_client_common_actions(actions);

    // `show_message` is emitted here rather than by the executor, whose match arm for it is a
    // deliberate no-op ("handled by the caller, to avoid duplicate output"). Accepting the
    // action without this loop would take the model's message and drop it, which is the same
    // advertise-a-no-op shape as rejecting it outright — just quieter.
    for action in &common_actions {
        if action.get("type").and_then(|t| t.as_str()) == Some("show_message") {
            if let Some(message) = action.get("message").and_then(|m| m.as_str()) {
                let _ = status_tx.send(format!("[CLIENT] {}", message));
            }
        }
    }

    if !common_actions.is_empty() {
        match crate::state::ClientId::from_string(&client_id) {
            Some(cid) => {
                if let Err(e) = crate::llm::actions::executor::execute_actions(
                    common_actions,
                    state,
                    None, // no server protocol in a client context
                    None, // no server id
                    Some(cid),
                )
                .await
                {
                    let error = if private_payloads {
                        crate::utils::redact::hide_error_details(e)
                    } else {
                        e
                    };
                    tracing::warn!("Client common action execution failed: {}", error);
                    let _ = status_tx.send(format!("[CLIENT] feedback action failed: {error}"));
                }
            }
            None => {
                // Cannot attribute the feedback to a client, so it cannot be stored. Say so
                // rather than silently discarding it.
                tracing::warn!(
                    "Client returned a common action but client_id {:?} could not be parsed; \
                     the action was discarded",
                    client_id
                );
            }
        }
    }

    // For now, memory updates are not extracted from client responses
    // This can be enhanced later if needed
    let memory_updates = None;

    Ok(ClientLlmResult {
        actions: protocol_actions,
        memory_updates,
    })
}

/// Actions `call_llm_for_client` advertises but no `Client::execute_action` implements.
///
/// Keep this list and the injection sites above in step: an entry here with no injection is
/// dead, and an injection with no entry is a tool the model is punished for using.
/// `tests/client_provide_feedback_test.rs` asserts both directions.
///
/// `set_memory` and `append_memory` are here because a client has a memory — `ClientInstance`
/// carries one and `call_llm_for_client` prefixes it to every message — but had no way to
/// write it. A model told "remember what you learned" could only answer with a protocol
/// action, and if it reached for `set_memory` anyway the name was rejected as unknown and the
/// call retried. The executor half of this was worse: with no `server_id`, `SetMemory` fell
/// through to `get_first_server_id_sync()` and wrote the client's note into whichever *server*
/// happened to be first.
pub const CLIENT_COMMON_ACTION_NAMES: &[&str] = &[
    "provide_feedback",
    "set_memory",
    "append_memory",
    "show_message",
];

/// Split a client model's actions into the common ones this module executes itself and the
/// protocol ones the calling client hands to `Client::execute_action`.
///
/// Order within each half is preserved, so a protocol still sees its actions in the sequence
/// the model produced them.
pub fn split_client_common_actions(
    actions: Vec<serde_json::Value>,
) -> (Vec<serde_json::Value>, Vec<serde_json::Value>) {
    actions.into_iter().partition(|action| {
        action
            .get("type")
            .and_then(|t| t.as_str())
            .map(|name| CLIENT_COMMON_ACTION_NAMES.contains(&name))
            .unwrap_or(false)
    })
}

/// Call LLM for feedback processing (server or client adjustment)
///
/// This is invoked when feedback has accumulated for a server/client with feedback_instructions.
/// The LLM analyzes the feedback and returns actions to adjust the instance behavior.
///
/// # Arguments
/// * `llm_client` - Ollama client for LLM invocations
/// * `state` - Application state
/// * `server_id` - Server ID if processing server feedback
/// * `client_id` - Client ID if processing client feedback
/// * `feedback_instructions` - Instructions for how to process feedback
/// * `current_instruction` - Current instruction of the instance
/// * `memory` - Current memory of the instance
/// * `feedback_entries` - Accumulated feedback entries
/// * `status_tx` - Channel for status messages
///
/// # Returns
/// * `Ok(Vec<serde_json::Value>)` - Actions to adjust the instance
/// * `Err(_)` - If LLM invocation fails
#[allow(clippy::too_many_arguments)]
pub async fn call_llm_for_feedback(
    llm_client: &OllamaClient,
    state: &AppState,
    server_id: Option<crate::state::ServerId>,
    client_id: Option<crate::state::ClientId>,
    feedback_instructions: &str,
    current_instruction: &str,
    memory: &str,
    feedback_entries: &[serde_json::Value],
    status_tx: &tokio::sync::mpsc::UnboundedSender<String>,
) -> Result<Vec<serde_json::Value>> {
    use crate::llm::actions::get_user_input_common_actions;
    use crate::llm::prompt::PromptBuilder;

    // Get available adjustment actions (user input actions for modifying server/client)
    let selected_mode = state.get_selected_scripting_mode().await;
    let scripting_env = state.get_scripting_env().await;
    let is_open_server_enabled = true;
    let is_open_client_enabled = true;
    let available_actions = get_user_input_common_actions(
        selected_mode,
        &scripting_env,
        is_open_server_enabled,
        is_open_client_enabled,
    );

    // Apply the same scripting-mode filter the prompt builder applies, so the
    // list we advertise to the model is exactly the list we validate against.
    // (Previously an empty Vec was passed to the validator, so every action the
    // model returned was rejected as "unknown action" and the call always failed.)
    let has_scripting = selected_mode != crate::state::app_state::ScriptingMode::Off;
    let feedback_actions =
        PromptBuilder::filter_actions_by_scripting_mode(available_actions, has_scripting);

    // Build feedback processing prompt
    let system_prompt = PromptBuilder::build_feedback_system_prompt(
        state,
        server_id,
        client_id,
        feedback_instructions,
        current_instruction,
        memory,
        feedback_entries,
        feedback_actions.clone(),
    )
    .await;

    // Get current model from state, auto-select if not set
    let current_model = state.get_ollama_model().await;
    let model =
        crate::llm::ensure_model_selected(current_model.clone(), &state.get_ollama_url().await)
            .await
            .context("Failed to ensure model is selected")?;

    // If model was auto-selected, notify via status_tx
    if current_model.is_none() {
        let _ = status_tx.send(format!(
            "⚠  Auto-selected model: {} (no model was configured)",
            model
        ));
    }

    let instance_type = if server_id.is_some() {
        "server"
    } else {
        "client"
    };
    let instance_id = server_id
        .map(|id| id.as_u32())
        .or_else(|| client_id.map(|id| id.as_u32()))
        .unwrap_or(0);

    debug!(
        "LLM feedback processing for {} #{} ({} feedback entries)",
        instance_type,
        instance_id,
        feedback_entries.len()
    );

    // Get rate limiter for feedback processing (user-initiated, should not be discarded)
    let rate_limiter = state.get_rate_limiter().await;

    // Create conversation handler with tracking
    let conversation_source = if let Some(sid) = server_id {
        crate::state::app_state::ConversationSource::Network {
            server_id: sid,
            connection_id: None,
        }
    } else if let Some(client_id) = client_id {
        crate::state::app_state::ConversationSource::Client { client_id }
    } else {
        crate::state::app_state::ConversationSource::Task {
            task_name: format!("feedback-client-{}", instance_id),
        }
    };

    let mut conversation = crate::llm::ConversationHandler::new(
        system_prompt,
        std::sync::Arc::new(llm_client.clone()),
        model,
        rate_limiter,
        crate::llm::RequestSource::User, // Feedback is user-initiated (via debounce timer)
    )
    .with_native_tools(&feedback_actions)
    .with_status_tx(status_tx.clone())
    .with_tracking(
        state.clone(),
        conversation_source,
        format!("Feedback processing ({} entries)", feedback_entries.len()),
    );

    // Add user message to trigger feedback processing
    conversation
        .add_user_message("Analyze the accumulated feedback and suggest adjustments.".to_string());

    // Generate actions with retry (no tools for feedback processing)
    let web_search_mode = state.get_web_search_mode().await;
    let actions = conversation
        .generate_with_tools_and_retry(
            state.get_web_approval_channel().await,
            web_search_mode,
            feedback_actions,
        )
        .await
        .context("✗  LLM failed to generate feedback processing response after retries")?;

    if actions.is_empty() {
        warn!(
            "LLM returned empty actions for {} #{} feedback processing (no adjustments needed)",
            instance_type, instance_id
        );
    } else {
        debug!(
            "LLM feedback processing completed for {} #{}: {} adjustment actions",
            instance_type,
            instance_id,
            actions.len()
        );
    }

    Ok(actions)
}

/// Append a per-event handler instruction to the event trigger message.
///
/// A `{"type":"llm","instruction":"…"}` entry in `event_handlers` configures an
/// instruction for one event type. It used to be parsed, logged, and thrown away, so an
/// MCP caller who configured one silently got the server-wide instruction instead. The
/// instruction goes in the *user* trigger message rather than the system prompt because
/// the system prompt is built per server, not per event, and because it must be adjacent
/// to the event it qualifies.
fn apply_handler_instruction(event_trigger: String, instruction: Option<&str>) -> String {
    match instruction {
        Some(instruction) if !instruction.trim().is_empty() => {
            debug!(
                "Applying per-event handler instruction ({} bytes) to the event prompt",
                instruction.len()
            );
            format!(
                "{}\n\n{}:\n{}",
                event_trigger,
                crate::llm::event_handler_executor::HANDLER_INSTRUCTION_HEADER,
                instruction
            )
        }
        _ => event_trigger,
    }
}

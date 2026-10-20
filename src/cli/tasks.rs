//! Scheduled-task execution: the 1s tick every interactive and non-interactive
//! mode runs, which fires each due task through the model with the action
//! vocabulary its scope allows.

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::llm::OllamaClient;
use crate::state::app_state::AppState;

/// Execute all tasks that are due (public wrapper for non-interactive mode)
pub async fn execute_due_tasks_public(
    state: &AppState,
    llm_client: &OllamaClient,
    status_tx: &mpsc::UnboundedSender<String>,
) {
    execute_due_tasks(state, llm_client, status_tx, None).await
}

/// Execute due tasks owned by a service. Closing that service cancels only the
/// executions it launched, retaining task definitions for other AppState owners.
pub async fn execute_due_tasks_owned_public(
    state: &AppState,
    llm_client: &OllamaClient,
    status_tx: &mpsc::UnboundedSender<String>,
    owner: CancellationToken,
) {
    execute_due_tasks(state, llm_client, status_tx, Some(owner)).await
}

/// Execute all tasks that are due
async fn execute_due_tasks(
    state: &AppState,
    llm_client: &OllamaClient,
    status_tx: &mpsc::UnboundedSender<String>,
    owner: Option<CancellationToken>,
) {
    for task in state.claim_due_tasks().await {
        // Spawn task execution to avoid blocking
        let state_clone = state.clone();
        let llm_clone = llm_client.clone();
        let status_tx_clone = status_tx.clone();
        let task_clone = task.clone();
        let owner = owner.clone();

        state
            .spawn_scheduled_task(task.id, async move {
                if let Some(owner) = owner {
                    let cancelled_state = state_clone.clone();
                    let id = task_clone.id;
                    tokio::select! {
                        biased;
                        _ = owner.cancelled() => {
                            cancelled_state.update_task_status(id, crate::state::task::TaskStatus::Failed("execution owner closed".into())).await;
                        }
                        _ = execute_single_task(state_clone, llm_clone, status_tx_clone, task_clone) => {}
                    }
                } else {
                    execute_single_task(state_clone, llm_clone, status_tx_clone, task_clone).await;
                }
            })
            .await;
    }
}

/// How long a protocol action injected into a connection or client may take to report.
const INJECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Why a task's instance is gone, if it is: a task whose server, connection or client has
/// closed has nothing to act on, so it is failed and removed without a model call.
async fn task_target_gone(
    state: &AppState,
    scope: &crate::state::task::TaskScope,
) -> Option<String> {
    use crate::state::server::{ConnectionStatus, ServerStatus};
    use crate::state::task::TaskScope;

    match scope {
        TaskScope::Global => None,
        TaskScope::Server(sid) | TaskScope::Connection(sid, _) => {
            let Some(server) = state.get_server(*sid).await else {
                return Some(format!("server #{} no longer exists", sid.as_u32()));
            };
            if matches!(
                server.status,
                ServerStatus::Stopped | ServerStatus::Error(_)
            ) {
                return Some(format!("server #{} is {}", sid.as_u32(), server.status));
            }
            if let TaskScope::Connection(_, cid) = scope {
                match server.connections.get(cid) {
                    Some(conn) if conn.status == ConnectionStatus::Active => None,
                    _ => Some(format!(
                        "connection {} on server #{} has closed",
                        cid,
                        sid.as_u32()
                    )),
                }
            } else {
                None
            }
        }
        TaskScope::Client(cid) => match state.get_client(*cid).await {
            Some(_) => None,
            None => Some(format!("client #{} no longer exists", cid.as_u32())),
        },
    }
}

/// Execute a single task
async fn execute_single_task(
    state: AppState,
    llm_client: OllamaClient,
    status_tx: mpsc::UnboundedSender<String>,
    task: crate::state::ScheduledTask,
) {
    use crate::llm::prompt::PromptBuilder;
    use crate::state::task::{TaskExecutionResult, TaskScope, TaskStatus};

    let _ = status_tx.send(format!("[TASK] Executing task '{}'", task.name));

    if let Some(gone) = task_target_gone(&state, &task.scope).await {
        let error = format!("{gone}; the task was removed");
        let _ = status_tx.send(format!(
            "[ERROR] Task '{}' cannot run: {}",
            task.name, error
        ));
        tracing::warn!("Scheduled task '{}' cannot run: {}", task.name, error);
        let result = TaskExecutionResult {
            success: false,
            actions: Vec::new(),
            error: Some(error.clone()),
        };
        state.record_task_execution(task.id, &result).await;
        state
            .update_task_status(task.id, TaskStatus::Failed(error))
            .await;
        state.remove_task(task.id).await;
        return;
    }

    // What this task may do, computed once: the prompt advertises exactly `set.actions`, the
    // conversation validates against exactly `set.actions`, and `run_task_actions` routes the
    // model's answer by the same set.
    let set = PromptBuilder::task_action_set(&state, &task).await;
    let prompt = PromptBuilder::build_task_execution_prompt(&state, &task, &set).await;

    // Get current model, ensuring one is selected
    let model = match crate::llm::ensure_model_selected(
        state.get_ollama_model().await,
        &state.get_ollama_url().await,
    )
    .await
    {
        Ok(m) => m,
        Err(e) => {
            let error_msg = format!("Model selection failed: {}", e);
            let _ = status_tx.send(format!(
                "[ERROR] Failed to ensure model is selected for task execution: {}",
                e
            ));
            // Update task status to failed
            state
                .update_task_status(task.id, TaskStatus::Failed(error_msg.clone()))
                .await;
            let result = TaskExecutionResult {
                success: false,
                actions: Vec::new(),
                error: Some(error_msg),
            };
            state.record_task_execution(task.id, &result).await;
            return;
        }
    };

    // Register task as conversation
    let conversation_source = match &task.scope {
        TaskScope::Global => crate::state::app_state::ConversationSource::Task {
            task_name: task.name.clone(),
        },
        TaskScope::Server(server_id) => crate::state::app_state::ConversationSource::Task {
            task_name: format!("{}#{}", task.name, server_id.as_u32()),
        },
        TaskScope::Connection(server_id, conn_id) => {
            crate::state::app_state::ConversationSource::Task {
                task_name: format!("{}#{}/{}", task.name, server_id.as_u32(), conn_id),
            }
        }
        TaskScope::Client(client_id) => crate::state::app_state::ConversationSource::Task {
            task_name: format!("{}@{}", task.name, client_id.as_u32()),
        },
    };

    let truncated_instruction = crate::utils::truncate_for_log(&task.instruction, 27);

    // Get rate limiter for scheduled tasks (discards if rate limited)
    let rate_limiter = state.get_rate_limiter().await;

    // Create conversation handler with tracking
    let mut conversation = crate::llm::ConversationHandler::new(
        prompt.clone(),
        std::sync::Arc::new(llm_client.clone()),
        model.clone(),
        rate_limiter,
        crate::llm::RequestSource::Network, // Scheduled tasks are discarded if rate limited
    )
    .with_native_tools(&set.actions)
    .with_status_tx(status_tx.clone())
    .with_tracking(state.clone(), conversation_source, truncated_instruction);

    // Add empty user message to trigger generation
    conversation.add_user_message("Execute the task.".to_string());

    // Generate with conversation handler (handles tracking automatically)
    let web_search_mode = state.get_web_search_mode().await;
    let actions = match conversation
        .generate_with_tools_and_retry(
            state.get_web_approval_channel().await,
            web_search_mode,
            set.actions.clone(),
        )
        .await
    {
        Ok(actions) => actions,
        Err(e) => {
            // Execution failed
            let error = format!("LLM call failed: {}", e);
            let _ = status_tx.send(format!("[ERROR] Task '{}' failed: {}", task.name, error));

            let result = TaskExecutionResult {
                success: false,
                actions: Vec::new(),
                error: Some(error),
            };

            handle_task_failure(&state, &status_tx, task, result).await;
            return;
        }
    };

    let failures = run_task_actions(&state, &llm_client, &status_tx, &task, &set, &actions).await;

    if failures.is_empty() {
        let _ = status_tx.send(format!(
            "[TASK] Task '{}' completed successfully ({} action(s))",
            task.name,
            actions.len()
        ));
        let result = TaskExecutionResult {
            success: true,
            actions,
            error: None,
        };
        handle_task_success(&state, &status_tx, task, result).await;
    } else {
        let error = format!(
            "{} of {} action(s) failed: {}",
            failures.len(),
            actions.len(),
            failures.join("; ")
        );
        let verdict = if failures.len() < actions.len() {
            "partly failed"
        } else {
            "failed"
        };
        let _ = status_tx.send(format!(
            "[ERROR] Task '{}' {}: {}",
            task.name, verdict, error
        ));
        tracing::error!("Scheduled task '{}' {}: {}", task.name, verdict, error);
        let result = TaskExecutionResult {
            success: false,
            actions,
            error: Some(error),
        };
        handle_task_failure(&state, &status_tx, task, result).await;
    }
}

/// Execute the model's answer to a task, in order, each action where it can actually run,
/// and return one `"<action>: <error>"` line per action that did not.
///
/// - The instance's protocol actions run inside the instance — `send_to_peer` for a server
///   or connection, `send_to_client` for a client — so their bytes reach the wire. Executing
///   them anywhere else produces output nobody writes.
/// - `show_message` goes to the status stream, named after the task.
/// - A global task's operator actions (open/close/update servers and clients, tasks,
///   databases) run through the same executor the operator's own commands use.
/// - Memory and log actions run through `execute_actions` with the task's instance as
///   context.
async fn run_task_actions(
    state: &AppState,
    llm_client: &OllamaClient,
    status_tx: &mpsc::UnboundedSender<String>,
    task: &crate::state::ScheduledTask,
    set: &crate::llm::prompt::TaskActionSet,
    actions: &[serde_json::Value],
) -> Vec<String> {
    use crate::llm::actions::common::CommonAction;
    use crate::state::task::TaskScope;

    let (server_id, client_id) = match &task.scope {
        TaskScope::Server(sid) | TaskScope::Connection(sid, _) => (Some(*sid), None),
        TaskScope::Client(cid) => (None, Some(*cid)),
        TaskScope::Global => (None, None),
    };

    let mut failures = Vec::new();
    for action in actions {
        let name = action
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();

        if set.protocol_actions.contains(&name) {
            match inject_protocol_action(state, task, set, &name, action.clone()).await {
                Ok(detail) => {
                    let _ =
                        status_tx.send(format!("[TASK] Task '{}': {} {}", task.name, name, detail));
                }
                Err(e) => failures.push(format!("{name}: {e}")),
            }
            continue;
        }

        if name == "show_message" {
            let message = action
                .get("message")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            let _ = status_tx.send(format!("[TASK] {}: {}", task.name, message));
            continue;
        }

        if matches!(task.scope, TaskScope::Global) {
            match CommonAction::from_json(action) {
                Ok(common) => {
                    let mut handler =
                        crate::events::EventHandler::new(state.clone(), llm_client.clone());
                    if let Err(e) = handler
                        .execute_server_management_action(common, status_tx)
                        .await
                    {
                        failures.push(format!("{name}: {e}"));
                    }
                }
                Err(e) => failures.push(format!("{name}: {e}")),
            }
            continue;
        }

        match crate::llm::execute_actions(vec![action.clone()], state, None, server_id, client_id)
            .await
        {
            Ok(result) => {
                for msg in result.messages {
                    let _ = status_tx.send(msg);
                }
                for failure in result.failures {
                    failures.push(format!("{}: {}", failure.action, failure.error));
                }
            }
            Err(e) => failures.push(format!("{name}: {e}")),
        }
    }
    failures
}

/// Run one protocol action inside the task's instance and describe what happened.
async fn inject_protocol_action(
    state: &AppState,
    task: &crate::state::ScheduledTask,
    set: &crate::llm::prompt::TaskActionSet,
    name: &str,
    mut action: serde_json::Value,
) -> anyhow::Result<String> {
    use crate::state::client_handles::ClientSendOutcome;
    use crate::state::task::TaskScope;

    let outcome = match &task.scope {
        TaskScope::Client(cid) => state.send_to_client(*cid, action, INJECT_TIMEOUT).await?,
        TaskScope::Connection(sid, cid) => {
            state
                .send_to_peer(*sid, cid.as_u32(), action, INJECT_TIMEOUT)
                .await?
        }
        TaskScope::Server(sid) => {
            let connection_id = action
                .get("connection_id")
                .and_then(parse_connection_id)
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "`connection_id` is required and must be one of {:?}",
                        set.peer_connections
                    )
                })?;
            if !set.peer_connections.contains(&connection_id) {
                anyhow::bail!(
                    "connection {} does not accept actions; use one of {:?}",
                    connection_id,
                    set.peer_connections
                );
            }
            if set.routing_only_connection_id.contains(name) {
                if let Some(obj) = action.as_object_mut() {
                    obj.remove("connection_id");
                }
            }
            state
                .send_to_peer(*sid, connection_id, action, INJECT_TIMEOUT)
                .await?
        }
        TaskScope::Global => anyhow::bail!("a global task has no instance to run it in"),
    };
    match outcome {
        ClientSendOutcome::Sent { bytes_sent } => Ok(format!("sent {bytes_sent} byte(s)")),
        ClientSendOutcome::Executed { detail } => Ok(format!("executed ({detail})")),
        ClientSendOutcome::Disconnected => Ok("executed; the connection is closed".to_string()),
        ClientSendOutcome::Rejected { error } => {
            anyhow::bail!("the protocol rejected the action: {error}")
        }
    }
}

/// A connection id as the model may write it: `3`, `"3"` or `"conn-3"`.
fn parse_connection_id(value: &serde_json::Value) -> Option<u32> {
    if let Some(n) = value.as_u64() {
        return u32::try_from(n).ok();
    }
    let s = value.as_str()?.trim();
    s.strip_prefix("conn-").unwrap_or(s).parse().ok()
}

/// Handle task success
async fn handle_task_success(
    state: &AppState,
    status_tx: &mpsc::UnboundedSender<String>,
    task: crate::state::ScheduledTask,
    result: crate::state::TaskExecutionResult,
) {
    use crate::state::task::{TaskStatus, TaskType};

    // Record execution
    state.record_task_execution(task.id, &result).await;

    match &task.task_type {
        TaskType::OneShot { .. } => {
            // One-shot task completed
            state
                .update_task_status(task.id, TaskStatus::Completed)
                .await;
            state.remove_task(task.id).await;
            let _ = status_tx.send(format!(
                "[TASK] One-shot task '{}' completed and removed",
                task.name
            ));
        }
        TaskType::Recurring {
            interval_secs,
            max_executions,
            executions_count,
        } => {
            // This snapshot predates record_task_execution above. Include the run
            // that just completed, or max_executions=1 schedules a second run.
            if let Some(max) = max_executions {
                if executions_count.saturating_add(1) >= *max {
                    state
                        .update_task_status(task.id, TaskStatus::Completed)
                        .await;
                    state.remove_task(task.id).await;
                    let _ = status_tx.send(format!(
                        "[TASK] Recurring task '{}' reached max executions ({}) and removed",
                        task.name, max
                    ));
                    return;
                }
            }

            // Schedule next execution
            let next = match crate::state::task::checked_task_deadline(*interval_secs) {
                Ok(next) => next,
                Err(error) => {
                    state
                        .update_task_status(task.id, TaskStatus::Failed(error.to_string()))
                        .await;
                    let _ = status_tx.send(format!("[ERROR] Task '{}': {}", task.name, error));
                    return;
                }
            };
            state.update_task_next_execution(task.id, next).await;
            state
                .update_task_status(task.id, TaskStatus::Scheduled)
                .await;
        }
    }
}

/// Handle task failure with exponential backoff retry
async fn handle_task_failure(
    state: &AppState,
    status_tx: &mpsc::UnboundedSender<String>,
    task: crate::state::ScheduledTask,
    result: crate::state::TaskExecutionResult,
) {
    use crate::state::task::TaskStatus;

    const MAX_FAILURES: u64 = 5;
    const BACKOFF_BASE_SECS: u64 = 60; // 1 minute base backoff

    // Record execution
    state.record_task_execution(task.id, &result).await;

    let failure_count = task.failure_count.saturating_add(1);

    if failure_count >= MAX_FAILURES {
        // Too many failures, disable task
        state
            .update_task_status(
                task.id,
                TaskStatus::Failed(result.error.unwrap_or_else(|| "Unknown error".to_string())),
            )
            .await;
        state.remove_task(task.id).await;
        let _ = status_tx.send(format!(
            "[ERROR] Task '{}' failed {} times, removing from schedule",
            task.name, MAX_FAILURES
        ));
    } else {
        // Retry with exponential backoff
        let backoff_secs = BACKOFF_BASE_SECS * 2u64.pow((failure_count - 1) as u32);
        let next = match crate::state::task::checked_task_deadline(backoff_secs) {
            Ok(next) => next,
            Err(error) => {
                state
                    .update_task_status(task.id, TaskStatus::Failed(error.to_string()))
                    .await;
                return;
            }
        };

        state.update_task_next_execution(task.id, next).await;
        state
            .update_task_status(task.id, TaskStatus::Scheduled)
            .await;

        let _ = status_tx.send(format!(
            "[WARN] Task '{}' failed (attempt {}/{}), retrying in {} seconds",
            task.name, failure_count, MAX_FAILURES, backoff_secs
        ));
    }
}

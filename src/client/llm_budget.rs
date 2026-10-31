//! Per-client LLM call budget.
//!
//! Every client protocol drives its own event loop: an event arrives, the loop
//! calls the model, executes the returned actions, and those actions may produce
//! another event. Nothing in that shape guarantees convergence — a handler that
//! always answers "issue another request" loops until the process dies. That is
//! not hypothetical: the DNS client made 211 model calls and then overflowed the
//! stack (`IMPROVEMENTS.md` item 49).
//!
//! Servers are protected by the per-connection Idle/Processing/Accumulating state
//! machine, which prevents re-entrancy. Clients have no equivalent, so this module
//! provides the backstop instead: a hard ceiling on LLM calls per client session,
//! enforced in one place.
//!
//! ## How it is applied
//!
//! [`call_llm_for_client`] here is a drop-in replacement for
//! [`crate::llm::action_helper::call_llm_for_client`] with an identical signature.
//! Client protocols import this one:
//!
//! ```ignore
//! use crate::client::llm_budget::call_llm_for_client;
//! ```
//!
//! Once the budget is exhausted the call returns `Err` with an explanatory message
//! instead of contacting the model, which every existing call site already logs.
//! A protocol that wants to fail louder can match on the error.
//!
//! The cap is `AppState::DEFAULT_CLIENT_LLM_CALL_LIMIT` (100), overridable at
//! runtime via `NETGET_CLIENT_LLM_CALL_LIMIT` (`0` = unlimited) or
//! `AppState::set_client_llm_call_limit()`.

use anyhow::Result;
use tokio::sync::mpsc;
use tracing::{debug, error, warn};

use crate::llm::actions::client_trait::Client;
use crate::llm::ollama_client::OllamaClient;
use crate::llm::ClientLlmResult;
use crate::protocol::Event;
use crate::state::app_state::AppState;
use crate::state::ClientId;

/// Fraction of the budget after which each call emits a warning.
const WARN_AT_PERCENT: u32 = 80;

/// Budget-checked wrapper around [`crate::llm::action_helper::call_llm_for_client`].
///
/// Consumes one unit of the calling client's LLM call budget and fails without
/// contacting the model once that budget is exhausted. See the module docs.
///
/// ## Event-handler routing lives here
///
/// This wrapper is the single choke point every client protocol calls, so the
/// client's configured `event_handlers` (script / static / per-event LLM
/// instruction) are dispatched **here**, before the budget debit — a
/// deterministic handler answers without contacting the model and without
/// consuming budget, which is the budget's whole point (it bounds *model*
/// calls). Anything calling `action_helper::call_llm_for_client` directly
/// bypasses both the budget and this routing.
///
/// Only events route (`event: Some`); the initial-instruction call
/// (`event: None`) has nothing to match a pattern against.
#[allow(clippy::too_many_arguments)]
pub async fn call_llm_for_client(
    llm_client: &OllamaClient,
    state: &AppState,
    client_id: String,
    instruction: &str,
    memory: &str,
    event: Option<&Event>,
    protocol: &dyn Client,
    status_tx: &mpsc::UnboundedSender<String>,
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
    let offered_actions =
        crate::llm::actions::client_trait::client_llm_action_set(protocol, state, event);
    let private_payloads = crate::utils::redact::actions_have_credentials(&offered_actions)
        || event.is_some_and(|event| crate::utils::redact::contains_credentials(&event.data));
    let run = call_llm_for_client_inner(
        llm_client,
        state,
        client_id,
        instruction,
        memory,
        event,
        &[],
        protocol,
        status_tx,
        offered_actions,
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

/// Answer several events from one client session — the ones that arrived while the model was
/// still answering an earlier one — in a single model call, when the client batches.
///
/// The client-side twin of `crate::llm::action_helper::call_llm_batch`: the newest event is
/// the trigger, the earlier ones are listed above it as arrived and not yet answered, and one
/// [`ClientLlmResult`] carries the model's actions for all of them, in its order. One budget
/// unit is spent, and every event is recorded in the access log and the session's history.
///
/// Falls back to answering the events one by one, in arrival order, with their actions
/// concatenated, when the client has batching off or any event is routed to a script, static
/// or manual rule — a rule decides its own event, and folding it into a model call would hand
/// the model a decision that was not its.
#[allow(clippy::too_many_arguments)]
pub async fn call_llm_for_client_batch(
    llm_client: &OllamaClient,
    state: &AppState,
    client_id: String,
    instruction: &str,
    memory: &str,
    events: &[Event],
    protocol: &dyn Client,
    status_tx: &mpsc::UnboundedSender<String>,
) -> Result<ClientLlmResult> {
    let Some((last, earlier)) = events.split_last() else {
        return Ok(ClientLlmResult {
            actions: Vec::new(),
            memory_updates: None,
        });
    };
    let ids: Vec<&str> = events.iter().map(|e| e.id()).collect();
    let one_call = !earlier.is_empty()
        && match ClientId::from_string(&client_id) {
            Some(cid) => {
                crate::llm::action_helper::client_batch_goes_to_the_model(state, cid, &ids).await
            }
            None => false,
        };
    if !one_call {
        let mut combined = ClientLlmResult {
            actions: Vec::new(),
            memory_updates: None,
        };
        for event in events {
            let result = call_llm_for_client(
                llm_client,
                state,
                client_id.clone(),
                instruction,
                memory,
                Some(event),
                protocol,
                status_tx,
            )
            .await?;
            combined.actions.extend(result.actions);
            if result.memory_updates.is_some() {
                combined.memory_updates = result.memory_updates;
            }
        }
        return Ok(combined);
    }

    for event in earlier {
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
    let mut offered_actions =
        crate::llm::actions::client_trait::client_llm_action_set(protocol, state, Some(last));
    for event in earlier {
        for action in
            crate::llm::actions::client_trait::client_llm_action_set(protocol, state, Some(event))
        {
            if !offered_actions.iter().any(|a| a.name == action.name) {
                offered_actions.push(action);
            }
        }
    }
    let private_payloads = crate::utils::redact::actions_have_credentials(&offered_actions)
        || events
            .iter()
            .any(|event| crate::utils::redact::contains_credentials(&event.data));
    let run = call_llm_for_client_inner(
        llm_client,
        state,
        client_id,
        instruction,
        memory,
        Some(last),
        earlier,
        protocol,
        status_tx,
        offered_actions,
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
    earlier: &[Event],
    protocol: &dyn Client,
    status_tx: &mpsc::UnboundedSender<String>,
    offered_actions: Vec<crate::llm::actions::ActionDefinition>,
    private_payloads: bool,
) -> Result<ClientLlmResult> {
    use crate::llm::action_helper::split_client_common_actions;
    use crate::llm::event_handler_executor::{
        try_execute_client_event_handler_with_privacy, ClientEventHandlerResult,
        HANDLER_INSTRUCTION_HEADER,
    };

    // Deterministic script/static routing, before any budget or model involvement.
    let mut handler_instruction: Option<String> = None;
    if let (Some(cid), Some(ev)) = (ClientId::from_string(&client_id), event) {
        match try_execute_client_event_handler_with_privacy(
            state,
            cid,
            ev.id(),
            &ev.event_type.description,
            Some(ev.data.clone()),
            private_payloads,
        )
        .await
        .map_err(|e| {
            if private_payloads {
                crate::utils::redact::hide_error_details(e)
            } else {
                e
            }
        }) {
            Ok(ClientEventHandlerResult::Handled { actions }) => {
                // Common actions (provide_feedback) are executed centrally,
                // mirroring the LLM path below; the protocol actions go back
                // to the client's loop.
                let (common_actions, protocol_actions) = split_client_common_actions(actions);
                if !common_actions.is_empty() {
                    if let Err(e) = crate::llm::actions::executor::execute_actions(
                        common_actions,
                        state,
                        None,
                        None,
                        Some(cid),
                    )
                    .await
                    {
                        warn!("Client common action execution failed: {}", e);
                    }
                }
                state
                    .record_access_log_answered(
                        crate::state::AccessLogOwner::Client(cid.as_u32()),
                        protocol.protocol_name(),
                        None,
                        ev.id(),
                        ev.data.clone(),
                        protocol_actions
                            .iter()
                            .map(|action| {
                                access_log_action(action, private_payloads, &offered_actions)
                            })
                            .collect(),
                        crate::state::app_state::answered_by::RULE,
                    )
                    .await;
                let _ = status_tx.send("__UPDATE_UI__".to_string());
                return Ok(ClientLlmResult {
                    actions: protocol_actions,
                    memory_updates: None,
                });
            }
            Ok(ClientEventHandlerResult::FallbackToLlm { instruction }) => {
                handler_instruction = instruction;
            }
            Err(e) => {
                // An unresolvable static reference is a hard error, same as the
                // server path — a typo'd field name must not look like it works.
                error!(
                    "Client {} event handler for '{}' failed: {}",
                    client_id,
                    ev.id(),
                    e
                );
                let _ = status_tx.send(format!(
                    "[CLIENT] ✖ client {} event handler for '{}' failed: {}",
                    client_id,
                    ev.id(),
                    e
                ));
                return Err(e);
            }
        }
    }

    // A memoised answer, when the client memoises: the model's answer to an identical event
    // within the TTL, re-rendered for this one, before any budget is spent. Never for a batch
    // or a credential-bearing event.
    let memo = match (ClientId::from_string(&client_id), event) {
        (Some(cid), Some(_)) if earlier.is_empty() && !private_payloads => {
            state.client_memo(cid).await
        }
        _ => None,
    };
    let memo_key = match (&memo, event) {
        (Some(memo), Some(ev)) => {
            memo.key_for(ev.id(), &ev.data, None, handler_instruction.as_deref())
        }
        _ => None,
    };
    if let (Some(memo), Some(key), Some(ev), Some(cid)) =
        (&memo, &memo_key, event, ClientId::from_string(&client_id))
    {
        if let Some(actions) = memo.memo.get(key, &ev.data) {
            debug!(
                "Answered client {} event '{}' from the memo (no model call)",
                client_id,
                ev.id()
            );
            state
                .record_access_log_answered(
                    crate::state::AccessLogOwner::Client(cid.as_u32()),
                    protocol.protocol_name(),
                    None,
                    ev.id(),
                    ev.data.clone(),
                    actions
                        .iter()
                        .map(|action| access_log_action(action, private_payloads, &offered_actions))
                        .collect(),
                    crate::state::app_state::answered_by::CACHE,
                )
                .await;
            let _ = status_tx.send("__UPDATE_UI__".to_string());
            return Ok(ClientLlmResult {
                actions,
                memory_updates: None,
            });
        }
    }

    // Per-event LLM instruction from an `{"type":"llm"}` handler augments the
    // client-wide instruction for this one call.
    let composed_instruction = handler_instruction
        .map(|extra| format!("{instruction}\n\n{HANDLER_INSTRUCTION_HEADER}: {extra}"));
    let instruction = composed_instruction.as_deref().unwrap_or(instruction);

    if let Some(cid) = ClientId::from_string(&client_id) {
        match state.try_consume_client_llm_call(cid).await {
            Ok(used) => {
                let limit = state.get_client_llm_call_limit().await;
                if limit > 0
                    && u64::from(used) * 100 >= u64::from(limit) * u64::from(WARN_AT_PERCENT)
                {
                    warn!(
                        "Client {} has used {}/{} of its LLM call budget",
                        cid, used, limit
                    );
                    let _ = status_tx.send(format!(
                        "[CLIENT] ⚠ client {} has used {}/{} LLM calls",
                        cid, used, limit
                    ));
                }
            }
            Err(msg) => {
                error!("{}", msg);
                let _ = status_tx.send(format!("[CLIENT] ✖ {}", msg));
                return Err(anyhow::anyhow!(msg));
            }
        }
    }

    let result = crate::llm::action_helper::call_llm_for_client_with_earlier(
        llm_client,
        state,
        client_id.clone(),
        instruction,
        memory,
        event,
        earlier,
        protocol,
        status_tx,
    )
    .await?;

    // Record the event and the actions the model produced, mirroring the
    // server-side access log. Client entries record *produced* actions —
    // execution happens later in the client's own loop, which does not report
    // back here.
    if let (Some(cid), Some(ev)) = (ClientId::from_string(&client_id), event) {
        // A batch is recorded event by event; the answer sits with the last, the others say
        // they were answered together with it — as on the server side.
        for earlier_event in earlier {
            state
                .record_access_log_answered(
                    crate::state::AccessLogOwner::Client(cid.as_u32()),
                    protocol.protocol_name(),
                    None,
                    earlier_event.id(),
                    earlier_event.data.clone(),
                    vec![serde_json::json!({
                        "type": crate::state::exchange_history::ANSWERED_WITH_NEXT
                    })],
                    crate::state::app_state::answered_by::MODEL,
                )
                .await;
        }
        state
            .record_access_log_answered(
                crate::state::AccessLogOwner::Client(cid.as_u32()),
                protocol.protocol_name(),
                None,
                ev.id(),
                ev.data.clone(),
                result
                    .actions
                    .iter()
                    .map(|action| access_log_action(action, private_payloads, &offered_actions))
                    .collect(),
                crate::state::app_state::answered_by::MODEL,
            )
            .await;
    }

    // Memoise the model's answer. An answer that also changed the client's memory is not
    // kept: replaying it would answer without making that change.
    if let (Some(memo), Some(key), Some(ev)) = (memo, memo_key, event) {
        if result.memory_updates.is_none() {
            memo.memo.put(key, &ev.data, &result.actions);
        }
    }

    Ok(result)
}

fn access_log_action(
    action: &serde_json::Value,
    private_payloads: bool,
    offered_actions: &[crate::llm::actions::ActionDefinition],
) -> serde_json::Value {
    if !private_payloads {
        return crate::utils::redact::redact_sensitive(action);
    }
    // A handler can copy a credential into any parameter or an invalid type.
    // Record only a name from the already-offered definitions, keeping the
    // original action untouched for execution and explicit display actions.
    match action["type"].as_str().filter(|name| {
        offered_actions
            .iter()
            .any(|definition| definition.name == *name)
    }) {
        Some(name) => serde_json::json!({"type":name}),
        None => serde_json::json!({}),
    }
}

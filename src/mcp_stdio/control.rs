//! The vocabularies behind the MCP control tools — `send_to_client`, `send_to_peer`,
//! `answer_intercept` — and the checks that hold an injected action to them.
//!
//! Each tool wraps an `AppState` method the dashboard already drives
//! (`send_to_client`, `send_to_peer`, `resolve_intercept`, `dismiss_intercept`). What the
//! tools add is validation **before** anything is handed to a running loop: an action whose
//! `type` the target cannot execute is refused here with the list of names it can, rather than
//! travelling into the connection task and coming back as an executor error — or, for a parked
//! request, being executed as the answer and failing after the peer has already been waiting.
//!
//! The sets are derived exactly as the dashboard derives the composer's list, so the MCP
//! surface and the TUI agree about what may be sent where:
//!
//! - **client**: [`client_llm_action_set`] — async ∪ sync, the union the model is shown
//!   (clients have one LLM entry point, so their split is vestigial; see that function).
//! - **server peer**: the server protocol's sync ∪ async actions.
//! - **parked request**: what the model would be offered for the same event — a server
//!   event's own declared actions (the protocol's sync set only where the event declares
//!   none), a client's async ∪ sync ∪ the event's — plus the common actions every protocol
//!   accepts. See `crate::state::intercepts::server_answer_actions`.

use crate::llm::actions::client_trait::client_llm_action_set;
use crate::llm::actions::ActionDefinition;
use crate::state::app_state::AppState;
use crate::state::client_handles::ClientSendOutcome;
use crate::state::intercepts::{InterceptOwner, InterceptView};

/// Append `extra` to `out`, skipping names already present (first occurrence wins).
fn union_into(out: &mut Vec<ActionDefinition>, extra: Vec<ActionDefinition>) {
    for action in extra {
        if !out.iter().any(|a| a.name == action.name) {
            out.push(action);
        }
    }
}

/// The actions `send_to_client` may inject into a running client of `protocol_name`.
pub fn client_vocabulary(
    state: &AppState,
    protocol_name: &str,
) -> Result<Vec<ActionDefinition>, String> {
    let protocol = crate::cli::client_startup::resolve_client_protocol(protocol_name)
        .and_then(|name| crate::protocol::CLIENT_REGISTRY.get(&name))
        .ok_or_else(|| format!("client protocol '{protocol_name}' is not compiled in"))?;
    Ok(client_llm_action_set(protocol.as_ref(), state, None))
}

/// The actions `send_to_peer` may inject into one live connection of a `protocol_name` server.
pub fn peer_vocabulary(
    state: &AppState,
    protocol_name: &str,
) -> Result<Vec<ActionDefinition>, String> {
    let protocol = crate::protocol::server_registry::registry()
        .resolve(protocol_name)
        .map_err(|e| e.to_string())?;
    let mut actions = protocol.get_sync_actions();
    union_into(&mut actions, protocol.get_async_actions(state));
    Ok(actions)
}

/// The protocol a parked request belongs to, and the actions it may be answered with.
///
/// The set is [`crate::state::intercepts::server_answer_actions`] /
/// [`crate::state::intercepts::client_answer_actions`] — what the model would be offered for
/// the same event — so `list_intercepts` offers, `answer_intercept` accepts and the dashboard's
/// composer lists one and the same vocabulary.
///
/// `Err` when the owning instance is gone (the request is then no longer answerable anyway).
pub async fn intercept_vocabulary(
    state: &AppState,
    view: &InterceptView,
) -> Result<(String, Vec<ActionDefinition>), String> {
    match view.owner {
        InterceptOwner::Server(server_id) => {
            let server = state
                .get_server(server_id)
                .await
                .ok_or_else(|| format!("server #{} no longer exists", server_id.as_u32()))?;
            crate::protocol::server_registry::registry()
                .resolve(&server.protocol_name)
                .map_err(|e| e.to_string())?;
            let actions = crate::state::intercepts::server_answer_actions(
                &server.protocol_name,
                &view.event_type,
            );
            Ok((server.protocol_name, actions))
        }
        InterceptOwner::Client(client_id) => {
            let client = state
                .get_client(client_id)
                .await
                .ok_or_else(|| format!("client #{} no longer exists", client_id.as_u32()))?;
            crate::cli::client_startup::resolve_client_protocol(&client.protocol_name)
                .and_then(|name| crate::protocol::CLIENT_REGISTRY.get(&name))
                .ok_or_else(|| {
                    format!(
                        "client protocol '{}' is not compiled in",
                        client.protocol_name
                    )
                })?;
            let actions = crate::state::intercepts::client_answer_actions(
                &client.protocol_name,
                state,
                &view.event_type,
            );
            Ok((client.protocol_name, actions))
        }
    }
}

/// Refuse any action whose `type` is not in `allowed` (or `also_allowed`).
///
/// The error names the offending action and lists every accepted name, so a caller can
/// correct it in one step.
pub fn check_action_types(
    actions: &[serde_json::Value],
    allowed: &[ActionDefinition],
    also_allowed: &[&str],
) -> Result<(), String> {
    for (index, action) in actions.iter().enumerate() {
        let Some(object) = action.as_object() else {
            return Err(format!(
                "action {index} is not a JSON object: {action}. Each action is \
                 {{\"type\": \"<name>\", ...parameters}}."
            ));
        };
        let Some(name) = object.get("type").and_then(|t| t.as_str()) else {
            return Err(format!(
                "action {index} has no string \"type\" field naming the action: {action}"
            ));
        };
        if allowed.iter().any(|a| a.name == name) || also_allowed.contains(&name) {
            continue;
        }
        let mut names: Vec<&str> = allowed.iter().map(|a| a.name.as_str()).collect();
        names.extend(also_allowed.iter().copied());
        return Err(format!(
            "'{name}' is not an action this target accepts. Accepted: {}",
            if names.is_empty() {
                "(none — the protocol declares no actions here)".to_string()
            } else {
                names.join(", ")
            }
        ));
    }
    Ok(())
}

/// One-line signature of an action: `send_tcp_data(data*, encoding)` — `*` marks required.
pub fn action_signature(action: &ActionDefinition) -> String {
    let params: Vec<String> = action
        .parameters
        .iter()
        .map(|p| {
            if p.required {
                format!("{}*", p.name)
            } else {
                p.name.clone()
            }
        })
        .collect();
    format!("{}({})", action.name, params.join(", "))
}

/// A `ClientSendOutcome` as the sentence a tool result carries.
pub fn describe_outcome(outcome: &ClientSendOutcome) -> String {
    match outcome {
        ClientSendOutcome::Sent { bytes_sent } => {
            format!("sent {bytes_sent} byte(s) on the wire")
        }
        ClientSendOutcome::Probed { bytes_sent, report } => format!(
            "sent {bytes_sent} byte(s) on the wire; replies:\n{}",
            serde_json::to_string_pretty(report).unwrap_or_else(|_| report.to_string())
        ),
        ClientSendOutcome::Executed { detail } => {
            format!("executed, nothing written to the wire ({detail})")
        }
        ClientSendOutcome::Rejected { error } => format!("rejected by the protocol: {error}"),
        ClientSendOutcome::Disconnected => {
            "the connection is closed (the action asked to disconnect, or the loop had already \
             exited)"
                .to_string()
        }
    }
}

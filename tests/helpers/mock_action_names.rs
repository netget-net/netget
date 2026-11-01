//! Reject mock rules that answer an event with an action the protocol cannot execute.
//!
//! Three suites have now been found mocking an action name belonging to a *different*
//! protocol (`send_jsonrpc_response` in the MCP tests, `send_token_response` in the OAuth2
//! tests, `write_file` in the HTTP tests). In each case the server rejected the action as
//! unknown, answered with its fallback, and the test either failed for an opaque reason or
//! — worse — passed, because its assertions accepted the fallback.
//!
//! `0069d90c` added exactly this check for `event_handlers` at `start_server` time. This is
//! the same check applied to mock rules, so the class is caught in tests too. The catalog is
//! read from the same registries the server uses, and the test binary is compiled with the
//! same feature set as the `netget` binary it drives, so the two see the same protocols.
//!
//! Deliberately *not* validated:
//! - rules that do not match on an event id (`on_instruction_containing`, `on_any`, …):
//!   those answer a user command, where the vocabulary is the common actions;
//! - `respond_with_actions_from_event`, whose actions are built by a closure at runtime;
//! - event ids no compiled protocol declares — the protocol is simply not in this build,
//!   so there is no catalog to check against and guessing would produce false failures.

use std::collections::BTreeSet;

/// Common action names the executor handles itself, valid for every protocol.
///
/// Mirrors `COMMON_ACTION_NAMES` in `src/events/handler.rs`. Kept as a local list because
/// that one is private; if it gains a variant this list needs the same one, and the
/// symptom of forgetting is a spurious "unknown action" in a test rather than silence.
const COMMON_ACTION_NAMES: &[&str] = &[
    "notify_operator",
    // notify_operator's former name, still accepted
    "show_message",
    "set_connection_memory",
    "append_connection_memory",
    "open_server",
    "close_server",
    "close_all_servers",
    "open_client",
    "close_client",
    "close_all_clients",
    "close_connection_by_id",
    "reconnect_client",
    "update_client_instruction",
    "update_instruction",
    "change_model",
    "set_memory",
    "append_memory",
    "append_to_log",
    "schedule_task",
    "cancel_task",
    "provide_feedback",
    #[cfg(feature = "sqlite")]
    "create_database",
    #[cfg(feature = "sqlite")]
    "delete_database",
];

/// `get_async_actions` takes an `AppState`, and building one probes the machine's scripting
/// environments. Do it at most once per test binary, and only when a client protocol
/// actually declares the event being checked.
fn client_app_state() -> &'static netget::state::app_state::AppState {
    static STATE: std::sync::OnceLock<netget::state::app_state::AppState> =
        std::sync::OnceLock::new();
    STATE.get_or_init(netget::state::app_state::AppState::new)
}

/// Every action name a protocol declaring `event_id` can execute, plus the protocol names
/// that contributed. An empty name set means no compiled protocol declares the event.
fn catalog_for_event(event_id: &str) -> (BTreeSet<String>, Vec<String>) {
    let mut names: BTreeSet<String> = COMMON_ACTION_NAMES
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    let mut scopes: BTreeSet<String> = BTreeSet::new();

    // A protocol contributes its protocol-wide sync actions plus the actions the matching
    // event type advertises itself — the same union `action_catalog_for_pattern` builds.
    for (_, protocol) in netget::protocol::server_registry::registry().all_protocols() {
        let event_types = protocol.get_event_types();
        let matching: Vec<_> = event_types.iter().filter(|et| et.id == event_id).collect();
        if matching.is_empty() {
            continue;
        }
        scopes.insert(protocol.protocol_name().to_string());
        names.extend(protocol.get_sync_actions().into_iter().map(|a| a.name));
        for event_type in matching {
            names.extend(event_type.actions.iter().map(|a| a.name.clone()));
        }
    }

    for protocol in netget::protocol::client_registry::CLIENT_REGISTRY.get_all() {
        let event_types = protocol.get_event_types();
        let matching: Vec<_> = event_types.iter().filter(|et| et.id == event_id).collect();
        if matching.is_empty() {
            continue;
        }
        scopes.insert(protocol.protocol_name().to_string());
        names.extend(protocol.get_sync_actions().into_iter().map(|a| a.name));
        // Client protocols are not consistent about which list a response action lives in —
        // the Redis client puts `disconnect` in `get_async_actions` and `execute_action`
        // accepts it either way — so both lists count, or the check would produce false
        // failures on actions the client can perfectly well execute.
        names.extend(
            protocol
                .get_async_actions(client_app_state())
                .into_iter()
                .map(|a| a.name),
        );
        for event_type in matching {
            names.extend(event_type.actions.iter().map(|a| a.name.clone()));
        }
    }

    if scopes.is_empty() {
        return (BTreeSet::new(), Vec::new());
    }
    (names, scopes.into_iter().collect())
}

/// Panic if any of `actions` names something no protocol declaring `event_id` can execute.
///
/// Panicking rather than returning an error is deliberate: this runs while a test is being
/// *configured*, long before any assertion, and the failure is always a defect in the test
/// itself. A silent skip is what let three suites ship a mock the server could never obey.
pub fn assert_actions_valid_for_event(event_id: &str, actions: &[serde_json::Value]) {
    let (catalog, scopes) = catalog_for_event(event_id);
    if catalog.is_empty() {
        // The protocol declaring this event is not compiled into this build.
        return;
    }

    for action in actions {
        let Some(name) = action.get("type").and_then(|v| v.as_str()) else {
            panic!("Mock action for event '{event_id}' has no \"type\" field: {action}");
        };
        if catalog.contains(name) {
            continue;
        }

        let valid: Vec<&str> = catalog.iter().map(|s| s.as_str()).collect();
        panic!(
            "Mock rule for event '{}' returns action \"{}\", which {} cannot execute.\n\
             The server will reject it as unknown and answer with its fallback, so this \
             mock proves nothing.\n\
             Valid actions for {}: {}",
            event_id,
            name,
            scopes.join(", "),
            scopes.join(", "),
            valid.join(", "),
        );
    }
}

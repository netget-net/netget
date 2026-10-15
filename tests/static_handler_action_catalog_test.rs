//! `event_handlers` validation must offer a **client** the same vocabulary the model gets,
//! and must keep holding a **server** to its narrowed one.
//!
//! `events::handler::action_catalog_for_pattern` decides, at `start_server` / `start_client`
//! time, which action names a `{"type": "static", …}` handler may use. It built that catalog
//! from `get_sync_actions()` plus the matching event types' own actions and never read
//! `get_async_actions()` — which is the same defect `client_llm_action_set` was written to fix
//! one layer over, where `call_llm_for_client` built the *model's* tool list from
//! `get_async_actions()` alone and 53 of 91 clients had an action the model could never see.
//!
//! The consequence was that a client declaring a verb async-only could not be routed
//! deterministically at all: WHOIS's own documented static-mode startup example —
//! `{"event_pattern": "whois_connected", "handler": {"type": "static", "actions":
//! [{"type": "query_whois", …}]}}` — was rejected at startup as an unknown action. Protocols
//! worked around it one at a time by repeating their async list into `get_sync_actions()`.
//!
//! The rule, and the asymmetry these tests pin:
//!
//! * **A client's catalog is the union** (`client_action_names_for_pattern` = async ∪ sync ∪
//!   the matching events' own actions). A client has one LLM entry point — `call_llm_for_client`
//!   serves both the initial instruction and every network event — so no client *can* express a
//!   narrowing, and a verb the model may use but a static handler may not is a distinction
//!   nothing in the client means.
//! * **A server's catalog stays narrowed** to sync ∪ the matching events' actions. A server has
//!   two entry points, so its async/sync split is a real statement: TCP's `close_connection`
//!   takes a `connection_id` and is a user-driven action against the server, while the verb for
//!   hanging up on the peer whose event this is, is `close_this_connection`. A handler answering
//!   an event is in the sync position and is held to the sync vocabulary. Widening it would be
//!   the tempting "fix" and is the wrong one.

use netget::events::handler::EventHandler;
use netget::llm::actions::client_trait::client_llm_action_set;
use netget::state::app_state::AppState;
use serde_json::json;

/// One `event_handlers` entry with a static handler.
fn static_handler(pattern: &str, actions: serde_json::Value) -> Vec<serde_json::Value> {
    vec![json!({
        "event_pattern": pattern,
        "handler": { "type": "static", "actions": actions }
    })]
}

/// The regression test for the defect itself.
///
/// `tcp_connected` is raised by the TCP **client** and by nothing else, and the TCP client
/// declares `disconnect` in `get_async_actions()` only: its sync list is `send_tcp_data` +
/// `wait_for_more`, and it attaches no actions to any event type. So the catalog for this
/// pattern is exactly the client's own vocabulary, with nothing else to hide the omission.
///
/// Revert `action_catalog_for_pattern` to `server_actions_for_pattern` for the client registry
/// too and this fails with `Unknown action "disconnect"`.
#[test]
fn static_handler_may_name_a_client_async_only_action() {
    let config = EventHandler::parse_event_handlers(static_handler(
        "tcp_connected",
        json!([{ "type": "disconnect" }]),
    ))
    .expect(
        "`disconnect` is async-only on the TCP client, and a client cannot express an \
         async/sync narrowing — a static handler must be allowed to name it",
    );
    assert_eq!(config.len(), 1);
}

/// Accepted is only half of it: the action a handler is allowed to name has to be one the
/// client can actually run, or validation has merely moved the failure.
///
/// Walks the whole path in-process — parse the configuration, store it on a client, dispatch
/// the event through the same `try_execute_client_event_handler` the client's loop calls, and
/// execute what comes back with the protocol's own executor.
#[tokio::test]
async fn a_client_async_only_action_from_a_static_handler_executes() {
    use netget::llm::actions::client_trait::{Client, ClientActionResult};
    use netget::llm::event_handler_executor::{
        try_execute_client_event_handler, ClientEventHandlerResult,
    };
    use netget::state::client::ClientInstance;
    use netget::state::ClientId;

    let config = EventHandler::parse_event_handlers(static_handler(
        "tcp_connected",
        json!([{ "type": "disconnect" }]),
    ))
    .expect("static handler naming the client's async-only verb must parse");

    let state = AppState::new();
    let client_id = state
        .add_client(ClientInstance::new(
            ClientId::new(0),
            "127.0.0.1:9".to_string(),
            "tcp".to_string(),
            "static handler test".to_string(),
        ))
        .await;
    state
        .set_client_event_handler_config(client_id, Some(config))
        .await;

    let result = try_execute_client_event_handler(
        &state,
        client_id,
        "tcp_connected",
        "TCP client connected",
        Some(json!({ "remote_addr": "127.0.0.1:9" })),
    )
    .await
    .expect("dispatching a static client handler must not error");

    let actions = match result {
        ClientEventHandlerResult::Handled { actions } => actions,
        ClientEventHandlerResult::FallbackToLlm { .. } => panic!(
            "a matching static handler must be handled deterministically, not sent to the model"
        ),
    };
    assert_eq!(actions, vec![json!({ "type": "disconnect" })]);

    let outcome = netget::client::TcpClientProtocol::new()
        .execute_action(actions[0].clone())
        .expect("the TCP client must execute the verb its own catalog now advertises");
    assert!(
        matches!(outcome, ClientActionResult::Disconnect),
        "`disconnect` must disconnect, got {outcome:?}"
    );
}

/// The whole client registry, so this holds for protocols no narrow feature set compiles.
///
/// For every registered client and every event type it declares, each action the model would
/// be shown for that event must be nameable by a static handler for it. Everything is batched
/// into one `parse_event_handlers` call per client — the call takes a list, and the catalog is
/// rebuilt per handler either way.
#[test]
fn every_client_action_the_model_sees_is_nameable_by_a_static_handler() {
    let state = AppState::new();
    let mut checked_clients = 0usize;
    let mut checked_actions = 0usize;
    let mut findings: Vec<String> = Vec::new();

    for client in netget::protocol::client_registry::CLIENT_REGISTRY.get_all() {
        let event_types = client.get_event_types();
        if event_types.is_empty() {
            continue;
        }

        let handlers: Vec<serde_json::Value> = event_types
            .iter()
            .map(|event_type| {
                let mut names: Vec<String> = client_llm_action_set(client.as_ref(), &state, None)
                    .into_iter()
                    .map(|a| a.name)
                    .collect();
                names.extend(event_type.actions.iter().map(|a| a.name.clone()));
                names.sort();
                names.dedup();
                checked_actions += names.len();
                let actions: Vec<serde_json::Value> =
                    names.into_iter().map(|n| json!({ "type": n })).collect();
                json!({
                    "event_pattern": event_type.id,
                    "handler": { "type": "static", "actions": actions }
                })
            })
            .collect();

        // Collect rather than panic on the first: with the fix reverted this list *is* the
        // measurement of how wide the defect was, and one protocol at a time would not show it.
        if let Err(e) = EventHandler::parse_event_handlers(handlers) {
            findings.push(format!("client '{}': {e}", client.protocol_name()));
        }
        checked_clients += 1;
    }

    assert!(
        findings.is_empty(),
        "{} of {checked_clients} client protocol(s) advertise an action to the model that a \
         static handler for their own event may not name. Handlers and the model must see the \
         same vocabulary:\n  {}",
        findings.len(),
        findings.join("\n  ")
    );

    println!(
        "{checked_clients} client protocol(s), {checked_actions} advertised action name(s), \
         every one nameable by a static handler"
    );
}

/// The asymmetry, stated as a test so it is not "fixed" by symmetry.
///
/// `tcp_connection_opened` is the TCP **server**'s event and nothing else raises it.
/// `close_connection` is in the server's async list only, and it is not the verb for this
/// position: it takes a `connection_id` and acts on the server, where an event answer wants
/// `close_this_connection`. The catalog must keep refusing it.
#[test]
fn a_servers_async_only_action_is_still_refused_to_a_sync_event_handler() {
    let err = EventHandler::parse_event_handlers(static_handler(
        "tcp_connection_opened",
        json!([{ "type": "close_connection", "connection_id": 1 }]),
    ))
    .expect_err(
        "a server CAN express an async/sync narrowing — it has two LLM entry points — so a \
         handler answering a network event must be held to the sync vocabulary",
    );

    let msg = err.to_string();
    assert!(
        msg.contains("close_connection"),
        "error must name the refused action, got: {msg}"
    );
    assert!(
        msg.contains("close_this_connection"),
        "error must point at the verb that does belong in this position, got: {msg}"
    );
}

/// The reported case, end to end through the parser: WHOIS's own static-mode startup example.
#[test]
fn the_whois_clients_own_static_startup_example_parses() {
    EventHandler::parse_event_handlers(vec![
        json!({
            "event_pattern": "whois_connected",
            "handler": {
                "type": "static",
                "actions": [{ "type": "query_whois", "query": "example.com" }]
            }
        }),
        json!({
            "event_pattern": "whois_response_received",
            "handler": { "type": "static", "actions": [{ "type": "disconnect" }] }
        }),
    ])
    .expect("the static-mode example in the WHOIS client's own get_startup_examples must parse");
}

//! The `manual` handler: a human answers the event, or nobody does and it
//! fails closed.
//!
//! The contract under test, end to end through the real dispatchers:
//!
//! - a matched event parks as a pending intercept and the dispatcher waits;
//! - `resolve_intercept` delivers the operator's actions as the answer;
//! - `dismiss_intercept` and the timeout both surface as `Err` — the same
//!   fail-closed path an LLM failure takes — never as an invented success;
//! - dead entries do not linger in the pending list.
//!
//! No sockets and no LLM: the client dispatcher returns actions verbatim, and
//! the server dispatcher executes them (a `set_memory` common action, which
//! needs no protocol), so both halves are observable without a mock model.

use std::time::Duration;

use netget::llm::event_handler_executor::{
    try_execute_client_event_handler, try_execute_event_handler, ClientEventHandlerResult,
    EventHandlerResult,
};
use netget::scripting::{EventHandler, EventHandlerConfig, EventHandlerType, EventPattern};
use netget::state::app_state::AppState;
use netget::state::client::ClientInstance;
use netget::state::intercepts::InterceptOwner;
use netget::state::server::ServerInstance;
use netget::state::{ClientId, ServerId};

async fn add_test_client(state: &AppState) -> ClientId {
    state
        .add_client(ClientInstance::new(
            ClientId::new(0),
            "127.0.0.1:9".to_string(),
            "TCP".to_string(),
            "be a client".to_string(),
        ))
        .await
}

async fn new_state() -> AppState {
    AppState::new_with_options(false, "http://127.0.0.1:1".to_string())
}

fn manual_config(timeout_secs: u64) -> EventHandlerConfig {
    let mut config = EventHandlerConfig::new();
    config.add_handler(EventHandler::new(
        EventPattern::wildcard(),
        EventHandlerType::Manual { timeout_secs },
    ));
    config
}

/// Park + resolve, through the client dispatcher (which returns the actions
/// verbatim, so the delivered answer is directly assertable).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_operator_answer_becomes_the_events_actions() {
    let state = new_state().await;
    let client_id = add_test_client(&state).await;
    state
        .set_client_event_handler_config(client_id, Some(manual_config(30)))
        .await;

    // The dispatcher blocks until the answer arrives, so it runs as its own
    // task — exactly as it does inside a client's connection loop.
    let dispatcher = {
        let state = state.clone();
        tokio::spawn(async move {
            try_execute_client_event_handler(
                &state,
                client_id,
                "tcp_data_received",
                "Data received",
                Some(serde_json::json!({"data": "hello"})),
            )
            .await
        })
    };

    // The intercept appears in the pending list.
    let view = {
        let mut found = None;
        for _ in 0..100 {
            let list = state.list_intercepts().await;
            if let Some(view) = list.first() {
                found = Some(view.clone());
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        found.expect("the parked event should be listed")
    };
    assert_eq!(view.event_type, "tcp_data_received");
    assert_eq!(view.owner, InterceptOwner::Client(client_id));

    // The operator answers. `{{event.data}}` proves the answer goes through
    // the same interpolation as a static handler.
    state
        .resolve_intercept(
            view.id,
            vec![serde_json::json!({"type": "send_data", "data": "you said {{event.data}}"})],
        )
        .await
        .expect("resolve");

    let result = dispatcher.await.expect("task").expect("dispatch");
    let ClientEventHandlerResult::Handled { actions } = result else {
        panic!("a resolved manual handler must produce actions, not fall back to the LLM");
    };
    assert_eq!(actions.len(), 1);
    assert_eq!(
        actions[0]["data"], "you said hello",
        "the operator's answer should be interpolated against the event"
    );

    // Answered means gone.
    assert!(state.list_intercepts().await.is_empty());
}

/// Dismissing fails the event closed immediately, without waiting out the
/// timeout — a refusal must be distinguishable from an answer, never invented.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dismissing_fails_closed_immediately() {
    let state = new_state().await;
    let client_id = add_test_client(&state).await;
    // A long timeout: if dismissal did not short-circuit, this test would hang.
    state
        .set_client_event_handler_config(client_id, Some(manual_config(600)))
        .await;

    let dispatcher = {
        let state = state.clone();
        tokio::spawn(async move {
            try_execute_client_event_handler(
                &state,
                client_id,
                "tcp_data_received",
                "Data received",
                None,
            )
            .await
        })
    };

    let id = {
        let mut found = None;
        for _ in 0..100 {
            if let Some(view) = state.list_intercepts().await.first() {
                found = Some(view.id);
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        found.expect("parked")
    };
    assert!(state.dismiss_intercept(id).await);

    let result = tokio::time::timeout(Duration::from_secs(5), dispatcher)
        .await
        .expect("dismissal must not wait out the timeout")
        .expect("task");
    let err = match result {
        Ok(_) => panic!("a dismissed request is a failure, not an answer"),
        Err(e) => e,
    };
    assert!(
        err.to_string().contains("dismissed"),
        "the error should say the operator refused: {err}"
    );
    assert!(!state.dismiss_intercept(id).await, "already gone");
}

/// No answer within the timeout: the dispatcher errors (fail closed) and the
/// dead entry is removed from the pending list.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn no_answer_times_out_and_fails_closed() {
    let state = new_state().await;
    let client_id = add_test_client(&state).await;
    state
        .set_client_event_handler_config(client_id, Some(manual_config(1)))
        .await;

    let result = try_execute_client_event_handler(
        &state,
        client_id,
        "tcp_data_received",
        "Data received",
        None,
    )
    .await;
    let err = match result {
        Ok(_) => panic!("no operator answer must fail, not fall through"),
        Err(e) => e,
    };
    assert!(err.to_string().contains("no operator answer"), "{err}");
    assert!(
        state.list_intercepts().await.is_empty(),
        "a timed-out intercept must not linger in the list"
    );

    // Answering after the fact is a clean error, not a silent no-op: the
    // peer already got the fail-closed reply.
    let stale = state
        .resolve_intercept(1, vec![serde_json::json!({"type": "x"})])
        .await;
    assert!(stale.is_err());
}

/// The server dispatcher: the operator's actions are executed exactly like a
/// static handler's (here `set_memory`, observable in server state).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_server_intercept_executes_the_answer_like_a_static_handler() {
    let state = new_state().await;
    let server_id = state
        .add_server(ServerInstance::new(
            ServerId::new(0),
            8080,
            "TCP".to_string(),
            "answer things".to_string(),
        ))
        .await;
    state
        .set_event_handler_config(server_id, Some(manual_config(30)))
        .await;

    let dispatcher = {
        let state = state.clone();
        tokio::spawn(async move {
            try_execute_event_handler(
                &state,
                server_id,
                None,
                "tcp_data_received",
                "Data received",
                Some(serde_json::json!({"data": "ping"})),
                None,
            )
            .await
        })
    };

    let view = {
        let mut found = None;
        for _ in 0..100 {
            if let Some(view) = state.list_intercepts().await.first() {
                found = Some(view.clone());
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        found.expect("parked")
    };
    assert_eq!(view.owner, InterceptOwner::Server(server_id));

    state
        .resolve_intercept(
            view.id,
            vec![serde_json::json!({
                "type": "set_memory",
                "value": "answered {{event.data}} by hand"
            })],
        )
        .await
        .expect("resolve");

    let result = dispatcher.await.expect("task").expect("dispatch");
    assert!(
        matches!(result, EventHandlerResult::Handled(_)),
        "a resolved manual handler is a handled event"
    );
    let server = state.get_server(server_id).await.expect("server");
    assert_eq!(
        server.memory, "answered ping by hand",
        "the operator's action should have executed with event interpolation"
    );
}

/// The wire format: `"manual"` parses (with and without a timeout), junk is
/// rejected, and serde round-trips the variant.
#[test]
fn manual_parses_and_round_trips() {
    use netget::events::EventHandler as Events;

    let config = Events::parse_event_handlers(vec![serde_json::json!({
        "event_pattern": "*",
        "handler": {"type": "manual"}
    })])
    .expect("default timeout");
    assert!(matches!(
        config.handlers[0].handler,
        EventHandlerType::Manual {
            timeout_secs: netget::scripting::DEFAULT_MANUAL_TIMEOUT_SECS
        }
    ));

    let config = Events::parse_event_handlers(vec![serde_json::json!({
        "event_pattern": "*",
        "handler": {"type": "manual", "timeout_secs": 42}
    })])
    .expect("explicit timeout");
    let EventHandlerType::Manual { timeout_secs } = config.handlers[0].handler else {
        panic!("expected manual");
    };
    assert_eq!(timeout_secs, 42);

    for junk in [serde_json::json!(0), serde_json::json!("soon")] {
        let err = Events::parse_event_handlers(vec![serde_json::json!({
            "event_pattern": "*",
            "handler": {"type": "manual", "timeout_secs": junk}
        })])
        .expect_err("junk timeout rejected");
        assert!(err.to_string().contains("timeout_secs"), "{err}");
    }

    // Serde round-trip (the save/load and MCP path).
    let handler = EventHandler::new(EventPattern::wildcard(), EventHandlerType::manual(77));
    let json = serde_json::to_value(&handler).expect("serialize");
    assert_eq!(json["handler"]["type"], "manual");
    assert_eq!(json["handler"]["timeout_secs"], 77);
    let back: EventHandler = serde_json::from_value(json).expect("deserialize");
    assert!(matches!(
        back.handler,
        EventHandlerType::Manual { timeout_secs: 77 }
    ));
}

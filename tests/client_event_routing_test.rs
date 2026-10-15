//! E2E for client-side event-handler dispatch: script/static routing for
//! clients, wired at the `client::llm_budget::call_llm_for_client` choke
//! point. Until this existed, client `event_handlers` were stored but never
//! consulted — every client event went to the LLM.
//!
//! Zero LLM involvement: all clients here route deterministically, and the
//! LLM client points at an unreachable URL, so any accidental model call
//! fails loudly.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features tcp --test client_event_routing_test -- --test-threads=100

use std::time::Duration;

use netget::cli::management::{ClientForm, ServerForm};
use netget::state::app_state::AppState;
use netget::state::{AccessLogOwner, ServerId};
use tokio::sync::mpsc;

async fn new_state() -> AppState {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".to_string());
    state
        .set_llm_client(netget::llm::OllamaClient::new(
            "http://127.0.0.1:1".to_string(),
        ))
        .await;
    state
}

async fn wait_for_port(state: &AppState, id: ServerId) -> u16 {
    for _ in 0..100 {
        if let Some(s) = state.get_server(id).await {
            if let Some(addr) = s.local_addr {
                return addr.port();
            }
            if s.port != 0 {
                return s.port;
            }
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("server #{} never bound a port", id.as_u32());
}

async fn wait_for_log_containing(
    state: &AppState,
    owner: AccessLogOwner,
    needle: &str,
) -> netget::state::app_state::AccessLogEntry {
    for _ in 0..150 {
        for entry in state.list_access_logs_for(Some(owner), None).await {
            let text = serde_json::to_string(&entry).unwrap_or_default();
            if text.contains(needle) {
                return entry;
            }
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("no access-log entry for {owner:?} containing {needle:?}");
}

/// A quiet TCP server: logs every data event, answers nothing.
async fn quiet_tcp_server(state: &AppState) -> (ServerId, u16) {
    let (tx, _rx) = mpsc::unbounded_channel();
    let form = ServerForm {
        protocol: "tcp".to_string(),
        port: Some(0),
        event_handlers: Some(vec![serde_json::json!({
            "event_pattern": "*",
            "handler": { "type": "static", "actions": [] }
        })]),
        ..Default::default()
    };
    let id = form.create(state, tx).await.expect("create tcp server");
    let port = wait_for_port(state, id).await;
    (id, port)
}

/// A static handler on the client's `tcp_connected` event puts bytes on the
/// wire with no LLM anywhere — the client-routing equivalent of the server
/// static handlers that have worked for a long time.
#[tokio::test]
async fn client_static_handler_answers_without_llm() {
    let state = new_state().await;
    let (server_id, port) = quiet_tcp_server(&state).await;
    let (tx, _rx) = mpsc::unbounded_channel();

    let client_form = ClientForm {
        protocol: "tcp".to_string(),
        remote_addr: Some(format!("127.0.0.1:{port}")),
        instruction: Some("static test client".to_string()),
        event_handlers: Some(vec![
            serde_json::json!({
                "event_pattern": "tcp_connected",
                "handler": {
                    "type": "static",
                    "actions": [ { "type": "send_tcp_data", "data": "hello-from-handler" } ]
                }
            }),
            serde_json::json!({
                "event_pattern": "tcp_data_received",
                "handler": { "type": "static", "actions": [] }
            }),
        ]),
        ..Default::default()
    };
    let client_id = client_form
        .create(
            &state,
            netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
            tx,
        )
        .await
        .expect("create tcp client");

    // The handler's bytes reached our server.
    wait_for_log_containing(
        &state,
        AccessLogOwner::Server(server_id.as_u32()),
        "hello-from-handler",
    )
    .await;

    // And the client's own log shows the handled event with the produced action.
    let entry = wait_for_log_containing(
        &state,
        AccessLogOwner::Client(client_id.as_u32()),
        "tcp_connected",
    )
    .await;
    assert_eq!(entry.event_type, "tcp_connected");
    assert!(
        serde_json::to_string(&entry.response)
            .unwrap()
            .contains("hello-from-handler"),
        "client entry must record the handler-produced action"
    );
}

/// A resident python script keeps state across events: it answers only the
/// FIRST data event, so the exchange converges instead of ping-ponging.
/// Needs python3 (same requirement as the existing scripting test suites).
#[tokio::test]
async fn client_resident_script_keeps_state_across_events() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    // Server echoes a fixed "pong" to every data event.
    let server_form = ServerForm {
        protocol: "tcp".to_string(),
        port: Some(0),
        event_handlers: Some(vec![serde_json::json!({
            "event_pattern": "tcp_data_received",
            "handler": {
                "type": "static",
                "actions": [ { "type": "send_tcp_data", "data": "pong" } ]
            }
        })]),
        ..Default::default()
    };
    let server_id = server_form
        .create(&state, tx.clone())
        .await
        .expect("create tcp server");
    let port = wait_for_port(&state, server_id).await;

    let script = r#"
count = 0
def handle(event_type, event, message):
    global count
    count += 1
    if count == 1:
        return [{"type": "send_tcp_data", "data": "again"}]
    return None
"#;

    let client_form = ClientForm {
        protocol: "tcp".to_string(),
        remote_addr: Some(format!("127.0.0.1:{port}")),
        instruction: Some("resident script client".to_string()),
        event_handlers: Some(vec![
            serde_json::json!({
                "event_pattern": "tcp_connected",
                "handler": {
                    "type": "static",
                    "actions": [ { "type": "send_tcp_data", "data": "ping" } ]
                }
            }),
            serde_json::json!({
                "event_pattern": "tcp_data_received",
                "handler": {
                    "type": "script",
                    "language": "python",
                    "resident": true,
                    "code": script
                }
            }),
        ]),
        ..Default::default()
    };
    let client_id = client_form
        .create(
            &state,
            netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
            tx,
        )
        .await
        .expect("create tcp client");

    // Round 1: connect → static "ping" → server logs it, answers "pong" →
    // script (count=1) sends "again" → server logs that, answers "pong" →
    // script (count=2) sends nothing → quiescence. "again" on the server side
    // proves the script ran; the second client entry with an empty response
    // proves its state advanced.
    wait_for_log_containing(&state, AccessLogOwner::Server(server_id.as_u32()), "again").await;

    // Wait for the second data event to be routed and recorded.
    let mut data_entries = Vec::new();
    for _ in 0..150 {
        data_entries = state
            .list_access_logs_for(Some(AccessLogOwner::Client(client_id.as_u32())), None)
            .await
            .into_iter()
            .filter(|e| e.event_type == "tcp_data_received")
            .collect();
        if data_entries.len() >= 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    assert!(
        data_entries.len() >= 2,
        "expected two routed data events, got {}",
        data_entries.len()
    );
    // Newest first: the latest data event produced no actions (count > 1).
    assert!(
        data_entries[0].response.is_empty(),
        "second event must produce no actions (resident state advanced): {:?}",
        data_entries[0].response
    );

    // Teardown kills the resident interpreter (shutdown_client path).
    state.remove_client(client_id).await;
    assert!(state.get_client(client_id).await.is_none());
}

/// Malformed event_handlers error at startup and leave no orphan client row.
#[tokio::test]
async fn malformed_client_handlers_error_with_no_orphan() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    let client_form = ClientForm {
        protocol: "tcp".to_string(),
        remote_addr: Some("127.0.0.1:1".to_string()),
        instruction: Some("bad handlers".to_string()),
        event_handlers: Some(vec![serde_json::json!({
            "event_pattern": "tcp_data_received"
            // no "handler" field at all
        })]),
        ..Default::default()
    };
    let err = client_form
        .create(
            &state,
            netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
            tx,
        )
        .await
        .expect_err("malformed handlers must be rejected");
    assert!(
        err.to_string().contains("event_handlers") || err.to_string().contains("handler"),
        "error should name the handler problem: {err}"
    );
    assert!(
        state.get_all_clients().await.is_empty(),
        "a rejected client must not leave a row behind"
    );
}

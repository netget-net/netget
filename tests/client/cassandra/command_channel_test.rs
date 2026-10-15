//! The dashboard's `[ send ]` path on a Cassandra client: `AppState::send_to_client` injects a
//! CQL statement from outside the client's own tasks and it reaches a NetGet Cassandra server
//! of our own. Zero LLM calls — the server answers through a `*` static handler (OPTIONS and
//! STARTUP fall through to its own SUPPORTED/READY defaults) and the client's LLM points at an
//! unreachable URL.
//!
//! Outcome semantics worth knowing: the scylla driver owns the socket and its connection pool,
//! so NetGet can never report a truthful `bytes_sent` for a statement. The honest outcome is
//! `Executed { detail }` naming the row count, never `Sent`.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features cassandra --test client -- cassandra::command_channel --test-threads=100

use std::time::Duration;

use netget::cli::management::{ClientForm, ServerForm};
use netget::state::app_state::AppState;
use netget::state::client_handles::ClientSendOutcome;
use netget::state::{AccessLogOwner, ClientId, ServerId};
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
    for _ in 0..1_000 {
        if let Some(s) = state.get_server(id).await {
            if let Some(addr) = s.local_addr {
                return addr.port();
            }
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("Cassandra server #{} never bound a port", id.as_u32());
}

async fn wait_for_client_handle(state: &AppState, id: ClientId) {
    for _ in 0..1_000 {
        if state.has_client_handle(id).await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!(
        "Cassandra client #{} never registered a command handle",
        id.as_u32()
    );
}

async fn wait_for_log_containing(state: &AppState, owner: AccessLogOwner, needle: &str) {
    for _ in 0..1_000 {
        for entry in state.list_access_logs_for(Some(owner), None).await {
            if serde_json::to_string(&entry)
                .unwrap_or_default()
                .contains(needle)
            {
                return;
            }
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("no access-log entry for {owner:?} containing {needle:?}");
}

#[tokio::test]
async fn injected_cql_reaches_our_own_server() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    let server_id = ServerForm {
        protocol: "cassandra".to_string(),
        port: Some(0),
        // One script handler branching on the request, not a blanket `*` static rule.
        //
        // The server fails closed on a request no handler answers, which is correct -- but
        // it means the CQL handshake has to be answered in kind: STARTUP wants
        // cassandra_ready and OPTIONS wants cassandra_supported. A `*` rule answering
        // everything with cassandra_result_rows made the driver's STARTUP fail with
        // "netget: no handler answer for this request", so the client never connected.
        //
        // It cannot be several static rules either: EventHandler has only `event_pattern`
        // and `handler`, so every rule registered against a given event id matches every
        // occurrence and first-match-wins.
        event_handlers: Some(vec![serde_json::json!({
            "event_pattern": "*",
            "handler": {
                "type": "script",
                "language": "python",
                "resident": true,
                "code": r#"
def handle(event_type, event, message):
    if event_type == "cassandra_startup":
        return [{"type": "cassandra_ready"}]
    if event_type == "cassandra_options":
        return [{"type": "cassandra_supported"}]
    if event_type == "cassandra_auth":
        return [{"type": "cassandra_auth_success"}]
    if event_type == "cassandra_prepare":
        return [{"type": "cassandra_prepared"}]
    return [{
        "type": "cassandra_result_rows",
        "columns": [{"name": "marker", "type": "varchar"}],
        "rows": [["served"]],
    }]
"#
            }
        })]),
        ..Default::default()
    }
    .create(&state, tx.clone())
    .await
    .expect("create cassandra server");
    let port = wait_for_port(&state, server_id).await;

    let client_id = ClientForm {
        protocol: "cassandra".to_string(),
        remote_addr: Some(format!("127.0.0.1:{port}")),
        instruction: Some("test client".to_string()),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
        tx.clone(),
    )
    .await
    .expect("create cassandra client");

    // Regression guard for "register the channel BEFORE the connected-event LLM call" — which
    // for this protocol is awaited *inline* in `connect()`, so the channel has to be live
    // before it or a parked manual rule would make [ send ] unreachable for the whole park.
    wait_for_client_handle(&state, client_id).await;

    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({
                "type": "execute_cql_query",
                "query": "SELECT dashboard_marker FROM probe"
            }),
            Duration::from_secs(20),
        )
        .await
        .expect("send_to_client");
    match &outcome {
        ClientSendOutcome::Executed { detail } => {
            assert!(
                detail.contains("CQL executed"),
                "expected the CQL summary in the detail, got {detail:?}"
            );
        }
        other => panic!("expected Executed, got {other:?}"),
    }

    // Recorded on the client like LLM-produced traffic, and received by the server.
    wait_for_log_containing(
        &state,
        AccessLogOwner::Client(client_id.as_u32()),
        "injected_action",
    )
    .await;
    wait_for_log_containing(
        &state,
        AccessLogOwner::Server(server_id.as_u32()),
        "dashboard_marker",
    )
    .await;

    // An action the protocol does not know is rejected, not silently swallowed.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "not_a_cassandra_action"}),
            Duration::from_secs(10),
        )
        .await
        .expect("send_to_client unknown action");
    assert!(
        matches!(outcome, ClientSendOutcome::Rejected { .. }),
        "expected Rejected, got {outcome:?}"
    );

    // An injected disconnect ends the loop and drops the handle.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "disconnect"}),
            Duration::from_secs(10),
        )
        .await
        .expect("send_to_client disconnect");
    assert!(
        matches!(outcome, ClientSendOutcome::Disconnected),
        "expected Disconnected, got {outcome:?}"
    );

    for _ in 0..1_000 {
        if !state.has_client_handle(client_id).await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("client should have dropped its command handle after an injected disconnect");
}

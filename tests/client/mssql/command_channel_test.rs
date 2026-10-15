//! The dashboard's `[ send ]` path on an MSSQL client: `AppState::send_to_client` injects an
//! action from outside the client's own tasks, and the query reaches a NetGet MSSQL server of
//! our own over a real TDS connection.
//!
//! Zero LLM calls. The server's PRELOGIN/LOGIN7 handshake is pure Rust and raises no event;
//! the one event that does fire (`mssql_query`) is answered by a `*` static rule. The client's
//! LLM points at an unreachable URL, so its connected-event call fails — the loop tolerates
//! that, and the command task is independent of it by design.
//!
//! Outcome semantics under test: tiberius owns the TDS framing, so a query that ran reports
//! `Executed` naming the row/column counts. There is no byte count this client can honestly
//! claim, and a fabricated `Sent` would be worse than the truth.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features mssql --test client -- mssql::command_channel --test-threads=100
//!
//! Condition waits here poll for up to ~30s (1_000 x 30ms).
//!
//! That budget is deliberately generous, and it is not a latency assertion: the loop exits
//! the moment the condition holds, so a healthy run costs milliseconds. It was 3s, which is
//! ample when this test runs alone and far too little at `--test-threads=100`, where the
//! handshake it waits on competes with a hundred other tests for the runtime. The test then
//! reported the condition as never happening when it simply had not happened *yet* -- a
//! failure that pointed at the protocol instead of at the deadline.


use std::time::Duration;

use netget::cli::management::{ClientForm, ServerForm};
use netget::state::app_state::AppState;
use netget::state::client_handles::ClientSendOutcome;
use netget::state::{AccessLogOwner, ClientId, ClientStatus, ServerId};
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
    panic!("MSSQL server #{} never bound a port", id.as_u32());
}

async fn wait_for_client_handle(state: &AppState, id: ClientId) {
    for _ in 0..1_000 {
        if state.has_client_handle(id).await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!(
        "MSSQL client #{} never registered a command handle",
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
async fn injected_mssql_query_reaches_our_own_server() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    let server_id = ServerForm {
        protocol: "mssql".to_string(),
        port: Some(0),
        // One script handler branching on the event, not a blanket `*` static rule.
        //
        // Login is a model decision now, and the server fails closed when nothing answers
        // it -- correctly. A `*` rule answering everything with mssql_query_response left
        // LOGIN7 unanswered, so tiberius got "Login failed for user ''" and the client
        // never connected.
        //
        // It cannot be two static rules either: EventHandler has only `event_pattern` and
        // `handler`, so every rule against a given event id matches every occurrence and
        // first-match-wins.
        event_handlers: Some(vec![serde_json::json!({
            "event_pattern": "*",
            "handler": {
                "type": "script",
                "language": "python",
                "resident": true,
                "code": r#"
def handle(event_type, event, message):
    if event_type == "mssql_login":
        return [{"type": "mssql_login_ack"}]
    return [{
        "type": "mssql_query_response",
        "columns": [{"name": "marker", "type": "NVARCHAR"}],
        "rows": [["dashboard-marker"]],
    }]
"#
            }
        })]),
        ..Default::default()
    }
    .create(&state, tx.clone())
    .await
    .expect("create mssql server");
    let port = wait_for_port(&state, server_id).await;

    let client_id = ClientForm {
        protocol: "mssql".to_string(),
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
    .expect("create mssql client");

    wait_for_client_handle(&state, client_id).await;

    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "execute_query", "query": "SELECT 'injected-probe'"}),
            Duration::from_secs(10),
        )
        .await
        .expect("send_to_client execute_query");
    match &outcome {
        ClientSendOutcome::Executed { detail } => {
            assert!(
                detail.contains("injected-probe") && detail.contains("1 row(s)"),
                "detail should name the query and what came back, got {detail:?}"
            );
        }
        other => panic!("expected Executed, got {other:?}"),
    }

    // Recorded on the client like LLM-produced traffic, and seen by the server — which is
    // what proves the SQL actually crossed the connection rather than being swallowed.
    wait_for_log_containing(
        &state,
        AccessLogOwner::Client(client_id.as_u32()),
        "injected_action",
    )
    .await;
    wait_for_log_containing(
        &state,
        AccessLogOwner::Server(server_id.as_u32()),
        "injected-probe",
    )
    .await;

    // An action the protocol refuses never reaches the server.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "not_a_real_action"}),
            Duration::from_secs(10),
        )
        .await
        .expect("send_to_client unknown action");
    assert!(
        matches!(outcome, ClientSendOutcome::Rejected { .. }),
        "expected Rejected, got {outcome:?}"
    );

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
        let status = state.get_client(client_id).await.map(|c| c.status);
        if matches!(status, Some(ClientStatus::Disconnected))
            && !state.has_client_handle(client_id).await
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!(
        "client should be Disconnected with no command handle; status={:?} has_handle={}",
        state.get_client(client_id).await.map(|c| c.status),
        state.has_client_handle(client_id).await
    );
}

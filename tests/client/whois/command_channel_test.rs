//! The dashboard's `[ query_whois ]` / `[ disconnect ]` path on a WHOIS client:
//! `AppState::send_to_client` injects an action from outside the client's task, and the query
//! reaches a NetGet WHOIS server of our own. Zero LLM calls - the server answers through a `*`
//! static handler and the client's LLM points at an unreachable URL (its connected-event call
//! fails; the client stays connected for exactly this case, and the command task is
//! independent of it by design).
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features whois --test client -- whois::command_channel --test-threads=100

use std::time::Duration;

use netget::cli::management::{ClientForm, ServerForm};
use netget::state::app_state::AppState;
use netget::state::client_handles::ClientSendOutcome;
use netget::state::server::ConnectionStatus;
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
    panic!("WHOIS server #{} never bound a port", id.as_u32());
}

async fn wait_for_client_handle(state: &AppState, id: ClientId, present: bool) {
    for _ in 0..1_000 {
        if state.has_client_handle(id).await == present {
            return;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!(
        "WHOIS client #{} command handle never became present={present}",
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
async fn injected_whois_query_reaches_our_own_server() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    // No close_connection in the static answer: the server keeps the connection open, so the
    // injected disconnect below is what ends it.
    let server_id = ServerForm {
        protocol: "whois".to_string(),
        port: Some(0),
        event_handlers: Some(vec![serde_json::json!({
            "event_pattern": "*",
            "handler": {
                "type": "static",
                "actions": [ { "type": "send_whois_response", "response": "static" } ]
            }
        })]),
        ..Default::default()
    }
    .create(&state, tx.clone())
    .await
    .expect("create whois server");
    let port = wait_for_port(&state, server_id).await;

    let client_id = ClientForm {
        protocol: "whois".to_string(),
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
    .expect("create whois client");

    wait_for_client_handle(&state, client_id, true).await;

    // The client's own wire verb, injected from outside its task.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "query_whois", "query": "dashboard-marker"}),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_client");
    assert!(
        matches!(outcome, ClientSendOutcome::Sent { bytes_sent: 18 }),
        "expected Sent{{18}}, got {outcome:?}"
    );

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
        "dashboard-marker",
    )
    .await;

    // An injected disconnect half-closes; the server sees EOF and closes its side.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "disconnect"}),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_client disconnect");
    assert!(
        matches!(outcome, ClientSendOutcome::Disconnected),
        "expected Disconnected, got {outcome:?}"
    );

    // The handle is gone, so the rail stops offering [ send ] on a dead client.
    wait_for_client_handle(&state, client_id, false).await;

    for _ in 0..1_000 {
        let server = state.get_server(server_id).await.expect("server");
        if server
            .connections
            .values()
            .any(|c| c.status == ConnectionStatus::Closed)
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("server never saw the client's half-close");
}

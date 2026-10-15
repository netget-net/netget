//! The dashboard's `[ send_dns_query ]` path on a DoT client: `AppState::send_to_client`
//! injects an action from outside the client's read loop, and the query reaches a NetGet DoT
//! server of our own over TLS. Zero LLM calls - the server answers through a `*` static handler
//! and the client's LLM points at an unreachable URL (its connected-event call fails; the loop
//! tolerates that, and the command task is independent of it by design).
//!
//! The client connects with `verify_tls: false` because the server's certificate is
//! self-signed; the parameter had been declared but never read until the command-channel pass.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features dot --test client -- dot::command_channel --test-threads=100


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
    panic!("DoT server #{} never bound a port", id.as_u32());
}

async fn wait_for_client_handle(state: &AppState, id: ClientId) {
    for _ in 0..1_000 {
        if state.has_client_handle(id).await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!(
        "DoT client #{} never registered a command handle",
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
async fn injected_dns_query_reaches_our_own_dot_server() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    let server_id = ServerForm {
        protocol: "dot".to_string(),
        port: Some(0),
        event_handlers: Some(vec![serde_json::json!({
            "event_pattern": "*",
            "handler": {
                "type": "static",
                "actions": [ { "type": "send_dns_nxdomain", "query_id": 0 } ]
            }
        })]),
        ..Default::default()
    }
    .create(&state, tx.clone())
    .await
    .expect("create dot server");
    let port = wait_for_port(&state, server_id).await;

    let client_id = ClientForm {
        protocol: "dot".to_string(),
        remote_addr: Some(format!("127.0.0.1:{port}")),
        instruction: Some("test client".to_string()),
        startup_params: Some(serde_json::json!({ "verify_tls": false })),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
        tx.clone(),
    )
    .await
    .expect("create dot client");

    wait_for_client_handle(&state, client_id).await;

    // The client's own wire verb, injected from outside its loop. The query is the 2-byte
    // length prefix plus a 12-byte header plus the encoded question for
    // `dashboard-marker.example.` (26 bytes) plus type/class (4 bytes) = 44 bytes.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({
                "type": "send_dns_query",
                "domain": "dashboard-marker.example",
                "query_type": "A"
            }),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_client");
    assert!(
        matches!(outcome, ClientSendOutcome::Sent { bytes_sent: 44 }),
        "expected Sent{{44}}, got {outcome:?}"
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
        "dashboard-marker.example",
    )
    .await;

    // An injected disconnect half-closes the TLS stream; the read loop sees EOF, marks the
    // client Disconnected and drops the command handle.
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
    for _ in 0..1_000 {
        let status = state.get_client(client_id).await.map(|c| c.status);
        if status == Some(ClientStatus::Disconnected) && !state.has_client_handle(client_id).await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("DoT client never reached Disconnected with its command handle removed");
}

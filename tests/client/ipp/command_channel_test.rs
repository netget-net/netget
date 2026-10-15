//! The dashboard's `[ send ]` path on an IPP client: `AppState::send_to_client` injects an
//! IPP operation from outside the client's own task and it reaches a NetGet IPP server of
//! our own. Zero LLM calls - the server answers through a `*` static handler and the
//! client's LLM points at an unreachable URL (its `ipp_connected` call fails; the loop
//! tolerates that, and the command loop is registered before that call by design).
//!
//! IPP is carried over HTTP, so this is a plain localhost TCP exchange; nothing here
//! contacts an external endpoint.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features ipp --test client -- ipp::command_channel --test-threads=100


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
    panic!("IPP server #{} never bound a port", id.as_u32());
}

/// The regression guard for rule 2: the handle must exist even though `connect()` makes an
/// `ipp_connected` LLM call that a manual routing rule could park for minutes.
async fn wait_for_client_handle(state: &AppState, id: ClientId) {
    for _ in 0..1_000 {
        if state.has_client_handle(id).await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!(
        "IPP client #{} never registered a command handle",
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
async fn injected_ipp_operation_reaches_our_own_server() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    let server_id = ServerForm {
        protocol: "ipp".to_string(),
        port: Some(0),
        event_handlers: Some(vec![serde_json::json!({
            "event_pattern": "*",
            "handler": {
                "type": "static",
                "actions": [{
                    "type": "ipp_printer_attributes",
                    "attributes": {
                        "printer-name": "NetGet Dashboard Printer",
                        "printer-state": "idle"
                    }
                }]
            }
        })]),
        ..Default::default()
    }
    .create(&state, tx.clone())
    .await
    .expect("create ipp server");
    let port = wait_for_port(&state, server_id).await;

    let client_id = ClientForm {
        protocol: "ipp".to_string(),
        remote_addr: Some(format!("http://127.0.0.1:{port}/printers/test")),
        instruction: Some("test client".to_string()),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
        tx.clone(),
    )
    .await
    .expect("create ipp client");

    wait_for_client_handle(&state, client_id).await;

    // IPP's own verb, injected from outside the client's task. `Executed`, not `Sent`:
    // the `ipp` crate owns the HTTP request and reports no wire byte count.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "get_printer_attributes"}),
            Duration::from_secs(30),
        )
        .await
        .expect("send_to_client");
    match &outcome {
        ClientSendOutcome::Executed { detail } => assert!(
            detail.contains("Get-Printer-Attributes completed"),
            "detail should name the operation that ran, got {detail:?}"
        ),
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
        "NetGet Dashboard Printer",
    )
    .await;

    // A verb the IPP client does not have is rejected by the protocol.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "cancel_job"}),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_client unknown");
    assert!(
        matches!(outcome, ClientSendOutcome::Rejected { .. }),
        "expected Rejected, got {outcome:?}"
    );

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

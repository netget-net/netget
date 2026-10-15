//! The dashboard's `[ send ]` path on an IMAP client: `AppState::send_to_client` injects an
//! action from outside the client's own tasks, and the IMAP command reaches a NetGet IMAP
//! server of our own over a real socket.
//!
//! Zero LLM calls. Three `static` rules carry the session — the greeting is *not* deterministic
//! on the server side (`imap_connection` is answered by a handler, and without one the server
//! writes `* BYE` and hangs up), LOGIN is `imap_auth`, and everything after it is
//! `imap_command`. The auth rule interpolates `{{event.tag}}` because `async_imap` picks its own
//! tags (`A0001`, `A0002`, …) and the server checks the tag rather than substring-matching.
//! The client's LLM points at an unreachable URL, so its connected-event call fails; the loop
//! tolerates that and the command task is independent of it by design.
//!
//! Outcome semantics under test: `async_imap` frames the tagged command itself, so a verb that
//! ran reports `Executed` naming it. There is no byte count this client can honestly claim.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features imap --test client -- imap::command_channel --test-threads=100


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
    panic!("IMAP server #{} never bound a port", id.as_u32());
}

async fn wait_for_client_handle(state: &AppState, id: ClientId) {
    for _ in 0..1_000 {
        if state.has_client_handle(id).await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!(
        "IMAP client #{} never registered a command handle",
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
async fn injected_imap_command_reaches_our_own_server() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    let server_id = ServerForm {
        protocol: "imap".to_string(),
        port: Some(0),
        event_handlers: Some(vec![
            serde_json::json!({
                "event_pattern": "imap_connection",
                "handler": {
                    "type": "static",
                    "actions": [{
                        "type": "send_imap_greeting",
                        "hostname": "localhost",
                        "capabilities": ["IMAP4rev1"]
                    }]
                }
            }),
            serde_json::json!({
                "event_pattern": "imap_auth",
                "handler": {
                    "type": "static",
                    "actions": [{
                        "type": "send_imap_response",
                        "tag": "{{event.tag}}",
                        "status": "OK",
                        "message": "LOGIN completed"
                    }]
                }
            }),
            serde_json::json!({
                "event_pattern": "imap_command",
                "handler": {
                    "type": "static",
                    "actions": [{
                        "type": "send_imap_select",
                        "exists": 3,
                        "recent": 1,
                        "uidvalidity": 1
                    }]
                }
            }),
        ]),
        ..Default::default()
    }
    .create(&state, tx.clone())
    .await
    .expect("create imap server");
    let port = wait_for_port(&state, server_id).await;

    let client_id = ClientForm {
        protocol: "imap".to_string(),
        remote_addr: Some(format!("127.0.0.1:{port}")),
        instruction: Some("test client".to_string()),
        startup_params: Some(serde_json::json!({
            "username": "testuser",
            "password": "testpass"
        })),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
        tx.clone(),
    )
    .await
    .expect("create imap client");

    wait_for_client_handle(&state, client_id).await;

    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "select_mailbox", "mailbox": "INBOX-marker"}),
            Duration::from_secs(15),
        )
        .await
        .expect("send_to_client select_mailbox");
    match &outcome {
        ClientSendOutcome::Executed { detail } => assert!(
            detail.contains("select_mailbox"),
            "detail should name the verb that ran, got {detail:?}"
        ),
        other => panic!("expected Executed, got {other:?}"),
    }

    // Recorded on the client like LLM-produced traffic, and seen by the server — which is
    // what proves the SELECT actually crossed the connection.
    wait_for_log_containing(
        &state,
        AccessLogOwner::Client(client_id.as_u32()),
        "injected_action",
    )
    .await;
    wait_for_log_containing(
        &state,
        AccessLogOwner::Server(server_id.as_u32()),
        "INBOX-marker",
    )
    .await;

    // An action the protocol refuses never reaches the server.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "not_a_real_action"}),
            Duration::from_secs(15),
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
            Duration::from_secs(15),
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

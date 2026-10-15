//! The dashboard's `[ send_dc_chat ]` path on a DC client: `AppState::send_to_client` injects
//! an action from outside the client's read loop, and the NMDC command reaches a NetGet DC hub
//! of our own. Zero LLM calls - the hub answers through a `*` static handler and the client's
//! LLM points at an unreachable URL (the command task is independent of it by design).
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features dc --test client -- dc::command_channel --test-threads=100


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
    panic!("DC server #{} never bound a port", id.as_u32());
}

async fn wait_for_client_handle(state: &AppState, id: ClientId) {
    for _ in 0..1_000 {
        if state.has_client_handle(id).await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!(
        "DC client #{} never registered a command handle",
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
async fn injected_dc_command_reaches_our_own_hub() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    let server_id = ServerForm {
        protocol: "dc".to_string(),
        port: Some(0),
        event_handlers: Some(vec![serde_json::json!({
            "event_pattern": "*",
            "handler": {
                "type": "static",
                "actions": [ { "type": "send_dc_hubname", "name": "StaticHub" } ]
            }
        })]),
        ..Default::default()
    }
    .create(&state, tx.clone())
    .await
    .expect("create dc server");
    let port = wait_for_port(&state, server_id).await;

    let client_id = ClientForm {
        protocol: "dc".to_string(),
        remote_addr: Some(format!("127.0.0.1:{port}")),
        instruction: Some("test client".to_string()),
        startup_params: Some(serde_json::json!({"nickname": "alice"})),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
        tx.clone(),
    )
    .await
    .expect("create dc client");

    wait_for_client_handle(&state, client_id).await;

    // The client's own wire verb (a Custom result), injected from outside its loop:
    // "<alice> dashboard-marker|" is 25 bytes.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "send_dc_chat", "message": "dashboard-marker"}),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_client");
    assert!(
        matches!(outcome, ClientSendOutcome::Sent { bytes_sent: 25 }),
        "expected Sent{{25}}, got {outcome:?}"
    );

    // Recorded on the client like LLM-produced traffic, and received by the hub.
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

    // A verb that only updates local state writes nothing and says so.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "send_dc_filelist", "files": []}),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_client filelist");
    assert!(
        matches!(outcome, ClientSendOutcome::Executed { .. }),
        "expected Executed, got {outcome:?}"
    );

    // An injected disconnect writes $Quit| and half-closes; the hub reads EOF and closes,
    // the client's read loop sees EOF and drops its handle.
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
    wait_for_log_containing(&state, AccessLogOwner::Server(server_id.as_u32()), "$Quit").await;

    for _ in 0..1_000 {
        if !state.has_client_handle(client_id).await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("client handle still registered after the hub closed the connection");
}

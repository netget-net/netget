//! The dashboard's `[ send_key_event ]` path on a VNC client: `AppState::send_to_client`
//! injects an action from outside the client's read loop, and the RFB message reaches a NetGet
//! VNC server of our own. Zero LLM calls - the server answers events through a `*` static
//! handler and the client's LLM points at an unreachable URL (its connected-event call fails;
//! the loop tolerates that, and the command task is independent of it by design).
//!
//! The client's wire verbs all yield `ClientActionResult::Custom`, so the generic
//! `handle_stream_client_command` cannot execute them; the client's own `command_loop` routes
//! them through `send_vnc_message_with_writer`, the same encoder the LLM path uses.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features vnc --test client -- vnc::command_channel --test-threads=100

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
    panic!("VNC server #{} never bound a port", id.as_u32());
}

async fn wait_for_client_handle(state: &AppState, id: ClientId) {
    for _ in 0..1_000 {
        if state.has_client_handle(id).await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!(
        "VNC client #{} never registered a command handle",
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
async fn injected_vnc_key_event_reaches_our_own_server() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    let server_id = ServerForm {
        protocol: "vnc".to_string(),
        port: Some(0),
        startup_params: Some(serde_json::json!({ "width": 32, "height": 32 })),
        event_handlers: Some(vec![serde_json::json!({
            "event_pattern": "*",
            "handler": {
                "type": "static",
                "actions": [ { "type": "vnc_no_change" } ]
            }
        })]),
        ..Default::default()
    }
    .create(&state, tx.clone())
    .await
    .expect("create vnc server");
    let port = wait_for_port(&state, server_id).await;

    let client_id = ClientForm {
        protocol: "vnc".to_string(),
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
    .expect("create vnc client");

    wait_for_client_handle(&state, client_id).await;

    // The client's own wire verb, injected from outside its loop. KeyEvent is 8 bytes on the
    // wire (type + down + 2 padding + 4-byte keysym).
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "send_key_event", "key": "a", "down": true}),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_client");
    assert!(
        matches!(outcome, ClientSendOutcome::Sent { bytes_sent: 8 }),
        "expected Sent{{8}}, got {outcome:?}"
    );

    // Recorded on the client like LLM-produced traffic, and received by the server as a
    // vnc_key_event (the server logs the event id it raised).
    wait_for_log_containing(
        &state,
        AccessLogOwner::Client(client_id.as_u32()),
        "injected_action",
    )
    .await;
    wait_for_log_containing(
        &state,
        AccessLogOwner::Server(server_id.as_u32()),
        "vnc_key_event",
    )
    .await;

    // An injected disconnect half-closes; the read loop sees EOF and drops the command handle.
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
        if !state.has_client_handle(client_id).await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("command handle still registered after the client disconnected");
}

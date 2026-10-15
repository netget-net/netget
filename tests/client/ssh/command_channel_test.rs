//! The dashboard's `[ send ]` path on an SSH client: `AppState::send_to_client` injects an
//! action from outside the client's own tasks, and the command really runs on a NetGet SSH
//! server of our own.
//!
//! Zero LLM calls. The server answers its `ssh_auth` event through a `*` static handler that
//! returns `ssh_auth_decision: allowed`, and the client's LLM points at an unreachable URL
//! (`http://127.0.0.1:1`), so its `ssh_connected` call fails and the loop must tolerate that —
//! which is part of what this verifies: the command channel is registered *before* that call,
//! so `[ send ]` works even while a `*` -> manual rule has it parked.
//!
//! What this does NOT cover: the server's `exec_request` also asks the LLM what the command
//! should print, and with an unreachable backend it prints nothing. So the assertion is on the
//! honest outcome shape (`Executed` naming the exit status and output size), not on command
//! output. SSH can never report `Sent`: russh owns the encrypted transport and NetGet never
//! sees a wire byte count.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features ssh --test client -- ssh::command_channel --test-threads=100


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
    panic!("SSH server #{} never bound a port", id.as_u32());
}

async fn wait_for_client_handle(state: &AppState, id: ClientId) {
    for _ in 0..1_000 {
        if state.has_client_handle(id).await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!(
        "SSH client #{} never registered a command handle",
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
async fn injected_ssh_command_runs_against_our_own_server() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    // `*` -> static ssh_auth_decision{allowed} answers the auth event with no LLM call. The
    // same rule matches the later shell/exec event, which has no output action in it, so the
    // exec produces an empty stdout - deliberately, see the module doc.
    let server_id = ServerForm {
        protocol: "ssh".to_string(),
        port: Some(0),
        event_handlers: Some(vec![serde_json::json!({
            "event_pattern": "*",
            "handler": {
                "type": "static",
                "actions": [ { "type": "ssh_auth_decision", "allowed": true } ]
            }
        })]),
        ..Default::default()
    }
    .create(&state, tx.clone())
    .await
    .expect("create ssh server");
    let port = wait_for_port(&state, server_id).await;

    let client_id = ClientForm {
        protocol: "ssh".to_string(),
        remote_addr: Some(format!("127.0.0.1:{port}")),
        instruction: Some("test client".to_string()),
        startup_params: Some(serde_json::json!({
            "username": "testuser",
            "password": "testpass",
        })),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
        tx.clone(),
    )
    .await
    .expect("create ssh client");

    // The regression guard for "register the channel before the connected-event LLM call".
    wait_for_client_handle(&state, client_id).await;

    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "execute_command", "command": "echo dashboard-marker"}),
            Duration::from_secs(20),
        )
        .await
        .expect("send_to_client");
    match &outcome {
        ClientSendOutcome::Executed { detail } => {
            assert!(
                detail.contains("execute_command") && detail.contains("bytes of output"),
                "detail should name the verb and the output size, got {detail:?}"
            );
        }
        other => panic!("expected Executed{{..}}, got {other:?}"),
    }

    // Recorded on the client like LLM-produced traffic, and the server really saw the exec.
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

    // An injected disconnect closes the session and drops the handle, so a later [ send ]
    // fails fast instead of being offered on a dead client.
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
    panic!("client should have no command handle after an injected disconnect");
}

#[tokio::test]
async fn unknown_action_is_rejected_not_silently_swallowed() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    let server_id = ServerForm {
        protocol: "ssh".to_string(),
        port: Some(0),
        event_handlers: Some(vec![serde_json::json!({
            "event_pattern": "*",
            "handler": {
                "type": "static",
                "actions": [ { "type": "ssh_auth_decision", "allowed": true } ]
            }
        })]),
        ..Default::default()
    }
    .create(&state, tx.clone())
    .await
    .expect("create ssh server");
    let port = wait_for_port(&state, server_id).await;

    let client_id = ClientForm {
        protocol: "ssh".to_string(),
        remote_addr: Some(format!("127.0.0.1:{port}")),
        instruction: Some("test client".to_string()),
        startup_params: Some(serde_json::json!({
            "username": "testuser",
            "password": "testpass",
        })),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
        tx.clone(),
    )
    .await
    .expect("create ssh client");

    wait_for_client_handle(&state, client_id).await;

    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "no_such_ssh_verb"}),
            Duration::from_secs(10),
        )
        .await
        .expect("send_to_client");
    match &outcome {
        ClientSendOutcome::Rejected { error } => {
            assert!(
                error.contains("no_such_ssh_verb"),
                "the rejection must name the verb, got {error:?}"
            );
        }
        other => panic!("expected Rejected{{..}}, got {other:?}"),
    }
}

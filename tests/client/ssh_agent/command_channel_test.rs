//! The dashboard's `[ send ]` path on an SSH Agent client: `AppState::send_to_client` injects
//! an action from outside the client's read loop. Zero LLM calls — the client connects to an
//! in-test Unix socket that parks the connection, its LLM points at an unreachable URL (the
//! connected-event call fails; the loop tolerates that), and the injected actions go through
//! the protocol's own `execute_action`, never a model.
//!
//! Cheap variant, by design. A genuine "bytes arrive on the wire" assertion is disproportionate
//! here for two reasons: (1) the SSH-agent framing is a request/response handshake, and (2) the
//! client's wire verbs (`request_identities`, `sign_request`, …) are `ClientActionResult::Custom`
//! results, and the generic `command_support::handle_stream_client_command` this client wires up
//! deliberately does **not** encode `Custom` results — it reports them `Executed` without
//! writing (see `client/command_support.rs`). So this test verifies the reachable command-channel
//! contract instead: the handle is registered, an injected `Custom` verb is accepted-but-not-
//! written (documenting the gap), an unknown action is rejected, and an injected `disconnect`
//! ends the loop and drops the handle. The wire encoding of the Custom verbs stays covered by
//! `e2e_test.rs`.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features ssh-agent --test client -- ssh_agent::command_channel --test-threads=100

#![cfg(unix)]

use std::time::Duration;

use netget::cli::management::ClientForm;
use netget::state::app_state::AppState;
use netget::state::client_handles::ClientSendOutcome;
use netget::state::ClientId;
use tokio::io::AsyncReadExt;
use tokio::net::UnixListener;
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

async fn wait_for_client_handle(state: &AppState, id: ClientId) {
    for _ in 0..1_000 {
        if state.has_client_handle(id).await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!(
        "ssh_agent client #{} never registered a command handle",
        id.as_u32()
    );
}

#[tokio::test]
async fn injected_ssh_agent_actions_drive_the_command_channel() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    let socket_path = std::env::temp_dir().join(format!(
        "netget_cmdchan_ssh_agent_{}.sock",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&socket_path);
    let listener = UnixListener::bind(&socket_path).expect("bind unix listener");

    // Accept and PARK the connection: keep reading so the socket stays open (and the client's
    // read loop stays live) until the client itself hangs up. Never answers, so no LLM fires.
    tokio::spawn(async move {
        if let Ok((mut stream, _)) = listener.accept().await {
            let mut buf = vec![0u8; 4096];
            loop {
                match stream.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
            }
        }
    });

    let client_id = ClientForm {
        protocol: "ssh-agent".to_string(),
        remote_addr: Some(socket_path.to_string_lossy().to_string()),
        instruction: Some("test client".to_string()),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
        tx.clone(),
    )
    .await
    .expect("create ssh_agent client");

    wait_for_client_handle(&state, client_id).await;

    // A Custom wire verb, injected: the generic command arm accepts it but writes nothing
    // (Custom results need a bespoke arm this client does not provide). It must NOT error.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "request_identities"}),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_client (request_identities)");
    assert!(
        matches!(outcome, ClientSendOutcome::Executed { .. }),
        "expected Executed (Custom not encoded by generic arm), got {outcome:?}"
    );

    // Unknown actions are rejected, not swallowed.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "no_such_action"}),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_client (bad action)");
    assert!(
        matches!(outcome, ClientSendOutcome::Rejected { .. }),
        "expected Rejected, got {outcome:?}"
    );

    // Injected disconnect ends the read loop; the handle is dropped on exit.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "disconnect"}),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_client (disconnect)");
    assert!(
        matches!(outcome, ClientSendOutcome::Disconnected),
        "expected Disconnected, got {outcome:?}"
    );

    for _ in 0..1_000 {
        if !state.has_client_handle(client_id).await {
            let _ = std::fs::remove_file(&socket_path);
            return;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    let _ = std::fs::remove_file(&socket_path);
    panic!("client handle still registered after disconnect");
}

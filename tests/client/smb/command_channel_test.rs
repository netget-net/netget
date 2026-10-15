//! The dashboard's `[ send ]` path on an SMB client: `AppState::send_to_client` injects an
//! action from outside the client's own tasks and it is carried out against the live
//! libsmbclient handle.
//!
//! Zero LLM calls: the client's LLM points at an unreachable URL (`http://127.0.0.1:1`), so its
//! `smb_client_connected` call fails and the loop must tolerate that — which is part of what
//! this verifies, because the command channel is registered *before* that call and must work
//! while a `*` -> manual rule has it parked.
//!
//! `pavao::SmbClient::new` only builds a libsmbclient context; the first real network round trip
//! happens on the first operation. So this test points the client at a port where nothing is
//! listening and asserts the honest outcome: SMB never reports `Sent` (libsmbclient owns and may
//! sign the transport, so NetGet never sees a wire byte count), it reports `Executed` with a
//! specific detail — here, the failure naming the path.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features smb-client --test client -- smb::command_channel --test-threads=100

#![cfg(all(unix, feature = "libsmbclient"))]

use std::time::Duration;

use netget::cli::management::ClientForm;
use netget::state::app_state::AppState;
use netget::state::client_handles::ClientSendOutcome;
use netget::state::{AccessLogOwner, ClientId};
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
        "SMB client #{} never registered a command handle",
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
async fn injected_smb_action_reaches_the_libsmbclient_handle() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    // 127.0.0.1 with no SMB server: creating the client context succeeds, the first
    // operation is what fails, which is exactly the split this test wants.
    let created = ClientForm {
        protocol: "smb".to_string(),
        remote_addr: Some("127.0.0.1".to_string()),
        instruction: Some("test client".to_string()),
        startup_params: Some(serde_json::json!({ "username": "guest", "password": "" })),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
        tx.clone(),
    )
    .await;

    let client_id = match created {
        Ok(id) => id,
        Err(e) => {
            // libsmbclient refused to initialise at all (no smb.conf, no /usr/lib support).
            // The only thing that can still be asserted is rule 3: a client that never
            // finished connecting must not be left offering [ send ].
            for client in state.get_all_clients().await {
                assert!(
                    !state.has_client_handle(client.id).await,
                    "client #{} left a stale command handle after a failed connect",
                    client.id.as_u32()
                );
            }
            eprintln!("SMB context could not be created here, injection half skipped: {e:#}");
            return;
        }
    };

    // The regression guard for "register the channel before the connected-event LLM call".
    wait_for_client_handle(&state, client_id).await;

    // An unknown verb must be reported as a rejection, never swallowed.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "no_such_smb_verb"}),
            Duration::from_secs(10),
        )
        .await
        .expect("send_to_client");
    match &outcome {
        ClientSendOutcome::Rejected { error } => assert!(
            error.contains("no_such_smb_verb"),
            "the rejection must name the verb, got {error:?}"
        ),
        other => panic!("expected Rejected{{..}}, got {other:?}"),
    }

    // A real verb goes all the way to libsmbclient. Nothing is listening, so the honest
    // answer is Executed naming the failure - never Sent, and never silence.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "list_directory", "path": "smb://127.0.0.1/dashboard-marker"}),
            Duration::from_secs(30),
        )
        .await
        .expect("send_to_client list_directory");
    match &outcome {
        ClientSendOutcome::Executed { detail } => assert!(
            detail.contains("list_directory") && detail.contains("dashboard-marker"),
            "detail must name the verb and the path, got {detail:?}"
        ),
        other => panic!("expected Executed{{..}}, got {other:?}"),
    }

    wait_for_log_containing(
        &state,
        AccessLogOwner::Client(client_id.as_u32()),
        "injected_action",
    )
    .await;

    // An injected disconnect drops the handle, so a later [ send ] fails fast.
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

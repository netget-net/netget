//! The dashboard's `[ send ]` path on a WebRTC client.
//!
//! WebRTC needs a real second peer before a data channel can carry anything, and there is none
//! in-tree, so this test pins what *can* be pinned without one: the command channel exists from
//! the moment the client is created (before any LLM call), injected actions run through the
//! protocol's own `execute_action`, the peer connection is reachable from the command loop
//! (`create_channel` really creates a channel on it), and a send on a channel that is not open
//! reports the failure instead of pretending to have sent something.
//!
//! Nothing leaves the machine: `ice_servers: []` turns off the default Google STUN server, so
//! ICE gathers host candidates only.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features webrtc --test client -- webrtc::command_channel --test-threads=100

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
        "WebRTC client #{} never registered a command handle",
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
async fn injected_actions_reach_the_peer_connection() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    let client_id = ClientForm {
        protocol: "webrtc".to_string(),
        remote_addr: Some("manual".to_string()),
        instruction: Some("test client".to_string()),
        // Local only: no STUN, so ICE gathering never leaves the host.
        startup_params: Some(serde_json::json!({ "ice_servers": [] })),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
        tx.clone(),
    )
    .await
    .expect("create webrtc client");

    wait_for_client_handle(&state, client_id).await;

    // The command loop holds the RTCPeerConnection, so this really creates a channel on it.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "create_channel", "channel_label": "dashboard-marker"}),
            Duration::from_secs(10),
        )
        .await
        .expect("send_to_client create_channel");
    match &outcome {
        ClientSendOutcome::Executed { detail } => assert!(
            detail.contains("dashboard-marker"),
            "detail should name the channel, got {detail:?}"
        ),
        other => panic!("expected Executed for create_channel, got {other:?}"),
    }

    // A label nobody opened is a bad parameter, not a silent no-op.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "send_message", "channel": "no-such-channel", "message": "hi"}),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_client unknown channel");
    assert!(
        matches!(outcome, ClientSendOutcome::Rejected { .. }),
        "expected Rejected for an unknown channel, got {outcome:?}"
    );

    // The default channel exists but no peer ever answered the offer, so it is not open.
    // The send must fail loudly rather than report a fake Sent.
    let err = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "send_message", "message": "hi"}),
            Duration::from_secs(5),
        )
        .await
        .expect_err("a send on an unopened data channel must not report success");
    let err = err.to_string();
    assert!(
        err.contains("netget"),
        "the error should name the channel it tried, got {err:?}"
    );

    // Unknown names are refused by the protocol's own execute_action.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "not_a_webrtc_action"}),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_client unknown action");
    assert!(
        matches!(outcome, ClientSendOutcome::Rejected { .. }),
        "expected Rejected, got {outcome:?}"
    );

    // Injected actions are recorded on the client like LLM-produced traffic.
    wait_for_log_containing(
        &state,
        AccessLogOwner::Client(client_id.as_u32()),
        "injected_action",
    )
    .await;

    // Disconnect closes the channels and the peer connection, and drops the handle.
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
    panic!("the command handle should be gone after an injected disconnect");
}

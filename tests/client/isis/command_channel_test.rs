//! The dashboard's `[ send ]` path on an IS-IS client: `AppState::send_to_client` injects an
//! action from outside the client's capture loop.
//!
//! Zero LLM calls - the client's LLM points at an unreachable URL and this client makes no
//! connected-event call at all.
//!
//! # This client can never report `Sent`, and that is the honest answer
//!
//! The IS-IS client is a **receive-only** libpcap sniffer: it opens a capture, never a
//! transmit path, and its entire vocabulary is `analyze_topology` / `wait_for_more` (both of
//! which mean "keep listening; the analysis lives in the LLM's memory") and `stop_capture`.
//! So the outcomes asserted below are the truth, not a stub:
//!
//! * `analyze_topology` → `Executed` with a reason saying no PDU is transmitted;
//! * an unknown verb → `Rejected` by the protocol's own `execute_action`;
//! * `stop_capture` → `Disconnected`, which is real work: it marks the client disconnected,
//!   and the capture loop polls that status every iteration and breaks out.
//!
//! Because none of that touches the pcap handle, this test is privilege-independent. It
//! still points the client at an interface that does not exist so no capture is attempted.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features isis --test client -- isis::command_channel --test-threads=100

#![cfg(all(unix, feature = "libpcap"))]

use std::time::Duration;

use netget::cli::management::ClientForm;
use netget::state::app_state::AppState;
use netget::state::client_handles::ClientSendOutcome;
use netget::state::{AccessLogOwner, ClientId, ClientStatus};
use tokio::sync::mpsc;

/// An interface name no host has. IS-IS is Ethernet-only and is rejected on loopback anyway,
/// so there is no interface this test could legitimately capture on.
const MISSING_INTERFACE: &str = "netget-no-such-if0";

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
        "ISIS client #{} never registered a command handle",
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
async fn injected_isis_actions_are_executed_and_reported_honestly() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    // For the IS-IS client, `remote_addr` is the interface to capture on.
    let client_id = ClientForm {
        protocol: "isis".to_string(),
        remote_addr: Some(MISSING_INTERFACE.to_string()),
        instruction: Some("test client".to_string()),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
        tx.clone(),
    )
    .await
    .expect("create isis client");

    wait_for_client_handle(&state, client_id).await;

    // The client's whole non-lifecycle vocabulary: acknowledged, and honest about the fact
    // that a receive-only capture puts nothing on the wire.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "analyze_topology"}),
            Duration::from_secs(10),
        )
        .await
        .expect("send_to_client analyze_topology");
    match &outcome {
        ClientSendOutcome::Executed { detail } => assert!(
            detail.contains("receive-only"),
            "the reason must say why nothing was sent, got {detail:?}"
        ),
        other => panic!("expected Executed with a reason, got {other:?}"),
    }

    // Recorded on the client like LLM-produced traffic.
    wait_for_log_containing(
        &state,
        AccessLogOwner::Client(client_id.as_u32()),
        "injected_action",
    )
    .await;

    // A verb the protocol does not know is rejected, not silently swallowed. (IS-IS cannot
    // originate an LSP, so this is exactly the shape of a plausible mistake.)
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "send_isis_lsp"}),
            Duration::from_secs(10),
        )
        .await
        .expect("send_to_client unknown verb");
    assert!(
        matches!(&outcome, ClientSendOutcome::Rejected { error } if error.contains("send_isis_lsp")),
        "expected Rejected, got {outcome:?}"
    );

    // `stop_capture` ends the command loop, drops the handle and marks the client
    // disconnected - which is also what stops the capture loop.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "stop_capture"}),
            Duration::from_secs(10),
        )
        .await
        .expect("send_to_client stop_capture");
    assert!(
        matches!(outcome, ClientSendOutcome::Disconnected),
        "expected Disconnected, got {outcome:?}"
    );

    // Either terminal state is correct, and which one wins is a race.
    //
    // `stop_capture` marks the client Disconnected, while the capture task independently
    // fails with Error("Device ... not found") because the test names an interface that
    // does not exist -- deliberately, so the test needs no real NIC and no privileges.
    // Under light load the injected disconnect lands first; under a full --all-protocols
    // run the capture task's failure often gets there first. Asserting only Disconnected
    // made this pass alone and fail in the full suite.
    //
    // What actually matters, and what is asserted, is that the client reaches SOME
    // terminal state and that the command handle is gone -- a live handle on a dead client
    // is what leaves the dashboard offering [ send ] into nothing.
    for _ in 0..1_000 {
        let status = state.get_client(client_id).await.map(|c| c.status);
        let terminal = matches!(
            status,
            Some(ClientStatus::Disconnected) | Some(ClientStatus::Error(_))
        );
        if terminal && !state.has_client_handle(client_id).await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!(
        "client should have reached a terminal state with no command handle; \
         status={:?} has_handle={}",
        state.get_client(client_id).await.map(|c| c.status),
        state.has_client_handle(client_id).await
    );
}

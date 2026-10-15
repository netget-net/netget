//! The dashboard's `[ send ]` path on an mDNS client: `AppState::send_to_client` injects a
//! `browse_service` from outside the client's own tasks and it drives the same
//! `ServiceDaemon` the LLM path drives - so an injected query goes out of the same sockets,
//! to the same multicast group.
//!
//! **The outcome here is `Executed`, not `Sent`, and that is deliberate.** `mdns-sd` owns
//! the multicast socket and reports neither the bytes it puts on the wire nor when; any
//! byte count this client produced would be invented. An honest `Executed { detail }`
//! naming what the daemon was asked to do beats a fabricated `Sent`.
//!
//! Zero LLM calls: every client event is routed to a static handler that answers with no
//! actions, and the client's LLM points at an unreachable URL as a second belt.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features mdns --test client -- mdns::command_channel --test-threads=100


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

/// Regression guard for "register the channel before the connected-event LLM call".
async fn wait_for_client_handle(state: &AppState, id: ClientId) {
    for _ in 0..1_000 {
        if state.has_client_handle(id).await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!(
        "mDNS client #{} never registered a command handle",
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
async fn injected_browse_drives_the_shared_service_daemon() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    // mDNS ignores remote_addr entirely; the form still requires one.
    let client_id = ClientForm {
        protocol: "mdns".to_string(),
        remote_addr: Some("224.0.0.251:5353".to_string()),
        instruction: Some("test client".to_string()),
        event_handlers: Some(vec![serde_json::json!({
            "event_pattern": "*",
            "handler": { "type": "static", "actions": [] }
        })]),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
        tx.clone(),
    )
    .await
    .expect("create mdns client");

    wait_for_client_handle(&state, client_id).await;

    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "not_an_mdns_action"}),
            Duration::from_secs(10),
        )
        .await
        .expect("send_to_client rejected action");
    assert!(
        matches!(outcome, ClientSendOutcome::Rejected { .. }),
        "expected Rejected, got {outcome:?}"
    );

    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({
                "type": "browse_service",
                "service_type": "_netget-marker._tcp.local."
            }),
            Duration::from_secs(10),
        )
        .await
        .expect("send_to_client browse_service");
    match &outcome {
        ClientSendOutcome::Executed { detail } => assert!(
            detail.contains("browse_service") && detail.contains("_netget-marker._tcp.local."),
            "detail should name what the daemon was asked to do, got {detail:?}"
        ),
        other => panic!("expected Executed, got {other:?}"),
    }

    wait_for_log_containing(
        &state,
        AccessLogOwner::Client(client_id.as_u32()),
        "injected_action",
    )
    .await;

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

    let mut handle_gone = false;
    for _ in 0..1_000 {
        if !state.has_client_handle(client_id).await {
            handle_gone = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    assert!(
        handle_gone,
        "command handle should be gone after an injected disconnect"
    );

    // The browse the test started keeps a task polling the daemon for as long as the
    // client row exists (that is the client's own stop condition), so tear it down
    // rather than leaving it spinning for the rest of the suite.
    state.remove_client(client_id).await;
}

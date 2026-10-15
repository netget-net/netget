//! The dashboard's `[ send ]` path on a UDP client: `AppState::send_to_client` injects an
//! action from outside the client's receive loop and the datagram really leaves the socket.
//!
//! Zero LLM calls - the client's LLM points at an unreachable URL, so its connected-event
//! call fails and the loop has to tolerate that; the command task is independent of it by
//! design, which is half of what this test proves.
//!
//! The peer here is a plain `tokio::net::UdpSocket` rather than a NetGet UDP server: what
//! needs proving is that *these exact bytes* reached the wire, and a raw socket asserts that
//! directly instead of through a server's event pipeline.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features udp --test client -- udp::command_channel --test-threads=100

use std::time::Duration;

use netget::cli::management::ClientForm;
use netget::state::app_state::AppState;
use netget::state::client_handles::ClientSendOutcome;
use netget::state::{AccessLogOwner, ClientId};
use tokio::net::UdpSocket;
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

/// Regression guard for the "register the channel before the connect LLM call" rule: if the
/// handle only appeared after that call, this poll would time out whenever the call parks.
async fn wait_for_client_handle(state: &AppState, id: ClientId) {
    for _ in 0..1_000 {
        if state.has_client_handle(id).await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!(
        "UDP client #{} never registered a command handle",
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
async fn injected_udp_datagram_reaches_the_peer() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    let peer = UdpSocket::bind("127.0.0.1:0").await.expect("bind peer");
    let peer_addr = peer.local_addr().expect("peer addr");

    let client_id = ClientForm {
        protocol: "udp".to_string(),
        remote_addr: Some(peer_addr.to_string()),
        instruction: Some("test client".to_string()),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
        tx.clone(),
    )
    .await
    .expect("create udp client");

    wait_for_client_handle(&state, client_id).await;

    // "dashboard-marker" is 16 bytes; `send_to` reports what really left the socket.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({
                "type": "send_udp_datagram",
                "data_hex": hex::encode("dashboard-marker"),
            }),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_client");
    assert!(
        matches!(outcome, ClientSendOutcome::Sent { bytes_sent: 16 }),
        "expected Sent{{16}}, got {outcome:?}"
    );

    let mut buf = vec![0u8; 1024];
    let (n, from) = tokio::time::timeout(Duration::from_secs(5), peer.recv_from(&mut buf))
        .await
        .expect("peer received nothing")
        .expect("peer recv failed");
    assert_eq!(&buf[..n], b"dashboard-marker");
    assert_eq!(from.ip().to_string(), "127.0.0.1");

    // Recorded on the client like LLM-produced traffic.
    wait_for_log_containing(
        &state,
        AccessLogOwner::Client(client_id.as_u32()),
        "injected_action",
    )
    .await;

    // `change_target` runs but writes nothing: an honest Executed, not a faked Sent.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "change_target", "new_target": peer_addr.to_string()}),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_client change_target");
    match outcome {
        ClientSendOutcome::Executed { ref detail } => {
            assert!(
                detail.contains("default target changed"),
                "unexpected detail: {detail}"
            );
        }
        other => panic!("expected Executed, got {other:?}"),
    }

    // A verb this client does not have is Rejected, never silently swallowed.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "not_a_udp_verb"}),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_client unknown");
    assert!(
        matches!(outcome, ClientSendOutcome::Rejected { .. }),
        "expected Rejected, got {outcome:?}"
    );

    // An injected close_socket ends the command loop and drops the handle.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "close_socket"}),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_client close_socket");
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
    panic!("command handle should be gone after an injected close_socket");
}

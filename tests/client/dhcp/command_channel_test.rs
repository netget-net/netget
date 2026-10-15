//! The dashboard's `[ send ]` path on a DHCP client: `AppState::send_to_client` injects an
//! action from outside the client's receive loop and the datagram really leaves the socket.
//!
//! Zero LLM calls: every client event is routed to a static handler that answers with no
//! actions, and the client's LLM points at an unreachable URL as a second belt.
//!
//! The receiver is a plain UDP socket rather than a NetGet DHCP server, because a DHCP
//! server binds privileged port 67 and this suite must run unprivileged. A raw socket is
//! also the stricter assertion: it shows the exact bytes and their length.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features dhcp --test client -- dhcp::command_channel --test-threads=100


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

/// Regression guard for "register the channel before the connected-event LLM call".
async fn wait_for_client_handle(state: &AppState, id: ClientId) {
    for _ in 0..1_000 {
        if state.has_client_handle(id).await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!(
        "DHCP client #{} never registered a command handle",
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
async fn injected_dhcp_discover_reaches_the_wire() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    // Stand-in DHCP server: we only need to observe the datagram.
    let server = UdpSocket::bind("127.0.0.1:0").await.expect("bind receiver");
    let server_addr = server.local_addr().unwrap();

    // The client prefers port 68 and falls back to an ephemeral port unprivileged;
    // creation must succeed either way, which is itself part of what this asserts.
    let client_id = ClientForm {
        protocol: "dhcp".to_string(),
        remote_addr: Some(server_addr.to_string()),
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
    .expect("create dhcp client");

    wait_for_client_handle(&state, client_id).await;

    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "not_a_dhcp_action"}),
            Duration::from_secs(10),
        )
        .await
        .expect("send_to_client rejected action");
    assert!(
        matches!(outcome, ClientSendOutcome::Rejected { .. }),
        "expected Rejected, got {outcome:?}"
    );

    // `broadcast: false` unicasts to the configured server, which is our socket.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({
                "type": "dhcp_discover",
                "mac_address": "00:11:22:33:44:55",
                "broadcast": false
            }),
            Duration::from_secs(10),
        )
        .await
        .expect("send_to_client dhcp_discover");
    let bytes_sent = match outcome {
        ClientSendOutcome::Sent { bytes_sent } => bytes_sent,
        other => panic!("expected Sent, got {other:?}"),
    };

    let mut buf = vec![0u8; 2048];
    let (n, _from) = tokio::time::timeout(Duration::from_secs(5), server.recv_from(&mut buf))
        .await
        .expect("no DHCP datagram arrived")
        .expect("recv_from");

    // `Sent { bytes_sent }` must be the real datagram length, not a hopeful one.
    assert_eq!(n, bytes_sent, "reported byte count differs from the wire");
    assert_eq!(buf[0], 1, "op should be BootRequest");
    assert_eq!(
        &buf[28..34],
        &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
        "chaddr should carry the MAC we injected"
    );
    assert_eq!(
        &buf[236..240],
        &[0x63, 0x82, 0x53, 0x63],
        "DHCP magic cookie should be present"
    );

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

    for _ in 0..1_000 {
        if !state.has_client_handle(client_id).await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("command handle should be gone after an injected disconnect");
}

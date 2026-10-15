//! The dashboard's `[ send ]` path on an NTP client: `AppState::send_to_client` injects
//! `query_time` from outside the client's own task and the 48-byte request really leaves the
//! socket.
//!
//! This is also the client's only multi-query path. The connect-time task marks the client
//! Disconnected after its single query, but the socket stays bound and the command channel
//! stays registered, so an injected `query_time` runs another exchange.
//!
//! Zero LLM calls - the client's LLM points at an unreachable URL, so its initial call fails
//! and the loop has to tolerate that. The peer is a plain `tokio::net::UdpSocket` because
//! what needs proving is that these exact bytes reached the wire.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features ntp --test client -- ntp::command_channel --test-threads=100


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

/// Regression guard for the "register the channel before the connect LLM call" rule.
async fn wait_for_client_handle(state: &AppState, id: ClientId) {
    for _ in 0..1_000 {
        if state.has_client_handle(id).await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!(
        "NTP client #{} never registered a command handle",
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
async fn injected_query_time_puts_an_ntp_request_on_the_wire() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    let peer = UdpSocket::bind("127.0.0.1:0").await.expect("bind peer");
    let peer_addr = peer.local_addr().expect("peer addr");

    let client_id = ClientForm {
        protocol: "ntp".to_string(),
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
    .expect("create ntp client");

    wait_for_client_handle(&state, client_id).await;

    // A verb this client does not have is Rejected. Done first because it writes nothing and
    // therefore never waits on a reply.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "not_an_ntp_verb"}),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_client unknown");
    assert!(
        matches!(outcome, ClientSendOutcome::Rejected { .. }),
        "expected Rejected, got {outcome:?}"
    );

    // An NTP client request is exactly 48 bytes (RFC 5905 §7.3).
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "query_time"}),
            Duration::from_secs(10),
        )
        .await
        .expect("send_to_client query_time");
    assert!(
        matches!(outcome, ClientSendOutcome::Sent { bytes_sent: 48 }),
        "expected Sent{{48}}, got {outcome:?}"
    );

    let mut buf = vec![0u8; 128];
    let (n, from) = tokio::time::timeout(Duration::from_secs(5), peer.recv_from(&mut buf))
        .await
        .expect("peer received nothing")
        .expect("peer recv failed");
    assert_eq!(n, 48, "an NTP request is 48 bytes");
    assert_eq!(buf[0], 0x1b, "LI=0, VN=3, Mode=3 (client)");

    // Answer so the client's follow-up receive completes promptly instead of sitting out its
    // 5-second timeout. Stratum 2, precision -20.
    let mut reply = vec![0u8; 48];
    reply[0] = 0x1c; // LI=0, VN=3, Mode=4 (server)
    reply[1] = 2;
    reply[3] = 0xec_u8; // -20 as i8
    reply[40..44].copy_from_slice(&[0xe9, 0x00, 0x00, 0x00]);
    peer.send_to(&reply, from).await.expect("peer reply");

    wait_for_log_containing(
        &state,
        AccessLogOwner::Client(client_id.as_u32()),
        "injected_action",
    )
    .await;

    // An injected disconnect ends the command loop and drops the handle. Generous timeout:
    // the loop is still finishing the previous query's LLM report, which has to fail against
    // the unreachable endpoint first.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "disconnect"}),
            Duration::from_secs(30),
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

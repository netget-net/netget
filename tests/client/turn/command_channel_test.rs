//! The dashboard's `[ send ]` path on a TURN client: `AppState::send_to_client` injects an
//! action from outside the client's read loop and the STUN/TURN message really leaves the
//! socket.
//!
//! Zero LLM calls - the client's LLM points at an unreachable URL, so its connected-event
//! call fails and the loop must tolerate that (part of what this verifies). The peer is a
//! plain UDP socket rather than a NetGet TURN server: the point of the test is that the
//! datagram reached the wire with the byte count the outcome claims, and a raw socket proves
//! exactly that without depending on any server-side allocation state.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features turn --test client -- turn::command_channel --test-threads=100

#![cfg(unix)]

use std::time::Duration;

use netget::cli::management::ClientForm;
use netget::state::app_state::AppState;
use netget::state::client_handles::ClientSendOutcome;
use netget::state::{AccessLogOwner, ClientId, ClientStatus};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

const STUN_MAGIC_COOKIE: [u8; 4] = [0x21, 0x12, 0xA4, 0x42];

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
        "TURN client #{} never registered a command handle",
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

/// Receive one datagram and return it, failing the test rather than hanging.
async fn recv_one(peer: &UdpSocket) -> Vec<u8> {
    let mut buf = vec![0u8; 2048];
    let (n, _from) = tokio::time::timeout(Duration::from_secs(5), peer.recv_from(&mut buf))
        .await
        .expect("no TURN datagram arrived within 5s")
        .expect("recv_from");
    buf.truncate(n);
    buf
}

#[tokio::test]
async fn injected_turn_actions_reach_the_server() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    // Stand-in for the TURN server: whatever the client sends lands here.
    let peer = UdpSocket::bind("127.0.0.1:0").await.expect("bind peer");
    let peer_addr = peer.local_addr().expect("peer addr");

    let client_id = ClientForm {
        protocol: "turn".to_string(),
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
    .expect("create turn client");

    // Regression guard for "register the channel before the connected-event LLM call".
    wait_for_client_handle(&state, client_id).await;

    // Allocate: the client's own wire verb, injected from outside its read loop.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "allocate_turn_relay", "lifetime_seconds": 600}),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_client allocate_turn_relay");
    let bytes_sent = match outcome {
        ClientSendOutcome::Sent { bytes_sent } => bytes_sent,
        other => panic!("expected Sent, got {other:?}"),
    };

    let datagram = recv_one(&peer).await;
    assert_eq!(
        datagram.len(),
        bytes_sent,
        "outcome claimed {bytes_sent} bytes, wire had {}",
        datagram.len()
    );
    assert_eq!(
        &datagram[0..2],
        &[0x00, 0x03],
        "expected an Allocate request (0x0003)"
    );
    assert_eq!(
        &datagram[4..8],
        &STUN_MAGIC_COOKIE,
        "not a STUN message: {datagram:02x?}"
    );

    // Recorded on the client like LLM-produced traffic.
    wait_for_log_containing(
        &state,
        AccessLogOwner::Client(client_id.as_u32()),
        "injected_action",
    )
    .await;

    // Relayed payload: a Send indication carrying the injected bytes.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({
                "type": "send_turn_data",
                "peer_address": "127.0.0.1:9",
                "data_hex": "6e6574676574",
            }),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_client send_turn_data");
    let bytes_sent = match outcome {
        ClientSendOutcome::Sent { bytes_sent } => bytes_sent,
        other => panic!("expected Sent, got {other:?}"),
    };
    let datagram = recv_one(&peer).await;
    assert_eq!(datagram.len(), bytes_sent);
    assert_eq!(
        &datagram[0..2],
        &[0x00, 0x16],
        "expected a Send indication (0x0016)"
    );
    assert!(
        datagram
            .windows(6)
            .any(|w| w == [0x6e, 0x65, 0x74, 0x67, 0x65, 0x74]),
        "the injected payload is not in the indication: {datagram:02x?}"
    );

    // A verb the protocol does not know is rejected, not silently swallowed.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "channel_bind"}),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_client unknown verb");
    assert!(
        matches!(&outcome, ClientSendOutcome::Rejected { error } if error.contains("channel_bind")),
        "expected Rejected, got {outcome:?}"
    );

    // A declared-but-wireless verb reports Executed, never a fake Sent{0}.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "wait_for_more"}),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_client wait_for_more");
    assert!(
        matches!(&outcome, ClientSendOutcome::Executed { .. }),
        "expected Executed, got {outcome:?}"
    );

    // `disconnect` deletes the allocation with Refresh(lifetime=0) - real bytes go out - and
    // then ends the command loop, drops the handle and marks the client disconnected.
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
    let datagram = recv_one(&peer).await;
    assert_eq!(
        &datagram[0..2],
        &[0x00, 0x04],
        "expected a Refresh request (0x0004) on disconnect"
    );

    for _ in 0..1_000 {
        let status = state.get_client(client_id).await.map(|c| c.status);
        if matches!(status, Some(ClientStatus::Disconnected))
            && !state.has_client_handle(client_id).await
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!(
        "client should be Disconnected with no command handle; status={:?} has_handle={}",
        state.get_client(client_id).await.map(|c| c.status),
        state.has_client_handle(client_id).await
    );
}

//! The dashboard's `[ send ]` path on a SIP client: `AppState::send_to_client` injects an
//! action from outside the client's read loop and the request really leaves the socket.
//!
//! Zero LLM calls - the client's LLM points at an unreachable URL, so its connected-event
//! call fails and the loop must tolerate that (part of what this verifies). The peer is a
//! plain UDP socket rather than a NetGet SIP server: the point of the test is that the
//! datagram reached the wire with the byte count the outcome claims, and a raw socket
//! proves exactly that without depending on any server-side behaviour.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features sip --test client -- sip::command_channel --test-threads=100


use std::time::Duration;

use netget::cli::management::ClientForm;
use netget::state::app_state::AppState;
use netget::state::client_handles::ClientSendOutcome;
use netget::state::{AccessLogOwner, ClientId, ClientStatus};
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

async fn wait_for_client_handle(state: &AppState, id: ClientId) {
    for _ in 0..1_000 {
        if state.has_client_handle(id).await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!(
        "SIP client #{} never registered a command handle",
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
async fn injected_sip_request_reaches_the_peer() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    // Stand-in for the SIP server: whatever the client sends lands here.
    let peer = UdpSocket::bind("127.0.0.1:0").await.expect("bind peer");
    let peer_addr = peer.local_addr().expect("peer addr");

    let client_id = ClientForm {
        protocol: "sip".to_string(),
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
    .expect("create sip client");

    // Regression guard for "register the channel before the connected-event LLM call".
    wait_for_client_handle(&state, client_id).await;

    // The client's own wire verb, injected from outside its read loop.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({
                "type": "sip_options",
                "from": "sip:probe@127.0.0.1",
                "to": "sip:peer@127.0.0.1",
                "request_uri": "sip:peer@127.0.0.1",
            }),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_client sip_options");
    let bytes_sent = match outcome {
        ClientSendOutcome::Sent { bytes_sent } => bytes_sent,
        other => panic!("expected Sent, got {other:?}"),
    };

    // `Sent { bytes_sent }` must be the truth: that many bytes, on the wire, as one datagram.
    let mut buf = vec![0u8; 65535];
    let (n, _from) = tokio::time::timeout(Duration::from_secs(5), peer.recv_from(&mut buf))
        .await
        .expect("no SIP datagram arrived within 5s")
        .expect("recv_from");
    assert_eq!(
        n, bytes_sent,
        "outcome claimed {bytes_sent} bytes, wire had {n}"
    );
    let request = String::from_utf8_lossy(&buf[..n]).to_string();
    assert!(
        request.starts_with("OPTIONS sip:peer@127.0.0.1 SIP/2.0\r\n"),
        "unexpected request on the wire: {request:?}"
    );
    assert!(
        request.contains("From: <sip:probe@127.0.0.1>;tag="),
        "injected action's fields did not reach the request: {request:?}"
    );

    // Recorded on the client like LLM-produced traffic.
    wait_for_log_containing(
        &state,
        AccessLogOwner::Client(client_id.as_u32()),
        "injected_action",
    )
    .await;

    // A verb the protocol does not know is rejected, not silently swallowed.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "sip_publish"}),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_client unknown verb");
    assert!(
        matches!(&outcome, ClientSendOutcome::Rejected { error } if error.contains("sip_publish")),
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
        matches!(&outcome, ClientSendOutcome::Executed { detail } if detail == "wait_for_more"),
        "expected Executed(wait_for_more), got {outcome:?}"
    );

    // SIP runs over UDP, so `disconnect` closes nothing on the wire; it ends the command
    // loop, drops the handle and marks the client disconnected.
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

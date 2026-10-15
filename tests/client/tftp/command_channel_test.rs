//! The dashboard's `[ send ]` path on a TFTP client: `AppState::send_to_client` injects
//! actions from outside the transfer loop and the packets really leave the socket.
//!
//! Both shapes are covered: `send_ack`, whose executor already produces
//! `ClientActionResult::SendData`, and `tftp_read_file`, which starts a transfer — the RRQ is
//! awaited before the outcome is reported, so it is a real `Sent` and not a dispatch.
//!
//! Zero LLM calls - the client's LLM points at an unreachable URL, so its `tftp_connected`
//! call fails and `connect()` has to tolerate that. That call runs *inline* in `connect()`,
//! which is exactly why the command channel is registered before it.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features tftp --test client -- tftp::command_channel --test-threads=100


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
        "TFTP client #{} never registered a command handle",
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
async fn injected_tftp_packets_reach_the_server() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    let server = UdpSocket::bind("127.0.0.1:0").await.expect("bind server");
    let server_addr = server.local_addr().expect("server addr");

    let client_id = ClientForm {
        protocol: "tftp".to_string(),
        remote_addr: Some(server_addr.to_string()),
        instruction: Some("test client".to_string()),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
        tx.clone(),
    )
    .await
    .expect("create tftp client");

    wait_for_client_handle(&state, client_id).await;

    // ACK is opcode(2) + block(2) = 4 bytes.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "send_ack", "block_number": 7}),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_client send_ack");
    assert!(
        matches!(outcome, ClientSendOutcome::Sent { bytes_sent: 4 }),
        "expected Sent{{4}}, got {outcome:?}"
    );

    let mut buf = vec![0u8; 1024];
    let (n, _from) = tokio::time::timeout(Duration::from_secs(5), server.recv_from(&mut buf))
        .await
        .expect("server received nothing")
        .expect("server recv failed");
    assert_eq!(&buf[..n], &[0x00, 0x04, 0x00, 0x07], "ACK for block 7");

    // A bad parameter is Rejected by the protocol's own executor.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "send_ack"}),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_client bad send_ack");
    assert!(
        matches!(outcome, ClientSendOutcome::Rejected { .. }),
        "expected Rejected, got {outcome:?}"
    );

    // Starting a transfer: the RRQ is awaited, so the byte count is real.
    // 2 (opcode) + "pxelinux.0" (10) + NUL + "octet" (5) + NUL = 19.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({
                "type": "tftp_read_file",
                "filename": "pxelinux.0",
                "mode": "octet"
            }),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_client tftp_read_file");
    assert!(
        matches!(outcome, ClientSendOutcome::Sent { bytes_sent: 19 }),
        "expected Sent{{19}}, got {outcome:?}"
    );

    let (n, _from) = tokio::time::timeout(Duration::from_secs(5), server.recv_from(&mut buf))
        .await
        .expect("server received no RRQ")
        .expect("server recv failed");
    assert_eq!(&buf[..2], &[0x00, 0x01], "opcode RRQ");
    assert_eq!(&buf[2..n], b"pxelinux.0\0octet\0");

    wait_for_log_containing(
        &state,
        AccessLogOwner::Client(client_id.as_u32()),
        "injected_action",
    )
    .await;

    // An injected disconnect ends the command loop and drops the handle.
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
        if !state.has_client_handle(client_id).await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("command handle should be gone after an injected disconnect");
}

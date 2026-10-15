//! The dashboard's `[ send ]` path on a RIP client: `AppState::send_to_client` injects an
//! action from outside the client's receive loop and the RIP Request really leaves the
//! socket.
//!
//! Zero LLM calls: the client's LLM points at an unreachable URL, so its connected-event
//! call fails immediately and `connect_with_llm_actions` must tolerate that - which is part
//! of what this verifies. The "router" is a plain UDP socket owned by the test; it never
//! answers, so no `rip_response_received` event fires and no further LLM call is attempted.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features rip --test client -- rip::command_channel --test-threads=100


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
        "RIP client #{} never registered a command handle",
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
async fn injected_rip_request_reaches_the_router() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    // A stand-in RIP router: we only need it to receive.
    let router = UdpSocket::bind("127.0.0.1:0").await.expect("bind router");
    let router_addr = router.local_addr().unwrap();

    let client_id = ClientForm {
        protocol: "RIP".to_string(),
        remote_addr: Some(router_addr.to_string()),
        instruction: Some("test client".to_string()),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
        tx.clone(),
    )
    .await
    .expect("create rip client");

    wait_for_client_handle(&state, client_id).await;

    // The client's own wire verb, injected from outside its loop. A RIP Request is a
    // 4-byte header plus one 20-byte route entry.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "send_rip_request", "version": 2}),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_client");
    assert!(
        matches!(outcome, ClientSendOutcome::Sent { bytes_sent: 24 }),
        "expected Sent{{24}}, got {outcome:?}"
    );

    // The datagram is real: it arrives at the router and decodes as a RIPv2 Request.
    let mut buf = vec![0u8; 1500];
    let (n, _from) = tokio::time::timeout(Duration::from_secs(5), router.recv_from(&mut buf))
        .await
        .expect("router received no datagram")
        .expect("recv_from");
    assert_eq!(n, 24, "RIP Request should be 24 bytes on the wire");
    assert_eq!(buf[0], 1, "command should be Request(1)");
    assert_eq!(buf[1], 2, "version should be 2");

    // Recorded on the client like LLM-produced traffic.
    wait_for_log_containing(
        &state,
        AccessLogOwner::Client(client_id.as_u32()),
        "injected_action",
    )
    .await;

    // `wait_for_more` runs but writes nothing - reported honestly, not as Sent{0}.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "wait_for_more"}),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_client wait_for_more");
    match outcome {
        ClientSendOutcome::Executed { ref detail } => {
            assert!(detail.contains("wait_for_more"), "detail was {detail:?}")
        }
        other => panic!("expected Executed, got {other:?}"),
    }

    // An action the protocol does not know is refused, not silently swallowed.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "definitely_not_a_rip_verb"}),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_client unknown");
    assert!(
        matches!(outcome, ClientSendOutcome::Rejected { .. }),
        "expected Rejected, got {outcome:?}"
    );

    // UDP has no wire close, so an injected `disconnect` means: stop receiving, release the
    // socket, drop the handle so [ send ] is greyed out again.
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

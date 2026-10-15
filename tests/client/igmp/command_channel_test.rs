//! The dashboard's `[ send ]` path on an IGMP client: `AppState::send_to_client` injects an
//! action from outside the client's receive loop and `send_multicast` really puts bytes on
//! the wire.
//!
//! Zero LLM calls: the client's LLM points at an unreachable URL, so its connected-event
//! call fails immediately and `connect_with_llm_actions` must tolerate that - which is part
//! of what this verifies. Nothing is sent *to* the client, so no `igmp_data_received` event
//! fires and no further LLM call is attempted.
//!
//! Two deliberate limits, asserted rather than papered over:
//!
//! * The destination is a loopback UDP socket, not a real multicast group. `send_multicast`
//!   is a plain `send_to` on the client's own socket, so this exercises the whole injected
//!   path end to end; using a real group would make the test depend on the host having a
//!   multicast-capable interface and on IGMP snooping, which is not something a unit test
//!   can guarantee. Group *joins* are covered by the honest outcome assertion below, not by
//!   a wire assertion.
//! * IGMP's vocabulary has no `disconnect` verb (see `get_async_actions`), so injecting one
//!   is `Rejected`. Ending an IGMP client is `remove_client`, not a wire action.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features igmp --test client -- igmp::command_channel --test-threads=100

#![cfg(unix)]

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

async fn wait_for_client_handle(state: &AppState, id: ClientId) {
    for _ in 0..1_000 {
        if state.has_client_handle(id).await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!(
        "IGMP client #{} never registered a command handle",
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
async fn injected_send_multicast_reaches_the_wire() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    // Destination for the injected datagram.
    let sink = UdpSocket::bind("127.0.0.1:0").await.expect("bind sink");
    let sink_addr = sink.local_addr().unwrap();

    // `remote_addr` is the IGMP client's *bind* address.
    let client_id = ClientForm {
        protocol: "igmp".to_string(),
        remote_addr: Some("127.0.0.1:0".to_string()),
        instruction: Some("test client".to_string()),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
        tx.clone(),
    )
    .await
    .expect("create igmp client");

    wait_for_client_handle(&state, client_id).await;

    // "netget" = 6 bytes.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({
                "type": "send_multicast",
                "multicast_addr": sink_addr.ip().to_string(),
                "port": sink_addr.port(),
                "data_hex": "6e6574676574"
            }),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_client");
    assert!(
        matches!(outcome, ClientSendOutcome::Sent { bytes_sent: 6 }),
        "expected Sent{{6}}, got {outcome:?}"
    );

    let mut buf = vec![0u8; 256];
    let (n, _from) = tokio::time::timeout(Duration::from_secs(5), sink.recv_from(&mut buf))
        .await
        .expect("sink received no datagram")
        .expect("recv_from");
    assert_eq!(&buf[..n], b"netget", "payload should reach the wire intact");

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

    // An action the protocol does not know is refused, not silently swallowed. IGMP's
    // vocabulary has no `disconnect`, so that lands here too.
    for action in [
        serde_json::json!({"type": "definitely_not_an_igmp_verb"}),
        serde_json::json!({"type": "disconnect"}),
    ] {
        let outcome = state
            .send_to_client(client_id, action.clone(), Duration::from_secs(5))
            .await
            .expect("send_to_client unknown");
        assert!(
            matches!(outcome, ClientSendOutcome::Rejected { .. }),
            "expected Rejected for {action}, got {outcome:?}"
        );
    }

    // A malformed known verb is rejected by the protocol's own parameter checks, so the
    // command channel never reaches the socket with it.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "send_multicast", "multicast_addr": "239.1.2.3"}),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_client malformed");
    assert!(
        matches!(outcome, ClientSendOutcome::Rejected { .. }),
        "expected Rejected, got {outcome:?}"
    );
}

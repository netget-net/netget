//! The dashboard's `[ send ]` path on an SNMP client: `AppState::send_to_client` injects a
//! `send_snmp_get` and the BER-encoded GetRequest really leaves the socket.
//!
//! This client has no standing read loop - each request awaits its own reply - so the
//! commands are drained by a task of their own, and the outcome is reported as soon as the
//! datagram is on the wire rather than after the reply timeout. `retries: 0` and a short
//! `timeout_ms` keep the abandoned reply wait from outliving the test.
//!
//! Zero LLM calls: every client event is routed to a static handler that answers with no
//! actions, and the client's LLM points at an unreachable URL as a second belt.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features snmp --test client -- snmp::command_channel --test-threads=100


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
        "SNMP client #{} never registered a command handle",
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
async fn injected_snmp_get_reaches_the_wire() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    // Stand-in SNMP agent: we only need to observe the request PDU.
    let agent = UdpSocket::bind("127.0.0.1:0").await.expect("bind agent");
    let agent_addr = agent.local_addr().unwrap();

    let client_id = ClientForm {
        protocol: "snmp".to_string(),
        remote_addr: Some(agent_addr.to_string()),
        instruction: Some("test client".to_string()),
        startup_params: Some(serde_json::json!({
            "community": "netget-marker",
            "version": "v2c",
            "timeout_ms": 200,
            "retries": 0
        })),
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
    .expect("create snmp client");

    wait_for_client_handle(&state, client_id).await;

    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "not_an_snmp_action"}),
            Duration::from_secs(10),
        )
        .await
        .expect("send_to_client rejected action");
    assert!(
        matches!(outcome, ClientSendOutcome::Rejected { .. }),
        "expected Rejected, got {outcome:?}"
    );

    // A GET with no OIDs is rejected by the protocol's own validation, before any
    // encoding happens.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "send_snmp_get", "oids": []}),
            Duration::from_secs(10),
        )
        .await
        .expect("send_to_client empty get");
    assert!(
        matches!(outcome, ClientSendOutcome::Rejected { .. }),
        "expected Rejected for an OID-less GET, got {outcome:?}"
    );

    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({
                "type": "send_snmp_get",
                "oids": ["1.3.6.1.2.1.1.1.0"]
            }),
            Duration::from_secs(10),
        )
        .await
        .expect("send_to_client snmp get");
    let bytes_sent = match outcome {
        ClientSendOutcome::Sent { bytes_sent } => bytes_sent,
        other => panic!("expected Sent, got {other:?}"),
    };

    let mut buf = vec![0u8; 65535];
    let (n, _from) = tokio::time::timeout(Duration::from_secs(5), agent.recv_from(&mut buf))
        .await
        .expect("no SNMP datagram arrived")
        .expect("recv_from");

    assert_eq!(n, bytes_sent, "reported byte count differs from the wire");
    assert_eq!(buf[0], 0x30, "an SNMP message is a BER SEQUENCE");
    assert!(
        buf[..n]
            .windows(b"netget-marker".len())
            .any(|w| w == b"netget-marker"),
        "the community string from startup_params should be on the wire"
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

//! Dashboard injection into a running BitTorrent peer-wire client
//! (`AppState::send_to_client`): a NetGet torrent-peer client connected to a NetGet
//! torrent-peer server, with a wire verb injected from outside the client's loop.
//!
//! Zero LLM calls: the server uses a static handler and the client's LLM points at an
//! unreachable URL (the loops tolerate that error). The client's read loop uses `read_exact`
//! (not cancellation-safe), so the command channel is drained by its own task.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features torrent-peer --test client -- torrent_peer::command_channel --test-threads=100


use std::time::Duration;

use netget::cli::management::{ClientForm, ServerForm};
use netget::state::app_state::AppState;
use netget::state::client_handles::ClientSendOutcome;
use netget::state::{AccessLogOwner, ClientId, ServerId};
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

async fn wait_for_port(state: &AppState, id: ServerId) -> u16 {
    for _ in 0..1_000 {
        if let Some(s) = state.get_server(id).await {
            if let Some(addr) = s.local_addr {
                return addr.port();
            }
            if s.port != 0 {
                return s.port;
            }
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("server #{} never bound a port", id.as_u32());
}

async fn wait_for_client_handle(state: &AppState, id: ClientId) {
    for _ in 0..1_000 {
        if state.has_client_handle(id).await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("client #{} never registered a command handle", id.as_u32());
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
async fn injected_peer_handshake_reaches_our_own_server() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    // Server echoes the handshake's info_hash back, so an injected client handshake completes
    // a real round-trip on the wire.
    let server_id = ServerForm {
        protocol: "torrent-peer".to_string(),
        port: Some(0),
        event_handlers: Some(vec![serde_json::json!({
            "event_pattern": "peer_handshake",
            "handler": {
                "type": "static",
                "actions": [ {
                    "type": "send_handshake",
                    "info_hash": "{{event.info_hash}}",
                    "peer_id": "-NT0001-xxxxxxxxxxxx"
                } ]
            }
        })]),
        ..Default::default()
    }
    .create(&state, tx.clone())
    .await
    .expect("create torrent-peer server");
    let port = wait_for_port(&state, server_id).await;

    let client_id = ClientForm {
        protocol: "torrent-peer".to_string(),
        remote_addr: Some(format!("127.0.0.1:{port}")),
        instruction: Some("test client".to_string()),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
        tx.clone(),
    )
    .await
    .expect("create torrent-peer client");

    wait_for_client_handle(&state, client_id).await;

    // Inject a handshake (info_hash + peer_id, 40 hex chars each). The command loop encodes
    // the fixed 68-byte handshake through the same execute_peer_action the LLM path uses.
    let info_hash_hex = "abababababababababababababababababababab";
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({
                "type": "peer_handshake",
                "info_hash": info_hash_hex,
                "peer_id": "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
            }),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_client");
    match outcome {
        ClientSendOutcome::Sent { bytes_sent } => assert_eq!(bytes_sent, 68),
        other => panic!("expected Sent, got {other:?}"),
    }

    // The server parsed the handshake and logged it (echoed info_hash) …
    wait_for_log_containing(
        &state,
        AccessLogOwner::Server(server_id.as_u32()),
        info_hash_hex,
    )
    .await;
    // … and the injection is in the client's own request log.
    wait_for_log_containing(
        &state,
        AccessLogOwner::Client(client_id.as_u32()),
        "injected_action",
    )
    .await;

    // Unknown actions are rejected, not swallowed.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "no_such_action"}),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_client (bad action)");
    assert!(
        matches!(outcome, ClientSendOutcome::Rejected { .. }),
        "{outcome:?}"
    );

    // Disconnect through the channel: half-close, server EOFs, read loop ends, handle gone.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "disconnect"}),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_client (disconnect)");
    assert!(
        matches!(outcome, ClientSendOutcome::Disconnected),
        "{outcome:?}"
    );

    for _ in 0..1_000 {
        if !state.has_client_handle(client_id).await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("client handle still registered after disconnect");
}

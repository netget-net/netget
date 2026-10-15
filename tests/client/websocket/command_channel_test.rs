//! The dashboard's `[ send ]` path on a WebSocket client: `AppState::send_to_client` injects an
//! action from outside the client's read loop and the frame reaches a NetGet WebSocket server of
//! our own.
//!
//! Zero LLM calls: the server answers through static handlers and the client's LLM points at an
//! unreachable URL, so its `websocket_client_connected` call fails and the loop has to tolerate
//! that. The command task is independent of that call by design — it is registered before it.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features websocket --test client -- websocket::command_channel --test-threads=100

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
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("WebSocket server #{} never bound a port", id.as_u32());
}

async fn wait_for_client_handle(state: &AppState, id: ClientId) {
    for _ in 0..1_000 {
        if state.has_client_handle(id).await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!(
        "WebSocket client #{} never registered a command handle",
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
async fn injected_websocket_frame_reaches_our_own_server() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    let server_id = ServerForm {
        protocol: "websocket".to_string(),
        port: Some(0),
        event_handlers: Some(vec![
            // The upgrade has to be accepted or nothing else happens.
            serde_json::json!({
                "event_pattern": "websocket_handshake",
                "handler": { "type": "static", "actions": [ { "type": "accept_websocket" } ] }
            }),
            // Everything else is answered with nothing: the assertion is the access log,
            // not a reply.
            serde_json::json!({
                "event_pattern": "*",
                "handler": { "type": "static", "actions": [] }
            }),
        ]),
        ..Default::default()
    }
    .create(&state, tx.clone())
    .await
    .expect("create websocket server");
    let port = wait_for_port(&state, server_id).await;

    let client_id = ClientForm {
        protocol: "websocket".to_string(),
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
    .expect("create websocket client");

    // The regression guard for "register the channel before the connected-event LLM call".
    wait_for_client_handle(&state, client_id).await;

    // The client's own wire verb, injected from outside its read loop. "dashboard-marker" is
    // 16 bytes of payload; the RFC 6455 header and mask are not counted.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "send_websocket_text", "text": "dashboard-marker"}),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_client");
    assert!(
        matches!(outcome, ClientSendOutcome::Sent { bytes_sent: 16 }),
        "expected Sent{{16}}, got {outcome:?}"
    );

    // Recorded on the client like LLM-produced traffic, and received by the server.
    wait_for_log_containing(
        &state,
        AccessLogOwner::Client(client_id.as_u32()),
        "injected_action",
    )
    .await;
    wait_for_log_containing(
        &state,
        AccessLogOwner::Server(server_id.as_u32()),
        "dashboard-marker",
    )
    .await;

    // A ping carries no payload here, so there is nothing to count: the honest answer is
    // Executed, not Sent{0}.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "send_websocket_ping"}),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_client ping");
    assert!(
        matches!(outcome, ClientSendOutcome::Executed { .. }),
        "expected Executed for an empty ping, got {outcome:?}"
    );

    // RFC 6455 validation still runs on injected actions - they go through the protocol's own
    // execute_action, so a reserved close code is refused rather than put on the wire.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "close_websocket", "code": 1006}),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_client bad close code");
    assert!(
        matches!(outcome, ClientSendOutcome::Rejected { .. }),
        "expected Rejected for close code 1006, got {outcome:?}"
    );

    // A polite close: the closing frame goes out, then the sink closes and the read loop
    // drops the command handle.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "close_websocket", "code": 1000, "reason": "bye"}),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_client close");
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
    panic!("the command handle should be gone once the connection closed");
}

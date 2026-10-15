//! The dashboard's `[ send ]` path on an AMQP client: `AppState::send_to_client` injects an
//! action into the running lapin connection, and both the channel it opens and the message it
//! publishes reach a NetGet AMQP broker of our own.
//!
//! Zero LLM calls: the broker answers through static handlers and the client's LLM points at an
//! unreachable URL, so its `amqp_connected` call fails and the client has to tolerate that.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features amqp --test client -- amqp::command_channel --test-threads=100

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
    panic!("AMQP broker #{} never bound a port", id.as_u32());
}

async fn wait_for_client_handle(state: &AppState, id: ClientId) {
    for _ in 0..1_000 {
        if state.has_client_handle(id).await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!(
        "AMQP client #{} never registered a command handle",
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
async fn injected_amqp_publish_reaches_our_own_broker() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    let server_id = ServerForm {
        protocol: "amqp".to_string(),
        port: Some(0),
        event_handlers: Some(vec![
            // Without this the handshake never finishes and lapin's connect never returns.
            serde_json::json!({
                "event_pattern": "amqp_connection_open",
                "handler": { "type": "static", "actions": [ { "type": "amqp_connection_open_ok" } ] }
            }),
            // Basic.Publish owes nothing on the wire outside confirm mode; the assertion is
            // the broker's access log.
            serde_json::json!({
                "event_pattern": "*",
                "handler": { "type": "static", "actions": [] }
            }),
        ]),
        ..Default::default()
    }
    .create(&state, tx.clone())
    .await
    .expect("create amqp broker");
    let port = wait_for_port(&state, server_id).await;

    let client_id = ClientForm {
        protocol: "amqp".to_string(),
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
    .expect("create amqp client");

    // The regression guard for "register the channel before the connected-event LLM call".
    wait_for_client_handle(&state, client_id).await;

    // Channel.Open is a real round trip: lapin only resolves once Channel.Open-Ok came back
    // from the broker. It reports no byte count, so the honest outcome is Executed - see
    // src/client/amqp/CLAUDE.md.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "open_channel"}),
            Duration::from_secs(10),
        )
        .await
        .expect("send_to_client open_channel");
    match &outcome {
        ClientSendOutcome::Executed { detail } => assert!(
            detail.contains("Channel.Open"),
            "detail should name the method, got {detail:?}"
        ),
        other => panic!("expected Executed for open_channel, got {other:?}"),
    }

    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({
                "type": "publish",
                "routing_key": "dashboard-marker",
                "payload": "hello-from-dashboard"
            }),
            Duration::from_secs(10),
        )
        .await
        .expect("send_to_client publish");
    match &outcome {
        ClientSendOutcome::Executed { detail } => assert!(
            detail.contains("Basic.Publish"),
            "detail should name the method, got {detail:?}"
        ),
        other => panic!("expected Executed for publish, got {other:?}"),
    }

    // Recorded on the client like LLM-produced traffic, and really received by the broker.
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

    // Unknown names are refused by the protocol's own execute_action.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "not_an_amqp_action"}),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_client unknown");
    assert!(
        matches!(outcome, ClientSendOutcome::Rejected { .. }),
        "expected Rejected, got {outcome:?}"
    );

    // An injected disconnect sends Connection.Close; the supervisor then sees the connection
    // go and drops the command handle.
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
    panic!("the command handle should be gone once the connection closed");
}

//! The dashboard's `[ send ]` path on an MQTT client: `AppState::send_to_client` injects a
//! publish from outside the client's event loop and the PUBLISH reaches a NetGet MQTT broker of
//! our own.
//!
//! Zero LLM calls: the broker answers through static handlers and the client's LLM points at an
//! unreachable URL, so its `mqtt_connected` call fails and the loop has to tolerate that. The
//! command task is registered before that call by design.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features mqtt --test client -- mqtt::command_channel --test-threads=100


use std::time::Duration;

use netget::cli::management::{ClientForm, ServerForm};
use netget::state::app_state::AppState;
use netget::state::client_handles::ClientSendOutcome;
use netget::state::{AccessLogOwner, ClientId, ClientStatus, ServerId};
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
    panic!("MQTT broker #{} never bound a port", id.as_u32());
}

async fn wait_for_client_handle(state: &AppState, id: ClientId) {
    for _ in 0..1_000 {
        if state.has_client_handle(id).await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!(
        "MQTT client #{} never registered a command handle",
        id.as_u32()
    );
}

async fn wait_for_connected(state: &AppState, id: ClientId) {
    for _ in 0..1_000 {
        if matches!(
            state.get_client(id).await.map(|c| c.status),
            Some(ClientStatus::Connected)
        ) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("MQTT client #{} never reached CONNACK", id.as_u32());
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
async fn injected_mqtt_publish_reaches_our_own_broker() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    let server_id = ServerForm {
        protocol: "mqtt".to_string(),
        port: Some(0),
        event_handlers: Some(vec![
            // Accept the CONNECT, otherwise rumqttc never gets a CONNACK.
            serde_json::json!({
                "event_pattern": "mqtt_connect",
                "handler": { "type": "static", "actions": [ { "type": "mqtt_connack", "return_code": 0 } ] }
            }),
            // A QoS 0 publish owes nothing on the wire; the assertion is the access log.
            serde_json::json!({
                "event_pattern": "*",
                "handler": { "type": "static", "actions": [] }
            }),
        ]),
        ..Default::default()
    }
    .create(&state, tx.clone())
    .await
    .expect("create mqtt broker");
    let port = wait_for_port(&state, server_id).await;

    let client_id = ClientForm {
        protocol: "mqtt".to_string(),
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
    .expect("create mqtt client");

    // The regression guard for "register the channel before the connected-event LLM call" -
    // for MQTT that call happens inside the event loop task, on CONNACK.
    wait_for_client_handle(&state, client_id).await;
    wait_for_connected(&state, client_id).await;

    // A publish injected from outside the event loop. The outcome is Executed, never Sent:
    // rumqttc accepts the request into its event loop's queue and reports no byte count, so
    // there is no honest number for bytes_sent - see src/client/mqtt/CLAUDE.md.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({
                "type": "publish",
                "topic": "dashboard/marker",
                "payload": "hello-from-dashboard"
            }),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_client publish");
    match &outcome {
        ClientSendOutcome::Executed { detail } => {
            assert!(
                detail.contains("dashboard/marker") && detail.contains("PUBLISH"),
                "detail should name the packet it sent, got {detail:?}"
            );
        }
        other => panic!("expected Executed for an MQTT publish, got {other:?}"),
    }

    // Recorded on the client like LLM-produced traffic, and - the point of the test - really
    // received by the broker.
    wait_for_log_containing(
        &state,
        AccessLogOwner::Client(client_id.as_u32()),
        "injected_action",
    )
    .await;
    wait_for_log_containing(
        &state,
        AccessLogOwner::Server(server_id.as_u32()),
        "dashboard/marker",
    )
    .await;

    // Unknown names are refused by the protocol's own execute_action, not silently swallowed.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "not_an_mqtt_action"}),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_client unknown");
    assert!(
        matches!(outcome, ClientSendOutcome::Rejected { .. }),
        "expected Rejected, got {outcome:?}"
    );

    // An injected disconnect sends DISCONNECT and ends the session.
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

//! The dashboard's `[ send ]` path on a Kafka client: `AppState::send_to_client` injects an
//! action from outside the client's own tasks, and the request reaches a NetGet **broker** of
//! our own over a real socket.
//!
//! Zero LLM calls. The broker answers through one `*` static rule (ApiVersions is pure Rust on
//! the broker side and raises no event at all), and the client's LLM points at an unreachable
//! URL — its connected-event call fails, the loop tolerates that, and the command task is
//! independent of it by design. That independence is the point of the feature: a
//! dashboard-created client defaults to a `*` → manual rule, so the connected-event call can
//! park for minutes and `[ send ]` still has to work.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features kafka --test client -- kafka::command_channel --test-threads=100


use std::time::Duration;

use netget::cli::management::{ClientForm, ServerForm};
use netget::state::app_state::AppState;
use netget::state::client_handles::ClientSendOutcome;
use netget::state::{AccessLogOwner, ClientId, ClientStatus, ServerId};
use tokio::sync::mpsc;

const TOPIC: &str = "netget-injected";

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
    panic!("Kafka broker #{} never bound a port", id.as_u32());
}

async fn wait_for_client_handle(state: &AppState, id: ClientId) {
    for _ in 0..1_000 {
        if state.has_client_handle(id).await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!(
        "Kafka client #{} never registered a command handle",
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
async fn injected_kafka_actions_reach_our_own_broker() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    // One `*` rule carrying both answers. The broker's `ask_model` picks the first result
    // whose name matches the action it is waiting for and ignores the rest, so this is one
    // rule rather than two. `brokers` is deliberately omitted from `metadata_response`: the
    // broker then advertises its own reachable address, which is what a client needs.
    let server_id = ServerForm {
        protocol: "kafka".to_string(),
        port: Some(0),
        event_handlers: Some(vec![serde_json::json!({
            "event_pattern": "*",
            "handler": {
                "type": "static",
                "actions": [
                    {
                        "type": "metadata_response",
                        "topics": [
                            {"name": TOPIC, "partitions": [{"partition": 0, "leader": 0}]}
                        ]
                    },
                    {
                        "type": "produce_response",
                        "topic": TOPIC,
                        "partition": 0,
                        "offset": 0,
                        "error_code": 0
                    }
                ]
            }
        })]),
        ..Default::default()
    }
    .create(&state, tx.clone())
    .await
    .expect("create kafka broker");
    let port = wait_for_port(&state, server_id).await;

    // No `topics` startup param, so the client does not start a poll loop: everything that
    // happens after connect is injected, which is exactly what is under test.
    let client_id = ClientForm {
        protocol: "kafka".to_string(),
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
    .expect("create kafka client");

    wait_for_client_handle(&state, client_id).await;

    // `list_topics` becomes a real Metadata exchange. The byte count is the request frame the
    // connection actually wrote, read back while it still held the connection mutex — so this
    // is `Sent`, not an `Executed` standing in for one.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "list_topics"}),
            Duration::from_secs(10),
        )
        .await
        .expect("send_to_client list_topics");
    match outcome {
        ClientSendOutcome::Sent { bytes_sent } => {
            assert!(bytes_sent > 0, "a Metadata request cannot be zero bytes")
        }
        other => panic!("expected Sent, got {other:?}"),
    }

    // A real Produce, decoded by the broker: the topic name only reaches the broker's event
    // data if the record batch this client encoded actually crossed the wire.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({
                "type": "produce_message",
                "topic": TOPIC,
                "partition": 0,
                "value": "dashboard-marker",
                "acks": 1
            }),
            Duration::from_secs(10),
        )
        .await
        .expect("send_to_client produce_message");
    match outcome {
        ClientSendOutcome::Sent { bytes_sent } => {
            assert!(bytes_sent > 0, "a Produce request cannot be zero bytes")
        }
        other => panic!("expected Sent, got {other:?}"),
    }

    // Recorded on the client like LLM-produced traffic, and seen by the broker.
    wait_for_log_containing(
        &state,
        AccessLogOwner::Client(client_id.as_u32()),
        "injected_action",
    )
    .await;
    wait_for_log_containing(&state, AccessLogOwner::Server(server_id.as_u32()), TOPIC).await;

    // An action the protocol refuses never reaches the broker.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "produce_message", "topic": "", "value": "x"}),
            Duration::from_secs(10),
        )
        .await
        .expect("send_to_client bad produce");
    assert!(
        matches!(outcome, ClientSendOutcome::Rejected { .. }),
        "expected Rejected, got {outcome:?}"
    );

    // An injected disconnect shuts the socket down and drops the handle.
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

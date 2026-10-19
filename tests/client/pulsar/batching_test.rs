//! Does the Pulsar client answer the messages delivered during a model call together, and
//! still acknowledge every one of them, when it batches?
//!
//! A raw listener plays the broker (frames from the server's own `wire`): it answers CONNECT,
//! the lookup and the subscription, then delivers `first`, which the mock model answers
//! slowly, then `second` and — 200 ms later — `third` while that call runs. They wait in the
//! client's dispatcher queue. Batching off is the control, in the same test as the claim:
//! three model calls, one per message. Batching on: two, the second triggered by `third` with
//! `second` listed above it. Either way all three messages are acknowledged.

use crate::helpers::mock_builder::MockLlmBuilder;
use crate::helpers::mock_ollama::MockOllamaServer;
use netget::cli::management::ClientForm;
use netget::server::pulsar::wire::{self, command_type as t, BaseCommand};
use netget::state::{app_state::AppState, client_handles::ClientSendOutcome};
use serde_json::{json, Value};
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::mpsc;

const EVENT: &str = "pulsar_message";

fn text(data: &Value) -> String {
    data["payload"].as_str().unwrap_or_default().to_string()
}

async fn calls(mock: &MockOllamaServer) -> Vec<(Value, String)> {
    mock.recorded_calls()
        .await
        .into_iter()
        .filter(|c| c.context.event_type.as_deref() == Some(EVENT))
        .map(|c| (c.context.event_data.clone(), c.context.prompt.clone()))
        .collect()
}

async fn wait_for(mock: &MockOllamaServer, want: &str) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        let calls = calls(mock).await;
        if calls.iter().any(|(d, _)| text(d) == want) {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "`{want}` never reached the model; calls: {calls:#?}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// The next command the client sends, skipping what this broker does not care about.
async fn expect(socket: &mut TcpStream, kind: i32) -> BaseCommand {
    loop {
        let (cmd, _) = wire::read_frame(socket, Duration::from_secs(10))
            .await
            .unwrap()
            .expect("the client closed the connection");
        if cmd.r#type == kind {
            return cmd;
        }
    }
}

async fn session(batching: bool) -> (Vec<(Value, String)>, Vec<u64>) {
    let mock = MockOllamaServer::start(
        MockLlmBuilder::new()
            .on_event(EVENT)
            .and_event_data_contains("payload", "first")
            .respond_with_actions(json!([]))
            .after_delay(Duration::from_millis(1500))
            .expect_calls(1)
            .and()
            .on_any()
            .respond_with_actions(json!([]))
            .expect_at_least(0)
            .build(),
    )
    .await
    .expect("mock ollama");
    let state = AppState::new_with_options(false, mock.base_url());
    let llm = netget::llm::OllamaClient::new(mock.base_url());
    state.set_llm_client(llm.clone()).await;

    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    // CONNECT is answered inside the client's connect, so the broker runs as a task.
    let broker = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        expect(&mut socket, t::CONNECT).await;
        let mut c = BaseCommand::of(t::CONNECTED);
        c.connected = Some(wire::CommandConnected {
            server_version: "batching-test".into(),
            protocol_version: Some(wire::PROTOCOL_VERSION),
            max_message_size: None,
        });
        socket.write_all(&wire::simple(&c)).await.unwrap();
        socket
    });
    let (tx, _rx) = mpsc::unbounded_channel();
    let id = ClientForm {
        protocol: "pulsar".into(),
        remote_addr: Some(addr.clone()),
        instruction: Some("Note what is delivered.".into()),
        batching: Some(batching),
        ..Default::default()
    }
    .create(&state, llm, tx)
    .await
    .expect("create client");
    let mut socket = tokio::time::timeout(Duration::from_secs(10), broker)
        .await
        .expect("client never connected")
        .unwrap();

    // The subscribe is answered once the broker has confirmed it, so the broker's side runs
    // alongside the injected action.
    let send = state.send_to_client(
        id,
        json!({"type":"pulsar_subscribe","topic":"t","subscription":"s"}),
        Duration::from_secs(10),
    );
    let broker_side = async {
        let lookup = expect(&mut socket, t::LOOKUP).await.lookup_topic.unwrap();
        let mut c = BaseCommand::of(t::LOOKUP_RESPONSE);
        c.lookup_topic_response = Some(wire::CommandLookupTopicResponse {
            broker_service_url: Some(format!("pulsar://{addr}")),
            response: Some(1),
            request_id: lookup.request_id,
            ..Default::default()
        });
        socket.write_all(&wire::simple(&c)).await.unwrap();
        let subscribe = expect(&mut socket, t::SUBSCRIBE).await.subscribe.unwrap();
        let mut c = BaseCommand::of(t::SUCCESS);
        c.success = Some(wire::CommandSuccess {
            request_id: subscribe.request_id,
        });
        socket.write_all(&wire::simple(&c)).await.unwrap();
        expect(&mut socket, t::FLOW).await;
        subscribe.consumer_id
    };
    let (outcome, consumer_id) = tokio::join!(send, broker_side);
    assert!(
        matches!(outcome, Ok(ClientSendOutcome::Executed { .. })),
        "{outcome:?}"
    );
    let delivery = |entry_id: u64, payload: &str| {
        let mut c = BaseCommand::of(t::MESSAGE);
        c.message = Some(wire::CommandMessage {
            consumer_id,
            message_id: wire::MessageIdData {
                ledger_id: 7,
                entry_id,
                partition: None,
                batch_index: None,
            },
            redelivery_count: None,
        });
        let meta = wire::MessageMetadata {
            producer_name: "batching-test".into(),
            sequence_id: entry_id,
            publish_time: 1,
            ..Default::default()
        };
        wire::with_payload(&c, &meta, payload.as_bytes())
    };
    let (mut reader, mut writer) = socket.into_split();
    let acks = tokio::spawn(async move {
        let mut acked = Vec::new();
        while let Ok(Some((cmd, _))) = wire::read_frame(&mut reader, Duration::from_secs(30)).await
        {
            if let Some(ack) = cmd.ack {
                acked.extend(ack.message_id.iter().map(|m| m.entry_id));
            }
        }
        acked
    });
    writer.write_all(&delivery(1, "first")).await.unwrap();
    wait_for(&mock, "first").await;
    writer.write_all(&delivery(2, "second")).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    writer.write_all(&delivery(3, "third")).await.unwrap();
    wait_for(&mock, "third").await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    let calls = calls(&mock).await;
    let _ = state.remove_client(id).await;
    let acked = tokio::time::timeout(Duration::from_secs(10), acks)
        .await
        .expect("the client never closed")
        .unwrap();
    (calls, acked)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pulsar_client_answers_messages_delivered_during_a_call_together() {
    let (separate, acked) = session(false).await;
    let texts: Vec<String> = separate.iter().map(|(d, _)| text(d)).collect();
    assert_eq!(
        texts,
        ["first", "second", "third"],
        "CONTROL FAILED: with batching off each message must be its own model call"
    );
    assert_eq!(acked, [1, 2, 3], "every message is acknowledged");

    let (batched, acked) = session(true).await;
    let texts: Vec<String> = batched.iter().map(|(d, _)| text(d)).collect();
    assert_eq!(
        texts,
        ["first", "third"],
        "the two messages that arrived during the first call must be one model call, \
         triggered by the newest"
    );
    assert_eq!(
        acked,
        [1, 2, 3],
        "a batched message is acknowledged like any other"
    );
    let prompt = &batched[1].1;
    let before = &prompt[..prompt.rfind(&format!("Event: {EVENT}")).expect("trigger")];
    assert!(
        before
            .lines()
            .any(|l| l.starts_with(&format!("(1) {EVENT} ")) && l.contains(r#""payload":"second""#)),
        "the earlier message must be listed as arrived and not yet answered:\n{prompt}"
    );
    assert!(
        before.contains("answers all 2 together"),
        "the model must be told it answers both:\n{prompt}"
    );
}

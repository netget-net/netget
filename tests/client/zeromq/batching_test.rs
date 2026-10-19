//! Does the ZeroMQ client answer the messages that arrived during a model call together, when
//! it batches?
//!
//! A raw listener plays a PUB socket (the ZMTP handshake is the server's own `wire`): it sends
//! `first`, which the mock model answers slowly, then `second` and — 200 ms later — `third`
//! while that call runs. They wait in the client's dispatcher queue. Batching off is the
//! control, in the same test as the claim: three model calls, one per message. Batching on:
//! two, the second triggered by `third` with `second` listed above it.

use std::time::Duration;

use crate::helpers::mock_builder::MockLlmBuilder;
use crate::helpers::mock_ollama::MockOllamaServer;
use netget::cli::management::ClientForm;
use netget::server::zeromq::wire;
use netget::state::app_state::AppState;
use serde_json::{json, Value};
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;

const EVENT: &str = "zmq_message";

fn text(data: &Value) -> String {
    data["frames"][0].as_str().unwrap_or_default().to_string()
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

async fn session(batching: bool) -> Vec<(Value, String)> {
    let mock = MockOllamaServer::start(
        MockLlmBuilder::new()
            .on_event(EVENT)
            .and_event_data_contains("frames", "first")
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
    let port = listener.local_addr().unwrap().port();
    // The handshake runs inside the client's connect, so the publisher answers it from a task.
    let publisher = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        wire::handshake(&mut socket, "PUB", None)
            .await
            .expect("ZMTP handshake");
        socket
    });
    let (tx, _rx) = mpsc::unbounded_channel();
    let id = ClientForm {
        protocol: "zeromq".into(),
        remote_addr: Some(format!("127.0.0.1:{port}")),
        instruction: Some("Note what the publisher says.".into()),
        startup_params: Some(json!({"socket_type": "sub"})),
        batching: Some(batching),
        ..Default::default()
    }
    .create(&state, llm, tx)
    .await
    .expect("create client");
    let mut socket = tokio::time::timeout(Duration::from_secs(10), publisher)
        .await
        .expect("client never connected")
        .unwrap();

    let message = |t: &str| wire::encode_message(&[t.as_bytes().to_vec()]);
    socket.write_all(&message("first")).await.unwrap();
    wait_for(&mock, "first").await;
    socket.write_all(&message("second")).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    socket.write_all(&message("third")).await.unwrap();
    wait_for(&mock, "third").await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    let calls = calls(&mock).await;
    let _ = state.remove_client(id).await;
    calls
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn zeromq_client_answers_messages_that_arrived_during_a_call_together() {
    let separate = session(false).await;
    let texts: Vec<String> = separate.iter().map(|(d, _)| text(d)).collect();
    assert_eq!(
        texts,
        ["first", "second", "third"],
        "CONTROL FAILED: with batching off each message must be its own model call"
    );

    let batched = session(true).await;
    let texts: Vec<String> = batched.iter().map(|(d, _)| text(d)).collect();
    assert_eq!(
        texts,
        ["first", "third"],
        "the two messages that arrived during the first call must be one model call, \
         triggered by the newest"
    );
    let prompt = &batched[1].1;
    let before = &prompt[..prompt.rfind(&format!("Event: {EVENT}")).expect("trigger")];
    assert!(
        before
            .lines()
            .any(|l| l.starts_with(&format!("(1) {EVENT} ")) && l.contains(r#""second""#)),
        "the earlier message must be listed as arrived and not yet answered:\n{prompt}"
    );
    assert!(
        before.contains("answers all 2 together"),
        "the model must be told it answers both:\n{prompt}"
    );
}

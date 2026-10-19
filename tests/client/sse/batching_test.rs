//! Does the SSE client answer the stream events that arrived during a model call together,
//! when it batches?
//!
//! A raw listener plays the server: it answers the GET with an event stream, sends `first`,
//! which the mock model answers slowly, then `second` and — 200 ms later — `third` while that
//! call runs. The client keeps reading the body during the call, so both are parsed and wait.
//! Batching off is the control, in the same test as the claim: three model calls, one per
//! event. Batching on: two, the second triggered by `third` with `second` listed above it.

use std::time::Duration;

use crate::helpers::mock_builder::MockLlmBuilder;
use crate::helpers::mock_ollama::MockOllamaServer;
use netget::cli::management::ClientForm;
use netget::state::app_state::AppState;
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

const EVENT: &str = "sse_event_received";

async fn wait_for(mock: &MockOllamaServer, text: &str) -> Vec<(Value, String)> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        let calls = calls(mock).await;
        if calls.iter().any(|(d, _)| d["data"] == text) {
            return calls;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "`{text}` never reached the model; calls: {calls:#?}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn calls(mock: &MockOllamaServer) -> Vec<(Value, String)> {
    mock.recorded_calls()
        .await
        .into_iter()
        .filter(|c| c.context.event_type.as_deref() == Some(EVENT))
        .map(|c| (c.context.event_data.clone(), c.context.prompt.clone()))
        .collect()
}

async fn session(batching: bool) -> Vec<(Value, String)> {
    let mock = MockOllamaServer::start(
        MockLlmBuilder::new()
            .on_event(EVENT)
            .and_event_data_contains("data", "first")
            .respond_with_actions(serde_json::json!([]))
            .after_delay(Duration::from_millis(1500))
            .expect_calls(1)
            .and()
            .on_any()
            .respond_with_actions(serde_json::json!([]))
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
    let (tx, _rx) = mpsc::unbounded_channel();
    let id = ClientForm {
        protocol: "sse".into(),
        remote_addr: Some(format!("http://127.0.0.1:{port}/stream")),
        instruction: Some("Note what the server says.".into()),
        batching: Some(batching),
        ..Default::default()
    }
    .create(&state, llm, tx)
    .await
    .expect("create client");

    let (mut socket, _) = tokio::time::timeout(Duration::from_secs(10), listener.accept())
        .await
        .expect("client never connected")
        .unwrap();
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        let mut b = [0u8];
        assert_eq!(socket.read(&mut b).await.unwrap(), 1, "request head");
        head.push(b[0]);
    }
    socket
        .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\n\r\n")
        .await
        .unwrap();
    socket.write_all(b"data: first\n\n").await.unwrap();
    wait_for(&mock, "first").await;
    // Both arrive while the slow first call is still running, as two separate reads.
    socket.write_all(b"data: second\n\n").await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    socket.write_all(b"data: third\n\n").await.unwrap();
    wait_for(&mock, "third").await;
    // Room for a stray extra call to show up before counting.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let calls = calls(&mock).await;
    let _ = state.remove_client(id).await;
    calls
}

fn data(calls: &[(Value, String)]) -> Vec<String> {
    calls
        .iter()
        .map(|(d, _)| d["data"].as_str().unwrap_or_default().to_string())
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sse_client_answers_events_that_arrived_during_a_call_together() {
    let separate = session(false).await;
    assert_eq!(
        data(&separate),
        ["first", "second", "third"],
        "CONTROL FAILED: with batching off each stream event must be its own model call"
    );

    let batched = session(true).await;
    assert_eq!(
        data(&batched),
        ["first", "third"],
        "the two events that arrived during the first call must be one model call, triggered \
         by the newest"
    );
    let prompt = &batched[1].1;
    let before = &prompt[..prompt.rfind(&format!("Event: {EVENT}")).expect("trigger")];
    assert!(
        before
            .lines()
            .any(|l| l.starts_with(&format!("(1) {EVENT} ")) && l.contains(r#""data":"second""#)),
        "the earlier event must be listed as arrived and not yet answered:\n{prompt}"
    );
    assert!(
        before.contains("answers all 2 together"),
        "the model must be told it answers both:\n{prompt}"
    );
}

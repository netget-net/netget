//! Batching on the socket_file server: what arrives while the model is answering.
//!
//! A Unix-socket byte stream has no message boundaries, so the server's queue keeps each read
//! that arrived during a call and `ConnectionData::take_next` decides what the next call
//! answers — the whole queue with batching on, one read at a time with it off. The same shape
//! as `tcp`'s `tests/connection_history_test.rs`.
//!
//! The first write is answered slowly; two more are sent, 200 ms apart, during that call. Off is
//! the control and runs first in the same test: three calls, one per write. On: two calls, the
//! second carrying both writes that arrived during the first.
#![cfg(unix)]

use std::path::Path;
use std::time::Duration;

use crate::helpers::mock_builder::MockLlmBuilder;
use crate::helpers::mock_ollama::MockOllamaServer;
use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::mpsc;

async fn wait_for_path(path: &Path) {
    for _ in 0..600 {
        if path.exists() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("{} was never created", path.display());
}

/// `first`, then two separate writes while the model answers it. Returns the `data` of every
/// `socket_file_data_received` the model was asked about.
async fn socket_payloads_for_three_writes(batching: bool) -> Vec<String> {
    let mock = MockOllamaServer::start(
        MockLlmBuilder::new()
            .on_event("socket_file_data_received")
            .and_event_data_contains("data", "first")
            .respond_with_actions(serde_json::json!([
                { "type": "send_socket_data", "data": "ok first\n", "encoding": "utf8" }
            ]))
            .after_delay(Duration::from_millis(1500))
            .expect_calls(1)
            .and()
            .on_event("socket_file_data_received")
            .respond_with_actions_from_event(|event| {
                let data = event["data"].as_str().unwrap_or_default().to_string();
                serde_json::json!([{ "type": "send_socket_data", "data": format!("ok {data}\n"), "encoding": "utf8" }])
            })
            .expect_at_least(1)
            .build(),
    )
    .await
    .expect("mock ollama");

    let state = AppState::new_with_options(false, mock.base_url());
    state
        .set_llm_client(netget::llm::OllamaClient::new(mock.base_url()))
        .await;
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("batch.sock");
    let (tx, _rx) = mpsc::unbounded_channel();
    let id = ServerForm {
        protocol: "socket_file".to_string(),
        port: None,
        instruction: Some("Acknowledge everything.".to_string()),
        startup_params: Some(serde_json::json!({ "socket_path": path.to_string_lossy() })),
        batching: Some(batching),
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .expect("create socket_file server");
    wait_for_path(&path).await;

    let mut peer = UnixStream::connect(&path).await.expect("connect");
    peer.write_all(b"first").await.expect("write");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while mock.call_count().await == 0 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "first never reached the model"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // Two reads the server sees separately, both during the slow first call.
    peer.write_all(b"second").await.expect("write");
    tokio::time::sleep(Duration::from_millis(200)).await;
    peer.write_all(b"third").await.expect("write");

    let mut seen = Vec::new();
    let mut buf = [0u8; 1024];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    while !String::from_utf8_lossy(&seen).contains("third") {
        let n = tokio::time::timeout_at(deadline, peer.read(&mut buf))
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "no answer naming third; read so far: {:?}",
                    String::from_utf8_lossy(&seen)
                )
            })
            .expect("read");
        assert!(n > 0, "connection closed before the answer to third");
        seen.extend_from_slice(&buf[..n]);
    }

    let payloads = mock
        .recorded_calls()
        .await
        .into_iter()
        .filter(|c| c.context.event_type.as_deref() == Some("socket_file_data_received"))
        .map(|c| {
            c.context.event_data["data"]
                .as_str()
                .unwrap_or_default()
                .to_string()
        })
        .collect();
    let _ = state.remove_server(id).await;
    payloads
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn socket_file_batching_joins_or_separates_what_arrived_during_a_call() {
    // === Control: batching off. Every write that arrived during the call is its own call. ===
    let separate = socket_payloads_for_three_writes(false).await;
    assert_eq!(
        separate,
        vec!["first", "second", "third"],
        "CONTROL FAILED: with batching off each read that arrived during the call must be \
         answered on its own, or the joined result below proves nothing"
    );
    // === The claim: with batching on they are the next call's payload, together. ===
    let batched = socket_payloads_for_three_writes(true).await;
    assert_eq!(
        batched,
        vec!["first", "secondthird"],
        "with batching on everything that arrived during the call is the next call's payload"
    );
}

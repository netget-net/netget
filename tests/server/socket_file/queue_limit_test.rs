//! Data queued on a socket_file connection while an answer is in flight is bounded.
//!
//! Every byte a peer sends during a model call is queued until the answer arrives. The queue had
//! no ceiling, so the peer decided how much memory its connection cost. It is now
//! `MAX_QUEUED_BYTES` (declared as `max_inbound_bytes`); past it the server shuts its write half
//! — the peer reads EOF — and logs `decision=queue_overflow`.
//!
//! Control and claim in one test: the same slow call with a quarter of the cap sent during it
//! must be answered normally, or the closed connection in the second half could be a server
//! that hangs up on everybody.
#![cfg(unix)]

use std::path::Path;
use std::time::Duration;

use crate::helpers::mock_builder::MockLlmBuilder;
use crate::helpers::mock_ollama::MockOllamaServer;
use netget::cli::management::ServerForm;
use netget::server::socket_file::MAX_QUEUED_BYTES;
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

/// What the peer reads after sending `first` (answered after a 5 s call) and then `extra` bytes
/// during that call: the bytes read before EOF, and whether EOF came.
async fn read_after_flooding_a_slow_call(extra: usize) -> (String, bool) {
    let mock = MockOllamaServer::start(
        MockLlmBuilder::new()
            .on_event("socket_file_data_received")
            .and_event_data_contains("data", "first")
            .respond_with_actions(serde_json::json!([
                { "type": "send_socket_data", "data": "ok first\n" }
            ]))
            .after_delay(Duration::from_secs(5))
            .expect_calls(1)
            .and()
            .on_event("socket_file_data_received")
            .respond_with_actions(serde_json::json!([
                { "type": "send_socket_data", "data": "ok rest\n" }
            ]))
            .expect_at_least(0)
            .build(),
    )
    .await
    .expect("mock ollama");

    let state = AppState::new_with_options(false, mock.base_url());
    state
        .set_llm_client(netget::llm::OllamaClient::new(mock.base_url()))
        .await;
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("queue.sock");
    let (tx, _rx) = mpsc::unbounded_channel();
    let id = ServerForm {
        protocol: "socket_file".to_string(),
        port: None,
        instruction: Some("Acknowledge everything.".to_string()),
        startup_params: Some(serde_json::json!({ "socket_path": path.to_string_lossy() })),
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .expect("create socket_file server");
    wait_for_path(&path).await;

    let peer = UnixStream::connect(&path).await.expect("connect");
    let (mut read_half, mut write_half) = peer.into_split();
    write_half.write_all(b"first").await.expect("write");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while mock.call_count().await == 0 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "first never reached the model"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    // Stream `extra` bytes during the call. Errors are expected once the server has hung up.
    let writer = tokio::spawn(async move {
        let chunk = vec![b'x'; 64 * 1024];
        let mut sent = 0;
        while sent < extra {
            let n = chunk.len().min(extra - sent);
            if write_half.write_all(&chunk[..n]).await.is_err() {
                break;
            }
            sent += n;
        }
        write_half
    });

    // Read until the answer to `first` or EOF.
    let mut seen = Vec::new();
    let mut buf = [0u8; 4096];
    let mut eof = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    while !String::from_utf8_lossy(&seen).contains("ok first") {
        match tokio::time::timeout_at(deadline, read_half.read(&mut buf)).await {
            Ok(Ok(0)) | Ok(Err(_)) => {
                eof = true;
                break;
            }
            Ok(Ok(n)) => seen.extend_from_slice(&buf[..n]),
            Err(_) => panic!("neither an answer nor EOF within 30 s"),
        }
    }
    writer.abort();
    let _ = state.remove_server(id).await;
    (String::from_utf8_lossy(&seen).into_owned(), eof)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_peer_that_queues_past_the_cap_during_a_call_is_closed() {
    // === Control: a quarter of the cap during the call is answered normally. ===
    let (seen, eof) = read_after_flooding_a_slow_call(MAX_QUEUED_BYTES / 4).await;
    assert!(
        !eof && seen.contains("ok first"),
        "CONTROL FAILED: a quarter of the cap must be queued and the call answered, or the \
         close below proves nothing (eof={eof}, read {seen:?})"
    );

    // === The claim: past the cap the server hangs up before the answer is written. ===
    let (seen, eof) = read_after_flooding_a_slow_call(MAX_QUEUED_BYTES + 1024 * 1024).await;
    assert!(
        eof && !seen.contains("ok first"),
        "past MAX_QUEUED_BYTES the connection must be closed (EOF) without the answer \
         (eof={eof}, read {seen:?})"
    );
}

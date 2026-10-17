//! `wait_for_more` on the TLS server must keep the fragment it was shown.
//!
//! The action means "these bytes are an incomplete message". TLS used to set `Accumulating` and
//! drop the payload, so a model reassembling a message split across two records never saw the
//! first half again — the defect `tcp`'s `test_wait_for_more_keeps_the_fragment` pins. Two
//! cases, one per half of the repair:
//!
//! 1. The second half arrives after the model answered `wait_for_more`: the echo the model
//!    finally sends must carry both halves.
//! 2. The second half arrives *while* the model is answering the first with `wait_for_more`:
//!    the server must go round again at once with the joined payload, with no further write
//!    from the peer.

use std::time::Duration;

use super::batching_test::{handshaked_peer, wait_for_port};
use crate::helpers::mock_builder::MockLlmBuilder;
use crate::helpers::mock_ollama::MockOllamaServer;
use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

/// A TLS server whose model answers `wait_for_more` until it sees `END`, then echoes what it
/// was shown. Every answer takes `delay`.
async fn start(delay: Duration) -> (MockOllamaServer, AppState, netget::state::ServerId, u16) {
    let mock = MockOllamaServer::start(
        MockLlmBuilder::new()
            // ONE rule that branches on the event: two rules on the same event would be
            // first-match-wins and the second would never fire.
            .on_event("tls_data_received")
            .respond_with_actions_from_event(|e| {
                let data = e["data"].as_str().unwrap_or("");
                if data.contains("END") {
                    serde_json::json!([{ "type": "send_tls_data", "data": data }])
                } else {
                    serde_json::json!([{ "type": "wait_for_more" }])
                }
            })
            .after_delay(delay)
            .expect_at_least(1)
            .build(),
    )
    .await
    .expect("mock ollama");

    let state = AppState::new_with_options(false, mock.base_url());
    state
        .set_llm_client(netget::llm::OllamaClient::new(mock.base_url()))
        .await;
    let (tx, _rx) = mpsc::unbounded_channel();
    let id = ServerForm {
        protocol: "tls".to_string(),
        port: Some(0),
        instruction: Some("Buffer until END then echo.".to_string()),
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .expect("create tls server");
    let port = wait_for_port(&state, id).await;
    (mock, state, id, port)
}

async fn read_echo<S: tokio::io::AsyncRead + Unpin>(peer: &mut S) -> String {
    let mut seen = Vec::new();
    let mut buf = [0u8; 1024];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    while !String::from_utf8_lossy(&seen).contains("END") {
        let n = match tokio::time::timeout_at(deadline, peer.read(&mut buf)).await {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => panic!("read error: {e}"),
            Err(_) => panic!(
                "no echo carrying END; read so far: {:?}",
                String::from_utf8_lossy(&seen)
            ),
        };
        assert!(n > 0, "connection closed without an echo");
        seen.extend_from_slice(&buf[..n]);
    }
    String::from_utf8_lossy(&seen).into_owned()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wait_for_more_keeps_the_fragment() {
    let (_mock, state, id, port) = start(Duration::ZERO).await;
    let mut peer = handshaked_peer(port).await;

    peer.write_all(b"PART1-").await.expect("write");
    peer.flush().await.expect("flush");

    // Nothing may come back yet. This is what stops the test passing vacuously: had the two
    // writes been read together the model would have seen END at once.
    let mut probe = [0u8; 64];
    match tokio::time::timeout(Duration::from_secs(2), peer.read(&mut probe)).await {
        Err(_) => {}
        Ok(Ok(0)) => panic!("server closed the connection on wait_for_more"),
        Ok(Ok(n)) => panic!(
            "server answered the incomplete first half with {:?}",
            String::from_utf8_lossy(&probe[..n])
        ),
        Ok(Err(e)) => panic!("read error while probing: {e}"),
    }

    peer.write_all(b"PART2-END").await.expect("write");
    peer.flush().await.expect("flush");
    let echo = read_echo(&mut peer).await;
    assert!(
        echo.contains("PART1-") && echo.contains("PART2-END"),
        "wait_for_more dropped the first fragment: the echo was {echo:?}"
    );
    let _ = state.remove_server(id).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bytes_that_arrive_during_a_wait_for_more_answer_complete_the_message() {
    let (mock, state, id, port) = start(Duration::from_millis(1500)).await;
    let mut peer = handshaked_peer(port).await;

    peer.write_all(b"PART1-").await.expect("write");
    peer.flush().await.expect("flush");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while mock.call_count().await == 0 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "PART1- never reached the model"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // The rest of the message, while the model is still deciding to wait for it. The peer
    // writes nothing after this, so only the server going round again can produce the echo.
    peer.write_all(b"PART2-END").await.expect("write");
    peer.flush().await.expect("flush");

    let echo = read_echo(&mut peer).await;
    assert!(
        echo.contains("PART1-") && echo.contains("PART2-END"),
        "the joined message must be answered: the echo was {echo:?}"
    );
    let _ = state.remove_server(id).await;
}

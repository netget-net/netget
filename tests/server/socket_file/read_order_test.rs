//! One Unix-socket connection's reads are answered in the order they arrived.
//!
//! The socket_file reader hands each read to the connection's state machine and goes straight
//! back to `read()`, so a peer that writes in quick succession has several reads in the server at
//! once. Each must be answered after the one before it: a byte stream has no message ids, so a
//! reply that overtakes an earlier one is a reply to the wrong message as far as the peer can
//! tell. The same test as `tests/server/tcp/read_order_test.rs`, over a Unix domain socket.
//!
//! The rule answering every read is static and echoes the read's own bytes, so no model is
//! involved and the answers are as fast as the server can make them — which is when two answers
//! racing each other is most likely. The peer writes numbered tokens one write at a time and
//! reads the echoes back; however the server split or joined the reads, the echoes concatenated
//! must be the tokens in the order they were written. Both with batching off (one read per
//! answer) and on (everything waiting per answer).
//!
//! The second test is the connect-time half of the same rule: with `send_first`, the banner
//! comes before the answer to anything written while it was being composed.
//!
//! The LLM endpoint is a dead port, and nothing may reach it.
#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::time::Duration;

use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::mpsc;

/// Tokens per connection, each its own write.
const TOKENS: usize = 300;
/// Connections per batching mode, each driven at the same time as the others.
const CONNECTIONS: usize = 4;

async fn wait_for_path(path: &Path) {
    for _ in 0..600 {
        if path.exists() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("{} was never created", path.display());
}

/// Write `TOKENS` numbered tokens one write each, and return everything echoed back.
async fn echo_tokens(path: PathBuf, connection: usize) -> (String, String) {
    let stream = UnixStream::connect(&path).await.expect("connect");
    let (mut read_half, mut write_half) = stream.into_split();
    let sent: String = (0..TOKENS).map(|i| format!("{connection}.{i};")).collect();
    let expected_len = sent.len();

    let writer = tokio::spawn(async move {
        for i in 0..TOKENS {
            write_half
                .write_all(format!("{connection}.{i};").as_bytes())
                .await
                .expect("write");
            // Let the server read between writes, so the reads stay small and many of them are
            // in the server at once rather than one large read.
            tokio::task::yield_now().await;
        }
        write_half
    });

    let mut echoed = Vec::with_capacity(expected_len);
    let mut buf = [0u8; 4096];
    let read = tokio::time::timeout(Duration::from_secs(60), async {
        while echoed.len() < expected_len {
            let n = read_half.read(&mut buf).await.expect("read");
            assert!(
                n > 0,
                "connection {connection} closed after {} of {expected_len} echoed bytes",
                echoed.len()
            );
            echoed.extend_from_slice(&buf[..n]);
        }
    })
    .await;
    let _write_half = writer.await.expect("writer");
    assert!(
        read.is_ok(),
        "connection {connection}: only {} of {expected_len} bytes echoed within the deadline",
        echoed.len()
    );
    (sent, String::from_utf8(echoed).expect("utf8 echo"))
}

async fn run(batching: bool) {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".to_string());
    state
        .set_llm_client(netget::llm::OllamaClient::new(
            "http://127.0.0.1:1".to_string(),
        ))
        .await;
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("order.sock");
    let (tx, _rx) = mpsc::unbounded_channel();
    let id = ServerForm {
        protocol: "socket_file".to_string(),
        port: None,
        // An empty instruction really is model-free; `None` is replaced by a default one.
        instruction: Some(String::new()),
        batching: Some(batching),
        startup_params: Some(serde_json::json!({ "socket_path": path.to_string_lossy() })),
        event_handlers: Some(vec![serde_json::json!({
            "event_pattern": "socket_file_data_received",
            "handler": {
                "type": "static",
                "actions": [{
                    "type": "send_socket_data",
                    "data": "{{event.data}}",
                    "encoding": "utf8"
                }]
            }
        })]),
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .expect("create socket_file server");
    wait_for_path(&path).await;

    let peers: Vec<_> = (0..CONNECTIONS)
        .map(|c| tokio::spawn(echo_tokens(path.clone(), c)))
        .collect();
    for peer in peers {
        let (sent, echoed) = peer.await.expect("peer");
        if echoed != sent {
            let at = sent
                .bytes()
                .zip(echoed.bytes())
                .position(|(a, b)| a != b)
                .unwrap_or(0);
            let from = at.saturating_sub(40);
            panic!(
                "batching {}: replies came back out of order from byte {at}:\n  sent   ...{}\n  echoed ...{}",
                if batching { "on" } else { "off" },
                &sent[from..(at + 40).min(sent.len())],
                &echoed[from..(at + 40).min(echoed.len())],
            );
        }
    }
    let _ = state.remove_server(id).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn socket_file_reads_are_answered_in_the_order_they_arrived() {
    run(false).await;
    run(true).await;
}

/// A `send_first` server's banner comes before the answer to anything the peer sent while the
/// banner was being composed.
///
/// The banner is parked on a `manual` rule, so it is outstanding for as long as the test likes,
/// and the peer writes during that window. The answer to that write is static and immediate;
/// before the reads were held behind the banner it reached the peer first, every time.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn socket_file_reads_wait_behind_the_send_first_banner() {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".to_string());
    state
        .set_llm_client(netget::llm::OllamaClient::new(
            "http://127.0.0.1:1".to_string(),
        ))
        .await;
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("banner.sock");
    let (tx, _rx) = mpsc::unbounded_channel();
    let id = ServerForm {
        protocol: "socket_file".to_string(),
        port: None,
        instruction: Some(String::new()),
        startup_params: Some(serde_json::json!({
            "socket_path": path.to_string_lossy(),
            "send_first": true,
        })),
        event_handlers: Some(vec![
            serde_json::json!({
                "event_pattern": "socket_file_connection_opened",
                "handler": { "type": "manual", "timeout_secs": 60 }
            }),
            serde_json::json!({
                "event_pattern": "socket_file_data_received",
                "handler": {
                    "type": "static",
                    "actions": [{
                        "type": "send_socket_data",
                        "data": "{{event.data}}",
                        "encoding": "utf8"
                    }]
                }
            }),
        ]),
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .expect("create socket_file server");
    wait_for_path(&path).await;

    let mut peer = UnixStream::connect(&path).await.expect("connect");
    peer.write_all(b"early;").await.expect("write");

    // The banner is now parked for a person.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let banner = loop {
        if let Some(i) = state
            .list_intercepts()
            .await
            .into_iter()
            .find(|i| i.event_type == "socket_file_connection_opened")
        {
            break i;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the connect event was never parked"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    };

    // Give the early write every chance to be answered ahead of the banner.
    let mut seen = Vec::new();
    let mut buf = [0u8; 256];
    if let Ok(read) = tokio::time::timeout(Duration::from_millis(500), peer.read(&mut buf)).await {
        let n = read.expect("read");
        seen.extend_from_slice(&buf[..n]);
    }

    state
        .resolve_intercept(
            banner.id,
            vec![serde_json::json!({
                "type": "send_socket_data",
                "data": "banner;",
                "encoding": "utf8"
            })],
        )
        .await
        .expect("answer the banner");

    let expected = b"banner;early;";
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while seen.len() < expected.len() {
        let n = tokio::time::timeout_at(deadline, peer.read(&mut buf))
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "only {:?} within the deadline",
                    String::from_utf8_lossy(&seen)
                )
            })
            .expect("read");
        assert!(n > 0, "closed after {:?}", String::from_utf8_lossy(&seen));
        seen.extend_from_slice(&buf[..n]);
    }
    assert_eq!(
        String::from_utf8_lossy(&seen),
        "banner;early;",
        "the answer to a read made while the banner was outstanding went out ahead of it"
    );
    let _ = state.remove_server(id).await;
}

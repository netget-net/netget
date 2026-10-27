//! One connection's reads are answered in the order they arrived.
//!
//! The TCP reader hands each read to the connection's state machine and goes straight back to
//! `read()`, so a peer that writes in quick succession has several reads in the server at once.
//! Each must be answered after the one before it: a byte stream has no message ids, so a reply
//! that overtakes an earlier one is a reply to the wrong message as far as the peer can tell.
//!
//! The rule answering every read is static and echoes the read's own bytes, so no model is
//! involved and the answers are as fast as the server can make them — which is when two
//! answers racing each other is most likely. The peer writes numbered tokens one write at a
//! time and reads the echoes back; whatever way the server split or joined the reads, the
//! echoes concatenated must be the tokens in the order they were written. Both with batching
//! off (one read per answer) and on (everything waiting per answer).
//!
//! Loopback only; the LLM endpoint is a dead port, and nothing may reach it.

use std::time::Duration;

use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use netget::state::ServerId;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

/// Tokens per connection, each its own write.
const TOKENS: usize = 300;
/// Connections per batching mode, each driven at the same time as the others.
const CONNECTIONS: usize = 4;

async fn wait_for_port(state: &AppState, id: ServerId) -> u16 {
    for _ in 0..300 {
        if let Some(s) = state.get_server(id).await {
            if let Some(addr) = s.local_addr {
                return addr.port();
            }
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("TCP server #{} never bound a port", id.as_u32());
}

/// Write `TOKENS` numbered tokens one write each, and return everything echoed back.
async fn echo_tokens(port: u16, connection: usize) -> (String, String) {
    let stream = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
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
    let (tx, _rx) = mpsc::unbounded_channel();
    let id = ServerForm {
        protocol: "tcp".to_string(),
        port: Some(0),
        host: Some("127.0.0.1".to_string()),
        // An empty instruction really is model-free; `None` is replaced by a default one.
        instruction: Some(String::new()),
        batching: Some(batching),
        event_handlers: Some(vec![serde_json::json!({
            "event_pattern": "tcp_data_received",
            "handler": {
                "type": "static",
                "actions": [{
                    "type": "send_tcp_data",
                    "data": "{{event.data}}",
                    "encoding": "utf8"
                }]
            }
        })]),
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .expect("create tcp server");
    let port = wait_for_port(&state, id).await;

    let peers: Vec<_> = (0..CONNECTIONS)
        .map(|c| tokio::spawn(echo_tokens(port, c)))
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
async fn reads_are_answered_in_the_order_they_arrived() {
    run(false).await;
    run(true).await;
}

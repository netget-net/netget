//! What a Bitcoin peer sends while a message is being answered is queued, and the queue is
//! bounded.
//!
//! The reader keeps reading while an answer is composed, so everything the peer sends meanwhile
//! waits behind it. The queue had no ceiling, so a peer streaming for the length of one answer
//! decided how much memory its connection cost. It is now `MAX_QUEUED_BYTES`; past it the server
//! shuts its write half — the peer reads EOF — and logs `decision=fail_closed_queue_overflow`.
//!
//! The answer in flight is the connection's opened event, parked on a `manual` rule, so it is
//! outstanding for as long as the test likes and no model is involved. Control and claim in one
//! test: a quarter of the cap queued behind it must still be answered once the opened event is,
//! or the closed connection in the second half could be a server that hangs up on everybody.

use std::io::Cursor;
use std::time::Duration;

use bitcoin::consensus::{Decodable, Encodable};
use bitcoin::p2p::message::{NetworkMessage, RawNetworkMessage};
use bitcoin::p2p::Magic;
use netget::cli::management::ServerForm;
use netget::server::bitcoin::MAX_QUEUED_BYTES;
use netget::state::app_state::AppState;
use netget::state::server::ConnectionStatus;
use netget::state::ServerId;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

async fn wait_for_port(state: &AppState, id: ServerId) -> u16 {
    for _ in 0..300 {
        if let Some(s) = state.get_server(id).await {
            if let Some(addr) = s.local_addr {
                return addr.port();
            }
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("Bitcoin server #{} never bound a port", id.as_u32());
}

fn ping(nonce: u64) -> Vec<u8> {
    let mut bytes = Vec::new();
    RawNetworkMessage::new(Magic::BITCOIN, NetworkMessage::Ping(nonce))
        .consensus_encode(&mut bytes)
        .expect("encode ping");
    bytes
}

/// What the peer sees after queueing at least `queue` bytes of pings behind its parked opened
/// event and then having that event answered with nothing: `Some(nonce)` of the first `pong`,
/// or `None` if the server closed the connection (EOF) first.
async fn first_answer_after_queueing(queue: usize) -> Option<u64> {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".to_string());
    state
        .set_llm_client(netget::llm::OllamaClient::new(
            "http://127.0.0.1:1".to_string(),
        ))
        .await;
    let (tx, _rx) = mpsc::unbounded_channel();
    let id = ServerForm {
        protocol: "bitcoin".to_string(),
        port: Some(0),
        host: Some("127.0.0.1".to_string()),
        // An empty instruction really is model-free; `None` is replaced by a default one.
        instruction: Some(String::new()),
        event_handlers: Some(vec![
            serde_json::json!({
                "event_pattern": "bitcoin_connection_opened",
                "handler": { "type": "manual", "timeout_secs": 120 }
            }),
            serde_json::json!({
                "event_pattern": "bitcoin_message_received",
                "handler": {
                    "type": "static",
                    "actions": [{
                        "type": "send_pong",
                        "network": "mainnet",
                        "nonce": "{{event.message.nonce}}"
                    }]
                }
            }),
        ]),
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .expect("create bitcoin server");
    let port = wait_for_port(&state, id).await;

    let stream = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    let (mut read_half, mut write_half) = stream.into_split();

    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let opened = loop {
        if let Some(i) = state
            .list_intercepts()
            .await
            .into_iter()
            .find(|i| i.event_type == "bitcoin_connection_opened")
        {
            break i;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the opened event was never parked"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    };

    // Queue the pings behind the parked answer, 64 KiB of them per write. A write fails once
    // the server has hung up, which is the claim's expected end.
    let chunk: Vec<u8> = (0..2048).flat_map(ping).collect();
    let mut sent = 0;
    while sent < queue {
        if write_half.write_all(&chunk).await.is_err() {
            break;
        }
        sent += chunk.len();
    }

    // A finished write only means the kernel took the bytes: loopback buffers hold megabytes,
    // and answering now would let the server drain the queue as the rest arrives, so it never
    // reaches the cap. Wait until the server has read everything sent, or closed the connection.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let server = state.get_server(id).await.expect("server");
        let conn = server
            .connections
            .values()
            .next()
            .expect("connection tracked");
        if conn.status == ConnectionStatus::Closed || conn.bytes_received as usize >= sent {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the server read {} of {sent} bytes and never closed the connection",
            conn.bytes_received
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    // Answer the opened event with nothing; whatever was queued is answered next. If the
    // connection was closed for its queue the intercept may already be gone with it.
    let _ = state.resolve_intercept(opened.id, vec![]).await;

    let mut header = [0u8; 24];
    let first =
        match tokio::time::timeout(Duration::from_secs(30), read_half.read_exact(&mut header))
            .await
            .expect("neither an answer nor EOF within 30 s")
        {
            Err(_) => None,
            Ok(_) => {
                let len =
                    u32::from_le_bytes([header[16], header[17], header[18], header[19]]) as usize;
                let mut full = header.to_vec();
                full.resize(24 + len, 0);
                read_half
                    .read_exact(&mut full[24..])
                    .await
                    .expect("read payload");
                match RawNetworkMessage::consensus_decode(&mut Cursor::new(full))
                    .expect("decode message")
                    .payload()
                {
                    NetworkMessage::Pong(n) => Some(*n),
                    other => panic!("expected a pong, got {other:?}"),
                }
            }
        };
    drop(write_half);
    let _ = state.remove_server(id).await;
    first
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_peer_that_queues_past_the_cap_behind_an_answer_is_closed() {
    // === Control: a quarter of the cap queued behind the answer is answered normally. ===
    assert_eq!(
        first_answer_after_queueing(MAX_QUEUED_BYTES / 4).await,
        Some(0),
        "CONTROL FAILED: a quarter of the cap must be queued and answered in order, or the \
         close below proves nothing"
    );

    // === The claim: past the cap the server hangs up, and nothing queued is answered. ===
    assert_eq!(
        first_answer_after_queueing(MAX_QUEUED_BYTES + 1024 * 1024).await,
        None,
        "past MAX_QUEUED_BYTES the connection must be closed (EOF) without answering what was \
         queued"
    );
}

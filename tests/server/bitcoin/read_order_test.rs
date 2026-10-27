//! One Bitcoin P2P connection's messages are answered in the order they arrived.
//!
//! The Bitcoin reader hands each read to the connection's state machine and goes straight back to
//! `read()`, so a peer that writes in quick succession has several reads in the server at once.
//! The answers must leave in the order the messages came: a `pong` that overtakes an earlier one
//! answers the wrong `ping` in sequence, and a read that is parsed ahead of the bytes before it
//! is not a P2P message at all. The same test as `tests/server/tcp/read_order_test.rs`, in P2P
//! framing.
//!
//! The rule answering every message is static: a `pong` carrying the `ping`'s own nonce (a
//! whole-value `{{event.message.nonce}}` reference keeps it a number), so no model is involved
//! and the answers are as fast as the server can make them — which is when two answers racing
//! each other is most likely. The opened event is answered with nothing by its own static rule.
//! The peer writes numbered pings, each in two writes split inside its header, and reads the
//! pongs back; their nonces must come back in the order the pings were written.
//!
//! The second test is the connect-time half of the same rule: the answer to the opened event
//! comes before the answer to anything the peer sent while it was being composed.
//!
//! Bitcoin declares batching `Unsupported`, so there is one mode to drive. Loopback only; the
//! LLM endpoint is a dead port, and nothing may reach it.

use std::io::Cursor;
use std::time::Duration;

use bitcoin::consensus::{Decodable, Encodable};
use bitcoin::p2p::message::{NetworkMessage, RawNetworkMessage};
use bitcoin::p2p::Magic;
use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use netget::state::ServerId;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

/// Pings per connection, each written in two halves.
const PINGS: u64 = 300;
/// Where each 32-byte ping is split: inside its 24-byte header, so neither half is a message.
const SPLIT: usize = 10;
/// Connections, each driven at the same time as the others.
const CONNECTIONS: u64 = 4;

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

fn nonce(connection: u64, i: u64) -> u64 {
    connection * 1_000_000 + i
}

fn ping(nonce: u64) -> Vec<u8> {
    let mut bytes = Vec::new();
    RawNetworkMessage::new(Magic::BITCOIN, NetworkMessage::Ping(nonce))
        .consensus_encode(&mut bytes)
        .expect("encode ping");
    bytes
}

/// Read exactly one framed P2P message off the socket.
async fn read_message(read_half: &mut tokio::net::tcp::OwnedReadHalf) -> RawNetworkMessage {
    let mut header = [0u8; 24];
    read_half
        .read_exact(&mut header)
        .await
        .expect("read header");
    let len = u32::from_le_bytes([header[16], header[17], header[18], header[19]]) as usize;
    let mut payload = vec![0u8; len];
    if len > 0 {
        read_half
            .read_exact(&mut payload)
            .await
            .expect("read payload");
    }
    let mut full = header.to_vec();
    full.extend_from_slice(&payload);
    RawNetworkMessage::consensus_decode(&mut Cursor::new(full)).expect("decode message")
}

/// Write `PINGS` numbered pings, each in two writes, and return the nonces of the pongs that came back.
async fn ping_pong(port: u16, connection: u64) -> Vec<u64> {
    let stream = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    let (mut read_half, mut write_half) = stream.into_split();

    let writer = tokio::spawn(async move {
        for i in 0..PINGS {
            let message = ping(nonce(connection, i));
            for half in [&message[..SPLIT], &message[SPLIT..]] {
                write_half.write_all(half).await.expect("write");
                // Let the server read between writes, so each half is likely a read of its
                // own and many reads are in the server at once.
                tokio::task::yield_now().await;
            }
        }
        write_half
    });

    let mut nonces = Vec::with_capacity(PINGS as usize);
    let read = tokio::time::timeout(Duration::from_secs(60), async {
        while (nonces.len() as u64) < PINGS {
            match read_message(&mut read_half).await.payload() {
                NetworkMessage::Pong(n) => nonces.push(*n),
                other => panic!("connection {connection}: expected a pong, got {other:?}"),
            }
        }
    })
    .await;
    let _write_half = writer.await.expect("writer");
    assert!(
        read.is_ok(),
        "connection {connection}: only {} of {PINGS} pongs within the deadline",
        nonces.len()
    );
    nonces
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bitcoin_messages_are_answered_in_the_order_they_arrived() {
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
                "handler": { "type": "static", "actions": [] }
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

    let peers: Vec<_> = (0..CONNECTIONS)
        .map(|c| tokio::spawn(ping_pong(port, c)))
        .collect();
    for (c, peer) in peers.into_iter().enumerate() {
        let c = c as u64;
        let got = peer.await.expect("peer");
        let want: Vec<u64> = (0..PINGS).map(|i| nonce(c, i)).collect();
        if got != want {
            let at = want.iter().zip(&got).position(|(a, b)| a != b).unwrap_or(0);
            let from = at.saturating_sub(3);
            panic!(
                "connection {c}: pongs came back out of order from pong {at}:\n  pinged ...{:?}\n  ponged ...{:?}",
                &want[from..(at + 5).min(want.len())],
                &got[from..(at + 5).min(got.len())],
            );
        }
    }
    let _ = state.remove_server(id).await;
}

/// The answer to the opened event goes out before the answer to anything the peer sent while it
/// was being composed — a node's `version` before its `verack`.
///
/// The opened event is parked on a `manual` rule, so it is outstanding for as long as the test
/// likes, and the peer pings during that window. The `pong` is static and immediate; before the
/// messages were held behind the opened answer it reached the peer first, every time.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bitcoin_messages_wait_behind_the_opened_answer() {
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
        instruction: Some(String::new()),
        event_handlers: Some(vec![
            serde_json::json!({
                "event_pattern": "bitcoin_connection_opened",
                "handler": { "type": "manual", "timeout_secs": 60 }
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
    write_half.write_all(&ping(42)).await.expect("write");

    // The opened answer is now parked for a person.
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
    // Give the ping every chance to be answered ahead of it.
    tokio::time::sleep(Duration::from_millis(500)).await;
    state
        .resolve_intercept(
            opened.id,
            vec![serde_json::json!({"type": "send_ping", "network": "mainnet", "nonce": 7})],
        )
        .await
        .expect("answer the opened event");

    let mut got = Vec::new();
    for _ in 0..2 {
        let message = tokio::time::timeout(Duration::from_secs(10), read_message(&mut read_half))
            .await
            .unwrap_or_else(|_| panic!("only {got:?} within the deadline"));
        got.push(message.payload().clone());
    }
    assert_eq!(
        got,
        vec![NetworkMessage::Ping(7), NetworkMessage::Pong(42)],
        "the answer to a message sent while the opened event was outstanding went out ahead of it"
    );
    drop(write_half);
    let _ = state.remove_server(id).await;
}

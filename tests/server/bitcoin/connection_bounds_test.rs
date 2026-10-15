//! The read deadlines on a real, running Bitcoin P2P server, driven from the wire.
//!
//! Before September 2026 this server accepted without limit and bounded no read in time: a peer
//! that connected and said nothing held a socket, a read task and an `AppState` row forever,
//! before any version handshake, on a server that would happily accept a hundred more.
//!
//! Two properties are asserted, and each one alone would be satisfied by a bug:
//!
//! 1. A peer that connects and **says nothing** is closed at `FIRST_BYTE_READ_TIMEOUT` (60s,
//!    Bitcoin Core's own `DEFAULT_PEER_CONNECT_TIMEOUT`), and closed *silently* — Bitcoin P2P
//!    has no message a node may send to explain a disconnect, and Core itself just drops.
//! 2. A peer that has **sent a message** survives well past that same bound. The longer bound
//!    (1800s) sits above Core's own 20-minute `TIMEOUT_INTERVAL`, so a peer this server closes
//!    is one Core would already have dropped.
//!
//! The server here is **model-free**: a zero-action static handler answers
//! `bitcoin_connection_opened` (so nothing is written on connect and the socket stays open) and
//! a `send_verack` handler answers `bitcoin_message_received`. That matters — this protocol
//! fails closed by *disconnecting*, so a server left to consult an unreachable model would drop
//! every peer instantly and this file would be measuring that instead of the deadline.
//!
//! **How this was proved to fail without the bound**: replace the `tokio::time::timeout(...)`
//! around `read_half.read(...)` in `src/server/bitcoin/mod.rs` with the bare call and the first
//! test hangs for its whole 100-second window, then fails with "still holding the socket".
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features bitcoin,tcp --test server -- bitcoin::connection_bounds --test-threads=100


use std::time::Duration;

use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use netget::state::ServerId;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

/// `src/server/bitcoin/mod.rs::FIRST_BYTE_READ_TIMEOUT`. Deliberately duplicated: if the
/// constant moves, this test should be re-read rather than silently follow it.
const FIRST_BYTE_READ_TIMEOUT: Duration = Duration::from_secs(60);

/// Mainnet message magic, the first four bytes of every Bitcoin P2P message.
const MAINNET_MAGIC: [u8; 4] = [0xF9, 0xBE, 0xB4, 0xD9];

/// A complete mainnet `verack`: magic, the 12-byte command field, a zero payload length, and
/// the double-SHA256 checksum of the empty payload (`5d f6 e0 e2`).
const VERACK: &[u8] = &[
    0xF9, 0xBE, 0xB4, 0xD9, // magic
    0x76, 0x65, 0x72, 0x61, 0x63, 0x6B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // "verack"
    0x00, 0x00, 0x00, 0x00, // payload length
    0x5D, 0xF6, 0xE0, 0xE2, // checksum of the empty payload
];

async fn new_state() -> AppState {
    // The LLM endpoint is a dead port on purpose: the handlers below are static, so if any of
    // this ever started consulting the model the tests would fail loudly — this protocol fails
    // closed by disconnecting — rather than quietly measuring something else.
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".to_string());
    state
        .set_llm_client(netget::llm::OllamaClient::new(
            "http://127.0.0.1:1".to_string(),
        ))
        .await;
    state
}

async fn wait_for_port(state: &AppState, id: ServerId) -> u16 {
    for _ in 0..200 {
        if let Some(s) = state.get_server(id).await {
            if let Some(addr) = s.local_addr {
                return addr.port();
            }
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("Bitcoin server #{} never bound a port", id.as_u32());
}

async fn start_server(state: &AppState) -> u16 {
    let (tx, _rx) = mpsc::unbounded_channel();
    let server_id = ServerForm {
        protocol: "bitcoin".to_string(),
        port: Some(0),
        instruction: Some(String::new()),
        event_handlers: Some(vec![
            // Answer with nothing. A Bitcoin node says nothing on connect until it has seen a
            // `version`, and a zero-action static handler suppresses the LLM call entirely
            // (`tests/empty_static_handler_test.rs` measures that).
            serde_json::json!({
                "event_pattern": "bitcoin_connection_opened",
                "handler": { "type": "static", "actions": [] }
            }),
            serde_json::json!({
                "event_pattern": "bitcoin_message_received",
                "handler": {
                    "type": "static",
                    "actions": [{ "type": "send_verack", "network": "mainnet" }]
                }
            }),
        ]),
        ..Default::default()
    }
    .create(state, tx)
    .await
    .expect("create bitcoin server");
    wait_for_port(state, server_id).await
}

#[tokio::test]
async fn a_peer_that_connects_and_says_nothing_is_closed_at_the_first_byte_bound() {
    let state = new_state().await;
    let port = start_server(&state).await;

    let mut peer = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");

    let started = std::time::Instant::now();
    let mut sink = Vec::new();
    // Generous against the 60s bound so an ordinary scheduling delay under --test-threads=100
    // is not mistaken for a missing timeout; the assertion that matters is that it ends at all.
    let read = tokio::time::timeout(
        FIRST_BYTE_READ_TIMEOUT + Duration::from_secs(40),
        peer.read_to_end(&mut sink),
    )
    .await;

    let elapsed = started.elapsed();
    assert!(
        read.is_ok(),
        "a peer that connected and sent nothing was still holding the socket, the read task and \
         its AppState row after {}s — the first-byte deadline is not being applied",
        elapsed.as_secs()
    );
    read.unwrap().expect("read to EOF");
    assert!(
        sink.is_empty(),
        "Bitcoin P2P has no message a node may send to explain a disconnect and every message \
         this server could send is an assertion about a node that has not handshaked; the \
         refusal must be a plain close. Got {sink:02x?}"
    );
    assert!(
        elapsed >= FIRST_BYTE_READ_TIMEOUT / 2,
        "closed after only {}ms — that is not the declared 60s bound, it is something else \
         tearing the connection down",
        elapsed.as_millis()
    );
}

#[tokio::test]
async fn a_peer_that_has_sent_a_message_gets_the_longer_idle_bound() {
    // The point of the pair. A live Bitcoin node speaks every two minutes (Core's
    // PING_INTERVAL), so the idle bound is generous by design; a single number applied to both
    // states would close this connection at the same moment the test above closes its own.
    let state = new_state().await;
    let port = start_server(&state).await;

    let mut peer = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");

    peer.write_all(VERACK).await.expect("write verack");
    peer.flush().await.expect("flush");

    let mut reply = [0u8; 128];
    let n = tokio::time::timeout(Duration::from_secs(30), peer.read(&mut reply))
        .await
        .expect("the server should answer the first message promptly")
        .expect("read");
    assert!(n >= 24, "expected a Bitcoin P2P message, got {n} bytes");
    assert_eq!(
        &reply[0..4],
        &MAINNET_MAGIC,
        "expected a mainnet message, got {:02x?}",
        &reply[..n]
    );

    // Now go quiet for longer than the *first* bound and assert the connection survives.
    tokio::time::sleep(FIRST_BYTE_READ_TIMEOUT + Duration::from_secs(8)).await;

    peer.write_all(VERACK).await.expect("write second verack");
    peer.flush().await.expect("flush");
    let n = tokio::time::timeout(Duration::from_secs(30), peer.read(&mut reply))
        .await
        .expect(
            "a peer that had sent a message and then paused for 68s was closed — the idle bound \
             has collapsed onto the first-byte bound, and Bitcoin Core would not have dropped \
             this peer for another nineteen minutes",
        )
        .expect("read");
    assert!(
        n >= 24,
        "the connection answered nothing after the pause; it was closed, not idle-tolerant"
    );
}

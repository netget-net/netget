//! The read deadlines on a real, running Modbus TCP server, driven from the wire.
//!
//! Modbus has **no authentication step of any kind**, so "pre-authentication" here means
//! "anyone who can reach the port". Before September 2026 this server accepted without limit and
//! bounded no read in time: such a peer could connect, say nothing, and hold a socket, a read
//! task, a peer handle and an `AppState` row forever, on a server that would happily accept a
//! hundred more.
//!
//! Two properties are asserted, and each one alone would be satisfied by a bug:
//!
//! 1. A peer that connects and **says nothing** is closed at `FIRST_BYTE_READ_TIMEOUT`, and
//!    closed *silently* — Modbus has no message a server may send unprompted, and inventing one
//!    means inventing a transaction.
//! 2. A peer that has **sent a request** survives well past that same bound. The longer bound
//!    exists because `handle_data` runs on its own task: the reader keeps reading while a
//!    request is being answered, so a peer waiting for its own reply — including one parked on a
//!    `manual` rule for a human — is silent on this socket for the whole of that work.
//!
//! **How this was proved to fail without the bound**: replace the `tokio::time::timeout(...)`
//! around `read_half.read(...)` in `src/server/modbus/mod.rs` with the bare call and the first
//! test hangs for its whole 70-second window, then fails with "still holding the socket".
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features modbus,tcp --test server -- modbus::connection_bounds --test-threads=100

use std::time::Duration;

use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use netget::state::ServerId;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

/// `src/server/modbus/mod.rs::FIRST_BYTE_READ_TIMEOUT`. Deliberately duplicated: if the constant
/// moves, this test should be re-read rather than silently follow it.
const FIRST_BYTE_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Read Holding Registers (function 0x03), one register at address 0, unit 1.
///
/// MBAP header `00 01` transaction · `00 00` protocol · `00 06` length · `01` unit,
/// then the PDU `03 00 00 00 01`.
const READ_HOLDING_REGISTERS: &[u8] = &[
    0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x01,
];

async fn new_state() -> AppState {
    // A dead LLM endpoint. These tests assert on deadlines, not on answers: Modbus's fail-closed
    // path answers a request it cannot decide with an exception response, which proves the
    // connection is alive exactly as well as register data would.
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
    panic!("Modbus server #{} never bound a port", id.as_u32());
}

async fn start_server(state: &AppState) -> u16 {
    let (tx, _rx) = mpsc::unbounded_channel();
    let server_id = ServerForm {
        protocol: "modbus".to_string(),
        port: Some(0),
        // An empty instruction really is model-free; `None` would be replaced by a default
        // instruction and every request would consult the LLM.
        instruction: Some(String::new()),
        ..Default::default()
    }
    .create(state, tx)
    .await
    .expect("create modbus server");
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
    // Generous against the 30s bound so an ordinary scheduling delay under --test-threads=100
    // is not mistaken for a missing timeout; the assertion that matters is that it ends at all.
    let read = tokio::time::timeout(
        FIRST_BYTE_READ_TIMEOUT + Duration::from_secs(40),
        peer.read_to_end(&mut sink),
    )
    .await;

    let elapsed = started.elapsed();
    assert!(
        read.is_ok(),
        "a peer that connected and sent nothing was still holding the socket, the read task, \
         its peer handle and its AppState row after {}s — the first-byte deadline is not being \
         applied",
        elapsed.as_secs()
    );
    read.unwrap().expect("read to EOF");
    assert!(
        sink.is_empty(),
        "every Modbus server message is a reply and carries the transaction id, unit id and \
         function code of a request this peer never sent; inventing one would be inventing a \
         transaction. The refusal must be a plain close. Got {sink:02x?}"
    );
    assert!(
        elapsed >= FIRST_BYTE_READ_TIMEOUT / 2,
        "closed after only {}ms — that is not the declared 30s bound, it is something else \
         tearing the connection down",
        elapsed.as_millis()
    );
}

#[tokio::test]
async fn a_peer_that_has_sent_a_request_gets_the_longer_idle_bound() {
    // The point of the pair. A polling master sends a request every few hundred milliseconds,
    // but this server's reader keeps reading while `handle_data` answers on its own task — so a
    // peer waiting for its own reply, or for a human at the dashboard, is silent here for the
    // whole of that work, and a single number applied to both states would cut it off.
    let state = new_state().await;
    let port = start_server(&state).await;

    let mut peer = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");

    peer.write_all(READ_HOLDING_REGISTERS)
        .await
        .expect("write request");
    peer.flush().await.expect("flush");

    let mut reply = [0u8; 64];
    let n = tokio::time::timeout(Duration::from_secs(30), peer.read(&mut reply))
        .await
        .expect("the server should answer the first request promptly")
        .expect("read");
    assert!(n >= 8, "expected a Modbus ADU, got {n} bytes");
    assert_eq!(
        &reply[0..2],
        &[0x00, 0x01],
        "the reply must echo the transaction identifier of the request it answers, got {:02x?}",
        &reply[..n]
    );

    // Now go quiet for longer than the *first* bound and assert the connection survives.
    tokio::time::sleep(FIRST_BYTE_READ_TIMEOUT + Duration::from_secs(8)).await;

    peer.write_all(READ_HOLDING_REGISTERS)
        .await
        .expect("write second request");
    peer.flush().await.expect("flush");
    let n = tokio::time::timeout(Duration::from_secs(30), peer.read(&mut reply))
        .await
        .expect(
            "a peer that had sent a request and then paused for 38s was closed — the idle bound \
             has collapsed onto the first-byte bound, which would cut off any client whose \
             answer was parked for a human",
        )
        .expect("read");
    assert!(
        n >= 8,
        "the connection answered nothing after the pause; it was closed, not idle-tolerant"
    );
}

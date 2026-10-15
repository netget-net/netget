//! The first-byte deadline on a real, running gRPC server, driven from the wire.
//!
//! Before September 2026 this server accepted without limit and bounded no read in time: a peer
//! that connected and said nothing held a socket, a connection task and an `AppState` entry
//! forever, pre-authentication, on a server that would happily accept a hundred more.
//!
//! Two properties are asserted here, and each one alone would be satisfied by a bug:
//!
//! 1. A peer that connects and **says nothing** is closed at `FIRST_BYTE_READ_TIMEOUT`.
//! 2. A peer that sends the **HTTP/2 connection preface** is served, and survives well past that
//!    same bound. gRPC multiplexes many RPCs over one long-lived connection, so a bound that
//!    closed a peer 30 seconds after it connected — rather than 30 seconds after it went quiet
//!    without ever speaking — would break every client.
//!
//! The bytes here are raw HTTP/2 rather than a gRPC call, deliberately: what is under test is
//! the deadline in front of hyper, and the preface plus an empty SETTINGS frame is the smallest
//! thing that makes hyper answer. `real_client_test.rs` is where grpcurl proves the protocol.
//!
//! **How this was proved to fail without the bound**: delete the `tokio::time::timeout(...)`
//! around `stream.peek(...)` in `src/server/grpc/mod.rs` and the first test hangs for its whole
//! 70-second window and then fails with "still holding the socket".
//!
//! The idle-between-requests bound is 900s, which no test can sit out. What is testable about
//! it — that a connection with work in flight is never reported as idle — is covered by
//! `tests/accept_bounded_test.rs` against the shared `ConnectionActivity`, and the wiring by
//! `tests/tcp_server_bounds_ratchet_test.rs`.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features grpc,tcp --test server -- connection_bounds --test-threads=100


use std::time::Duration;

use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use netget::state::ServerId;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

/// `src/server/grpc/mod.rs::FIRST_BYTE_READ_TIMEOUT`. Deliberately duplicated: if the constant
/// moves, this test should be re-read rather than silently follow it.
const FIRST_BYTE_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// RFC 9113 §3.4: the client connection preface, which every HTTP/2 client sends before
/// anything else, followed by the required (here empty) SETTINGS frame.
const HTTP2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
/// A SETTINGS frame with no entries: length 0, type 0x04, no flags, stream 0.
const EMPTY_SETTINGS: &[u8] = &[0, 0, 0, 4, 0, 0, 0, 0, 0];

/// The smallest schema this server will start with. `proto_schema` is required, and a service
/// with at least one method must exist.
const PROTO_SCHEMA: &str = r#"
syntax = "proto3";
package bounds;
message Ping { int64 id = 1; }
message Pong { int64 id = 1; }
service Bounds { rpc Check(Ping) returns (Pong); }
"#;

async fn new_state() -> AppState {
    // A dead LLM endpoint. These tests assert on deadlines, not on answers, and they never get
    // as far as an RPC.
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
    panic!("gRPC server #{} never bound a port", id.as_u32());
}

async fn start_server(state: &AppState) -> u16 {
    let (tx, _rx) = mpsc::unbounded_channel();
    let server_id = ServerForm {
        protocol: "grpc".to_string(),
        port: Some(0),
        // An empty instruction really is model-free; `None` would be replaced by a default
        // instruction and every request would consult the LLM.
        instruction: Some(String::new()),
        startup_params: Some(serde_json::json!({ "proto_schema": PROTO_SCHEMA })),
        ..Default::default()
    }
    .create(state, tx)
    .await
    .expect("create grpc server (needs protoc on PATH)");
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
        "a peer that connected and sent nothing was still holding the socket, the connection \
         task and its AppState entry after {}s — the first-byte deadline is not being applied",
        elapsed.as_secs()
    );
    read.unwrap().expect("read to EOF");
    assert!(
        sink.is_empty(),
        "HTTP/2 is client-speaks-first: the server sends nothing before the client's preface, \
         so a peer that sent nothing should be closed, not written to. Got {:?}",
        sink
    );
    assert!(
        elapsed >= FIRST_BYTE_READ_TIMEOUT / 2,
        "closed after only {}ms — that is not the declared 30s bound, it is something else \
         tearing the connection down",
        elapsed.as_millis()
    );
}

#[tokio::test]
async fn a_peer_that_sends_the_preface_outlives_the_first_byte_bound() {
    // The other half of the pair: the deadline bounds silence, not the connection. A gRPC
    // client dials once and reuses the connection, so this is the assertion that fails if
    // someone "simplifies" the peek into a deadline on every read.
    let state = new_state().await;
    let port = start_server(&state).await;

    let mut peer = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");

    peer.write_all(HTTP2_PREFACE).await.expect("write preface");
    peer.write_all(EMPTY_SETTINGS)
        .await
        .expect("write SETTINGS");
    peer.flush().await.expect("flush");

    // hyper answers with its own SETTINGS, then an ACK of ours. Drain whatever has arrived so
    // the assertion after the pause cannot be satisfied by bytes from before it.
    let mut scratch = [0u8; 256];
    let n = tokio::time::timeout(Duration::from_secs(30), peer.read(&mut scratch))
        .await
        .expect("the server should send its SETTINGS promptly")
        .expect("read");
    assert!(n > 0, "expected the server's own SETTINGS frame");
    while let Ok(Ok(extra)) =
        tokio::time::timeout(Duration::from_millis(300), peer.read(&mut scratch)).await
    {
        if extra == 0 {
            panic!("the server closed the connection immediately after the preface");
        }
    }

    tokio::time::sleep(FIRST_BYTE_READ_TIMEOUT + Duration::from_secs(8)).await;

    // A second empty SETTINGS frame: hyper must answer it with an ACK (type 0x04, flag 0x01).
    peer.write_all(EMPTY_SETTINGS)
        .await
        .expect("write second SETTINGS");
    peer.flush().await.expect("flush");
    let n = tokio::time::timeout(Duration::from_secs(30), peer.read(&mut scratch))
        .await
        .expect(
            "an established HTTP/2 peer that paused for 38s got no answer — the first-byte \
             bound has leaked onto the whole connection, which would break every gRPC client",
        )
        .expect("read");
    assert!(
        n > 0,
        "the connection answered nothing after the pause; it was closed, not idle-tolerant"
    );
    assert_eq!(
        &scratch[..n],
        &[0u8, 0, 0, 4, 1, 0, 0, 0, 0],
        "expected a SETTINGS ACK from a live HTTP/2 connection"
    );
}

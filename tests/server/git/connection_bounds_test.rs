//! The first-byte deadline on a real, running Git Smart HTTP server, driven from the wire.
//!
//! Before September 2026 this server accepted without limit and bounded no read in time: a peer
//! that connected and said nothing held a socket, a connection task and an `AppState` entry
//! forever, pre-authentication, on a server that would happily accept a hundred more.
//!
//! Two properties are asserted here, and each one alone would be satisfied by a bug:
//!
//! 1. A peer that connects and **says nothing** is closed at `FIRST_BYTE_READ_TIMEOUT`.
//! 2. A peer that **speaks** is served, and survives well past that same bound — the deadline
//!    is on the silence, not on the connection. A single number applied to both would break
//!    every keep-alive client, which is what a `git clone` is: two requests on one connection.
//!
//! **How this was proved to fail without the bound**: delete the `tokio::time::timeout(...)`
//! around `stream.peek(...)` in `src/server/git/mod.rs` and the first test hangs for its whole
//! 70-second window and then fails with "still holding the socket"; hyper waits for a request
//! line that never comes and nothing else in the process is watching.
//!
//! The idle-between-requests bound is 900s, which no test can sit out. What is testable about
//! it — that a connection with work in flight is never reported as idle — is covered by
//! `tests/accept_bounded_test.rs` against the shared `ConnectionActivity`, and the wiring by
//! `tests/tcp_server_bounds_ratchet_test.rs`.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features git --test server -- git::connection_bounds --test-threads=100

use std::time::Duration;

use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use netget::state::ServerId;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

/// `src/server/git/mod.rs::FIRST_BYTE_READ_TIMEOUT`. Deliberately duplicated: if the constant
/// moves, this test should be re-read rather than silently follow it.
const FIRST_BYTE_READ_TIMEOUT: Duration = Duration::from_secs(30);

async fn new_state() -> AppState {
    // A dead LLM endpoint. These tests assert on deadlines, not on answers, and a fail-closed
    // 5xx proves the connection is alive exactly as well as a pack would.
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
    panic!("Git server #{} never bound a port", id.as_u32());
}

async fn start_server(state: &AppState) -> u16 {
    let (tx, _rx) = mpsc::unbounded_channel();
    let server_id = ServerForm {
        protocol: "git".to_string(),
        port: Some(0),
        // An empty instruction really is model-free; `None` would be replaced by a default
        // instruction and every request would consult the LLM.
        instruction: Some(String::new()),
        ..Default::default()
    }
    .create(state, tx)
    .await
    .expect("create git server");
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
        "HTTP is client-speaks-first and this server has nothing to say to a peer that asked \
         nothing; it should close, not write. Got {:?}",
        String::from_utf8_lossy(&sink)
    );
    assert!(
        elapsed >= FIRST_BYTE_READ_TIMEOUT / 2,
        "closed after only {}ms — that is not the declared 30s bound, it is something else \
         tearing the connection down",
        elapsed.as_millis()
    );
}

#[tokio::test]
async fn a_peer_that_speaks_is_served_and_outlives_the_first_byte_bound() {
    // The other half of the pair: the deadline bounds silence, not the connection. A clone is
    // two requests on one keep-alive connection, so a bound that closed a peer 30 seconds after
    // it connected — rather than 30 seconds after it went quiet without ever speaking — would
    // break a working client.
    let state = new_state().await;
    let port = start_server(&state).await;

    let mut peer = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");

    peer.write_all(
        b"GET /hello-world.git/info/refs?service=git-upload-pack HTTP/1.1\r\n\
          Host: 127.0.0.1\r\nUser-Agent: git/2.54\r\n\r\n",
    )
    .await
    .expect("write request");
    peer.flush().await.expect("flush");

    let mut reply = [0u8; 256];
    let n = tokio::time::timeout(Duration::from_secs(30), peer.read(&mut reply))
        .await
        .expect("the server should answer promptly")
        .expect("read");
    assert!(n > 0, "expected an HTTP response to the first request");
    assert!(
        reply[..n].starts_with(b"HTTP/1.1 "),
        "expected an HTTP status line, got {:?}",
        String::from_utf8_lossy(&reply[..n])
    );

    // Now hold the connection open, having spoken, for longer than the first-byte bound and
    // assert it is still there. This is the assertion that fails if someone "simplifies" the
    // peek into a deadline on every read.
    tokio::time::sleep(FIRST_BYTE_READ_TIMEOUT + Duration::from_secs(8)).await;

    peer.write_all(
        b"GET /hello-world.git/info/refs?service=git-upload-pack HTTP/1.1\r\n\
          Host: 127.0.0.1\r\nUser-Agent: git/2.54\r\n\r\n",
    )
    .await
    .expect("write second request");
    peer.flush().await.expect("flush");
    let n = tokio::time::timeout(Duration::from_secs(30), peer.read(&mut reply))
        .await
        .expect(
            "an established client that paused for 38s was closed — the first-byte bound has \
             leaked onto the whole connection, which would break every keep-alive client",
        )
        .expect("read");
    assert!(
        n > 0,
        "the connection answered nothing after the pause; it was closed, not idle-tolerant"
    );
}

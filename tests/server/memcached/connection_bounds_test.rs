//! The read deadlines on a real, running Memcached server, driven from the wire.
//!
//! Memcached is the shortest of the eighteen — `FIRST_COMMAND_READ_TIMEOUT` is 30s and
//! `IDLE_BETWEEN_COMMANDS_TIMEOUT` is 120s — which makes it the one protocol whose *pair* can
//! be demonstrated end to end in a test that finishes: the first bound fires, and the second
//! demonstrably has not fired at the same moment. Remove the `tokio::time::timeout` around the
//! read in `src/server/memcached/mod.rs` and the first test below hangs until its own 60s
//! assertion window expires; shorten the pair to one number and the second fails.
//!
//! The shared mechanism (the cap, `IdleTimeoutReader`, `ConnectionActivity`) is covered by
//! `tests/accept_bounded_test.rs`, and that every one of the eighteen is wired to both by
//! `tests/tcp_server_bounds_ratchet_test.rs`. This file is the evidence that the wiring does
//! what it says against a socket.
//!
//! No mock backend: the LLM endpoint is a dead port, so any command is answered
//! `SERVER_ERROR` on memcached's fail-closed path. That is deliberate — these tests assert on
//! *deadlines*, not on answers, and a fail-closed reply proves the connection is alive exactly
//! as well as a cache hit would. The first test sends no command at all.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features memcached --test server -- memcached::connection_bounds --test-threads=100


use std::time::Duration;

use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use netget::state::ServerId;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

/// `src/server/memcached/mod.rs::FIRST_COMMAND_READ_TIMEOUT`.
const FIRST_COMMAND_READ_TIMEOUT: Duration = Duration::from_secs(30);

async fn new_state() -> AppState {
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
    panic!("Memcached server #{} never bound a port", id.as_u32());
}

async fn start_server(state: &AppState) -> u16 {
    let (tx, _rx) = mpsc::unbounded_channel();
    let server_id = ServerForm {
        protocol: "memcached".to_string(),
        port: Some(0),
        // An empty instruction really is model-free; `None` would be replaced by a default
        // instruction and every command would consult the LLM.
        instruction: Some(String::new()),
        ..Default::default()
    }
    .create(state, tx)
    .await
    .expect("create memcached server");
    wait_for_port(state, server_id).await
}

#[tokio::test]
async fn a_peer_that_connects_and_says_nothing_is_closed_at_the_first_command_bound() {
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
        FIRST_COMMAND_READ_TIMEOUT + Duration::from_secs(30),
        peer.read_to_end(&mut sink),
    )
    .await;

    let elapsed = started.elapsed();
    assert!(
        read.is_ok(),
        "a peer that connected and sent nothing was still holding the socket, the connection \
         task and its AppState entry after {}s — the first-command read deadline is not being \
         applied",
        elapsed.as_secs()
    );
    read.unwrap().expect("read to EOF");
    assert!(
        sink.is_empty(),
        "memcached has no greeting and nothing to say to a peer that asked nothing; it should \
         close, not write. Got {:?}",
        String::from_utf8_lossy(&sink)
    );
    assert!(
        elapsed >= FIRST_COMMAND_READ_TIMEOUT / 2,
        "closed after only {}ms — that is not the declared 30s bound, it is something else \
         tearing the connection down",
        elapsed.as_millis()
    );
}

#[tokio::test]
async fn an_answered_peer_gets_the_longer_idle_bound() {
    // The point of the pair: "has said nothing at all" and "has gone quiet mid-session" are
    // different claims and get different answers. A single number applied to both would close
    // this connection at the same moment the test above closes its own.
    let state = new_state().await;
    let port = start_server(&state).await;

    let mut peer = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");

    // Any complete command makes this peer an established client — that is what the read loop
    // keys the longer bound on. With no reachable backend the answer is `SERVER_ERROR`, which
    // is the correct fail-closed reply and is just as good a proof of life as a cache hit;
    // what this test is about is the *deadline*, not the answer.
    peer.write_all(b"version\r\n").await.expect("write version");
    peer.flush().await.expect("flush");

    let mut reply = [0u8; 128];
    let n = tokio::time::timeout(Duration::from_secs(20), peer.read(&mut reply))
        .await
        .expect("the server should answer promptly")
        .expect("read");
    assert!(n > 0, "expected a reply to the first command");

    // Now go quiet for longer than the *first* bound and assert the connection survives: the
    // idle bound for an established client is 120s, four times as long.
    tokio::time::sleep(FIRST_COMMAND_READ_TIMEOUT + Duration::from_secs(8)).await;

    peer.write_all(b"version\r\n").await.expect("write again");
    peer.flush().await.expect("flush");
    let n = tokio::time::timeout(Duration::from_secs(20), peer.read(&mut reply))
        .await
        .expect(
            "an established client that paused for 38s was closed — the idle bound has \
             collapsed onto the first-command bound, which would break every pooling client",
        )
        .expect("read");
    assert!(
        n > 0,
        "the connection answered nothing after the pause; it was closed, not idle-tolerant"
    );
}

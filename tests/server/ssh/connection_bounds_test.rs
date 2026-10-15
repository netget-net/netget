//! The read deadlines on a real, running SSH server, driven from the wire.
//!
//! Before September 2026 this server accepted without limit and bounded no read in time at the
//! point that mattered: a peer that connected and never sent its identification string held a
//! socket, a task and an `AppState` row for as long as it liked, before any authentication, on a
//! server that would happily accept a hundred more. russh's `inactivity_timeout` was set to an
//! hour as an unexplained literal, which is not a bound on *that* state in any useful sense.
//!
//! Two properties are asserted, and each one alone would be satisfied by a bug:
//!
//! 1. A peer that connects and **sends no identification string** is closed at
//!    `FIRST_BYTE_READ_TIMEOUT`. The server's own `SSH-2.0-…` line still goes out first — SSH is
//!    the one protocol in this sweep where the server legitimately speaks first, which is why the
//!    bound is on the stream rather than a `peek`.
//! 2. A peer that **has sent its identification string** is not closed at that bound. An
//!    interactive shell is legitimately silent for a long time, so the session bound is an hour;
//!    collapsing the two numbers would disconnect anyone who stopped typing for a minute.
//!
//! **How this was proved to fail without the bound**: hand `run_stream` the raw `TcpStream`
//! instead of the `DeadlinedStream` in `src/server/ssh/mod.rs` and the first test hangs for its
//! whole 100-second window, then fails with "still holding the socket".
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features ssh,tcp --test server -- ssh::connection_bounds --test-threads=100


use std::time::Duration;

use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use netget::state::ServerId;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

/// `src/server/ssh/mod.rs::FIRST_BYTE_READ_TIMEOUT`. Deliberately duplicated: if the constant
/// moves, this test should be re-read rather than silently follow it.
const FIRST_BYTE_READ_TIMEOUT: Duration = Duration::from_secs(60);

/// A client identification string, as RFC 4253 §4.2 defines it.
const CLIENT_IDENT: &[u8] = b"SSH-2.0-netget_bounds_test\r\n";

async fn new_state() -> AppState {
    // A dead LLM endpoint. Nothing in this file gets as far as an event: `ssh_auth` needs an
    // authentication attempt and `ssh_banner` needs a shell channel, and neither test completes
    // a key exchange.
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
    panic!("SSH server #{} never bound a port", id.as_u32());
}

async fn start_server(state: &AppState) -> u16 {
    let (tx, _rx) = mpsc::unbounded_channel();
    let server_id = ServerForm {
        protocol: "ssh".to_string(),
        port: Some(0),
        // An empty instruction really is model-free; `None` would be replaced by a default
        // instruction. Nothing here reaches an event either way.
        instruction: Some(String::new()),
        ..Default::default()
    }
    .create(state, tx)
    .await
    .expect("create ssh server");
    wait_for_port(state, server_id).await
}

#[tokio::test]
async fn a_peer_that_never_sends_its_identification_string_is_closed_at_the_first_byte_bound() {
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
        "a peer that connected and never identified itself was still holding the socket, its \
         task and its AppState row after {}s — the first-byte deadline is not being applied",
        elapsed.as_secs()
    );
    read.unwrap().expect("read to EOF");
    assert!(
        sink.starts_with(b"SSH-2.0-"),
        "the server sends its identification string first, per RFC 4253 §4.2; got {:?}",
        String::from_utf8_lossy(&sink)
    );
    assert!(
        elapsed >= FIRST_BYTE_READ_TIMEOUT / 2,
        "closed after only {}ms — that is not the declared 60s bound, it is something else \
         tearing the connection down",
        elapsed.as_millis()
    );
}

#[tokio::test]
async fn a_peer_that_has_identified_itself_is_not_closed_at_the_first_byte_bound() {
    // The other half of the pair. An interactive shell is legitimately silent for a long time —
    // SSH has no keepalive that is on by default, since OpenSSH's ServerAliveInterval and
    // ClientAliveInterval both default to 0 — so the session bound is an hour. A single number
    // applied to both states would close this connection at the same moment the test above
    // closes its own, which would end any session where someone stopped typing.
    let state = new_state().await;
    let port = start_server(&state).await;

    let mut peer = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");

    let mut buf = [0u8; 4096];
    let n = tokio::time::timeout(Duration::from_secs(30), peer.read(&mut buf))
        .await
        .expect("the server's identification string should arrive promptly")
        .expect("read");
    assert!(
        buf[..n].starts_with(b"SSH-2.0-"),
        "expected an SSH identification string, got {:?}",
        String::from_utf8_lossy(&buf[..n])
    );

    peer.write_all(CLIENT_IDENT).await.expect("write ident");
    peer.flush().await.expect("flush");

    // Having identified itself, this peer stops — exactly what a client does between a user's
    // keystrokes, only earlier in the exchange. Wait out the first-byte bound with margin.
    tokio::time::sleep(FIRST_BYTE_READ_TIMEOUT + Duration::from_secs(8)).await;

    // The connection must still be open. A closed one reads `Ok(0)` immediately; a live one
    // that has nothing further to say to us simply blocks, which is the timeout below.
    match tokio::time::timeout(Duration::from_secs(3), peer.read(&mut buf)).await {
        Err(_) => {} // still open, nothing pending — the expected outcome
        Ok(Ok(0)) => panic!(
            "a peer that had identified itself was closed after 68s — the session bound has \
             collapsed onto the first-byte bound, which would end any SSH session where someone \
             stopped typing"
        ),
        Ok(Ok(_)) => {} // the server sent us its KEXINIT: also alive
        Ok(Err(e)) => panic!("the connection was reset rather than kept open: {e}"),
    }
}

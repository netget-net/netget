//! The read deadlines on a real, running IMAP server, driven from the wire.
//!
//! Before September 2026 this server accepted without limit and bounded no read in time: a peer
//! that connected, took the greeting and said nothing held a socket, a connection task, a
//! peer-command channel and an `AppState` entry forever, before any `LOGIN`, on a server that
//! would happily accept a hundred more.
//!
//! Two properties are asserted, and each one alone would be satisfied by a bug:
//!
//! 1. A greeted peer that **says nothing** is closed at `FIRST_COMMAND_READ_TIMEOUT`, with an
//!    untagged `BYE` rather than a silent drop.
//! 2. A peer that **has issued a command** survives well past that same bound. The longer bound
//!    (`IDLE_BETWEEN_COMMANDS_TIMEOUT`, 2100s) exists for `IDLE`: RFC 2177 lets a client sit
//!    silent, waiting for the *server* to speak, and only requires it to re-issue at least every
//!    29 minutes. Collapsing the two numbers into one would disconnect every idling mail client.
//!
//! Both servers here are **model-free**: static `event_handlers` answer the greeting and the
//! commands, so nothing in this file depends on an LLM being reachable, and what is measured is
//! the deadline rather than a backend.
//!
//! **How this was proved to fail without the bound**: replace the `tokio::time::timeout(...)`
//! around `read_bounded_line(...)` in `src/server/imap/mod.rs` with the bare call and the first
//! test hangs for its whole 100-second window, then fails with "still holding the socket".
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features imap,tcp --test server -- imap::connection_bounds --test-threads=100

use std::time::Duration;

use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use netget::state::ServerId;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

/// `src/server/imap/mod.rs::FIRST_COMMAND_READ_TIMEOUT`. Deliberately duplicated: if the
/// constant moves, this test should be re-read rather than silently follow it.
const FIRST_COMMAND_READ_TIMEOUT: Duration = Duration::from_secs(60);

const CAPABILITY_COMMAND: &[u8] = b"A001 CAPABILITY\r\n";

async fn new_state() -> AppState {
    // The LLM endpoint is a dead port on purpose: the handlers below are static, so if any of
    // this ever started consulting the model the tests would fail loudly rather than quietly
    // measuring something else.
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
    panic!("IMAP server #{} never bound a port", id.as_u32());
}

async fn start_server(state: &AppState) -> u16 {
    let (tx, _rx) = mpsc::unbounded_channel();
    let server_id = ServerForm {
        protocol: "imap".to_string(),
        port: Some(0),
        // An empty instruction really is model-free; `None` would be replaced by a default
        // instruction and the greeting would consult the LLM.
        instruction: Some(String::new()),
        event_handlers: Some(vec![
            serde_json::json!({
                "event_pattern": "imap_connection",
                "handler": {
                    "type": "static",
                    "actions": [{
                        "type": "send_imap_greeting",
                        "hostname": "bounds.test",
                        "capabilities": ["IMAP4rev1", "IDLE"]
                    }]
                }
            }),
            serde_json::json!({
                "event_pattern": "*",
                "handler": {
                    "type": "static",
                    "actions": [{
                        "type": "send_imap_response",
                        "tag": "A001",
                        "status": "OK",
                        "message": "completed"
                    }]
                }
            }),
        ]),
        ..Default::default()
    }
    .create(state, tx)
    .await
    .expect("create imap server");
    wait_for_port(state, server_id).await
}

#[tokio::test]
async fn a_greeted_peer_that_says_nothing_is_closed_at_the_first_command_bound() {
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
        FIRST_COMMAND_READ_TIMEOUT + Duration::from_secs(40),
        peer.read_to_end(&mut sink),
    )
    .await;

    let elapsed = started.elapsed();
    assert!(
        read.is_ok(),
        "a peer that took the greeting and sent nothing was still holding the socket, the \
         connection task, its peer-command channel and its AppState entry after {}s — the \
         first-command deadline is not being applied",
        elapsed.as_secs()
    );
    read.unwrap().expect("read to EOF");

    let text = String::from_utf8_lossy(&sink);
    assert!(
        text.starts_with("* OK"),
        "expected the greeting first, got {:?}",
        text
    );
    assert!(
        text.contains("* BYE"),
        "IMAP has an untagged BYE for exactly this and RFC 5530 gives it a reason; a silent \
         drop tells the client nothing. Got {:?}",
        text
    );
    assert!(
        elapsed >= FIRST_COMMAND_READ_TIMEOUT / 2,
        "closed after only {}ms — that is not the declared 60s bound, it is something else \
         tearing the connection down",
        elapsed.as_millis()
    );
}

#[tokio::test]
async fn a_peer_that_has_issued_a_command_gets_the_longer_idle_bound() {
    // This is the IDLE case in miniature. A client that has spoken once may then sit silent for
    // a long time — in real IMAP, up to the 29 minutes RFC 2177 allows before it must re-issue
    // IDLE — and closing it would be a bug rather than a bound. A single number applied to both
    // states would close this connection at the same moment the test above closes its own.
    let state = new_state().await;
    let port = start_server(&state).await;

    let mut peer = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");

    let mut buf = [0u8; 512];
    let n = tokio::time::timeout(Duration::from_secs(30), peer.read(&mut buf))
        .await
        .expect("the greeting should arrive promptly")
        .expect("read greeting");
    assert!(
        String::from_utf8_lossy(&buf[..n]).starts_with("* OK"),
        "expected an IMAP greeting, got {:?}",
        String::from_utf8_lossy(&buf[..n])
    );

    peer.write_all(CAPABILITY_COMMAND)
        .await
        .expect("write command");
    peer.flush().await.expect("flush");
    let n = tokio::time::timeout(Duration::from_secs(30), peer.read(&mut buf))
        .await
        .expect("the server should answer the first command promptly")
        .expect("read");
    assert!(n > 0, "expected a tagged response to CAPABILITY");

    // Now go quiet for longer than the *first* bound and assert the connection survives.
    tokio::time::sleep(FIRST_COMMAND_READ_TIMEOUT + Duration::from_secs(8)).await;

    peer.write_all(CAPABILITY_COMMAND)
        .await
        .expect("write second command");
    peer.flush().await.expect("flush");
    let n = tokio::time::timeout(Duration::from_secs(30), peer.read(&mut buf))
        .await
        .expect(
            "a peer that had issued a command and then paused for 68s was closed — the idle \
             bound has collapsed onto the first-command bound, which would disconnect every \
             client sitting in IDLE",
        )
        .expect("read");
    assert!(n > 0, "the connection answered nothing after the pause");
    assert!(
        !String::from_utf8_lossy(&buf[..n]).contains("BYE"),
        "the server said BYE to a peer that was mid-session: {:?}",
        String::from_utf8_lossy(&buf[..n])
    );
}

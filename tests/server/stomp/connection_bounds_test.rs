//! The read deadlines and the connection cap on a real, running STOMP server, from the wire.
//!
//! Before September 2026 this server accepted without limit and bounded no read in time: a peer
//! that connected and said nothing held a socket, a connection task and an `AppState` entry
//! forever — before `CONNECT`, so before the model had decided anything about it — on a server
//! that would happily accept a hundred more.
//!
//! Three properties are asserted, and each one alone would be satisfied by a bug:
//!
//! 1. A peer that connects and **says nothing** is closed at `FIRST_FRAME_READ_TIMEOUT`, and
//!    told so with an `ERROR` frame rather than dropped.
//! 2. A peer that has **connected** survives well past that same bound. STOMP's own reason for
//!    the two numbers to differ is that a subscriber sends `SUBSCRIBE` once and then only
//!    receives; collapsing them would cut every subscription at 30 seconds.
//! 3. The connection past `MAX_CONNECTIONS` is refused with a well-formed `ERROR` frame — the
//!    protocol's own vocabulary — and releasing one admitted connection frees exactly one slot.
//!
//! **How this was proved to fail without the bound**: replace the `tokio::time::timeout(...)`
//! around `reader.read(...)` in `src/server/stomp/mod.rs` with the bare call and the first test
//! hangs for its whole 70-second window, then fails with "still holding the socket".
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features stomp,tcp --test server -- stomp::connection_bounds --test-threads=100


use std::time::Duration;

use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use netget::state::ServerId;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

/// `src/server/stomp/mod.rs::FIRST_FRAME_READ_TIMEOUT`. Deliberately duplicated: if the constant
/// moves, this test should be re-read rather than silently follow it.
const FIRST_FRAME_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// `src/server/stomp/mod.rs::MAX_CONNECTIONS`.
const MAX_CONNECTIONS: usize = 256;

/// A STOMP 1.2 `CONNECT`. The NUL terminates the frame.
const CONNECT_FRAME: &[u8] = b"CONNECT\naccept-version:1.2\nhost:bounds.test\n\n\0";

/// A `SEND` to a destination — a second frame, used to prove the connection is still live.
const SEND_FRAME: &[u8] = b"SEND\ndestination:/queue/bounds\ncontent-length:2\n\nhi\0";

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
    panic!("STOMP server #{} never bound a port", id.as_u32());
}

/// A model-free server: static handlers answer `CONNECT` and everything else, so nothing here
/// depends on an LLM being reachable and what is measured is the deadline rather than a backend.
async fn start_server(state: &AppState) -> u16 {
    let (tx, _rx) = mpsc::unbounded_channel();
    let server_id = ServerForm {
        protocol: "stomp".to_string(),
        port: Some(0),
        instruction: Some(String::new()),
        event_handlers: Some(vec![
            serde_json::json!({
                "event_pattern": "stomp_connect",
                "handler": {
                    "type": "static",
                    "actions": [{
                        "type": "send_stomp_connected",
                        "session": "bounds-1",
                        "server": "netget/stomp"
                    }]
                }
            }),
            serde_json::json!({
                "event_pattern": "*",
                "handler": {
                    "type": "static",
                    "actions": [{
                        "type": "send_stomp_message",
                        "destination": "/queue/bounds",
                        "subscription": "0",
                        "message_id": "m-1",
                        "body": "ok",
                        "encoding": "utf8"
                    }]
                }
            }),
        ]),
        ..Default::default()
    }
    .create(state, tx)
    .await
    .expect("create stomp server");
    wait_for_port(state, server_id).await
}

#[tokio::test]
async fn a_peer_that_connects_and_says_nothing_is_closed_at_the_first_frame_bound() {
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
        FIRST_FRAME_READ_TIMEOUT + Duration::from_secs(40),
        peer.read_to_end(&mut sink),
    )
    .await;

    let elapsed = started.elapsed();
    assert!(
        read.is_ok(),
        "a peer that connected and sent nothing was still holding the socket, the connection \
         task and its AppState entry after {}s — the first-frame deadline is not being applied",
        elapsed.as_secs()
    );
    read.unwrap().expect("read to EOF");
    let text = String::from_utf8_lossy(&sink);
    assert!(
        text.starts_with("ERROR\n"),
        "STOMP has an ERROR frame and the spec has the server close after one, which is exactly \
         the shape of this refusal; a silent drop tells the client nothing. Got {text:?}"
    );
    assert!(
        elapsed >= FIRST_FRAME_READ_TIMEOUT / 2,
        "closed after only {}ms — that is not the declared 30s bound, it is something else \
         tearing the connection down",
        elapsed.as_millis()
    );
}

#[tokio::test]
async fn a_connected_peer_gets_the_longer_idle_bound() {
    // A STOMP subscriber sends SUBSCRIBE once and then only receives, so "has begun no session"
    // and "is mid-session" have to be different claims with different answers. A single number
    // applied to both would close this connection at the same moment the test above closes its
    // own.
    let state = new_state().await;
    let port = start_server(&state).await;

    let mut peer = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");

    peer.write_all(CONNECT_FRAME).await.expect("write CONNECT");
    peer.flush().await.expect("flush");

    let mut buf = [0u8; 512];
    let n = tokio::time::timeout(Duration::from_secs(30), peer.read(&mut buf))
        .await
        .expect("the server should answer CONNECT promptly")
        .expect("read");
    let text = String::from_utf8_lossy(&buf[..n]).to_string();
    assert!(
        text.starts_with("CONNECTED\n"),
        "expected CONNECTED, got {text:?}"
    );

    // Now go quiet for longer than the *first* bound and assert the connection survives: the
    // idle bound for a connected session is 1800s, sixty times as long.
    tokio::time::sleep(FIRST_FRAME_READ_TIMEOUT + Duration::from_secs(8)).await;

    peer.write_all(SEND_FRAME).await.expect("write SEND");
    peer.flush().await.expect("flush");
    let n = tokio::time::timeout(Duration::from_secs(30), peer.read(&mut buf))
        .await
        .expect(
            "a connected peer that paused for 38s was closed — the idle bound has collapsed onto \
             the first-frame bound, which would cut every subscription",
        )
        .expect("read");
    let text = String::from_utf8_lossy(&buf[..n]).to_string();
    assert!(n > 0, "the connection answered nothing after the pause");
    assert!(
        !text.starts_with("ERROR\n"),
        "the server refused a peer that was mid-session: {text:?}"
    );
}

#[tokio::test]
async fn the_connection_past_the_cap_gets_an_error_frame_and_the_slot_comes_back() {
    let state = new_state().await;
    let port = start_server(&state).await;

    // Fill the cap. These peers say nothing, which is fine: they are admitted, and the
    // first-frame deadline is 30s — far longer than this test needs.
    let mut held = Vec::with_capacity(MAX_CONNECTIONS);
    for i in 0..MAX_CONNECTIONS {
        held.push(
            TcpStream::connect(("127.0.0.1", port))
                .await
                .unwrap_or_else(|e| panic!("connection {i} of the cap failed: {e}")),
        );
    }
    tokio::time::sleep(Duration::from_millis(500)).await;

    let mut over = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("the listener must still accept — a cap is not a closed socket");
    let mut refusal = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), over.read_to_end(&mut refusal))
        .await
        .expect("the connection past the cap was neither answered nor closed")
        .expect("read the refusal");
    let text = String::from_utf8_lossy(&refusal).to_string();
    assert!(
        text.starts_with("ERROR\n"),
        "the peer over the cap must be refused with a STOMP ERROR frame, not dropped: {text:?}"
    );
    assert!(
        text.contains("message:too many connections"),
        "the ERROR frame must name the reason in its `message` header: {text:?}"
    );
    assert!(
        refusal.ends_with(b"\0"),
        "a STOMP frame is NUL-terminated; this one is not, so a client would still be reading: \
         {text:?}"
    );

    // Releasing one admitted connection must free exactly one slot. A permit dropped early
    // un-caps the server silently; a permit never released wedges it shut after MAX peers have
    // ever connected, which is worse than no cap at all.
    drop(held.pop().expect("one held connection"));
    tokio::time::sleep(Duration::from_millis(500)).await;

    let mut admitted = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect after freeing a slot");
    admitted
        .write_all(CONNECT_FRAME)
        .await
        .expect("write CONNECT");
    admitted.flush().await.expect("flush");
    let mut buf = [0u8; 512];
    let n = tokio::time::timeout(Duration::from_secs(30), admitted.read(&mut buf))
        .await
        .expect("the freed slot was not reused — the permit is not being released")
        .expect("read");
    let text = String::from_utf8_lossy(&buf[..n]).to_string();
    assert!(
        text.starts_with("CONNECTED\n"),
        "the freed slot answered {text:?} rather than admitting the session"
    );
}

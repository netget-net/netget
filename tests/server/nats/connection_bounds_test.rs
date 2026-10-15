//! The read deadlines and the connection cap on a real, running NATS server, from the wire.
//!
//! Before September 2026 this server accepted without limit and bounded no read in time: a peer
//! that took the `INFO` greeting and said nothing held a socket, **two** tasks, a 256-frame
//! queue and an `AppState` entry forever, before `CONNECT`, on a server that would happily
//! accept a hundred more.
//!
//! Three properties are asserted, and each one alone would be satisfied by a bug:
//!
//! 1. A greeted peer that **says nothing** is closed at `FIRST_FRAME_READ_TIMEOUT`, and told
//!    `-ERR 'Stale Connection'` rather than dropped silently.
//! 2. A peer that **has spoken** survives well past that same bound. The longer bound
//!    (`IDLE_BETWEEN_FRAMES_TIMEOUT`, 600s) is what lets a subscriber sit there: it must be
//!    above the interval at which NATS clients PING — 60s for `async-nats`, 2 minutes for
//!    `nats-server` itself — and collapsing the two numbers into one would drop every
//!    subscription.
//! 3. The connection past `MAX_CONNECTIONS` is refused in NATS's own vocabulary, with the exact
//!    `-ERR 'Maximum Connections Exceeded'` line `nats-server` sends, and releasing one admitted
//!    connection frees exactly one slot.
//!
//! **How this was proved to fail without the bound**: delete the `tokio::time::sleep(...)` arm
//! from the reader's `select!` in `src/server/nats/mod.rs` and the first test hangs for its
//! whole 70-second window, then fails with "still holding the socket".
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features nats,tcp --test server -- nats::connection_bounds --test-threads=100

use std::time::Duration;

use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use netget::state::ServerId;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

/// `src/server/nats/mod.rs::FIRST_FRAME_READ_TIMEOUT`. Deliberately duplicated: if the constant
/// moves, this test should be re-read rather than silently follow it.
const FIRST_FRAME_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// `src/server/nats/mod.rs::MAX_CONNECTIONS`.
const MAX_CONNECTIONS: usize = 256;

/// `src/server/nats/mod.rs::CONNECTION_CAP_REFUSAL`.
const MAX_CONNECTIONS_REFUSAL: &str = "-ERR 'Maximum Connections Exceeded'\r\n";

/// A `PING` is the smallest complete frame a NATS client can send, and the reader answers it
/// with `PONG` without any model call at all — protocol bookkeeping, not a decision.
const PING: &[u8] = b"PING\r\n";

async fn new_state() -> AppState {
    // A dead LLM endpoint. Nothing in this file provokes a model call: `INFO` is built by the
    // server and `PING`/`PONG` is answered by the reader.
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
    panic!("NATS server #{} never bound a port", id.as_u32());
}

async fn start_server(state: &AppState) -> u16 {
    let (tx, _rx) = mpsc::unbounded_channel();
    let server_id = ServerForm {
        protocol: "nats".to_string(),
        port: Some(0),
        // An empty instruction really is model-free; `None` would be replaced by a default
        // instruction and every frame would consult the LLM.
        instruction: Some(String::new()),
        ..Default::default()
    }
    .create(state, tx)
    .await
    .expect("create nats server");
    wait_for_port(state, server_id).await
}

async fn read_greeting(peer: &mut TcpStream) -> String {
    let mut buf = [0u8; 1024];
    let n = tokio::time::timeout(Duration::from_secs(30), peer.read(&mut buf))
        .await
        .expect("the INFO greeting should arrive promptly")
        .expect("read greeting");
    let text = String::from_utf8_lossy(&buf[..n]).to_string();
    assert!(
        text.starts_with("INFO "),
        "NATS is server-speaks-first; expected an INFO line, got {text:?}"
    );
    text
}

#[tokio::test]
async fn a_greeted_peer_that_says_nothing_is_closed_at_the_first_frame_bound() {
    let state = new_state().await;
    let port = start_server(&state).await;

    let mut peer = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    read_greeting(&mut peer).await;

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
        "a peer that took the INFO greeting and sent nothing was still holding the socket, both \
         connection tasks and its AppState entry after {}s — the first-frame deadline is not \
         being applied",
        elapsed.as_secs()
    );
    read.unwrap().expect("read to EOF");
    assert!(
        String::from_utf8_lossy(&sink).contains("-ERR"),
        "NATS has an error line and a client told why does not record a permanent fault; a \
         silent drop says nothing. Got {:?}",
        String::from_utf8_lossy(&sink)
    );
    assert!(
        elapsed >= FIRST_FRAME_READ_TIMEOUT / 2,
        "closed after only {}ms — that is not the declared 30s bound, it is something else \
         tearing the connection down",
        elapsed.as_millis()
    );
}

#[tokio::test]
async fn a_peer_that_has_spoken_gets_the_longer_idle_bound() {
    // This is the subscriber case in miniature. A NATS subscriber sends `SUB` once and then
    // only receives, so the idle bound has to sit above the interval at which clients PING —
    // and a single number applied to both states would close this connection at the same moment
    // the test above closes its own.
    let state = new_state().await;
    let port = start_server(&state).await;

    let mut peer = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    read_greeting(&mut peer).await;

    peer.write_all(PING).await.expect("write PING");
    peer.flush().await.expect("flush");
    let mut buf = [0u8; 64];
    let n = tokio::time::timeout(Duration::from_secs(30), peer.read(&mut buf))
        .await
        .expect("the reader should answer PING with PONG promptly")
        .expect("read");
    assert_eq!(
        &buf[..n],
        b"PONG\r\n",
        "expected PONG, got {:?}",
        String::from_utf8_lossy(&buf[..n])
    );

    // Now go quiet for longer than the *first* bound and assert the connection survives.
    tokio::time::sleep(FIRST_FRAME_READ_TIMEOUT + Duration::from_secs(8)).await;

    peer.write_all(PING).await.expect("write second PING");
    peer.flush().await.expect("flush");
    let n = tokio::time::timeout(Duration::from_secs(30), peer.read(&mut buf))
        .await
        .expect(
            "a peer that had spoken and then paused for 38s was closed — the idle bound has \
             collapsed onto the first-frame bound, which would drop every subscription",
        )
        .expect("read");
    assert_eq!(
        &buf[..n],
        b"PONG\r\n",
        "expected the connection to still be answering, got {:?}",
        String::from_utf8_lossy(&buf[..n])
    );
}

#[tokio::test]
async fn the_connection_past_the_cap_is_refused_in_nats_vocabulary_and_the_slot_comes_back() {
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
    assert_eq!(
        String::from_utf8_lossy(&refusal),
        MAX_CONNECTIONS_REFUSAL,
        "the peer over the cap must be refused with the exact -ERR line nats-server sends, and \
         must not be greeted with INFO first — it was never admitted"
    );

    // Releasing one admitted connection must free exactly one slot. A permit dropped early
    // un-caps the server silently; a permit never released wedges it shut after MAX peers have
    // ever connected, which is worse than no cap at all.
    drop(held.pop().expect("one held connection"));
    tokio::time::sleep(Duration::from_millis(500)).await;

    let mut admitted = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect after freeing a slot");
    let greeting = read_greeting(&mut admitted).await;
    assert!(
        !greeting.contains("-ERR"),
        "the freed slot answered with another refusal — the permit is not being released: {greeting:?}"
    );
}

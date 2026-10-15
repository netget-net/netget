//! The connection bounds on a real, running DC server, driven from the wire.
//!
//! Two claims, and they pull in opposite directions — which is the point. A peer that has
//! connected and said nothing must be let go of; a connection that is in the middle of being
//! answered must not be.
//!
//! **The first test fails without the bound.** Remove the deadline around the read in
//! `src/server/dc/mod.rs` and it hangs until its own assertion window expires, because
//! nothing else in the process will ever close that socket: the peer is holding a task, an
//! `AppState` row and a connection slot, pre-authentication, and it is the server that has to
//! give up first.
//!
//! **The second test is what stops a lazy fix.** A deadline that wrapped the answer as well as
//! the read would satisfy the first test and break the protocol, because an LLM round-trip takes
//! seconds and a `manual` rule parks the event for a *human* — 300 seconds by default
//! (`src/state/intercepts.rs`). Here every event is routed to `manual`, so the answer is
//! outstanding for the whole of the wait, and the connection has to survive it.
//!
//! DC's `$Lock` challenge is written in Rust with no model call, so the first test needs no handler
//! at all: the hub speaks, and then waits for the `$Key`/`$ValidateNick` that a real client sends
//! straight back. The idle bound is five minutes, which is five missed NMDC keepalives.
//!
//! No mock backend: the LLM endpoint is a dead port. These tests assert on *deadlines*, not on
//! answers. Loopback only.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features dc --test server -- dc::connection_bounds --test-threads=100

use std::time::Duration;

use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use netget::state::ServerId;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

/// `src/server/dc/mod.rs::FIRST_BYTE_READ_TIMEOUT`.
const FIRST_READ_TIMEOUT: Duration = Duration::from_secs(60);

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
    for _ in 0..300 {
        if let Some(s) = state.get_server(id).await {
            if let Some(addr) = s.local_addr {
                return addr.port();
            }
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("DC server #{} never bound a port", id.as_u32());
}

/// A server whose events are answered deterministically, with no model call at all: this test
/// is about the clock, and a reachable backend would only add noise to it.
async fn start_server(state: &AppState) -> u16 {
    let (tx, _rx) = mpsc::unbounded_channel();
    let server_id = ServerForm {
        protocol: "dc".to_string(),
        port: Some(0),
        // An empty instruction really is model-free; `None` is replaced by a default one and
        // every event would consult the LLM.
        instruction: Some(String::new()),
        ..Default::default()
    }
    .create(state, tx)
    .await
    .expect("create dc server");
    wait_for_port(state, server_id).await
}

/// The same server with every event parked for a human, which is the 300-second window the
/// second test exists for.
async fn start_parked_server(state: &AppState) -> (ServerId, u16) {
    let (tx, _rx) = mpsc::unbounded_channel();
    let server_id = ServerForm {
        protocol: "dc".to_string(),
        port: Some(0),
        instruction: Some(String::new()),
        event_handlers: Some(vec![serde_json::json!({
            "event_pattern": "*",
            "handler": {"type": "manual", "timeout_secs": 600}
        })]),
        ..Default::default()
    }
    .create(state, tx)
    .await
    .expect("create parked dc server");
    let port = wait_for_port(state, server_id).await;
    (server_id, port)
}

#[tokio::test]
async fn a_peer_that_connects_and_says_nothing_is_closed_at_the_first_bound() {
    let state = new_state().await;
    let port = start_server(&state).await;

    let mut peer = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");

    let started = std::time::Instant::now();
    let mut sink = Vec::new();
    // Generous against the declared bound so an ordinary scheduling delay under
    // --test-threads=100 is not mistaken for a missing deadline; what is being asserted is
    // that the read ends at all.
    let read = tokio::time::timeout(
        FIRST_READ_TIMEOUT + Duration::from_secs(45),
        peer.read_to_end(&mut sink),
    )
    .await;

    let elapsed = started.elapsed();
    assert!(
        read.is_ok(),
        "a peer that connected and sent nothing was still holding the socket, the connection \
         task and its AppState entry after {}s — the first-byte read deadline is not being \
         applied",
        elapsed.as_secs()
    );
    read.unwrap().expect("read to EOF");
    assert!(
        elapsed >= FIRST_READ_TIMEOUT / 2,
        "closed after only {}ms — that is not the declared {}s bound, it is something else \
         tearing the connection down, and this test would then pass without the bound existing",
        elapsed.as_millis(),
        FIRST_READ_TIMEOUT.as_secs()
    );
}

#[tokio::test]
async fn a_connection_whose_answer_is_parked_for_a_human_is_not_closed() {
    let state = new_state().await;
    let (server_id, port) = start_parked_server(&state).await;

    let mut peer = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");

    peer.write_all(b"$ValidateNick netgettest|")
        .await
        .expect("write $ValidateNick");
    peer.flush().await.expect("flush");
    // Past the first-byte bound, and past it by a margin — but well inside the 600-second
    // window the human has to answer in.
    tokio::time::sleep(FIRST_READ_TIMEOUT + Duration::from_secs(20)).await;

    // Asserted on the server's own view first, because that is the half that cannot be
    // satisfied by accident. A read loop that has given up removes the connection's row or
    // marks it `Closed`, and it does so whether or not the peer has noticed: the write half is
    // still held by whatever is composing the parked answer, so a socket that has not seen EOF
    // proves less than it looks like it does.
    let live = state
        .get_server(server_id)
        .await
        .expect("the server is still registered")
        .connections
        .values()
        .filter(|c| !matches!(c.status, netget::state::server::ConnectionStatus::Closed))
        .count();
    assert_eq!(
        live, 1,
        "the server no longer has a live connection for a peer whose answer is parked for a \
         human — the read deadline is being applied to the answer as well as to the read, which \
         gives up on the connection it is in the middle of answering"
    );

    let mut buf = [0u8; 256];
    match tokio::time::timeout(Duration::from_secs(3), peer.read(&mut buf)).await {
        // Nothing to read and the socket is still open: the parked answer is still outstanding
        // and the peer is still being served. This is the passing case.
        Err(_) => {}
        Ok(Ok(0)) => panic!(
            "the server hung up on a connection whose answer was parked for a human after \
             {}s — the read deadline is being applied to the answer as well as to the read, \
             which closes the connection it is in the middle of answering",
            (FIRST_READ_TIMEOUT + Duration::from_secs(20)).as_secs()
        ),
        // Bytes rather than silence would mean the routing broke and something answered; the
        // connection is alive either way, which is what this test is about.
        Ok(Ok(_)) => {}
        Ok(Err(e)) => panic!("read failed on a connection that should still be open: {e}"),
    }
}

/// `src/server/dc/mod.rs::MAX_CONNECTIONS`, which takes
/// `accept_bounded::DEFAULT_MAX_CONNECTIONS`.
const MAX_CONNECTIONS: usize = 256;

/// `src/server/dc/mod.rs::CONNECTION_CAP_REFUSAL`: NMDC's own way for a hub to turn a client away.
const CONNECTION_CAP_REFUSAL: &[u8] = b"$HubIsFull|";

#[tokio::test]
async fn the_connection_past_the_cap_is_refused_in_the_protocols_own_words() {
    let state = new_state().await;
    let (server_id, port) = start_parked_server(&state).await;

    // Every event is parked for a human, so an admitted connection stays admitted for the whole
    // test: the cap counts *live* connections, and a peer that was let go of would re-open a
    // slot and make the assertion below pass for the wrong reason.
    let mut admitted = Vec::with_capacity(MAX_CONNECTIONS);
    for i in 0..MAX_CONNECTIONS {
        admitted.push(
            TcpStream::connect(("127.0.0.1", port))
                .await
                .unwrap_or_else(|e| panic!("connection {i} of the cap could not be opened: {e}")),
        );
    }

    // A `connect()` the kernel completed is not yet an accept, and it is the accept that takes
    // the permit — so wait for the server's own view to show the cap filled before testing it.
    let mut live = 0;
    for _ in 0..400 {
        live = state
            .get_server(server_id)
            .await
            .expect("the server is still registered")
            .connections
            .values()
            .filter(|c| !matches!(c.status, netget::state::server::ConnectionStatus::Closed))
            .count();
        if live >= MAX_CONNECTIONS {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        live >= MAX_CONNECTIONS,
        "only {live} of {MAX_CONNECTIONS} connections were admitted, so what the next one \
         meets is not the cap"
    );

    let mut over = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("a refused peer still completes the TCP handshake; the refusal is above it");
    let mut sink = Vec::new();
    tokio::time::timeout(Duration::from_secs(15), over.read_to_end(&mut sink))
        .await
        .expect(
            "the connection past the cap was admitted and held rather than refused — a read \
             deadline alone still lets an attacker hold `deadline x rate` connections at once, \
             which is what the cap exists to stop",
        )
        .expect("read to EOF");
    assert_eq!(
        sink,
        CONNECTION_CAP_REFUSAL,
        "a refused peer must be told in this protocol's own words, or told nothing at all where \
         the wire cannot carry a reason — a silent drop it cannot distinguish from a crash makes \
         it retry immediately and forever. Got {:?}",
        String::from_utf8_lossy(&sink)
    );
}

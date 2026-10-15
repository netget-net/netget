//! The connection bounds on a real, running FTP server, driven from the wire.
//!
//! Four claims, and the first two pull in opposite directions — which is the point. A peer that
//! has connected and said nothing must be let go of; a connection that is in the middle of being
//! answered must not be. The third says the two bounds are different claims. The fourth says the
//! *default* first-byte bound is long enough for a person, and it is the slow one.
//!
//! **The first test fails without the bound.** Remove the deadline around the read in
//! `src/server/ftp/mod.rs` and it hangs until its own assertion window expires, because
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
//! FTP's idle bound is vsftpd's `idle_session_timeout` default of five minutes, which has to be on
//! a human timescale because `ftp(1)` prompts the person at it between commands.
//!
//! **The fourth test is the regression for the defect this file was extended for.** The
//! first-byte bound was 60 seconds, exempted on the grounds that "FTP is server-speaks-first".
//! The greeting is *ours*; sending it says nothing about whether the peer will answer it, and
//! NetGet's own FTP client is precisely a peer that will not — `src/client/ftp/mod.rs` reads
//! the `220` in its read loop and writes nothing until an action or `[ send message ]` says to,
//! and a client created from the dashboard is routed `*` → manual. At 60 seconds this server
//! dropped the operator's own client while they were still looking at it. Proving the fix means
//! waiting past 60 seconds, so that test is deliberately the slowest thing here.
//!
//! The values the first three tests use are *overrides*, not the defaults: a test that asserted
//! the 300-second default by waiting it out would be slower still. What they assert is that each
//! declared parameter is read and applied to the read it names; the numbers are argued where
//! they are declared.
//!
//! No mock backend: the LLM endpoint is a dead port. These tests assert on *deadlines*, not on
//! answers. Loopback only.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features ftp --test server -- ftp::connection_bounds --test-threads=100


use std::time::Duration;

use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use netget::state::ServerId;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

/// The first-byte bound the tests below drive, passed as `first_byte_timeout_secs`.
const SHORT_FIRST_BYTE: Duration = Duration::from_secs(6);

/// The idle bound one test drives, passed as `idle_timeout_secs`.
const SHORT_IDLE: Duration = Duration::from_secs(3);

/// How long the last test holds a silent peer against the *default* first-byte bound.
///
/// Past the 60 seconds this bound used to be, by a margin that survives a 100-thread run, and
/// far inside the 300 it now is. A cheaper test cannot exist: the claim is about a number
/// larger than 60, so the wait has to be larger than 60 too.
const PAST_THE_OLD_BOUND: Duration = Duration::from_secs(75);

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
    panic!("FTP server #{} never bound a port", id.as_u32());
}

/// A server whose events are answered deterministically, with no model call at all: this test
/// is about the clock, and a reachable backend would only add noise to it.
async fn start_server(state: &AppState, startup_params: Option<serde_json::Value>) -> u16 {
    let (tx, _rx) = mpsc::unbounded_channel();
    let server_id = ServerForm {
        protocol: "ftp".to_string(),
        port: Some(0),
        startup_params,
        // An empty instruction really is model-free; `None` is replaced by a default one and
        // every event would consult the LLM.
        instruction: Some(String::new()),
        event_handlers: Some(vec![serde_json::json!({
            "event_pattern": "ftp_command",
            "handler": {"type": "static", "actions": [{
                "type": "send_ftp_response",
                "code": 220,
                "message": "NetGet FTP ready"
            }]}
        })]),
        ..Default::default()
    }
    .create(state, tx)
    .await
    .expect("create ftp server");
    wait_for_port(state, server_id).await
}

/// The same server with every event parked for a human, which is the 300-second window the
/// second test exists for.
async fn start_parked_server(
    state: &AppState,
    startup_params: Option<serde_json::Value>,
) -> (ServerId, u16) {
    let (tx, _rx) = mpsc::unbounded_channel();
    let server_id = ServerForm {
        protocol: "ftp".to_string(),
        port: Some(0),
        startup_params,
        instruction: Some(String::new()),
        event_handlers: Some(vec![serde_json::json!({
            "event_pattern": "*",
            "handler": {"type": "manual", "timeout_secs": 600}
        })]),
        ..Default::default()
    }
    .create(state, tx)
    .await
    .expect("create parked ftp server");
    let port = wait_for_port(state, server_id).await;
    (server_id, port)
}

#[tokio::test]
async fn a_peer_that_connects_and_says_nothing_is_closed_at_the_first_bound() {
    let state = new_state().await;
    let port = start_server(
        &state,
        Some(serde_json::json!({
            "first_byte_timeout_secs": SHORT_FIRST_BYTE.as_secs(),
        })),
    )
    .await;

    let mut peer = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");

    let started = std::time::Instant::now();
    let mut sink = Vec::new();
    // Generous against the declared bound so an ordinary scheduling delay under
    // --test-threads=100 is not mistaken for a missing deadline; what is being asserted is
    // that the read ends at all, and that it ends on this bound rather than on the
    // 300-second default.
    let read = tokio::time::timeout(
        SHORT_FIRST_BYTE + Duration::from_secs(45),
        peer.read_to_end(&mut sink),
    )
    .await;

    let elapsed = started.elapsed();
    assert!(
        read.is_ok(),
        "a peer that connected and sent nothing was still holding the socket, the connection \
         task and its AppState entry after {}s — either the first-byte read deadline is not \
         applied at all, or `first_byte_timeout_secs` was declared and never read and the \
         300-second default is still in force",
        elapsed.as_secs()
    );
    read.unwrap().expect("read to EOF");
    assert!(
        elapsed >= SHORT_FIRST_BYTE / 2,
        "closed after only {}ms — that is not the declared {}s bound, it is something else \
         tearing the connection down, and this test would then pass without the bound existing",
        elapsed.as_millis(),
        SHORT_FIRST_BYTE.as_secs()
    );
}

#[tokio::test]
async fn a_connection_whose_answer_is_parked_for_a_human_is_not_closed() {
    let state = new_state().await;
    // A deliberately tiny first-byte bound, so the park outlives it several times over. If the
    // deadline covered the answer as well as the read, this connection would be gone in six
    // seconds.
    let (server_id, port) = start_parked_server(
        &state,
        Some(serde_json::json!({
            "first_byte_timeout_secs": SHORT_FIRST_BYTE.as_secs(),
        })),
    )
    .await;

    let mut peer = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");

    // Nothing is sent: FTP greets first, and with every event parked the `220` is waiting on a
    // human. The read loop has not begun, so the first-byte clock has not started either —
    // which is the whole claim.
    // Several times past the first-byte bound, but well inside the 600-second window the human
    // has to answer in.
    tokio::time::sleep(SHORT_FIRST_BYTE * 5).await;

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
            (SHORT_FIRST_BYTE * 5).as_secs()
        ),
        // Bytes rather than silence would mean the routing broke and something answered; the
        // connection is alive either way, which is what this test is about.
        Ok(Ok(_)) => {}
        Ok(Err(e)) => panic!("read failed on a connection that should still be open: {e}"),
    }
}

/// `src/server/ftp/mod.rs::MAX_CONNECTIONS`, which takes
/// `accept_bounded::DEFAULT_MAX_CONNECTIONS`.
const MAX_CONNECTIONS: usize = 256;

/// `src/server/ftp/mod.rs::CONNECTION_CAP_REFUSAL`: RFC 959's own reply for a server declining to open a session.
const CONNECTION_CAP_REFUSAL: &[u8] = b"421 Too many connections, closing control connection\r\n";

#[tokio::test]
async fn the_connection_past_the_cap_is_refused_in_the_protocols_own_words() {
    let state = new_state().await;
    let (server_id, port) = start_parked_server(&state, None).await;

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

#[tokio::test]
async fn once_a_command_has_been_answered_the_idle_bound_governs_not_the_first_byte_one() {
    let state = new_state().await;
    // The two bounds are set far apart and the wrong way round on purpose: if the read loop
    // kept using the first-byte bound after answering, this connection would live 60 seconds
    // and the assertion below would time out.
    let port = start_server(
        &state,
        Some(serde_json::json!({
            "first_byte_timeout_secs": 60,
            "idle_timeout_secs": SHORT_IDLE.as_secs(),
        })),
    )
    .await;

    let mut peer = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");

    // The greeting is answered by the same static rule, so something arrives before the
    // command is even sent; drain whatever is there and then speak, which is what puts the
    // connection into the post-answer state this test is about.
    peer.write_all(b"USER anonymous\r\n")
        .await
        .expect("write USER");

    let mut reply = [0u8; 256];
    let n = tokio::time::timeout(Duration::from_secs(20), peer.read(&mut reply))
        .await
        .expect("the static handler did not answer within 20s")
        .expect("read reply");
    assert!(
        reply[..n].starts_with(b"220"),
        "the static rule did not answer, so what follows is not the post-answer state this \
         test is about; got {:?}",
        String::from_utf8_lossy(&reply[..n])
    );

    let started = std::time::Instant::now();
    let mut sink = Vec::new();
    let read = tokio::time::timeout(Duration::from_secs(45), peer.read_to_end(&mut sink)).await;
    let elapsed = started.elapsed();

    assert!(
        read.is_ok(),
        "an answered connection that then went quiet was never closed — `idle_timeout_secs` \
         was declared and is not being read"
    );
    read.unwrap().expect("read to EOF");
    assert!(
        elapsed < Duration::from_secs(40),
        "closed after {}s, which is the 60-second first-byte bound rather than the {}s idle \
         one — the read loop never switched bounds",
        elapsed.as_secs(),
        SHORT_IDLE.as_secs()
    );
}

#[tokio::test]
async fn the_default_leaves_a_silent_peer_alone_for_longer_than_a_person_takes() {
    let state = new_state().await;
    // No startup parameters at all: this is the shipped default, which is the whole point.
    let port = start_server(&state, None).await;

    let mut peer = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");

    // Drain the greeting the static rule answers with, so what the read below is waiting on is
    // the server closing rather than the `220` arriving.
    let mut greeting = [0u8; 256];
    let _ = tokio::time::timeout(Duration::from_secs(20), peer.read(&mut greeting)).await;

    // A dashboard-created FTP client is exactly this peer: connected, reading our greeting,
    // and silent until a person uses [ send message ].
    let mut sink = Vec::new();
    match tokio::time::timeout(PAST_THE_OLD_BOUND, peer.read_to_end(&mut sink)).await {
        // Still open with nothing further to read: the passing case.
        Err(_) => {}
        Ok(Ok(0)) => panic!(
            "the server hung up on a silent peer within {}s. The default first-byte bound was \
             60 seconds and that is less than a person takes: NetGet's own FTP client reads the \
             220 in its read loop and writes nothing until someone types into [ send message ], \
             so the operator watched their own client disappear. See \
             FIRST_COMMAND_READ_TIMEOUT in src/server/ftp/mod.rs",
            PAST_THE_OLD_BOUND.as_secs()
        ),
        Ok(Ok(_)) => panic!(
            "the server wrote further bytes to a peer that had sent no command; the static rule \
             answers commands, and there was none"
        ),
        Ok(Err(e)) => panic!("read failed on a connection that should still be open: {e}"),
    }
}

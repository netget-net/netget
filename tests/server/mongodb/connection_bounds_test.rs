//! The header read deadline on a real, running MongoDB server, driven from the wire.
//!
//! `BODY_READ_TIMEOUT` used to be the only deadline in `run_session`, and it arms only *after*
//! a sixteen-byte header has arrived. So a peer that connected and sent nothing — or fewer
//! than sixteen bytes — parked the connection task in `read_exact` with no clock running at
//! all, holding the socket, the registered task and the `AppState` row until the peer itself
//! chose to close. The operator-visible form is worse: `[ disconnect this peer ]` half-closes
//! the write side and marks the row `Closed`, which a peer that is not reading never notices,
//! so the dashboard reported a hang-up that had not happened.
//!
//! `FIRST_HEADER_READ_TIMEOUT` (30s) and `IDLE_BETWEEN_MESSAGES_TIMEOUT` (600s) are the pair
//! the other seventeen TCP servers use, for the reason `whois` states: "has said nothing at
//! all" and "has gone quiet mid-session" are different claims and deserve different answers.
//!
//! **This test fails without the fix**: remove the `tokio::time::timeout` around the header
//! read and the first test hangs until its own 60s assertion window expires. The second test
//! is what stops a lazy fix — one short number applied to both reads would close an answered
//! connection at 30s, and it asserts that does not happen.
//!
//! Both deadlines are armed lazily, per read: the future is constructed at the top of the loop
//! after the previous message's work has finished, so no clock runs during an LLM round-trip
//! or a `manual` rule parked for a human. That is the property the TFTP eviction defect is
//! about, and the second test is also its evidence — a server answering a message spends time
//! outside the read.
//!
//! No mock backend: the LLM endpoint is a dead port. These tests assert on *deadlines*, not on
//! answers, and the first sends nothing at all; the second drives only the `hello` handshake,
//! which MongoDB answers in Rust with no model call (see `src/server/mongodb/mod.rs`).
//! Loopback only.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features mongodb-server --test server -- mongodb::connection_bounds --test-threads=100

use std::time::Duration;

use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use netget::state::ServerId;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

/// `src/server/mongodb/mod.rs::FIRST_HEADER_READ_TIMEOUT`.
const FIRST_HEADER_READ_TIMEOUT: Duration = Duration::from_secs(30);

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
    panic!("MongoDB server #{} never bound a port", id.as_u32());
}

async fn start_server(state: &AppState) -> (ServerId, u16) {
    let (tx, _rx) = mpsc::unbounded_channel();
    let server_id = ServerForm {
        protocol: "mongodb".to_string(),
        port: Some(0),
        // An empty instruction is genuinely model-free; `None` is replaced by a default one
        // and every command would consult the LLM.
        instruction: Some(String::new()),
        ..Default::default()
    }
    .create(state, tx)
    .await
    .expect("create mongodb server");
    let port = wait_for_port(state, server_id).await;
    (server_id, port)
}

/// An OP_MSG carrying one BSON document, framed with the 16-byte wire header.
fn op_msg(request_id: i32, body: &[u8]) -> Vec<u8> {
    // header(16) + flagBits(4) + sectionKind(1) + document
    let total = 16 + 4 + 1 + body.len();
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&(total as i32).to_le_bytes());
    out.extend_from_slice(&request_id.to_le_bytes());
    out.extend_from_slice(&0i32.to_le_bytes()); // responseTo
    out.extend_from_slice(&2013i32.to_le_bytes()); // OP_MSG
    out.extend_from_slice(&0u32.to_le_bytes()); // flagBits
    out.push(0); // section kind 0: body
    out.extend_from_slice(body);
    out
}

/// `{hello: 1, $db: "admin"}`, hand-encoded so this test needs only the server feature.
fn hello_document() -> Vec<u8> {
    let mut doc = Vec::new();
    // int32 "hello" = 1
    doc.push(0x10);
    doc.extend_from_slice(b"hello\0");
    doc.extend_from_slice(&1i32.to_le_bytes());
    // string "$db" = "admin"
    doc.push(0x02);
    doc.extend_from_slice(b"$db\0");
    doc.extend_from_slice(&6i32.to_le_bytes());
    doc.extend_from_slice(b"admin\0");
    doc.push(0x00); // document terminator

    let mut out = Vec::with_capacity(doc.len() + 4);
    out.extend_from_slice(&((doc.len() + 4) as i32).to_le_bytes());
    out.extend_from_slice(&doc);
    out
}

#[tokio::test]
async fn a_peer_that_connects_and_says_nothing_is_closed_at_the_first_header_bound() {
    let state = new_state().await;
    let (server_id, port) = start_server(&state).await;

    let mut peer = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");

    let started = std::time::Instant::now();
    let mut sink = Vec::new();
    // Generous against the 30s bound so an ordinary scheduling delay under --test-threads=100
    // is not mistaken for a missing timeout; the assertion that matters is that it ends at all.
    let read = tokio::time::timeout(
        FIRST_HEADER_READ_TIMEOUT + Duration::from_secs(30),
        peer.read_to_end(&mut sink),
    )
    .await;
    let elapsed = started.elapsed();

    assert!(
        read.is_ok(),
        "a peer that connected and sent nothing was still holding the socket, the connection \
         task and its AppState entry after {}s — the header read has no deadline. \
         BODY_READ_TIMEOUT does not cover this: it arms only once sixteen bytes have arrived.",
        elapsed.as_secs()
    );
    read.unwrap().expect("read to EOF");
    assert!(
        sink.is_empty(),
        "MongoDB is client-speaks-first and has nothing to say to a peer that asked nothing; \
         it should close, not write. Got {:?}",
        sink
    );
    assert!(
        elapsed >= FIRST_HEADER_READ_TIMEOUT / 2,
        "closed after only {}ms — that is not the declared 30s bound, it is something else \
         tearing the connection down",
        elapsed.as_millis()
    );

    let _ = state.remove_server(server_id).await;
}

#[tokio::test]
async fn a_partial_header_is_bounded_too() {
    // Eight bytes is a plausible-looking start and not a header. The old code sat in
    // `read_exact` for the other eight forever; `BODY_READ_TIMEOUT` never came into it,
    // because the body read is downstream of a *complete* header.
    let state = new_state().await;
    let (server_id, port) = start_server(&state).await;

    let mut peer = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    peer.write_all(&[0x30, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00])
        .await
        .expect("write half a header");

    let started = std::time::Instant::now();
    let mut sink = Vec::new();
    let read = tokio::time::timeout(
        FIRST_HEADER_READ_TIMEOUT + Duration::from_secs(30),
        peer.read_to_end(&mut sink),
    )
    .await;

    assert!(
        read.is_ok(),
        "a peer that sent half a header held the connection for {}s — the header read is \
         unbounded",
        started.elapsed().as_secs()
    );
    read.unwrap().expect("read to EOF");

    let _ = state.remove_server(server_id).await;
}

#[tokio::test]
async fn an_answered_peer_gets_the_longer_idle_bound() {
    // The point of the pair: "has said nothing at all" and "has gone quiet mid-session" are
    // different claims and get different answers. Collapsing the two into one short number
    // would close a pooled driver connection between operations — MongoDB drivers keep those
    // open for minutes by design — and this is the assertion that catches it.
    let state = new_state().await;
    let (server_id, port) = start_server(&state).await;

    let mut peer = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    peer.write_all(&op_msg(7, &hello_document()))
        .await
        .expect("write hello");

    // The handshake is answered by Rust, with no model call. Reading its header is enough to
    // know the session has answered one message and moved on to the idle bound.
    let mut reply_header = [0u8; 16];
    tokio::time::timeout(Duration::from_secs(20), peer.read_exact(&mut reply_header))
        .await
        .expect("a hello reply within 20s")
        .expect("read the reply header");
    let reply_len = i32::from_le_bytes([
        reply_header[0],
        reply_header[1],
        reply_header[2],
        reply_header[3],
    ]);
    assert!(
        reply_len >= 16,
        "the hello reply announced a length of {reply_len}, which is not a MongoDB message"
    );
    let mut reply_body = vec![0u8; (reply_len - 16) as usize];
    peer.read_exact(&mut reply_body)
        .await
        .expect("read the reply body");

    // Now go quiet. If both reads shared the 30s first-header bound this connection would be
    // closed well inside the window below; on the real pair it must survive it.
    let quiet = FIRST_HEADER_READ_TIMEOUT + Duration::from_secs(10);
    let mut sink = Vec::new();
    let closed_early = tokio::time::timeout(quiet, peer.read_to_end(&mut sink)).await;

    assert!(
        closed_early.is_err(),
        "an answered connection was closed after {:?} of silence. A driver's pooled connection \
         is legitimately idle for minutes between operations: the first-message bound must not \
         be applied to a session that has already been answered. (read_to_end returned {:?})",
        quiet,
        closed_early.map(|r| r.map(|n| n))
    );

    let _ = state.remove_server(server_id).await;
}

// ---------------------------------------------------------------------------------------
// The connection cap
// ---------------------------------------------------------------------------------------
//
// The deadlines above bound how long *one* peer holds a connection. They say nothing about
// how many such peers there may be, and until September 2026 this accept loop admitted every
// connection offered to it — so `IDLE_BETWEEN_MESSAGES_TIMEOUT`'s ten minutes multiplied by an
// unbounded arrival rate was not a bound at all.
//
// Three claims below, and the second is the unusual one:
//
//  1. `MAX_CONNECTIONS` peers are admitted.
//  2. The next one is closed **with nothing written**, and that is the right answer rather than
//     a shortcut. Every MongoDB reply is addressed to a request through the header's
//     `responseTo`, which the driver matches against its own outstanding `requestID`; a peer
//     over the cap has sent nothing, so the only value available is zero. A driver receiving a
//     reply it did not ask for has no request to fail and simply discards it, so an invented
//     OP_MSG would leave the peer waiting out its own `connectTimeoutMS` — strictly worse than
//     the immediate EOF it gets here, which every driver already treats as a failed connection.
//  3. Closing an admitted connection **frees exactly one slot**. A permit dropped before the
//     connection ends un-caps the server silently; one never released wedges it shut after
//     `MAX_CONNECTIONS` peers have ever connected.
//
// Because the refusal is silence, "refused" and "admitted" are told apart by *time* rather
// than by content: a refused peer reads EOF at once, while an admitted one that says nothing
// is held for `FIRST_HEADER_READ_TIMEOUT` — thirty seconds — before this server closes it. The
// assertion windows below sit well inside that gap on both sides.
//
// **How this was proved to fail without the cap**: replace the `accept_bounded` call in
// `src/server/mongodb/mod.rs` with a bare `listener.accept().await` (and drop the permit from
// the connection task). The over-cap peer is then admitted and held for the full header
// deadline, and the test fails on "was neither answered nor closed".

/// `src/server/mongodb/mod.rs::MAX_CONNECTIONS`. Deliberately duplicated rather than imported:
/// if the constant moves, this test should be re-read rather than silently follow it.
const MAX_CONNECTIONS: usize = 256;

/// Wait until the accept loop has taken `n` connections out of the listen backlog. A
/// `connect()` succeeds as soon as the kernel queues it, so without this the over-cap peer
/// races the accept loop and the test measures scheduling rather than the cap.
///
/// This server registers the connection in the accept loop itself, before the session task
/// reads a header, so the count reflects admitted peers rather than peers that have spoken.
async fn wait_for_admitted(state: &AppState, id: ServerId, n: usize) {
    for _ in 0..600 {
        if let Some(s) = state.get_server(id).await {
            if s.connections.len() >= n {
                return;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let seen = state
        .get_server(id)
        .await
        .map(|s| s.connections.len())
        .unwrap_or(0);
    panic!("the server admitted only {seen} of {n} connections");
}

#[tokio::test]
async fn the_connection_past_the_cap_is_closed_without_a_fabricated_reply_and_the_slot_comes_back()
{
    let state = new_state().await;
    let (server_id, port) = start_server(&state).await;

    let mut held = Vec::with_capacity(MAX_CONNECTIONS);
    for i in 0..MAX_CONNECTIONS {
        held.push(
            TcpStream::connect(("127.0.0.1", port))
                .await
                .unwrap_or_else(|e| panic!("connection {i} of the cap failed: {e}")),
        );
    }
    wait_for_admitted(&state, server_id, MAX_CONNECTIONS).await;

    let mut over = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("the listener must still accept — a cap is not a closed socket");
    let mut refusal = Vec::new();
    let started = std::time::Instant::now();
    tokio::time::timeout(Duration::from_secs(10), over.read_to_end(&mut refusal))
        .await
        .expect(
            "the connection past the cap was neither answered nor closed — it was admitted, so \
             there is no cap",
        )
        .expect("read to EOF");
    assert!(
        refusal.is_empty(),
        "every MongoDB reply is addressed to a request through responseTo, and a refused peer \
         has sent none — so the refusal must be a plain close, not an invented reply. \
         Got {refusal:02x?}"
    );
    // The gap that makes silence readable: a refused peer sees EOF now, an admitted one would
    // not for thirty seconds. Without this the assertion above would also pass for a peer that
    // was admitted and then timed out, which is the opposite outcome.
    assert!(
        started.elapsed() < FIRST_HEADER_READ_TIMEOUT / 3,
        "the refusal took {:?}, which is close enough to FIRST_HEADER_READ_TIMEOUT that this \
         peer may simply have been admitted and then closed for saying nothing",
        started.elapsed()
    );

    drop(held.pop().expect("one held connection"));

    let mut admitted = false;
    for _ in 0..100 {
        let mut candidate = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("connect after freeing a slot");
        let mut buf = [0u8; 64];
        match tokio::time::timeout(Duration::from_millis(300), candidate.read(&mut buf)).await {
            // Neither bytes nor EOF: MongoDB is client-speaks-first, so a connection still open
            // and still silent after the window is one that was admitted and is waiting for a
            // header. A refused peer, whose refusal is a bare close, returns `Ok(0)` at once.
            Err(_) => {
                admitted = true;
                break;
            }
            Ok(_) => {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
    assert!(
        admitted,
        "the cap never freed its slot after an admitted connection ended — the permit is being \
         held past the life of the connection, which wedges the server shut"
    );
}

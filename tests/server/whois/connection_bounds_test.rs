//! The two read deadlines on a real, running WHOIS server, driven from the wire.
//!
//! WHOIS is client-speaks-first: the server says nothing until a line arrives, so a peer that
//! connects and stays quiet holds a socket, a task and an `AppState` row while having begun no
//! session at all. That is what `FIRST_QUERY_READ_TIMEOUT` exists for.
//!
//! **The default is 300 seconds and these tests do not wait it out.** The peer this server most
//! often has is NetGet's own WHOIS client, which opens the socket and sends *nothing* until the
//! model or a person supplies a query — the dashboard's `[ + whois client ]` answers the connect
//! event with nothing and then waits for someone to type into `[ send message ]`. The bound was
//! 30 seconds, which is less than a person takes, so the server dropped the operator's own
//! client while they were still looking at it. Both bounds are therefore declared startup
//! parameters (`first_byte_timeout_secs`, `idle_timeout_secs`) and these tests set them small;
//! what is asserted is that each deadline is applied to the read it names and to nothing else.
//!
//! Three properties, and each alone would be satisfied by a bug:
//!
//! 1. A peer that connects and **says nothing** is closed at `first_byte_timeout_secs`.
//! 2. The two bounds are **separate numbers**: a peer that has been answered is closed at
//!    `idle_timeout_secs` instead, so setting one does not silently set the other.
//! 3. A query **parked for a human** is never closed by either deadline — the clock wraps the
//!    `read()` and not the answer, which is the whole point of a `manual` rule having a
//!    300-second window of its own.
//!
//! **How this was proved to fail without the bound**: replace the `next_query(read_timeout)`
//! deadline in `src/server/whois/mod.rs` with an unbounded read and the first test hangs for
//! its whole assertion window, then fails with "still holding the socket".
//!
//! No mock backend: the LLM endpoint is a dead port, because these tests assert on deadlines
//! rather than on answers. Loopback only.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features whois --test server -- whois::connection_bounds --test-threads=100


use std::time::Duration;

use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use netget::state::ServerId;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

/// The first-query bound these tests drive, passed as `first_byte_timeout_secs`.
///
/// **Not the default**, which is 300 seconds — see the module note.
const FIRST_QUERY_TIMEOUT: Duration = Duration::from_secs(6);

/// The after-a-reply bound these tests drive, passed as `idle_timeout_secs`.
///
/// Deliberately a *different* number from [`FIRST_QUERY_TIMEOUT`], and deliberately longer, so
/// the second test can tell the two apart: a server that ignored one parameter and applied the
/// other to both reads would close at the wrong moment and the assertion would catch it.
const IDLE_AFTER_REPLY_TIMEOUT: Duration = Duration::from_secs(20);

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
    panic!("WHOIS server #{} never bound a port", id.as_u32());
}

/// A server that answers every query from a static handler, so no model is consulted at all.
async fn start_server(state: &AppState) -> u16 {
    let (tx, _rx) = mpsc::unbounded_channel();
    let server_id = ServerForm {
        protocol: "whois".to_string(),
        port: Some(0),
        // An empty instruction really is model-free; `None` is replaced by a default one and
        // every event would consult the LLM.
        instruction: Some(String::new()),
        startup_params: Some(serde_json::json!({
            "first_byte_timeout_secs": FIRST_QUERY_TIMEOUT.as_secs(),
            "idle_timeout_secs": IDLE_AFTER_REPLY_TIMEOUT.as_secs(),
        })),
        event_handlers: Some(vec![serde_json::json!({
            "event_pattern": "whois_query",
            "handler": {
                "type": "static",
                // No `close_connection`: this test is about what happens to a connection the
                // handler left open, which is the case `idle_timeout_secs` exists for.
                "actions": [{"type": "send_whois_response", "response": "% netget: ok"}]
            }
        })]),
        ..Default::default()
    }
    .create(state, tx)
    .await
    .expect("create whois server");
    wait_for_port(state, server_id).await
}

/// The same server with every event parked for a **human** — the `*` → manual rule the
/// dashboard gives every instance it creates.
async fn start_server_with_manual_rule(state: &AppState) -> u16 {
    let (tx, _rx) = mpsc::unbounded_channel();
    let server_id = ServerForm {
        protocol: "whois".to_string(),
        port: Some(0),
        instruction: Some(String::new()),
        startup_params: Some(serde_json::json!({
            "first_byte_timeout_secs": FIRST_QUERY_TIMEOUT.as_secs(),
            "idle_timeout_secs": IDLE_AFTER_REPLY_TIMEOUT.as_secs(),
        })),
        event_handlers: Some(vec![serde_json::json!({
            "event_pattern": "*",
            "handler": { "type": "manual", "timeout_secs": 300 }
        })]),
        ..Default::default()
    }
    .create(state, tx)
    .await
    .expect("create whois server with a manual rule");
    wait_for_port(state, server_id).await
}

#[tokio::test]
async fn a_peer_that_connects_and_says_nothing_is_closed_at_the_first_query_bound() {
    let state = new_state().await;
    let port = start_server(&state).await;

    let mut peer = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");

    let started = std::time::Instant::now();
    let mut sink = Vec::new();
    // Generous against the configured bound so an ordinary scheduling delay under
    // --test-threads=100 is not read as a missing timeout. The assertion that matters is that
    // the read ends at all.
    let read = tokio::time::timeout(
        FIRST_QUERY_TIMEOUT + Duration::from_secs(40),
        peer.read_to_end(&mut sink),
    )
    .await;

    let elapsed = started.elapsed();
    assert!(
        read.is_ok(),
        "a peer that connected and sent nothing was still holding the socket, the connection \
         task and its AppState entry after {}s — the first-query deadline is not being applied, \
         or `first_byte_timeout_secs` is declared and read by nothing",
        elapsed.as_secs()
    );
    read.unwrap().expect("read to EOF");
    assert!(
        sink.is_empty(),
        "a peer dropped for silence has asked nothing, so there is nothing to answer it with; \
         it should get a clean close, not text. Got {:?}",
        String::from_utf8_lossy(&sink)
    );
    // The lower edge is what proves the *parameter* took effect rather than some other teardown:
    // without it, a connection closed instantly would pass the assertion above.
    assert!(
        elapsed >= FIRST_QUERY_TIMEOUT / 2,
        "closed after only {}ms — that is not the configured {}s bound, it is something else \
         tearing the connection down",
        elapsed.as_millis(),
        FIRST_QUERY_TIMEOUT.as_secs()
    );
}

#[tokio::test]
async fn an_answered_peer_is_held_for_the_idle_bound_instead_of_the_first_one() {
    // The pair is the point. "Has asked nothing at all" and "has been answered and gone quiet"
    // are different claims with different numbers, and a server that collapsed them onto one
    // would close this connection at the first-query bound. RFC 3912 says the connection is
    // over once the output is finished, so this bound is what unblocks a real `whois(1)` when a
    // handler answered without `close_connection` — the static rule above deliberately does.
    let state = new_state().await;
    let port = start_server(&state).await;

    let mut peer = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    peer.write_all(b"example.com\r\n").await.expect("write");
    peer.flush().await.expect("flush");

    let mut reply = [0u8; 256];
    let n = tokio::time::timeout(Duration::from_secs(30), peer.read(&mut reply))
        .await
        .expect("the server should answer the query promptly")
        .expect("read");
    assert!(n > 0, "expected an answer to the query, got EOF");

    let started = std::time::Instant::now();
    let mut sink = Vec::new();
    tokio::time::timeout(
        IDLE_AFTER_REPLY_TIMEOUT + Duration::from_secs(40),
        peer.read_to_end(&mut sink),
    )
    .await
    .expect("the answered connection was never closed — the idle bound is not being applied")
    .expect("read to EOF");
    let elapsed = started.elapsed();

    assert!(
        elapsed >= FIRST_QUERY_TIMEOUT + Duration::from_secs(2),
        "an answered connection was closed after {}ms, which is the {}s first-query bound \
         rather than the {}s idle bound: the two numbers have collapsed onto one, so \
         `idle_timeout_secs` is not reaching the read it names",
        elapsed.as_millis(),
        FIRST_QUERY_TIMEOUT.as_secs(),
        IDLE_AFTER_REPLY_TIMEOUT.as_secs()
    );
}

#[tokio::test]
async fn a_query_parked_for_a_human_is_never_closed_by_the_deadline() {
    // The bound a careless implementation gets wrong. A `manual` rule parks the query for a
    // **person** at the dashboard with a 300-second default, and the peer is silent for the
    // whole of that wait because it is waiting for us. If the deadline covered anything but the
    // `read()` itself, this connection would be torn down while the operator was still reading
    // the question — and on this protocol the operator *is* the expected peer.
    let state = new_state().await;
    let port = start_server_with_manual_rule(&state).await;

    let mut peer = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    peer.write_all(b"example.com\r\n").await.expect("write");
    peer.flush().await.expect("flush");

    // Well past both configured bounds, and well short of the manual rule's own 300s.
    tokio::time::sleep(IDLE_AFTER_REPLY_TIMEOUT + Duration::from_secs(10)).await;

    let mut buf = [0u8; 256];
    match tokio::time::timeout(Duration::from_secs(3), peer.read(&mut buf)).await {
        Err(_) => {} // still open, still parked — the expected outcome
        Ok(Ok(0)) => panic!(
            "the connection was closed while its query was parked for a human: the read \
             deadline is covering the manual round-trip rather than the read, so no operator \
             could ever answer an intercept on this protocol"
        ),
        Ok(Ok(n)) => panic!(
            "the server answered a query nobody had decided: {:?}",
            String::from_utf8_lossy(&buf[..n])
        ),
        Ok(Err(e)) => panic!("the connection was reset while parked: {e}"),
    }
}

// ---------------------------------------------------------------------------------------
// The connection cap
// ---------------------------------------------------------------------------------------
//
// The deadlines above bound how long *one* peer holds a socket. They are the reason this
// server needs a cap and not a substitute for one: `FIRST_QUERY_READ_TIMEOUT` is 300 seconds
// precisely so NetGet's own client is not stranded waiting for a person to type, which is 300
// seconds of held socket per stranger, and a per-connection bound multiplied by an unbounded
// number of connections is not a bound at all.
//
// **How this was proved to fail without the cap**: replace the `accept_bounded` call in
// `src/server/whois/mod.rs` with a bare `listener.accept().await` (and drop the permit from the
// connection task). The over-cap peer is then admitted and silent, so the `read_to_end` times
// out and the test fails on "was neither answered nor closed".

/// `src/server/whois/mod.rs::MAX_CONNECTIONS`. Deliberately duplicated rather than imported: if
/// the constant moves, this test should be re-read rather than silently follow it.
const MAX_CONNECTIONS: usize = 256;

/// `src/server/whois/mod.rs::CONNECTION_CAP_REFUSAL`, byte for byte.
const CONNECTION_CAP_REFUSAL: &[u8] = b"% netget: too many connections, retry later\r\n";

/// A model-free server with the *default* bounds, so the peers filling the cap are not closed
/// by a deadline part-way through the test.
async fn start_server_with_default_bounds(state: &AppState) -> (ServerId, u16) {
    let (tx, _rx) = mpsc::unbounded_channel();
    let server_id = ServerForm {
        protocol: "whois".to_string(),
        port: Some(0),
        instruction: Some(String::new()),
        ..Default::default()
    }
    .create(state, tx)
    .await
    .expect("create whois server");
    let port = wait_for_port(state, server_id).await;
    (server_id, port)
}

/// Wait until the accept loop has taken `n` connections out of the listen backlog. A
/// `connect()` succeeds as soon as the kernel queues it, so without this the over-cap peer
/// races the accept loop and the test measures scheduling rather than the cap.
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
async fn the_connection_past_the_cap_is_refused_with_an_rpsl_comment_and_the_slot_comes_back() {
    let state = new_state().await;
    let (server_id, port) = start_server_with_default_bounds(&state).await;

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
    tokio::time::timeout(Duration::from_secs(20), over.read_to_end(&mut refusal))
        .await
        .expect("the connection past the cap was neither answered nor closed")
        .expect("read the refusal");
    assert_eq!(
        refusal,
        CONNECTION_CAP_REFUSAL,
        "WHOIS has no status codes, so the refusal is an RPSL comment line — the `% netget:` \
         prefix this server already uses for everything that is not data — followed by EOF. A \
         silent drop leaves a client unable to tell a full server from a crashed one. Got {:?}",
        String::from_utf8_lossy(&refusal)
    );

    drop(held.pop().expect("one held connection"));

    let mut admitted = false;
    for _ in 0..100 {
        let mut candidate = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("connect after freeing a slot");
        let mut buf = [0u8; 64];
        match tokio::time::timeout(Duration::from_millis(300), candidate.read(&mut buf)).await {
            // WHOIS is client-speaks-first: silence means this peer was admitted and is
            // waiting for its query line.
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

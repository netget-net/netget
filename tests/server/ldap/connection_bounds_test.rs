//! The read deadlines and the connection cap on a real, running LDAP server, from the wire.
//!
//! Before September 2026 this server accepted without limit and bounded no read in time: a peer
//! that connected and said nothing held a socket, a connection task and an `AppState` entry
//! forever, pre-authentication — which for LDAP means before any bind at all — on a server that
//! would happily accept a hundred more.
//!
//! Three properties are asserted, and each one alone would be satisfied by a bug:
//!
//! 1. A peer that connects and **says nothing** is closed at the first-message bound (set here
//!    through the `first_byte_timeout_secs` startup parameter, so the test does not have to
//!    wait out the 300-second default).
//! 2. A peer that **binds** is answered and survives well past that same bound: the deadline is
//!    on the silence, not on the connection. A pooling LDAP client holds a bound connection open
//!    between operations, so a single number applied to both would break it.
//! 3. The connection past `MAX_CONNECTIONS` is refused **in LDAP's own vocabulary** — an
//!    unsolicited Notice of Disconnection (RFC 4511 §4.4.1) carrying `unavailable (52)` — and
//!    releasing one admitted connection frees exactly one slot.
//!
//! **How this was proved to fail without the bound**: replace the `tokio::time::timeout(...)`
//! around `self.stream.read(...)` in `src/server/ldap/mod.rs` with a bare read and the first
//! test hangs for its whole assertion window, then fails with "still holding the socket".
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features ldap,tcp --test server -- ldap::connection_bounds --test-threads=100


use std::time::Duration;

use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use netget::state::ServerId;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

/// The first-message bound these tests drive, passed to the server as `first_byte_timeout_secs`.
///
/// **Not the default.** `src/server/ldap/mod.rs::FIRST_MESSAGE_READ_TIMEOUT` is 300 seconds —
/// the window a `manual` rule gives a human — because the peer is most often NetGet's own LDAP
/// client, which opens the socket and then sends nothing at all until someone uses
/// `[ send message ]`. A test cannot wait five minutes, and one that asserted the default by
/// waiting it out would be the slowest thing in the suite, so the bound is a declared startup
/// parameter and these tests set it small. What is asserted here is that the deadline is applied
/// to the `read()` and to nothing else; the *value* is the operator's to choose and is argued
/// where it is declared.
const FIRST_MESSAGE_READ_TIMEOUT: Duration = Duration::from_secs(6);

/// `src/server/ldap/mod.rs::MAX_CONNECTIONS`.
const MAX_CONNECTIONS: usize = 256;

/// A simple anonymous BindRequest, messageID 1, LDAP version 3, empty DN and empty password.
///
/// `30 0C` SEQUENCE(12) · `02 01 01` messageID 1 · `60 07` \[APPLICATION 0\] BindRequest(7)
/// · `02 01 03` version 3 · `04 00` name "" · `80 00` simple authentication, empty.
const ANONYMOUS_BIND: &[u8] = &[
    0x30, 0x0C, 0x02, 0x01, 0x01, 0x60, 0x07, 0x02, 0x01, 0x03, 0x04, 0x00, 0x80, 0x00,
];

/// `src/server/ldap/mod.rs::CONNECTION_CAP_REFUSAL` — the Notice of Disconnection.
const NOTICE_OF_DISCONNECTION: &[u8] = &[
    0x30, 0x18, 0x02, 0x01, 0x00, 0x78, 0x13, 0x0A, 0x01, 0x34, 0x04, 0x00, 0x04, 0x00, 0x8A, 0x0A,
    0x2B, 0x06, 0x01, 0x04, 0x01, 0x8B, 0x3A, 0x81, 0x9C, 0x44,
];

async fn new_state() -> AppState {
    // A dead LLM endpoint. These tests assert on deadlines, not on answers: LDAP's fail-closed
    // path answers a bind it cannot decide with `unavailable (52)`, which proves the connection
    // is alive exactly as well as a success would.
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
    panic!("LDAP server #{} never bound a port", id.as_u32());
}

async fn start_server(state: &AppState) -> u16 {
    let (tx, _rx) = mpsc::unbounded_channel();
    let server_id = ServerForm {
        protocol: "ldap".to_string(),
        port: Some(0),
        // An empty instruction really is model-free; `None` would be replaced by a default
        // instruction and every message would consult the LLM.
        instruction: Some(String::new()),
        startup_params: Some(serde_json::json!({
            "first_byte_timeout_secs": FIRST_MESSAGE_READ_TIMEOUT.as_secs(),
        })),
        ..Default::default()
    }
    .create(state, tx)
    .await
    .expect("create ldap server");
    wait_for_port(state, server_id).await
}

/// The same server, but every event parks for a **human** at the dashboard instead of being
/// answered — the `*` → manual rule the TUI gives every instance it creates.
async fn start_server_with_manual_rule(state: &AppState) -> u16 {
    let (tx, _rx) = mpsc::unbounded_channel();
    let server_id = ServerForm {
        protocol: "ldap".to_string(),
        port: Some(0),
        instruction: Some(String::new()),
        startup_params: Some(serde_json::json!({
            "first_byte_timeout_secs": FIRST_MESSAGE_READ_TIMEOUT.as_secs(),
        })),
        event_handlers: Some(vec![serde_json::json!({
            "event_pattern": "*",
            "handler": { "type": "manual", "timeout_secs": 300 }
        })]),
        ..Default::default()
    }
    .create(state, tx)
    .await
    .expect("create ldap server with a manual rule");
    wait_for_port(state, server_id).await
}

#[tokio::test]
async fn a_peer_that_connects_and_says_nothing_is_closed_at_the_first_message_bound() {
    let state = new_state().await;
    let port = start_server(&state).await;

    let mut peer = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");

    let started = std::time::Instant::now();
    let mut sink = Vec::new();
    // Generous against the configured bound so an ordinary scheduling delay under
    // --test-threads=100 is not mistaken for a missing timeout; the assertion that matters is
    // that it ends at all.
    let read = tokio::time::timeout(
        FIRST_MESSAGE_READ_TIMEOUT + Duration::from_secs(40),
        peer.read_to_end(&mut sink),
    )
    .await;

    let elapsed = started.elapsed();
    assert!(
        read.is_ok(),
        "a peer that connected and sent nothing was still holding the socket, the connection \
         task and its AppState entry after {}s — the first-message deadline is not being applied",
        elapsed.as_secs()
    );
    read.unwrap().expect("read to EOF");
    assert!(
        sink.is_empty(),
        "LDAP is client-speaks-first and a peer dropped for silence is not being refused, so \
         there is nothing to say to it; it should close, not write. Got {:02x?}",
        sink
    );
    assert!(
        elapsed >= FIRST_MESSAGE_READ_TIMEOUT / 2,
        "closed after only {}ms — that is not the configured {}s bound, it is something else \
         tearing the connection down",
        elapsed.as_millis(),
        FIRST_MESSAGE_READ_TIMEOUT.as_secs()
    );
}

#[tokio::test]
async fn a_bound_peer_gets_the_longer_idle_bound() {
    // The point of the pair: "has said nothing at all" and "has gone quiet mid-session" are
    // different claims and get different answers. A single number applied to both would close
    // this connection at the same moment the test above closes its own, and every pooling LDAP
    // client would see its idle connections vanish.
    let state = new_state().await;
    let port = start_server(&state).await;

    let mut peer = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");

    peer.write_all(ANONYMOUS_BIND).await.expect("write bind");
    peer.flush().await.expect("flush");

    let mut reply = [0u8; 256];
    let n = tokio::time::timeout(Duration::from_secs(30), peer.read(&mut reply))
        .await
        .expect("the server should answer the bind promptly")
        .expect("read");
    assert!(n >= 7, "expected a BindResponse, got {} bytes", n);
    assert_eq!(reply[0], 0x30, "expected an LDAPMessage SEQUENCE");
    assert_eq!(
        reply[5], 0x61,
        "expected a BindResponse ([APPLICATION 1]) in reply to a BindRequest, got tag 0x{:02x}",
        reply[5]
    );

    // Now go quiet for longer than the *first* bound and assert the connection survives: the
    // idle bound for an established session is 900s and is not overridden here.
    tokio::time::sleep(FIRST_MESSAGE_READ_TIMEOUT + Duration::from_secs(8)).await;

    peer.write_all(ANONYMOUS_BIND)
        .await
        .expect("write second bind");
    peer.flush().await.expect("flush");
    let n = tokio::time::timeout(Duration::from_secs(30), peer.read(&mut reply))
        .await
        .expect(
            "an established session that paused well past the first-message bound was closed — \
             the idle bound has collapsed onto it, which would break every pooling client",
        )
        .expect("read");
    assert!(
        n > 0,
        "the connection answered nothing after the pause; it was closed, not idle-tolerant"
    );
}

#[tokio::test]
async fn the_connection_past_the_cap_gets_a_notice_of_disconnection_and_the_slot_comes_back() {
    let state = new_state().await;
    let port = start_server(&state).await;

    // Fill the cap. These peers say nothing, which is fine: they are admitted, and the
    // configured first-message deadline is far longer than this test needs.
    let mut held = Vec::with_capacity(MAX_CONNECTIONS);
    for i in 0..MAX_CONNECTIONS {
        held.push(
            TcpStream::connect(("127.0.0.1", port))
                .await
                .unwrap_or_else(|e| panic!("connection {i} of the cap failed: {e}")),
        );
    }
    // The server admits asynchronously; give the accept loop a moment to take every slot.
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
        refusal, NOTICE_OF_DISCONNECTION,
        "the peer over the cap must be refused in LDAP's own vocabulary — an unsolicited \
         Notice of Disconnection with resultCode unavailable (52) — not dropped silently"
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
        .write_all(ANONYMOUS_BIND)
        .await
        .expect("write bind");
    admitted.flush().await.expect("flush");
    let mut reply = [0u8; 256];
    let n = tokio::time::timeout(Duration::from_secs(30), admitted.read(&mut reply))
        .await
        .expect("the freed slot was not reused — the permit is not being released")
        .expect("read");
    assert!(n > 0, "the reused slot answered nothing");
    assert_eq!(
        reply[0],
        0x30,
        "expected an LDAPMessage on the reused slot, got {:02x?}",
        &reply[..n]
    );
    assert_ne!(
        &reply[..n],
        NOTICE_OF_DISCONNECTION,
        "the freed slot answered with another refusal — the permit is not being released"
    );
}

#[tokio::test]
async fn a_bind_parked_for_a_human_is_never_closed_by_the_deadline() {
    // The bound that matters most, and the one a careless implementation gets wrong: a `manual`
    // rule parks the event for a **person** at the dashboard, with a 300-second default, and the
    // peer is silent for the whole of that wait because it is waiting for us. If the deadline
    // covered anything but the `read()` itself, this connection would be torn down at the
    // first-message bound — while the operator was still reading the question.
    //
    // Nothing answers the intercept here. The assertion is that the connection is *still there*
    // well past the first-message bound, which is exactly the state an operator needs.
    let state = new_state().await;
    let port = start_server_with_manual_rule(&state).await;

    let mut peer = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");

    peer.write_all(ANONYMOUS_BIND).await.expect("write bind");
    peer.flush().await.expect("flush");

    // Well past FIRST_MESSAGE_READ_TIMEOUT, and well short of the manual rule's own 300s.
    tokio::time::sleep(FIRST_MESSAGE_READ_TIMEOUT + Duration::from_secs(15)).await;

    let mut buf = [0u8; 256];
    match tokio::time::timeout(Duration::from_secs(3), peer.read(&mut buf)).await {
        Err(_) => {} // still open, still parked — the expected outcome
        Ok(Ok(0)) => panic!(
            "the connection was closed while its bind was parked for a human: the read deadline \
             is covering the model/manual round-trip rather than the read, so no operator could \
             ever answer an intercept on this protocol"
        ),
        Ok(Ok(n)) => panic!(
            "the server answered a bind nobody had decided: {:02x?}",
            &buf[..n]
        ),
        Ok(Err(e)) => panic!("the connection was reset while parked: {e}"),
    }
}

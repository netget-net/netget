//! The connection bounds on a real, running VNC server, driven from the wire.
//!
//! Two claims, and they pull in opposite directions — which is the point. A peer that has
//! connected and said nothing must be let go of; a connection that is in the middle of being
//! answered must not be.
//!
//! **The first test fails without the bound.** VNC reads in several scattered steps — the
//! version exchange, the security choice, `ClientInit`, each message-type octet and each message
//! body — so `src/server/vnc/mod.rs` wraps its read half in an `IdleTimeoutReader` rather than
//! timing out one call. Take that wrapper off and the first test hangs until its own assertion
//! window expires: the server has written `RFB 003.008\n` and is parked in `read_exact` waiting
//! for twelve bytes that will never come, holding a task, an `AppState` row and a connection
//! slot. Nothing else in the process will close that socket.
//!
//! **The second test is what stops a lazy fix.** `IdleTimeoutReader`'s deadline is armed lazily,
//! only while a read is actually pending, so an LLM round-trip — or a `manual` rule parking an
//! event for a *human*, 300 seconds by default (`src/state/intercepts.rs`) — runs with no clock
//! against it. Arm it eagerly instead and a viewer whose `FramebufferUpdateRequest` is waiting on
//! a person is hung up on mid-answer.
//!
//! This test completes the whole RFB 3.8 handshake by hand, because that is the only way to
//! reach an event: version, security type `None`, `SecurityResult`, `ClientInit`, `ServerInit`,
//! and then one `FramebufferUpdateRequest`.
//!
//! No mock backend: the LLM endpoint is a dead port. These tests assert on *deadlines*, not on
//! answers. Loopback only.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features vnc --test server -- vnc::connection_bounds --test-threads=100


use std::time::Duration;

use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use netget::state::ServerId;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

/// `src/server/vnc/mod.rs::FIRST_BYTE_READ_TIMEOUT`.
const FIRST_READ_TIMEOUT: Duration = Duration::from_secs(30);

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
    panic!("VNC server #{} never bound a port", id.as_u32());
}

/// `parked` routes every event to a human, which is the 300-second window the second test
/// exists for. The RFB handshake itself needs no model call either way.
async fn start_server(state: &AppState, parked: bool) -> (ServerId, u16) {
    let (tx, _rx) = mpsc::unbounded_channel();
    let server_id = ServerForm {
        protocol: "vnc".to_string(),
        port: Some(0),
        // An empty instruction really is model-free; `None` is replaced by a default one and
        // every event would consult the LLM.
        instruction: Some(String::new()),
        event_handlers: parked.then(|| {
            vec![serde_json::json!({
                "event_pattern": "*",
                "handler": {"type": "manual", "timeout_secs": 600}
            })]
        }),
        ..Default::default()
    }
    .create(state, tx)
    .await
    .expect("create vnc server");
    let port = wait_for_port(state, server_id).await;
    (server_id, port)
}

/// Take the connection through RFB 3.8 to the point where client messages are accepted.
async fn complete_rfb_handshake(peer: &mut TcpStream) {
    let mut version = [0u8; 12];
    peer.read_exact(&mut version).await.expect("server version");
    assert_eq!(&version, b"RFB 003.008\n", "unexpected RFB version banner");
    peer.write_all(b"RFB 003.008\n").await.expect("our version");

    let mut security = [0u8; 2];
    peer.read_exact(&mut security)
        .await
        .expect("security types");
    assert_eq!(security[0], 1, "expected exactly one security type");
    assert_eq!(security[1], 1, "expected security type None (1)");
    peer.write_all(&[1u8]).await.expect("choose None");

    let mut result = [0u8; 4];
    peer.read_exact(&mut result).await.expect("SecurityResult");
    assert_eq!(u32::from_be_bytes(result), 0, "SecurityResult was not OK");

    // ClientInit: shared-flag.
    peer.write_all(&[1u8]).await.expect("ClientInit");

    // ServerInit: width, height, 16-byte pixel format, then a length-prefixed name.
    let mut fixed = [0u8; 24];
    peer.read_exact(&mut fixed).await.expect("ServerInit");
    let name_len = u32::from_be_bytes([fixed[20], fixed[21], fixed[22], fixed[23]]) as usize;
    let mut name = vec![0u8; name_len];
    peer.read_exact(&mut name).await.expect("desktop name");
}

#[tokio::test]
async fn a_peer_that_connects_and_says_nothing_is_closed_at_the_first_bound() {
    let state = new_state().await;
    let (_server_id, port) = start_server(&state, false).await;

    let mut peer = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");

    let started = std::time::Instant::now();
    let mut sink = Vec::new();
    // Generous against the declared bound so an ordinary scheduling delay under
    // --test-threads=100 is not mistaken for a missing deadline; what is being asserted is that
    // the read ends at all.
    let read = tokio::time::timeout(
        FIRST_READ_TIMEOUT + Duration::from_secs(45),
        peer.read_to_end(&mut sink),
    )
    .await;

    let elapsed = started.elapsed();
    assert!(
        read.is_ok(),
        "a peer that connected and never returned its ProtocolVersion was still holding the \
         socket, the connection task and its AppState entry after {}s — the first-byte read \
         deadline is not being applied",
        elapsed.as_secs()
    );
    read.unwrap().expect("read to EOF");
    assert_eq!(
        sink, b"RFB 003.008\n",
        "the server should have sent its version banner and then nothing else"
    );
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
    let (server_id, port) = start_server(&state, true).await;

    let mut peer = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    complete_rfb_handshake(&mut peer).await;

    // FramebufferUpdateRequest: type 3, non-incremental, the whole 1024x768 default screen.
    let request = [3u8, 0, 0, 0, 0, 0, 0x04, 0x00, 0x03, 0x00];
    peer.write_all(&request)
        .await
        .expect("FramebufferUpdateRequest");
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
        // and the viewer is still being served. This is the passing case, and it is also RFB's
        // own normal behaviour — a client with an outstanding incremental request is *required*
        // to stay silent until the server has an update for it.
        Err(_) => {}
        Ok(Ok(0)) => panic!(
            "the server hung up on a viewer whose framebuffer update was parked for a human \
             after {}s — the read deadline is being applied to the answer as well as to the \
             read, which closes the connection it is in the middle of answering",
            (FIRST_READ_TIMEOUT + Duration::from_secs(20)).as_secs()
        ),
        Ok(Ok(_)) => {}
        Ok(Err(e)) => panic!("read failed on a connection that should still be open: {e}"),
    }
}

/// `src/server/vnc/mod.rs::MAX_CONNECTIONS`, which takes
/// `accept_bounded::DEFAULT_MAX_CONNECTIONS`.
const MAX_CONNECTIONS: usize = 256;

/// `src/server/vnc/mod.rs::CONNECTION_CAP_REFUSAL`: nothing — RFB's refusal is only sendable after the peer has returned its ProtocolVersion, which a capped peer never gets to do.
const CONNECTION_CAP_REFUSAL: &[u8] = b"";

#[tokio::test]
async fn the_connection_past_the_cap_is_refused_in_the_protocols_own_words() {
    let state = new_state().await;
    let (server_id, port) = start_server(&state, true).await;

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

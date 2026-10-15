//! The connection cap on a real, running BGP speaker, driven from the wire.
//!
//! `OPEN_HOLD_TIME` is four minutes — RFC 4271 §8.2.2's own recommendation for the window
//! before an OPEN has been exchanged — so one silent stranger legitimately holds a socket, a
//! session task, a writer task and an `AppState` row for 240 seconds. Nothing bounded how many
//! such strangers there could be at once, and four minutes multiplied by an unbounded arrival
//! rate is not a bound.
//!
//! Three claims:
//!
//! 1. `MAX_CONNECTIONS` peers are admitted.
//! 2. The next one is refused with NOTIFICATION 6/8 — Cease / Out of Resources — and then
//!    closed. The expected message is rebuilt here from RFC 4271 §4.5's framing rather than
//!    imported from `wire.rs`, so this asserts against the RFC and not against the encoder
//!    that produced it.
//! 3. Closing an admitted session **frees exactly one slot**. A permit dropped before the
//!    session ends un-caps the speaker silently; one never released wedges it shut after
//!    `MAX_CONNECTIONS` peers have ever connected.
//!
//! **BGP is the rare protocol in this sweep whose refusal needs nothing from the peer**, which
//! is why it gets a real message where `mongodb`, `doh` and `dot` get a plain close. A
//! NOTIFICATION is self-contained — marker, length, type, code, subcode — with no field
//! echoing anything the sender has received, and RFC 4271 §6 allows one in any state including
//! Connect and Active. The subcode is 8 rather than 5 because a full connection table is a
//! transient resource condition that RFC 4486 §8 has the peer damp and retry, where §4's
//! `Connection Rejected` means a permanent policy refusal.
//!
//! **How this was proved to fail without the cap**: replace the `accept_bounded` call in
//! `src/server/bgp/mod.rs` with a bare `listener.accept().await` (and drop the permit from the
//! session task). The over-cap peer is then admitted and sits in OpenSent waiting for an OPEN
//! for four minutes, and the test fails on the read timing out.
//!
//! The server is model-free: an empty instruction really is model-free, where `None` is
//! replaced by a default one. BGP waits for the peer's OPEN, so a peer that says nothing
//! provokes no model call. Loopback only.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features bgp --test server -- bgp::connection_bounds --test-threads=100

use std::time::Duration;

use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use netget::state::ServerId;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::sync::mpsc;

/// `src/server/bgp/mod.rs::MAX_CONNECTIONS`. Deliberately duplicated rather than imported: if
/// the constant moves, this test should be re-read rather than silently follow it.
const MAX_CONNECTIONS: usize = 256;

/// The refusal RFC 4271 says this is, rebuilt from the spec.
///
/// §4.1: every message opens with a 16-octet marker of all ones, a two-octet length covering
/// the whole message, and a one-octet type — 3 for NOTIFICATION. §4.5: the NOTIFICATION body is
/// an error code and a subcode, with no data here. 6 is Cease (§6.7); 8 is
/// RFC 4486 §8's `Out of Resources`.
fn expected_refusal() -> Vec<u8> {
    let mut msg = vec![0xFFu8; 16];
    msg.extend_from_slice(&21u16.to_be_bytes()); // 19-octet header + code + subcode
    msg.push(3); // NOTIFICATION
    msg.push(6); // Cease
    msg.push(8); // Out of Resources
    msg
}

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
    panic!("BGP speaker #{} never bound a port", id.as_u32());
}

async fn start_server(state: &AppState) -> (ServerId, u16) {
    let (tx, _rx) = mpsc::unbounded_channel();
    let server_id = ServerForm {
        protocol: "bgp".to_string(),
        port: Some(0),
        instruction: Some(String::new()),
        ..Default::default()
    }
    .create(state, tx)
    .await
    .expect("create bgp server");
    let port = wait_for_port(state, server_id).await;
    (server_id, port)
}

/// Wait until the accept loop has taken `n` connections out of the listen backlog. A
/// `connect()` succeeds as soon as the kernel queues it, so without this the over-cap peer
/// races the accept loop and the test measures scheduling rather than the cap.
///
/// This speaker registers the connection in the accept loop itself, before the session task
/// reads anything, so the count reflects admitted peers rather than peers that have spoken.
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
    panic!("the speaker admitted only {seen} of {n} connections");
}

#[tokio::test]
async fn the_connection_past_the_cap_gets_a_cease_notification_and_the_slot_comes_back() {
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
    tokio::time::timeout(Duration::from_secs(20), over.read_to_end(&mut refusal))
        .await
        .expect(
            "the connection past the cap was neither answered nor closed — it was admitted and \
             is sitting in OpenSent, so there is no cap",
        )
        .expect("read to EOF");
    assert_eq!(
        refusal,
        expected_refusal(),
        "a refused peer must get one NOTIFICATION 6/8 and nothing else, then EOF. \
         Got {refusal:02x?}"
    );

    drop(held.pop().expect("one held connection"));

    let mut admitted = false;
    for _ in 0..100 {
        let mut candidate = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("connect after freeing a slot");
        let mut buf = [0u8; 64];
        match tokio::time::timeout(Duration::from_millis(300), candidate.read(&mut buf)).await {
            // Neither bytes nor EOF: this speaker waits for the peer's OPEN rather than sending
            // one unprompted, so a connection still open and still silent after the window is
            // one that was admitted. A refused peer gets a NOTIFICATION and an immediate close.
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
        "the cap never freed its slot after an admitted session ended — the permit is being held \
         past the life of the session, which wedges the speaker shut"
    );
}

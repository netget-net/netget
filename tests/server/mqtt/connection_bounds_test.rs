//! The connection cap and the read deadlines on a real, running MQTT broker, driven from the
//! wire.
//!
//! An MQTT connection is a *session*, not a request: a subscriber holds its socket open for the
//! life of the application, so this broker's live-connection count is its client count rather
//! than its arrival rate. Until September 2026 that count had no ceiling — the accept loop
//! admitted every connection offered to it, before any CONNECT.
//!
//! Three claims, and the second is where the version question lands:
//!
//! 1. `MAX_CONNECTIONS` peers are admitted.
//! 2. The next one is refused with **CONNACK return code 3, "Server unavailable"** — the one
//!    code MQTT defines for "I am working, come back later", and the same one this broker
//!    already sends when a handler refuses a CONNECT. The framing is 3.1.1's, which is not a
//!    guess about the peer: `build_connack` is this broker's single CONNACK site and has no
//!    version parameter, so a peer that could have completed a session here is a peer that
//!    accepts this shape. 3.1.1 §3.2 then requires the server to close, which it does.
//! 3. Closing an admitted connection **frees exactly one slot**. This is the claim that matters
//!    most here, because one MQTT connection is *two* tasks — the session and the writer it
//!    spawns — so the permit is an `Arc` held by both and released by whichever ends last.
//!    Holding it in the session alone would release the slot while a writer was still draining.
//!
//! **How this was proved to fail without the cap**: replace the `accept_bounded` call in
//! `src/server/mqtt/mod.rs` with a bare `listener.accept().await` (and drop the permit). The
//! over-cap peer is then admitted and, having sent no CONNECT, is answered with nothing — so
//! the `read_to_end` times out and the test fails on "was neither answered nor closed".
//!
//! # The read deadlines
//!
//! Each asserted from the peer's side, with the startup parameters set short:
//!
//! * **No CONNECT within `first_byte_timeout_secs`** — the peer is closed (3.1.1 §3.1.4).
//! * **A session with a non-zero Keep Alive** is closed after 1.5x of it with no packet from the
//!   client (§3.1.2.10, a MUST), and a session that keeps sending PINGREQ inside that window is
//!   *not* closed. The other two bounds are set long, so a test that passed on either of them
//!   would time out instead.
//! * **A session that declared Keep Alive 0** is closed at `idle_timeout_secs` instead, so the
//!   client cannot switch the bound off in its own CONNECT.
//! * **A packet parked for a human keeps its session**, far past 1.5x Keep Alive: packets are
//!   dispatched inline, so the read — and the deadline around it — is not running while the
//!   answer is composed.
//!
//! Removing the `timeout` around the read in `handle_mqtt_connection` makes the first three
//! hang to their windows; the fourth is the pin against the deadline being moved outward to
//! cover dispatch as well.
//!
//! The broker is model-free: an empty instruction really is model-free, where `None` is replaced
//! by a default one. MQTT is client-speaks-first, so a peer that never sends CONNECT provokes no
//! model call. Loopback only.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features mqtt --test server -- mqtt::connection_bounds --test-threads=100

use std::time::Duration;

use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use netget::state::ServerId;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

/// `src/server/mqtt/mod.rs::MAX_CONNECTIONS`. Deliberately duplicated rather than imported: if
/// the constant moves, this test should be re-read rather than silently follow it.
const MAX_CONNECTIONS: usize = 256;

/// `src/server/mqtt/mod.rs::CONNECTION_CAP_REFUSAL`: CONNACK, remaining length 2, no session
/// present, return code 3 ("Server unavailable", 3.1.1 §3.2.2.3).
const CONNECTION_CAP_REFUSAL: &[u8] = &[0x20, 0x02, 0x00, 0x03];

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
    panic!("MQTT broker #{} never bound a port", id.as_u32());
}

async fn start_server(state: &AppState) -> (ServerId, u16) {
    // The admitted peers send no CONNECT; keep them past the connect bound for the whole test.
    start_server_with(
        state,
        serde_json::json!({"first_byte_timeout_secs": 300}),
        vec![],
    )
    .await
}

async fn start_server_with(
    state: &AppState,
    startup_params: serde_json::Value,
    event_handlers: Vec<serde_json::Value>,
) -> (ServerId, u16) {
    let (tx, _rx) = mpsc::unbounded_channel();
    let server_id = ServerForm {
        protocol: "mqtt".to_string(),
        port: Some(0),
        instruction: Some(String::new()),
        startup_params: Some(startup_params),
        event_handlers: Some(event_handlers),
        ..Default::default()
    }
    .create(state, tx)
    .await
    .expect("create mqtt broker");
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
    panic!("the broker admitted only {seen} of {n} connections");
}

#[tokio::test]
async fn the_connection_past_the_cap_gets_connack_server_unavailable_and_the_slot_comes_back() {
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
        .expect("the connection past the cap was neither answered nor closed")
        .expect("read the refusal");
    assert_eq!(
        refusal, CONNECTION_CAP_REFUSAL,
        "the peer over the cap must read CONNACK 3 and then EOF; a silent drop leaves a client \
         unable to tell a full broker from a crashed one. Got {refusal:02x?}"
    );

    // Releasing one admitted connection must free exactly one slot — and an MQTT connection is
    // two tasks, so this is what catches a permit released by the session while the writer is
    // still alive (un-caps the broker) or never released at all (wedges it shut).
    drop(held.pop().expect("one held connection"));

    let mut admitted = false;
    for _ in 0..100 {
        let mut candidate = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("connect after freeing a slot");
        let mut buf = [0u8; 64];
        match tokio::time::timeout(Duration::from_millis(300), candidate.read(&mut buf)).await {
            // MQTT is client-speaks-first: silence means this peer was admitted and the broker
            // is waiting for its CONNECT.
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
         held past the life of the connection, which wedges the broker shut"
    );
}

/// An MQTT 3.1.1 CONNECT with clean session and the given Keep Alive.
fn connect_packet(keep_alive: u16) -> Vec<u8> {
    let client_id = b"bounds";
    let mut body = vec![0x00, 0x04, b'M', b'Q', b'T', b'T', 0x04, 0x02];
    body.extend_from_slice(&keep_alive.to_be_bytes());
    body.extend_from_slice(&(client_id.len() as u16).to_be_bytes());
    body.extend_from_slice(client_id);
    let mut packet = vec![0x10, body.len() as u8];
    packet.extend_from_slice(&body);
    packet
}

const CONNACK_ACCEPTED: [u8; 4] = [0x20, 0x02, 0x00, 0x00];
const PINGREQ: [u8; 2] = [0xC0, 0x00];

/// Every CONNECT is accepted by a static rule — no model — so what follows is a live session.
fn accept_every_connect() -> serde_json::Value {
    serde_json::json!({
        "event_pattern": "mqtt_connect",
        "handler": {
            "type": "static",
            "actions": [{"type": "mqtt_connack", "return_code": 0, "session_present": false}]
        }
    })
}

async fn connected_session(port: u16, keep_alive: u16) -> TcpStream {
    let mut peer = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    peer.write_all(&connect_packet(keep_alive))
        .await
        .expect("write CONNECT");
    let mut connack = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(20), peer.read_exact(&mut connack))
        .await
        .expect("no CONNACK within 20s")
        .expect("read CONNACK");
    assert_eq!(
        connack, CONNACK_ACCEPTED,
        "the static rule did not accept the CONNECT"
    );
    peer
}

async fn has_live_connection(state: &AppState, id: ServerId) -> bool {
    state
        .get_server(id)
        .await
        .map(|s| {
            s.connections
                .values()
                .any(|c| !matches!(c.status, netget::state::server::ConnectionStatus::Closed))
        })
        .unwrap_or(false)
}

/// Read until EOF and say how long it took, or `None` if it never came inside `window`.
async fn time_to_eof(peer: &mut TcpStream, window: Duration) -> Option<Duration> {
    let started = std::time::Instant::now();
    let mut sink = Vec::new();
    match tokio::time::timeout(window, peer.read_to_end(&mut sink)).await {
        Ok(_) => Some(started.elapsed()),
        Err(_) => None,
    }
}

#[tokio::test]
async fn a_peer_that_never_sends_connect_is_closed_at_the_connect_bound() {
    let state = new_state().await;
    let (_, port) = start_server_with(
        &state,
        serde_json::json!({"first_byte_timeout_secs": 4}),
        vec![],
    )
    .await;

    let mut peer = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    let elapsed = time_to_eof(&mut peer, Duration::from_secs(50))
        .await
        .expect("a peer that sent no CONNECT was never closed — the connect bound is not applied");
    assert!(
        elapsed >= Duration::from_secs(2),
        "closed after {}ms, which is not the declared 4s bound",
        elapsed.as_millis()
    );
}

#[tokio::test]
async fn a_silent_session_is_closed_at_one_and_a_half_times_its_keep_alive() {
    let state = new_state().await;
    // Both other bounds are set long: a test that passed on either of them times out instead.
    let (_, port) = start_server_with(
        &state,
        serde_json::json!({"first_byte_timeout_secs": 120, "idle_timeout_secs": 120}),
        vec![accept_every_connect()],
    )
    .await;

    // Keep Alive 2s: the broker must close after 3s with nothing from the client.
    let mut peer = connected_session(port, 2).await;
    let elapsed = time_to_eof(&mut peer, Duration::from_secs(50))
        .await
        .expect("a session silent past 1.5x its Keep Alive was never closed (3.1.1 §3.1.2.10)");
    assert!(
        elapsed >= Duration::from_millis(2500) && elapsed < Duration::from_secs(40),
        "closed after {}ms; 1.5x a 2-second Keep Alive is 3s",
        elapsed.as_millis()
    );
}

#[tokio::test]
async fn a_session_that_keeps_pinging_is_not_closed() {
    let state = new_state().await;
    let (server_id, port) = start_server_with(
        &state,
        serde_json::json!({"first_byte_timeout_secs": 120, "idle_timeout_secs": 120}),
        vec![accept_every_connect()],
    )
    .await;

    let mut peer = connected_session(port, 2).await;
    // Eight seconds of PINGREQ every second — well past 1.5x Keep Alive in total, never past it
    // between packets. Each PINGRESP is read back, so a closed connection fails here.
    for i in 0..8 {
        tokio::time::sleep(Duration::from_secs(1)).await;
        peer.write_all(&PINGREQ).await.expect("write PINGREQ");
        let mut pingresp = [0u8; 2];
        tokio::time::timeout(Duration::from_secs(10), peer.read_exact(&mut pingresp))
            .await
            .unwrap_or_else(|_| panic!("no PINGRESP to ping {i}"))
            .unwrap_or_else(|e| {
                panic!("the broker closed a session that was pinging inside its Keep Alive: {e}")
            });
        assert_eq!(
            pingresp,
            [0xD0, 0x00],
            "ping {i} was not answered with PINGRESP"
        );
    }
    assert!(
        has_live_connection(&state, server_id).await,
        "the broker no longer has a live connection for a session that kept pinging"
    );
}

#[tokio::test]
async fn keep_alive_zero_falls_back_to_the_idle_bound_rather_than_to_no_bound() {
    let state = new_state().await;
    let (_, port) = start_server_with(
        &state,
        serde_json::json!({"first_byte_timeout_secs": 120, "idle_timeout_secs": 3}),
        vec![accept_every_connect()],
    )
    .await;

    let mut peer = connected_session(port, 0).await;
    let elapsed = time_to_eof(&mut peer, Duration::from_secs(50))
        .await
        .expect(
            "a Keep Alive 0 session was never closed — the client switched the bound off in its \
             own CONNECT",
        );
    assert!(
        elapsed >= Duration::from_millis(1500) && elapsed < Duration::from_secs(40),
        "closed after {}ms, which is not the declared 3s idle bound",
        elapsed.as_millis()
    );
}

#[tokio::test]
async fn a_packet_parked_for_a_human_keeps_its_session() {
    let state = new_state().await;
    let (server_id, port) = start_server_with(
        &state,
        serde_json::json!({"first_byte_timeout_secs": 120, "idle_timeout_secs": 120}),
        vec![
            accept_every_connect(),
            serde_json::json!({
                "event_pattern": "*",
                "handler": {"type": "manual", "timeout_secs": 600}
            }),
        ],
    )
    .await;

    // Keep Alive 2s, then a SUBSCRIBE whose SUBACK is parked for a human. The client sends
    // nothing more: it is waiting for the SUBACK, which is the broker's to send.
    let mut peer = connected_session(port, 2).await;
    peer.write_all(&[0x82, 0x06, 0x00, 0x01, 0x00, 0x01, b't', 0x00])
        .await
        .expect("write SUBSCRIBE");

    // Four times the 3-second keep-alive bound, well inside the 600-second window.
    let closed = time_to_eof(&mut peer, Duration::from_secs(12)).await;
    assert!(
        closed.is_none(),
        "the broker closed a session after {closed:?} while its SUBACK was parked for a human — \
         the keep-alive deadline is covering dispatch as well as the read"
    );
    assert!(
        has_live_connection(&state, server_id).await,
        "the broker no longer has a live connection for a session whose answer is parked"
    );
}

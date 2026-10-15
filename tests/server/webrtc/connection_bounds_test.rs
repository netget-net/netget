//! The connection cap and the idle bound on a real, running WebRTC server, driven from the
//! wire. The idle tests are described where they start, below the cap test.
//!
//! `SIGNALLING_HANDSHAKE_TIMEOUT` (10s) bounds how long *one* peer holds a socket before it has
//! upgraded, and `max_peers` bounds how many *offers* are accepted — but `max_peers` counts
//! peers that have already upgraded, sent an SDP offer and been approved by a handler, so a
//! stranger who merely connects is nowhere near it. Until September 2026 nothing bounded the
//! number of pre-admission signalling connections at all, which is the population an attacker
//! actually controls.
//!
//! Three claims:
//!
//! 1. `MAX_CONNECTIONS` peers are admitted, each completing a real RFC 6455 upgrade.
//!    Handshaking them rather than leaving them silent is what keeps claim 3 honest: a peer
//!    that only opens a socket is evicted by `SIGNALLING_HANDSHAKE_TIMEOUT` after ten seconds, which would
//!    free slots on its own and let the slot-return assertion pass for a reason that has
//!    nothing to do with the permit.
//! 2. The next one is refused with `HTTP/1.1 503` and `Retry-After`. This server's own refusal for a peer over
//!    `max_peers` is a `Rejected` signalling frame, and it is unreachable here: that is a
//!    WebSocket text message, and a peer refused at the accept has not upgraded, so it has no
//!    frame parser running. What it *is* in the middle of is an ordinary HTTP/1.1 GET
//!    (RFC 6455 §4.1), so 503 is inside the protocol rather than beside it.
//! 3. Closing an admitted connection **frees exactly one slot**. A permit dropped before the
//!    connection ends un-caps the server silently; one never released wedges it shut after
//!    `MAX_CONNECTIONS` peers have ever connected. The connection task here spawns a writer,
//!    but `.await`s it on its only exit path, so the single permit it holds covers both.
//!
//! **How this was proved to fail without the cap**: replace the `accept_bounded` call in
//! `src/server/webrtc/mod.rs` with a bare `listener.accept().await` (and drop the permit from
//! the connection task). The over-cap peer is then upgraded and the test fails on reading 101
//! where it demanded 503.
//!
//! The server is model-free: an empty instruction really is model-free, where `None` is
//! replaced by a default one. The WebSocket upgrade itself consults nothing, and no signalling
//! frame is ever sent, so 256 connections cost no model calls at all. Loopback only.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features webrtc --test server -- webrtc::connection_bounds --test-threads=100


use std::time::Duration;

use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use netget::state::ServerId;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

/// `src/server/webrtc/mod.rs::MAX_CONNECTIONS`. Deliberately duplicated rather than imported: if
/// the constant moves, this test should be re-read rather than silently follow it.
const MAX_CONNECTIONS: usize = 256;

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
    panic!("WebRTC server #{} never bound a port", id.as_u32());
}

async fn start_server(state: &AppState) -> (ServerId, u16) {
    let (tx, _rx) = mpsc::unbounded_channel();
    let server_id = ServerForm {
        protocol: "webrtc".to_string(),
        port: Some(0),
        instruction: Some(String::new()),
        ..Default::default()
    }
    .create(state, tx)
    .await
    .expect("create webrtc server");
    let port = wait_for_port(state, server_id).await;
    (server_id, port)
}

/// The status line of the server's answer to one opening handshake, and the socket it came on.
///
/// 101 means the peer was admitted and upgraded; 503 means it was refused at the accept. The
/// socket is returned so an admitted connection can be *held*, which is what fills the cap.
async fn attempt_handshake(port: u16) -> (u16, TcpStream) {
    let mut stream = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("the listener must still accept — a cap is not a closed socket");
    // A fixed nonce keeps this reproducible; RFC 6455 only requires 16 random bytes, base64'd.
    let request = format!(
        "GET / HTTP/1.1\r\n\
         Host: 127.0.0.1:{port}\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
         Sec-WebSocket-Version: 13\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write handshake");
    stream.flush().await.expect("flush handshake");

    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    // Read only as far as the end of the status line; stopping there leaves an upgraded
    // connection's frames untouched.
    loop {
        let n = tokio::time::timeout(Duration::from_secs(10), stream.read(&mut byte))
            .await
            .expect("the server neither upgraded nor refused this handshake")
            .expect("read the status line");
        assert!(n == 1, "the server closed without answering the handshake");
        if byte[0] == b'\n' {
            break;
        }
        head.push(byte[0]);
    }
    let line = String::from_utf8_lossy(&head).trim().to_string();
    let status: u16 = line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| panic!("unparseable status line {line:?}"));
    (status, stream)
}

#[tokio::test]
async fn the_handshake_past_the_cap_gets_a_503_and_the_slot_comes_back() {
    let state = new_state().await;
    let (_server_id, port) = start_server(&state).await;

    let mut held = Vec::with_capacity(MAX_CONNECTIONS);
    for i in 0..MAX_CONNECTIONS {
        let (status, stream) = attempt_handshake(port).await;
        assert_eq!(
            status, 101,
            "handshake {i} of the cap was not upgraded (status {status}); the cap must admit \
             MAX_CONNECTIONS peers before it refuses any"
        );
        held.push(stream);
    }

    let (status, _over) = attempt_handshake(port).await;
    assert_eq!(
        status, 503,
        "the handshake past the cap was upgraded instead of refused, so there is no cap"
    );

    // Every one of them is an upgraded session with no deadline on it, so none can have been
    // evicted by the handshake bound: whatever slot appears below came from the permit.
    assert_eq!(
        held.len(),
        MAX_CONNECTIONS,
        "the held connections must all still be open for the next assertion to mean anything"
    );
    drop(held.pop().expect("one held connection"));

    let mut admitted = false;
    for _ in 0..100 {
        let (status, _stream) = attempt_handshake(port).await;
        if status == 101 {
            admitted = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        admitted,
        "the cap never freed its slot after an upgraded connection ended — the permit is being \
         held past the life of the connection, which wedges the server shut"
    );
}

/// The protocol these idle tests start, by registry name.
const PROTOCOL: &str = "webrtc";

/// The first signal the parked test sends. A minimal SDP offer: it parses, so the offer decision runs — and parks.
const PARKED_SIGNAL: &str = "{\"type\":\"offer\",\"peer_id\":\"p1\",\"sdp\":\"v=0\\r\\no=- 0 0 IN IP4 127.0.0.1\\r\\ns=-\\r\\nt=0 0\\r\\n\"}";

/// Whether the server legitimately writes a frame before the parked handler answers.
const PARKED_EXPECTS_FRAMES: bool = false;

// ---------------------------------------------------------------------------------------------
// The idle bound
// ---------------------------------------------------------------------------------------------
//
// `IDLE_TIMEOUT` (600s, declared as `idle_timeout_secs`) bounds the signalling WebSocket on the
// peer's *liveness*: at half of it the server sends a Ping, every RFC 6455 endpoint answers with
// a Pong by itself, and only a peer that sends no frame at all — not even that Pong — reaches the
// bound. Three tests: a raw peer that never answers is sent the Ping and then Close 1001; a real
// client that only answers Pings is kept; a signal whose handling is parked for a human keeps its
// connection, and gets a fresh bound once the human answers.
//
// Removing the `watch_idle_with_probe` arm makes the first hang to its window and the second see
// no Ping; removing the probe makes the second see its live client closed; replacing the
// per-frame `busy()` guard with a bare `touch()` makes the third see its connection closed the
// moment the parked signal is answered.

/// The idle bound these tests drive, as `idle_timeout_secs`.
const SHORT_IDLE: Duration = Duration::from_secs(2);

async fn start_server_with(
    state: &AppState,
    event_handlers: Vec<serde_json::Value>,
) -> (ServerId, u16) {
    let (tx, _rx) = mpsc::unbounded_channel();
    let server_id = ServerForm {
        protocol: PROTOCOL.to_string(),
        port: Some(0),
        instruction: Some(String::new()),
        startup_params: Some(serde_json::json!({"idle_timeout_secs": SHORT_IDLE.as_secs()})),
        event_handlers: Some(event_handlers),
        ..Default::default()
    }
    .create(state, tx)
    .await
    .expect("create server");
    let port = wait_for_port(state, server_id).await;
    (server_id, port)
}

/// Consume the rest of the 101 response head, so what follows on the socket is frames.
async fn finish_upgrade_head(stream: &mut TcpStream) {
    let mut window = [0u8; 3];
    let mut byte = [0u8; 1];
    loop {
        tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut byte))
            .await
            .expect("the 101 head never ended")
            .expect("read the 101 head");
        if window == *b"\r\n\r" && byte[0] == b'\n' {
            return;
        }
        window = [window[1], window[2], byte[0]];
    }
}

/// One masked text frame from a client (a zero mask key leaves the payload as written).
fn masked_text_frame(text: &str) -> Vec<u8> {
    let payload = text.as_bytes();
    assert!(payload.len() < 126, "short frames only");
    let mut frame = vec![0x81, 0x80 | payload.len() as u8, 0, 0, 0, 0];
    frame.extend_from_slice(payload);
    frame
}

#[tokio::test]
async fn an_upgraded_peer_that_never_answers_the_keepalive_is_closed_with_1001() {
    let state = new_state().await;
    let (_, port) = start_server_with(
        &state,
        vec![serde_json::json!({"event_pattern": "*",
                                "handler": {"type": "static", "actions": []}})],
    )
    .await;

    let (status, mut peer) = attempt_handshake(port).await;
    assert_eq!(status, 101, "the handshake was not upgraded");
    finish_upgrade_head(&mut peer).await;

    // This peer reads but never writes, so it never answers the keepalive Ping.
    let started = std::time::Instant::now();
    let mut frames = Vec::new();
    let ended = tokio::time::timeout(Duration::from_secs(45), peer.read_to_end(&mut frames)).await;
    let elapsed = started.elapsed();
    assert!(
        ended.is_ok(),
        "an upgraded signalling peer that sent no frame at all was still connected after 45s — \
         nothing bounds the signalling WebSocket after its upgrade"
    );
    assert!(
        elapsed >= SHORT_IDLE / 2,
        "closed after {}ms, which is not the declared {}s idle bound",
        elapsed.as_millis(),
        SHORT_IDLE.as_secs()
    );
    let ping = [&[0x89u8, 16][..], b"netget-keepalive"].concat();
    assert!(
        frames.windows(ping.len()).any(|w| w == ping.as_slice()),
        "the server closed without first sending the keepalive Ping: {frames:02x?}"
    );
    assert!(
        frames
            .windows(4)
            .any(|w| w[0] == 0x88 && w[2] == 0x03 && w[3] == 0xE9),
        "the server did not close with 1001 (going away): {frames:02x?}"
    );
}

#[tokio::test]
async fn a_client_that_only_answers_pings_is_not_closed() {
    use futures::StreamExt;

    let state = new_state().await;
    let (_, port) = start_server_with(
        &state,
        vec![serde_json::json!({"event_pattern": "*",
                                "handler": {"type": "static", "actions": []}})],
    )
    .await;

    // tokio-tungstenite answers every Ping with a Pong by itself, as a browser does. The client
    // sends nothing of its own: a peer waiting on signalling, which must be kept.
    let tcp = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    let (mut ws, _) = tokio_tungstenite::client_async(format!("ws://127.0.0.1:{port}/"), tcp)
        .await
        .expect("websocket upgrade");

    let deadline = tokio::time::Instant::now() + SHORT_IDLE * 5;
    let mut pings = 0;
    loop {
        match tokio::time::timeout_at(deadline, ws.next()).await {
            Err(_) => break,
            Ok(Some(Ok(tokio_tungstenite::tungstenite::Message::Ping(_)))) => pings += 1,
            Ok(Some(Ok(other))) => panic!(
                "a client that answered every Ping was sent {other:?} — the keepalive Pong is \
                 not counted as activity"
            ),
            Ok(Some(Err(e))) => panic!("the connection failed under a live client: {e}"),
            Ok(None) => panic!("the server closed a client that answered every Ping"),
        }
    }
    assert!(
        pings >= 2,
        "only {pings} keepalive Ping(s) in five idle bounds — the server is not probing a silent \
         signalling peer"
    );
}

/// The opcodes of the unmasked server frames in `bytes`, in order.
fn opcodes(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = 0;
    while i + 2 <= bytes.len() {
        out.push(bytes[i] & 0x0F);
        let (len, header) = match bytes[i + 1] & 0x7F {
            126 if i + 4 <= bytes.len() => {
                (u16::from_be_bytes([bytes[i + 2], bytes[i + 3]]) as usize, 4)
            }
            n if n < 126 => (n as usize, 2),
            _ => break,
        };
        i += header + len;
    }
    out
}

#[tokio::test]
async fn a_signal_parked_for_a_human_keeps_its_connection() {
    let state = new_state().await;
    let (_, port) = start_server_with(
        &state,
        vec![serde_json::json!({"event_pattern": "*",
                                "handler": {"type": "manual", "timeout_secs": 600}})],
    )
    .await;

    let (status, mut peer) = attempt_handshake(port).await;
    assert_eq!(status, 101, "the handshake was not upgraded");
    finish_upgrade_head(&mut peer).await;
    peer.write_all(&masked_text_frame(PARKED_SIGNAL))
        .await
        .expect("write the signal");

    // Its handling is parked for a human; the peer says nothing more and never answers a Ping.
    // Four times the idle bound, well inside the 600-second window the human has to answer in.
    let mut received = Vec::new();
    let mut buf = [0u8; 1024];
    let deadline = tokio::time::Instant::now() + SHORT_IDLE * 4;
    loop {
        match tokio::time::timeout_at(deadline, peer.read(&mut buf)).await {
            Err(_) => break,
            Ok(Ok(0)) => panic!(
                "the server closed a signalling connection whose {PARKED_SIGNAL} was parked for \
                 a human; received {received:02x?}"
            ),
            Ok(Ok(n)) => received.extend_from_slice(&buf[..n]),
            Ok(Err(e)) => panic!("read failed: {e}"),
        }
    }
    let ops = opcodes(&received);
    assert!(
        !ops.iter().any(|op| *op == 0x9 || *op == 0x8),
        "a connection whose signal is parked was sent a Ping or a Close ({ops:?}, \
         {received:02x?}) — the watchdog is running while the handler decides"
    );
    assert!(
        PARKED_EXPECTS_FRAMES == !ops.is_empty(),
        "unexpected frames while parked: {ops:?} ({received:02x?})"
    );

    // The human answers, four idle bounds after the signal arrived. The answer is activity: the
    // connection must get a fresh bound from here, not be closed the moment the loop comes back
    // to a clock that ran out during the park. That is what the `busy()` guard is for.
    let intercept = state
        .list_intercepts()
        .await
        .into_iter()
        .find(|i| i.event_type == "webrtc_offer_received")
        .expect("the signal is not parked as an intercept");
    state
        .resolve_intercept(
            intercept.id,
            vec![serde_json::json!({"type": "reject_offer", "reason": "not today"})],
        )
        .await
        .expect("answer the parked signal");
    let mut after = Vec::new();
    let deadline = tokio::time::Instant::now() + SHORT_IDLE / 2;
    loop {
        match tokio::time::timeout_at(deadline, peer.read(&mut buf)).await {
            Err(_) => break,
            Ok(Ok(0)) => panic!(
                "the connection was closed right after its parked signal was answered — the \
                 answer did not count as activity; received {after:02x?}"
            ),
            Ok(Ok(n)) => after.extend_from_slice(&buf[..n]),
            Ok(Err(e)) => panic!("read failed: {e}"),
        }
    }
    assert!(
        !opcodes(&after).contains(&0x8),
        "the connection was sent a Close right after its parked signal was answered — the answer \
         did not count as activity: {after:02x?}"
    );
}

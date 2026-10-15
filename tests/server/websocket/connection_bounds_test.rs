//! The connection cap and the idle bound on a real, running WebSocket server, driven from the
//! wire.
//!
//! `HANDSHAKE_TIMEOUT_SECS` (15s) bounds how long a peer may hold a connection *before* it has
//! sent a request head. After the upgrade a WebSocket is a session the client is entitled to hold
//! open with nothing to say, so the upgraded bound (`IDLE_TIMEOUT`) is on the peer's *liveness*
//! rather than its conversation — a keepalive Ping at half of it, which every client answers by
//! itself. The idle tests are described where they start, below the cap test.
//!
//! The cap test makes three claims:
//!
//! 1. `MAX_CONNECTIONS` peers are admitted, each completing a real RFC 6455 upgrade. Handshaking
//!    them rather than leaving them silent is what keeps claim 3 honest: a peer that only opens
//!    a socket is evicted after fifteen seconds, which would free slots on its own and let the
//!    slot-return assertion pass for a reason that has nothing to do with the permit.
//! 2. The next one is refused with `HTTP/1.1 503` and `Retry-After`. A WebSocket client is an
//!    HTTP client first — RFC 6455 §4.1 makes the opening handshake an ordinary GET and §4.2.2
//!    has the server answer anything it will not upgrade with a normal HTTP response — so 503
//!    is inside the protocol rather than beside it, and every client surfaces a non-101 status
//!    as a failed handshake carrying that code. A close frame would be wrong twice over: it
//!    belongs to a connection that was never upgraded, and the peer has no frame parser running.
//! 3. Closing an admitted connection **frees exactly one slot**, and this is the claim the
//!    server's own structure puts at risk. One upgraded WebSocket here is *two* tasks, and the
//!    read loop waits only five seconds for the writer before giving up on it, so the permit is
//!    an `Arc` held by both halves and the slot comes back when the later of the two ends.
//!    Holding it in the reader alone would release the slot while a writer was still draining.
//!
//! **How this was proved to fail without the cap**: replace the `accept_bounded` call in
//! `src/server/websocket/mod.rs` with a bare `listener.accept().await` (and drop the permit from
//! the connection task). The over-cap peer is then upgraded and the test fails on reading 101
//! where it demanded 503.
//!
//! The server is model-free. The handshake is answered by a static `accept_websocket` rule and
//! everything after it by a zero-action `*` rule, so 256 upgrades cost no model calls at all —
//! without that, each one would be an LLM round-trip against a dead endpoint. Loopback only.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features websocket --test server -- websocket::connection_bounds --test-threads=100


use std::time::Duration;

use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use netget::state::ServerId;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

/// `src/server/websocket/mod.rs::MAX_CONNECTIONS`. Deliberately duplicated rather than
/// imported: if the constant moves, this test should be re-read rather than silently follow it.
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
    panic!("WebSocket server #{} never bound a port", id.as_u32());
}

async fn start_server(state: &AppState) -> (ServerId, u16) {
    let (tx, _rx) = mpsc::unbounded_channel();
    let server_id = ServerForm {
        protocol: "websocket".to_string(),
        port: Some(0),
        instruction: Some(String::new()),
        event_handlers: Some(vec![
            serde_json::json!({
                "event_pattern": "websocket_handshake",
                "handler": {"type": "static", "actions": [{"type": "accept_websocket"}]}
            }),
            // Everything after the upgrade is answered with nothing. First-match-wins, so this
            // must come second or it would swallow the handshake too.
            serde_json::json!({
                "event_pattern": "*",
                "handler": {"type": "static", "actions": []}
            }),
        ]),
        ..Default::default()
    }
    .create(state, tx)
    .await
    .expect("create websocket server");
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
    // Read only as far as the end of the status line; the rest of the head is not what this
    // test is about, and stopping here keeps an upgraded connection's frames untouched.
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

    // Every one of the 256 is an upgraded session, past HANDSHAKE_TIMEOUT_SECS and far inside the
    // 600-second idle bound this test runs with, so none can have been evicted: whatever slot
    // appears below came from the permit — and from *both* halves of it, since the writer task
    // holds its own clone.
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
        "the cap never freed its slot after an upgraded connection ended — a permit held past \
         the life of the connection (by the reader or by the writer task) wedges the server shut"
    );
}

// ---------------------------------------------------------------------------------------------
// The idle bound
// ---------------------------------------------------------------------------------------------
//
// `IDLE_TIMEOUT` (600s, declared as `idle_timeout_secs`) is a bound on the peer's *liveness*:
// at half of it the server sends a Ping, every RFC 6455 endpoint answers it with a Pong by
// itself, and only a peer that sent no frame at all — not even that Pong — reaches the bound.
// Three tests: a raw peer that never answers is closed with 1001; a real client that only
// answers pings is kept; a message parked for a human keeps its connection even from a peer
// that never answers (busy is not idle, and a busy connection is not even pinged).
//
// Removing the `watch_idle_with_probe` arm makes the first hang to its window; removing the
// keepalive Ping makes the second see its live client closed; removing the `busy()` guard makes
// the third see a Ping and then a close under its parked message.

/// The idle bound these tests drive, as `idle_timeout_secs`.
const SHORT_IDLE: Duration = Duration::from_secs(2);

async fn start_server_with(
    state: &AppState,
    idle_secs: u64,
    message_rule: serde_json::Value,
) -> (ServerId, u16) {
    let (tx, _rx) = mpsc::unbounded_channel();
    let server_id = ServerForm {
        protocol: "websocket".to_string(),
        port: Some(0),
        instruction: Some(String::new()),
        startup_params: Some(serde_json::json!({"idle_timeout_secs": idle_secs})),
        event_handlers: Some(vec![
            serde_json::json!({
                "event_pattern": "websocket_handshake",
                "handler": {"type": "static", "actions": [{"type": "accept_websocket"}]}
            }),
            serde_json::json!({
                "event_pattern": "websocket_connection_opened",
                "handler": {"type": "static", "actions": []}
            }),
            message_rule,
            serde_json::json!({
                "event_pattern": "*",
                "handler": {"type": "static", "actions": []}
            }),
        ]),
        ..Default::default()
    }
    .create(state, tx)
    .await
    .expect("create websocket server");
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

#[tokio::test]
async fn an_upgraded_peer_that_never_answers_the_keepalive_is_closed_with_1001() {
    let state = new_state().await;
    let (_, port) = start_server_with(
        &state,
        SHORT_IDLE.as_secs(),
        serde_json::json!({"event_pattern": "websocket_text_message",
                           "handler": {"type": "static", "actions": []}}),
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
        "an upgraded peer that sent no frame at all was still connected after 45s — nothing \
         bounds an upgraded WebSocket"
    );
    assert!(
        elapsed >= SHORT_IDLE / 2,
        "closed after {}ms, which is not the declared {}s idle bound",
        elapsed.as_millis(),
        SHORT_IDLE.as_secs()
    );
    // An unmasked Ping carrying the keepalive payload, then an unmasked Close with 1001.
    let ping = [&[0x89u8, 16][..], b"netget-keepalive"].concat();
    assert!(
        frames.windows(ping.len()).any(|w| w == ping.as_slice()),
        "the server closed without first sending the keepalive Ping at half the bound: \
         {frames:02x?}"
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
    let (server_id, port) = start_server_with(
        &state,
        SHORT_IDLE.as_secs(),
        serde_json::json!({"event_pattern": "websocket_text_message",
                           "handler": {"type": "static", "actions": []}}),
    )
    .await;

    // tokio-tungstenite answers every Ping with a Pong by itself, as browsers do. The client
    // never sends a message of its own: a live but silent session, which must be kept.
    let tcp = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    let (mut ws, _) = tokio_tungstenite::client_async(format!("ws://127.0.0.1:{port}/"), tcp)
        .await
        .expect("websocket upgrade");

    // Five times the idle bound: at least two keepalive rounds.
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
        "only {pings} keepalive Ping(s) in five idle bounds — the server is not probing a \
         silent session"
    );
    assert!(
        has_live_connection(&state, server_id).await,
        "the server no longer has a live connection for a client that answered every Ping"
    );
}

#[tokio::test]
async fn a_message_parked_for_a_human_keeps_its_connection() {
    let state = new_state().await;
    let (server_id, port) = start_server_with(
        &state,
        SHORT_IDLE.as_secs(),
        serde_json::json!({"event_pattern": "websocket_text_message",
                           "handler": {"type": "manual", "timeout_secs": 600}}),
    )
    .await;

    let (status, mut peer) = attempt_handshake(port).await;
    assert_eq!(status, 101, "the handshake was not upgraded");
    finish_upgrade_head(&mut peer).await;

    // One masked text frame, "hi" (a zero mask key leaves the payload as written). Its answer
    // is parked for a human; the peer then says nothing, and never answers a Ping.
    peer.write_all(&[0x81, 0x82, 0, 0, 0, 0, b'h', b'i'])
        .await
        .expect("write text frame");

    // Four times the idle bound, well inside the 600-second window the human has to answer in.
    let mut received = Vec::new();
    let mut buf = [0u8; 256];
    let deadline = tokio::time::Instant::now() + SHORT_IDLE * 4;
    loop {
        match tokio::time::timeout_at(deadline, peer.read(&mut buf)).await {
            Err(_) => break,
            Ok(Ok(0)) => panic!(
                "the server closed a connection whose message was parked for a human — the idle \
                 watchdog is not honouring ConnectionActivity::busy; received {received:02x?}"
            ),
            Ok(Ok(n)) => received.extend_from_slice(&buf[..n]),
            Ok(Err(e)) => panic!("read failed: {e}"),
        }
    }
    assert!(
        received.is_empty(),
        "the server sent {received:02x?} to a connection whose answer is parked — a busy \
         connection is neither pinged nor closed"
    );
    assert!(
        has_live_connection(&state, server_id).await,
        "the server no longer has a live connection for a message parked for a human"
    );
}

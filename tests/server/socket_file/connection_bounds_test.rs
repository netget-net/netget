//! The socket_file server's connection bounds, driven from the peer's end of the Unix socket.
//!
//! `src/server/socket_file/mod.rs` declares three numbers and argues each beside itself:
//! `FIRST_BYTE_READ_TIMEOUT` (300s — the peer is often NetGet's own client, connected and silent
//! while a person decides what to send), `IDLE_BETWEEN_MESSAGES_TIMEOUT` (900s) and
//! `MAX_CONNECTIONS` (256). The two read bounds are declared startup parameters, so these tests
//! set them short; what is asserted is that each is applied to the state it names.
//!
//! * **A peer that connects and says nothing is closed at the first-byte bound.** Remove the
//!   deadline around the read and the first test hangs until its own window expires.
//! * **Once the peer has spoken, the idle bound governs, not the first-byte one.** The two are
//!   set the wrong way round on purpose, so a first-byte bound applied to the whole connection
//!   times the assertion out.
//! * **A message whose answer is parked for a human keeps its connection open**, far past both
//!   bounds. The read loop goes straight back to `read()` while the answer is composed on
//!   another task, so this is the claim `ConnectionActivity::busy` exists for; remove the guard
//!   and the connection is closed under the parked message. **It is asserted on the server's
//!   own view as well as the peer's, and the server's view is the half that catches it**: the
//!   parked answer still holds the write half, so a reader that has given up does not show the
//!   peer an EOF — verified by removing the guard, when only the `live_connections` assertion
//!   failed.
//! * **The connection past `MAX_CONNECTIONS` reads EOF at once, and closing one admitted
//!   connection frees exactly one slot.** A byte stream has no refusal vocabulary, so the
//!   refusal is the clean EOF.
//!
//! No mock backend: the LLM endpoint is a dead port and every rule is static or manual.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features socket_file --test server -- \
//!       socket_file::connection_bounds_test --test-threads=100

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::time::Duration;

use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use netget::state::server::ConnectionStatus;
use netget::state::ServerId;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::mpsc;

const SHORT_FIRST_BYTE: Duration = Duration::from_secs(4);
const SHORT_IDLE: Duration = Duration::from_secs(3);

/// `MAX_CONNECTIONS` exactly as `mod.rs` declares it. Copied on purpose: if it moves, this file
/// should be re-read rather than silently follow.
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

/// A model-free socket_file server on a fresh socket path. The returned `TempDir` owns the
/// directory; keep it alive for the test.
async fn start_server(
    state: &AppState,
    mut startup_params: serde_json::Value,
    event_handlers: Vec<serde_json::Value>,
) -> (ServerId, PathBuf, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("bounds.sock");
    startup_params["socket_path"] = serde_json::json!(path.to_string_lossy());
    let (tx, _rx) = mpsc::unbounded_channel();
    let server_id = ServerForm {
        protocol: "socket_file".to_string(),
        port: None,
        instruction: Some(String::new()),
        startup_params: Some(startup_params),
        event_handlers: Some(event_handlers),
        ..Default::default()
    }
    .create(state, tx)
    .await
    .expect("create socket_file server");
    wait_for_path(&path).await;
    (server_id, path, dir)
}

async fn wait_for_path(path: &Path) {
    for _ in 0..600 {
        if path.exists() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("{} was never created", path.display());
}

async fn live_connections(state: &AppState, id: ServerId) -> usize {
    state
        .get_server(id)
        .await
        .map(|s| {
            s.connections
                .values()
                .filter(|c| !matches!(c.status, ConnectionStatus::Closed))
                .count()
        })
        .unwrap_or(0)
}

/// Read until EOF, and say how long it took. `None` if it never came inside `window`.
async fn time_to_eof(peer: &mut UnixStream, window: Duration) -> Option<Duration> {
    let started = std::time::Instant::now();
    let mut sink = Vec::new();
    match tokio::time::timeout(window, peer.read_to_end(&mut sink)).await {
        Ok(Ok(_)) | Ok(Err(_)) => Some(started.elapsed()),
        Err(_) => None,
    }
}

#[tokio::test]
async fn a_peer_that_connects_and_says_nothing_is_closed_at_the_first_byte_bound() {
    let state = new_state().await;
    let (_, path, _dir) = start_server(
        &state,
        serde_json::json!({ "first_byte_timeout_secs": SHORT_FIRST_BYTE.as_secs() }),
        vec![],
    )
    .await;

    let mut peer = UnixStream::connect(&path).await.expect("connect");
    let elapsed = time_to_eof(&mut peer, SHORT_FIRST_BYTE + Duration::from_secs(45))
        .await
        .expect(
            "a peer that connected and sent nothing was still holding the socket — the \
             first-byte bound is not applied, or `first_byte_timeout_secs` is never read",
        );
    assert!(
        elapsed >= SHORT_FIRST_BYTE / 2,
        "closed after only {}ms, which is not the declared {}s bound",
        elapsed.as_millis(),
        SHORT_FIRST_BYTE.as_secs()
    );
}

#[tokio::test]
async fn once_the_peer_has_spoken_the_idle_bound_governs() {
    let state = new_state().await;
    let (_, path, _dir) = start_server(
        &state,
        serde_json::json!({
            "first_byte_timeout_secs": 60,
            "idle_timeout_secs": SHORT_IDLE.as_secs(),
        }),
        vec![serde_json::json!({
            "event_pattern": "socket_file_data_received",
            "handler": {
                "type": "static",
                "actions": [{"type": "send_socket_data", "data": "ACK\n"}]
            }
        })],
    )
    .await;

    let mut peer = UnixStream::connect(&path).await.expect("connect");
    peer.write_all(b"hello\n").await.expect("write");
    let mut reply = [0u8; 16];
    let n = tokio::time::timeout(Duration::from_secs(20), peer.read(&mut reply))
        .await
        .expect("the static rule did not answer within 20s")
        .expect("read reply");
    assert_eq!(&reply[..n], b"ACK\n", "the static rule did not answer");

    let elapsed = time_to_eof(&mut peer, Duration::from_secs(45))
        .await
        .expect("a session that went quiet after an answer was never closed");
    assert!(
        elapsed >= SHORT_IDLE / 2,
        "closed after only {}ms, below the declared {}s idle bound",
        elapsed.as_millis(),
        SHORT_IDLE.as_secs()
    );
    assert!(
        elapsed < Duration::from_secs(40),
        "closed after {}s — the 60-second first-byte bound, not the {}s idle one",
        elapsed.as_secs(),
        SHORT_IDLE.as_secs()
    );
}

#[tokio::test]
async fn a_message_whose_answer_is_parked_for_a_human_keeps_its_connection() {
    let state = new_state().await;
    let (server_id, path, _dir) = start_server(
        &state,
        serde_json::json!({
            "first_byte_timeout_secs": SHORT_IDLE.as_secs(),
            "idle_timeout_secs": SHORT_IDLE.as_secs(),
        }),
        vec![serde_json::json!({
            "event_pattern": "*",
            "handler": {"type": "manual", "timeout_secs": 600}
        })],
    )
    .await;

    let mut peer = UnixStream::connect(&path).await.expect("connect");
    peer.write_all(b"question\n").await.expect("write");

    // Well past both bounds, well inside the 600-second window the human has to answer in.
    let closed = time_to_eof(&mut peer, SHORT_IDLE * 4 + Duration::from_secs(8)).await;
    assert!(
        closed.is_none(),
        "the server closed a connection whose message was parked for a human, after {:?} — \
         the read deadline is not honouring ConnectionActivity::busy",
        closed
    );
    assert_eq!(
        live_connections(&state, server_id).await,
        1,
        "the server no longer has a live connection for a peer whose answer is parked"
    );
}

#[tokio::test]
async fn the_connection_past_the_cap_reads_eof_and_a_slot_comes_back() {
    let state = new_state().await;
    let (server_id, path, _dir) = start_server(
        &state,
        serde_json::json!({ "first_byte_timeout_secs": 120 }),
        vec![],
    )
    .await;

    let mut admitted = Vec::with_capacity(MAX_CONNECTIONS);
    for _ in 0..MAX_CONNECTIONS {
        admitted.push(
            UnixStream::connect(&path)
                .await
                .expect("connect under the cap"),
        );
    }
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    while live_connections(&state, server_id).await < MAX_CONNECTIONS {
        assert!(
            std::time::Instant::now() < deadline,
            "only {} of {MAX_CONNECTIONS} connections were admitted",
            live_connections(&state, server_id).await
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let mut refused = UnixStream::connect(&path)
        .await
        .expect("connect over the cap");
    assert!(
        time_to_eof(&mut refused, Duration::from_secs(20))
            .await
            .is_some(),
        "the connection over the cap was admitted rather than refused"
    );

    drop(admitted.pop());
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    while live_connections(&state, server_id).await >= MAX_CONNECTIONS {
        assert!(
            std::time::Instant::now() < deadline,
            "closing an admitted connection never released its slot"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // The row is marked closed a moment before the task ends and drops its permit, so an EOF
    // right here can be the slot not yet being free: retry until one is admitted (left open).
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    let _next = loop {
        let mut next = UnixStream::connect(&path)
            .await
            .expect("connect into the freed slot");
        if time_to_eof(&mut next, Duration::from_secs(2))
            .await
            .is_none()
        {
            break next;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the freed slot never admitted a connection"
        );
    };

    let mut over = UnixStream::connect(&path)
        .await
        .expect("connect over again");
    assert!(
        time_to_eof(&mut over, Duration::from_secs(20))
            .await
            .is_some(),
        "closing one connection freed more than one slot"
    );
}

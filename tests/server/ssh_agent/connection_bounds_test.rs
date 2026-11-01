//! The SSH agent server's connection bounds, driven from the peer's end of the Unix socket.
//!
//! `src/server/ssh_agent/mod.rs` declares three numbers and argues each beside itself:
//! `FIRST_BYTE_READ_TIMEOUT` (300s — NetGet's own agent client connects and waits for a
//! person), `IDLE_BETWEEN_REQUESTS_TIMEOUT` (900s) and `MAX_CONNECTIONS` (256). The two read
//! bounds are declared startup parameters, so these tests set them short; what is asserted is
//! that each is applied to the state it names.
//!
//! * **A peer that connects and asks nothing is closed at the first-byte bound.** Remove the
//!   deadline around the read and the first test hangs until its own window expires.
//! * **Once a request has been answered, the idle bound governs, not the first-byte one.** The
//!   two are set the wrong way round on purpose.
//! * **A request whose answer is parked for a human keeps its connection open**, far past both
//!   bounds. Requests are answered inline, so the read is not polled while the answer is
//!   pending; this pins that the deadline wraps the read and nothing else. There is no guard to
//!   remove for this one — the property is the shape of the loop — so it is a regression pin
//!   against a deadline moved outward, not a mutation-verified bound.
//! * **The connection past `MAX_CONNECTIONS` reads EOF at once** (the protocol's only negative
//!   is an answer, so the refusal is a clean close), **and closing one admitted connection frees
//!   exactly one slot.**
//! * **Stopping the server unlinks its socket node**, so a client pointed at the path gets
//!   ENOENT ("no agent") rather than ECONNREFUSED. Remove the cleanup guard in `mod.rs` and the
//!   last test fails with the node still on disk.
//!
//! No mock backend: the LLM endpoint is a dead port and every rule is static or manual.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features ssh-agent --test server -- \
//!       ssh_agent::connection_bounds_test --test-threads=100

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

/// `uint32 length || byte type` — SSH_AGENTC_REQUEST_IDENTITIES.
const REQUEST_IDENTITIES: [u8; 5] = [0, 0, 0, 1, 11];

/// SSH_AGENT_FAILURE, framed.
const FAILURE: [u8; 5] = [0, 0, 0, 1, 5];

async fn new_state() -> AppState {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".to_string());
    state
        .set_llm_client(netget::llm::OllamaClient::new(
            "http://127.0.0.1:1".to_string(),
        ))
        .await;
    state
}

/// A model-free agent on a fresh socket path. Keep the returned `TempDir` alive for the test.
async fn start_server(
    state: &AppState,
    mut startup_params: serde_json::Value,
    event_handlers: Vec<serde_json::Value>,
) -> (ServerId, PathBuf, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("agent.sock");
    startup_params["socket_path"] = serde_json::json!(path.to_string_lossy());
    let (tx, _rx) = mpsc::unbounded_channel();
    let server_id = ServerForm {
        protocol: "ssh_agent".to_string(),
        port: None,
        instruction: Some(String::new()),
        startup_params: Some(startup_params),
        event_handlers: Some(event_handlers),
        ..Default::default()
    }
    .create(state, tx)
    .await
    .expect("create ssh_agent server");
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
async fn a_peer_that_connects_and_asks_nothing_is_closed_at_the_first_byte_bound() {
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
            "a peer that connected and asked nothing was still holding the socket — the \
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
async fn once_a_request_is_answered_the_idle_bound_governs() {
    let state = new_state().await;
    let (_, path, _dir) = start_server(
        &state,
        serde_json::json!({
            "first_byte_timeout_secs": 60,
            "idle_timeout_secs": SHORT_IDLE.as_secs(),
        }),
        vec![serde_json::json!({
            "event_pattern": "ssh_agent_request_identities",
            "handler": {"type": "static", "actions": [{"type": "send_failure"}]}
        })],
    )
    .await;

    let mut peer = UnixStream::connect(&path).await.expect("connect");
    peer.write_all(&REQUEST_IDENTITIES).await.expect("write");
    let mut reply = [0u8; 5];
    tokio::time::timeout(Duration::from_secs(20), peer.read_exact(&mut reply))
        .await
        .expect("the static rule did not answer within 20s")
        .expect("read reply");
    assert_eq!(reply, FAILURE, "the static rule did not answer");

    let elapsed = time_to_eof(&mut peer, Duration::from_secs(45))
        .await
        .expect("a connection that went quiet after an answer was never closed");
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
async fn a_request_whose_answer_is_parked_for_a_human_keeps_its_connection() {
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
    peer.write_all(&REQUEST_IDENTITIES).await.expect("write");

    // Well past both bounds, well inside the 600-second window the human has to answer in.
    let closed = time_to_eof(&mut peer, SHORT_IDLE * 4 + Duration::from_secs(8)).await;
    assert!(
        closed.is_none(),
        "the agent closed a connection whose request was parked for a human, after {:?} — the \
         deadline is covering the answer as well as the read",
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
        // The connection-opened event is answered with nothing, so no admitted connection
        // spends its life on a dead-port model call.
        vec![serde_json::json!({
            "event_pattern": "ssh_agent_connection_opened",
            "handler": {"type": "static", "actions": []}
        })],
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

#[tokio::test]
async fn stopping_the_server_unlinks_its_socket_node() {
    let state = new_state().await;
    let (id, path, _dir) = start_server(&state, serde_json::json!({}), Vec::new()).await;
    assert!(
        path.exists(),
        "the socket node exists while the server runs"
    );

    // Let the accept loop run first: a stop arrives at a server that is serving, and a task
    // aborted before its first poll drops its captures without ever running.
    tokio::time::sleep(Duration::from_millis(100)).await;
    state.remove_server(id).await;

    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while path.exists() {
        assert!(
            std::time::Instant::now() < deadline,
            "{} is still on disk 10s after the server stopped",
            path.display()
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

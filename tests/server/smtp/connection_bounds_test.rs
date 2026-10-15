//! The connection cap on a real, running SMTP server, driven from the wire.
//!
//! `READ_TIMEOUT` is 300 seconds, which is RFC 5321 §4.5.3.2's own server-side command timeout
//! — so one stranger legitimately holds a socket, a task and an `AppState` row for five minutes.
//! Until September 2026 nothing bounded how many such strangers there could be: this accept loop
//! admitted every connection offered to it, and five minutes multiplied by an unbounded number
//! of connections is not a bound. A mail server is the canonical target for this, which is why
//! every real MTA ships a connection limit of its own.
//!
//! Three claims, and the second is where SMTP differs from everything else in this sweep:
//!
//! 1. `MAX_CONNECTIONS` peers are admitted.
//! 2. The next one is refused with a **421 greeting**. SMTP is server-speaks-first, so a refusal
//!    has a natural place: RFC 5321 §3.1 and §4.3.2 let the server open with something other
//!    than 220, and 421 — "Service not available, closing transmission channel" — is precisely
//!    this case. Postfix answers its own connection-count limit with a 421 greeting, so every
//!    MTA in the world already backs off on it rather than recording a permanent failure.
//! 3. Closing an admitted connection **frees exactly one slot**. A permit dropped before the
//!    connection ends un-caps the server silently; one never released wedges it shut after
//!    `MAX_CONNECTIONS` peers have ever connected.
//!
//! **How this was proved to fail without the cap**: replace the `accept_bounded` call in
//! `src/server/smtp/mod.rs` with a bare `listener.accept().await` (and drop the permit from the
//! connection task). The over-cap peer is then admitted and greeted with the static handler's
//! `220`, and the test fails on the 421 assertion.
//!
//! **The server here is model-free and has to be**, which is not true of most files in this
//! sweep. SMTP greets the peer, so every one of the 256 connections filling the cap would
//! otherwise be an LLM call against a dead endpoint — slow, and it would make the *admitted*
//! reply a `421 4.3.0 Service not available` that this test could not tell apart from the
//! refusal. A static `send_smtp_greeting` handler makes an admitted connection unambiguously a
//! `220`. Loopback only.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features smtp --test server -- smtp::connection_bounds --test-threads=100

use std::time::Duration;

use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use netget::state::ServerId;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::sync::mpsc;

/// `src/server/smtp/mod.rs::MAX_CONNECTIONS`. Deliberately duplicated rather than imported: if
/// the constant moves, this test should be re-read rather than silently follow it.
const MAX_CONNECTIONS: usize = 256;

/// `src/server/smtp/mod.rs::CONNECTION_CAP_REFUSAL`, byte for byte.
const CONNECTION_CAP_REFUSAL: &[u8] = b"421 4.3.2 Too many connections, try again later\r\n";

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
    panic!("SMTP server #{} never bound a port", id.as_u32());
}

async fn start_server(state: &AppState) -> (ServerId, u16) {
    let (tx, _rx) = mpsc::unbounded_channel();
    let server_id = ServerForm {
        protocol: "smtp".to_string(),
        port: Some(0),
        // An empty instruction really is model-free; `None` is replaced by a default one and
        // every event would consult the LLM.
        instruction: Some(String::new()),
        event_handlers: Some(vec![serde_json::json!({
            "event_pattern": "*",
            "handler": {
                "type": "static",
                "actions": [{"type": "send_smtp_greeting", "hostname": "cap.test.invalid"}]
            }
        })]),
        ..Default::default()
    }
    .create(state, tx)
    .await
    .expect("create smtp server");
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

/// Read whatever the server says first, with a bound.
async fn read_reply(stream: &mut TcpStream, window: Duration) -> Option<String> {
    let mut buf = [0u8; 256];
    match tokio::time::timeout(window, stream.read(&mut buf)).await {
        Ok(Ok(0)) => Some(String::new()),
        Ok(Ok(n)) => Some(String::from_utf8_lossy(&buf[..n]).to_string()),
        Ok(Err(_)) | Err(_) => None,
    }
}

#[tokio::test]
async fn the_connection_past_the_cap_gets_a_421_greeting_and_the_slot_comes_back() {
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
        refusal,
        CONNECTION_CAP_REFUSAL,
        "the peer over the cap must be greeted with 421 and then closed — a transient refusal \
         every MTA backs off on — rather than dropped in silence or greeted with 220. Got {:?}",
        String::from_utf8_lossy(&refusal)
    );

    drop(held.pop().expect("one held connection"));

    let mut admitted = false;
    for _ in 0..100 {
        let mut candidate = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("connect after freeing a slot");
        match read_reply(&mut candidate, Duration::from_secs(5)).await {
            // SMTP speaks first, so an admitted connection is the one that gets a 220 greeting
            // from the static handler; the refusal is the 421.
            Some(reply) if reply.starts_with("220") => {
                admitted = true;
                break;
            }
            _ => {
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

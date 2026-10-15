//! The connection cap on a real, running IPP server, driven from the wire.
//!
//! An IPP connection is worth more than most in this tree: `MAX_IPP_BODY_BYTES` is 8 MiB of
//! print job the server will buffer for one peer. That is a per-connection bound, and until
//! September 2026 nothing multiplied it by a finite number — this accept loop admitted every
//! connection offered to it, pre-authentication.
//!
//! Three claims, and the second is the interesting one:
//!
//! 1. `MAX_CONNECTIONS` peers are admitted.
//! 2. The next one is refused with **HTTP 503 + `Retry-After`**, not with an IPP status. IPP has
//!    `server-error-busy` (0x0507) of its own, but every IPP status rides in an
//!    `application/ipp` body answering a specific operation and echoing that operation's
//!    `request-id` — and a peer over the cap has not sent an operation, so there is no
//!    request-id to echo and nothing to say `server-error-busy` *about*. CUPS reads the version,
//!    operation and request-id back out and would report a protocol error rather than backing
//!    off. RFC 8010 makes HTTP the transport, so 503 is inside the protocol.
//! 3. Closing an admitted connection **frees exactly one slot**. A permit dropped before the
//!    connection ends un-caps the server silently; one never released wedges it shut after
//!    `MAX_CONNECTIONS` peers have ever connected.
//!
//! **How this was proved to fail without the cap**: replace the `accept_bounded` call in
//! `src/server/ipp/mod.rs` with a bare `listener.accept().await` (and drop the permit from the
//! connection task). The over-cap peer is then handed to hyper, which answers nothing until a
//! request arrives — so the `read_to_end` times out and the test fails on "was neither answered
//! nor closed".
//!
//! Loopback only.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features ipp --test server -- ipp::connection_bounds --test-threads=100


use std::time::Duration;

use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use netget::state::ServerId;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::sync::mpsc;

/// `src/server/ipp/mod.rs::MAX_CONNECTIONS`. Deliberately duplicated rather than imported: if
/// the constant moves, this test should be re-read rather than silently follow it.
const MAX_CONNECTIONS: usize = 256;

/// The body of `src/server/ipp/mod.rs::CONNECTION_CAP_REFUSAL`.
const CONNECTION_CAP_BODY: &str = "Too many connections, try again later.\n";

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
    panic!("IPP server #{} never bound a port", id.as_u32());
}

async fn start_server(state: &AppState) -> (ServerId, u16) {
    let (tx, _rx) = mpsc::unbounded_channel();
    let server_id = ServerForm {
        protocol: "ipp".to_string(),
        port: Some(0),
        // An empty instruction really is model-free; `None` is replaced by a default one and
        // every event would consult the LLM.
        instruction: Some(String::new()),
        ..Default::default()
    }
    .create(state, tx)
    .await
    .expect("create ipp server");
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
async fn the_connection_past_the_cap_gets_an_http_503_not_an_ipp_status_and_the_slot_comes_back() {
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
    let refusal = String::from_utf8_lossy(&refusal).to_string();
    assert!(
        refusal.starts_with("HTTP/1.1 503 Service Unavailable\r\n"),
        "the peer over the cap must get HTTP's own 'come back later', not a silent drop and not \
         a 500 it would record as a permanent fault. Got {refusal:?}"
    );
    assert!(
        refusal.contains("Retry-After:"),
        "503 without Retry-After leaves a client guessing how long to wait; this server's \
         overload path already sends the pair. Got {refusal:?}"
    );
    assert!(
        refusal.contains(CONNECTION_CAP_BODY),
        "the refusal must carry the declared body, built rather than written out so \
         Content-Length cannot drift from it. Got {refusal:?}"
    );

    drop(held.pop().expect("one held connection"));

    let mut admitted = false;
    for _ in 0..100 {
        let mut candidate = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("connect after freeing a slot");
        let mut buf = [0u8; 64];
        match tokio::time::timeout(Duration::from_millis(300), candidate.read(&mut buf)).await {
            // IPP is client-speaks-first: silence means hyper has this connection and is waiting for a request.
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

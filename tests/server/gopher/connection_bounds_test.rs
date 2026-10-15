//! The connection cap on a real, running Gopher server, driven from the wire.
//!
//! `SELECTOR_READ_TIMEOUT` bounds how long *one* connected-but-silent peer holds a socket, a
//! task and an `AppState` row. It says nothing about how many such peers there can be at once,
//! and until September 2026 this accept loop admitted every connection offered to it.
//!
//! Three claims, and the third is the one that catches the subtle bug:
//!
//! 1. `MAX_CONNECTIONS` peers are admitted.
//! 2. The next one is refused with a **type-3 error item** — RFC 1436's own way of saying "this
//!    did not work", and the same shape `gopher_error_item` writes for every other refusal here
//!    — followed by the `.` terminator and EOF. A menu client renders it as an error line;
//!    `curl`, which reads until EOF, prints it and exits 0 rather than 28.
//! 3. Closing an admitted connection **frees exactly one slot**. A permit dropped before the
//!    connection ends un-caps the server silently; one never released wedges it shut after
//!    `MAX_CONNECTIONS` peers have ever connected.
//!
//! **How this was proved to fail without the cap**: replace the `accept_bounded` call in
//! `src/server/gopher/mod.rs` with a bare `listener.accept().await` (and drop the permit from
//! the connection task). The test then reads nothing from the over-cap peer and fails on the
//! refusal assertion.
//!
//! The server is model-free: an empty instruction really is model-free, where `None` is replaced
//! by a default one. Gopher is client-speaks-first, so a silent peer provokes no model call.
//! Loopback only.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features gopher --test server -- gopher::connection_bounds --test-threads=100

use std::time::Duration;

use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use netget::state::ServerId;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::sync::mpsc;

/// `src/server/gopher/mod.rs::MAX_CONNECTIONS`. Deliberately duplicated rather than imported:
/// if the constant moves, this test should be re-read rather than silently follow it.
const MAX_CONNECTIONS: usize = 256;

/// `src/server/gopher/mod.rs::CONNECTION_CAP_REFUSAL`, byte for byte.
const CONNECTION_CAP_REFUSAL: &[u8] =
    b"3Too many connections, try again later\t\terror.host\t1\r\n.\r\n";

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
    panic!("Gopher server #{} never bound a port", id.as_u32());
}

async fn start_server(state: &AppState) -> (ServerId, u16) {
    let (tx, _rx) = mpsc::unbounded_channel();
    let server_id = ServerForm {
        protocol: "gopher".to_string(),
        port: Some(0),
        instruction: Some(String::new()),
        ..Default::default()
    }
    .create(state, tx)
    .await
    .expect("create gopher server");
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
async fn the_connection_past_the_cap_gets_a_type_3_error_item_and_the_slot_comes_back() {
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
        "the peer over the cap must read a type-3 error item and then EOF; a silent drop leaves \
         a client unable to tell a full server from a crashed one. Got {:?}",
        String::from_utf8_lossy(&refusal)
    );

    drop(held.pop().expect("one held connection"));

    let mut admitted = false;
    for _ in 0..100 {
        let mut candidate = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("connect after freeing a slot");
        let mut buf = [0u8; 64];
        match tokio::time::timeout(Duration::from_millis(300), candidate.read(&mut buf)).await {
            // Gopher is client-speaks-first: silence means this peer was admitted and is
            // waiting for its selector line.
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

//! The dashboard's "message this peer" / "disconnect this peer" path on a Memcached server
//! connection: `AppState::send_to_peer` injects a wire action into one live connection and
//! the bytes reach the socket. Zero LLM calls — the injected actions are executed by the
//! protocol's own executor, and the client sends no command, so the LLM is never consulted.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features memcached --test server -- memcached::peer_inject --test-threads=100


use std::time::Duration;

use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use netget::state::client_handles::ClientSendOutcome;
use netget::state::ServerId;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

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
    for _ in 0..100 {
        if let Some(s) = state.get_server(id).await {
            if let Some(addr) = s.local_addr {
                return addr.port();
            }
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("Memcached server #{} never bound a port", id.as_u32());
}

/// The first connection that has a peer handle registered.
async fn wait_for_peer_handle(state: &AppState, id: ServerId) -> u32 {
    for _ in 0..100 {
        if let Some(s) = state.get_server(id).await {
            for conn in s.connections.values() {
                if state.has_peer_handle(id, conn.id.as_u32()).await {
                    return conn.id.as_u32();
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!(
        "Memcached server #{} never registered a peer handle",
        id.as_u32()
    );
}

#[tokio::test]
async fn injected_memcached_action_reaches_raw_socket_and_close_sends_eof() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    // No event handlers: the client sends nothing, so no event ever fires and the LLM is
    // never called. Everything below is driven purely by send_to_peer.
    let server_id = ServerForm {
        protocol: "memcached".to_string(),
        port: Some(0),
        ..Default::default()
    }
    .create(&state, tx.clone())
    .await
    .expect("create memcached server");
    let port = wait_for_port(&state, server_id).await;

    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .expect("connect");

    // The peer handle is registered the moment the connection is accepted — memcached has no
    // greeting, so nothing needs to be sent first.
    let conn = wait_for_peer_handle(&state, server_id).await;

    // A wire verb, injected from outside the connection task. "VERSION 1.6.45\r\n" == 16 bytes.
    let outcome = state
        .send_to_peer(
            server_id,
            conn,
            serde_json::json!({"type": "send_memcached_version", "version": "1.6.45"}),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_peer");
    assert!(
        matches!(outcome, ClientSendOutcome::Sent { bytes_sent: 16 }),
        "expected Sent{{16}}, got {outcome:?}"
    );

    let mut buf = [0u8; 32];
    let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf))
        .await
        .expect("injected bytes within 5s")
        .expect("read injected bytes");
    assert_eq!(&buf[..n], b"VERSION 1.6.45\r\n");

    // Injected writes ARE counted: `src/server/peer_support.rs` calls
    // `update_connection_stats` on `ClientSendOutcome::Sent`. (This comment used to claim the
    // opposite; `tests/server/redis/peer_inject_test.rs` asserts the counters move for
    // exactly this path.) Not asserted here because this connection has never been read
    // from, so only the injected write would show — the e2e suite covers the read side.

    // "disconnect this peer": the dashboard injects {"type":"close_connection"}, which the
    // executor maps to CloseConnection; the peer task half-closes and the socket reads EOF.
    let outcome = state
        .send_to_peer(
            server_id,
            conn,
            serde_json::json!({"type": "close_connection"}),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_peer close");
    assert!(
        matches!(outcome, ClientSendOutcome::Disconnected),
        "expected Disconnected, got {outcome:?}"
    );

    let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf))
        .await
        .expect("EOF within 5s")
        .expect("read after close");
    assert_eq!(n, 0, "expected EOF after close_connection");

    // Draining the write half fully: further writes from us are irrelevant, but the peer
    // handle must go away with the connection.
    let _ = stream.shutdown().await;
    for _ in 0..100 {
        if !state.has_peer_handle(server_id, conn).await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("peer handle still registered after the connection closed");
}

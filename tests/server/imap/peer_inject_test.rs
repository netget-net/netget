//! The dashboard's "message this peer" / "disconnect this peer" path on an IMAP server
//! connection: `AppState::send_to_peer` injects a wire action into one live connection and
//! the bytes reach the socket. Zero LLM calls - the greeting comes from a `*` static handler.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features imap --test server -- imap::peer_inject --test-threads=100

use std::time::Duration;

use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use netget::state::client_handles::ClientSendOutcome;
use netget::state::ServerId;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
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
    panic!("IMAP server #{} never bound a port", id.as_u32());
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
        "IMAP server #{} never registered a peer handle",
        id.as_u32()
    );
}

#[tokio::test]
async fn injected_imap_action_reaches_raw_socket_and_close_sends_eof() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    // A `*` static handler answers the greeting (IMAP_CONNECTION_EVENT) with an untagged
    // banner, so no LLM is contacted at any point.
    let server_id = ServerForm {
        protocol: "imap".to_string(),
        port: Some(0),
        event_handlers: Some(vec![serde_json::json!({
            "event_pattern": "*",
            "handler": {
                "type": "static",
                "actions": [ {
                    "type": "send_imap_response",
                    "response": "* OK [CAPABILITY IMAP4rev1] netget ready"
                } ]
            }
        })]),
        ..Default::default()
    }
    .create(&state, tx.clone())
    .await
    .expect("create imap server");
    let port = wait_for_port(&state, server_id).await;

    let stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .expect("connect");
    let mut reader = BufReader::new(stream);

    let mut line = String::new();
    tokio::time::timeout(Duration::from_secs(5), reader.read_line(&mut line))
        .await
        .expect("greeting within 5s")
        .expect("read greeting");
    assert_eq!(line, "* OK [CAPABILITY IMAP4rev1] netget ready\r\n");

    let conn = wait_for_peer_handle(&state, server_id).await;

    // A wire verb, injected from outside the connection task.
    let outcome = state
        .send_to_peer(
            server_id,
            conn,
            serde_json::json!({
                "type": "send_imap_response",
                "response": "* OK injected untagged"
            }),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_peer");
    assert!(
        matches!(outcome, ClientSendOutcome::Sent { .. }),
        "expected Sent, got {outcome:?}"
    );

    line.clear();
    tokio::time::timeout(Duration::from_secs(5), reader.read_line(&mut line))
        .await
        .expect("injected line within 5s")
        .expect("read injected line");
    assert_eq!(line, "* OK injected untagged\r\n");

    // Counters moved: the greeting and the injected line were both counted as writes.
    let server = state.get_server(server_id).await.expect("server");
    let conn_state = server
        .connections
        .values()
        .find(|c| c.id.as_u32() == conn)
        .expect("connection tracked");
    assert!(
        conn_state.bytes_sent >= 41,
        "bytes_sent should count the greeting, got {}",
        conn_state.bytes_sent
    );

    // "disconnect this peer": half-close from outside, the socket reads EOF.
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

    let mut buf = [0u8; 16];
    let n = tokio::time::timeout(Duration::from_secs(5), reader.read(&mut buf))
        .await
        .expect("EOF within 5s")
        .expect("read after close");
    assert_eq!(n, 0, "expected EOF after close_connection");

    // The handle goes away with the connection.
    for _ in 0..100 {
        if !state.has_peer_handle(server_id, conn).await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("peer handle still registered after the connection closed");
}

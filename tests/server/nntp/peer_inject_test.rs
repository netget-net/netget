//! The dashboard's "message this peer" / "disconnect this peer" path on an NNTP server
//! connection: `AppState::send_to_peer` injects a wire action into one live connection and
//! the bytes reach the socket. Zero LLM calls - the greeting comes from a `*` static handler.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features nntp --test server -- nntp::peer_inject --test-threads=100


use std::time::Duration;

use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use netget::state::client_handles::ClientSendOutcome;
use netget::state::ServerId;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
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
    panic!("NNTP server #{} never bound a port", id.as_u32());
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
        "NNTP server #{} never registered a peer handle",
        id.as_u32()
    );
}

#[tokio::test]
async fn injected_nntp_action_reaches_raw_socket_and_close_sends_eof() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    let server_id = ServerForm {
        protocol: "nntp".to_string(),
        port: Some(0),
        event_handlers: Some(vec![serde_json::json!({
            "event_pattern": "*",
            "handler": {
                "type": "static",
                "actions": [ { "type": "send_nntp_response", "code": 200, "text": "static ready" } ]
            }
        })]),
        ..Default::default()
    }
    .create(&state, tx.clone())
    .await
    .expect("create nntp server");
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
    assert_eq!(line, "200 static ready\r\n");

    let conn = wait_for_peer_handle(&state, server_id).await;

    // A wire verb, injected from outside the connection task.
    let outcome = state
        .send_to_peer(
            server_id,
            conn,
            serde_json::json!({"type": "send_nntp_response", "code": 111, "text": "injected"}),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_peer");
    assert!(
        matches!(outcome, ClientSendOutcome::Sent { bytes_sent: 14 }),
        "expected Sent{{14}}, got {outcome:?}"
    );

    line.clear();
    tokio::time::timeout(Duration::from_secs(5), reader.read_line(&mut line))
        .await
        .expect("injected line within 5s")
        .expect("read injected line");
    assert_eq!(line, "111 injected\r\n");

    // A command from the socket is counted as a read and answered by the static handler.
    reader
        .get_mut()
        .write_all(b"HELP\r\n")
        .await
        .expect("write command");
    line.clear();
    tokio::time::timeout(Duration::from_secs(5), reader.read_line(&mut line))
        .await
        .expect("reply within 5s")
        .expect("read reply");
    assert_eq!(line, "200 static ready\r\n");

    // Counters moved in both directions: the greeting and the static reply (the generic peer
    // task does not count injected writes), and the 6-byte command. (Not MODE READER: NetGet
    // answers that itself, so it would never reach the static handler.)
    let mut counted = false;
    for _ in 0..100 {
        let server = state.get_server(server_id).await.expect("server");
        let conn_state = server
            .connections
            .values()
            .find(|c| c.id.as_u32() == conn)
            .expect("connection tracked");
        if conn_state.bytes_sent >= 18 + 18 && conn_state.bytes_received >= 6 {
            counted = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    assert!(counted, "connection counters did not move");

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

    // The handle goes away with the connection once the client side closes too.
    drop(reader);
    for _ in 0..100 {
        if !state.has_peer_handle(server_id, conn).await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("peer handle still registered after the connection closed");
}

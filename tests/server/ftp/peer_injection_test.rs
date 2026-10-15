//! Dashboard injection into ONE live FTP control connection (`AppState::send_to_peer`).
//!
//! Zero LLM calls: the server answers every event through a static handler, the peer is a
//! raw tokio socket, and the bytes are asserted on that socket. Also proves connection
//! counters move, which the rail shows as `↓ ↑`.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features ftp --test server -- ftp::peer_injection --test-threads=100


use std::time::Duration;

use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use netget::state::client_handles::ClientSendOutcome;
use netget::state::ServerId;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
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
            if s.port != 0 {
                return s.port;
            }
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("server #{} never bound a port", id.as_u32());
}

/// Wait until the server lists one connection that has a peer handle; return its id.
async fn wait_for_peer_handle(state: &AppState, id: ServerId) -> u32 {
    for _ in 0..100 {
        if let Some(s) = state.get_server(id).await {
            for conn in s.connections.keys() {
                if state.has_peer_handle(id, conn.as_u32()).await {
                    return conn.as_u32();
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("server #{} never registered a peer handle", id.as_u32());
}

#[tokio::test]
async fn injected_ftp_response_reaches_raw_peer_and_close_sends_eof() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    // Static 220 on the greeting sentinel, and 200 on every other line.
    let server_id = ServerForm {
        protocol: "ftp".to_string(),
        port: Some(0),
        event_handlers: Some(vec![serde_json::json!({
            "event_pattern": "*",
            "handler": {
                "type": "static",
                "actions": [ { "type": "send_ftp_response", "code": 220, "message": "static ready" } ]
            }
        })]),
        ..Default::default()
    }
    .create(&state, tx.clone())
    .await
    .expect("create ftp server");
    let port = wait_for_port(&state, server_id).await;

    let stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    let (read_half, mut write_half) = tokio::io::split(stream);
    let mut reader = BufReader::new(read_half);

    let mut line = String::new();
    reader.read_line(&mut line).await.expect("greeting");
    assert_eq!(line, "220 static ready\r\n");

    let conn = wait_for_peer_handle(&state, server_id).await;

    // A line from the peer bumps the inbound counters.
    write_half.write_all(b"NOOP\r\n").await.unwrap();
    line.clear();
    reader.read_line(&mut line).await.expect("noop reply");
    assert_eq!(line, "220 static ready\r\n");

    // Inject a reply from the dashboard side.
    let outcome = state
        .send_to_peer(
            server_id,
            conn,
            serde_json::json!({"type": "send_ftp_response", "code": 230, "message": "injected"}),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_peer");
    let expected = "230 injected\r\n";
    match outcome {
        ClientSendOutcome::Sent { bytes_sent } => assert_eq!(bytes_sent, expected.len()),
        other => panic!("expected Sent, got {other:?}"),
    }
    line.clear();
    reader.read_line(&mut line).await.expect("injected reply");
    assert_eq!(line, expected);

    // Counters moved in both directions (greeting + NOOP reply + injected = 3 writes).
    let server = state.get_server(server_id).await.unwrap();
    let c = server
        .connections
        .values()
        .find(|c| c.id.as_u32() == conn)
        .expect("connection row");
    assert!(c.bytes_received >= "NOOP\r\n".len() as u64, "{c:?}");
    assert!(c.packets_received >= 1, "{c:?}");
    assert!(
        c.bytes_sent >= (2 * "220 static ready\r\n".len()) as u64,
        "{c:?}"
    );
    assert!(c.packets_sent >= 2, "{c:?}");

    // Disconnect this peer: the socket reads EOF and the handle goes away.
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
        "{outcome:?}"
    );

    let mut rest = Vec::new();
    let n = tokio::time::timeout(Duration::from_secs(5), reader.read_to_end(&mut rest))
        .await
        .expect("EOF within 5s")
        .expect("read_to_end");
    assert_eq!(n, 0, "unexpected trailing bytes: {rest:?}");

    for _ in 0..100 {
        if !state.has_peer_handle(server_id, conn).await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("peer handle still registered after close_connection");
}

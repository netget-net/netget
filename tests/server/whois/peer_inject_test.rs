//! The dashboard's "message this peer" / "disconnect this peer" path on a WHOIS server
//! connection: `AppState::send_to_peer` injects a wire action into one live connection and
//! the bytes reach the socket. Zero LLM calls - the server's own answer comes from a `*`
//! static handler, and the injected actions never touch the model.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features whois --test server -- whois::peer_inject --test-threads=100

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
    panic!("WHOIS server #{} never bound a port", id.as_u32());
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
        "WHOIS server #{} never registered a peer handle",
        id.as_u32()
    );
}

#[tokio::test]
async fn injected_whois_action_reaches_raw_socket_and_close_sends_eof() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    // The static answer deliberately omits close_connection so the connection stays open
    // for the injected close below.
    let server_id = ServerForm {
        protocol: "whois".to_string(),
        port: Some(0),
        event_handlers: Some(vec![serde_json::json!({
            "event_pattern": "*",
            "handler": {
                "type": "static",
                "actions": [ { "type": "send_whois_response", "response": "static answer" } ]
            }
        })]),
        ..Default::default()
    }
    .create(&state, tx.clone())
    .await
    .expect("create whois server");
    let port = wait_for_port(&state, server_id).await;

    let stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .expect("connect");
    let mut reader = BufReader::new(stream);

    // A WHOIS server says nothing until asked, so the handle must exist before any traffic.
    let conn = wait_for_peer_handle(&state, server_id).await;

    // A wire verb, injected from outside the connection task, before the peer has spoken.
    let outcome = state
        .send_to_peer(
            server_id,
            conn,
            serde_json::json!({"type": "send_whois_response", "response": "injected"}),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_peer");
    assert!(
        matches!(outcome, ClientSendOutcome::Sent { bytes_sent: 10 }),
        "expected Sent{{10}}, got {outcome:?}"
    );

    let mut line = String::new();
    tokio::time::timeout(Duration::from_secs(5), reader.read_line(&mut line))
        .await
        .expect("injected line within 5s")
        .expect("read injected line");
    assert_eq!(line, "injected\r\n");

    // The protocol's own path still works alongside, and is counted.
    reader
        .get_mut()
        .write_all(b"example.com\r\n")
        .await
        .expect("write query");
    line.clear();
    tokio::time::timeout(Duration::from_secs(5), reader.read_line(&mut line))
        .await
        .expect("static answer within 5s")
        .expect("read static answer");
    assert_eq!(line, "static answer\r\n");

    let server = state.get_server(server_id).await.expect("server");
    let conn_state = server
        .connections
        .values()
        .find(|c| c.id.as_u32() == conn)
        .expect("connection tracked");
    // The protocol's own reply is counted. (The generic peer task in peer_support.rs does not
    // update the counters for injected writes, so the 10 injected bytes are not included.)
    assert!(
        conn_state.bytes_sent >= 15,
        "bytes_sent should count the static reply, got {}",
        conn_state.bytes_sent
    );
    assert_eq!(conn_state.bytes_received, 13, "query bytes counted");

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

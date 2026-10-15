//! The dashboard's "disconnect this peer" path on a Modbus TCP server connection:
//! `AppState::send_to_peer` injects an action into one live connection. Zero LLM calls -
//! the one request is answered by a `*` static handler.
//!
//! Modbus's four wire verbs are request-bound `ActionResult::Custom` results, so an
//! injected one is reported as executed without writing; `close_connection` is the
//! generic path that does reach the wire (half-close, the peer reads EOF).
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features modbus --test server -- modbus::peer_inject --test-threads=100

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
    panic!("Modbus server #{} never bound a port", id.as_u32());
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
        "Modbus server #{} never registered a peer handle",
        id.as_u32()
    );
}

#[tokio::test]
async fn injected_close_connection_sends_eof_and_counters_move() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    let server_id = ServerForm {
        protocol: "modbus".to_string(),
        port: Some(0),
        event_handlers: Some(vec![serde_json::json!({
            "event_pattern": "*",
            "handler": {
                "type": "static",
                "actions": [ { "type": "send_modbus_registers", "values": [1834, 1450] } ]
            }
        })]),
        ..Default::default()
    }
    .create(&state, tx.clone())
    .await
    .expect("create modbus server");
    let port = wait_for_port(&state, server_id).await;

    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .expect("connect");

    let conn = wait_for_peer_handle(&state, server_id).await;

    // Read Holding Registers, unit 1, start 0, quantity 2: txid=0x0102.
    let request: [u8; 12] = [
        0x01, 0x02, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x02,
    ];
    stream.write_all(&request).await.expect("write request");

    // MBAP(7) + fc(1) + byte count(1) + 2 registers(4) = 13 bytes.
    let mut response = [0u8; 13];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut response))
        .await
        .expect("response within 5s")
        .expect("read response");
    assert_eq!(
        response,
        [0x01, 0x02, 0x00, 0x00, 0x00, 0x07, 0x01, 0x03, 0x04, 0x07, 0x2A, 0x05, 0xAA]
    );

    // Counters moved on both directions.
    let server = state.get_server(server_id).await.expect("server");
    let conn_state = server
        .connections
        .values()
        .find(|c| c.id.as_u32() == conn)
        .expect("connection tracked");
    assert_eq!(conn_state.bytes_received, 12);
    assert_eq!(conn_state.bytes_sent, 13);
    assert_eq!(conn_state.packets_received, 1);
    assert_eq!(conn_state.packets_sent, 1);

    // A Modbus wire verb is request-bound: injected, it is executed but writes nothing.
    let outcome = state
        .send_to_peer(
            server_id,
            conn,
            serde_json::json!({"type": "send_modbus_write_ack"}),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_peer write_ack");
    assert!(
        matches!(outcome, ClientSendOutcome::Executed { .. }),
        "expected Executed, got {outcome:?}"
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
    let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf))
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

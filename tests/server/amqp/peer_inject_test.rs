//! The dashboard's "message this peer" / "disconnect this peer" path on an AMQP broker
//! connection: `AppState::send_to_peer` injects a wire action into one live connection and
//! the frame reaches the socket. Zero LLM calls - the connection never gets past the
//! protocol header, and the `*` static handler would answer it anyway.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features amqp --test server -- amqp::peer_inject --test-threads=100

use std::time::Duration;

use netget::cli::management::ServerForm;
use netget::server::amqp::codec::{
    CLASS_CONNECTION, CONNECTION_CLOSE, CONNECTION_START, FRAME_END, FRAME_METHOD,
    PROTOCOL_HEADER_091,
};
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
    panic!("AMQP server #{} never bound a port", id.as_u32());
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
        "AMQP server #{} never registered a peer handle",
        id.as_u32()
    );
}

/// Read one AMQP frame off a raw socket: (type, channel, payload).
async fn read_frame(stream: &mut TcpStream) -> (u8, u16, Vec<u8>) {
    let mut header = [0u8; 7];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut header))
        .await
        .expect("frame header within 5s")
        .expect("read frame header");
    let size = u32::from_be_bytes([header[3], header[4], header[5], header[6]]) as usize;
    let mut payload = vec![0u8; size];
    stream.read_exact(&mut payload).await.expect("read payload");
    let mut end = [0u8; 1];
    stream.read_exact(&mut end).await.expect("read frame end");
    assert_eq!(end[0], FRAME_END);
    (
        header[0],
        u16::from_be_bytes([header[1], header[2]]),
        payload,
    )
}

#[tokio::test]
async fn injected_amqp_action_reaches_raw_socket_and_close_sends_eof() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    let server_id = ServerForm {
        protocol: "amqp".to_string(),
        port: Some(0),
        event_handlers: Some(vec![serde_json::json!({
            "event_pattern": "*",
            "handler": {
                "type": "static",
                "actions": [ { "type": "amqp_connection_open_ok" } ]
            }
        })]),
        ..Default::default()
    }
    .create(&state, tx.clone())
    .await
    .expect("create amqp server");
    let port = wait_for_port(&state, server_id).await;

    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .expect("connect");
    stream
        .write_all(&PROTOCOL_HEADER_091)
        .await
        .expect("write protocol header");

    // Connection.Start proves the broker is talking to this socket.
    let (frame_type, channel, payload) = read_frame(&mut stream).await;
    assert_eq!(frame_type, FRAME_METHOD);
    assert_eq!(channel, 0);
    assert_eq!(
        u16::from_be_bytes([payload[0], payload[1]]),
        CLASS_CONNECTION
    );
    assert_eq!(
        u16::from_be_bytes([payload[2], payload[3]]),
        CONNECTION_START
    );

    let conn = wait_for_peer_handle(&state, server_id).await;

    // A wire verb, injected from outside the connection task. AMQP actions write their
    // frames through the connection's writer channel and return ActionResult::Custom, so
    // the outcome is Executed (not Sent) - the bytes still reach the socket.
    let outcome = state
        .send_to_peer(
            server_id,
            conn,
            serde_json::json!({
                "type": "amqp_connection_close",
                "reply_code": 320,
                "reply_text": "CONNECTION_FORCED - injected"
            }),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_peer");
    assert!(
        matches!(outcome, ClientSendOutcome::Executed { .. }),
        "expected Executed, got {outcome:?}"
    );

    let (frame_type, channel, payload) = read_frame(&mut stream).await;
    assert_eq!(frame_type, FRAME_METHOD);
    assert_eq!(channel, 0);
    assert_eq!(
        u16::from_be_bytes([payload[0], payload[1]]),
        CLASS_CONNECTION
    );
    assert_eq!(
        u16::from_be_bytes([payload[2], payload[3]]),
        CONNECTION_CLOSE
    );
    assert_eq!(u16::from_be_bytes([payload[4], payload[5]]), 320);
    let text_len = payload[6] as usize;
    assert_eq!(&payload[7..7 + text_len], b"CONNECTION_FORCED - injected");

    // Counters moved in both directions: the protocol header was counted as a read, and
    // Connection.Start plus the injected Connection.Close as writes.
    let mut counted = false;
    for _ in 0..100 {
        let server = state.get_server(server_id).await.expect("server");
        let conn_state = server
            .connections
            .values()
            .find(|c| c.id.as_u32() == conn)
            .expect("connection tracked");
        if conn_state.bytes_received >= 8 && conn_state.packets_sent >= 2 {
            counted = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    assert!(counted, "connection counters never reflected the traffic");

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
    drop(stream);
    for _ in 0..100 {
        if !state.has_peer_handle(server_id, conn).await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("peer handle still registered after the connection closed");
}

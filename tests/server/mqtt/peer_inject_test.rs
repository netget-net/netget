//! The dashboard's "message this peer" / "disconnect this peer" path on an MQTT server
//! connection: `AppState::send_to_peer` injects a wire action into one live connection and
//! the bytes reach the socket. Zero LLM calls - the peer handle is registered as soon as the
//! TCP connection is accepted, before any CONNECT, so nothing needs a model.
//!
//! MQTT's wire verbs (mqtt_publish, ...) write through the connection's own out channel and
//! return `ActionResult::Custom`, so the generic peer task reports `Executed` (not
//! `Sent{bytes}`) even though the bytes do reach the wire - hence the assertions read the
//! socket and the counters rather than trusting the outcome's byte count.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features mqtt --test server -- mqtt::peer_inject --test-threads=100


use std::time::Duration;

use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use netget::state::client_handles::ClientSendOutcome;
use netget::state::ServerId;
use tokio::io::AsyncReadExt;
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
    panic!("MQTT server #{} never bound a port", id.as_u32());
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
        "MQTT server #{} never registered a peer handle",
        id.as_u32()
    );
}

#[tokio::test]
async fn injected_mqtt_publish_reaches_raw_socket_and_close_sends_eof() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    let server_id = ServerForm {
        protocol: "mqtt".to_string(),
        port: Some(0),
        ..Default::default()
    }
    .create(&state, tx.clone())
    .await
    .expect("create mqtt server");
    let port = wait_for_port(&state, server_id).await;

    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .expect("connect");

    // The handle exists as soon as the connection is accepted - no CONNECT required.
    let conn = wait_for_peer_handle(&state, server_id).await;

    // A broker-originated PUBLISH, injected from outside the connection task. MQTT actions
    // return a Custom result (bytes go out through the connection's own channel), so the
    // reported outcome is Executed, not Sent - the wire is the source of truth.
    let outcome = state
        .send_to_peer(
            server_id,
            conn,
            serde_json::json!({
                "type": "mqtt_publish",
                "topic": "test/topic",
                "payload": "hello",
                "qos": 0
            }),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_peer publish");
    assert!(
        matches!(outcome, ClientSendOutcome::Executed { .. }),
        "expected Executed (Custom result), got {outcome:?}"
    );

    // Read the PUBLISH packet off the socket.
    let mut buf = [0u8; 64];
    let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf))
        .await
        .expect("publish within 5s")
        .expect("read publish");
    assert!(n > 0, "expected PUBLISH bytes on the wire");
    // MQTT PUBLISH fixed header: top nibble of the first byte is packet type 3.
    assert_eq!(
        buf[0] >> 4,
        3,
        "expected an MQTT PUBLISH (type 3), got {buf:?}"
    );
    // The topic string travels verbatim in the packet body.
    assert!(
        buf[..n].windows(10).any(|w| w == b"test/topic"),
        "PUBLISH should carry the topic, got {:?}",
        &buf[..n]
    );

    // Counters moved: the injected PUBLISH was counted as a write.
    let server = state.get_server(server_id).await.expect("server");
    let conn_state = server
        .connections
        .values()
        .find(|c| c.id.as_u32() == conn)
        .expect("connection tracked");
    assert!(
        conn_state.bytes_sent >= n as u64,
        "bytes_sent should count the PUBLISH, got {}",
        conn_state.bytes_sent
    );

    // "disconnect this peer": the dashboard injects {"type":"close_connection"}, which
    // half-closes the shared write half; the socket reads EOF.
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

    // The handle goes away with the connection.
    for _ in 0..100 {
        if !state.has_peer_handle(server_id, conn).await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("peer handle still registered after the connection closed");
}

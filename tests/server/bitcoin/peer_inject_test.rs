//! The dashboard's "message this peer" / "disconnect this peer" path on a Bitcoin P2P server
//! connection: `AppState::send_to_peer` injects a wire action into one live connection and
//! the encoded message reaches the socket. Zero LLM calls - a `*` static handler answers the
//! opened event with a `verack`, so the model is never consulted.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features bitcoin --test server -- bitcoin::peer_inject --test-threads=100


use std::io::Cursor;
use std::time::Duration;

use bitcoin::consensus::Decodable;
use bitcoin::p2p::message::{NetworkMessage, RawNetworkMessage};
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
    panic!("Bitcoin server #{} never bound a port", id.as_u32());
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
        "Bitcoin server #{} never registered a peer handle",
        id.as_u32()
    );
}

/// Read exactly one framed P2P message off the socket.
async fn read_message(stream: &mut TcpStream) -> RawNetworkMessage {
    let mut header = [0u8; 24];
    stream.read_exact(&mut header).await.expect("read header");
    let len = u32::from_le_bytes([header[16], header[17], header[18], header[19]]) as usize;
    let mut payload = vec![0u8; len];
    if len > 0 {
        stream.read_exact(&mut payload).await.expect("read payload");
    }
    let mut full = header.to_vec();
    full.extend_from_slice(&payload);
    RawNetworkMessage::consensus_decode(&mut Cursor::new(full)).expect("decode message")
}

#[tokio::test]
async fn injected_bitcoin_action_reaches_raw_socket_and_close_sends_eof() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    let server_id = ServerForm {
        protocol: "bitcoin".to_string(),
        port: Some(0),
        event_handlers: Some(vec![serde_json::json!({
            "event_pattern": "*",
            "handler": {
                "type": "static",
                "actions": [ { "type": "send_verack", "network": "mainnet" } ]
            }
        })]),
        ..Default::default()
    }
    .create(&state, tx.clone())
    .await
    .expect("create bitcoin server");
    let port = wait_for_port(&state, server_id).await;

    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .expect("connect");

    // The static handler's answer to the opened event.
    let greeting = tokio::time::timeout(Duration::from_secs(5), read_message(&mut stream))
        .await
        .expect("verack within 5s");
    assert!(
        matches!(greeting.payload(), NetworkMessage::Verack),
        "expected verack, got {:?}",
        greeting.payload()
    );

    let conn = wait_for_peer_handle(&state, server_id).await;

    // A wire verb, injected from outside the connection task: ping is 24 + 8 bytes.
    let outcome = state
        .send_to_peer(
            server_id,
            conn,
            serde_json::json!({"type": "send_ping", "nonce": 4242}),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_peer");
    assert!(
        matches!(outcome, ClientSendOutcome::Sent { bytes_sent: 32 }),
        "expected Sent{{32}}, got {outcome:?}"
    );

    let ping = tokio::time::timeout(Duration::from_secs(5), read_message(&mut stream))
        .await
        .expect("ping within 5s");
    assert!(
        matches!(ping.payload(), NetworkMessage::Ping(4242)),
        "expected ping(4242), got {:?}",
        ping.payload()
    );

    // Counters moved: the verack (24 bytes) was counted on the protocol's own write path.
    let server = state.get_server(server_id).await.expect("server");
    let conn_state = server
        .connections
        .values()
        .find(|c| c.id.as_u32() == conn)
        .expect("connection tracked");
    assert!(
        conn_state.bytes_sent >= 24,
        "bytes_sent should count the verack, got {}",
        conn_state.bytes_sent
    );
    assert!(
        conn_state.packets_sent >= 1,
        "packets_sent should count the verack, got {}",
        conn_state.packets_sent
    );

    // "disconnect this peer": the dashboard injects the generic `close_connection` name (the
    // model's own verb is `close_this_connection`); half-close from outside, the socket reads EOF.
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

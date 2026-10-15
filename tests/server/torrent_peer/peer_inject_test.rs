//! Dashboard injection into ONE live BitTorrent peer-wire connection
//! (`AppState::send_to_peer`).
//!
//! Zero LLM calls: the server answers the handshake through a static handler, the peer is a
//! raw tokio socket, and the bytes are asserted on that socket. Also proves the connection
//! counters move (the rail shows `↓ ↑`) and that `close_connection` half-closes and releases
//! the peer handle.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features torrent-peer --test server -- torrent_peer::peer_inject --test-threads=100

use std::time::Duration;

use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use netget::state::client_handles::ClientSendOutcome;
use netget::state::ServerId;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
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

/// Build the fixed 68-byte peer-wire handshake for a given info_hash / peer_id (20 bytes each).
fn handshake(info_hash: &[u8; 20], peer_id: &[u8; 20]) -> Vec<u8> {
    let mut h = Vec::with_capacity(68);
    h.push(19u8);
    h.extend_from_slice(b"BitTorrent protocol");
    h.extend_from_slice(&[0u8; 8]);
    h.extend_from_slice(info_hash);
    h.extend_from_slice(peer_id);
    h
}

#[tokio::test]
async fn injected_peer_message_reaches_raw_peer_and_close_sends_eof() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    // Static handler: reply to the handshake by echoing the same info_hash.
    let server_id = ServerForm {
        protocol: "torrent-peer".to_string(),
        port: Some(0),
        event_handlers: Some(vec![serde_json::json!({
            "event_pattern": "peer_handshake",
            "handler": {
                "type": "static",
                "actions": [ {
                    "type": "send_handshake",
                    "info_hash": "{{event.info_hash}}",
                    "peer_id": "-NT0001-xxxxxxxxxxxx"
                } ]
            }
        })]),
        ..Default::default()
    }
    .create(&state, tx.clone())
    .await
    .expect("create torrent-peer server");
    let port = wait_for_port(&state, server_id).await;

    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");

    // Send our handshake; the server static handler echoes info_hash back (68 bytes).
    let info_hash = [0xABu8; 20];
    let peer_id = *b"-PC0001-peerpeerpeer";
    stream
        .write_all(&handshake(&info_hash, &peer_id))
        .await
        .expect("send handshake");

    let mut reply = [0u8; 68];
    stream
        .read_exact(&mut reply)
        .await
        .expect("server handshake reply");
    assert_eq!(&reply[28..48], &info_hash, "server must echo info_hash");

    let conn = wait_for_peer_handle(&state, server_id).await;

    // Inject an unchoke from the dashboard side: <len=1><id=1> = 00 00 00 01 01.
    let outcome = state
        .send_to_peer(
            server_id,
            conn,
            serde_json::json!({"type": "send_unchoke"}),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_peer");
    match outcome {
        ClientSendOutcome::Sent { bytes_sent } => assert_eq!(bytes_sent, 5),
        other => panic!("expected Sent, got {other:?}"),
    }
    let mut unchoke = [0u8; 5];
    stream
        .read_exact(&mut unchoke)
        .await
        .expect("injected unchoke");
    assert_eq!(unchoke, [0, 0, 0, 1, 1]);

    // Counters moved: the reader accounted the 68-byte handshake in and the 68-byte reply out.
    let server = state.get_server(server_id).await.unwrap();
    let c = server
        .connections
        .values()
        .find(|c| c.id.as_u32() == conn)
        .expect("connection row");
    assert!(c.bytes_received >= 68, "{c:?}");
    assert!(c.packets_received >= 1, "{c:?}");
    assert!(c.bytes_sent >= 68, "{c:?}");
    assert!(c.packets_sent >= 1, "{c:?}");

    // Disconnect this peer: half-close, the socket reads EOF, the handle goes away.
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
    let n = tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut rest))
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

//! The dashboard's "message this peer" / "disconnect this peer" path on a ZooKeeper server
//! connection: `AppState::send_to_peer` injects a wire action into one live connection and a
//! correctly framed reply reaches the socket. Zero LLM calls - the handshake is answered in
//! Rust and no request ever reaches a handler.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features zookeeper --test server -- zookeeper::peer_inject --test-threads=100

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
    panic!("ZooKeeper server #{} never bound a port", id.as_u32());
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
        "ZooKeeper server #{} never registered a peer handle",
        id.as_u32()
    );
}

/// `[4 len][4 protocolVersion][8 lastZxidSeen][4 timeOut][8 sessionId][4 16][16 passwd][1 readOnly]`
fn build_connect_request() -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&0i32.to_be_bytes());
    payload.extend_from_slice(&0i64.to_be_bytes());
    payload.extend_from_slice(&30_000i32.to_be_bytes());
    payload.extend_from_slice(&0i64.to_be_bytes());
    payload.extend_from_slice(&16i32.to_be_bytes());
    payload.extend_from_slice(&[0u8; 16]);
    payload.push(0);
    let mut frame = (payload.len() as i32).to_be_bytes().to_vec();
    frame.extend_from_slice(&payload);
    frame
}

async fn read_frame(stream: &mut TcpStream) -> Vec<u8> {
    let mut len_buf = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut len_buf))
        .await
        .expect("frame length within 5s")
        .expect("read frame length");
    let len = i32::from_be_bytes(len_buf) as usize;
    let mut body = vec![0u8; len];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut body))
        .await
        .expect("frame body within 5s")
        .expect("read frame body");
    body
}

#[tokio::test]
async fn injected_zookeeper_action_reaches_raw_socket_and_close_sends_eof() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    let server_id = ServerForm {
        protocol: "zookeeper".to_string(),
        port: Some(0),
        ..Default::default()
    }
    .create(&state, tx.clone())
    .await
    .expect("create zookeeper server");
    let port = wait_for_port(&state, server_id).await;

    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .expect("connect");

    // Complete the handshake (answered in Rust, no handler involved).
    stream
        .write_all(&build_connect_request())
        .await
        .expect("send ConnectRequest");
    let connect_response = read_frame(&mut stream).await;
    assert_eq!(connect_response.len(), 37, "ConnectResponse layout");

    let conn = wait_for_peer_handle(&state, server_id).await;

    // A wire verb, injected from outside the connection task. The Custom result is framed by
    // the protocol's own reply encoder: [4 len][4 xid][8 zxid][4 err][buffer(data)][68 Stat].
    let outcome = state
        .send_to_peer(
            server_id,
            conn,
            serde_json::json!({
                "type": "zookeeper_data",
                "xid": 7,
                "zxid": 42,
                "data": "injected",
                "version": 3
            }),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_peer");
    let expected_len = 4 + 16 + (4 + 8) + 68;
    assert!(
        matches!(outcome, ClientSendOutcome::Sent { bytes_sent } if bytes_sent == expected_len),
        "expected Sent{{{expected_len}}}, got {outcome:?}"
    );

    let reply = read_frame(&mut stream).await;
    assert_eq!(reply.len(), expected_len - 4);
    assert_eq!(&reply[0..4], &7i32.to_be_bytes(), "xid echoed");
    assert_eq!(&reply[4..12], &42i64.to_be_bytes(), "zxid");
    assert_eq!(&reply[12..16], &0i32.to_be_bytes(), "error code 0");
    assert_eq!(&reply[16..20], &8i32.to_be_bytes(), "data length");
    assert_eq!(&reply[20..28], b"injected");

    // An injected reply that names no xid goes out as a watch notification (xid -1), never as
    // the answer to a request the operator cannot see.
    let outcome = state
        .send_to_peer(
            server_id,
            conn,
            // `error_code` is required on this action: 0 says the operation succeeded, and
            // the executor refuses to assume it.
            serde_json::json!({"type": "zookeeper_response", "zxid": 43, "error_code": 0}),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_peer without xid");
    assert!(
        matches!(outcome, ClientSendOutcome::Sent { bytes_sent: 20 }),
        "expected Sent{{20}}, got {outcome:?}"
    );
    let reply = read_frame(&mut stream).await;
    assert_eq!(&reply[0..4], &(-1i32).to_be_bytes(), "default xid is -1");

    // Counters moved: the handshake read, the ConnectResponse and both injected frames.
    let server = state.get_server(server_id).await.expect("server");
    let conn_state = server
        .connections
        .values()
        .find(|c| c.id.as_u32() == conn)
        .expect("connection tracked");
    assert_eq!(
        conn_state.bytes_received, 49,
        "ConnectRequest (4 + 45) must be counted as received"
    );
    assert_eq!(
        conn_state.bytes_sent as usize,
        41 + expected_len + 20,
        "ConnectResponse + both injected frames must be counted as sent"
    );
    assert_eq!(conn_state.packets_received, 1);
    assert_eq!(conn_state.packets_sent, 3);

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

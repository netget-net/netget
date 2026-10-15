//! The dashboard's "message this peer" / "disconnect this peer" path on a DC hub
//! connection: `AppState::send_to_peer` injects a wire action into one live connection and
//! the bytes reach the socket. Zero LLM calls - every command is answered by a `*` static
//! handler.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features dc --test server -- dc::peer_inject --test-threads=100

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
    panic!("DC server #{} never bound a port", id.as_u32());
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
    panic!("DC server #{} never registered a peer handle", id.as_u32());
}

/// Read one `|`-terminated NMDC command (terminator included).
async fn read_dc_command(stream: &mut TcpStream) -> String {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut byte))
            .await
            .expect("DC command within 5s")
            .expect("read");
        assert_ne!(n, 0, "unexpected EOF while reading a DC command");
        buf.push(byte[0]);
        if byte[0] == b'|' {
            return String::from_utf8(buf).expect("utf8");
        }
    }
}

#[tokio::test]
async fn injected_dc_action_reaches_raw_socket_and_close_sends_eof() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    let server_id = ServerForm {
        protocol: "dc".to_string(),
        port: Some(0),
        event_handlers: Some(vec![serde_json::json!({
            "event_pattern": "*",
            "handler": {
                "type": "static",
                "actions": [ { "type": "send_dc_hubname", "name": "StaticHub" } ]
            }
        })]),
        ..Default::default()
    }
    .create(&state, tx.clone())
    .await
    .expect("create dc server");
    let port = wait_for_port(&state, server_id).await;

    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .expect("connect");

    // The hub greets with its $Lock unprompted.
    let lock = read_dc_command(&mut stream).await;
    assert!(lock.starts_with("$Lock "), "expected $Lock, got {lock:?}");

    let conn = wait_for_peer_handle(&state, server_id).await;

    // A wire verb, injected from outside the connection task.
    let outcome = state
        .send_to_peer(
            server_id,
            conn,
            serde_json::json!({"type": "send_dc_hello", "nickname": "injected"}),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_peer");
    assert!(
        matches!(outcome, ClientSendOutcome::Sent { bytes_sent: 16 }),
        "expected Sent{{16}}, got {outcome:?}"
    );
    assert_eq!(read_dc_command(&mut stream).await, "$Hello injected|");

    // The reader still works alongside the peer task: a client command is answered by the
    // static handler and counted as a read.
    stream
        .write_all(b"$ValidateNick alice|")
        .await
        .expect("write");
    assert_eq!(read_dc_command(&mut stream).await, "$HubName StaticHub|");

    let server = state.get_server(server_id).await.expect("server");
    let conn_state = server
        .connections
        .values()
        .find(|c| c.id.as_u32() == conn)
        .expect("connection tracked");
    assert_eq!(
        conn_state.bytes_received, 20,
        "bytes_received counts the client command"
    );
    // The $Lock (54) and the handler's "$HubName StaticHub|" (19) are both counted as writes.
    // (The injected $Hello goes through the generic peer task, which does not count.)
    assert!(
        conn_state.bytes_sent >= lock.len() as u64 + 19,
        "bytes_sent should count the $Lock and the handler's $HubName, got {}",
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

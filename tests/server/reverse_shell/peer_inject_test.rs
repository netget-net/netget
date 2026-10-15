//! Dashboard injection into ONE live reverse-shell connection (`AppState::send_to_peer`).
//!
//! Zero LLM calls: the server answers every event through a `*` static handler, the peer is a
//! raw tokio socket (exactly what an operator's `nc`/`socat` is), and the bytes are asserted on
//! that socket. Also proves the connection counters move (the rail shows `↓ ↑`) and that the
//! dashboard's [ disconnect this peer ] — which injects `{"type":"close_connection"}` — half
//! closes the socket and removes the peer handle.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features reverse-shell --test server -- reverse_shell::peer_inject --test-threads=100


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

/// Read from the socket until `needle` appears, EOF, or a read times out. Returns all bytes seen.
async fn read_until(stream: &mut tokio::net::TcpStream, needle: &str) -> String {
    let mut acc = String::new();
    let mut buf = vec![0u8; 4096];
    for _ in 0..16 {
        match tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf)).await {
            Ok(Ok(0)) => break, // EOF
            Ok(Ok(n)) => {
                acc.push_str(&String::from_utf8_lossy(&buf[..n]));
                if acc.contains(needle) {
                    break;
                }
            }
            _ => break,
        }
    }
    acc
}

#[tokio::test]
async fn injected_shell_output_reaches_raw_peer_and_close_sends_eof() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    // A `*` static handler answers every event (session_opened + each command) with a fixed
    // line, so no LLM is ever consulted.
    let server_id = ServerForm {
        protocol: "reverse_shell".to_string(),
        port: Some(0),
        event_handlers: Some(vec![serde_json::json!({
            "event_pattern": "*",
            "handler": {
                "type": "static",
                "actions": [ { "type": "send_shell_output", "output": "static-line\n" } ]
            }
        })]),
        ..Default::default()
    }
    .create(&state, tx.clone())
    .await
    .expect("create reverse-shell server");
    let port = wait_for_port(&state, server_id).await;

    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");

    // Greeting: the session_opened event goes through the static handler.
    let greeting = read_until(&mut stream, "static-line").await;
    assert!(greeting.contains("static-line"), "greeting: {greeting:?}");

    let conn = wait_for_peer_handle(&state, server_id).await;

    // A command line from the peer bumps the inbound counters and draws one static reply.
    stream.write_all(b"whoami\n").await.unwrap();
    stream.flush().await.unwrap();
    let reply = read_until(&mut stream, "static-line").await;
    assert!(reply.contains("static-line"), "command reply: {reply:?}");

    // Inject shell output from the dashboard side — encoded by the same executor the model uses.
    let expected = "injected-output\n";
    let outcome = state
        .send_to_peer(
            server_id,
            conn,
            serde_json::json!({"type": "send_shell_output", "output": expected}),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_peer output");
    match outcome {
        ClientSendOutcome::Sent { bytes_sent } => assert_eq!(bytes_sent, expected.len()),
        other => panic!("expected Sent, got {other:?}"),
    }
    let injected = read_until(&mut stream, "injected-output").await;
    assert!(
        injected.contains("injected-output"),
        "injected output: {injected:?}"
    );

    // Counters moved in both directions (the reader's greeting + command reply are its writes;
    // the injected write goes through the peer task, which does not touch stats — but the two
    // reader writes and the one inbound line are enough to prove the wiring).
    let server = state.get_server(server_id).await.unwrap();
    let c = server
        .connections
        .values()
        .find(|c| c.id.as_u32() == conn)
        .expect("connection row");
    assert!(c.bytes_received >= "whoami\n".len() as u64, "{c:?}");
    assert!(c.packets_received >= 1, "{c:?}");
    assert!(c.bytes_sent >= (2 * "static-line\n".len()) as u64, "{c:?}");
    assert!(c.packets_sent >= 2, "{c:?}");

    // [ disconnect this peer ] injects close_connection: the socket reads EOF and the handle goes.
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

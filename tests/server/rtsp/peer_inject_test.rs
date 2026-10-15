//! The dashboard's "message this peer" / "disconnect this peer" path on an RTSP server
//! connection. RTSP registers a peer handle the moment a connection is accepted, so the
//! operator can reach it without waiting for any request. Zero LLM calls — OPTIONS is
//! answered by a `*`-scoped static handler.
//!
//! Two things this proves, both specific to RTSP:
//!   * Read/write byte counters move on real TCP traffic (`update_connection_stats`).
//!   * `close_connection` half-closes the connection from outside its task (the reader sees
//!     EOF), while an injected RTSP *response* verb writes nothing — RTSP framing (CSeq,
//!     Transport, Session) is built in `mod.rs`, so `execute_action` returns `NoAction` and
//!     there is no bespoke peer path for the response verbs.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features rtsp --test server -- rtsp::peer_inject --test-threads=100

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
    panic!("RTSP server #{} never bound a port", id.as_u32());
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
        "RTSP server #{} never registered a peer handle",
        id.as_u32()
    );
}

#[tokio::test]
async fn injected_close_disconnects_rtsp_peer_and_counters_move() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    let server_id = ServerForm {
        protocol: "rtsp".to_string(),
        port: Some(0),
        event_handlers: Some(vec![serde_json::json!({
            "event_pattern": "rtsp_options",
            "handler": {
                "type": "static",
                "actions": [ { "type": "rtsp_options_response" } ]
            }
        })]),
        ..Default::default()
    }
    .create(&state, tx.clone())
    .await
    .expect("create rtsp server");
    let port = wait_for_port(&state, server_id).await;

    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .expect("connect");

    // The handle exists as soon as the connection task starts — no request needed.
    let conn = wait_for_peer_handle(&state, server_id).await;

    // Drive one OPTIONS so the read and write counters move. The static handler answers
    // with zero LLM calls (the LLM endpoint is unreachable and would fail closed to 503).
    stream
        .write_all(b"OPTIONS rtsp://127.0.0.1/ RTSP/1.0\r\nCSeq: 1\r\n\r\n")
        .await
        .expect("write OPTIONS");

    let mut buf = vec![0u8; 2048];
    let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf))
        .await
        .expect("OPTIONS response within 5s")
        .expect("read OPTIONS response");
    let resp = String::from_utf8_lossy(&buf[..n]);
    assert!(
        resp.starts_with("RTSP/1.0 200"),
        "expected a 200 OPTIONS response, got: {resp}"
    );

    // Counters moved in both directions.
    let mut moved = false;
    for _ in 0..100 {
        let server = state.get_server(server_id).await.expect("server");
        if let Some(c) = server.connections.values().find(|c| c.id.as_u32() == conn) {
            if c.bytes_received > 0 && c.bytes_sent > 0 {
                moved = true;
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    assert!(
        moved,
        "read/write counters never moved for connection {conn}"
    );

    // An injected RTSP *response* verb: framing lives in mod.rs, so execute_action returns
    // NoAction and nothing reaches the wire. This documents the (non-Custom) gap.
    let outcome = state
        .send_to_peer(
            server_id,
            conn,
            serde_json::json!({"type": "rtsp_options_response"}),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_peer options");
    assert!(
        matches!(outcome, ClientSendOutcome::Executed { .. }),
        "an RTSP response verb writes no bytes, expected Executed, got {outcome:?}"
    );

    // "disconnect this peer": half-close from outside; the socket reads EOF.
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

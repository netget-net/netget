//! A WebSocket server created at the dashboard keeps reading its connections once a person has
//! accepted the handshake.
//!
//! The dashboard gives every server `*` → manual, preceded by a zero-action rule for each event
//! the protocol declares `raised_on_every_connection()`
//! (`src/tui/modal/form.rs::default_event_handlers`). `websocket_connection_opened` is answered
//! before the frame loop reads anything, so without a rule of its own it parks behind the
//! wildcard and the connection reads nothing — not a Ping, not a Close — until a person answers
//! a second question about the same connection.
//!
//! The test uses the routing the dashboard really builds (called, not inlined), answers the
//! parked handshake with `accept_websocket` the way a person would, and then sends a Ping: the
//! Pong comes back only if the frame loop is reading. Remove `.raised_on_every_connection()`
//! from `WEBSOCKET_CONNECTION_OPENED_EVENT` and the opened event parks, no Pong arrives, and the
//! test fails on its timeout. Model-free and loopback only.

use std::time::Duration;

use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use netget::state::ServerId;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

async fn wait_for_port(state: &AppState, id: ServerId) -> u16 {
    for _ in 0..300 {
        if let Some(s) = state.get_server(id).await {
            if let Some(addr) = s.local_addr {
                return addr.port();
            }
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("WebSocket server #{} never bound a port", id.as_u32());
}

/// Wait for the parked event `event_type` and return its intercept id.
async fn wait_for_intercept(state: &AppState, event_type: &str) -> u64 {
    for _ in 0..300 {
        if let Some(view) = state
            .list_intercepts()
            .await
            .into_iter()
            .find(|v| v.event_type == event_type)
        {
            return view.id;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("{event_type} never parked for a person to answer");
}

#[tokio::test]
async fn a_dashboard_websocket_reads_frames_once_the_handshake_is_accepted() {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".to_string());
    state
        .set_llm_client(netget::llm::OllamaClient::new(
            "http://127.0.0.1:1".to_string(),
        ))
        .await;

    let routing = netget::tui::modal::form::default_event_handlers(
        netget::tui::app::Section::Servers,
        "websocket",
    );
    let rules = routing.as_array().expect("an array of rules").clone();
    assert_eq!(
        rules.first().map(|r| r["event_pattern"].clone()),
        Some(serde_json::json!("websocket_connection_opened")),
        "the dashboard's routing must answer the opened event ahead of the manual wildcard: \
         {routing}"
    );

    let (tx, _rx) = mpsc::unbounded_channel();
    let server_id = ServerForm {
        protocol: "websocket".to_string(),
        port: Some(0),
        instruction: Some(String::new()),
        event_handlers: Some(rules),
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .expect("create websocket server");
    let port = wait_for_port(&state, server_id).await;

    let mut peer = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    let request = format!(
        "GET / HTTP/1.1\r\n\
         Host: 127.0.0.1:{port}\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
         Sec-WebSocket-Version: 13\r\n\r\n"
    );
    peer.write_all(request.as_bytes()).await.expect("handshake");

    // The person at the dashboard accepts the upgrade.
    let handshake = wait_for_intercept(&state, "websocket_handshake").await;
    state
        .resolve_intercept(
            handshake,
            vec![serde_json::json!({"type": "accept_websocket"})],
        )
        .await
        .expect("answer the handshake");

    // Read the whole 101 head, so what follows is frames.
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        tokio::time::timeout(Duration::from_secs(10), peer.read_exact(&mut byte))
            .await
            .expect("the 101 head never ended")
            .expect("read the 101 head");
        head.push(byte[0]);
    }
    assert!(
        head.starts_with(b"HTTP/1.1 101"),
        "the accepted handshake was not upgraded: {}",
        String::from_utf8_lossy(&head)
    );

    // A masked, empty Ping. Every RFC 6455 endpoint answers it with a Pong by itself — but only
    // once its frame loop reads it.
    peer.write_all(&[0x89, 0x80, 0, 0, 0, 0])
        .await
        .expect("send ping");
    let mut pong = [0u8; 2];
    tokio::time::timeout(Duration::from_secs(5), peer.read_exact(&mut pong))
        .await
        .expect(
            "no Pong: the frame loop is not reading, so websocket_connection_opened is parked \
             behind the dashboard's manual wildcard",
        )
        .expect("read pong");
    assert_eq!(pong, [0x8A, 0x00], "expected an empty Pong");

    let _ = state.remove_server(server_id).await;
}

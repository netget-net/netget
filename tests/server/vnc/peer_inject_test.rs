//! The dashboard's "message this peer" / "disconnect this peer" path on a VNC server
//! connection: `AppState::send_to_peer` injects a wire action into one live connection through
//! the same executor the LLM path uses. Zero LLM calls - the screen is drawn by a `*` static
//! handler.
//!
//! VNC's drawing verbs (`vnc_render_display`, `vnc_set_clipboard`) return
//! `ActionResult::Custom` and cannot be executed by the generic peer task (rendering needs the
//! connection's framebuffer state, which lives in the message loop). The one verb the peer task
//! *does* run is disconnect: `close_connection` (the generic row the dashboard injects) maps to
//! `ActionResult::CloseConnection`, half-closes the write side, and the socket reads EOF. This
//! test asserts that path plus the live byte counters.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features vnc --test server -- vnc::peer_inject --test-threads=100


use std::time::Duration;

use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use netget::state::client_handles::ClientSendOutcome;
use netget::state::ServerId;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

const FB_WIDTH: u16 = 32;
const FB_HEIGHT: u16 = 32;

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
    panic!("VNC server #{} never bound a port", id.as_u32());
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
    panic!("VNC server #{} never registered a peer handle", id.as_u32());
}

/// Drive the RFB 3.8 handshake and ClientInit, returning once a full FramebufferUpdate has been
/// read off the wire (which means the static handler drew a screen and the server counted the
/// write).
async fn handshake_and_first_frame(stream: &mut TcpStream) {
    // ProtocolVersion.
    let mut version = [0u8; 12];
    stream.read_exact(&mut version).await.expect("read version");
    assert_eq!(&version, b"RFB 003.008\n");
    stream
        .write_all(b"RFB 003.008\n")
        .await
        .expect("write version");

    // Security negotiation: pick None (1).
    let num_types = stream.read_u8().await.expect("num security types");
    let mut types = vec![0u8; num_types as usize];
    stream.read_exact(&mut types).await.expect("security types");
    assert!(types.contains(&1), "server must offer security type None");
    stream.write_u8(1).await.expect("choose None");
    let security_result = stream.read_u32().await.expect("security result");
    assert_eq!(security_result, 0, "SecurityResult must be OK");

    // ClientInit / ServerInit.
    stream.write_u8(1).await.expect("shared flag");
    let width = stream.read_u16().await.expect("fb width");
    let height = stream.read_u16().await.expect("fb height");
    assert_eq!((width, height), (FB_WIDTH, FB_HEIGHT));
    let mut pixel_format = [0u8; 16];
    stream
        .read_exact(&mut pixel_format)
        .await
        .expect("pixel format");
    let name_len = stream.read_u32().await.expect("name length");
    let mut name = vec![0u8; name_len as usize];
    stream.read_exact(&mut name).await.expect("desktop name");

    // Ask for the whole screen (non-incremental): the server answers via the static handler.
    let mut req = vec![3u8, 0];
    req.extend_from_slice(&0u16.to_be_bytes()); // x
    req.extend_from_slice(&0u16.to_be_bytes()); // y
    req.extend_from_slice(&width.to_be_bytes());
    req.extend_from_slice(&height.to_be_bytes());
    stream.write_all(&req).await.expect("request update");

    // Read one FramebufferUpdate (type 0) with a single Raw rectangle.
    let msg_type = stream.read_u8().await.expect("message type");
    assert_eq!(msg_type, 0, "expected FramebufferUpdate");
    let _padding = stream.read_u8().await.expect("padding");
    let num_rects = stream.read_u16().await.expect("num rects");
    assert_eq!(num_rects, 1, "server sends one Raw rectangle");
    let _x = stream.read_u16().await.expect("rect x");
    let _y = stream.read_u16().await.expect("rect y");
    let rw = stream.read_u16().await.expect("rect w");
    let rh = stream.read_u16().await.expect("rect h");
    let encoding = stream.read_i32().await.expect("encoding");
    assert_eq!(encoding, 0, "Raw encoding");
    let mut pixels = vec![0u8; rw as usize * rh as usize * 4];
    stream.read_exact(&mut pixels).await.expect("pixels");
}

#[tokio::test]
async fn injected_close_disconnects_vnc_peer_and_counters_move() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    let server_id = ServerForm {
        protocol: "vnc".to_string(),
        port: Some(0),
        startup_params: Some(serde_json::json!({
            "width": FB_WIDTH,
            "height": FB_HEIGHT,
        })),
        event_handlers: Some(vec![serde_json::json!({
            "event_pattern": "*",
            "handler": {
                "type": "static",
                "actions": [ {
                    "type": "vnc_render_display",
                    "commands": [ { "type": "background", "color": "#204060" } ]
                } ]
            }
        })]),
        ..Default::default()
    }
    .create(&state, tx.clone())
    .await
    .expect("create vnc server");
    let port = wait_for_port(&state, server_id).await;

    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .expect("connect");
    tokio::time::timeout(
        Duration::from_secs(10),
        handshake_and_first_frame(&mut stream),
    )
    .await
    .expect("handshake + first frame within 10s");

    let conn = wait_for_peer_handle(&state, server_id).await;

    // Live counters: the handshake reads and the frame write were both counted.
    let server = state.get_server(server_id).await.expect("server");
    let conn_state = server
        .connections
        .values()
        .find(|c| c.id.as_u32() == conn)
        .expect("connection tracked");
    assert!(
        conn_state.bytes_sent >= (FB_WIDTH as u64 * FB_HEIGHT as u64 * 4),
        "bytes_sent should count the full frame, got {}",
        conn_state.bytes_sent
    );
    assert!(
        conn_state.bytes_received > 0,
        "bytes_received should count the client's requests, got {}",
        conn_state.bytes_received
    );

    // "[ disconnect this peer ]" injects the generic `close_connection` verb.
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

    // The half-close reaches the socket as EOF.
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

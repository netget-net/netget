//! A WebSocket peer that never reads is cut off and its connection ends.
//!
//! Every text message is answered by a static rule with a 16 KiB text frame, through the
//! connection's outbound queue (`utils::outbox`). A peer that keeps sending without reading
//! fills it, and past the bound the server cuts the peer off. This pins that the cut-off ends
//! the *connection*, not just the writer: the peer reads what was already sent and then EOF (or
//! a reset), within a deadline, and the server's state no longer lists the connection as
//! active. Without that, a peer that never reads keeps its socket and its connection slot until
//! the idle deadline.
//!
//! Model-free (static rules only); the client is a few lines of RFC 6455 framing written here,
//! not the crate the server frames with. Loopback only.

use std::time::Duration;

use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use netget::state::server::ConnectionStatus;
use netget::state::ServerId;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

/// Far more messages than the server's queue plus both sockets' buffers can answer: a server
/// that never cuts the peer off reads every one of these.
const FLOOD_BYTES: usize = 32 * 1024 * 1024;

async fn wait_for_port(state: &AppState, id: ServerId) -> u16 {
    for _ in 0..300 {
        if let Some(s) = state.get_server(id).await {
            if let Some(addr) = s.local_addr {
                return addr.port();
            }
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("server #{} never bound a port", id.as_u32());
}

/// A masked client text frame (RFC 6455 §5.2, §5.3); payloads here are under 126 bytes.
fn text_frame(text: &str) -> Vec<u8> {
    let payload = text.as_bytes();
    assert!(payload.len() < 126);
    let mask = [0x11u8, 0x22, 0x33, 0x44];
    let mut out = vec![0x81, 0x80 | payload.len() as u8];
    out.extend_from_slice(&mask);
    out.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
    out
}

async fn active_connections(state: &AppState, id: ServerId) -> usize {
    state
        .get_server(id)
        .await
        .map(|s| {
            s.connections
                .values()
                .filter(|c| c.status == ConnectionStatus::Active)
                .count()
        })
        .unwrap_or(0)
}

/// Write `unit` repeatedly without ever reading, until a write fails (the server ended the
/// connection) or `FLOOD_BYTES` have gone. Returns whether a write failed.
async fn flood_without_reading(peer: &mut TcpStream, unit: &[u8]) -> bool {
    let chunk: Vec<u8> = unit.repeat((64 * 1024) / unit.len());
    let deadline = tokio::time::Instant::now() + Duration::from_secs(120);
    let mut sent = 0usize;
    while sent < FLOOD_BYTES && tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_secs(10), peer.write_all(&chunk)).await {
            Ok(Ok(())) => sent += chunk.len(),
            Ok(Err(_)) => return true,
            Err(_) => return false,
        }
    }
    false
}

/// Read until EOF or a reset; `Err` if the connection is still open at the deadline.
async fn read_to_end_or_reset(peer: &mut TcpStream) -> Result<usize, String> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let mut buf = vec![0u8; 64 * 1024];
    let mut total = 0usize;
    loop {
        match tokio::time::timeout_at(deadline, peer.read(&mut buf)).await {
            Ok(Ok(0)) => return Ok(total),
            Ok(Ok(n)) => total += n,
            Ok(Err(e))
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::ConnectionAborted
                        | std::io::ErrorKind::BrokenPipe
                ) =>
            {
                return Ok(total)
            }
            Ok(Err(e)) => return Err(format!("read failed: {e}")),
            Err(_) => {
                return Err(format!(
                    "the connection was still open 30 s after the flood ({total} bytes read)"
                ))
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_peer_that_never_reads_is_cut_off_and_its_connection_ends() {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".to_string());
    state
        .set_llm_client(netget::llm::OllamaClient::new(
            "http://127.0.0.1:1".to_string(),
        ))
        .await;
    let (tx, _rx) = mpsc::unbounded_channel();
    let id = ServerForm {
        protocol: "websocket".to_string(),
        port: Some(0),
        instruction: Some(String::new()),
        event_handlers: Some(vec![
            serde_json::json!({
                "event_pattern": "websocket_handshake",
                "handler": {"type": "static", "actions": [{"type": "accept_websocket"}]}
            }),
            serde_json::json!({
                "event_pattern": "websocket_connection_opened",
                "handler": {"type": "static", "actions": []}
            }),
            serde_json::json!({
                "event_pattern": "websocket_text_message",
                "handler": {
                    "type": "static",
                    "actions": [{"type": "send_websocket_text", "text": "x".repeat(16 * 1024)}]
                }
            }),
        ]),
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .expect("create websocket server");
    let port = wait_for_port(&state, id).await;

    // A small receive buffer, so the server's answers back up after a few kilobytes.
    let socket = tokio::net::TcpSocket::new_v4().expect("socket");
    socket.set_recv_buffer_size(4096).expect("SO_RCVBUF");
    let mut peer = socket
        .connect(([127, 0, 0, 1], port).into())
        .await
        .expect("connect");
    peer.write_all(
        format!(
            "GET / HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nUpgrade: websocket\r\n\
             Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
             Sec-WebSocket-Version: 13\r\n\r\n"
        )
        .as_bytes(),
    )
    .await
    .expect("write handshake");
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        let n = tokio::time::timeout(Duration::from_secs(20), peer.read(&mut byte))
            .await
            .expect("no handshake answer within 20s")
            .expect("read handshake");
        assert!(n > 0, "closed during the handshake");
        head.push(byte[0]);
    }
    assert!(
        head.starts_with(b"HTTP/1.1 101"),
        "handshake refused: {:?}",
        String::from_utf8_lossy(&head)
    );
    assert_eq!(active_connections(&state, id).await, 1);

    let refused = flood_without_reading(&mut peer, &text_frame("x")).await;
    let read = read_to_end_or_reset(&mut peer).await;
    assert!(
        read.is_ok(),
        "a peer that never read was not disconnected (a write failed: {refused}): {}",
        read.unwrap_err()
    );

    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while active_connections(&state, id).await > 0 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the cut-off connection is still listed as active"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let _ = state.remove_server(id).await;
}

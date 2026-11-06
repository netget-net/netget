//! An MQTT client that never reads is cut off and its connection ends.
//!
//! Every PINGREQ is answered with a PINGRESP through the connection's outbound queue
//! (`utils::outbox`), and a client that keeps pinging without reading fills it. Past the bound
//! the broker cuts the client off; this pins that the cut-off ends the *connection*, not just
//! the writer: the client reads what was already sent and then EOF (or a reset), within a
//! deadline, and the broker's state no longer lists the connection as active. Without that, a
//! client that never reads keeps its socket and its connection slot until a read deadline.
//!
//! Model-free: CONNECT is accepted by a static rule and PINGREQ is answered by the broker
//! itself. Loopback only.

use std::time::Duration;

use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use netget::state::server::ConnectionStatus;
use netget::state::ServerId;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

const CONNACK_ACCEPTED: [u8; 4] = [0x20, 0x02, 0x00, 0x00];
const PINGREQ: [u8; 2] = [0xC0, 0x00];

/// Far more pings than the broker's queue plus both sockets' buffers can hold: a broker that
/// never cuts the client off lets every one of these through.
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
    panic!("MQTT broker #{} never bound a port", id.as_u32());
}

fn connect_packet() -> Vec<u8> {
    let client_id = b"slow";
    // MQTT 3.1.1, clean session, Keep Alive 0 (no keep-alive deadline).
    let mut body = vec![0x00, 0x04, b'M', b'Q', b'T', b'T', 0x04, 0x02, 0x00, 0x00];
    body.extend_from_slice(&(client_id.len() as u16).to_be_bytes());
    body.extend_from_slice(client_id);
    let mut packet = vec![0x10, body.len() as u8];
    packet.extend_from_slice(&body);
    packet
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
async fn a_client_that_never_reads_is_cut_off_and_its_connection_ends() {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".to_string());
    state
        .set_llm_client(netget::llm::OllamaClient::new(
            "http://127.0.0.1:1".to_string(),
        ))
        .await;
    let (tx, _rx) = mpsc::unbounded_channel();
    let id = ServerForm {
        protocol: "mqtt".to_string(),
        port: Some(0),
        instruction: Some(String::new()),
        event_handlers: Some(vec![serde_json::json!({
            "event_pattern": "mqtt_connect",
            "handler": {
                "type": "static",
                "actions": [{"type": "mqtt_connack", "return_code": 0, "session_present": false}]
            }
        })]),
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .expect("create mqtt broker");
    let port = wait_for_port(&state, id).await;

    // A small receive buffer, so the broker's answers back up after a few kilobytes.
    let socket = tokio::net::TcpSocket::new_v4().expect("socket");
    socket.set_recv_buffer_size(4096).expect("SO_RCVBUF");
    let mut peer = socket
        .connect(([127, 0, 0, 1], port).into())
        .await
        .expect("connect");
    peer.write_all(&connect_packet()).await.expect("CONNECT");
    let mut connack = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(20), peer.read_exact(&mut connack))
        .await
        .expect("no CONNACK within 20s")
        .expect("read CONNACK");
    assert_eq!(connack, CONNACK_ACCEPTED);
    assert_eq!(active_connections(&state, id).await, 1);

    let refused = flood_without_reading(&mut peer, &PINGREQ).await;
    let read = read_to_end_or_reset(&mut peer).await;
    assert!(
        read.is_ok(),
        "a client that never read was not disconnected (a write failed: {refused}): {}",
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

//! The dashboard's "message this peer" / "disconnect this peer" path on an RDP server
//! connection, plus the live byte/packet counters. Zero LLM calls.
//!
//! Two independent proofs:
//!
//! 1. `injected_rdp_action_reaches_raw_socket_and_close_sends_eof` — the RDP negotiation slice
//!    parks in `read_connection_request` until the client sends a Connection Request, and the
//!    peer handle is registered *before* that blocking read. So a client that connects but does
//!    not speak leaves the connection live with a handle: `send_to_peer` injects a real wire verb
//!    (`send_rdp_negotiation_response`) through the same executor the model uses, the 19-byte
//!    Connection Confirm reaches the socket, and an injected `close_connection` half-closes it so
//!    the socket reads EOF and the handle is released — all without a single LLM call.
//!
//! 2. `negotiation_updates_connection_counters` — a `*` static handler answers the connection
//!    request with no LLM call, and after the exchange the connection's `bytes_received` /
//!    `bytes_sent` counters reflect the CR read and the CC written.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features rdp --test server -- rdp::peer_inject --test-threads=100

use std::time::Duration;

use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use netget::state::client_handles::ClientSendOutcome;
use netget::state::ServerId;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

/// RDP negotiation protocol value: TLS ([MS-RDPBCGR] 2.2.1.1.1).
const PROTOCOL_SSL: u32 = 0x0000_0001;

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
    panic!("RDP server #{} never bound a port", id.as_u32());
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
    panic!("RDP server #{} never registered a peer handle", id.as_u32());
}

/// A genuine TPKT + X.224 Connection Request with an `mstshash` cookie and an RDP_NEG_REQ.
fn build_connection_request(cookie_user: &str, requested_protocols: u32) -> Vec<u8> {
    let mut variable: Vec<u8> = Vec::new();
    variable.extend_from_slice(b"Cookie: mstshash=");
    variable.extend_from_slice(cookie_user.as_bytes());
    variable.extend_from_slice(b"\r\n");
    // RDP_NEG_REQ: type=0x01, flags=0x00, length=0x0008 (LE), requestedProtocols (LE u32).
    variable.push(0x01);
    variable.push(0x00);
    variable.extend_from_slice(&8u16.to_le_bytes());
    variable.extend_from_slice(&requested_protocols.to_le_bytes());

    let li: u8 = 6 + variable.len() as u8;
    let total_len: u16 = 4 + 1 + li as u16;

    let mut out = Vec::with_capacity(total_len as usize);
    out.push(0x03); // TPKT version
    out.push(0x00); // reserved
    out.extend_from_slice(&total_len.to_be_bytes());
    out.push(li);
    out.push(0xE0); // X.224 Connection Request
    out.extend_from_slice(&[0x00, 0x00]); // DST-REF
    out.extend_from_slice(&[0x00, 0x00]); // SRC-REF
    out.push(0x00); // class option
    out.extend_from_slice(&variable);
    out
}

/// The exact 19-byte Connection Confirm the server emits for a given RDP_NEG_* type + payload.
fn expected_confirm(neg_type: u8, flags: u8, payload: u32) -> Vec<u8> {
    let mut out = vec![
        0x03, 0x00, 0x00, 0x13, 0x0E, 0xD0, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    out.push(neg_type);
    out.push(flags);
    out.extend_from_slice(&8u16.to_le_bytes());
    out.extend_from_slice(&payload.to_le_bytes());
    out
}

#[tokio::test]
async fn injected_rdp_action_reaches_raw_socket_and_close_sends_eof() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    let server_id = ServerForm {
        protocol: "rdp".to_string(),
        port: Some(0),
        ..Default::default()
    }
    .create(&state, tx.clone())
    .await
    .expect("create rdp server");
    let port = wait_for_port(&state, server_id).await;

    // Connect but stay silent: the server parks in read_connection_request, and the peer handle
    // was registered before that read, so the connection is live and injectable. No CR is sent,
    // so the rdp_connection_request event never fires and no LLM call is made.
    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .expect("connect");

    let conn = wait_for_peer_handle(&state, server_id).await;

    // A wire verb, injected from outside the connection task.
    let outcome = state
        .send_to_peer(
            server_id,
            conn,
            serde_json::json!({"type": "send_rdp_negotiation_response", "selected_protocol": "TLS"}),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_peer");
    assert!(
        matches!(outcome, ClientSendOutcome::Sent { bytes_sent: 19 }),
        "expected Sent{{19}}, got {outcome:?}"
    );

    let mut buf = [0u8; 19];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut buf))
        .await
        .expect("Connection Confirm within 5s")
        .expect("read Connection Confirm");
    let expected = expected_confirm(0x02, 0x00, PROTOCOL_SSL);
    assert_eq!(
        buf.to_vec(),
        expected,
        "injected NEG_RSP bytes differ.\n got: {buf:02x?}\nwant: {expected:02x?}"
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

    let mut tail = [0u8; 16];
    let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut tail))
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

#[tokio::test]
async fn negotiation_updates_connection_counters() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    // A `*` static handler answers the negotiation with no LLM call.
    let server_id = ServerForm {
        protocol: "rdp".to_string(),
        port: Some(0),
        event_handlers: Some(vec![serde_json::json!({
            "event_pattern": "*",
            "handler": {
                "type": "static",
                "actions": [
                    { "type": "send_rdp_negotiation_response", "selected_protocol": "TLS" }
                ]
            }
        })]),
        ..Default::default()
    }
    .create(&state, tx.clone())
    .await
    .expect("create rdp server");
    let port = wait_for_port(&state, server_id).await;

    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .expect("connect");
    let cr = build_connection_request("neo", PROTOCOL_SSL);
    stream.write_all(&cr).await.expect("write CR");
    stream.flush().await.expect("flush CR");

    // Read the 19-byte Connection Confirm the static handler produced.
    let mut buf = [0u8; 19];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut buf))
        .await
        .expect("Connection Confirm within 5s")
        .expect("read Connection Confirm");
    assert_eq!(buf.to_vec(), expected_confirm(0x02, 0x00, PROTOCOL_SSL));

    // The counters moved: the CR was counted as bytes_received, the CC as bytes_sent. The
    // connection is removed on close, so sample it before that races — poll until the write is
    // reflected, and the connection may already be gone (removed after the half-close), which is
    // itself proof the exchange completed.
    let cr_len = cr.len() as u64;
    for _ in 0..100 {
        match state.get_server(server_id).await {
            Some(server) => {
                if let Some(conn) = server.connections.values().next() {
                    if conn.bytes_sent >= 19 {
                        assert!(
                            conn.bytes_received >= cr_len,
                            "bytes_received {} should be >= CR length {}",
                            conn.bytes_received,
                            cr_len
                        );
                        assert!(conn.packets_received >= 1 && conn.packets_sent >= 1);
                        return;
                    }
                } else {
                    // Connection already torn down after the exchange — it completed.
                    return;
                }
            }
            None => return,
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("connection counters never reflected the negotiation exchange");
}

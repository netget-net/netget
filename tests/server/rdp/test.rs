//! End-to-end tests for the RDP server's connection-negotiation slice.
//!
//! No real RDP client (`xfreerdp`/FreeRDP or `mstsc`) was installable in this environment, so
//! these tests drive the real `netget` binary with a raw TCP client that sends a genuine,
//! correctly-framed X.224 Connection Request ([MS-RDPBCGR] 2.2.1.1) and assert the **exact bytes**
//! of the Connection Confirm ([MS-RDPBCGR] 2.2.1.2). Asserting literal RFC-derived bytes is weaker
//! evidence than a real client rendering a session — it proves the handshake framing, not that a
//! client proceeds past it — and that limitation is stated here and in the protocol's metadata.


use super::super::super::helpers::{self, E2EResult, NetGetConfig};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const READ_TIMEOUT: Duration = Duration::from_secs(15);

/// RDP negotiation protocol values ([MS-RDPBCGR] 2.2.1.1.1 / 2.2.1.2.1).
const PROTOCOL_SSL: u32 = 0x0000_0001; // TLS
const PROTOCOL_HYBRID: u32 = 0x0000_0002; // CredSSP/NLA

/// Build a TPKT + X.224 Connection Request with an optional `mstshash` cookie and an RDP_NEG_REQ.
fn build_connection_request(cookie_user: Option<&str>, requested_protocols: u32) -> Vec<u8> {
    let mut variable: Vec<u8> = Vec::new();
    if let Some(user) = cookie_user {
        variable.extend_from_slice(b"Cookie: mstshash=");
        variable.extend_from_slice(user.as_bytes());
        variable.extend_from_slice(b"\r\n");
    }
    // RDP_NEG_REQ: type=0x01, flags=0x00, length=0x0008 (LE), requestedProtocols (LE u32).
    variable.push(0x01);
    variable.push(0x00);
    variable.extend_from_slice(&8u16.to_le_bytes());
    variable.extend_from_slice(&requested_protocols.to_le_bytes());

    // X.224 CR header after LI: code(1)+dstRef(2)+srcRef(2)+class(1) = 6 bytes.
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

/// The exact 19-byte Connection Confirm this server emits for a given RDP_NEG_* type + payload.
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

async fn read_confirm(stream: &mut TcpStream) -> E2EResult<Vec<u8>> {
    let mut buf = [0u8; 19];
    tokio::time::timeout(READ_TIMEOUT, stream.read_exact(&mut buf))
        .await
        .map_err(|_| "timed out reading Connection Confirm")?
        .map_err(|e| format!("failed reading Connection Confirm: {e}"))?;
    Ok(buf.to_vec())
}

#[tokio::test]
async fn test_rdp_negotiation_response_tls() -> E2EResult<()> {
    println!("\n=== E2E Test: RDP negotiation response (TLS) ===");

    let prompt = "RDP server on port {AVAILABLE_PORT} that selects TLS during negotiation";

    let server = helpers::start_netget_server(NetGetConfig::new(prompt).with_mock(|mock| {
        mock
            // The connection request event. Match on the parsed cookie to prove the CR parser
            // fed the model the right fields.
            .on_event("rdp_connection_request")
            .and_event_data_contains("cookie_username", "neo")
            .respond_with_actions(serde_json::json!([
                { "type": "send_rdp_negotiation_response", "selected_protocol": "TLS" }
            ]))
            .expect_calls(1)
            .and()
            .on_instruction_containing("RDP")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "rdp",
                    "instruction": "RDP server that selects TLS"
                }
            ]))
            .expect_calls(1)
            .and()
    }))
    .await?;
    println!("RDP server started on port {}", server.port);

    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", server.port)).await?;
    let cr = build_connection_request(Some("neo"), PROTOCOL_SSL | PROTOCOL_HYBRID);
    stream.write_all(&cr).await?;
    stream.flush().await?;

    let confirm = read_confirm(&mut stream).await?;
    // RDP_NEG_RSP (0x02), flags 0, selectedProtocol = TLS (1).
    let expected = expected_confirm(0x02, 0x00, PROTOCOL_SSL);
    assert_eq!(
        confirm, expected,
        "Connection Confirm bytes differ.\n got: {confirm:02x?}\nwant: {expected:02x?}"
    );
    println!("✓ NEG_RSP TLS bytes match MS-RDPBCGR literal");

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    println!("=== Test passed ===\n");
    Ok(())
}

#[tokio::test]
async fn test_rdp_fails_closed_on_no_answer() -> E2EResult<()> {
    println!("\n=== E2E Test: RDP fails closed ===");

    let prompt = "RDP server on port {AVAILABLE_PORT}";

    let server = helpers::start_netget_server(NetGetConfig::new(prompt).with_mock(|mock| {
        mock
            // Answer the event with only show_message: valid, but no protocol output. The server
            // must fail closed with an explicit NEG_FAILURE, NOT silently accept a default.
            .on_event("rdp_connection_request")
            .respond_with_actions(serde_json::json!([
                { "type": "show_message", "message": "no negotiation decision" }
            ]))
            .expect_calls(1)
            .and()
            .on_instruction_containing("RDP")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "rdp",
                    "instruction": "RDP server"
                }
            ]))
            .expect_calls(1)
            .and()
    }))
    .await?;

    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", server.port)).await?;
    let cr = build_connection_request(None, 0); // standard RDP, no cookie
    stream.write_all(&cr).await?;
    stream.flush().await?;

    let confirm = read_confirm(&mut stream).await?;
    // Fail-closed default: RDP_NEG_FAILURE (0x03), SSL_REQUIRED_BY_SERVER (1).
    let expected = expected_confirm(0x03, 0x00, 0x0000_0001);
    assert_eq!(
        confirm, expected,
        "Expected a fail-closed NEG_FAILURE(SSL_REQUIRED_BY_SERVER).\n got: {confirm:02x?}\nwant: {expected:02x?}"
    );
    println!("✓ Fail-closed NEG_FAILURE bytes match");

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    println!("=== Test passed ===\n");
    Ok(())
}

#[tokio::test]
async fn test_rdp_model_rejects_connection() -> E2EResult<()> {
    println!("\n=== E2E Test: RDP model-chosen rejection ===");

    let prompt = "RDP server on port {AVAILABLE_PORT} that requires NLA";

    let server = helpers::start_netget_server(NetGetConfig::new(prompt).with_mock(|mock| {
        mock
            // The model deliberately rejects, demanding CredSSP/NLA. This path is structurally
            // distinct from the fail-closed default: it carries the model's chosen failure code.
            .on_event("rdp_connection_request")
            .respond_with_actions(serde_json::json!([
                { "type": "reject_rdp_connection", "failure_code": "HYBRID_REQUIRED_BY_SERVER" }
            ]))
            .expect_calls(1)
            .and()
            .on_instruction_containing("RDP")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "rdp",
                    "instruction": "RDP server requiring NLA"
                }
            ]))
            .expect_calls(1)
            .and()
    }))
    .await?;

    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", server.port)).await?;
    // Client only offers standard RDP; the model demands HYBRID (NLA) instead.
    let cr = build_connection_request(Some("alice"), 0);
    stream.write_all(&cr).await?;
    stream.flush().await?;

    let confirm = read_confirm(&mut stream).await?;
    // RDP_NEG_FAILURE (0x03), HYBRID_REQUIRED_BY_SERVER (5).
    let expected = expected_confirm(0x03, 0x00, 0x0000_0005);
    assert_eq!(
        confirm, expected,
        "Expected NEG_FAILURE(HYBRID_REQUIRED_BY_SERVER).\n got: {confirm:02x?}\nwant: {expected:02x?}"
    );
    println!("✓ Model rejection NEG_FAILURE bytes match");

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    println!("=== Test passed ===\n");
    Ok(())
}

//! What a TFTP client gets when the LLM backend fails.
//!
//! The failure is forced the same way `tests/server/dns/llm_failure_test.rs` does it: the
//! mock is configured for the *startup* instruction (and, where the test needs to get
//! mid-transfer, for the first network event only). Every later event matches no rule, the
//! mock Ollama server answers HTTP 500, and `call_llm` returns `Err` - the same shape as a
//! real backend outage, an overload, or a malformed model response.
//!
//! Two of TFTP's four LLM call sites used to write nothing at all on that path:
//! `continue_read_transfer` (the client has ACKed block N and is waiting for block N+1) and
//! `receive_write_data` (the client has sent a DATA block and is waiting for its ACK). A
//! transfer that simply stops mid-stream is worse than one that fails - for a PXE boot it
//! looks like a corrupt image. All four now answer with opcode 5 (ERROR) and end the
//! transfer.
//!
//! The assertions are at the protocol level: real bytes off a real UDP socket, checked for
//! opcode 5, an error code, and a NUL-terminated message, because that is all a client
//! parses.

use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;

/// How long to wait for the server's reply. The LLM path includes the mock's 500 and any
/// retry/repair the harness does before giving up, so this is generous on purpose.
const REPLY_TIMEOUT: Duration = Duration::from_secs(30);

fn build_rrq_packet(filename: &str, mode: &str) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.extend_from_slice(&1u16.to_be_bytes()); // Opcode RRQ
    packet.extend_from_slice(filename.as_bytes());
    packet.push(0);
    packet.extend_from_slice(mode.as_bytes());
    packet.push(0);
    packet
}

fn build_wrq_packet(filename: &str, mode: &str) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.extend_from_slice(&2u16.to_be_bytes()); // Opcode WRQ
    packet.extend_from_slice(filename.as_bytes());
    packet.push(0);
    packet.extend_from_slice(mode.as_bytes());
    packet.push(0);
    packet
}

fn build_ack_packet(block_number: u16) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.extend_from_slice(&4u16.to_be_bytes()); // Opcode ACK
    packet.extend_from_slice(&block_number.to_be_bytes());
    packet
}

fn build_data_packet(block_number: u16, data: &[u8]) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.extend_from_slice(&3u16.to_be_bytes()); // Opcode DATA
    packet.extend_from_slice(&block_number.to_be_bytes());
    packet.extend_from_slice(data);
    packet
}

/// Assert `packet` is a well-formed RFC 1350 ERROR packet and return (code, message).
///
/// Byte level on purpose: opcode 5 in the first two bytes, a two-byte error code, and a
/// NUL-terminated message. A client that cannot parse the packet is back to a timeout, so
/// "the server sent something" is not the assertion this test needs to make.
fn expect_error_packet(packet: &[u8]) -> (u16, String) {
    assert!(
        packet.len() >= 5,
        "ERROR packet is shorter than opcode+code+NUL: {} bytes",
        packet.len()
    );
    let opcode = u16::from_be_bytes([packet[0], packet[1]]);
    assert_eq!(
        opcode, 5,
        "expected opcode 5 (ERROR), got {opcode} - the server answered in the wrong \
         vocabulary or resumed the transfer"
    );
    let error_code = u16::from_be_bytes([packet[2], packet[3]]);
    assert_eq!(
        *packet.last().unwrap(),
        0,
        "ERROR message must be NUL-terminated"
    );
    let message = String::from_utf8_lossy(&packet[4..packet.len() - 1]).to_string();
    assert!(
        !message.is_empty(),
        "error code 0 means 'see error message', so the message cannot be empty"
    );
    (error_code, message)
}

/// The read request itself fails: the client gets ERROR instead of a first DATA block.
#[tokio::test]
async fn test_tftp_read_request_errors_when_llm_fails() -> E2EResult<()> {
    let config = NetGetConfig::new_no_scripts(
        "listen on port {AVAILABLE_PORT} via tftp. Serve file boot.bin",
    )
    .with_mock(|mock| {
        mock.on_instruction_containing("via tftp")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "TFTP",
                    "instruction": "Serve file boot.bin"
                }
            ]))
            .expect_calls(1)
            .and()
        // Deliberately NO rule for `tftp_read_request`: the mock answers 500, which is
        // what drives the server down its LLM-failure path.
    });

    let server = start_netget_server(config).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let client = UdpSocket::bind("127.0.0.1:0").await?;
    client
        .send_to(
            &build_rrq_packet("boot.bin", "octet"),
            format!("127.0.0.1:{}", server.port),
        )
        .await?;

    let mut buffer = vec![0u8; 516];
    let (n, _) = timeout(REPLY_TIMEOUT, client.recv_from(&mut buffer))
        .await
        .map_err(|_| {
            "No TFTP reply within 30s - the server went silent on LLM failure, which is the \
             exact defect this test exists to catch"
        })??;

    let (code, message) = expect_error_packet(&buffer[..n]);
    assert_eq!(code, 0, "LLM failure is reported as 'not defined' (code 0)");
    println!("  [TEST] RRQ failure -> ERROR {code}: {message}");

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

/// A read transfer that dies *mid-stream*: block 1 is delivered, the client ACKs it, and
/// the LLM call for the next block fails. This is the site that used to write nothing.
#[tokio::test]
async fn test_tftp_read_transfer_errors_when_llm_fails_mid_stream() -> E2EResult<()> {
    // Exactly 512 bytes, so the server treats block 1 as non-final and waits for an ACK
    // before asking the model for block 2.
    let block1 = vec![0x41u8; 512];
    let block1_hex = hex::encode(&block1);

    let config = NetGetConfig::new_no_scripts(
        "listen on port {AVAILABLE_PORT} via tftp. Serve file large.bin",
    )
    .with_mock(move |mock| {
        mock.on_instruction_containing("via tftp")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "TFTP",
                    "instruction": "Serve file large.bin"
                }
            ]))
            .expect_calls(1)
            .and()
            .on_event("tftp_read_request")
            .and_event_data_contains("filename", "large.bin")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "send_tftp_data",
                    "block_number": 1,
                    "data_hex": block1_hex,
                    "is_final": false
                }
            ]))
            .expect_calls(1)
            .and()
        // No rule for `tftp_ack_received`: block 2 is where the backend "goes down".
    });

    let server = start_netget_server(config).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let client = UdpSocket::bind("127.0.0.1:0").await?;
    client
        .send_to(
            &build_rrq_packet("large.bin", "octet"),
            format!("127.0.0.1:{}", server.port),
        )
        .await?;

    let mut buffer = vec![0u8; 516];
    let (n, tid_addr) = timeout(REPLY_TIMEOUT, client.recv_from(&mut buffer)).await??;
    assert_eq!(
        u16::from_be_bytes([buffer[0], buffer[1]]),
        3,
        "expected DATA block 1 to start the transfer"
    );
    assert_eq!(n, 516, "block 1 must be a full 512-byte block");

    // ACK block 1 to the transfer's TID port; the server now asks the model for block 2.
    client.send_to(&build_ack_packet(1), tid_addr).await?;

    let (n, _) = timeout(REPLY_TIMEOUT, client.recv_from(&mut buffer))
        .await
        .map_err(|_| {
            "No TFTP reply within 30s after ACK - the transfer stopped silently mid-stream, \
             which is the exact defect this test exists to catch"
        })??;

    let (code, message) = expect_error_packet(&buffer[..n]);
    assert_eq!(code, 0, "LLM failure is reported as 'not defined' (code 0)");
    println!("  [TEST] mid-transfer failure -> ERROR {code}: {message}");

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

/// A write transfer that dies after ACK 0: the client sends a DATA block and the LLM call
/// that would produce its ACK fails. The other site that used to write nothing.
#[tokio::test]
async fn test_tftp_write_data_block_errors_when_llm_fails() -> E2EResult<()> {
    let config = NetGetConfig::new_no_scripts(
        "listen on port {AVAILABLE_PORT} via tftp. Accept uploads of config.txt",
    )
    .with_mock(|mock| {
        mock.on_instruction_containing("via tftp")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "TFTP",
                    "instruction": "Accept uploads of config.txt"
                }
            ]))
            .expect_calls(1)
            .and()
            .on_event("tftp_write_request")
            .and_event_data_contains("filename", "config.txt")
            .respond_with_actions(serde_json::json!([
                {"type": "send_tftp_ack", "block_number": 0}
            ]))
            .expect_calls(1)
            .and()
        // No rule for `tftp_data_block`: the upload's first block is where it fails.
    });

    let server = start_netget_server(config).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let client = UdpSocket::bind("127.0.0.1:0").await?;
    client
        .send_to(
            &build_wrq_packet("config.txt", "octet"),
            format!("127.0.0.1:{}", server.port),
        )
        .await?;

    let mut buffer = vec![0u8; 516];
    let (n, tid_addr) = timeout(REPLY_TIMEOUT, client.recv_from(&mut buffer)).await??;
    assert_eq!(n, 4, "ACK 0 is exactly four bytes");
    assert_eq!(
        u16::from_be_bytes([buffer[0], buffer[1]]),
        4,
        "expected ACK to open the write transfer"
    );
    assert_eq!(u16::from_be_bytes([buffer[2], buffer[3]]), 0, "ACK block 0");

    client
        .send_to(&build_data_packet(1, b"hostname=netget\n"), tid_addr)
        .await?;

    let (n, _) = timeout(REPLY_TIMEOUT, client.recv_from(&mut buffer))
        .await
        .map_err(|_| {
            "No TFTP reply within 30s after DATA - the upload stalled silently, which is the \
             exact defect this test exists to catch"
        })??;

    let (code, message) = expect_error_packet(&buffer[..n]);
    assert_eq!(code, 0, "LLM failure is reported as 'not defined' (code 0)");
    assert_ne!(
        u16::from_be_bytes([buffer[0], buffer[1]]),
        4,
        "an LLM failure must never be answered with an ACK - that reads as a successful write"
    );
    println!("  [TEST] write-block failure -> ERROR {code}: {message}");

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

//! TFTP client tests.
//!
//! The client was re-enabled in August 2026 after sitting commented out of the registry since
//! November 2025 (`66212c37`, "Client needs call_llm_for_client API updates"). These tests
//! exist because it had none before — being unregistered, nothing could have run them.
//!
//! **Peer honesty:** the E2E test's server is a minimal RFC 1350 responder written inside
//! this file, not NetGet's TFTP server, so at least the two sides do not share a codec. That
//! is still weaker than a third-party implementation. macOS ships `/usr/bin/tftp` (a client,
//! no use for testing a client) and `/usr/libexec/tftpd`, which only runs under inetd and
//! cannot easily be driven from a test. If a standalone TFTP server becomes available here,
//! it should replace the in-test one.


use super::super::super::helpers::{self, E2EResult, NetGetConfig};
use netget::client::tftp::{build_request_packet, TftpPacket, OP_ACK, OP_DATA, OP_RRQ, OP_WRQ};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

// ===========================================================================
// Codec against RFC 1350 literal bytes
// ===========================================================================

/// RFC 1350 §5: `opcode(2) | filename | 0 | mode | 0`.
#[test]
fn builds_rrq_and_wrq_exactly_as_rfc_1350_specifies() {
    assert_eq!(
        build_request_packet(OP_RRQ, "pxelinux.0", "octet"),
        b"\x00\x01pxelinux.0\x00octet\x00".to_vec()
    );
    assert_eq!(
        build_request_packet(OP_WRQ, "config.txt", "netascii"),
        b"\x00\x02config.txt\x00netascii\x00".to_vec()
    );
}

#[test]
fn decodes_data_ack_and_error_packets() {
    assert_eq!(
        TftpPacket::decode(b"\x00\x03\x00\x01hello"),
        Some(TftpPacket::Data {
            block: 1,
            payload: b"hello".to_vec()
        })
    );
    assert_eq!(
        TftpPacket::decode(b"\x00\x04\x00\x2a"),
        Some(TftpPacket::Ack { block: 42 })
    );
    assert_eq!(
        TftpPacket::decode(b"\x00\x05\x00\x01File not found\x00"),
        Some(TftpPacket::Error {
            code: 1,
            message: "File not found".to_string()
        })
    );
}

#[test]
fn a_final_data_block_is_shorter_than_512_bytes() {
    // A full block is not final; anything shorter is.
    let full = {
        let mut p = vec![0x00, 0x03, 0x00, 0x01];
        p.extend_from_slice(&[b'x'; 512]);
        p
    };
    match TftpPacket::decode(&full).unwrap() {
        TftpPacket::Data { payload, .. } => assert_eq!(payload.len(), 512),
        other => panic!("wrong packet: {:?}", other),
    }
    match TftpPacket::decode(b"\x00\x03\x00\x02short").unwrap() {
        TftpPacket::Data { payload, .. } => assert!(payload.len() < 512),
        other => panic!("wrong packet: {:?}", other),
    }
}

#[test]
fn rejects_truncated_and_client_only_opcodes() {
    assert_eq!(TftpPacket::decode(b"\x00\x03\x00"), None, "too short");
    assert_eq!(
        TftpPacket::decode(b"\x00\x01name\x00octet\x00"),
        None,
        "a client never receives an RRQ"
    );
}

/// An ERROR packet whose message is not NUL-terminated must still decode rather than panic —
/// a malformed peer should not take the client down.
#[test]
fn tolerates_an_unterminated_error_message() {
    assert_eq!(
        TftpPacket::decode(b"\x00\x05\x00\x02Access violation"),
        Some(TftpPacket::Error {
            code: 2,
            message: "Access violation".to_string()
        })
    );
}

// ===========================================================================
// E2E: the client against an RFC 1350 responder written here, LLM mocked
// ===========================================================================

/// What the in-test server observed, so the test can assert on protocol behaviour rather
/// than on log strings.
#[derive(Default, Debug)]
struct Observed {
    rrq_filename: Option<String>,
    rrq_mode: Option<String>,
    acked_blocks: Vec<u16>,
}

/// A two-block RFC 1350 read server. Deliberately written from the RFC in this file rather
/// than reusing NetGet's TFTP server, so the two ends of the exchange share no code.
///
/// It also switches to a fresh socket for the transfer, exactly as a real TFTP server does
/// (RFC 1350 §4: the server answers from a newly allocated TID), which is the part of the
/// protocol a client most often gets wrong.
async fn start_rfc1350_read_server(observed: Arc<Mutex<Observed>>) -> E2EResult<u16> {
    let control = UdpSocket::bind("127.0.0.1:0").await?;
    let port = control.local_addr()?.port();

    tokio::spawn(async move {
        let mut buf = vec![0u8; 1024];
        let Ok((n, peer)) = control.recv_from(&mut buf).await else {
            return;
        };
        let packet = &buf[..n];
        if packet.len() < 4 || u16::from_be_bytes([packet[0], packet[1]]) != OP_RRQ {
            return;
        }
        // filename NUL mode NUL
        let mut fields = packet[2..].split(|b| *b == 0);
        let filename = String::from_utf8_lossy(fields.next().unwrap_or(&[])).into_owned();
        let mode = String::from_utf8_lossy(fields.next().unwrap_or(&[])).into_owned();
        {
            let mut o = observed.lock().await;
            o.rrq_filename = Some(filename);
            o.rrq_mode = Some(mode);
        }

        // RFC 1350 §4: reply from a freshly allocated TID.
        let Ok(transfer) = UdpSocket::bind("127.0.0.1:0").await else {
            return;
        };

        // Block 1: a full 512 bytes, so the transfer is not over.
        let mut block1 = vec![0x00, OP_DATA as u8, 0x00, 0x01];
        block1.extend_from_slice(&[b'A'; 512]);
        let _ = transfer.send_to(&block1, peer).await;

        // Expect ACK 1, then send the short final block.
        let mut ack = vec![0u8; 64];
        for _ in 0..2 {
            let Ok(Ok((len, _))) =
                tokio::time::timeout(Duration::from_secs(15), transfer.recv_from(&mut ack)).await
            else {
                return;
            };
            if len >= 4 && u16::from_be_bytes([ack[0], ack[1]]) == OP_ACK {
                let block = u16::from_be_bytes([ack[2], ack[3]]);
                observed.lock().await.acked_blocks.push(block);
                if block == 1 {
                    let mut block2 = vec![0x00, OP_DATA as u8, 0x00, 0x02];
                    block2.extend_from_slice(b"tail");
                    let _ = transfer.send_to(&block2, peer).await;
                } else {
                    return;
                }
            }
        }
    });

    Ok(port)
}

/// Full read transfer: the model asks for a file, acknowledges each block, and the client
/// follows the server's new TID.
#[tokio::test]
async fn reads_a_two_block_file() -> E2EResult<()> {
    let observed = Arc::new(Mutex::new(Observed::default()));
    let port = start_rfc1350_read_server(observed.clone()).await?;

    let config = NetGetConfig::new(format!(
        "connect to 127.0.0.1:{} via tftp and read the file boot.img in octet mode",
        port
    ))
    .with_log_level("debug")
    .with_mock(|mock| {
        mock
            // Each DATA block is acknowledged with its own block number, taken from the
            // event. A static ACK would stall the transfer at block 1.
            .on_event("tftp_data_received")
            .respond_with_actions_from_event(|event| {
                let block = event["block_number"].as_u64().unwrap_or(0);
                serde_json::json!([{ "type": "send_ack", "block_number": block }])
            })
            .expect_calls(2)
            .and()
            .on_event("tftp_transfer_complete")
            .respond_with_actions(serde_json::json!([{ "type": "disconnect" }]))
            .expect_calls(1)
            .and()
            .on_event("tftp_connected")
            .respond_with_actions(serde_json::json!([{
                "type": "tftp_read_file",
                "filename": "boot.img",
                "mode": "octet"
            }]))
            .expect_calls(1)
            .and()
            .on_instruction_containing("via tftp")
            .respond_with_actions_from_event(move |_| {
                serde_json::json!([{
                    "type": "open_client",
                    "remote_addr": format!("127.0.0.1:{}", port),
                    "base_stack": "tftp",
                    "instruction": "Read boot.img in octet mode"
                }])
            })
            .expect_calls(1)
            .and()
    });

    let client = helpers::start_netget_client(config).await?;

    // Give the transfer time to run: four LLM round trips plus the UDP exchange.
    client.wait_for_mocks(30).await;

    let seen = observed.lock().await;
    assert_eq!(
        seen.rrq_filename.as_deref(),
        Some("boot.img"),
        "the filename the model chose must reach the wire. Client output: {:?}",
        client.get_output().await
    );
    assert_eq!(seen.rrq_mode.as_deref(), Some("octet"));
    assert_eq!(
        seen.acked_blocks,
        vec![1, 2],
        "both blocks must be acknowledged, in order, on the server's new TID"
    );
    drop(seen);

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last response routinely lands
    // after the sleep expires, and the test reports it as never having happened.
    client.wait_for_mocks(30).await;
    client.verify_mocks().await?;
    client.stop().await?;
    Ok(())
}

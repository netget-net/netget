//! The lockstep's failure cases, driven from raw UDP sockets so each one can be provoked.
//!
//! Real clients rarely lose a datagram on loopback, so `real_client_test.rs` cannot show any
//! of this: what a client does when a packet is late, repeated, or from the wrong place.
//!
//! * **A repeated RRQ is one transfer.** Two copies of the same request from the same port
//!   (what a client sends while the model is thinking) reach the model once and produce one
//!   stream of DATA from one TID. Verified by removing `claim_request`: the read rule is then
//!   called twice and a second TID answers.
//! * **An unacknowledged block is sent again**, on the same TID, and the transfer continues
//!   once it is acknowledged. Verified by making `await_ack` give up on its first timeout.
//! * **A stale ACK is not answered** (no Sorcerer's Apprentice), and **a stranger's datagram on
//!   the TID gets ERROR 5** without disturbing the transfer.
//! * **A repeated upload block gets its ACK again and does not reach the model**: the data-block
//!   rule expects exactly as many calls as there are distinct blocks.

use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;

fn request(opcode: u16, filename: &str) -> Vec<u8> {
    let mut packet = opcode.to_be_bytes().to_vec();
    packet.extend_from_slice(filename.as_bytes());
    packet.push(0);
    packet.extend_from_slice(b"octet");
    packet.push(0);
    packet
}

fn ack(block: u16) -> Vec<u8> {
    let mut packet = 4u16.to_be_bytes().to_vec();
    packet.extend_from_slice(&block.to_be_bytes());
    packet
}

fn data(block: u16, bytes: &[u8]) -> Vec<u8> {
    let mut packet = 3u16.to_be_bytes().to_vec();
    packet.extend_from_slice(&block.to_be_bytes());
    packet.extend_from_slice(bytes);
    packet
}

/// The next datagram, its sender, opcode and block (or error code).
async fn recv(socket: &UdpSocket, secs: u64) -> E2EResult<(SocketAddr, u16, u16, Vec<u8>)> {
    let mut buf = vec![0u8; 600];
    let (n, from) = timeout(Duration::from_secs(secs), socket.recv_from(&mut buf))
        .await
        .map_err(|_| format!("no datagram within {secs}s"))??;
    let packet = buf[..n].to_vec();
    assert!(n >= 4, "short packet {packet:?}");
    let opcode = u16::from_be_bytes([packet[0], packet[1]]);
    let field = u16::from_be_bytes([packet[2], packet[3]]);
    Ok((from, opcode, field, packet[4..].to_vec()))
}

/// Nothing arrives within `secs`.
async fn quiet(socket: &UdpSocket, secs: u64) -> bool {
    let mut buf = vec![0u8; 600];
    timeout(Duration::from_secs(secs), socket.recv_from(&mut buf))
        .await
        .is_err()
}

#[tokio::test]
async fn tftp_transfers_survive_repeats_losses_and_strangers() -> E2EResult<()> {
    let file: String = (0..40)
        .map(|i| format!("line {i:03} of the file\n"))
        .collect();
    assert!(file.len() > 512 && file.len() < 1024, "two blocks");
    let served = file.clone();
    let config = NetGetConfig::new_no_scripts("listen on port {AVAILABLE_PORT} via tftp")
        .with_mock(move |mock| {
            mock.on_instruction_containing("via tftp")
                .respond_with_actions(serde_json::json!([{
                    "type": "open_server", "port": 0, "base_stack": "TFTP",
                    "instruction": "serve files"
                }]))
                .expect_calls(1)
                .and()
                .on_event("tftp_read_request")
                .respond_with_actions(serde_json::json!([
                    {"type": "send_tftp_file", "content": served}
                ]))
                .expect_calls(1)
                .and()
                .on_event("tftp_write_request")
                .respond_with_actions(serde_json::json!([
                    {"type": "send_tftp_ack", "block_number": 0}
                ]))
                .expect_calls(1)
                .and()
                .on_event("tftp_data_block")
                .respond_with_actions_from_event(|event| {
                    serde_json::json!([{"type": "send_tftp_ack",
                            "block_number": event["block_number"].as_u64().unwrap_or(0)}])
                })
                .expect_calls(2)
                .and()
        });
    let server = start_netget_server(config).await?;
    let main: SocketAddr = format!("127.0.0.1:{}", server.port).parse()?;
    let client = UdpSocket::bind("127.0.0.1:0").await?;

    // The same RRQ twice, back to back: one transfer.
    let rrq = request(1, "two-blocks.txt");
    client.send_to(&rrq, main).await?;
    client.send_to(&rrq, main).await?;
    let (tid, opcode, block, first) = recv(&client, 30).await?;
    assert_eq!((opcode, block), (3, 1), "DATA 1");
    assert_eq!(first.len(), 512);

    // Withhold the ACK: block 1 comes again, from the same TID.
    let (again_from, opcode, block, again) = recv(&client, 10).await?;
    assert_eq!(
        (again_from, opcode, block),
        (tid, 3, 1),
        "block 1 retransmitted"
    );
    assert_eq!(again, first);

    // A stranger writing to the TID is told it has the wrong transfer.
    let stranger = UdpSocket::bind("127.0.0.1:0").await?;
    stranger.send_to(&ack(1), tid).await?;
    let (_, opcode, code, _) = recv(&stranger, 10).await?;
    assert_eq!(
        (opcode, code),
        (5, 5),
        "ERROR 5 (unknown transfer ID) to the stranger"
    );

    // ACK 1: block 2. Then a stale ACK 1 again: answered with nothing.
    client.send_to(&ack(1), tid).await?;
    let (from, opcode, block, second) = recv(&client, 10).await?;
    assert_eq!((from, opcode, block), (tid, 3, 2));
    client.send_to(&ack(1), tid).await?;
    client.send_to(&ack(2), tid).await?;
    let mut whole = first.clone();
    whole.extend_from_slice(&second);
    assert_eq!(String::from_utf8_lossy(&whole), file);
    assert!(
        quiet(&client, 3).await,
        "a stale ACK must not be answered with a retransmission, and nothing follows ACK 2"
    );

    // Upload: block 1 twice (the client missed our ACK), then the final block.
    let uploader = UdpSocket::bind("127.0.0.1:0").await?;
    uploader.send_to(&request(2, "up.txt"), main).await?;
    let (utid, opcode, block, _) = recv(&uploader, 30).await?;
    assert_eq!((opcode, block), (4, 0), "ACK 0 for the WRQ");
    let block1 = vec![b'u'; 512];
    uploader.send_to(&data(1, &block1), utid).await?;
    let (_, opcode, block, _) = recv(&uploader, 30).await?;
    assert_eq!((opcode, block), (4, 1));
    uploader.send_to(&data(1, &block1), utid).await?;
    let (_, opcode, block, _) = recv(&uploader, 10).await?;
    assert_eq!(
        (opcode, block),
        (4, 1),
        "the repeated block gets its ACK again"
    );
    uploader.send_to(&data(2, b"end\n"), utid).await?;
    let (_, opcode, block, _) = recv(&uploader, 30).await?;
    assert_eq!((opcode, block), (4, 2));

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

//! BitTorrent Peer Wire Protocol E2E tests with mocks

use crate::helpers::*;
use serde_json::json;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Test peer handshake and bitfield exchange with mocks
///
/// LLM calls: 3 total
/// - 1 server startup
/// - 1 handshake response
/// - 1 bitfield message
#[tokio::test]
async fn test_peer_handshake_and_bitfield() -> E2EResult<()> {
    let test_info_hash = "0123456789abcdef0123456789abcdef01234567";

    // Start peer server with mocks
    let server_config = NetGetConfig::new(
        format!("Listen on port {{AVAILABLE_PORT}} via torrent-peer. You are a seeder with all pieces for info_hash {}. Respond to handshakes and send bitfield ff.", test_info_hash)
    )
    .with_mock(|mock| {
        mock
            // Mock 1: Server startup
            .on_instruction_containing("Listen on port")
            .and_instruction_containing("torrent-peer")
            .respond_with_actions(json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "Torrent-Peer",
                    "instruction": "BitTorrent seeder"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 2: Handshake received
            .on_event("peer_handshake")
            .and_event_data_contains("info_hash", test_info_hash)
            .respond_with_actions(json!([
                {
                    "type": "send_handshake",
                    "info_hash": test_info_hash,
                    "peer_id": "-NT0001-xxxxxxxxxxxx"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 3: After handshake, send bitfield and unchoke
            .on_event("peer_bitfield_message")
            .respond_with_actions(json!([
                {
                    "type": "send_bitfield",
                    "bitfield": "ff"
                },
                {
                    "type": "send_unchoke"
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let mut server = start_netget_server(server_config).await?;

    tokio::time::sleep(Duration::from_millis(500)).await;

    // Connect to peer server
    let peer_addr = format!("127.0.0.1:{}", server.port);
    println!("Connecting to peer at {}", peer_addr);

    let mut stream = TcpStream::connect(&peer_addr).await?;

    // Send handshake
    let mut handshake = Vec::new();
    handshake.push(19u8);
    handshake.extend_from_slice(b"BitTorrent protocol");
    handshake.extend_from_slice(&[0u8; 8]); // reserved
    handshake.extend_from_slice(&hex::decode(test_info_hash)?);
    handshake.extend_from_slice(b"TEST_CLIENT_12345678");

    println!("Sending handshake ({} bytes)", handshake.len());
    stream.write_all(&handshake).await?;

    // Read handshake response
    let mut response = vec![0u8; 68];
    stream.read_exact(&mut response).await?;

    println!("Received handshake response ({} bytes)", response.len());

    // Verify handshake
    assert_eq!(response[0], 19, "Invalid pstrlen");
    assert_eq!(&response[1..20], b"BitTorrent protocol", "Invalid pstr");

    let peer_info_hash = hex::encode(&response[28..48]);
    assert_eq!(peer_info_hash, test_info_hash, "Info hash mismatch");

    let peer_id = String::from_utf8_lossy(&response[48..68]);
    println!("Peer ID: {}", peer_id);

    println!("✅ Handshake exchange successful");

    // Send bitfield message (simulate we have no pieces)
    let bitfield_msg = vec![
        0, 0, 0, 2,    // length = 2
        5,    // id = bitfield
        0x00, // bitfield = 00000000 (no pieces)
    ];
    stream.write_all(&bitfield_msg).await?;
    println!("Sent bitfield message");

    // Read messages from peer (expecting bitfield and unchoke)
    for i in 0..2 {
        let mut len_buf = [0u8; 4];
        match tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut len_buf)).await {
            Ok(Ok(_)) => {
                let length = u32::from_be_bytes(len_buf) as usize;

                if length == 0 {
                    println!("Message {}: keepalive", i + 1);
                    continue;
                }

                let mut message = vec![0u8; length];
                stream.read_exact(&mut message).await?;

                let message_id = message[0];
                println!(
                    "Message {}: id={} ({} bytes)",
                    i + 1,
                    message_id,
                    message.len()
                );

                match message_id {
                    1 => println!("  Type: unchoke"),
                    5 => {
                        println!("  Type: bitfield");
                        let bitfield = &message[1..];
                        println!("  Bitfield: {}", hex::encode(bitfield));
                    }
                    _ => println!("  Type: {}", message_id),
                }
            }
            Ok(Err(e)) => {
                println!("Error reading message {}: {}", i + 1, e);
                break;
            }
            Err(_) => {
                println!("Timeout waiting for message {}", i + 1);
                break;
            }
        }
    }

    println!("✅ Bitfield exchange successful");

    // Verify all mocks were called
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;

    // Cleanup
    server.stop().await?;

    Ok(())
}

/// Test peer piece request and transfer with mocks
///
/// LLM calls: 3 total
/// - 1 server startup
/// - 1 handshake response
/// - 1 piece request response
#[tokio::test]
async fn test_peer_piece_request() -> E2EResult<()> {
    let test_info_hash = "fedcba9876543210fedcba9876543210fedcba98";

    // Start peer server with mocks
    let server_config = NetGetConfig::new(
        format!("Listen on port {{AVAILABLE_PORT}} via torrent-peer. You are a seeder for info_hash {}. Send pieces when requested. Keep peers unchoked.", test_info_hash)
    )
    .with_mock(|mock| {
        mock
            // Mock: Server startup
            .on_instruction_containing("Listen on port")
            .and_instruction_containing("torrent-peer")
            .respond_with_actions(json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "Torrent-Peer",
                    "instruction": "Seeder with piece data"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock: Handshake
            .on_event("peer_handshake")
            .respond_with_actions(json!([
                {
                    "type": "send_handshake",
                    "info_hash": test_info_hash,
                    "peer_id": "-NT0001-yyyyyyyyyyyy"
                },
                {
                    "type": "send_unchoke"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock: Interested/Choke message (client sends interested)
            .on_event("peer_choke_message")
            .respond_with_actions(json!([
                {
                    "type": "send_unchoke"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock: Piece request (match any index since we're only testing one request)
            .on_event("peer_request_message")
            .respond_with_actions_from_event(|event_data| {
                let index = event_data["index"].as_u64().unwrap_or(0);
                let begin = event_data["begin"].as_u64().unwrap_or(0);
                json!([
                    {
                        "type": "send_piece",
                        "index": index,
                        "begin": begin,
                        "block_hex": "48656c6c6f20576f726c64"  // "Hello World"
                    }
                ])
            })
            .expect_calls(1)
            .and()
    });

    let mut server = start_netget_server(server_config).await?;

    tokio::time::sleep(Duration::from_millis(500)).await;

    // Connect to peer
    let peer_addr = format!("127.0.0.1:{}", server.port);
    let mut stream = TcpStream::connect(&peer_addr).await?;

    // Send handshake
    let mut handshake = Vec::new();
    handshake.push(19u8);
    handshake.extend_from_slice(b"BitTorrent protocol");
    handshake.extend_from_slice(&[0u8; 8]);
    handshake.extend_from_slice(&hex::decode(test_info_hash)?);
    handshake.extend_from_slice(b"TEST_CLIENT_87654321");

    stream.write_all(&handshake).await?;

    // Read handshake response
    let mut response = vec![0u8; 68];
    stream.read_exact(&mut response).await?;

    println!("Handshake complete");

    // Read unchoke message (if sent)
    let mut len_buf = [0u8; 4];
    if let Ok(Ok(_)) =
        tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut len_buf)).await
    {
        let length = u32::from_be_bytes(len_buf) as usize;
        if length > 0 {
            let mut message = vec![0u8; length];
            stream.read_exact(&mut message).await?;
            println!("Received message: id={}", message[0]);
        }
    }

    // Send interested message
    stream.write_all(&[0, 0, 0, 1, 2]).await?;
    println!("Sent interested message");

    // Read unchoke response after interested
    let mut len_buf = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut len_buf))
        .await
        .ok();
    if let Ok(length) = u32::from_be_bytes(len_buf).try_into() {
        if length > 0 && length < 1000 {
            let mut msg = vec![0u8; length];
            stream.read_exact(&mut msg).await.ok();
            println!(
                "Received response to interested: id={}",
                msg.get(0).unwrap_or(&255)
            );
        }
    }

    // Send piece request (piece 0, begin 0, length 11)
    let request = vec![
        0, 0, 0, 13, // length = 13
        6,  // id = request
        0, 0, 0, 0, // index = 0
        0, 0, 0, 0, // begin = 0
        0, 0, 0, 11, // length = 11
    ];
    stream.write_all(&request).await?;
    println!("Sent piece request");

    // Read piece response
    let mut len_buf = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut len_buf))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "Piece timeout"))??;

    let length = u32::from_be_bytes(len_buf) as usize;
    println!("Piece message length: {}", length);

    let mut message = vec![0u8; length];
    stream.read_exact(&mut message).await?;

    assert_eq!(message[0], 7, "Expected piece message (id=7)");

    let index = u32::from_be_bytes([message[1], message[2], message[3], message[4]]);
    let begin = u32::from_be_bytes([message[5], message[6], message[7], message[8]]);
    let block = &message[9..];

    println!(
        "Received piece: index={}, begin={}, block size={}",
        index,
        begin,
        block.len()
    );
    println!("Block data: {}", String::from_utf8_lossy(block));

    assert_eq!(index, 0, "Piece index should be 0");
    assert_eq!(begin, 0, "Begin offset should be 0");
    assert_eq!(block, b"Hello World", "Block data should match");

    println!("✅ Piece request and transfer successful");

    // Verify all mocks
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;

    // Cleanup
    server.stop().await?;

    Ok(())
}

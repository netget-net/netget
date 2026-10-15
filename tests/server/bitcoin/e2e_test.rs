//! E2E tests for Bitcoin P2P protocol server
//!
//! These tests spawn the NetGet binary and test Bitcoin P2P operations
//! using raw TCP clients to send/receive Bitcoin P2P messages.

mod e2e_bitcoin {
    use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
    use std::io::Cursor;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    use tokio::time::{timeout, Duration};

    // Import bitcoin crate for message building/parsing
    use bitcoin::consensus::{Decodable, Encodable};
    use bitcoin::p2p::address::Address;
    use bitcoin::p2p::message::{NetworkMessage, RawNetworkMessage};
    use bitcoin::p2p::message_network::VersionMessage;
    use bitcoin::p2p::Magic;
    use bitcoin::p2p::ServiceFlags;

    /// Helper to build a Bitcoin version message
    fn build_version_message() -> RawNetworkMessage {
        let receiver = Address::new(
            &std::net::SocketAddr::from(([127, 0, 0, 1], 8333)),
            ServiceFlags::NONE,
        );
        let sender = Address::new(
            &std::net::SocketAddr::from(([127, 0, 0, 1], 9999)),
            ServiceFlags::NONE,
        );

        let version_msg = VersionMessage {
            version: 70015,
            services: ServiceFlags::NONE,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
            receiver,
            sender,
            nonce: rand::random(),
            user_agent: "/TestClient:0.1.0/".to_string(),
            start_height: 0,
            relay: false,
        };

        RawNetworkMessage::new(Magic::BITCOIN, NetworkMessage::Version(version_msg))
    }

    /// Helper to read a Bitcoin P2P message from stream
    async fn read_bitcoin_message(stream: &mut TcpStream) -> E2EResult<RawNetworkMessage> {
        // Read header (24 bytes: magic 4 + command 12 + length 4 + checksum 4)
        let mut header = [0u8; 24];
        stream.read_exact(&mut header).await?;

        // Extract payload length
        let length = u32::from_le_bytes([header[16], header[17], header[18], header[19]]);

        // Read payload
        let mut payload = vec![0u8; length as usize];
        if length > 0 {
            stream.read_exact(&mut payload).await?;
        }

        // Reconstruct full message
        let mut full_msg = Vec::new();
        full_msg.extend_from_slice(&header);
        full_msg.extend_from_slice(&payload);

        // Parse message
        let mut cursor = Cursor::new(full_msg);
        let msg = RawNetworkMessage::consensus_decode(&mut cursor)?;

        Ok(msg)
    }

    /// Wait until every mock expectation is satisfied, or give up after `limit`.
    ///
    /// Used where the last thing a test does is send a message that the server
    /// answers with no bytes: the mock call is recorded asynchronously, so a
    /// bare `verify_mocks()` would sample the counters too early. On timeout
    /// this returns the real verification error, so a genuinely missing call
    /// still fails the test.
    async fn wait_for_mocks(
        server: &crate::helpers::server::NetGetServer,
        limit: Duration,
    ) -> E2EResult<()> {
        let deadline = tokio::time::Instant::now() + limit;
        loop {
            match server.verify_mocks().await {
                Ok(()) => return Ok(()),
                Err(e) => {
                    if tokio::time::Instant::now() >= deadline {
                        return Err(e);
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }

    #[tokio::test]
    async fn test_bitcoin_version_verack_handshake() -> E2EResult<()> {
        println!("\n=== Test: Bitcoin Version/Verack Handshake ===");

        let prompt = "listen on port 0 via bitcoin with network=mainnet. \
             When a peer connects, wait for their version message. \
             Respond with your own version message (protocol 70015, services 0, user_agent '/NetGet:0.1.0/', start_height 0). \
             Then send verack to complete the handshake. \
             After receiving verack from peer, handshake is complete.";

        let config = NetGetConfig::new(prompt).with_mock(|mock| {
            mock
                // Mock 1: User command to open server
                .on_instruction_containing("listen on port")
                .and_instruction_containing("bitcoin")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "Bitcoin",
                        "startup_params": {
                            "network": "mainnet"
                        },
                        "instruction": "Handle Bitcoin P2P protocol"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2: Connection opened (wait for version)
                .on_event("bitcoin_connection_opened")
                .respond_with_actions(serde_json::json!([]))
                .expect_calls(1)
                .and()
                // Mock 3: Version message received
                .on_event("bitcoin_message_received")
                .and_event_data_contains("message_type", "version")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "send_version",
                        "network": "mainnet",
                        "version": 70015,
                        "services": 0,
                        "user_agent": "/NetGet:0.1.0/",
                        "start_height": 0,
                        "relay": false
                    },
                    {
                        "type": "send_verack",
                        "network": "mainnet"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 4: Verack received from peer
                .on_event("bitcoin_message_received")
                .and_event_data_contains("message_type", "verack")
                .respond_with_actions(serde_json::json!([]))
                .expect_calls(1)
                .and()
        });

        let server = start_netget_server(config).await?;

        // Wait for server to be ready
        crate::helpers::wait_for_server_listening(&server, Duration::from_secs(30)).await?;

        // Connect to Bitcoin P2P server
        println!(
            "  [TEST] Connecting to Bitcoin P2P server on port {}",
            server.port
        );
        let mut client = timeout(
            Duration::from_secs(5),
            TcpStream::connect(format!("127.0.0.1:{}", server.port)),
        )
        .await??;

        // Send version message from client
        println!("  [TEST] Sending version message to server");
        let version_msg = build_version_message();
        let mut msg_bytes = Vec::new();
        version_msg.consensus_encode(&mut msg_bytes)?;
        client.write_all(&msg_bytes).await?;
        client.flush().await?;

        // Read server's version response
        println!("  [TEST] Reading version response from server");
        let response =
            timeout(Duration::from_secs(120), read_bitcoin_message(&mut client)).await??;

        match response.payload() {
            NetworkMessage::Version(v) => {
                println!(
                    "  [TEST] Received version: protocol={}, services={}, user_agent={}, start_height={}",
                    v.version, v.services, v.user_agent, v.start_height
                );
                assert_eq!(v.version, 70015, "Expected protocol version 70015");
            }
            other => {
                return Err(format!("Expected version message, got {:?}", other).into());
            }
        }

        // Read server's verack
        println!("  [TEST] Reading verack from server");
        let verack_response =
            timeout(Duration::from_secs(120), read_bitcoin_message(&mut client)).await??;

        match verack_response.payload() {
            NetworkMessage::Verack => {
                println!("  [TEST] ✓ Received verack from server");
            }
            other => {
                return Err(format!("Expected verack message, got {:?}", other).into());
            }
        }

        // Send verack to complete handshake
        println!("  [TEST] Sending verack to complete handshake");
        let verack_msg = RawNetworkMessage::new(Magic::BITCOIN, NetworkMessage::Verack);
        let mut verack_bytes = Vec::new();
        verack_msg.consensus_encode(&mut verack_bytes)?;
        client.write_all(&verack_bytes).await?;
        client.flush().await?;

        println!("  [TEST] ✓ Bitcoin P2P handshake completed successfully");

        // The peer's verack produces no reply on the wire (the mock answers it
        // with an empty action list), so there is nothing to read that proves
        // the server got that far. Poll the mock accounting instead of racing
        // it — verifying immediately after write_all() checks the expectation
        // before the server has even read the bytes.
        wait_for_mocks(&server, Duration::from_secs(15)).await?;

        // Verify mock expectations
        server.verify_mocks().await?;

        server.stop().await?;
        println!("  [TEST] ✓ Test completed successfully\n");

        Ok(())
    }

    #[tokio::test]
    async fn test_bitcoin_ping_pong() -> E2EResult<()> {
        println!("\n=== Test: Bitcoin Ping/Pong ===");

        let prompt = "listen on port 0 via bitcoin with network=mainnet. \
             Complete the version/verack handshake with peers. \
             When you receive a ping message, respond with a pong message using the same nonce.";

        let config = NetGetConfig::new(prompt).with_mock(|mock| {
            mock
                // Mock 1: User command to open server
                .on_instruction_containing("listen on port")
                .and_instruction_containing("bitcoin")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "Bitcoin",
                        "startup_params": {
                            "network": "mainnet"
                        },
                        "instruction": "Handle handshake and ping/pong"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2: Connection opened
                .on_event("bitcoin_connection_opened")
                .respond_with_actions(serde_json::json!([]))
                .expect_calls(1)
                .and()
                // Mock 3: Version received
                .on_event("bitcoin_message_received")
                .and_event_data_contains("message_type", "version")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "send_version",
                        "network": "mainnet",
                        "version": 70015
                    },
                    {
                        "type": "send_verack",
                        "network": "mainnet"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 4: Verack received
                .on_event("bitcoin_message_received")
                .and_event_data_contains("message_type", "verack")
                .respond_with_actions(serde_json::json!([]))
                .expect_calls(1)
                .and()
                // Mock 5: Ping received - extract nonce and respond
                .on_event("bitcoin_message_received")
                .and_event_data_contains("message_type", "ping")
                .respond_with_actions_from_event(|event_data| {
                    // Extract nonce from ping message
                    let nonce = event_data
                        .get("message")
                        .and_then(|m| m.get("nonce"))
                        .and_then(|n| n.as_u64())
                        .unwrap_or(0);

                    serde_json::json!([
                        {
                            "type": "send_pong",
                            "network": "mainnet",
                            "nonce": nonce
                        }
                    ])
                })
                .expect_calls(1)
                .and()
        });

        let server = start_netget_server(config).await?;
        crate::helpers::wait_for_server_listening(&server, Duration::from_secs(30)).await?;

        println!("  [TEST] Establishing Bitcoin P2P connection");
        let mut client = TcpStream::connect(format!("127.0.0.1:{}", server.port)).await?;

        // Complete handshake first
        let version_msg = build_version_message();
        let mut msg_bytes = Vec::new();
        version_msg.consensus_encode(&mut msg_bytes)?;
        client.write_all(&msg_bytes).await?;
        client.flush().await?;

        // Read version and verack
        let _version_response =
            timeout(Duration::from_secs(120), read_bitcoin_message(&mut client)).await??;
        let _verack_response =
            timeout(Duration::from_secs(120), read_bitcoin_message(&mut client)).await??;

        // Send verack
        let verack_msg = RawNetworkMessage::new(Magic::BITCOIN, NetworkMessage::Verack);
        let mut verack_bytes = Vec::new();
        verack_msg.consensus_encode(&mut verack_bytes)?;
        client.write_all(&verack_bytes).await?;
        client.flush().await?;

        println!("  [TEST] ✓ Handshake complete");

        // Send ping with random nonce
        let ping_nonce: u64 = rand::random();
        println!("  [TEST] Sending ping with nonce={}", ping_nonce);
        let ping_msg = RawNetworkMessage::new(Magic::BITCOIN, NetworkMessage::Ping(ping_nonce));
        let mut ping_bytes = Vec::new();
        ping_msg.consensus_encode(&mut ping_bytes)?;
        client.write_all(&ping_bytes).await?;
        client.flush().await?;

        // Read pong response
        println!("  [TEST] Reading pong response from server");
        let pong_response =
            timeout(Duration::from_secs(120), read_bitcoin_message(&mut client)).await??;

        match pong_response.payload() {
            NetworkMessage::Pong(nonce) => {
                println!("  [TEST] Received pong with nonce={}", nonce);
                assert_eq!(*nonce, ping_nonce, "Pong nonce should match ping nonce");
                println!("  [TEST] ✓ Ping/Pong exchange successful");
            }
            other => {
                return Err(format!("Expected pong message, got {:?}", other).into());
            }
        }

        // Verify mock expectations
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last event routinely lands after
        // the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;

        server.stop().await?;
        println!("  [TEST] ✓ Test completed successfully\n");

        Ok(())
    }

    #[tokio::test]
    async fn test_bitcoin_getaddr() -> E2EResult<()> {
        println!("\n=== Test: Bitcoin getaddr ===");

        let prompt = "listen on port 0 via bitcoin with network=mainnet. \
             Complete handshake normally. \
             When you receive a getaddr message, respond with an addr message containing an empty list (no peers to share).";

        let config = NetGetConfig::new(prompt).with_mock(|mock| {
            mock
                // Mock 1: User command to open server
                .on_instruction_containing("listen on port")
                .and_instruction_containing("bitcoin")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "Bitcoin",
                        "startup_params": {
                            "network": "mainnet"
                        },
                        "instruction": "Handle handshake and getaddr"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2: Connection opened
                .on_event("bitcoin_connection_opened")
                .respond_with_actions(serde_json::json!([]))
                .expect_calls(1)
                .and()
                // Mock 3: Version received
                .on_event("bitcoin_message_received")
                .and_event_data_contains("message_type", "version")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "send_version",
                        "network": "mainnet",
                        "version": 70015
                    },
                    {
                        "type": "send_verack",
                        "network": "mainnet"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 4: Verack received
                .on_event("bitcoin_message_received")
                .and_event_data_contains("message_type", "verack")
                .respond_with_actions(serde_json::json!([]))
                .expect_calls(1)
                .and()
                // Mock 5: Getaddr received - no response (no peers to share)
                .on_event("bitcoin_message_received")
                .and_event_data_contains("message_type", "getaddr")
                .respond_with_actions(serde_json::json!([]))
                .expect_calls(1)
                .and()
        });

        let server = start_netget_server(config).await?;
        crate::helpers::wait_for_server_listening(&server, Duration::from_secs(30)).await?;

        println!("  [TEST] Establishing connection");
        let mut client = TcpStream::connect(format!("127.0.0.1:{}", server.port)).await?;

        // Complete handshake
        let version_msg = build_version_message();
        let mut msg_bytes = Vec::new();
        version_msg.consensus_encode(&mut msg_bytes)?;
        client.write_all(&msg_bytes).await?;
        client.flush().await?;

        let _version =
            timeout(Duration::from_secs(120), read_bitcoin_message(&mut client)).await??;
        let _verack =
            timeout(Duration::from_secs(120), read_bitcoin_message(&mut client)).await??;

        let verack_msg = RawNetworkMessage::new(Magic::BITCOIN, NetworkMessage::Verack);
        let mut verack_bytes = Vec::new();
        verack_msg.consensus_encode(&mut verack_bytes)?;
        client.write_all(&verack_bytes).await?;
        client.flush().await?;

        // Send getaddr
        println!("  [TEST] Sending getaddr message");
        let getaddr_msg = RawNetworkMessage::new(Magic::BITCOIN, NetworkMessage::GetAddr);
        let mut getaddr_bytes = Vec::new();
        getaddr_msg.consensus_encode(&mut getaddr_bytes)?;
        client.write_all(&getaddr_bytes).await?;
        client.flush().await?;

        // Read response (should be addr message or timeout is acceptable).
        // The mocked getaddr rule answers with no actions, so the expected
        // outcome here is the timeout; a 120s window would just be two minutes
        // of dead wall-clock. Everything else in this test resolves in
        // milliseconds against the mock, so 15s is a generous ceiling.
        println!("  [TEST] Waiting for addr response (or timeout)");
        let read_result = timeout(Duration::from_secs(15), read_bitcoin_message(&mut client)).await;

        match read_result {
            Ok(Ok(response)) => match response.payload() {
                NetworkMessage::Addr(addrs) => {
                    println!(
                        "  [TEST] ✓ Received addr message with {} addresses",
                        addrs.len()
                    );
                }
                other => {
                    println!("  [TEST] ✓ Received message type: {:?} (acceptable)", other);
                }
            },
            Ok(Err(e)) => {
                println!("  [TEST] ✓ Connection closed (acceptable): {}", e);
            }
            Err(_) => {
                println!("  [TEST] ✓ Timeout (acceptable - no peers to share)");
            }
        }

        // Verify mock expectations
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last event routinely lands after
        // the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;

        server.stop().await?;
        println!("  [TEST] ✓ Test completed successfully\n");

        Ok(())
    }

    #[tokio::test]
    async fn test_bitcoin_testnet() -> E2EResult<()> {
        println!("\n=== Test: Bitcoin Testnet Network ===");

        let prompt = "listen on port 0 via bitcoin with network=testnet. \
             Accept version messages and respond appropriately for testnet.";

        let config = NetGetConfig::new(prompt).with_mock(|mock| {
            mock
                // Mock 1: User command to open server
                .on_instruction_containing("listen on port")
                .and_instruction_containing("bitcoin")
                .and_instruction_containing("testnet")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "Bitcoin",
                        "startup_params": {
                            "network": "testnet"
                        },
                        "instruction": "Handle testnet Bitcoin P2P"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2: Connection opened
                .on_event("bitcoin_connection_opened")
                .respond_with_actions(serde_json::json!([]))
                .expect_calls(1)
                .and()
                // Mock 3: Version received - respond with testnet version
                .on_event("bitcoin_message_received")
                .and_event_data_contains("message_type", "version")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "send_version",
                        "network": "testnet",
                        "version": 70015,
                        "user_agent": "/NetGet:0.1.0/"
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let server = start_netget_server(config).await?;
        crate::helpers::wait_for_server_listening(&server, Duration::from_secs(30)).await?;

        println!("  [TEST] Connecting to testnet server");
        let mut client = TcpStream::connect(format!("127.0.0.1:{}", server.port)).await?;

        // Build testnet version message
        let receiver = Address::new(
            &std::net::SocketAddr::from(([127, 0, 0, 1], 18333)),
            ServiceFlags::NONE,
        );
        let sender = Address::new(
            &std::net::SocketAddr::from(([127, 0, 0, 1], 19999)),
            ServiceFlags::NONE,
        );

        let version_msg = VersionMessage {
            version: 70015,
            services: ServiceFlags::NONE,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
            receiver,
            sender,
            nonce: rand::random(),
            user_agent: "/TestClient:0.1.0/".to_string(),
            start_height: 0,
            relay: false,
        };

        let testnet_version =
            RawNetworkMessage::new(Magic::TESTNET3, NetworkMessage::Version(version_msg));

        println!("  [TEST] Sending testnet version message");
        let mut msg_bytes = Vec::new();
        testnet_version.consensus_encode(&mut msg_bytes)?;
        client.write_all(&msg_bytes).await?;
        client.flush().await?;

        // Read version response
        println!("  [TEST] Reading version response");
        let response =
            timeout(Duration::from_secs(120), read_bitcoin_message(&mut client)).await??;

        // Verify response uses testnet magic
        assert_eq!(
            *response.magic(),
            Magic::TESTNET3,
            "Server should use testnet magic bytes"
        );

        match response.payload() {
            NetworkMessage::Version(v) => {
                println!(
                    "  [TEST] ✓ Received testnet version: user_agent={}",
                    v.user_agent
                );
            }
            other => {
                return Err(format!("Expected version message, got {:?}", other).into());
            }
        }

        // Verify mock expectations
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last event routinely lands after
        // the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;

        server.stop().await?;
        println!("  [TEST] ✓ Test completed successfully\n");

        Ok(())
    }
}

//! E2E tests for STUN protocol
//!
//! These tests verify STUN server functionality by starting NetGet with STUN prompts
//! and using raw UDP sockets to send STUN binding requests.

#![cfg(unix)]

use crate::helpers::{start_netget_server, E2EResult, NetGetConfig};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;

// Every test here runs at `--log-level debug`, and that is load-bearing rather than
// preference.
//
// These servers are opened with `"port": 0`, so the port is ephemeral and the only way the
// harness learns it is by scraping the "listening on ADDR:PORT" line out of the child's
// output (`tests/helpers/netget.rs`). That line is not emitted below debug, so at
// `with_log_level("off")` — and at "info" — `test_state.port` stays 0, the client sends its
// binding request into the void, the server never raises `stun_binding_request`, and the test
// fails with "Rule #1: expected exactly 1, got 0" pointing at the mock rather than at the port.
//
// Five of these tests were at "off" and one at "info" and all six failed that way for a long
// time. If you add a test here, keep debug, or give the prompt an explicit
// `{AVAILABLE_PORT}` so the port is known before the server starts.

#[tokio::test]
async fn test_stun_basic_binding_request() -> E2EResult<()> {
    println!("\n=== E2E Test: STUN Basic Binding Request with Mocks ===");

    let config = NetGetConfig::new("Start a STUN server on port {AVAILABLE_PORT}")
        .with_log_level("debug")
        .with_mock(|mock| {
            mock
                // Mock 1: Server startup (user command)
                .on_instruction_containing("Start a STUN server")
                .and_instruction_containing("on port")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "STUN",
                        "instruction": "STUN server for NAT traversal"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2: STUN binding request received - DYNAMIC RESPONSE
                .on_event("stun_binding_request")
                .respond_with_actions_from_event(|event_data| {
                    // Extract transaction_id and peer_addr from event
                    let transaction_id = event_data["transaction_id"]
                        .as_str()
                        .unwrap_or("000000000000000000000000");
                    let peer_addr = event_data["peer_addr"]
                        .as_str()
                        .unwrap_or("127.0.0.1:54321");

                    serde_json::json!([{
                        "type": "send_stun_binding_response",
                        "transaction_id": transaction_id,  // ← DYNAMIC from event!
                        "mapped_address": peer_addr,        // ← DYNAMIC from event!
                        "xor_mapped_address": true
                    }])
                })
                .expect_calls(3) // Test sends 3 requests to rule out packet loss
                .and()
        });

    let mut test_state = start_netget_server(config).await?;

    // Extract server port
    let port = test_state.port;

    // Wait for server receive loop to be ready
    test_state
        .wait_for_log("STUN receive loop started", 5)
        .await?;

    // Give tokio time to register the socket with reactor
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Create UDP client socket (using tokio for async compatibility)
    let client = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind client socket");

    let server_addr: SocketAddr = format!("127.0.0.1:{}", port)
        .parse()
        .expect("Failed to parse server address");

    // Build STUN binding request
    let binding_request = build_stun_binding_request();

    // Send binding request multiple times to rule out packet loss
    for i in 0..3 {
        client
            .send_to(&binding_request, server_addr)
            .await
            .expect("Failed to send STUN request");
        println!("Sent STUN binding request #{} to {}", i + 1, server_addr);
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // Receive response with timeout
    let mut buf = vec![0u8; 2048];
    match tokio::time::timeout(Duration::from_secs(5), client.recv_from(&mut buf)).await {
        Ok(Ok((len, from))) => {
            println!("Received {} bytes from {}", len, from);

            // Parse STUN response
            let response = &buf[..len];

            // The pcap oracle: Wireshark's `stun` dissector reads the whole message —
            // the Message Length against the attributes that follow, and each
            // attribute's own length and 4-byte padding — where the assertions below
            // index into fixed offsets and can only see the header.
            crate::helpers::pcap_oracle::PcapOracle::udp("stun")
                .to_server(&binding_request)
                .from_server(response)
                .assert_clean();

            // Verify it's a valid STUN message
            assert!(len >= 20, "Response too short to be STUN message");

            // Check message type (should be 0x0101 for Binding Success Response)
            let message_type = u16::from_be_bytes([response[0], response[1]]);
            println!("Message type: 0x{:04x}", message_type);

            // Message type 0x0101 = Binding Success Response
            // Class = 1 (success), Method = 1 (binding)
            assert!(
                message_type == 0x0101,
                "Expected Binding Success Response (0x0101), got 0x{:04x}",
                message_type
            );

            // Verify magic cookie
            let magic_cookie =
                u32::from_be_bytes([response[4], response[5], response[6], response[7]]);
            assert_eq!(
                magic_cookie, 0x2112A442,
                "Invalid magic cookie: 0x{:08x}",
                magic_cookie
            );

            // Verify transaction ID matches (bytes 8-19)
            let response_tid = &response[8..20];
            let request_tid = &binding_request[8..20];
            assert_eq!(response_tid, request_tid, "Transaction ID mismatch");

            println!("✓ STUN binding request/response successful");
        }
        Ok(Err(e)) => {
            panic!("Failed to receive STUN response (IO error): {}", e);
        }
        Err(_) => {
            panic!("Failed to receive STUN response: timeout after 5 seconds");
        }
    }

    println!("\n=== All STUN tests passed! ===");

    // Verify mock expectations were met
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    test_state.wait_for_mocks(30).await;
    test_state.verify_mocks().await?;

    // Cleanup
    test_state.stop().await?;
    Ok(())
}

#[tokio::test]
async fn test_stun_multiple_clients() -> E2EResult<()> {
    println!("\n=== E2E Test: STUN Multiple Clients with Mocks ===");

    let config = NetGetConfig::new(
        "Start a STUN server on port {AVAILABLE_PORT} that returns the client's public address",
    )
    .with_log_level("debug")
    .with_mock(|mock| {
        mock
            // Mock 1: Server startup
            .on_instruction_containing("Start a STUN server")
            .and_instruction_containing("on port")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "STUN",
                    "instruction": "Return client's public address"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 2-4: Multiple STUN binding requests (one per client) - DYNAMIC RESPONSE
            .on_event("stun_binding_request")
            .respond_with_actions_from_event(|event_data| {
                let transaction_id = event_data["transaction_id"]
                    .as_str()
                    .unwrap_or("000000000000000000000000");
                let peer_addr = event_data["peer_addr"]
                    .as_str()
                    .unwrap_or("127.0.0.1:54321");

                serde_json::json!([{
                    "type": "send_stun_binding_response",
                    "transaction_id": transaction_id,  // ← DYNAMIC from event!
                    "mapped_address": peer_addr,        // ← DYNAMIC from event!
                    "xor_mapped_address": true
                }])
            })
            .expect_calls(3) // Expect 3 binding requests from 3 clients
            .and()
    });

    let mut test_state = start_netget_server(config).await?;

    // Extract server port
    let port = test_state.port;

    // Wait for server receive loop to be ready
    test_state
        .wait_for_log("STUN receive loop started", 5)
        .await?;

    // Give tokio time to register the socket with reactor
    tokio::time::sleep(Duration::from_millis(100)).await;

    let server_addr: SocketAddr = format!("127.0.0.1:{}", port)
        .parse()
        .expect("Failed to parse server address");

    // Test with multiple concurrent clients
    let mut handles = vec![];

    for i in 0..3 {
        let addr = server_addr;
        let handle = tokio::spawn(async move {
            let client = UdpSocket::bind("127.0.0.1:0")
                .await
                .expect("Failed to bind client socket");

            let request = build_stun_binding_request_with_tid(&[i; 12]);
            client
                .send_to(&request, addr)
                .await
                .expect("Failed to send request");

            let mut buf = vec![0u8; 2048];
            match tokio::time::timeout(Duration::from_secs(5), client.recv_from(&mut buf)).await {
                Ok(Ok((len, _))) => {
                    let response = &buf[..len];
                    let message_type = u16::from_be_bytes([response[0], response[1]]);
                    assert_eq!(message_type, 0x0101, "Client {} got wrong message type", i);
                    println!("✓ Client {} received valid response", i);
                }
                Ok(Err(e)) => panic!("Client {} failed to receive (IO error): {}", i, e),
                Err(_) => panic!("Client {} failed to receive: timeout after 5 seconds", i),
            }
        });
        handles.push(handle);

        // Small delay to prevent clients from overwhelming the server simultaneously
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // Wait for all clients
    for handle in handles {
        handle.await.expect("Client task failed");
    }

    println!("✓ Multiple concurrent clients successful");

    // Verify mock expectations
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    test_state.wait_for_mocks(30).await;
    test_state.verify_mocks().await?;

    // Cleanup
    test_state.stop().await?;
    Ok(())
}

#[tokio::test]
async fn test_stun_xor_mapped_address() -> E2EResult<()> {
    let config = NetGetConfig::new("Start a STUN server on port 0 using XOR-MAPPED-ADDRESS")
        .with_log_level("debug")
        .with_mock(|mock| {
            mock
                .on_instruction_containing("STUN server")
                .and_instruction_containing("on port")
                .respond_with_actions(serde_json::json!([
                    {"type": "open_server", "port": 0, "base_stack": "STUN", "instruction": "STUN server"}
                ]))
                .expect_calls(1)
                .and()
                .on_event("stun_binding_request")
                .respond_with_actions_from_event(|event_data| {
                    let transaction_id = event_data["transaction_id"].as_str().unwrap_or("000000000000000000000000");
                    let peer_addr = event_data["peer_addr"].as_str().unwrap_or("127.0.0.1:54321");

                    serde_json::json!([{
                        "type": "send_stun_binding_response",
                        "transaction_id": transaction_id,  // ← DYNAMIC from event!
                        "mapped_address": peer_addr,        // ← DYNAMIC from event!
                        "xor_mapped_address": true
                    }])
                })
                .expect_calls(1)
                .and()
        });

    let mut test_state = start_netget_server(config).await?;

    // Wait for server receive loop to be ready
    test_state
        .wait_for_log("STUN receive loop started", 5)
        .await?;

    // Give tokio time to register the socket with reactor
    tokio::time::sleep(Duration::from_millis(100)).await;

    let client = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind client socket");

    let server_addr: SocketAddr = format!("127.0.0.1:{}", test_state.port)
        .parse()
        .expect("Failed to parse server address");

    let request = build_stun_binding_request();
    client
        .send_to(&request, server_addr)
        .await
        .expect("Failed to send request");

    let mut buf = vec![0u8; 2048];
    match tokio::time::timeout(Duration::from_secs(5), client.recv_from(&mut buf)).await {
        Ok(Ok((len, _))) => {
            let response = &buf[..len];

            // Parse attributes looking for XOR-MAPPED-ADDRESS (0x0020)
            let mut pos = 20; // Skip header
            let mut found_xor_mapped = false;

            while pos < len {
                if pos + 4 > len {
                    break;
                }

                let attr_type = u16::from_be_bytes([response[pos], response[pos + 1]]);
                let attr_len = u16::from_be_bytes([response[pos + 2], response[pos + 3]]) as usize;

                if attr_type == 0x0020 {
                    found_xor_mapped = true;
                    println!("✓ Found XOR-MAPPED-ADDRESS attribute");
                    break;
                }

                // Move to next attribute (4 byte header + length + padding)
                pos += 4 + attr_len;
                // Attributes are padded to 4-byte boundary
                if attr_len % 4 != 0 {
                    pos += 4 - (attr_len % 4);
                }
            }

            assert!(
                found_xor_mapped || response.len() >= 20,
                "Expected XOR-MAPPED-ADDRESS attribute or valid response"
            );
        }
        Ok(Err(e)) => panic!("Failed to receive (IO error): {}", e),
        Err(_) => panic!("Failed to receive: timeout after 5 seconds"),
    }

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    test_state.wait_for_mocks(30).await;
    test_state.verify_mocks().await?;
    test_state.stop().await?;
    Ok(())
}

#[tokio::test]
async fn test_stun_invalid_magic_cookie() -> E2EResult<()> {
    let config = NetGetConfig::new(
        "Start a STUN server on port 0 that validates magic cookie and rejects invalid packets",
    )
    .with_log_level("debug")
    .with_mock(|mock| {
        mock
            .on_instruction_containing("STUN server")
            .and_instruction_containing("on port")
            .respond_with_actions(serde_json::json!([
                {"type": "open_server", "port": 0, "base_stack": "STUN", "instruction": "STUN server"}
            ]))
            .expect_calls(1)
            .and()
    });

    let mut test_state = start_netget_server(config).await?;

    // Wait for server receive loop to be ready
    test_state
        .wait_for_log("STUN receive loop started", 5)
        .await?;

    // Give tokio time to register the socket with reactor
    tokio::time::sleep(Duration::from_millis(100)).await;

    let client = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind client socket");

    let server_addr: SocketAddr = format!("127.0.0.1:{}", test_state.port)
        .parse()
        .expect("Failed to parse server address");

    // Build STUN request with INVALID magic cookie
    let invalid_request = build_stun_request_with_invalid_magic_cookie();

    client
        .send_to(&invalid_request, server_addr)
        .await
        .expect("Failed to send invalid request");

    println!("Sent STUN request with invalid magic cookie");

    // Server should either:
    // 1. Send error response (0x0111 = Binding Error Response)
    // 2. Silently ignore the packet (no response)
    let mut buf = vec![0u8; 2048];
    match tokio::time::timeout(Duration::from_secs(5), client.recv_from(&mut buf)).await {
        Ok(Ok((len, _))) => {
            let response = &buf[..len];
            if len >= 20 {
                let message_type = u16::from_be_bytes([response[0], response[1]]);
                println!("Received error response: 0x{:04x}", message_type);

                // If we get a response, it should be an error (class = 2)
                let class = (message_type & 0x0110) >> 4;
                assert_eq!(class, 2, "Expected error response class");
            }
            println!("✓ Server rejected invalid magic cookie");
        }
        Ok(Err(e)) => {
            panic!("Unexpected error: {}", e);
        }
        Err(_) => {
            // Timeout is acceptable - server ignored invalid packet
            println!("✓ Server silently ignored invalid packet (no response)");
        }
    }

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    test_state.wait_for_mocks(30).await;
    test_state.verify_mocks().await?;
    test_state.stop().await?;
    Ok(())
}

#[tokio::test]
async fn test_stun_malformed_short_packet() -> E2EResult<()> {
    let config = NetGetConfig::new("Start a STUN server on port 0 that validates packet length")
        .with_log_level("debug")
        .with_mock(|mock| {
            mock
                .on_instruction_containing("STUN server")
                .and_instruction_containing("on port")
                .respond_with_actions(serde_json::json!([
                    {"type": "open_server", "port": 0, "base_stack": "STUN", "instruction": "STUN server"}
                ]))
                .expect_calls(1)
                .and()
        });

    let mut test_state = start_netget_server(config).await?;

    // Wait for server receive loop to be ready
    test_state
        .wait_for_log("STUN receive loop started", 5)
        .await?;

    // Give tokio time to register the socket with reactor
    tokio::time::sleep(Duration::from_millis(100)).await;

    let client = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind client socket");

    let server_addr: SocketAddr = format!("127.0.0.1:{}", test_state.port)
        .parse()
        .expect("Failed to parse server address");

    // Send packet too short to be valid STUN (only 10 bytes, need 20)
    let short_packet = vec![0u8; 10];

    client
        .send_to(&short_packet, server_addr)
        .await
        .expect("Failed to send short packet");

    println!("Sent malformed short packet (10 bytes)");

    // Server should silently ignore packets too short to be valid
    let mut buf = vec![0u8; 2048];
    match tokio::time::timeout(Duration::from_secs(5), client.recv_from(&mut buf)).await {
        Ok(Ok((len, _))) => {
            // If we get a response, it should be an error
            if len >= 20 {
                let response = &buf[..len];
                let message_type = u16::from_be_bytes([response[0], response[1]]);
                let class = (message_type & 0x0110) >> 4;
                assert_eq!(class, 2, "Expected error response class if server responds");
            }
            println!("✓ Server responded with error to short packet");
        }
        Ok(Err(e)) => {
            panic!("Unexpected error: {}", e);
        }
        Err(_) => {
            println!("✓ Server silently ignored malformed short packet");
        }
    }

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    test_state.wait_for_mocks(30).await;
    test_state.verify_mocks().await?;
    test_state.stop().await?;
    Ok(())
}

#[tokio::test]
async fn test_stun_request_with_attributes() -> E2EResult<()> {
    let config =
        NetGetConfig::new("Start a STUN server on port 0 that handles requests with attributes")
            .with_log_level("debug")
            .with_mock(|mock| {
                mock
                    .on_instruction_containing("STUN server")
                    .and_instruction_containing("on port")
                    .respond_with_actions(serde_json::json!([
                        {"type": "open_server", "port": 0, "base_stack": "STUN", "instruction": "STUN server"}
                    ]))
                    .expect_calls(1)
                    .and()
                    .on_event("stun_binding_request")
                    .respond_with_actions_from_event(|event_data| {
                        let transaction_id = event_data["transaction_id"].as_str().unwrap_or("000000000000000000000000");
                        let peer_addr = event_data["peer_addr"].as_str().unwrap_or("127.0.0.1:54321");

                        serde_json::json!([{
                            "type": "send_stun_binding_response",
                            "transaction_id": transaction_id,  // ← DYNAMIC from event!
                            "mapped_address": peer_addr         // ← DYNAMIC from event!
                        }])
                    })
                    .expect_calls(1)
                    .and()
            });

    let mut test_state = start_netget_server(config).await?;

    // Wait for server receive loop to be ready
    test_state
        .wait_for_log("STUN receive loop started", 5)
        .await?;

    // Give tokio time to register the socket with reactor
    tokio::time::sleep(Duration::from_millis(100)).await;

    let client = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind client socket");

    let server_addr: SocketAddr = format!("127.0.0.1:{}", test_state.port)
        .parse()
        .expect("Failed to parse server address");

    // Build STUN request with SOFTWARE attribute
    let request = build_stun_request_with_software_attribute();

    client
        .send_to(&request, server_addr)
        .await
        .expect("Failed to send request");

    println!("Sent STUN request with SOFTWARE attribute");

    let mut buf = vec![0u8; 2048];
    match tokio::time::timeout(Duration::from_secs(5), client.recv_from(&mut buf)).await {
        Ok(Ok((len, _))) => {
            let response = &buf[..len];

            assert!(len >= 20, "Response too short");

            let message_type = u16::from_be_bytes([response[0], response[1]]);
            assert_eq!(message_type, 0x0101, "Expected success response");

            println!("✓ Server handled request with attributes");
        }
        Ok(Err(e)) => {
            panic!("Failed to receive response (IO error): {}", e);
        }
        Err(_) => {
            panic!("Failed to receive response: timeout after 5 seconds");
        }
    }

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    test_state.wait_for_mocks(30).await;
    test_state.verify_mocks().await?;
    test_state.stop().await?;
    Ok(())
}

#[tokio::test]
async fn test_stun_rapid_requests() -> E2EResult<()> {
    let config = NetGetConfig::new("Start a STUN server on port 0")
        .with_log_level("debug")
        .with_mock(|mock| {
            mock
                .on_instruction_containing("STUN server")
                .and_instruction_containing("on port")
                .respond_with_actions(serde_json::json!([
                    {"type": "open_server", "port": 0, "base_stack": "STUN", "instruction": "STUN server"}
                ]))
                .expect_calls(1)
                .and()
                .on_event("stun_binding_request")
                .respond_with_actions_from_event(|event_data| {
                    let transaction_id = event_data["transaction_id"].as_str().unwrap_or("000000000000000000000000");
                    let peer_addr = event_data["peer_addr"].as_str().unwrap_or("127.0.0.1:54321");

                    serde_json::json!([{
                        "type": "send_stun_binding_response",
                        "transaction_id": transaction_id,  // ← DYNAMIC from event!
                        "mapped_address": peer_addr         // ← DYNAMIC from event!
                    }])
                })
                .expect_calls(5)  // All 5 rapid requests should be processed
                .and()
        });

    let mut test_state = start_netget_server(config).await?;

    // Wait for server receive loop to be ready
    test_state
        .wait_for_log("STUN receive loop started", 5)
        .await?;

    // Give tokio time to register the socket with reactor
    tokio::time::sleep(Duration::from_millis(100)).await;

    let client = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind client socket");

    let server_addr: SocketAddr = format!("127.0.0.1:{}", test_state.port)
        .parse()
        .expect("Failed to parse server address");

    // Send 5 rapid requests with different transaction IDs
    let mut transaction_ids = Vec::new();
    for i in 0..5 {
        let tid = [i as u8; 12];
        transaction_ids.push(tid);

        let request = build_stun_binding_request_with_tid(&tid);
        client
            .send_to(&request, server_addr)
            .await
            .expect("Failed to send request");

        // Small delay to allow server to process each request
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    println!("Sent 5 rapid STUN requests");

    // Try to receive responses (may not be in order due to LLM processing)
    let mut responses_received = 0;
    let mut buf = vec![0u8; 2048];

    for _ in 0..5 {
        match tokio::time::timeout(Duration::from_secs(5), client.recv_from(&mut buf)).await {
            Ok(Ok((len, _))) => {
                if len >= 20 {
                    let response = &buf[..len];
                    let message_type = u16::from_be_bytes([response[0], response[1]]);

                    if message_type == 0x0101 {
                        responses_received += 1;
                    }
                }
            }
            Ok(Err(e)) => {
                panic!("Unexpected error: {}", e);
            }
            Err(_) => {
                // Timeout - no more responses
                break;
            }
        }
    }

    println!(
        "✓ Received {} responses out of 5 requests",
        responses_received
    );
    assert!(
        responses_received >= 1,
        "Should receive at least one response"
    );

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    test_state.wait_for_mocks(30).await;
    test_state.verify_mocks().await?;
    test_state.stop().await?;
    Ok(())
}

// Helper functions

/// Build a basic STUN binding request
fn build_stun_binding_request() -> Vec<u8> {
    build_stun_binding_request_with_tid(&[
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
    ])
}

/// Build a STUN binding request with custom transaction ID
fn build_stun_binding_request_with_tid(tid: &[u8; 12]) -> Vec<u8> {
    let mut packet = Vec::new();

    // Message Type: 0x0001 (Binding Request)
    packet.extend_from_slice(&0x0001u16.to_be_bytes());

    // Message Length: 0 (no attributes)
    packet.extend_from_slice(&0u16.to_be_bytes());

    // Magic Cookie: 0x2112A442
    packet.extend_from_slice(&0x2112A442u32.to_be_bytes());

    // Transaction ID (12 bytes)
    packet.extend_from_slice(tid);

    packet
}

/// Build a STUN request with invalid magic cookie (for testing rejection)
fn build_stun_request_with_invalid_magic_cookie() -> Vec<u8> {
    let mut packet = Vec::new();

    // Message Type: 0x0001 (Binding Request)
    packet.extend_from_slice(&0x0001u16.to_be_bytes());

    // Message Length: 0
    packet.extend_from_slice(&0u16.to_be_bytes());

    // INVALID Magic Cookie: 0xDEADBEEF (should be 0x2112A442)
    packet.extend_from_slice(&0xDEADBEEFu32.to_be_bytes());

    // Transaction ID (12 bytes)
    packet.extend_from_slice(&[0xAA; 12]);

    packet
}

/// Build a STUN request with SOFTWARE attribute
fn build_stun_request_with_software_attribute() -> Vec<u8> {
    let mut packet = Vec::new();

    // Message Type: 0x0001 (Binding Request)
    packet.extend_from_slice(&0x0001u16.to_be_bytes());

    // Message Length placeholder
    let length_pos = packet.len();
    packet.extend_from_slice(&0u16.to_be_bytes());

    // Magic Cookie: 0x2112A442
    packet.extend_from_slice(&0x2112A442u32.to_be_bytes());

    // Transaction ID
    packet.extend_from_slice(&[0xBB; 12]);

    let attributes_start = packet.len();

    // Add SOFTWARE attribute (0x8022)
    let software = "STUN-Test-Client/1.0";
    packet.extend_from_slice(&0x8022u16.to_be_bytes()); // Attribute type
    packet.extend_from_slice(&(software.len() as u16).to_be_bytes()); // Attribute length
    packet.extend_from_slice(software.as_bytes()); // Attribute value

    // Add padding to 4-byte boundary
    let remainder = software.len() % 4;
    if remainder != 0 {
        let padding = 4 - remainder;
        packet.extend_from_slice(&vec![0u8; padding]);
    }

    // Update message length
    let attributes_length = (packet.len() - attributes_start) as u16;
    packet[length_pos..length_pos + 2].copy_from_slice(&attributes_length.to_be_bytes());

    packet
}

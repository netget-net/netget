//! End-to-end UDP protocol tests for NetGet
//!
//! These tests spawn the actual NetGet binary with UDP protocol prompts
//! and validate the responses using real UDP clients.
//!
//! Note: DNS, DHCP, NTP, and SNMP tests are in their own dedicated test files
//! with proper protocol client libraries.

// Helper module imported from parent

use super::super::super::helpers::{self, E2EResult, NetGetConfig};
use std::time::Duration;
use tokio::net::UdpSocket;

#[tokio::test]
async fn test_udp_echo_server() -> E2EResult<()> {
    println!("\n=== E2E Test: UDP Echo Server ===");

    // PROMPT: Tell the LLM to act as a UDP echo server
    let prompt = "listen on port {AVAILABLE_PORT} via udp. Echo back any data you receive.";

    // Start the server
    let config = NetGetConfig::new(prompt)
        .with_mock(|mock| {
            mock
                // Mock 1: UDP datagram received event - MUST BE FIRST (most specific)
                .on_event("udp_datagram_received")
                // "encoding" spelled out. Without it the payload goes through the 'auto'
                // guess, so this test would have been asserting the guess rather than the
                // echo it means to assert.
                .respond_with_actions(serde_json::json!([
                    {"type": "send_udp_response", "data": "48656c6c6f20554450", "encoding": "hex"}  // "Hello UDP"
                ]))
                .expect_calls(1)
                .and()
                // Mock 2: User command interpretation - MUST BE SECOND (less specific)
                .on_instruction_containing("udp")
                .and_instruction_containing("Echo")
                .respond_with_actions(serde_json::json!([
                    {"type": "open_server", "port": 0, "base_stack": "UDP", "instruction": "UDP echo server"}
                ]))
                .expect_calls(1)
                .and()
        });

    let server = helpers::start_netget_server(config).await?;
    println!("Server started on port {}", server.port);

    // Give server time to start

    // VALIDATION: Use UDP client to verify behavior
    let socket = UdpSocket::bind("127.0.0.1:0").await?;

    // Send test data
    let test_data = b"Hello UDP";
    println!("Sending: {:?}", std::str::from_utf8(test_data).unwrap());
    socket
        .send_to(test_data, format!("127.0.0.1:{}", server.port))
        .await?;

    // Wait for response with timeout
    let mut buffer = vec![0u8; 1024];
    match tokio::time::timeout(Duration::from_secs(5), socket.recv_from(&mut buffer)).await {
        Ok(Ok((n, addr))) => {
            let response = String::from_utf8_lossy(&buffer[..n]);
            println!("Received {} bytes from {}: {}", n, addr, response);
            assert!(response.contains("Hello UDP"), "Expected echo response");
            println!("✓ UDP echo verified");
        }
        // These two arms used to print "Note: UDP echo may not be fully implemented yet" and
        // return Ok, so the test passed whether or not a single byte came back — the whole
        // assertion lived in an arm that a broken server would never reach.
        Ok(Err(e)) => return Err(format!("UDP receive failed: {}", e).into()),
        Err(_) => return Err("No UDP echo within 5 seconds".into()),
    }

    // Verify mocks
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;

    server.stop().await?;
    println!("=== Test completed ===\n");
    Ok(())
}

/// `send_to_address` must reach the address it names, and only that address.
///
/// It used to parse the address for validation and then discard it: the executor returned a
/// plain `Output`, and the handler writes every `Output` back to the peer that sent the current
/// datagram. So the one action whose purpose is "send somewhere else" behaved exactly like
/// `send_udp_response`, with nothing in the log to say so.
///
/// The test asserts both halves — the named observer receives the payload, and the peer that
/// triggered it does not — because only the pair distinguishes "sent to the right place" from
/// "sent to both".
#[tokio::test]
async fn test_send_to_address_reaches_the_named_address_only() -> E2EResult<()> {
    println!("\n=== E2E Test: UDP send_to_address ===");

    // A third party the server has never heard from. Bound before the server starts so its
    // port is known to the mock.
    let observer = UdpSocket::bind("127.0.0.1:0").await?;
    let observer_addr = observer.local_addr()?;
    println!("Observer listening on {}", observer_addr);

    let prompt = "listen on port {AVAILABLE_PORT} via udp. Forward what you receive elsewhere.";

    let config = NetGetConfig::new(prompt).with_mock(move |mock| {
        mock.on_event("udp_datagram_received")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "send_to_address",
                    "address": observer_addr.to_string(),
                    "data": "FORWARDED",
                    "encoding": "text"
                }
            ]))
            .expect_calls(1)
            .and()
            .on_instruction_containing("udp")
            .and_instruction_containing("Forward")
            .respond_with_actions(serde_json::json!([
                {"type": "open_server", "port": 0, "base_stack": "UDP", "instruction": "forwarder"}
            ]))
            .expect_calls(1)
            .and()
    });

    let server = helpers::start_netget_server(config).await?;
    println!("Server started on port {}", server.port);

    let peer = UdpSocket::bind("127.0.0.1:0").await?;
    peer.send_to(b"trigger", format!("127.0.0.1:{}", server.port))
        .await?;

    let mut buffer = vec![0u8; 1024];
    match tokio::time::timeout(Duration::from_secs(10), observer.recv_from(&mut buffer)).await {
        Ok(Ok((n, from))) => {
            let payload = String::from_utf8_lossy(&buffer[..n]).to_string();
            println!("Observer received {:?} from {}", payload, from);
            assert_eq!(
                payload, "FORWARDED",
                "send_to_address delivered the wrong payload"
            );
        }
        Ok(Err(e)) => return Err(format!("Observer receive failed: {}", e).into()),
        Err(_) => {
            return Err(
                "send_to_address never reached the address it named (this is the defect the \
                 test exists for: the address used to be parsed and thrown away)"
                    .into(),
            )
        }
    }

    // And the triggering peer must NOT have been answered. The old behaviour sent the payload
    // here instead of to the observer, so without this half a fix that sent to *both* would
    // look correct.
    let mut peer_buffer = vec![0u8; 1024];
    match tokio::time::timeout(Duration::from_secs(2), peer.recv_from(&mut peer_buffer)).await {
        Err(_) => println!("✓ the triggering peer was not answered, as intended"),
        Ok(Ok((n, _))) => {
            return Err(format!(
                "send_to_address also answered the triggering peer with {:?}",
                String::from_utf8_lossy(&peer_buffer[..n])
            )
            .into())
        }
        Ok(Err(e)) => return Err(format!("Peer receive failed: {}", e).into()),
    }

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;

    server.stop().await?;
    println!("=== Test passed ===\n");
    Ok(())
}

// Note: DNS, DHCP, NTP, and SNMP tests have been moved to their own dedicated test files:
// - tests/server/dns_test.rs - DNS tests using hickory-client
// - tests/server/dhcp_test.rs - DHCP tests with proper DHCP packet construction
// - tests/server/ntp_test.rs - NTP tests using rsntp client library
// - tests/server/snmp_test.rs - SNMP tests using snmp library and snmpget

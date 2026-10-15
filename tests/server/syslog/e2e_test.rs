//! E2E tests for Syslog protocol
//!
//! These tests verify Syslog server functionality by starting NetGet with Syslog prompts
//! and using the `logger` command (built-in on Linux/macOS) or raw UDP sockets to send messages.


use crate::helpers::{start_netget_server, E2EResult, NetGetConfig};
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

#[tokio::test]
async fn test_syslog_comprehensive() -> E2EResult<()> {
    println!("\n=== E2E Test: Syslog with Mocks ===");

    // Simplified test with mocks for a few key message types
    let config = NetGetConfig::new("Listen on port {AVAILABLE_PORT} via syslog")
        .with_log_level("info")
        .with_mock(|mock| {
            mock
                // Mock 1: Server startup
                .on_instruction_containing("Listen on port")
                .and_instruction_containing("syslog")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "SYSLOG",
                        "instruction": "Syslog server with filtering"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2-4: Multiple syslog messages (we'll send 3 different messages)
                .on_event("syslog_message")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "store_syslog_message"
                    }
                ]))
                .expect_calls(3) // Expect 3 syslog messages
                .and()
        });

    let mut test_state = start_netget_server(config).await?;

    // Extract server port
    let port = test_state.port;

    // Wait for server to be ready
    tokio::time::sleep(Duration::from_secs(2)).await;

    let server_addr: SocketAddr = format!("127.0.0.1:{}", port)
        .parse()
        .expect("Failed to parse server address");

    // Create UDP client socket
    let client = UdpSocket::bind("127.0.0.1:0").expect("Failed to bind client socket");
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("Failed to set read timeout");

    println!("✓ Syslog server started on {}", server_addr);

    // Test 1: Emergency message (facility=kernel, severity=emergency)
    println!("\n[Test 1] Send emergency kernel message");
    let emergency_msg = "<0>Oct 11 22:14:15 server-01 kernel: Kernel panic - not syncing";
    client
        .send_to(emergency_msg.as_bytes(), server_addr)
        .expect("Failed to send emergency message");
    tokio::time::sleep(Duration::from_millis(500)).await;
    println!("✓ Emergency message sent");

    // Test 2: Auth failure (facility=auth, severity=notice)
    println!("\n[Test 2] Send auth failure message");
    let auth_msg =
        "<37>Oct 11 22:14:16 server-01 sshd: Failed password for root from 192.168.1.100";
    client
        .send_to(auth_msg.as_bytes(), server_addr)
        .expect("Failed to send auth message");
    tokio::time::sleep(Duration::from_millis(500)).await;
    println!("✓ Auth message sent");

    // Test 3: Error message (facility=daemon, severity=error)
    println!("\n[Test 3] Send daemon error message");
    let error_msg = "<27>Oct 11 22:14:17 server-02 httpd: Database connection failed";
    client
        .send_to(error_msg.as_bytes(), server_addr)
        .expect("Failed to send error message");
    tokio::time::sleep(Duration::from_millis(500)).await;
    println!("✓ Error message sent");

    // Give server time to process all messages
    test_state.wait_for_mocks(30).await;

    println!("\n✓ Syslog test with mocks passed!");
    println!("  - Sent 3 syslog messages (emergency, auth, error)");
    println!("  - Verified mock LLM calls");

    // Verify mocks
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    test_state.wait_for_mocks(30).await;
    test_state.verify_mocks().await?;

    // Cleanup
    test_state.stop().await?;
    Ok(())
}

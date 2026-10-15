//! BOOTP client end-to-end tests
//!
//! Tests BOOTP client with mock LLM responses.


use crate::helpers::*;
use std::time::Duration;

/// Test BOOTP client connecting to BOOTP server with mocks
/// LLM calls: 4 (server startup, server request received, client startup, client connected)
#[tokio::test]
async fn test_bootp_request_reply() -> E2EResult<()> {
    // Start a BOOTP server first that can respond to the client
    let server_instruction = r#"
BOOTP server that assigns IP address 192.168.1.100.
When receiving BOOTREQUEST:
  - Assign IP 192.168.1.100
  - Server IP: 192.168.1.1
  - Boot file: "boot/pxeboot.n12"
  - Server hostname: "bootserver"
"#;

    let server_config = NetGetConfig::new(format!(
        "Listen on port {{AVAILABLE_PORT}} via BOOTP. {}",
        server_instruction
    ))
    .with_mock(|mock| {
        mock
            // Mock 1: Server startup
            .on_instruction_containing("Listen on port")
            .and_instruction_containing("BOOTP")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "BOOTP",
                    "instruction": server_instruction
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 2: Server receives BOOTP request
            .on_event("bootp_request")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "send_bootp_reply",
                    "assigned_ip": "192.168.1.100",
                    "server_ip": "192.168.1.1",
                    "boot_file": "boot/pxeboot.n12",
                    "server_hostname": "bootserver"
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let mut server = start_netget_server(server_config).await?;

    // Give server time to start
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Start BOOTP client connecting to the server
    let client_config = NetGetConfig::new(format!(
        "Connect to 127.0.0.1:{} via BOOTP. Request IP for MAC 00:11:22:33:44:55",
        server.port
    ))
    .with_mock(|mock| {
        mock
            // Mock 1: Client startup
            .on_instruction_containing("Connect to")
            .and_instruction_containing("BOOTP")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_client",
                    "remote_addr": format!("127.0.0.1:{}", server.port),
                    "protocol": "BOOTP",
                    "instruction": "Request IP for MAC 00:11:22:33:44:55"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 2: Client connected
            .on_event("bootp_connected")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "send_bootp_request",
                    "client_mac": "00:11:22:33:44:55",
                    "broadcast": false
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 3: Client receives BOOTP reply
            .on_event("bootp_reply_received")
            .and_event_data_contains("assigned_ip", "192.168.1.100")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "disconnect"
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let mut client = start_netget_client(client_config).await?;

    // Give client time to connect and exchange data

    // Verify client output shows connection
    client.wait_for_any(&["connected"], 30).await;
    assert!(
        client.output_contains("connected").await,
        "Client should show connection message. Output: {:?}",
        client.get_output().await
    );

    println!("✓ BOOTP client connected to server and received IP assignment");

    // Verify mock expectations were met
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last response routinely lands
    // after the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    client.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    client.verify_mocks().await?;

    // Cleanup
    server.stop().await?;
    client.stop().await?;

    Ok(())
}

/// Test BOOTP client broadcast discovery with mocks
/// LLM calls: 2 (client startup, client connected)
#[tokio::test]
async fn test_bootp_broadcast_discovery() -> E2EResult<()> {
    // Test client startup with broadcast mode (no server needed, just verify client starts)
    let client_config = NetGetConfig::new(
        "Connect to 255.255.255.255:67 via BOOTP. Broadcast BOOTP request to discover boot servers. Use MAC 52:54:00:12:34:56"
    )
    .with_mock(|mock| {
        mock
            // Mock 1: Client startup
            .on_instruction_containing("Connect to")
            .and_instruction_containing("BOOTP")
            // Case-sensitive: the instruction says "Broadcast BOOTP request", with no
            // lowercase "broadcast" anywhere in it, so this rule never matched and the
            // client's own startup call got a 500.
            .and_instruction_containing("Broadcast")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_client",
                    "remote_addr": "255.255.255.255:67",
                    "protocol": "BOOTP",
                    "instruction": "Broadcast BOOTP request. Use MAC 52:54:00:12:34:56"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 2: Client connected
            .on_event("bootp_connected")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "send_bootp_request",
                    "client_mac": "52:54:00:12:34:56",
                    "broadcast": true
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let mut client = start_netget_client(client_config).await?;

    // Give client time to start and send broadcast request

    // Verify client started
    client.wait_for_any(&["BOOTP", "connected"], 30).await;
    assert!(
        client.output_contains("BOOTP").await || client.output_contains("connected").await,
        "Client should show startup. Output: {:?}",
        client.get_output().await
    );

    println!("✓ BOOTP client broadcast discovery test completed");

    // Verify mock expectations were met
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last response routinely lands
    // after the sleep expires, and the test reports it as never having happened.
    client.wait_for_mocks(30).await;
    client.verify_mocks().await?;

    // Cleanup
    client.stop().await?;

    Ok(())
}

/// Test BOOTP client error handling (no server) with mocks
/// LLM calls: 2 (client startup, client connected)
#[tokio::test]
async fn test_bootp_no_server() -> E2EResult<()> {
    // Test client connecting to non-existent server (should start but no reply)
    let client_config = NetGetConfig::new(
        "Connect to 192.0.2.1:67 via BOOTP. Request IP for MAC 00:11:22:33:44:55",
    )
    .with_mock(|mock| {
        mock
            // Mock 1: Client startup
            .on_instruction_containing("Connect to")
            .and_instruction_containing("BOOTP")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_client",
                    "remote_addr": "192.0.2.1:67",
                    "protocol": "BOOTP",
                    "instruction": "Request IP for MAC 00:11:22:33:44:55"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 2: Client connected (UDP is connectionless)
            .on_event("bootp_connected")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "send_bootp_request",
                    "client_mac": "00:11:22:33:44:55",
                    "broadcast": false
                }
            ]))
            .expect_calls(1)
            .and()
        // No reply expected - test will timeout waiting for reply
    });

    let mut client = start_netget_client(client_config).await?;

    // Give client time to start and send request (no reply expected)

    // Verify client started
    client.wait_for_any(&["BOOTP", "connected"], 30).await;
    assert!(
        client.output_contains("BOOTP").await || client.output_contains("connected").await,
        "BOOTP client should start even without server. Output: {:?}",
        client.get_output().await
    );

    println!("✓ BOOTP no-server test completed (timeout expected)");

    // Verify mock expectations were met
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last response routinely lands
    // after the sleep expires, and the test reports it as never having happened.
    client.wait_for_mocks(30).await;
    client.verify_mocks().await?;

    // Cleanup
    client.stop().await?;

    Ok(())
}

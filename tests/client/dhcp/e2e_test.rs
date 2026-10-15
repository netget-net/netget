//! E2E tests for DHCP client
//!
//! These tests verify DHCP client functionality by spawning the actual NetGet binary
//! and testing client behavior as a black-box.
//! Test strategy: Use netget binary to start DHCP server + client, < 10 LLM calls total.
//!
//! NOTE: DHCP client requires binding to port 68, which may need elevated privileges.
//! These tests may fail on systems without sufficient permissions.

mod dhcp_client_tests {
    use crate::helpers::*;
    use std::time::Duration;

    /// Test DHCP client can send DISCOVER and receive OFFER
    /// LLM calls: 4 (server startup, client startup, client action after OFFER)
    #[tokio::test]
    #[ignore = "Requires elevated privileges to bind port 68"]
    async fn test_dhcp_client_discover_offer() -> E2EResult<()> {
        // Start a DHCP server that offers IP 192.168.1.100 with mocks
        let server_config = NetGetConfig::new(
            "Listen on port 67 via DHCP. \
            When receiving DHCP DISCOVER, offer IP 192.168.1.100 with subnet mask 255.255.255.0, \
            router 192.168.1.1, and DNS 8.8.8.8. Lease time 24 hours.",
        )
        .with_mock(|mock| {
            mock
                // Mock 1: Server startup
                .on_instruction_containing("Listen on port")
                .and_instruction_containing("DHCP")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 67,
                        "base_stack": "DHCP",
                        "instruction": "DHCP server - offer 192.168.1.100 on DISCOVER"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2: Server receives DHCP DISCOVER
                .on_event("dhcp_request")
                .and_event_data_contains("message_type", "DISCOVER")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "send_dhcp_offer",
                        "offered_ip": "192.168.1.100",
                        "subnet_mask": "255.255.255.0",
                        "router": "192.168.1.1",
                        "dns_servers": ["8.8.8.8"],
                        "lease_time": 86400
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let mut server = start_netget_server(server_config).await?;

        // Give server time to start
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Start DHCP client to send DISCOVER with mocks
        let client_config = NetGetConfig::new(
            "Connect to 127.0.0.1:67 via DHCP. \
            Send DHCP DISCOVER with MAC address 00:11:22:33:44:55. \
            When receiving OFFER, log the offered IP address and network configuration.",
        )
        .with_mock(|mock| {
            mock
                // Mock 1: Client startup
                .on_instruction_containing("Connect to")
                .and_instruction_containing("DHCP")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_client",
                        "remote_addr": "127.0.0.1:67",
                        "protocol": "DHCP",
                        "instruction": "Send DISCOVER with MAC 00:11:22:33:44:55"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2: Client connected - send DISCOVER
                .on_event("dhcp_connected")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "dhcp_discover",
                        "mac_address": "00:11:22:33:44:55",
                        "broadcast": false
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 3: Client receives OFFER - log and wait
                .on_event("dhcp_response_received")
                .and_event_data_contains("message_type", "OFFER")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "wait_for_more"
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let mut client = start_netget_client(client_config).await?;

        // Give client time to connect and receive OFFER
        tokio::time::sleep(Duration::from_secs(3)).await;

        // Verify client shows connection
        client.wait_for_any(&["dhcp", "DHCP"], 30).await;
        assert!(
            client.output_contains("dhcp").await || client.output_contains("DHCP").await,
            "Client should show DHCP activity. Output: {:?}",
            client.get_output().await
        );

        println!("✅ DHCP client sent DISCOVER and received OFFER");

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

    /// Test DHCP client can complete full DORA exchange
    /// LLM calls: 6 (server startup, client startup, server OFFER, client REQUEST, server ACK, client parse ACK)
    #[tokio::test]
    #[ignore = "Requires elevated privileges to bind port 68"]
    async fn test_dhcp_client_full_dora() -> E2EResult<()> {
        // Start a DHCP server with mocks
        let server_config = NetGetConfig::new(
            "Listen on port 67 via DHCP. \
            When receiving DHCP DISCOVER, offer IP 192.168.1.100. \
            When receiving DHCP REQUEST, acknowledge with ACK including subnet mask 255.255.255.0.",
        )
        .with_mock(|mock| {
            mock
                // Mock 1: Server startup
                .on_instruction_containing("Listen on port")
                .and_instruction_containing("DHCP")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 67,
                        "base_stack": "DHCP",
                        "instruction": "DHCP server - OFFER on DISCOVER, ACK on REQUEST"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2: Server receives DHCP DISCOVER
                .on_event("dhcp_request")
                .and_event_data_contains("message_type", "DISCOVER")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "send_dhcp_offer",
                        "offered_ip": "192.168.1.100",
                        "subnet_mask": "255.255.255.0",
                        "lease_time": 86400
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 3: Server receives DHCP REQUEST
                .on_event("dhcp_request")
                .and_event_data_contains("message_type", "REQUEST")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "send_dhcp_ack",
                        "assigned_ip": "192.168.1.100",
                        "subnet_mask": "255.255.255.0",
                        "lease_time": 86400
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let mut server = start_netget_server(server_config).await?;

        tokio::time::sleep(Duration::from_millis(500)).await;

        // Start DHCP client to complete full DORA with mocks
        let client_config = NetGetConfig::new(
            "Connect to 127.0.0.1:67 via DHCP. \
            Send DHCP DISCOVER with MAC 00:11:22:33:44:55. \
            When receiving OFFER, send DHCP REQUEST for the offered IP. \
            When receiving ACK, log the assigned IP and disconnect.",
        )
        .with_mock(|mock| {
            mock
                // Mock 1: Client startup
                .on_instruction_containing("Connect to")
                .and_instruction_containing("DHCP")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_client",
                        "remote_addr": "127.0.0.1:67",
                        "protocol": "DHCP",
                        "instruction": "Complete DORA exchange"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2: Client connected - send DISCOVER
                .on_event("dhcp_connected")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "dhcp_discover",
                        "mac_address": "00:11:22:33:44:55",
                        "broadcast": false
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 3: Client receives OFFER - send REQUEST
                .on_event("dhcp_response_received")
                .and_event_data_contains("message_type", "OFFER")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "dhcp_request",
                        "requested_ip": "192.168.1.100",
                        "mac_address": "00:11:22:33:44:55",
                        "broadcast": false
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 4: Client receives ACK - disconnect
                .on_event("dhcp_response_received")
                .and_event_data_contains("message_type", "ACK")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "disconnect"
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let mut client = start_netget_client(client_config).await?;

        // Give time for DORA exchange (DISCOVER → OFFER → REQUEST → ACK)
        tokio::time::sleep(Duration::from_secs(5)).await;

        // Verify protocol is DHCP
        assert_eq!(client.protocol, "DHCP", "Client should be DHCP protocol");

        println!("✅ DHCP client completed full DORA exchange");

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

    /// Test DHCP client with broadcast mode
    /// LLM calls: 4 (server startup, client startup)
    #[tokio::test]
    #[ignore = "Requires elevated privileges to bind port 68"]
    async fn test_dhcp_client_broadcast() -> E2EResult<()> {
        // Start DHCP server with mocks
        let server_config = NetGetConfig::new(
            "Listen on port 67 via DHCP. \
            Respond to all DHCP DISCOVER messages with OFFER.",
        )
        .with_mock(|mock| {
            mock
                // Mock 1: Server startup
                .on_instruction_containing("Listen on port")
                .and_instruction_containing("DHCP")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 67,
                        "base_stack": "DHCP",
                        "instruction": "Respond to all DISCOVER with OFFER"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2: Server receives broadcast DHCP DISCOVER
                .on_event("dhcp_request")
                .and_event_data_contains("message_type", "DISCOVER")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "send_dhcp_offer",
                        "offered_ip": "192.168.1.100",
                        "lease_time": 86400
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let mut server = start_netget_server(server_config).await?;

        tokio::time::sleep(Duration::from_millis(500)).await;

        // Start DHCP client with broadcast and mocks
        let client_config = NetGetConfig::new(
            "Connect to 255.255.255.255:67 via DHCP. \
            Send DHCP DISCOVER as broadcast to find all DHCP servers on the network. \
            Log any OFFER responses received.",
        )
        .with_mock(|mock| {
            mock
                // Mock 1: Client startup
                .on_instruction_containing("Connect to")
                .and_instruction_containing("DHCP")
                .and_instruction_containing("broadcast")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_client",
                        "remote_addr": "255.255.255.255:67",
                        "protocol": "DHCP",
                        "instruction": "Send broadcast DISCOVER"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2: Client connected - send broadcast DISCOVER
                .on_event("dhcp_connected")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "dhcp_discover",
                        "broadcast": true
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let mut client = start_netget_client(client_config).await?;

        tokio::time::sleep(Duration::from_secs(2)).await;

        // Verify client initiated DHCP activity
        client.wait_for_any(&["DHCP", "dhcp"], 30).await;
        assert!(
            client.output_contains("DHCP").await || client.output_contains("dhcp").await,
            "Client should show DHCP activity"
        );

        println!("✅ DHCP client sent broadcast DISCOVER");

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
}

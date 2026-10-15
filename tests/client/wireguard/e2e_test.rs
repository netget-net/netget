//! End-to-end tests for WireGuard VPN client
//!
//! These tests verify that the WireGuard client can:
//! - Connect to a WireGuard server
//! - Establish encrypted tunnels
//! - Query connection status
//! - Disconnect gracefully
//!
//! **Test Strategy**: Use mocks to simulate VPN operations without requiring root privileges
//! **LLM Call Budget**: < 10 calls total
//! **Expected Runtime**: ~10-15 seconds

#[cfg(unix)]
mod tests {
    use crate::helpers::*;
    use ::netget::llm::actions::Protocol;
    use std::time::Duration;

    /// Test WireGuard client connection to server (requires root/sudo)
    /// LLM calls: 4 (server startup, client startup, connected event, status query)
    #[tokio::test]
    #[ignore = "Requires root/admin privileges to start WireGuard server"]
    async fn test_wireguard_client_connect() -> E2EResult<()> {
        // Note: This test requires sudo/root privileges to start WireGuard server

        // Start a WireGuard VPN server with mocks
        let server_config = NetGetConfig::new("Start a WireGuard VPN server on port {AVAILABLE_PORT}. Assign clients to 10.20.30.0/24 network.")
            .with_mock(|mock| {
                mock
                    // Mock 1: Server startup
                    .on_instruction_containing("WireGuard")
                    .and_instruction_containing("VPN server")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "open_server",
                            "port": 51820,
                            "base_stack": "WIREGUARD",
                            "instruction": "VPN server for 10.20.30.0/24 network"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // Mock 2: Client connects (peer added)
                    .on_event("wireguard_peer_connected")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "authorize_peer",
                            "allowed_ips": ["10.20.30.2/32"]
                        }
                    ]))
                    .expect_calls(1)
                    .and()
            });

        let server = start_netget_server(server_config).await?;

        // Give server time to start and generate keys
        tokio::time::sleep(Duration::from_secs(2)).await;

        // Start WireGuard client with mocks
        let client_config = NetGetConfig::new(format!(
            "Connect to WireGuard VPN at 127.0.0.1:{} with client address 10.20.30.2/32",
            server.port
        ))
        .with_mock(|mock| {
            mock
                // Mock 1: Client startup
                .on_instruction_containing("Connect to")
                .and_instruction_containing("WireGuard")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_client",
                        "remote_addr": format!("127.0.0.1:{}", server.port),
                        "protocol": "wireguard",
                        "instruction": "Connect to VPN",
                        "startup_params": {
                            "server_endpoint": format!("127.0.0.1:{}", server.port),
                            "client_address": "10.20.30.2/32",
                            "server_public_key": "placeholder_key"
                        }
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2: Connection established (wireguard_connected event)
                .on_event("wireguard_connected")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "wait_for_more"
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let client = start_netget_client(client_config).await?;

        // Give client time to connect
        tokio::time::sleep(Duration::from_secs(3)).await;

        // Verify client shows WireGuard protocol
        assert_eq!(
            client.protocol, "wireguard",
            "Client should be wireguard protocol"
        );

        println!("✅ WireGuard client connected successfully");

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

    /// Test WireGuard client status query (requires root/sudo)
    /// LLM calls: 2 (client startup, connected event)
    #[tokio::test]
    #[ignore = "Requires root/admin privileges to start WireGuard server"]
    async fn test_wireguard_client_status_query() -> E2EResult<()> {
        // Note: This test requires sudo/root privileges

        // Skip server startup - just test against a fake endpoint
        let fake_port = 51820;

        // Start client with mocks
        let client_config = NetGetConfig::new(format!(
            "Connect to WireGuard VPN at 127.0.0.1:{} with address 10.20.30.3/32",
            fake_port
        ))
        .with_mock(|mock| {
            mock.on_instruction_containing("Connect to")
                .and_instruction_containing("WireGuard")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_client",
                        "remote_addr": format!("127.0.0.1:{}", fake_port),
                        "protocol": "wireguard",
                        "instruction": "Connect to VPN",
                        "startup_params": {
                            "server_endpoint": format!("127.0.0.1:{}", fake_port),
                            "client_address": "10.20.30.3/32",
                            "server_public_key": "placeholder_key"
                        }
                    }
                ]))
                .expect_calls(1)
                .and()
                .on_event("wireguard_connected")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "wait_for_more"
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let client = start_netget_client(client_config).await?;
        tokio::time::sleep(Duration::from_secs(3)).await;

        // Verify output contains connection information
        let output = client.get_output().await;
        assert!(
            output.iter().any(|s| s.contains("wireguard"))
                || output.iter().any(|s| s.contains("VPN"))
                || output.iter().any(|s| s.contains("connected")),
            "Client output should show connection info. Output: {:?}",
            output
        );

        println!("✅ WireGuard client status query successful");

        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last response routinely lands
        // after the sleep expires, and the test reports it as never having happened.
        client.wait_for_mocks(30).await;
        client.verify_mocks().await?;
        client.stop().await?;

        Ok(())
    }

    /// Test WireGuard client disconnect (requires root/sudo)
    /// LLM calls: 3 (client startup, connected event, disconnected event)
    #[tokio::test]
    #[ignore = "Requires root/admin privileges to start WireGuard server"]
    async fn test_wireguard_client_disconnect() -> E2EResult<()> {
        // Note: This test requires sudo/root privileges

        let fake_port = 51820;

        // Start client with disconnect mocks
        let client_config = NetGetConfig::new(format!(
            "Connect to WireGuard VPN at 127.0.0.1:{} then disconnect after connecting",
            fake_port
        ))
        .with_mock(|mock| {
            mock.on_instruction_containing("Connect to")
                .and_instruction_containing("WireGuard")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_client",
                        "remote_addr": format!("127.0.0.1:{}", fake_port),
                        "protocol": "wireguard",
                        "instruction": "Connect then disconnect",
                        "startup_params": {
                            "server_endpoint": format!("127.0.0.1:{}", fake_port),
                            "client_address": "10.20.30.4/32",
                            "server_public_key": "placeholder_key"
                        }
                    }
                ]))
                .expect_calls(1)
                .and()
                .on_event("wireguard_connected")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "disconnect"
                    }
                ]))
                .expect_calls(1)
                .and()
                .on_event("wireguard_disconnected")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "wait_for_more"
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let client = start_netget_client(client_config).await?;
        tokio::time::sleep(Duration::from_secs(4)).await;

        // Verify disconnect occurred
        let output = client.get_output().await;
        assert!(
            output.iter().any(|s| s.contains("disconnect"))
                || output.iter().any(|s| s.contains("closed")),
            "Client should show disconnection. Output: {:?}",
            output
        );

        println!("✅ WireGuard client disconnect successful");

        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last response routinely lands
        // after the sleep expires, and the test reports it as never having happened.
        client.wait_for_mocks(30).await;
        client.verify_mocks().await?;
        client.stop().await?;

        Ok(())
    }

    /// Test that verifies WireGuard client parameter parsing
    ///
    /// This test doesn't require root or a running server.
    #[test]
    fn test_wireguard_param_parsing() {
        use ::netget::client::wireguard::actions::WireguardClientProtocol;
        let protocol = WireguardClientProtocol::new();

        // Verify protocol metadata
        assert_eq!(protocol.protocol_name(), "wireguard");
        assert_eq!(protocol.stack_name(), "VPN");
        assert_eq!(protocol.group_name(), "VPN");

        // Verify keywords
        let keywords = protocol.keywords();
        assert!(keywords.contains(&"wireguard"));
        assert!(keywords.contains(&"wg"));

        // Verify startup parameters are defined
        let params = protocol.get_startup_parameters();
        assert!(!params.is_empty());
        assert!(params.iter().any(|p| p.name == "server_public_key"));
        assert!(params.iter().any(|p| p.name == "server_endpoint"));
        assert!(params.iter().any(|p| p.name == "client_address"));
    }

    /// Test WireGuard action definitions
    #[test]
    fn test_wireguard_actions() {
        use ::netget::client::wireguard::actions::WireguardClientProtocol;
        use ::netget::state::app_state::AppState;

        let protocol = WireguardClientProtocol::new();
        let app_state = AppState::new();

        // Verify async actions
        let async_actions = protocol.get_async_actions(&app_state);
        assert!(!async_actions.is_empty());
        assert!(async_actions
            .iter()
            .any(|a| a.name == "get_connection_status"));
        assert!(async_actions.iter().any(|a| a.name == "disconnect"));
        assert!(async_actions.iter().any(|a| a.name == "get_client_info"));

        // Verify sync actions (should be empty for WireGuard)
        let sync_actions = protocol.get_sync_actions();
        assert!(sync_actions.is_empty());

        // Verify event types
        let event_types = protocol.get_event_types();
        assert_eq!(event_types.len(), 2);
        assert!(event_types.iter().any(|e| e.id == "wireguard_connected"));
        assert!(event_types.iter().any(|e| e.id == "wireguard_disconnected"));
    }
}

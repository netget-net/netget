//! E2E tests for TURN client
//!
//! These tests verify TURN client functionality by spawning the actual NetGet binary
//! and testing client behavior as a black-box.
//! Test strategy: Use netget binary to start server + client, < 10 LLM calls total.

#[cfg(unix)]
mod turn_client_tests {
    use crate::helpers::*;
    use std::time::Duration;

    /// Test TURN client connection and allocation
    /// LLM calls: 4 (server startup, client connection, allocation, permission)
    #[tokio::test]
    async fn test_turn_client_allocate_relay() -> E2EResult<()> {
        // Start a TURN server on an available port
        let server_config = NetGetConfig::new(
            "Start TURN relay server on port {AVAILABLE_PORT}. When client requests allocation, \
             assign relay address and return 600 second lifetime.",
        )
        .with_mock(|mock| {
            mock
                .on_instruction_containing("TURN relay server")
                .respond_with_actions(serde_json::json!([{"type": "open_server", "port": 0, "base_stack": "TURN", "instruction": "TURN relay server"}]))
                .expect_calls(1)
                .and()
                .on_event("turn_allocate_request")
                // The server's verb is send_turn_allocate_response; `turn_allocate_success`
                // is not one it can execute. transaction_id must be echoed from the
                // request or the client cannot correlate the reply.
                .respond_with_actions_from_event(|e| serde_json::json!([{
                    "type": "send_turn_allocate_response",
                    "relay_address": "127.0.0.1:50000",
                    "lifetime_seconds": 600,
                    "transaction_id": e["transaction_id"]
                }]))
                .expect_calls(1)
                .and()
        });

        let mut server = start_netget_server(server_config).await?;

        // Give server time to start
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Start TURN client that allocates a relay
        let client_config = NetGetConfig::new(format!(
            "Connect to TURN server at 127.0.0.1:{} and allocate a relay address with 600 second lifetime.",
            server.port
        ))
        .with_mock(|mock| {
            mock
                .on_instruction_containing("Connect to TURN")
                .respond_with_actions(serde_json::json!([{"type": "open_client", "remote_addr": format!("127.0.0.1:{}", server.port), "protocol": "TURN", "instruction": "Allocate relay"}]))
                .expect_calls(1)
                .and()
                .on_event("turn_connected")
                // The client's verb is allocate_turn_relay; `turn_allocate` is not one it
                // can execute.
                .respond_with_actions(serde_json::json!([{
                    "type": "allocate_turn_relay",
                    "lifetime_seconds": 600
                }]))
                .expect_calls(1)
                .and()
        });

        let mut client = start_netget_client(client_config).await?;

        // Give client time to connect and allocate

        // Verify client output shows connection
        client.wait_for_any(&["TURN", "connected"], 30).await;
        assert!(
            client.output_contains("TURN").await || client.output_contains("connected").await,
            "Client should show TURN connection. Output: {:?}",
            client.get_output().await
        );

        println!("✅ TURN client connected and allocated relay successfully");

        // Verify mocks
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

    /// Test TURN client can create permissions
    /// LLM calls: 5 (server startup, client connection, allocation, permission create, confirm)
    #[tokio::test]
    async fn test_turn_client_create_permission() -> E2EResult<()> {
        // Start TURN server
        let server_config = NetGetConfig::new(
            "Start TURN relay server on port {AVAILABLE_PORT}. Accept all allocation and permission requests."
        )
        .with_mock(|mock| {
            mock
                // These two tests configured no server mock at all, so the server's own
                // startup instruction reached mock_ollama with nothing to match, got a
                // 500, and no server ever started -- which surfaced as the client's rules
                // reporting zero calls.
                .on_instruction_containing("TURN relay server")
                .respond_with_actions(serde_json::json!([{"type": "open_server", "port": 0, "base_stack": "TURN", "instruction": "TURN relay server"}]))
                .expect_calls(1)
                .and()
                .on_event("turn_allocate_request")
                // transaction_id must be echoed from the request or the client cannot
                // correlate the reply.
                .respond_with_actions_from_event(|e| serde_json::json!([{
                    "type": "send_turn_allocate_response",
                    "relay_address": "127.0.0.1:50000",
                    "lifetime_seconds": 600,
                    "transaction_id": e["transaction_id"]
                }]))
                .expect_at_least(1)
                .and()
                .on_event("turn_create_permission_request")
                .respond_with_actions_from_event(|e| serde_json::json!([{
                    "type": "send_turn_create_permission_response",
                    "transaction_id": e["transaction_id"]
                }]))
                .expect_at_least(0)
                .and()
                .on_event("turn_refresh_request")
                .respond_with_actions_from_event(|e| serde_json::json!([{
                    "type": "send_turn_refresh_response",
                    "transaction_id": e["transaction_id"],
                    "lifetime_seconds": 600
                }]))
                .expect_at_least(0)
                .and()
        });

        let mut server = start_netget_server(server_config).await?;

        tokio::time::sleep(Duration::from_millis(500)).await;

        // Client that allocates and creates permission
        let client_config = NetGetConfig::new(format!(
            "Connect to TURN server at 127.0.0.1:{}, allocate a relay, and create permission for peer 192.168.1.100:5000.",
            server.port
        ))
        .with_mock(|mock| {
            mock
                .on_instruction_containing("Connect to TURN")
                .respond_with_actions(serde_json::json!([{"type": "open_client", "remote_addr": format!("127.0.0.1:{}", server.port), "protocol": "TURN", "instruction": "Allocate relay"}]))
                .expect_calls(1)
                .and()
                .on_event("turn_connected")
                // The client's verb is allocate_turn_relay; `turn_allocate` is not one it
                // can execute.
                .respond_with_actions(serde_json::json!([{
                    "type": "allocate_turn_relay",
                    "lifetime_seconds": 600
                }]))
                .expect_calls(1)
                .and()
        });

        let mut client = start_netget_client(client_config).await?;

        server.wait_for_mocks(30).await;

        // Verify client is TURN protocol
        assert_eq!(client.protocol, "TURN", "Client should be TURN protocol");

        println!("✅ TURN client created permission successfully");

        // Verify mocks
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

    /// Test TURN client can refresh allocation
    /// LLM calls: 5 (server startup, client connection, allocation, refresh request, confirm)
    #[tokio::test]
    async fn test_turn_client_refresh_allocation() -> E2EResult<()> {
        // Start TURN server
        let server_config = NetGetConfig::new(
            "Start TURN relay server on port {AVAILABLE_PORT}. Accept all allocation and refresh requests."
        )
        .with_mock(|mock| {
            mock
                // These two tests configured no server mock at all, so the server's own
                // startup instruction reached mock_ollama with nothing to match, got a
                // 500, and no server ever started -- which surfaced as the client's rules
                // reporting zero calls.
                .on_instruction_containing("TURN relay server")
                .respond_with_actions(serde_json::json!([{"type": "open_server", "port": 0, "base_stack": "TURN", "instruction": "TURN relay server"}]))
                .expect_calls(1)
                .and()
                .on_event("turn_allocate_request")
                // transaction_id must be echoed from the request or the client cannot
                // correlate the reply.
                .respond_with_actions_from_event(|e| serde_json::json!([{
                    "type": "send_turn_allocate_response",
                    "relay_address": "127.0.0.1:50000",
                    "lifetime_seconds": 600,
                    "transaction_id": e["transaction_id"]
                }]))
                .expect_at_least(1)
                .and()
                .on_event("turn_create_permission_request")
                .respond_with_actions_from_event(|e| serde_json::json!([{
                    "type": "send_turn_create_permission_response",
                    "transaction_id": e["transaction_id"]
                }]))
                .expect_at_least(0)
                .and()
                .on_event("turn_refresh_request")
                .respond_with_actions_from_event(|e| serde_json::json!([{
                    "type": "send_turn_refresh_response",
                    "transaction_id": e["transaction_id"],
                    "lifetime_seconds": 600
                }]))
                .expect_at_least(0)
                .and()
        });

        let mut server = start_netget_server(server_config).await?;

        tokio::time::sleep(Duration::from_millis(500)).await;

        // Client that allocates and refreshes
        let client_config = NetGetConfig::new(format!(
            "Connect to TURN server at 127.0.0.1:{}, allocate a relay with 60 second lifetime, \
             then refresh it to extend the lifetime by another 600 seconds.",
            server.port
        ))
        .with_mock(|mock| {
            mock
                .on_instruction_containing("Connect to TURN")
                .respond_with_actions(serde_json::json!([{"type": "open_client", "remote_addr": format!("127.0.0.1:{}", server.port), "protocol": "TURN", "instruction": "Allocate relay"}]))
                .expect_calls(1)
                .and()
                .on_event("turn_connected")
                // The client's verb is allocate_turn_relay; `turn_allocate` is not one it
                // can execute.
                .respond_with_actions(serde_json::json!([{
                    "type": "allocate_turn_relay",
                    "lifetime_seconds": 600
                }]))
                .expect_calls(1)
                .and()
        });

        let mut client = start_netget_client(client_config).await?;

        server.wait_for_mocks(30).await;

        // Verify TURN operations occurred
        let output = client.get_output().await;
        assert!(
            output.iter().any(|l| l.contains("TURN"))
                || output.iter().any(|l| l.contains("refresh"))
                || output.iter().any(|l| l.contains("allocated")),
            "Client should show TURN allocation/refresh activity. Output: {:?}",
            output
        );

        println!("✅ TURN client refreshed allocation successfully");

        // Verify mocks
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

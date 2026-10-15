//! E2E tests for Bitcoin RPC client
//!
//! These tests verify Bitcoin RPC client functionality by spawning the actual NetGet binary
//! and testing client behavior as a black-box.

mod bitcoin_client_tests {
    use crate::helpers::*;
    use std::time::Duration;

    /// Test Bitcoin RPC client connecting to a server
    /// LLM calls: 4 (server startup, server POST received, client connection, client response)
    ///
    /// Note: This test uses a Bitcoin server mock since we don't have a real Bitcoin Core node.
    /// The server responds with minimal JSON-RPC responses to verify client connectivity.
    #[tokio::test]
    async fn test_bitcoin_client_connection() -> E2EResult<()> {
        // Start a Bitcoin server mock (HTTP server that responds to JSON-RPC calls)
        let server_config = NetGetConfig::new(
            "Listen on port {AVAILABLE_PORT} via HTTP. \
             Respond to POST requests with JSON-RPC format. \
             Return blockchain info when method is getblockchaininfo.",
        )
        .with_mock(|mock| {
            mock
                // Mock 1: User command to open HTTP server
                .on_instruction_containing("Listen on port")
                .and_instruction_containing("HTTP")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "HTTP",
                        "instruction": "Respond to Bitcoin RPC requests"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2: Server receives POST request (JSON-RPC call)
                .on_event("http_request")
                .and_event_data_contains("method", "POST")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "send_http_response",
                        "status": 200,
                        "headers": {
                            "Content-Type": "application/json"
                        },
                        "body": "{\"jsonrpc\":\"2.0\",\"result\":{\"chain\":\"main\",\"blocks\":750000},\"id\":1}"
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let mut server = start_netget_server(server_config).await?;

        // Give server time to start
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Now start a Bitcoin RPC client
        let server_port = server.port;
        let client_config = NetGetConfig::new(format!(
            "Connect to http://test:test@127.0.0.1:{} via Bitcoin RPC. \
             Get blockchain information.",
            server_port
        ))
        .with_mock(move |mock| {
            mock
                // Mock 1: User command to open Bitcoin RPC client
                .on_instruction_containing("Connect to")
                .and_instruction_containing("Bitcoin RPC")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_client",
                        "remote_addr": format!("http://test:test@127.0.0.1:{}", server_port),
                        "protocol": "Bitcoin",
                        "instruction": "Get blockchain information"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2: Bitcoin client connected
                .on_event("bitcoin_connected")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "get_blockchain_info"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 3: Bitcoin RPC response received
                .on_event("bitcoin_response_received")
                .and_event_data_contains("method", "getblockchaininfo")
                .respond_with_actions(serde_json::json!([]))
                .expect_calls(1)
                .and()
        });

        let mut client = start_netget_client(client_config).await?;

        // Give client time to initialize
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Verify client output shows Bitcoin protocol or connection message
        client
            .wait_for_any(&["Bitcoin", "bitcoin", "connected"], 30)
            .await;
        assert!(
            client.output_contains("Bitcoin").await
                || client.output_contains("bitcoin").await
                || client.output_contains("connected").await,
            "Client should show Bitcoin protocol or connection message. Output: {:?}",
            client.get_output().await
        );

        println!("✅ Bitcoin RPC client connected successfully");

        // Verify mock expectations
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

    /// Test Bitcoin RPC client can execute RPC commands
    /// LLM calls: 4 (server startup, server POST, client connection, client response)
    #[tokio::test]
    async fn test_bitcoin_client_rpc_command() -> E2EResult<()> {
        // Start a minimal HTTP server to simulate Bitcoin RPC
        let server_config = NetGetConfig::new(
            "Listen on port {AVAILABLE_PORT} via HTTP. \
             Log all incoming POST requests.",
        )
        .with_mock(|mock| {
            mock
                // Mock 1: User command to open HTTP server
                .on_instruction_containing("Listen on port")
                .and_instruction_containing("HTTP")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "HTTP",
                        "instruction": "Log POST requests"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2: Server receives POST request
                .on_event("http_request")
                .and_event_data_contains("method", "POST")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "send_http_response",
                        "status": 200,
                        "headers": {
                            "Content-Type": "application/json"
                        },
                        "body": "{\"jsonrpc\":\"2.0\",\"result\":{\"chain\":\"main\"},\"id\":1}"
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let mut server = start_netget_server(server_config).await?;

        tokio::time::sleep(Duration::from_millis(500)).await;

        // Client that makes an RPC call
        let server_port = server.port;
        let client_config = NetGetConfig::new(format!(
            "Connect to Bitcoin RPC at http://bitcoinrpc:pass@127.0.0.1:{} \
             and execute getblockchaininfo command.",
            server_port
        ))
        .with_mock(move |mock| {
            mock
                // Mock 1: User command to open Bitcoin RPC client
                .on_instruction_containing("Connect to Bitcoin RPC")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_client",
                        "remote_addr": format!("http://bitcoinrpc:pass@127.0.0.1:{}", server_port),
                        "protocol": "Bitcoin",
                        "instruction": "Execute getblockchaininfo"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2: Bitcoin client connected - execute command
                .on_event("bitcoin_connected")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "get_blockchain_info"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 3: Response received
                .on_event("bitcoin_response_received")
                .respond_with_actions(serde_json::json!([]))
                .expect_calls(1)
                .and()
        });

        let mut client = start_netget_client(client_config).await?;

        tokio::time::sleep(Duration::from_millis(500)).await;

        // Verify the client is Bitcoin protocol
        assert_eq!(
            client.protocol, "Bitcoin",
            "Client should be Bitcoin protocol"
        );

        println!("✅ Bitcoin RPC client executed command");

        // Verify mock expectations
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

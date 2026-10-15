//! E2E tests for Telnet client
//!
//! These tests verify Telnet client functionality by spawning the actual NetGet binary
//! and testing client behavior as a black-box.
//! Test strategy: Use netget binary to start server + client, < 10 LLM calls total.

mod telnet_client_tests {
    use crate::helpers::*;
    use std::time::Duration;

    /// Test Telnet client connection to a Telnet server with mocks
    /// LLM calls: 4 (server startup, client startup, connection, greeting sent)
    #[tokio::test]
    async fn test_telnet_client_connect_to_server() -> E2EResult<()> {
        // Start a Telnet server with mocks
        let server_config = NetGetConfig::new(
            "Listen on port {AVAILABLE_PORT} via Telnet. When you receive a greeting, respond with 'Welcome!\r\n'."
        )
        .with_mock(|mock| {
            mock
                // Mock: Server startup (more specific to avoid matching events)
                .on_instruction_containing("Listen on port")
                .and_instruction_containing("Telnet")
                .and_instruction_containing("Welcome")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "Telnet",
                        "instruction": "Send welcome when client sends greeting"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock: Client sent greeting message
                .on_event("telnet_connection_opened")
                // Raised for every connection; this server has nothing to say first.
                .respond_with_actions(serde_json::json!([]))
                .expect_calls(1)
                .and()
                .on_event("telnet_message_received")
                .and_event_data_contains("message", "hello")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "send_telnet_line",
                        "line": "Welcome!"
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let server = start_netget_server(server_config).await?;

        tokio::time::sleep(Duration::from_millis(500)).await;

        // Start Telnet client with mocks - client sends greeting first to trigger server response
        let client_config = NetGetConfig::new(format!(
            "Connect to 127.0.0.1:{} via Telnet. Send 'hello' as greeting, then wait for server response.",
            server.port
        ))
        .with_mock(|mock| {
            mock
                // Mock: Client startup
                .on_instruction_containing("Telnet")
                .and_instruction_containing("127.0.0.1")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_client",
                        "remote_addr": format!("127.0.0.1:{}", server.port),
                        "protocol": "Telnet",
                        "instruction": "Send greeting and wait for response"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock: Connection established - send greeting
                .on_event("telnet_connected")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "send_command",
                        "command": "hello"
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let client = start_netget_client(client_config).await?;

        tokio::time::sleep(Duration::from_millis(500)).await;

        // Verify client output shows connection
        client.wait_for_any(&["connected"], 30).await;
        assert!(
            client.output_contains("connected").await,
            "Client should show connection message. Output: {:?}",
            client.get_output().await
        );

        println!("✅ Telnet client connected to server successfully");

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

    /// Test Telnet client can send commands with mocks
    /// LLM calls: 4 (server startup, client startup, command sent, echo received)
    #[tokio::test]
    async fn test_telnet_client_send_command() -> E2EResult<()> {
        // Start a Telnet server that echoes commands with mocks
        let server_config = NetGetConfig::new(
            "Listen on port {AVAILABLE_PORT} via Telnet. Echo back any text received.",
        )
        .with_mock(|mock| {
            mock
                // Mock: Server startup
                .on_instruction_containing("Telnet")
                .and_instruction_containing("Echo")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "Telnet",
                        "instruction": "Echo all text"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock: Text received from client
                .on_event("telnet_connection_opened")
                // Raised for every connection; this server has nothing to say first.
                .respond_with_actions(serde_json::json!([]))
                .expect_calls(1)
                .and()
                .on_event("telnet_message_received")
                .and_event_data_contains("message", "hello")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "send_telnet_line",
                        "line": "hello"
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let server = start_netget_server(server_config).await?;

        tokio::time::sleep(Duration::from_millis(500)).await;

        // Client that sends a command with mocks
        let client_config = NetGetConfig::new(format!(
            "Connect to 127.0.0.1:{} via Telnet and send the command 'hello'.",
            server.port
        ))
        .with_mock(|mock| {
            mock
                // Mock: Client startup
                .on_instruction_containing("Telnet")
                .and_instruction_containing("hello")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_client",
                        "remote_addr": format!("127.0.0.1:{}", server.port),
                        "protocol": "Telnet",
                        "instruction": "Send command 'hello'"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock: Connected event
                .on_event("telnet_connected")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "send_command",
                        "command": "hello"
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let client = start_netget_client(client_config).await?;

        tokio::time::sleep(Duration::from_millis(500)).await;

        // Verify the client protocol is Telnet
        assert_eq!(
            client.protocol, "Telnet",
            "Client should be Telnet protocol"
        );

        println!("✅ Telnet client sent command successfully");

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

    /// Test Telnet client can handle option negotiation with mocks
    /// LLM calls: 2 (server startup, client startup)
    #[tokio::test]
    async fn test_telnet_client_option_negotiation() -> E2EResult<()> {
        // Start a Telnet server that negotiates options with mocks
        let server_config = NetGetConfig::new(
            "Listen on port {AVAILABLE_PORT} via Telnet. Send WILL ECHO and DO TERMINAL_TYPE options."
        )
        .with_mock(|mock| {
            mock
                // Mock: Server startup
                .on_instruction_containing("Telnet")
                .and_instruction_containing("WILL ECHO")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "Telnet",
                        "instruction": "Send WILL ECHO and DO TERMINAL_TYPE on connection"
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let server = start_netget_server(server_config).await?;

        tokio::time::sleep(Duration::from_millis(500)).await;

        // Client that responds to negotiation with mocks
        let client_config = NetGetConfig::new(format!(
            "Connect to 127.0.0.1:{} via Telnet. Handle option negotiation automatically.",
            server.port
        ))
        .with_mock(|mock| {
            mock
                // Mock: Client startup
                .on_instruction_containing("Telnet")
                .and_instruction_containing("negotiation")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_client",
                        "remote_addr": format!("127.0.0.1:{}", server.port),
                        "protocol": "Telnet",
                        "instruction": "Handle option negotiation automatically"
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let client = start_netget_client(client_config).await?;

        tokio::time::sleep(Duration::from_millis(500)).await;

        // Verify client connected (negotiation happens automatically)
        client.wait_for_any(&["connected", "Telnet"], 30).await;
        assert!(
            client.output_contains("connected").await || client.output_contains("Telnet").await,
            "Client should show connection or Telnet activity. Output: {:?}",
            client.get_output().await
        );

        println!("✅ Telnet client handled option negotiation");

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

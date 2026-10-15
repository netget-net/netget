//! E2E tests for TCP client
//!
//! These tests verify TCP client functionality by spawning the actual NetGet binary
//! and testing client behavior as a black-box.
//! Test strategy: Use netget binary to start server + client, < 10 LLM calls total.

mod tcp_client_tests {
    use crate::helpers::*;
    use ::netget::logging::patterns;
    use std::time::Duration;

    /// Test TCP client connection to a local server with data exchange
    /// LLM calls: 4 (server startup, server data received, client startup, client connected)
    #[tokio::test]
    async fn test_tcp_client_connect_to_server() -> E2EResult<()> {
        // Start a TCP server listening on an available port with mocks
        let server_config = NetGetConfig::new("Listen on port {AVAILABLE_PORT} via TCP. Accept one connection, echo received data back.")
            .with_mock(|mock| {
                mock
                    // Mock 1: Server startup (user command)
                    .on_instruction_containing("Listen on port")
                    .and_instruction_containing("TCP")
                    .and_instruction_containing("echo")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "open_server",
                            "port": 0,
                            "base_stack": "TCP",
                            "instruction": "Echo server - respond with exactly what is received"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // Mock 2: Server receives data (tcp_data_received event)
                    .on_event("tcp_data_received")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "send_tcp_data",
                            "data": "HELLO" // UTF-8 string (echoed back)
                        }
                    ]))
                    .expect_calls(1)
                    .and()
            });

        let server = start_netget_server(server_config).await?;

        // Wait for server to be listening (no sleep needed)
        server
            .wait_for_pattern(patterns::TCP_SERVER_LISTENING, Duration::from_secs(5))
            .await?;

        // Now start a TCP client that connects to this server with mocks
        let client_config = NetGetConfig::new(format!(
            "Connect to 127.0.0.1:{} via TCP. Send 'HELLO' and wait for response.",
            server.port
        ))
        .with_mock(|mock| {
            mock
                // Mock 1: Client startup (user command)
                .on_instruction_containing("Connect to")
                .and_instruction_containing("TCP")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_client",
                        "remote_addr": format!("127.0.0.1:{}", server.port),
                        "protocol": "TCP",
                        "instruction": "Send HELLO and wait for echo"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2: Client connected (tcp_connected event)
                .on_event("tcp_connected")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "send_tcp_data",
                        "data": "HELLO" // UTF-8 string
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let client = start_netget_client(client_config).await?;

        // Wait for complete data exchange sequence
        client
            .wait_for_patterns(
                &[
                    patterns::TCP_CLIENT_CONNECTED, // Client connected
                    patterns::TCP_CLIENT_SENT,      // Client sent HELLO
                ],
                Duration::from_secs(5),
            )
            .await?;

        // Wait for server to receive and process the data
        server
            .wait_for_pattern(patterns::TCP_SERVER_RECEIVED, Duration::from_secs(5))
            .await?;

        println!("✅ TCP client connected to server and sent data successfully");

        // Verify mock expectations were met on both ends.
        //
        // The client side was previously skipped with a note that "the echo might not arrive
        // before the connection closes". Its client rule carries no `expect_calls`, so
        // verifying it asserts only that no harness diagnostic fired — which is exactly the
        // check that was missing, and costs nothing in flakiness.
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

    /// Test TCP client can be controlled via prompts with mocks
    /// LLM calls: 4 (server startup, client startup, connection, data received)
    #[tokio::test]
    async fn test_tcp_client_command_via_prompt() -> E2EResult<()> {
        // Start a simple TCP server with mocks
        let server_config =
            NetGetConfig::new("Listen on port {AVAILABLE_PORT} via TCP. Log all incoming data.")
                .with_mock(|mock| {
                    mock
                        // Mock: Server startup
                        .on_instruction_containing("TCP")
                        .and_instruction_containing("Log")
                        .respond_with_actions(serde_json::json!([
                            {
                                "type": "open_server",
                                "port": 0,
                                "base_stack": "TCP",
                                "instruction": "Log all data"
                            }
                        ]))
                        .expect_calls(1)
                        .and()
                        // Mock: Server receives data
                        .on_event("tcp_data_received")
                        .respond_with_actions(serde_json::json!([
                            {
                                "type": "wait_for_more"
                            }
                        ]))
                        .expect_calls(1)
                        .and()
                });

        let server = start_netget_server(server_config).await?;

        // Wait for server to be listening
        server
            .wait_for_pattern(patterns::TCP_SERVER_LISTENING, Duration::from_secs(5))
            .await?;

        // Client that sends specific data based on LLM instruction with mocks
        let client_config = NetGetConfig::new(format!(
            "Connect to 127.0.0.1:{} via TCP and send the string 'TEST_DATA' then disconnect.",
            server.port
        ))
        .with_mock(|mock| {
            mock
                // Mock: Client startup
                .on_instruction_containing("TCP")
                .and_instruction_containing("TEST_DATA")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_client",
                        "remote_addr": format!("127.0.0.1:{}", server.port),
                        "protocol": "TCP",
                        "instruction": "Send TEST_DATA then disconnect"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock: Client connected
                .on_event("tcp_connected")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "send_tcp_data",
                        "data": "544553545f44415441" // "TEST_DATA" in hex
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let client = start_netget_client(client_config).await?;

        // Wait for client to connect and send data
        client
            .wait_for_patterns(
                &[patterns::TCP_CLIENT_CONNECTED, patterns::TCP_CLIENT_SENT],
                Duration::from_secs(5),
            )
            .await?;

        // Verify the client initiated the connection
        assert_eq!(client.protocol, "TCP", "Client should be TCP protocol");

        println!("✅ TCP client responded to LLM instruction");

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

//! E2E tests for Redis client
//!
//! These tests verify Redis client functionality by spawning the actual NetGet binary
//! and testing client behavior as a black-box.

mod redis_client_tests {
    use crate::helpers::*;
    use std::time::Duration;

    /// Test Redis client connection and command execution with mocks
    /// LLM calls: 4 (server startup, client startup, connection event, response event)
    #[tokio::test]
    async fn test_redis_client_connect_and_command_with_mocks() -> E2EResult<()> {
        // Start a Redis server listening on an available port with mocks
        let server_config = NetGetConfig::new("Listen on port {AVAILABLE_PORT} via Redis. Accept PING commands and respond with PONG.")
            .with_mock(|mock| {
                mock
                    // Mock 1: Server startup
                    .on_instruction_containing("Listen on port")
                    .and_instruction_containing("via Redis")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "open_server",
                            "port": 0,
                            "base_stack": "Redis",
                            "instruction": "Accept PING and respond with PONG"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // Mock 2: Redis command received (PING)
                    .on_event("redis_command")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "redis_simple_string",
                            "value": "PONG"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
            });

        let server = start_netget_server(server_config).await?;

        // Give server time to start
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Now start a Redis client that connects and sends a command
        let client_config = NetGetConfig::new(format!(
            "Connect to 127.0.0.1:{} via Redis. Send PING command and read response.",
            server.port
        ))
        .with_mock(|mock| {
            mock
                // Mock 1: Client startup
                .on_instruction_containing("Connect to")
                .and_instruction_containing("Redis")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_client",
                        "remote_addr": format!("127.0.0.1:{}", server.port),
                        "protocol": "Redis",
                        "instruction": "Send PING command"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2: Redis connected event
                .on_event("redis_connected")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "execute_redis_command",
                        "command": "PING"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 3: Redis response received.
                //
                // `set_memory` is the honest way to say "note the reply and send nothing
                // further": it is a common action the executor handles itself, so it
                // actually runs. (This comment used to say `wait_for_more` had no executor
                // arm in this client; it has had one for a long time —
                // `src/client/redis/actions.rs`. Either would work here.)
                .on_event("redis_response_received")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "set_memory",
                        "value": "PING answered"
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let client = start_netget_client(client_config).await?;

        // Give client time to connect and execute command
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Verify client output shows connection
        client.wait_for_any(&["connected"], 30).await;
        assert!(
            client.output_contains("connected").await,
            "Client should show connection message. Output: {:?}",
            client.get_output().await
        );

        println!("✅ Redis client connected and executed command successfully");

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

    /// Test Redis client can be controlled via LLM instructions with mocks
    /// LLM calls: 3 (server startup, client startup, SET command)
    #[tokio::test]
    async fn test_redis_client_llm_controlled_commands_with_mocks() -> E2EResult<()> {
        // Start a simple Redis server with mocks
        let server_config = NetGetConfig::new(
            "Listen on port {AVAILABLE_PORT} via Redis. Log all incoming commands.",
        )
        .with_mock(|mock| {
            mock.on_instruction_containing("Listen on port")
                .and_instruction_containing("via Redis")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "Redis",
                        "instruction": "Log all incoming commands"
                    }
                ]))
                .expect_calls(1)
                .and()
                .on_event("redis_command")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "redis_simple_string",
                        "value": "OK"
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let server = start_netget_server(server_config).await?;

        tokio::time::sleep(Duration::from_millis(500)).await;

        // Client that sends specific commands based on LLM instruction
        let client_config = NetGetConfig::new(format!(
            "Connect to 127.0.0.1:{} via Redis. Execute SET key1 'value1' command.",
            server.port
        ))
        .with_mock(|mock| {
            mock.on_instruction_containing("Redis")
                .and_instruction_containing("SET")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_client",
                        "remote_addr": format!("127.0.0.1:{}", server.port),
                        "protocol": "Redis",
                        "instruction": "Execute SET key1 'value1'"
                    }
                ]))
                .expect_calls(1)
                .and()
                .on_event("redis_connected")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "execute_redis_command",
                        "command": "SET key1 'value1'"
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let client = start_netget_client(client_config).await?;

        tokio::time::sleep(Duration::from_millis(500)).await;

        // Verify the client is Redis protocol
        assert_eq!(client.protocol, "Redis", "Client should be Redis protocol");

        println!("✅ Redis client responded to LLM instruction");

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

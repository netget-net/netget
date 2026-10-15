//! E2E tests for Redis server with mocks
//!
//! These tests verify Redis server functionality using mock LLM responses.
//! Test strategy: Mock Redis RESP protocol responses, < 10 LLM calls total.

mod redis_server_tests {
    use crate::helpers::*;
    use redis::AsyncCommands;

    /// Test Redis PING command with mocks
    /// LLM calls: 2 (server startup, redis_command event)
    #[tokio::test]
    async fn test_redis_ping_with_mocks() -> E2EResult<()> {
        // Start a Redis server with mocks
        let server_config = NetGetConfig::new(
            "Listen on port {AVAILABLE_PORT} via Redis. Respond to PING with PONG.",
        )
        .with_mock(|mock| {
            mock
                // Mock 1: Server startup (match initial instruction)
                .on_instruction_containing("Redis")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "Redis",
                        "instruction": "Respond to PING with PONG"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2: PING command (most specific - must come before generic redis_command)
                .on_event("redis_command")
                .and_event_data_contains("command", "PING")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "redis_simple_string",
                        "value": "PONG"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 3: Generic redis_command (CLIENT SETINFO commands)
                .on_event("redis_command")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "redis_simple_string",
                        "value": "OK"
                    }
                ]))
                .and()
        });

        let server = start_netget_server(server_config).await?;

        // Connect Redis client and send PING command
        let redis_url = format!("redis://127.0.0.1:{}", server.port);
        let client = redis::Client::open(redis_url.as_str())?;
        let mut con = client.get_multiplexed_async_connection().await?;

        // Execute PING command
        let pong: String = with_client_timeout(redis::cmd("PING").query_async(&mut con)).await?;
        assert_eq!(pong, "PONG", "Expected PING to return PONG");

        println!("✅ Redis server responded to PING with mocks");

        // Explicitly drop connection before mock verification to prevent hanging
        drop(con);
        drop(client);
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last event routinely lands after
        // the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;

        Ok(())
    }

    /// Test Redis GET/SET commands with mocks
    /// LLM calls: 3 (server startup, SET command, GET command)
    #[tokio::test]
    async fn test_redis_get_set_with_mocks() -> E2EResult<()> {
        // Start a Redis server
        let server_config = NetGetConfig::new(
            "Listen on port {AVAILABLE_PORT} via Redis. Handle GET and SET commands.",
        )
        .with_mock(|mock| {
            mock
                // Mock 1: Server startup (match initial instruction)
                .on_instruction_containing("Redis")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "Redis",
                        "instruction": "Handle GET and SET commands"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2: SET command (specific - must match "SET " with space)
                .on_event("redis_command")
                .and_event_data_contains("command", "SET ")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "redis_simple_string",
                        "value": "OK"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 3: GET command (specific - must match "GET " with space)
                .on_event("redis_command")
                .and_event_data_contains("command", "GET ")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "redis_bulk_string",
                        "value": "test_value"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 4: Generic redis_command (CLIENT commands) - LAST
                .on_event("redis_command")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "redis_simple_string",
                        "value": "OK"
                    }
                ]))
                .and()
        });

        let server = start_netget_server(server_config).await?;

        // Connect Redis client and execute GET/SET commands
        let redis_url = format!("redis://127.0.0.1:{}", server.port);
        let client = redis::Client::open(redis_url.as_str())?;
        let mut con = client.get_multiplexed_async_connection().await?;

        // Test SET command
        let result: String = with_client_timeout(con.set("mykey", "myvalue")).await?;
        assert_eq!(result, "OK", "Expected SET to return OK");

        // Test GET command
        let value: String = with_client_timeout(con.get("mykey")).await?;
        assert_eq!(value, "test_value", "Expected GET to return test_value");

        println!("✅ Redis server handled GET/SET commands with mocks");

        // Explicitly drop connection before mock verification to prevent hanging
        drop(con);
        drop(client);
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last event routinely lands after
        // the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;

        Ok(())
    }

    /// Test Redis integer response with mocks
    /// LLM calls: 2 (server startup, INCR command)
    #[tokio::test]
    async fn test_redis_integer_response_with_mocks() -> E2EResult<()> {
        // Start a Redis server
        let server_config = NetGetConfig::new(
            "Listen on port {AVAILABLE_PORT} via Redis. Handle INCR command returning integer.",
        )
        .with_mock(|mock| {
            mock
                // Mock 1: Server startup (match initial instruction)
                .on_instruction_containing("Redis")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "Redis",
                        "instruction": "Handle INCR command"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2: INCR command (specific - before generic)
                .on_event("redis_command")
                .and_event_data_contains("command", "INCR")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "redis_integer",
                        "value": 42
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 3: Generic redis_command (CLIENT commands) - LAST
                .on_event("redis_command")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "redis_simple_string",
                        "value": "OK"
                    }
                ]))
                .and()
        });

        let server = start_netget_server(server_config).await?;

        // Connect Redis client and execute INCR command
        let redis_url = format!("redis://127.0.0.1:{}", server.port);
        let client = redis::Client::open(redis_url.as_str())?;
        let mut con = client.get_multiplexed_async_connection().await?;

        // Test INCR command (returns integer)
        let result: i64 = with_client_timeout(con.incr("counter", 1)).await?;
        assert_eq!(result, 42, "Expected INCR to return 42");

        println!("✅ Redis server returned integer response with mocks");

        // Explicitly drop connection before mock verification to prevent hanging
        drop(con);
        drop(client);
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last event routinely lands after
        // the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;

        Ok(())
    }

    /// Test Redis array response with mocks
    /// LLM calls: 2 (server startup, KEYS command)
    #[tokio::test]
    async fn test_redis_array_response_with_mocks() -> E2EResult<()> {
        // Start a Redis server
        let server_config = NetGetConfig::new(
            "Listen on port {AVAILABLE_PORT} via Redis. Handle KEYS command returning array.",
        )
        .with_mock(|mock| {
            mock
                // Mock 1: Server startup (match initial instruction)
                .on_instruction_containing("Redis")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "Redis",
                        "instruction": "Handle KEYS command"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2: KEYS command (specific - before generic)
                .on_event("redis_command")
                .and_event_data_contains("command", "KEYS")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "redis_array",
                        "values": ["key1", "key2", "key3"]
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 3: Generic redis_command (CLIENT commands) - LAST
                .on_event("redis_command")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "redis_simple_string",
                        "value": "OK"
                    }
                ]))
                .and()
        });

        let server = start_netget_server(server_config).await?;

        // Connect Redis client and execute KEYS command
        let redis_url = format!("redis://127.0.0.1:{}", server.port);
        let client = redis::Client::open(redis_url.as_str())?;
        let mut con = client.get_multiplexed_async_connection().await?;

        // Test KEYS command (returns array)
        let keys: Vec<String> =
            with_client_timeout(redis::cmd("KEYS").arg("*").query_async(&mut con)).await?;
        assert!(!keys.is_empty(), "Expected at least one key");

        println!("✅ Redis server returned array response with mocks");

        // Explicitly drop connection before mock verification to prevent hanging
        drop(con);
        drop(client);
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last event routinely lands after
        // the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;

        Ok(())
    }

    /// Test Redis null response with mocks
    /// LLM calls: 2 (server startup, GET nonexistent key)
    #[tokio::test]
    async fn test_redis_null_response_with_mocks() -> E2EResult<()> {
        // Start a Redis server
        let server_config = NetGetConfig::new(
            "Listen on port {AVAILABLE_PORT} via Redis. Return null for non-existent keys.",
        )
        .with_mock(|mock| {
            mock
                // Mock 1: Server startup (match initial instruction)
                .on_instruction_containing("Redis")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "Redis",
                        "instruction": "Return null for non-existent keys"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2: GET command (specific - must match "GET " with space)
                .on_event("redis_command")
                .and_event_data_contains("command", "GET ")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "redis_null"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 3: Generic redis_command (CLIENT commands) - LAST
                .on_event("redis_command")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "redis_simple_string",
                        "value": "OK"
                    }
                ]))
                .and()
        });

        let server = start_netget_server(server_config).await?;

        // Connect Redis client and execute GET on nonexistent key
        let redis_url = format!("redis://127.0.0.1:{}", server.port);
        let client = redis::Client::open(redis_url.as_str())?;
        let mut con = client.get_multiplexed_async_connection().await?;

        // Test GET for nonexistent key (should return nil)
        let value: Option<String> = with_client_timeout(con.get("nonexistent")).await?;
        assert_eq!(value, None, "Expected GET nonexistent to return None");

        println!("✅ Redis server returned null response with mocks");

        // Explicitly drop connection before mock verification to prevent hanging
        drop(con);
        drop(client);
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last event routinely lands after
        // the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;

        Ok(())
    }

    /// Test Redis error response with mocks
    /// LLM calls: 2 (server startup, invalid command)
    #[tokio::test]
    async fn test_redis_error_response_with_mocks() -> E2EResult<()> {
        // Start a Redis server
        let server_config = NetGetConfig::new(
            "Listen on port {AVAILABLE_PORT} via Redis. Return error for invalid commands.",
        )
        .with_mock(|mock| {
            mock
                // Mock 1: Server startup (match initial instruction)
                .on_instruction_containing("Redis")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "Redis",
                        "instruction": "Return error for invalid commands"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2: INVALID command (specific - before generic)
                .on_event("redis_command")
                .and_event_data_contains("command", "INVALID")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "redis_error",
                        "message": "ERR unknown command"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 3: Generic redis_command (CLIENT commands) - LAST
                .on_event("redis_command")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "redis_simple_string",
                        "value": "OK"
                    }
                ]))
                .and()
        });

        let server = start_netget_server(server_config).await?;

        // Connect Redis client and send invalid command
        let redis_url = format!("redis://127.0.0.1:{}", server.port);
        let client = redis::Client::open(redis_url.as_str())?;
        let mut con = client.get_multiplexed_async_connection().await?;

        // Test invalid command (should return error)
        let result =
            with_client_timeout(redis::cmd("INVALID").query_async::<String>(&mut con)).await;

        match result {
            Ok(_) => {
                return Err("Expected error but command succeeded".into());
            }
            Err(e) => {
                let err_str = e.to_string();
                assert!(
                    err_str.contains("ERR") || err_str.contains("unknown"),
                    "Error message should contain expected text"
                );
            }
        }

        println!("✅ Redis server returned error response with mocks");

        // Explicitly drop connection before mock verification to prevent hanging
        drop(con);
        drop(client);
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last event routinely lands after
        // the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;

        Ok(())
    }
}

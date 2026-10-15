//! E2E tests for HTTP client
//!
//! These tests verify HTTP client functionality by spawning the actual NetGet binary
//! and testing client behavior as a black-box.

mod http_client_tests {
    use crate::helpers::*;
    use std::time::Duration;

    /// Test HTTP client making a GET request
    /// LLM calls: 4 (server startup, server request, client startup, client connected)
    #[tokio::test]
    async fn test_http_client_get_request() -> E2EResult<()> {
        // Start an HTTP server listening on an available port with mocks
        let server_config = NetGetConfig::new(
            "Listen on port 0 via HTTP. Respond to GET requests with 'Hello from server'.",
        )
        .with_mock(|mock| {
            mock
                // Mock 1: Server startup (user command)
                .on_instruction_containing("Listen on port")
                .and_instruction_containing("HTTP")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "HTTP",
                        "instruction": "Respond to GET requests with 'Hello from server'"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2: Server receives HTTP request (http_request event)
                .on_event("http_request")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "send_http_response",
                        "status": 200,
                        "headers": {"Content-Type": "text/plain"},
                        "body": "Hello from server"
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let server = start_netget_server(server_config).await?;

        // Give server time to fully bind and start listening
        crate::helpers::wait_for_server_listening(&server, Duration::from_secs(30)).await?;

        println!("[TEST] Server started on port {}", server.port);

        // Now start an HTTP client that makes a GET request with mocks
        let client_config = NetGetConfig::new(format!(
            "Connect to http://127.0.0.1:{} via HTTP. Send a GET request to / and read the response.",
            server.port
        ))
            .with_mock(|mock| {
                mock
                    // Mock 1: Client startup (user command)
                    .on_instruction_containing("Connect to")
                    .and_instruction_containing("HTTP")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "open_client",
                            "remote_addr": format!("127.0.0.1:{}", server.port),
                            "protocol": "HTTP",
                            "instruction": "Send GET request to / and read response"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // Mock 2: Client connected (http_connected event)
                    .on_event("http_connected")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "send_http_request",
                            "method": "GET",
                            "path": "/",
                            "headers": {},
                            "body": ""
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // Mock 3: Client receives response (http_response_received event).
                    //
                    // This answered `wait_for_more`, which the HTTP client has no executor
                    // for — `HttpClientProtocol::execute_action` knows only
                    // `send_http_request`. `set_memory` is the honest way to say "note the
                    // response and send nothing further": it is a common action the executor
                    // handles itself, so it actually runs.
                    .on_event("http_response_received")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "set_memory",
                            "value": "response received"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
            });

        let client = start_netget_client(client_config).await?;

        // Give client time to make request

        // Verify client output shows connection/response
        client.wait_for_any(&["HTTP", "connected"], 30).await;
        assert!(
            client.output_contains("HTTP").await || client.output_contains("connected").await,
            "Client should show HTTP protocol or connection message. Output: {:?}",
            client.get_output().await
        );

        println!("✅ HTTP client made GET request successfully");

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

    /// Test HTTP client can send requests based on LLM instructions
    /// LLM calls: 4 (server startup, server request, client startup, client connected)
    #[tokio::test]
    async fn test_http_client_lllm_controlled_request() -> E2EResult<()> {
        // Start a simple HTTP server with mocks
        let server_config = NetGetConfig::new(
            "Listen on port 0 via HTTP. Log all incoming requests.",
        )
        .with_mock(|mock| {
            mock
                // Mock 1: Server startup
                .on_instruction_containing("Listen on port")
                .and_instruction_containing("HTTP")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "HTTP",
                        "instruction": "Log all incoming requests"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2: Server receives custom header request
                .on_event("http_request")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "send_http_response",
                        "status": 200,
                        "headers": {},
                        "body": "Request logged"
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let server = start_netget_server(server_config).await?;

        // Give server time to fully bind and start listening
        crate::helpers::wait_for_server_listening(&server, Duration::from_secs(30)).await?;

        println!("[TEST] Server started on port {}", server.port);

        // Client that makes a specific request based on LLM instruction with mocks
        let client_config = NetGetConfig::new(format!(
            "Connect to http://127.0.0.1:{} via HTTP and send a GET request with custom headers.",
            server.port
        ))
        .with_mock(|mock| {
            mock
                // Mock 1: Client startup
                .on_instruction_containing("Connect to")
                .and_instruction_containing("HTTP")
                .and_instruction_containing("custom headers")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_client",
                        "remote_addr": format!("127.0.0.1:{}", server.port),
                        "protocol": "HTTP",
                        "instruction": "Send GET request with custom headers"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2: Client connected - send request with custom headers
                .on_event("http_connected")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "send_http_request",
                        "method": "GET",
                        "path": "/",
                        "headers": {"X-Custom-Header": "test-value"},
                        "body": ""
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 3: Client receives response. See the note above: `wait_for_more` is
                // not an action this client can execute.
                .on_event("http_response_received")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "set_memory",
                        "value": "response received"
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let client = start_netget_client(client_config).await?;

        server.wait_for_mocks(30).await;

        // Verify the client is HTTP protocol
        assert_eq!(client.protocol, "HTTP", "Client should be HTTP protocol");

        println!("✅ HTTP client responded to LLM instruction");

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

//! E2E tests for HTTP/2 client
//!
//! These tests verify HTTP/2 client functionality by spawning the actual NetGet binary
//! and testing client behavior as a black-box.

mod http2_client_tests {
    use crate::helpers::*;
    use std::time::Duration;

    /// Test HTTP/2 client making a GET request
    /// LLM calls: 5 (server startup, server request, client startup, client connected, client response)
    #[tokio::test]
    async fn test_http2_client_get_request() -> E2EResult<()> {
        // Start an HTTP/2 server listening on an available port with mocks
        let server_config = NetGetConfig::new("Listen on port {AVAILABLE_PORT} via HTTP/2. Respond to GET requests with 'Hello from HTTP/2 server'.")
            .with_mock(|mock| {
                mock
                    // Mock 1: Server startup
                    .on_instruction_containing("Listen on port")
                    .and_instruction_containing("HTTP/2")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "open_server",
                            "port": 0,
                            "base_stack": "HTTP2",
                            "instruction": "Respond to GET requests with 'Hello from HTTP/2 server'"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // Mock 2: Server receives GET request
                    .on_event("http2_request")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "send_http2_response",
                            "status": 200,
                            "headers": {"Content-Type": "text/plain"},
                            "body": "Hello from HTTP/2 server"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
            });

        let mut server = start_netget_server(server_config).await?;

        // Give server time to start
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Now start an HTTP/2 client that makes a GET request with mocks
        let client_config = NetGetConfig::new(format!(
            "Connect to http://127.0.0.1:{} via HTTP/2. Send a GET request to / and read the response.",
            server.port
        ))
            .with_mock(|mock| {
                mock
                    // Mock 1: Client startup
                    .on_instruction_containing("Connect to")
                    .and_instruction_containing("HTTP/2")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "open_client",
                            "remote_addr": format!("127.0.0.1:{}", server.port),
                            "protocol": "HTTP2",
                            "instruction": "Send GET request to / and read response"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // Mock 2: Client connected
                    .on_event("http2_connected")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "send_http2_request",
                            "method": "GET",
                            "path": "/",
                            "headers": {},
                            "body": ""
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // Mock 3: Client receives response
                    .on_event("http2_response_received")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "wait_for_more"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
            });

        let mut client = start_netget_client(client_config).await?;

        // Give client time to make request

        // Verify client output shows connection/response
        client
            .wait_for_any(&["HTTP2", "http2", "HTTP/2", "connected"], 30)
            .await;
        assert!(
            client.output_contains("HTTP2").await
                || client.output_contains("http2").await
                || client.output_contains("HTTP/2").await
                || client.output_contains("connected").await,
            "Client should show HTTP/2 protocol or connection message. Output: {:?}",
            client.get_output().await
        );

        println!("✅ HTTP/2 client made GET request successfully");

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

    /// Test HTTP/2 client can send requests based on LLM instructions
    /// LLM calls: 5 (server startup, server request, client startup, client connected, client response)
    #[tokio::test]
    async fn test_http2_client_llm_controlled_request() -> E2EResult<()> {
        // Start a simple HTTP/2 server with mocks
        let server_config = NetGetConfig::new(
            "Listen on port {AVAILABLE_PORT} via HTTP/2. Log all incoming requests.",
        )
        .with_mock(|mock| {
            mock
                // Mock 1: Server startup
                .on_instruction_containing("Listen on port")
                .and_instruction_containing("HTTP/2")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "HTTP2",
                        "instruction": "Log all incoming requests"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2: Server receives custom header request
                .on_event("http2_request")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "send_http2_response",
                        "status": 200,
                        "headers": {},
                        "body": "Request logged"
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let mut server = start_netget_server(server_config).await?;

        tokio::time::sleep(Duration::from_millis(500)).await;

        // Client that makes a specific request based on LLM instruction with mocks
        let client_config = NetGetConfig::new(format!(
            "Connect to http://127.0.0.1:{} via HTTP/2 and send a GET request with custom headers.",
            server.port
        ))
        .with_mock(|mock| {
            mock
                // Mock 1: Client startup
                .on_instruction_containing("Connect to")
                .and_instruction_containing("HTTP/2")
                .and_instruction_containing("custom headers")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_client",
                        "remote_addr": format!("127.0.0.1:{}", server.port),
                        "protocol": "HTTP2",
                        "instruction": "Send GET request with custom headers"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2: Client connected - send request with custom headers
                .on_event("http2_connected")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "send_http2_request",
                        "method": "GET",
                        "path": "/",
                        "headers": {"X-Custom-Header": "test-value"},
                        "body": ""
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 3: Client receives response
                .on_event("http2_response_received")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "wait_for_more"
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let mut client = start_netget_client(client_config).await?;

        server.wait_for_mocks(30).await;

        // Verify the client is HTTP2 protocol
        assert_eq!(client.protocol, "HTTP2", "Client should be HTTP2 protocol");

        println!("✅ HTTP/2 client responded to LLM instruction");

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

    /// Test HTTP/2 multiplexing with concurrent requests
    /// LLM calls: 5 (server startup, 2x server requests, client startup, client connected)
    #[tokio::test]
    async fn test_http2_client_multiplexing() -> E2EResult<()> {
        // Start an HTTP/2 server with mocks
        let server_config = NetGetConfig::new(
            "Listen on port {AVAILABLE_PORT} via HTTP/2. Respond to all requests with their path.",
        )
        .with_mock(|mock| {
            mock
                // Mock 1: Server startup
                .on_instruction_containing("Listen on port")
                .and_instruction_containing("HTTP/2")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "HTTP2",
                        "instruction": "Respond to all requests with their path"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2: Server receives /first request
                .on_event("http2_request")
                // `uri`, not `path`: the http2_request event carries method/uri/version/
                // headers/body. A constraint on a field that is not there can never
                // match, so both requests fell through to a real LLM call.
                .and_event_data_contains("uri", "/first")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "send_http2_response",
                        "status": 200,
                        "headers": {},
                        "body": "/first"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 3: Server receives /second request
                .on_event("http2_request")
                // `uri`, not `path`: the http2_request event carries method/uri/version/
                // headers/body. A constraint on a field that is not there can never
                // match, so both requests fell through to a real LLM call.
                .and_event_data_contains("uri", "/second")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "send_http2_response",
                        "status": 200,
                        "headers": {},
                        "body": "/second"
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let mut server = start_netget_server(server_config).await?;

        tokio::time::sleep(Duration::from_millis(500)).await;

        // Client that makes multiple requests with mocks
        let client_config = NetGetConfig::new(format!(
            "Connect to http://127.0.0.1:{} via HTTP/2. Send GET requests to /first and /second.",
            server.port
        ))
        .with_mock(|mock| {
            mock
                // Mock 1: Client startup
                .on_instruction_containing("Connect to")
                .and_instruction_containing("HTTP/2")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_client",
                        "remote_addr": format!("127.0.0.1:{}", server.port),
                        "protocol": "HTTP2",
                        "instruction": "Send GET requests to /first and /second"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2: Client connected - send first request
                .on_event("http2_connected")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "send_http2_request",
                        "method": "GET",
                        "path": "/first",
                        "headers": {},
                        "body": ""
                    },
                    {
                        "type": "send_http2_request",
                        "method": "GET",
                        "path": "/second",
                        "headers": {},
                        "body": ""
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let mut client = start_netget_client(client_config).await?;

        // Verify client shows HTTP/2 protocol
        client.wait_for_any(&["HTTP2", "http2", "HTTP/2"], 30).await;
        assert!(
            client.output_contains("HTTP2").await
                || client.output_contains("http2").await
                || client.output_contains("HTTP/2").await,
            "Client should show HTTP/2 protocol"
        );

        println!("✅ HTTP/2 client demonstrated multiplexing capability");

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

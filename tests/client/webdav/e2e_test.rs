//! E2E tests for WebDAV client
//!
//! These tests verify WebDAV client functionality by spawning the actual NetGet binary
//! and testing client behavior as a black-box.

mod webdav_client_tests {
    use crate::helpers::*;
    use std::time::Duration;

    /// Test WebDAV client making a PROPFIND request
    /// LLM calls: 5 (server startup, server request, client startup, client connected, client response)
    #[tokio::test]
    async fn test_webdav_client_propfind() -> E2EResult<()> {
        // Start a WebDAV server listening on an available port with mocks
        let server_config = NetGetConfig::new("Listen on port {AVAILABLE_PORT} via WebDAV. Respond to PROPFIND requests with a simple directory listing.")
            .with_mock(|mock| {
                mock
                    // Mock 1: Server startup
                    .on_instruction_containing("Listen on port")
                    .and_instruction_containing("WebDAV")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "open_server",
                            "port": 0,
                            "base_stack": "WebDAV",
                            "instruction": "Respond to PROPFIND with directory listing"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // Mock 2: Server receives PROPFIND request
                    .on_event("webdav_request")
                    .and_event_data_contains("method", "PROPFIND")
                    .respond_with_actions(serde_json::json!([
                        {
                            // The WebDAV server builds DAV:multistatus itself;
                            // send_http_response is the HTTP server's verb and this
                            // server cannot execute it.
                            "type": "send_webdav_listing",
                            "path": "/",
                            "entries": [
                                { "name": "documents", "is_collection": true }
                            ]
                        }
                    ]))
                    .expect_calls(1)
                    .and()
            });

        let mut server = start_netget_server(server_config).await?;

        // Give server time to start
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Now start a WebDAV client that makes a PROPFIND request with mocks
        let client_config = NetGetConfig::new(format!(
            "Connect to http://127.0.0.1:{} via WebDAV. Send a PROPFIND request to / to list directory contents.",
            server.port
        ))
            .with_mock(|mock| {
                mock
                    // Mock 1: Client startup
                    .on_instruction_containing("Connect to")
                    .and_instruction_containing("WebDAV")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "open_client",
                            "remote_addr": format!("http://127.0.0.1:{}", server.port),
                            "protocol": "WebDAV",
                            "instruction": "Send PROPFIND to / to list contents"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // Mock 2: Client connected
                    .on_event("webdav_connected")
                    .respond_with_actions(serde_json::json!([
                        {
                            // WebDAV's own verb. `send_http_request` is the HTTP
                            // client's, and WebDAV cannot execute it.
                            "type": "propfind",
                            "path": "/",
                            "depth": "1"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // Mock 3: Client receives multistatus response
                    .on_event("webdav_response_received")
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
            .wait_for_any(&["WebDAV", "connected", "PROPFIND"], 30)
            .await;
        assert!(
            client.output_contains("WebDAV").await
                || client.output_contains("connected").await
                || client.output_contains("PROPFIND").await,
            "Client should show WebDAV protocol or PROPFIND message. Output: {:?}",
            client.get_output().await
        );

        println!("✅ WebDAV client made PROPFIND request successfully");

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

    /// Test WebDAV client can perform LLM-controlled operations
    /// LLM calls: 5 (server startup, server request, client startup, client connected, client response)
    #[tokio::test]
    async fn test_webdav_client_llm_controlled() -> E2EResult<()> {
        // Start a simple WebDAV server with mocks
        let server_config = NetGetConfig::new(
            "Listen on port {AVAILABLE_PORT} via WebDAV. Log all incoming WebDAV requests.",
        )
        .with_mock(|mock| {
            mock
                // Mock 1: Server startup
                .on_instruction_containing("Listen on port")
                .and_instruction_containing("WebDAV")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "WebDAV",
                        "instruction": "Log all incoming requests"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2: Server receives PROPFIND
                .on_event("webdav_request")
                .and_event_data_contains("method", "PROPFIND")
                .respond_with_actions(serde_json::json!([
                    {
                        // The WebDAV server builds DAV:multistatus itself;
                        // send_http_response is the HTTP server's verb and this
                        // server cannot execute it.
                        "type": "send_webdav_listing",
                        "path": "/",
                        "entries": [
                            { "name": "documents", "is_collection": true }
                        ]
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let mut server = start_netget_server(server_config).await?;

        tokio::time::sleep(Duration::from_millis(500)).await;

        // Client that performs WebDAV operations based on LLM instruction with mocks
        let client_config = NetGetConfig::new(format!(
            "Connect to http://127.0.0.1:{} via WebDAV and list the root directory using PROPFIND.",
            server.port
        ))
        .with_mock(|mock| {
            mock
                // Mock 1: Client startup
                .on_instruction_containing("Connect to")
                .and_instruction_containing("WebDAV")
                .and_instruction_containing("PROPFIND")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_client",
                        "remote_addr": format!("http://127.0.0.1:{}", server.port),
                        "protocol": "WebDAV",
                        "instruction": "List root directory with PROPFIND"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2: Client connected - send PROPFIND
                .on_event("webdav_connected")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "propfind",
                        "path": "/",
                        "depth": "1"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 3: Client receives response
                .on_event("webdav_response_received")
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

        // Verify the client is WebDAV protocol
        assert_eq!(
            client.protocol, "WebDAV",
            "Client should be WebDAV protocol"
        );

        println!("✅ WebDAV client responded to LLM instruction");

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

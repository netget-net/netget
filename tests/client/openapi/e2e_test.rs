//! E2E tests for OpenAPI client
//!
//! These tests verify OpenAPI client functionality with spec-driven requests.

mod openapi_client_tests {
    use crate::helpers::*;
    use serde_json::json;
    use std::time::Duration;

    /// Test OpenAPI client executing operations from spec file
    /// LLM calls: 4 (server startup, server request, client startup, client connected)
    #[tokio::test]
    async fn test_openapi_client_with_spec() -> E2EResult<()> {
        // Load test OpenAPI spec from file
        let spec_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/client/openapi/test-api.yaml");
        let spec_template =
            std::fs::read_to_string(&spec_path).expect("Failed to read test-api.yaml");

        // Start an HTTP server to act as the OpenAPI backend
        let server_config =
            NetGetConfig::new("Listen on port 0 via HTTP. Respond to GET /users with user list.")
                .with_mock(|mock| {
                    mock
                // Mock 1: Server startup
                .on_instruction_containing("Listen on port")
                .and_instruction_containing("HTTP")
                .respond_with_actions(json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "HTTP",
                        "instruction": "Respond to GET /users with user list"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2: Server receives GET /users request
                .on_event("http_request")
                // `path`, not `uri`: the http_request event carries method/path/query/
                // headers/body, and a constraint on a field that is not there can never
                // match -- so every request fell through to a real LLM call.
                .and_event_data_contains("path", "/users")
                .respond_with_actions(json!([
                    {
                        "type": "send_http_response",
                        "status": 200,
                        "headers": {"Content-Type": "application/json"},
                        "body": "[{\"id\": 1, \"name\": \"Alice\"}, {\"id\": 2, \"name\": \"Bob\"}]"
                    }
                ]))
                .expect_calls(1)
                .and()
                });

        let server = start_netget_server(server_config).await?;

        // Give server time to start
        crate::helpers::wait_for_server_listening(&server, Duration::from_secs(30)).await?;

        println!("[TEST] Server started on port {}", server.port);

        // Inject actual port into spec
        let openapi_spec = spec_template.replace("{port}", &server.port.to_string());

        // Start OpenAPI client with spec
        let client_config = NetGetConfig::new("Connect via OpenAPI client and list users")
            .with_mock(|mock| {
                mock
                    // Mock 1: Client startup
                    .on_instruction_containing("Connect via OpenAPI")
                    .respond_with_actions(json!([
                        {
                            "type": "open_client",
                            "remote_addr": format!("127.0.0.1:{}", server.port),
                            "protocol": "OpenAPI",
                            "startup_params": {
                                "spec": openapi_spec.clone(),
                            },
                            "instruction": "Execute listUsers operation"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // Mock 2: Client connected - execute listUsers operation
                    .on_event("openapi_client_connected")
                    .respond_with_actions(json!([
                        {
                            "type": "execute_operation",
                            "operation_id": "listUsers",
                            "path_params": {},
                            "query_params": {},
                            "headers": {},
                            "body": null
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // Mock 3: Operation response received - verify and disconnect
                    .on_event("openapi_operation_response")
                    .and_event_data_contains("operation_id", "listUsers")
                    .and_event_data_contains("status_code", "200")
                    .respond_with_actions(json!([
                        {
                            "type": "disconnect"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
            });

        let client = start_netget_client(client_config).await?;

        // Wait for test to complete

        // Verify all mocks were called
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last response routinely lands
        // after the sleep expires, and the test reports it as never having happened.
        client.wait_for_mocks(30).await;
        server.wait_for_mocks(30).await;
        client.verify_mocks().await?;
        server.verify_mocks().await?;

        Ok(())
    }

    /// Test OpenAPI client with path parameter substitution
    /// LLM calls: 4 (server startup, server request, client startup, client connected)
    #[tokio::test]
    async fn test_openapi_client_path_params() -> E2EResult<()> {
        // Load test OpenAPI spec from file
        let spec_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/client/openapi/test-api.yaml");
        let spec_template =
            std::fs::read_to_string(&spec_path).expect("Failed to read test-api.yaml");

        // Start an HTTP server
        let server_config = NetGetConfig::new("Listen on port 0 via HTTP. Respond to GET /users/123")
            .with_mock(|mock| {
                mock
                    .on_instruction_containing("Listen on port")
                    .respond_with_actions(json!([
                        {
                            "type": "open_server",
                            "port": 0,
                            "base_stack": "HTTP",
                            "instruction": "Respond to GET /users/123"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // Verify path substitution worked - expect /users/123
                    .on_event("http_request")
                    .and_event_data_contains("path", "/users/123")
                    .respond_with_actions(json!([
                        {
                            "type": "send_http_response",
                            "status": 200,
                            "headers": {"Content-Type": "application/json"},
                            "body": "{\"id\": 123, \"name\": \"Alice\", \"email\": \"alice@example.com\"}"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
            });

        let server = start_netget_server(server_config).await?;
        crate::helpers::wait_for_server_listening(&server, Duration::from_secs(30)).await?;

        // Inject actual port into spec
        let openapi_spec = spec_template.replace("{port}", &server.port.to_string());

        let client_config = NetGetConfig::new("Get user 123 via OpenAPI").with_mock(|mock| {
            mock.on_instruction_containing("Get user 123")
                .respond_with_actions(json!([
                    {
                        "type": "open_client",
                        "remote_addr": format!("127.0.0.1:{}", server.port),
                        "protocol": "OpenAPI",
                        "startup_params": {
                            "spec": openapi_spec.clone(),
                        },
                        "instruction": "Execute getUser with id=123"
                    }
                ]))
                .expect_calls(1)
                .and()
                .on_event("openapi_client_connected")
                .respond_with_actions(json!([
                    {
                        "type": "execute_operation",
                        "operation_id": "getUser",
                        "path_params": {"id": "123"},
                        "query_params": {},
                        "headers": {},
                        "body": null
                    }
                ]))
                .expect_calls(1)
                .and()
                .on_event("openapi_operation_response")
                .and_event_data_contains("operation_id", "getUser")
                .and_event_data_contains("status_code", "200")
                .respond_with_actions(json!([{"type": "disconnect"}]))
                .expect_calls(1)
                .and()
        });

        let client = start_netget_client(client_config).await?;

        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last response routinely lands
        // after the sleep expires, and the test reports it as never having happened.
        client.wait_for_mocks(30).await;
        server.wait_for_mocks(30).await;
        client.verify_mocks().await?;
        server.verify_mocks().await?;

        Ok(())
    }
}

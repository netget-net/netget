//! E2E tests for gRPC client
//!
//! These tests verify gRPC client functionality by spawning NetGet gRPC server and client
//! and testing client behavior as a black-box.

mod grpc_client_tests {
    use crate::helpers::*;
    use std::time::Duration;

    // Base64-encoded FileDescriptorSet for a simple calculator service
    // Generated from:
    // syntax = "proto3";
    // package calculator;
    //
    // service Calculator {
    //   rpc Add(AddRequest) returns (AddResponse);
    // }
    //
    // message AddRequest {
    //   int32 a = 1;
    //   int32 b = 2;
    // }
    //
    // message AddResponse {
    //   int32 result = 1;
    // }
    /// A base64 `FileDescriptorSet` for the calculator service, produced by
    /// `protoc --descriptor_set_out`. The previous value decoded cleanly as base64 but
    /// declared a 277-byte file message inside 194 bytes of payload, so prost rejected it
    /// and the server refused to start with "Failed to compile protobuf schema".
    const CALCULATOR_SCHEMA: &str = "Cr8BChBjYWxjdWxhdG9yLnByb3RvEgpjYWxjdWxhdG9yIigKCkFkZFJlcXVlc3QSDAoBYRgBIAEoBVIBYRIMCgFiGAIgASgFUgFiIiUKC0FkZFJlc3BvbnNlEhYKBnJlc3VsdBgBIAEoBVIGcmVzdWx0MkYKCkNhbGN1bGF0b3ISOAoDQWRkEhYuY2FsY3VsYXRvci5BZGRSZXF1ZXN0GhcuY2FsY3VsYXRvci5BZGRSZXNwb25zZSIAYgZwcm90bzM=";

    /// Test gRPC client connecting to server and making RPC call
    /// LLM calls: 4 with mocks (server startup, server handles request, client startup, client makes call)
    #[tokio::test]
    async fn test_grpc_client_add_request() -> E2EResult<()> {
        // Start a gRPC server listening on an available port with mocks
        let server_config = NetGetConfig::new(format!(
            "Listen on port {{AVAILABLE_PORT}} via gRPC. Use this schema: {}. When you receive Add requests, return the sum of a and b in the result field.",
            CALCULATOR_SCHEMA
        ))
        .with_mock(|mock| {
            mock
                // Mock 1: Server startup
                .on_instruction_containing("gRPC")
                .and_instruction_containing("Add requests")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "gRPC",
                        "instruction": "Return sum of a and b in result field for Add requests",
                        // `open_server` takes protocol parameters inside `startup_params`,
                        // not at the top level. Loose, this was ignored and the server
                        // refused to start: "Missing 'proto_schema' in startup_params".
                        "startup_params": { "proto_schema": CALCULATOR_SCHEMA }
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2: Server handles Add request
                .on_event("grpc_unary_request")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "grpc_unary_response",
                        "message": {
                            "result": 8  // 5 + 3
                        }
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let mut server = start_netget_server(server_config).await?;

        // Give server time to start
        tokio::time::sleep(Duration::from_millis(1000)).await;

        // Now start a gRPC client that makes an Add request with mocks
        let client_config = NetGetConfig::new(format!(
            "Connect to 127.0.0.1:{} via gRPC. Use this schema: {}. Call calculator.Calculator/Add with a=5, b=3 and show the result.",
            server.port, CALCULATOR_SCHEMA
        ))
        .with_mock(|mock| {
            mock
                // Mock 1: Client startup
                .on_instruction_containing("Connect")
                .and_instruction_containing("gRPC")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_client",
                        "remote_addr": format!("127.0.0.1:{}", server.port),
                        "protocol": "gRPC",
                        "instruction": "Call calculator.Calculator/Add with a=5, b=3",
                        // Same as the server above: protocol parameters go inside
                        // `startup_params`, not at the action's top level.
                        "startup_params": { "proto_schema": CALCULATOR_SCHEMA }
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2: Client makes Add RPC call upon connection
                .on_event("grpc_connected")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "call_grpc_method",
                        "service": "calculator.Calculator",
                        "method": "Add",
                        "request": {
                            "a": 5,
                            "b": 3
                        }
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 3: Client receives response
                .on_event("grpc_response_received")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "wait_for_more"
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let mut client = start_netget_client(client_config).await?;

        // Give client time to make request and receive response
        tokio::time::sleep(Duration::from_millis(2000)).await;

        // Verify client output shows gRPC connection or result
        let output = client.get_output().await;
        assert!(
            output.iter().any(|l| l.contains("gRPC"))
                || output.iter().any(|l| l.contains("Calculator"))
                || output.iter().any(|l| l.contains("result"))
                || output.iter().any(|l| l.contains("8")),
            "Client should show gRPC protocol, service name, result field, or sum (8). Output: {:?}",
            output
        );

        println!("✅ gRPC client made Add RPC call successfully");

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

    /// Test gRPC client can handle connection errors gracefully
    /// LLM calls: 1 with mock (client connection attempt)
    #[tokio::test]
    async fn test_grpc_client_connection_error() -> E2EResult<()> {
        // Try to connect to a non-existent gRPC server with mocks
        let client_config = NetGetConfig::new(format!(
            "Connect to 127.0.0.1:54321 via gRPC. Use this schema: {}. Call calculator.Calculator/Add with a=1, b=2.",
            CALCULATOR_SCHEMA
        ))
        .with_mock(|mock| {
            mock
                // Mock: Client connection attempt (will fail)
                .on_instruction_containing("Connect")
                .and_instruction_containing("gRPC")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_client",
                        "remote_addr": "127.0.0.1:54321",
                        "protocol": "gRPC",
                        "instruction": "Call calculator.Calculator/Add with a=1, b=2",
                        // Same as the server above: protocol parameters go inside
                        // `startup_params`, not at the action's top level.
                        "startup_params": { "proto_schema": CALCULATOR_SCHEMA }
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let mut client = start_netget_client(client_config).await?;

        // Give client time to attempt connection
        tokio::time::sleep(Duration::from_millis(1000)).await;

        // Verify client shows error or connection failure
        let output = client.get_output().await;
        assert!(
            output.iter().any(|l| l.contains("ERROR"))
                || output.iter().any(|l| l.contains("error"))
                || output.iter().any(|l| l.contains("failed"))
                || output.iter().any(|l| l.contains("Error")),
            "Client should show connection error. Output: {:?}",
            output
        );

        println!("✅ gRPC client handled connection error gracefully");

        // Verify mock expectations were met
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last response routinely lands
        // after the sleep expires, and the test reports it as never having happened.
        client.wait_for_mocks(30).await;
        client.verify_mocks().await?;

        // Cleanup
        client.stop().await?;

        Ok(())
    }
}

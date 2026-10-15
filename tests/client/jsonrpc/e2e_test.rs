//! E2E tests for JSON-RPC client
//!
//! These tests verify JSON-RPC client functionality by spawning the actual NetGet binary
//! and testing client behavior as a black-box.

mod jsonrpc_client_tests {
    use crate::helpers::*;
    use std::time::Duration;

    /// Test JSON-RPC client making a single request
    /// LLM calls: 2 (server startup, client connection and request)
    #[tokio::test]
    async fn test_jsonrpc_client_single_request() -> E2EResult<()> {
        // Start a JSON-RPC server listening on an available port with mocks
        let server_config = NetGetConfig::new(
            "Listen on port {AVAILABLE_PORT} via JSON-RPC. \
             Implement these methods: \
             - add(a, b): Return the sum of a and b \
             - greet(name): Return 'Hello, {name}!'",
        )
        .with_mock(|mock| {
            mock
                // Mock 1: Server startup (user command)
                .on_instruction_containing("Listen on port")
                .and_instruction_containing("JSON-RPC")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "HTTP",
                        "protocol": "JSON-RPC",
                        "instruction": "JSON-RPC server with add and greet methods"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2: JSON-RPC method call received (jsonrpc_method_call event)
                .on_event("jsonrpc_method_call")
                .and_event_data_contains("method", "add")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "jsonrpc_success",
                        "result": 8,
                        "id": 1
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let mut server = start_netget_server(server_config).await?;

        // Give server time to start
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Now start a JSON-RPC client that makes a request with mocks
        let client_config = NetGetConfig::new(format!(
            "Connect to http://127.0.0.1:{} via JSON-RPC. \
             Call method 'add' with params [5, 3] and id 1.",
            server.port
        ))
        .with_mock(|mock| {
            mock
                // Mock 1: Client startup (user command)
                .on_instruction_containing("Connect to")
                .and_instruction_containing("JSON-RPC")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_client",
                        "remote_addr": format!("127.0.0.1:{}", server.port),
                        "protocol": "JSON-RPC",
                        "instruction": "Call add method with params [5, 3]"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2: Client connected (jsonrpc_connected event)
                .on_event("jsonrpc_connected")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "send_jsonrpc_request",
                        "method": "add",
                        "params": [5, 3],
                        "id": 1
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 3: Client receives response (jsonrpc_response_received event)
                .on_event("jsonrpc_response_received")
                .and_event_data_contains("result", "8")
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
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Verify client output shows connection/response
        client.wait_for_any(&["JSON-RPC", "jsonrpc"], 30).await;
        assert!(
            client.output_contains("JSON-RPC").await || client.output_contains("jsonrpc").await,
            "Client should show JSON-RPC protocol message. Output: {:?}",
            client.get_output().await
        );

        println!("✅ JSON-RPC client made single request successfully");

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

    /// A request the model issues *in answer to a response* gets its own response event.
    ///
    /// The chain `request -> jsonrpc_response_received -> the model's next request` is
    /// self-referential, and this client has had it wrong twice. First the follow-up actions
    /// were discarded outright (`actions: _` at both notify sites), so answering the response
    /// event did nothing at all. Then they were dispatched through the `perform_*` cores,
    /// which raise no event — bounded, but exactly **one** step deep, so the second request's
    /// own reply went nowhere and the model went deaf after it. That is the
    /// `elasticsearch`/`http2` shape the root CLAUDE.md names; the prescribed answer is a
    /// depth bound (`MAX_FOLLOWUP_DEPTH`), not silence.
    ///
    /// This pins depth 2: `step_one` on connect, `step_two` in answer to its response, and a
    /// third model call for `step_two`'s response. One rule handles both responses and
    /// branches on the event, because two rules on the same event with no way to tell them
    /// apart is first-match-wins and the second would never fire.
    ///
    /// LLM calls: 3 on the server (startup + two methods), 3 on the client.
    #[tokio::test]
    async fn test_jsonrpc_client_chains_a_second_request_from_a_response() -> E2EResult<()> {
        let server_config = NetGetConfig::new(
            "Listen on port {AVAILABLE_PORT} via JSON-RPC. \
             Implement step_one and step_two.",
        )
        .with_mock(|mock| {
            mock.on_instruction_containing("Listen on port")
                .and_instruction_containing("JSON-RPC")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "HTTP",
                        "protocol": "JSON-RPC",
                        "instruction": "JSON-RPC server with step_one and step_two"
                    }
                ]))
                .expect_calls(1)
                .and()
                // One rule, branching on the method: two rules on the same event with no way
                // to tell them apart would let the first answer both.
                .on_event("jsonrpc_method_call")
                .respond_with_actions_from_event(|e| {
                    let method = e["method"].as_str().unwrap_or_default();
                    serde_json::json!([{
                        "type": "jsonrpc_success",
                        "result": format!("{method}-done")
                    }])
                })
                .expect_calls(2)
                .and()
        });

        let mut server = start_netget_server(server_config).await?;
        tokio::time::sleep(Duration::from_millis(500)).await;

        let client_config = NetGetConfig::new(format!(
            "Connect to http://127.0.0.1:{} via JSON-RPC. Call step_one, then step_two.",
            server.port
        ))
        .with_mock(|mock| {
            mock.on_instruction_containing("Connect to")
                .and_instruction_containing("JSON-RPC")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_client",
                        "remote_addr": format!("127.0.0.1:{}", server.port),
                        "protocol": "JSON-RPC",
                        "instruction": "Call step_one, then step_two"
                    }
                ]))
                .expect_calls(1)
                .and()
                .on_event("jsonrpc_connected")
                .respond_with_actions(serde_json::json!([
                    {"type": "send_jsonrpc_request", "method": "step_one", "id": 1}
                ]))
                .expect_calls(1)
                .and()
                // The second call is what the bug suppressed: without it this rule fires once
                // and `expect_calls(2)` fails.
                .on_event("jsonrpc_response_received")
                .respond_with_actions_from_event(|e| {
                    if e["result"].as_str() == Some("step_one-done") {
                        serde_json::json!([
                            {"type": "send_jsonrpc_request", "method": "step_two", "id": 2}
                        ])
                    } else {
                        serde_json::json!([{"type": "wait_for_more"}])
                    }
                })
                .expect_calls(2)
                .and()
        });

        let mut client = start_netget_client(client_config).await?;

        server.wait_for_mocks(30).await;
        client.wait_for_mocks(30).await;
        // The server having answered two distinct methods is the load-bearing assertion: the
        // second one exists only because the client acted on the first one's response.
        server.verify_mocks().await?;
        client.verify_mocks().await?;

        server.stop().await?;
        client.stop().await?;
        Ok(())
    }

    /// Test JSON-RPC client can handle LLM-controlled method calls
    /// LLM calls: 2 (server startup, client connection and request)
    #[tokio::test]
    async fn test_jsonrpc_client_llm_controlled_request() -> E2EResult<()> {
        // Start a JSON-RPC server with mocks
        let server_config = NetGetConfig::new(
            "Listen on port {AVAILABLE_PORT} via JSON-RPC. \
             Implement method 'echo' that returns whatever params it receives.",
        )
        .with_mock(|mock| {
            mock
                // Mock 1: Server startup (user command)
                .on_instruction_containing("Listen on port")
                .and_instruction_containing("JSON-RPC")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "HTTP",
                        "protocol": "JSON-RPC",
                        "instruction": "JSON-RPC server with echo method"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2: JSON-RPC method call received (jsonrpc_method_call event)
                .on_event("jsonrpc_method_call")
                .and_event_data_contains("method", "echo")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "jsonrpc_success",
                        "result": "test message",
                        "id": 1
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let mut server = start_netget_server(server_config).await?;

        tokio::time::sleep(Duration::from_millis(500)).await;

        // Client that makes a specific request based on LLM instruction with mocks
        let client_config = NetGetConfig::new(format!(
            "Connect to http://127.0.0.1:{} via JSON-RPC and call the echo method.",
            server.port
        ))
        .with_mock(|mock| {
            mock
                // Mock 1: Client startup (user command)
                .on_instruction_containing("Connect to")
                .and_instruction_containing("JSON-RPC")
                .and_instruction_containing("echo")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_client",
                        "remote_addr": format!("127.0.0.1:{}", server.port),
                        "protocol": "JSON-RPC",
                        "instruction": "Call echo method"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2: Client connected (jsonrpc_connected event)
                .on_event("jsonrpc_connected")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "send_jsonrpc_request",
                        "method": "echo",
                        "params": ["test message"],
                        "id": 1
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 3: Client receives response (jsonrpc_response_received event)
                .on_event("jsonrpc_response_received")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "wait_for_more"
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let mut client = start_netget_client(client_config).await?;

        tokio::time::sleep(Duration::from_millis(500)).await;

        // Verify the client is JSON-RPC protocol
        assert_eq!(
            client.protocol, "JSON-RPC",
            "Client should be JSON-RPC protocol"
        );

        println!("✅ JSON-RPC client responded to LLM instruction");

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

    /// Test JSON-RPC client can send batch requests
    /// LLM calls: 2 (server startup, client connection and batch request)
    #[tokio::test]
    async fn test_jsonrpc_client_batch_request() -> E2EResult<()> {
        // Start a JSON-RPC server with mocks
        let server_config = NetGetConfig::new(
            "Listen on port {AVAILABLE_PORT} via JSON-RPC. \
             Implement these methods: \
             - add(a, b): Return a + b \
             - multiply(a, b): Return a * b",
        )
        .with_mock(|mock| {
            mock
                // Mock 1: Server startup (user command)
                .on_instruction_containing("Listen on port")
                .and_instruction_containing("JSON-RPC")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "HTTP",
                        "protocol": "JSON-RPC",
                        "instruction": "JSON-RPC server with add and multiply methods"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2-3: Two batch requests (jsonrpc_method_call event x2)
                .on_event("jsonrpc_method_call")
                .and_event_data_contains("method", "add")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "jsonrpc_success",
                        "result": 3,
                        "id": 1
                    }
                ]))
                .expect_calls(1)
                .and()
                .on_event("jsonrpc_method_call")
                .and_event_data_contains("method", "multiply")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "jsonrpc_success",
                        "result": 12,
                        "id": 2
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let mut server = start_netget_server(server_config).await?;

        tokio::time::sleep(Duration::from_millis(500)).await;

        // Client that sends a batch request with mocks
        let client_config = NetGetConfig::new(format!(
            "Connect to http://127.0.0.1:{} via JSON-RPC. \
             Send a batch request with two calls: \
             1. add([1, 2]) with id 1 \
             2. multiply([3, 4]) with id 2",
            server.port
        ))
        .with_mock(|mock| {
            mock
                // Mock 1: Client startup (user command)
                .on_instruction_containing("Connect to")
                .and_instruction_containing("JSON-RPC")
                .and_instruction_containing("batch")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_client",
                        "remote_addr": format!("127.0.0.1:{}", server.port),
                        "protocol": "JSON-RPC",
                        "instruction": "Send batch request with add and multiply"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2: Client connected (jsonrpc_connected event)
                .on_event("jsonrpc_connected")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "send_jsonrpc_batch",
                        "requests": [
                            {"method": "add", "params": [1, 2], "id": 1},
                            {"method": "multiply", "params": [3, 4], "id": 2}
                        ]
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 3: Client receives batch response (jsonrpc_response_received event)
                .on_event("jsonrpc_response_received")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "wait_for_more"
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let mut client = start_netget_client(client_config).await?;

        tokio::time::sleep(Duration::from_millis(500)).await;

        // Verify client is connected
        client.wait_for_any(&["JSON-RPC", "connected"], 30).await;
        assert!(
            client.output_contains("JSON-RPC").await || client.output_contains("connected").await,
            "Client should show JSON-RPC connection. Output: {:?}",
            client.get_output().await
        );

        println!("✅ JSON-RPC client sent batch request successfully");

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

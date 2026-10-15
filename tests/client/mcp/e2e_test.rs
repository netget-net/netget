//! E2E tests for the MCP client, driven against NetGet's own MCP server.
//!
//! **These were all three `#[ignore]`d**, on the grounds that they configured no
//! `.with_mock()` and so needed `--use-ollama`. That left the MCP client with no running e2e
//! coverage at all — only `command_channel_test.rs`, which points the client's LLM at an
//! unreachable URL and never exercises the handshake or an operation. An `#[ignore]`d test is
//! not evidence (root CLAUDE.md, rubric point 6), and the gap it left is exactly where the
//! `initialized` / `notifications/initialized` defect lived: phase 3 of the MCP handshake was
//! an unrecognised notification to every server this client ever spoke to, including ours.
//!
//! They are mocked now and run by default. Each mocks both ends, so the assertions are about
//! the exchange rather than about a substring in the output.
//!
//! Total LLM call budget across the file: 15 (5 server + 4 client + 3 + 3, see each test).

mod mcp_client_tests {
    use crate::helpers::*;

    /// The `serverInfo` the client's `connect()` requires — it errors with "Missing serverInfo
    /// in initialize response" without it, so a mock that omits it fails the handshake rather
    /// than the assertion under test.
    fn initialize_result() -> serde_json::Value {
        serde_json::json!({
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {}, "resources": {}, "prompts": {}},
            "serverInfo": {"name": "netget-test-mcp", "version": "9.9.9"}
        })
    }

    /// The three-phase handshake completes and the client reaches Connected.
    ///
    /// LLM calls: 2 server (startup, `mcp_initialize`), 2 client (startup, `mcp_client_connected`).
    #[tokio::test]
    async fn test_mcp_client_initialize() -> E2EResult<()> {
        let server_config = NetGetConfig::new(
            "Listen on port {AVAILABLE_PORT} via MCP. \
             Provide a tool called 'calculate' that evaluates math expressions.",
        )
        .with_mock(|mock| {
            mock.on_instruction_containing("Listen on port")
                .and_instruction_containing("MCP")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "MCP",
                        "instruction": "MCP server offering a calculate tool"
                    }
                ]))
                .expect_calls(1)
                .and()
                .on_event("mcp_initialize")
                .respond_with_actions(serde_json::json!([
                    {"type": "mcp_initialize_response", "response": initialize_result()}
                ]))
                .expect_calls(1)
                .and()
        });

        let mut server = start_netget_server(server_config).await?;

        let client_config = NetGetConfig::new(format!(
            "Connect to http://127.0.0.1:{} via MCP. After connecting, wait.",
            server.port
        ))
        .with_mock(|mock| {
            mock.on_instruction_containing("Connect to")
                .and_instruction_containing("MCP")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_client",
                        "remote_addr": format!("127.0.0.1:{}", server.port),
                        "protocol": "MCP",
                        "instruction": "Stay connected"
                    }
                ]))
                .expect_calls(1)
                .and()
                // The connected event carries what the server said about itself; asserting on
                // it is what proves the handshake really completed rather than that a string
                // appeared in the log.
                .on_event("mcp_client_connected")
                .and_event_data_contains("server_name", "netget-test-mcp")
                .respond_with_actions(
                    serde_json::json!([{"type": "show_message", "message": "done"}]),
                )
                .expect_calls(1)
                .and()
        });

        let mut client = start_netget_client(client_config).await?;

        // Phase 3 of the handshake actually reached the server's router.
        //
        // This is the assertion the whole file exists for. The client sent method
        // `initialized`; MCP namespaces every notification under `notifications/`, so our own
        // server — which matches `notifications/initialized` and drops anything else into a
        // `debug!("Unknown MCP notification")` — never logged "MCP client initialized". Nothing
        // failed visibly, because a notification has no reply: the client logged that it had
        // sent one, got its 204, and declared the handshake complete. Only the server's own
        // log can tell the difference, which is why it is checked here and not on the client.
        server.wait_for_any(&["MCP client initialized"], 30).await;
        assert!(
            server.output_contains("MCP client initialized").await,
            "the server must have recognised notifications/initialized; if this fails the \
             client is sending the bare `initialized` again. Server output: {:?}",
            server.get_output().await
        );

        server.wait_for_mocks(30).await;
        client.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        client.verify_mocks().await?;

        server.stop().await?;
        client.stop().await?;
        Ok(())
    }

    /// `tools/list` then `tools/call`, chained off the response event.
    ///
    /// LLM calls: 4 server (startup, initialize, tools/list, tools/call), 4 client (startup,
    /// connected, two response events through the same branching rule).
    ///
    /// The terminating answer is `show_message`, not `wait_for_more`: `wait_for_more` is not
    /// an MCP client action, so the executor rejects it, the LLM repair loop re-asks, and the
    /// response event fires a second time — which shows up as `expected 2, got 3`.
    /// `tests/helpers/mock_action_names.rs` catches the statically-declared form of this
    /// mistake but cannot see inside a `respond_with_actions_from_event` closure.
    #[tokio::test]
    async fn test_mcp_client_call_tool() -> E2EResult<()> {
        let server_config = NetGetConfig::new(
            "Listen on port {AVAILABLE_PORT} via MCP. \
             Provide a tool called 'calculate' that evaluates the expression parameter.",
        )
        .with_mock(|mock| {
            mock.on_instruction_containing("Listen on port")
                .and_instruction_containing("MCP")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "MCP",
                        "instruction": "MCP server offering a calculate tool"
                    }
                ]))
                .expect_calls(1)
                .and()
                .on_event("mcp_initialize")
                .respond_with_actions(serde_json::json!([
                    {"type": "mcp_initialize_response", "response": initialize_result()}
                ]))
                .expect_calls(1)
                .and()
                .on_event("mcp_tools_list")
                .respond_with_actions(serde_json::json!([
                    {"type": "mcp_tools_list_response", "response": {"tools": [
                        {"name": "calculate", "description": "Evaluate arithmetic",
                         "inputSchema": {"type": "object",
                                         "properties": {"expression": {"type": "string"}}}}
                    ]}}
                ]))
                .expect_calls(1)
                .and()
                .on_event("mcp_tools_call")
                .and_event_data_contains("name", "calculate")
                .respond_with_actions(serde_json::json!([
                    {"type": "mcp_tools_call_response", "response": {
                        "content": [{"type": "text", "text": "4"}], "isError": false}}
                ]))
                .expect_calls(1)
                .and()
        });

        let mut server = start_netget_server(server_config).await?;

        let client_config = NetGetConfig::new(format!(
            "Connect to http://127.0.0.1:{} via MCP. List tools, then call 'calculate'.",
            server.port
        ))
        .with_mock(|mock| {
            mock.on_instruction_containing("Connect to")
                .and_instruction_containing("MCP")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_client",
                        "remote_addr": format!("127.0.0.1:{}", server.port),
                        "protocol": "MCP",
                        "instruction": "List tools, then call calculate"
                    }
                ]))
                .expect_calls(1)
                .and()
                .on_event("mcp_client_connected")
                .respond_with_actions(serde_json::json!([{"type": "list_tools"}]))
                .expect_calls(1)
                .and()
                // ONE rule for both responses, branching on the event. Two rules on the same
                // event with no way to tell them apart is first-match-wins, and the second
                // would report zero calls.
                .on_event("mcp_response_received")
                .respond_with_actions_from_event(|e| {
                    if e["method"].as_str() == Some("mcp_list_tools") {
                        serde_json::json!([{
                            "type": "call_tool",
                            "name": "calculate",
                            "arguments": {"expression": "2+2"}
                        }])
                    } else {
                        serde_json::json!([{"type": "show_message", "message": "done"}])
                    }
                })
                .expect_calls(2)
                .and()
        });

        let mut client = start_netget_client(client_config).await?;

        server.wait_for_mocks(30).await;
        client.wait_for_mocks(30).await;
        // The server having served both tools/list and tools/call is the load-bearing part:
        // the second exists only because the client acted on the first one's response.
        server.verify_mocks().await?;
        client.verify_mocks().await?;

        server.stop().await?;
        client.stop().await?;
        Ok(())
    }

    /// `resources/list` then `resources/read`.
    ///
    /// LLM calls: 4 server (startup, initialize, resources/list, resources/read), 3 client.
    #[tokio::test]
    async fn test_mcp_client_read_resource() -> E2EResult<()> {
        let server_config = NetGetConfig::new(
            "Listen on port {AVAILABLE_PORT} via MCP. \
             Provide a resource at URI 'file:///README.md'.",
        )
        .with_mock(|mock| {
            mock.on_instruction_containing("Listen on port")
                .and_instruction_containing("MCP")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "MCP",
                        "instruction": "MCP server offering one resource"
                    }
                ]))
                .expect_calls(1)
                .and()
                .on_event("mcp_initialize")
                .respond_with_actions(serde_json::json!([
                    {"type": "mcp_initialize_response", "response": initialize_result()}
                ]))
                .expect_calls(1)
                .and()
                .on_event("mcp_resources_list")
                .respond_with_actions(serde_json::json!([
                    {"type": "mcp_resources_list_response", "response": {"resources": [
                        {"uri": "file:///README.md", "name": "README",
                         "mimeType": "text/markdown"}
                    ]}}
                ]))
                .expect_calls(1)
                .and()
                .on_event("mcp_resources_read")
                .and_event_data_contains("uri", "file:///README.md")
                .respond_with_actions(serde_json::json!([
                    {"type": "mcp_resources_read_response", "response": {"contents": [
                        {"uri": "file:///README.md", "mimeType": "text/markdown",
                         "text": "Test resource content"}
                    ]}}
                ]))
                .expect_calls(1)
                .and()
        });

        let mut server = start_netget_server(server_config).await?;

        let client_config = NetGetConfig::new(format!(
            "Connect to http://127.0.0.1:{} via MCP. List resources, then read README.",
            server.port
        ))
        .with_mock(|mock| {
            mock.on_instruction_containing("Connect to")
                .and_instruction_containing("MCP")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_client",
                        "remote_addr": format!("127.0.0.1:{}", server.port),
                        "protocol": "MCP",
                        "instruction": "List resources, then read README"
                    }
                ]))
                .expect_calls(1)
                .and()
                .on_event("mcp_client_connected")
                .respond_with_actions(serde_json::json!([{"type": "list_resources"}]))
                .expect_calls(1)
                .and()
                .on_event("mcp_response_received")
                .respond_with_actions_from_event(|e| {
                    if e["method"].as_str() == Some("mcp_list_resources") {
                        serde_json::json!([
                            {"type": "read_resource", "uri": "file:///README.md"}
                        ])
                    } else {
                        serde_json::json!([{"type": "show_message", "message": "done"}])
                    }
                })
                .expect_calls(2)
                .and()
        });

        let mut client = start_netget_client(client_config).await?;

        assert_eq!(client.protocol, "MCP", "Client should be MCP protocol");

        server.wait_for_mocks(30).await;
        client.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        client.verify_mocks().await?;

        server.stop().await?;
        client.stop().await?;
        Ok(())
    }
}

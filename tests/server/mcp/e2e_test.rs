//! End-to-end MCP (Model Context Protocol) tests for NetGet
//!
//! These tests spawn the actual NetGet binary with MCP prompts
//! and validate the responses using HTTP JSON-RPC 2.0 clients.


use crate::server::helpers::{self, E2EResult, NetGetConfig};
use serde_json::{json, Value};
use std::time::Duration;

/// Helper function to send MCP JSON-RPC request
async fn send_mcp_request(
    port: u16,
    method: &str,
    params: Option<Value>,
    id: Option<i64>,
) -> E2EResult<Value> {
    let client = reqwest::Client::new();

    let mut request_body = json!({
        "jsonrpc": "2.0",
        "method": method,
    });

    if let Some(p) = params {
        request_body["params"] = p;
    }

    if let Some(i) = id {
        request_body["id"] = json!(i);
    }

    println!(
        "→ Sending MCP request: {}",
        serde_json::to_string_pretty(&request_body)?
    );

    let response = match tokio::time::timeout(
        Duration::from_secs(30),
        client
            .post(format!("http://127.0.0.1:{}", port))
            .header("Content-Type", "application/json")
            .json(&request_body)
            .send(),
    )
    .await
    {
        Ok(Ok(resp)) => {
            println!("✓ Received HTTP response: {}", resp.status());
            resp
        }
        Ok(Err(e)) => {
            println!("✗ HTTP request error: {}", e);
            return Err(e.into());
        }
        Err(_) => {
            println!("✗ HTTP request timeout");
            return Err("Request timeout".into());
        }
    };

    if !response.status().is_success() {
        println!("✗ HTTP error: {}", response.status());
        return Err(format!("HTTP error: {}", response.status()).into());
    }

    let json: Value = response.json().await?;
    println!("← Response: {}", serde_json::to_string_pretty(&json)?);

    Ok(json)
}

#[tokio::test]
async fn test_mcp_initialize() -> E2EResult<()> {
    println!("\n=== E2E Test: MCP Initialize ===");

    let prompt = "Listen on port {AVAILABLE_PORT} via MCP (Model Context Protocol). \
        You are an MCP server. When a client sends an initialize request, respond with: \
        - protocolVersion: 2024-11-05 \
        - capabilities: resources with subscribe support, tools, and prompts \
        - serverInfo: name=netget-mcp, version=0.1.0";

    let server_config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock
            // Mock 1: Server startup
            .on_instruction_containing("MCP")
            .and_instruction_containing("port")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "MCP",
                    "instruction": "MCP server with resources, tools, and prompts capabilities"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 2: Initialize request
            .on_event("mcp_initialize")
            // `mcp_initialize_response`, not `send_jsonrpc_response` — the latter belongs
            // to the *jsonrpc* protocol and `McpProtocol::execute_action` rejects it.
            // The handler supplies only the `result` body; the server echoes the JSON-RPC
            // `id` itself, so the mock must not carry one.
            .respond_with_actions(serde_json::json!([
                {
                    "type": "mcp_initialize_response",
                    "response": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {
                            "resources": {
                                "subscribe": true
                            },
                            "tools": {},
                            "prompts": {}
                        },
                        "serverInfo": {
                            "name": "netget-mcp",
                            "version": "0.1.0"
                        }
                    }
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let server = helpers::start_netget_server(server_config).await?;
    println!("Server started on port {}", server.port);

    // Wait for server to be ready
    crate::helpers::wait_for_server_listening(&server, Duration::from_secs(30)).await?;

    // Send initialize request
    println!("\n→ Sending MCP initialize request...");

    let response = send_mcp_request(
        server.port,
        "initialize",
        Some(json!({
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {
                "name": "test-client",
                "version": "1.0.0"
            }
        })),
        Some(1),
    )
    .await?;

    // Validate JSON-RPC 2.0 response
    assert_eq!(
        response.get("jsonrpc").and_then(|v| v.as_str()),
        Some("2.0"),
        "Expected 'jsonrpc' field to be '2.0'"
    );

    assert_eq!(
        response.get("id"),
        Some(&json!(1)),
        "Expected 'id' field to match request id"
    );

    // The whole handler-supplied `result` must reach the client verbatim. Asserting on
    // the decoded body (not merely on its presence) is what proves the action was
    // accepted and executed rather than falling back to a canned reply.
    let result = response
        .get("result")
        .unwrap_or_else(|| panic!("expected a result, got {:?}", response.get("error")));

    assert_eq!(
        result.get("protocolVersion").and_then(|v| v.as_str()),
        Some("2024-11-05"),
        "Expected protocolVersion to be '2024-11-05'"
    );
    assert_eq!(
        result.pointer("/serverInfo/name").and_then(|v| v.as_str()),
        Some("netget-mcp"),
        "serverInfo.name must come from the handler's response"
    );
    assert_eq!(
        result
            .pointer("/serverInfo/version")
            .and_then(|v| v.as_str()),
        Some("0.1.0"),
        "serverInfo.version must come from the handler's response"
    );
    assert_eq!(
        result
            .pointer("/capabilities/resources/subscribe")
            .and_then(|v| v.as_bool()),
        Some(true),
        "declared capabilities must survive the round trip"
    );

    println!("✓ MCP Initialize test completed\n");

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;

    Ok(())
}

#[tokio::test]
async fn test_mcp_ping() -> E2EResult<()> {
    println!("\n=== E2E Test: MCP Ping ===");

    let prompt = "Listen on port {AVAILABLE_PORT} via MCP. You are an MCP server.";

    let server_config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock
            // Mock: Server startup
            .on_instruction_containing("MCP")
            .and_instruction_containing("port")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "MCP",
                    "instruction": "MCP server that responds to ping"
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let server = helpers::start_netget_server(server_config).await?;
    println!("Server started on port {}", server.port);

    tokio::time::sleep(Duration::from_millis(500)).await;

    // Send ping request
    println!("\n→ Sending MCP ping request...");

    let response = send_mcp_request(server.port, "ping", None, Some(2)).await?;

    // Validate response
    assert_eq!(
        response.get("jsonrpc").and_then(|v| v.as_str()),
        Some("2.0")
    );
    assert_eq!(response.get("id"), Some(&json!(2)));

    if response.get("result").is_some() {
        println!("✓ Ping successful");
        println!("✓ MCP Ping test completed\n");

        // Verify mocks
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last event routinely lands after
        // the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;

        Ok(())
    } else {
        println!("✗ Ping failed: {:?}", response.get("error"));
        Err("Ping failed".into())
    }
}

#[tokio::test]
async fn test_mcp_resources_list() -> E2EResult<()> {
    println!("\n=== E2E Test: MCP Resources List ===");

    let prompt = "Listen on port {AVAILABLE_PORT} via MCP. \
        Use a Python script to handle requests deterministically. \
        When a client requests resources/list, return a list with these resources: \
        - uri: file:///example.txt, name: Example File, description: A sample text file \
        - uri: file:///data.json, name: Data File, description: JSON data file";

    let server_config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock
            // Mock 1: Server startup
            .on_instruction_containing("MCP")
            .and_instruction_containing("port")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "MCP",
                    "instruction": "MCP server with resources capability"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 2: Resources list request
            .on_event("mcp_resources_list")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "mcp_resources_list_response",
                    "response": {
                        "resources": [
                            {
                                "uri": "file:///example.txt",
                                "name": "Example File",
                                "description": "A sample text file"
                            },
                            {
                                "uri": "file:///data.json",
                                "name": "Data File",
                                "description": "JSON data file"
                            }
                        ]
                    }
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let server = helpers::start_netget_server(server_config).await?;
    println!("Server started on port {}", server.port);

    server.wait_for_mocks(30).await;

    // Send resources/list request
    println!("\n→ Sending MCP resources/list request...");

    let response = send_mcp_request(server.port, "resources/list", None, Some(3)).await?;

    // Validate response
    assert_eq!(
        response.get("jsonrpc").and_then(|v| v.as_str()),
        Some("2.0")
    );
    assert_eq!(response.get("id"), Some(&json!(3)));

    let result = response
        .get("result")
        .unwrap_or_else(|| panic!("expected a result, got {:?}", response.get("error")));

    let resources = result
        .get("resources")
        .and_then(|v| v.as_array())
        .expect("result must carry a `resources` array");
    assert_eq!(resources.len(), 2, "both mocked resources must be returned");
    assert_eq!(
        resources[0].get("uri").and_then(|v| v.as_str()),
        Some("file:///example.txt")
    );
    assert_eq!(
        resources[0].get("name").and_then(|v| v.as_str()),
        Some("Example File")
    );
    assert_eq!(
        resources[1].get("uri").and_then(|v| v.as_str()),
        Some("file:///data.json")
    );

    println!("✓ MCP Resources List test completed\n");

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;

    Ok(())
}

#[tokio::test]
async fn test_mcp_resources_read() -> E2EResult<()> {
    println!("\n=== E2E Test: MCP Resources Read ===");

    let prompt = "Listen on port {AVAILABLE_PORT} via MCP. \
        Use a Python script to handle requests deterministically. \
        When a client reads resource 'file:///example.txt', \
        return contents with uri and text: 'Hello from NetGet MCP server!'";

    let server_config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock
            // Mock 1: Server startup
            .on_instruction_containing("MCP")
            .and_instruction_containing("port")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "MCP",
                    "instruction": "MCP server with resource read capability"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 2: Resource read request
            .on_event("mcp_resources_read")
            .and_event_data_contains("uri", "file:///example.txt")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "mcp_resources_read_response",
                    "response": {
                        "contents": [
                            {
                                "uri": "file:///example.txt",
                                "text": "Hello from NetGet MCP server!"
                            }
                        ]
                    }
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let server = helpers::start_netget_server(server_config).await?;
    println!("Server started on port {}", server.port);

    server.wait_for_mocks(30).await;

    // Send resources/read request
    println!("\n→ Sending MCP resources/read request...");

    let response = send_mcp_request(
        server.port,
        "resources/read",
        Some(json!({
            "uri": "file:///example.txt"
        })),
        Some(4),
    )
    .await?;

    // Validate response
    assert_eq!(
        response.get("jsonrpc").and_then(|v| v.as_str()),
        Some("2.0")
    );
    assert_eq!(response.get("id"), Some(&json!(4)));

    // The old version accepted a JSON-RPC *error* here as "resource not found is
    // expected", which made the test unfailable: it stayed green for as long as the mock
    // returned an action MCP rejects. The mock supplies a specific body, so demand it.
    let result = response
        .get("result")
        .unwrap_or_else(|| panic!("expected a result, got {:?}", response.get("error")));

    let contents = result
        .get("contents")
        .and_then(|v| v.as_array())
        .expect("result must carry a `contents` array");
    assert_eq!(contents.len(), 1);
    assert_eq!(
        contents[0].get("uri").and_then(|v| v.as_str()),
        Some("file:///example.txt")
    );
    assert_eq!(
        contents[0].get("text").and_then(|v| v.as_str()),
        Some("Hello from NetGet MCP server!")
    );

    println!("✓ MCP Resources Read test completed\n");

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;

    Ok(())
}

#[tokio::test]
async fn test_mcp_tools_list() -> E2EResult<()> {
    println!("\n=== E2E Test: MCP Tools List ===");

    let prompt = "Listen on port {AVAILABLE_PORT} via MCP. \
        You are an MCP server. When a client requests tools/list, return a list with these tools: \
        - name: calculate, description: Perform calculations, inputSchema with 'expression' string parameter \
        - name: search, description: Search files, inputSchema with 'query' string parameter";

    let server_config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock
            // Mock 1: Server startup
            .on_instruction_containing("MCP")
            .and_instruction_containing("port")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "MCP",
                    "instruction": "MCP server with tools capability"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 2: Tools list request
            .on_event("mcp_tools_list")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "mcp_tools_list_response",
                    "response": {
                        "tools": [
                            {
                                "name": "calculate",
                                "description": "Perform calculations",
                                "inputSchema": {
                                    "type": "object",
                                    "properties": {
                                        "expression": {
                                            "type": "string"
                                        }
                                    }
                                }
                            },
                            {
                                "name": "search",
                                "description": "Search files",
                                "inputSchema": {
                                    "type": "object",
                                    "properties": {
                                        "query": {
                                            "type": "string"
                                        }
                                    }
                                }
                            }
                        ]
                    }
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let server = helpers::start_netget_server(server_config).await?;
    println!("Server started on port {}", server.port);

    server.wait_for_mocks(30).await;

    // Send tools/list request
    println!("\n→ Sending MCP tools/list request...");

    let response = send_mcp_request(server.port, "tools/list", None, Some(5)).await?;

    // Validate response
    assert_eq!(
        response.get("jsonrpc").and_then(|v| v.as_str()),
        Some("2.0")
    );
    assert_eq!(response.get("id"), Some(&json!(5)));

    let result = response
        .get("result")
        .unwrap_or_else(|| panic!("expected a result, got {:?}", response.get("error")));

    let tools = result
        .get("tools")
        .and_then(|v| v.as_array())
        .expect("result must carry a `tools` array");
    assert_eq!(tools.len(), 2, "both mocked tools must be returned");
    assert_eq!(
        tools[0].get("name").and_then(|v| v.as_str()),
        Some("calculate")
    );
    // The JSON Schema is the part a real MCP client needs in order to call the tool, so
    // assert it survives rather than only its name.
    assert_eq!(
        tools[0]
            .pointer("/inputSchema/properties/expression/type")
            .and_then(|v| v.as_str()),
        Some("string"),
        "inputSchema must round-trip intact"
    );
    assert_eq!(
        tools[1].get("name").and_then(|v| v.as_str()),
        Some("search")
    );

    println!("✓ MCP Tools List test completed\n");

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;

    Ok(())
}

#[tokio::test]
async fn test_mcp_tools_call() -> E2EResult<()> {
    println!("\n=== E2E Test: MCP Tools Call ===");

    let prompt = "Listen on port {AVAILABLE_PORT} via MCP. \
        Use a Python script to handle requests deterministically. \
        When a client calls tool 'calculate' with expression '2+2', \
        return content with type text and text '4'";

    let server_config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock
            // Mock 1: Server startup
            .on_instruction_containing("MCP")
            .and_instruction_containing("port")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "MCP",
                    "instruction": "MCP server with tools call capability"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 2: Tool call request
            .on_event("mcp_tools_call")
            .and_event_data_contains("name", "calculate")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "mcp_tools_call_response",
                    "response": {
                        "content": [
                            {
                                "type": "text",
                                "text": "4"
                            }
                        ]
                    }
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let server = helpers::start_netget_server(server_config).await?;
    println!("Server started on port {}", server.port);

    server.wait_for_mocks(30).await;

    // Send tools/call request
    println!("\n→ Sending MCP tools/call request...");

    let response = send_mcp_request(
        server.port,
        "tools/call",
        Some(json!({
            "name": "calculate",
            "arguments": {
                "expression": "2+2"
            }
        })),
        Some(6),
    )
    .await?;

    // Validate response
    assert_eq!(
        response.get("jsonrpc").and_then(|v| v.as_str()),
        Some("2.0")
    );
    assert_eq!(response.get("id"), Some(&json!(6)));

    // Previously an "execution error is expected" branch swallowed the failure case,
    // leaving nothing that could fail.
    let result = response
        .get("result")
        .unwrap_or_else(|| panic!("expected a result, got {:?}", response.get("error")));

    let content = result
        .get("content")
        .and_then(|v| v.as_array())
        .expect("result must carry a `content` array");
    assert_eq!(content.len(), 1);
    assert_eq!(
        content[0].get("type").and_then(|v| v.as_str()),
        Some("text")
    );
    assert_eq!(
        content[0].get("text").and_then(|v| v.as_str()),
        Some("4"),
        "the handler's calculate(2+2) result must reach the client"
    );

    println!("✓ MCP Tools Call test completed\n");

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;

    Ok(())
}

#[tokio::test]
async fn test_mcp_prompts_list() -> E2EResult<()> {
    println!("\n=== E2E Test: MCP Prompts List ===");

    let prompt = "Listen on port {AVAILABLE_PORT} via MCP. \
        You are an MCP server. When a client requests prompts/list, return a list with these prompts: \
        - name: code-review, description: Review code for quality and bugs \
        - name: summarize, description: Summarize text content";

    let server_config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock
            // Mock 1: Server startup
            .on_instruction_containing("MCP")
            .and_instruction_containing("port")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "MCP",
                    "instruction": "MCP server with prompts capability"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 2: Prompts list request
            .on_event("mcp_prompts_list")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "mcp_prompts_list_response",
                    "response": {
                        "prompts": [
                            {
                                "name": "code-review",
                                "description": "Review code for quality and bugs"
                            },
                            {
                                "name": "summarize",
                                "description": "Summarize text content"
                            }
                        ]
                    }
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let server = helpers::start_netget_server(server_config).await?;
    println!("Server started on port {}", server.port);

    server.wait_for_mocks(30).await;

    // Send prompts/list request
    println!("\n→ Sending MCP prompts/list request...");

    let response = send_mcp_request(server.port, "prompts/list", None, Some(7)).await?;

    // Validate response
    assert_eq!(
        response.get("jsonrpc").and_then(|v| v.as_str()),
        Some("2.0")
    );
    assert_eq!(response.get("id"), Some(&json!(7)));

    let result = response
        .get("result")
        .unwrap_or_else(|| panic!("expected a result, got {:?}", response.get("error")));

    let prompts = result
        .get("prompts")
        .and_then(|v| v.as_array())
        .expect("result must carry a `prompts` array");
    assert_eq!(prompts.len(), 2, "both mocked prompts must be returned");
    assert_eq!(
        prompts[0].get("name").and_then(|v| v.as_str()),
        Some("code-review")
    );
    assert_eq!(
        prompts[0].get("description").and_then(|v| v.as_str()),
        Some("Review code for quality and bugs")
    );
    assert_eq!(
        prompts[1].get("name").and_then(|v| v.as_str()),
        Some("summarize")
    );

    println!("✓ MCP Prompts List test completed\n");

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;

    Ok(())
}

#[tokio::test]
async fn test_mcp_prompts_get() -> E2EResult<()> {
    println!("\n=== E2E Test: MCP Prompts Get ===");

    let prompt = "Listen on port {AVAILABLE_PORT} via MCP. \
        Use a Python script to handle requests deterministically. \
        When a client gets prompt 'code-review', \
        return messages with role 'user' and content with type 'text' and text 'Review this code'";

    let server_config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock
            // Mock 1: Server startup
            .on_instruction_containing("MCP")
            .and_instruction_containing("port")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "MCP",
                    "instruction": "MCP server with prompt get capability"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 2: Prompt get request
            .on_event("mcp_prompts_get")
            .and_event_data_contains("name", "code-review")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "mcp_prompts_get_response",
                    "response": {
                        "messages": [
                            {
                                "role": "user",
                                "content": {
                                    "type": "text",
                                    "text": "Review this code"
                                }
                            }
                        ]
                    }
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let server = helpers::start_netget_server(server_config).await?;
    println!("Server started on port {}", server.port);

    server.wait_for_mocks(30).await;

    // Send prompts/get request
    println!("\n→ Sending MCP prompts/get request...");

    let response = send_mcp_request(
        server.port,
        "prompts/get",
        Some(json!({
            "name": "code-review"
        })),
        Some(8),
    )
    .await?;

    // Validate response
    assert_eq!(
        response.get("jsonrpc").and_then(|v| v.as_str()),
        Some("2.0")
    );
    assert_eq!(response.get("id"), Some(&json!(8)));

    // Previously a "prompt not found is expected" branch made this test unfailable.
    let result = response
        .get("result")
        .unwrap_or_else(|| panic!("expected a result, got {:?}", response.get("error")));

    let messages = result
        .get("messages")
        .and_then(|v| v.as_array())
        .expect("result must carry a `messages` array");
    assert_eq!(messages.len(), 1);
    assert_eq!(
        messages[0].get("role").and_then(|v| v.as_str()),
        Some("user")
    );
    assert_eq!(
        messages[0]
            .pointer("/content/text")
            .and_then(|v| v.as_str()),
        Some("Review this code"),
        "the prompt body must reach the client"
    );

    println!("✓ MCP Prompts Get test completed\n");

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;

    Ok(())
}

#[tokio::test]
async fn test_mcp_error_handling() -> E2EResult<()> {
    println!("\n=== E2E Test: MCP Error Handling ===");

    let prompt = "Listen on port {AVAILABLE_PORT} via MCP. You are an MCP server.";

    let server_config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock
            // Mock: Server startup
            .on_instruction_containing("MCP")
            .and_instruction_containing("port")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "MCP",
                    "instruction": "MCP server for error handling test"
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let server = helpers::start_netget_server(server_config).await?;
    println!("Server started on port {}", server.port);

    tokio::time::sleep(Duration::from_millis(500)).await;

    // Send invalid method request
    println!("\n→ Sending invalid method request...");

    let response = send_mcp_request(server.port, "invalid/method", None, Some(99)).await?;

    // Should receive an error response
    assert_eq!(
        response.get("jsonrpc").and_then(|v| v.as_str()),
        Some("2.0")
    );
    assert_eq!(response.get("id"), Some(&json!(99)));

    if let Some(error) = response.get("error") {
        println!("✓ Received error response: {:?}", error);

        // Check error structure
        assert!(
            error.get("code").is_some(),
            "Error should have 'code' field"
        );
        assert!(
            error.get("message").is_some(),
            "Error should have 'message' field"
        );

        println!("✓ MCP Error Handling test completed\n");

        // Verify mocks
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last event routinely lands after
        // the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;

        Ok(())
    } else {
        println!("✗ Expected error response, got result");
        Err("Expected error response".into())
    }
}

//! End-to-end JSON-RPC tests for NetGet
//!
//! These tests spawn the actual NetGet binary with JSON-RPC prompts
//! and validate the responses using HTTP clients.

use crate::server::helpers::{self, E2EResult, NetGetConfig};
use serde_json::{json, Value};
use std::time::Duration;

#[tokio::test]
async fn test_jsonrpc_basic_method_call() -> E2EResult<()> {
    println!("\n=== E2E Test: JSON-RPC Basic Method Call ===");

    // Start JSON-RPC server with mocks
    let prompt = "Open JSON-RPC on port {AVAILABLE_PORT}. This is a JSON-RPC 2.0 server. \
        When clients call method 'add' with params [a, b], return their sum. \
        When clients call 'greet' with param name, return 'Hello, <name>!'.";

    let server = helpers::start_netget_server(NetGetConfig::new(prompt).with_mock(|mock| {
        mock
            // Mock 1: Server startup (user command)
            .on_instruction_containing("Open JSON-RPC")
            .and_instruction_containing("port")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "jsonrpc",
                    "instruction": "JSON-RPC 2.0 server with add and greet methods"
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
    }))
    .await?;
    println!("Server started on port {}", server.port);

    // Wait for server to be ready
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Send JSON-RPC request for 'add' method
    println!("Sending JSON-RPC 'add' method call...");

    let client = reqwest::Client::new();
    let request_body = json!({
        "jsonrpc": "2.0",
        "method": "add",
        "params": [5, 3],
        "id": 1
    });

    println!("Request: {}", serde_json::to_string_pretty(&request_body)?);

    let response = match tokio::time::timeout(
        Duration::from_secs(20),
        client
            .post(format!("http://127.0.0.1:{}", server.port))
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

    assert_eq!(response.status(), 200, "Expected HTTP 200 OK");

    // Parse JSON-RPC response
    let json: Value = response.json().await?;
    println!("Response: {}", serde_json::to_string_pretty(&json)?);

    // Validate JSON-RPC 2.0 response format
    assert_eq!(
        json.get("jsonrpc").and_then(|v| v.as_str()),
        Some("2.0"),
        "Expected 'jsonrpc' field to be '2.0'"
    );

    assert_eq!(
        json.get("id"),
        Some(&json!(1)),
        "Expected 'id' field to match request id"
    );

    // Should have either 'result' or 'error', not both
    let has_result = json.get("result").is_some();
    let has_error = json.get("error").is_some();
    assert!(
        has_result || has_error,
        "Response must have 'result' or 'error'"
    );
    assert!(
        !(has_result && has_error),
        "Response cannot have both 'result' and 'error'"
    );

    if has_result {
        println!(
            "✓ Received success response with result: {:?}",
            json["result"]
        );
    } else {
        println!("✗ Received error response: {:?}", json["error"]);
    }

    println!("✓ JSON-RPC Basic Method Call test completed\n");

    // Verify mock expectations were met
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;

    Ok(())
}

#[tokio::test]
async fn test_jsonrpc_notification() -> E2EResult<()> {
    println!("\n=== E2E Test: JSON-RPC Notification (no response expected) ===");

    let prompt = "Open JSON-RPC on port {AVAILABLE_PORT}. This is a JSON-RPC 2.0 server. \
        Handle notifications (requests without 'id') by logging them but not sending responses.";

    let server = helpers::start_netget_server(NetGetConfig::new(prompt).with_mock(|mock| {
        mock
            // Mock 1: Server startup (user command)
            .on_instruction_containing("Open JSON-RPC")
            .and_instruction_containing("port")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "jsonrpc",
                    "instruction": "JSON-RPC 2.0 server handling notifications"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 2: JSON-RPC notification received (jsonrpc_method_call event with id=null)
            .on_event("jsonrpc_method_call")
            .and_event_data_contains("method", "log_event")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "show_message",
                    "message": "Logged notification"
                }
            ]))
            .expect_calls(1)
            .and()
    }))
    .await?;
    println!("Server started on port {}", server.port);

    tokio::time::sleep(Duration::from_millis(500)).await;

    // Send JSON-RPC notification (no 'id' field)
    println!("Sending JSON-RPC notification (no id)...");

    let client = reqwest::Client::new();
    let request_body = json!({
        "jsonrpc": "2.0",
        "method": "log_event",
        "params": {"event": "test", "timestamp": 1234567890}
    });

    println!("Request: {}", serde_json::to_string_pretty(&request_body)?);

    let response = match tokio::time::timeout(
        Duration::from_secs(10),
        client
            .post(format!("http://127.0.0.1:{}", server.port))
            .header("Content-Type", "application/json")
            .json(&request_body)
            .send(),
    )
    .await
    {
        Ok(Ok(resp)) => resp,
        Ok(Err(e)) => return Err(e.into()),
        Err(_) => return Err("Request timeout".into()),
    };

    // Notifications should return 204 No Content or 200 with empty body
    let status = response.status();
    println!("✓ Received HTTP response: {}", status);
    assert!(
        status == 200 || status == 204,
        "Expected 200 or 204 for notification"
    );

    println!("✓ JSON-RPC Notification test completed\n");

    // Verify mock expectations were met
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;

    Ok(())
}

#[tokio::test]
async fn test_jsonrpc_batch_request() -> E2EResult<()> {
    println!("\n=== E2E Test: JSON-RPC Batch Request ===");

    let prompt = "Open JSON-RPC on port {AVAILABLE_PORT}. This is a JSON-RPC 2.0 server. \
        Handle batch requests by processing each method call and returning results in an array. \
        For method 'echo', return the first parameter as the result.";

    let server = helpers::start_netget_server(NetGetConfig::new(prompt).with_mock(|mock| {
        mock
            // Mock 1: Server startup (user command)
            .on_instruction_containing("Open JSON-RPC")
            .and_instruction_containing("port")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "jsonrpc",
                    "instruction": "JSON-RPC 2.0 server with batch support and echo method"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 2-4: Three batch requests (jsonrpc_method_call event x3)
            // Note: ID matching - the id field is a JSON number, so we just match on method
            .on_event("jsonrpc_method_call")
            .and_event_data_contains("method", "echo")
            .respond_with_actions_from_event(|event_data| {
                let id = event_data["id"].as_u64().unwrap_or(0);
                let params = &event_data["params"];
                let result = if let Some(arr) = params.as_array() {
                    arr.first().cloned().unwrap_or(json!(""))
                } else {
                    json!("")
                };

                serde_json::json!([{
                    "type": "jsonrpc_success",
                    "result": result,
                    "id": id
                }])
            })
            .expect_calls(3)
            .and()
    }))
    .await?;
    println!("Server started on port {}", server.port);

    tokio::time::sleep(Duration::from_millis(500)).await;

    // Send JSON-RPC batch request
    println!("Sending JSON-RPC batch request...");

    let client = reqwest::Client::new();
    let request_body = json!([
        {"jsonrpc": "2.0", "method": "echo", "params": ["first"], "id": 1},
        {"jsonrpc": "2.0", "method": "echo", "params": ["second"], "id": 2},
        {"jsonrpc": "2.0", "method": "echo", "params": ["third"], "id": 3}
    ]);

    println!("Request: {}", serde_json::to_string_pretty(&request_body)?);

    let response = match tokio::time::timeout(
        Duration::from_secs(30), // Longer timeout for batch processing
        client
            .post(format!("http://127.0.0.1:{}", server.port))
            .header("Content-Type", "application/json")
            .json(&request_body)
            .send(),
    )
    .await
    {
        Ok(Ok(resp)) => resp,
        Ok(Err(e)) => return Err(e.into()),
        Err(_) => return Err("Request timeout".into()),
    };

    assert_eq!(response.status(), 200, "Expected HTTP 200 OK");

    // Parse JSON-RPC batch response
    let json: Value = response.json().await?;
    println!("Response: {}", serde_json::to_string_pretty(&json)?);

    // Validate batch response format (should be an array)
    let responses = json.as_array().expect("Batch response should be an array");
    println!("✓ Received batch response with {} items", responses.len());

    // Each response should be a valid JSON-RPC 2.0 response
    for (i, resp) in responses.iter().enumerate() {
        assert_eq!(
            resp.get("jsonrpc").and_then(|v| v.as_str()),
            Some("2.0"),
            "Response {} should have jsonrpc=2.0",
            i
        );
        assert!(resp.get("id").is_some(), "Response {} should have id", i);
        println!("✓ Response {} is valid", i + 1);
    }

    println!("✓ JSON-RPC Batch Request test completed\n");

    // Verify mock expectations were met
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;

    Ok(())
}

#[tokio::test]
async fn test_jsonrpc_method_not_found() -> E2EResult<()> {
    println!("\n=== E2E Test: JSON-RPC Method Not Found Error ===");

    let prompt = "Open JSON-RPC on port {AVAILABLE_PORT}. This is a JSON-RPC 2.0 server. \
        When clients call unknown methods, return error code -32601 (Method not found).";

    let server = helpers::start_netget_server(NetGetConfig::new(prompt).with_mock(|mock| {
        mock
            // Mock 1: Server startup (user command)
            .on_instruction_containing("Open JSON-RPC")
            .and_instruction_containing("port")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "jsonrpc",
                    "instruction": "JSON-RPC 2.0 server that returns error for unknown methods"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 2: JSON-RPC request with unknown method (jsonrpc_method_call event)
            .on_event("jsonrpc_method_call")
            .and_event_data_contains("method", "this_method_does_not_exist")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "jsonrpc_error",
                    "code": -32601,
                    "message": "Method not found",
                    "id": 99
                }
            ]))
            .expect_calls(1)
            .and()
    }))
    .await?;
    println!("Server started on port {}", server.port);

    tokio::time::sleep(Duration::from_millis(500)).await;

    // Send JSON-RPC request with unknown method
    println!("Sending JSON-RPC request with unknown method...");

    let client = reqwest::Client::new();
    let request_body = json!({
        "jsonrpc": "2.0",
        "method": "this_method_does_not_exist",
        "params": [],
        "id": 99
    });

    let response = match tokio::time::timeout(
        Duration::from_secs(15),
        client
            .post(format!("http://127.0.0.1:{}", server.port))
            .header("Content-Type", "application/json")
            .json(&request_body)
            .send(),
    )
    .await
    {
        Ok(Ok(resp)) => resp,
        Ok(Err(e)) => return Err(e.into()),
        Err(_) => return Err("Request timeout".into()),
    };

    assert_eq!(
        response.status(),
        200,
        "Expected HTTP 200 OK (JSON-RPC errors use 200)"
    );

    // Parse JSON-RPC error response
    let json: Value = response.json().await?;
    println!("Response: {}", serde_json::to_string_pretty(&json)?);

    // Validate error response format
    assert_eq!(json.get("jsonrpc").and_then(|v| v.as_str()), Some("2.0"));
    assert_eq!(json.get("id"), Some(&json!(99)));

    let error = json.get("error").expect("Should have 'error' field");
    let code = error
        .get("code")
        .and_then(|v| v.as_i64())
        .expect("Error should have 'code'");
    let message = error
        .get("message")
        .and_then(|v| v.as_str())
        .expect("Error should have 'message'");

    println!("✓ Error code: {}, message: {}", code, message);

    // Code -32601 is "Method not found" in JSON-RPC 2.0 spec
    // The LLM might return this or another appropriate error code
    assert!(code < 0, "Error code should be negative");

    println!("✓ JSON-RPC Method Not Found test completed\n");

    // Verify mock expectations were met
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;

    Ok(())
}

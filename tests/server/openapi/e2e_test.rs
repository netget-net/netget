//! End-to-end OpenAPI tests for NetGet
//!
//! These tests use mock LLM responses to validate OpenAPI server functionality.


use crate::helpers::*;
use serde_json::Value;
use std::time::Duration;

#[tokio::test]
async fn test_openapi_todo_list() -> E2EResult<()> {
    println!("\n=== E2E Test: OpenAPI TODO List ===");

    // Get path to test spec file
    let spec_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/server/openapi/test_spec.yaml");
    let spec_content = std::fs::read_to_string(&spec_path).unwrap();

    let server_config =
        NetGetConfig::new("Start OpenAPI server with todo list spec on port {AVAILABLE_PORT}")
            .with_mock(|mock| {
                mock
                    // Mock 1: Server startup (user command)
                    .on_instruction_containing("Start OpenAPI server")
                    .and_instruction_containing("todo list spec")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "open_server",
                            "port": 0,
                            "base_stack": "openapi",
                            "instruction": "OpenAPI server for TODO API",
                            "startup_params": {
                                "spec": spec_content
                            }
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // Mock 2: OpenAPI GET /todos request
                    .on_event("openapi_request")
                    .and_event_data_contains("path", "/todos")
                    .and_event_data_contains("method", "GET")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "send_openapi_response",
                            "status_code": 200,
                            "headers": {"Content-Type": "application/json"},
                            "body": serde_json::json!([
                                {"id": 1, "title": "Buy milk", "done": false},
                                {"id": 2, "title": "Write tests", "done": true}
                            ]).to_string()
                        }
                    ]))
                    .expect_calls(1)
                    .and()
            });

    let mut server = start_netget_server(server_config).await?;
    println!("Server started on port {}", server.port);

    // Wait for server to be ready
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Send GET /todos request
    println!("Sending GET /todos request...");

    let client = reqwest::Client::new();
    let response = match tokio::time::timeout(
        Duration::from_secs(20),
        client
            .get(format!("http://127.0.0.1:{}/todos", server.port))
            .header("Accept", "application/json")
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

    // The server might return placeholder response or actual todo list
    let status = response.status();
    println!("Response status: {}", status);

    // Parse JSON response
    let json: Value = response.json().await?;
    println!("Response JSON: {}", serde_json::to_string_pretty(&json)?);

    // Validate response
    assert_eq!(status, 200, "Expected HTTP 200, got {}", status);

    // Validate JSON structure
    let todos = json.as_array().expect("Response should be an array");
    println!("✓ Received todo list with {} items", todos.len());

    assert!(!todos.is_empty(), "Todo list should not be empty");

    // Validate structure of first todo
    let first_todo = &todos[0];
    assert!(
        first_todo.get("id").is_some(),
        "Todo should have 'id' field"
    );
    assert!(
        first_todo.get("title").is_some(),
        "Todo should have 'title' field"
    );
    assert!(
        first_todo.get("done").is_some(),
        "Todo should have 'done' field"
    );
    println!("✓ First todo: {}", serde_json::to_string(&first_todo)?);

    println!("✓ OpenAPI TODO List test completed\n");

    // Verify mock expectations
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;

    // Cleanup
    server.stop().await?;

    Ok(())
}

#[tokio::test]
async fn test_openapi_create_todo() -> E2EResult<()> {
    println!("\n=== E2E Test: OpenAPI Create TODO ===");

    // Get path to test spec file
    let spec_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/server/openapi/test_spec.yaml");
    let spec_content = std::fs::read_to_string(&spec_path).unwrap();

    let server_config =
        NetGetConfig::new("Start OpenAPI server with todo list spec on port {AVAILABLE_PORT}")
            .with_mock(|mock| {
                mock
                    // Mock 1: Server startup
                    .on_instruction_containing("Start OpenAPI server")
                    .and_instruction_containing("todo list spec")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "open_server",
                            "port": 0,
                            "base_stack": "openapi",
                            "instruction": "OpenAPI server for TODO API",
                            "startup_params": {
                                "spec": spec_content
                            }
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // Mock 2: OpenAPI POST /todos request
                    .on_event("openapi_request")
                    .and_event_data_contains("path", "/todos")
                    .and_event_data_contains("method", "POST")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "send_openapi_response",
                            "status_code": 201,
                            "headers": {"Content-Type": "application/json"},
                            "body": serde_json::json!({
                                "id": 3,
                                "title": "Buy milk",
                                "done": false
                            }).to_string()
                        }
                    ]))
                    .expect_calls(1)
                    .and()
            });

    let mut server = start_netget_server(server_config).await?;
    println!("Server started on port {}", server.port);

    tokio::time::sleep(Duration::from_millis(500)).await;

    // Send POST /todos request
    println!("Sending POST /todos request...");

    let client = reqwest::Client::new();
    let request_body = serde_json::json!({
        "title": "Buy milk",
        "done": false
    });

    println!(
        "Request body: {}",
        serde_json::to_string_pretty(&request_body)?
    );

    let response = match tokio::time::timeout(
        Duration::from_secs(20),
        client
            .post(format!("http://127.0.0.1:{}/todos", server.port))
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

    let status = response.status();
    println!("Response status: {}", status);

    // Parse JSON response
    let json: Value = response.json().await?;
    println!("Response JSON: {}", serde_json::to_string_pretty(&json)?);

    // Validate response
    assert_eq!(status, 201, "Expected HTTP 201, got {}", status);

    // Validate todo response structure
    assert!(
        json.get("id").is_some(),
        "Created todo should have 'id' field"
    );
    assert!(
        json.get("title").is_some(),
        "Created todo should have 'title' field"
    );
    assert!(
        json.get("done").is_some(),
        "Created todo should have 'done' field"
    );
    println!("✓ Created todo: {}", serde_json::to_string(&json)?);

    println!("✓ OpenAPI Create TODO test completed\n");

    // Verify mock expectations
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;

    // Cleanup
    server.stop().await?;

    Ok(())
}

#[tokio::test]
async fn test_openapi_method_validation() -> E2EResult<()> {
    println!("\n=== E2E Test: OpenAPI Method Validation ===");

    // Get path to test spec file
    let spec_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/server/openapi/test_spec.yaml");
    let spec_content = std::fs::read_to_string(&spec_path).unwrap();

    // For this test, OpenAPI server automatically returns 405 without LLM consultation
    let server_config = NetGetConfig::new("Start OpenAPI server on port {AVAILABLE_PORT}")
        .with_mock(|mock| {
            mock.on_instruction_containing("OpenAPI")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "openapi",
                        "instruction": "OpenAPI server for TODO API",
                        "startup_params": {
                            "spec": spec_content
                        }
                    }
                ]))
                .expect_calls(1)
                .and()
        });

    let mut server = start_netget_server(server_config).await?;
    println!("Server started on port {}", server.port);

    tokio::time::sleep(Duration::from_millis(500)).await;

    // Send GET request to POST-only endpoint (/admin/reset only supports POST)
    println!("Sending GET /admin/reset (should fail with 405)...");

    let client = reqwest::Client::new();
    let response = match tokio::time::timeout(
        Duration::from_secs(20),
        client
            .get(format!("http://127.0.0.1:{}/admin/reset", server.port))
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

    let status = response.status();
    println!("Response status: {}", status);

    // With route matching, should get immediate 405 without LLM consultation
    assert_eq!(
        status, 405,
        "Expected 405 Method Not Allowed for wrong method, got {}",
        status
    );
    println!("✓ Correctly returned 405 Method Not Allowed");

    // Check for Allow header
    let allow_header = response.headers().get("allow");
    assert!(
        allow_header.is_some(),
        "405 response should include Allow header"
    );
    let allowed_methods = allow_header.unwrap().to_str()?;
    println!("✓ Allow header: {}", allowed_methods);
    assert!(
        allowed_methods.contains("POST"),
        "Allow header should list POST"
    );

    // Parse error response
    let json: Value = response.json().await?;
    println!("Error response: {}", serde_json::to_string_pretty(&json)?);
    assert!(
        json.get("error").is_some(),
        "405 response should contain error field"
    );

    println!("✓ OpenAPI Method Validation test completed\n");

    // Verify mock expectations
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;

    // Cleanup
    server.stop().await?;

    Ok(())
}

#[tokio::test]
async fn test_openapi_spec_compliant_flag() -> E2EResult<()> {
    println!("\n=== E2E Test: OpenAPI Spec Compliance Flag ===");

    // Get path to test spec file
    let spec_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/server/openapi/test_spec.yaml");
    let spec_content = std::fs::read_to_string(&spec_path).unwrap();

    let server_config = NetGetConfig::new("Start OpenAPI server on port {AVAILABLE_PORT}")
        .with_mock(|mock| {
            mock.on_instruction_containing("Start OpenAPI server")
                .and_instruction_containing("on port")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "openapi",
                        "instruction": "OpenAPI server for TODO API",
                        "startup_params": {
                            "spec": spec_content
                        }
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock OpenAPI request - return intentional spec violation (201 instead of 200)
                .on_event("openapi_request")
                .and_event_data_contains("path", "/todos")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "send_openapi_response",
                        "status_code": 201,  // Intentional violation - spec says 200
                        "headers": {"Content-Type": "application/json"},
                        "body": "[]"
                    }
                ]))
                .expect_calls(1)
                .and()
        });

    let mut server = start_netget_server(server_config).await?;
    println!("Server started on port {}", server.port);

    tokio::time::sleep(Duration::from_millis(500)).await;

    // Send GET /todos request
    println!("Sending GET /todos (expecting intentional spec violation)...");

    let client = reqwest::Client::new();
    let response = match tokio::time::timeout(
        Duration::from_secs(20),
        client
            .get(format!("http://127.0.0.1:{}/todos", server.port))
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

    let status = response.status();
    println!("Response status: {}", status);

    // Verify we got the intentional violation (201 instead of 200)
    assert_eq!(
        status, 201,
        "Expected HTTP 201 (spec violation), got {}",
        status
    );

    println!("✓ Received response (spec_compliant flag test completed)");
    println!("✓ OpenAPI Spec Compliance Flag test completed\n");

    // Verify mock expectations
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;

    // Cleanup
    server.stop().await?;

    Ok(())
}

#[tokio::test]
async fn test_openapi_404_not_found() -> E2EResult<()> {
    println!("\n=== E2E Test: OpenAPI 404 Not Found ===");

    // Get path to test spec file
    let spec_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/server/openapi/test_spec.yaml");
    let spec_content = std::fs::read_to_string(&spec_path).unwrap();

    // OpenAPI server automatically returns 404 for undefined paths without LLM consultation
    let server_config = NetGetConfig::new("Start OpenAPI server on port {AVAILABLE_PORT}")
        .with_mock(|mock| {
            mock.on_instruction_containing("OpenAPI")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "openapi",
                        "instruction": "OpenAPI server for TODO API",
                        "startup_params": {
                            "spec": spec_content
                        }
                    }
                ]))
                .expect_calls(1)
                .and()
        });

    let mut server = start_netget_server(server_config).await?;
    println!("Server started on port {}", server.port);

    tokio::time::sleep(Duration::from_millis(500)).await;

    // Send request to undefined endpoint
    println!("Sending GET /unknown (should return 404)...");

    let client = reqwest::Client::new();
    let response = match tokio::time::timeout(
        Duration::from_secs(20),
        client
            .get(format!("http://127.0.0.1:{}/unknown", server.port))
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

    let status = response.status();
    println!("Response status: {}", status);

    // With route matching, should get immediate 404 without LLM consultation
    assert_eq!(
        status, 404,
        "Expected 404 Not Found for undefined path, got {}",
        status
    );
    println!("✓ Correctly returned 404 Not Found");

    // Parse error response
    let json: Value = response.json().await?;
    println!("Error response: {}", serde_json::to_string_pretty(&json)?);
    assert!(
        json.get("error").is_some(),
        "404 response should contain error field"
    );

    println!("✓ OpenAPI 404 Not Found test completed\n");

    // Verify mock expectations
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;

    // Cleanup
    server.stop().await?;

    Ok(())
}

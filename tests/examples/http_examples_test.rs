//! E2E tests for HTTP protocol examples
//!
//! These tests verify that HTTP protocol examples work correctly:
//! - StartupExamples (llm_mode, script_mode, static_mode) start servers
//! - EventType response_examples execute correctly
//! - HTTP request/response cycle works properly

use crate::helpers::{start_netget_server, E2EResult, NetGetConfig};
use serde_json::json;
use std::time::Duration;

/// Test HTTP protocol response_example for http_request event
///
/// This test verifies that the http_request response_example works correctly.
///
/// Response example from protocol:
/// {"type": "send_http_response", "status": 200, "headers": {"Content-Type": "text/html"}, "body": "<html><body>Hello World</body></html>"}
#[tokio::test]
async fn example_test_http_request() -> E2EResult<()> {
    println!("\n=== E2E Example Test: HTTP http_request ===");

    let config = NetGetConfig::new("Start an HTTP server on port 0")
        .with_log_level("debug")
        .with_mock(|mock| {
            mock
                // Mock 1: Server startup
                .on_instruction_containing("Start an HTTP server")
                .respond_with_actions(json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "HTTP",
                    "instruction": "Respond to all requests with Hello World"
                }]))
                .and()
                // Mock 2: HTTP request event
                // Use the actual response_example from the protocol
                .on_event("http_request")
                .respond_with_actions(json!({
                    "type": "send_http_response",
                    "status": 200,
                    "headers": {
                        "Content-Type": "text/html"
                    },
                    "body": "<html><body>Hello World</body></html>"
                }))
                .and()
        });

    let server = start_netget_server(config).await?;
    let port = server.port;
    println!("HTTP server started on port {}", port);

    // Wait for server to be ready
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Make HTTP request using reqwest
    let client = reqwest::Client::new();
    let response = client
        .get(format!("http://127.0.0.1:{}/", port))
        .timeout(Duration::from_secs(10))
        .send()
        .await?;

    println!("HTTP response status: {}", response.status());
    assert_eq!(response.status().as_u16(), 200, "Expected 200 OK");

    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    println!("Content-Type: {}", content_type);
    assert!(
        content_type.contains("text/html"),
        "Expected text/html content type"
    );

    let body = response.text().await?;
    println!("Body: {}", body);
    assert!(
        body.contains("Hello World"),
        "Expected 'Hello World' in body"
    );

    println!("✓ http_request response_example executed correctly");

    // Verify mock expectations
    server.verify_mocks().await?;

    server.stop().await?;
    println!("=== Test completed ===\n");
    Ok(())
}

/// Test HTTP GET request with path parameters
///
/// Verifies that HTTP server handles different paths correctly.
#[tokio::test]
async fn example_test_http_get_with_path() -> E2EResult<()> {
    println!("\n=== E2E Example Test: HTTP GET with Path ===");

    let config = NetGetConfig::new("Start an HTTP server on port 0")
        .with_log_level("debug")
        .with_mock(|mock| {
            mock
                // Server startup
                .on_instruction_containing("Start an HTTP server")
                .respond_with_actions(json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "HTTP",
                    "instruction": "Respond based on path"
                }]))
                .and()
                // API endpoint
                .on_event("http_request")
                .and_event_data_contains("path", "/api/users")
                .respond_with_actions(json!({
                    "type": "send_http_response",
                    "status": 200,
                    "headers": {
                        "Content-Type": "application/json"
                    },
                    "body": "{\"users\": [\"alice\", \"bob\"]}"
                }))
                .and()
                // Default handler
                .on_event("http_request")
                .respond_with_actions(json!({
                    "type": "send_http_response",
                    "status": 200,
                    "headers": {
                        "Content-Type": "text/html"
                    },
                    "body": "<html><body>Home Page</body></html>"
                }))
                .and()
        });

    let server = start_netget_server(config).await?;
    let port = server.port;
    println!("HTTP server started on port {}", port);

    tokio::time::sleep(Duration::from_millis(500)).await;

    let client = reqwest::Client::new();

    // Test root path
    let response = client
        .get(format!("http://127.0.0.1:{}/", port))
        .timeout(Duration::from_secs(10))
        .send()
        .await?;
    assert_eq!(response.status().as_u16(), 200);
    let body = response.text().await?;
    assert!(body.contains("Home Page"), "Expected home page response");
    println!("✓ Root path returned home page");

    // Test API path
    let response = client
        .get(format!("http://127.0.0.1:{}/api/users", port))
        .timeout(Duration::from_secs(10))
        .send()
        .await?;
    assert_eq!(response.status().as_u16(), 200);
    let body = response.text().await?;
    assert!(body.contains("alice"), "Expected user data");
    println!("✓ API path returned user data");

    server.verify_mocks().await?;
    server.stop().await?;

    println!("=== Test completed ===\n");
    Ok(())
}

/// Test HTTP POST request
///
/// Verifies that HTTP server handles POST requests correctly.
#[tokio::test]
async fn example_test_http_post_request() -> E2EResult<()> {
    println!("\n=== E2E Example Test: HTTP POST Request ===");

    let config = NetGetConfig::new("Start an HTTP server on port 0")
        .with_log_level("debug")
        .with_mock(|mock| {
            mock
                // Server startup
                .on_instruction_containing("Start an HTTP server")
                .respond_with_actions(json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "HTTP",
                    "instruction": "Accept POST requests"
                }]))
                .and()
                // POST handler
                .on_event("http_request")
                .and_event_data_contains("method", "POST")
                .respond_with_actions(json!({
                    "type": "send_http_response",
                    "status": 201,
                    "headers": {
                        "Content-Type": "application/json",
                        "Location": "/api/resources/123"
                    },
                    "body": "{\"id\": 123, \"status\": \"created\"}"
                }))
                .and()
                // GET handler (fallback)
                .on_event("http_request")
                .respond_with_actions(json!({
                    "type": "send_http_response",
                    "status": 200,
                    "headers": {"Content-Type": "text/plain"},
                    "body": "OK"
                }))
                .and()
        });

    let server = start_netget_server(config).await?;
    let port = server.port;
    println!("HTTP server started on port {}", port);

    tokio::time::sleep(Duration::from_millis(500)).await;

    let client = reqwest::Client::new();

    // Send POST request
    let response = client
        .post(format!("http://127.0.0.1:{}/api/resources", port))
        .header("Content-Type", "application/json")
        .body(r#"{"name": "test"}"#)
        .timeout(Duration::from_secs(10))
        .send()
        .await?;

    println!("HTTP response status: {}", response.status());
    assert_eq!(response.status().as_u16(), 201, "Expected 201 Created");

    let location = response
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    println!("Location: {}", location);
    assert!(
        location.contains("/api/resources/123"),
        "Expected Location header"
    );

    let body = response.text().await?;
    println!("Body: {}", body);
    assert!(body.contains("created"), "Expected 'created' in body");

    println!("✓ HTTP POST response_example executed correctly");

    server.verify_mocks().await?;
    server.stop().await?;

    println!("=== Test completed ===\n");
    Ok(())
}

/// Test HTTP startup examples (llm_mode)
///
/// Verifies that the LLM mode startup example starts an HTTP server correctly.
#[tokio::test]
async fn example_test_http_startup_llm_mode() -> E2EResult<()> {
    println!("\n=== E2E Example Test: HTTP Startup (LLM Mode) ===");

    let config = NetGetConfig::new("Start an HTTP server on port 0")
        .with_log_level("debug")
        .with_mock(|mock| {
            mock.on_instruction_containing("Start an HTTP server")
                .respond_with_actions(json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "HTTP",
                    "instruction": "Respond with JSON to all requests"
                }]))
                .and()
                .on_event("http_request")
                .respond_with_actions(json!({
                    "type": "send_http_response",
                    "status": 200,
                    "headers": {"Content-Type": "application/json"},
                    "body": "{\"message\": \"Hello from LLM mode\"}"
                }))
                .and()
        });

    let server = start_netget_server(config).await?;
    let port = server.port;

    assert!(port > 0, "Server should have started on a port");
    println!(
        "✓ HTTP server started successfully on port {} using LLM mode",
        port
    );

    // Verify by making a request
    let client = reqwest::Client::new();
    let response = client
        .get(format!("http://127.0.0.1:{}/test", port))
        .timeout(Duration::from_secs(10))
        .send()
        .await?;

    assert_eq!(response.status().as_u16(), 200);
    println!("✓ HTTP request succeeded");

    server.verify_mocks().await?;
    server.stop().await?;

    println!("=== Test completed ===\n");
    Ok(())
}

/// Test HTTP startup examples (static_mode)
///
/// Verifies that the static mode startup example with event handlers works.
#[tokio::test]
async fn example_test_http_startup_static_mode() -> E2EResult<()> {
    println!("\n=== E2E Example Test: HTTP Startup (Static Mode) ===");

    // Static mode uses event_handlers with static responses
    // Note: field is "event_pattern" not "event_type"
    // Note: "instruction" is optional when using static/script handlers
    let config = NetGetConfig::new("Start an HTTP server on port 0 with static handler")
        .with_log_level("debug")
        .with_mock(|mock| {
            mock.on_instruction_containing("Start an HTTP server")
                .respond_with_actions(json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "HTTP",
                    "event_handlers": [{
                        "event_pattern": "http_request",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "send_http_response",
                                "status": 200,
                                "headers": {"Content-Type": "text/plain"},
                                "body": "Static HTTP response"
                            }]
                        }
                    }]
                }]))
                .and()
        });

    let server = start_netget_server(config).await?;
    let port = server.port;

    assert!(port > 0, "Server should have started on a port");
    println!(
        "✓ HTTP server started successfully on port {} using static mode",
        port
    );

    // Verify static response
    let client = reqwest::Client::new();
    let response = client
        .get(format!("http://127.0.0.1:{}/", port))
        .timeout(Duration::from_secs(10))
        .send()
        .await?;

    assert_eq!(response.status().as_u16(), 200);
    let body = response.text().await?;
    assert!(
        body.contains("Static HTTP response"),
        "Expected static response"
    );
    println!("✓ Static handler executed correctly");

    server.verify_mocks().await?;
    server.stop().await?;

    println!("=== Test completed ===\n");
    Ok(())
}

/// Test HTTP error responses
///
/// Verifies that HTTP server can return error status codes.
#[tokio::test]
async fn example_test_http_error_responses() -> E2EResult<()> {
    println!("\n=== E2E Example Test: HTTP Error Responses ===");

    let config = NetGetConfig::new("Start an HTTP server on port 0")
        .with_log_level("debug")
        .with_mock(|mock| {
            mock
                // Server startup
                .on_instruction_containing("Start an HTTP server")
                .respond_with_actions(json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "HTTP",
                    "instruction": "Return 404 for unknown paths"
                }]))
                .and()
                // 404 handler for unknown paths
                .on_event("http_request")
                .respond_with_actions(json!({
                    "type": "send_http_response",
                    "status": 404,
                    "headers": {"Content-Type": "text/plain"},
                    "body": "Not Found"
                }))
                .and()
        });

    let server = start_netget_server(config).await?;
    let port = server.port;
    println!("HTTP server started on port {}", port);

    tokio::time::sleep(Duration::from_millis(500)).await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!("http://127.0.0.1:{}/nonexistent", port))
        .timeout(Duration::from_secs(10))
        .send()
        .await?;

    println!("HTTP response status: {}", response.status());
    assert_eq!(response.status().as_u16(), 404, "Expected 404 Not Found");

    let body = response.text().await?;
    assert!(body.contains("Not Found"), "Expected 'Not Found' in body");

    println!("✓ HTTP 404 response_example executed correctly");

    server.verify_mocks().await?;
    server.stop().await?;

    println!("=== Test completed ===\n");
    Ok(())
}

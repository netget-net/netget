use reqwest;
use std::path::PathBuf;
use std::time::Duration;

use crate::helpers::{start_netget_server, wait_for_server_startup, E2EResult, NetGetConfig};

/// Test comprehensive route matching with file-based OpenAPI spec
#[tokio::test]
async fn test_openapi_route_matching_comprehensive() -> E2EResult<()> {
    // Get path to test spec file
    let spec_path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/server/openapi/test_spec.yaml");
    let spec_content = std::fs::read_to_string(&spec_path).unwrap();

    // Create prompt
    let prompt =
        "Start OpenAPI server on port {AVAILABLE_PORT} with comprehensive route matching test spec";

    let server_config = NetGetConfig::new_no_scripts(prompt).with_mock(|mock| {
        mock.on_instruction_containing("Start OpenAPI server")
            .and_instruction_containing("route matching")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "openapi",
                    "instruction": "OpenAPI server for route matching test",
                    "startup_params": {
                        "spec": spec_content
                    }
                }
            ]))
            .expect_calls(1)
            .and()
            .on_event("openapi_request")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "send_openapi_response",
                    "status_code": 200,
                    "headers": {"Content-Type": "application/json"},
                    "body": serde_json::json!({"users": [{"id": 1, "name": "Test User"}]}).to_string()
                }
            ]))
            .expect_at_least(1)
            .and()
    });

    let mut server = start_netget_server(server_config).await?;

    // Wait for server to start
    wait_for_server_startup(&server, Duration::from_secs(30), "OpenAPI").await?;

    // Verify correct stack
    // REMOVED: assert_stack_name call

    // Create HTTP client
    let client = reqwest::Client::builder()
        .resolve("127.0.0.1", std::net::SocketAddr::from(([127, 0, 0, 1], 0)))
        .timeout(Duration::from_secs(10))
        .build()?;

    let base_url = format!("http://127.0.0.1:{}", server.port);

    println!("\n=== Testing 404 Not Found (path doesn't exist) ===");
    let response = client
        .get(&format!("{}/nonexistent", base_url))
        .send()
        .await?;

    assert_eq!(response.status(), 404, "Expected 404 for non-existent path");

    let json: serde_json::Value = response.json().await?;
    assert!(
        json.get("error").is_some(),
        "404 response should contain error field"
    );
    println!("✓ 404 response: {:?}", json);

    println!("\n=== Testing 405 Method Not Allowed (path exists, wrong method) ===");
    // /users supports GET and POST, but not DELETE
    let response = client.delete(&format!("{}/users", base_url)).send().await?;

    assert_eq!(
        response.status(),
        405,
        "Expected 405 for unsupported method"
    );

    // Check for Allow header
    let allow_header = response.headers().get("allow");
    assert!(
        allow_header.is_some(),
        "405 response should include Allow header"
    );
    let allowed_methods = allow_header.unwrap().to_str()?;
    println!("✓ 405 response with Allow header: {}", allowed_methods);
    assert!(
        allowed_methods.contains("GET") || allowed_methods.contains("POST"),
        "Allow header should list GET and POST"
    );

    let json: serde_json::Value = response.json().await?;
    assert!(
        json.get("error").is_some(),
        "405 response should contain error field"
    );

    println!("\n=== Testing path parameter extraction: /users/123 ===");
    let response = client
        .get(&format!("{}/users/123", base_url))
        .send()
        .await?;

    let status = response.status();
    let body = response.text().await?;

    println!(
        "Status: {}, Body preview: {:?}",
        status,
        body.chars().take(200).collect::<String>()
    );

    // LLM should receive path_params with id=123
    // Response status could be 200 or error depending on LLM
    // Just verify we got a response (not immediate 404/405)
    assert!(
        status.as_u16() != 404 && status.as_u16() != 405,
        "Path parameter route should be matched (not 404/405)"
    );

    println!("\n=== Testing nested path parameters: /products/abc123/reviews ===");
    let response = client
        .get(&format!("{}/products/abc123/reviews", base_url))
        .send()
        .await?;

    let status = response.status();
    println!("Status: {}", status);
    assert!(
        status.as_u16() != 404 && status.as_u16() != 405,
        "Nested path parameter route should be matched"
    );

    println!("\n=== Testing successful endpoint: GET /users ===");
    let response = client.get(&format!("{}/users", base_url)).send().await?;

    // Should get LLM-generated response
    let status = response.status();
    let body = response.text().await?;

    println!("Status: {}, Body: {}", status, body);

    // Verify we got a JSON response from LLM (not empty, not error-only)
    let json: serde_json::Value = serde_json::from_str(&body)?;
    assert!(
        json.is_array() || json.is_object(),
        "Should receive structured JSON from LLM"
    );

    println!("\n=== Testing POST with body: POST /users ===");
    let response = client
        .post(&format!("{}/users", base_url))
        .header("Content-Type", "application/json")
        .json(&serde_json::json!({
            "name": "Test User"
        }))
        .send()
        .await?;

    let status = response.status();
    let body = response.text().await?;

    println!("Status: {}, Body: {}", status, body);

    // Should get LLM-generated response
    assert!(
        status.is_success() || status.is_client_error(),
        "Should receive response from LLM"
    );

    println!("\n=== All route matching tests passed! ===");

    // Cleanup
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;

    Ok(())
}

/// Test llm_on_invalid configuration
#[tokio::test]
#[ignore = "llm_on_invalid can only be switched on by the configure_error_handling action, \
            which has to run after the server exists — a second model turn this one-prompt \
            harness cannot drive. `spec` is openapi's only startup parameter, so the flag \
            cannot be set at startup either. Un-ignoring it needs a mock that answers a \
            second user turn (or an injected async action), not a change here."]
async fn test_openapi_llm_on_invalid_override() -> E2EResult<()> {
    let spec_path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/server/openapi/test_spec.yaml");
    let spec_content = std::fs::read_to_string(&spec_path).unwrap();

    // Create prompt
    let prompt =
        "Start OpenAPI server on port {AVAILABLE_PORT} with LLM override for 404/405 errors";

    let server_config = NetGetConfig::new_no_scripts(prompt).with_mock(|mock| {
        mock.on_instruction_containing("Start OpenAPI server")
            .and_instruction_containing("LLM override")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "openapi",
                    "instruction": "OpenAPI server for route matching test",
                    "startup_params": {
                        "spec": spec_content
                    }
                }
            ]))
            .expect_calls(1)
            .and()
            // `send_openapi_response`, not `send_http_response`: OpenAPI cannot execute the
            // latter. This mock named it for as long as the test was ignored, so the server
            // would have rejected the action as unknown and answered with its own fallback —
            // the rule would have been "satisfied" by a reply the model never chose.
            // `assert_actions_valid_for_event` catches exactly this, and is what the test
            // tripped on the moment it was un-ignored.
            .on_event("openapi_request")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "send_openapi_response",
                    "status_code": 404,
                    "headers": {"content-type": "application/json"},
                    "body": "{\"error\": \"Custom LLM 404 response\"}"
                }
            ]))
            .expect_at_least(1)
            .and()
    });

    let mut server = start_netget_server(server_config).await?;

    wait_for_server_startup(&server, Duration::from_secs(30), "OpenAPI").await?;

    // REMOVED: assert_stack_name call

    let client = reqwest::Client::builder()
        .resolve("127.0.0.1", std::net::SocketAddr::from(([127, 0, 0, 1], 0)))
        .timeout(Duration::from_secs(10))
        .build()?;

    let base_url = format!("http://127.0.0.1:{}", server.port);

    println!("\n=== Testing 404 with LLM override ===");
    // With llm_on_invalid enabled, LLM should handle 404
    let response = client
        .get(&format!("{}/nonexistent", base_url))
        .send()
        .await?;

    // LLM might return any status code
    let status = response.status();
    let body = response.text().await?;

    println!("Status: {}, Body: {}", status, body);

    // The model's own answer has to reach the peer. Asserting only that the body is
    // non-empty passes just as happily on the server's built-in fallback, which is what
    // this test is supposed to prove was overridden.
    assert_eq!(
        status, 404,
        "the model's status code should be what the peer sees, got {status}: {body}"
    );
    assert!(
        body.contains("Custom LLM 404 response"),
        "the peer got the server's fallback rather than the model's override: {body}"
    );

    println!("\n=== LLM override test passed! ===");

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;

    Ok(())
}

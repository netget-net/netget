//! End-to-end HTTP tests for NetGet
//!
//! These tests spawn the actual NetGet binary with HTTP prompts
//! and validate the responses using real HTTP clients.

// Helper module imported from parent

use super::super::super::helpers::{self, E2EResult, NetGetConfig};

#[tokio::test]
async fn test_http_simple_get() -> E2EResult<()> {
    println!("\n=== E2E Test: Simple HTTP GET ===");

    // PROMPT: Simple HTML response
    // Get an available port first (since port 0 has issues in non-interactive mode)
    let prompt = "listen on port {AVAILABLE_PORT} via http stack. For any GET request, return status 200 with body: <h1>Hello World</h1>";

    // Start the server
    let server = helpers::start_netget_server(NetGetConfig::new(prompt).with_mock(|mock| {
        mock.on_instruction_containing("listen on port")
            .and_instruction_containing("via http")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "HTTP",
                    "instruction": "HTTP server"
                }
            ]))
            .expect_calls(1)
            .and()
            .on_event("http_request")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "send_http_response",
                    "status": 200,
                    "body": "<h1>Hello World</h1>"
                }
            ]))
            .expect_calls(1)
            .and()
    }))
    .await?;
    println!(
        "Server started: {} stack on port {}",
        server.stack, server.port
    );

    // Verify it's actually an HTTP server
    assert_eq!(
        server.stack, "HTTP",
        "Expected HTTP server but got {}",
        server.stack
    );

    // VALIDATION: Make request and check response
    let client = reqwest::Client::new();
    let url = format!("http://127.0.0.1:{}/", server.port);

    let response = client.get(&url).send().await?;

    assert_eq!(response.status(), 200);
    let body = response.text().await?;
    assert!(body.contains("Hello World"));

    println!("✓ Response validated");
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    println!("=== Test passed ===\n");
    Ok(())
}

#[tokio::test]
async fn test_http_json_api() -> E2EResult<()> {
    println!("\n=== E2E Test: JSON API ===");

    // PROMPT: JSON API response
    let prompt = r#"listen on port {AVAILABLE_PORT} via http stack. For any POST to /api/data, return status 201 with Content-Type: application/json and body: {"status": "created", "id": 123}"#;

    // Start the server
    let server = helpers::start_netget_server(NetGetConfig::new(prompt).with_mock(|mock| {
        mock.on_instruction_containing("listen on port")
            .and_instruction_containing("via http")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "HTTP",
                    "instruction": "HTTP JSON API server"
                }
            ]))
            .expect_calls(1)
            .and()
            .on_event("http_request")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "send_http_response",
                    "status": 201,
                    "headers": {"Content-Type": "application/json"},
                    "body": "{\"status\": \"created\", \"id\": 123}"
                }
            ]))
            .expect_calls(1)
            .and()
    }))
    .await?;
    println!("Server started on port {}", server.port);

    // VALIDATION: Make POST request
    let client = reqwest::Client::new();
    let url = format!("http://127.0.0.1:{}/api/data", server.port);

    let response = client
        .post(&url)
        .json(&serde_json::json!({"name": "test"}))
        .send()
        .await?;

    assert_eq!(response.status(), 201);

    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(content_type.contains("json"));

    let json: serde_json::Value = response.json().await?;
    assert_eq!(json["status"], "created");
    assert_eq!(json["id"], 123);

    println!("✓ JSON response validated");
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    println!("=== Test passed ===\n");
    Ok(())
}

#[tokio::test]
async fn test_http_routing() -> E2EResult<()> {
    println!("\n=== E2E Test: HTTP Routing ===");

    // PROMPT: Route-based responses
    let prompt = "listen on port {AVAILABLE_PORT} via http stack. For GET /home return 'Welcome Home'. For GET /about return 'About Us'. For other paths return 404 with 'Not Found'";

    // Start the server
    let server = helpers::start_netget_server(NetGetConfig::new(prompt).with_mock(|mock| {
        mock.on_instruction_containing("listen on port")
            .and_instruction_containing("via http")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "HTTP",
                    "instruction": "HTTP routing server"
                }
            ]))
            .expect_calls(1)
            .and()
            // GET /home
            .on_event("http_request")
            .and_event_data_contains("path", "/home")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "send_http_response",
                    "status": 200,
                    "body": "Welcome Home"
                }
            ]))
            .expect_calls(1)
            .and()
            // GET /about
            .on_event("http_request")
            .and_event_data_contains("path", "/about")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "send_http_response",
                    "status": 200,
                    "body": "About Us"
                }
            ]))
            .expect_calls(1)
            .and()
            // GET /unknown
            .on_event("http_request")
            .and_event_data_contains("path", "/unknown")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "send_http_response",
                    "status": 404,
                    "body": "Not Found"
                }
            ]))
            .expect_calls(1)
            .and()
    }))
    .await?;
    println!("Server started on port {}", server.port);

    let client = reqwest::Client::new();

    // Test /home route
    let response = client
        .get(&format!("http://127.0.0.1:{}/home", server.port))
        .send()
        .await?;
    assert_eq!(response.status(), 200);
    let body = response.text().await?;
    assert!(body.contains("Welcome") || body.contains("Home"));
    println!("✓ /home route works");

    // Test /about route
    let response = client
        .get(&format!("http://127.0.0.1:{}/about", server.port))
        .send()
        .await?;
    assert_eq!(response.status(), 200);
    let body = response.text().await?;
    assert!(body.contains("About"));
    println!("✓ /about route works");

    // Test 404 for unknown route
    let response = client
        .get(&format!("http://127.0.0.1:{}/unknown", server.port))
        .send()
        .await?;
    assert_eq!(response.status(), 404);
    let body = response.text().await?;
    assert!(body.contains("Not Found") || body.contains("not found"));
    println!("✓ 404 response works");

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    println!("=== Test passed ===\n");
    Ok(())
}

#[tokio::test]
async fn test_http_headers() -> E2EResult<()> {
    println!("\n=== E2E Test: Custom Headers ===");

    // PROMPT: Custom headers in response
    let prompt = "listen on port {AVAILABLE_PORT} via http stack. For GET /api return status 200 with headers: X-API-Version: 1.0, X-Custom: test-value, and body: API Response";

    // Start the server
    let server = helpers::start_netget_server(NetGetConfig::new(prompt).with_mock(|mock| {
        mock.on_instruction_containing("listen on port")
            .and_instruction_containing("via http")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "HTTP",
                    "instruction": "HTTP server with custom headers"
                }
            ]))
            .expect_calls(1)
            .and()
            .on_event("http_request")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "send_http_response",
                    "status": 200,
                    "headers": {
                        "X-API-Version": "1.0",
                        "X-Custom": "test-value"
                    },
                    "body": "API Response"
                }
            ]))
            .expect_calls(1)
            .and()
    }))
    .await?;
    println!("Server started on port {}", server.port);

    // VALIDATION: Check headers
    let client = reqwest::Client::new();
    let url = format!("http://127.0.0.1:{}/api", server.port);

    let response = client.get(&url).send().await?;

    assert_eq!(response.status(), 200);

    // Check custom headers (case-insensitive)
    let headers = response.headers();

    let api_version = headers.get("x-api-version").and_then(|v| v.to_str().ok());
    assert_eq!(api_version, Some("1.0"));

    let custom = headers.get("x-custom").and_then(|v| v.to_str().ok());
    assert_eq!(custom, Some("test-value"));

    let body = response.text().await?;
    assert!(body.contains("API Response") || body.contains("API"));

    println!("✓ Custom headers validated");
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    println!("=== Test passed ===\n");
    Ok(())
}

#[tokio::test]
async fn test_http_methods() -> E2EResult<()> {
    println!("\n=== E2E Test: HTTP Methods ===");

    // PROMPT: Different responses for different methods
    let prompt = "listen on port {AVAILABLE_PORT} via http stack. For GET return 'GET Response'. For POST return 'POST Response'. For PUT return 'PUT Response'. For DELETE return 'DELETE Response'";

    // Start the server
    let server = helpers::start_netget_server(NetGetConfig::new(prompt).with_mock(|mock| {
        mock.on_instruction_containing("listen on port")
            .and_instruction_containing("via http")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "HTTP",
                    "instruction": "HTTP server with method routing"
                }
            ]))
            .expect_calls(1)
            .and()
            // GET
            .on_event("http_request")
            .and_event_data_contains("method", "GET")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "send_http_response",
                    "status": 200,
                    "body": "GET Response"
                }
            ]))
            .expect_calls(1)
            .and()
            // POST
            .on_event("http_request")
            .and_event_data_contains("method", "POST")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "send_http_response",
                    "status": 200,
                    "body": "POST Response"
                }
            ]))
            .expect_calls(1)
            .and()
            // PUT
            .on_event("http_request")
            .and_event_data_contains("method", "PUT")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "send_http_response",
                    "status": 200,
                    "body": "PUT Response"
                }
            ]))
            .expect_calls(1)
            .and()
            // DELETE
            .on_event("http_request")
            .and_event_data_contains("method", "DELETE")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "send_http_response",
                    "status": 200,
                    "body": "DELETE Response"
                }
            ]))
            .expect_calls(1)
            .and()
    }))
    .await?;
    println!("Server started on port {}", server.port);

    let client = reqwest::Client::new();
    let url = format!("http://127.0.0.1:{}/", server.port);

    // Test GET
    let response = client.get(&url).send().await?;
    assert_eq!(response.status(), 200);
    let body = response.text().await?;
    assert!(body.contains("GET"));
    println!("✓ GET method works");

    // Test POST
    let response = client.post(&url).send().await?;
    assert_eq!(response.status(), 200);
    let body = response.text().await?;
    assert!(body.contains("POST"));
    println!("✓ POST method works");

    // Test PUT
    let response = client.put(&url).send().await?;
    assert_eq!(response.status(), 200);
    let body = response.text().await?;
    assert!(body.contains("PUT"));
    println!("✓ PUT method works");

    // Test DELETE
    let response = client.delete(&url).send().await?;
    assert_eq!(response.status(), 200);
    let body = response.text().await?;
    assert!(body.contains("DELETE"));
    println!("✓ DELETE method works");

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    println!("=== Test passed ===\n");
    Ok(())
}

#[tokio::test]
async fn test_http_error_responses() -> E2EResult<()> {
    println!("\n=== E2E Test: Error Responses ===");

    // PROMPT: Various error codes
    let prompt = "listen on port {AVAILABLE_PORT} via http stack. For GET /forbidden return 403 with 'Access Denied'. For GET /error return 500 with 'Server Error'. For GET /redirect return 301 with Location header: /home";

    // Start the server
    let server = helpers::start_netget_server(NetGetConfig::new(prompt).with_mock(|mock| {
        mock.on_instruction_containing("listen on port")
            .and_instruction_containing("via http")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "HTTP",
                    "instruction": "HTTP server with error responses"
                }
            ]))
            .expect_calls(1)
            .and()
            // GET /forbidden
            .on_event("http_request")
            .and_event_data_contains("path", "/forbidden")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "send_http_response",
                    "status": 403,
                    "body": "Access Denied"
                }
            ]))
            .expect_calls(1)
            .and()
            // GET /error
            .on_event("http_request")
            .and_event_data_contains("path", "/error")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "send_http_response",
                    "status": 500,
                    "body": "Server Error"
                }
            ]))
            .expect_calls(1)
            .and()
            // GET /redirect
            .on_event("http_request")
            .and_event_data_contains("path", "/redirect")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "send_http_response",
                    "status": 301,
                    "headers": {"Location": "/home"},
                    "body": ""
                }
            ]))
            .expect_calls(1)
            .and()
    }))
    .await?;
    println!("Server started on port {}", server.port);

    // Don't follow redirects for this test
    let client = reqwest::Client::builder()
        .resolve("127.0.0.1", std::net::SocketAddr::from(([127, 0, 0, 1], 0)))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;

    // Test 403 Forbidden
    let response = client
        .get(&format!("http://127.0.0.1:{}/forbidden", server.port))
        .send()
        .await?;
    assert_eq!(response.status(), 403);
    let body = response.text().await?;
    assert!(body.contains("Denied") || body.contains("denied") || body.contains("Forbidden"));
    println!("✓ 403 response works");

    // Test 500 Error
    let response = client
        .get(&format!("http://127.0.0.1:{}/error", server.port))
        .send()
        .await?;
    assert_eq!(response.status(), 500);
    let body = response.text().await?;
    assert!(body.contains("Error") || body.contains("error"));
    println!("✓ 500 response works");

    // Test 301 Redirect
    let response = client
        .get(&format!("http://127.0.0.1:{}/redirect", server.port))
        .send()
        .await?;
    assert_eq!(response.status(), 301);
    let location = response
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok());
    assert_eq!(location, Some("/home"));
    println!("✓ 301 redirect works");

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    println!("=== Test passed ===\n");
    Ok(())
}

/// Every `netget_access_logs_*.log` currently in the working directory.
///
/// The working directory is the repository root and is shared by the whole run, and the
/// filename `append_to_log` chooses is `netget_<output_name>_<timestamp>_s<server id>.log` —
/// so a test that wants "its" log must diff this before and after, never take the first match.
fn existing_access_logs() -> Vec<std::path::PathBuf> {
    let Ok(dir) = std::env::current_dir() else {
        return Vec::new();
    };
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut out: Vec<std::path::PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("netget_access_logs_") && n.ends_with(".log"))
        })
        .collect();
    out.sort();
    out
}

#[tokio::test]
async fn test_http_simple_get_with_logging() -> E2EResult<()> {
    println!("\n=== E2E Test: Simple HTTP GET with Access Log ===");

    // PROMPT: Simple HTML response with access logging
    let prompt = "listen on port {AVAILABLE_PORT} via http stack. For any GET request, return status 200 with body: <h1>Hello World</h1>. Also, log all access logs to a file named 'access_logs'";

    // Every `append_to_log` in the tree writes `netget_<output_name>_*.log` into the process's
    // working directory, which is the repository root and shared by every test in the run.
    // Eleven tests use the output name `access_logs`, so "the" access log file is not a thing
    // that exists: this test must consider only files that were not already here.
    //
    // It did not, and the cost was a wrong diagnosis. It took the first match from an
    // unordered `read_dir`, which was a stale file left behind by the WHOIS suite
    // (`WHOIS query from 192.168.1.100 for netget.example`), so the content assertion failed
    // against another test's log — and presented as a regression in HTTP.
    let logs_before = existing_access_logs();

    // Start the server
    let server = helpers::start_netget_server(NetGetConfig::new(prompt).with_mock(|mock| {
        mock.on_instruction_containing("listen on port")
            .and_instruction_containing("via http")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "HTTP",
                    "instruction": "HTTP server with logging"
                }
            ]))
            .expect_calls(1)
            .and()
            .on_event("http_request")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "send_http_response",
                    "status": 200,
                    "body": "<h1>Hello World</h1>"
                },
                {
                    "type": "append_to_log",
                    "output_name": "access_logs",
                    "content": "GET / 200"
                }
            ]))
            .expect_calls(1)
            .and()
    }))
    .await?;
    println!(
        "Server started: {} stack on port {}",
        server.stack, server.port
    );

    // Verify it's actually an HTTP server
    assert_eq!(
        server.stack, "HTTP",
        "Expected HTTP server but got {}",
        server.stack
    );

    // VALIDATION: Make request and check response
    let client = reqwest::Client::new();
    let url = format!("http://127.0.0.1:{}/", server.port);

    let response = client.get(&url).send().await?;

    assert_eq!(response.status(), 200);
    let body = response.text().await?;
    assert!(body.contains("Hello World"));
    println!("✓ Response validated");

    // Give LLM time to write the log
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    // Check that a log file was created matching pattern: netget_access_logs_*.log,
    // considering ONLY files that appeared while this test ran.
    let new_logs: Vec<std::path::PathBuf> = existing_access_logs()
        .into_iter()
        .filter(|p| !logs_before.contains(p))
        .collect();

    // Cleaning up must not depend on the assertions below passing. A failing run used to
    // leave its file behind, so the next run had one more stale candidate to trip over — the
    // failure was self-perpetuating, which is why it looked deterministic.
    struct Cleanup(Vec<std::path::PathBuf>);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            for p in &self.0 {
                let _ = std::fs::remove_file(p);
            }
        }
    }
    let _cleanup = Cleanup(new_logs.clone());

    assert_eq!(
        new_logs.len(),
        1,
        "expected exactly one new netget_access_logs_*.log from the mocked append_to_log \
         action; got {new_logs:?}"
    );
    let log_path = &new_logs[0];
    println!("✓ Found access log file: {:?}", log_path);

    let content = std::fs::read_to_string(log_path)?;
    println!("Log file content:\n{}", content);

    assert!(
        content.contains("GET / 200"),
        "Expected access log to contain the logged request line, got: {}",
        content
    );

    println!("✓ Access log contains the expected content");

    println!("✓ Access log cleaned up on the way out");

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    println!("=== Test passed ===\n");
    Ok(())
}

// Request-filter behavior (which requests reach the LLM) is covered by pure unit
// tests in tests/http_request_filter_test.rs — no LLM/server harness needed.

// Remove the ctor/dtor functions to avoid the panic issue
// Tests will handle their own cleanup

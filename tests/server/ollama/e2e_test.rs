//! End-to-end Ollama API tests for NetGet
//!
//! These tests spawn the actual NetGet binary with Ollama API prompts
//! and validate the responses using HTTP clients.

use crate::server::helpers::{self, E2EResult, NetGetConfig};
use serde_json::Value;
use std::time::Duration;

#[tokio::test]
async fn test_ollama_list_models() -> E2EResult<()> {
    println!("\n=== E2E Test: Ollama List Models ===");

    // Start Ollama-compatible server
    let prompt = "Open Ollama on port {AVAILABLE_PORT}. This is an Ollama-compatible API server. \
        When clients request GET /api/tags, list available Ollama models from the backend.";

    let config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock
            // Mock 1: User command to open Ollama server
            .on_instruction_containing("Open Ollama")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "Ollama",
                    "instruction": "Handle Ollama API requests"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 2: Models list request (GET /api/tags)
            .on_event("ollama_models_request")
            .respond_with_actions(serde_json::json!([
                // `ollama_models_response` with a list of model *names*. This mock used to
                // say `send_ollama_response` with a nested `body`, an action Ollama has
                // never had, so the server rejected it as unknown and answered with its
                // fallback — the assertions below were passing against that fallback rather
                // than against anything the mock said.
                {
                    "type": "ollama_models_response",
                    "models": ["qwen2.5-coder:0.5b"]
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let server = helpers::start_netget_server(config).await?;
    println!("Server started on port {}", server.port);

    // Wait a bit for server to be ready
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Send GET /api/tags request
    println!("Sending GET /api/tags request...");

    let client = reqwest::Client::new();
    let response = match tokio::time::timeout(
        Duration::from_secs(15),
        client
            .get(format!("http://127.0.0.1:{}/api/tags", server.port))
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

    // Parse JSON response
    let json: Value = response.json().await?;
    println!("Response JSON: {}", serde_json::to_string_pretty(&json)?);

    // Validate Ollama models list format
    assert!(
        json.get("models").and_then(|v| v.as_array()).is_some(),
        "Expected 'models' field to be an array"
    );

    let models = json["models"].as_array().unwrap();
    println!("✓ Found {} models", models.len());

    // Verify at least one model exists
    if !models.is_empty() {
        let first_model = &models[0];
        assert!(
            first_model.get("name").is_some(),
            "Model should have 'name' field"
        );
        println!("✓ First model: {}", first_model.get("name").unwrap());
    }

    // Verify mock expectations
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;

    println!("✓ Ollama List Models test completed\n");
    Ok(())
}

#[tokio::test]
async fn test_ollama_generate() -> E2EResult<()> {
    println!("\n=== E2E Test: Ollama Generate ===");

    let prompt = "Open Ollama on port {AVAILABLE_PORT}. This is an Ollama-compatible API server. \
        When clients send POST /api/generate requests, use the backend Ollama to generate responses.";

    let config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock
            // Mock 1: User command to open Ollama server
            .on_instruction_containing("Open Ollama")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "Ollama",
                    "instruction": "Handle Ollama generate requests"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 2: Generate request (POST /api/generate)
            .on_event("ollama_generate_request")
            .and_event_data_contains("model", "qwen2.5-coder:0.5b")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "ollama_generate_response",
                    "response_text": "Hello from NetGet Ollama"
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let server = helpers::start_netget_server(config).await?;
    println!("Server started on port {}", server.port);

    // Wait for server to be ready
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Send generate request
    println!("Sending POST /api/generate request...");

    let client = reqwest::Client::new();
    let request_body = serde_json::json!({
        "model": "qwen2.5-coder:0.5b",
        "prompt": "Say 'Hello from NetGet Ollama' and nothing else.",
        "stream": false
    });

    let response = match tokio::time::timeout(
        Duration::from_secs(30),
        client
            .post(format!("http://127.0.0.1:{}/api/generate", server.port))
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

    // Parse JSON response
    let json: Value = response.json().await?;
    println!("Response JSON: {}", serde_json::to_string_pretty(&json)?);

    // Validate Ollama generate response format
    assert!(json.get("model").is_some(), "Expected 'model' field");
    assert!(json.get("response").is_some(), "Expected 'response' field");
    assert_eq!(
        json.get("done").and_then(|v| v.as_bool()),
        Some(true),
        "Expected 'done' to be true"
    );

    let response_text = json["response"].as_str().unwrap();
    println!("✓ Generated response: {}", response_text);
    assert!(!response_text.is_empty(), "Response should not be empty");

    // Verify mock expectations
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;

    println!("✓ Ollama Generate test completed\n");
    Ok(())
}

#[tokio::test]
async fn test_ollama_chat() -> E2EResult<()> {
    println!("\n=== E2E Test: Ollama Chat ===");

    let prompt = "Open Ollama on port {AVAILABLE_PORT}. This is an Ollama-compatible API server. \
        When clients send POST /api/chat requests, use the backend Ollama to generate chat responses.";

    let config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock
            // Mock 1: User command to open Ollama server
            .on_instruction_containing("Open Ollama")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "Ollama",
                    "instruction": "Handle Ollama chat requests"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 2: Chat request (POST /api/chat)
            .on_event("ollama_chat_request")
            .and_event_data_contains("model", "qwen2.5-coder:0.5b")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "ollama_chat_response",
                    "message_content": "NetGet Ollama Chat"
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let server = helpers::start_netget_server(config).await?;
    println!("Server started on port {}", server.port);

    // Wait for server to be ready
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Send chat request
    println!("Sending POST /api/chat request...");

    let client = reqwest::Client::new();
    let request_body = serde_json::json!({
        "model": "qwen2.5-coder:0.5b",
        "messages": [
            {"role": "user", "content": "Say 'NetGet Ollama Chat' and nothing else."}
        ],
        "stream": false
    });

    let response = match tokio::time::timeout(
        Duration::from_secs(30),
        client
            .post(format!("http://127.0.0.1:{}/api/chat", server.port))
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

    // Parse JSON response
    let json: Value = response.json().await?;
    println!("Response JSON: {}", serde_json::to_string_pretty(&json)?);

    // Validate Ollama chat response format
    assert!(json.get("model").is_some(), "Expected 'model' field");
    assert!(json.get("message").is_some(), "Expected 'message' field");
    assert_eq!(
        json.get("done").and_then(|v| v.as_bool()),
        Some(true),
        "Expected 'done' to be true"
    );

    let message = json["message"].as_object().unwrap();
    assert_eq!(
        message.get("role").and_then(|v| v.as_str()),
        Some("assistant"),
        "Expected message role to be 'assistant'"
    );

    let content = message.get("content").and_then(|v| v.as_str()).unwrap();
    println!("✓ Chat response: {}", content);
    assert!(!content.is_empty(), "Response content should not be empty");

    // Verify mock expectations
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;

    println!("✓ Ollama Chat test completed\n");
    Ok(())
}

#[tokio::test]
async fn test_ollama_invalid_endpoint() -> E2EResult<()> {
    println!("\n=== E2E Test: Ollama Invalid Endpoint ===");

    let prompt = "Open Ollama on port {AVAILABLE_PORT}. This is an Ollama-compatible API server.";

    let config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock
            // Mock 1: User command to open Ollama server
            .on_instruction_containing("Open Ollama")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "Ollama",
                    "instruction": "Handle Ollama API server"
                }
            ]))
            .expect_calls(1)
            .and()
        // Note: Invalid endpoints are handled directly by Ollama server
        // No LLM call is made, so no mock needed for the 404 response
    });

    let server = helpers::start_netget_server(config).await?;
    println!("Server started on port {}", server.port);

    tokio::time::sleep(Duration::from_millis(500)).await;

    // Request non-existent endpoint
    println!("Sending GET /api/nonexistent request...");

    let client = reqwest::Client::new();
    let response = client
        .get(format!("http://127.0.0.1:{}/api/nonexistent", server.port))
        .send()
        .await?;

    println!("✓ Received HTTP response: {}", response.status());

    // Should return 404 Not Found
    assert_eq!(response.status(), 404, "Expected HTTP 404 Not Found");

    let json: Value = response.json().await?;
    println!("Response JSON: {}", serde_json::to_string_pretty(&json)?);

    assert!(
        json.get("error").is_some(),
        "Expected 'error' field in response"
    );

    // Verify mock expectations
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;

    println!("✓ Ollama Invalid Endpoint test completed\n");
    Ok(())
}

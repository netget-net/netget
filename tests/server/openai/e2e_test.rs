//! End-to-end OpenAI API tests for NetGet.
//!
//! Two views of the same server:
//!
//! - `reqwest` for the raw JSON envelope, which an SDK hides (field names, the `object`
//!   discriminators, the error object's shape).
//! - **`async-openai` 0.26, the real Rust OpenAI client**, for the thing that actually
//!   matters: that a client written against the OpenAI API deserializes our responses into
//!   its own types without a fallback path. It is a normal dependency of the `openai`
//!   feature, not a test-only stub.
//!
//! LLM call budget: 2 (models) + 2 (chat) + 3 (error paths) + 3 (SDK) = 10.

use crate::server::helpers::{self, E2EResult, NetGetConfig};
use serde_json::Value;
use std::time::Duration;

#[tokio::test]
async fn test_openai_list_models() -> E2EResult<()> {
    println!("\n=== E2E Test: OpenAI List Models ===");

    // Start OpenAI-compatible server
    let prompt = "Open OpenAI on port {AVAILABLE_PORT}. This is an OpenAI-compatible API server \
        that wraps Ollama. When clients request GET /v1/models, list available Ollama models.";

    let config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock
            // Mock 1: User command to open OpenAI server
            .on_instruction_containing("Open OpenAI")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "OpenAI",
                    "instruction": "Handle OpenAI API requests"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 2: OpenAI request event for GET /v1/models
            .on_event("openai_request")
            .and_event_data_contains("path", "/v1/models")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "openai_models_response",
                    "models": ["qwen2.5-coder:0.5b", "qwen3-coder:30b"]
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let server = helpers::start_netget_server(config).await?;
    println!("Server started on port {}", server.port);

    // Wait a bit for server to be ready
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Send GET /v1/models request
    println!("Sending GET /v1/models request...");

    let client = reqwest::Client::new();
    let response = match tokio::time::timeout(
        Duration::from_secs(15),
        client
            .get(format!("http://127.0.0.1:{}/v1/models", server.port))
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

    // Validate OpenAI models list format
    assert_eq!(
        json.get("object").and_then(|v| v.as_str()),
        Some("list"),
        "Expected 'object' field to be 'list'"
    );

    assert!(
        json.get("data").and_then(|v| v.as_array()).is_some(),
        "Expected 'data' field to be an array"
    );

    let models = json["data"].as_array().unwrap();
    println!("✓ Found {} models", models.len());

    // Verify at least one model exists
    if !models.is_empty() {
        let first_model = &models[0];
        assert!(
            first_model.get("id").is_some(),
            "Model should have 'id' field"
        );
        assert_eq!(
            first_model.get("object").and_then(|v| v.as_str()),
            Some("model"),
            "Model object should have 'object'='model'"
        );
        println!("✓ First model: {}", first_model.get("id").unwrap());
    }

    // Verify mock expectations
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;

    println!("✓ OpenAI List Models test completed\n");
    Ok(())
}

#[tokio::test]
async fn test_openai_chat_completion() -> E2EResult<()> {
    println!("\n=== E2E Test: OpenAI Chat Completion ===");

    let prompt = "Open OpenAI on port {AVAILABLE_PORT}. This is an OpenAI-compatible API server \
        that wraps Ollama. When clients send POST /v1/chat/completions requests, \
        use Ollama to generate responses and return them in OpenAI format.";

    let config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock
            // Mock 1: User command to open OpenAI server
            .on_instruction_containing("Open OpenAI")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "OpenAI",
                    "instruction": "Handle OpenAI chat completions"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 2: OpenAI request event for POST /v1/chat/completions
            .on_event("openai_request")
            .and_event_data_contains("path", "/v1/chat/completions")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "openai_chat_response",
                    "content": "Hello from NetGet",
                    "model": "qwen2.5-coder:0.5b"
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let server = helpers::start_netget_server(config).await?;
    println!("Server started on port {}", server.port);

    // Wait for server to be ready
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Send chat completion request
    println!("Sending POST /v1/chat/completions request...");

    let client = reqwest::Client::new();
    let request_body = serde_json::json!({
        "model": "qwen2.5-coder:0.5b",
        "messages": [
            {"role": "user", "content": "Say 'Hello from NetGet' and nothing else."}
        ],
        "temperature": 0.7,
        "max_tokens": 50
    });

    println!(
        "Request body: {}",
        serde_json::to_string_pretty(&request_body)?
    );

    let response = match tokio::time::timeout(
        Duration::from_secs(30), // Longer timeout for LLM generation
        client
            .post(format!(
                "http://127.0.0.1:{}/v1/chat/completions",
                server.port
            ))
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

    // Parse JSON response
    let json: Value = response.json().await?;
    println!("Response JSON: {}", serde_json::to_string_pretty(&json)?);

    // Validate OpenAI chat completion format
    assert_eq!(
        json.get("object").and_then(|v| v.as_str()),
        Some("chat.completion"),
        "Expected 'object' field to be 'chat.completion'"
    );

    assert!(
        json.get("id").and_then(|v| v.as_str()).is_some(),
        "Expected 'id' field to exist"
    );

    assert!(
        json.get("created").and_then(|v| v.as_u64()).is_some(),
        "Expected 'created' timestamp field"
    );

    assert!(
        json.get("model").and_then(|v| v.as_str()).is_some(),
        "Expected 'model' field"
    );

    // Validate choices array
    let choices = json
        .get("choices")
        .and_then(|v| v.as_array())
        .expect("Expected 'choices' array");

    assert!(!choices.is_empty(), "Expected at least one choice");

    let first_choice = &choices[0];
    assert_eq!(
        first_choice.get("index").and_then(|v| v.as_u64()),
        Some(0),
        "First choice should have index 0"
    );

    // Validate message structure
    let message = first_choice
        .get("message")
        .expect("Expected 'message' object");
    assert_eq!(
        message.get("role").and_then(|v| v.as_str()),
        Some("assistant"),
        "Message role should be 'assistant'"
    );

    let content = message
        .get("content")
        .and_then(|v| v.as_str())
        .expect("Expected message content");

    println!("✓ Assistant response: {}", content);
    assert!(!content.is_empty(), "Response content should not be empty");

    // Validate finish_reason
    assert!(
        first_choice.get("finish_reason").is_some(),
        "Expected 'finish_reason' field"
    );

    // Validate usage object
    let usage = json.get("usage").expect("Expected 'usage' object");
    assert!(
        usage.get("prompt_tokens").is_some(),
        "Expected 'prompt_tokens'"
    );
    assert!(
        usage.get("completion_tokens").is_some(),
        "Expected 'completion_tokens'"
    );
    assert!(
        usage.get("total_tokens").is_some(),
        "Expected 'total_tokens'"
    );

    // Verify mock expectations
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;

    println!("✓ OpenAI Chat Completion test completed\n");
    Ok(())
}

#[tokio::test]
async fn test_openai_invalid_endpoint() -> E2EResult<()> {
    println!("\n=== E2E Test: OpenAI Invalid Endpoint ===");

    let prompt = "Open OpenAI on port {AVAILABLE_PORT}. Return 404 errors for unknown endpoints.";

    let config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock
            // Mock 1: User command to open OpenAI server
            .on_instruction_containing("Open OpenAI")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "OpenAI",
                    "instruction": "Handle OpenAI API with 404 for unknown"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 2: OpenAI request event for invalid endpoint
            .on_event("openai_request")
            .and_event_data_contains("path", "/v1/invalid")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "openai_error_response",
                    "message": "Not Found",
                    "error_type": "invalid_request_error",
                    "status": 404
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 3: the same error, on a path the real SDK can be pointed at
            .on_event("openai_request")
            .and_event_data_contains("path", "/v1/models/no-such-model")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "openai_error_response",
                    "message": "The model 'no-such-model' does not exist",
                    "error_type": "invalid_request_error",
                    "status": 404
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let server = helpers::start_netget_server(config).await?;
    println!("Server started on port {}", server.port);

    tokio::time::sleep(Duration::from_millis(500)).await;

    // Send request to non-existent endpoint
    println!("Sending request to invalid endpoint /v1/invalid...");

    let client = reqwest::Client::new();
    let response = match tokio::time::timeout(
        Duration::from_secs(10),
        client
            .get(format!("http://127.0.0.1:{}/v1/invalid", server.port))
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

    assert_eq!(response.status(), 404, "Expected HTTP 404 Not Found");

    // Verify error response format
    let json: Value = response.json().await?;
    println!("Error response: {}", serde_json::to_string_pretty(&json)?);

    assert!(
        json.get("error").is_some(),
        "Expected 'error' object in response"
    );

    let error = json.get("error").unwrap();
    assert!(
        error.get("message").is_some(),
        "Expected error 'message' field"
    );
    assert!(error.get("type").is_some(), "Expected error 'type' field");

    // The raw shape above is only half the story: the real client has to be able to turn it
    // into its own error type. An OpenAI-compatible server whose error body the SDK cannot
    // deserialize surfaces as a transport/JSON error, which callers handle very differently
    // from an API error.
    let sdk = async_openai::Client::with_config(
        async_openai::config::OpenAIConfig::new()
            .with_api_base(format!("http://127.0.0.1:{}/v1", server.port))
            .with_api_key("dummy-key"),
    );

    let sdk_result = tokio::time::timeout(
        Duration::from_secs(15),
        sdk.models().retrieve("no-such-model"),
    )
    .await
    .map_err(|_| "async-openai models().retrieve() timed out")?;

    match sdk_result {
        Ok(model) => panic!("expected a 404 from the SDK, got model {:?}", model.id),
        Err(async_openai::error::OpenAIError::ApiError(api_error)) => {
            assert_eq!(
                api_error.message, "The model 'no-such-model' does not exist",
                "the SDK must surface the message the server sent"
            );
            assert_eq!(
                api_error.r#type.as_deref(),
                Some("invalid_request_error"),
                "the SDK must surface the error type the server sent"
            );
        }
        Err(other) => panic!(
            "async-openai could not parse the error body as an API error, which means a real \
             client sees a transport failure instead of a 404: {other}"
        ),
    }

    // Verify mock expectations
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;

    println!("✓ OpenAI Invalid Endpoint test completed\n");
    Ok(())
}

#[tokio::test]
async fn test_openai_with_rust_client() -> E2EResult<()> {
    println!("\n=== E2E Test: OpenAI with Official Rust Client ===");

    let prompt = "Open OpenAI on port {AVAILABLE_PORT}. This is an OpenAI-compatible API server \
        that wraps Ollama. When clients request models, list available Ollama models. \
        When clients request chat completions, use Ollama to generate responses.";

    let config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock
            // Mock 1: User command to open OpenAI server
            .on_instruction_containing("Open OpenAI")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "OpenAI",
                    "instruction": "Handle OpenAI API with models and chat"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 2: OpenAI request event for GET /v1/models
            .on_event("openai_request")
            .and_event_data_contains("path", "/v1/models")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "openai_models_response",
                    "models": ["qwen2.5-coder:0.5b"]
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 3: OpenAI request event for POST /v1/chat/completions
            .on_event("openai_request")
            .and_event_data_contains("path", "/v1/chat/completions")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "openai_chat_response",
                    "content": "Test response from NetGet OpenAI",
                    "model": "qwen2.5-coder:0.5b"
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let server = helpers::start_netget_server(config).await?;
    println!("Server started on port {}", server.port);

    // Wait for server to be ready
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Create OpenAI client pointing to our NetGet server
    let config = async_openai::config::OpenAIConfig::new()
        .with_api_base(format!("http://127.0.0.1:{}/v1", server.port))
        .with_api_key("dummy-key"); // NetGet doesn't validate API keys

    let client = async_openai::Client::with_config(config);

    // Test 1: List models
    println!("Testing list_models with OpenAI client...");
    let models_result = tokio::time::timeout(Duration::from_secs(15), client.models().list()).await;

    let models = match models_result {
        Ok(Ok(response)) => {
            println!("✓ Successfully listed models");
            println!("  Found {} models", response.data.len());

            // Validate response structure
            for model in &response.data {
                println!("  - {}", model.id);
                assert!(!model.id.is_empty(), "Model ID should not be empty");
                assert_eq!(model.object, "model", "Model object should be 'model'");
            }

            response.data
        }
        Ok(Err(e)) => {
            println!("✗ Failed to list models: {}", e);
            return Err(format!("Failed to list models: {}", e).into());
        }
        Err(_) => {
            println!("✗ List models timeout");
            return Err("List models timeout".into());
        }
    };

    assert!(!models.is_empty(), "Expected at least one model");

    // Test 2: Chat completion
    println!("\nTesting chat completion with OpenAI client...");

    // Use the first available model (or a specific one if we know it exists)
    let model_name = if models.iter().any(|m| m.id.contains("qwen2.5-coder:0.5b")) {
        "qwen2.5-coder:0.5b"
    } else {
        &models[0].id
    };

    println!("Using model: {}", model_name);

    let request = async_openai::types::CreateChatCompletionRequestArgs::default()
        .model(model_name)
        .messages(vec![
            async_openai::types::ChatCompletionRequestMessage::User(
                async_openai::types::ChatCompletionRequestUserMessageArgs::default()
                    .content("Say 'Hello from OpenAI Rust client!' and nothing else.")
                    .build()?,
            ),
        ])
        .temperature(0.7)
        .max_tokens(50_u32)
        .build()?;

    let completion_result =
        tokio::time::timeout(Duration::from_secs(30), client.chat().create(request)).await;

    let response = match completion_result {
        Ok(Ok(resp)) => {
            println!("✓ Successfully received chat completion");
            resp
        }
        Ok(Err(e)) => {
            println!("✗ Chat completion error: {}", e);
            return Err(format!("Chat completion failed: {}", e).into());
        }
        Err(_) => {
            println!("✗ Chat completion timeout");
            return Err("Chat completion timeout".into());
        }
    };

    // Validate response structure
    println!("Response validation:");
    println!("  - ID: {}", response.id);
    println!("  - Model: {}", response.model);
    println!("  - Object: {}", response.object);

    assert_eq!(
        response.object, "chat.completion",
        "Object should be 'chat.completion'"
    );
    assert!(!response.id.is_empty(), "Response ID should not be empty");
    assert!(!response.model.is_empty(), "Model should not be empty");

    assert!(
        !response.choices.is_empty(),
        "Should have at least one choice"
    );
    let first_choice = &response.choices[0];

    println!("  - Choice index: {}", first_choice.index);
    assert_eq!(first_choice.index, 0, "First choice should have index 0");

    // Validate message structure
    let message = &first_choice.message;
    assert_eq!(
        message.role,
        async_openai::types::Role::Assistant,
        "Message role should be Assistant"
    );

    if let Some(content_text) = &message.content {
        println!("  - Assistant response: {}", content_text);
        assert!(
            !content_text.is_empty(),
            "Response content should not be empty"
        );
    } else {
        return Err("Expected content in assistant message".into());
    }

    println!("  - Finish reason: {:?}", first_choice.finish_reason);
    assert!(
        first_choice.finish_reason.is_some(),
        "Should have finish_reason"
    );

    // Validate usage
    if let Some(usage) = &response.usage {
        println!(
            "  - Usage: {} prompt + {} completion = {} total tokens",
            usage.prompt_tokens, usage.completion_tokens, usage.total_tokens
        );
    }

    // Verify mock expectations
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;

    println!("\n✓ OpenAI Rust Client test completed - Full compatibility verified!\n");
    Ok(())
}

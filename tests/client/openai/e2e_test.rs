//! E2E tests for OpenAI client
//!
//! These tests verify OpenAI client functionality by spawning the actual NetGet binary
//! and testing client behavior as a black-box using mocked LLM responses.
//!
//! **Note**: mocked throughout. No test contacts api.openai.com — every client points at
//! a dead loopback port and answers its own events with a no-action static rule, so no
//! key is needed and none could be used. The `api_key` values below are dummies present
//! only because the protocol declares the parameter required.

mod openai_client_tests {
    use crate::helpers::*;
    use std::time::Duration;

    /// Test OpenAI client initialization with chat completion intent with mocks
    /// LLM calls: 1 (client startup only - no actual connection since OpenAI requires real API)
    #[tokio::test]
    async fn test_openai_client_chat_completion_with_mocks() -> E2EResult<()> {
        // Create client that initializes for chat completion with mocks
        let client_config = NetGetConfig::new(
            "Connect to OpenAI API with key 'sk-test-key' and send a chat completion: 'Say hello in exactly 3 words.'"
        )
        .with_mock(|mock| {
            mock
                // Mock: Client startup creates OpenAI client
                .on_instruction_containing("OpenAI")
                .and_instruction_containing("chat completion")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_client",
                        "remote_addr": "http://127.0.0.1:1/v1",
                        // A no-action `*` rule answers every client event without an
                        // LLM call, so nothing here can produce a chat action - and a
                        // chat action against `api.openai.com:443`, which this field
                        // used to hold, would be a real request to real OpenAI signed
                        // with whatever key the test passed.
                        "event_handlers": [
                            {"event_pattern": "*", "handler": {"type": "static", "actions": []}}
                        ],
                        "protocol": "OpenAI",
                        "instruction": "Send chat completion: 'Say hello in exactly 3 words'",
                        "startup_params": {
                            "api_key": "sk-test-key",
                            "default_model": "gpt-3.5-turbo"
                        }
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let client = start_netget_client(client_config).await?;

        // Give client time to initialize
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Verify client output shows OpenAI protocol
        client.wait_for_any(&["OpenAI", "openai"], 30).await;
        assert!(
            client.output_contains("OpenAI").await || client.output_contains("openai").await,
            "Client should show OpenAI protocol. Output: {:?}",
            client.get_output().await
        );

        println!("✅ OpenAI client initialized successfully");

        // Note: Mock verification is skipped for OpenAI tests because the client
        // doesn't actually connect (requires real API), so mock calls happen in
        // the subprocess and can't be verified from the parent test process.
        // The test assertions above verify the client initialized correctly.

        // Cleanup
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last response routinely lands
        // after the sleep expires, and the test reports it as never having happened.
        client.wait_for_mocks(30).await;
        client.verify_mocks().await?;
        client.stop().await?;

        Ok(())
    }

    /// Test OpenAI client initialization with gpt-4 model selection with mocks
    /// LLM calls: 1 (client startup only)
    #[tokio::test]
    async fn test_openai_client_with_model_selection_with_mocks() -> E2EResult<()> {
        // Client with specific model selection
        let client_config = NetGetConfig::new(
            "Connect to OpenAI with key 'sk-test-key' using model gpt-4 and ask: 'What is 2+2?'",
        )
        .with_mock(|mock| {
            mock
                // Mock: Client startup creates OpenAI client with gpt-4
                .on_instruction_containing("OpenAI")
                .and_instruction_containing("gpt-4")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_client",
                        "remote_addr": "http://127.0.0.1:1/v1",
                        // A no-action `*` rule answers every client event without an
                        // LLM call, so nothing here can produce a chat action - and a
                        // chat action against `api.openai.com:443`, which this field
                        // used to hold, would be a real request to real OpenAI signed
                        // with whatever key the test passed.
                        "event_handlers": [
                            {"event_pattern": "*", "handler": {"type": "static", "actions": []}}
                        ],
                        "protocol": "OpenAI",
                        "instruction": "Ask: 'What is 2+2?' using gpt-4",
                        "startup_params": {
                            "api_key": "sk-test-key",
                            "default_model": "gpt-4"
                        }
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let client = start_netget_client(client_config).await?;

        tokio::time::sleep(Duration::from_millis(500)).await;

        // Verify the client is OpenAI protocol
        assert_eq!(
            client.protocol, "OpenAI",
            "Client should be OpenAI protocol"
        );

        println!("✅ OpenAI client with model selection initialized");

        // Cleanup
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last response routinely lands
        // after the sleep expires, and the test reports it as never having happened.
        client.wait_for_mocks(30).await;
        client.verify_mocks().await?;
        client.stop().await?;

        Ok(())
    }

    /// Test OpenAI client initialization for embedding requests with mocks
    /// LLM calls: 1 (client startup only)
    #[tokio::test]
    async fn test_openai_client_embeddings_with_mocks() -> E2EResult<()> {
        // Client that initializes for embeddings
        let client_config = NetGetConfig::new(
            "Connect to OpenAI with key 'sk-test-key' and generate embeddings for the text: 'The quick brown fox'"
        )
        .with_mock(|mock| {
            mock
                // Mock: Client startup creates OpenAI client for embeddings
                .on_instruction_containing("OpenAI")
                .and_instruction_containing("embeddings")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_client",
                        "remote_addr": "http://127.0.0.1:1/v1",
                        // A no-action `*` rule answers every client event without an
                        // LLM call, so nothing here can produce a chat action - and a
                        // chat action against `api.openai.com:443`, which this field
                        // used to hold, would be a real request to real OpenAI signed
                        // with whatever key the test passed.
                        "event_handlers": [
                            {"event_pattern": "*", "handler": {"type": "static", "actions": []}}
                        ],
                        "protocol": "OpenAI",
                        "instruction": "Generate embeddings for: 'The quick brown fox'",
                        "startup_params": {
                            "api_key": "sk-test-key"
                        }
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let client = start_netget_client(client_config).await?;

        tokio::time::sleep(Duration::from_millis(500)).await;

        // Verify client is running
        client.wait_for_any(&["OpenAI"], 30).await;
        assert!(
            client.output_contains("OpenAI").await,
            "Client should show OpenAI connection. Output: {:?}",
            client.get_output().await
        );

        println!("✅ OpenAI client initialized for embeddings");

        // Cleanup
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last response routinely lands
        // after the sleep expires, and the test reports it as never having happened.
        client.wait_for_mocks(30).await;
        client.verify_mocks().await?;
        client.stop().await?;

        Ok(())
    }

    /// Test OpenAI client initialization with custom parameters with mocks
    /// LLM calls: 1 (client startup only)
    #[tokio::test]
    async fn test_openai_client_custom_parameters_with_mocks() -> E2EResult<()> {
        // Client with custom parameters (organization)
        let client_config = NetGetConfig::new(
            "Connect to OpenAI with key 'sk-test-key' and organization 'org-test' and ask: 'Hello'",
        )
        .with_mock(|mock| {
            mock
                // Mock: Client startup creates OpenAI client with custom params
                .on_instruction_containing("OpenAI")
                .and_instruction_containing("organization")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_client",
                        "remote_addr": "http://127.0.0.1:1/v1",
                        // A no-action `*` rule answers every client event without an
                        // LLM call, so nothing here can produce a chat action - and a
                        // chat action against `api.openai.com:443`, which this field
                        // used to hold, would be a real request to real OpenAI signed
                        // with whatever key the test passed.
                        "event_handlers": [
                            {"event_pattern": "*", "handler": {"type": "static", "actions": []}}
                        ],
                        "protocol": "OpenAI",
                        "instruction": "Ask: 'Hello'",
                        "startup_params": {
                            "api_key": "sk-test-key",
                            "organization": "org-test",
                            "default_model": "gpt-3.5-turbo"
                        }
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let client = start_netget_client(client_config).await?;

        tokio::time::sleep(Duration::from_millis(500)).await;

        // Verify client initialized
        client.wait_for_any(&["OpenAI"], 30).await;
        assert!(
            client.output_contains("OpenAI").await,
            "Client should show OpenAI connection. Output: {:?}",
            client.get_output().await
        );

        println!("✅ OpenAI client with custom parameters initialized");

        // Cleanup
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last response routinely lands
        // after the sleep expires, and the test reports it as never having happened.
        client.wait_for_mocks(30).await;
        client.verify_mocks().await?;
        client.stop().await?;

        Ok(())
    }
}

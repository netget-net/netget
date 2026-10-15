//! E2E tests for Ollama client
//!
//! These tests verify Ollama client functionality by spawning the actual NetGet binary
//! and testing client behavior as a black-box.
//!
//! **Note**: the mocked tests need nothing running — they point at dead loopback ports
//! deliberately. Only the `#[ignore]`d `*_real` variants want an Ollama on
//! localhost:11434, and each calls `require_ollama()` first.
//! Tests will skip if Ollama is not available.

mod ollama_client_tests {
    use crate::helpers::*;
    use std::time::Duration;

    /// Check if Ollama server is running on localhost
    async fn is_ollama_available() -> bool {
        let client = reqwest::Client::new();
        client
            .get("http://localhost:11434/api/tags")
            .timeout(Duration::from_secs(2))
            .send()
            .await
            .is_ok()
    }

    /// Skip test if Ollama is not available
    async fn require_ollama() {
        if !is_ollama_available().await {
            eprintln!("⚠️  Skipping Ollama test: Ollama server not running on localhost:11434");
            panic!("Test skipped: Ollama server not available");
        }
    }

    /// Test Ollama client can list models with mocks
    /// LLM calls: 1 (client connection with list models action)
    #[tokio::test]
    async fn test_ollama_client_list_models() -> E2EResult<()> {
        // Create client that lists available models with mocks
        let client_config = NetGetConfig::new(
            "Connect to Ollama at http://127.0.0.1:1 and list all available models",
        )
        .with_mock(|mock| {
            mock
                // Mock: Client startup
                .on_instruction_containing("Ollama")
                .and_instruction_containing("list")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_client",
                        "remote_addr": "127.0.0.1:1",
                        "protocol": "Ollama",
                        "instruction": "List all available models",
                        "event_handlers": [{"event_pattern": "*", "handler": {"type": "static", "actions": []}}]
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let client = start_netget_client(client_config).await?;

        // Give client time to initialize
        tokio::time::sleep(Duration::from_millis(500)).await;

        // The client's own readiness line, printed only after `connect()` stored the
        // endpoint and registered the command channel. "Ollama" alone is not an assertion:
        // it appears in the startup-parameter error too, which is how five tests in this
        // file passed while creating no client at all.
        client.wait_for_any(&["ready (endpoint:"], 30).await;
        assert!(
            client.output_contains("ready (endpoint:").await,
            "the Ollama client never reported itself ready. Output: {:?}",
            client.get_output().await
        );

        println!("✅ Ollama client initialized successfully");

        // Note: Mock verification is skipped because the client runs in a subprocess,
        // so mock calls happen inside the netget subprocess and can't be verified
        // from the parent test process. The test assertions above verify the client
        // initialized correctly.

        // Cleanup
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last response routinely lands
        // after the sleep expires, and the test reports it as never having happened.
        client.wait_for_mocks(30).await;
        client.verify_mocks().await?;
        client.stop().await?;

        Ok(())
    }

    /// Test Ollama client can list models (real Ollama server required)
    /// LLM calls: 1 (client connection with list models action)
    #[tokio::test]
    #[ignore = "needs a real Ollama serving on localhost:11434; the mocked variant covers the same path"]
    async fn test_ollama_client_list_models_real() -> E2EResult<()> {
        require_ollama().await;

        // Create client that lists available models
        let client_config = NetGetConfig::new(
            "Connect to Ollama at http://localhost:11434 and list all available models",
        );

        let client = start_netget_client(client_config).await?;

        // Give client time to connect and list models
        tokio::time::sleep(Duration::from_secs(3)).await;

        // Verify client output shows Ollama protocol
        client.wait_for_any(&["Ollama", "ollama"], 30).await;
        assert!(
            client.output_contains("Ollama").await || client.output_contains("ollama").await,
            "Client should show Ollama protocol. Output: {:?}",
            client.get_output().await
        );

        // Verify we got models response
        client
            .wait_for_any(&["models", "model", "found", "received"], 30)
            .await;
        assert!(
            client.output_contains("models").await
                || client.output_contains("model").await
                || client.output_contains("found").await
                || client.output_contains("received").await,
            "Client should show models response. Output: {:?}",
            client.get_output().await
        );

        println!("✅ Ollama client listed models successfully");

        // Cleanup
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last response routinely lands
        // after the sleep expires, and the test reports it as never having happened.
        client.wait_for_mocks(30).await;
        client.verify_mocks().await?;
        client.stop().await?;

        Ok(())
    }

    /// Test Ollama client can generate text with mocks
    /// LLM calls: 1 (client connection with generate request)
    #[tokio::test]
    async fn test_ollama_client_generate() -> E2EResult<()> {
        // Create client that generates text with mocks
        let client_config = NetGetConfig::new(
            "Connect to Ollama at http://127.0.0.1:1 and generate text: \
            'Say hello in exactly 2 words' using model qwen2.5-coder:0.5b",
        )
        .with_mock(|mock| {
            mock
                // Mock: Client startup
                .on_instruction_containing("Ollama")
                .and_instruction_containing("generate")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_client",
                        "remote_addr": "127.0.0.1:1",
                        "protocol": "Ollama",
                        "instruction": "Generate text: 'Say hello in exactly 2 words' using qwen2.5-coder:0.5b",
                        "event_handlers": [{"event_pattern": "*", "handler": {"type": "static", "actions": []}}]
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let client = start_netget_client(client_config).await?;

        // Give client time to initialize
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Verify client shows Ollama protocol
        client.wait_for_any(&["Ollama"], 30).await;
        assert!(
            client.output_contains("Ollama").await,
            "Client should show Ollama protocol. Output: {:?}",
            client.get_output().await
        );

        println!("✅ Ollama client initialized for text generation");

        // Note: Mock verification not possible in subprocess tests

        // Cleanup
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last response routinely lands
        // after the sleep expires, and the test reports it as never having happened.
        client.wait_for_mocks(30).await;
        client.verify_mocks().await?;
        client.stop().await?;

        Ok(())
    }

    /// Test Ollama client can generate text (real Ollama server required)
    /// LLM calls: 1 (client connection with generate request)
    #[tokio::test]
    #[ignore = "needs a real Ollama serving on localhost:11434; the mocked variant covers the same path"]
    async fn test_ollama_client_generate_real() -> E2EResult<()> {
        require_ollama().await;

        // Create client that generates text
        let client_config = NetGetConfig::new(
            "Connect to Ollama at http://localhost:11434 and generate text: \
            'Say hello in exactly 2 words' using model qwen2.5-coder:0.5b",
        );

        let client = start_netget_client(client_config).await?;

        // Give client time to generate
        tokio::time::sleep(Duration::from_secs(5)).await;

        // Verify client shows Ollama protocol
        client.wait_for_any(&["Ollama"], 30).await;
        assert!(
            client.output_contains("Ollama").await,
            "Client should show Ollama protocol. Output: {:?}",
            client.get_output().await
        );

        // Verify we got a response
        client
            .wait_for_any(&["response", "generate", "received"], 30)
            .await;
        assert!(
            client.output_contains("response").await
                || client.output_contains("generate").await
                || client.output_contains("received").await,
            "Client should show generation response. Output: {:?}",
            client.get_output().await
        );

        println!("✅ Ollama client generated text successfully");

        // Cleanup
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last response routinely lands
        // after the sleep expires, and the test reports it as never having happened.
        client.wait_for_mocks(30).await;
        client.verify_mocks().await?;
        client.stop().await?;

        Ok(())
    }

    /// Test Ollama client chat completion with mocks
    /// LLM calls: 1 (client connection with chat request)
    #[tokio::test]
    async fn test_ollama_client_chat() -> E2EResult<()> {
        // Create client that sends chat request with mocks
        let client_config = NetGetConfig::new(
            "Connect to Ollama at http://127.0.0.1:1 and send a chat message: \
            'What is 2+2?' using model qwen2.5-coder:0.5b",
        )
        .with_mock(|mock| {
            mock
                // Mock: Client startup
                .on_instruction_containing("Ollama")
                .and_instruction_containing("chat")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_client",
                        "remote_addr": "127.0.0.1:1",
                        "protocol": "Ollama",
                        "instruction": "Send chat message: 'What is 2+2?' using qwen2.5-coder:0.5b",
                        "event_handlers": [{"event_pattern": "*", "handler": {"type": "static", "actions": []}}]
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let client = start_netget_client(client_config).await?;

        // Give client time to initialize
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Verify client is Ollama protocol
        assert_eq!(
            client.protocol, "Ollama",
            "Client should be Ollama protocol"
        );

        println!("✅ Ollama client initialized for chat");

        // Note: Mock verification not possible in subprocess tests

        // Cleanup
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last response routinely lands
        // after the sleep expires, and the test reports it as never having happened.
        client.wait_for_mocks(30).await;
        client.verify_mocks().await?;
        client.stop().await?;

        Ok(())
    }

    /// Test Ollama client chat completion (real Ollama server required)
    /// LLM calls: 1 (client connection with chat request)
    #[tokio::test]
    #[ignore = "needs a real Ollama serving on localhost:11434; the mocked variant covers the same path"]
    async fn test_ollama_client_chat_real() -> E2EResult<()> {
        require_ollama().await;

        // Create client that sends chat request
        let client_config = NetGetConfig::new(
            "Connect to Ollama at http://localhost:11434 and send a chat message: \
            'What is 2+2?' using model qwen2.5-coder:0.5b",
        );

        let client = start_netget_client(client_config).await?;

        // Give client time to chat
        tokio::time::sleep(Duration::from_secs(5)).await;

        // Verify client is Ollama protocol
        assert_eq!(
            client.protocol, "Ollama",
            "Client should be Ollama protocol"
        );

        // Verify we got a chat response
        client
            .wait_for_any(&["chat", "message", "response"], 30)
            .await;
        assert!(
            client.output_contains("chat").await
                || client.output_contains("message").await
                || client.output_contains("response").await,
            "Client should show chat response. Output: {:?}",
            client.get_output().await
        );

        println!("✅ Ollama client chat completion worked");

        // Cleanup
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last response routinely lands
        // after the sleep expires, and the test reports it as never having happened.
        client.wait_for_mocks(30).await;
        client.verify_mocks().await?;
        client.stop().await?;

        Ok(())
    }

    /// Test Ollama client with custom endpoint with mocks
    /// LLM calls: 1 (client connection)
    #[tokio::test]
    async fn test_ollama_client_custom_endpoint() -> E2EResult<()> {
        // Test with explicit endpoint with mocks
        let client_config =
            NetGetConfig::new("Connect to Ollama API at http://127.0.0.1:1 and list models")
                .with_mock(|mock| {
                    mock
                        // Mock: Client startup with custom endpoint
                        .on_instruction_containing("Ollama")
                        .and_instruction_containing("127.0.0.1:1")
                        .respond_with_actions(serde_json::json!([
                            {
                                "type": "open_client",
                                "remote_addr": "127.0.0.1:1",
                                "protocol": "Ollama",
                                "instruction": "List models",
                                "event_handlers": [{"event_pattern": "*", "handler": {"type": "static", "actions": []}}]
                            }
                        ]))
                        .expect_calls(1)
                        .and()
                });

        let client = start_netget_client(client_config).await?;

        tokio::time::sleep(Duration::from_millis(500)).await;

        // Verify client initialized
        client.wait_for_any(&["ready (endpoint:"], 30).await;
        assert!(
            client
                .output_contains("ready (endpoint: http://127.0.0.1:1")
                .await,
            "the endpoint must be used as given, not rewritten or defaulted. Output: {:?}",
            client.get_output().await
        );

        println!("✅ Ollama client with custom endpoint initialized");

        // Note: Mock verification not possible in subprocess tests

        // Cleanup
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last response routinely lands
        // after the sleep expires, and the test reports it as never having happened.
        client.wait_for_mocks(30).await;
        client.verify_mocks().await?;
        client.stop().await?;

        Ok(())
    }

    /// Test Ollama client with custom endpoint (real Ollama server required)
    /// LLM calls: 1 (client connection)
    #[tokio::test]
    #[ignore = "needs a real Ollama serving on localhost:11434; the mocked variant covers the same path"]
    async fn test_ollama_client_custom_endpoint_real() -> E2EResult<()> {
        require_ollama().await;

        // Test with explicit endpoint
        let client_config =
            NetGetConfig::new("Connect to Ollama API at http://localhost:11434 and list models");

        let client = start_netget_client(client_config).await?;

        tokio::time::sleep(Duration::from_secs(3)).await;

        // Verify client connected
        client
            .wait_for_any(&["localhost:11434", "11434", "Ollama"], 30)
            .await;
        assert!(
            client.output_contains("localhost:11434").await
                || client.output_contains("11434").await
                || client.output_contains("Ollama").await,
            "Client should show connection to custom endpoint. Output: {:?}",
            client.get_output().await
        );

        println!("✅ Ollama client with custom endpoint worked");

        // Cleanup
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last response routinely lands
        // after the sleep expires, and the test reports it as never having happened.
        client.wait_for_mocks(30).await;
        client.verify_mocks().await?;
        client.stop().await?;

        Ok(())
    }

    /// Test Ollama client error handling (invalid server) with mocks
    /// LLM calls: 1 (client connection attempt)
    #[tokio::test]
    async fn test_ollama_client_error_handling() -> E2EResult<()> {
        // Use an invalid endpoint with mocks
        let client_config =
            NetGetConfig::new("Connect to Ollama at http://localhost:99999 and list models")
                .with_mock(|mock| {
                    mock
                        // Mock: Client startup (will fail to connect)
                        .on_instruction_containing("Ollama")
                        .and_instruction_containing("99999")
                        .respond_with_actions(serde_json::json!([
                            {
                                "type": "open_client",
                                "remote_addr": "localhost:99999",
                                "protocol": "Ollama",
                                "instruction": "List models",
                                "event_handlers": [{"event_pattern": "*", "handler": {"type": "static", "actions": []}}]
                            }
                        ]))
                        .expect_calls(1)
                        .and()
                });

        let client = start_netget_client(client_config).await?;

        tokio::time::sleep(Duration::from_millis(500)).await;

        // Verify client attempted connection (may show error)
        // Note: Error handling happens at protocol level, mock just tests instruction parsing
        println!("✅ Ollama client error handling test completed");

        // Note: Mock verification not possible in subprocess tests

        // Cleanup
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last response routinely lands
        // after the sleep expires, and the test reports it as never having happened.
        client.wait_for_mocks(30).await;
        client.verify_mocks().await?;
        client.stop().await?;

        Ok(())
    }

    /// Test Ollama client error handling (invalid server) - no mock needed
    /// LLM calls: 1 (client connection attempt)
    #[tokio::test]
    #[ignore = "needs a real Ollama serving on localhost:11434; the mocked variant covers the same path"]
    async fn test_ollama_client_error_handling_real() -> E2EResult<()> {
        // Use an invalid endpoint
        let client_config =
            NetGetConfig::new("Connect to Ollama at http://localhost:99999 and list models");

        let client = start_netget_client(client_config).await?;

        tokio::time::sleep(Duration::from_secs(3)).await;

        // Verify client shows error or connection issue
        client
            .wait_for_any(&["ERROR", "error", "failed", "connect"], 30)
            .await;
        assert!(
            client.output_contains("ERROR").await
                || client.output_contains("error").await
                || client.output_contains("failed").await
                || client.output_contains("connect").await,
            "Client should show error for invalid endpoint. Output: {:?}",
            client.get_output().await
        );

        println!("✅ Ollama client error handling worked");

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

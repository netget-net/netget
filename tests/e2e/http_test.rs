//! E2E tests for HTTP protocol using the new test framework

mod tests {
    use anyhow::Result;
    use reqwest::StatusCode;
    use serde_json::json;
    use std::time::Duration;

    // Import from parent crate
    use crate::e2e::netget_wrapper::{NetGetWrapper, ServerInfo};
    use crate::validators::HttpValidator;

    #[tokio::test]
    #[ignore = "Drives the real netget binary against a real Ollama (qwen2.5-coder:7b); there is no mock path through NetGetWrapper. Run with --ignored."]
    async fn test_http_server_basic() -> Result<()> {
        // Start NetGet
        let mut netget = NetGetWrapper::new();
        netget
            .start("qwen2.5-coder:7b", vec!["--no-scripting"])
            .await?;

        // Create HTTP server with comprehensive prompt
        let prompt = r#"
            Start an HTTP server on port {AVAILABLE_PORT} that:
            1. Returns "Hello NetGet" for GET /
            2. Returns JSON {"status": "ok", "message": "Test response"} for GET /api/status
            3. Echoes back the request body for POST /echo
            4. Returns 404 for unknown paths
        "#;

        let server = netget.create_server(prompt).await?;
        println!("Created HTTP server on port {}", server.port);

        // Create validator
        let validator = HttpValidator::new(server.port);
        validator.wait_for_ready(20).await?;

        // Test 1: Basic GET
        validator.expect_contains("/", "Hello NetGet").await?;

        // Test 2: JSON endpoint
        let expected_json = json!({
            "status": "ok",
            "message": "Test response"
        });
        validator.expect_json("/api/status", &expected_json).await?;

        // Test 3: Echo endpoint
        let response = validator.post_text("/echo", "Test data").await?;
        let body = response.text().await?;
        assert_eq!(body, "Test data");

        // Test 4: 404 handling
        validator
            .expect_status("/nonexistent", StatusCode::NOT_FOUND)
            .await?;

        // Cleanup
        netget.stop().await?;
        Ok(())
    }

    #[tokio::test]
    #[ignore = "Drives the real netget binary against a real Ollama (qwen2.5-coder:7b); there is no mock path through NetGetWrapper. Run with --ignored."]
    async fn test_http_server_with_memory() -> Result<()> {
        let mut netget = NetGetWrapper::new();
        netget.start("qwen2.5-coder:7b", vec![]).await?;

        // Create stateful HTTP server
        let prompt = r#"
            Start an HTTP server on port {AVAILABLE_PORT} that maintains a counter:
            - GET /counter returns current count as JSON {"count": N}
            - POST /counter/increment increases counter and returns new value
            - POST /counter/reset resets to 0
            Use memory to track the counter value.
        "#;

        let server = netget.create_server(prompt).await?;
        let validator = HttpValidator::new(server.port);
        validator.wait_for_ready(20).await?;

        // Initial count should be 0
        validator
            .expect_json_field("/counter", "count", &json!(0))
            .await?;

        // Increment counter
        let response = validator.post_text("/counter/increment", "").await?;
        let json: serde_json::Value = response.json().await?;
        assert_eq!(json["count"], 1);

        // Increment again
        validator.post_text("/counter/increment", "").await?;
        validator
            .expect_json_field("/counter", "count", &json!(2))
            .await?;

        // Reset
        validator.post_text("/counter/reset", "").await?;
        validator
            .expect_json_field("/counter", "count", &json!(0))
            .await?;

        netget.stop().await?;
        Ok(())
    }

    #[tokio::test]
    #[ignore = "Drives the real netget binary against a real Ollama (qwen2.5-coder:7b); there is no mock path through NetGetWrapper. Run with --ignored."]
    async fn test_multiple_servers() -> Result<()> {
        let mut netget = NetGetWrapper::new();
        netget.start("qwen2.5-coder:7b", vec![]).await?;

        // Create first server
        let server1 = netget
            .create_server("Start HTTP server on port {AVAILABLE_PORT} returning 'Server 1'")
            .await?;

        // Create second server
        let server2 = netget
            .create_server("Start HTTP server on port {AVAILABLE_PORT} returning 'Server 2'")
            .await?;

        // Validate both servers are running
        let validator1 = HttpValidator::new(server1.port);
        let validator2 = HttpValidator::new(server2.port);

        validator1.wait_for_ready(20).await?;
        validator2.wait_for_ready(20).await?;

        validator1.expect_contains("/", "Server 1").await?;
        validator2.expect_contains("/", "Server 2").await?;

        // Update first server
        netget
            .send_user_input(&format!(
                "Update server {} to return 'Updated Server 1'",
                server1.id
            ))
            .await?;

        tokio::time::sleep(Duration::from_secs(2)).await;

        // Verify update
        validator1.expect_contains("/", "Updated Server 1").await?;
        validator2.expect_contains("/", "Server 2").await?; // Should be unchanged

        netget.stop().await?;
        Ok(())
    }
}

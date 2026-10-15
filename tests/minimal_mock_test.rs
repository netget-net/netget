//! Minimal test to verify mock Ollama server works

mod helpers;

mod minimal_test {
    use crate::helpers::common::E2EResult;
    use crate::helpers::netget::NetGetConfig;
    use serde_json::json;

    #[tokio::test]
    async fn test_mock_server_minimal() -> E2EResult<()> {
        println!("\n=== Minimal Mock Server Test ===");

        // Test that the mock LLM integration works by starting a simple TCP server
        let config = NetGetConfig::new("Start a TCP server on port 0")
            .with_log_level("debug") // More verbose logging
            .with_mock(|mock| {
                mock.on_instruction_containing("TCP")
                    .and_instruction_containing("server")
                    .respond_with_actions(json!([
                        {
                            "type": "open_server",
                            "port": 0,
                            "base_stack": "TCP",
                            "instruction": "Echo server"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
            });

        println!("Starting NetGet with mock...");
        let instance = crate::helpers::netget::start_netget(config).await?;

        println!("NetGet started, waiting for server to initialize...");
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

        // Get output
        let output = instance.get_output().await;
        let output_text = output.join("\n");

        println!("\n=== NetGet Output ===");
        println!("{}", output_text);
        println!("=== End Output ===\n");

        // Verify we have 1 server
        assert_eq!(instance.servers.len(), 1, "Expected 1 server to be started");
        assert_eq!(instance.clients.len(), 0, "Expected 0 clients");

        // Verify the mock was called
        println!("Verifying mock expectations...");
        instance.verify_mocks().await?;

        println!("✅ Mock server test passed!");
        Ok(())
    }
}

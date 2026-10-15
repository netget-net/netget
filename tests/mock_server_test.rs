//! Test to verify the mock Ollama HTTP server works correctly
//!
//! This test ensures that:
//! 1. Mock server starts and binds to a random port
//! 2. NetGet binary can connect to the mock server
//! 3. Mocked responses are returned correctly
//! 4. Call count verification works

#[path = ""]
mod tests {
    use serde_json::json;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    use tokio::time::sleep;

    #[path = "helpers/mod.rs"]
    mod helpers;
    use helpers::common::E2EResult;
    use helpers::netget::NetGetConfig;

    #[tokio::test]
    async fn test_mock_server_basic() -> E2EResult<()> {
        println!("\n🧪 Testing mock Ollama server - verifying basic TCP server starts");

        // Simplified test: just verify server starts with mock LLM
        let config = NetGetConfig::new("listen on port 0 via tcp").with_mock(|mock| {
            mock.on_instruction_containing("listen on port 0")
                .and_instruction_containing("tcp")
                .respond_with_actions(json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "TCP",
                    "instruction": "TCP echo server"
                }]))
                .expect_calls(1)
                .and()
        });

        // Start NetGet with mocks
        let server = helpers::netget::start_netget(config).await?;

        // Give server time to start
        sleep(Duration::from_millis(500)).await;

        // Verify server started
        assert!(!server.servers.is_empty(), "No servers started");
        assert_eq!(server.servers.len(), 1, "Expected exactly 1 server");
        let port = server.servers[0].port;
        println!("📡 Server listening on port {}", port);

        // Verify we can connect to the server
        let stream = TcpStream::connect(format!("127.0.0.1:{}", port)).await?;
        println!("🔗 Connected to TCP server successfully");

        // Close connection
        drop(stream);

        // Verify mock expectations
        server.verify_mocks().await?;

        println!("✅ Mock server test passed!");
        Ok(())
    }
}

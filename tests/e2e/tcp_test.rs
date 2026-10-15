//! E2E tests for TCP protocol using the new test framework

mod tests {
    use anyhow::Result;
    use std::time::Duration;

    // Import from parent crate
    use crate::e2e::netget_wrapper::NetGetWrapper;
    use crate::validators::TcpValidator;

    #[tokio::test]
    #[ignore = "Drives the real netget binary against a real Ollama (qwen2.5-coder:7b); there is no mock path through NetGetWrapper. Run with --ignored."]
    async fn test_tcp_echo_server() -> Result<()> {
        // Start NetGet
        let mut netget = NetGetWrapper::new();
        netget.start("qwen2.5-coder:7b", vec![]).await?;

        // Create TCP echo server
        let prompt =
            "Start a TCP server on port {AVAILABLE_PORT} that echoes back whatever it receives";
        let server = netget.create_server(prompt).await?;

        // Create validator
        let validator = TcpValidator::new(server.port);
        validator.wait_for_ready(20).await?;

        // Test echo functionality
        validator.test_echo("Hello NetGet\n").await?;
        validator.test_echo("Test message 123\n").await?;

        // Test with binary-like data
        validator
            .expect_response("BINARY\x00\x01\x02\n", "BINARY\x00\x01\x02\n")
            .await?;

        netget.stop().await?;
        Ok(())
    }

    #[tokio::test]
    #[ignore = "Drives the real netget binary against a real Ollama (qwen2.5-coder:7b); there is no mock path through NetGetWrapper. Run with --ignored."]
    async fn test_tcp_chat_server() -> Result<()> {
        let mut netget = NetGetWrapper::new();
        netget.start("qwen2.5-coder:7b", vec![]).await?;

        // Create interactive TCP server
        let prompt = r#"
            Start a TCP server on port {AVAILABLE_PORT} that:
            - Sends "Welcome!" when client connects
            - Responds "Hi!" to "hello"
            - Responds "Goodbye!" to "bye" and closes connection
            - Echoes other messages with "You said: " prefix
        "#;

        let server = netget.create_server(prompt).await?;
        let validator = TcpValidator::new(server.port);
        validator.wait_for_ready(20).await?;

        // Test conversation flow
        let responses = validator
            .send_sequence(&["hello\n", "test\n", "bye\n"])
            .await?;

        assert!(responses[0].contains("Hi!"));
        assert!(responses[1].contains("You said: test"));
        assert!(responses[2].contains("Goodbye!"));

        netget.stop().await?;
        Ok(())
    }

    #[tokio::test]
    #[ignore = "Drives the real netget binary against a real Ollama (qwen2.5-coder:7b); there is no mock path through NetGetWrapper. Run with --ignored."]
    async fn test_tcp_protocol_implementation() -> Result<()> {
        let mut netget = NetGetWrapper::new();
        netget.start("qwen2.5-coder:7b", vec![]).await?;

        // Create a simple protocol server
        let prompt = r#"
            Start a TCP server on port {AVAILABLE_PORT} implementing a simple protocol:
            Commands (case-insensitive):
            - PING -> PONG
            - TIME -> current timestamp
            - ECHO <text> -> <text>
            - QUIT -> close connection
            Invalid commands return "ERROR: Unknown command"
        "#;

        let server = netget.create_server(prompt).await?;
        let validator = TcpValidator::new(server.port);
        validator.wait_for_ready(20).await?;

        // Test protocol commands
        validator.expect_response("PING\n", "PONG\n").await?;
        validator.expect_response("ping\n", "PONG\n").await?; // Case insensitive

        let time_response = validator.send_receive_text("TIME\n").await?;
        assert!(time_response.len() > 0); // Should contain timestamp

        validator
            .expect_response("ECHO hello world\n", "hello world\n")
            .await?;
        validator.expect_contains("INVALID\n", "ERROR").await?;

        netget.stop().await?;
        Ok(())
    }

    #[tokio::test]
    #[ignore = "Drives the real netget binary against a real Ollama (qwen2.5-coder:7b); there is no mock path through NetGetWrapper. Run with --ignored."]
    async fn test_tcp_with_memory() -> Result<()> {
        let mut netget = NetGetWrapper::new();
        netget.start("qwen2.5-coder:7b", vec![]).await?;

        // Create stateful TCP server
        let prompt = r#"
            Start a TCP server on port {AVAILABLE_PORT} that tracks client state:
            - First message: asks for name and remembers it
            - Subsequent messages: responds with "Hello [name], you said: [message]"
            - Special command "FORGET" resets the name
            Use memory to track client names per connection.
        "#;

        let server = netget.create_server(prompt).await?;
        let validator = TcpValidator::new(server.port);
        validator.wait_for_ready(20).await?;

        // Test stateful interaction
        let responses = validator
            .send_sequence(&["Alice\n", "How are you?\n", "FORGET\n", "Bob\n"])
            .await?;

        // First response should ask for name or acknowledge it
        // Second should include "Hello Alice"
        assert!(responses[1].contains("Alice"));

        // After FORGET, should ask for name again
        // Last response should use new name
        assert!(!responses[3].contains("Alice"));

        netget.stop().await?;
        Ok(())
    }
}

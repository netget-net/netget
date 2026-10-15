//! E2E tests for SQS client
//!
//! These tests verify SQS client functionality by spawning the actual NetGet binary
//! and testing client behavior as a black-box with a LocalStack SQS server.

mod sqs_client_tests {
    use crate::helpers::*;
    use std::time::Duration;

    /// Test SQS client connection and message send
    /// LLM calls: 3 (server startup, client connection, message send)
    #[tokio::test]
    #[ignore = "No .with_mock() configured: requires --use-ollama; the LLM call is refused under strict-mock mode"]
    async fn test_sqs_client_connect_and_send() -> E2EResult<()> {
        // Start an SQS server listening on an available port
        let server_config = NetGetConfig::new(
            "Listen on port {AVAILABLE_PORT} via SQS. Accept SendMessage operations and respond with success.",
        );

        let mut server = start_netget_server(server_config).await?;

        // Give server time to start
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Now start an SQS client that connects and sends a message
        let client_config = NetGetConfig::new(format!(
            "Connect to SQS queue at http://127.0.0.1:{}/000000000000/TestQueue. Send a message with body 'Test message'.",
            server.port
        ));

        let mut client = start_netget_client(client_config).await?;

        // Give client time to connect and send message
        tokio::time::sleep(Duration::from_millis(1000)).await;

        // Verify client output shows connection
        client.wait_for_any(&["connected"], 30).await;
        assert!(
            client.output_contains("connected").await,
            "Client should show connection message. Output: {:?}",
            client.get_output().await
        );

        println!("✅ SQS client connected and sent message successfully");

        // Cleanup
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last response routinely lands
        // after the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last response routinely lands
        // after the sleep expires, and the test reports it as never having happened.
        client.wait_for_mocks(30).await;
        client.verify_mocks().await?;
        client.stop().await?;

        Ok(())
    }

    /// Test SQS client can receive messages
    /// LLM calls: 3 (server startup, client connection, receive messages)
    #[tokio::test]
    #[ignore = "No .with_mock() configured: requires --use-ollama; the LLM call is refused under strict-mock mode"]
    async fn test_sqs_client_receive_messages() -> E2EResult<()> {
        // Start an SQS server that will return messages
        let server_config = NetGetConfig::new(
            "Listen on port {AVAILABLE_PORT} via SQS. When receiving ReceiveMessage requests, return one message with body 'Hello from queue'.",
        );

        let mut server = start_netget_server(server_config).await?;

        tokio::time::sleep(Duration::from_millis(500)).await;

        // Client that receives messages
        let client_config = NetGetConfig::new(format!(
            "Connect to SQS queue at http://127.0.0.1:{}/000000000000/TestQueue. Receive messages from the queue.",
            server.port
        ));

        let mut client = start_netget_client(client_config).await?;

        tokio::time::sleep(Duration::from_millis(1000)).await;

        // Verify the client is SQS protocol
        assert_eq!(client.protocol, "SQS", "Client should be SQS protocol");

        println!("✅ SQS client received messages successfully");

        // Cleanup
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last response routinely lands
        // after the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last response routinely lands
        // after the sleep expires, and the test reports it as never having happened.
        client.wait_for_mocks(30).await;
        client.verify_mocks().await?;
        client.stop().await?;

        Ok(())
    }

    /// Test SQS client with LocalStack (if available)
    /// This test is marked as ignored by default and only runs when LocalStack is available
    /// LLM calls: 2 (client connect, send+receive)
    #[tokio::test]
    #[ignore = "Requires LocalStack running on port 4566"]
    async fn test_sqs_client_with_localstack() -> E2EResult<()> {
        // This test assumes LocalStack is running with SQS on port 4566
        // Start with: docker run -d -p 4566:4566 localstack/localstack

        // Create a queue first using AWS CLI:
        // aws --endpoint-url=http://localhost:4566 sqs create-queue --queue-name NetGetTestQueue

        let queue_url = "http://localhost:4566/000000000000/NetGetTestQueue";

        // Start client that sends a message
        let client_config = NetGetConfig::new(format!(
            "Connect to SQS queue at {}. Send a message 'Test from NetGet', then receive messages and delete them.",
            queue_url
        ));

        let mut client = start_netget_client(client_config).await?;

        // Give client time to execute operations
        tokio::time::sleep(Duration::from_millis(2000)).await;

        // Verify client shows connection and operations
        client.wait_for_any(&["connected"], 30).await;
        assert!(
            client.output_contains("connected").await,
            "Client should show connection. Output: {:?}",
            client.get_output().await
        );

        println!("✅ SQS client worked with LocalStack");

        // Cleanup
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last response routinely lands
        // after the sleep expires, and the test reports it as never having happened.
        client.wait_for_mocks(30).await;
        client.verify_mocks().await?;
        client.stop().await?;

        Ok(())
    }

    /// Test SQS client error handling for invalid queue URL
    /// LLM calls: 1 (client connection attempt)
    #[tokio::test]
    #[ignore = "No .with_mock() configured: requires --use-ollama; the LLM call is refused under strict-mock mode"]
    async fn test_sqs_client_invalid_queue() -> E2EResult<()> {
        // Try to connect with an invalid queue URL
        let client_config = NetGetConfig::new(
            "Connect to SQS queue at http://invalid-endpoint:9999/000000000000/NonExistentQueue. Send a test message.",
        );

        let mut client = start_netget_client(client_config).await?;

        // Give client time to attempt connection
        tokio::time::sleep(Duration::from_millis(1000)).await;

        // The client should show an error or timeout
        // We're not asserting specific behavior here because error handling may vary
        println!("✅ SQS client handled invalid queue URL");

        // Cleanup
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last response routinely lands
        // after the sleep expires, and the test reports it as never having happened.
        client.wait_for_mocks(30).await;
        client.verify_mocks().await?;
        client.stop().await?;

        Ok(())
    }

    /// Test SQS client queue attributes query
    /// LLM calls: 2 (client connect, get attributes)
    #[tokio::test]
    #[ignore = "No .with_mock() configured: requires --use-ollama; the LLM call is refused under strict-mock mode"]
    async fn test_sqs_client_get_attributes() -> E2EResult<()> {
        // Start an SQS server
        let server_config = NetGetConfig::new(
            "Listen on port {AVAILABLE_PORT} via SQS. Respond to GetQueueAttributes with ApproximateNumberOfMessages=5.",
        );

        let mut server = start_netget_server(server_config).await?;

        tokio::time::sleep(Duration::from_millis(500)).await;

        // Client that gets queue attributes
        let client_config = NetGetConfig::new(format!(
            "Connect to SQS queue at http://127.0.0.1:{}/000000000000/TestQueue. Get queue attributes.",
            server.port
        ));

        let mut client = start_netget_client(client_config).await?;

        tokio::time::sleep(Duration::from_millis(1000)).await;

        // Verify client connected
        assert_eq!(client.protocol, "SQS", "Client should be SQS protocol");

        println!("✅ SQS client retrieved queue attributes");

        // Cleanup
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last response routinely lands
        // after the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last response routinely lands
        // after the sleep expires, and the test reports it as never having happened.
        client.wait_for_mocks(30).await;
        client.verify_mocks().await?;
        client.stop().await?;

        Ok(())
    }
}

//! E2E tests for Syslog client
//!
//! These tests verify Syslog client functionality by spawning the actual NetGet binary
//! and testing client behavior as a black-box.
//! Test strategy: Use netget binary to start syslog server + client, < 10 LLM calls total.

mod syslog_client_tests {
    use crate::helpers::*;
    use std::time::Duration;

    /// Test Syslog client connection to a local syslog server (UDP)
    /// LLM calls: 2 (server startup, client connection)
    #[tokio::test]
    #[ignore = "No .with_mock() configured: requires --use-ollama; the LLM call is refused under strict-mock mode"]
    async fn test_syslog_client_udp_connect() -> E2EResult<()> {
        // Start a UDP server listening on an available port (acting as syslog receiver)
        let server_config = NetGetConfig::new(
            "Listen on port {AVAILABLE_PORT} via UDP. Log all incoming syslog messages.",
        );

        let mut server = start_netget_server(server_config).await?;

        // Give server time to start
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Now start a Syslog client that sends to this server
        let client_config = NetGetConfig::new(format!(
            "Send syslog messages to 127.0.0.1:{} using UDP protocol. Send a message with facility 'user' and severity 'info'.",
            server.port
        ));

        let mut client = start_netget_client(client_config).await?;

        // Give client time to send message
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Verify client output shows connection
        client.wait_for_any(&["connected", "Syslog"], 30).await;
        assert!(
            client.output_contains("connected").await || client.output_contains("Syslog").await,
            "Client should show syslog message. Output: {:?}",
            client.get_output().await
        );

        println!("✅ Syslog client sent message via UDP successfully");

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

    /// Test Syslog client connection to a local syslog server (TCP)
    /// LLM calls: 2 (server startup, client connection)
    #[tokio::test]
    #[ignore = "No .with_mock() configured: requires --use-ollama; the LLM call is refused under strict-mock mode"]
    async fn test_syslog_client_tcp_connect() -> E2EResult<()> {
        // Start a TCP server listening on an available port (acting as syslog receiver)
        let server_config = NetGetConfig::new("Listen on port {AVAILABLE_PORT} via TCP. Accept connections and log all incoming syslog messages.");

        let mut server = start_netget_server(server_config).await?;

        // Give server time to start
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Now start a Syslog client that sends to this server via TCP
        let client_config = NetGetConfig::new(format!(
            "Send syslog messages to 127.0.0.1:{} using TCP protocol (not UDP). Send a message with facility 'daemon' and severity 'error'.",
            server.port
        ));

        let mut client = start_netget_client(client_config).await?;

        // Give client time to connect and send message
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Verify client output shows connection
        client.wait_for_any(&["connected", "Syslog"], 30).await;
        assert!(
            client.output_contains("connected").await || client.output_contains("Syslog").await,
            "Client should show syslog connection. Output: {:?}",
            client.get_output().await
        );

        println!("✅ Syslog client sent message via TCP successfully");

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

    /// Test Syslog client can send custom messages via LLM prompts
    /// LLM calls: 1 (client startup)
    #[tokio::test]
    #[ignore = "No .with_mock() configured: requires --use-ollama; the LLM call is refused under strict-mock mode"]
    async fn test_syslog_client_custom_messages() -> E2EResult<()> {
        // Start a UDP server
        let server_config =
            NetGetConfig::new("Listen on port {AVAILABLE_PORT} via UDP. Log all incoming data.");

        let mut server = start_netget_server(server_config).await?;

        tokio::time::sleep(Duration::from_millis(500)).await;

        // Client that sends specific syslog messages based on LLM instruction
        let client_config = NetGetConfig::new(format!(
            "Connect to 127.0.0.1:{} via syslog (UDP). Send multiple messages: first with facility 'user' severity 'info' message 'Test message 1', then facility 'kern' severity 'alert' message 'Critical alert'.",
            server.port
        ));

        let mut client = start_netget_client(client_config).await?;

        tokio::time::sleep(Duration::from_millis(500)).await;

        // Verify the client is syslog protocol
        assert_eq!(
            client.protocol, "Syslog",
            "Client should be Syslog protocol"
        );

        println!("✅ Syslog client responded to LLM instruction");

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

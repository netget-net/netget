//! E2E tests for POP3 client
//!
//! These tests verify POP3 client functionality by spawning the actual NetGet binary
//! and testing client behavior as a black-box.
//!
//! **Test Infrastructure Requirements**:
//! - Local POP3 server (NetGet POP3 server or Dovecot)
//! - For testing, we use NetGet's own POP3 server

mod pop3_client_tests {
    use crate::helpers::*;
    use std::time::Duration;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpListener;

    /// Helper to start a local POP3 server using NetGet
    async fn start_local_pop3_server() -> E2EResult<server::NetGetServer> {
        let prompt = "listen on port {AVAILABLE_PORT} via pop3. \
            Send greeting '+OK POP3 server ready'. \
            For USER command, respond '+OK user accepted'. \
            For PASS command, respond '+OK logged in'. \
            For STAT command, respond '+OK 2 1024'. \
            For QUIT command, respond '+OK goodbye'";

        let server = start_netget_server(NetGetConfig::new(prompt)).await?;

        // Give server time to start
        tokio::time::sleep(Duration::from_millis(1000)).await;

        Ok(server)
    }

    /// Test POP3 client connection
    /// LLM calls: 2 (1 server startup + 1 client connection)
    #[tokio::test]
    #[ignore = "No .with_mock() configured: requires --use-ollama; the LLM call is refused under strict-mock mode"]
    async fn test_pop3_client_connection() -> E2EResult<()> {
        println!("\n=== E2E Test: POP3 Client Connection ===");

        // Start local POP3 server
        let server = start_local_pop3_server().await?;
        println!("✓ POP3 server started on port {}", server.port);

        // Now start a POP3 client
        let client_config = NetGetConfig::new(&format!(
            "Connect to 127.0.0.1:{} via POP3. Authenticate as user 'alice' with password 'secret'.",
            server.port
        ));

        let mut client = start_netget_client(client_config).await?;
        println!("✓ POP3 client started");

        // Give client time to connect and receive greeting
        tokio::time::sleep(Duration::from_secs(2)).await;

        // Verify client output shows POP3 protocol or connection
        let output = client.get_output().await;
        assert!(
            output.iter().any(|l| l.contains("POP3"))
                || output.iter().any(|l| l.contains("pop3"))
                || output.iter().any(|l| l.contains("+OK"))
                || output.iter().any(|l| l.contains("connected")),
            "Client should show POP3 protocol or connection message. Output: {:?}",
            output
        );

        println!("✓ POP3 client connected successfully");
        println!("Client output: {:?}", output);

        // Cleanup
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last response routinely lands
        // after the sleep expires, and the test reports it as never having happened.
        client.wait_for_mocks(30).await;
        client.verify_mocks().await?;
        client.stop().await?;
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last response routinely lands
        // after the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;

        println!("=== Test completed ===\n");
        Ok(())
    }

    /// Test POP3 client authentication flow
    /// LLM calls: 2 (1 server startup + 1 client connection)
    #[tokio::test]
    #[ignore = "No .with_mock() configured: requires --use-ollama; the LLM call is refused under strict-mock mode"]
    async fn test_pop3_client_authentication() -> E2EResult<()> {
        println!("\n=== E2E Test: POP3 Client Authentication ===");

        // Start local POP3 server
        let server = start_local_pop3_server().await?;
        println!("✓ POP3 server started on port {}", server.port);

        // Start POP3 client with authentication instruction
        let client_config = NetGetConfig::new(&format!(
            "Connect to 127.0.0.1:{} via POP3 and authenticate as user 'testuser' with password 'testpass'.",
            server.port
        ));

        let mut client = start_netget_client(client_config).await?;
        println!("✓ POP3 client started");

        // Give client time to authenticate
        tokio::time::sleep(Duration::from_secs(2)).await;

        // Verify client shows connection or POP3
        let output = client.get_output().await;
        assert!(
            output.iter().any(|l| l.contains("POP3"))
                || output.iter().any(|l| l.contains("pop3"))
                || output.iter().any(|l| l.contains("connected")),
            "Client should show POP3 protocol. Output: {:?}",
            output
        );

        println!("✓ POP3 client authentication flow completed");
        println!("Client output: {:?}", output);

        // Cleanup
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last response routinely lands
        // after the sleep expires, and the test reports it as never having happened.
        client.wait_for_mocks(30).await;
        client.verify_mocks().await?;
        client.stop().await?;
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last response routinely lands
        // after the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;

        println!("=== Test completed ===\n");
        Ok(())
    }

    /// Test POP3 client mailbox operations
    /// LLM calls: 2 (1 server startup + 1 client connection)
    #[tokio::test]
    #[ignore = "No .with_mock() configured: requires --use-ollama; the LLM call is refused under strict-mock mode"]
    async fn test_pop3_client_mailbox_operations() -> E2EResult<()> {
        println!("\n=== E2E Test: POP3 Client Mailbox Operations ===");

        // Start local POP3 server with enhanced mailbox responses
        let prompt = "listen on port {AVAILABLE_PORT} via pop3. \
            Send greeting '+OK POP3 ready'. \
            For USER, respond '+OK'. \
            For PASS, respond '+OK logged in'. \
            For STAT, respond '+OK 3 2048' (3 messages, 2048 bytes). \
            For LIST, respond '+OK 3 messages' then '1 512' then '2 768' then '3 768' then '.'. \
            For QUIT, respond '+OK goodbye'";

        let server = start_netget_server(NetGetConfig::new(prompt)).await?;
        println!("✓ POP3 server started on port {}", server.port);

        // Give server time to start
        tokio::time::sleep(Duration::from_millis(1000)).await;

        // Start POP3 client with mailbox query instruction
        let client_config = NetGetConfig::new(&format!(
            "Connect to 127.0.0.1:{} via POP3. Login and check mailbox status.",
            server.port
        ));

        let mut client = start_netget_client(client_config).await?;
        println!("✓ POP3 client started");

        // Give client time to connect and query mailbox
        tokio::time::sleep(Duration::from_secs(2)).await;

        // Verify client shows POP3 protocol
        let output = client.get_output().await;
        assert!(
            output.iter().any(|l| l.contains("POP3"))
                || output.iter().any(|l| l.contains("pop3"))
                || output.iter().any(|l| l.contains("connected")),
            "Client should show POP3 protocol. Output: {:?}",
            output
        );

        println!("✓ POP3 client mailbox operations completed");
        println!("Client output: {:?}", output);

        // Cleanup
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last response routinely lands
        // after the sleep expires, and the test reports it as never having happened.
        client.wait_for_mocks(30).await;
        client.verify_mocks().await?;
        client.stop().await?;
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last response routinely lands
        // after the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;

        println!("=== Test completed ===\n");
        Ok(())
    }
}

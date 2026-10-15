//! E2E tests for SMTP client
//!
//! These tests verify SMTP client functionality by spawning the actual NetGet binary
//! and testing client behavior as a black-box.
//!
//! **Test Infrastructure Requirements**:
//! - Local SMTP server (mailhog, fakesmtp, or Python's smtp debugging server)
//! - For testing, use: `python3 -m smtpd -n -c DebuggingServer localhost:1025`

mod smtp_client_tests {
    use crate::helpers::*;
    use std::process::{Command, Stdio};
    use std::time::Duration;

    /// Helper to start a local SMTP debugging server using Python
    async fn start_local_smtp_server() -> E2EResult<std::process::Child> {
        // Start Python SMTP debugging server on port 1025
        let child = Command::new("python3")
            .args(&[
                "-m",
                "smtpd",
                "-n",
                "-c",
                "DebuggingServer",
                "localhost:1025",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| {
                format!(
                    "Failed to start Python SMTP server: {}. Make sure Python 3 is installed.",
                    e
                )
            })?;

        // Give server time to start
        tokio::time::sleep(Duration::from_millis(500)).await;

        Ok(child)
    }

    /// Test SMTP client connection
    /// LLM calls: 1 (client connection)
    #[tokio::test]
    #[ignore = "No .with_mock() configured: requires --use-ollama and a local python3 SMTP debugging server; the LLM call is refused under strict-mock mode"]
    async fn test_smtp_client_connection() -> E2EResult<()> {
        // Start local SMTP server
        let mut smtp_server = start_local_smtp_server().await?;

        // Give server time to fully initialize
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Now start an SMTP client
        let client_config = NetGetConfig::new(
            "Connect to localhost:1025 via SMTP. Prepare to send an email from test@example.com to recipient@example.com."
        );

        let mut client = start_netget_client(client_config).await?;

        // Give client time to connect
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Verify client output shows SMTP protocol or connection
        client.wait_for_any(&["SMTP", "connected"], 30).await;
        assert!(
            client.output_contains("SMTP").await || client.output_contains("connected").await,
            "Client should show SMTP protocol or connection message. Output: {:?}",
            client.get_output().await
        );

        println!("✅ SMTP client connected successfully");

        // Cleanup
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last response routinely lands
        // after the sleep expires, and the test reports it as never having happened.
        client.wait_for_mocks(30).await;
        client.verify_mocks().await?;
        client.stop().await?;
        smtp_server
            .kill()
            .map_err(|e| format!("Failed to kill SMTP server: {}", e))?;

        Ok(())
    }

    /// Test SMTP client can compose email based on LLM instructions
    /// LLM calls: 1 (client connection)
    /// Note: This test verifies the client is ready to send, not actually sending
    /// (full send test requires email verification which is complex for E2E)
    #[tokio::test]
    #[ignore = "No .with_mock() configured: requires --use-ollama and a local python3 SMTP debugging server; the LLM call is refused under strict-mock mode"]
    async fn test_smtp_client_email_preparation() -> E2EResult<()> {
        // Start local SMTP server
        let mut smtp_server = start_local_smtp_server().await?;

        tokio::time::sleep(Duration::from_millis(500)).await;

        // Client that prepares to send an email
        let client_config = NetGetConfig::new(
            "Connect to localhost:1025 via SMTP and prepare to send a test email with subject 'NetGet Test'."
        );

        let mut client = start_netget_client(client_config).await?;

        tokio::time::sleep(Duration::from_millis(500)).await;

        // Verify the client is SMTP protocol
        assert_eq!(client.protocol, "SMTP", "Client should be SMTP protocol");

        println!("✅ SMTP client prepared to send email based on LLM instruction");

        // Cleanup
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last response routinely lands
        // after the sleep expires, and the test reports it as never having happened.
        client.wait_for_mocks(30).await;
        client.verify_mocks().await?;
        client.stop().await?;
        smtp_server
            .kill()
            .map_err(|e| format!("Failed to kill SMTP server: {}", e))?;

        Ok(())
    }

    /// Test SMTP client without authentication (local server)
    /// LLM calls: 1 (client connection)
    #[tokio::test]
    #[ignore = "No .with_mock() configured: requires --use-ollama and a local python3 SMTP debugging server; the LLM call is refused under strict-mock mode"]
    async fn test_smtp_client_no_auth() -> E2EResult<()> {
        // Start local SMTP server (no auth required)
        let mut smtp_server = start_local_smtp_server().await?;

        tokio::time::sleep(Duration::from_millis(500)).await;

        // Client connecting without authentication
        let client_config = NetGetConfig::new(
            "Connect to localhost:1025 via SMTP without authentication. Ready to send emails.",
        );

        let mut client = start_netget_client(client_config).await?;

        tokio::time::sleep(Duration::from_millis(500)).await;

        // Verify connection
        client.wait_for_any(&["SMTP", "ready"], 30).await;
        assert!(
            client.output_contains("SMTP").await || client.output_contains("ready").await,
            "Client should show SMTP readiness. Output: {:?}",
            client.get_output().await
        );

        println!("✅ SMTP client connected without authentication");

        // Cleanup
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last response routinely lands
        // after the sleep expires, and the test reports it as never having happened.
        client.wait_for_mocks(30).await;
        client.verify_mocks().await?;
        client.stop().await?;
        smtp_server
            .kill()
            .map_err(|e| format!("Failed to kill SMTP server: {}", e))?;

        Ok(())
    }
}

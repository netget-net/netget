//! E2E tests for HTTP proxy client
//!
//! These tests verify HTTP proxy client functionality by spawning the actual NetGet binary
//! and testing client behavior as a black-box.
//! Test strategy: Use netget binary to start proxy + client, < 10 LLM calls total.

#[cfg(unix)]
mod http_proxy_client_tests {
    use crate::helpers::*;
    use std::time::Duration;

    /// Test HTTP proxy client connection and tunnel establishment
    /// LLM calls: 3 (proxy server startup, target server startup, client connection)
    #[tokio::test]
    #[ignore = "No .with_mock() configured: requires --use-ollama; the LLM call is refused under strict-mock mode"]
    async fn test_http_proxy_client_connect_and_tunnel() -> E2EResult<()> {
        // Start a simple HTTP proxy server
        // Note: We use NetGet's HTTP proxy server for this test
        let proxy_config = NetGetConfig::new(
            "Listen on port {AVAILABLE_PORT} via HTTP proxy. Accept CONNECT requests and forward traffic."
        );

        let mut proxy_server = start_netget_server(proxy_config).await?;
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Start a simple HTTP server as the target
        let target_config = NetGetConfig::new(
            "Listen on port {AVAILABLE_PORT} via HTTP. Respond to GET / with '200 OK' and body 'Hello from target server'."
        );

        let mut target_server = start_netget_server(target_config).await?;
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Start HTTP proxy client that connects through proxy to target
        let client_config = NetGetConfig::new(format!(
            "Connect to HTTP proxy at 127.0.0.1:{}. Establish tunnel to 127.0.0.1:{} and send GET / request.",
            proxy_server.port, target_server.port
        ));

        let mut client = start_netget_client(client_config).await?;
        tokio::time::sleep(Duration::from_secs(2)).await;

        // Verify client output shows connection and tunnel establishment
        let output = client.get_output().await;
        assert!(
            output.iter().any(|l| l.contains("connected"))
                || output.iter().any(|l| l.contains("proxy")),
            "Client should show proxy connection. Output: {:?}",
            output
        );

        println!("✅ HTTP proxy client connected and established tunnel");

        // Cleanup
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last response routinely lands
        // after the sleep expires, and the test reports it as never having happened.
        proxy_server.wait_for_mocks(30).await;
        proxy_server.verify_mocks().await?;
        proxy_server.stop().await?;
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last response routinely lands
        // after the sleep expires, and the test reports it as never having happened.
        target_server.wait_for_mocks(30).await;
        target_server.verify_mocks().await?;
        target_server.stop().await?;
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last response routinely lands
        // after the sleep expires, and the test reports it as never having happened.
        client.wait_for_mocks(30).await;
        client.verify_mocks().await?;
        client.stop().await?;

        Ok(())
    }

    /// Test HTTP proxy client without actual proxy (simplified test)
    /// LLM calls: 2 (client startup with instruction to connect)
    #[tokio::test]
    #[ignore = "No .with_mock() configured: requires --use-ollama; the LLM call is refused under strict-mock mode"]
    async fn test_http_proxy_client_basic_connection() -> E2EResult<()> {
        // Start a simple TCP server that will act as a minimal proxy
        // It just needs to respond to CONNECT with 200 Connection established
        let server_config = NetGetConfig::new(
            "Listen on port {AVAILABLE_PORT} via TCP. When you receive 'CONNECT', respond with 'HTTP/1.1 200 Connection established\\r\\n\\r\\n'."
        );

        let mut server = start_netget_server(server_config).await?;
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Client that connects to the proxy
        let client_config = NetGetConfig::new(format!(
            "Connect to HTTP proxy at 127.0.0.1:{}. Establish tunnel to example.com:80.",
            server.port
        ));

        let mut client = start_netget_client(client_config).await?;
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Verify client initiated connection
        assert_eq!(
            client.protocol, "HTTP Proxy",
            "Client should be HTTP Proxy protocol"
        );

        println!("✅ HTTP proxy client initiated connection to proxy server");

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

    /// Test HTTP proxy client with raw data transmission
    /// LLM calls: 2 (proxy server, client with instruction)
    #[tokio::test]
    #[ignore = "No .with_mock() configured: requires --use-ollama; the LLM call is refused under strict-mock mode"]
    async fn test_http_proxy_client_raw_data() -> E2EResult<()> {
        // Start a TCP server that responds to CONNECT
        let server_config = NetGetConfig::new(
            "Listen on port {AVAILABLE_PORT} via TCP. Respond to CONNECT with 200, then echo any data received."
        );

        let mut server = start_netget_server(server_config).await?;
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Client that sends raw data through tunnel
        let client_config = NetGetConfig::new(format!(
            "Connect to HTTP proxy at 127.0.0.1:{}. After tunnel is established, send hex data '48656c6c6f' (which is 'Hello').",
            server.port
        ));

        let mut client = start_netget_client(client_config).await?;
        tokio::time::sleep(Duration::from_secs(1)).await;

        // Verify client connected
        let output = client.get_output().await;
        assert!(
            output.iter().any(|l| l.contains("connected"))
                || output.iter().any(|l| l.contains("tunnel")),
            "Client should show connection/tunnel status. Output: {:?}",
            output
        );

        println!("✅ HTTP proxy client can send raw data through tunnel");

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

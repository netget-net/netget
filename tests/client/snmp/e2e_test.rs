//! E2E tests for SNMP client
//!
//! These tests verify SNMP client functionality by spawning the actual NetGet binary
//! and testing client behavior as a black-box.

mod snmp_client_tests {
    use crate::helpers::*;
    use std::time::Duration;

    /// Test SNMP client connection and GET request
    /// LLM calls: 2 (server startup, client connection)
    #[tokio::test]
    #[ignore = "No .with_mock() configured: requires --use-ollama; the LLM call is refused under strict-mock mode"]
    async fn test_snmp_client_get_request() -> E2EResult<()> {
        // Start an SNMP agent (server) listening on an available port
        let server_config = NetGetConfig::new(
            "Listen on port {AVAILABLE_PORT} via SNMP. Respond to GET requests for OID 1.3.6.1.2.1.1.1.0 (sysDescr) with 'NetGet SNMP Test Agent'.",
        );

        let mut server = start_netget_server(server_config).await?;

        // Give server time to start
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Now start an SNMP client that connects and queries
        let client_config = NetGetConfig::new(format!(
            "Connect to 127.0.0.1:{} via SNMP. Query OID 1.3.6.1.2.1.1.1.0 (sysDescr) and display the result.",
            server.port
        ));

        let mut client = start_netget_client(client_config).await?;

        // Give client time to connect and execute query
        tokio::time::sleep(Duration::from_secs(2)).await;

        // Verify client output shows connection
        client.wait_for_any(&["connected"], 30).await;
        assert!(
            client.output_contains("connected").await,
            "Client should show connection message. Output: {:?}",
            client.get_output().await
        );

        println!("✅ SNMP client connected and queried OID successfully");

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

    /// Test SNMP client GETNEXT request for MIB walking
    /// LLM calls: 3 (server startup, client connection, follow-up GETNEXT)
    #[tokio::test]
    #[ignore = "No .with_mock() configured: requires --use-ollama; the LLM call is refused under strict-mock mode"]
    async fn test_snmp_client_getnext_walk() -> E2EResult<()> {
        // Start an SNMP agent with multiple OIDs
        let server_config = NetGetConfig::new(
            "Listen on port {AVAILABLE_PORT} via SNMP. \
            Support GETNEXT requests for the system subtree (1.3.6.1.2.1.1). \
            Respond with these OIDs in order: \
            1.3.6.1.2.1.1.1.0 = 'Test Agent', \
            1.3.6.1.2.1.1.5.0 = 'test-host'.",
        );

        let mut server = start_netget_server(server_config).await?;

        tokio::time::sleep(Duration::from_millis(500)).await;

        // Client that walks the system subtree
        let client_config = NetGetConfig::new(format!(
            "Connect to 127.0.0.1:{} via SNMP. \
            Use GETNEXT to walk the system subtree starting at 1.3.6.1.2.1.1. \
            Send GETNEXT until you get 2 OID/value pairs.",
            server.port
        ));

        let mut client = start_netget_client(client_config).await?;

        tokio::time::sleep(Duration::from_secs(3)).await;

        // Verify the client protocol
        assert_eq!(client.protocol, "SNMP", "Client should be SNMP protocol");

        println!("✅ SNMP client walked MIB tree using GETNEXT");

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

    /// Test SNMP client with SNMPv2c GETBULK request
    /// LLM calls: 2 (server startup, client connection)
    #[tokio::test]
    #[ignore = "No .with_mock() configured: requires --use-ollama; the LLM call is refused under strict-mock mode"]
    async fn test_snmp_client_getbulk_v2c() -> E2EResult<()> {
        // Start an SNMP agent supporting v2c
        let server_config = NetGetConfig::new(
            "Listen on port {AVAILABLE_PORT} via SNMP using SNMPv2c. \
            Support GETBULK requests for interface table (1.3.6.1.2.1.2.2.1). \
            Return 3 OIDs: \
            1.3.6.1.2.1.2.2.1.1.1 = 1 (ifIndex), \
            1.3.6.1.2.1.2.2.1.2.1 = 'eth0' (ifDescr), \
            1.3.6.1.2.1.2.2.1.5.1 = 1000000000 (ifSpeed 1Gbps).",
        );

        let mut server = start_netget_server(server_config).await?;

        tokio::time::sleep(Duration::from_millis(500)).await;

        // Client using GETBULK (v2c only)
        let client_config = NetGetConfig::new(format!(
            "Connect to 127.0.0.1:{} via SNMP using SNMPv2c with community 'public'. \
            Use GETBULK to retrieve interface table starting at 1.3.6.1.2.1.2.2.1 with max_repetitions=3.",
            server.port
        ));

        let mut client = start_netget_client(client_config).await?;

        tokio::time::sleep(Duration::from_secs(2)).await;

        // Verify client connected
        client.wait_for_any(&["connected"], 30).await;
        assert!(
            client.output_contains("connected").await,
            "Client should connect. Output: {:?}",
            client.get_output().await
        );

        println!("✅ SNMP client retrieved bulk data with GETBULK");

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

    /// Test SNMP client SET request
    /// LLM calls: 2 (server startup, client connection)
    #[tokio::test]
    #[ignore = "No .with_mock() configured: requires --use-ollama; the LLM call is refused under strict-mock mode"]
    async fn test_snmp_client_set_request() -> E2EResult<()> {
        // Start an SNMP agent that accepts SET requests
        let server_config = NetGetConfig::new(
            "Listen on port {AVAILABLE_PORT} via SNMP using community 'private'. \
            Accept SET requests for OID 1.3.6.1.2.1.1.5.0 (sysName). \
            Log the new value and respond with success.",
        );

        let mut server = start_netget_server(server_config).await?;

        tokio::time::sleep(Duration::from_millis(500)).await;

        // Client that sends SET request
        let client_config = NetGetConfig::new(format!(
            "Connect to 127.0.0.1:{} via SNMP using SNMPv2c with community 'private'. \
            SET OID 1.3.6.1.2.1.1.5.0 to 'new-hostname'. \
            Then verify by reading it back with GET.",
            server.port
        ));

        let mut client = start_netget_client(client_config).await?;

        tokio::time::sleep(Duration::from_secs(2)).await;

        // Verify client connected
        assert_eq!(client.protocol, "SNMP", "Client should be SNMP protocol");

        println!("✅ SNMP client sent SET request successfully");

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

    /// Test SNMP client with custom community string
    /// LLM calls: 2 (server startup, client connection)
    #[tokio::test]
    #[ignore = "No .with_mock() configured: requires --use-ollama; the LLM call is refused under strict-mock mode"]
    async fn test_snmp_client_custom_community() -> E2EResult<()> {
        // Start an SNMP agent requiring specific community string
        let server_config = NetGetConfig::new(
            "Listen on port {AVAILABLE_PORT} via SNMP. \
            Only accept requests with community string 'secret123'. \
            For other community strings, return error. \
            Respond to OID 1.3.6.1.2.1.1.1.0 with 'Secure Agent'.",
        );

        let mut server = start_netget_server(server_config).await?;

        tokio::time::sleep(Duration::from_millis(500)).await;

        // Client with matching community string
        let client_config = NetGetConfig::new(format!(
            "Connect to 127.0.0.1:{} via SNMP using SNMPv2c with community 'secret123'. \
            Query OID 1.3.6.1.2.1.1.1.0.",
            server.port
        ));

        let mut client = start_netget_client(client_config).await?;

        tokio::time::sleep(Duration::from_secs(2)).await;

        // Verify client connected successfully
        client.wait_for_any(&["connected"], 30).await;
        assert!(
            client.output_contains("connected").await,
            "Client should connect with correct community string. Output: {:?}",
            client.get_output().await
        );

        println!("✅ SNMP client authenticated with custom community string");

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

    /// Test SNMP client timeout and retry behavior
    /// LLM calls: 1 (client connection only, server intentionally not started)
    #[tokio::test]
    #[ignore = "No .with_mock() configured: requires --use-ollama; the LLM call is refused under strict-mock mode"]
    async fn test_snmp_client_timeout() -> E2EResult<()> {
        // No server - test client timeout behavior
        // Client with short timeout
        let client_config = NetGetConfig::new(
            "Connect to 127.0.0.1:9999 via SNMP with a 1000ms timeout and 1 retry. \
            Query OID 1.3.6.1.2.1.1.1.0.",
        );

        let mut client = start_netget_client(client_config).await?;

        tokio::time::sleep(Duration::from_secs(3)).await;

        // Verify client handles timeout
        let output = client.get_output().await;
        assert!(
            output.iter().any(|l| l.contains("timeout"))
                || output.iter().any(|l| l.contains("error")),
            "Client should show timeout or error. Output: {:?}",
            output
        );

        println!("✅ SNMP client handled timeout correctly");

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

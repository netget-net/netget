//! E2E tests for DoH (DNS-over-HTTPS) client
//!
//! These tests verify DoH client functionality by connecting to a local DoH server
//! and testing DNS query resolution as a black-box with Ollama mocks.

mod doh_client_tests {
    use crate::helpers::*;
    use std::time::Duration;

    /// Test DoH client connecting to local DoH server with A record query
    /// LLM calls: 4 (server startup, server query, client startup, client query)
    #[tokio::test]
    async fn test_doh_client_local_server_a_query() -> E2EResult<()> {
        // Start a local DoH server with mocks
        let server_config =
            NetGetConfig::new("Listen on port {AVAILABLE_PORT} via DoH. Respond to DNS queries.")
                .with_mock(|mock| {
                    mock
                        // Mock 1: Server startup
                        .on_instruction_containing("Listen")
                        .and_instruction_containing("DoH")
                        .respond_with_actions(serde_json::json!([
                            {
                                "type": "open_server",
                                "port": 0,
                                "base_stack": "DoH",
                                "instruction": "DoH server for client testing"
                            }
                        ]))
                        .expect_calls(1)
                        .and()
                        // Mock 2: Server receives query for example.com
                        .on_event("doh_query")
                        .and_event_data_contains("domain", "example.com")
                        .respond_with_actions_from_event(|e| {
                            serde_json::json!([
                                {
                                    "type": "send_dns_a_response",
                                    // The client picks a random DNS id and drops any
                                    // answer that does not carry it back. Omitted, it
                                    // defaults to 0 and the response is discarded.
                                    "query_id": e["query_id"].as_u64().unwrap_or(0),
                                    "domain": "example.com",
                                    "ip": "93.184.216.34",
                                    "ttl": 300
                                }
                            ])
                        })
                        .expect_calls(1)
                        .and()
                });

        let mut server = start_netget_server(server_config).await?;

        // Wait for server to start
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Start DoH client connecting to local server with mocks
        let client_config = NetGetConfig::new(format!(
            "Connect to https://127.0.0.1:{}/dns-query via DoH. Query example.com A record.",
            server.port
        ))
        .with_mock(|mock| {
            mock
                // Mock 1: Client startup
                .on_instruction_containing("Connect to")
                .and_instruction_containing("DoH")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_client",
                        "remote_addr": format!("https://127.0.0.1:{}/dns-query", server.port),
                        "protocol": "DoH",
                        "instruction": "Query example.com A record",
                        // NetGet's DoH server is TLS-only and serves a self-signed
                        // certificate, so a client using the system roots cannot reach it
                        // -- the two halves of this codebase could not talk to each other.
                        // Opted into explicitly here rather than the client quietly
                        // accepting any certificate.
                        "startup_params": { "insecure_skip_verify": true }
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2: Client connected
                .on_event("doh_connected")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "query_dns",
                        "domain": "example.com",
                        "record_type": "A"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 3: Client receives response
                .on_event("doh_response_received")
                .and_event_data_contains("domain", "example.com")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "wait_for_more"
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let mut client = start_netget_client(client_config).await?;

        // Give client time to connect and query

        // Verify client output shows connection
        client.wait_for_any(&["connected"], 30).await;
        assert!(
            client.output_contains("connected").await,
            "Client should show connection. Output: {:?}",
            client.get_output().await
        );

        println!("✅ DoH client connected to local server and queried successfully");

        // Verify mock expectations were met
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last response routinely lands
        // after the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        client.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        client.verify_mocks().await?;

        // Cleanup
        server.stop().await?;
        client.stop().await?;

        Ok(())
    }

    /// Test DoH client connecting to local DoH server with AAAA record query
    /// LLM calls: 4 (server startup, server query, client startup, client query)
    #[tokio::test]
    async fn test_doh_client_local_server_aaaa_query() -> E2EResult<()> {
        // Start a local DoH server with mocks
        let server_config =
            NetGetConfig::new("Listen on port {AVAILABLE_PORT} via DoH. Respond to DNS queries.")
                .with_mock(|mock| {
                    mock
                        // Mock 1: Server startup
                        .on_instruction_containing("Listen")
                        .and_instruction_containing("DoH")
                        .respond_with_actions(serde_json::json!([
                            {
                                "type": "open_server",
                                "port": 0,
                                "base_stack": "DoH",
                                "instruction": "DoH server for AAAA testing"
                            }
                        ]))
                        .expect_calls(1)
                        .and()
                        // Mock 2: Server receives AAAA query
                        .on_event("doh_query")
                        .and_event_data_contains("domain", "example.com")
                        .and_event_data_contains("query_type", "AAAA")
                        .respond_with_actions_from_event(|e| {
                            serde_json::json!([
                                {
                                    "type": "send_dns_aaaa_response",
                                    // The client picks a random DNS id and drops any
                                    // answer that does not carry it back. Omitted, it
                                    // defaults to 0 and the response is discarded.
                                    "query_id": e["query_id"].as_u64().unwrap_or(0),
                                    "domain": "example.com",
                                    "ip": "2001:db8::1",
                                    "ttl": 300
                                }
                            ])
                        })
                        .expect_calls(1)
                        .and()
                });

        let mut server = start_netget_server(server_config).await?;

        // Wait for server to start
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Start DoH client with mocks
        let client_config = NetGetConfig::new(format!(
            "Connect to https://127.0.0.1:{}/dns-query via DoH. Query example.com AAAA record.",
            server.port
        ))
        .with_mock(|mock| {
            mock
                // Mock 1: Client startup
                .on_instruction_containing("Connect to")
                .and_instruction_containing("DoH")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_client",
                        "remote_addr": format!("https://127.0.0.1:{}/dns-query", server.port),
                        "protocol": "DoH",
                        "instruction": "Query example.com AAAA record",
                        // NetGet's DoH server is TLS-only and serves a self-signed
                        // certificate, so a client using the system roots cannot reach it
                        // -- the two halves of this codebase could not talk to each other.
                        // Opted into explicitly here rather than the client quietly
                        // accepting any certificate.
                        "startup_params": { "insecure_skip_verify": true }
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2: Client connected
                .on_event("doh_connected")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "query_dns",
                        "domain": "example.com",
                        "record_type": "AAAA"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 3: Client receives response
                .on_event("doh_response_received")
                .and_event_data_contains("query_type", "AAAA")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "wait_for_more"
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let mut client = start_netget_client(client_config).await?;

        // Give client time to connect and query
        server.wait_for_mocks(30).await;

        // Verify client connected
        // `client.protocol` is the name the client was opened with, which is what the
        // registry resolves and what the startup line reports. "DNS-over-HTTPS" is the
        // separate display name `protocol_name()` gives the model; comparing the two can
        // never hold.
        assert_eq!(client.protocol, "DoH", "Client should be DoH protocol");

        println!("✅ DoH client AAAA query test passed");

        // Verify mock expectations
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last response routinely lands
        // after the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        client.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        client.verify_mocks().await?;

        // Cleanup
        server.stop().await?;
        client.stop().await?;

        Ok(())
    }

    /// Test DoH client making multiple queries
    /// LLM calls: 6 (server startup, 2 server queries, client startup, client connected, 2 client queries)
    #[tokio::test]
    async fn test_doh_client_multiple_queries() -> E2EResult<()> {
        // Start a local DoH server with mocks
        let server_config =
            NetGetConfig::new("Listen on port {AVAILABLE_PORT} via DoH. Respond to DNS queries.")
                .with_mock(|mock| {
                    mock
                        // Mock 1: Server startup
                        .on_instruction_containing("Listen")
                        .and_instruction_containing("DoH")
                        .respond_with_actions(serde_json::json!([
                            {
                                "type": "open_server",
                                "port": 0,
                                "base_stack": "DoH",
                                "instruction": "DoH server for multi-query testing"
                            }
                        ]))
                        .expect_calls(1)
                        .and()
                        // Mock 2: Server receives first query (example.com)
                        .on_event("doh_query")
                        .and_event_data_contains("domain", "example.com")
                        .respond_with_actions_from_event(|e| {
                            serde_json::json!([
                                {
                                    "type": "send_dns_a_response",
                                    // The client picks a random DNS id and drops any
                                    // answer that does not carry it back. Omitted, it
                                    // defaults to 0 and the response is discarded.
                                    "query_id": e["query_id"].as_u64().unwrap_or(0),
                                    "domain": "example.com",
                                    "ip": "93.184.216.34",
                                    "ttl": 300
                                }
                            ])
                        })
                        .expect_calls(1)
                        .and()
                        // Mock 3: Server receives second query (example.org)
                        .on_event("doh_query")
                        .and_event_data_contains("domain", "example.org")
                        .respond_with_actions_from_event(|e| {
                            serde_json::json!([
                                {
                                    "type": "send_dns_a_response",
                                    // The client picks a random DNS id and drops any
                                    // answer that does not carry it back. Omitted, it
                                    // defaults to 0 and the response is discarded.
                                    "query_id": e["query_id"].as_u64().unwrap_or(0),
                                    "domain": "example.org",
                                    "ip": "93.184.216.35",
                                    "ttl": 300
                                }
                            ])
                        })
                        .expect_calls(1)
                        .and()
                });

        let mut server = start_netget_server(server_config).await?;

        // Wait for server to start
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Start DoH client with mocks for multiple queries
        let client_config = NetGetConfig::new(format!(
            "Connect to https://127.0.0.1:{}/dns-query via DoH. Query example.com A record, then query example.org A record.",
            server.port
        ))
        .with_mock(|mock| {
            mock
                // Mock 1: Client startup
                .on_instruction_containing("Connect to")
                .and_instruction_containing("DoH")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_client",
                        "remote_addr": format!("https://127.0.0.1:{}/dns-query", server.port),
                        "protocol": "DoH",
                        "instruction": "Query example.com then example.org",
                        // NetGet's DoH server is TLS-only and serves a self-signed
                        // certificate, so a client using the system roots cannot reach it
                        // -- the two halves of this codebase could not talk to each other.
                        // Opted into explicitly here rather than the client quietly
                        // accepting any certificate.
                        "startup_params": { "insecure_skip_verify": true }
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2: Client connected - issue first query
                .on_event("doh_connected")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "query_dns",
                        "domain": "example.com",
                        "record_type": "A"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 3: First response received - issue second query
                .on_event("doh_response_received")
                .and_event_data_contains("domain", "example.com")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "query_dns",
                        "domain": "example.org",
                        "record_type": "A"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 4: Second response received - done
                .on_event("doh_response_received")
                .and_event_data_contains("domain", "example.org")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "wait_for_more"
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let mut client = start_netget_client(client_config).await?;

        // Give client time to make multiple queries
        server.wait_for_mocks(30).await;

        // Verify client is using DNS-over-HTTPS protocol
        assert_eq!(client.protocol, "DoH", "Client should be DoH protocol");

        println!("✅ DoH client made multiple queries successfully");

        // Verify mock expectations
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last response routinely lands
        // after the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        client.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        client.verify_mocks().await?;

        // Cleanup
        server.stop().await?;
        client.stop().await?;

        Ok(())
    }

    /// Test DoH client query different record types (MX)
    /// LLM calls: 4 (server startup, server query, client startup, client query)
    #[tokio::test]
    async fn test_doh_client_mx_record_query() -> E2EResult<()> {
        // Start a local DoH server with mocks
        let server_config =
            NetGetConfig::new("Listen on port {AVAILABLE_PORT} via DoH. Respond to DNS queries.")
                .with_mock(|mock| {
                    mock
                        // Mock 1: Server startup
                        .on_instruction_containing("Listen")
                        .and_instruction_containing("DoH")
                        .respond_with_actions(serde_json::json!([
                            {
                                "type": "open_server",
                                "port": 0,
                                "base_stack": "DoH",
                                "instruction": "DoH server for MX record testing"
                            }
                        ]))
                        .expect_calls(1)
                        .and()
                        // Mock 2: Server receives MX query
                        .on_event("doh_query")
                        .and_event_data_contains("domain", "example.com")
                        .and_event_data_contains("query_type", "MX")
                        .respond_with_actions_from_event(|e| {
                            serde_json::json!([
                                {
                                    "type": "send_dns_mx_response",
                                    // The client picks a random DNS id and drops any
                                    // answer that does not carry it back. Omitted, it
                                    // defaults to 0 and the response is discarded.
                                    "query_id": e["query_id"].as_u64().unwrap_or(0),
                                    "domain": "example.com",
                                    // `exchange`/`preference`, the names the action declares --
                                    // not mail_server/priority. `exchange` is required, so the
                                    // wrong name made the action fail and the server answered
                                    // HTTP 500 "No response generated".
                                    "exchange": "mail.example.com",
                                    "preference": 10,
                                    "ttl": 300
                                }
                            ])
                        })
                        .expect_calls(1)
                        .and()
                });

        let mut server = start_netget_server(server_config).await?;

        // Wait for server to start
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Start DoH client with mocks
        let client_config = NetGetConfig::new(format!(
            "Connect to https://127.0.0.1:{}/dns-query via DoH. Query example.com MX records to find mail servers.",
            server.port
        ))
        .with_mock(|mock| {
            mock
                // Mock 1: Client startup
                .on_instruction_containing("Connect to")
                .and_instruction_containing("DoH")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_client",
                        "remote_addr": format!("https://127.0.0.1:{}/dns-query", server.port),
                        "protocol": "DoH",
                        "instruction": "Query example.com MX records",
                        // NetGet's DoH server is TLS-only and serves a self-signed
                        // certificate, so a client using the system roots cannot reach it
                        // -- the two halves of this codebase could not talk to each other.
                        // Opted into explicitly here rather than the client quietly
                        // accepting any certificate.
                        "startup_params": { "insecure_skip_verify": true }
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2: Client connected
                .on_event("doh_connected")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "query_dns",
                        "domain": "example.com",
                        "record_type": "MX"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 3: Client receives MX response
                .on_event("doh_response_received")
                .and_event_data_contains("query_type", "MX")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "wait_for_more"
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let mut client = start_netget_client(client_config).await?;

        // Give client time to connect and make query
        server.wait_for_mocks(30).await;

        // Verify output shows MX query or mail-related content
        let output = client.get_output().await;
        assert!(
            output.iter().any(|l| l.contains("MX"))
                || output.iter().any(|l| l.contains("mail"))
                || output.iter().any(|l| l.contains("example.com")),
            "Client should show MX query or mail server info. Output: {:?}",
            output
        );

        println!("✅ DoH client queried MX records successfully");

        // Verify mock expectations
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last response routinely lands
        // after the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        client.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        client.verify_mocks().await?;

        // Cleanup
        server.stop().await?;
        client.stop().await?;

        Ok(())
    }
}

//! DoT (DNS over TLS) client E2E tests
//!
//! Tests the DoT client with mock LLM responses
//! to ensure LLM-controlled DNS query functionality works correctly.


use crate::helpers::{E2EResult, NetGetConfig};

/// Test DoT client basic query with mocks
/// LLM calls: 3 (startup, connected event, response event)
#[ignore = "Contacts a real external endpoint. CLAUDE.md requires tests to use localhost only (127.0.0.1/::1) and never reach external services. These were orphaned from tests/client/mod.rs and had never actually run; wiring them in made the calls live. Re-enable by pointing remote_addr at a NetGet server on 127.0.0.1."]
#[tokio::test]
async fn test_dot_client_basic_query() -> E2EResult<()> {
    println!("\n=== E2E Test: DoT Client Basic Query with Mocks ===");

    // Create a DoT client that queries dns.google:853
    let client_config = NetGetConfig::new(
        "Connect to dns.google:853 via DoT. Query example.com A record and show me the IP address.",
    )
    .with_log_level("info")
    .with_mock(|mock| {
        mock
            // Mock 1: Client startup (user command)
            .on_instruction_containing("Connect to")
            .and_instruction_containing("DoT")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_client",
                    "remote_addr": "dns.google:853",
                    "protocol": "DoT",
                    "instruction": "Query example.com A record and show the IP"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 2: Client connected (dot_connected event)
            .on_event("dot_connected")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "send_dns_query",
                    "domain": "example.com",
                    "query_type": "A",
                    "recursive": true
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 3: Response received (dot_response_received event)
            .on_event("dot_response_received")
            .and_event_data_contains("response_code", "NOERROR")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "wait_for_more"
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let mut client = crate::helpers::netget::start_netget(client_config).await?;

    // Give client time to connect and query
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

    // Verify client output shows connection
    client.wait_for_any(&["connected"], 30).await;
    assert!(
        client.output_contains("connected").await,
        "Client should show connection message"
    );

    // Verify query was sent
    client.wait_for_any(&["query", "Query"], 30).await;
    assert!(
        client.output_contains("query").await || client.output_contains("Query").await,
        "Client should show query message"
    );

    println!("✅ DoT client connected and queried DNS successfully");

    // Verify mock expectations were met
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last response routinely lands
    // after the sleep expires, and the test reports it as never having happened.
    client.wait_for_mocks(30).await;
    client.verify_mocks().await?;

    // Cleanup
    client.stop().await?;

    Ok(())
}

/// Test DoT client with multiple queries
/// LLM calls: 5 (startup, connected, 3 responses)
#[ignore = "Contacts a real external endpoint. CLAUDE.md requires tests to use localhost only (127.0.0.1/::1) and never reach external services. These were orphaned from tests/client/mod.rs and had never actually run; wiring them in made the calls live. Re-enable by pointing remote_addr at a NetGet server on 127.0.0.1."]
#[tokio::test]
async fn test_dot_client_multiple_queries() -> E2EResult<()> {
    println!("\n=== E2E Test: DoT Client Multiple Queries with Mocks ===");

    // Create a DoT client that queries multiple record types
    let client_config = NetGetConfig::new(
        "Connect to 1.1.1.1:853 via DoT. Query example.com for A, AAAA, and MX records.",
    )
    .with_log_level("info")
    .with_mock(|mock| {
        mock
            // Mock 1: Client startup
            .on_instruction_containing("Connect to")
            .and_instruction_containing("DoT")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_client",
                    "remote_addr": "1.1.1.1:853",
                    "protocol": "DoT",
                    "instruction": "Query example.com for A, AAAA, and MX records"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 2: Client connected - send A query
            .on_event("dot_connected")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "send_dns_query",
                    "domain": "example.com",
                    "query_type": "A"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 3: A response - send AAAA query
            .on_event("dot_response_received")
            .and_event_data_contains("response_code", "NOERROR")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "send_dns_query",
                    "domain": "example.com",
                    "query_type": "AAAA"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 4: AAAA response - send MX query
            .on_event("dot_response_received")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "send_dns_query",
                    "domain": "example.com",
                    "query_type": "MX"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 5: MX response - done
            .on_event("dot_response_received")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "wait_for_more"
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let mut client = crate::helpers::netget::start_netget(client_config).await?;

    // Give client time for multiple queries
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;

    // Verify multiple queries in output
    let output = client.get_output().await;
    let query_count = output
        .iter()
        .filter(|line| line.contains("query") || line.contains("Query"))
        .count();
    assert!(query_count >= 3, "Should have at least 3 queries in output");

    println!("✅ DoT client sent multiple queries successfully");

    // Verify mock expectations
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last response routinely lands
    // after the sleep expires, and the test reports it as never having happened.
    client.wait_for_mocks(30).await;
    client.verify_mocks().await?;

    // Cleanup
    client.stop().await?;

    Ok(())
}

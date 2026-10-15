//! E2E tests for DNS protocol examples
//!
//! These tests verify that DNS protocol examples work correctly:
//! - StartupExamples (llm_mode, script_mode, static_mode) start servers
//! - EventType response_examples execute correctly with dynamic correlation ID matching
//! - DNS query/response cycle works properly
//!
//! CRITICAL: DNS uses UDP and requires transaction ID (query_id) matching.
//! Responses must use the same query_id as the request, or clients will time out.
//! Tests use `respond_with_actions_from_event()` to dynamically extract the query_id.

use crate::helpers::{start_netget_server, E2EResult, NetGetConfig};
use hickory_client::client::{AsyncClient, ClientHandle};
use hickory_client::rr::{DNSClass, Name, RecordType};
use hickory_client::udp::UdpClientStream;
use serde_json::json;
use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Duration;

/// Test DNS protocol response_example for dns_query event (A record)
///
/// This test verifies that the dns_query response_example works correctly.
/// Uses dynamic correlation ID matching to ensure query_id matches.
///
/// Response example from protocol:
/// {"type": "send_dns_a_response", "query_id": 12345, "domain": "example.com", "ip": "93.184.216.34", "ttl": 300}
#[tokio::test]
async fn example_test_dns_query_a_record() -> E2EResult<()> {
    println!("\n=== E2E Example Test: DNS dns_query (A Record) ===");

    let config = NetGetConfig::new("Start a DNS server on port 0")
        .with_log_level("debug")
        .with_mock(|mock| {
            mock
                // Mock 1: Server startup
                .on_instruction_containing("Start a DNS server")
                .respond_with_actions(json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "DNS",
                    "instruction": "Respond to A record queries with 93.184.216.34"
                }]))
                .expect_calls(1)
                .and()
                // Mock 2: DNS query event with DYNAMIC query_id matching
                // This is the response_example from the protocol, but with dynamic query_id
                .on_event("dns_query")
                .and_event_data_contains("query_type", "A")
                .respond_with_actions_from_event(|event_data| {
                    // Extract query_id from event (CRITICAL for UDP correlation)
                    let query_id = event_data["query_id"].as_u64().unwrap_or(0);

                    // Use the response_example format but with dynamic query_id
                    json!([{
                        "type": "send_dns_a_response",
                        "query_id": query_id,
                        "domain": "example.com",
                        "ip": "93.184.216.34",
                        "ttl": 300
                    }])
                })
                .expect_calls(1)
                .and()
        });

    let server = start_netget_server(config).await?;
    let port = server.port;
    println!("DNS server started on port {}", port);

    // Wait for server to be ready
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Query using hickory-client
    let address: SocketAddr = format!("127.0.0.1:{}", port).parse()?;
    let stream = UdpClientStream::<tokio::net::UdpSocket>::new(address);
    let (mut client, bg) = AsyncClient::connect(stream).await?;
    tokio::spawn(bg);

    // Query for example.com A record
    let name = Name::from_str("example.com.")?;
    let response = client.query(name, DNSClass::IN, RecordType::A).await?;

    println!("DNS response received:");
    let answers = response.answers();
    assert!(
        !answers.is_empty(),
        "Expected at least one A record in response"
    );

    for record in answers {
        println!("  Record: {:?}", record);
    }

    println!(
        "✓ dns_query response_example executed correctly with {} answers",
        answers.len()
    );

    // Verify mock expectations
    server.verify_mocks().await?;

    server.stop().await?;
    println!("=== Test completed ===\n");
    Ok(())
}

/// Test DNS protocol response_example for TXT record queries
///
/// Verifies that TXT record responses work correctly.
#[tokio::test]
async fn example_test_dns_query_txt_record() -> E2EResult<()> {
    println!("\n=== E2E Example Test: DNS dns_query (TXT Record) ===");

    let config = NetGetConfig::new("Start a DNS server on port 0")
        .with_log_level("debug")
        .with_mock(|mock| {
            mock
                // Mock 1: Server startup
                .on_instruction_containing("Start a DNS server")
                .respond_with_actions(json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "DNS",
                    "instruction": "Respond to TXT queries with SPF record"
                }]))
                .expect_calls(1)
                .and()
                // Mock 2: TXT query with dynamic query_id
                .on_event("dns_query")
                .and_event_data_contains("query_type", "TXT")
                .respond_with_actions_from_event(|event_data| {
                    let query_id = event_data["query_id"].as_u64().unwrap_or(0);

                    json!([{
                        "type": "send_dns_txt_response",
                        "query_id": query_id,
                        "domain": "example.com",
                        "text": "v=spf1 include:_spf.example.com ~all",
                        "ttl": 300
                    }])
                })
                .expect_calls(1)
                .and()
        });

    let server = start_netget_server(config).await?;
    let port = server.port;
    println!("DNS server started on port {}", port);

    tokio::time::sleep(Duration::from_millis(500)).await;

    // Query using hickory-client
    let address: SocketAddr = format!("127.0.0.1:{}", port).parse()?;
    let stream = UdpClientStream::<tokio::net::UdpSocket>::new(address);
    let (mut client, bg) = AsyncClient::connect(stream).await?;
    tokio::spawn(bg);

    let name = Name::from_str("example.com.")?;
    let response = client.query(name, DNSClass::IN, RecordType::TXT).await?;

    println!("DNS TXT response received:");
    let answers = response.answers();
    assert!(!answers.is_empty(), "Expected TXT record in response");

    for record in answers {
        println!("  TXT Record: {:?}", record);
    }

    println!("✓ DNS TXT response_example executed correctly");

    server.verify_mocks().await?;
    server.stop().await?;

    println!("=== Test completed ===\n");
    Ok(())
}

/// Test DNS protocol startup examples (llm_mode)
///
/// Verifies that the LLM mode startup example starts a DNS server correctly.
#[tokio::test]
async fn example_test_dns_startup_llm_mode() -> E2EResult<()> {
    println!("\n=== E2E Example Test: DNS Startup (LLM Mode) ===");

    let config = NetGetConfig::new("Start a DNS server on port 0")
        .with_log_level("debug")
        .with_mock(|mock| {
            mock.on_instruction_containing("Start a DNS server")
                .respond_with_actions(json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "DNS",
                    "instruction": "Respond to all A queries with 1.2.3.4"
                }]))
                .and()
                .on_event("dns_query")
                .respond_with_actions_from_event(|event_data| {
                    let query_id = event_data["query_id"].as_u64().unwrap_or(0);
                    json!([{
                        "type": "send_dns_a_response",
                        "query_id": query_id,
                        "domain": "test.example.com",
                        "ip": "1.2.3.4",
                        "ttl": 60
                    }])
                })
                .and()
        });

    let server = start_netget_server(config).await?;
    let port = server.port;

    assert!(port > 0, "Server should have started on a port");
    println!(
        "✓ DNS server started successfully on port {} using LLM mode",
        port
    );

    // Verify by making a query
    let address: SocketAddr = format!("127.0.0.1:{}", port).parse()?;
    let stream = UdpClientStream::<tokio::net::UdpSocket>::new(address);
    let (mut client, bg) = AsyncClient::connect(stream).await?;
    tokio::spawn(bg);

    let name = Name::from_str("test.example.com.")?;
    let response = client.query(name, DNSClass::IN, RecordType::A).await?;
    assert!(!response.answers().is_empty(), "Should get DNS response");

    println!("✓ DNS query succeeded");

    server.verify_mocks().await?;
    server.stop().await?;

    println!("=== Test completed ===\n");
    Ok(())
}

/// Test DNS with multiple query types
///
/// Verifies that a DNS server can handle multiple different query types.
#[tokio::test]
async fn example_test_dns_multiple_query_types() -> E2EResult<()> {
    println!("\n=== E2E Example Test: DNS Multiple Query Types ===");

    let config = NetGetConfig::new("Start a DNS server on port 0")
        .with_log_level("debug")
        .with_mock(|mock| {
            mock
                // Server startup
                .on_instruction_containing("Start a DNS server")
                .respond_with_actions(json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "DNS",
                    "instruction": "Handle multiple record types"
                }]))
                .and()
                // Handle any DNS query with appropriate response
                .on_event("dns_query")
                .respond_with_actions_from_event(|event_data| {
                    let query_id = event_data["query_id"].as_u64().unwrap_or(0);
                    let query_type = event_data["query_type"].as_str().unwrap_or("A");
                    let domain = event_data["domain"].as_str().unwrap_or("example.com");

                    match query_type {
                        "TXT" => json!([{
                            "type": "send_dns_txt_response",
                            "query_id": query_id,
                            "domain": domain,
                            "text": "test txt record",
                            "ttl": 300
                        }]),
                        "MX" => json!([{
                            "type": "send_dns_mx_response",
                            "query_id": query_id,
                            "domain": domain,
                            "exchange": "mail.example.com",
                            "preference": 10,
                            "ttl": 300
                        }]),
                        _ => json!([{
                            "type": "send_dns_a_response",
                            "query_id": query_id,
                            "domain": domain,
                            "ip": "93.184.216.34",
                            "ttl": 300
                        }]),
                    }
                })
                .and()
        });

    let server = start_netget_server(config).await?;
    let port = server.port;
    println!("DNS server started on port {}", port);

    tokio::time::sleep(Duration::from_millis(500)).await;

    let address: SocketAddr = format!("127.0.0.1:{}", port).parse()?;
    let stream = UdpClientStream::<tokio::net::UdpSocket>::new(address);
    let (mut client, bg) = AsyncClient::connect(stream).await?;
    tokio::spawn(bg);

    // Test A record
    let name = Name::from_str("example.com.")?;
    let response = client
        .query(name.clone(), DNSClass::IN, RecordType::A)
        .await?;
    assert!(!response.answers().is_empty(), "Expected A record response");
    println!("✓ A record query succeeded");

    // Test TXT record (need new connection for hickory-client)
    let stream2 = UdpClientStream::<tokio::net::UdpSocket>::new(address);
    let (mut client2, bg2) = AsyncClient::connect(stream2).await?;
    tokio::spawn(bg2);

    let response2 = client2.query(name, DNSClass::IN, RecordType::TXT).await?;
    assert!(
        !response2.answers().is_empty(),
        "Expected TXT record response"
    );
    println!("✓ TXT record query succeeded");

    server.verify_mocks().await?;
    server.stop().await?;

    println!("=== Test completed ===\n");
    Ok(())
}

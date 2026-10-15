//! End-to-end DNS tests for NetGet
//!
//! These tests spawn the actual NetGet binary with DNS prompts
//! and validate the responses using the hickory-client DNS client library.


// Helper module imported from parent

use super::super::super::helpers::{self, E2EResult, NetGetConfig};
use hickory_client::client::{AsyncClient, ClientHandle};
use hickory_client::op::ResponseCode;
use hickory_client::rr::{DNSClass, Name, RData, RecordType};
use hickory_client::udp::UdpClientStream;
use std::net::{Ipv4Addr, SocketAddr};
use std::str::FromStr;

/// The single A record in a reply's answer section, as an address.
///
/// `None` when the answer section does not hold exactly one A record — which must fail the
/// test rather than pass quietly. `assert!(!answers.is_empty())` was the previous bar, and it
/// passes for an executor that ignores the `ip` it was given.
fn answer_a(response: &hickory_client::op::DnsResponse) -> Option<Ipv4Addr> {
    let answers = response.answers();
    if answers.len() != 1 {
        return None;
    }
    match answers[0].data() {
        Some(RData::A(addr)) => Some(addr.0),
        _ => None,
    }
}

#[tokio::test]
async fn test_dns_a_record_query() -> E2EResult<()> {
    println!("\n=== E2E Test: DNS A Record Query ===");

    // PROMPT: Tell the LLM to act as a DNS server with mocks
    let prompt = "listen on port {AVAILABLE_PORT} via dns. Respond to all A record queries for example.com with IP address 93.184.216.34";

    let server_config = NetGetConfig::new(prompt)
        .with_log_level("debug")
        .with_mock(|mock| {
            mock
                // Mock 1: Server startup (user command)
                .on_instruction_containing("listen on port")
                .and_instruction_containing("dns")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "DNS",
                        "instruction": "Respond to all A record queries for example.com with IP address 93.184.216.34"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2: DNS query received (dns_query event) - DYNAMIC RESPONSE
                .on_event("dns_query")
                .and_event_data_contains("domain", "example.com")
                .and_event_data_contains("query_type", "A")
                .respond_with_actions_from_event(|event_data| {
                    // Extract query_id from event (transaction ID must match request)
                    let query_id = event_data["query_id"].as_u64().unwrap_or(0);

                    serde_json::json!([{
                        "type": "send_dns_a_response",
                        "query_id": query_id,  // ← DYNAMIC from event!
                        "domain": "example.com",
                        "ip": "93.184.216.34",
                        "ttl": 300
                    }])
                })
                .expect_calls(1)
                .and()
        });

    // Start the server
    let server = helpers::start_netget_server(server_config).await?;
    println!("DNS server started on port {}", server.port);

    // Wait on the server's own readiness line, not a fixed sleep.
    //
    // `start_netget_server` returns when startup has been *parsed*; the UDP socket may not be
    // bound for a moment longer, and a datagram to an unbound local port draws an ICMP port
    // unreachable rather than being queued. 500ms was usually enough and is not a guarantee
    // under `--test-threads=100`.
    server
        .wait_for_log("DNS server listening on", 20)
        .await
        .map_err(|e| format!("DNS server never reported a listening socket: {e}"))?;

    // VALIDATION: Use hickory-client to query DNS
    println!("Querying example.com A record...");

    let address: SocketAddr = format!("127.0.0.1:{}", server.port).parse()?;
    let stream = UdpClientStream::<tokio::net::UdpSocket>::new(address);
    let (mut client, bg) = AsyncClient::connect(stream).await?;

    // Run the background task
    tokio::spawn(bg);

    // Query for example.com A record
    let name = Name::from_str("example.com.")?;
    let response = client.query(name, DNSClass::IN, RecordType::A).await?;

    println!("DNS response received:");
    assert_eq!(
        answer_a(&response),
        Some("93.184.216.34".parse::<Ipv4Addr>().unwrap()),
        "example.com must resolve to the address its handler chose; got {:?}",
        response.answers()
    );
    assert_eq!(
        response.response_code(),
        ResponseCode::NoError,
        "a successful A answer must carry RCODE 0"
    );

    println!("✓ DNS A record query returned 93.184.216.34");

    // Verify mock expectations were met
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;

    server.stop().await?;
    println!("=== Test completed ===\n");
    Ok(())
}

#[tokio::test]
async fn test_dns_multiple_records() -> E2EResult<()> {
    println!("\n=== E2E Test: DNS Multiple Records ===");

    // PROMPT: Tell the LLM to handle multiple record types
    let prompt = "listen on port {AVAILABLE_PORT} via dns. For example.com A records return 1.2.3.4. For mail.example.com A records return 5.6.7.8";

    let server_config = NetGetConfig::new(prompt)
        .with_log_level("debug")
        .with_mock(|mock| {
            mock
                // Mock 1: Query for mail.example.com - MUST BE FIRST (most specific, avoids substring match)
                .on_event("dns_query")
                .and_event_data_contains("domain", "mail.example.com.")
                .and_event_data_contains("query_type", "A")
                .respond_with_actions_from_event(|event_data| {
                    let query_id = event_data["query_id"].as_u64().unwrap_or(0);
                    serde_json::json!([{
                        "type": "send_dns_a_response",
                        "query_id": query_id,
                        "domain": "mail.example.com",
                        "ip": "5.6.7.8",
                        "ttl": 300
                    }])
                })
                .expect_calls(1)
                .and()
                // Mock 2: Query for example.com - MUST BE SECOND (less specific)
                .on_event("dns_query")
                .and_event_data_contains("domain", "example.com.")
                .and_event_data_contains("query_type", "A")
                .respond_with_actions_from_event(|event_data| {
                    let query_id = event_data["query_id"].as_u64().unwrap_or(0);
                    serde_json::json!([{
                        "type": "send_dns_a_response",
                        "query_id": query_id,
                        "domain": "example.com",
                        "ip": "1.2.3.4",
                        "ttl": 300
                    }])
                })
                .expect_calls(1)
                .and()
                // Mock 3: Server startup (user command) - MUST BE LAST (less specific)
                .on_instruction_containing("listen on port")
                .and_instruction_containing("dns")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "DNS",
                        "instruction": "For example.com A records return 1.2.3.4. For mail.example.com A records return 5.6.7.8"
                    }
                ]))
                .expect_calls(1)
                .and()
        });

    // Start the server
    let server = helpers::start_netget_server(server_config).await?;
    println!("DNS server started on port {}", server.port);

    // Wait on the server's own readiness line, not a fixed sleep.
    //
    // `start_netget_server` returns when startup has been *parsed*; the UDP socket may not be
    // bound for a moment longer, and a datagram to an unbound local port draws an ICMP port
    // unreachable rather than being queued. 500ms was usually enough and is not a guarantee
    // under `--test-threads=100`.
    server
        .wait_for_log("DNS server listening on", 20)
        .await
        .map_err(|e| format!("DNS server never reported a listening socket: {e}"))?;

    // VALIDATION: Query multiple domains
    let address: SocketAddr = format!("127.0.0.1:{}", server.port).parse()?;
    let stream = UdpClientStream::<tokio::net::UdpSocket>::new(address);
    let (mut client, bg) = AsyncClient::connect(stream).await?;
    tokio::spawn(bg);

    // Query example.com
    println!("Querying example.com...");
    let name1 = Name::from_str("example.com.")?;
    let response1 = client.query(name1, DNSClass::IN, RecordType::A).await?;
    // The two domains answer with different addresses, so a reply routed to the wrong
    // question is visible here. Asserting only that *some* record came back could not
    // tell the two apart.
    assert_eq!(
        answer_a(&response1),
        Some("1.2.3.4".parse::<Ipv4Addr>().unwrap()),
        "example.com must resolve to 1.2.3.4; got {:?}",
        response1.answers()
    );
    println!("  ✓ example.com returned 1.2.3.4");

    // Query mail.example.com
    println!("Querying mail.example.com...");
    let name2 = Name::from_str("mail.example.com.")?;
    let response2 = client.query(name2, DNSClass::IN, RecordType::A).await?;
    assert_eq!(
        answer_a(&response2),
        Some("5.6.7.8".parse::<Ipv4Addr>().unwrap()),
        "mail.example.com must resolve to its own address, not example.com's; got {:?}",
        response2.answers()
    );
    println!("  ✓ mail.example.com returned 5.6.7.8");

    // Verify mock expectations were met
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;

    server.stop().await?;
    println!("=== Test completed ===\n");
    Ok(())
}

#[tokio::test]
async fn test_dns_txt_record() -> E2EResult<()> {
    println!("\n=== E2E Test: DNS TXT Record ===");

    // PROMPT: Tell the LLM to handle TXT records
    let prompt = "listen on port {AVAILABLE_PORT} via dns. For TXT record queries on example.com, return 'v=spf1 include:_spf.example.com ~all'";

    let server_config = NetGetConfig::new(prompt)
        .with_log_level("debug")
        .with_mock(|mock| {
            mock
                // Mock 1: Server startup (user command)
                .on_instruction_containing("listen on port")
                .and_instruction_containing("dns")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "DNS",
                        "instruction": "For TXT record queries on example.com, return 'v=spf1 include:_spf.example.com ~all'"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2: Query for TXT record - DYNAMIC RESPONSE
                .on_event("dns_query")
                .and_event_data_contains("domain", "example.com")
                .and_event_data_contains("query_type", "TXT")
                .respond_with_actions_from_event(|event_data| {
                    let query_id = event_data["query_id"].as_u64().unwrap_or(0);
                    serde_json::json!([{
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

    // Start the server
    let server = helpers::start_netget_server(server_config).await?;
    println!("DNS server started on port {}", server.port);

    // Wait on the server's own readiness line, not a fixed sleep.
    //
    // `start_netget_server` returns when startup has been *parsed*; the UDP socket may not be
    // bound for a moment longer, and a datagram to an unbound local port draws an ICMP port
    // unreachable rather than being queued. 500ms was usually enough and is not a guarantee
    // under `--test-threads=100`.
    server
        .wait_for_log("DNS server listening on", 20)
        .await
        .map_err(|e| format!("DNS server never reported a listening socket: {e}"))?;

    // VALIDATION: Query TXT record
    let address: SocketAddr = format!("127.0.0.1:{}", server.port).parse()?;
    let stream = UdpClientStream::<tokio::net::UdpSocket>::new(address);
    let (mut client, bg) = AsyncClient::connect(stream).await?;
    tokio::spawn(bg);

    println!("Querying example.com TXT record...");
    let name = Name::from_str("example.com.")?;
    let response = client.query(name, DNSClass::IN, RecordType::TXT).await?;

    println!("DNS TXT response received:");
    let answers = response.answers();
    assert_eq!(answers.len(), 1, "Expected exactly one TXT record");

    let txt = match answers[0].data() {
        Some(RData::TXT(txt)) => txt
            .iter()
            .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
            .collect::<String>(),
        other => panic!("expected a TXT record in the answer section, got {other:?}"),
    };
    assert_eq!(
        txt, "v=spf1 include:_spf.example.com ~all",
        "the TXT record must carry the text the handler chose"
    );

    println!("✓ DNS TXT record returned the expected text");

    // Verify mock expectations were met
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;

    server.stop().await?;
    println!("=== Test completed ===\n");
    Ok(())
}

#[tokio::test]
async fn test_dns_nxdomain() -> E2EResult<()> {
    println!("\n=== E2E Test: DNS NXDOMAIN Response ===");

    // PROMPT: Tell the LLM to return NXDOMAIN for unknown domains
    let prompt = "listen on port {AVAILABLE_PORT} via dns. Only respond with A records for known.example.com (1.2.3.4). For all other domains, return NXDOMAIN";

    let server_config = NetGetConfig::new(prompt)
        .with_log_level("debug")
        .with_mock(|mock| {
            mock
                // Mock 1: Server startup (user command)
                .on_instruction_containing("listen on port")
                .and_instruction_containing("dns")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "DNS",
                        "instruction": "Only respond with A records for known.example.com (1.2.3.4). For all other domains, return NXDOMAIN"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2: Query for unknown domain - return NXDOMAIN - DYNAMIC RESPONSE
                .on_event("dns_query")
                .and_event_data_contains("domain", "unknown.example.com")
                .and_event_data_contains("query_type", "A")
                .respond_with_actions_from_event(|event_data| {
                    let query_id = event_data["query_id"].as_u64().unwrap_or(0);
                    serde_json::json!([{
                        "type": "send_dns_nxdomain",
                        "query_id": query_id,
                        "domain": "unknown.example.com"
                    }])
                })
                .expect_calls(1)
                .and()
        });

    // Start the server
    let server = helpers::start_netget_server(server_config).await?;
    println!("DNS server started on port {}", server.port);

    // Wait on the server's own readiness line, not a fixed sleep.
    //
    // `start_netget_server` returns when startup has been *parsed*; the UDP socket may not be
    // bound for a moment longer, and a datagram to an unbound local port draws an ICMP port
    // unreachable rather than being queued. 500ms was usually enough and is not a guarantee
    // under `--test-threads=100`.
    server
        .wait_for_log("DNS server listening on", 20)
        .await
        .map_err(|e| format!("DNS server never reported a listening socket: {e}"))?;

    // VALIDATION: Query an unknown domain
    let address: SocketAddr = format!("127.0.0.1:{}", server.port).parse()?;
    let stream = UdpClientStream::<tokio::net::UdpSocket>::new(address);
    let (mut client, bg) = AsyncClient::connect(stream).await?;
    tokio::spawn(bg);

    println!("Querying unknown.example.com, which the handler answers with NXDOMAIN...");
    let name = Name::from_str("unknown.example.com.")?;

    // This is the assertion the test exists for, and it was missing: the old version
    // matched on `Ok`/`Err` and printed "implementation-dependent behavior" in one arm and
    // "server indicated domain not found" in the other, so *every* outcome passed —
    // including NOERROR with an empty answer section, which means the opposite of NXDOMAIN
    // to a resolver. Nothing about this is implementation-dependent: the mock forces
    // `send_dns_nxdomain`, so RCODE 3 is the only correct answer.
    let response = client
        .query(name.clone(), DNSClass::IN, RecordType::A)
        .await?;

    assert_eq!(
        response.response_code(),
        ResponseCode::NXDomain,
        "send_dns_nxdomain must set RCODE 3; got {:?} with {} answers",
        response.response_code(),
        response.answers().len()
    );
    assert!(
        response.answers().is_empty(),
        "NXDOMAIN carries no answer records; got {:?}",
        response.answers()
    );
    // With no answer section, the echoed question is the only thing tying this reply to
    // the query — a resolver discards it otherwise.
    assert_eq!(
        response.queries().len(),
        1,
        "the reply must echo exactly one question"
    );
    assert_eq!(
        response.queries()[0].name(),
        &name,
        "the reply must echo the queried name"
    );
    assert_eq!(
        response.queries()[0].query_type(),
        RecordType::A,
        "send_dns_nxdomain defaults query_type to A, which is what was asked"
    );
    println!("  ✓ NXDOMAIN (RCODE 3), no answers, question echoed");

    // Verify mock expectations were met
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;

    server.stop().await?;
    println!("=== Test completed ===\n");
    Ok(())
}

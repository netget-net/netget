//! E2E tests for DNS client
//!
//! These drive the NetGet DNS **client** against a NetGet DNS **server** started in the same
//! test, both mocked. No external network.
//!
//! They previously queried 8.8.8.8 and 1.1.1.1 and slept 3-5 seconds hoping for an answer.
//! That broke CLAUDE.md's rule ("Bind to localhost only (127.0.0.1 / ::1); never contact
//! external endpoints") and made them genuinely flaky: three identical runs at one commit
//! produced 1, 2 and 3 passes. The `dns_response_received` rule expects one call and gets none
//! whenever the public resolver does not answer inside the sleep, so the failure presented as a
//! product bug and was twice diagnosed as a pre-existing regression before being measured.
//! This suite's own CLAUDE.md had listed the dependency as a known issue with "add a local DNS
//! server" as future work.
//!
//! Two things to keep in mind when editing these:
//!
//! * The **server** mock must echo `query_id` back via `respond_with_actions_from_event`. DNS
//!   transaction IDs are random per query, so a hardcoded id makes the client discard the reply
//!   and time out — the trap documented in `tests/server/dns/CLAUDE.md`.
//! * `and_event_data_contains` is a **substring** match and the first matching rule wins, so a
//!   rule keyed on `"A"` also matches `"AAAA"`. Declare the AAAA rule first. This exact
//!   ordering bug once looped the client into a stack overflow (IMPROVEMENTS.md item 49).
//!
//! `dns_response_received` firing is the real assertion in every test here: it can only happen
//! if a reply actually arrived and parsed.

mod dns_client_tests {
    use crate::helpers::*;
    use std::time::Duration;

    /// Build the client half: connect, send one query on connect, count the replies.
    fn querying_client(
        remote: String,
        domain: &'static str,
        query_type: &'static str,
    ) -> NetGetConfig {
        NetGetConfig::new(format!(
            "Connect to {remote} via DNS. Query {query_type} records for {domain}."
        ))
        .with_mock(move |mock| {
            mock.on_instruction_containing("Connect to")
                .and_instruction_containing("DNS")
                .respond_with_actions(serde_json::json!([{
                    "type": "open_client",
                    "remote_addr": remote,
                    "protocol": "DNS",
                    "instruction": format!("Query {query_type} records for {domain}")
                }]))
                .expect_calls(1)
                .and()
                .on_event("dns_connected")
                .respond_with_actions(serde_json::json!([{
                    "type": "send_dns_query",
                    "domain": domain,
                    "query_type": query_type,
                    "recursion_desired": true
                }]))
                .expect_calls(1)
                .and()
                .on_event("dns_response_received")
                .respond_with_actions(serde_json::json!([{"type": "wait_for_more"}]))
                .expect_calls(1)
                .and()
        })
    }

    #[tokio::test]
    async fn test_dns_client_a_record_query() -> E2EResult<()> {
        let server_config = NetGetConfig::new(
            "listen on port {AVAILABLE_PORT} via dns. Answer A queries for example.com.",
        )
        .with_mock(|mock| {
            mock.on_instruction_containing("listen on port")
                .and_instruction_containing("dns")
                .respond_with_actions(serde_json::json!([{
                    "type": "open_server", "port": 0, "base_stack": "DNS",
                    "instruction": "Answer A queries for example.com with 93.184.216.34"
                }]))
                .expect_calls(1)
                .and()
                .on_event("dns_query")
                .and_event_data_contains("domain", "example.com")
                .respond_with_actions_from_event(|e| {
                    serde_json::json!([{
                        "type": "send_dns_a_response",
                        "query_id": e["query_id"].as_u64().unwrap_or(0), // must be dynamic
                        "domain": "example.com", "ip": "93.184.216.34", "ttl": 300
                    }])
                })
                .expect_calls(1)
                .and()
        });

        let mut server = start_netget_server(server_config).await?;
        tokio::time::sleep(Duration::from_millis(500)).await;

        let mut client = start_netget_client(querying_client(
            format!("127.0.0.1:{}", server.port),
            "example.com",
            "A",
        ))
        .await?;

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
        Ok(())
    }

    /// A different record type, end to end.
    #[tokio::test]
    async fn test_dns_client_mx_record_query() -> E2EResult<()> {
        let server_config = NetGetConfig::new(
            "listen on port {AVAILABLE_PORT} via dns. Answer MX queries for example.com.",
        )
        .with_mock(|mock| {
            mock.on_instruction_containing("listen on port")
                .and_instruction_containing("dns")
                .respond_with_actions(serde_json::json!([{
                    "type": "open_server", "port": 0, "base_stack": "DNS",
                    "instruction": "Answer MX queries for example.com"
                }]))
                .expect_calls(1)
                .and()
                .on_event("dns_query")
                .and_event_data_contains("domain", "example.com")
                .respond_with_actions_from_event(|e| {
                    serde_json::json!([{
                        "type": "send_dns_mx_response",
                        "query_id": e["query_id"].as_u64().unwrap_or(0),
                        "domain": "example.com",
                        // Flat fields, not a mail_servers array: see the action definition in
                        // src/server/dns/actions.rs. One MX record per action.
                        "exchange": "mail.example.com",
                        "preference": 10,
                        "ttl": 300
                    }])
                })
                .expect_calls(1)
                .and()
        });

        let mut server = start_netget_server(server_config).await?;
        tokio::time::sleep(Duration::from_millis(500)).await;

        let mut client = start_netget_client(querying_client(
            format!("127.0.0.1:{}", server.port),
            "example.com",
            "MX",
        ))
        .await?;

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
        Ok(())
    }

    /// A negative answer must reach the client as a parsed response, not a timeout.
    #[tokio::test]
    async fn test_dns_client_nxdomain() -> E2EResult<()> {
        let server_config = NetGetConfig::new(
            "listen on port {AVAILABLE_PORT} via dns. Return NXDOMAIN for unknown names.",
        )
        .with_mock(|mock| {
            mock.on_instruction_containing("listen on port")
                .and_instruction_containing("dns")
                .respond_with_actions(serde_json::json!([{
                    "type": "open_server", "port": 0, "base_stack": "DNS",
                    "instruction": "Return NXDOMAIN for every query"
                }]))
                .expect_calls(1)
                .and()
                .on_event("dns_query")
                .respond_with_actions_from_event(|e| {
                    serde_json::json!([{
                        "type": "send_dns_nxdomain",
                        "query_id": e["query_id"].as_u64().unwrap_or(0),
                        "domain": e["domain"].as_str().unwrap_or("nonexistent.invalid")
                    }])
                })
                .expect_calls(1)
                .and()
        });

        let mut server = start_netget_server(server_config).await?;
        tokio::time::sleep(Duration::from_millis(500)).await;

        // .invalid is reserved by RFC 2606 and can never resolve, so this cannot accidentally
        // depend on a real resolver if the remote address is ever changed back.
        let mut client = start_netget_client(querying_client(
            format!("127.0.0.1:{}", server.port),
            "nonexistent-domain-12345-xyz.invalid",
            "A",
        ))
        .await?;

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
        Ok(())
    }

    /// Two record types on one client, proving the socket survives a completed exchange.
    ///
    /// Both queries are issued from `dns_connected` rather than chaining the second off the
    /// first response. Chaining is what made this test recurse: the response rule keyed on
    /// `"A"` also matched the `"AAAA"` reply, so the client answered every response by sending
    /// another query — 211 LLM calls and a stack overflow. Issuing both up front removes the
    /// ambiguity entirely; the server rules are still ordered AAAA-first as a second guard.
    #[tokio::test]
    async fn test_dns_client_multiple_queries() -> E2EResult<()> {
        let server_config = NetGetConfig::new(
            "listen on port {AVAILABLE_PORT} via dns. Answer A and AAAA queries for example.com.",
        )
        .with_mock(|mock| {
            mock.on_instruction_containing("listen on port")
                .and_instruction_containing("dns")
                .respond_with_actions(serde_json::json!([{
                    "type": "open_server", "port": 0, "base_stack": "DNS",
                    "instruction": "Answer A and AAAA queries for example.com"
                }]))
                .expect_calls(1)
                .and()
                // AAAA first: "A" is a substring of "AAAA" and the first matching rule wins.
                .on_event("dns_query")
                .and_event_data_contains("query_type", "AAAA")
                .respond_with_actions_from_event(|e| {
                    serde_json::json!([{
                        "type": "send_dns_aaaa_response",
                        "query_id": e["query_id"].as_u64().unwrap_or(0),
                        "domain": "example.com",
                        "ip": "2606:2800:220:1:248:1893:25c8:1946",
                        "ttl": 300
                    }])
                })
                .expect_calls(1)
                .and()
                .on_event("dns_query")
                .and_event_data_contains("query_type", "A")
                .respond_with_actions_from_event(|e| {
                    serde_json::json!([{
                        "type": "send_dns_a_response",
                        "query_id": e["query_id"].as_u64().unwrap_or(0),
                        "domain": "example.com", "ip": "93.184.216.34", "ttl": 300
                    }])
                })
                .expect_calls(1)
                .and()
        });

        let mut server = start_netget_server(server_config).await?;
        tokio::time::sleep(Duration::from_millis(500)).await;

        let remote = format!("127.0.0.1:{}", server.port);
        let client_config = NetGetConfig::new(format!(
            "Connect to {remote} via DNS. Query A and AAAA records for example.com."
        ))
        .with_mock(move |mock| {
            mock.on_instruction_containing("Connect to")
                .and_instruction_containing("DNS")
                .respond_with_actions(serde_json::json!([{
                    "type": "open_client", "remote_addr": remote, "protocol": "DNS",
                    "instruction": "Query A and AAAA records for example.com"
                }]))
                .expect_calls(1)
                .and()
                .on_event("dns_connected")
                .respond_with_actions(serde_json::json!([
                    {"type": "send_dns_query", "domain": "example.com",
                     "query_type": "A", "recursion_desired": true},
                    {"type": "send_dns_query", "domain": "example.com",
                     "query_type": "AAAA", "recursion_desired": true}
                ]))
                .expect_calls(1)
                .and()
                // Two replies, neither of which sends anything further.
                .on_event("dns_response_received")
                .respond_with_actions(serde_json::json!([{"type": "wait_for_more"}]))
                .expect_calls(2)
                .and()
        });

        let mut client = start_netget_client(client_config).await?;

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
        Ok(())
    }
}

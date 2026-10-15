//! End-to-end DNS-over-HTTPS (DoH) tests for NetGet
//!
//! This test spawns a single NetGet DoH server with a Python script
//! and validates multiple query types against the same server instance.

use super::super::super::helpers::{self, E2EResult};
use hickory_proto::op::{Message as DnsMessage, Query};
use hickory_proto::rr::{Name, RecordType};
use reqwest::Client;
use std::str::FromStr;
use std::time::Duration;

/// Assert a DoH reply correlates with the query that produced it.
///
/// Both helpers below used to leave the transaction id at `DnsMessage::new()`'s default of
/// 0 and never look at it again, so a server that answered with the wrong id — or with no
/// question section — looked identical to one that answered correctly. That is exactly the
/// defect `tests/server/dot/e2e_test.rs` found and fixed in its own client, and DoH still
/// had it. RFC 8484 carries an ordinary RFC 1035 message, so the same two checks apply:
/// the id a resolver chose must come back, and the question it asked must be repeated.
fn assert_correlates(response: &DnsMessage, query_id: u16, name: &Name) {
    assert_eq!(
        response.id(),
        query_id,
        "DoH reply carried transaction id {} but the query used {query_id}; \
         a resolver would discard this reply",
        response.id()
    );
    assert_eq!(
        response.queries().len(),
        1,
        "reply must echo exactly one question"
    );
    assert_eq!(
        response.queries()[0].name(),
        name,
        "reply must echo the queried name"
    );
}

/// The single A record in a reply's answer section, as an address.
///
/// `None` when the answer section does not hold exactly one A record, which must fail the
/// test rather than pass quietly — `!answers.is_empty()` passes for an executor that
/// ignores the `ip` it was handed.
fn answer_a(response: &DnsMessage) -> Option<std::net::Ipv4Addr> {
    let answers = response.answers();
    if answers.len() != 1 {
        return None;
    }
    match answers[0].data() {
        Some(hickory_proto::rr::RData::A(addr)) => Some(addr.0),
        _ => None,
    }
}

/// Helper to query DoH server using GET method (base64url encoded)
async fn query_doh_get(
    client: &Client,
    port: u16,
    domain: &str,
    record_type: RecordType,
) -> E2EResult<DnsMessage> {
    let url = format!("https://127.0.0.1:{}/dns-query", port);

    // Build DNS query message. A real resolver picks the id at random and drops any reply
    // whose id does not match; the test must do the same or a server that never echoes it
    // looks healthy here while failing against every real client.
    let name = Name::from_str(domain)?;
    let query_id: u16 = rand::random();
    let mut query_msg = DnsMessage::new();
    query_msg.set_id(query_id);
    query_msg.add_query(Query::query(name.clone(), record_type));
    query_msg.set_recursion_desired(true);

    // Serialize to wire format
    let query_bytes = query_msg.to_vec()?;

    // Encode as base64url
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    let encoded = URL_SAFE_NO_PAD.encode(&query_bytes);

    // Send GET request
    let response = client.get(&url).query(&[("dns", encoded)]).send().await?;

    assert_eq!(
        response.status(),
        reqwest::StatusCode::OK,
        "RFC 8484 §4.2.1: a DNS message comes back as 200, whatever its RCODE"
    );
    assert_eq!(
        response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok()),
        Some("application/dns-message"),
        "the body is a DNS message and must be labelled as one"
    );

    let response_bytes = response.bytes().await?;

    // Parse DNS response
    let dns_response = DnsMessage::from_vec(&response_bytes)?;
    assert_correlates(&dns_response, query_id, &name);

    Ok(dns_response)
}

/// Helper to query DoH server using POST method (binary DNS message)
async fn query_doh_post(
    client: &Client,
    port: u16,
    domain: &str,
    record_type: RecordType,
) -> E2EResult<DnsMessage> {
    let url = format!("https://127.0.0.1:{}/dns-query", port);

    // Build DNS query message
    let name = Name::from_str(domain)?;
    let query_id: u16 = rand::random();
    let mut query_msg = DnsMessage::new();
    query_msg.set_id(query_id);
    query_msg.add_query(Query::query(name.clone(), record_type));
    query_msg.set_recursion_desired(true);

    // Serialize to wire format
    let query_bytes = query_msg.to_vec()?;

    // Send POST request. The Content-Type carries a `charset` parameter deliberately:
    // RFC 9110 §8.3 makes the media type case-insensitive and allows parameters, and the
    // server compared the whole header value byte-for-byte against the canonical spelling,
    // so a conformant client was rejected for being conformant.
    let response = client
        .post(&url)
        .header("Content-Type", "Application/DNS-Message; charset=utf-8")
        .body(query_bytes)
        .send()
        .await?;

    assert_eq!(
        response.status(),
        reqwest::StatusCode::OK,
        "a Content-Type differing only in case and parameters must be accepted"
    );

    let response_bytes = response.bytes().await?;

    // Parse DNS response
    let dns_response = DnsMessage::from_vec(&response_bytes)?;
    assert_correlates(&dns_response, query_id, &name);

    Ok(dns_response)
}

/// Create an HTTP client that accepts self-signed certificates (for testing)
///
/// `pub(crate)` so `llm_failure_test` can reuse it rather than growing a second copy that
/// drifts from this one — the same arrangement `dot` uses for `NoCertificateVerification`.
pub(crate) fn create_insecure_client(port: u16) -> E2EResult<Client> {
    // Initialize rustls crypto provider (required for rustls 0.23+)
    use rustls::crypto::CryptoProvider;
    let _ = CryptoProvider::install_default(rustls::crypto::ring::default_provider());

    // `http2_prior_knowledge()` asserts HTTP/2 out of band and skips ALPN entirely, so nothing
    // below exercises protocol negotiation. That is a real gap in coverage — see
    // `server_advertises_h2_alpn` for what does cover it, and the note in
    // src/server/doh/CLAUDE.md for why this client cannot: under
    // `danger_accept_invalid_certs` reqwest builds its own rustls ClientConfig that does not
    // offer `h2`, so dropping prior knowledge here just makes it send HTTP/1.1 to an
    // HTTP/2-only server.
    // `tls_built_in_root_certs(false)`: nothing here is verified against the platform roots —
    // `danger_accept_invalid_certs` is set on the line above — so loading them is pure cost.
    // On macOS that load reads the keychain through Security.framework, synchronously.
    //
    // `.resolve(..)` is the one that made this test stop failing, and it is worth explaining
    // because it is not obvious that a *literal IP* needs a resolver override at all.
    //
    // reqwest hands the URL's host to its DNS resolver unconditionally. `hyper-util`'s default
    // `GaiResolver` does not special-case a dotted quad, so `https://127.0.0.1:PORT/` still
    // becomes a `getaddrinfo("127.0.0.1")` call. On macOS that goes through libinfo to
    // mDNSResponder, a single system-wide daemon — and at `--test-threads=100` roughly a
    // hundred test processes ask it at once. It blocked for **8.25 seconds** in a measured
    // failing run, out of this request's 10-second budget.
    //
    // The measurement that pinned it: a raw `TcpStream::connect` to the same port, issued from
    // this same test on the same runtime immediately beforehand, completed in **464µs** and the
    // server logged the accept — while reqwest's own connect had still not reached the server
    // 8 seconds later. So the machine, the runtime and the server were all healthy; only the
    // name lookup was stuck. Overriding it took this test from 4 failures in 6 full-suite runs
    // to 0 in 8, at the same machine load.
    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .tls_built_in_root_certs(false)
        .resolve(
            "127.0.0.1",
            std::net::SocketAddr::from(([127, 0, 0, 1], port)),
        )
        .http2_prior_knowledge()
        // 30s, matching this test's other budgets (`wait_for_log(.., 20)`,
        // `wait_for_mocks(30)`). It was 10s, the only tight deadline in the file, and it is a
        // *scheduling* budget rather than a server-health one: what it bounds is a TLS + HTTP/2
        // handshake between two processes on a box running 100 test threads on 12 cores.
        //
        // Raised only after the two real defects behind the failures were found and fixed — the
        // `getaddrinfo` stall above, and the per-request `reqwest::Client` in
        // `src/llm/ollama_client.rs`. Raising it *first* would have buried both. What proves
        // DoH works here is the mock expectations and the parsed DNS answers, not the latency.
        .timeout(Duration::from_secs(30))
        .build()?;
    Ok(client)
}

#[tokio::test]
async fn test_doh_server() -> E2EResult<()> {
    println!("\n=== E2E Test: DNS-over-HTTPS Server with Mocks ===");

    // Create server with mocks for startup and DNS queries
    let server_config = helpers::NetGetConfig::new(
        "listen on port {AVAILABLE_PORT} via doh. Respond to all A record queries for example.com with IP 93.184.216.34 and TTL 300."
    )
    .with_mock(|mock| {
        mock
            // Mock 1: First GET query for example.com - MUST BE FIRST (most specific)
            .on_event("doh_query")
            .and_event_data_contains("domain", "example.com")
            .and_event_data_contains("method", "GET")
            .respond_with_actions_from_event(|event_data| {
                let query_id = event_data["query_id"].as_u64().unwrap_or(0);
                serde_json::json!([
                    {
                        "type": "send_dns_a_response",
                        "query_id": query_id,
                        "domain": "example.com",
                        "ip": "93.184.216.34",
                        "ttl": 300
                    }
                ])
            })
            .expect_calls(1)
            .and()
            // Mock 2: POST query for example.com - MUST BE SECOND (most specific)
            .on_event("doh_query")
            .and_event_data_contains("domain", "example.com")
            .and_event_data_contains("method", "POST")
            .respond_with_actions_from_event(|event_data| {
                let query_id = event_data["query_id"].as_u64().unwrap_or(0);
                serde_json::json!([
                    {
                        "type": "send_dns_a_response",
                        "query_id": query_id,
                        "domain": "example.com",
                        "ip": "93.184.216.34",
                        "ttl": 300
                    }
                ])
            })
            .expect_calls(1)
            .and()
            // Mock 3: Second GET query for test.com - MUST BE THIRD (most specific)
            .on_event("doh_query")
            .and_event_data_contains("domain", "test.com")
            .and_event_data_contains("method", "GET")
            .respond_with_actions_from_event(|event_data| {
                let query_id = event_data["query_id"].as_u64().unwrap_or(0);
                serde_json::json!([
                    {
                        "type": "send_dns_a_response",
                        "query_id": query_id,
                        // Distinct from example.com's, so an answer routed to the wrong
                        // question is visible rather than accidentally correct.
                        "domain": "test.com",
                        "ip": "93.184.216.35",
                        "ttl": 300
                    }
                ])
            })
            .expect_calls(1)
            .and()
            // Mock 4: Server startup - MUST BE LAST (less specific)
            .on_instruction_containing("listen")
            .and_instruction_containing("doh")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "DoH",
                    "instruction": "DNS-over-HTTPS server responding to queries"
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let server = helpers::start_netget_server(server_config).await?;

    println!("DoH server started on port {}", server.port);

    // Wait on the server's own readiness line rather than a fixed sleep.
    //
    // This was `sleep(3s)`, which is both slower than it needs to be and unreliable: under
    // --test-threads=100 on a 12-core box three seconds is not always enough for the child to
    // bind, and the first query then failed against a socket nobody was listening on. That is
    // the whole reason this test appeared in the load-flaky list. `wait_for_log` returns as
    // soon as the listener is actually up, and gives up after 20s with a clear message instead
    // of failing later as a mysterious query timeout.
    server
        .wait_for_log("DoH server listening on", 20)
        .await
        .map_err(|e| format!("DoH server never reported a listening socket: {e}"))?;

    // Create HTTP client
    let client = create_insecure_client(server.port)?;

    // Test both GET and POST methods against the same server. `query_doh_*` additionally
    // asserts the HTTP status, the Content-Type, and that the transaction id and question
    // came back — none of which was checked before, so a reply no resolver would accept
    // passed here.
    //
    // The `!!!T!!!` timing probes that used to sit in this block, and the `panic!("DIAG")`
    // that replaced the `?`, were left over from the getaddrinfo investigation written up in
    // `create_insecure_client` and `src/server/doh/CLAUDE.md`. That investigation is closed;
    // the diagnostics turned a helpful error into "DIAG".
    println!("\n[Test 1] Querying via GET method...");
    let response1 = query_doh_get(&client, server.port, "example.com.", RecordType::A).await?;
    assert_eq!(
        answer_a(&response1),
        Some("93.184.216.34".parse().unwrap()),
        "example.com must resolve to the address its handler chose"
    );
    println!("✓ GET response: 93.184.216.34");

    println!("\n[Test 2] Querying via POST method...");
    let response2 = query_doh_post(&client, server.port, "example.com.", RecordType::A).await?;
    assert_eq!(
        answer_a(&response2),
        Some("93.184.216.34".parse().unwrap()),
        "POST must reach the same handler as GET and get the same answer"
    );
    println!("✓ POST response: 93.184.216.34");

    println!("\n[Test 3] Another GET query - different domain...");
    let response3 = query_doh_get(&client, server.port, "test.com.", RecordType::A).await?;
    assert_eq!(
        answer_a(&response3),
        Some("93.184.216.35".parse().unwrap()),
        "test.com must resolve to its own address, not example.com's"
    );
    println!("✓ GET response: 93.184.216.35");

    println!("\n=== All DoH tests passed! ===");

    // Verify mock expectations were met
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;

    // Cleanup
    server.stop().await?;

    Ok(())
}

/// The DoH listener must advertise `h2` in the TLS handshake.
///
/// RFC 8484 DoH runs over HTTP/2 and this server speaks nothing else, so a client that
/// negotiates normally has to be told `h2` during the handshake — otherwise it falls back to
/// HTTP/1.1, which hyper's `http2::Builder` rejects with "http2 error", or it refuses outright.
///
/// The server advertised no ALPN at all until August 2026 and `test_doh_server` did not catch
/// it, because that test connects with `http2_prior_knowledge()` and so never negotiates. This
/// asserts the property that test cannot: the config the listener is built from offers exactly
/// `h2`, and nothing else that the server could not honour.
#[test]
fn server_advertises_h2_alpn() {
    let config = ::netget::server::tls_cert_manager::generate_default_tls_config_with_alpn(&["h2"])
        .expect("build DoH TLS config");
    assert_eq!(
        config.alpn_protocols,
        vec![b"h2".to_vec()],
        "DoH must advertise exactly h2: anything less leaves a negotiating client unable to \
         reach an HTTP/2-only server, anything more advertises a protocol it cannot speak"
    );

    // The shared default must stay ALPN-less: `dot`, `tls` and `quic` are built from it and
    // document themselves as negotiating nothing.
    let shared = ::netget::server::tls_cert_manager::generate_default_tls_config()
        .expect("build shared TLS config");
    assert!(
        shared.alpn_protocols.is_empty(),
        "the shared default gained ALPN, which changes dot/tls/quic behaviour out from under them"
    );
}

//! E2E tests for the WHOIS client, against NetGet's own WHOIS server on loopback.
//!
//! **These three tests used to query `whois.iana.org` and `whois.verisign-grs.com`.** They
//! were `#[ignore]`d for it, correctly — the repo's testing rules are "bind to localhost only;
//! never contact external endpoints", and a test with no `.with_mock()` also needs a real
//! Ollama. So they ran nowhere, asserted nothing, and still sat in the tree looking like
//! coverage of the client's model-driven path, which had none.
//!
//! They are now one test that runs, following the shape of
//! `tests/client/finger/e2e_test.rs::test_finger_client_round_trip_against_netget_server`:
//! a NetGet WHOIS server and a NetGet WHOIS client, both on mocked models, on loopback. The
//! mock's response generator runs *inside* this test, so what it captures is the model's
//! actual view of the event — which is the only way to assert the fields the client puts on
//! `whois_response_received`.
//!
//! LLM calls: 4 (two startups, one server-side query, one client-side response).

mod whois_client_tests {
    use crate::helpers::*;
    use std::sync::{Arc, Mutex};

    /// The client must send the query, read the reply to EOF, and hand the model an event
    /// naming both the record and the query that produced it.
    #[tokio::test]
    async fn test_whois_client_round_trip_against_netget_server() -> E2EResult<()> {
        let server_config = NetGetConfig::new("Listen on port {AVAILABLE_PORT} via whois")
            .with_log_level("info")
            .with_mock(|mock| {
                mock.on_instruction_containing("Listen on port")
                    .and_instruction_containing("whois")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "open_server",
                            "port": 0,
                            "base_stack": "whois",
                            "instruction": "Answer example.com with a record, then close"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    .on_event("whois_query")
                    .and_event_data_contains("query", "example.com")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "send_whois_record",
                            "domain": "example.com",
                            "registrar": "Round Trip Registrar",
                            "registrant": "Round Trip Org",
                            "name_servers": ["ns1.example.com", "ns2.example.com"]
                        },
                        // RFC 3912: the client reads to EOF, so the server has to close.
                        {"type": "close_connection"}
                    ]))
                    .expect_calls(1)
                    .and()
            });

        let server = start_netget_server(server_config).await?;
        let target = format!("127.0.0.1:{}", server.port);

        // The event the client hands the model, captured in-process.
        let observed: Arc<Mutex<Vec<serde_json::Value>>> = Arc::new(Mutex::new(Vec::new()));
        let observed_for_mock = observed.clone();

        let target_for_mock = target.clone();
        let client_config = NetGetConfig::new(format!(
            "Connect to {target} via whois and ask about example.com"
        ))
        .with_log_level("info")
        .with_mock(move |mock| {
            mock.on_instruction_containing("Connect to")
                .and_instruction_containing("whois")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_client",
                        "protocol": "whois",
                        "remote_addr": target_for_mock,
                        "instruction": "Ask about example.com and report the registrar",
                        "event_handlers": [{
                            "event_pattern": "whois_connected",
                            "handler": {
                                "type": "static",
                                "actions": [{
                                    "type": "query_whois",
                                    "query": "example.com"
                                }]
                            }
                        }]
                    }
                ]))
                .expect_calls(1)
                .and()
                .on_event("whois_response_received")
                .respond_with_actions_from_event(move |event| {
                    observed_for_mock
                        .lock()
                        .expect("observed lock")
                        .push(event.clone());
                    serde_json::json!([{"type": "disconnect"}])
                })
                .expect_calls(1)
                .and()
        });

        let client = start_netget_client(client_config).await?;

        server.wait_for_mocks(30).await;
        client.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        client.verify_mocks().await?;

        let events = observed.lock().expect("observed lock").clone();
        assert_eq!(
            events.len(),
            1,
            "exactly one whois_response_received should have reached the model: {events:?}"
        );
        let event = &events[0];

        let response = event["response"].as_str().unwrap_or_default();
        assert!(
            response.contains("Domain Name: example.com"),
            "the server's record should reach the model verbatim: {response:?}"
        );
        assert!(
            response.contains("Registrar: Round Trip Registrar"),
            "the registrar line should survive into the event: {response:?}"
        );
        assert!(
            response.contains("Name Server: ns1.example.com")
                && response.contains("Name Server: ns2.example.com"),
            "the client read only part of the reply before EOF: {response:?}"
        );
        assert_eq!(
            event["query"].as_str(),
            Some("example.com"),
            "the event should name the query that produced it - the client tracks the query \
             it actually put on the wire, whether the model or an injected action sent it: \
             {event:?}"
        );

        // A record this size is nowhere near the 1 MB cap, so `truncated` must be false. It
        // is on the event at all because a model that read half a record and believed it had
        // the whole one would answer confidently and wrongly - and how much a WHOIS server
        // sends is the server's choice, not ours.
        assert_eq!(
            event["truncated"].as_bool(),
            Some(false),
            "a short record must not be reported as truncated: {event:?}"
        );

        println!("✅ WHOIS client round trip against NetGet's own WHOIS server");

        client.stop().await?;
        server.stop().await?;
        Ok(())
    }
}

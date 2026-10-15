//! E2E tests for the Kafka client.
//!
//! A mocked NetGet **broker** speaks Kafka to a mocked NetGet **client** over a real socket,
//! in two separate processes. Nothing here asserts NetGet against a reimplementation of
//! itself: the client encodes requests and decodes responses, the broker does the opposite,
//! and the assertions are on *content that crossed the wire and was decoded by the other
//! side*.
//!
//! The strongest assertion in each test reads a value out of the broker's own event data:
//!
//! * `test_kafka_client_produces_a_record_the_broker_decodes` captures the `records` array the
//!   broker decoded from the client's v2 record batch and compares it to the bytes the client
//!   was told to send. The key is handed to the client as **hex** and must arrive as the text
//!   it decodes to — if the client failed to honour `key_encoding` and put the literal string
//!   `"6f726465722d31"` on the wire, the broker would report exactly that and the assertion
//!   fails.
//! * `test_kafka_client_fetches_polls_and_commits` captures every `fetch_offset` the broker
//!   saw and the offset the client committed. The client is given one record at offset 0 and
//!   must work out for itself that the next fetch starts at 1 — which it can only do by
//!   decoding the record batch the broker encoded.
//!
//! ## What these replaced
//!
//! Four `#[ignore]`d tests whose premise was that no Kafka client was compiled into any
//! `--features kafka` build (`src/client/mod.rs` gated it on the `rdkafka` feature, which only
//! `all-protocols` turned on). The client is now pure Rust on `kafka-protocol`, `rdkafka` is
//! gone, and the ignores went with it. Two of those tests were also written against consumer
//! groups, which neither half implements; this suite assigns partitions manually instead,
//! which is what the broker actually supports.
//!
//! ## Harness note
//!
//! The mock server evaluates a `respond_with_actions_from_event` generator **twice** per
//! request — once to report routing consistency and once to build the answer. A generator that
//! appends to a list therefore records every value twice. The captures below are sets, and the
//! call counts come from `expect_calls` on the rules instead.
//!
//! LLM call budget: 6 (test A) + 8 (test B) = 14.

mod kafka_client_tests {
    use crate::helpers::*;
    use serde_json::json;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    /// The client is told to send this key as hex. It decodes to "order-1".
    const KEY_HEX: &str = "6f726465722d31";
    const KEY_TEXT: &str = "order-1";
    const VALUE_TEXT: &str = "{\"item\":\"laptop\",\"price\":999}";

    /// Produce: the record the client builds must be the record the broker decodes.
    ///
    /// LLM calls: 6 (broker: startup + metadata + produce; client: startup + kafka_connected +
    /// kafka_message_delivered).
    #[tokio::test]
    async fn test_kafka_client_produces_a_record_the_broker_decodes() -> E2EResult<()> {
        // Filled in by the broker's mock, read by the test. This is the only place the
        // client's encoder output is observed after another codec has decoded it.
        let captured: Arc<Mutex<Vec<serde_json::Value>>> = Arc::new(Mutex::new(Vec::new()));
        let captured_produce = captured.clone();

        let server_config =
            NetGetConfig::new("Start a Kafka broker on port {AVAILABLE_PORT} for topic 'orders'.")
                .with_mock(move |mock| {
                    let captured_produce = captured_produce.clone();
                    mock
                        // A client asks for metadata before it can address a partition leader.
                        // Naming no broker makes the reply advertise this server itself.
                        .on_event("kafka_metadata_request")
                        .respond_with_actions(json!([{
                            "type": "metadata_response",
                            "topics": [
                                {"name": "orders", "partitions": [{"partition": 0}]}
                            ]
                        }]))
                        .expect_calls(1)
                        .and()
                        // Fires only if the client's record batch arrived and decoded.
                        .on_event("kafka_produce_request")
                        .and_event_data_contains("topic", "orders")
                        .respond_with_actions_from_event(move |event| {
                            *captured_produce.lock().unwrap() = event
                                .get("records")
                                .and_then(|r| r.as_array())
                                .cloned()
                                .unwrap_or_default();
                            json!([{
                                "type": "produce_response",
                                "topic": "orders",
                                "partition": 0,
                                "offset": 42,
                                "error_code": 0
                            }])
                        })
                        .expect_calls(1)
                        .and()
                        // Declared last: rules are first-match-wins and this one matches
                        // anything, including the event requests above.
                        .on_any()
                        .respond_with_actions(json!([{
                            "type": "open_server",
                            "port": 0,
                            "base_stack": "KAFKA",
                            "instruction": "Kafka broker for the 'orders' topic"
                        }]))
                        .expect_calls(1)
                        .and()
                });

        let server = start_netget_server(server_config).await?;
        wait_for_server_startup(&server, Duration::from_secs(20), "KAFKA").await?;

        let remote = format!("127.0.0.1:{}", server.port);
        let client_config = NetGetConfig::new(format!(
            "Connect to {remote} via Kafka and publish one order record to the 'orders' topic."
        ))
        .with_mock(move |mock| {
            mock
                // Matching on `topics` proves the client parsed the Metadata reply into
                // structured fields rather than reporting a blob.
                .on_event("kafka_connected")
                .and_event_data_contains("topics", "orders")
                .respond_with_actions(json!([{
                    "type": "produce_message",
                    "topic": "orders",
                    "partition": 0,
                    "key": KEY_HEX,
                    "key_encoding": "hex",
                    "value": VALUE_TEXT
                }]))
                .expect_calls(1)
                .and()
                // The broker's acknowledgement came back and was decoded: base_offset is the
                // offset the *broker's* model chose, which the client has no other way to know.
                .on_event("kafka_message_delivered")
                .and_event_data_contains("base_offset", "42")
                .and_event_data_contains("delivered", "true")
                .respond_with_actions(json!([{ "type": "wait_for_more" }]))
                .expect_calls(1)
                .and()
                .on_any()
                .respond_with_actions(json!([{
                    "type": "open_client",
                    "remote_addr": remote,
                    "protocol": "Kafka",
                    "instruction": "Publish one order record",
                    "startup_params": {"client_id": "netget-e2e-producer"}
                }]))
                .expect_calls(1)
                .and()
        });

        let client = start_netget_client(client_config).await?;

        // ApiVersions -> Metadata -> kafka_connected -> Produce -> kafka_message_delivered,
        // with a model round trip at three of those steps across two processes.
        //
        // Waiting on the mocks rather than on a clock, and waiting *before* the assertions
        // rather than after them. `captured` is filled by the broker's produce rule, so the
        // assertion below is only meaningful once that rule has fired - a fixed five seconds
        // is enough alone and not when a hundred tests run together, and the failure it
        // produces reads as "the client never sent the record" rather than "the test looked
        // too early".
        server.wait_for_mocks(30).await;
        client.wait_for_mocks(30).await;

        assert_eq!(
            client.protocol, "Kafka",
            "client should be the Kafka client"
        );

        // The load-bearing assertion. `records` is what the broker's RecordBatchDecoder made
        // of the batch this client's RecordBatchEncoder produced.
        {
            let seen = captured.lock().unwrap();
            assert_eq!(
                seen.len(),
                1,
                "exactly one produced record must reach the broker's handler, got {seen:?}"
            );
            assert_eq!(
                seen[0]["key"].as_str(),
                Some(KEY_TEXT),
                "the hex key must be decoded before it goes on the wire, not sent literally"
            );
            assert_eq!(
                seen[0]["key_encoding"].as_str(),
                Some("utf8"),
                "decoded key bytes are printable, so the broker must present them as text"
            );
            assert_eq!(
                seen[0]["value"].as_str(),
                Some(VALUE_TEXT),
                "the value must survive client encode -> broker decode unchanged"
            );
            assert_eq!(
                seen[0]["value_encoding"].as_str(),
                Some("utf8"),
                "printable payloads must never reach a model as base64"
            );
        }

        println!("✅ Kafka client produced a record the broker decoded field for field");

        server.verify_mocks().await?;
        client.verify_mocks().await?;

        client.stop().await?;
        server.stop().await?;

        Ok(())
    }

    /// Fetch, decode, advance, commit.
    ///
    /// The client is configured with `topics: ["orders"]`, so its poll loop runs a Fetch as
    /// soon as the connection is up. The broker hands back one record at offset 0, and only to
    /// a consumer asking from offset 0; anything else gets an empty answer. The handler then
    /// commits and asks for the *next* records without naming an offset, so the second fetch
    /// carries whatever the client worked out for itself.
    ///
    /// The three assertions are therefore each about a number the client had to derive:
    ///
    /// * `next_offset` = 1 in the event data — only obtainable by decoding the record batch;
    /// * the broker sees `fetch_offset` 0 then 1 — the tracked position advanced;
    /// * the committed offset is 1 — the handler's action became a real OffsetCommit request.
    ///
    /// `poll_interval_ms` is deliberately far larger than the test window: NetGet's
    /// non-interactive *client* mode exits about 500ms after the prompt is handled
    /// (`src/cli/non_interactive.rs` only enters a keep-alive loop for `Mode::Server`), so a
    /// second timed round would never run and asserting on one would be flaky. Everything here
    /// happens in the first, immediate round.
    ///
    /// LLM calls: 8 (broker: startup + metadata + 2 fetches + commit; client: startup +
    /// kafka_connected + kafka_records_received).
    #[tokio::test]
    async fn test_kafka_client_fetches_polls_and_commits() -> E2EResult<()> {
        const PAYLOAD: &str = "Test Flow";

        // Sets, not lists, and the *counts* come from `expect_calls` on the rules instead.
        // `respond_with_actions_from_event` generators are evaluated twice per request by the
        // mock server (once to report routing, once to answer), so a generator that appends
        // records every value twice. What each generator observes is still exactly what
        // arrived on the wire; only the multiplicity is a harness artefact.
        let fetch_offsets: Arc<Mutex<std::collections::BTreeSet<i64>>> =
            Arc::new(Mutex::new(std::collections::BTreeSet::new()));
        let committed: Arc<Mutex<std::collections::BTreeSet<i64>>> =
            Arc::new(Mutex::new(std::collections::BTreeSet::new()));
        let fetch_offsets_mock = fetch_offsets.clone();
        let committed_mock = committed.clone();

        let server_config =
            NetGetConfig::new("Start a Kafka broker on port {AVAILABLE_PORT} for topic 'orders'.")
                .with_mock(move |mock| {
                    let fetch_offsets_mock = fetch_offsets_mock.clone();
                    let committed_mock = committed_mock.clone();
                    mock.on_event("kafka_metadata_request")
                        .respond_with_actions(json!([{
                            "type": "metadata_response",
                            "topics": [
                                {"name": "orders", "partitions": [{"partition": 0}]}
                            ]
                        }]))
                        .expect_calls(1)
                        .and()
                        // One record, once, and only to a consumer reading from offset 0. The
                        // broker keeps no storage, so "replay" here is the mock's choice, not
                        // the broker's.
                        .on_event("kafka_fetch_request")
                        // Two rounds: the poll loop's immediate first fetch, and the one the
                        // records handler asks for without naming an offset.
                        .respond_with_actions_from_event(move |event| {
                            let offset = event
                                .get("fetch_offset")
                                .and_then(|v| v.as_i64())
                                .unwrap_or(-1);
                            fetch_offsets_mock.lock().unwrap().insert(offset);

                            let records = if offset == 0 {
                                json!([{"offset": 0, "key": "k1", "value": PAYLOAD}])
                            } else {
                                json!([])
                            };
                            json!([{
                                "type": "fetch_response",
                                "topic": "orders",
                                "partition": 0,
                                "records": records
                            }])
                        })
                        .expect_calls(2)
                        .and()
                        // Fires only if the client turned the handler's commit_offset action
                        // into a real OffsetCommit request.
                        .on_event("kafka_offset_commit_request")
                        .respond_with_actions_from_event(move |event| {
                            committed_mock
                                .lock()
                                .unwrap()
                                .insert(event.get("offset").and_then(|v| v.as_i64()).unwrap_or(-1));
                            json!([{
                                "type": "offset_commit_response",
                                "topic": "orders",
                                "partition": 0,
                                "error_code": 0
                            }])
                        })
                        .expect_calls(1)
                        .and()
                        .on_any()
                        .respond_with_actions(json!([{
                            "type": "open_server",
                            "port": 0,
                            "base_stack": "KAFKA",
                            "instruction": "Kafka broker for the 'orders' topic"
                        }]))
                        .expect_calls(1)
                        .and()
                });

        let server = start_netget_server(server_config).await?;
        wait_for_server_startup(&server, Duration::from_secs(20), "KAFKA").await?;

        let remote = format!("127.0.0.1:{}", server.port);
        let client_config = NetGetConfig::new(format!(
            "Connect to {remote} via Kafka, read the 'orders' topic and commit what you read."
        ))
        .with_mock(move |mock| {
            mock.on_event("kafka_connected")
                .respond_with_actions(json!([{ "type": "wait_for_more" }]))
                .expect_calls(1)
                .and()
                // Matching on the payload inside `records` proves the client decoded the
                // broker's record batch rather than forwarding bytes; matching on
                // `next_offset` proves it read the record's own offset out of that batch and
                // added one, which is the whole of a consumer's position bookkeeping.
                .on_event("kafka_records_received")
                .and_event_data_contains("records", PAYLOAD)
                .and_event_data_contains("next_offset", "1")
                .respond_with_actions(json!([
                    {
                        "type": "commit_offset",
                        "topic": "orders",
                        "partition": 0,
                        "offset": 1
                    },
                    {
                        // No offset: the client must use the position it tracked.
                        "type": "fetch_records",
                        "topic": "orders",
                        "partition": 0
                    }
                ]))
                .expect_calls(1)
                .and()
                .on_any()
                .respond_with_actions(json!([{
                    "type": "open_client",
                    "remote_addr": remote,
                    "protocol": "Kafka",
                    "instruction": "Read the orders topic and commit what you read",
                    "startup_params": {
                        "client_id": "netget-e2e-consumer",
                        "topics": ["orders"],
                        "partition": 0,
                        "start_offset": 0,
                        "poll_interval_ms": 60000
                    }
                }]))
                .expect_calls(1)
                .and()
        });

        let client = start_netget_client(client_config).await?;

        // Everything happens in the first poll round. Wait for the exchange the mocks
        // describe, and wait for it *before* the assertions: `fetch_offsets` and `committed`
        // are filled by the broker's own rules, so asserting on them ahead of the wait is
        // asserting on a snapshot that may be one round trip short.
        server.wait_for_mocks(30).await;
        client.wait_for_mocks(30).await;

        assert_eq!(
            client.protocol, "Kafka",
            "client should be the Kafka client"
        );

        {
            let offsets = fetch_offsets.lock().unwrap();
            // `expect_calls(2)` on the fetch rule already fixes the count at two, so this
            // fixes *which* two: the poll loop's opening read at start_offset 0, and the
            // handler's offset-less fetch carrying the position the client derived from the
            // batch it decoded.
            let seen: Vec<i64> = offsets.iter().copied().collect();
            assert_eq!(seen, vec![0, 1], "fetch offsets the broker saw");
        }
        {
            let committed = committed.lock().unwrap();
            let seen: Vec<i64> = committed.iter().copied().collect();
            assert_eq!(
                seen,
                vec![1],
                "the handler's commit_offset must reach the broker as an OffsetCommit for \
                 offset 1"
            );
        }

        println!("✅ Kafka client polled, decoded a record batch, advanced and committed");

        server.verify_mocks().await?;
        client.verify_mocks().await?;

        client.stop().await?;
        server.stop().await?;

        Ok(())
    }
}

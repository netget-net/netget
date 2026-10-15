//! End-to-end NATS tests.
//!
//! `test_nats_delivers_model_authored_message_to_async_nats` is what the maturity rating
//! rests on: the official `async-nats` client completes a real CONNECT/PING/PONG handshake,
//! subscribes, publishes, and receives messages the **model** authored - asserted from
//! inside the client's own `Message`, so the subject, payload, reply subject and headers all
//! had to be framed correctly for it to see them at all.
//!
//! It is not `#[ignore]`d and it cannot silently skip: `async-nats` is a dev-dependency, so
//! it exists wherever this suite compiles. That is the distinction the root CLAUDE.md draws
//! between real evidence and a skip-when-missing gate.
//!
//! The other tests cover what a client library cannot reach:
//!
//! * the parser, directly (no server, no LLM) - partial frames, HPUB, wildcards;
//! * the raw wire: the INFO greeting's shape, `PING`->`PONG` and the verbose `+OK` being
//!   answered with **no** LLM call, and a malformed frame producing `-ERR` plus a hang-up;
//! * the fail-closed path, where the backend is unreachable and the peer must get a
//!   category rather than netget's internals.
mod nats_e2e_test {
    use crate::helpers::{start_netget_server, E2EResult, NetGetConfig};
    use netget::server::nats::{parse_frame, subject_matches, Frame, FrameError};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    const MAX_PAYLOAD: u64 = 1_048_576;

    // ========================================================================
    // Parser - no server, no LLM calls
    // ========================================================================

    #[test]
    fn test_nats_parser_frames_control_lines_and_payloads() {
        // A control line that has not arrived in full yields None rather than an error:
        // this is a stream, and half a frame is normal.
        assert_eq!(parse_frame(b"PIN", MAX_PAYLOAD).unwrap(), None);
        assert_eq!(
            parse_frame(b"PING\r\n", MAX_PAYLOAD).unwrap(),
            Some((Frame::Ping, 6))
        );
        assert_eq!(
            parse_frame(b"pong\r\n", MAX_PAYLOAD).unwrap(),
            Some((Frame::Pong, 6))
        );

        // CONNECT keeps the document verbatim - splitting on whitespace would corrupt any
        // JSON string containing a space.
        let (frame, consumed) = parse_frame(
            b"CONNECT {\"verbose\":true,\"name\":\"my app\"}\r\n",
            MAX_PAYLOAD,
        )
        .unwrap()
        .expect("CONNECT should parse");
        assert_eq!(consumed, 42);
        match frame {
            Frame::Connect(doc) => {
                assert_eq!(doc["verbose"], serde_json::json!(true));
                assert_eq!(doc["name"], serde_json::json!("my app"));
            }
            other => panic!("expected Connect, got {other:?}"),
        }

        // SUB with and without a queue group.
        assert_eq!(
            parse_frame(b"SUB orders.* 3\r\n", MAX_PAYLOAD).unwrap(),
            Some((
                Frame::Subscribe {
                    subject: "orders.*".to_string(),
                    queue_group: None,
                    sid: "3".to_string(),
                },
                16
            ))
        );
        assert_eq!(
            parse_frame(b"SUB orders.eu workers 4\r\n", MAX_PAYLOAD).unwrap(),
            Some((
                Frame::Subscribe {
                    subject: "orders.eu".to_string(),
                    queue_group: Some("workers".to_string()),
                    sid: "4".to_string(),
                },
                25
            ))
        );

        assert_eq!(
            parse_frame(b"UNSUB 4 10\r\n", MAX_PAYLOAD).unwrap(),
            Some((
                Frame::Unsubscribe {
                    sid: "4".to_string(),
                    max_msgs: Some(10),
                },
                12
            ))
        );

        // A PUB whose payload has not fully arrived must consume nothing.
        assert_eq!(parse_frame(b"PUB a 5\r\nhel", MAX_PAYLOAD).unwrap(), None);

        let (frame, consumed) =
            parse_frame(b"PUB orders.eu reply.1 5\r\nhello\r\nPING\r\n", MAX_PAYLOAD)
                .unwrap()
                .expect("PUB should parse");
        assert_eq!(consumed, 32, "only the PUB frame may be consumed");
        match frame {
            Frame::Publish {
                subject,
                reply_to,
                headers,
                payload,
            } => {
                assert_eq!(subject, "orders.eu");
                assert_eq!(reply_to.as_deref(), Some("reply.1"));
                assert!(headers.is_empty());
                assert_eq!(payload, b"hello");
            }
            other => panic!("expected Publish, got {other:?}"),
        }
    }

    #[test]
    fn test_nats_parser_reads_hpub_headers_and_binary_payloads() {
        // 29 header bytes ("NATS/1.0" + one header + the blank line), 3 payload bytes.
        let frame_bytes: &[u8] =
            b"HPUB orders.eu 29 32\r\nNATS/1.0\r\nNats-Msg-Id: 42\r\n\r\n\x00\xff\x01\r\n";
        let (frame, consumed) = parse_frame(frame_bytes, MAX_PAYLOAD)
            .unwrap()
            .expect("HPUB should parse");
        assert_eq!(consumed, frame_bytes.len());
        match frame {
            Frame::Publish {
                subject,
                headers,
                payload,
                ..
            } => {
                assert_eq!(subject, "orders.eu");
                assert_eq!(headers.get("Nats-Msg-Id").map(String::as_str), Some("42"));
                assert_eq!(payload, vec![0x00, 0xff, 0x01]);
            }
            other => panic!("expected Publish, got {other:?}"),
        }
    }

    #[test]
    fn test_nats_parser_rejects_bad_frames() {
        assert_eq!(
            parse_frame(b"BOGUS foo\r\n", MAX_PAYLOAD),
            Err(FrameError::UnknownProtocolOperation)
        );
        assert_eq!(
            parse_frame(b"CONNECT not-json\r\n", MAX_PAYLOAD),
            Err(FrameError::InvalidConnectConfig)
        );
        // The declared size is checked before a single byte of it is buffered, so a peer
        // cannot make the server allocate its way to death.
        assert_eq!(
            parse_frame(b"PUB orders.eu 9999999\r\n", 1024),
            Err(FrameError::MaximumPayloadViolation)
        );
        // ...and the same is true of HPUB. It was not: the payload limit was applied to
        // `total - header`, so `header == total` gave a zero-length body that passed every
        // check with `total` unbounded. This one line is 30 bytes on the wire and made the
        // reader buffer its way toward 4 GB. The claim above was tested only for PUB.
        assert_eq!(
            parse_frame(b"HPUB orders.eu 4000000000 4000000000\r\n", 1024),
            Err(FrameError::MaximumPayloadViolation)
        );
        let long_line = format!("SUB {} 1\r\n", "x".repeat(5000));
        assert_eq!(
            parse_frame(long_line.as_bytes(), MAX_PAYLOAD),
            Err(FrameError::MaximumControlLineExceeded)
        );
    }

    /// A run of newlines must not recurse, must not grow the buffer, and must not hide a
    /// frame that follows it.
    ///
    /// The blank-line skip used to recurse into `parse_frame` once per blank line, one stack
    /// frame deeper each time and not in tail position. 8 KB of newlines is a single `read`,
    /// and about 8000 frames of recursion overflowed the stack - which in Rust is `SIGSEGV`,
    /// not a catchable panic, so `tokio::spawn` could not contain it and the whole NetGet
    /// process aborted. Every other server in the process went with it.
    ///
    /// 100_000 is far past the depth that used to abort, so this test failing to complete
    /// *is* the regression.
    #[test]
    fn test_nats_parser_survives_a_flood_of_blank_lines() {
        let mut flood = vec![b'\n'; 100_000];
        assert_eq!(
            parse_frame(&flood, MAX_PAYLOAD),
            Ok(None),
            "a buffer of only blank lines holds no frame"
        );
        assert_eq!(
            netget::server::nats::blank_line_prefix_len(&flood),
            flood.len(),
            "the reader must be able to drain the whole run, or the buffer grows forever"
        );

        // CRLF, and whitespace-only lines, count as blank the same way - and a real frame
        // after the flood is still found, at the right offset.
        flood.extend_from_slice(b"\r\n   \r\nPING\r\n");
        let consumed_before_ping = flood.len() - 6;
        assert_eq!(
            parse_frame(&flood, MAX_PAYLOAD),
            Ok(Some((Frame::Ping, flood.len()))),
            "PING after the flood, consuming the blank lines with it"
        );
        assert_eq!(
            netget::server::nats::blank_line_prefix_len(&flood),
            consumed_before_ping
        );
    }

    /// A declared size must never be able to wrap the index that reads it.
    ///
    /// `HPUB x <usize::MAX> <usize::MAX>` passed the old payload check (zero-length body) and
    /// then computed `after_line + total_len`, which panicked on overflow in debug and in
    /// release wrapped to a `start > end` slice that panicked one line further on. Either way
    /// the connection task died with its cleanup un-run, leaking the connection as `Active`.
    #[test]
    fn test_nats_parser_rejects_a_size_that_would_wrap_the_index() {
        let line = format!("HPUB s {max} {max}\r\n", max = usize::MAX);
        assert_eq!(
            parse_frame(line.as_bytes(), u64::MAX),
            Err(FrameError::MaximumPayloadViolation)
        );
    }

    #[test]
    fn test_nats_subject_matching() {
        assert!(subject_matches("orders.eu", "orders.eu"));
        assert!(!subject_matches("orders.eu", "orders.us"));
        assert!(subject_matches("orders.*", "orders.eu"));
        assert!(!subject_matches("orders.*", "orders.eu.new"));
        assert!(subject_matches("orders.>", "orders.eu.new"));
        assert!(subject_matches("orders.>", "orders.eu"));
        assert!(!subject_matches("orders.>", "orders"));
        assert!(subject_matches("*.eu.>", "orders.eu.new.2024"));
        assert!(!subject_matches("orders", "orders.eu"));
    }

    // ========================================================================
    // The real client
    // ========================================================================

    /// The evidence behind the maturity rating.
    ///
    /// `async-nats` connects (INFO -> CONNECT+PING -> PONG), subscribes, publishes, and then
    /// receives two messages the model authored in reply to the publish: a plain `MSG`, and
    /// an `HMSG` carrying headers and a reply subject. A raw socket would only prove bytes
    /// moved; the client's own `Message` struct proves the framing is right.
    ///
    /// 4 LLM calls: startup, nats_connect, nats_subscribe, nats_publish.
    #[tokio::test]
    async fn test_nats_delivers_model_authored_message_to_async_nats() -> E2EResult<()> {
        let config = NetGetConfig::new("listen on port {AVAILABLE_PORT} via nats")
            .with_log_level("debug")
            .with_mock(|mock| {
                mock.on_instruction_containing("listen on port")
                    .and_instruction_containing("nats")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "open_server",
                            "port": 0,
                            "base_stack": "nats",
                            "instruction": "Deliver a greeting to every subscription that matches a publish"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // Accept the connection without saying anything: the CONNECT
                    // acknowledgement and the PING are answered by the server itself.
                    .on_event("nats_connect")
                    .respond_with_actions(serde_json::json!([]))
                    .expect_calls(1)
                    .and()
                    .on_event("nats_subscribe")
                    .and_event_data_contains("subject", "greetings")
                    .respond_with_actions(serde_json::json!([]))
                    .expect_calls(1)
                    .and()
                    // The subscription id is chosen by the client, so it MUST come from the
                    // event rather than being hardcoded - the same rule the UDP protocols
                    // follow for transaction ids.
                    .on_event("nats_publish")
                    .and_event_data_contains("subject", "greetings")
                    .respond_with_actions_from_event(|e| {
                        let sid = e["matching_subscriptions"][0]["sid"]
                            .as_str()
                            .unwrap_or("0")
                            .to_string();
                        serde_json::json!([
                            {
                                "type": "send_nats_message",
                                "subject": "greetings",
                                "sid": sid,
                                "payload": format!("the model saw: {}", e["payload"].as_str().unwrap_or(""))
                            },
                            {
                                "type": "send_nats_message",
                                "subject": "greetings",
                                "sid": sid,
                                "reply_to": "greetings.reply",
                                "payload": "second",
                                "headers": {"Nats-Msg-Id": "42"}
                            }
                        ])
                    })
                    .expect_calls(1)
                    .and()
            });

        let server = start_netget_server(config).await?;

        let client = tokio::time::timeout(
            Duration::from_secs(20),
            async_nats::connect(format!("nats://127.0.0.1:{}", server.port)),
        )
        .await
        .map_err(|_| "async-nats did not finish connecting within 20s")?
        .map_err(|e| format!("async-nats could not connect: {e}"))?;

        use futures::StreamExt;
        let mut subscription = client
            .subscribe("greetings")
            .await
            .map_err(|e| format!("subscribe failed: {e}"))?;

        client
            .publish("greetings", "hi".into())
            .await
            .map_err(|e| format!("publish failed: {e}"))?;
        client
            .flush()
            .await
            .map_err(|e| format!("flush failed: {e}"))?;

        let first = tokio::time::timeout(Duration::from_secs(20), subscription.next())
            .await
            .map_err(|_| "no MSG reached the async-nats subscriber within 20s")?
            .ok_or("subscription ended before a message arrived")?;
        assert_eq!(first.subject.as_str(), "greetings");
        assert_eq!(
            std::str::from_utf8(&first.payload).unwrap(),
            "the model saw: hi",
            "the payload must be the one the model authored, and it must have seen ours"
        );

        let second = tokio::time::timeout(Duration::from_secs(20), subscription.next())
            .await
            .map_err(|_| "the second (HMSG) message did not arrive within 20s")?
            .ok_or("subscription ended before the second message arrived")?;
        assert_eq!(std::str::from_utf8(&second.payload).unwrap(), "second");
        assert_eq!(
            second.reply.as_ref().map(|s| s.as_str()),
            Some("greetings.reply"),
            "reply subject must survive the round trip"
        );
        let headers = second
            .headers
            .as_ref()
            .ok_or("the HMSG frame carried no headers the client could parse")?;
        assert_eq!(
            headers.get("Nats-Msg-Id").map(|v| v.as_str()),
            Some("42"),
            "header value must survive the round trip"
        );

        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;
        Ok(())
    }

    // ========================================================================
    // Raw wire
    // ========================================================================

    async fn read_until(stream: &mut TcpStream, needle: &str, secs: u64) -> String {
        let mut collected = Vec::new();
        let mut chunk = vec![0u8; 4096];
        let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            match tokio::time::timeout(remaining, stream.read(&mut chunk)).await {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => {
                    collected.extend_from_slice(&chunk[..n]);
                    if String::from_utf8_lossy(&collected).contains(needle) {
                        break;
                    }
                }
                _ => break,
            }
        }
        String::from_utf8_lossy(&collected).to_string()
    }

    /// The greeting, the keepalive and the verbose acknowledgement, none of which may cost
    /// an LLM call, plus the protocol-error path.
    ///
    /// 2 LLM calls: startup and nats_connect. If `PING` or the verbose `+OK` were routed
    /// through the model, the `nats_connect` rule would be short of its expected count or a
    /// second rule would be needed - `verify_mocks()` is what asserts they are not.
    #[tokio::test]
    async fn test_nats_greeting_keepalive_and_protocol_error() -> E2EResult<()> {
        let config = NetGetConfig::new("listen on port {AVAILABLE_PORT} via nats")
            .with_log_level("debug")
            .with_mock(|mock| {
                mock.on_instruction_containing("listen on port")
                    .and_instruction_containing("nats")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "open_server",
                            "port": 0,
                            "base_stack": "nats",
                            "instruction": "Accept every connection"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // Answering with nothing keeps the byte stream below deterministic:
                    // everything the client reads was written by the server itself.
                    .on_event("nats_connect")
                    .respond_with_actions(serde_json::json!([]))
                    .expect_calls(1)
                    .and()
            });

        let server = start_netget_server(config).await?;
        let addr = format!("127.0.0.1:{}", server.port);

        let mut stream = TcpStream::connect(&addr).await.expect("connect");

        // The server speaks first.
        let greeting = read_until(&mut stream, "\r\n", 10).await;
        let info_json = greeting
            .strip_prefix("INFO ")
            .and_then(|rest| rest.split("\r\n").next())
            .ok_or_else(|| format!("expected an INFO greeting, got {greeting:?}"))?;
        let info: serde_json::Value =
            serde_json::from_str(info_json).map_err(|e| format!("INFO is not JSON: {e}"))?;
        for field in [
            "server_id",
            "server_name",
            "version",
            "proto",
            "host",
            "port",
            "headers",
            "max_payload",
        ] {
            assert!(
                info.get(field).is_some(),
                "INFO is missing {field}, which real clients require: {info}"
            );
        }
        assert_eq!(info["proto"], serde_json::json!(1));
        assert_eq!(info["headers"], serde_json::json!(true));
        assert!(info["max_payload"].as_u64().unwrap_or(0) > 0);

        // Verbose mode: +OK for the CONNECT, then PONG for the PING - both written by the
        // server, with no model in the path.
        stream
            .write_all(b"CONNECT {\"verbose\":true,\"name\":\"raw\",\"lang\":\"rust\"}\r\nPING\r\n")
            .await
            .expect("write CONNECT");
        let acks = read_until(&mut stream, "PONG\r\n", 10).await;
        assert!(
            acks.contains("+OK\r\n"),
            "a verbose client must be acknowledged: {acks:?}"
        );
        assert!(
            acks.contains("PONG\r\n"),
            "PING must be answered with PONG: {acks:?}"
        );

        // A frame the protocol does not define: -ERR with the real NATS text, then EOF.
        stream.write_all(b"BOGUS\r\n").await.expect("write BOGUS");
        let err = read_until(&mut stream, "\r\n", 10).await;
        assert!(
            err.contains("-ERR 'Unknown Protocol Operation'"),
            "expected the standard NATS error, got {err:?}"
        );
        let mut tail = vec![0u8; 64];
        let closed = tokio::time::timeout(Duration::from_secs(10), stream.read(&mut tail)).await;
        let hung_up = match &closed {
            // EOF, or the peer reset: either way the server ended the connection.
            Ok(Ok(0)) | Ok(Err(_)) => true,
            // More bytes, or nothing at all before the deadline: still connected.
            Ok(Ok(_)) | Err(_) => false,
        };
        assert!(
            hung_up,
            "the server must hang up after a protocol error, got {closed:?}"
        );

        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;
        Ok(())
    }

    /// When the backend cannot answer, the peer gets a NATS `-ERR` naming a category and
    /// nothing else - no URL, no model name, no Rust error chain.
    ///
    /// 2 LLM calls: startup and nats_connect. There is deliberately **no** rule for
    /// `nats_publish` and no `on_any()` catch-all, so the mock answers that request with
    /// HTTP 500 and netget sees a real backend failure.
    #[tokio::test]
    async fn test_nats_llm_failure_answers_with_a_category_only() -> E2EResult<()> {
        let config = NetGetConfig::new("listen on port {AVAILABLE_PORT} via nats")
            .with_log_level("debug")
            .with_mock(|mock| {
                mock.on_instruction_containing("listen on port")
                    .and_instruction_containing("nats")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "open_server",
                            "port": 0,
                            "base_stack": "nats",
                            "instruction": "Answer publishes with a message"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    .on_event("nats_connect")
                    .respond_with_actions(serde_json::json!([]))
                    .expect_calls(1)
                    .and()
            });

        let server = start_netget_server(config).await?;
        let addr = format!("127.0.0.1:{}", server.port);

        let mut stream = TcpStream::connect(&addr).await.expect("connect");
        let _greeting = read_until(&mut stream, "\r\n", 10).await;
        stream
            .write_all(
                b"CONNECT {\"verbose\":false,\"lang\":\"rust\"}\r\nPUB orders.eu 2\r\nhi\r\n",
            )
            .await
            .expect("write");

        let reply = read_until(&mut stream, "\r\n", 20).await;
        assert!(
            reply.contains("-ERR '"),
            "a publish the backend could not answer must produce -ERR, got {reply:?}"
        );
        assert!(
            reply.contains("request could not be processed")
                || reply.contains("backend at capacity, retry later"),
            "the -ERR text must be a WireFailure category, got {reply:?}"
        );
        for forbidden in [
            "http://",
            "127.0.0.1:",
            "ollama",
            "llama",
            "src/",
            ".rs",
            "retries",
            "LLM",
        ] {
            assert!(
                !reply.contains(forbidden),
                "internal detail {forbidden:?} leaked to the peer: {reply:?}"
            );
        }

        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;
        Ok(())
    }
}

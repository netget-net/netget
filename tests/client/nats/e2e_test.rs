//! End-to-end NATS **client** tests.
//!
//! `test_nats_client_round_trips_through_the_official_nats_server` is what the `Beta` rating
//! rests on, and it is the only test here with **independent** peers on both sides: the
//! official Go `nats-server` routes the traffic and `async-nats` asks the question and reads
//! the answer. It is not `#[ignore]`d and it cannot skip — a missing binary fails the test
//! with a message saying why, because a `SKIP: … is not installed` gate is a silent pass and
//! would leave the rating resting on nothing.
//!
//! The other three peers are **same-project** and are here for what a real broker cannot show,
//! not as evidence of conformance:
//!
//! * the parser called directly — partial frames, byte counts, `HMSG` blocks;
//! * a broker hand-written in this file, which records the **exact bytes** NetGet puts on the
//!   wire and can inject frames (`-ERR`, an unsolicited `PING`) that a real server will not
//!   produce on demand;
//! * NetGet's own NATS server, which exercises this client's `MSG` parser against the other
//!   half's `MSG` writer.
//!
//! Read those three as internal consistency checks. On their own they would be the
//! circular-evidence class the root `CLAUDE.md` names for `webrtc_signaling` and `websocket`.
//!
//! LLM call budget: 13 across the whole file (0 + 3 + 3 + 5 + 2). The parser test makes none.
mod nats_client_e2e_test {
    use crate::helpers::{start_netget_client, start_netget_server, E2EResult, NetGetConfig};
    use netget::client::nats::{
        classify_permission_error, parse_server_frame, payload_for_event, ServerFrame,
        ServerFrameError,
    };
    use serde_json::json;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::{mpsc, Mutex};

    const MAX_PAYLOAD: usize = 1_048_576;

    // ========================================================================
    // Parser — no broker, no LLM calls
    // ========================================================================

    #[test]
    fn test_nats_client_parses_broker_frames() {
        // Half a control line is the normal case on a stream, not an error.
        assert_eq!(parse_server_frame(b"PIN", MAX_PAYLOAD).unwrap(), None);
        assert_eq!(
            parse_server_frame(b"PING\r\n", MAX_PAYLOAD).unwrap(),
            Some((ServerFrame::Ping, 6))
        );
        assert_eq!(
            parse_server_frame(b"PONG\r\n", MAX_PAYLOAD).unwrap(),
            Some((ServerFrame::Pong, 6))
        );
        assert_eq!(
            parse_server_frame(b"+OK\r\n", MAX_PAYLOAD).unwrap(),
            Some((ServerFrame::Ok, 5))
        );

        // -ERR: the single quotes are framing, not message.
        assert_eq!(
            parse_server_frame(b"-ERR 'Authorization Violation'\r\n", MAX_PAYLOAD).unwrap(),
            Some((ServerFrame::Err("Authorization Violation".to_string()), 32))
        );

        // INFO keeps the document verbatim — splitting on whitespace would corrupt any JSON
        // string containing a space.
        let (frame, consumed) = parse_server_frame(
            b"INFO {\"server_name\":\"my broker\",\"max_payload\":1024}\r\n",
            MAX_PAYLOAD,
        )
        .unwrap()
        .expect("INFO should parse");
        assert_eq!(consumed, 53);
        match frame {
            ServerFrame::Info(doc) => {
                assert_eq!(doc["server_name"], json!("my broker"));
                assert_eq!(doc["max_payload"], json!(1024));
            }
            other => panic!("expected Info, got {other:?}"),
        }

        // MSG with and without a reply subject. The payload is byte-counted, so it may
        // contain CRLF — a delimiter-based parser would split this message in two.
        assert_eq!(
            parse_server_frame(b"MSG greetings 7 5\r\nhello\r\n", MAX_PAYLOAD).unwrap(),
            Some((
                ServerFrame::Message {
                    subject: "greetings".to_string(),
                    sid: "7".to_string(),
                    reply_to: None,
                    headers: Default::default(),
                    payload: b"hello".to_vec(),
                },
                26
            ))
        );
        let (frame, _) = parse_server_frame(b"MSG q 1 _INBOX.9 6\r\na\r\nb\r\n\r\n", MAX_PAYLOAD)
            .unwrap()
            .expect("MSG with an embedded CRLF should parse");
        match frame {
            ServerFrame::Message {
                reply_to, payload, ..
            } => {
                assert_eq!(reply_to.as_deref(), Some("_INBOX.9"));
                assert_eq!(payload, b"a\r\nb\r\n".to_vec());
            }
            other => panic!("expected Message, got {other:?}"),
        }

        // A MSG whose payload has not fully arrived yields None, not a truncated message.
        assert_eq!(
            parse_server_frame(b"MSG greetings 7 5\r\nhel", MAX_PAYLOAD).unwrap(),
            None
        );

        // HMSG: header block and body are counted separately, and the block is parsed out.
        let (frame, _) = parse_server_frame(
            b"HMSG greetings 7 _INBOX.1 29 34\r\nNATS/1.0\r\nNats-Msg-Id: 42\r\n\r\nhello\r\n",
            MAX_PAYLOAD,
        )
        .unwrap()
        .expect("HMSG should parse");
        match frame {
            ServerFrame::Message {
                headers, payload, ..
            } => {
                assert_eq!(headers.get("Nats-Msg-Id").map(String::as_str), Some("42"));
                assert_eq!(payload, b"hello".to_vec());
            }
            other => panic!("expected Message, got {other:?}"),
        }

        // A body larger than the negotiated maximum is refused rather than allocated.
        assert_eq!(
            parse_server_frame(b"MSG greetings 7 99999\r\n", 10).unwrap_err(),
            ServerFrameError::MaximumPayloadViolation
        );
        // ...and so is an HMSG, whose header length used to be unbounded: the limit was
        // applied to `total - header`, so `header == total` gave a zero-length body that
        // passed every check with `total` free. 4 GB of buffering from one 38-byte line.
        assert_eq!(
            parse_server_frame(b"HMSG greetings 7 4000000000 4000000000\r\n", 10).unwrap_err(),
            ServerFrameError::MaximumPayloadViolation
        );
        // A declared size must never wrap the index that reads it. This one panicked on the
        // `after_line + total_len` overflow in debug, and on a `start > end` slice in release.
        let wrapping = format!("HMSG s 7 {max} {max}\r\n", max = usize::MAX);
        assert_eq!(
            parse_server_frame(wrapping.as_bytes(), usize::MAX).unwrap_err(),
            ServerFrameError::MaximumPayloadViolation
        );
        // A run of blank lines must not recurse. The skip used to call parse_server_frame
        // again per blank line, so 8 KB of newlines - one read - overflowed the stack, and a
        // Rust stack overflow is SIGSEGV rather than a catchable panic: the whole NetGet
        // process aborted. This test failing to complete *is* the regression.
        let mut flood = vec![b'\n'; 100_000];
        assert_eq!(parse_server_frame(&flood, MAX_PAYLOAD).unwrap(), None);
        assert_eq!(
            netget::client::nats::blank_line_prefix_len(&flood),
            flood.len(),
            "the reader must be able to drain the whole run, or the buffer grows forever"
        );
        flood.extend_from_slice(b"PING\r\n");
        assert_eq!(
            parse_server_frame(&flood, MAX_PAYLOAD).unwrap(),
            Some((ServerFrame::Ping, flood.len())),
            "a frame after the flood is still found, and the blank lines go with it"
        );
        // A verb no broker sends is a stream that is no longer frame-aligned.
        assert_eq!(
            parse_server_frame(b"BOGUS\r\n", MAX_PAYLOAD).unwrap_err(),
            ServerFrameError::UnknownProtocolOperation
        );

        // Event payload encoding: printable bytes go out as themselves, anything else as hex,
        // and payload_encoding is what makes the round trip reversible.
        assert_eq!(payload_for_event(b"hello"), ("hello".to_string(), "utf8"));
        assert_eq!(
            payload_for_event(&[0x00, 0xff]),
            ("00ff".to_string(), "hex")
        );

        // A permission denial names an operation and a subject the model can act on.
        assert_eq!(
            classify_permission_error("Permissions Violation for Publish to \"orders.eu\""),
            ("publish", Some("orders.eu".to_string()))
        );
        assert_eq!(
            classify_permission_error("Permissions Violation for Subscription to \"orders.>\"").0,
            "subscription"
        );
    }

    // ========================================================================
    // A NATS broker, hand-written from the protocol description
    // ========================================================================

    /// Accepts exactly one connection, greets it with `INFO`, records everything the client
    /// sends, and writes whatever the test hands it.
    ///
    /// Deliberately dumb: it routes nothing and decides nothing, so every assertion below is
    /// about bytes NetGet's client produced rather than about broker behaviour.
    struct TestBroker {
        addr: std::net::SocketAddr,
        from_client: Arc<Mutex<Vec<u8>>>,
        to_client: mpsc::UnboundedSender<Vec<u8>>,
        handle: tokio::task::JoinHandle<()>,
    }

    impl TestBroker {
        async fn start() -> E2EResult<Self> {
            let info = json!({
                "server_id": "NETGET-TEST-BROKER",
                "server_name": "test-broker",
                "version": "2.10.0",
                "proto": 1,
                "go": "",
                "host": "127.0.0.1",
                "port": 0,
                "headers": true,
                "max_payload": MAX_PAYLOAD,
                "client_id": 1,
                "client_ip": "127.0.0.1",
                "auth_required": false,
                "tls_required": false,
                "jetstream": false,
                "connect_urls": [],
            });

            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let addr = listener.local_addr()?;
            let from_client = Arc::new(Mutex::new(Vec::<u8>::new()));
            let (to_client, mut outbound) = mpsc::unbounded_channel::<Vec<u8>>();

            let recorded = from_client.clone();
            let handle = tokio::spawn(async move {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let (mut read_half, mut write_half) = tokio::io::split(stream);
                if write_half
                    .write_all(format!("INFO {}\r\n", info).as_bytes())
                    .await
                    .is_err()
                {
                    return;
                }
                let _ = write_half.flush().await;

                let mut chunk = vec![0u8; 8192];
                loop {
                    tokio::select! {
                        read = read_half.read(&mut chunk) => match read {
                            Ok(0) | Err(_) => break,
                            Ok(n) => recorded.lock().await.extend_from_slice(&chunk[..n]),
                        },
                        Some(bytes) = outbound.recv() => {
                            if write_half.write_all(&bytes).await.is_err() {
                                break;
                            }
                            let _ = write_half.flush().await;
                        }
                    }
                }
            });

            Ok(Self {
                addr,
                from_client,
                to_client,
                handle,
            })
        }

        fn send(&self, bytes: &str) {
            let _ = self.to_client.send(bytes.as_bytes().to_vec());
        }

        async fn text(&self) -> String {
            String::from_utf8_lossy(&self.from_client.lock().await).to_string()
        }

        /// Wait for the client to have sent `needle`, rather than sleeping and hoping. Under
        /// `--test-threads=100` a fixed sleep is the difference between a green suite and an
        /// arbitrary one.
        async fn wait_for(&self, needle: &str, secs: u64) -> String {
            let deadline = std::time::Instant::now() + Duration::from_secs(secs);
            loop {
                let seen = self.text().await;
                if seen.contains(needle) || std::time::Instant::now() >= deadline {
                    return seen;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }

    impl Drop for TestBroker {
        fn drop(&mut self) {
            self.handle.abort();
        }
    }

    // ========================================================================
    // The round trip: subscribe, receive, publish a model-authored reply
    // ========================================================================

    /// LLM calls: 3 (client startup, nats_connected, nats_message_received).
    #[tokio::test]
    async fn test_nats_client_subscribes_and_publishes_a_model_authored_reply() -> E2EResult<()> {
        let broker = TestBroker::start().await?;
        let broker_addr = broker.addr.to_string();

        let config = NetGetConfig::new(format!(
            "Join the NATS fabric at {} and act as an auditor. THIS-IS-THE-STARTUP-TURN.",
            broker_addr
        ))
        .with_mock({
            let broker_addr = broker_addr.clone();
            move |mock| {
                mock
                    // Startup. Matched on a phrase that appears only in the top-level prompt,
                    // so the per-event calls below (which carry the client's own instruction)
                    // cannot match it first — rules are first-match-wins.
                    .on_instruction_containing("THIS-IS-THE-STARTUP-TURN")
                    .respond_with_actions(json!([{
                        "type": "open_client",
                        "protocol": "NATS",
                        "remote_addr": broker_addr,
                        "instruction": "Subscribe to greetings and answer every message on its reply subject."
                    }]))
                    .expect_calls(1)
                    .and()
                    // The model chooses what to listen to. A client that subscribes to nothing
                    // hears nothing, so this is the first real decision of the session.
                    .on_event("nats_connected")
                    .respond_with_actions(json!([{
                        "type": "send_nats_subscribe",
                        "subject": "greetings",
                        "sid": "7"
                    }]))
                    .expect_calls(1)
                    .and()
                    // The capability this client exists for: live traffic in, a model-authored
                    // publish out, on the same connection. The reply quotes what arrived, so
                    // the assertion cannot pass on a canned response.
                    .on_event("nats_message_received")
                    .and_event_data_contains("subject", "greetings")
                    .respond_with_actions_from_event(|event| {
                        json!([{
                            "type": "send_nats_publish",
                            "subject": event["reply_to"].as_str().unwrap_or("greetings.reply"),
                            "payload": format!(
                                "the model saw: {}",
                                event["payload"].as_str().unwrap_or("")
                            )
                        }])
                    })
                    .expect_calls(1)
                    .and()
            }
        });

        let client = start_netget_client(config).await?;

        // The handshake NetGet performs before the model is consulted at all.
        let seen = broker.wait_for("CONNECT ", 30).await;
        assert!(
            seen.contains("CONNECT "),
            "client should send CONNECT after reading INFO. Saw: {seen:?}"
        );
        assert!(
            seen.contains("\"lang\":\"rust\""),
            "CONNECT should identify the client language. Saw: {seen:?}"
        );
        assert!(
            seen.contains("PING\r\n"),
            "client should PING after CONNECT to learn it was accepted. Saw: {seen:?}"
        );

        // The model's subscription.
        let seen = broker.wait_for("SUB greetings 7", 30).await;
        assert!(
            seen.contains("SUB greetings 7\r\n"),
            "the model's subscription should reach the broker verbatim. Saw: {seen:?}"
        );

        // Keepalive is answered in Rust. If it were routed through the model there would be no
        // matching mock rule, the request would 500, and no PONG would appear.
        broker.send("PING\r\n");
        let seen = broker.wait_for("PONG\r\n", 30).await;
        assert!(
            seen.contains("PONG\r\n"),
            "PING must be answered with PONG without an LLM call. Saw: {seen:?}"
        );

        // Deliver a message on the subscription the model made, with a reply subject.
        broker.send("MSG greetings 7 _INBOX.audit.1 5\r\nhello\r\n");

        let seen = broker.wait_for("PUB _INBOX.audit.1", 30).await;
        assert!(
            seen.contains("PUB _INBOX.audit.1 20\r\nthe model saw: hello\r\n"),
            "the model's reply should be published on the message's reply subject, with the \
             right byte count. Saw: {seen:?}"
        );

        client.wait_for_mocks(30).await;
        client.verify_mocks().await?;
        client.stop().await?;
        Ok(())
    }

    // ========================================================================
    // -ERR handling
    // ========================================================================

    /// A permissions violation leaves the connection open and names a subject; every other
    /// `-ERR` is fatal. The two are separate events because the model can act on one of them.
    ///
    /// LLM calls: 3 (client startup, nats_permission_error, nats_error_received). The
    /// `nats_connected` event is answered by a static handler, so it costs nothing.
    #[tokio::test]
    async fn test_nats_client_separates_permission_denials_from_fatal_errors() -> E2EResult<()> {
        let broker = TestBroker::start().await?;
        let broker_addr = broker.addr.to_string();

        let config = NetGetConfig::new(format!(
            "Join the NATS fabric at {} and report refusals. THIS-IS-THE-STARTUP-TURN.",
            broker_addr
        ))
        .with_mock({
            let broker_addr = broker_addr.clone();
            move |mock| {
                mock.on_instruction_containing("THIS-IS-THE-STARTUP-TURN")
                    .respond_with_actions(json!([{
                        "type": "open_client",
                        "protocol": "NATS",
                        "remote_addr": broker_addr,
                        "instruction": "Report anything the broker refuses.",
                        // The two -ERRs below arrive back to back and this test asserts each
                        // is its own event; batching them is `batching_test.rs`'s subject.
                        "batching": false,
                        "event_handlers": [{
                            "event_pattern": "nats_connected",
                            "handler": {
                                "type": "static",
                                "actions": [{
                                    "type": "send_nats_subscribe",
                                    "subject": "orders.>",
                                    "sid": "1"
                                }]
                            }
                        }]
                    }]))
                    .expect_calls(1)
                    .and()
                    .on_event("nats_permission_error")
                    .and_event_data_contains("operation", "publish")
                    .respond_with_actions(json!([{"type": "wait_for_more"}]))
                    .expect_calls(1)
                    .and()
                    .on_event("nats_error_received")
                    .and_event_data_contains("message", "Authorization Violation")
                    .respond_with_actions(json!([{"type": "disconnect"}]))
                    .expect_calls(1)
                    .and()
            }
        });

        let client = start_netget_client(config).await?;

        // The static handler subscribed with no model involvement, which is also the proof
        // that a zero-LLM routing rule reaches this client's action executor.
        let seen = broker.wait_for("SUB orders.> 1", 30).await;
        assert!(
            seen.contains("SUB orders.> 1\r\n"),
            "the static nats_connected handler should have subscribed. Saw: {seen:?}"
        );

        // Denied, but the session survives: the model answers wait_for_more and the socket
        // stays up for the fatal error that follows.
        broker.send("-ERR 'Permissions Violation for Publish to \"orders.eu\"'\r\n");
        // Fatal.
        broker.send("-ERR 'Authorization Violation'\r\n");

        client.wait_for_mocks(30).await;
        client.verify_mocks().await?;
        client.stop().await?;
        Ok(())
    }

    // ========================================================================
    // Against NetGet's own NATS server
    // ========================================================================

    /// Both halves of the same protocol, talking to each other.
    ///
    /// This is worth having — it is the only test that exercises NetGet's `MSG` writer against
    /// NetGet's `MSG` parser, and a byte-count mistake on either side fails it — but it is
    /// **same-project evidence** and proves nothing about spec conformance. See the file
    /// header.
    ///
    /// LLM calls: 5 (server startup, nats_subscribe, nats_publish; client startup,
    /// nats_message_received). The server's `nats_connect` and the client's `nats_connected`
    /// are answered by zero-action static handlers, and the client's own subscription comes
    /// from the `subscribe_subjects` startup parameter, so none of the three costs a call.
    #[tokio::test]
    async fn test_nats_client_completes_a_round_trip_with_the_netget_nats_server() -> E2EResult<()>
    {
        let server_config = NetGetConfig::new(
            "Run a NATS broker on port {AVAILABLE_PORT}. THIS-IS-THE-SERVER-STARTUP-TURN.",
        )
        .with_mock(|mock| {
            mock.on_instruction_containing("THIS-IS-THE-SERVER-STARTUP-TURN")
                .respond_with_actions(json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "nats",
                    "instruction": "Deliver a greeting to whoever subscribes.",
                    "event_handlers": [{
                        "event_pattern": "nats_connect",
                        // Answering with nothing is a real answer, and it costs no LLM call:
                        // the CONNECT document needs no reply when the client is not verbose.
                        "handler": {"type": "static", "actions": []}
                    }]
                }]))
                .expect_calls(1)
                .and()
                // The subscription arrives with a sid the client chose, so the delivery has to
                // be built from the event rather than from a constant.
                .on_event("nats_subscribe")
                .and_event_data_contains("subject", "greetings")
                .respond_with_actions_from_event(|event| {
                    json!([{
                        "type": "send_nats_message",
                        "subject": "greetings",
                        "sid": event["sid"].as_str().unwrap_or("1"),
                        "reply_to": "_INBOX.server.1",
                        "payload": "hello from the netget broker"
                    }])
                })
                .expect_calls(1)
                .and()
                // The last leg: the client's model-authored publish, arriving back at the
                // server as a real PUB frame.
                .on_event("nats_publish")
                .and_event_data_contains("subject", "_INBOX.server.1")
                .respond_with_actions(json!([]))
                .expect_calls(1)
                .and()
        });

        let server = start_netget_server(server_config).await?;
        server.wait_for_any(&["listening", "NATS"], 30).await;

        let client_config = NetGetConfig::new(format!(
            "Join the NATS broker at 127.0.0.1:{}. THIS-IS-THE-CLIENT-STARTUP-TURN.",
            server.port
        ))
        .with_mock({
            let remote = format!("127.0.0.1:{}", server.port);
            move |mock| {
                mock.on_instruction_containing("THIS-IS-THE-CLIENT-STARTUP-TURN")
                    .respond_with_actions(json!([{
                        "type": "open_client",
                        "protocol": "NATS",
                        "remote_addr": remote,
                        "instruction": "Answer greetings on their reply subject.",
                        // Subscribing from a startup parameter rather than from the model:
                        // messages published before the model has answered would otherwise be
                        // missed, and on a dashboard-created instance that answer waits for a
                        // human.
                        "startup_params": {"subscribe_subjects": ["greetings"]},
                        "event_handlers": [{
                            "event_pattern": "nats_connected",
                            "handler": {"type": "static", "actions": []}
                        }]
                    }]))
                    .expect_calls(1)
                    .and()
                    .on_event("nats_message_received")
                    .and_event_data_contains("payload", "hello from the netget broker")
                    .respond_with_actions_from_event(|event| {
                        json!([{
                            "type": "send_nats_publish",
                            "subject": event["reply_to"].as_str().unwrap_or("greetings.reply"),
                            "payload": "ack"
                        }])
                    })
                    .expect_calls(1)
                    .and()
            }
        });

        let client = start_netget_client(client_config).await?;
        client.wait_for_any(&["connected"], 30).await;

        server.wait_for_mocks(30).await;
        client.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        client.verify_mocks().await?;

        client.stop().await?;
        server.stop().await?;
        Ok(())
    }

    // ========================================================================
    // Against the official nats-server binary — the evidence the rating rests on
    // ========================================================================

    /// The real `nats-server`, spawned on an ephemeral loopback port and killed on every exit
    /// path including a panic.
    ///
    /// A leaked broker would poison later runs, and `Drop` runs during unwinding, so the kill
    /// lives there rather than at the end of the test body.
    struct RealNatsServer {
        port: u16,
        child: std::process::Child,
    }

    impl RealNatsServer {
        /// Spawn `nats-server -a 127.0.0.1 -p -1` and read the port it chose out of its log.
        ///
        /// **Hard-fails when the binary is missing.** It deliberately does not print
        /// `SKIP: nats-server is not installed` and return `Ok(())`: on a runner without the
        /// binary that is a silent pass, and this client's `Beta` rating would then rest on
        /// nothing. `npm`'s real-CLI test is the shape being copied, and
        /// `kubernetes`/`oci_registry`/`maven`/`websocket` are what the other shape costs.
        fn start() -> E2EResult<Self> {
            let mut child = std::process::Command::new("nats-server")
                .args(["-a", "127.0.0.1", "-p", "-1"])
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .map_err(|e| -> Box<dyn std::error::Error> {
                    format!(
                        "could not spawn the official `nats-server` binary: {e}. This test is \
                         the only independent evidence the NATS client has - every other peer \
                         in this file is same-project - so it fails rather than skipping. \
                         Skipping would leave the client's maturity rating resting on nothing. \
                         Install it with `brew install nats-server` (or the release tarball) \
                         and re-run."
                    )
                    .into()
                })?;

            // nats-server logs "Listening for client connections on 127.0.0.1:<port>" to
            // stderr on startup. Reading it is how the ephemeral port is learned; -p -1 is
            // used rather than binding a probe socket ourselves precisely so there is no
            // window in which another test can take the port.
            use std::io::{BufRead, BufReader};
            let stderr = child.stderr.take().expect("piped stderr");
            let mut reader = BufReader::new(stderr);
            let mut port = None;
            let deadline = std::time::Instant::now() + Duration::from_secs(20);
            let mut transcript = String::new();
            while std::time::Instant::now() < deadline {
                let mut line = String::new();
                match reader.read_line(&mut line) {
                    Ok(0) => break,
                    Ok(_) => {}
                    Err(e) => {
                        let _ = child.kill();
                        return Err(format!("reading nats-server output failed: {e}").into());
                    }
                }
                transcript.push_str(&line);
                if let Some(rest) = line.split("Listening for client connections on ").nth(1) {
                    if let Some(found) = rest.trim().rsplit(':').next() {
                        port = found.trim().parse::<u16>().ok();
                    }
                }
                if port.is_some() {
                    break;
                }
            }

            match port {
                Some(port) => Ok(Self { port, child }),
                None => {
                    let _ = child.kill();
                    Err(format!(
                        "nats-server never reported a listening port. Output so far:\n{transcript}"
                    )
                    .into())
                }
            }
        }
    }

    impl Drop for RealNatsServer {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    /// **This is the test the maturity rating rests on.** Two independent implementations sit
    /// on either side of NetGet: the official Go `nats-server` routes the traffic, and
    /// `async-nats` is the peer that asks the question and reads the answer. Neither is ours.
    ///
    /// What passing it proves, in order, none of which a same-project peer can show:
    ///
    /// 1. `nats-server` accepted NetGet's `CONNECT` document. It parses the document
    ///    strictly, so a wrongly-typed field would fail the session here and nowhere else.
    /// 2. NetGet parsed a real `INFO` — one carrying fields, a `max_payload` and a
    ///    `server_id` nothing in this project wrote.
    /// 3. `nats-server`'s own routing table matched NetGet's `SUB` and delivered to it. The
    ///    subject match is Go's, not ours.
    /// 4. NetGet framed the inbound `MSG` correctly, handed it to the model, and published
    ///    the model's answer on the reply subject — the round trip the client exists for.
    /// 5. `nats-server` routed that answer back to `async-nats`, which parsed it as a reply
    ///    to its own request.
    ///
    /// LLM calls: 2 (client startup, nats_message_received). The `nats_connected` event is
    /// answered by a static handler, which costs none.
    #[tokio::test]
    async fn test_nats_client_round_trips_through_the_official_nats_server() -> E2EResult<()> {
        let broker = RealNatsServer::start()?;
        let broker_addr = format!("127.0.0.1:{}", broker.port);

        // The independent peer. It connects first and subscribes to the readiness subject
        // *before* NetGet starts, so there is no window in which the announcement below can be
        // published to nobody.
        let peer = async_nats::connect(&broker_addr).await?;
        let mut ready = peer.subscribe("netget.ready").await?;
        peer.flush().await?;

        let config = NetGetConfig::new(format!(
            "Join the NATS fabric at {} as a responder. THIS-IS-THE-STARTUP-TURN.",
            broker_addr
        ))
        .with_mock({
            let broker_addr = broker_addr.clone();
            move |mock| {
                mock.on_instruction_containing("THIS-IS-THE-STARTUP-TURN")
                    .respond_with_actions(json!([{
                        "type": "open_client",
                        "protocol": "NATS",
                        "remote_addr": broker_addr,
                        "instruction": "Answer every request on its reply subject.",
                        // Subscribing from the startup parameter rather than from the model
                        // is what makes the readiness announcement below meaningful: the SUB
                        // is written before the announcement, on the same connection, so a
                        // broker that has processed the announcement has processed the SUB.
                        "startup_params": {"subscribe_subjects": ["netget.e2e"]},
                        "event_handlers": [{
                            "event_pattern": "nats_connected",
                            "handler": {
                                "type": "static",
                                "actions": [{
                                    "type": "send_nats_publish",
                                    "subject": "netget.ready",
                                    "payload": "subscribed"
                                }]
                            }
                        }]
                    }]))
                    .expect_calls(1)
                    .and()
                    // The one decision in the test. The answer quotes the request, so it
                    // cannot be satisfied by anything canned.
                    .on_event("nats_message_received")
                    .and_event_data_contains("subject", "netget.e2e")
                    .respond_with_actions_from_event(|event| {
                        json!([{
                            "type": "send_nats_publish",
                            "subject": event["reply_to"].as_str().unwrap_or("netget.e2e.reply"),
                            "payload": format!(
                                "the model saw: {}",
                                event["payload"].as_str().unwrap_or("")
                            )
                        }])
                    })
                    .expect_calls(1)
                    .and()
            }
        });

        let client = start_netget_client(config).await?;

        // Readiness, established through the real broker rather than by sleeping: this message
        // travelled NetGet -> nats-server -> async-nats, so by the time it arrives the
        // subscription that preceded it on the same connection is registered.
        //
        // It is also the first proof of the handshake: nats-server would have refused the
        // CONNECT document, and no announcement would exist to receive.
        let announcement = tokio::time::timeout(
            Duration::from_secs(30),
            futures::StreamExt::next(&mut ready),
        )
        .await
        .map_err(|_| -> Box<dyn std::error::Error> {
            "the NetGet client never announced itself through nats-server. Either its \
                 CONNECT was refused, or its startup subscription/publish never reached the \
                 broker."
                .into()
        })?
        .ok_or_else(|| -> Box<dyn std::error::Error> {
            "the readiness subscription closed before the announcement arrived".into()
        })?;
        assert_eq!(
            announcement.payload.as_ref(),
            b"subscribed",
            "the announcement should carry the payload the static handler published"
        );

        // The round trip. `request` allocates its own inbox, subscribes to it, publishes with
        // that subject as reply-to and waits — so the reply has to be routed back by
        // nats-server to a subject NetGet learned only from the inbound MSG.
        let response = tokio::time::timeout(
            Duration::from_secs(30),
            peer.request("netget.e2e", "ping from async-nats".into()),
        )
        .await
        .map_err(|_| -> Box<dyn std::error::Error> {
            "no reply within 30s: nats-server delivered the request but the model's answer \
             never came back. This is the shape the 'client throws the model's answer away' \
             defect takes."
                .into()
        })??;

        assert_eq!(
            String::from_utf8_lossy(&response.payload),
            "the model saw: ping from async-nats",
            "the reply must be the model's, and must quote the request that async-nats sent \
             through the real broker"
        );

        client.wait_for_mocks(30).await;
        client.verify_mocks().await?;
        client.stop().await?;
        Ok(())
    }
}

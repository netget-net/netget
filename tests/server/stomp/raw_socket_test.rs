//! STOMP cases a real client library cannot express.
//!
//! `e2e_test.rs` drives the server with `async-stomp`, and that is where the `Beta` rating's
//! evidence lives. This file exists for the things that client *cannot do*, and only those:
//!
//! - **A body containing NUL.** `async-stomp` never writes a `content-length` header
//!   (`ToServer::Send` builds its frame without one), so it physically cannot publish a body
//!   with a NUL in it. That is precisely the case where `content-length` becomes authoritative,
//!   and the case a "read to the terminator" parser silently truncates.
//! - **A frame sent before the handshake**, an **unsupported `accept-version`**, and
//!   **deliberately broken framing**. `Connector::connect()` always handshakes first and always
//!   sends `accept-version:1.2`, so none of these is reachable through it.
//!
//! The peer below is therefore a raw socket with a hand-written reader. It is **not** evidence
//! for the maturity rating — an independent reading of the spec is not an independent
//! implementation — and it does not call `netget::server::stomp::frame`, for the same
//! circular-evidence reason stated in `e2e_test.rs`.
//!
//! LLM budget: 3 calls across two tests.

mod stomp_raw_socket_test {
    use crate::helpers::{start_netget_server, E2EResult, NetGetConfig};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    /// One frame as this test understands it.
    #[derive(Debug)]
    struct ParsedFrame {
        command: String,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    }

    impl ParsedFrame {
        fn header(&self, name: &str) -> Option<&str> {
            self.headers
                .iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.as_str())
        }
    }

    /// A deliberately independent STOMP peer.
    ///
    /// It honours `content-length` when present and falls back to the NUL terminator when it
    /// is not — the one framing rule this test cannot skip, since the whole point below is a
    /// body that contains NUL.
    struct RawStomp {
        stream: TcpStream,
        buf: Vec<u8>,
    }

    impl RawStomp {
        async fn connect(addr: &str) -> Self {
            let stream = tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(addr))
                .await
                .expect("timed out connecting to the STOMP server")
                .expect("could not connect to the STOMP server");
            Self {
                stream,
                buf: Vec::new(),
            }
        }

        async fn send_frame(&mut self, command: &str, headers: &[(&str, &str)], body: &[u8]) {
            let mut wire = Vec::new();
            wire.extend_from_slice(command.as_bytes());
            wire.push(b'\n');
            for (k, v) in headers {
                wire.extend_from_slice(format!("{k}:{v}\n").as_bytes());
            }
            if !body.is_empty() {
                wire.extend_from_slice(format!("content-length:{}\n", body.len()).as_bytes());
            }
            wire.push(b'\n');
            wire.extend_from_slice(body);
            wire.push(0);
            self.stream
                .write_all(&wire)
                .await
                .expect("failed to write a STOMP frame");
            self.stream.flush().await.expect("failed to flush");
        }

        /// Write bytes exactly as given — for the malformed-input cases.
        async fn send_raw(&mut self, bytes: &[u8]) {
            self.stream.write_all(bytes).await.expect("failed to write");
            self.stream.flush().await.expect("failed to flush");
        }

        async fn next_frame(&mut self) -> ParsedFrame {
            let mut tmp = vec![0u8; 4096];
            loop {
                if let Some(frame) = take_frame(&mut self.buf) {
                    return frame;
                }
                let n = tokio::time::timeout(Duration::from_secs(20), self.stream.read(&mut tmp))
                    .await
                    .expect("timed out waiting for a STOMP frame")
                    .expect("read error while waiting for a STOMP frame");
                assert!(
                    n > 0,
                    "the server closed the connection while a frame was expected; buffered so \
                     far: {:?}",
                    String::from_utf8_lossy(&self.buf)
                );
                self.buf.extend_from_slice(&tmp[..n]);
            }
        }

        /// The server must hang up, and must not have said anything we did not read.
        async fn expect_eof(&mut self) {
            assert!(
                take_frame(&mut self.buf).is_none(),
                "an unread frame was still buffered when EOF was expected"
            );
            let mut tmp = vec![0u8; 4096];
            let n = tokio::time::timeout(Duration::from_secs(20), self.stream.read(&mut tmp))
                .await
                .expect("timed out waiting for the server to close the connection")
                .expect("read error while waiting for EOF");
            assert_eq!(
                n,
                0,
                "expected the server to close, but it sent {:?}",
                String::from_utf8_lossy(&tmp[..n])
            );
        }
    }

    /// Take one complete frame off the front of `buf`, or leave it untouched.
    fn take_frame(buf: &mut Vec<u8>) -> Option<ParsedFrame> {
        let mut pos = 0usize;
        while pos < buf.len() && (buf[pos] == b'\n' || buf[pos] == b'\r') {
            pos += 1;
        }

        let mut command: Option<String> = None;
        let mut headers: Vec<(String, String)> = Vec::new();
        loop {
            let nl = buf[pos..].iter().position(|&b| b == b'\n')? + pos;
            let mut end = nl;
            if end > pos && buf[end - 1] == b'\r' {
                end -= 1;
            }
            let line = String::from_utf8_lossy(&buf[pos..end]).to_string();
            pos = nl + 1;
            if command.is_none() {
                command = Some(line);
                continue;
            }
            if line.is_empty() {
                break;
            }
            let (k, v) = line
                .split_once(':')
                .unwrap_or_else(|| panic!("server sent a header line with no ':': {line:?}"));
            headers.push((k.to_string(), v.to_string()));
        }

        let declared = headers
            .iter()
            .find(|(k, _)| k == "content-length")
            .map(|(_, v)| {
                v.parse::<usize>()
                    .unwrap_or_else(|_| panic!("server sent a non-numeric content-length: {v:?}"))
            });

        let (body, consumed) = match declared {
            Some(len) => {
                if pos + len >= buf.len() {
                    return None;
                }
                assert_eq!(
                    buf[pos + len],
                    0,
                    "content-length bytes were not followed by a NUL terminator"
                );
                (buf[pos..pos + len].to_vec(), pos + len + 1)
            }
            None => {
                let offset = buf[pos..].iter().position(|&b| b == 0)?;
                (buf[pos..pos + offset].to_vec(), pos + offset + 1)
            }
        };

        let frame = ParsedFrame {
            command: command?,
            headers,
            body,
        };
        buf.drain(..consumed);
        Some(frame)
    }

    /// A body containing NUL survives the `body`/`body_encoding` contract byte for byte.
    ///
    /// The handshake is answered by a **static** handler declared on the server, so it costs no
    /// LLM call — which is also worth exercising, since a static `stomp_connect` rule is the
    /// obvious way an operator would run this protocol deterministically.
    #[tokio::test]
    async fn test_stomp_binary_body_survives_the_encoding_round_trip() -> E2EResult<()> {
        let config =
            NetGetConfig::new("listen on port {AVAILABLE_PORT} via stomp")
                .with_log_level("debug")
                .with_mock(|mock| {
                    mock.on_instruction_containing("listen on port")
                    .and_instruction_containing("stomp")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "open_server",
                            "port": 0,
                            "base_stack": "stomp",
                            "instruction": "STOMP broker: echo whatever is published",
                            "event_handlers": [{
                                "event_pattern": "stomp_connect",
                                "handler": {
                                    "type": "static",
                                    "actions": [{
                                        "type": "send_stomp_connected",
                                        "session": "session-raw",
                                        "server": "netget/stomp"
                                    }]
                                }
                            }]
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // Echo the published body back with the *same* encoding the event
                    // reported. The body is binary, so the exact bytes only come back if the
                    // hex contract holds in both directions.
                    .on_event("stomp_send")
                    .respond_with_actions_from_event(|e| serde_json::json!([{
                        "type": "send_stomp_message",
                        "destination": e["destination"].as_str().unwrap_or("/queue/unknown"),
                        "subscription": "sub-0",
                        "message_id": "msg-echo",
                        "body": e["body"].as_str().unwrap_or(""),
                        "encoding": e["body_encoding"].as_str().unwrap_or("utf8")
                    }]))
                    .expect_calls(1)
                    .and()
                });

        let server = start_netget_server(config).await?;
        let addr = format!("127.0.0.1:{}", server.port);
        let mut client = RawStomp::connect(&addr).await;

        client
            .send_frame(
                "CONNECT",
                &[
                    ("accept-version", "1.2"),
                    ("host", "localhost"),
                    ("heart-beat", "10000,10000"),
                ],
                b"",
            )
            .await;

        let connected = client.next_frame().await;
        assert_eq!(connected.command, "CONNECTED", "frame: {connected:?}");
        assert_eq!(connected.header("session"), Some("session-raw"));
        assert_eq!(
            connected.header("heart-beat"),
            Some("0,0"),
            "the client asked for 10000,10000 but this server implements no heart-beat timer, \
             so it must negotiate it off rather than promise something it cannot keep"
        );

        let binary_body: Vec<u8> = vec![0x00, 0x01, 0xff, 0x00, 0x7f, 0x80];
        client
            .send_frame(
                "SEND",
                &[("destination", "/queue/test"), ("receipt", "r-send")],
                &binary_body,
            )
            .await;

        let echoed = client.next_frame().await;
        assert_eq!(echoed.command, "MESSAGE", "frame: {echoed:?}");
        assert_eq!(echoed.header("message-id"), Some("msg-echo"));
        assert_eq!(
            echoed.body, binary_body,
            "the published bytes did not survive the body/body_encoding round trip"
        );

        // The receipt comes *after* the handler's own output: the spec has it acknowledge a
        // frame that has been processed, and that is also the only order in which a handler
        // can answer before the acknowledgement.
        let receipt = client.next_frame().await;
        assert_eq!(receipt.command, "RECEIPT", "frame: {receipt:?}");
        assert_eq!(receipt.header("receipt-id"), Some("r-send"));

        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;
        Ok(())
    }

    /// Everything a peer can get wrong about the protocol is refused in Rust, without a single
    /// LLM call — three connections against one server, and the only mocked call is the
    /// startup one.
    ///
    /// This is the check that matters most for a honeypot: if framing were a question the model
    /// got asked, a stranger could provoke an LLM round trip with one malformed byte. The
    /// assertion is `verify_mocks` — any event that reached the model would match no rule, fall
    /// through, and fail the run.
    #[tokio::test]
    async fn test_stomp_protocol_errors_never_reach_the_model() -> E2EResult<()> {
        let config = NetGetConfig::new("listen on port {AVAILABLE_PORT} via stomp")
            .with_log_level("debug")
            .with_mock(|mock| {
                mock.on_instruction_containing("listen on port")
                    .and_instruction_containing("stomp")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "open_server",
                            "port": 0,
                            "base_stack": "stomp",
                            "instruction": "STOMP broker"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
            });

        let server = start_netget_server(config).await?;
        let addr = format!("127.0.0.1:{}", server.port);

        // 1. A frame before the handshake.
        let mut client = RawStomp::connect(&addr).await;
        client
            .send_frame(
                "SUBSCRIBE",
                &[("destination", "/queue/test"), ("id", "sub-0")],
                b"",
            )
            .await;
        let error = client.next_frame().await;
        assert_eq!(error.command, "ERROR", "frame: {error:?}");
        assert_eq!(error.header("message"), Some("expected CONNECT"));
        client.expect_eof().await;

        // 2. A version this server does not implement. The refusal names what it does speak,
        //    as the spec asks.
        let mut client = RawStomp::connect(&addr).await;
        client
            .send_frame(
                "CONNECT",
                &[("accept-version", "1.0,1.1"), ("host", "localhost")],
                b"",
            )
            .await;
        let error = client.next_frame().await;
        assert_eq!(error.command, "ERROR", "frame: {error:?}");
        assert_eq!(error.header("message"), Some("unsupported version"));
        assert_eq!(error.header("version"), Some("1.2"));
        client.expect_eof().await;

        // 3. Framing the parser cannot recover from.
        let mut client = RawStomp::connect(&addr).await;
        client
            .send_raw(b"CONNECT\nthis-line-has-no-colon\n\n\0")
            .await;
        let error = client.next_frame().await;
        assert_eq!(error.command, "ERROR", "frame: {error:?}");
        assert_eq!(error.header("message"), Some("malformed frame"));
        client.expect_eof().await;

        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;
        Ok(())
    }
}

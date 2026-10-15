//! E2E tests for the WebSocket (RFC 6455) server.
//!
//! # Why there is a hand-written client in here
//!
//! The server's framing comes from `tokio-tungstenite`. Driving it with `tokio-tungstenite`
//! would prove that the crate agrees with itself, which is the weak-evidence trap CLAUDE.md
//! warns about. So the primary peer in this file is a **raw TCP client written here**: it
//! composes the HTTP upgrade by hand, recomputes `Sec-WebSocket-Accept` from the RFC 6455
//! §4.2.2 algorithm using `sha1` + `base64` directly, masks its own frames per §5.3, and
//! parses the server's frames byte by byte — asserting, among other things, that the server
//! never masks (§5.1) and that close frames carry a big-endian status code (§5.5).
//!
//! On top of that, `websocat` (a separately built, widely used binary) drives the same server
//! end to end, so the whole path is exercised by something that is not this test. `websocat`
//! 1.x is built on the `websocket` / `websocket-base` crates (rust-websocket) rather than on
//! `tungstenite`, so it is a second, genuinely independent RFC 6455 implementation and not the
//! circular-evidence case. That test **fails** when `websocat` is missing; it does not skip.
//!
//! # LLM call budget: 6 (plus repair retries on the one deliberate failure)
//!
//! - `test_websocket_wire_protocol_against_raw_client`: 1 (`open_server`; every event on that
//!   server is answered by a static handler, so frames cost nothing)
//! - `test_websocket_subprotocol_and_rejection`: 4 (`open_server`, two `websocket_handshake`
//!   decisions, one `websocket_connection_opened`)
//! - `test_websocket_with_websocat`: 0 additional (reuses the static-handler server started
//!   inside it — 1 `open_server`)
//! - `test_websocket_handshake_backend_failure_is_tagged_fail_closed`: 1 (`open_server`) plus
//!   one deliberately unanswerable `websocket_handshake`, which the repair loop retries

use crate::server::helpers::*;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

// ============================================================================
// A deliberately independent WebSocket client
// ============================================================================

const OPCODE_CONTINUATION: u8 = 0x0;
const OPCODE_TEXT: u8 = 0x1;
const OPCODE_BINARY: u8 = 0x2;
const OPCODE_CLOSE: u8 = 0x8;
const OPCODE_PING: u8 = 0x9;
const OPCODE_PONG: u8 = 0xA;

/// One frame read off the wire, with the bits that matter kept separate.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Frame {
    fin: bool,
    opcode: u8,
    /// Asserted inside `next_frame`; kept so a failure message can show it.
    #[allow(dead_code)]
    masked: bool,
    payload: Vec<u8>,
}

struct RawWsClient {
    stream: TcpStream,
    buf: Vec<u8>,
    /// The `Sec-WebSocket-Accept` the server answered with.
    accept: String,
    /// The `Sec-WebSocket-Protocol` the server answered with, if any.
    subprotocol: Option<String>,
}

/// `base64(SHA-1(key + GUID))` — RFC 6455 §4.2.2 step 5.4, implemented here from the spec
/// text rather than reused from the server, so the two are independent.
fn expected_accept_key(client_key: &str) -> String {
    use base64::Engine as _;
    use sha1::{Digest, Sha1};

    let mut hasher = Sha1::new();
    hasher.update(client_key.as_bytes());
    hasher.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    base64::engine::general_purpose::STANDARD.encode(hasher.finalize())
}

impl RawWsClient {
    /// Open a connection and perform the handshake by hand.
    async fn connect(
        port: u16,
        path: &str,
        subprotocols: &[&str],
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let mut stream = TcpStream::connect(("127.0.0.1", port)).await?;

        // A fixed nonce keeps the assertion reproducible; RFC 6455 only requires that the
        // client picks a random 16-byte value and base64s it.
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        let mut request = format!(
            "GET {path} HTTP/1.1\r\n\
             Host: 127.0.0.1:{port}\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Key: {key}\r\n\
             Sec-WebSocket-Version: 13\r\n"
        );
        if !subprotocols.is_empty() {
            request.push_str(&format!(
                "Sec-WebSocket-Protocol: {}\r\n",
                subprotocols.join(", ")
            ));
        }
        request.push_str("\r\n");
        stream.write_all(request.as_bytes()).await?;
        stream.flush().await?;

        let (status, headers, leftover) = read_http_response(&mut stream).await?;
        if status != 101 {
            return Err(format!("expected 101, got {status}").into());
        }

        let accept = headers
            .iter()
            .find(|(k, _)| k == "sec-websocket-accept")
            .map(|(_, v)| v.clone())
            .ok_or("101 response has no Sec-WebSocket-Accept header")?;

        // The header the RFC actually specifies, checked against an implementation that is
        // not the server's.
        assert_eq!(
            accept,
            expected_accept_key(key),
            "Sec-WebSocket-Accept does not match base64(SHA-1(key + GUID))"
        );

        assert!(
            headers
                .iter()
                .any(|(k, v)| k == "upgrade" && v.eq_ignore_ascii_case("websocket")),
            "101 response is missing Upgrade: websocket"
        );
        assert!(
            headers
                .iter()
                .any(|(k, v)| k == "connection" && v.to_ascii_lowercase().contains("upgrade")),
            "101 response is missing Connection: Upgrade"
        );

        let subprotocol = headers
            .iter()
            .find(|(k, _)| k == "sec-websocket-protocol")
            .map(|(_, v)| v.clone());

        Ok(Self {
            stream,
            buf: leftover,
            accept,
            subprotocol,
        })
    }

    /// Write a client frame. RFC 6455 §5.3: every client-to-server frame is masked with a
    /// fresh 32-bit key, and the payload is XORed with it.
    async fn send_frame(
        &mut self,
        opcode: u8,
        payload: &[u8],
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.send_frame_fin(opcode, payload, true).await
    }

    /// As `send_frame`, but with control over the FIN bit so a message can be fragmented.
    async fn send_frame_fin(
        &mut self,
        opcode: u8,
        payload: &[u8],
        fin: bool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut out = vec![if fin { 0x80 | opcode } else { opcode }];
        let len = payload.len();
        if len < 126 {
            out.push(0x80 | len as u8);
        } else if len <= u16::MAX as usize {
            out.push(0x80 | 126);
            out.extend_from_slice(&(len as u16).to_be_bytes());
        } else {
            out.push(0x80 | 127);
            out.extend_from_slice(&(len as u64).to_be_bytes());
        }
        let mask: [u8; 4] = [0x37, 0xfa, 0x21, 0x3d];
        out.extend_from_slice(&mask);
        out.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));

        self.stream.write_all(&out).await?;
        self.stream.flush().await?;
        Ok(())
    }

    async fn send_text(&mut self, text: &str) -> Result<(), Box<dyn std::error::Error>> {
        self.send_frame(OPCODE_TEXT, text.as_bytes()).await
    }

    async fn send_close(
        &mut self,
        code: u16,
        reason: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut payload = code.to_be_bytes().to_vec();
        payload.extend_from_slice(reason.as_bytes());
        self.send_frame(OPCODE_CLOSE, &payload).await
    }

    /// Read exactly `n` more bytes into the buffer.
    async fn fill(&mut self, n: usize) -> Result<(), Box<dyn std::error::Error>> {
        while self.buf.len() < n {
            let mut chunk = [0u8; 4096];
            let read = self.stream.read(&mut chunk).await?;
            if read == 0 {
                return Err("connection closed while reading a frame".into());
            }
            self.buf.extend_from_slice(&chunk[..read]);
        }
        Ok(())
    }

    /// Parse one server frame. Server-to-client frames must not be masked (§5.1).
    async fn next_frame(&mut self) -> Result<Frame, Box<dyn std::error::Error>> {
        self.fill(2).await?;
        let b0 = self.buf[0];
        let b1 = self.buf[1];
        let fin = b0 & 0x80 != 0;
        let opcode = b0 & 0x0f;
        let masked = b1 & 0x80 != 0;
        assert!(
            !masked,
            "RFC 6455 section 5.1: a server MUST NOT mask frames it sends"
        );

        let short_len = (b1 & 0x7f) as usize;
        let (len, header) = match short_len {
            126 => {
                self.fill(4).await?;
                (
                    u16::from_be_bytes([self.buf[2], self.buf[3]]) as usize,
                    4usize,
                )
            }
            127 => {
                self.fill(10).await?;
                let mut raw = [0u8; 8];
                raw.copy_from_slice(&self.buf[2..10]);
                (u64::from_be_bytes(raw) as usize, 10usize)
            }
            n => (n, 2usize),
        };

        self.fill(header + len).await?;
        let payload = self.buf[header..header + len].to_vec();
        self.buf.drain(..header + len);

        Ok(Frame {
            fin,
            opcode,
            masked,
            payload,
        })
    }

    /// Read frames until one with a data or close opcode turns up, answering nothing.
    async fn next_frame_timeout(&mut self, secs: u64) -> Result<Frame, Box<dyn std::error::Error>> {
        match tokio::time::timeout(Duration::from_secs(secs), self.next_frame()).await {
            Ok(r) => r,
            Err(_) => Err(format!("timed out after {secs}s waiting for a frame").into()),
        }
    }
}

/// Read an HTTP response head, returning the status, lowercased headers, and any bytes that
/// followed the blank line.
async fn read_http_response(
    stream: &mut TcpStream,
) -> Result<(u16, Vec<(String, String)>, Vec<u8>), Box<dyn std::error::Error>> {
    let mut buf: Vec<u8> = Vec::new();
    loop {
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf[..pos]).to_string();
            let leftover = buf[pos + 4..].to_vec();

            let mut lines = head.split("\r\n");
            let status_line = lines.next().unwrap_or("");
            let status: u16 = status_line
                .split(' ')
                .nth(1)
                .and_then(|s| s.parse().ok())
                .ok_or_else(|| format!("malformed status line: {status_line:?}"))?;
            let headers = lines
                .filter_map(|l| l.split_once(':'))
                .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
                .collect();
            return Ok((status, headers, leftover));
        }
        if buf.len() > 64 * 1024 {
            return Err("HTTP response head too large".into());
        }
        let mut chunk = [0u8; 1024];
        let read = tokio::time::timeout(Duration::from_secs(10), stream.read(&mut chunk)).await??;
        if read == 0 {
            return Err(format!(
                "connection closed before a complete HTTP response; got {:?}",
                String::from_utf8_lossy(&buf)
            )
            .into());
        }
        buf.extend_from_slice(&chunk[..read]);
    }
}

// ============================================================================
// Spec vectors and codec symmetry — no server, no LLM
// ============================================================================

/// RFC 6455 §1.3 publishes the worked example for the handshake. If the server's
/// `Sec-WebSocket-Accept` computation ever drifts, every real client rejects the connection,
/// so this vector is the cheapest possible guard.
#[test]
fn test_sec_websocket_accept_matches_the_rfc6455_worked_example() {
    let response =
        ::netget::server::websocket::build_accept_response("dGhlIHNhbXBsZSBub25jZQ==", None, None);

    assert!(
        response.contains("Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo="),
        "RFC 6455 section 1.3 says the key dGhlIHNhbXBsZSBub25jZQ== must produce \
         s3pPLMBiTxaQ9kYGzzhZRbK+xOo=; got:\n{response}"
    );
    assert!(response.starts_with("HTTP/1.1 101 Switching Protocols\r\n"));
    assert!(response.contains("Upgrade: websocket\r\n"));
    assert!(response.contains("Connection: Upgrade\r\n"));
    assert!(
        !response.contains("Sec-WebSocket-Protocol"),
        "no subprotocol was chosen, so the header must be absent"
    );
    assert!(
        !response.contains("Sec-WebSocket-Extensions"),
        "no extension was negotiated, so the header must be absent"
    );
    assert!(response.ends_with("\r\n\r\n"));
}

#[test]
fn test_accept_response_echoes_only_a_chosen_subprotocol() {
    let response = ::netget::server::websocket::build_accept_response(
        "dGhlIHNhbXBsZSBub25jZQ==",
        Some("chat"),
        None,
    );
    assert!(response.contains("Sec-WebSocket-Protocol: chat\r\n"));
}

#[test]
fn test_parse_request_head_splits_target_and_headers() {
    let head = ::netget::server::websocket::parse_request_head(
        b"GET /ws?token=abc HTTP/1.1\r\n\
          Host: example.com\r\n\
          Upgrade: WebSocket\r\n\
          Sec-WebSocket-Protocol: chat, superchat\r\n\
          Sec-WebSocket-Protocol: json\r\n",
    )
    .expect("well formed request head");

    assert_eq!(head.method, "GET");
    assert_eq!(head.path(), "/ws");
    assert_eq!(head.query(), "token=abc");
    assert_eq!(head.header("HOST"), Some("example.com"));
    // RFC 6455 section 4.1 allows the header both repeated and comma-separated.
    assert_eq!(
        head.offered_subprotocols(),
        vec![
            "chat".to_string(),
            "superchat".to_string(),
            "json".to_string()
        ]
    );
}

#[test]
fn test_validate_upgrade_enforces_rfc6455_preconditions() {
    let parse = ::netget::server::websocket::parse_request_head;
    let validate = ::netget::server::websocket::validate_upgrade;

    let good = parse(
        b"GET /ws HTTP/1.1\r\n\
          Host: h\r\n\
          Upgrade: websocket\r\n\
          Connection: keep-alive, Upgrade\r\n\
          Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
          Sec-WebSocket-Version: 13\r\n",
    )
    .unwrap();
    assert_eq!(
        validate(&good).unwrap(),
        "dGhlIHNhbXBsZSBub25jZQ==",
        "a Connection header listing several tokens is still a valid upgrade"
    );

    // Wrong version must be a 426 that advertises the version we do speak (section 4.4).
    let old = parse(
        b"GET /ws HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
          Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 8\r\n",
    )
    .unwrap();
    let rejection = validate(&old).unwrap_err();
    assert_eq!(rejection.status, 426);
    assert!(rejection
        .extra_headers
        .iter()
        .any(|(k, v)| k == "Sec-WebSocket-Version" && v == "13"));

    // A key that is not 16 base64-encoded bytes is not a handshake.
    let short_key = parse(
        b"GET /ws HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
          Sec-WebSocket-Key: c2hvcnQ=\r\nSec-WebSocket-Version: 13\r\n",
    )
    .unwrap();
    assert_eq!(validate(&short_key).unwrap_err().status, 400);

    // POST is not a WebSocket handshake.
    let posted = parse(
        b"POST /ws HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
          Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n",
    )
    .unwrap();
    assert_eq!(validate(&posted).unwrap_err().status, 405);

    // A plain HTTP GET gets a plain 400, not a panic.
    let plain = parse(b"GET / HTTP/1.1\r\nHost: h\r\n").unwrap();
    assert_eq!(validate(&plain).unwrap_err().status, 400);
}

/// The `send_tcp_data` bug (`d70bb5b5`) in miniature: inbound was encoded and outbound was
/// not, so an echo server could not echo. This asserts the two halves are inverses for bytes
/// that are not valid UTF-8 and not printable.
#[test]
fn test_binary_payload_encoding_is_symmetric() {
    use ::netget::server::websocket::actions::{decode_outbound_payload, encode_inbound_payload};

    let awkward: Vec<u8> = vec![0x00, 0xff, 0xfe, 0x01, 0x80, 0x7f, 0xc3, 0x28];
    assert!(
        String::from_utf8(awkward.clone()).is_err(),
        "the fixture must not be valid UTF-8, or it proves nothing"
    );

    let (data, encoding) = encode_inbound_payload(&awkward);
    assert_eq!(encoding, "base64");
    let round_tripped = decode_outbound_payload(&data, Some(encoding)).unwrap();
    assert_eq!(
        round_tripped, awkward,
        "handing an event's (data, encoding) pair straight back to send_websocket_binary must \
         put the exact received bytes on the wire"
    );

    // Printable ASCII travels as text, and that also round-trips.
    let (data, encoding) = encode_inbound_payload(b"hello world");
    assert_eq!(encoding, "utf8");
    assert_eq!(data, "hello world");
    assert_eq!(
        decode_outbound_payload(&data, Some(encoding)).unwrap(),
        b"hello world"
    );

    // hex is accepted on the way out as well.
    assert_eq!(
        decode_outbound_payload("00fffe", Some("hex")).unwrap(),
        vec![0x00, 0xff, 0xfe]
    );

    // There is deliberately no sniffing: the same string means different bytes.
    assert_eq!(
        decode_outbound_payload("48656c6c6f", None).unwrap(),
        b"48656c6c6f".to_vec(),
        "without an explicit encoding the characters are sent as-is"
    );
    assert_eq!(
        decode_outbound_payload("48656c6c6f", Some("hex")).unwrap(),
        b"Hello".to_vec()
    );

    // Bad input is an error the model can read, never a panic.
    assert!(decode_outbound_payload("zz", Some("hex")).is_err());
    assert!(decode_outbound_payload("!!!!", Some("base64")).is_err());
    assert!(decode_outbound_payload("x", Some("rot13")).is_err());
}

// ============================================================================
// E2E
// ============================================================================

/// An echo server whose every event is answered by a static handler, so the whole
/// conversation below costs exactly one LLM call (the `open_server` that starts it).
fn echo_server_config(prompt: &str) -> NetGetConfig {
    NetGetConfig::new(prompt)
        .with_log_level("debug")
        .with_mock(|mock| {
            mock.on_instruction_containing("WebSocket")
                .respond_with_actions(serde_json::json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "websocket",
                    "instruction": "WebSocket echo server",
                    "event_handlers": [
                        {
                            "event_pattern": "websocket_handshake",
                            "handler": {"type": "static", "actions": [{"type": "accept_websocket"}]}
                        },
                        {
                            "event_pattern": "websocket_connection_opened",
                            "handler": {"type": "static", "actions": [
                                {"type": "send_websocket_text", "text": "welcome"}
                            ]}
                        },
                        {
                            "event_pattern": "websocket_text_message",
                            "handler": {"type": "static", "actions": [
                                {"type": "send_websocket_text", "text": "{{event.text}}"}
                            ]}
                        },
                        {
                            "event_pattern": "websocket_binary_message",
                            "handler": {"type": "static", "actions": [
                                {"type": "send_websocket_binary",
                                 "data": "{{event.data}}",
                                 "encoding": "{{event.encoding}}"}
                            ]}
                        },
                        {
                            "event_pattern": "websocket_ping",
                            "handler": {"type": "static", "actions": [
                                {"type": "show_message", "message": "ping observed"}
                            ]}
                        },
                        {
                            "event_pattern": "websocket_close",
                            "handler": {"type": "static", "actions": [
                                {"type": "show_message", "message": "close observed"}
                            ]}
                        }
                    ]
                }]))
                .expect_calls(1)
                .and()
        })
}

/// The main protocol-level test. Everything asserted here is decoded off the wire by the
/// hand-written client above, not by a WebSocket library.
#[tokio::test]
async fn test_websocket_wire_protocol_against_raw_client() -> E2EResult<()> {
    let server = start_netget_server(echo_server_config(
        "Start a WebSocket server on port 0 that echoes every message back",
    ))
    .await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let mut client = RawWsClient::connect(server.port, "/anything", &[]).await?;
    assert!(
        client.subprotocol.is_none(),
        "the handler chose no subprotocol, so the server must not send the header"
    );
    assert!(!client.accept.is_empty());

    // 1. The server speaks first — the whole point of a bidirectional session.
    let welcome = client.next_frame_timeout(10).await?;
    assert_eq!(welcome.opcode, OPCODE_TEXT, "greeting must be a text frame");
    assert!(welcome.fin, "a short greeting must not be fragmented");
    assert_eq!(String::from_utf8(welcome.payload)?, "welcome");

    // 2. Text round-trip, including a multi-byte character.
    client.send_text("héllo ✓").await?;
    let echoed = client.next_frame_timeout(10).await?;
    assert_eq!(echoed.opcode, OPCODE_TEXT);
    assert_eq!(String::from_utf8(echoed.payload)?, "héllo ✓");

    // 3. THE binary round-trip. These bytes are not valid UTF-8 and not printable, so the
    //    event carries them base64-encoded; the static handler feeds `data` and `encoding`
    //    straight back into send_websocket_binary. If the two directions disagree by so much
    //    as one byte, this fails — which is exactly the bug send_tcp_data shipped with.
    let awkward: Vec<u8> = vec![0x00, 0xff, 0xfe, 0x01, 0x80, 0x7f, 0xc3, 0x28, 0x0d, 0x0a];
    assert!(String::from_utf8(awkward.clone()).is_err());
    client.send_frame(OPCODE_BINARY, &awkward).await?;
    let echoed = client.next_frame_timeout(10).await?;
    assert_eq!(
        echoed.opcode, OPCODE_BINARY,
        "a binary message must come back as a binary frame, not text"
    );
    assert_eq!(
        echoed.payload, awkward,
        "binary echo must be byte-for-byte identical"
    );

    // 4. Ping is answered with a pong carrying the same payload (RFC 6455 section 5.5.3).
    client.send_frame(OPCODE_PING, b"heartbeat").await?;
    let pong = client.next_frame_timeout(10).await?;
    assert_eq!(
        pong.opcode, OPCODE_PONG,
        "a ping must be answered by a pong"
    );
    assert_eq!(pong.payload, b"heartbeat");

    // 5. A fragmented text message must be reassembled into one event before the model sees
    //    it, so the echo comes back whole and unfragmented.
    //    First fragment: text opcode with FIN clear. Second: continuation (opcode 0) with FIN.
    client.send_frame_fin(OPCODE_TEXT, b"frag", false).await?;
    client
        .send_frame_fin(OPCODE_CONTINUATION, b"ment", true)
        .await?;
    let echoed = client.next_frame_timeout(10).await?;
    assert_eq!(echoed.opcode, OPCODE_TEXT);
    assert_eq!(
        String::from_utf8(echoed.payload)?,
        "fragment",
        "continuation frames must be reassembled before the handler runs"
    );

    // 6. Closing handshake: our close must be echoed with the same status code.
    client.send_close(1000, "bye").await?;
    let close = client.next_frame_timeout(10).await?;
    assert_eq!(close.opcode, OPCODE_CLOSE);
    assert!(
        close.payload.len() >= 2,
        "a close frame with a status code carries at least two bytes"
    );
    let code = u16::from_be_bytes([close.payload[0], close.payload[1]]);
    assert_eq!(code, 1000, "the server must echo the peer's close code");

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

/// A request that is not a WebSocket handshake must get an HTTP error and must never reach
/// the model — there is no decision in "this is not a WebSocket upgrade".
#[tokio::test]
async fn test_non_upgrade_request_is_refused_without_a_model_call() -> E2EResult<()> {
    let server = start_netget_server(echo_server_config(
        "Start a WebSocket server on port 0 that echoes every message back",
    ))
    .await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let mut stream = TcpStream::connect(("127.0.0.1", server.port)).await?;
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
        .await?;
    let (status, _headers, _) = read_http_response(&mut stream).await?;
    assert_eq!(
        status, 400,
        "a plain HTTP GET is not an upgrade and must be answered with 400"
    );

    // Wrong protocol version gets a 426 naming the version we speak.
    let mut stream = TcpStream::connect(("127.0.0.1", server.port)).await?;
    stream
        .write_all(
            b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
              Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 8\r\n\r\n",
        )
        .await?;
    let (status, headers, _) = read_http_response(&mut stream).await?;
    assert_eq!(status, 426);
    assert!(headers
        .iter()
        .any(|(k, v)| k == "sec-websocket-version" && v == "13"));

    // The mock expects exactly one call (open_server); if any of the above had reached the
    // model, verify_mocks would report the extra invocation.
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

/// Subprotocol negotiation and refusal, both decided by the model.
///
/// Budget: 4 LLM calls (open_server, two handshakes, one connection_opened).
#[tokio::test]
async fn test_websocket_subprotocol_and_rejection() -> E2EResult<()> {
    let config = NetGetConfig::new(
        "Start a WebSocket server on port 0 for a chat service that only serves /chat",
    )
    .with_log_level("debug")
    .with_mock(|mock| {
        mock.on_instruction_containing("chat service")
            .respond_with_actions(serde_json::json!([{
                "type": "open_server",
                "port": 0,
                "base_stack": "websocket",
                "instruction": "Chat service. Accept upgrades on /chat and agree the 'chat' subprotocol; refuse anything else."
            }]))
            .expect_calls(1)
            .and()
            // Accept /chat, agreeing the subprotocol the client offered first.
            .on_event("websocket_handshake")
            .and_event_data_contains("path", "/chat")
            // Matches only when the event lists what this client offered.
            .and_event_data_contains("answer_with", "(chat, superchat)")
            .respond_with_actions(serde_json::json!([
                {"type": "accept_websocket", "subprotocol": "chat"}
            ]))
            .expect_calls(1)
            .and()
            // Refuse everything else.
            .on_event("websocket_handshake")
            .respond_with_actions(serde_json::json!([
                {"type": "reject_websocket", "status_code": 404, "reason": "No such endpoint"}
            ]))
            .expect_calls(1)
            .and()
            .on_event("websocket_connection_opened")
            .respond_with_actions(serde_json::json!([
                {"type": "send_websocket_text", "text": "joined"}
            ]))
            .expect_calls(1)
            .and()
    });

    let server = start_netget_server(config).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // 1. The accepted path: the server echoes back exactly one of the offered subprotocols.
    let mut client = RawWsClient::connect(server.port, "/chat", &["chat", "superchat"]).await?;
    assert_eq!(
        client.subprotocol.as_deref(),
        Some("chat"),
        "the server must echo the single subprotocol it agreed on"
    );
    let greeting = client.next_frame_timeout(10).await?;
    assert_eq!(greeting.opcode, OPCODE_TEXT);
    assert_eq!(String::from_utf8(greeting.payload)?, "joined");

    // 2. The refused path: a well-formed upgrade the handler declines gets the status it chose,
    //    not a 101.
    let mut stream = TcpStream::connect(("127.0.0.1", server.port)).await?;
    stream
        .write_all(
            b"GET /other HTTP/1.1\r\nHost: 127.0.0.1\r\nUpgrade: websocket\r\n\
              Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
              Sec-WebSocket-Version: 13\r\n\r\n",
        )
        .await?;
    let (status, _headers, _) = read_http_response(&mut stream).await?;
    assert_eq!(status, 404, "the handler's rejection status must be used");

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

/// Drive the same server with `websocat`, a separately built WebSocket implementation, so the
/// evidence is not limited to code in this repository.
///
/// **This test fails rather than skips when `websocat` is absent**, and that is the whole
/// reason this protocol may be rated `Beta`. `websocat` 1.x is built on the `websocket` /
/// `websocket-base` crates (rust-websocket), *not* on `tungstenite` — verified by reading the
/// crate versions out of the installed binary — so it is a genuinely independent RFC 6455
/// implementation rather than the circular-evidence case where the peer is the same crate the
/// server frames with. A `SKIP: … is not installed` gate returns `Ok(())` on any runner
/// without the binary, which is a silent pass, and the rating would then rest on nothing.
/// `tests/server/npm/e2e_test.rs::test_npm_with_real_cli` is the shape copied here.
///
/// Install it with `brew install websocat`, `cargo install websocat`, or from
/// <https://github.com/vi/websocat/releases>.
#[tokio::test]
async fn test_websocket_with_websocat() -> E2EResult<()> {
    let websocat = which_websocat().ok_or_else(|| -> Box<dyn std::error::Error> {
        "websocat is not installed. This test drives a WebSocket implementation NetGet did not \
         write (rust-websocket, not the tokio-tungstenite the server frames with) against the \
         server, and it is the only independent evidence behind the WebSocket server's maturity \
         rating. Skipping would leave that rating resting on nothing, so this is a failure and \
         not a skip. Install it with `brew install websocat`, `cargo install websocat`, or from \
         https://github.com/vi/websocat/releases."
            .into()
    })?;
    println!("websocat: {}", websocat.display());

    let server = start_netget_server(echo_server_config(
        "Start a WebSocket server on port 0 that echoes every message back",
    ))
    .await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let url = format!("ws://127.0.0.1:{}/ws", server.port);
    let output = tokio::time::timeout(
        Duration::from_secs(20),
        run_websocat(&url, "hello from websocat\n"),
    )
    .await
    .map_err(|_| "websocat timed out")??;

    assert!(
        output.contains("welcome"),
        "websocat should have received the server's unprompted greeting; got:\n{output}"
    );
    assert!(
        output.contains("hello from websocat"),
        "websocat should have received its own message echoed back; got:\n{output}"
    );

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

fn which_websocat() -> Option<std::path::PathBuf> {
    let output = std::process::Command::new("which")
        .arg("websocat")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if path.is_empty() {
        None
    } else {
        Some(std::path::PathBuf::from(path))
    }
}

/// Feed one line to `websocat` and collect everything it prints.
async fn run_websocat(url: &str, input: &str) -> Result<String, Box<dyn std::error::Error>> {
    use tokio::process::Command;

    // No `--no-close`: websocat would then hold the connection open after stdin EOF and never
    // exit, and `wait_with_output` below would time out with the transcript still unread.
    let mut child = Command::new("websocat")
        .arg("-t")
        .arg("-")
        .arg(url)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;

    let mut stdin = child.stdin.take().ok_or("no stdin")?;
    stdin.write_all(input.as_bytes()).await?;
    stdin.flush().await?;

    // Give the echo time to come back, then close stdin so websocat exits.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    drop(stdin);

    let out = match tokio::time::timeout(Duration::from_secs(8), child.wait_with_output()).await {
        Ok(r) => r?,
        Err(_) => return Err("websocat did not exit".into()),
    };

    Ok(format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    ))
}

/// A backend failure and a model that deliberately refused the upgrade both put an HTTP error
/// on the wire and nothing else. The peer cannot tell them apart and never could; the log has
/// to.
///
/// The failure is forced the way `tests/server/cdp/e2e_test.rs` forces it — the mock answers
/// `websocket_handshake` with something that is not an action, so the retry/repair loop
/// exhausts and `call_llm` returns `Err`.
///
/// Both halves of the contract are asserted: the upgrade is **refused** (503, never a 101 —
/// silence must not read as consent), and the refusal carries `decision=fail_closed_llm_error`
/// rather than `decision=model_reject`, which is what an explicit `reject_websocket` gets.
#[tokio::test]
async fn test_websocket_handshake_backend_failure_is_tagged_fail_closed() -> E2EResult<()> {
    let config = NetGetConfig::new("Start a WebSocket server on port 0 for a chat service")
        .with_mock(|mock| {
            mock.on_instruction_containing("chat service")
                .respond_with_actions(serde_json::json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "websocket",
                    "instruction": "Chat service."
                }]))
                .expect_calls(1)
                .and()
                // Not JSON, not an action: `call_llm` ends in `Err`, which is the path here.
                .on_event("websocket_handshake")
                .respond_with_raw("the backend is having a bad day and this is not an action")
                .expect_at_least(1)
                .and()
        });

    let server = start_netget_server(config).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let mut stream = TcpStream::connect(("127.0.0.1", server.port)).await?;
    stream
        .write_all(
            b"GET /chat HTTP/1.1\r\nHost: 127.0.0.1\r\nUpgrade: websocket\r\n\
              Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
              Sec-WebSocket-Version: 13\r\n\r\n",
        )
        .await?;
    let (status, _headers, _) = read_http_response(&mut stream).await?;
    assert_eq!(
        status, 503,
        "a handshake the backend could not answer must be refused, never upgraded"
    );

    server
        .wait_for_any(&["decision=fail_closed_llm_error"], 30)
        .await;

    let output = server.get_output().await;
    assert!(
        output
            .iter()
            .any(|line| line.contains("decision=fail_closed_llm_error")),
        "a backend failure on websocket_handshake must be tagged \
         decision=fail_closed_llm_error; output was:\n{}",
        output.join("\n")
    );
    assert!(
        !output
            .iter()
            .any(|line| line.contains("decision=model_reject")),
        "a backend failure is not the model refusing, and must never be logged as one; output \
         was:\n{}",
        output.join("\n")
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

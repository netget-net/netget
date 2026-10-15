//! E2E tests for the WebSocket (RFC 6455) client.
//!
//! The peer here is a **hand-written WebSocket server in this file**: it parses the upgrade
//! request itself, recomputes `Sec-WebSocket-Accept` from the RFC algorithm with `sha1` +
//! `base64`, and reads the client's frames byte by byte. That matters for two reasons —
//! it is not the same code the client is built on, and it lets the test assert the one
//! requirement a WebSocket *client* can get wrong invisibly: RFC 6455 §5.3 says every
//! client-to-server frame MUST be masked, and a server that tolerates unmasked frames (many
//! do) would never reveal the bug.
//!
//! LLM call budget: 4 (`open_client`, `websocket_client_connected`,
//! `websocket_client_binary_message`, `websocket_client_closed`).

use crate::helpers::*;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

/// What the hand-written server observed, reported back to the test.
#[derive(Debug, Default)]
struct Observed {
    /// Subprotocols the NetGet client offered.
    offered_subprotocols: Vec<String>,
    /// Path the client requested.
    path: String,
    /// The first text message the client sent, unmasked.
    first_text: Option<String>,
    /// Whether every client frame carried the mask bit (RFC 6455 section 5.3).
    all_frames_masked: bool,
    /// The binary payload the client echoed back.
    echoed_binary: Option<Vec<u8>>,
}

fn expected_accept_key(client_key: &str) -> String {
    use base64::Engine as _;
    use sha1::{Digest, Sha1};

    let mut hasher = Sha1::new();
    hasher.update(client_key.as_bytes());
    hasher.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    base64::engine::general_purpose::STANDARD.encode(hasher.finalize())
}

/// Bytes the awkward-binary assertion round-trips: not valid UTF-8, not printable.
const AWKWARD: &[u8] = &[0x00, 0xff, 0xfe, 0x01, 0x80, 0x7f, 0xc3, 0x28];

/// Start the hand-written server. Returns its port and a receiver for what it observed.
async fn start_raw_ws_server() -> E2EResult<(u16, oneshot::Receiver<Observed>)> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let port = listener.local_addr()?.port();
    let (tx, rx) = oneshot::channel();

    tokio::spawn(async move {
        let mut observed = Observed {
            all_frames_masked: true,
            ..Default::default()
        };
        if let Ok((stream, _)) = listener.accept().await {
            if let Err(e) = serve_one(stream, &mut observed).await {
                eprintln!("raw ws server ended: {e}");
            }
        }
        let _ = tx.send(observed);
    });

    Ok((port, rx))
}

async fn serve_one(
    mut stream: TcpStream,
    observed: &mut Observed,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // ---- handshake, parsed by hand ----------------------------------------
    let mut buf: Vec<u8> = Vec::new();
    loop {
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        let mut chunk = [0u8; 1024];
        let n = tokio::time::timeout(Duration::from_secs(10), stream.read(&mut chunk)).await??;
        if n == 0 {
            return Err("client closed during handshake".into());
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    let head_end = buf.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
    let mut leftover = buf[head_end + 4..].to_vec();

    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or("").to_string();
    let mut parts = request_line.split(' ');
    assert_eq!(parts.next(), Some("GET"), "handshake must be a GET");
    observed.path = parts.next().unwrap_or("").to_string();
    assert_eq!(parts.next(), Some("HTTP/1.1"));

    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
        .collect();
    let get = |name: &str| {
        headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.clone())
    };

    assert_eq!(
        get("upgrade").map(|v| v.to_ascii_lowercase()),
        Some("websocket".to_string())
    );
    assert!(get("connection")
        .map(|v| v.to_ascii_lowercase().contains("upgrade"))
        .unwrap_or(false));
    assert_eq!(get("sec-websocket-version").as_deref(), Some("13"));

    let key = get("sec-websocket-key").expect("client must send Sec-WebSocket-Key");
    {
        use base64::Engine as _;
        let raw = base64::engine::general_purpose::STANDARD
            .decode(&key)
            .expect("Sec-WebSocket-Key must be base64");
        assert_eq!(
            raw.len(),
            16,
            "RFC 6455 section 4.1: the nonce is exactly 16 bytes"
        );
    }

    observed.offered_subprotocols = get("sec-websocket-protocol")
        .map(|v| v.split(',').map(|s| s.trim().to_string()).collect())
        .unwrap_or_default();

    let response = format!(
        "HTTP/1.1 101 Switching Protocols\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Accept: {}\r\n\
         Sec-WebSocket-Protocol: chat\r\n\r\n",
        expected_accept_key(&key)
    );
    stream.write_all(response.as_bytes()).await?;
    stream.flush().await?;

    // ---- frames ------------------------------------------------------------
    let (opcode, payload) = read_frame(&mut stream, &mut leftover, observed).await?;
    assert_eq!(opcode, 0x1, "expected a text frame from the client");
    observed.first_text = Some(String::from_utf8_lossy(&payload).to_string());

    // Send a binary frame the client is expected to echo. Server frames are unmasked.
    write_unmasked_frame(&mut stream, 0x2, AWKWARD).await?;

    let (opcode, payload) = read_frame(&mut stream, &mut leftover, observed).await?;
    assert_eq!(opcode, 0x2, "the client's echo must be a binary frame");
    observed.echoed_binary = Some(payload);

    // Close the connection from this side so the client raises websocket_client_closed.
    let mut close_payload = 1000u16.to_be_bytes().to_vec();
    close_payload.extend_from_slice(b"done");
    write_unmasked_frame(&mut stream, 0x8, &close_payload).await?;
    let _ = stream.flush().await;

    // Give the client time to process the close before the socket goes away.
    tokio::time::sleep(Duration::from_millis(500)).await;
    Ok(())
}

/// Read one client frame, verifying it is masked, and return `(opcode, unmasked payload)`.
/// Control frames other than close are handled transparently.
async fn read_frame(
    stream: &mut TcpStream,
    buf: &mut Vec<u8>,
    observed: &mut Observed,
) -> Result<(u8, Vec<u8>), Box<dyn std::error::Error + Send + Sync>> {
    loop {
        let frame = read_one_frame(stream, buf, observed).await?;
        match frame.0 {
            // Skip ping/pong; the test only cares about data frames.
            0x9 | 0xA => continue,
            _ => return Ok(frame),
        }
    }
}

async fn read_one_frame(
    stream: &mut TcpStream,
    buf: &mut Vec<u8>,
    observed: &mut Observed,
) -> Result<(u8, Vec<u8>), Box<dyn std::error::Error + Send + Sync>> {
    async fn fill(
        stream: &mut TcpStream,
        buf: &mut Vec<u8>,
        n: usize,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        while buf.len() < n {
            let mut chunk = [0u8; 4096];
            let read =
                tokio::time::timeout(Duration::from_secs(15), stream.read(&mut chunk)).await??;
            if read == 0 {
                return Err("client closed while a frame was expected".into());
            }
            buf.extend_from_slice(&chunk[..read]);
        }
        Ok(())
    }

    fill(stream, buf, 2).await?;
    let opcode = buf[0] & 0x0f;
    let masked = buf[1] & 0x80 != 0;
    if !masked {
        observed.all_frames_masked = false;
    }

    let short = (buf[1] & 0x7f) as usize;
    let (len, mut header) = match short {
        126 => {
            fill(stream, buf, 4).await?;
            (u16::from_be_bytes([buf[2], buf[3]]) as usize, 4usize)
        }
        127 => {
            fill(stream, buf, 10).await?;
            let mut raw = [0u8; 8];
            raw.copy_from_slice(&buf[2..10]);
            (u64::from_be_bytes(raw) as usize, 10usize)
        }
        n => (n, 2usize),
    };

    let mask = if masked {
        fill(stream, buf, header + 4).await?;
        let m = [
            buf[header],
            buf[header + 1],
            buf[header + 2],
            buf[header + 3],
        ];
        header += 4;
        Some(m)
    } else {
        None
    };

    fill(stream, buf, header + len).await?;
    let mut payload = buf[header..header + len].to_vec();
    if let Some(m) = mask {
        for (i, b) in payload.iter_mut().enumerate() {
            *b ^= m[i % 4];
        }
    }
    buf.drain(..header + len);
    Ok((opcode, payload))
}

async fn write_unmasked_frame(
    stream: &mut TcpStream,
    opcode: u8,
    payload: &[u8],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut out = vec![0x80 | opcode];
    let len = payload.len();
    if len < 126 {
        out.push(len as u8);
    } else {
        out.push(126);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    }
    out.extend_from_slice(payload);
    stream.write_all(&out).await?;
    stream.flush().await?;
    Ok(())
}

// ============================================================================
// The test
// ============================================================================

#[tokio::test]
async fn test_websocket_client_against_hand_written_server() -> E2EResult<()> {
    let (port, observed_rx) = start_raw_ws_server().await?;

    let config = NetGetConfig::new(format!(
        "Connect to the WebSocket at 127.0.0.1:{port} on /ws and echo anything binary back"
    ))
    .with_log_level("debug")
    .with_mock(move |mock| {
        mock.on_instruction_containing("Connect to the WebSocket")
            .respond_with_actions(serde_json::json!([{
                "type": "open_client",
                "base_stack": "websocket",
                "remote_addr": format!("127.0.0.1:{port}"),
                "startup_params": {"path": "/ws", "subprotocols": ["chat", "superchat"]},
                "instruction": "Say hello, then echo any binary message back unchanged"
            }]))
            .expect_calls(1)
            .and()
            .on_event("websocket_client_connected")
            .respond_with_actions(serde_json::json!([{
                "type": "send_websocket_text",
                "text": "hello from netget"
            }]))
            .expect_calls(1)
            .and()
            // The symmetry assertion: feed the event's own (data, encoding) pair back.
            .on_event("websocket_client_binary_message")
            .respond_with_actions_from_event(|event| {
                serde_json::json!([{
                    "type": "send_websocket_binary",
                    "data": event["data"],
                    "encoding": event["encoding"],
                }])
            })
            .expect_calls(1)
            .and()
            .on_event("websocket_client_closed")
            .respond_with_actions(serde_json::json!([{
                "type": "show_message",
                "message": "server closed the connection"
            }]))
            .expect_at_least(0)
            .and()
    });

    let client = start_netget_client(config).await?;

    let observed = tokio::time::timeout(Duration::from_secs(30), observed_rx)
        .await
        .map_err(|_| "the hand-written server never finished its exchange")??;

    assert_eq!(
        observed.path, "/ws",
        "the 'path' startup parameter must be used"
    );
    assert_eq!(
        observed.offered_subprotocols,
        vec!["chat".to_string(), "superchat".to_string()],
        "the 'subprotocols' startup parameter must reach Sec-WebSocket-Protocol in order"
    );
    assert!(
        observed.all_frames_masked,
        "RFC 6455 section 5.3: every client-to-server frame MUST be masked"
    );
    assert_eq!(
        observed.first_text.as_deref(),
        Some("hello from netget"),
        "the client must send the text frame the handler asked for"
    );
    assert_eq!(
        observed.echoed_binary.as_deref(),
        Some(AWKWARD),
        "binary echo must be byte-for-byte identical: the event's (data, encoding) pair fed \
         straight back into send_websocket_binary must reproduce the received bytes"
    );

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last response routinely lands
    // after the sleep expires, and the test reports it as never having happened.
    client.wait_for_mocks(30).await;
    client.verify_mocks().await?;
    client.stop().await?;
    Ok(())
}

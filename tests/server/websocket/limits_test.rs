//! Every size and time bound the WebSocket server declares, driven from the wire on both sides
//! of the number, in the direction it governs (what the peer sends):
//!
//! | Bound | Inside | Past it |
//! |---|---|---|
//! | `MAX_REQUEST_HEAD` (16 KiB) | a head of exactly 16 384 bytes is upgraded | one byte more is 431 |
//! | `handshake_timeout_secs` | a head finished inside it is upgraded | a head still unfinished is 408 |
//! | `max_frame_size`, uncompressed | a frame of exactly the limit is echoed | one byte more: Close 1009 |
//! | `max_frame_size`, compressed | a compressed frame under it inflating past it is echoed | a compressed frame over it: Close 1009 |
//! | `max_message_size`, fragmented | frames adding up to exactly the limit are one message | one byte more: Close 1009 |
//! | `max_message_size`, inflated | a message inflating to exactly the limit is echoed | one byte more: Close 1009, refused by the inflate bound |
//! | `max_message_size`, compressed bytes | — | compressed frames past it are refused before inflating |
//! | `max_message_size`, joined by `wait_for_websocket_data` | two held parts joined under it | a join past it: Close 1009 |
//! | the 125-byte floor on both limits | a 125-byte message under `max_message_size: 1` | 126 bytes: Close 1009 |
//! | `MAX_QUEUED_INBOUND_BYTES` | — | a peer sending while its handler is busy is held back by TCP |
//! | `MAX_QUEUED_INBOUND_MESSAGES` | — | the same, with empty messages |
//!
//! And the walk to a size bound is timed: a compressed message of a mebibyte sent as one-byte
//! continuation frames is answered in seconds, not in the frame count squared.
//!
//! No LLM calls: a Python script handler echoes, a `manual` rule parks where the handler must be
//! busy. Each limit was checked by removing it (see `tests/server/websocket/AGENTS.md`).

use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use netget::state::{AccessLogOwner, ServerId};
use serde_json::{json, Value};
use std::io::Write;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

const ECHO: &str = r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']
if t=='websocket_handshake': a=[{'type':'accept_websocket'}]
elif t=='websocket_text_message': a=[{'type':'send_websocket_text','text':'echo:%d'%len(e['text'])}]
elif t=='websocket_binary_message': a=[{'type':'send_websocket_text','text':'echo:%d'%e['message_bytes']}]
else: a=[]
print(json.dumps({'actions':a}))"#;

/// The deflate offer every compressed test makes: the server resets its context per message,
/// so each reply inflates on its own.
const DEFLATE_OFFER: &str = "permessage-deflate; server_no_context_takeover";

struct Server {
    state: AppState,
    id: ServerId,
    port: u16,
    log: mpsc::UnboundedReceiver<String>,
}

impl Server {
    async fn start(params: Value, handlers: Vec<Value>) -> Server {
        let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
        let (tx, log) = mpsc::unbounded_channel();
        let id = ServerForm {
            protocol: "websocket".into(),
            port: Some(0),
            host: Some("127.0.0.1".into()),
            instruction: Some(String::new()),
            startup_params: Some(params),
            event_handlers: Some(handlers),
            // One message per handler call, so what is held and joined is exactly what was sent.
            batching: Some(false),
            ..Default::default()
        }
        .create(&state, tx)
        .await
        .unwrap();
        let port = tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                if let Some(a) = state.get_server(id).await.and_then(|s| s.local_addr) {
                    break a.port();
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("the WebSocket server never bound");
        Server {
            state,
            id,
            port,
            log,
        }
    }

    async fn echo(params: Value) -> Server {
        Self::start(
            params,
            vec![json!({"event_pattern":"*","handler":{"type":"script","language":"python","code":ECHO}})],
        )
        .await
    }

    fn log_lines(&mut self) -> Vec<String> {
        let mut out = Vec::new();
        while let Ok(line) = self.log.try_recv() {
            out.push(line);
        }
        out
    }

    async fn texts(&self) -> Vec<Value> {
        self.state
            .list_access_logs_for(Some(AccessLogOwner::Server(self.id.as_u32())), None)
            .await
            .iter()
            .map(|e| serde_json::to_value(e).unwrap())
            .filter(|e| e["event_type"] == "websocket_text_message")
            .map(|e| e["request"].clone())
            .collect()
    }
}

/// Send a request head and read the response head. `pad` header bytes make the head (without
/// its final blank line) exactly `len` bytes when given.
fn upgrade_request(extensions: Option<&str>, head_len: Option<usize>) -> Vec<u8> {
    let mut head = String::from(
        "GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13",
    );
    if let Some(ext) = extensions {
        head.push_str(&format!("\r\nSec-WebSocket-Extensions: {ext}"));
    }
    if let Some(len) = head_len {
        let prefix = "\r\nX-Pad: ";
        let pad = len - head.len() - prefix.len();
        head.push_str(prefix);
        head.push_str(&"a".repeat(pad));
        assert_eq!(head.len(), len);
    }
    head.push_str("\r\n\r\n");
    head.into_bytes()
}

async fn read_head(c: &mut TcpStream) -> String {
    let mut head = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), async {
        while !head.ends_with(b"\r\n\r\n") {
            let mut b = [0u8; 1];
            if c.read_exact(&mut b).await.is_err() {
                break;
            }
            head.push(b[0]);
        }
    })
    .await
    .expect("no response head");
    String::from_utf8_lossy(&head).to_string()
}

async fn connect(port: u16, extensions: Option<&str>) -> TcpStream {
    let mut c = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    c.write_all(&upgrade_request(extensions, None))
        .await
        .unwrap();
    let head = read_head(&mut c).await;
    assert!(head.starts_with("HTTP/1.1 101"), "{head}");
    if extensions.is_some() {
        assert!(
            head.contains("Sec-WebSocket-Extensions: permessage-deflate"),
            "{head}"
        );
    }
    c
}

/// One masked client frame.
fn frame(fin: bool, rsv1: bool, opcode: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![(if fin { 0x80 } else { 0 }) | (if rsv1 { 0x40 } else { 0 }) | opcode];
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
    let mask = [0x11u8, 0x22, 0x33, 0x44];
    out.extend_from_slice(&mask);
    out.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
    out
}

/// RFC 7692 §7.2.1: raw deflate, sync-flushed, the trailing `00 00 ff ff` removed.
fn deflate(data: &[u8]) -> Vec<u8> {
    let mut enc = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::best());
    enc.write_all(data).unwrap();
    enc.flush().unwrap();
    let mut out = enc.get_ref().clone();
    if out.ends_with(&[0, 0, 0xff, 0xff]) {
        out.truncate(out.len() - 4);
    }
    out
}

/// Letters with no short period, so they barely compress.
fn noise(n: usize) -> Vec<u8> {
    let mut x: u64 = 7;
    (0..n)
        .map(|_| {
            x = x
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            b'a' + ((x >> 33) % 26) as u8
        })
        .collect()
}

/// What the server sends next: `Ok((opcode, payload))`, or `Err` at EOF.
async fn read_frame(c: &mut TcpStream) -> Result<(u8, Vec<u8>), ()> {
    let fut = async {
        let mut h = [0u8; 2];
        c.read_exact(&mut h).await.map_err(|_| ())?;
        let mut len = (h[1] & 0x7f) as u64;
        if len == 126 {
            let mut b = [0u8; 2];
            c.read_exact(&mut b).await.map_err(|_| ())?;
            len = u16::from_be_bytes(b) as u64;
        } else if len == 127 {
            let mut b = [0u8; 8];
            c.read_exact(&mut b).await.map_err(|_| ())?;
            len = u64::from_be_bytes(b);
        }
        let mut payload = vec![0u8; len as usize];
        c.read_exact(&mut payload).await.map_err(|_| ())?;
        let payload = if h[0] & 0x40 != 0 {
            // A compressed reply (permessage-deflate is on): inflate it.
            // The tests offer `server_no_context_takeover`, so every reply inflates alone.
            let mut input = payload.clone();
            input.extend_from_slice(&[0, 0, 0xff, 0xff]);
            let mut out = Vec::with_capacity(64 * 1024);
            let mut d = flate2::Decompress::new(false);
            match d.decompress_vec(&input, &mut out, flate2::FlushDecompress::Sync) {
                Ok(_) => out,
                Err(_) => payload,
            }
        } else {
            payload
        };
        Ok((h[0] & 0x0f, payload))
    };
    tokio::time::timeout(Duration::from_secs(10), fut)
        .await
        .expect("the server sent nothing for 10 seconds")
}

async fn expect_text(c: &mut TcpStream, want: &str) {
    let (op, payload) = read_frame(c).await.expect("connection ended");
    assert_eq!(
        (op, String::from_utf8_lossy(&payload).to_string()),
        (1, want.to_string())
    );
}

/// The server closes with `code`: a Close frame carrying it, then EOF.
async fn expect_close(c: &mut TcpStream, code: u16) {
    loop {
        match read_frame(c).await {
            Ok((8, payload)) => {
                assert!(payload.len() >= 2, "close frame without a code");
                assert_eq!(u16::from_be_bytes([payload[0], payload[1]]), code);
                return;
            }
            Ok(_) => continue,
            Err(()) => panic!("EOF without a close frame carrying {code}"),
        }
    }
}

#[tokio::test]
async fn the_request_head_limit_is_16_kib_exactly() {
    let s = Server::echo(json!({})).await;
    let mut c = TcpStream::connect(("127.0.0.1", s.port)).await.unwrap();
    c.write_all(&upgrade_request(None, Some(16 * 1024)))
        .await
        .unwrap();
    let head = read_head(&mut c).await;
    assert!(head.starts_with("HTTP/1.1 101"), "{head}");

    let mut c = TcpStream::connect(("127.0.0.1", s.port)).await.unwrap();
    c.write_all(&upgrade_request(None, Some(16 * 1024 + 1)))
        .await
        .unwrap();
    let head = read_head(&mut c).await;
    assert!(head.starts_with("HTTP/1.1 431"), "{head}");

    // Past the limit with no blank line at all: refused as soon as it is past, not at EOF.
    let mut c = TcpStream::connect(("127.0.0.1", s.port)).await.unwrap();
    c.write_all(&vec![b'a'; 20 * 1024]).await.unwrap();
    let head = read_head(&mut c).await;
    assert!(head.starts_with("HTTP/1.1 431"), "{head}");
}

#[tokio::test]
async fn an_unfinished_request_head_is_answered_408_at_the_handshake_timeout() {
    let s = Server::echo(json!({"handshake_timeout_secs": 1})).await;
    // Inside the bound: half of the head now, the rest after 400 ms.
    let mut c = TcpStream::connect(("127.0.0.1", s.port)).await.unwrap();
    let req = upgrade_request(None, None);
    c.write_all(&req[..20]).await.unwrap();
    tokio::time::sleep(Duration::from_millis(400)).await;
    c.write_all(&req[20..]).await.unwrap();
    let head = read_head(&mut c).await;
    assert!(head.starts_with("HTTP/1.1 101"), "{head}");

    // Past it: the head never finishes.
    let started = Instant::now();
    let mut c = TcpStream::connect(("127.0.0.1", s.port)).await.unwrap();
    c.write_all(&req[..20]).await.unwrap();
    let head = read_head(&mut c).await;
    assert!(head.starts_with("HTTP/1.1 408"), "{head}");
    let took = started.elapsed();
    assert!(
        took >= Duration::from_millis(900) && took < Duration::from_secs(5),
        "408 after {took:?}, not at the 1 s bound"
    );
}

#[tokio::test]
async fn an_uncompressed_frame_of_exactly_max_frame_size_is_taken_and_one_more_byte_is_1009() {
    let s = Server::echo(json!({"max_frame_size": 1000, "permessage_deflate": false})).await;
    let mut c = connect(s.port, None).await;
    c.write_all(&frame(true, false, 1, &[b'x'; 1000]))
        .await
        .unwrap();
    expect_text(&mut c, "echo:1000").await;
    c.write_all(&frame(true, false, 1, &[b'x'; 1001]))
        .await
        .unwrap();
    expect_close(&mut c, 1009).await;
}

#[tokio::test]
async fn a_compressed_frame_is_held_to_max_frame_size_too() {
    let mut s = Server::echo(json!({"max_frame_size": 1000})).await;
    let mut c = connect(s.port, Some(DEFLATE_OFFER)).await;
    // Under the frame limit on the wire, over it inflated: a frame is judged as it was sent.
    let small = deflate(&[b'a'; 5000]);
    assert!(small.len() < 1000);
    c.write_all(&frame(true, true, 1, &small)).await.unwrap();
    expect_text(&mut c, "echo:5000").await;
    // Over the frame limit on the wire, though it inflates to far less than max_message_size.
    let big = deflate(&noise(2000));
    assert!(big.len() > 1000, "{}", big.len());
    c.write_all(&frame(true, true, 1, &big)).await.unwrap();
    expect_close(&mut c, 1009).await;
    assert_eq!(
        s.texts().await.len(),
        1,
        "the oversized frame reached the handler"
    );
    let log = s.log_lines();
    assert!(
        log.iter()
            .any(|l| l.contains("exceeds the 1000-byte limit") && l.contains("closed with 1009")),
        "{log:#?}"
    );
}

#[tokio::test]
async fn a_fragmented_message_of_exactly_max_message_size_is_taken_and_one_more_byte_is_1009() {
    let s = Server::echo(json!({
        "max_message_size": 2000, "max_frame_size": 1000, "permessage_deflate": false
    }))
    .await;
    let mut c = connect(s.port, None).await;
    c.write_all(&frame(false, false, 1, &[b'x'; 1000]))
        .await
        .unwrap();
    c.write_all(&frame(true, false, 0, &[b'x'; 1000]))
        .await
        .unwrap();
    expect_text(&mut c, "echo:2000").await;
    c.write_all(&frame(false, false, 1, &[b'x'; 1000]))
        .await
        .unwrap();
    c.write_all(&frame(false, false, 0, &[b'x'; 1000]))
        .await
        .unwrap();
    c.write_all(&frame(true, false, 0, b"x")).await.unwrap();
    expect_close(&mut c, 1009).await;
}

#[tokio::test]
async fn a_message_inflating_to_exactly_max_message_size_is_taken_and_one_more_byte_is_1009() {
    let mut s = Server::echo(json!({"max_message_size": 4096})).await;
    let mut c = connect(s.port, Some(DEFLATE_OFFER)).await;
    c.write_all(&frame(true, true, 1, &deflate(&[b'a'; 4096])))
        .await
        .unwrap();
    expect_text(&mut c, "echo:4096").await;
    c.write_all(&frame(true, true, 1, &deflate(&[b'a'; 4097])))
        .await
        .unwrap();
    expect_close(&mut c, 1009).await;
    let log = s.log_lines();
    assert!(
        log.iter()
            .any(|l| l.contains("inflates past 4096") && l.contains("permessage_deflate_refused")),
        "{log:#?}"
    );
}

#[tokio::test]
async fn compressed_frames_past_max_message_size_are_refused_before_inflating() {
    let mut s = Server::echo(json!({"max_message_size": 4096, "max_frame_size": 4096})).await;
    let mut c = connect(s.port, Some(DEFLATE_OFFER)).await;
    // Compressed fragments of 2000 bytes each: the compressed message alone is past
    // the limit, so it is refused while it is still being collected.
    let compressed = deflate(&noise(10000));
    assert!(compressed.len() > 4096);
    let parts: Vec<&[u8]> = compressed.chunks(2000).collect();
    for (i, part) in parts.iter().enumerate() {
        let last = i == parts.len() - 1;
        let _ = c
            .write_all(&frame(last, i == 0, if i == 0 { 1 } else { 0 }, part))
            .await;
    }
    expect_close(&mut c, 1009).await;
    let log = s.log_lines();
    assert!(
        log.iter()
            .any(|l| l.contains("compressed message exceeds 4096")),
        "{log:#?}"
    );
}

#[tokio::test]
async fn the_125_byte_floor_applies_to_a_smaller_max_message_size() {
    let s = Server::echo(json!({"max_message_size": 1, "permessage_deflate": false})).await;
    let mut c = connect(s.port, None).await;
    c.write_all(&frame(true, false, 1, &[b'x'; 125]))
        .await
        .unwrap();
    expect_text(&mut c, "echo:125").await;
    c.write_all(&frame(true, false, 1, &[b'x'; 126]))
        .await
        .unwrap();
    expect_close(&mut c, 1009).await;
}

#[tokio::test]
async fn a_message_joined_by_wait_for_websocket_data_is_held_to_max_message_size() {
    // Every text is held for more; the handler never answers one.
    const WAIT: &str = r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']
a=[{'type':'accept_websocket'}] if t=='websocket_handshake' else ([{'type':'wait_for_websocket_data'}] if t=='websocket_text_message' else [])
print(json.dumps({'actions':a}))"#;
    let s = Server::start(
        json!({"max_message_size": 2000, "permessage_deflate": false}),
        vec![
            json!({"event_pattern":"*","handler":{"type":"script","language":"python","code":WAIT}}),
        ],
    )
    .await;
    let mut c = connect(s.port, None).await;
    c.write_all(&frame(true, false, 1, &[b'a'; 900]))
        .await
        .unwrap();
    c.write_all(&frame(true, false, 1, &[b'b'; 900]))
        .await
        .unwrap();
    // The two are joined (1800 bytes, inside the bound) and the join is held in turn.
    tokio::time::timeout(Duration::from_secs(20), async {
        while !s.texts().await.iter().any(|t| t["message_bytes"] == 1800) {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the two held parts were never joined");
    // A third part takes the join past 2000 bytes.
    c.write_all(&frame(true, false, 1, &[b'c'; 900]))
        .await
        .unwrap();
    expect_close(&mut c, 1009).await;
}

/// The handler is parked by a `manual` rule on the first message, so everything after it is
/// backlog. Returns how many bytes the peer managed to write before the server stopped reading.
async fn bytes_written_while_the_handler_is_busy(message: &[u8], ceiling: usize) -> usize {
    let s = Server::start(
        json!({"permessage_deflate": false, "max_message_size": 1048576}),
        vec![
            json!({"event_pattern":"websocket_handshake","handler":{"type":"static","actions":[{"type":"accept_websocket"}]}}),
            json!({"event_pattern":"*","handler":{"type":"manual","timeout_secs":600}}),
        ],
    )
    .await;
    let mut c = connect(s.port, None).await;
    let one = frame(true, false, 2, message);
    let mut written = 0usize;
    while written < ceiling {
        // Several frames per write, so the walk to the ceiling is quick when nothing pushes back.
        let batch: Vec<u8> = one.repeat((64 * 1024 / one.len()).max(1));
        match tokio::time::timeout(Duration::from_secs(2), c.write_all(&batch)).await {
            Ok(Ok(())) => written += batch.len(),
            Ok(Err(e)) => panic!("the server closed the connection instead of pushing back: {e}"),
            Err(_) => return written,
        }
    }
    drop(s);
    written
}

#[tokio::test]
async fn a_peer_outrunning_its_handler_is_held_back_by_the_byte_bound() {
    // 8 MiB of backlog, plus whatever the two sockets' buffers and tungstenite's read buffer hold.
    let ceiling = 96 * 1024 * 1024;
    let written = bytes_written_while_the_handler_is_busy(&[0x5a; 64 * 1024], ceiling).await;
    assert!(
        written < 40 * 1024 * 1024,
        "the server kept reading while its handler was busy: the peer wrote {written} bytes"
    );
}

#[tokio::test]
async fn a_peer_outrunning_its_handler_is_held_back_by_the_message_bound() {
    // Empty binary messages: 1024 of them are 6 KiB, so only the count can stop the reading.
    let ceiling = 96 * 1024 * 1024;
    let written = bytes_written_while_the_handler_is_busy(&[], ceiling).await;
    assert!(
        written < 40 * 1024 * 1024,
        "the server kept reading while its handler was busy: the peer wrote {written} bytes"
    );
}

#[tokio::test]
async fn a_mebibyte_compressed_message_in_one_byte_frames_is_answered_promptly() {
    let s = Server::echo(json!({})).await;
    let mut c = connect(s.port, Some(DEFLATE_OFFER)).await;
    let compressed = deflate(&noise(16 * 1024));
    // Padded with empty stored blocks to a mebibyte, so the message is ~1 MiB of one-byte
    // frames whichever way the compressor fell.
    let mut payload = compressed.clone();
    while payload.len() < 1024 * 1024 - 8 {
        // Completes the sync flush's empty stored block the tail removal left open, and opens
        // the next one (the receiver appends the closing `00 00 ff ff`).
        payload.extend_from_slice(&[0x00, 0x00, 0xff, 0xff, 0x00]);
    }
    let mut wire = frame(false, true, 1, &payload[..1]);
    for (i, b) in payload[1..].iter().enumerate() {
        let last = i == payload.len() - 2;
        wire.extend_from_slice(&frame(last, false, 0, std::slice::from_ref(b)));
    }
    let started = Instant::now();
    c.write_all(&wire).await.unwrap();
    expect_text(&mut c, &format!("echo:{}", 16 * 1024)).await;
    let took = started.elapsed();
    assert!(
        took < Duration::from_secs(20),
        "{} one-byte frames took {took:?}",
        payload.len()
    );
}

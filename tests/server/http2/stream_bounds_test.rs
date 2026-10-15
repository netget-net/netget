//! HTTP/2's per-connection stream bounds, driven from the wire.
//!
//! `src/server/http2/h2_server.rs` declares the SETTINGS it advertises and a body budget the
//! streams of one connection share, and argues each number beside itself:
//! `MAX_CONCURRENT_STREAMS` (100), `INITIAL_STREAM_WINDOW_BYTES` (65,535),
//! `INITIAL_CONNECTION_WINDOW_BYTES` (1 MiB), `MAX_FRAME_BYTES` (16,384),
//! `MAX_HEADER_LIST_BYTES` (32 KiB) and `CONNECTION_BODY_BUDGET_BYTES` (8 MiB).
//!
//! Three claims, from the peer's side:
//!
//! * **The SETTINGS frame on the wire carries those values.** Read by a hand-written frame
//!   reader, not by `h2`, so the server's own library is not what checks it; and read again by
//!   curl (nghttp2), a third-party HTTP/2 stack, which reports the stream limit it received.
//! * **A stream past the limit is refused with `REFUSED_STREAM`.** A raw client that ignores the
//!   SETTINGS opens 101 streams whose requests are parked for a human; the 101st is reset with
//!   error code 7 and the first hundred are not reset at all. (`h2`'s own client honours the
//!   limit and would never send the 101st, which is why this one is written by hand.)
//! * **The streams of one connection share one body budget.** A stream holding 6 MiB of body is
//!   parked; a second stream on the same connection sending 3 MiB is answered `503` with
//!   `Retry-After` before the model sees it, while the first stays parked.
//!
//! No mock backend: the LLM endpoint is a dead port and every rule is static or manual. Loopback
//! only.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features http2 --test server -- \
//!       http2::stream_bounds --test-threads=100

use std::time::Duration;

use bytes::Bytes;
use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use netget::state::intercepts::InterceptOwner;
use netget::state::ServerId;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

/// The values `h2_server.rs` declares. Copied on purpose: if they move, this file should be
/// re-read rather than silently follow.
const MAX_CONCURRENT_STREAMS: u32 = 100;
const INITIAL_STREAM_WINDOW_BYTES: u32 = 65_535;
const INITIAL_CONNECTION_WINDOW_BYTES: u32 = 1024 * 1024;
const MAX_FRAME_BYTES: u32 = 16_384;
const MAX_HEADER_LIST_BYTES: u32 = 32 * 1024;

const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const FRAME_HEADERS: u8 = 0x1;
const FRAME_RST_STREAM: u8 = 0x3;
const FRAME_SETTINGS: u8 = 0x4;
const FRAME_GOAWAY: u8 = 0x7;
const FRAME_WINDOW_UPDATE: u8 = 0x8;
const FLAG_ACK: u8 = 0x1;
const FLAG_END_STREAM: u8 = 0x1;
const FLAG_END_HEADERS: u8 = 0x4;
const REFUSED_STREAM: u32 = 0x7;

async fn new_state() -> AppState {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".to_string());
    state
        .set_llm_client(netget::llm::OllamaClient::new(
            "http://127.0.0.1:1".to_string(),
        ))
        .await;
    state
}

async fn start_server(state: &AppState, event_handlers: Vec<serde_json::Value>) -> (ServerId, u16) {
    let (tx, _rx) = mpsc::unbounded_channel();
    let server_id = ServerForm {
        protocol: "http2".to_string(),
        port: Some(0),
        instruction: Some(String::new()),
        event_handlers: Some(event_handlers),
        ..Default::default()
    }
    .create(state, tx)
    .await
    .expect("create http2 server");
    for _ in 0..300 {
        if let Some(s) = state.get_server(server_id).await {
            if let Some(addr) = s.local_addr {
                return (server_id, addr.port());
            }
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("HTTP/2 server #{} never bound a port", server_id.as_u32());
}

/// Every request parks for a human, so a stream stays open for as long as the test needs.
fn park_everything() -> Vec<serde_json::Value> {
    vec![serde_json::json!({
        "event_pattern": "*",
        "handler": {"type": "manual", "timeout_secs": 600}
    })]
}

async fn parked_on(state: &AppState, id: ServerId) -> usize {
    state
        .list_intercepts()
        .await
        .into_iter()
        .filter(|v| v.owner == InterceptOwner::Server(id))
        .count()
}

async fn write_frame(tcp: &mut TcpStream, kind: u8, flags: u8, stream: u32, payload: &[u8]) {
    let len = payload.len() as u32;
    let mut frame = Vec::with_capacity(9 + payload.len());
    frame.extend_from_slice(&len.to_be_bytes()[1..]);
    frame.push(kind);
    frame.push(flags);
    frame.extend_from_slice(&(stream & 0x7fff_ffff).to_be_bytes());
    frame.extend_from_slice(payload);
    tcp.write_all(&frame).await.expect("write frame");
}

/// One frame: (type, flags, stream id, payload). `None` at EOF or when `deadline` passes.
async fn read_frame(tcp: &mut TcpStream, deadline: Duration) -> Option<(u8, u8, u32, Vec<u8>)> {
    tokio::time::timeout(deadline, async {
        let mut head = [0u8; 9];
        tcp.read_exact(&mut head).await.ok()?;
        let len = u32::from_be_bytes([0, head[0], head[1], head[2]]) as usize;
        let stream = u32::from_be_bytes([head[5], head[6], head[7], head[8]]) & 0x7fff_ffff;
        let mut payload = vec![0u8; len];
        tcp.read_exact(&mut payload).await.ok()?;
        Some((head[3], head[4], stream, payload))
    })
    .await
    .ok()
    .flatten()
}

/// The server's SETTINGS as (identifier, value) pairs, and the connection WINDOW_UPDATE
/// increment it sent alongside, after exchanging prefaces and acknowledging its SETTINGS.
async fn open_raw_connection(port: u16) -> (TcpStream, Vec<(u16, u32)>, Option<u32>) {
    let mut tcp = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    tcp.write_all(PREFACE).await.expect("preface");
    write_frame(&mut tcp, FRAME_SETTINGS, 0, 0, &[]).await;

    let mut settings = None;
    let mut window_increment = None;
    // The server's preface is its SETTINGS, typically followed at once by a connection
    // WINDOW_UPDATE and the ACK of ours. Read until the SETTINGS and the ACK have both come.
    let mut acked = false;
    while settings.is_none() || !acked {
        let (kind, flags, stream, payload) = read_frame(&mut tcp, Duration::from_secs(10))
            .await
            .expect("the server ended the connection before its preface");
        match (kind, flags & FLAG_ACK != 0) {
            (FRAME_SETTINGS, false) => {
                settings = Some(
                    payload
                        .chunks_exact(6)
                        .map(|c| {
                            (
                                u16::from_be_bytes([c[0], c[1]]),
                                u32::from_be_bytes([c[2], c[3], c[4], c[5]]),
                            )
                        })
                        .collect::<Vec<_>>(),
                );
                write_frame(&mut tcp, FRAME_SETTINGS, FLAG_ACK, 0, &[]).await;
            }
            (FRAME_SETTINGS, true) => acked = true,
            (FRAME_WINDOW_UPDATE, _) if stream == 0 => {
                window_increment = Some(
                    u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]])
                        & 0x7fff_ffff,
                );
            }
            _ => {}
        }
    }
    // The WINDOW_UPDATE may trail the ACK; give it a moment.
    if window_increment.is_none() {
        if let Some((FRAME_WINDOW_UPDATE, _, 0, payload)) =
            read_frame(&mut tcp, Duration::from_millis(500)).await
        {
            window_increment = Some(
                u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]) & 0x7fff_ffff,
            );
        }
    }
    (tcp, settings.unwrap(), window_increment)
}

/// A HEADERS block for `GET http://127.0.0.1/`, HPACK-encoded from the static table:
/// `:method GET` (2), `:scheme http` (6), `:path /` (4), and `:authority` as a literal with an
/// indexed name (1). No dynamic table, so every stream can reuse it.
fn get_headers_block() -> Vec<u8> {
    let authority = b"127.0.0.1";
    let mut block = vec![0x82, 0x86, 0x84, 0x01, authority.len() as u8];
    block.extend_from_slice(authority);
    block
}

#[tokio::test]
async fn the_settings_frame_carries_the_declared_bounds() {
    let state = new_state().await;
    let (_, port) = start_server(&state, park_everything()).await;

    let (_tcp, settings, window_increment) = open_raw_connection(port).await;
    let value = |id: u16| settings.iter().find(|(k, _)| *k == id).map(|(_, v)| *v);

    assert_eq!(
        value(0x3),
        Some(MAX_CONCURRENT_STREAMS),
        "SETTINGS_MAX_CONCURRENT_STREAMS; server sent {settings:?}"
    );
    // 0x4 may be omitted when it equals the protocol default of 65,535, which is the declared
    // value; either way the effective value must be the declared one.
    assert_eq!(
        value(0x4).unwrap_or(65_535),
        INITIAL_STREAM_WINDOW_BYTES,
        "SETTINGS_INITIAL_WINDOW_SIZE; server sent {settings:?}"
    );
    assert_eq!(
        value(0x5).unwrap_or(16_384),
        MAX_FRAME_BYTES,
        "SETTINGS_MAX_FRAME_SIZE; server sent {settings:?}"
    );
    assert_eq!(
        value(0x6),
        Some(MAX_HEADER_LIST_BYTES),
        "SETTINGS_MAX_HEADER_LIST_SIZE; server sent {settings:?}"
    );
    // The connection window is not a SETTINGS value: it is opened past its 65,535 default by a
    // WINDOW_UPDATE on stream 0.
    assert_eq!(
        window_increment,
        Some(INITIAL_CONNECTION_WINDOW_BYTES - 65_535),
        "the connection-level WINDOW_UPDATE should open the window to 1 MiB"
    );
}

#[tokio::test]
async fn curl_reads_the_stream_limit_from_the_server() {
    let state = new_state().await;
    let (_, port) = start_server(
        &state,
        vec![serde_json::json!({
            "event_pattern": "http2_request",
            "handler": {"type": "static", "actions": [
                {"type": "send_http2_response", "status": 200, "body": "stream-bounds-ok"}
            ]}
        })],
    )
    .await;

    let output = tokio::process::Command::new("curl")
        .args([
            "--http2-prior-knowledge",
            "--silent",
            "--show-error",
            "--verbose",
            "--trace-config",
            "http/2",
            "--max-time",
            "20",
            &format!("http://127.0.0.1:{port}/"),
        ])
        .output()
        .await
        .unwrap_or_else(|e| {
            panic!(
                "could not run curl: {e}. It is the independent HTTP/2 stack this test reads the \
                 SETTINGS with (nghttp2); install curl built with HTTP/2 support."
            )
        });
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success() && stdout.contains("stream-bounds-ok"),
        "curl --http2-prior-knowledge must complete a request; exit {:?}, stdout {stdout:?}, \
         stderr:\n{stderr}",
        output.status
    );
    assert!(
        stderr.contains(&format!("MAX_CONCURRENT_STREAMS: {MAX_CONCURRENT_STREAMS}"))
            || stderr.contains(&format!("MAX_CONCURRENT_STREAMS == {MAX_CONCURRENT_STREAMS}")),
        "curl should report the server's stream limit of {MAX_CONCURRENT_STREAMS}; stderr:\n{stderr}"
    );
}

#[tokio::test]
async fn a_stream_past_the_limit_is_refused_and_the_rest_are_not() {
    let state = new_state().await;
    let (server_id, port) = start_server(&state, park_everything()).await;
    let (mut tcp, _, _) = open_raw_connection(port).await;

    // One more stream than advertised, all at once, as a client that ignores the SETTINGS would.
    let block = get_headers_block();
    let streams: Vec<u32> = (0..=MAX_CONCURRENT_STREAMS).map(|i| 2 * i + 1).collect();
    for &id in &streams {
        write_frame(
            &mut tcp,
            FRAME_HEADERS,
            FLAG_END_STREAM | FLAG_END_HEADERS,
            id,
            &block,
        )
        .await;
    }
    let last = *streams.last().unwrap();

    // Read until the last stream's fate is known. Every request that is admitted parks, so the
    // server writes nothing for the first hundred; what it writes is about the last one.
    let mut resets: Vec<(u32, u32)> = Vec::new();
    let mut goaway = None;
    while !resets.iter().any(|(id, _)| *id == last) {
        match read_frame(&mut tcp, Duration::from_secs(10)).await {
            Some((FRAME_RST_STREAM, _, id, payload)) => {
                resets.push((
                    id,
                    u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]),
                ));
            }
            Some((FRAME_GOAWAY, _, _, payload)) => {
                goaway = Some(payload);
                break;
            }
            Some(_) => {}
            None => break,
        }
    }
    assert_eq!(
        resets,
        vec![(last, REFUSED_STREAM)],
        "exactly the stream past the limit (#{last}) must be reset, with REFUSED_STREAM (7); \
         resets seen: {resets:?}, GOAWAY: {goaway:?}"
    );

    // And the hundred before it were admitted: each reached the handler and parked.
    for _ in 0..500 {
        if parked_on(&state, server_id).await >= MAX_CONCURRENT_STREAMS as usize {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(
        parked_on(&state, server_id).await,
        MAX_CONCURRENT_STREAMS as usize,
        "every admitted stream should be parked for a human, and only those"
    );
}

/// Send `len` bytes of body on `stream` in flow-controlled chunks, then end the stream. Returns
/// early (quietly) if the server resets the stream or closes the connection.
async fn send_body(mut stream: h2::SendStream<Bytes>, len: usize) {
    let mut remaining = len;
    while remaining > 0 {
        stream.reserve_capacity(remaining.min(64 * 1024));
        let granted = match futures::future::poll_fn(|cx| stream.poll_capacity(cx)).await {
            Some(Ok(n)) if n > 0 => n.min(remaining),
            Some(Ok(_)) => continue,
            _ => return,
        };
        remaining -= granted;
        if stream
            .send_data(Bytes::from(vec![b'x'; granted]), remaining == 0)
            .is_err()
        {
            return;
        }
    }
}

#[tokio::test]
async fn the_streams_of_one_connection_share_one_body_budget() {
    let state = new_state().await;
    let (server_id, port) = start_server(&state, park_everything()).await;

    let tcp = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    let (client, connection) = h2::client::handshake(tcp).await.expect("h2 handshake");
    tokio::spawn(connection);
    let mut client = client.ready().await.expect("ready");

    let post = |path: &str| {
        http::Request::builder()
            .method("POST")
            .uri(format!("http://127.0.0.1:{port}{path}"))
            .body(())
            .expect("build request")
    };

    // Stream A: 6 MiB, read whole by the server and then parked, holding 6 of the 8 MiB.
    let (response_a, body_a) = client.send_request(post("/a"), false).expect("send A");
    send_body(body_a, 6 * 1024 * 1024).await;
    for _ in 0..500 {
        if parked_on(&state, server_id).await == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(
        parked_on(&state, server_id).await,
        1,
        "stream A should have been read whole and parked"
    );

    // Stream B: 3 MiB on the same connection. 6 + 3 > 8, so B is refused before it parks.
    let mut client = client.ready().await.expect("ready for B");
    let (response_b, body_b) = client.send_request(post("/b"), false).expect("send B");
    let sender = tokio::spawn(send_body(body_b, 3 * 1024 * 1024));
    let response_b = tokio::time::timeout(Duration::from_secs(15), response_b)
        .await
        .expect("stream B was never answered - it should have been refused, not parked")
        .expect("stream B response");
    sender.abort();
    assert_eq!(
        response_b.status(),
        http::StatusCode::SERVICE_UNAVAILABLE,
        "stream B should be refused with 503"
    );
    assert_eq!(
        response_b
            .headers()
            .get(http::header::RETRY_AFTER)
            .and_then(|v| v.to_str().ok()),
        Some("1"),
        "the 503 should say when to retry"
    );
    assert_eq!(
        parked_on(&state, server_id).await,
        1,
        "stream B must not reach the handler, and stream A must still be parked"
    );
    drop(response_a);
}

/// The HTTP/1.1 server's `Upgrade: h2c` path hands its connection to the same handler and must
/// advertise the same SETTINGS; curl's `--http2` over `http://` is exactly that upgrade.
///
/// Only the SETTINGS are asserted. curl's request itself does not complete: RFC 9113's
/// predecessor (RFC 7540 §3.2) makes the upgraded request stream 1, half-closed from the client,
/// and this server hands the upgraded socket to a fresh `h2` handshake that knows nothing of
/// stream 1 — curl's WINDOW_UPDATE on it draws a GOAWAY(PROTOCOL_ERROR). That defect predates
/// the stream bounds (it reproduces with `h2`'s default builder) and is recorded in
/// `src/server/http/CLAUDE.md`.
#[tokio::test]
async fn an_h2c_upgrade_from_http1_advertises_the_same_stream_limit() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();
    let server_id = ServerForm {
        protocol: "http".to_string(),
        port: Some(0),
        instruction: Some(String::new()),
        event_handlers: Some(vec![
            serde_json::json!({
                "event_pattern": "http_request",
                "handler": {"type": "static", "actions": [
                    {"type": "send_http_response", "status": 200, "body": "h1-ok"}
                ]}
            }),
            serde_json::json!({
                "event_pattern": "http2_request",
                "handler": {"type": "static", "actions": [
                    {"type": "send_http2_response", "status": 200, "body": "h2c-ok"}
                ]}
            }),
        ]),
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .expect("create http server");
    let mut port = 0;
    for _ in 0..300 {
        if let Some(addr) = state.get_server(server_id).await.and_then(|s| s.local_addr) {
            port = addr.port();
            break;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    assert_ne!(port, 0, "HTTP server never bound a port");

    let output = tokio::process::Command::new("curl")
        .args([
            "--http2",
            "--silent",
            "--show-error",
            "--verbose",
            "--trace-config",
            "http/2",
            "--max-time",
            "10",
            &format!("http://127.0.0.1:{port}/"),
        ])
        .output()
        .await
        .expect("run curl");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(&format!("MAX_CONCURRENT_STREAMS: {MAX_CONCURRENT_STREAMS}")),
        "curl should report the upgraded connection's stream limit of {MAX_CONCURRENT_STREAMS}; \
         exit {:?}, stdout {:?}, stderr:\n{stderr}",
        output.status,
        String::from_utf8_lossy(&output.stdout)
    );
}

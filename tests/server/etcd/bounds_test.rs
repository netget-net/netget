//! Every bound the etcd server declares, driven from the wire on both sides of the boundary.
//!
//! `src/server/etcd/mod.rs` declares six, and each is asserted here in the direction it governs:
//!
//! | bound | at the bound | one past it |
//! |---|---|---|
//! | `MAX_REQUEST_BYTES` (1.5 MiB body) | answered, and in bounded time | `8 RESOURCE_EXHAUSTED` before the handler |
//! | `MAX_BUFFERED_REQUEST_BYTES` (32 x that, server-wide) | a request that exactly fills it parks | the next byte is `8 RESOURCE_EXHAUSTED` |
//! | `MAX_CONCURRENT_STREAMS` (200 per connection) | 200 streams open | the 201st is `RST_STREAM(REFUSED_STREAM)` |
//! | `MAX_CONNECTIONS` (256) | the 256th gets the server's SETTINGS | the 257th reads HTTP/1.1 503 |
//! | `first_byte_timeout_secs` | a peer that sent its preface is not closed | a silent peer is closed |
//! | `idle_timeout_secs` | a second request inside the window is answered | silence is closed, **including a request whose body stopped arriving** |
//!
//! The last cell is the defect this file found: the connection was marked busy for the whole of
//! a request, body included, so a peer that sent HEADERS and then nothing held its connection,
//! task and slot forever — the idle watchdog refuses to fire while anything is in flight.
//!
//! No model: the LLM endpoint is a dead port and every rule is static or manual. Loopback only.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features mcp-stdio,sqlite \
//!       --test server -- server::etcd::bounds_test --test-threads=8

use std::time::{Duration, Instant};

use bytes::Bytes;
use netget::cli::management::ServerForm;
use netget::server::etcd::{MAX_BUFFERED_REQUEST_BYTES, MAX_CONCURRENT_STREAMS, MAX_REQUEST_BYTES};
use netget::state::app_state::AppState;
use netget::state::intercepts::InterceptOwner;
use netget::state::ServerId;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const FRAME_DATA: u8 = 0x0;
const FRAME_HEADERS: u8 = 0x1;
const FRAME_RST_STREAM: u8 = 0x3;
const FRAME_SETTINGS: u8 = 0x4;
const FRAME_GOAWAY: u8 = 0x7;
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

async fn start_server(
    state: &AppState,
    startup_params: Option<serde_json::Value>,
    event_handlers: Vec<serde_json::Value>,
) -> (ServerId, u16) {
    let (tx, _rx) = mpsc::unbounded_channel();
    let server_id = ServerForm {
        protocol: "etcd".to_string(),
        port: Some(0),
        instruction: Some(String::new()),
        startup_params,
        event_handlers: Some(event_handlers),
        ..Default::default()
    }
    .create(state, tx)
    .await
    .expect("create etcd server");
    for _ in 0..300 {
        if let Some(s) = state.get_server(server_id).await {
            if let Some(addr) = s.local_addr {
                return (server_id, addr.port());
            }
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("etcd server #{} never bound a port", server_id.as_u32());
}

/// Static answers for Put and Range, so a request that reaches the handler is answered at once.
fn answer_everything() -> Vec<serde_json::Value> {
    vec![
        serde_json::json!({
            "event_pattern": "etcd_put_request",
            "handler": {"type": "static", "actions": [{"type": "etcd_put_response"}]}
        }),
        serde_json::json!({
            "event_pattern": "etcd_range_request",
            "handler": {"type": "static", "actions": [
                {"type": "etcd_range_response", "kvs": [], "count": 0}
            ]}
        }),
    ]
}

/// Every request parks for a human, so a request that reached the handler stays in flight — with
/// its body still counted against the server — for as long as the test needs.
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

async fn wait_parked(state: &AppState, id: ServerId, n: usize) -> usize {
    for _ in 0..1500 {
        let parked = parked_on(state, id).await;
        if parked >= n {
            return parked;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    parked_on(state, id).await
}

/// A gRPC request body of exactly `total` bytes: the 5-byte message header and a `PutRequest`
/// for `/k` whose value fills the rest.
fn put_body(total: usize) -> Bytes {
    // key field (tag 1, 2 bytes) + value tag; the value's varint length is solved for below.
    let fixed = 2 + 2 + 1;
    let mut value_len = total - 5 - fixed;
    loop {
        let varint = varint(value_len as u64);
        if 5 + fixed + varint.len() + value_len == total {
            break;
        }
        value_len -= 1;
    }
    let mut msg = vec![0x0a, 0x02, b'/', b'k', 0x12];
    msg.extend_from_slice(&varint(value_len as u64));
    msg.extend(std::iter::repeat(b'v').take(value_len));
    let mut body = vec![0u8];
    body.extend_from_slice(&(msg.len() as u32).to_be_bytes());
    body.extend_from_slice(&msg);
    assert_eq!(body.len(), total);
    Bytes::from(body)
}

fn varint(mut v: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let byte = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(byte);
            return out;
        }
        out.push(byte | 0x80);
    }
}

/// An `h2` client: the server's own HTTP/2 library, used here only as a flow-control-honouring
/// way to push large bodies; nothing is asserted about h2 itself.
async fn h2_client(port: u16) -> h2::client::SendRequest<Bytes> {
    let tcp = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    let (client, connection) = h2::client::handshake(tcp).await.expect("h2 handshake");
    tokio::spawn(connection);
    client.ready().await.expect("ready")
}

fn grpc_request(port: u16, method: &str) -> http::Request<()> {
    http::Request::builder()
        .method("POST")
        .uri(format!("http://127.0.0.1:{port}/etcdserverpb.KV/{method}"))
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .body(())
        .expect("build request")
}

/// Send `body` on a new stream, ending it, and return the response future.
async fn send_unary(
    client: &mut h2::client::SendRequest<Bytes>,
    port: u16,
    method: &str,
    body: Bytes,
) -> h2::client::ResponseFuture {
    let mut ready = client.clone().ready().await.expect("ready");
    let (response, mut stream) = ready
        .send_request(grpc_request(port, method), false)
        .expect("send request");
    *client = ready;
    let mut remaining = body;
    while !remaining.is_empty() {
        stream.reserve_capacity(remaining.len().min(256 * 1024));
        let granted = match futures::future::poll_fn(|cx| stream.poll_capacity(cx)).await {
            Some(Ok(n)) if n > 0 => n.min(remaining.len()),
            Some(Ok(_)) => continue,
            _ => break,
        };
        let chunk = remaining.split_to(granted);
        if stream.send_data(chunk, remaining.is_empty()).is_err() {
            break;
        }
    }
    response
}

/// The gRPC status of a reply, wherever it rides: the initial headers for a Trailers-Only reply,
/// the trailers otherwise.
async fn grpc_status(response: h2::client::ResponseFuture) -> String {
    let response = tokio::time::timeout(Duration::from_secs(60), response)
        .await
        .expect("no response within 60s")
        .expect("response");
    if let Some(status) = response.headers().get("grpc-status") {
        return status.to_str().unwrap_or("?").to_string();
    }
    let mut body = response.into_body();
    while let Some(chunk) = body.data().await {
        let chunk = chunk.expect("body");
        let _ = body.flow_control().release_capacity(chunk.len());
    }
    let trailers = body.trailers().await.expect("trailers").unwrap_or_default();
    trailers
        .get("grpc-status")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("none")
        .to_string()
}

#[tokio::test]
async fn a_body_of_exactly_max_request_bytes_is_answered_and_one_byte_more_is_refused() {
    let state = new_state().await;
    let (_, port) = start_server(&state, None, answer_everything()).await;
    let mut client = h2_client(port).await;

    let started = Instant::now();
    let at = send_unary(&mut client, port, "Put", put_body(MAX_REQUEST_BYTES)).await;
    assert_eq!(
        grpc_status(at).await,
        "0",
        "a Put whose body is exactly MAX_REQUEST_BYTES is inside the bound and must be answered"
    );
    let elapsed = started.elapsed();
    // A size bound bounds memory, not work: the walk to it must be linear. Collecting is one
    // pass over the frames, so 1.5 MiB takes milliseconds; a guard that re-walked the buffer on
    // every frame would take ~100x longer.
    assert!(
        elapsed < Duration::from_secs(20),
        "a maximum-size request took {elapsed:?} to be answered"
    );

    let past = send_unary(&mut client, port, "Put", put_body(MAX_REQUEST_BYTES + 1)).await;
    assert_eq!(
        grpc_status(past).await,
        "8",
        "one byte past MAX_REQUEST_BYTES must be RESOURCE_EXHAUSTED"
    );
}

#[tokio::test]
async fn the_server_wide_body_budget_admits_exactly_its_size_and_refuses_the_next_byte() {
    let state = new_state().await;
    let (server_id, port) = start_server(&state, None, park_everything()).await;
    let held = MAX_BUFFERED_REQUEST_BYTES / MAX_REQUEST_BYTES;
    assert_eq!(held * MAX_REQUEST_BYTES, MAX_BUFFERED_REQUEST_BYTES);

    // `held` maximum-size requests, spread over two connections to show the budget is not a
    // per-connection one, each parked for a human with its body still counted.
    let mut clients = [h2_client(port).await, h2_client(port).await];
    let mut pending = Vec::new();
    for i in 0..held {
        let client = &mut clients[i % 2];
        pending.push(send_unary(client, port, "Put", put_body(MAX_REQUEST_BYTES)).await);
    }
    assert_eq!(
        wait_parked(&state, server_id, held).await,
        held,
        "every request that fits the budget, the last of which fills it exactly, must reach the \
         handler"
    );

    // The budget is now exactly full. The smallest request there is — an empty Range, five
    // bytes — no longer fits.
    let mut third = h2_client(port).await;
    let refused = send_unary(
        &mut third,
        port,
        "Range",
        Bytes::from_static(&[0, 0, 0, 0, 0]),
    )
    .await;
    assert_eq!(
        grpc_status(refused).await,
        "8",
        "with every budgeted byte held, the next request must be RESOURCE_EXHAUSTED"
    );
    assert_eq!(parked_on(&state, server_id).await, held);
    drop(pending);
}

#[tokio::test]
async fn the_budget_is_returned_when_a_request_is_answered() {
    // The other side of the budget: bytes held by an answered request go back, so a full
    // budget's worth of requests, sent one after another, never meets it.
    let state = new_state().await;
    let (_, port) = start_server(&state, None, answer_everything()).await;
    let mut client = h2_client(port).await;
    let rounds = 2 * MAX_BUFFERED_REQUEST_BYTES / MAX_REQUEST_BYTES;
    for i in 0..rounds {
        let reply = send_unary(&mut client, port, "Put", put_body(MAX_REQUEST_BYTES)).await;
        assert_eq!(
            grpc_status(reply).await,
            "0",
            "request {i} of {rounds}, each answered before the next, met a budget that should \
             have been returned"
        );
    }
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

/// Exchange prefaces and SETTINGS by hand; returns the server's SETTINGS.
async fn open_raw_connection(port: u16) -> (TcpStream, Vec<(u16, u32)>) {
    let mut tcp = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    tcp.write_all(PREFACE).await.expect("preface");
    write_frame(&mut tcp, FRAME_SETTINGS, 0, 0, &[]).await;
    let mut settings = None;
    let mut acked = false;
    while settings.is_none() || !acked {
        let (kind, flags, _, payload) = read_frame(&mut tcp, Duration::from_secs(10))
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
            _ => {}
        }
    }
    (tcp, settings.unwrap())
}

/// HEADERS for `POST /etcdserverpb.KV/Range`, HPACK-encoded without the dynamic table:
/// `:method POST` (static 3), `:scheme http` (static 6), and `:path` / `:authority` as literals
/// with indexed names (4 and 1).
fn range_headers_block() -> Vec<u8> {
    let path = b"/etcdserverpb.KV/Range";
    let authority = b"127.0.0.1";
    let mut block = vec![0x83, 0x86, 0x04, path.len() as u8];
    block.extend_from_slice(path);
    block.push(0x01);
    block.push(authority.len() as u8);
    block.extend_from_slice(authority);
    block
}

#[tokio::test]
async fn the_settings_carry_the_stream_limit_and_a_stream_past_it_is_refused() {
    let state = new_state().await;
    let (_, port) = start_server(&state, None, answer_everything()).await;
    let (mut tcp, settings) = open_raw_connection(port).await;
    assert_eq!(
        settings.iter().find(|(id, _)| *id == 0x3).map(|(_, v)| *v),
        Some(MAX_CONCURRENT_STREAMS),
        "SETTINGS_MAX_CONCURRENT_STREAMS; the server sent {settings:?}"
    );

    // One more stream than advertised, each left open (no END_STREAM, no body), as a client
    // that ignores the SETTINGS would. An admitted stream waits for its body and writes nothing.
    let block = range_headers_block();
    let streams: Vec<u32> = (0..=MAX_CONCURRENT_STREAMS).map(|i| 2 * i + 1).collect();
    for &id in &streams {
        write_frame(&mut tcp, FRAME_HEADERS, FLAG_END_HEADERS, id, &block).await;
    }
    let last = *streams.last().unwrap();

    let mut resets: Vec<(u32, u32)> = Vec::new();
    let mut goaway = None;
    while !resets.iter().any(|(id, _)| *id == last) {
        match read_frame(&mut tcp, Duration::from_secs(10)).await {
            Some((FRAME_RST_STREAM, _, id, payload)) => resets.push((
                id,
                u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]),
            )),
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

    // And the first stream, admitted, still works: its body arrives and it is answered.
    write_frame(&mut tcp, FRAME_DATA, FLAG_END_STREAM, 1, &[0, 0, 0, 0, 0]).await;
    let mut answered = false;
    while let Some((kind, flags, id, _)) = read_frame(&mut tcp, Duration::from_secs(10)).await {
        if id == 1 && kind == FRAME_HEADERS && flags & FLAG_END_STREAM != 0 {
            answered = true;
            break;
        }
    }
    assert!(
        answered,
        "stream 1 was admitted and must be answered once its body arrives"
    );
}

#[tokio::test]
async fn the_257th_connection_is_refused_with_a_503_and_the_256th_is_not() {
    let state = new_state().await;
    let (_, port) = start_server(&state, None, answer_everything()).await;
    let cap = netget::server::accept_bounded::DEFAULT_MAX_CONNECTIONS;

    let mut held = Vec::with_capacity(cap);
    for _ in 0..cap - 1 {
        held.push(
            TcpStream::connect(("127.0.0.1", port))
                .await
                .expect("connect"),
        );
    }
    // The 256th is admitted: it gets the server's own HTTP/2 preface.
    let (last_admitted, _) = open_raw_connection(port).await;
    held.push(last_admitted);

    let mut refused = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    let mut reply = Vec::new();
    tokio::time::timeout(Duration::from_secs(20), refused.read_to_end(&mut reply))
        .await
        .expect("the refused connection was not closed")
        .expect("read");
    let text = String::from_utf8_lossy(&reply);
    assert!(
        text.starts_with("HTTP/1.1 503"),
        "the connection past MAX_CONNECTIONS must read the 503 refusal; got {text:?}"
    );
    drop(held);
}

#[tokio::test]
async fn a_silent_peer_is_closed_at_first_byte_timeout_secs_and_a_talking_one_is_not() {
    let state = new_state().await;
    let first_byte = Duration::from_secs(3);
    let (_, port) = start_server(
        &state,
        Some(serde_json::json!({"first_byte_timeout_secs": first_byte.as_secs()})),
        answer_everything(),
    )
    .await;

    let mut silent = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    let (mut talking, _) = open_raw_connection(port).await;

    let started = Instant::now();
    let mut sink = Vec::new();
    // The window stays under the 30-second default, so a server ignoring the parameter fails.
    let closed = tokio::time::timeout(
        first_byte + Duration::from_secs(20),
        silent.read_to_end(&mut sink),
    )
    .await;
    let elapsed = started.elapsed();
    assert!(
        closed.is_ok(),
        "a peer that sent nothing was still connected after {elapsed:?}; \
         first_byte_timeout_secs is not applied"
    );
    assert!(
        elapsed >= first_byte / 2,
        "closed after {elapsed:?}, well before the {first_byte:?} bound — something else closed it"
    );

    // The peer that sent its preface is past the first-byte bound and still served.
    write_frame(
        &mut talking,
        FRAME_HEADERS,
        FLAG_END_HEADERS,
        1,
        &range_headers_block(),
    )
    .await;
    write_frame(
        &mut talking,
        FRAME_DATA,
        FLAG_END_STREAM,
        1,
        &[0, 0, 0, 0, 0],
    )
    .await;
    let mut answered = false;
    while let Some((kind, flags, id, _)) = read_frame(&mut talking, Duration::from_secs(10)).await {
        if id == 1 && kind == FRAME_HEADERS && flags & FLAG_END_STREAM != 0 {
            answered = true;
            break;
        }
    }
    assert!(
        answered,
        "the peer that spoke must not be governed by the first-byte bound"
    );
}

/// Read frames until the connection ends, or `deadline` passes; true when it ended.
async fn closes_within(tcp: &mut TcpStream, deadline: Duration) -> bool {
    let started = Instant::now();
    while started.elapsed() < deadline {
        let left = deadline.saturating_sub(started.elapsed());
        let mut buf = [0u8; 4096];
        match tokio::time::timeout(left, tcp.read(&mut buf)).await {
            Ok(Ok(0)) | Ok(Err(_)) => return true,
            Ok(Ok(_)) => continue,
            Err(_) => return false,
        }
    }
    false
}

#[tokio::test]
async fn a_request_whose_body_stops_arriving_is_closed_at_idle_timeout_secs() {
    let state = new_state().await;
    let idle = Duration::from_secs(3);
    let (_, port) = start_server(
        &state,
        Some(serde_json::json!({"idle_timeout_secs": idle.as_secs()})),
        answer_everything(),
    )
    .await;

    // Inside the window: two requests on one connection, the second sent well within the idle
    // bound after the first was answered, are both answered.
    let (mut tcp, _) = open_raw_connection(port).await;
    for id in [1u32, 3] {
        write_frame(
            &mut tcp,
            FRAME_HEADERS,
            FLAG_END_HEADERS,
            id,
            &range_headers_block(),
        )
        .await;
        write_frame(&mut tcp, FRAME_DATA, FLAG_END_STREAM, id, &[0, 0, 0, 0, 0]).await;
        let mut answered = false;
        while let Some((kind, flags, sid, _)) = read_frame(&mut tcp, Duration::from_secs(10)).await
        {
            if sid == id && kind == FRAME_HEADERS && flags & FLAG_END_STREAM != 0 {
                answered = true;
                break;
            }
        }
        assert!(
            answered,
            "request on stream {id} inside the idle window was not answered"
        );
    }

    // Then a request whose HEADERS arrive and whose body never does. Before the fix this held
    // the connection busy forever.
    write_frame(
        &mut tcp,
        FRAME_HEADERS,
        FLAG_END_HEADERS,
        5,
        &range_headers_block(),
    )
    .await;
    write_frame(&mut tcp, FRAME_DATA, 0, 5, &[0, 0, 0]).await;
    let started = Instant::now();
    assert!(
        closes_within(&mut tcp, idle + Duration::from_secs(30)).await,
        "a request whose body stopped arriving kept its connection open past {:?}; a peer that \
         stops sending mid-body is silent, and the idle bound must govern it",
        idle + Duration::from_secs(30)
    );
    assert!(
        started.elapsed() >= idle / 2,
        "closed after {:?}, before the idle bound — something else closed it",
        started.elapsed()
    );
}

//! Every bound the PostgreSQL server declares, driven from the wire on both sides of the boundary.
//!
//! | bound | at the bound | one past it |
//! |---|---|---|
//! | `MAX_FRONTEND_MESSAGE_BYTES` (1 MiB) | a Query of exactly that size is answered, in bounded time | `FATAL 08P01` before a byte of its body reaches pgwire, after everything sent before it is answered |
//! | `MAX_STARTUP_PACKET_BYTES` (10 000) | a startup packet of that size is read | `FATAL 08P01` |
//! | `MAX_CONNECTIONS` (256) | the 256th completes startup | the 257th reads `53300` |
//! | `MAX_PENDING_DESCRIBES` (64) | 64 described statements each execute without a second model call | the 65th evicts the first, which is resolved again |
//! | `first_byte_timeout_secs` | a peer that sent its startup is served | a silent peer is closed |
//! | `idle_timeout_secs` | a statement inside the window is answered | a silent session is closed |
//!
//! The first row is the defect this file was written against. pgwire buffers a Query, Parse or
//! Bind whole up to 0x3ffffffe bytes (PostgreSQL's 1 GB), and this server authenticates nobody,
//! so a stranger could make it hold a gigabyte per connection. NetGet now screens the frontend
//! framing in front of pgwire (`src/server/postgresql/guard.rs`).
//!
//! No model: the LLM endpoint is a dead port and every rule is static. Loopback only.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features mcp-stdio,sqlite \
//!       --test server -- server::postgresql::bounds_test --test-threads=8

use std::time::{Duration, Instant};

use netget::cli::management::ServerForm;
use netget::server::postgresql::guard::{MAX_FRONTEND_MESSAGE_BYTES, MAX_STARTUP_PACKET_BYTES};
use netget::state::app_state::AppState;
use netget::state::ServerId;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

async fn new_state() -> AppState {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".to_string());
    state
        .set_llm_client(netget::llm::OllamaClient::new(
            "http://127.0.0.1:1".to_string(),
        ))
        .await;
    state
}

/// A model-free server: every statement answered `SELECT 1` with one int4 column.
async fn start_server(
    state: &AppState,
    startup_params: Option<serde_json::Value>,
) -> (ServerId, u16) {
    let (tx, _rx) = mpsc::unbounded_channel();
    let server_id = ServerForm {
        protocol: "postgresql".to_string(),
        port: Some(0),
        instruction: Some(String::new()),
        startup_params,
        event_handlers: Some(vec![serde_json::json!({
            "event_pattern": "postgresql_query",
            "handler": {"type": "static", "actions": [{
                "type": "postgresql_query_response",
                "columns": [{"name": "n", "type": "int4"}],
                "rows": [[1]]
            }]}
        })]),
        ..Default::default()
    }
    .create(state, tx)
    .await
    .expect("create postgresql server");
    for _ in 0..300 {
        if let Some(s) = state.get_server(server_id).await {
            if let Some(addr) = s.local_addr {
                return (server_id, addr.port());
            }
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!(
        "PostgreSQL server #{} never bound a port",
        server_id.as_u32()
    );
}

fn startup_message() -> Vec<u8> {
    startup_with_padding(0)
}

/// A v3 StartupMessage, with an extra `options` parameter of `pad` bytes to size it.
fn startup_with_padding(pad: usize) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&196_608i32.to_be_bytes());
    for kv in ["user", "netget", "database", "netget"] {
        body.extend_from_slice(kv.as_bytes());
        body.push(0);
    }
    if pad > 0 {
        body.extend_from_slice(b"application_name\0");
        body.extend(std::iter::repeat_n(b'a', pad));
        body.push(0);
    }
    body.push(0);
    let mut msg = ((body.len() + 4) as i32).to_be_bytes().to_vec();
    msg.extend_from_slice(&body);
    msg
}

/// One backend message: (type, body). `None` at EOF or after `deadline`.
async fn read_message(tcp: &mut TcpStream, deadline: Duration) -> Option<(u8, Vec<u8>)> {
    tokio::time::timeout(deadline, async {
        let mut head = [0u8; 5];
        tcp.read_exact(&mut head).await.ok()?;
        let len = u32::from_be_bytes([head[1], head[2], head[3], head[4]]) as usize;
        let mut body = vec![0u8; len.saturating_sub(4)];
        tcp.read_exact(&mut body).await.ok()?;
        Some((head[0], body))
    })
    .await
    .ok()
    .flatten()
}

/// Read messages until ReadyForQuery; returns their types. Panics on EOF.
async fn until_ready(tcp: &mut TcpStream) -> Vec<u8> {
    let mut seen = Vec::new();
    loop {
        let (kind, _) = read_message(tcp, Duration::from_secs(20))
            .await
            .unwrap_or_else(|| panic!("connection ended before ReadyForQuery; saw {seen:?}"));
        seen.push(kind);
        if kind == b'Z' {
            return seen;
        }
    }
}

async fn connect_and_start(port: u16) -> TcpStream {
    let mut tcp = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    tcp.write_all(&startup_message()).await.expect("startup");
    until_ready(&mut tcp).await;
    tcp
}

/// A simple Query message of exactly `total` bytes on the wire (type byte and length included).
fn query_of(total: usize) -> Vec<u8> {
    let sql_len = total - 1 - 4 - 1;
    let mut sql = b"SELECT 1 -- ".to_vec();
    sql.resize(sql_len, b'x');
    let mut msg = vec![b'Q'];
    msg.extend_from_slice(&((4 + sql_len + 1) as u32).to_be_bytes());
    msg.extend_from_slice(&sql);
    msg.push(0);
    assert_eq!(msg.len(), total);
    msg
}

/// Everything the server sends until it closes the connection.
async fn read_to_close(tcp: &mut TcpStream) -> Vec<u8> {
    let mut all = Vec::new();
    tokio::time::timeout(Duration::from_secs(30), tcp.read_to_end(&mut all))
        .await
        .expect("the server did not close the connection within 30s")
        .expect("read");
    all
}

fn is_fatal_08p01(bytes: &[u8]) -> bool {
    let text = String::from_utf8_lossy(bytes);
    bytes.contains(&b'E') && text.contains("SFATAL") && text.contains("C08P01")
}

#[tokio::test]
async fn a_query_of_exactly_the_bound_is_answered_and_one_byte_more_is_refused() {
    let state = new_state().await;
    let (_, port) = start_server(&state, None).await;

    let mut tcp = connect_and_start(port).await;
    let started = Instant::now();
    tcp.write_all(&query_of(MAX_FRONTEND_MESSAGE_BYTES))
        .await
        .expect("write");
    let seen = until_ready(&mut tcp).await;
    let elapsed = started.elapsed();
    assert!(
        seen.contains(&b'T') && seen.contains(&b'D') && seen.contains(&b'C'),
        "a Query of exactly MAX_FRONTEND_MESSAGE_BYTES must be answered with rows; saw {seen:?}"
    );
    // A size bound bounds memory, not work: the screen counts a body rather than re-reading it,
    // so the walk to the bound is linear.
    assert!(
        elapsed < Duration::from_secs(20),
        "a maximum-size Query took {elapsed:?} to be answered"
    );

    // One byte past the bound, sent right behind a small Query on the same connection. The
    // small one is answered first; then the refusal, then the close. Only the oversize header is
    // sent: the refusal must come from the declared length alone.
    let mut pipelined = query_of(64);
    pipelined.extend_from_slice(&query_of(MAX_FRONTEND_MESSAGE_BYTES + 1)[..5]);
    tcp.write_all(&pipelined).await.expect("write");
    let reply = read_to_close(&mut tcp).await;
    let rows_at = reply.iter().position(|b| *b == b'D');
    let error_at = reply.windows(6).position(|w| w == b"SFATAL");
    assert!(
        rows_at.is_some() && error_at.is_some() && rows_at < error_at,
        "the Query before the oversize one must be answered before the refusal; got {:?}",
        String::from_utf8_lossy(&reply)
    );
    assert!(
        is_fatal_08p01(&reply),
        "one byte past the bound must be refused FATAL 08P01; got {:?}",
        String::from_utf8_lossy(&reply)
    );
}

#[tokio::test]
async fn a_startup_packet_at_the_bound_is_read_and_one_byte_more_is_refused() {
    let state = new_state().await;
    let (_, port) = start_server(&state, None).await;
    let base = startup_with_padding(1).len() - 1;

    let mut at = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    let packet = startup_with_padding(MAX_STARTUP_PACKET_BYTES - base);
    assert_eq!(packet.len(), MAX_STARTUP_PACKET_BYTES);
    at.write_all(&packet).await.expect("write");
    until_ready(&mut at).await;

    let mut past = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    let packet = startup_with_padding(MAX_STARTUP_PACKET_BYTES - base + 1);
    past.write_all(&packet[..8]).await.expect("write");
    let reply = read_to_close(&mut past).await;
    assert!(
        is_fatal_08p01(&reply),
        "a startup packet one byte past the bound must be refused FATAL 08P01; got {:?}",
        String::from_utf8_lossy(&reply)
    );
}

#[tokio::test]
async fn the_257th_connection_reads_53300_and_the_256th_is_served() {
    let state = new_state().await;
    let (_, port) = start_server(&state, None).await;
    let cap = netget::server::accept_bounded::DEFAULT_MAX_CONNECTIONS;

    let mut held = Vec::with_capacity(cap);
    for _ in 0..cap - 1 {
        held.push(
            TcpStream::connect(("127.0.0.1", port))
                .await
                .expect("connect"),
        );
    }
    held.push(connect_and_start(port).await);

    let mut refused = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    let reply = read_to_close(&mut refused).await;
    assert!(
        String::from_utf8_lossy(&reply).contains("C53300"),
        "the connection past MAX_CONNECTIONS must read SQLSTATE 53300; got {:?}",
        String::from_utf8_lossy(&reply)
    );
    drop(held);
}

/// Extended-protocol messages, written by hand so the test controls exactly what is described
/// and executed.
fn parse(name: &str, sql: &str) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(name.as_bytes());
    body.push(0);
    body.extend_from_slice(sql.as_bytes());
    body.push(0);
    body.extend_from_slice(&0u16.to_be_bytes());
    framed(b'P', &body)
}

fn describe_statement(name: &str) -> Vec<u8> {
    let mut body = vec![b'S'];
    body.extend_from_slice(name.as_bytes());
    body.push(0);
    framed(b'D', &body)
}

fn bind_and_execute(statement: &str) -> Vec<u8> {
    let mut body = Vec::new();
    body.push(0); // unnamed portal
    body.extend_from_slice(statement.as_bytes());
    body.push(0);
    body.extend_from_slice(&0u16.to_be_bytes()); // parameter formats
    body.extend_from_slice(&0u16.to_be_bytes()); // parameters
    body.extend_from_slice(&0u16.to_be_bytes()); // result formats
    let mut out = framed(b'B', &body);
    let mut execute = vec![0u8]; // unnamed portal
    execute.extend_from_slice(&0u32.to_be_bytes());
    out.extend(framed(b'E', &execute));
    out
}

fn sync() -> Vec<u8> {
    framed(b'S', &[])
}

fn framed(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![kind];
    out.extend_from_slice(&((body.len() + 4) as u32).to_be_bytes());
    out.extend_from_slice(body);
    out
}

/// Describe `n` statements, then execute the first. Returns how many events the server handled
/// for the execute alone: 0 when the first statement's described answer was still cached.
async fn events_for_executing_the_first_of(n: usize) -> u64 {
    let state = new_state().await;
    let (_, port) = start_server(&state, None).await;
    let mut tcp = connect_and_start(port).await;

    let mut batch = Vec::new();
    for i in 0..n {
        batch.extend(parse(&format!("s{i}"), &format!("SELECT {i}")));
        batch.extend(describe_statement(&format!("s{i}")));
    }
    batch.extend(sync());
    tcp.write_all(&batch).await.expect("write");
    until_ready(&mut tcp).await;

    let before = state.access_log_total().await;
    let mut execute = bind_and_execute("s0");
    execute.extend(sync());
    tcp.write_all(&execute).await.expect("write");
    let seen = until_ready(&mut tcp).await;
    assert!(
        seen.contains(&b'D'),
        "the execute must return its row; saw {seen:?}"
    );
    state.access_log_total().await - before
}

#[tokio::test]
async fn sixty_four_described_statements_stay_cached_and_the_sixty_fifth_evicts_the_first() {
    assert_eq!(
        events_for_executing_the_first_of(64).await,
        0,
        "with 64 statements described, the first one's answer must still be cached: its \
         Execute must not ask the handler again"
    );
    assert_eq!(
        events_for_executing_the_first_of(65).await,
        1,
        "the 65th described statement must evict the first, whose Execute is then resolved again"
    );
}

#[tokio::test]
async fn a_silent_peer_is_closed_at_first_byte_timeout_secs_and_a_started_one_is_not() {
    let state = new_state().await;
    let first_byte = Duration::from_secs(3);
    let (server_id, port) = start_server(
        &state,
        Some(serde_json::json!({"first_byte_timeout_secs": first_byte.as_secs()})),
    )
    .await;

    let mut silent = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    let mut started_peer = connect_and_start(port).await;

    let started = Instant::now();
    let mut sink = Vec::new();
    let closed = tokio::time::timeout(
        first_byte + Duration::from_secs(30),
        silent.read_to_end(&mut sink),
    )
    .await;
    assert!(
        closed.is_ok(),
        "a silent peer was still connected after {:?}; first_byte_timeout_secs is not applied",
        started.elapsed()
    );
    assert!(
        started.elapsed() >= first_byte / 2,
        "closed after {:?}, before the bound — something else closed it",
        started.elapsed()
    );
    // The silent peer's row closes too. The early return on this path used to skip
    // `close_connection_on_server`, leaving an Active row nothing would ever collect.
    let mut open = usize::MAX;
    for _ in 0..200 {
        open = state
            .get_server(server_id)
            .await
            .expect("server")
            .connections
            .values()
            .filter(|c| c.status != netget::state::server::ConnectionStatus::Closed)
            .count();
        if open == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert_eq!(
        open, 1,
        "only the started peer's row may stay open once the silent one is closed"
    );

    started_peer.write_all(&query_of(64)).await.expect("write");
    let seen = until_ready(&mut started_peer).await;
    assert!(
        seen.contains(&b'D'),
        "the started peer must still be served"
    );
}

#[tokio::test]
async fn a_silent_session_is_closed_at_idle_timeout_secs_and_a_query_inside_it_is_answered() {
    let state = new_state().await;
    let idle = Duration::from_secs(3);
    let (_, port) = start_server(
        &state,
        Some(serde_json::json!({"idle_timeout_secs": idle.as_secs()})),
    )
    .await;

    let mut tcp = connect_and_start(port).await;
    for _ in 0..2 {
        tcp.write_all(&query_of(64)).await.expect("write");
        let seen = until_ready(&mut tcp).await;
        assert!(
            seen.contains(&b'D'),
            "a query inside the idle window must be answered"
        );
    }

    let started = Instant::now();
    let mut sink = Vec::new();
    let closed =
        tokio::time::timeout(idle + Duration::from_secs(30), tcp.read_to_end(&mut sink)).await;
    assert!(
        closed.is_ok(),
        "a silent session was still open after {:?}; idle_timeout_secs is not applied",
        started.elapsed()
    );
    assert!(
        started.elapsed() >= idle / 2,
        "closed after {:?}, before the bound — something else closed it",
        started.elapsed()
    );
}

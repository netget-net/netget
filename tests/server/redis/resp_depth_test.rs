//! A RESP frame's shape is chosen by the peer, before any authentication, and
//! `redis-protocol` 6.0's decoder recurses once per nested array with no depth limit
//! (`d_parse_frame` → `d_parse_array` → `nom::multi::count(d_parse_frame)`). `*1\r\n` is four
//! bytes per level, so a few hundred kilobytes overflow a tokio worker's stack — and a Rust
//! stack overflow is a `SIGSEGV` against the guard page, not a panic: the whole process dies,
//! every other server and client in it with it.
//!
//! These tests drive `src/utils/resp.rs`'s pre-scan from a raw socket:
//!
//! - a 100 000-level bomb is refused and the server still answers a fresh connection;
//! - a small bomb that fits one read gets the exact refusal, then EOF;
//! - a frame exactly at `MAX_RESP_DEPTH` is still answered, one level more is not;
//! - a declared array or bulk length the buffer cap guarantees can never complete is refused
//!   at the header, rather than after the peer has been allowed to fill 64 MiB.
//!
//! Without the guard the first test does not fail — the test binary aborts with
//! `fatal runtime error: stack overflow`, which is how the defect was confirmed.
//!
//! Zero LLM calls: a `*` static handler answers every command that gets through, and
//! `instruction: Some(String::new())` keeps `ServerForm::create` from substituting its default
//! instruction.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features redis --test server -- server::redis::resp_depth --test-threads=100


use std::time::Duration;

use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use netget::state::ServerId;
use netget::utils::resp::MAX_RESP_DEPTH;
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

async fn wait_for_port(state: &AppState, id: ServerId) -> u16 {
    for _ in 0..100 {
        if let Some(s) = state.get_server(id).await {
            if let Some(addr) = s.local_addr {
                return addr.port();
            }
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("Redis server #{} never bound a port", id.as_u32());
}

/// A server that answers every command it is allowed to see with `+PONG`.
async fn start_pong_server(state: &AppState) -> u16 {
    let (tx, _rx) = mpsc::unbounded_channel();
    let server_id = ServerForm {
        protocol: "redis".to_string(),
        port: Some(0),
        instruction: Some(String::new()),
        event_handlers: Some(vec![serde_json::json!({
            "event_pattern": "*",
            "handler": {
                "type": "static",
                "actions": [ { "type": "redis_simple_string", "value": "PONG" } ]
            }
        })]),
        ..Default::default()
    }
    .create(state, tx)
    .await
    .expect("create redis server");
    wait_for_port(state, server_id).await
}

/// `levels` nested one-element arrays around a single `PING` bulk string.
fn nested(levels: usize) -> Vec<u8> {
    let mut frame = b"*1\r\n".repeat(levels);
    frame.extend_from_slice(b"$4\r\nPING\r\n");
    frame
}

/// Everything the server writes until it closes, or until `deadline` passes.
///
/// A reset counts as a close: when the server hangs up on a peer that is still sending, the
/// peer's kernel may see RST rather than FIN. What was read before it is still returned.
async fn read_until_close(stream: &mut TcpStream, deadline: Duration) -> (Vec<u8>, bool) {
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    let result = tokio::time::timeout(deadline, async {
        loop {
            match stream.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(n) => out.extend_from_slice(&buf[..n]),
            }
        }
    })
    .await;
    (out, result.is_ok())
}

/// One command on a fresh connection, one reply.
async fn ping(port: u16) -> Vec<u8> {
    let mut stream = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect for PING");
    stream
        .write_all(b"*1\r\n$4\r\nPING\r\n")
        .await
        .expect("write PING");
    let mut buf = [0u8; 256];
    let n = tokio::time::timeout(Duration::from_secs(10), stream.read(&mut buf))
        .await
        .expect("a PING reply within 10s")
        .expect("read PING reply");
    buf[..n].to_vec()
}

/// The headline: 100 000 levels, 400 KB on the wire, from a peer that has not authenticated
/// and never will. Before the guard this aborted the whole process.
#[tokio::test]
async fn a_nesting_bomb_is_refused_and_the_server_survives() {
    let state = new_state().await;
    let port = start_pong_server(&state).await;

    let bomb = nested(100_000);
    assert!(bomb.len() > 400_000, "the bomb is {} bytes", bomb.len());

    let stream = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    let (mut read_half, mut write_half) = stream.into_split();
    // The server refuses after the first read and closes with most of the bomb unread, so
    // the write side is expected to fail part-way; that is the refusal working.
    let writer = tokio::spawn(async move {
        let _ = write_half.write_all(&bomb).await;
        let _ = write_half.shutdown().await;
    });

    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    let closed = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            match read_half.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(n) => out.extend_from_slice(&buf[..n]),
            }
        }
    })
    .await
    .is_ok();
    writer.abort();

    assert!(
        closed,
        "the server neither refused nor closed a 100 000-level frame within 20s; it read {:?}",
        String::from_utf8_lossy(&out)
    );
    // Either the refusal arrived, or the peer's kernel saw RST first and discarded it. What
    // must never arrive is an answer: that would mean the frame reached the handler.
    assert!(
        out.is_empty() || out.starts_with(b"-ERR"),
        "expected a RESP error or a bare close, got {:?}",
        String::from_utf8_lossy(&out)
    );
    assert!(
        !out.windows(5).any(|w| w == b"+PONG"),
        "the nested frame was decoded and answered"
    );

    // The part that matters: the process is still here and still serving.
    assert_eq!(
        ping(port).await,
        b"+PONG\r\n",
        "the server must still answer a fresh connection after refusing the bomb"
    );
}

/// A bomb small enough to arrive in one read, so the refusal is never raced by a reset: the
/// exact error, then EOF.
#[tokio::test]
async fn a_small_bomb_gets_the_fixed_error_then_eof() {
    let state = new_state().await;
    let port = start_pong_server(&state).await;

    let mut stream = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    stream
        .write_all(&nested(MAX_RESP_DEPTH + 8))
        .await
        .expect("write");
    let (out, closed) = read_until_close(&mut stream, Duration::from_secs(10)).await;
    assert_eq!(
        String::from_utf8_lossy(&out),
        "-ERR Protocol error: nesting too deep\r\n",
        "expected the fixed refusal and nothing else"
    );
    assert!(closed, "the server must close after refusing");
}

/// The bound must not refuse what it allows: `MAX_RESP_DEPTH` levels is answered, one more is
/// not. Each on its own connection, because a refusal closes the connection.
#[tokio::test]
async fn a_frame_at_the_depth_limit_is_answered_and_one_deeper_is_not() {
    let state = new_state().await;
    let port = start_pong_server(&state).await;

    // `nested(n)` has n arrays; the innermost bulk string is not an aggregate, so it adds no
    // level.
    let mut at_limit = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    at_limit
        .write_all(&nested(MAX_RESP_DEPTH))
        .await
        .expect("write");
    let mut buf = [0u8; 256];
    let n = tokio::time::timeout(Duration::from_secs(10), at_limit.read(&mut buf))
        .await
        .expect("a reply within 10s")
        .expect("read");
    assert_eq!(
        &buf[..n],
        b"+PONG\r\n",
        "a frame exactly {MAX_RESP_DEPTH} arrays deep must reach the handler"
    );

    let mut over = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    over.write_all(&nested(MAX_RESP_DEPTH + 1))
        .await
        .expect("write");
    let (out, closed) = read_until_close(&mut over, Duration::from_secs(10)).await;
    assert_eq!(
        String::from_utf8_lossy(&out),
        "-ERR Protocol error: nesting too deep\r\n"
    );
    assert!(closed, "the server must close after refusing");
}

/// A declared length is a promise about bytes that have not arrived. One the 64 MiB buffer cap
/// guarantees can never be kept is refused on the header line — without the check the server
/// sat on `Incomplete` and let the peer fill the whole buffer first.
#[tokio::test]
async fn an_impossible_declared_length_is_refused_at_the_header() {
    let state = new_state().await;
    let port = start_pong_server(&state).await;

    for (header, expected) in [
        (
            &b"*4000000000\r\n"[..],
            "-ERR Protocol error: invalid multibulk length\r\n",
        ),
        (
            &b"*1\r\n$4000000000\r\n"[..],
            "-ERR Protocol error: invalid bulk length\r\n",
        ),
    ] {
        let mut stream = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("connect");
        stream.write_all(header).await.expect("write header");
        let (out, closed) = read_until_close(&mut stream, Duration::from_secs(10)).await;
        assert_eq!(
            String::from_utf8_lossy(&out),
            expected,
            "header {:?}",
            String::from_utf8_lossy(header)
        );
        assert!(
            closed,
            "the server must close after refusing {:?}",
            String::from_utf8_lossy(header)
        );
    }

    assert_eq!(ping(port).await, b"+PONG\r\n");
}

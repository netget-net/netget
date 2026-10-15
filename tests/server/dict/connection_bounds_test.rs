//! Every bound the DICT server declares, driven from the wire on a real, running server.
//!
//! 1. **Line length** — `max_inbound_bytes` is RFC 2229's 1024 bytes including CRLF. A line of
//!    exactly 1024 is answered; 1025 gets `500` and a close, before any handler runs.
//! 2. **First command** — a greeted peer that says nothing is closed at
//!    `first_byte_timeout_secs`.
//! 3. **Idle** — a peer that has been answered is closed at `idle_timeout_secs`, a *different*
//!    number, so a server that applied one parameter to both reads fails.
//! 4. **Parked for a human** — a command waiting on a `manual` rule is closed by neither.
//! 5. **Connection cap** — the peer past `MAX_CONNECTIONS` gets `420 Server temporarily
//!    unavailable` instead of the banner, and the slot comes back when a connection ends.
//!
//! How each was proved to fail without its bound is recorded in the commit that added it; in
//! short: removing the length check in `LineReader::next_line` makes the 1025-byte line an
//! ordinary command answered with 250 content; replacing either `tokio::time::timeout` around
//! the read with a bare read makes tests 2 and 3 hang past their windows; replacing
//! `accept_bounded` with `listener.accept()` admits the over-cap peer, which then reads a 220
//! banner instead of a 420.
//!
//! No model: static handlers, and the LLM endpoint is a dead port.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features dict --test server -- dict::connection_bounds --test-threads=100


use super::common::{self, Peer};
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

const FIRST_COMMAND_TIMEOUT: Duration = Duration::from_secs(6);
const IDLE_TIMEOUT: Duration = Duration::from_secs(20);

/// `src/server/dict/mod.rs::MAX_CONNECTIONS`, duplicated so a change to it makes someone
/// re-read this test.
const MAX_CONNECTIONS: usize = 256;

fn define_handler() -> serde_json::Value {
    serde_json::json!({
        "event_pattern": "dict_define",
        "handler": {"type": "static", "actions": [{
            "type": "send_dict_definitions",
            "word": "w",
            "definitions": [{"database": "db", "database_description": "D", "text": "defined"}]
        }]}
    })
}

fn bounds() -> Option<serde_json::Value> {
    Some(serde_json::json!({
        "first_byte_timeout_secs": FIRST_COMMAND_TIMEOUT.as_secs(),
        "idle_timeout_secs": IDLE_TIMEOUT.as_secs(),
    }))
}

#[tokio::test]
async fn a_1024_byte_line_is_answered_and_1025_is_refused_before_any_handler() {
    let state = common::new_state().await;
    let (_id, port, mut rx) = common::start(&state, vec![define_handler()], None).await;

    // "DEFINE db " is 10 bytes and CRLF 2, so a word of 1012 makes the line exactly 1024.
    let mut peer = Peer::connect(port).await;
    assert!(peer.line(10).await.starts_with("220 "));
    peer.send(&format!("DEFINE db {}", "a".repeat(1012))).await;
    let reply = peer.until_status(&["250", "552", "420", "500"], 30).await;
    assert!(
        reply[0].starts_with("150 "),
        "a 1024-byte line (CRLF included) is inside the RFC's limit and must be answered: \
         {reply:?}"
    );

    let mut peer = Peer::connect(port).await;
    assert!(peer.line(10).await.starts_with("220 "));
    common::drain(&mut rx);
    // Pipelined commands behind the oversize line are still unread when the server closes.
    // Closing over unread input sends RST, which can destroy the 500 before the peer reads it;
    // the server drains in-flight input first (`linger`) so the refusal arrives and then FIN.
    peer.send(&format!(
        "DEFINE db {}\r\n{}STATUS",
        "a".repeat(1013),
        "STATUS\r\n".repeat(200)
    ))
    .await;
    let reply = peer.line(10).await;
    assert_eq!(
        reply, "500 Syntax error, command line too long\r\n",
        "a 1025-byte line exceeds RFC 2229's 1024 and must be refused"
    );
    assert_eq!(
        peer.line(10).await,
        "",
        "the connection must close after the refusal"
    );
    let log = common::wait_for_log(&mut rx, "decision=fail_closed_line_too_long", 10).await;
    assert!(
        !log.iter().any(|l| l.contains("decision=model_")),
        "the oversize line reached the handler: {log:#?}"
    );
}

#[tokio::test]
async fn a_line_with_no_newline_is_refused_once_it_passes_the_limit() {
    let state = common::new_state().await;
    let (_id, port, _rx) = common::start(&state, vec![define_handler()], None).await;
    let mut peer = Peer::connect(port).await;
    assert!(peer.line(10).await.starts_with("220 "));
    use tokio::io::AsyncWriteExt;
    peer.reader
        .get_mut()
        .write_all(&vec![b'x'; 64 * 1024])
        .await
        .ok();
    assert_eq!(
        peer.line(10).await,
        "500 Syntax error, command line too long\r\n",
        "the server must not buffer toward a newline that never comes"
    );
}

#[tokio::test]
async fn a_greeted_peer_that_says_nothing_is_closed_at_the_first_command_bound() {
    let state = common::new_state().await;
    let (_id, port, _rx) = common::start(&state, vec![define_handler()], bounds()).await;
    let mut peer = Peer::connect(port).await;
    assert!(peer.line(10).await.starts_with("220 "));

    let started = std::time::Instant::now();
    let mut sink = Vec::new();
    let read = tokio::time::timeout(
        FIRST_COMMAND_TIMEOUT + Duration::from_secs(40),
        peer.reader.read_to_end(&mut sink),
    )
    .await;
    let elapsed = started.elapsed();
    assert!(
        read.is_ok(),
        "a silent peer still held the socket after {}s: first_byte_timeout_secs is not applied",
        elapsed.as_secs()
    );
    assert!(sink.is_empty(), "got {:?}", String::from_utf8_lossy(&sink));
    assert!(
        elapsed >= FIRST_COMMAND_TIMEOUT / 2,
        "closed after {}ms, which is not the configured bound",
        elapsed.as_millis()
    );
}

#[tokio::test]
async fn an_answered_peer_is_held_for_the_idle_bound_instead() {
    let state = common::new_state().await;
    let (_id, port, _rx) = common::start(&state, vec![define_handler()], bounds()).await;
    let mut peer = Peer::connect(port).await;
    assert!(peer.line(10).await.starts_with("220 "));
    peer.send("CLIENT bounds-test").await;
    assert_eq!(peer.line(10).await, "250 ok\r\n");

    let started = std::time::Instant::now();
    let mut sink = Vec::new();
    tokio::time::timeout(
        IDLE_TIMEOUT + Duration::from_secs(40),
        peer.reader.read_to_end(&mut sink),
    )
    .await
    .expect("the answered connection was never closed: idle_timeout_secs is not applied")
    .expect("read to EOF");
    let elapsed = started.elapsed();
    assert!(
        elapsed >= FIRST_COMMAND_TIMEOUT + Duration::from_secs(2),
        "closed after {}ms — the first-command bound, not the idle bound",
        elapsed.as_millis()
    );
}

#[tokio::test]
async fn a_command_parked_for_a_human_is_never_closed_by_either_deadline() {
    let state = common::new_state().await;
    let manual = serde_json::json!({
        "event_pattern": "*",
        "handler": {"type": "manual", "timeout_secs": 300}
    });
    let (_id, port, _rx) = common::start(&state, vec![manual], bounds()).await;
    let mut peer = Peer::connect(port).await;
    assert!(peer.line(10).await.starts_with("220 "));
    peer.send("DEFINE * parked").await;

    tokio::time::sleep(IDLE_TIMEOUT + Duration::from_secs(10)).await;
    let mut buf = [0u8; 256];
    match tokio::time::timeout(Duration::from_secs(3), peer.reader.read(&mut buf)).await {
        Err(_) => {}
        Ok(Ok(0)) => panic!("closed while its DEFINE was parked for a human"),
        Ok(Ok(n)) => panic!(
            "answered a command nobody decided: {:?}",
            String::from_utf8_lossy(&buf[..n])
        ),
        Ok(Err(e)) => panic!("reset while parked: {e}"),
    }
}

#[tokio::test]
async fn the_connection_past_the_cap_is_told_420_and_the_slot_comes_back() {
    let state = common::new_state().await;
    let (server_id, port, _rx) = common::start(&state, vec![define_handler()], None).await;

    let mut held = Vec::with_capacity(MAX_CONNECTIONS);
    for i in 0..MAX_CONNECTIONS {
        held.push(
            TcpStream::connect(("127.0.0.1", port))
                .await
                .unwrap_or_else(|e| panic!("connection {i} of the cap failed: {e}")),
        );
    }
    for _ in 0..600 {
        if state
            .get_server(server_id)
            .await
            .map(|s| s.connections.len())
            .unwrap_or(0)
            >= MAX_CONNECTIONS
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let mut over = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("the listener must still accept");
    let mut refusal = Vec::new();
    tokio::time::timeout(Duration::from_secs(20), over.read_to_end(&mut refusal))
        .await
        .expect("the over-cap connection was neither answered nor closed")
        .expect("read the refusal");
    assert_eq!(
        String::from_utf8_lossy(&refusal),
        "420 Server temporarily unavailable\r\n",
        "RFC 2229 lets the server greet with 420 instead of 220"
    );

    drop(held.pop());
    let mut admitted = false;
    for _ in 0..100 {
        let mut candidate = Peer::connect(port).await;
        if candidate.line(10).await.starts_with("220 ") {
            admitted = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        admitted,
        "the slot never came back after a connection ended"
    );
}

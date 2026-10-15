//! Every bound the Beanstalkd server declares, driven from the wire on a real, running server.
//!
//! 1. **Line length** — upstream's 224 bytes including CRLF. A 224-byte line is answered; 225
//!    gets `BAD_FORMAT` and a close, before any handler runs.
//! 2. **Job size** (`max_inbound_bytes`) — a `put` of exactly 65535 bytes is accepted; 65536 is
//!    `JOB_TOO_BIG`. A `put` *declaring* four gigabytes and sending no body is answered at once
//!    — the size is judged from the declaration, before any body byte is read — and closed.
//! 3. **First command** — a peer that says nothing is closed at `first_byte_timeout_secs`.
//! 4. **Idle** — a peer that has been answered is closed at `idle_timeout_secs`, a *different*
//!    number, so a server that applied one parameter to both reads fails.
//! 5. **A worker waiting in `reserve` is not idle** — the idle bound does not cut it; a
//!    `reserve-with-timeout` is answered `TIMED_OUT` at its own timeout.
//! 6. **Parked for a human** — a command waiting on a `manual` rule is closed by neither.
//! 7. **Connection cap** — the peer past `MAX_CONNECTIONS` reads `OUT_OF_MEMORY` and EOF, and
//!    the slot comes back when a connection ends.
//!
//! How each was shown to fail without its bound is recorded in the commit that added it and in
//! `tests/server/beanstalkd/CLAUDE.md`.
//!
//! No model: static handlers, and the LLM endpoint is a dead port.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features beanstalkd --test server -- beanstalkd::connection_bounds --test-threads=100

use super::common::{self, Peer};
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

const FIRST_COMMAND_TIMEOUT: Duration = Duration::from_secs(6);
const IDLE_TIMEOUT: Duration = Duration::from_secs(20);

/// `src/server/beanstalkd/mod.rs::MAX_CONNECTIONS`, duplicated so a change to it makes someone
/// re-read this test.
const MAX_CONNECTIONS: usize = 256;

/// `wire::MAX_JOB_BYTES`, duplicated for the same reason.
const MAX_JOB_BYTES: usize = 65_535;

fn handlers() -> Vec<serde_json::Value> {
    vec![
        serde_json::json!({
            "event_pattern": "beanstalkd_put",
            "handler": {"type": "static", "actions": [{"type": "insert_beanstalkd_job", "job_id": 1}]}
        }),
        serde_json::json!({
            "event_pattern": "beanstalkd_reserve",
            "handler": {"type": "static", "actions": [{"type": "wait_for_beanstalkd_job"}]}
        }),
    ]
}

fn bounds() -> Option<serde_json::Value> {
    Some(serde_json::json!({
        "first_byte_timeout_secs": FIRST_COMMAND_TIMEOUT.as_secs(),
        "idle_timeout_secs": IDLE_TIMEOUT.as_secs(),
    }))
}

#[tokio::test]
async fn a_224_byte_line_is_answered_and_225_is_refused_before_any_handler() {
    let state = common::new_state().await;
    let (_id, port, mut rx) = common::start(&state, handlers(), None).await;

    // 222 bytes of an unknown command plus CRLF is exactly 224: inside the bound, so it is
    // read and answered as a command, and the connection goes on.
    let mut peer = Peer::connect(port).await;
    peer.send(&"x".repeat(222)).await;
    assert_eq!(peer.line(10).await, "UNKNOWN_COMMAND\r\n");
    peer.send("list-tube-used").await;
    assert_eq!(peer.line(10).await, "USING default\r\n");

    // 225, with pipelined commands behind it that are still unread when the server closes.
    // Closing over unread input sends RST, which can destroy the refusal; the server drains
    // in-flight input first (`linger`) so it arrives and then FIN.
    let mut peer = Peer::connect(port).await;
    common::drain(&mut rx);
    peer.send_raw(
        format!(
            "{}\r\n{}",
            "x".repeat(223),
            "list-tube-used\r\n".repeat(2000)
        )
        .as_bytes(),
    )
    .await;
    assert_eq!(peer.line(10).await, "BAD_FORMAT\r\n");
    assert_eq!(
        peer.line(10).await,
        "",
        "the connection must close after the refusal"
    );
    let log = common::wait_for_log(&mut rx, "decision=fail_closed_line_too_long", 10).await;
    assert!(
        !log.iter().any(|l| l.contains("decision=model_")),
        "the oversize line reached a handler: {log:#?}"
    );
}

#[tokio::test]
async fn a_line_with_no_newline_is_refused_once_it_passes_the_limit() {
    let state = common::new_state().await;
    let (_id, port, _rx) = common::start(&state, handlers(), None).await;
    let mut peer = Peer::connect(port).await;
    use tokio::io::AsyncWriteExt;
    peer.reader
        .get_mut()
        .write_all(&vec![b'x'; 64 * 1024])
        .await
        .ok();
    assert_eq!(
        peer.line(10).await,
        "BAD_FORMAT\r\n",
        "the server must not buffer toward a newline that never comes"
    );
}

#[tokio::test]
async fn a_job_of_max_job_size_is_accepted_and_one_byte_more_is_too_big() {
    let state = common::new_state().await;
    let (_id, port, mut rx) = common::start(&state, handlers(), None).await;
    let mut peer = Peer::connect(port).await;

    peer.put(&vec![b'a'; MAX_JOB_BYTES]).await;
    assert_eq!(peer.line(30).await, "INSERTED 1\r\n");

    common::drain(&mut rx);
    peer.put(&vec![b'a'; MAX_JOB_BYTES + 1]).await;
    assert_eq!(peer.line(30).await, "JOB_TOO_BIG\r\n");
    // Upstream skips the oversize body and carries on; so does NetGet.
    peer.send("list-tube-used").await;
    assert_eq!(peer.line(10).await, "USING default\r\n");
    let log = common::wait_for_log(&mut rx, "decision=fail_closed_job_too_big", 10).await;
    assert!(
        !log.iter().any(|l| l.contains("decision=model_")),
        "the oversize job reached a handler: {log:#?}"
    );
}

#[tokio::test]
async fn a_put_declaring_gigabytes_is_refused_from_the_declaration_alone() {
    let state = common::new_state().await;
    let (_id, port, _rx) = common::start(&state, handlers(), None).await;

    for declared in ["4000000000", "99999999999999999999999"] {
        let mut peer = Peer::connect(port).await;
        // No body follows. A server that waited for the body before judging its size would
        // never answer; one that allocated for it would try to reserve 4 GB.
        peer.send(&format!("put 0 0 60 {declared}")).await;
        assert_eq!(
            peer.line(10).await,
            "JOB_TOO_BIG\r\n",
            "declared {declared}: answered before any body byte"
        );
        assert_eq!(
            peer.line(10).await,
            "",
            "declared {declared}: too large to skip, so the connection closes"
        );
    }
}

#[tokio::test]
async fn a_peer_that_says_nothing_is_closed_at_the_first_command_bound() {
    let state = common::new_state().await;
    let (_id, port, _rx) = common::start(&state, handlers(), bounds()).await;
    let mut peer = Peer::connect(port).await;

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
    let (_id, port, _rx) = common::start(&state, handlers(), bounds()).await;
    let mut peer = Peer::connect(port).await;
    peer.send("use bounds").await;
    assert_eq!(peer.line(10).await, "USING bounds\r\n");

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
async fn a_worker_waiting_in_reserve_outlives_the_idle_bound() {
    let state = common::new_state().await;
    let short = Some(serde_json::json!({
        "first_byte_timeout_secs": 3,
        "idle_timeout_secs": 3,
    }));
    let (_id, port, mut rx) = common::start(&state, handlers(), short).await;

    // Plain reserve: the model left it waiting, so the server owes the worker an answer and
    // the 3-second idle bound must not cut it.
    let mut worker = Peer::connect(port).await;
    worker.send("reserve").await;
    common::wait_for_log(&mut rx, "decision=model_wait", 30).await;
    worker
        .assert_silent_and_open(10, "waiting in reserve past the idle bound")
        .await;

    // reserve-with-timeout: NetGet answers TIMED_OUT at the worker's own timeout, and the
    // session goes on.
    let mut worker = Peer::connect(port).await;
    worker.send("reserve-with-timeout 2").await;
    let started = std::time::Instant::now();
    assert_eq!(worker.line(30).await, "TIMED_OUT\r\n");
    assert!(
        started.elapsed() >= Duration::from_millis(1500),
        "TIMED_OUT after {}ms, before the worker's 2s",
        started.elapsed().as_millis()
    );
    worker.send("list-tube-used").await;
    assert_eq!(worker.line(10).await, "USING default\r\n");

    // reserve-with-timeout 0 is upstream's poll: answered at once.
    worker.send("reserve-with-timeout 0").await;
    assert_eq!(worker.line(10).await, "TIMED_OUT\r\n");
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
    peer.send("delete 5").await;

    tokio::time::sleep(IDLE_TIMEOUT + Duration::from_secs(10)).await;
    peer.assert_silent_and_open(3, "its delete was parked for a human")
        .await;
}

#[tokio::test]
async fn the_connection_past_the_cap_reads_out_of_memory_and_the_slot_comes_back() {
    let state = common::new_state().await;
    let (server_id, port, _rx) = common::start(&state, handlers(), None).await;

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
        "OUT_OF_MEMORY\r\n",
        "upstream's try-again-later answer, then EOF"
    );

    drop(held.pop());
    let mut admitted = false;
    for _ in 0..100 {
        let mut candidate = Peer::connect(port).await;
        candidate.send("list-tube-used").await;
        if candidate.line(10).await == "USING default\r\n" {
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

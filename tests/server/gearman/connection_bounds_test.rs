//! Every bound the Gearman server declares, driven from the wire on a real, running server.
//!
//! 1. **Packet size** (`max_inbound_bytes`, 1 MiB) — a packet of exactly 1 MiB is answered; a
//!    header *declaring* one byte more is refused `ERROR too_large` at once, with no body sent.
//! 2. **Admin line** — 1024 bytes including LF answered, 1025 refused `ERR LINE_TOO_LONG` and
//!    closed; a newline-less flood refused the same way.
//! 3. **Not `\0REQ`** — a binary message with another magic is closed without an answer.
//! 4. **First byte** and **idle** — distinct numbers, so a server applying one to both reads
//!    fails.
//! 5. **Parked for a human** — a job waiting on a `manual` rule is closed by neither.
//! 6. **Connection cap** — the peer past `MAX_CONNECTIONS` is closed with no bytes, and the slot
//!    comes back.
//!
//! How each was shown to fail without its bound is in `tests/server/gearman/CLAUDE.md`.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features gearman --test server -- gearman::connection_bounds --test-threads=100


use super::common::{self, req, Peer};
use netget::server::gearman::wire;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const FIRST_BYTE_TIMEOUT: Duration = Duration::from_secs(6);
const IDLE_TIMEOUT: Duration = Duration::from_secs(20);

/// `src/server/gearman/mod.rs::MAX_CONNECTIONS`, duplicated so a change to it makes someone
/// re-read this test.
const MAX_CONNECTIONS: usize = 256;

fn complete() -> serde_json::Value {
    serde_json::json!({
        "event_pattern": "gearman_job_submitted",
        "handler": {"type": "static", "actions": [
            {"type": "complete_gearman_job", "result": "ok"}
        ]}
    })
}

fn bounds() -> Option<serde_json::Value> {
    Some(serde_json::json!({
        "first_byte_timeout_secs": FIRST_BYTE_TIMEOUT.as_secs(),
        "idle_timeout_secs": IDLE_TIMEOUT.as_secs(),
    }))
}

#[tokio::test]
async fn a_packet_of_exactly_the_limit_is_answered_and_one_byte_more_is_refused() {
    let state = common::new_state().await;
    let (_id, port, mut rx) = common::start(&state, vec![complete()], None).await;

    // "f" NUL "" NUL workload: 3 bytes of framing, so the workload makes the body exactly 1 MiB.
    let workload = vec![b'w'; wire::MAX_PACKET_BYTES - 3];
    let mut peer = Peer::connect(port).await;
    peer.send(&req(wire::SUBMIT_JOB, &[b"f", b"", &workload]))
        .await;
    assert_eq!(peer.packet(30).await.0, wire::JOB_CREATED);
    assert_eq!(peer.packet(30).await.0, wire::WORK_COMPLETE);

    common::drain(&mut rx);
    let mut peer = Peer::connect(port).await;
    let mut header = b"\0REQ".to_vec();
    header.extend_from_slice(&wire::SUBMIT_JOB.to_be_bytes());
    header.extend_from_slice(&(wire::MAX_PACKET_BYTES as u32 + 1).to_be_bytes());
    // The header alone, with 48 KiB of a body the server will never read behind it: the
    // refusal must come from the declaration, and survive the unread input at close.
    header.extend(std::iter::repeat_n(b'w', 48 * 1024));
    peer.send(&header).await;
    let (t, args, _) = peer.packet(10).await;
    assert_eq!((t, &args[0]), (wire::ERROR, &b"too_large".to_vec()));
    assert!(peer.rest(10).await.is_empty(), "the connection must close");
    let log = common::wait_for_log(&mut rx, "decision=fail_closed_too_large", 10).await;
    assert!(
        !log.iter().any(|l| l.contains("decision=model_")),
        "the oversize packet reached a handler: {log:#?}"
    );
}

#[tokio::test]
async fn an_admin_line_of_the_limit_is_answered_and_one_byte_more_is_refused() {
    let state = common::new_state().await;
    let (_id, port, _rx) = common::start(&state, vec![complete()], None).await;

    let mut peer = Peer::connect(port).await;
    peer.send(format!("{}\n", "x".repeat(wire::MAX_ADMIN_LINE - 1)).as_bytes())
        .await;
    assert_eq!(
        peer.line(10).await,
        "ERR UNKNOWN_COMMAND Unknown+server+command\n",
        "1024 bytes including LF is a line"
    );

    let mut peer = Peer::connect(port).await;
    peer.send(format!("{}\n", "x".repeat(wire::MAX_ADMIN_LINE)).as_bytes())
        .await;
    assert_eq!(
        peer.line(10).await,
        "ERR LINE_TOO_LONG Command+line+too+long\n"
    );
    assert_eq!(peer.line(10).await, "", "the connection must close");

    let mut peer = Peer::connect(port).await;
    peer.send(&vec![b'x'; 64 * 1024]).await;
    assert_eq!(
        peer.line(10).await,
        "ERR LINE_TOO_LONG Command+line+too+long\n",
        "the server must not buffer toward a newline that never comes"
    );
}

#[tokio::test]
async fn a_binary_message_without_req_magic_is_closed_unanswered() {
    let state = common::new_state().await;
    let (_id, port, _rx) = common::start(&state, vec![complete()], None).await;
    let mut peer = Peer::connect(port).await;
    peer.send(b"\0XYZ\0\0\0\x07\0\0\0\0").await;
    assert!(peer.rest(10).await.is_empty());
}

#[tokio::test]
async fn a_peer_that_says_nothing_is_closed_at_the_first_byte_bound() {
    let state = common::new_state().await;
    let (_id, port, _rx) = common::start(&state, vec![complete()], bounds()).await;
    let mut peer = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let started = std::time::Instant::now();
    let mut sink = Vec::new();
    tokio::time::timeout(
        FIRST_BYTE_TIMEOUT + Duration::from_secs(40),
        peer.read_to_end(&mut sink),
    )
    .await
    .expect("a silent peer still held the socket: first_byte_timeout_secs is not applied")
    .expect("read to EOF");
    assert!(sink.is_empty());
    assert!(
        started.elapsed() >= FIRST_BYTE_TIMEOUT / 2,
        "closed after {}ms, which is not the configured bound",
        started.elapsed().as_millis()
    );
}

#[tokio::test]
async fn an_answered_peer_is_held_for_the_idle_bound_instead() {
    let state = common::new_state().await;
    let (_id, port, _rx) = common::start(&state, vec![complete()], bounds()).await;
    let mut peer = Peer::connect(port).await;
    peer.send(&req(wire::ECHO_REQ, &[b"hi"])).await;
    assert_eq!(peer.packet(10).await.0, wire::ECHO_RES);

    let started = std::time::Instant::now();
    let rest = peer.rest(IDLE_TIMEOUT.as_secs() + 40).await;
    assert!(rest.is_empty());
    assert!(
        started.elapsed() >= FIRST_BYTE_TIMEOUT + Duration::from_secs(2),
        "closed after {}ms — the first-byte bound, not the idle bound",
        started.elapsed().as_millis()
    );
}

#[tokio::test]
async fn a_job_parked_for_a_human_is_never_closed_by_either_deadline() {
    let state = common::new_state().await;
    let (_id, port, _rx) = common::start(&state, vec![common::manual_handler()], bounds()).await;
    let mut peer = Peer::connect(port).await;
    peer.send(&req(wire::SUBMIT_JOB, &[b"reverse", b"", b"abc"]))
        .await;
    assert_eq!(peer.packet(10).await.0, wire::JOB_CREATED);

    tokio::time::sleep(IDLE_TIMEOUT + Duration::from_secs(10)).await;
    let mut buf = [0u8; 64];
    match tokio::time::timeout(Duration::from_secs(3), peer.reader.read(&mut buf)).await {
        Err(_) => {}
        Ok(Ok(0)) => panic!("closed while its job was parked for a human"),
        Ok(Ok(n)) => panic!("answered a job nobody decided: {:?}", &buf[..n]),
        Ok(Err(e)) => panic!("reset while parked: {e}"),
    }
}

#[tokio::test]
async fn the_connection_past_the_cap_is_closed_and_the_slot_comes_back() {
    let state = common::new_state().await;
    let (server_id, port, _rx) = common::start(&state, vec![complete()], None).await;

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
    assert!(
        refusal.is_empty(),
        "no bytes: a packet it did not ask for would be misread"
    );

    drop(held.pop());
    let mut admitted = false;
    for _ in 0..100 {
        let mut candidate = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        candidate
            .write_all(&req(wire::ECHO_REQ, &[b"slot"]))
            .await
            .unwrap();
        let mut buf = [0u8; 16];
        if let Ok(Ok(n)) =
            tokio::time::timeout(Duration::from_secs(10), candidate.read(&mut buf)).await
        {
            if n > 0 {
                admitted = true;
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        admitted,
        "the slot never came back after a connection ended"
    );
}

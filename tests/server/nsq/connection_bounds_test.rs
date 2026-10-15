//! Every bound the NSQ server declares, driven from the wire on a real, running server.
//!
//! 1. **Message size** — a PUB of exactly 1 MiB is answered; one *declaring* a byte more is
//!    refused `E_BAD_MESSAGE` from its size field alone, with no body sent.
//! 2. **Body size** (`max_inbound_bytes`, 5 MiB) — an MPUB declaring a byte more is refused
//!    `E_BAD_BODY`; an MPUB declaring one message more than nsqd's count bound is refused from
//!    its eight leading bytes.
//! 3. **Line** — 1024 bytes including LF is a line; 1024 without one is refused.
//! 4. **Magic** — anything but `"  V2"` gets `E_BAD_PROTOCOL` and the close.
//! 5. **First byte**, **heartbeat silence** and **idle** — distinct numbers, so a server applying
//!    one to another fails. A client that answers heartbeats stays; one that does not is closed
//!    after two intervals; one that disabled heartbeats is held to the idle bound.
//! 6. **Parked for a human** — a publish waiting on a `manual` rule is closed by none of them,
//!    and keeps receiving heartbeats while it waits.
//! 7. **RDY and the pending queue** — the model's deliveries past RDY wait; past
//!    `MAX_PENDING_MESSAGES` they are dropped and logged, and RDY never lets more through.
//! 8. **Connection cap** — the peer past `MAX_CONNECTIONS` is closed with no bytes, and the slot
//!    comes back.
//!
//! How each was shown to fail without its bound is in `tests/server/nsq/CLAUDE.md`.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features nsq --test server -- nsq::connection_bounds --test-threads=100

use super::common::{self, static_handler, Peer};
use netget::server::nsq::wire::{self, Command};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const FIRST_BYTE_TIMEOUT: Duration = Duration::from_secs(6);
const IDLE_TIMEOUT: Duration = Duration::from_secs(14);

/// `src/server/nsq/mod.rs::MAX_CONNECTIONS` and `MAX_PENDING_MESSAGES`, duplicated so a change
/// to either makes someone re-read this test.
const MAX_CONNECTIONS: usize = 256;
const MAX_PENDING_MESSAGES: usize = 1000;

fn accept_all() -> Vec<serde_json::Value> {
    vec![
        static_handler("nsq_publish", serde_json::json!([{"type": "send_nsq_ok"}])),
        static_handler(
            "nsq_subscribe",
            serde_json::json!([{"type": "send_nsq_ok"}]),
        ),
        static_handler("nsq_ready", serde_json::json!([])),
        static_handler("nsq_finish", serde_json::json!([])),
    ]
}

fn bounds() -> Option<serde_json::Value> {
    Some(serde_json::json!({
        "first_byte_timeout_secs": FIRST_BYTE_TIMEOUT.as_secs(),
        "idle_timeout_secs": IDLE_TIMEOUT.as_secs(),
    }))
}

#[tokio::test]
async fn a_message_of_exactly_the_limit_is_accepted_and_one_byte_more_is_refused() {
    let state = common::new_state().await;
    let (_id, port, mut rx) = common::start(&state, accept_all(), None).await;

    let mut peer = Peer::connect(port).await;
    peer.command(&Command::Pub {
        topic: "t".into(),
        body: vec![b'w'; wire::MAX_MSG_SIZE],
    })
    .await;
    peer.expect_response(b"OK", 30).await;

    common::drain(&mut rx);
    let mut peer = Peer::connect(port).await;
    let mut header = b"PUB t\n".to_vec();
    header.extend_from_slice(&(wire::MAX_MSG_SIZE as u32 + 1).to_be_bytes());
    // 48 KiB of a body the server will never read: the refusal must come from the declaration,
    // and survive the unread input at close.
    header.extend(std::iter::repeat_n(b'w', 48 * 1024));
    peer.send(&header).await;
    assert_eq!(
        peer.expect_error(10).await,
        "E_BAD_MESSAGE PUB message too big 1048577 > 1048576"
    );
    assert!(peer.rest(10).await.is_empty(), "the connection must close");
    let log = common::wait_for_log(&mut rx, "decision=fail_closed_too_large", 10).await;
    assert!(
        !log.iter().any(|l| l.contains("decision=model_")),
        "the oversize message reached a handler: {log:#?}"
    );
}

#[tokio::test]
async fn an_mpub_past_the_body_bound_or_the_count_bound_is_refused_before_its_body() {
    let state = common::new_state().await;
    let (_id, port, mut rx) = common::start(&state, accept_all(), None).await;

    let mut peer = Peer::connect(port).await;
    let mut header = b"MPUB t\n".to_vec();
    header.extend_from_slice(&(wire::MAX_BODY_SIZE as u32 + 1).to_be_bytes());
    peer.send(&header).await;
    assert_eq!(
        peer.expect_error(10).await,
        "E_BAD_BODY MPUB body too big 5242881 > 5242880"
    );
    assert!(peer.rest(10).await.is_empty());

    let mut peer = Peer::connect(port).await;
    let mut header = b"MPUB t\n".to_vec();
    header.extend_from_slice(&1000u32.to_be_bytes());
    header.extend_from_slice(&(wire::MAX_MPUB_MESSAGES as u32 + 1).to_be_bytes());
    peer.send(&header).await;
    assert_eq!(
        peer.expect_error(10).await,
        format!(
            "E_BAD_BODY MPUB invalid message count {}",
            wire::MAX_MPUB_MESSAGES + 1
        )
    );
    assert!(peer.rest(10).await.is_empty());
    let log = common::wait_for_log(&mut rx, "decision=fail_closed_mpub_count", 10).await;
    assert!(
        !log.iter().any(|l| l.contains("decision=model_")),
        "{log:#?}"
    );
}

#[tokio::test]
async fn a_line_of_the_limit_is_read_and_one_byte_more_is_refused() {
    let state = common::new_state().await;
    let (_id, port, _rx) = common::start(&state, accept_all(), None).await;

    let mut peer = Peer::connect(port).await;
    peer.send(format!("{}\n", "x".repeat(wire::MAX_LINE - 1)).as_bytes())
        .await;
    assert!(
        peer.expect_error(10)
            .await
            .starts_with("E_INVALID invalid command xxx"),
        "1024 bytes including LF is a line"
    );

    let mut peer = Peer::connect(port).await;
    peer.send(&vec![b'x'; 64 * 1024]).await;
    assert_eq!(
        peer.expect_error(10).await,
        "E_INVALID command line too long (over 1024 bytes)",
        "the server must not buffer toward a newline that never comes"
    );
    assert!(peer.rest(10).await.is_empty());
}

#[tokio::test]
async fn anything_but_the_v2_magic_is_refused_with_e_bad_protocol() {
    let state = common::new_state().await;
    let (_id, port, mut rx) = common::start(&state, accept_all(), None).await;
    let mut peer = Peer::connect_raw(port).await;
    peer.send(b"  V1PUB t\n").await;
    assert_eq!(peer.expect_error(10).await, "E_BAD_PROTOCOL");
    assert!(peer.rest(10).await.is_empty());
    common::wait_for_log(&mut rx, "decision=fail_closed_bad_magic", 10).await;
}

#[tokio::test]
async fn a_peer_that_says_nothing_is_closed_at_the_first_byte_bound() {
    let state = common::new_state().await;
    let (_id, port, _rx) = common::start(&state, accept_all(), bounds()).await;
    let mut peer = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let started = Instant::now();
    let mut sink = Vec::new();
    tokio::time::timeout(
        FIRST_BYTE_TIMEOUT + Duration::from_secs(40),
        peer.read_to_end(&mut sink),
    )
    .await
    .expect("a silent peer still held the socket: first_byte_timeout_secs is not applied")
    .expect("read to EOF");
    assert!(sink.is_empty(), "no heartbeat before the magic");
    assert!(
        started.elapsed() >= FIRST_BYTE_TIMEOUT / 2,
        "closed after {}ms, which is not the configured bound",
        started.elapsed().as_millis()
    );
}

#[tokio::test]
async fn a_client_silent_for_two_heartbeats_is_closed_and_one_that_answers_them_stays() {
    let state = common::new_state().await;
    let (_id, port, mut rx) = common::start(&state, accept_all(), bounds()).await;

    // Answers each heartbeat with NOP, as go-nsq does: held well past two intervals.
    let mut lively = Peer::connect(port).await;
    lively
        .identify(serde_json::json!({"heartbeat_interval": 1000}))
        .await;
    lively.expect_response(b"OK", 10).await;
    let started = Instant::now();
    let mut beats = 0;
    while started.elapsed() < Duration::from_secs(5) {
        let frame = lively.frame_raw(5, false).await;
        assert_eq!(
            (frame.frame_type, frame.data.as_slice()),
            (wire::FRAME_RESPONSE, wire::HEARTBEAT)
        );
        beats += 1;
        lively.command(&Command::Nop).await;
    }
    assert!(beats >= 3, "one heartbeat a second, got {beats} in 5s");

    // Says nothing after IDENTIFY: closed after two missed heartbeats, not the idle bound.
    let mut silent = Peer::connect(port).await;
    silent
        .identify(serde_json::json!({"heartbeat_interval": 1000}))
        .await;
    silent.expect_response(b"OK", 10).await;
    let started = Instant::now();
    let rest = silent.rest(IDLE_TIMEOUT.as_secs()).await;
    let elapsed = started.elapsed();
    assert!(
        elapsed >= Duration::from_millis(1500) && elapsed < FIRST_BYTE_TIMEOUT,
        "closed after {}ms; two heartbeats is 2000ms",
        elapsed.as_millis()
    );
    let heartbeat = wire::response_frame(wire::HEARTBEAT);
    assert!(
        rest.len() >= heartbeat.len() && rest.chunks(heartbeat.len()).all(|c| c == heartbeat),
        "only heartbeats before the close: {rest:?}"
    );
    common::wait_for_log(&mut rx, "decision=fail_closed_idle", 10).await;
}

#[tokio::test]
async fn a_client_that_disabled_heartbeats_is_held_to_the_idle_bound() {
    let state = common::new_state().await;
    let (_id, port, _rx) = common::start(&state, accept_all(), bounds()).await;
    let mut peer = Peer::connect(port).await;
    peer.identify(serde_json::json!({"heartbeat_interval": -1}))
        .await;
    peer.expect_response(b"OK", 10).await;
    let started = Instant::now();
    let rest = peer.rest(IDLE_TIMEOUT.as_secs() + 40).await;
    assert!(rest.is_empty(), "no heartbeats once disabled: {rest:?}");
    assert!(
        started.elapsed() >= FIRST_BYTE_TIMEOUT + Duration::from_secs(2),
        "closed after {}ms — the first-byte bound, not the idle bound",
        started.elapsed().as_millis()
    );
}

#[tokio::test]
async fn a_publish_parked_for_a_human_is_never_closed_and_keeps_its_heartbeats() {
    let state = common::new_state().await;
    let (_id, port, _rx) = common::start(&state, vec![common::manual_handler()], bounds()).await;
    let mut peer = Peer::connect(port).await;
    peer.identify(serde_json::json!({"heartbeat_interval": 1000}))
        .await;
    peer.expect_response(b"OK", 10).await;
    peer.command(&Command::Pub {
        topic: "t".into(),
        body: b"waiting".to_vec(),
    })
    .await;

    // Five seconds is two and a half silence windows; the client sends nothing.
    let started = Instant::now();
    let mut beats = 0;
    while started.elapsed() < Duration::from_secs(5) {
        let frame = peer.frame_raw(5, false).await;
        assert_eq!(
            (frame.frame_type, frame.data.as_slice()),
            (wire::FRAME_RESPONSE, wire::HEARTBEAT),
            "only heartbeats while the publish is parked"
        );
        beats += 1;
    }
    assert!(
        beats >= 3,
        "heartbeats continue while the model is asked: {beats}"
    );
}

#[tokio::test]
async fn deliveries_past_rdy_wait_and_past_the_pending_bound_are_dropped() {
    let state = common::new_state().await;
    let many: Vec<serde_json::Value> = (0..=MAX_PENDING_MESSAGES)
        .map(|i| serde_json::json!({"body": format!("m{i}")}))
        .collect();
    // The subscription is answered with OK and 1001 messages, before any RDY: all of them wait.
    let handlers = vec![
        static_handler(
            "nsq_subscribe",
            serde_json::json!([
                {"type": "send_nsq_ok"},
                {"type": "deliver_nsq_messages", "messages": many}
            ]),
        ),
        static_handler("nsq_ready", serde_json::json!([])),
        static_handler("nsq_finish", serde_json::json!([])),
    ];
    let (_id, port, mut rx) = common::start(&state, handlers, None).await;
    let mut peer = Peer::connect(port).await;
    peer.command(&Command::Sub {
        topic: "t".into(),
        channel: "c".into(),
    })
    .await;
    peer.expect_response(b"OK", 30).await;
    common::wait_for_log(&mut rx, "decision=fail_closed_pending_full", 10).await;
    peer.quiet_for(1).await;

    // RDY 3: exactly three arrive.
    peer.command(&Command::Rdy(3)).await;
    let mut ids = Vec::new();
    for i in 0..3 {
        let m = peer.expect_message(10).await;
        assert_eq!(m.body, format!("m{i}").into_bytes());
        ids.push(String::from_utf8(m.id.to_vec()).unwrap());
    }
    peer.quiet_for(1).await;

    // FIN one: exactly one more.
    peer.command(&Command::Fin(ids[0].clone())).await;
    assert_eq!(peer.expect_message(10).await.body, b"m3");
    peer.quiet_for(1).await;

    // RDY 2500: the rest of the thousand that were kept, and not the one that was dropped.
    peer.command(&Command::Rdy(wire::MAX_RDY_COUNT)).await;
    let mut last = Vec::new();
    for _ in 4..MAX_PENDING_MESSAGES {
        last = peer.expect_message(10).await.body;
    }
    assert_eq!(last, format!("m{}", MAX_PENDING_MESSAGES - 1).into_bytes());
    peer.quiet_for(1).await;
}

#[tokio::test]
async fn the_connection_past_the_cap_is_closed_and_the_slot_comes_back() {
    let state = common::new_state().await;
    let (server_id, port, _rx) = common::start(&state, accept_all(), None).await;

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
        "no bytes: a frame it did not ask for would be misread"
    );

    drop(held.pop());
    let mut admitted = false;
    for _ in 0..100 {
        let mut candidate = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        candidate
            .write_all(b"  V2IDENTIFY\n\0\0\0\x02{}")
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

//! Every bound the relay declares, driven from the wire. Model-free: static and manual rules.
//!
//! * the connection cap — 256 upgraded peers, the next one refused `503`, one slot back per close;
//! * the handshake deadline — a peer that sends no complete request head gets `408`;
//! * the idle bound — a peer that never answers the relay's Ping is closed `1001`, while a peer
//!   that answers (any RFC 6455 client, by itself) outlives the bound;
//! * the message size — `MAX_MESSAGE_BYTES` is read, one byte more is closed `1009`;
//! * subscriptions per connection, filters per REQ, subscription id length;
//! * JSON nesting — a depth bomb is a `NOTICE`, and the connection lives on;
//! * the queue in front of the model — past `MAX_QUEUED_MESSAGES` an event is refused
//!   `rate-limited:` rather than buffered.
//!
//! Each bound was verified by removing it and watching its test here fail.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features nostr --test server -- nostr::connection_bounds --test-threads=100

use super::common::{self, event_frame, note, relay_handlers, Peer, Read};
use futures::SinkExt;
use netget::server::nostr::{wire, MAX_MESSAGE_BYTES, MAX_QUEUED_MESSAGES};
use serde_json::json;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;

/// `src/server/nostr/mod.rs::MAX_CONNECTIONS`, duplicated so a change to it makes someone
/// re-read this test.
const MAX_CONNECTIONS: usize = 256;

const UPGRADE: &str = "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nUpgrade: websocket\r\n\
                       Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
                       Sec-WebSocket-Version: 13\r\n\r\n";

/// The status code of the relay's answer to a raw upgrade, and the socket it came on.
async fn raw_upgrade(port: u16) -> (u16, TcpStream) {
    let (status, _, stream) = raw_upgrade_head(port).await;
    (status, stream)
}

/// The status code, the response head and the socket.
async fn raw_upgrade_head(port: u16) -> (u16, String, TcpStream) {
    let mut stream = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    stream.write_all(UPGRADE.as_bytes()).await.expect("write");
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        let n = tokio::time::timeout(Duration::from_secs(10), stream.read(&mut byte))
            .await
            .expect("the relay neither upgraded nor refused")
            .expect("read");
        assert_eq!(
            n,
            1,
            "closed mid-head: {:?}",
            String::from_utf8_lossy(&head)
        );
        head.push(byte[0]);
    }
    let text = String::from_utf8_lossy(&head);
    let status = text
        .split(' ')
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| panic!("no status line: {text}"));
    (status, text.to_string(), stream)
}

#[tokio::test]
async fn the_connection_cap_refuses_503_and_returns_a_slot_per_close() {
    let state = common::new_state().await;
    let (_id, port, _rx) = common::start(&state, relay_handlers(json!([])), None).await;

    let mut held = Vec::with_capacity(MAX_CONNECTIONS);
    for i in 0..MAX_CONNECTIONS {
        let (status, stream) = raw_upgrade(port).await;
        assert_eq!(
            status, 101,
            "peer {i} of {MAX_CONNECTIONS} was not admitted"
        );
        held.push(stream);
    }
    let (status, head, _refused) = raw_upgrade_head(port).await;
    assert_eq!(status, 503, "the peer over the cap is refused in HTTP");
    assert!(head.contains("Retry-After: 30"), "{head}");

    drop(held.pop());
    let mut admitted = false;
    for _ in 0..100 {
        let (status, stream) = raw_upgrade(port).await;
        if status == 101 {
            held.push(stream);
            admitted = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(admitted, "closing one connection never freed its slot");
    let (status, _) = raw_upgrade(port).await;
    assert_eq!(status, 503, "exactly one slot came back");
}

#[tokio::test]
async fn a_peer_that_sends_no_request_head_is_answered_408() {
    let state = common::new_state().await;
    let (_id, port, mut rx) = common::start(
        &state,
        Vec::new(),
        Some(json!({"handshake_timeout_secs": 1})),
    )
    .await;
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: x\r\n")
        .await
        .unwrap();
    let mut reply = String::new();
    tokio::time::timeout(Duration::from_secs(10), stream.read_to_string(&mut reply))
        .await
        .expect("the handshake deadline did not fire")
        .unwrap();
    assert!(reply.starts_with("HTTP/1.1 408"), "{reply}");
    common::wait_for_log(&mut rx, "decision=fail_closed_handshake_timeout", 5).await;
}

#[tokio::test]
async fn a_peer_that_never_answers_a_ping_is_closed_1001_and_one_that_does_is_not() {
    let state = common::new_state().await;
    let (_id, port, mut rx) = common::start(
        &state,
        relay_handlers(json!([])),
        Some(json!({"idle_timeout_secs": 2})),
    )
    .await;

    // A live client: tungstenite answers the relay's Ping by itself while it is read.
    let mut live = Peer::connect(port).await;
    // A dead one: upgraded, then never reads or writes again.
    let (status, mut dead) = raw_upgrade(port).await;
    assert_eq!(status, 101);

    // Both are watched at once: the live one has to be read for its Pongs to go out.
    let dead_side = async {
        let mut bytes = Vec::new();
        let mut buf = [0u8; 256];
        loop {
            match tokio::time::timeout(Duration::from_secs(10), dead.read(&mut buf)).await {
                Ok(Ok(0)) | Ok(Err(_)) => break,
                Ok(Ok(n)) => bytes.extend_from_slice(&buf[..n]),
                Err(_) => panic!("the silent peer was never closed; got {bytes:02x?}"),
            }
        }
        bytes
    };
    let live_side = live.assert_silent(5, "an idle but live connection");
    let (bytes, ()) = tokio::join!(dead_side, live_side);
    assert_eq!(
        bytes[0], 0x89,
        "a Ping at half the bound first: {bytes:02x?}"
    );
    let close_at = bytes
        .iter()
        .position(|b| *b == 0x88)
        .unwrap_or_else(|| panic!("no close frame: {bytes:02x?}"));
    assert_eq!(
        u16::from_be_bytes([bytes[close_at + 2], bytes[close_at + 3]]),
        1001,
        "closed as going away"
    );
    common::wait_for_log(&mut rx, "decision=fail_closed_idle_timeout", 5).await;

    // The live one has been there longer than the bound, answering pings, and is still served.
    live.send_json(json!(["REQ", "still-here", {}])).await;
    assert_eq!(live.json(10).await, json!(["EOSE", "still-here"]));
}

#[tokio::test]
async fn max_message_bytes_is_read_and_one_more_is_closed_1009() {
    let state = common::new_state().await;
    let (_id, port, mut rx) = common::start(&state, relay_handlers(json!([])), None).await;
    let mut peer = Peer::connect(port).await;

    // Exactly the bound: a JSON string of that size, which is not a message, so a NOTICE.
    let at_bound = format!("\"{}\"", "x".repeat(MAX_MESSAGE_BYTES - 2));
    assert_eq!(at_bound.len(), MAX_MESSAGE_BYTES);
    peer.ws.send(Message::Text(at_bound)).await.unwrap();
    assert_eq!(peer.json(10).await[0], "NOTICE");

    let over = format!("\"{}\"", "x".repeat(MAX_MESSAGE_BYTES - 1));
    let _ = peer.ws.send(Message::Text(over)).await;
    match peer.read(10).await {
        Read::Closed(Some((code, _))) => assert_eq!(code, 1009),
        other => panic!("expected close 1009, got {other:?}"),
    }
    common::wait_for_log(&mut rx, "decision=fail_closed_message_too_large", 5).await;
}

#[tokio::test]
async fn subscriptions_filters_and_ids_are_bounded() {
    let state = common::new_state().await;
    let (_id, port, _rx) = common::start(&state, relay_handlers(json!([])), None).await;
    let mut peer = Peer::connect(port).await;

    for i in 0..wire::MAX_SUBSCRIPTIONS {
        peer.send_json(json!(["REQ", format!("s{i}"), {}])).await;
        assert_eq!(peer.json(10).await, json!(["EOSE", format!("s{i}")]));
    }
    peer.send_json(json!(["REQ", "one-too-many", {}])).await;
    let closed = peer.json(10).await;
    assert_eq!(closed[0], "CLOSED");
    assert!(
        closed[2].as_str().unwrap().starts_with("rate-limited:"),
        "{closed}"
    );
    // Re-using an open id overwrites it rather than counting twice.
    peer.send_json(json!(["REQ", "s0", {"kinds": [1]}])).await;
    assert_eq!(peer.json(10).await, json!(["EOSE", "s0"]));
    // CLOSE gives the slot back.
    peer.send_json(json!(["CLOSE", "s1"])).await;
    peer.send_json(json!(["REQ", "one-too-many", {}])).await;
    assert_eq!(peer.json(10).await, json!(["EOSE", "one-too-many"]));

    // Free room first, so a refusal below can only be the bound under test.
    for i in 2..6 {
        peer.send_json(json!(["CLOSE", format!("s{i}")])).await;
    }

    let filters: Vec<_> = (0..=wire::MAX_FILTERS).map(|_| json!({})).collect();
    let mut req = vec![json!("REQ"), json!("wide")];
    req.extend(filters);
    peer.send_json(json!(req)).await;
    assert_eq!(
        peer.json(10).await,
        json!([
            "CLOSED",
            "wide",
            format!(
                "invalid: more than {} filters in one REQ",
                wire::MAX_FILTERS
            )
        ])
    );
    let filters: Vec<_> = (0..wire::MAX_FILTERS).map(|_| json!({})).collect();
    let mut req = vec![json!("REQ"), json!("wide")];
    req.extend(filters);
    peer.send_json(json!(req)).await;
    assert_eq!(peer.json(10).await, json!(["EOSE", "wide"]));

    let long = "s".repeat(wire::MAX_SUBSCRIPTION_ID_CHARS + 1);
    peer.send_json(json!(["REQ", long, {}])).await;
    assert_eq!(
        peer.json(10).await,
        json!([
            "CLOSED",
            long,
            format!(
                "invalid: subscription id longer than {} characters",
                wire::MAX_SUBSCRIPTION_ID_CHARS
            )
        ])
    );
    let at_limit = "s".repeat(wire::MAX_SUBSCRIPTION_ID_CHARS);
    peer.send_json(json!(["REQ", at_limit, {}])).await;
    assert_eq!(peer.json(10).await, json!(["EOSE", at_limit]));
}

#[tokio::test]
async fn a_depth_bomb_is_a_notice_and_the_connection_lives_on() {
    let state = common::new_state().await;
    let (_id, port, _rx) = common::start(&state, relay_handlers(json!([])), None).await;
    let mut peer = Peer::connect(port).await;
    // ~60 000 levels, well inside the message bound: serde_json refuses at 128.
    let depth = (MAX_MESSAGE_BYTES - 32) / 2;
    peer.send(&format!(
        r#"["REQ","s",{}{}]"#,
        "[".repeat(depth),
        "]".repeat(depth)
    ))
    .await;
    assert_eq!(
        peer.json(10).await,
        json!(["NOTICE", "invalid: message is nested too deeply"])
    );
    peer.send_json(json!(["REQ", "after", {}])).await;
    assert_eq!(peer.json(10).await, json!(["EOSE", "after"]));
}

#[tokio::test]
async fn past_the_queue_an_event_is_refused_rate_limited() {
    let state = common::new_state().await;
    let (_id, port, _rx) = common::start(
        &state,
        vec![json!({
            "event_pattern": "nostr_event",
            "handler": {"type": "manual", "timeout_secs": 600}
        })],
        None,
    )
    .await;
    let mut peer = Peer::connect(port).await;

    // The first is taken off the queue and parked for a human.
    peer.send(&event_frame(&note("parked", vec![], 1))).await;
    for _ in 0..200 {
        if !state.list_intercepts().await.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert_eq!(
        state.list_intercepts().await.len(),
        1,
        "the first event parked"
    );

    // The queue holds MAX_QUEUED_MESSAGES more; the one after is refused.
    let mut last = None;
    for i in 0..=MAX_QUEUED_MESSAGES {
        let event = note(&format!("queued {i}"), vec![], 2 + i as u64);
        peer.send(&event_frame(&event)).await;
        last = Some(event);
    }
    let refused = last.unwrap();
    assert_eq!(
        peer.json(10).await,
        json!([
            "OK",
            refused.id,
            false,
            "rate-limited: too many messages waiting on this connection"
        ])
    );
    peer.assert_silent(1, "the queued events wait for the parked one")
        .await;
}

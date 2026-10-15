//! Every bound the Zabbix trapper declares, driven from the wire on a real, running server.
//!
//! 1. **Request size** (`max_inbound_bytes`, 1 MiB) — a request of exactly 1 MiB is answered;
//!    a header *declaring* one byte more is refused `message is too large` at once, with no
//!    body sent — the length is judged from the declaration, before anything is allocated.
//!    The same for a large-header declaration of 2^40 bytes.
//! 2. **Compressed / unknown flags / not ZBXD** — refused without reading further.
//! 3. **First byte** — a peer that says nothing is closed at `first_byte_timeout_secs`.
//! 4. **Idle** — a peer that stalls mid-request is closed at `idle_timeout_secs`, a different
//!    number, so a server that applied one to both reads fails.
//! 5. **Parked for a human** — a request waiting on a `manual` rule is closed by neither.
//! 6. **Connection cap** — the peer past `MAX_CONNECTIONS` is closed with no bytes, and the
//!    slot comes back.
//!
//! How each was shown to fail without its bound is in `tests/server/zabbix/CLAUDE.md`.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features zabbix --test server -- zabbix::connection_bounds --test-threads=100


use super::common::{self, exchange, response, sender_data};
use netget::server::zabbix::wire;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const FIRST_BYTE_TIMEOUT: Duration = Duration::from_secs(4);
const IDLE_TIMEOUT: Duration = Duration::from_secs(14);

/// `src/server/zabbix/mod.rs::MAX_CONNECTIONS`, duplicated so a change to it makes someone
/// re-read this test.
const MAX_CONNECTIONS: usize = 256;

fn accept_all() -> serde_json::Value {
    serde_json::json!({
        "event_pattern": "zabbix_sender_data",
        "handler": {"type": "static", "actions": [
            {"type": "send_zabbix_result", "processed": 1, "failed": 0}
        ]}
    })
}

fn bounds() -> Option<serde_json::Value> {
    Some(serde_json::json!({
        "first_byte_timeout_secs": FIRST_BYTE_TIMEOUT.as_secs(),
        "idle_timeout_secs": IDLE_TIMEOUT.as_secs(),
    }))
}

/// A one-item sender-data body padded with a long value to exactly `len` bytes.
fn body_of_len(len: usize) -> Vec<u8> {
    let base = sender_data(&[("h", "k", "")]);
    let pad = len - base.len();
    let body = sender_data(&[("h", "k", &"v".repeat(pad))]);
    assert_eq!(body.len(), len);
    body
}

#[tokio::test]
async fn a_request_of_exactly_the_limit_is_answered() {
    let state = common::new_state().await;
    let (_id, port, _rx) = common::start(&state, vec![accept_all()], None).await;
    let packet = wire::encode(&body_of_len(wire::MAX_DATA_BYTES));
    let (_, _, body) = response(&exchange(port, &packet, 30).await);
    assert!(
        body["info"]
            .as_str()
            .unwrap()
            .starts_with("processed: 1; failed: 0; total: 1;"),
        "{body}"
    );
}

#[tokio::test]
async fn a_declared_length_past_the_limit_is_refused_before_any_body() {
    let state = common::new_state().await;
    let (_id, port, mut rx) = common::start(&state, vec![accept_all()], None).await;

    let mut standard = b"ZBXD\x01".to_vec();
    standard.extend_from_slice(&((wire::MAX_DATA_BYTES as u32) + 1).to_le_bytes());
    standard.extend_from_slice(&0u32.to_le_bytes());
    let mut large = b"ZBXD\x05".to_vec();
    large.extend_from_slice(&(1u64 << 40).to_le_bytes());
    large.extend_from_slice(&0u64.to_le_bytes());

    for header in [standard, large] {
        // The header alone: a server that waited for the body before judging its size would
        // never answer, and one that allocated for it would try to reserve a terabyte.
        let (_, _, body) = response(&exchange(port, &header, 10).await);
        assert_eq!(
            body,
            serde_json::json!({"response": "failed", "info": "message is too large"})
        );
    }
    let log = common::wait_for_log(&mut rx, "decision=fail_closed_too_large", 10).await;
    assert!(
        !log.iter().any(|l| l.contains("decision=model_")),
        "an oversize request reached a handler: {log:#?}"
    );
}

/// The refusal arrives even when the body the sender wrote anyway is still unread at close.
/// Closing over unread input makes the kernel send RST, which can destroy the response before
/// the sender reads it; the server drains in-flight input first (`linger`).
#[tokio::test]
async fn the_too_large_refusal_survives_a_body_the_server_never_read() {
    let state = common::new_state().await;
    let (_id, port, _rx) = common::start(&state, vec![accept_all()], None).await;
    let mut packet = b"ZBXD\x01".to_vec();
    packet.extend_from_slice(&((wire::MAX_DATA_BYTES as u32) + 1).to_le_bytes());
    packet.extend_from_slice(&0u32.to_le_bytes());
    packet.extend(std::iter::repeat_n(b'x', 48 * 1024));
    let (_, _, body) = response(&exchange(port, &packet, 10).await);
    assert_eq!(body["info"], "message is too large");
}

#[tokio::test]
async fn compressed_unknown_flags_and_non_zbxd_are_refused() {
    let state = common::new_state().await;
    let (_id, port, _rx) = common::start(&state, vec![accept_all()], None).await;

    let mut compressed = b"ZBXD\x03".to_vec();
    compressed.extend_from_slice(&10u32.to_le_bytes());
    compressed.extend_from_slice(&1000u32.to_le_bytes());
    let (_, _, body) = response(&exchange(port, &compressed, 10).await);
    assert_eq!(body["info"], "compressed data is not supported");

    let mut odd = b"ZBXD\x09".to_vec();
    odd.extend_from_slice(&[0u8; 8]);
    let (_, _, body) = response(&exchange(port, &odd, 10).await);
    assert_eq!(body["info"], "unsupported protocol flags");

    let plain = exchange(port, b"{\"request\":\"sender data\",\"data\":[]}", 10).await;
    assert!(
        plain.is_empty(),
        "a peer that does not speak ZBXD gets nothing it would misread: {plain:?}"
    );
}

#[tokio::test]
async fn a_peer_that_says_nothing_is_closed_at_the_first_byte_bound() {
    let state = common::new_state().await;
    let (_id, port, _rx) = common::start(&state, vec![accept_all()], bounds()).await;
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
async fn a_peer_that_stalls_mid_request_is_closed_at_the_idle_bound() {
    let state = common::new_state().await;
    let (_id, port, _rx) = common::start(&state, vec![accept_all()], bounds()).await;
    let mut peer = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    // A header promising 100 bytes, and ten of them.
    let mut partial = b"ZBXD\x01".to_vec();
    partial.extend_from_slice(&100u32.to_le_bytes());
    partial.extend_from_slice(&0u32.to_le_bytes());
    partial.extend_from_slice(b"{\"request\"");
    peer.write_all(&partial).await.unwrap();

    let started = std::time::Instant::now();
    let mut sink = Vec::new();
    tokio::time::timeout(
        IDLE_TIMEOUT + Duration::from_secs(40),
        peer.read_to_end(&mut sink),
    )
    .await
    .expect("a stalled request was never closed: idle_timeout_secs is not applied")
    .expect("read to EOF");
    assert!(
        sink.is_empty(),
        "an incomplete request was answered: {sink:?}"
    );
    assert!(
        started.elapsed() >= FIRST_BYTE_TIMEOUT + Duration::from_secs(2),
        "closed after {}ms — the first-byte bound, not the idle bound",
        started.elapsed().as_millis()
    );
}

#[tokio::test]
async fn a_request_parked_for_a_human_is_never_closed_by_either_deadline() {
    let state = common::new_state().await;
    let manual = serde_json::json!({
        "event_pattern": "*",
        "handler": {"type": "manual", "timeout_secs": 300}
    });
    let (_id, port, _rx) = common::start(&state, vec![manual], bounds()).await;
    let mut peer = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    peer.write_all(&wire::encode(&sender_data(&[("h", "k", "1")])))
        .await
        .unwrap();

    tokio::time::sleep(IDLE_TIMEOUT + Duration::from_secs(6)).await;
    let mut buf = [0u8; 256];
    match tokio::time::timeout(Duration::from_secs(3), peer.read(&mut buf)).await {
        Err(_) => {}
        Ok(Ok(0)) => panic!("closed while its request was parked for a human"),
        Ok(Ok(n)) => panic!("answered a request nobody decided: {:?}", &buf[..n]),
        Ok(Err(e)) => panic!("reset while parked: {e}"),
    }
}

#[tokio::test]
async fn the_connection_past_the_cap_is_closed_and_the_slot_comes_back() {
    let state = common::new_state().await;
    // Held connections send nothing; keep them past the default 30 s first-byte bound.
    let hold = Some(serde_json::json!({"first_byte_timeout_secs": 300}));
    let (server_id, port, _rx) = common::start(&state, vec![accept_all()], hold).await;

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
        "no bytes: a response to an unsent request would be misread"
    );

    drop(held.pop());
    let packet = wire::encode(&sender_data(&[("h", "k", "1")]));
    let mut admitted = false;
    for _ in 0..100 {
        let reply = exchange(port, &packet, 10).await;
        if !reply.is_empty() {
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

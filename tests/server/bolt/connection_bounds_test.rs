//! Every bound the Bolt server declares, driven from the wire on a real, running server.
//!
//! 1. **Message size** — `max_inbound_bytes` is 1 MiB summed over a message's chunks. A RUN of
//!    exactly 1 MiB is answered; one byte more is a `Neo.ClientError.Request.Invalid` FAILURE
//!    and a close, before any handler runs.
//! 2. **Depth** — a RUN whose parameters nest past `MAX_PACKSTREAM_DEPTH` is refused the same
//!    way, and the process survives it.
//! 3. **Handshake** — a peer that connects and sends nothing, or half a handshake, is closed at
//!    `first_byte_timeout_secs`.
//! 4. **Idle** — a logged-in peer that goes quiet is closed at `idle_timeout_secs`, a *different*
//!    number, so a server that applied one parameter to both reads fails.
//! 5. **Parked for a human** — a RUN waiting on a `manual` rule is closed by neither.
//! 6. **Connection cap** — the peer past `MAX_CONNECTIONS` is closed without a handshake answer,
//!    and the slot comes back when a connection ends.
//!
//! Each was verified by removing its bound, recorded in the commit that added it: without the
//! size check in `Dechunker::next_message` the 1 MiB + 1 RUN reaches the handler and is
//! answered; without the depth check the test binary aborts with a stack overflow; replacing
//! either `tokio::time::timeout` around the handshake or the message read with a bare read makes
//! tests 3 and 4 hang past their windows; replacing `accept_bounded` with `listener.accept()`
//! answers the over-cap peer's handshake.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features bolt --test server -- bolt::connection_bounds --test-threads=100

use super::common::{self, *};
use netget::server::bolt::packstream::{Value, MAX_MESSAGE_BYTES, MAX_PACKSTREAM_DEPTH};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const FIRST_BYTE_TIMEOUT: Duration = Duration::from_secs(5);
const IDLE_TIMEOUT: Duration = Duration::from_secs(20);

/// `src/server/bolt/mod.rs::MAX_CONNECTIONS`, duplicated so a change to it makes someone
/// re-read this test.
const MAX_CONNECTIONS: usize = 256;

fn static_answer() -> serde_json::Value {
    serde_json::json!({
        "event_pattern": "bolt_query",
        "handler": {"type": "static", "actions": [{
            "type": "send_bolt_records", "fields": ["ok"], "records": [[true]]
        }]}
    })
}

fn bounds() -> Option<serde_json::Value> {
    Some(serde_json::json!({
        "first_byte_timeout_secs": FIRST_BYTE_TIMEOUT.as_secs(),
        "idle_timeout_secs": IDLE_TIMEOUT.as_secs(),
    }))
}

/// A RUN whose encoded message is exactly `size` bytes: B3 10, a STRING_32 header (5 bytes), the
/// query, and two empty maps.
fn run_of_size(size: usize) -> Value {
    run(&"x".repeat(size - 9))
}

#[tokio::test]
async fn a_message_of_exactly_1_mib_is_answered_and_one_byte_more_is_refused() {
    let state = common::new_state().await;
    let (_id, port, mut rx) =
        common::start(&state, vec![common::accept_logins(), static_answer()], None).await;

    let mut peer = Peer::connect_and_login(port).await;
    let at_limit = run_of_size(MAX_MESSAGE_BYTES);
    assert_eq!(
        netget::server::bolt::packstream::to_bytes(&at_limit).len(),
        MAX_MESSAGE_BYTES
    );
    peer.send_all(&[at_limit, pull(-1)]).await;
    assert_success(&peer.recv().await);
    assert_eq!(record_values(&peer.recv().await), [Value::Bool(true)]);

    let mut peer = Peer::connect_and_login(port).await;
    common::drain(&mut rx);
    // The server refuses on the chunk header that crosses the limit, possibly while this write
    // is still in flight, so the write's own outcome is not the assertion.
    let mut oversize =
        netget::server::bolt::packstream::message_bytes(&run_of_size(MAX_MESSAGE_BYTES + 1));
    oversize.extend(netget::server::bolt::packstream::message_bytes(&pull(-1)));
    let _ = peer.stream.write_all(&oversize).await;
    let refused = peer.recv().await;
    assert_failure(&refused, "Neo.ClientError.Request.Invalid");
    peer.expect_eof(10).await;
    let log = common::wait_for_log(&mut rx, "decision=fail_closed_message_too_large", 10).await;
    assert!(
        !log.iter().any(|l| l.contains("decision=model_")),
        "the oversize message reached the handler: {log:#?}"
    );
}

#[tokio::test]
async fn a_message_that_never_ends_is_refused_once_it_passes_the_limit() {
    let state = common::new_state().await;
    let (_id, port, _rx) =
        common::start(&state, vec![common::accept_logins(), static_answer()], None).await;
    let mut peer = Peer::connect_and_login(port).await;
    // Full chunks and never the terminating zero chunk: the server must not buffer past 1 MiB.
    let chunk: Vec<u8> = [0xFFu8, 0xFF]
        .into_iter()
        .chain(std::iter::repeat_n(0u8, 65535))
        .collect();
    // Seventeen: the sixteenth fills the limit to within 16 bytes and the seventeenth's header
    // crosses it. What is left unread is one chunk, which the server's close linger absorbs, so
    // the refusal is not destroyed by a reset.
    let writer = async {
        for _ in 0..17 {
            if peer.stream.write_all(&chunk).await.is_err() {
                break;
            }
        }
    };
    let _ = tokio::time::timeout(Duration::from_secs(20), writer).await;
    assert_failure(&peer.recv().await, "Neo.ClientError.Request.Invalid");
}

#[tokio::test]
async fn a_depth_bomb_in_the_parameters_is_refused_and_the_server_survives() {
    let state = common::new_state().await;
    let (_id, port, mut rx) =
        common::start(&state, vec![common::accept_logins(), static_answer()], None).await;
    let mut peer = Peer::connect_and_login(port).await;
    // RUN "q" {"p": [[[[...]]]]} {} — 100,000 one-element lists, 100 KB.
    let mut bytes = vec![0xB3, 0x10, 0x81, b'q', 0xA1, 0x81, b'p'];
    bytes.extend(std::iter::repeat_n(0x91u8, 100_000));
    bytes.push(0xC0);
    bytes.push(0xA0);
    peer.send_raw(&netget::server::bolt::packstream::chunk(&bytes))
        .await;
    assert_failure(&peer.recv().await, "Neo.ClientError.Request.Invalid");
    peer.expect_eof(10).await;
    common::wait_for_log(&mut rx, "decision=fail_closed_too_deep", 10).await;

    // Parameters exactly at the limit (message struct = 1, parameter map = 2, lists below)
    // are accepted.
    let mut peer = Peer::connect_and_login(port).await;
    let mut nested = Value::Int(1);
    for _ in 0..(MAX_PACKSTREAM_DEPTH - 2) {
        nested = Value::List(vec![nested]);
    }
    peer.send_all(&[
        run_with("q", Value::map([("p", nested)]), Value::Map(vec![])),
        pull(-1),
    ])
    .await;
    assert_success(&peer.recv().await);
}

async fn assert_closed_within(stream: &mut TcpStream, window: Duration) -> Duration {
    let started = std::time::Instant::now();
    let mut sink = Vec::new();
    tokio::time::timeout(window, stream.read_to_end(&mut sink))
        .await
        .unwrap_or_else(|_| {
            panic!(
                "a silent peer still held the socket after {}s",
                started.elapsed().as_secs()
            )
        })
        .expect("read to EOF");
    started.elapsed()
}

#[tokio::test]
async fn a_peer_that_never_sends_the_handshake_is_closed_at_the_first_byte_bound() {
    let state = common::new_state().await;
    let (_id, port, _rx) = common::start(&state, vec![common::accept_logins()], bounds()).await;

    let mut silent = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let elapsed =
        assert_closed_within(&mut silent, FIRST_BYTE_TIMEOUT + Duration::from_secs(40)).await;
    assert!(
        elapsed >= FIRST_BYTE_TIMEOUT / 2,
        "closed after {}ms, which is not the configured bound",
        elapsed.as_millis()
    );

    // Half a handshake does not reset the clock: the deadline covers all 20 bytes.
    let mut half = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    half.write_all(&[0x60, 0x60, 0xB0, 0x17, 0x00])
        .await
        .unwrap();
    assert_closed_within(&mut half, FIRST_BYTE_TIMEOUT + Duration::from_secs(40)).await;
}

#[tokio::test]
async fn a_logged_in_peer_is_held_for_the_idle_bound_instead() {
    let state = common::new_state().await;
    let (_id, port, _rx) = common::start(
        &state,
        vec![common::accept_logins(), static_answer()],
        bounds(),
    )
    .await;
    let mut peer = Peer::connect_and_login(port).await;
    let elapsed =
        assert_closed_within(&mut peer.stream, IDLE_TIMEOUT + Duration::from_secs(40)).await;
    assert!(
        elapsed >= FIRST_BYTE_TIMEOUT + Duration::from_secs(2),
        "closed after {}ms — the handshake bound, not the idle bound",
        elapsed.as_millis()
    );
}

#[tokio::test]
async fn a_query_parked_for_a_human_is_never_closed_by_either_deadline() {
    let state = common::new_state().await;
    let manual = serde_json::json!({
        "event_pattern": "bolt_query",
        "handler": {"type": "manual", "timeout_secs": 300}
    });
    let (_id, port, _rx) =
        common::start(&state, vec![common::accept_logins(), manual], bounds()).await;
    let mut peer = Peer::connect_and_login(port).await;
    peer.send_all(&[run("MATCH (n) RETURN n"), pull(-1)]).await;

    tokio::time::sleep(IDLE_TIMEOUT + Duration::from_secs(10)).await;
    let mut buf = [0u8; 256];
    match tokio::time::timeout(Duration::from_secs(3), peer.stream.read(&mut buf)).await {
        Err(_) => {}
        Ok(Ok(0)) => panic!("closed while its RUN was parked for a human"),
        Ok(Ok(n)) => panic!("answered a query nobody decided: {:02X?}", &buf[..n]),
        Ok(Err(e)) => panic!("reset while parked: {e}"),
    }
}

#[tokio::test]
async fn the_connection_past_the_cap_is_closed_unanswered_and_the_slot_comes_back() {
    let state = common::new_state().await;
    // A handshake bound longer than this test, so held connections are not timed out from
    // under it and a slot freed by a deadline cannot pass for the cap.
    let (server_id, port, _rx) = common::start(
        &state,
        vec![common::accept_logins()],
        Some(serde_json::json!({"first_byte_timeout_secs": 300})),
    )
    .await;

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

    let mut over = Peer::connect(port).await;
    let mut hs = vec![0x60, 0x60, 0xB0, 0x17];
    hs.extend_from_slice(&CYPHER_SHELL_PROPOSALS);
    let _ = over.stream.write_all(&hs).await;
    let mut answer = Vec::new();
    let _ = tokio::time::timeout(
        Duration::from_secs(20),
        over.stream.read_to_end(&mut answer),
    )
    .await
    .expect("the over-cap connection was neither answered nor closed");
    assert!(
        answer.is_empty(),
        "the over-cap connection got a handshake answer: {answer:02X?}"
    );

    drop(held.pop());
    let mut admitted = false;
    for _ in 0..100 {
        let mut candidate = Peer::connect(port).await;
        let mut hs = vec![0x60, 0x60, 0xB0, 0x17];
        hs.extend_from_slice(&CYPHER_SHELL_PROPOSALS);
        let _ = candidate.stream.write_all(&hs).await;
        let mut answer = [0u8; 4];
        if let Ok(Ok(_)) = tokio::time::timeout(
            Duration::from_secs(5),
            candidate.stream.read_exact(&mut answer),
        )
        .await
        {
            assert_eq!(answer, [0, 0, 8, 5]);
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

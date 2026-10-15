//! NATS' inbound bound, driven from the wire: the per-instance `max_payload` and the
//! `MAX_PAYLOAD_CEILING` that no configuration can exceed.
//!
//! NATS has one peer-chosen length that is buffered: the `<#bytes>` a `PUB` (or the total an
//! `HPUB`) declares. It is checked against `max_payload` on the **declared** number, before any
//! payload is read, and `max_payload` itself is capped at `MAX_PAYLOAD_CEILING` — the declared
//! `max_inbound_bytes`. So there are two numbers and each is tested:
//!
//! 1. At the default `max_payload` (1 MiB), a `PUB` of exactly 1 MiB reaches the model; one of
//!    1 MiB + 1 is answered `-ERR 'Maximum Payload Violation'` and closed with zero model calls;
//!    and a fresh connection is still served.
//! 2. `max_payload` above `MAX_PAYLOAD_CEILING` refuses to start, and at exactly the ceiling a
//!    `PUB` declaring ceiling + 1 is refused on its control line alone — no 64 MiB is sent,
//!    because the check is on the declared size, which is the property being tested.
//!
//! **Verified by removal.** With the `total_len > max_payload` check in `parse_one_frame`
//! removed, test 1's over-bound `PUB` is buffered and handed to the model (the refusal
//! assertion fails); with the startup ceiling removed, test 2's server starts.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features nats --test server -- nats::inbound_limit --test-threads=100

use std::time::Duration;

use netget::server::nats::actions::{DEFAULT_MAX_PAYLOAD, MAX_PAYLOAD_CEILING};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::helpers::inbound_limit::InboundLimitServer;

/// Read until `needle` has arrived, EOF, or the deadline. Returns what was read and whether the
/// server closed.
async fn read_until(stream: &mut TcpStream, needle: &[u8], secs: u64) -> (Vec<u8>, bool) {
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
    loop {
        match tokio::time::timeout_at(deadline, stream.read(&mut buf)).await {
            Ok(Ok(0)) | Ok(Err(_)) => return (out, true),
            Ok(Ok(n)) => {
                out.extend_from_slice(&buf[..n]);
                if out.windows(needle.len()).any(|w| w == needle) {
                    return (out, false);
                }
            }
            Err(_) => return (out, false),
        }
    }
}

/// Connect, take the `INFO` greeting, and send a `CONNECT` so the session is established the
/// way a real client establishes it.
async fn session(server: &InboundLimitServer) -> TcpStream {
    let mut s = server.connect().await;
    let (info, _) = read_until(&mut s, b"\r\n", 10).await;
    assert!(
        info.starts_with(b"INFO "),
        "expected the INFO greeting, got {:?}",
        String::from_utf8_lossy(&info)
    );
    s.write_all(b"CONNECT {\"verbose\":false,\"pedantic\":false}\r\n")
        .await
        .unwrap();
    s
}

fn pub_frame(len: usize) -> Vec<u8> {
    let mut out = format!("PUB bound.probe {len}\r\n").into_bytes();
    out.resize(out.len() + len, b'p');
    out.extend_from_slice(b"\r\n");
    out
}

#[tokio::test]
async fn a_pub_over_max_payload_is_refused_before_the_model_and_the_server_keeps_serving() {
    let server = InboundLimitServer::start("nats", None).await;
    let bound = DEFAULT_MAX_PAYLOAD as usize;

    // 1. Exactly the bound: reaches the model.
    let mut s = session(&server).await;
    let before = server.settled_calls().await;
    s.write_all(&pub_frame(bound)).await.unwrap();
    let after = server.wait_for_calls_above(before, 30).await;
    assert!(
        after > before,
        "a PUB of exactly max_payload ({bound}) bytes never reached the model — the bound \
         refuses a payload it advertises as acceptable"
    );
    drop(s);

    // 2. One past the bound: -ERR in NATS' own words, closed, no model call. Only the control
    //    line is sent: the refusal must come from the declared size, before any payload.
    let mut s = session(&server).await;
    let before = server.settled_calls().await;
    s.write_all(format!("PUB bound.probe {}\r\n", bound + 1).as_bytes())
        .await
        .unwrap();
    let (reply, _) = read_until(&mut s, b"Maximum Payload Violation'\r\n", 30).await;
    let (_, closed) = read_until(&mut s, b"\x00never", 10).await;
    let after = server.settled_calls().await;
    let reply = String::from_utf8_lossy(&reply);
    assert!(
        reply.contains("-ERR 'Maximum Payload Violation'\r\n"),
        "a PUB declaring max_payload + 1 must be refused with -ERR 'Maximum Payload \
         Violation'; got {reply:?}"
    );
    assert!(
        closed,
        "after -ERR 'Maximum Payload Violation' the server must close"
    );
    assert_eq!(
        after - before,
        0,
        "a PUB declaring {} bytes against max_payload {bound} cost {} model call(s)",
        bound + 1,
        after - before
    );

    // 3. A fresh connection is still served.
    let mut s = session(&server).await;
    let before = server.settled_calls().await;
    s.write_all(&pub_frame(5)).await.unwrap();
    let after = server.wait_for_calls_above(before, 30).await;
    assert!(
        after > before,
        "after refusing an over-bound PUB, a fresh connection's PUB never reached the model"
    );

    server.stop().await;
}

#[tokio::test]
async fn max_payload_cannot_exceed_the_declared_ceiling() {
    // Above the ceiling: the server refuses to start rather than silently accepting a bound
    // larger than the one it declares.
    let refused = InboundLimitServer::try_start(
        "nats",
        Some(serde_json::json!({ "max_payload": MAX_PAYLOAD_CEILING + 1 })),
    )
    .await;
    assert!(
        refused.is_err(),
        "a NATS server started with max_payload = MAX_PAYLOAD_CEILING + 1 ({}) — the declared \
         max_inbound_bytes would then be a number the server does not enforce",
        MAX_PAYLOAD_CEILING + 1
    );

    // At the ceiling: starts, advertises it, and refuses ceiling + 1 on the control line.
    let server = InboundLimitServer::start(
        "nats",
        Some(serde_json::json!({ "max_payload": MAX_PAYLOAD_CEILING })),
    )
    .await;
    let mut s = server.connect().await;
    let (info, _) = read_until(&mut s, b"\r\n", 10).await;
    assert!(
        String::from_utf8_lossy(&info).contains(&format!("\"max_payload\":{MAX_PAYLOAD_CEILING}")),
        "INFO must advertise the configured max_payload; got {:?}",
        String::from_utf8_lossy(&info)
    );
    let before = server.settled_calls().await;
    s.write_all(format!("PUB bound.probe {}\r\n", MAX_PAYLOAD_CEILING + 1).as_bytes())
        .await
        .unwrap();
    let (reply, _) = read_until(&mut s, b"Maximum Payload Violation'\r\n", 30).await;
    let after = server.settled_calls().await;
    assert!(
        String::from_utf8_lossy(&reply).contains("-ERR 'Maximum Payload Violation'"),
        "a PUB declaring MAX_PAYLOAD_CEILING + 1 must be refused on its control line; got {:?}",
        String::from_utf8_lossy(&reply)
    );
    assert_eq!(after - before, 0, "the refused PUB reached the model");

    server.stop().await;
}

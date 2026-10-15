//! Every bound the Gemini server declares, driven from the wire on a real, running server.
//!
//! 1. **Request size** — `max_inbound_bytes` is the specification's 1024-byte URL plus CRLF. A
//!    1024-byte URL is answered; 1025 gets `59 Request too long` before any handler runs, and
//!    so does a flood with no newline.
//! 2. **Handshake** — a peer that connects and never sends a ClientHello is closed at
//!    `handshake_timeout_secs`.
//! 3. **Request line** — a peer that completes the handshake and sends nothing is closed at
//!    `first_byte_timeout_secs`, a different number, so a server applying one to both fails.
//! 4. **Parked for a human** — a request waiting on a `manual` rule is closed by neither.
//! 5. **Connection cap** — the peer past `MAX_CONNECTIONS` is closed before any handshake (a
//!    plaintext response would be a malformed TLS record, not a refusal), and the slot returns.
//!
//! How each was proved to fail without its bound is in the commit that added it.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features gemini --test server -- gemini::connection_bounds --test-threads=100

use super::common::{self, raw_request, split_response, tls_connect};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const FIRST_BYTE_TIMEOUT: Duration = Duration::from_secs(15);

/// `src/server/gemini/mod.rs::MAX_CONNECTIONS`, duplicated on purpose.
const MAX_CONNECTIONS: usize = 256;

fn ok_handler() -> serde_json::Value {
    serde_json::json!({
        "event_pattern": "gemini_request",
        "handler": {"type": "static", "actions": [{
            "type": "send_gemini_response", "status": 20, "meta": "text/plain", "body": "ok"
        }]}
    })
}

fn bounds() -> Option<serde_json::Value> {
    Some(serde_json::json!({
        "handshake_timeout_secs": HANDSHAKE_TIMEOUT.as_secs(),
        "first_byte_timeout_secs": FIRST_BYTE_TIMEOUT.as_secs(),
    }))
}

/// A `gemini://h/aaa…` URL of exactly `len` bytes.
fn url_of_len(len: usize) -> String {
    let prefix = "gemini://h/";
    format!("{prefix}{}", "a".repeat(len - prefix.len()))
}

#[tokio::test]
async fn a_1024_byte_url_is_answered_and_1025_is_refused_before_any_handler() {
    let state = common::new_state().await;
    let (_id, port, mut rx) = common::start(&state, vec![ok_handler()], None).await;

    let response = raw_request(port, url_of_len(1024).as_bytes(), 30).await;
    assert_eq!(
        split_response(&response).0,
        "20 text/plain",
        "a 1024-byte URL is inside the specification's limit"
    );

    common::drain(&mut rx);
    let response = raw_request(port, url_of_len(1025).as_bytes(), 30).await;
    assert_eq!(split_response(&response).0, "59 Request too long");
    let log = common::wait_for_log(&mut rx, "decision=fail_closed_request_too_long", 10).await;
    assert!(
        !log.iter().any(|l| l.contains("decision=model_")),
        "the over-long request reached the handler: {log:#?}"
    );
}

#[tokio::test]
async fn a_request_with_no_newline_is_refused_once_it_passes_the_limit() {
    let state = common::new_state().await;
    let (_id, port, _rx) = common::start(&state, vec![ok_handler()], None).await;
    let mut tls = tls_connect(port).await;
    tls.write_all(&vec![b'a'; 64 * 1024]).await.ok();
    let _ = tls.flush().await;
    let response = common::read_all(&mut tls, 10).await;
    assert_eq!(
        split_response(&response).0,
        "59 Request too long",
        "the server must not buffer toward a newline that never comes"
    );
}

#[tokio::test]
async fn a_peer_that_never_starts_the_handshake_is_closed_at_the_handshake_bound() {
    let state = common::new_state().await;
    let (_id, port, _rx) = common::start(&state, vec![ok_handler()], bounds()).await;
    let mut peer = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    let started = std::time::Instant::now();
    let mut sink = Vec::new();
    let read = tokio::time::timeout(
        HANDSHAKE_TIMEOUT + Duration::from_secs(40),
        peer.read_to_end(&mut sink),
    )
    .await;
    let elapsed = started.elapsed();
    assert!(
        read.is_ok(),
        "a peer that sent no ClientHello still held the socket after {}s",
        elapsed.as_secs()
    );
    assert!(
        sink.is_empty(),
        "nothing may be written outside TLS: {sink:?}"
    );
    assert!(
        elapsed >= HANDSHAKE_TIMEOUT / 2 && elapsed < FIRST_BYTE_TIMEOUT,
        "closed after {}ms, which is not the {}s handshake bound",
        elapsed.as_millis(),
        HANDSHAKE_TIMEOUT.as_secs()
    );
}

#[tokio::test]
async fn a_handshaked_peer_that_sends_no_request_is_closed_at_the_first_byte_bound() {
    let state = common::new_state().await;
    let (_id, port, _rx) = common::start(&state, vec![ok_handler()], bounds()).await;
    let mut tls = tls_connect(port).await;
    let started = std::time::Instant::now();
    let response = common::read_all(&mut tls, FIRST_BYTE_TIMEOUT.as_secs() + 40).await;
    let elapsed = started.elapsed();
    assert!(
        response.is_empty(),
        "got {:?}",
        String::from_utf8_lossy(&response)
    );
    assert!(
        elapsed >= HANDSHAKE_TIMEOUT + Duration::from_secs(3),
        "closed after {}ms — the handshake bound, not the first-byte bound",
        elapsed.as_millis()
    );
}

#[tokio::test]
async fn a_request_parked_for_a_human_is_closed_by_neither_deadline() {
    let state = common::new_state().await;
    let manual = serde_json::json!({
        "event_pattern": "*",
        "handler": {"type": "manual", "timeout_secs": 300}
    });
    let (_id, port, _rx) = common::start(&state, vec![manual], bounds()).await;
    let mut tls = tls_connect(port).await;
    tls.write_all(b"gemini://h/parked\r\n")
        .await
        .expect("write");
    tls.flush().await.expect("flush");

    tokio::time::sleep(FIRST_BYTE_TIMEOUT + Duration::from_secs(5)).await;
    let mut buf = [0u8; 256];
    match tokio::time::timeout(Duration::from_secs(3), tls.read(&mut buf)).await {
        Err(_) => {}
        Ok(Ok(0)) => panic!("closed while its request was parked for a human"),
        Ok(Ok(n)) => panic!(
            "answered a request nobody decided: {:?}",
            String::from_utf8_lossy(&buf[..n])
        ),
        Ok(Err(e)) => panic!("error while parked: {e}"),
    }
}

#[tokio::test]
async fn the_connection_past_the_cap_is_closed_before_any_handshake_and_the_slot_returns() {
    let state = common::new_state().await;
    let (server_id, port, _rx) = common::start(&state, vec![ok_handler()], None).await;

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
        .expect("the over-cap connection was neither handshaken nor closed")
        .expect("read");
    assert!(
        refusal.is_empty(),
        "a refusal before the handshake must be a bare close; got {refusal:?}"
    );

    drop(held.pop());
    let mut answered = false;
    for _ in 0..50 {
        // The freed slot may not be back yet, in which case this attempt is refused before
        // the handshake; only a handshake that succeeds is worth a request.
        if let Some(mut tls) = common::try_tls_connect(port).await {
            tls.write_all(b"gemini://h/\r\n").await.expect("write");
            let response = common::read_all(&mut tls, 20).await;
            if split_response(&response).0 == "20 text/plain" {
                answered = true;
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        answered,
        "the slot never came back after a connection ended"
    );
}

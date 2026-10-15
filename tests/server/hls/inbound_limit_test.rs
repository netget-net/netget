//! HLS's declared `max_inbound_bytes` — `MAX_REQUEST_HEAD_BYTES` — driven from the wire.
//!
//! The request head is the only thing an HLS peer sends that the server reads: players send
//! bodiless GETs, and a request that declares a body is refused with 413 before any of it is
//! read. So:
//!
//! 1. **`bound` is accepted**: a GET whose head is exactly `MAX_REQUEST_HEAD_BYTES` long (padded
//!    with one long header) reaches the model as a segment request.
//! 2. **`bound + 1` is refused before the model**: the same head one byte longer is answered
//!    `431 Request Header Fields Too Large` and closed, with zero model calls.
//! 3. **A declared body is refused unread**: `POST` with `Content-Length` gets 413 and no model
//!    call — what `max_inbound_bytes_bound_plus_one_test`'s HTTP-body probe meets.
//! 4. **The server still serves**: a fresh GET reaches the model.
//!
//! **Verified by removal.** With the `len <= MAX_REQUEST_HEAD_BYTES` / `buffer.len() >
//! MAX_REQUEST_HEAD_BYTES` checks made to accept anything, assertion 2 fails (the over-bound
//! head reaches the model); with `declares_body` returning `None`, assertion 3 fails.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features hls --test server -- hls::inbound_limit --test-threads=100

use std::time::Duration;

use netget::server::hls::MAX_REQUEST_HEAD_BYTES;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::helpers::inbound_limit::InboundLimitServer;

/// A GET for a segment whose head — through the final `\r\n\r\n` — is exactly `len` bytes.
fn get_with_head_len(len: usize) -> Vec<u8> {
    let prefix = "GET /seg0.ts HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Pad: ";
    let suffix = "\r\n\r\n";
    let pad = len - prefix.len() - suffix.len();
    let mut out = prefix.as_bytes().to_vec();
    out.resize(out.len() + pad, b'a');
    out.extend_from_slice(suffix.as_bytes());
    assert_eq!(out.len(), len);
    out
}

/// Write `bytes` while reading the response to EOF (or the deadline).
async fn exchange(stream: TcpStream, bytes: Vec<u8>) -> String {
    let (mut rd, mut wr) = stream.into_split();
    let writer = tokio::spawn(async move {
        for chunk in bytes.chunks(16 * 1024) {
            if wr.write_all(chunk).await.is_err() {
                break;
            }
        }
        wr
    });
    let mut out = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(30), rd.read_to_end(&mut out)).await;
    let _ = writer.await;
    String::from_utf8_lossy(&out).into_owned()
}

#[tokio::test]
async fn a_request_head_over_the_bound_is_refused_before_the_model_and_the_server_keeps_serving() {
    let server = InboundLimitServer::start("hls", None).await;

    // 1. A head of exactly the bound reaches the model.
    let before = server.settled_calls().await;
    let reply = exchange(
        server.connect().await,
        get_with_head_len(MAX_REQUEST_HEAD_BYTES),
    )
    .await;
    let after = server.settled_calls().await;
    assert!(
        after > before,
        "a GET whose head is exactly MAX_REQUEST_HEAD_BYTES ({MAX_REQUEST_HEAD_BYTES}) never \
         reached the model. Reply: {reply:?}"
    );
    assert!(
        !reply.starts_with("HTTP/1.1 431"),
        "a head of exactly the bound was refused as too large"
    );

    // 2. One byte more: 431, closed, no model call.
    let before = server.settled_calls().await;
    let reply = exchange(
        server.connect().await,
        get_with_head_len(MAX_REQUEST_HEAD_BYTES + 1),
    )
    .await;
    let after = server.settled_calls().await;
    assert!(
        reply.starts_with("HTTP/1.1 431 Request Header Fields Too Large\r\n"),
        "a head of MAX_REQUEST_HEAD_BYTES + 1 must be answered 431; got {:?}",
        crate::helpers::inbound_limit::head_of(&reply)
    );
    assert!(reply.contains("Connection: close\r\n"));
    assert_eq!(
        after - before,
        0,
        "a request head of {} bytes against a bound of {MAX_REQUEST_HEAD_BYTES} cost {} model \
         call(s)",
        MAX_REQUEST_HEAD_BYTES + 1,
        after - before
    );

    // 3. A declared body is refused unread, and the model is not asked.
    let before = server.settled_calls().await;
    let mut post =
        b"POST /seg0.ts HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 65537\r\n\r\n".to_vec();
    post.resize(post.len() + 65537, b'b');
    let reply = exchange(server.connect().await, post).await;
    let after = server.settled_calls().await;
    assert!(
        reply.starts_with("HTTP/1.1 413 Content Too Large\r\n"),
        "a request declaring a body must be answered 413; got {:?}",
        crate::helpers::inbound_limit::head_of(&reply)
    );
    assert_eq!(
        after - before,
        0,
        "a request declaring a body reached the model"
    );

    // 4. A fresh, ordinary GET still reaches the model.
    let before = server.settled_calls().await;
    let _ = exchange(
        server.connect().await,
        b"GET /live.m3u8 HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n".to_vec(),
    )
    .await;
    let after = server.settled_calls().await;
    assert!(
        after > before,
        "after the refusals, a fresh GET never reached the model"
    );

    server.stop().await;
}

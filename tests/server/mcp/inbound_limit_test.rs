//! MCP's declared `max_inbound_bytes` — `MAX_REQUEST_BODY_BYTES` — driven from the wire.
//!
//! The JSON-RPC request body is what an MCP peer sends, and the router bounds it with an
//! explicit `DefaultBodyLimit`. Four things are asserted over raw HTTP/1.1:
//!
//! 1. **`bound` is accepted**: a `tools/list` request whose body is exactly
//!    `MAX_REQUEST_BODY_BYTES` (padded inside `params`) reaches the model.
//! 2. **`bound + 1` with a `Content-Length` is refused before the model**: 413 carrying a
//!    JSON-RPC error with the fixed message, and zero model calls.
//! 3. **`bound + 1` chunked is refused the same way** — the limit applies while the body
//!    streams, not only to a declared length.
//! 4. **The server still serves**: a fresh request reaches the model.
//!
//! **Verified by removal.** With `.layer(DefaultBodyLimit::max(..))` replaced by
//! `DefaultBodyLimit::disable()`, assertions 2 and 3 fail: the over-limit body is parsed and
//! reaches the model.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features mcp --test server -- mcp::inbound_limit --test-threads=100

use std::time::Duration;

use netget::server::mcp::MAX_REQUEST_BODY_BYTES;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::helpers::inbound_limit::{head_of, InboundLimitServer};

/// A `tools/list` JSON-RPC request padded to exactly `len` bytes.
fn tools_list_body(len: usize) -> Vec<u8> {
    let prefix = r#"{"jsonrpc":"2.0","id":7,"method":"tools/list","params":{"pad":""#;
    let suffix = r#""}}"#;
    let mut out = prefix.as_bytes().to_vec();
    out.resize(len - suffix.len(), b'a');
    out.extend_from_slice(suffix.as_bytes());
    assert_eq!(out.len(), len);
    out
}

fn post_with_length(body: &[u8]) -> Vec<u8> {
    let mut out = format!(
        "POST / HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    out.extend_from_slice(body);
    out
}

fn post_chunked(body: &[u8]) -> Vec<u8> {
    let mut out = b"POST / HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n\
                    Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
        .to_vec();
    for chunk in body.chunks(32 * 1024) {
        out.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
        out.extend_from_slice(chunk);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"0\r\n\r\n");
    out
}

async fn exchange(stream: TcpStream, bytes: Vec<u8>) -> String {
    let (mut rd, mut wr) = stream.into_split();
    let writer = tokio::spawn(async move {
        for chunk in bytes.chunks(64 * 1024) {
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

fn assert_refused(reply: &str, what: &str) {
    assert!(
        reply.starts_with("HTTP/1.1 413"),
        "{what} must be answered 413; got {:?}",
        head_of(reply)
    );
    assert!(
        reply.contains(r#""message":"request body too large""#),
        "{what}: the 413 must carry the fixed JSON-RPC error message; got {reply:?}"
    );
}

#[tokio::test]
async fn a_request_body_over_the_bound_is_refused_before_the_model_and_the_server_keeps_serving() {
    let server = InboundLimitServer::start("mcp", None).await;

    // 1. Exactly the bound reaches the model.
    let before = server.settled_calls().await;
    let reply = exchange(
        server.connect().await,
        post_with_length(&tools_list_body(MAX_REQUEST_BODY_BYTES)),
    )
    .await;
    let after = server.settled_calls().await;
    assert!(
        after > before,
        "a tools/list body of exactly MAX_REQUEST_BODY_BYTES ({MAX_REQUEST_BODY_BYTES}) never \
         reached the model; got {:?}",
        head_of(&reply)
    );

    // 2. One byte more, declared by Content-Length.
    let before = server.settled_calls().await;
    let reply = exchange(
        server.connect().await,
        post_with_length(&tools_list_body(MAX_REQUEST_BODY_BYTES + 1)),
    )
    .await;
    let after = server.settled_calls().await;
    assert_refused(
        &reply,
        "a Content-Length body of MAX_REQUEST_BODY_BYTES + 1",
    );
    assert_eq!(after - before, 0, "the over-limit body reached the model");

    // 3. One byte more, chunked: the limit holds while the body streams.
    let before = server.settled_calls().await;
    let reply = exchange(
        server.connect().await,
        post_chunked(&tools_list_body(MAX_REQUEST_BODY_BYTES + 1)),
    )
    .await;
    let after = server.settled_calls().await;
    assert_refused(&reply, "a chunked body of MAX_REQUEST_BODY_BYTES + 1");
    assert_eq!(
        after - before,
        0,
        "the over-limit chunked body reached the model"
    );

    // 4. A fresh, small request is still served.
    let before = server.settled_calls().await;
    let _ = exchange(
        server.connect().await,
        post_with_length(br#"{"jsonrpc":"2.0","id":8,"method":"tools/list"}"#),
    )
    .await;
    let after = server.settled_calls().await;
    assert!(
        after > before,
        "after the refusals, a fresh tools/list never reached the model"
    );

    server.stop().await;
}

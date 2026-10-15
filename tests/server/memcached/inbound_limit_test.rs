//! Memcached's declared `max_inbound_bytes` — `protocol::MAX_VALUE_LEN` — driven from the wire.
//!
//! The text protocol has exactly one length a peer chooses: the `<bytes>` a storage command
//! declares for its data block. Everything else is one CRLF-terminated line under
//! `MAX_COMMAND_LINE`. So the bound is tested the way a real client meets it — a `set` that
//! declares `MAX_VALUE_LEN` and one that declares `MAX_VALUE_LEN + 1`, each followed by its full
//! data block, exactly as libmemcached writes them — and three things are asserted:
//!
//! 1. **`bound` is accepted**: the `set` at exactly the cap reaches the model. Without this the
//!    refusal below could be a server that refuses every large value.
//! 2. **`bound + 1` is refused before the model**: the peer reads upstream memcached's own
//!    `SERVER_ERROR object too large for cache`, then EOF, and the model is called zero times.
//! 3. **The server still serves**: a fresh connection's command reaches the model.
//!
//! **Verified by removal.** With the `bytes > MAX_VALUE_LEN` check in `parse_storage` removed,
//! assertion 2 fails: the over-cap `set` is buffered whole and handed to the model, which the
//! call count records.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features memcached --test server -- memcached::inbound_limit --test-threads=100

use std::time::Duration;

use netget::server::memcached::protocol::MAX_VALUE_LEN;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::helpers::inbound_limit::InboundLimitServer;

/// A storage command declaring `len` bytes, with its data block and terminator.
fn set_command(key: &str, len: usize) -> Vec<u8> {
    let mut out = format!("set {key} 0 0 {len}\r\n").into_bytes();
    out.resize(out.len() + len, b'v');
    out.extend_from_slice(b"\r\n");
    out
}

/// Write `bytes` from a separate task while this one reads, so a server that refuses part-way
/// is observed rather than deadlocking against a full send buffer.
async fn send_and_read_reply(stream: TcpStream, bytes: Vec<u8>) -> (Vec<u8>, bool) {
    let (mut rd, mut wr) = stream.into_split();
    let writer = tokio::spawn(async move {
        for chunk in bytes.chunks(64 * 1024) {
            if wr.write_all(chunk).await.is_err() {
                break;
            }
        }
        wr
    });
    let mut reply = Vec::new();
    let mut buf = [0u8; 4096];
    let mut eof = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        match tokio::time::timeout_at(deadline, rd.read(&mut buf)).await {
            Ok(Ok(0)) | Ok(Err(_)) => {
                eof = true;
                break;
            }
            Ok(Ok(n)) => {
                reply.extend_from_slice(&buf[..n]);
                if reply.ends_with(b"\r\n") {
                    // One reply line is all either case produces; for the refusal, keep
                    // reading to observe the close.
                    if !reply.starts_with(b"SERVER_ERROR object too large") {
                        break;
                    }
                }
            }
            Err(_) => break,
        }
    }
    let _ = writer.await;
    (reply, eof)
}

#[tokio::test]
async fn a_value_over_max_value_len_is_refused_before_the_model_and_the_server_keeps_serving() {
    let server = InboundLimitServer::start("memcached", None).await;

    // 1. Exactly the bound: accepted, so the model is asked.
    let before = server.settled_calls().await;
    let (reply, _) =
        send_and_read_reply(server.connect().await, set_command("atcap", MAX_VALUE_LEN)).await;
    let after = server.settled_calls().await;
    assert!(
        after > before,
        "a set declaring exactly MAX_VALUE_LEN ({MAX_VALUE_LEN}) bytes never reached the model — \
         the bound refuses values it declares acceptable. Reply: {:?}",
        String::from_utf8_lossy(&reply)
    );

    // 2. One past the bound: refused in memcached's own words, then closed, with no model call.
    let before = server.settled_calls().await;
    let (reply, eof) = send_and_read_reply(
        server.connect().await,
        set_command("overcap", MAX_VALUE_LEN + 1),
    )
    .await;
    let after = server.settled_calls().await;
    assert_eq!(
        String::from_utf8_lossy(&reply),
        "SERVER_ERROR object too large for cache\r\n",
        "a set declaring MAX_VALUE_LEN + 1 must be answered with upstream memcached's own refusal"
    );
    assert!(
        eof,
        "after refusing an over-cap data block the server must close: the block's octets \
         cannot be skipped without reading them"
    );
    assert_eq!(
        after - before,
        0,
        "a set declaring {} bytes against a declared bound of {MAX_VALUE_LEN} reached the \
         model {} time(s); the bound must be enforced before any model call",
        MAX_VALUE_LEN + 1,
        after - before
    );

    // 3. The server is still serving: a fresh connection's command reaches the model.
    let before = server.settled_calls().await;
    let mut fresh = server.connect().await;
    fresh.write_all(b"get afterwards\r\n").await.unwrap();
    let after = server.wait_for_calls_above(before, 30).await;
    assert!(
        after > before,
        "after refusing an over-cap value, a fresh connection's `get` never reached the model"
    );

    server.stop().await;
}

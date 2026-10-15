//! SMB's inbound bounds — `MAX_MESSAGE_BYTES`, the declared `max_inbound_bytes`, and
//! `MAX_WRITE_SIZE`, the negotiated `MaxWriteSize` — driven from the wire.
//!
//! Every SMB2 message arrives behind a Direct TCP transport header that announces its length
//! (MS-SMB2 2.1), so the frame length is the one number that decides what the server
//! allocates. Two bounds follow from it, and each is tested at the bound and one past it,
//! after a NEGOTIATE, a SESSION_SETUP the model approves, a TREE_CONNECT and a CREATE:
//!
//! 1. **`NEGOTIATE` advertises `MAX_WRITE_SIZE`** as `MaxWriteSize`, so a client never sends
//!    more.
//! 2. **A WRITE of exactly `MAX_WRITE_SIZE` bytes** is read and handed to the model.
//! 3. **A WRITE of `MAX_WRITE_SIZE + 1` bytes** — a whole, well-framed message — is answered
//!    `STATUS_INVALID_PARAMETER` (MS-SMB2 3.3.5.13) with zero model calls, and because the
//!    frame was read whole the connection stays in step: an ECHO after it is answered.
//! 4. **A frame announcing `MAX_MESSAGE_BYTES + 1`** is refused after its 64-byte SMB2 header
//!    alone — `STATUS_INVALID_PARAMETER` to that request's MessageId — and the connection
//!    closes, because the rest of the frame is unread. Zero model calls.
//! 5. **The server still serves**: a fresh connection's SESSION_SETUP reaches the model.
//!
//! **Verified by removal.** With the `length > MAX_WRITE_SIZE` check removed, assertion 3
//! fails: the over-size WRITE reaches the model. With the `len > MAX_MESSAGE_BYTES` check
//! removed, assertion 4 fails: the server allocates the announced frame and waits for bytes
//! that never come, so no reply arrives.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features smb --test server -- smb::inbound_limit --test-threads=100


use std::time::Duration;

use netget::server::smb::{MAX_MESSAGE_BYTES, MAX_WRITE_SIZE};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use super::wire_util::{self as w, nbss, read_frame};
use crate::helpers::inbound_limit::InboundLimitServer;
use crate::helpers::mock_builder::MockLlmBuilder;

/// Read one response frame; `None` on EOF, error or a 30s silence.
async fn read_response(stream: &mut TcpStream) -> Option<Vec<u8>> {
    match tokio::time::timeout(Duration::from_secs(30), read_frame(stream)).await {
        Ok(Ok(msg)) => Some(msg),
        _ => None,
    }
}

async fn send(stream: &mut TcpStream, msg: Vec<u8>) {
    stream.write_all(&nbss(msg)).await.unwrap();
}

/// NEGOTIATE, SESSION_SETUP, TREE_CONNECT, CREATE. Returns the NEGOTIATE response and the
/// FileId the CREATE opened on tree 1 of session 1.
async fn handshake(stream: &mut TcpStream) -> (Vec<u8>, Vec<u8>) {
    send(stream, w::negotiate(0)).await;
    let neg = read_response(stream).await.expect("NEGOTIATE response");
    send(stream, w::session_setup(1)).await;
    let setup = read_response(stream).await.expect("SESSION_SETUP response");
    assert_eq!(
        w::status(&setup),
        0,
        "SESSION_SETUP must succeed for the WRITE to be reached"
    );
    send(stream, w::tree_connect(2, 1, r"\\127.0.0.1\share")).await;
    let tree = read_response(stream).await.expect("TREE_CONNECT response");
    assert_eq!(w::status(&tree), 0, "TREE_CONNECT");
    send(stream, w::create(3, 1, 1, "big.bin")).await;
    let create = read_response(stream).await.expect("CREATE response");
    assert_eq!(w::status(&create), 0, "CREATE");
    (neg, w::create_file_id(&create))
}

async fn start() -> InboundLimitServer {
    InboundLimitServer::try_start_with_mock(
        "smb",
        None,
        MockLlmBuilder::new()
            .on_event("smb_operation")
            .and_event_data_contains("operation", "session_setup")
            .respond_with_actions(serde_json::json!([
                {"type": "smb_auth_success", "username": "guest"}
            ]))
            .expect_at_least(0)
            .and()
            .on_event("smb_operation")
            .and_event_data_contains("operation", "create")
            .respond_with_actions(serde_json::json!([
                {"type": "smb_create_file", "path": "/big.bin"}
            ]))
            .expect_at_least(0)
            .and()
            .on_any()
            .respond_with_actions(serde_json::json!([]))
            .expect_at_least(0)
            .build(),
    )
    .await
    .unwrap_or_else(|e| panic!("start smb: {e}"))
}

#[tokio::test]
async fn a_write_over_max_write_size_is_refused_before_the_model_and_the_server_keeps_serving() {
    let server = start().await;
    let bound = MAX_WRITE_SIZE as usize;

    // 1 + 2. The bound is advertised, and a WRITE of exactly that size reaches the model.
    let mut s = server.connect().await;
    let (neg, file_id) = handshake(&mut s).await;
    // NEGOTIATE response body: MaxTransactSize, MaxReadSize, MaxWriteSize at body offsets
    // 28, 32 and 36 (MS-SMB2 2.2.4).
    let advertised = u32::from_le_bytes([neg[64 + 36], neg[64 + 37], neg[64 + 38], neg[64 + 39]]);
    assert_eq!(
        advertised, MAX_WRITE_SIZE,
        "NEGOTIATE must advertise MaxWriteSize equal to the bound the WRITE arm enforces"
    );
    let before = server.settled_calls().await;
    send(&mut s, w::write(4, 1, 1, &file_id, &vec![b'w'; bound])).await;
    let after = server.wait_for_calls_above(before, 30).await;
    assert!(
        after > before,
        "a WRITE of exactly MaxWriteSize ({bound}) bytes never reached the model"
    );
    let reply = read_response(&mut s)
        .await
        .expect("a reply to the at-bound WRITE");
    assert_ne!(
        w::status(&reply),
        w::STATUS_INVALID_PARAMETER,
        "a WRITE of exactly MaxWriteSize was refused as too large"
    );

    // 3. One byte past MaxWriteSize, in a whole frame: refused before the model, and the
    // connection is still in step.
    let before = server.settled_calls().await;
    send(&mut s, w::write(5, 1, 1, &file_id, &vec![b'w'; bound + 1])).await;
    let reply = read_response(&mut s)
        .await
        .expect("an over-size WRITE must be answered");
    assert_eq!(
        w::status(&reply),
        w::STATUS_INVALID_PARAMETER,
        "a WRITE longer than MaxWriteSize must fail with STATUS_INVALID_PARAMETER (MS-SMB2 3.3.5.13)"
    );
    assert_eq!(
        w::message_id(&reply),
        5,
        "the refusal names the WRITE it refuses"
    );
    send(&mut s, w::simple(w::ECHO, 6, 0, 1)).await;
    let echo = read_response(&mut s)
        .await
        .expect("the connection must stay in step after refusing a whole over-size WRITE");
    assert_eq!((w::command(&echo), w::message_id(&echo)), (w::ECHO, 6));
    let after = server.settled_calls().await;
    assert_eq!(
        after - before,
        0,
        "a WRITE of {} bytes against MaxWriteSize {bound} cost {} model call(s)",
        bound + 1,
        after - before
    );
    drop(s);

    // 4. A frame announcing one byte more than MAX_MESSAGE_BYTES: only its header is sent,
    // and only its header is read.
    let mut s = server.connect().await;
    handshake(&mut s).await;
    let before = server.settled_calls().await;
    let fixed = w::write_fixed(7, 1, 1, &file_id, MAX_WRITE_SIZE);
    s.write_all(&w::nbss_header(MAX_MESSAGE_BYTES + 1))
        .await
        .unwrap();
    s.write_all(&fixed).await.unwrap();
    let reply = read_response(&mut s)
        .await
        .expect("an over-size frame must be answered, not left waiting for its payload");
    assert_eq!(w::status(&reply), w::STATUS_INVALID_PARAMETER);
    assert_eq!(
        w::message_id(&reply),
        7,
        "the refusal names the request it refuses"
    );
    let mut sink = [0u8; 64];
    let closed = matches!(
        tokio::time::timeout(Duration::from_secs(20), s.read(&mut sink)).await,
        Ok(Ok(0)) | Ok(Err(_))
    );
    assert!(
        closed,
        "after refusing an over-size frame the server must close: the rest of it is unread, \
         and reading on would parse it as the next message"
    );
    let after = server.settled_calls().await;
    assert_eq!(after - before, 0, "an over-size frame cost a model call");

    // 5. A fresh connection is still served.
    let mut s = server.connect().await;
    let before = server.settled_calls().await;
    handshake(&mut s).await;
    let after = server.settled_calls().await;
    assert!(
        after > before,
        "after refusing an over-size frame, a fresh SESSION_SETUP never reached the model"
    );

    server.stop().await;
}

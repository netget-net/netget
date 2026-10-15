//! WebRTC Signaling's declared `max_inbound_bytes` — `SIGNALING_MAX_MESSAGE_BYTES` — driven
//! from the wire.
//!
//! The generic `max_inbound_bytes_bound_plus_one_test` reaches this server over TCP, but with
//! raw bytes that fail the HTTP upgrade — it proves the upgrade reader is bounded and nothing
//! about the WebSocket message limit. This file speaks real RFC 6455 (a hand-written client,
//! `tests/helpers/inbound_limit.rs::ws`) so it can reach the limit itself:
//!
//! 1. **`bound` is accepted**: a `register` message of exactly `SIGNALING_MAX_MESSAGE_BYTES`
//!    (padded with a field serde ignores) registers the peer and reaches the model.
//! 2. **`bound + 1` is refused on the frame header, before the model**: only the header
//!    declaring `SIGNALING_MAX_MESSAGE_BYTES + 1` is sent, and the server answers a close frame
//!    with code 1009 (Message Too Big), ends the connection, and makes no model call.
//! 3. **The server still serves**: a fresh connection registers and reaches the model.
//!
//! **Verified by removal.** With `max_message_size`/`max_frame_size` set to `None` in
//! `WebSocketConfig`, assertion 2 fails: the server waits for the declared payload instead of
//! refusing it.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features webrtc --test server -- webrtc_signaling::inbound_limit --test-threads=100


use netget::server::webrtc_signaling::SIGNALING_MAX_MESSAGE_BYTES;
use tokio::io::AsyncWriteExt;

use crate::helpers::inbound_limit::{ws, InboundLimitServer};

/// A `register` message for `peer_id`, padded to exactly `len` bytes.
fn register(peer_id: &str, len: usize) -> Vec<u8> {
    let prefix = format!(r#"{{"type":"register","peer_id":"{peer_id}","pad":""#);
    let suffix = r#""}"#;
    let mut out = prefix.into_bytes();
    out.resize(len - suffix.len(), b'a');
    out.extend_from_slice(suffix.as_bytes());
    assert_eq!(out.len(), len);
    out
}

#[tokio::test]
async fn a_message_over_the_bound_is_refused_with_1009_before_the_model() {
    let server = InboundLimitServer::start("webrtc_signaling", None).await;

    // 1. Exactly the bound: parsed, registered, and the model is asked about the new peer.
    let mut s = server.connect().await;
    ws::upgrade(&mut s).await;
    let before = server.settled_calls().await;
    s.write_all(&ws::text(&register("atbound", SIGNALING_MAX_MESSAGE_BYTES)))
        .await
        .unwrap();
    let after = server.wait_for_calls_above(before, 30).await;
    assert!(
        after > before,
        "a register message of exactly SIGNALING_MAX_MESSAGE_BYTES \
         ({SIGNALING_MAX_MESSAGE_BYTES}) never reached the model"
    );
    let (opcode, payload) = ws::read_frame(&mut s, 30)
        .await
        .expect("a reply to the at-bound register");
    assert_eq!(opcode, 0x1, "expected a text reply");
    assert!(
        String::from_utf8_lossy(&payload).contains("registered"),
        "the at-bound register was not accepted: {:?}",
        String::from_utf8_lossy(&payload)
    );
    drop(s);

    // 2. One past the bound, declared by the header alone.
    let mut s = server.connect().await;
    ws::upgrade(&mut s).await;
    let before = server.settled_calls().await;
    s.write_all(&ws::header(0x1, SIGNALING_MAX_MESSAGE_BYTES as u64 + 1))
        .await
        .unwrap();
    let frame = ws::read_frame(&mut s, 20).await;
    let (opcode, payload) = frame.expect(
        "a header declaring SIGNALING_MAX_MESSAGE_BYTES + 1 got no close frame: the server is \
         waiting to buffer a message over its declared bound",
    );
    assert_eq!(opcode, 0x8, "expected a close frame");
    assert_eq!(
        payload.get(..2),
        Some(&1009u16.to_be_bytes()[..]),
        "the close must carry 1009 (Message Too Big)"
    );
    assert!(
        ws::closed_within(&mut s, 20).await,
        "after the 1009 close the server must end the connection"
    );
    let after = server.settled_calls().await;
    assert_eq!(
        after - before,
        0,
        "the over-bound message reached the model"
    );

    // 3. A fresh connection is still served.
    let mut s = server.connect().await;
    ws::upgrade(&mut s).await;
    let before = server.settled_calls().await;
    s.write_all(&ws::text(br#"{"type":"register","peer_id":"afterwards"}"#))
        .await
        .unwrap();
    let after = server.wait_for_calls_above(before, 30).await;
    assert!(
        after > before,
        "after refusing an over-bound message, a fresh register never reached the model"
    );

    server.stop().await;
}

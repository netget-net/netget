//! WebRTC's declared `max_inbound_bytes` — `SIGNALLING_MAX_MESSAGE_BYTES` — driven from the wire.
//!
//! WebRTC's `stack_name()` is UDP, so the generic `max_inbound_bytes_bound_plus_one_test` skips
//! it entirely — but the largest thing NetGet itself buffers from a peer is a message on the
//! **TCP** signalling WebSocket, so that is where the bound is tested, with a hand-written RFC
//! 6455 client (`tests/helpers/inbound_limit.rs::ws`):
//!
//! 1. **`bound` is accepted**: an `offer` of exactly `SIGNALLING_MAX_MESSAGE_BYTES` (a minimal
//!    SDP, padded with a field serde ignores) is parsed and put to the model.
//! 2. **`bound + 1` is refused on the frame header, before the model**: only the header is sent;
//!    the server answers a close frame with code 1009 (Message Too Big), ends the connection,
//!    and makes no model call.
//! 3. **The server still serves**: a fresh connection's offer reaches the model.
//!
//! Data-channel messages are not tested here: webrtc-rs reads them into a fixed 65 535-byte
//! buffer and closes the channel on a larger one, and webrtc-sctp drops DATA once its 1 MiB
//! receive window is full — both inside the crate, both below the declared bound.
//!
//! **Verified by removal.** With `max_message_size`/`max_frame_size` set to `None` in
//! `WebSocketConfig`, assertion 2 fails: the server waits for the declared payload instead of
//! refusing it.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features webrtc --test server -- webrtc::inbound_limit --test-threads=100


use netget::server::webrtc::SIGNALLING_MAX_MESSAGE_BYTES;
use tokio::io::AsyncWriteExt;

use crate::helpers::inbound_limit::{ws, InboundLimitServer};

/// The smallest SDP webrtc-rs will parse as an offer: version, origin, session name, timing.
const MINIMAL_SDP: &str = "v=0\\r\\no=- 1 1 IN IP4 127.0.0.1\\r\\ns=-\\r\\nt=0 0\\r\\n";

/// An `offer` for `peer_id`, padded to exactly `len` bytes.
fn offer(peer_id: &str, len: usize) -> Vec<u8> {
    let prefix = format!(r#"{{"type":"offer","peer_id":"{peer_id}","sdp":"{MINIMAL_SDP}","pad":""#);
    let suffix = r#""}"#;
    let mut out = prefix.into_bytes();
    out.resize(len - suffix.len(), b'a');
    out.extend_from_slice(suffix.as_bytes());
    assert_eq!(out.len(), len);
    out
}

#[tokio::test]
async fn a_signalling_message_over_the_bound_is_refused_with_1009_before_the_model() {
    let server = InboundLimitServer::start("webrtc", None).await;

    // 1. Exactly the bound: parsed as an offer and put to the model.
    let mut s = server.connect().await;
    ws::upgrade(&mut s).await;
    let before = server.settled_calls().await;
    s.write_all(&ws::text(&offer("atbound", SIGNALLING_MAX_MESSAGE_BYTES)))
        .await
        .unwrap();
    let after = server.wait_for_calls_above(before, 30).await;
    assert!(
        after > before,
        "an offer of exactly SIGNALLING_MAX_MESSAGE_BYTES ({SIGNALLING_MAX_MESSAGE_BYTES}) never \
         reached the model"
    );
    drop(s);

    // 2. One past the bound, declared by the header alone.
    let mut s = server.connect().await;
    ws::upgrade(&mut s).await;
    let before = server.settled_calls().await;
    s.write_all(&ws::header(0x1, SIGNALLING_MAX_MESSAGE_BYTES as u64 + 1))
        .await
        .unwrap();
    let (opcode, payload) = ws::read_frame(&mut s, 20).await.expect(
        "a header declaring SIGNALLING_MAX_MESSAGE_BYTES + 1 got no close frame: the server is \
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
    s.write_all(&ws::text(&offer("afterwards", 512)))
        .await
        .unwrap();
    let after = server.wait_for_calls_above(before, 30).await;
    assert!(
        after > before,
        "after refusing an over-bound message, a fresh offer never reached the model"
    );

    server.stop().await;
}

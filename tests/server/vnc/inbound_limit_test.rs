//! VNC's declared `max_inbound_bytes` — `MAX_CUT_TEXT_LEN` — driven from the wire.
//!
//! RFB lets a client size exactly one message: `ClientCutText`, whose length is a u32 the server
//! reads before allocating the buffer for the text. Every other client message is fixed length.
//! So the bound is tested with that message, after a real RFB 3.8 handshake:
//!
//! 1. **`bound` is accepted**: a `ClientCutText` of exactly `MAX_CUT_TEXT_LEN` bytes reaches the
//!    model as `vnc_client_cut_text`.
//! 2. **`bound + 1` is refused before the model**: only the eight-byte header declaring
//!    `MAX_CUT_TEXT_LEN + 1` is sent, and the server closes the connection with zero model
//!    calls. RFB has no error message once the session is up, so a close is the refusal.
//! 3. **The server still serves**: a fresh connection completes the handshake and its
//!    `ClientCutText` reaches the model.
//!
//! **Verified by removal.** With the `length > MAX_CUT_TEXT_LEN` check removed, assertion 2
//! fails: the server allocates and waits for the declared payload instead of closing.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features vnc --test server -- vnc::inbound_limit --test-threads=100


use std::time::Duration;

use netget::server::vnc::MAX_CUT_TEXT_LEN;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::helpers::inbound_limit::InboundLimitServer;

/// RFB 3.8 to the point where client messages are accepted.
async fn handshake(peer: &mut TcpStream) {
    let mut version = [0u8; 12];
    peer.read_exact(&mut version).await.expect("server version");
    assert_eq!(&version, b"RFB 003.008\n");
    peer.write_all(b"RFB 003.008\n").await.unwrap();
    let mut security = [0u8; 2];
    peer.read_exact(&mut security)
        .await
        .expect("security types");
    peer.write_all(&[1u8]).await.unwrap();
    let mut result = [0u8; 4];
    peer.read_exact(&mut result).await.expect("SecurityResult");
    assert_eq!(u32::from_be_bytes(result), 0, "SecurityResult was not OK");
    peer.write_all(&[1u8]).await.unwrap(); // ClientInit, shared
    let mut fixed = [0u8; 24];
    peer.read_exact(&mut fixed).await.expect("ServerInit");
    let name_len = u32::from_be_bytes([fixed[20], fixed[21], fixed[22], fixed[23]]) as usize;
    let mut name = vec![0u8; name_len];
    peer.read_exact(&mut name).await.expect("desktop name");
}

/// `ClientCutText`: type 6, three bytes of padding, the u32 length.
fn cut_text_header(len: u32) -> Vec<u8> {
    let mut out = vec![6u8, 0, 0, 0];
    out.extend_from_slice(&len.to_be_bytes());
    out
}

/// Read and discard until EOF or `secs`; true when the server closed.
async fn closed_within(peer: &mut TcpStream, secs: u64) -> bool {
    let mut buf = [0u8; 8192];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
    loop {
        match tokio::time::timeout_at(deadline, peer.read(&mut buf)).await {
            Ok(Ok(0)) | Ok(Err(_)) => return true,
            Ok(Ok(_)) => continue,
            Err(_) => return false,
        }
    }
}

#[tokio::test]
async fn a_cut_text_over_max_cut_text_len_is_refused_before_the_model_and_the_server_keeps_serving()
{
    let server = InboundLimitServer::start("vnc", None).await;
    let bound = MAX_CUT_TEXT_LEN as usize;

    // 1. Exactly the bound: reaches the model.
    let mut peer = server.connect().await;
    handshake(&mut peer).await;
    let before = server.settled_calls().await;
    let mut msg = cut_text_header(MAX_CUT_TEXT_LEN);
    msg.resize(msg.len() + bound, b'c');
    peer.write_all(&msg).await.unwrap();
    let after = server.wait_for_calls_above(before, 30).await;
    assert!(
        after > before,
        "a ClientCutText of exactly MAX_CUT_TEXT_LEN ({bound}) bytes never reached the model"
    );
    drop(peer);

    // 2. One past the bound: the header alone decides it — closed, no model call.
    let mut peer = server.connect().await;
    handshake(&mut peer).await;
    let before = server.settled_calls().await;
    peer.write_all(&cut_text_header(MAX_CUT_TEXT_LEN + 1))
        .await
        .unwrap();
    assert!(
        closed_within(&mut peer, 20).await,
        "a ClientCutText declaring MAX_CUT_TEXT_LEN + 1 left the connection open: the server \
         is waiting to buffer a payload over its declared bound"
    );
    let after = server.settled_calls().await;
    assert_eq!(
        after - before,
        0,
        "a ClientCutText declaring {} bytes against a bound of {bound} cost {} model call(s)",
        bound + 1,
        after - before
    );

    // 3. A fresh connection is still served.
    let mut peer = server.connect().await;
    handshake(&mut peer).await;
    let before = server.settled_calls().await;
    let mut msg = cut_text_header(5);
    msg.extend_from_slice(b"hello");
    peer.write_all(&msg).await.unwrap();
    let after = server.wait_for_calls_above(before, 30).await;
    assert!(
        after > before,
        "after refusing an over-bound ClientCutText, a fresh connection's was never answered"
    );

    server.stop().await;
}

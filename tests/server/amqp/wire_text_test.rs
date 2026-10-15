//! A malformed frame gets a *category* on the wire, never netget's own decoder diagnostic.
//!
//! `src/server/amqp/mod.rs` answers a framing or decoding error with a `connection.close`
//! carrying reply code 505. It used to build that method's `reply_text` as
//! `format!("UNEXPECTED_FRAME - {}", e)`, where `e` is whatever `codec.rs` said — for a
//! truncated payload, literally
//!
//! ```text
//! AMQP payload truncated: 24 bytes wanted at offset 6, only 2 available
//! ```
//!
//! That is netget's internal buffer arithmetic on an unauthenticated stranger's wire, and it
//! is the leak class `tests/wire_failure_test.rs` exists for: a pass that taught ~25 protocols
//! to answer their peer on failure interpolated the error into the reply in every one of them.
//! `WireFailure` is not the tool here — this is a decode failure, not a backend failure, and
//! neither `Overloaded` nor `Unavailable` describes it — but the rule is the same one: the
//! peer gets a category, the log gets the error.
//!
//! **This test fails without the fix.** Restore the `format!` and the assertion below finds
//! `offset` in the peer's `reply_text`.
//!
//! Zero LLM calls: the connection never gets past `connection.start-ok`, which the broker
//! decodes itself, and the LLM endpoint is a dead port so a stray call would fail loudly.
//! Loopback only.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features amqp --test server -- amqp::wire_text --test-threads=100

use std::time::Duration;

use netget::cli::management::ServerForm;
use netget::server::amqp::codec::{
    CLASS_CONNECTION, CONNECTION_CLOSE, CONNECTION_START, CONNECTION_START_OK, FRAME_END,
    FRAME_METHOD, PROTOCOL_HEADER_091,
};
use netget::state::app_state::AppState;
use netget::state::ServerId;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

async fn new_state() -> AppState {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".to_string());
    state
        .set_llm_client(netget::llm::OllamaClient::new(
            "http://127.0.0.1:1".to_string(),
        ))
        .await;
    state
}

async fn wait_for_port(state: &AppState, id: ServerId) -> u16 {
    for _ in 0..200 {
        if let Some(s) = state.get_server(id).await {
            if let Some(addr) = s.local_addr {
                return addr.port();
            }
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("AMQP server #{} never bound a port", id.as_u32());
}

/// Read one AMQP frame off a raw socket: (type, channel, payload).
async fn read_frame(stream: &mut TcpStream) -> (u8, u16, Vec<u8>) {
    let mut header = [0u8; 7];
    tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut header))
        .await
        .expect("frame header within 10s")
        .expect("read frame header");
    let size = u32::from_be_bytes([header[3], header[4], header[5], header[6]]) as usize;
    let mut payload = vec![0u8; size];
    stream.read_exact(&mut payload).await.expect("read payload");
    let mut end = [0u8; 1];
    stream.read_exact(&mut end).await.expect("read frame end");
    assert_eq!(end[0], FRAME_END);
    (
        header[0],
        u16::from_be_bytes([header[1], header[2]]),
        payload,
    )
}

fn method_frame(channel: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![FRAME_METHOD];
    out.extend_from_slice(&channel.to_be_bytes());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out.push(FRAME_END);
    out
}

#[tokio::test]
async fn a_decode_error_reaches_the_peer_as_a_category_not_as_the_decoder_message() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    let server_id = ServerForm {
        protocol: "amqp".to_string(),
        port: Some(0),
        // An empty instruction is genuinely model-free; `None` is replaced by a default one.
        instruction: Some(String::new()),
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .expect("create amqp server");
    let port = wait_for_port(&state, server_id).await;

    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .expect("connect");
    stream
        .write_all(&PROTOCOL_HEADER_091)
        .await
        .expect("write protocol header");

    // Connection.Start proves the broker is talking to this socket and that the session is in
    // `Phase::AwaitStartOk`, which is where the decode below happens.
    let (frame_type, channel, payload) = read_frame(&mut stream).await;
    assert_eq!(frame_type, FRAME_METHOD);
    assert_eq!(channel, 0);
    assert_eq!(
        u16::from_be_bytes([payload[0], payload[1]]),
        CLASS_CONNECTION
    );
    assert_eq!(
        u16::from_be_bytes([payload[2], payload[3]]),
        CONNECTION_START
    );

    // A `connection.start-ok` whose `client-properties` field table declares 24 bytes and
    // carries 2. `Decoder::take` refuses it with the offsets it was working at — the exact
    // string that used to be handed to the peer.
    let mut bad = Vec::new();
    bad.extend_from_slice(&CLASS_CONNECTION.to_be_bytes());
    bad.extend_from_slice(&CONNECTION_START_OK.to_be_bytes());
    bad.extend_from_slice(&24u32.to_be_bytes()); // declared field-table length
    bad.extend_from_slice(&[0xAA, 0xBB]); // ...and only two bytes of it
    stream
        .write_all(&method_frame(0, &bad))
        .await
        .expect("write malformed start-ok");

    let (frame_type, channel, payload) = read_frame(&mut stream).await;
    assert_eq!(frame_type, FRAME_METHOD, "expected a method frame back");
    assert_eq!(channel, 0, "a connection exception is channel 0");
    assert_eq!(
        u16::from_be_bytes([payload[0], payload[1]]),
        CLASS_CONNECTION
    );
    assert_eq!(
        u16::from_be_bytes([payload[2], payload[3]]),
        CONNECTION_CLOSE,
        "a frame the broker cannot decode must produce connection.close"
    );

    let reply_code = u16::from_be_bytes([payload[4], payload[5]]);
    assert_eq!(reply_code, 505, "505 is AMQP's UNEXPECTED_FRAME");

    // `reply_text` is a short-string: one length octet then that many bytes.
    let text_len = payload[6] as usize;
    let reply_text = String::from_utf8_lossy(&payload[7..7 + text_len]).into_owned();

    // The category. Fixed text, so a peer can match on it and an operator reading a client's
    // log sees the same words every time.
    assert_eq!(
        reply_text, "UNEXPECTED_FRAME - frame could not be decoded or was not expected here",
        "the peer must get the fixed category from `UNEXPECTED_FRAME_REPLY_TEXT`"
    );

    // And, separately, none of the decoder's own vocabulary. Asserted by substring as well as
    // by equality above, because the equality would also pass if someone changed the category
    // to a *different* interpolated string and updated this test to match it.
    for leaked in [
        "truncated",
        "offset",
        "available",
        "wanted",
        "AMQP payload",
        "field table",
        "0xAA",
    ] {
        assert!(
            !reply_text.to_lowercase().contains(&leaked.to_lowercase()),
            "netget's decoder diagnostic reached the peer: reply_text = {reply_text:?} contains \
             {leaked:?}. The peer gets a category; the log gets the error."
        );
    }

    let _ = state.remove_server(server_id).await;
}

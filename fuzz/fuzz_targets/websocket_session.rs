//! The WebSocket server's whole inbound stack, in the order a connection meets it:
//!
//! 1. the request head up to the first `\r\n\r\n` (bounded by `MAX_REQUEST_HEAD`), parsed by
//!    NetGet's hand-written `parse_request_head` and checked by `validate_upgrade`;
//! 2. `deflate::negotiate` over every `Sec-WebSocket-Extensions` value — RFC 7692 parameter
//!    parsing, also NetGet's own;
//! 3. everything after the head handed to `deflate::DeflateStream::server` as the leftover, so
//!    NetGet's frame parser (`deflate::Frame::parse`), its fragment reassembly and its bounded
//!    inflater (`Codec::inflate`) run on it, and what they pass up is read by tungstenite's
//!    server-role frame decoder through `WebSocketStream::from_partially_read`, with the
//!    server's default `WebSocketConfig` limits.
//!
//! Exactly what the server does with a peer's first segment, minus the model's
//! accept-or-reject decision, which no byte can influence. The socket under the stream is an
//! in-memory one that reports end-of-file after the input and swallows whatever the server
//! writes back, so every future here completes without a runtime.
//!
//! Asserted: nothing panics, no inflated message passes `DEFAULT_MAX_MESSAGE_SIZE` (the
//! decompression-bomb seed is a 64 KiB frame that inflates to 64 MiB), and the session ends.
//!
//! WebSocket does not nest, so there is no depth bomb. The long and lying axes are seeded
//! instead: the inflation bomb, a 127-length frame declaring 2^63 - 1 bytes, a message split
//! into 20 000 one-byte continuation frames (and a compressed one into ~900), and a compressed
//! message with RSV1 on a continuation frame.

#![no_main]

use futures_util::StreamExt;
use libfuzzer_sys::fuzz_target;
use netget::server::websocket::{
    deflate, parse_request_head, validate_upgrade, DEFAULT_MAX_FRAME_SIZE,
    DEFAULT_MAX_MESSAGE_SIZE, MAX_REQUEST_HEAD,
};
use std::future::Future;
use std::pin::{pin, Pin};
use std::task::{Context, Poll, Waker};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_tungstenite::tungstenite::protocol::{Role, WebSocketConfig};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;

/// A socket that has already delivered everything (the leftover holds it) and accepts writes.
struct Drained;

impl AsyncRead for Drained {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for Drained {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Poll::Ready(Ok(buf.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// Drive a future that cannot be pending: every I/O under it is in memory.
fn complete<F: Future>(fut: F) -> F::Output {
    let mut fut = pin!(fut);
    let mut cx = Context::from_waker(Waker::noop());
    match fut.as_mut().poll(&mut cx) {
        Poll::Ready(v) => v,
        Poll::Pending => panic!("an in-memory WebSocket session went pending"),
    }
}

fuzz_target!(|data: &[u8]| {
    let Some(end) = data.windows(4).position(|w| w == b"\r\n\r\n") else {
        return;
    };
    if end > MAX_REQUEST_HEAD {
        return;
    }
    let (head_bytes, leftover) = (&data[..end], &data[end + 4..]);
    let Ok(head) = parse_request_head(head_bytes) else {
        return;
    };
    let _ = head.headers_json();
    let _ = head.offered_subprotocols();
    if validate_upgrade(&head).is_err() {
        return;
    }
    let negotiated = deflate::negotiate(head.header_all("sec-websocket-extensions"));
    if let Some((params, value)) = &negotiated {
        assert_eq!(
            &params.header_value(),
            value,
            "negotiate's two answers disagree"
        );
    }

    let config = WebSocketConfig {
        max_message_size: Some(DEFAULT_MAX_MESSAGE_SIZE),
        max_frame_size: Some(DEFAULT_MAX_FRAME_SIZE),
        accept_unmasked_frames: false,
        ..Default::default()
    };
    let stream = deflate::DeflateStream::server(
        Drained,
        negotiated.map(|(p, _)| p),
        DEFAULT_MAX_MESSAGE_SIZE,
        DEFAULT_MAX_FRAME_SIZE,
        leftover.to_vec(),
    );
    let mut ws = complete(WebSocketStream::from_partially_read(
        stream,
        Vec::new(),
        Role::Server,
        Some(config),
    ));

    // Each message consumes at least a frame header, so this bounds the session.
    for _ in 0..leftover.len() / 2 + 2 {
        match complete(ws.next()) {
            Some(Ok(msg)) => {
                let len = match &msg {
                    Message::Text(t) => t.len(),
                    Message::Binary(b) | Message::Ping(b) | Message::Pong(b) => b.len(),
                    Message::Close(_) | Message::Frame(_) => 0,
                };
                assert!(
                    len <= DEFAULT_MAX_MESSAGE_SIZE,
                    "a {len}-byte message passed the {DEFAULT_MAX_MESSAGE_SIZE}-byte limit"
                );
            }
            Some(Err(_)) | None => return,
        }
    }
});

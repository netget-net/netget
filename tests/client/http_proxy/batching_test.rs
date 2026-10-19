//! Does the HTTP proxy client answer what came through the tunnel during a model call
//! together, when it batches — and does each read reach the model at all?
//!
//! The tunnel loop used to call the model inline beside an Idle/Processing/Accumulating
//! machine that could never leave Idle and cleared a queue nothing filled, so what arrived
//! during a call merged in the kernel buffer: batching off and on were indistinguishable. The
//! tunnel is now read on a registered task feeding a bounded queue (`client/inbound_queue.rs`).
//!
//! A local proxy answers the CONNECT for `default_target` with 200 and then plays the target
//! (see `batching_support`). Off: one model call per read. On: what arrived during the slow
//! first call is the next payload, joined.

use std::time::Duration;

use crate::client::batching_support::{assert_reads_join, Session};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::oneshot;

async fn peer(listener: TcpListener, go: oneshot::Receiver<()>) {
    let (sock, _) = tokio::time::timeout(Duration::from_secs(10), listener.accept())
        .await
        .expect("client never connected")
        .expect("accept");
    let mut sock = BufReader::new(sock);
    let mut line = String::new();
    loop {
        line.clear();
        sock.read_line(&mut line).await.expect("CONNECT head");
        if line == "\r\n" || line.is_empty() {
            break;
        }
    }
    let sock = sock.get_mut();
    sock.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
        .await
        .expect("write");
    // Its own write, after the tunnel is up.
    tokio::time::sleep(Duration::from_millis(200)).await;
    sock.write_all(b"alpha").await.expect("write");
    let _ = go.await;
    sock.write_all(b"bravo").await.expect("write");
    tokio::time::sleep(Duration::from_millis(200)).await;
    sock.write_all(b"charlie").await.expect("write");
    let mut sink = [0u8; 64];
    while matches!(sock.read(&mut sink).await, Ok(n) if n > 0) {}
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http_proxy_client_joins_or_separates_what_arrived_during_a_call() {
    assert_reads_join(
        &Session {
            protocol: "HTTP Proxy",
            startup_params: Some(serde_json::json!({ "default_target": "example.com:80" })),
            data_event: "http_proxy_response_received",
            alpha: ("data_hex", "616c706861"),
            connected: None,
        },
        peer,
    )
    .await;
}

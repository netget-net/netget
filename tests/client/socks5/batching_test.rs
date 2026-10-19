//! Does the SOCKS5 client answer what the target sent during a model call together, when it
//! batches — and does each read reach the model at all?
//!
//! The client used to call the model inline in its read loop beside an Idle/Processing/
//! Accumulating machine that could never leave Idle (the loop was sequential) and cleared a
//! queue nothing filled. What arrived during a call merged in the kernel buffer and came back
//! as one read, so batching off and on could not be told apart. The tunnel is now read on a
//! registered task feeding a bounded queue (`client/inbound_queue.rs`).
//!
//! A minimal no-auth SOCKS5 proxy completes the handshake and then plays the target (see
//! `batching_support`). Off: one model call per read. On: what arrived during the slow first
//! call is the next payload, joined.

use std::time::Duration;

use crate::client::batching_support::{assert_reads_join, Session};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

/// Complete a no-auth SOCKS5 greeting + CONNECT and return the tunnel socket.
pub async fn accept_socks5(listener: &TcpListener) -> TcpStream {
    let (mut sock, _) = tokio::time::timeout(Duration::from_secs(10), listener.accept())
        .await
        .expect("client never connected")
        .expect("accept");
    let mut head = [0u8; 2];
    sock.read_exact(&mut head).await.expect("greeting");
    let mut methods = vec![0u8; head[1] as usize];
    sock.read_exact(&mut methods).await.expect("methods");
    sock.write_all(&[0x05, 0x00]).await.expect("method");
    let mut req = [0u8; 4];
    sock.read_exact(&mut req).await.expect("connect");
    let addr_len = match req[3] {
        0x01 => 4,
        0x04 => 16,
        _ => {
            let mut l = [0u8; 1];
            sock.read_exact(&mut l).await.expect("len");
            l[0] as usize
        }
    };
    let mut rest = vec![0u8; addr_len + 2];
    sock.read_exact(&mut rest).await.expect("addr");
    sock.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await
        .expect("reply");
    sock
}

async fn peer(listener: TcpListener, go: oneshot::Receiver<()>) {
    let mut sock = accept_socks5(&listener).await;
    sock.write_all(b"alpha").await.expect("write");
    let _ = go.await;
    sock.write_all(b"bravo").await.expect("write");
    tokio::time::sleep(Duration::from_millis(200)).await;
    sock.write_all(b"charlie").await.expect("write");
    // Hold the tunnel open until the test drops the client.
    let mut sink = [0u8; 64];
    while matches!(sock.read(&mut sink).await, Ok(n) if n > 0) {}
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn socks5_client_joins_or_separates_what_arrived_during_a_call() {
    assert_reads_join(
        &Session {
            protocol: "socks5",
            startup_params: Some(serde_json::json!({ "target_addr": "example.com:80" })),
            data_event: "socks5_data_received",
            alpha: ("data", "alpha"),
            connected: None,
        },
        peer,
    )
    .await;
}

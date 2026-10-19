//! Does the FTP client answer control-channel lines that arrived during a model call together,
//! when it batches — and does each line reach the model at all?
//!
//! The client used to read and answer in one loop beside an Idle/Processing/Accumulating
//! machine that could never leave Idle and cleared a queue nothing filled. A server sends lines
//! the client did not just ask for — the rest of a multi-line reply, a 226 after a 150, the
//! replies to several commands sent in one answer — and those waited unread in the socket. The
//! control channel is now read on a registered task, one queued line each; with batching on,
//! everything waiting is one model call with one `ftp_response` event per line.

use std::time::Duration;

use crate::client::batching_support::{assert_one_event_per_message, Session};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;

async fn peer(listener: TcpListener, go: oneshot::Receiver<()>) {
    let (mut sock, _) = tokio::time::timeout(Duration::from_secs(10), listener.accept())
        .await
        .expect("client never connected")
        .expect("accept");
    sock.write_all(b"220 alpha\r\n").await.expect("write");
    let _ = go.await;
    sock.write_all(b"150 bravo\r\n").await.expect("write");
    tokio::time::sleep(Duration::from_millis(200)).await;
    sock.write_all(b"226 charlie\r\n").await.expect("write");
    let mut sink = [0u8; 64];
    while matches!(sock.read(&mut sink).await, Ok(n) if n > 0) {}
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ftp_client_answers_lines_that_arrived_during_a_call_together() {
    assert_one_event_per_message(
        &Session {
            protocol: "ftp",
            startup_params: None,
            data_event: "ftp_response",
            alpha: ("response", "alpha"),
            connected: None,
        },
        peer,
    )
    .await;
}

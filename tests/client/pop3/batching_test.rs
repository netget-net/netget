//! Does the POP3 client answer responses that arrived during a model call together, when it
//! batches?
//!
//! A POP3 server only ever answers, but a model often sends several commands in one answer
//! (`USER` then `PASS`, `LIST` then `RETR`), and the replies to the later ones arrive while the
//! model is still on the first. The client used to read inline between calls, so those replies
//! sat in the socket and each became its own call whatever batching said. Responses are now
//! framed on a registered task into a queue; with batching on, everything waiting is one model
//! call, one `pop3_response_received` event per response.
//!
//! The model answers the greeting with three `NOOP`s; the fixture answers the first
//! (`alpha`), and the other two only once the model is busy with it.

use std::time::Duration;

use crate::client::batching_support::{assert_one_event_per_message, Session};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::oneshot;

async fn peer(listener: TcpListener, go: oneshot::Receiver<()>) {
    let (sock, _) = tokio::time::timeout(Duration::from_secs(10), listener.accept())
        .await
        .expect("client never connected")
        .expect("accept");
    let mut sock = BufReader::new(sock);
    sock.get_mut()
        .write_all(b"+OK fixture ready\r\n")
        .await
        .expect("write");
    for _ in 0..3 {
        let mut line = String::new();
        sock.read_line(&mut line).await.expect("command");
        assert_eq!(line, "NOOP\r\n");
    }
    let sock = sock.get_mut();
    sock.write_all(b"+OK alpha\r\n").await.expect("write");
    let _ = go.await;
    sock.write_all(b"+OK bravo\r\n").await.expect("write");
    tokio::time::sleep(Duration::from_millis(200)).await;
    sock.write_all(b"+OK charlie\r\n").await.expect("write");
    let mut sink = [0u8; 64];
    while matches!(sock.read(&mut sink).await, Ok(n) if n > 0) {}
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pop3_client_answers_responses_that_arrived_during_a_call_together() {
    let noop = serde_json::json!({"type": "send_pop3_command", "command": "NOOP"});
    assert_one_event_per_message(
        &Session {
            protocol: "pop3",
            startup_params: None,
            data_event: "pop3_response_received",
            alpha: ("response", "alpha"),
            connected: Some(("pop3_connected", serde_json::json!([noop, noop, noop]))),
        },
        peer,
    )
    .await;
}

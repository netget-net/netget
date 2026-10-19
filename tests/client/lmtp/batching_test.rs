//! Does the LMTP client answer transaction results that arrived during a model call together,
//! when it batches?
//!
//! The session runs the model's `lmtp_send`s one after another while the dispatcher is still
//! asking the model about the first result, so with three in one answer the second and third
//! results queue during that call. With batching on the dispatcher answers everything waiting
//! in one call, one `lmtp_result` event each; off, one call per result.
//!
//! The fixture refuses every recipient (the client then resets), and holds the second
//! transaction's MAIL reply until the model is busy with the first result.

use std::time::Duration;

use crate::client::batching_support::{assert_one_event_per_message, Session};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

async fn line(r: &mut BufReader<TcpStream>) -> String {
    let mut s = String::new();
    r.read_line(&mut s).await.expect("read");
    s
}

async fn peer(listener: TcpListener, go: oneshot::Receiver<()>) {
    let (stream, _) = tokio::time::timeout(Duration::from_secs(10), listener.accept())
        .await
        .expect("client never connected")
        .expect("accept");
    let mut r = BufReader::new(stream);
    r.get_mut().write_all(b"220 fixture\r\n").await.unwrap();
    assert!(line(&mut r).await.starts_with("LHLO "));
    r.get_mut().write_all(b"250 fixture\r\n").await.unwrap();
    let mut go = Some(go);
    for marker in ["alpha", "bravo", "charlie"] {
        assert!(line(&mut r).await.starts_with("MAIL FROM:"));
        match marker {
            "bravo" => {
                let _ = go.take().expect("once").await;
            }
            "charlie" => tokio::time::sleep(Duration::from_millis(200)).await,
            _ => {}
        }
        r.get_mut().write_all(b"250 2.1.0 ok\r\n").await.unwrap();
        assert_eq!(
            line(&mut r).await,
            format!("RCPT TO:<{marker}@example.test>\r\n")
        );
        r.get_mut()
            .write_all(b"550 5.1.1 no such user\r\n")
            .await
            .unwrap();
        assert_eq!(line(&mut r).await, "RSET\r\n");
        r.get_mut().write_all(b"250 2.0.0 ok\r\n").await.unwrap();
    }
    let mut sink = [0u8; 64];
    while matches!(r.read(&mut sink).await, Ok(n) if n > 0) {}
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lmtp_client_answers_results_that_arrived_during_a_call_together() {
    let send = |to: &str| {
        serde_json::json!({"type": "lmtp_send", "from": "s@example.test", "to": [to],
            "subject": "Hi", "body": "Hello"})
    };
    assert_one_event_per_message(
        &Session {
            protocol: "lmtp",
            startup_params: None,
            data_event: "lmtp_result",
            alpha: ("recipients", "alpha"),
            connected: Some((
                "lmtp_connected",
                serde_json::json!([
                    send("alpha@example.test"),
                    send("bravo@example.test"),
                    send("charlie@example.test"),
                ]),
            )),
        },
        peer,
    )
    .await;
}

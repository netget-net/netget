//! Does the ManageSieve client answer responses that arrived during a model call together,
//! when it batches?
//!
//! The session runs the model's commands one after another while the dispatcher is still
//! asking the model about the first response, so with three in one answer the second and third
//! responses queue during that call. With batching on the dispatcher answers everything waiting
//! in one call, one `managesieve_response` event each; off, one call per response.
//!
//! The fixture offers SASL PLAIN, accepts the login, and answers three `LISTSCRIPTS` with an
//! `OK` whose message is the marker — the second and third only once the model is busy.

use std::time::Duration;

use crate::client::batching_support::{assert_one_event_per_message, Session};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::oneshot;

async fn peer(listener: TcpListener, go: oneshot::Receiver<()>) {
    let (stream, _) = tokio::time::timeout(Duration::from_secs(10), listener.accept())
        .await
        .expect("client never connected")
        .expect("accept");
    let mut r = BufReader::new(stream);
    r.get_mut()
        .write_all(b"\"IMPLEMENTATION\" \"fixture\"\r\n\"SASL\" \"PLAIN\"\r\n\"SIEVE\" \"fileinto\"\r\nOK \"ready\"\r\n")
        .await
        .unwrap();
    let mut line = String::new();
    r.read_line(&mut line).await.unwrap();
    assert!(line.starts_with("AUTHENTICATE "), "{line:?}");
    r.get_mut()
        .write_all(b"OK \"logged in\"\r\n")
        .await
        .unwrap();
    let mut go = Some(go);
    for marker in ["alpha", "bravo", "charlie"] {
        line.clear();
        r.read_line(&mut line).await.unwrap();
        assert_eq!(line, "LISTSCRIPTS\r\n");
        match marker {
            "bravo" => {
                let _ = go.take().expect("once").await;
            }
            "charlie" => tokio::time::sleep(Duration::from_millis(200)).await,
            _ => {}
        }
        r.get_mut()
            .write_all(format!("OK \"{marker}\"\r\n").as_bytes())
            .await
            .unwrap();
    }
    let mut sink = [0u8; 64];
    while matches!(r.read(&mut sink).await, Ok(n) if n > 0) {}
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn managesieve_client_answers_responses_that_arrived_during_a_call_together() {
    let list = serde_json::json!({"type": "managesieve_list"});
    assert_one_event_per_message(
        &Session {
            protocol: "managesieve",
            startup_params: Some(serde_json::json!({"user": "alice", "password": "secret"})),
            data_event: "managesieve_response",
            alpha: ("message", "alpha"),
            connected: Some((
                "managesieve_connected",
                serde_json::json!([list, list, list]),
            )),
        },
        peer,
    )
    .await;
}

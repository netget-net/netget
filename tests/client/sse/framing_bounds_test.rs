//! NetGet's SSE client against a hostile 127.0.0.1 server that never ends a line: a status line
//! followed by 1 MiB with no newline, and a chunked stream whose chunk-size line is 64 KiB of
//! `f`. Each line read is bounded (`MAX_HEAD_BYTES`, `MAX_CHUNK_LINE_BYTES`), so the client must
//! end the stream with `sse_stream_ended {reason: error}` naming the bound, well before its
//! 30 s I/O deadline, and not reconnect. No LLM calls: static handlers disconnect on the end.
use netget::cli::management::ClientForm;
use netget::client::sse::{MAX_CHUNK_LINE_BYTES, MAX_HEAD_BYTES};
use netget::state::app_state::AppState;
use netget::state::{AccessLogOwner, ClientId, ClientStatus};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

/// Well inside `IO_TIMEOUT` (30 s): a bound that only fired at the deadline fails this.
const WITHIN: Duration = Duration::from_secs(15);

/// A server that answers every connection with `head` and then `filler` bytes of `byte`, never
/// a newline, and holds the socket open. Returns its address and how many connections it took.
async fn hostile_server(head: &'static [u8], byte: u8, filler: usize) -> (u16, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let accepted = Arc::new(AtomicUsize::new(0));
    let count = accepted.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            count.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let mut request = Vec::new();
                let mut chunk = [0u8; 1024];
                while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                    match socket.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => request.extend_from_slice(&chunk[..n]),
                    }
                }
                let _ = socket.write_all(head).await;
                // Blocks once the client stops reading; the client closing ends it.
                let _ = socket.write_all(&vec![byte; filler]).await;
                let mut sink = [0u8; 1024];
                while matches!(socket.read(&mut sink).await, Ok(n) if n > 0) {}
            });
        }
    });
    (port, accepted)
}

async fn client(state: &AppState, port: u16) -> ClientId {
    let (tx, _) = mpsc::unbounded_channel();
    ClientForm {
        protocol: "sse".into(),
        remote_addr: Some(format!("http://127.0.0.1:{port}/events")),
        instruction: Some("Read the stream".into()),
        event_handlers: Some(vec![
            json!({"event_pattern":"sse_stream_ended",
                   "handler":{"type":"static","actions":[{"type":"disconnect"}]}}),
            json!({"event_pattern":"*","handler":{"type":"static","actions":[]}}),
        ]),
        ..Default::default()
    }
    .create(
        state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1"),
        tx,
    )
    .await
    .expect("connect")
}

/// The `sse_stream_ended` the client reported, once it has disconnected.
async fn ended(state: &AppState, id: ClientId) -> Value {
    tokio::time::timeout(WITHIN, async {
        loop {
            let disconnected = matches!(
                state.get_client(id).await.map(|c| c.status),
                Some(ClientStatus::Disconnected)
            );
            let found = state
                .list_access_logs_for(Some(AccessLogOwner::Client(id.as_u32())), None)
                .await
                .iter()
                .map(|e| serde_json::to_value(e).unwrap())
                .find(|e| e["event_type"] == "sse_stream_ended");
            if let (true, Some(e)) = (disconnected, found) {
                return e["request"].clone();
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the client neither reported the broken stream nor disconnected in time")
}

#[tokio::test]
async fn a_response_head_with_no_line_end_is_refused_at_the_head_bound() {
    let (port, accepted) = hostile_server(b"HTTP/1.1 200 ", b'a', 1024 * 1024).await;
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    let id = client(&state, port).await;
    let ev = ended(&state, id).await;
    assert_eq!(ev["reason"], "error", "{ev}");
    let error = ev["error"].as_str().unwrap_or_default();
    assert!(
        error.contains(&format!("response head over {MAX_HEAD_BYTES} bytes")),
        "{ev}"
    );
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        accepted.load(Ordering::SeqCst),
        1,
        "a broken head is not retried"
    );
}

#[tokio::test]
async fn a_chunk_size_line_with_no_line_end_is_refused_at_the_chunk_line_bound() {
    let (port, accepted) = hostile_server(
        b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n",
        b'f',
        64 * 1024,
    )
    .await;
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    let id = client(&state, port).await;
    let ev = ended(&state, id).await;
    assert_eq!(ev["reason"], "error", "{ev}");
    let error = ev["error"].as_str().unwrap_or_default();
    assert!(
        error.contains(&format!(
            "chunk-size line over {MAX_CHUNK_LINE_BYTES} bytes"
        )),
        "{ev}"
    );
    assert!(
        ev.get("reconnecting_in_ms").is_none(),
        "broken framing is not reconnected by itself: {ev}"
    );
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        accepted.load(Ordering::SeqCst),
        1,
        "broken framing is not retried"
    );
}

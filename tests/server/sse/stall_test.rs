//! A subscriber that stops reading cannot stall the others.
//!
//! Two raw subscribers open `/news`; one reads everything, the other never reads. Large
//! broadcasts fill the stalled one's socket buffers, after which each write to it makes no
//! progress. Every broadcast must still complete within `SUBSCRIBER_WRITE_TIMEOUT` plus slack,
//! the reading subscriber must receive the last one, and the stalled stream must be dropped:
//! its connection reaches EOF once the bytes already buffered for it are read. No LLM calls: a
//! python handler answers every request.
use netget::cli::management::ServerForm;
use netget::server::sse::SUBSCRIBER_WRITE_TIMEOUT;
use netget::state::app_state::AppState;
use serde_json::json;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

const HANDLER: &str = r#"import json,sys
e=json.load(sys.stdin)['event']; p=e['path']; q=e['query']
if p=='/news':
  a=[{'type':'sse_accept'}]
elif p=='/post':
  a=[{'type':'sse_broadcast','path':'/news','event':'post','id':q.get('i','0'),'data':q.get('tag','')+'x'*65536},{'type':'sse_respond','status':202,'body':'queued'}]
else:
  a=[{'type':'sse_respond','status':404,'body':'no'}]
print(json.dumps({'actions':a}))"#;

async fn server() -> (AppState, u16) {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    let (tx, _) = mpsc::unbounded_channel();
    let id = ServerForm {
        protocol: "sse".into(),
        port: Some(0),
        host: Some("127.0.0.1".into()),
        instruction: Some("Stream news".into()),
        event_handlers: Some(vec![
            json!({"event_pattern":"*","handler":{"type":"script","language":"python","code":HANDLER}}),
        ]),
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .unwrap();
    let port = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if let Some(a) = state.get_server(id).await.and_then(|s| s.local_addr) {
                break a.port();
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the SSE server never bound");
    (state, port)
}

/// Opens `/news` and reads until the stream's response head has arrived.
async fn subscribe(port: u16) -> TcpStream {
    let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    s.write_all(b"GET /news HTTP/1.1\r\nHost: localhost\r\nAccept: text/event-stream\r\n\r\n")
        .await
        .unwrap();
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        let n = tokio::time::timeout(Duration::from_secs(30), s.read(&mut byte))
            .await
            .expect("no response head")
            .unwrap();
        assert!(n > 0, "the stream closed before its head");
        head.push(byte[0]);
    }
    assert!(
        head.starts_with(b"HTTP/1.1 200"),
        "{}",
        String::from_utf8_lossy(&head)
    );
    s
}

/// Asks for one broadcast and returns once its 202 has been read.
async fn post(port: u16, i: usize, tag: &str) {
    let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    s.write_all(
        format!(
            "GET /post?i={i}&tag={tag} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    let mut answer = Vec::new();
    s.read_to_end(&mut answer).await.unwrap();
    assert!(
        answer.starts_with(b"HTTP/1.1 202"),
        "{}",
        String::from_utf8_lossy(&answer[..answer.len().min(200)])
    );
}

#[tokio::test]
async fn a_subscriber_that_stops_reading_is_dropped_without_stalling_broadcasts() {
    let (_state, port) = server().await;
    let stalled = subscribe(port).await;
    let mut reader = subscribe(port).await;

    // The reading subscriber drains its stream and notes when the final broadcast arrives.
    let seen_last = Arc::new(AtomicBool::new(false));
    let drain = {
        let seen_last = seen_last.clone();
        tokio::spawn(async move {
            let mut window = Vec::new();
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                match reader.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        window.extend_from_slice(&buf[..n]);
                        if window.windows(13).any(|w| w == b"data: LASTONE") {
                            seen_last.store(true, Ordering::SeqCst);
                            break;
                        }
                        let keep = window.len().saturating_sub(16);
                        window.drain(..keep);
                    }
                }
            }
        })
    };

    // 64 broadcasts of 64 KiB is far more than both socket buffers of the stalled stream hold,
    // so writes to it stop making progress partway through.
    let started = Instant::now();
    let bound = SUBSCRIBER_WRITE_TIMEOUT + Duration::from_secs(10);
    for i in 0..64 {
        let one = Instant::now();
        tokio::time::timeout(bound, post(port, i, "p"))
            .await
            .unwrap_or_else(|_| panic!("broadcast {i} stalled for more than {bound:?}"));
        assert!(one.elapsed() < bound);
    }
    tokio::time::timeout(bound, post(port, 64, "LASTONE"))
        .await
        .expect("the final broadcast stalled");
    assert!(
        started.elapsed() < Duration::from_secs(120),
        "broadcasts took {:?}",
        started.elapsed()
    );

    tokio::time::timeout(Duration::from_secs(30), drain)
        .await
        .expect("the reading subscriber never got the final broadcast")
        .unwrap();
    assert!(seen_last.load(Ordering::SeqCst));

    // The stalled stream was dropped: reading what was buffered for it ends in EOF.
    let mut stalled = stalled;
    let mut buf = vec![0u8; 256 * 1024];
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            match stalled.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
    })
    .await
    .expect("the stalled subscriber's stream was never closed");
}

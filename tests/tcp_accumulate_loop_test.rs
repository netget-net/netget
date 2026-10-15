//! The accumulate loop must consume its queue.
//!
//! `handle_data_with_actions` queues data that arrives while an event is being
//! handled, then loops to process it. The payload was bound outside that loop
//! and the queue was never drained, so a single line of input produced an
//! endless stream of identical responses — one model call per iteration,
//! forever. tcp, tls, socket_file and quic all shared the shape.
//!
//! This drives the real server with a static handler (no model involved) and a
//! client that writes twice in quick succession, which is what fills the queue.


use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use netget::state::{AccessLogOwner, ServerId};
use tokio::sync::mpsc;

async fn wait_for_port(state: &AppState, id: ServerId) -> u16 {
    for _ in 0..100 {
        if let Some(s) = state.get_server(id).await {
            if let Some(addr) = s.local_addr {
                return addr.port();
            }
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("server never bound a port");
}

/// Multi-threaded: the blocking socket I/O below would starve the server task
/// on a current-thread runtime.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn queued_data_is_consumed_rather_than_reprocessed_forever() {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".to_string());
    state
        .set_llm_client(netget::llm::OllamaClient::new(
            "http://127.0.0.1:1".to_string(),
        ))
        .await;
    let (tx, _rx) = mpsc::unbounded_channel();

    // Static handlers: every event is answered deterministically, so the only
    // thing that can produce more responses is the loop itself.
    let form = ServerForm {
        protocol: "tcp".to_string(),
        port: Some(0),
        event_handlers: Some(vec![
            serde_json::json!({
                "event_pattern": "tcp_data_received",
                "handler": {
                    "type": "static",
                    "actions": [{ "type": "send_tcp_data", "data": "ack" }]
                }
            }),
            serde_json::json!({
                "event_pattern": "*",
                "handler": { "type": "static", "actions": [] }
            }),
        ]),
        ..Default::default()
    };
    let server_id = form.create(&state, tx).await.expect("create tcp server");
    let port = wait_for_port(&state, server_id).await;

    // Write several times back-to-back: whatever lands while the first event is
    // in flight goes on the queue, which is the path under test.
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    for line in ["one\r\n", "two\r\n", "three\r\n"] {
        stream.write_all(line.as_bytes()).expect("write");
    }
    stream.flush().unwrap();

    // Drain whatever the server sends for a bounded window.
    let mut received = Vec::new();
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    let mut chunk = [0u8; 4096];
    while std::time::Instant::now() < deadline {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => received.extend_from_slice(&chunk[..n]),
            Err(_) => break, // read timeout: nothing more coming
        }
    }
    drop(stream);

    // Give the server a moment to settle, then count what it logged.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let entries = state
        .list_access_logs_for(Some(AccessLogOwner::Server(server_id.as_u32())), None)
        .await;
    let data_events = entries
        .iter()
        .filter(|e| e.event_type == "tcp_data_received")
        .count();

    // Three writes can coalesce or queue, so the exact count is not fixed —
    // but it is bounded by the number of writes. Before the fix this ran away
    // without limit (15+ for a single line).
    assert!(
        data_events >= 1,
        "the server should have seen the data at all"
    );
    assert!(
        data_events <= 6,
        "runaway loop: {data_events} data events for 3 writes — the queue is \
         being reprocessed instead of consumed"
    );

    let acks = String::from_utf8_lossy(&received).matches("ack").count();
    assert!(
        acks <= 6,
        "runaway responses: {acks} acks for 3 writes (payload: {:?})",
        String::from_utf8_lossy(&received)
    );

    // And the connection's byte counters must reflect the traffic; TCP was the
    // one server that never updated them, so every peer read ↓0 ↑0.
    let server = state.get_server(server_id).await.expect("server exists");
    let counted: u64 = server
        .connections
        .values()
        .map(|c| c.bytes_received)
        .chain(server.recent_connections.iter().map(|c| c.bytes_received))
        .sum();
    assert!(
        counted > 0,
        "the connection's received-byte counter should not be zero after traffic"
    );
}

/// A request whose handling fails must still be visible: the request pane going
/// blank exactly when the model is unreachable is the opposite of useful.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_failed_event_is_still_recorded() {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".to_string());
    state
        .set_llm_client(netget::llm::OllamaClient::new(
            "http://127.0.0.1:1".to_string(),
        ))
        .await;
    let (tx, _rx) = mpsc::unbounded_channel();

    // No handlers at all, and an unreachable model: handling must fail.
    let form = ServerForm {
        protocol: "tcp".to_string(),
        port: Some(0),
        ..Default::default()
    };
    let server_id = form.create(&state, tx).await.expect("create tcp server");
    let port = wait_for_port(&state, server_id).await;

    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    stream.write_all(b"hello\r\n").expect("write");
    stream.flush().unwrap();

    let mut recorded = None;
    for _ in 0..200 {
        let entries = state
            .list_access_logs_for(Some(AccessLogOwner::Server(server_id.as_u32())), None)
            .await;
        if let Some(entry) = entries
            .into_iter()
            .find(|e| e.event_type == "tcp_data_received")
        {
            recorded = Some(entry);
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let entry = recorded.expect(
        "a request that failed to be handled must still appear in the access log — \
         otherwise the dashboard shows nothing when the model is down",
    );
    let response = serde_json::to_string(&entry.response).unwrap_or_default();
    assert!(
        response.contains("FAILED"),
        "the recorded response should say it failed, got {response}"
    );
}

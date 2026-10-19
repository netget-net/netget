//! Does the Matrix client answer the room messages that arrived during a model call together,
//! when it batches?
//!
//! A raw listener plays the homeserver: login, the first `/sync`, then one message per
//! long-polled `/sync` as the test releases them — `first`, which the mock model answers
//! slowly, then `second` and, 200 ms later, `third` while that call runs. They wait in the
//! client's dispatcher queue. Batching off is the control, in the same test as the claim:
//! three model calls, one per message. Batching on: two, the second triggered by `third`
//! with `second` listed above it.

use crate::helpers::mock_builder::MockLlmBuilder;
use crate::helpers::mock_ollama::MockOllamaServer;
use netget::cli::management::ClientForm;
use netget::state::app_state::AppState;
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};

const EVENT: &str = "matrix_message";
const ROOM: &str = "!room:batching.test";

fn text(data: &Value) -> String {
    data["content"]["body"]
        .as_str()
        .unwrap_or_default()
        .to_string()
}

async fn calls(mock: &MockOllamaServer) -> Vec<(Value, String)> {
    mock.recorded_calls()
        .await
        .into_iter()
        .filter(|c| c.context.event_type.as_deref() == Some(EVENT))
        .map(|c| (c.context.event_data.clone(), c.context.prompt.clone()))
        .collect()
}

async fn wait_for(mock: &MockOllamaServer, want: &str) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        let calls = calls(mock).await;
        if calls.iter().any(|(d, _)| text(d) == want) {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "`{want}` never reached the model; calls: {calls:#?}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// One request: its request line (the head is read whole, the body by Content-Length).
async fn request(socket: &mut TcpStream) -> Option<String> {
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        let mut b = [0u8];
        if socket.read(&mut b).await.ok()? == 0 {
            return None;
        }
        head.push(b[0]);
    }
    let head = String::from_utf8_lossy(&head).to_string();
    let length = head
        .lines()
        .find_map(|l| {
            l.to_ascii_lowercase()
                .strip_prefix("content-length:")
                .map(|v| v.trim().parse::<usize>().unwrap_or(0))
        })
        .unwrap_or(0);
    let mut body = vec![0u8; length];
    socket.read_exact(&mut body).await.ok()?;
    head.lines().next().map(str::to_string)
}

async fn answer(socket: &mut TcpStream, body: Value) {
    let body = body.to_string();
    let _ = socket
        .write_all(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .as_bytes(),
        )
        .await;
}

/// A homeserver whose long-polled `/sync` returns one released message each.
async fn homeserver(listener: TcpListener, messages: mpsc::Receiver<String>) {
    let messages = Arc::new(Mutex::new(messages));
    let mut batch = 0u64;
    loop {
        let Ok((mut socket, _)) = listener.accept().await else {
            return;
        };
        let messages = messages.clone();
        batch += 1;
        tokio::spawn(async move {
            let Some(line) = request(&mut socket).await else {
                return;
            };
            if line.contains("/login") {
                answer(
                    &mut socket,
                    json!({"user_id":"@me:batching.test","device_id":"DEV","access_token":"tok"}),
                )
                .await;
            } else if line.contains("/sync") && !line.contains("since=") {
                answer(
                    &mut socket,
                    json!({"next_batch":"s0","rooms":{"join":{(ROOM):{}}}}),
                )
                .await;
            } else if line.contains("/sync") {
                let next = format!("s{batch}");
                let released =
                    tokio::time::timeout(Duration::from_secs(20), messages.lock().await.recv())
                        .await;
                let events = match released {
                    Ok(Some(body)) => json!([{
                        "type": "m.room.message",
                        "sender": "@bob:batching.test",
                        "event_id": format!("${body}"),
                        "content": {"msgtype": "m.text", "body": body},
                    }]),
                    _ => json!([]),
                };
                answer(
                    &mut socket,
                    json!({"next_batch": next, "rooms": {"join": {(ROOM): {"timeline": {"events": events}}}}}),
                )
                .await;
            } else {
                answer(&mut socket, json!({})).await;
            }
        });
    }
}

async fn session(batching: bool) -> Vec<(Value, String)> {
    let mock = MockOllamaServer::start(
        MockLlmBuilder::new()
            .on_event(EVENT)
            .and_event_data_contains("content", "first")
            .respond_with_actions(json!([]))
            .after_delay(Duration::from_millis(1500))
            .expect_calls(1)
            .and()
            .on_any()
            .respond_with_actions(json!([]))
            .expect_at_least(0)
            .build(),
    )
    .await
    .expect("mock ollama");
    let state = AppState::new_with_options(false, mock.base_url());
    let llm = netget::llm::OllamaClient::new(mock.base_url());
    state.set_llm_client(llm.clone()).await;

    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (release, released) = mpsc::channel::<String>(8);
    let server = tokio::spawn(homeserver(listener, released));
    let (tx, _rx) = mpsc::unbounded_channel();
    let id = ClientForm {
        protocol: "matrix".into(),
        remote_addr: Some(format!("127.0.0.1:{port}")),
        instruction: Some("Note what people say.".into()),
        startup_params: Some(json!({"user": "me", "password": "pw"})),
        batching: Some(batching),
        ..Default::default()
    }
    .create(&state, llm, tx)
    .await
    .expect("create client");

    release.send("first".into()).await.unwrap();
    wait_for(&mock, "first").await;
    release.send("second".into()).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    release.send("third".into()).await.unwrap();
    wait_for(&mock, "third").await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    let calls = calls(&mock).await;
    let _ = state.remove_client(id).await;
    server.abort();
    calls
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn matrix_client_answers_messages_that_arrived_during_a_call_together() {
    let separate = session(false).await;
    let texts: Vec<String> = separate.iter().map(|(d, _)| text(d)).collect();
    assert_eq!(
        texts,
        ["first", "second", "third"],
        "CONTROL FAILED: with batching off each message must be its own model call"
    );

    let batched = session(true).await;
    let texts: Vec<String> = batched.iter().map(|(d, _)| text(d)).collect();
    assert_eq!(
        texts,
        ["first", "third"],
        "the two messages that arrived during the first call must be one model call, \
         triggered by the newest"
    );
    let prompt = &batched[1].1;
    let before = &prompt[..prompt.rfind(&format!("Event: {EVENT}")).expect("trigger")];
    assert!(
        before
            .lines()
            .any(|l| l.starts_with(&format!("(1) {EVENT} ")) && l.contains(r#""body":"second""#)),
        "the earlier message must be listed as arrived and not yet answered:\n{prompt}"
    );
    assert!(
        before.contains("answers all 2 together"),
        "the model must be told it answers both:\n{prompt}"
    );
}

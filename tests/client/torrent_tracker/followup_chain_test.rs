//! The tracker client acts on what the model answers a *response* event with.
//!
//! `notify_response` used to destructure the model's answer as
//! `Ok(ClientLlmResult { memory_updates, .. })` — the actions dropped by the `..`. Every chain
//! was one step deep: the model asked for an announce, the tracker's peer list came back, the
//! model was told about it, chose what to do next, and was ignored. A tracker client could
//! make exactly one request per instruction and then went deaf.
//!
//! This drives the real thing: a loopback stub tracker plus the in-process mock LLM, and the
//! assertion is that the stub sees **both** requests. Before the fix the second one never
//! happened.
//!
//! **One rule, branching on the event data — deliberately.** The connect-event and the real
//! announce reply are both `tracker_announce_response` (the client reuses that event type to
//! greet the model on connect). Two rules on one event id is the most common mocking mistake
//! in this repo: the first answers every occurrence and the second reports zero calls. So the
//! single rule reads the event and decides, which is also what makes "then" expressible.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features torrent-tracker --test client -- torrent_tracker::followup --test-threads=100


use std::sync::Arc;
use std::time::Duration;

use crate::helpers::mock_builder::MockLlmBuilder;
use crate::helpers::mock_ollama::MockOllamaServer;
use netget::cli::management::ClientForm;
use netget::state::app_state::AppState;
use netget::state::ClientId;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, Mutex};

/// Read one whole HTTP/1.1 request off the socket.
async fn read_request(socket: &mut tokio::net::TcpStream) -> Option<String> {
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let n = socket.read(&mut chunk).await.ok()?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        let text = String::from_utf8_lossy(&buf).to_string();
        if text.contains("\r\n\r\n") {
            return Some(text);
        }
    }
    if buf.is_empty() {
        None
    } else {
        Some(String::from_utf8_lossy(&buf).to_string())
    }
}

/// Loopback stub tracker. Records every request line it is asked for and answers each with a
/// minimal bencoded body — `TrackerResponse`/`ScrapeResponse` fields are all optional, so an
/// interval and peer counts are enough for both.
async fn spawn_stub_tracker() -> (u16, Arc<Mutex<Vec<String>>>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_task = seen.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            let seen = seen_task.clone();
            tokio::spawn(async move {
                let request = read_request(&mut socket).await.unwrap_or_default();
                seen.lock().await.push(request);
                let body = "d8:intervali1800e8:completei1e10:incompletei0ee";
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\
                     Connection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.flush().await;
                let _ = socket.shutdown().await;
            });
        }
    });
    (port, seen)
}

async fn wait_for_request(seen: &Arc<Mutex<Vec<String>>>, needle: &str, secs: u64) -> bool {
    for _ in 0..(secs * 40) {
        if seen.lock().await.iter().any(|r| r.contains(needle)) {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    false
}

#[tokio::test]
async fn the_answer_to_an_announce_response_is_carried_out() {
    let (tracker_port, seen) = spawn_stub_tracker().await;

    // One rule. `tracker_announce_response` arrives twice with different shapes: the client
    // greets the model on connect with `status: "connected"`, and the tracker's real reply
    // carries `interval`. Branching inside the generator is how "then" is expressed here.
    let mock = MockOllamaServer::start(
        MockLlmBuilder::new()
            .on_event("tracker_announce_response")
            .respond_with_actions_from_event(|event| {
                if event.get("status").and_then(|v| v.as_str()) == Some("connected") {
                    serde_json::json!([{
                        "type": "tracker_announce",
                        "info_hash": "firstannouncemarker1",
                        "peer_id": "-NG0001-followupchain",
                        "port": 6881,
                        "uploaded": 0,
                        "downloaded": 0,
                        "left": 0,
                        "event": "started"
                    }])
                } else {
                    // The follow-up. This is the action that used to be discarded.
                    serde_json::json!([{
                        "type": "tracker_scrape",
                        "info_hash": "followupscrapemarker"
                    }])
                }
            })
            .expect_at_least(2)
            .and()
            // The scrape's own reply ends the chain, so it cannot run away.
            .on_event("tracker_scrape_response")
            .respond_with_actions(serde_json::json!([{ "type": "disconnect" }]))
            .expect_at_least(1)
            .build(),
    )
    .await
    .expect("mock ollama");

    let state = AppState::new_with_options(false, mock.base_url());
    state
        .set_llm_client(netget::llm::OllamaClient::new(mock.base_url()))
        .await;

    let (tx, _rx) = mpsc::unbounded_channel();
    let _client_id: ClientId = ClientForm {
        protocol: "torrent_tracker".to_string(),
        remote_addr: Some(format!("http://127.0.0.1:{tracker_port}/announce")),
        instruction: Some("Announce, then scrape what the tracker reports.".to_string()),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new(mock.base_url()),
        tx.clone(),
    )
    .await
    .expect("create torrent tracker client");

    assert!(
        wait_for_request(&seen, "firstannouncemarker1", 20).await,
        "the connect-event announce never reached the stub tracker: {:?}",
        seen.lock().await
    );

    // The whole point. This request exists only if the model's answer to
    // `tracker_announce_response` was executed.
    assert!(
        wait_for_request(&seen, "followupscrapemarker", 20).await,
        "the follow-up scrape never reached the stub tracker — the model's answer to \
         tracker_announce_response was discarded: {:?}",
        seen.lock().await
    );

    mock.wait_for_expectations(20).await;
    mock.verify_calls().await.expect("mock expectations");
}

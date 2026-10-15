//! The dashboard's `[ send ]` path on an Elasticsearch client: `AppState::send_to_client`
//! injects an action from outside the client's own tasks, the client's command loop runs it
//! through the same `apply_action` the LLM path uses, and the request really reaches a
//! listener on loopback.
//!
//! Zero LLM calls: the client's LLM points at an unreachable URL, so the connected-event call
//! fails - the loop has to tolerate that, which is part of what this verifies. Nothing here
//! contacts a real Elasticsearch cluster; the stub is a plain TCP listener on 127.0.0.1.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features elasticsearch --test client -- elasticsearch::command_channel --test-threads=100


use std::sync::{Arc, Mutex};
use std::time::Duration;

use netget::cli::management::ClientForm;
use netget::state::app_state::AppState;
use netget::state::client_handles::ClientSendOutcome;
use netget::state::{AccessLogOwner, ClientId};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

/// A canned-response HTTP listener on loopback. Records every request it saw so a test can
/// prove the injected action actually put bytes on the wire.
struct HttpStub {
    port: u16,
    seen: Arc<Mutex<Vec<String>>>,
}

impl HttpStub {
    fn saw(&self, needle: &str) -> bool {
        self.seen
            .lock()
            .map(|v| v.iter().any(|r| r.contains(needle)))
            .unwrap_or(false)
    }
}

fn content_length(head: &str) -> usize {
    head.lines()
        .find(|l| l.to_ascii_lowercase().starts_with("content-length:"))
        .and_then(|l| l.split(':').nth(1))
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(0)
}

async fn spawn_http_stub(
    status: &'static str,
    content_type: &'static str,
    body: &'static str,
) -> HttpStub {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_task = seen.clone();

    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            let seen = seen_task.clone();
            tokio::spawn(async move {
                let mut buf: Vec<u8> = Vec::new();
                let mut chunk = [0u8; 4096];
                loop {
                    match sock.read(&mut chunk).await {
                        Ok(0) => break,
                        Ok(n) => {
                            buf.extend_from_slice(&chunk[..n]);
                            if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                                let head = String::from_utf8_lossy(&buf[..pos]).to_string();
                                if buf.len() - (pos + 4) >= content_length(&head) {
                                    break;
                                }
                            }
                        }
                        Err(_) => return,
                    }
                }
                if let Ok(mut guard) = seen.lock() {
                    guard.push(String::from_utf8_lossy(&buf).to_string());
                }
                let resp = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.flush().await;
                let _ = sock.shutdown().await;
            });
        }
    });

    HttpStub { port, seen }
}

async fn new_state() -> AppState {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".to_string());
    state
        .set_llm_client(netget::llm::OllamaClient::new(
            "http://127.0.0.1:1".to_string(),
        ))
        .await;
    state
}

async fn wait_for_client_handle(state: &AppState, id: ClientId) {
    for _ in 0..1_000 {
        if state.has_client_handle(id).await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!(
        "Elasticsearch client #{} never registered a command handle",
        id.as_u32()
    );
}

async fn wait_for_log_containing(state: &AppState, owner: AccessLogOwner, needle: &str) {
    for _ in 0..1_000 {
        for entry in state.list_access_logs_for(Some(owner), None).await {
            if serde_json::to_string(&entry)
                .unwrap_or_default()
                .contains(needle)
            {
                return;
            }
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("no access-log entry for {owner:?} containing {needle:?}");
}

#[tokio::test]
async fn injected_search_reaches_the_cluster_endpoint() {
    let stub = spawn_http_stub(
        "200 OK",
        "application/json",
        r#"{"took":1,"hits":{"total":{"value":0},"hits":[]}}"#,
    )
    .await;
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    let client_id = ClientForm {
        protocol: "elasticsearch".to_string(),
        remote_addr: Some(format!("http://127.0.0.1:{}", stub.port)),
        instruction: Some("test client".to_string()),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
        tx.clone(),
    )
    .await
    .expect("create elasticsearch client");

    // Regression guard for "register the channel before the connected-event LLM call".
    wait_for_client_handle(&state, client_id).await;

    // An unknown verb is refused by the client's own `execute_action`, not silently eaten.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "no_such_verb"}),
            Duration::from_secs(30),
        )
        .await
        .expect("send_to_client rejected action");
    assert!(
        matches!(outcome, ClientSendOutcome::Rejected { .. }),
        "expected Rejected, got {outcome:?}"
    );

    // The client's own wire verb, injected from outside its loop. `Executed`, not `Sent`:
    // reqwest frames and sends the request, so there is no honest byte count to report -
    // the detail carries the HTTP status the cluster actually answered with.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({
                "type": "search",
                "index": "dashboard-marker",
                "query": {"match_all": {}}
            }),
            Duration::from_secs(30),
        )
        .await
        .expect("send_to_client search");
    match &outcome {
        ClientSendOutcome::Executed { detail } => {
            assert!(
                detail.contains("search completed: HTTP 200"),
                "expected a completed search with the stub's status, got {detail:?}"
            );
        }
        other => panic!("expected Executed, got {other:?}"),
    }

    // Proof it was a real request, not a bookkeeping entry.
    assert!(
        stub.saw("/dashboard-marker/_search"),
        "the stub never saw the search request: {:?}",
        stub.seen.lock().unwrap()
    );

    // Recorded on the client like LLM-produced traffic.
    wait_for_log_containing(
        &state,
        AccessLogOwner::Client(client_id.as_u32()),
        "injected_action",
    )
    .await;

    // An injected disconnect ends the command loop, which drops the handle so the dashboard
    // stops offering [ send ] into a client that is finished.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "disconnect"}),
            Duration::from_secs(30),
        )
        .await
        .expect("send_to_client disconnect");
    assert!(
        matches!(outcome, ClientSendOutcome::Disconnected),
        "expected Disconnected, got {outcome:?}"
    );

    for _ in 0..1_000 {
        if !state.has_client_handle(client_id).await {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(
        !state.has_client_handle(client_id).await,
        "the command handle outlived the disconnected client"
    );

    state.remove_client(client_id).await;
}

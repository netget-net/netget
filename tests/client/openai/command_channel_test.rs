//! The dashboard's `[ send ]` path on an OpenAI client: `AppState::send_to_client` injects a
//! `send_chat_completion` from outside the client's own loop and the request reaches a stub
//! endpoint on loopback.
//!
//! Zero LLM calls and no external endpoint: a `*` static handler with no actions answers
//! every client event, and the client's LLM points at an unreachable URL anyway. The
//! "endpoint" is a local `TcpListener` speaking just enough HTTP/1.1 to satisfy
//! `async-openai`; `api_key` is a dummy because the protocol declares it required.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features openai --test client -- openai::command_channel --test-threads=100

use std::sync::Arc;
use std::time::Duration;

use netget::cli::management::ClientForm;
use netget::state::app_state::AppState;
use netget::state::client_handles::ClientSendOutcome;
use netget::state::{AccessLogOwner, ClientId};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, Mutex};

/// Every client event is answered by a no-action static handler, so nothing in this test
/// reaches an LLM backend.
fn no_llm_handlers() -> Vec<serde_json::Value> {
    vec![serde_json::json!({
        "event_pattern": "*",
        "handler": { "type": "static", "actions": [] }
    })]
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
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!(
        "OpenAI client #{} never registered a command handle",
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
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("no access-log entry for {owner:?} containing {needle:?}");
}

/// Read one whole HTTP/1.1 request (headers plus a Content-Length body) off the socket.
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
        if let Some(idx) = text.find("\r\n\r\n") {
            let content_len = text[..idx]
                .lines()
                .find(|l| l.to_ascii_lowercase().starts_with("content-length:"))
                .and_then(|l| l.split(':').nth(1))
                .and_then(|v| v.trim().parse::<usize>().ok())
                .unwrap_or(0);
            if buf.len() >= idx + 4 + content_len {
                return Some(text);
            }
        }
    }
    if buf.is_empty() {
        None
    } else {
        Some(String::from_utf8_lossy(&buf).to_string())
    }
}

/// A loopback HTTP/1.1 stub. Records every request it sees and answers each with `body`.
/// Returns the bound port and the request log.
async fn spawn_http_stub(body: String) -> (u16, Arc<Mutex<Vec<String>>>) {
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
            let body = body.clone();
            tokio::spawn(async move {
                if let Some(request) = read_request(&mut socket).await {
                    seen.lock().await.push(request);
                }
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
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

fn chat_completion_body() -> String {
    serde_json::json!({
        "id": "chatcmpl-netget-test",
        "object": "chat.completion",
        "created": 1_700_000_000u64,
        "model": "gpt-3.5-turbo",
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": "pong"},
            "finish_reason": "stop"
        }],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}
    })
    .to_string()
}

#[tokio::test]
async fn injected_chat_completion_reaches_the_endpoint() {
    let (port, seen) = spawn_http_stub(chat_completion_body()).await;

    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    let client_id = ClientForm {
        protocol: "openai".to_string(),
        remote_addr: Some(format!("http://127.0.0.1:{port}/v1")),
        instruction: Some("test client".to_string()),
        startup_params: Some(serde_json::json!({
            "api_key": "sk-netget-test-dummy",
            "default_model": "gpt-3.5-turbo"
        })),
        event_handlers: Some(no_llm_handlers()),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
        tx.clone(),
    )
    .await
    .expect("create openai client");

    // Rule 2's regression guard: the handle exists before anything is injected, and would
    // exist even if the connected-event call had parked.
    wait_for_client_handle(&state, client_id).await;

    // The client's own wire verb, injected from outside its loop. The command loop awaits
    // the API call, so the outcome describes a request that really completed - but the
    // OpenAI client owns no socket, so there is no honest byte count and it reports
    // Executed rather than Sent.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({
                "type": "send_chat_completion",
                "messages": [{"role": "user", "content": "dashboard-marker"}],
                "model": "gpt-3.5-turbo"
            }),
            Duration::from_secs(30),
        )
        .await
        .expect("send_to_client");
    match &outcome {
        ClientSendOutcome::Executed { detail } => {
            assert!(
                detail.contains("send_chat_completion") && detail.contains("gpt-3.5-turbo"),
                "unexpected detail: {detail}"
            );
        }
        other => panic!("expected Executed, got {other:?}"),
    }

    // The request really went out, carrying what the injected action asked for.
    let requests = seen.lock().await.clone();
    assert!(
        requests
            .iter()
            .any(|r| r.contains("/v1/chat/completions") && r.contains("dashboard-marker")),
        "stub endpoint never saw the chat completion: {requests:?}"
    );

    // Recorded on the client like LLM-produced traffic.
    wait_for_log_containing(
        &state,
        AccessLogOwner::Client(client_id.as_u32()),
        "injected_action",
    )
    .await;
}

#[tokio::test]
async fn injected_unknown_action_is_rejected_and_disconnect_drops_the_handle() {
    let (port, _seen) = spawn_http_stub(chat_completion_body()).await;

    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    let client_id = ClientForm {
        protocol: "openai".to_string(),
        remote_addr: Some(format!("http://127.0.0.1:{port}/v1")),
        instruction: Some("test client".to_string()),
        startup_params: Some(serde_json::json!({"api_key": "sk-netget-test-dummy"})),
        event_handlers: Some(no_llm_handlers()),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
        tx.clone(),
    )
    .await
    .expect("create openai client");

    wait_for_client_handle(&state, client_id).await;

    // An action the protocol does not know is reported back, not silently swallowed.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "not_an_openai_action"}),
            Duration::from_secs(10),
        )
        .await
        .expect("send_to_client rejected action");
    assert!(
        matches!(outcome, ClientSendOutcome::Rejected { .. }),
        "expected Rejected, got {outcome:?}"
    );

    // An injected disconnect ends the command loop and drops the handle, so the dashboard
    // stops offering [ send ] into a dead client.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "disconnect"}),
            Duration::from_secs(10),
        )
        .await
        .expect("send_to_client disconnect");
    assert!(
        matches!(outcome, ClientSendOutcome::Disconnected),
        "expected Disconnected, got {outcome:?}"
    );

    for _ in 0..1_000 {
        if !state.has_client_handle(client_id).await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("command handle should be gone after an injected disconnect");
}

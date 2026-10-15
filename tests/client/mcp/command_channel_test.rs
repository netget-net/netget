//! The dashboard's `[ send ]` path on an MCP client: `AppState::send_to_client` injects a
//! `list_tools` from outside the client's own loop and the JSON-RPC call reaches a stub MCP
//! server on loopback.
//!
//! Zero LLM calls and no external endpoint: a `*` static handler with no actions answers every
//! client event, and the client's LLM points at an unreachable URL anyway.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features mcp --test client -- mcp::command_channel --test-threads=100


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
        "MCP client #{} never registered a command handle",
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

/// A loopback HTTP/1.1 stub. Records every request it sees and answers each with whatever
/// `respond` returns for it. Bound to 127.0.0.1, so no external endpoint is contacted.
async fn spawn_http_stub<F>(respond: F) -> (u16, Arc<Mutex<Vec<String>>>)
where
    F: Fn(&str) -> String + Send + Sync + 'static,
{
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_task = seen.clone();
    let respond: Arc<dyn Fn(&str) -> String + Send + Sync> = Arc::new(respond);
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            let seen = seen_task.clone();
            let respond = respond.clone();
            tokio::spawn(async move {
                let request = read_request(&mut socket).await.unwrap_or_default();
                let body = respond(&request);
                seen.lock().await.push(request);
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

/// Order matters: "initialized" contains "initialize" as a substring, and both contain
/// neither of the other method names, so the most specific test comes first.
fn mcp_stub_body(request: &str) -> String {
    if request.contains("tools/list") {
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"tools": [{"name": "dashboard-marker-tool"}]}
        })
        .to_string()
    } else if request.contains("\"initialized\"") {
        serde_json::json!({"jsonrpc": "2.0", "id": 1, "result": {}}).to_string()
    } else if request.contains("\"initialize\"") {
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "serverInfo": {"name": "netget-test-stub", "version": "0.1.0"}
            }
        })
        .to_string()
    } else {
        serde_json::json!({"jsonrpc": "2.0", "id": 1, "result": {}}).to_string()
    }
}

async fn open_client(state: &AppState, port: u16, tx: mpsc::UnboundedSender<String>) -> ClientId {
    ClientForm {
        protocol: "mcp".to_string(),
        remote_addr: Some(format!("http://127.0.0.1:{port}")),
        instruction: Some("test client".to_string()),
        event_handlers: Some(no_llm_handlers()),
        ..Default::default()
    }
    .create(
        state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
        tx,
    )
    .await
    .expect("create mcp client")
}

#[tokio::test]
async fn injected_list_tools_reaches_the_server() {
    let (port, seen) = spawn_http_stub(mcp_stub_body).await;
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();
    let client_id = open_client(&state, port, tx.clone()).await;

    // Rule 2's regression guard: the handle exists before anything is injected.
    wait_for_client_handle(&state, client_id).await;

    // The command loop awaits the JSON-RPC call, so the outcome describes a request that
    // really completed - but reqwest owns the socket, so there is no honest byte count and
    // it reports Executed rather than Sent.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "list_tools"}),
            Duration::from_secs(30),
        )
        .await
        .expect("send_to_client");
    match &outcome {
        ClientSendOutcome::Executed { detail } => assert!(
            detail.contains("mcp_list_tools"),
            "unexpected detail: {detail}"
        ),
        other => panic!("expected Executed, got {other:?}"),
    }

    let requests = seen.lock().await.clone();
    assert!(
        requests.iter().any(|r| r.contains("tools/list")),
        "stub MCP server never saw the tools/list call: {requests:?}"
    );

    wait_for_log_containing(
        &state,
        AccessLogOwner::Client(client_id.as_u32()),
        "injected_action",
    )
    .await;
}

#[tokio::test]
async fn injected_unknown_action_is_rejected_and_disconnect_drops_the_handle() {
    let (port, _seen) = spawn_http_stub(mcp_stub_body).await;
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();
    let client_id = open_client(&state, port, tx.clone()).await;
    wait_for_client_handle(&state, client_id).await;

    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "not_an_mcp_action"}),
            Duration::from_secs(10),
        )
        .await
        .expect("send_to_client rejected action");
    assert!(
        matches!(outcome, ClientSendOutcome::Rejected { .. }),
        "expected Rejected, got {outcome:?}"
    );

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

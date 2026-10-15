//! The Ollama client must reach the endpoint it was pointed at, and must not buffer whatever
//! that endpoint chooses to send back.
//!
//! This family impersonates an LLM backend while NetGet itself *is* an LLM backend client, so
//! the dangerous confusion is a client that loses its target and falls through to the
//! operator's own Ollama on `127.0.0.1:11434` — the shape `CLAUDE.md` records for the DynamoDB
//! client, which dropped `remote_addr` and signed real requests against real AWS. The first
//! test proves the target survives; nothing in it can succeed by accident, because the only
//! endpoint in the test is a loopback stub on an ephemeral port that no default could name.
//!
//! The second covers the response side: `response.json()` buffers the whole body with no
//! limit, and `/api/generate` is an arbitrarily long NDJSON stream by design, so the endpoint
//! decided how much memory NetGet spent.
//!
//! Zero LLM calls: a `*` static handler with no actions answers every client event, and the
//! client's own LLM points at an unreachable URL.

use std::sync::Arc;
use std::time::Duration;

use netget::cli::management::ClientForm;
use netget::state::app_state::AppState;
use netget::state::client_handles::ClientSendOutcome;
use netget::state::ClientId;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, Mutex};

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
        "Ollama client #{} never registered a command handle",
        id.as_u32()
    );
}

async fn read_headers(socket: &mut tokio::net::TcpStream) -> String {
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let Ok(n) = socket.read(&mut chunk).await else {
            break;
        };
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if String::from_utf8_lossy(&buf).contains("\r\n\r\n") {
            break;
        }
    }
    String::from_utf8_lossy(&buf).to_string()
}

/// Records the `Host` header of every request it receives, then answers with `body`.
async fn spawn_recording_stub(body: &'static str) -> (u16, Arc<Mutex<Vec<String>>>) {
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
                let request = read_headers(&mut socket).await;
                seen.lock().await.push(request);
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.shutdown().await;
            });
        }
    });
    (port, seen)
}

/// Answers with a `Content-Length` far past the client's cap and then dribbles bytes forever.
///
/// A client that buffers the whole body would never return; one that refuses at the cap
/// reports an error promptly, which is what the test times.
async fn spawn_firehose_stub() -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let _ = read_headers(&mut socket).await;
                let header = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                              Transfer-Encoding: chunked\r\n\r\n";
                if socket.write_all(header.as_bytes()).await.is_err() {
                    return;
                }
                // 64 KiB chunks of JSON-ish filler, forever. The client should refuse
                // somewhere past its cap rather than reading until the peer stops.
                let payload = "A".repeat(64 * 1024);
                loop {
                    let chunk = format!("{:x}\r\n{}\r\n", payload.len(), payload);
                    if socket.write_all(chunk.as_bytes()).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    port
}

async fn open_client(state: &AppState, port: u16, tx: mpsc::UnboundedSender<String>) -> ClientId {
    ClientForm {
        protocol: "ollama".to_string(),
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
    .expect("create ollama client")
}

/// Every verb goes to the named endpoint, not to a default.
///
/// The stub is on an ephemeral loopback port, so `127.0.0.1:11434` — or any other fallback a
/// library might reach for — could not produce these requests.
#[tokio::test]
async fn every_verb_reaches_the_endpoint_the_operator_named() {
    let (port, seen) = spawn_recording_stub(
        r#"{"model":"llama2","response":"pong","message":{"role":"assistant","content":"pong"},"models":[{"name":"llama2"}],"embedding":[0.1,0.2],"done":true}"#,
    )
    .await;
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();
    let client_id = open_client(&state, port, tx).await;
    wait_for_client_handle(&state, client_id).await;

    for action in [
        serde_json::json!({"type": "send_generate_request", "prompt": "p", "model": "llama2"}),
        serde_json::json!({"type": "send_chat_request", "messages": [{"role": "user", "content": "hi"}], "model": "llama2"}),
        serde_json::json!({"type": "list_models"}),
        serde_json::json!({"type": "generate_embeddings", "prompt": "p", "model": "llama2"}),
    ] {
        let name = action["type"].as_str().unwrap().to_string();
        let outcome = state
            .send_to_client(client_id, action, Duration::from_secs(30))
            .await
            .unwrap_or_else(|e| panic!("{name} could not be injected: {e}"));
        assert!(
            matches!(outcome, ClientSendOutcome::Executed { .. }),
            "{name} did not complete: {outcome:?}"
        );
    }

    let requests = seen.lock().await.clone();
    let host = format!("127.0.0.1:{port}");
    assert_eq!(
        requests.len(),
        4,
        "each of the four verbs must reach the endpoint exactly once: {requests:?}"
    );
    for request in &requests {
        assert!(
            request.contains(&host),
            "a request went somewhere other than the endpoint the operator named ({host}): \
             {request}"
        );
        assert!(
            !request.contains("11434"),
            "a request carried the default Ollama port; the target was dropped: {request}"
        );
    }
    for path in ["/api/generate", "/api/chat", "/api/tags", "/api/embeddings"] {
        assert!(
            requests.iter().any(|r| r.contains(path)),
            "{path} was never requested: {requests:?}"
        );
    }
}

/// An endpoint that answers forever does not take the process with it.
///
/// The client's cap is 8 MiB; the stub sends 64 KiB chunks with no end, so a client using
/// `response.json()` would buffer until it ran out of memory. Completing at all — with an
/// error rather than a hang — is the assertion.
#[tokio::test]
async fn an_endless_response_body_is_refused_rather_than_buffered() {
    let port = spawn_firehose_stub().await;
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();
    let client_id = open_client(&state, port, tx).await;
    wait_for_client_handle(&state, client_id).await;

    let outcome = tokio::time::timeout(
        Duration::from_secs(60),
        state.send_to_client(
            client_id,
            serde_json::json!({"type": "send_generate_request", "prompt": "p", "model": "llama2"}),
            Duration::from_secs(55),
        ),
    )
    .await
    .expect("the request must finish rather than buffer an unbounded body");

    // The cap makes the exchange fail; which failure it is does not matter, only that one
    // arrived. A success here would mean the whole stream was read.
    match outcome {
        Err(_) => {}
        Ok(ClientSendOutcome::Rejected { .. }) => {}
        Ok(other) => panic!("an endless body must not read as a completed exchange: {other:?}"),
    }
}

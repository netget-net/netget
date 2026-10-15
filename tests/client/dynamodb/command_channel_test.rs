//! The dashboard's `[ send ]` path on a DynamoDB client: `AppState::send_to_client` injects an
//! action from outside the client's own tasks, the client's command loop runs it through the
//! same `apply_action` any other path would use, and the PutItem request really reaches a
//! listener on loopback.
//!
//! Zero LLM calls: the client's LLM points at an unreachable URL, so the response-event call
//! fails - the loop has to tolerate that, which is part of what this verifies. Nothing here
//! contacts AWS; `endpoint_url` is a plain TCP listener on 127.0.0.1 and the credentials are
//! fixed test strings.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features dynamodb --test client -- dynamodb::command_channel --test-threads=100

#![cfg(unix)]

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
        "DynamoDB client #{} never registered a command handle",
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
async fn injected_put_item_reaches_the_endpoint() {
    let stub = spawn_http_stub("200 OK", "application/x-amz-json-1.0", "{}").await;
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    let client_id = ClientForm {
        protocol: "dynamodb".to_string(),
        remote_addr: Some(format!("127.0.0.1:{}", stub.port)),
        instruction: Some("test client".to_string()),
        startup_params: Some(serde_json::json!({
            "region": "us-east-1",
            // Everything is pointed at the loopback stub; no AWS endpoint is reachable
            // from this test, and the credentials below are fixed strings.
            "endpoint_url": format!("http://127.0.0.1:{}", stub.port),
            "access_key_id": "netget-test",
            "secret_access_key": "netget-test-secret",
        })),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
        tx.clone(),
    )
    .await
    .expect("create dynamodb client");

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
    // the AWS SDK owns the socket and reports no byte count, so the detail names the
    // operation and what it returned rather than inventing a number.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({
                "type": "put_item",
                "table_name": "dashboard-marker",
                "item": {"id": {"S": "injected"}}
            }),
            Duration::from_secs(30),
        )
        .await
        .expect("send_to_client put_item");
    match &outcome {
        ClientSendOutcome::Executed { detail } => {
            assert!(
                detail.starts_with("put_item "),
                "expected the detail to name the operation, got {detail:?}"
            );
        }
        other => panic!("expected Executed, got {other:?}"),
    }

    // Proof it was a real request, not a bookkeeping entry.
    assert!(
        stub.saw("dashboard-marker"),
        "the stub never saw the PutItem request: {:?}",
        stub.seen.lock().unwrap()
    );

    wait_for_log_containing(
        &state,
        AccessLogOwner::Client(client_id.as_u32()),
        "injected_action",
    )
    .await;

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

/// `remote_addr` alone must be the endpoint — the target the operator typed cannot be ignored.
///
/// It was: `connect_with_llm_actions` took the address as `_remote_addr` and dropped it, so a
/// client created against `127.0.0.1:PORT` with no explicit `endpoint_url` had the AWS SDK
/// resolve `https://dynamodb.<region>.amazonaws.com` and sign with whatever ambient
/// credentials the machine happened to have. A client aimed at localhost issued real reads and
/// writes against real AWS. This test passes no `endpoint_url` at all: if the address is
/// dropped again, the stub never sees the request and the send does not report success.
///
/// It also pins the second half of the same fix: `region` is the only startup parameter given.
/// All four are declared `required: false` but were read with `get_string`, which errors when
/// the key is absent, so any subset of them failed the connect outright.
#[tokio::test]
async fn remote_addr_alone_is_the_endpoint() {
    let stub = spawn_http_stub("200 OK", "application/x-amz-json-1.0", "{}").await;
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    let client_id = ClientForm {
        protocol: "dynamodb".to_string(),
        remote_addr: Some(format!("127.0.0.1:{}", stub.port)),
        instruction: Some("test client".to_string()),
        // No `endpoint_url`: the address is the only thing saying where to go. Credentials
        // are supplied because the SDK will not sign without them and nothing would reach
        // the wire at all — the point here is *where* the request lands, not whether it is
        // signed. Passing a strict subset of the four optional parameters is also exactly
        // what used to fail the connect outright.
        startup_params: Some(serde_json::json!({
            "region": "us-east-1",
            "access_key_id": "netget-test",
            "secret_access_key": "netget-test-secret",
        })),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
        tx.clone(),
    )
    .await
    .expect("create dynamodb client with only remote_addr and region");

    wait_for_client_handle(&state, client_id).await;

    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({
                "type": "put_item",
                "table_name": "remote-addr-marker",
                "item": {"id": {"S": "injected"}}
            }),
            Duration::from_secs(30),
        )
        .await
        .expect("send_to_client put_item");
    assert!(
        matches!(outcome, ClientSendOutcome::Executed { .. }),
        "expected Executed, got {outcome:?}"
    );
    assert!(
        stub.saw("remote-addr-marker"),
        "the request did not go to remote_addr: {:?}",
        stub.seen.lock().unwrap()
    );

    state.remove_client(client_id).await;
}

/// An attribute type this client cannot convert must be refused, not silently dropped.
///
/// `json_to_attribute_value` returned `Option` and both callers skipped a `None`, so a
/// `put_item` carrying a Map, List or set attribute wrote an item **missing that attribute**
/// and reported success, and a malformed base64 `B` value was written as an empty blob.
/// Nothing was logged on any path. The model has to be told, so this is now a `Rejected`.
#[tokio::test]
async fn an_unsupported_attribute_type_is_refused_not_dropped() {
    let stub = spawn_http_stub("200 OK", "application/x-amz-json-1.0", "{}").await;
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    let client_id = ClientForm {
        protocol: "dynamodb".to_string(),
        remote_addr: Some(format!("127.0.0.1:{}", stub.port)),
        instruction: Some("test client".to_string()),
        startup_params: Some(serde_json::json!({
            "region": "us-east-1",
            "access_key_id": "netget-test",
            "secret_access_key": "netget-test-secret",
        })),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
        tx.clone(),
    )
    .await
    .expect("create dynamodb client");

    wait_for_client_handle(&state, client_id).await;

    // A Map attribute alongside a supported one: the whole write must fail rather than
    // silently storing only `id`.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({
                "type": "put_item",
                "table_name": "unsupported-attr-marker",
                "item": {
                    "id": {"S": "injected"},
                    "profile": {"M": {"nested": {"S": "value"}}}
                }
            }),
            Duration::from_secs(30),
        )
        .await
        .expect("send_to_client put_item");
    match &outcome {
        ClientSendOutcome::Rejected { error } => {
            assert!(
                error.contains("profile"),
                "the refusal must name the attribute the model got wrong, got {error:?}"
            );
        }
        other => panic!("expected Rejected for an unsupported attribute type, got {other:?}"),
    }
    assert!(
        !stub.saw("unsupported-attr-marker"),
        "a write with an unconvertible attribute must not reach the endpoint at all: {:?}",
        stub.seen.lock().unwrap()
    );

    // Malformed base64 in a B attribute is the same class: it used to become an empty blob.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({
                "type": "put_item",
                "table_name": "bad-base64-marker",
                "item": {"id": {"S": "x"}, "blob": {"B": "not base64!!"}}
            }),
            Duration::from_secs(30),
        )
        .await
        .expect("send_to_client put_item");
    assert!(
        matches!(outcome, ClientSendOutcome::Rejected { .. }),
        "expected Rejected for undecodable base64, got {outcome:?}"
    );
    assert!(
        !stub.saw("bad-base64-marker"),
        "an undecodable value must not be written as an empty blob: {:?}",
        stub.seen.lock().unwrap()
    );

    state.remove_client(client_id).await;
}

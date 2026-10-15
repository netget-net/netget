//! The dashboard's `[ send ]` path on an SQS client: `AppState::send_to_client` injects an
//! action from outside the client's own tasks, the client's command loop runs it through the
//! same `apply_action` the LLM path uses, and the SendMessage request really reaches a
//! listener on loopback.
//!
//! Zero LLM calls: the client's LLM points at an unreachable URL, so the connected-event call
//! fails - the loop has to tolerate that, which is part of what this verifies. Nothing here
//! contacts AWS; `endpoint_url` and `queue_url` both point at a plain TCP listener on
//! 127.0.0.1, and static credentials are set so the SDK never reaches for a metadata service.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features sqs --test client -- sqs::command_channel --test-threads=100

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
        "SQS client #{} never registered a command handle",
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

/// Credentials come from this client's own startup parameters.
///
/// They used to come from four `std::env::set_var` calls, because the protocol declared no
/// credential parameters and the SDK's default chain would otherwise have consulted the
/// ambient profile and the EC2 metadata service. That was a test working around a production
/// behaviour — and `set_var` is process-global in a test binary that runs at
/// `--test-threads=100`, so it mutated `AWS_ACCESS_KEY_ID` and friends for every other test
/// running alongside, racing any concurrent `getenv` inside the AWS SDK. The protocol now
/// declares `access_key_id` and `secret_access_key`, which is both the honest fix here and
/// the only way an operator can stop a model-created client signing with their real AWS
/// identity.
#[tokio::test]
async fn injected_send_message_reaches_the_endpoint() {
    let stub = spawn_http_stub(
        "200 OK",
        "application/x-amz-json-1.0",
        r#"{"MessageId":"m-1","MD5OfMessageBody":"0"}"#,
    )
    .await;
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    let client_id = ClientForm {
        protocol: "sqs".to_string(),
        remote_addr: Some(format!("127.0.0.1:{}", stub.port)),
        instruction: Some("test client".to_string()),
        startup_params: Some(serde_json::json!({
            "queue_url": format!("http://127.0.0.1:{}/000000000000/dashboard-marker", stub.port),
            "region": "us-east-1",
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
    .expect("create sqs client");

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
    // the AWS SDK owns the socket and reports no byte count, so the detail names the
    // operation and what it returned rather than inventing a number.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "send_message", "message_body": "injected-marker"}),
            Duration::from_secs(30),
        )
        .await
        .expect("send_to_client send_message");
    match &outcome {
        ClientSendOutcome::Executed { detail } => {
            assert!(
                detail.starts_with("send_message "),
                "expected the detail to name the operation, got {detail:?}"
            );
        }
        other => panic!("expected Executed, got {other:?}"),
    }

    // Proof it was a real request, not a bookkeeping entry.
    assert!(
        stub.saw("injected-marker"),
        "the stub never saw the SendMessage body: {:?}",
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

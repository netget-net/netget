//! The dashboard's `[ send ]` path on an S3 client: `AppState::send_to_client` injects an
//! action from outside the client's own tasks, the client's command loop runs it through the
//! same `apply_action` the LLM path uses, and the S3 request really reaches a listener on
//! loopback.
//!
//! Zero LLM calls: the client's LLM points at an unreachable URL, so the connected-event call
//! fails - the loop has to tolerate that, which is part of what this verifies. Nothing here
//! contacts AWS; the stub is a plain TCP listener on 127.0.0.1 answering with the S3 XML the
//! SDK expects, and the client's endpoint is that listener.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features s3 --test client -- s3::command_channel --test-threads=100


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
        "S3 client #{} never registered a command handle",
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
async fn injected_list_buckets_reaches_the_endpoint() {
    let stub = spawn_http_stub(
        "200 OK",
        "application/xml",
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><ListAllMyBucketsResult \
         xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Owner><ID>netget</ID>\
         </Owner><Buckets><Bucket><Name>dashboard-marker</Name>\
         <CreationDate>2024-01-01T00:00:00.000Z</CreationDate></Bucket></Buckets>\
         </ListAllMyBucketsResult>",
    )
    .await;
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    let client_id = ClientForm {
        protocol: "s3".to_string(),
        // `remote_addr` is the endpoint unless `endpoint_url` overrides it, so every
        // operation is pointed at the loopback stub and never at AWS.
        remote_addr: Some(format!("http://127.0.0.1:{}", stub.port)),
        instruction: Some("test client".to_string()),
        // A custom endpoint needs explicit credentials; the stub never checks them.
        startup_params: Some(serde_json::json!({
            "access_key_id": "NETGETTESTKEYID",
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
    .expect("create s3 client");

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
            serde_json::json!({"type": "list_buckets"}),
            Duration::from_secs(30),
        )
        .await
        .expect("send_to_client list_buckets");
    match &outcome {
        ClientSendOutcome::Executed { detail } => {
            assert!(
                detail.starts_with("s3_list_buckets "),
                "expected the detail to name the operation, got {detail:?}"
            );
        }
        other => panic!("expected Executed, got {other:?}"),
    }

    // Proof it was a real request, not a bookkeeping entry.
    assert!(
        stub.saw("HTTP/1.1"),
        "the stub never saw an S3 request: {:?}",
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

/// The declared startup parameters must reach the signature.
///
/// All four (`access_key_id`, `secret_access_key`, `region`, `endpoint_url`) were declared —
/// two of them `required: true` — and read out of `protocol_data`, which nothing populates
/// before connect: `client_startup.rs` builds the instance with `protocol_data: Null` and the
/// only writer runs *after* the read. So every S3 client signed with
/// `Credentials::new("", "", ...)` and was pinned to `us-east-1` no matter what the caller
/// passed, and no S3-compatible service could have authenticated it.
///
/// SigV4 itself is the AWS SDK's job; what this pins is that netget hands it the operator's
/// values. The access key id and the region both appear in the `Credential=` scope of the
/// `Authorization` header, so the stub can see them.
#[tokio::test]
async fn startup_credentials_reach_the_signature() {
    let stub = spawn_http_stub(
        "200 OK",
        "application/xml",
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><ListAllMyBucketsResult \
         xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Owner><ID>netget</ID>\
         </Owner><Buckets/></ListAllMyBucketsResult>",
    )
    .await;
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    let client_id = ClientForm {
        protocol: "s3".to_string(),
        // Deliberately not the stub: `endpoint_url` must win over `remote_addr`, and if it
        // is ignored the request goes nowhere the stub can see it.
        remote_addr: Some("example.invalid:9000".to_string()),
        instruction: Some("test client".to_string()),
        startup_params: Some(serde_json::json!({
            "access_key_id": "NETGETTESTKEYID",
            "secret_access_key": "netget-test-secret",
            "region": "eu-west-3",
            "endpoint_url": format!("http://127.0.0.1:{}", stub.port),
        })),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
        tx.clone(),
    )
    .await
    .expect("create s3 client with startup parameters");

    wait_for_client_handle(&state, client_id).await;

    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "list_buckets"}),
            Duration::from_secs(30),
        )
        .await
        .expect("send_to_client list_buckets");
    assert!(
        matches!(outcome, ClientSendOutcome::Executed { .. }),
        "expected Executed, got {outcome:?}"
    );

    assert!(
        stub.saw("NETGETTESTKEYID"),
        "the access key id from the startup parameters never reached the signature: {:?}",
        stub.seen.lock().unwrap()
    );
    assert!(
        stub.saw("eu-west-3"),
        "the region from the startup parameters never reached the signature: {:?}",
        stub.seen.lock().unwrap()
    );

    state.remove_client(client_id).await;
}

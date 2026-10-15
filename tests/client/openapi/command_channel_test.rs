//! The dashboard's `[ send ]` path on an OpenAPI client: `AppState::send_to_client` injects
//! an `execute_operation` from outside the client's own task, the spec is resolved and the
//! request really goes out. Zero LLM calls - the client's LLM points at an unreachable URL,
//! so both the `openapi_client_connected` call and the response event's call fail and the
//! loop must tolerate that; that tolerance is part of what this test verifies.
//!
//! The API is a throwaway `TcpListener` on 127.0.0.1 speaking just enough HTTP/1.1.
//! Nothing here contacts an external endpoint.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features openapi --test client -- openapi::command_channel --test-threads=100

use std::sync::{Arc, Mutex};
use std::time::Duration;

use netget::cli::management::ClientForm;
use netget::state::app_state::AppState;
use netget::state::client_handles::ClientSendOutcome;
use netget::state::{AccessLogOwner, ClientId, ClientStatus};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

const USERS_JSON: &str = r#"[{"id":1,"name":"Alice"}]"#;

/// A local stand-in for the API. Returns the port and the request lines it saw.
async fn stub_api(body: &'static str) -> (u16, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind stub");
    let port = listener.local_addr().unwrap().port();
    let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_task = seen.clone();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            let seen = seen_task.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                let n = sock.read(&mut buf).await.unwrap_or(0);
                let first = String::from_utf8_lossy(&buf[..n])
                    .lines()
                    .next()
                    .unwrap_or("")
                    .to_string();
                seen.lock().unwrap().push(first);
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.flush().await;
            });
        }
    });
    (port, seen)
}

fn spec_for(port: u16) -> String {
    format!(
        "openapi: 3.1.0\n\
         info:\n  title: Command Channel Test API\n  version: 1.0.0\n\
         servers:\n  - url: http://127.0.0.1:{port}\n\
         paths:\n  \
         /users:\n    get:\n      operationId: listUsers\n      responses:\n        '200':\n          description: ok\n  \
         /users/{{id}}:\n    get:\n      operationId: getUser\n      responses:\n        '200':\n          description: ok\n"
    )
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

/// The regression guard for rule 2: the handle must exist even though `connect()` makes an
/// `openapi_client_connected` LLM call that a manual routing rule could park for minutes.
async fn wait_for_client_handle(state: &AppState, id: ClientId) {
    for _ in 0..1_000 {
        if state.has_client_handle(id).await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!(
        "OpenAPI client #{} never registered a command handle",
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

#[tokio::test]
async fn injected_openapi_operation_reaches_the_api() {
    let (port, seen) = stub_api(USERS_JSON).await;
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    let client_id = ClientForm {
        protocol: "openapi".to_string(),
        remote_addr: Some(format!("127.0.0.1:{port}")),
        instruction: Some("test client".to_string()),
        startup_params: Some(serde_json::json!({ "spec": spec_for(port) })),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
        tx.clone(),
    )
    .await
    .expect("create openapi client");

    wait_for_client_handle(&state, client_id).await;

    // The spec-driven verb, injected from outside the client's task. `Executed`, not
    // `Sent`: reqwest issues the request but reports no wire byte count.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "execute_operation", "operation_id": "listUsers"}),
            Duration::from_secs(30),
        )
        .await
        .expect("send_to_client");
    match &outcome {
        ClientSendOutcome::Executed { detail } => assert!(
            detail.contains("operation listUsers"),
            "detail should name the operation that ran, got {detail:?}"
        ),
        other => panic!("expected Executed, got {other:?}"),
    }

    let requests = seen.lock().unwrap().clone();
    assert!(
        requests.iter().any(|r| r.starts_with("GET /users ")),
        "stub API should have seen GET /users, saw {requests:?}"
    );

    wait_for_log_containing(
        &state,
        AccessLogOwner::Client(client_id.as_u32()),
        "injected_action",
    )
    .await;

    // Path parameters are substituted from the spec on the injected path too.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({
                "type": "execute_operation",
                "operation_id": "getUser",
                "path_params": {"id": "42"}
            }),
            Duration::from_secs(30),
        )
        .await
        .expect("send_to_client getUser");
    assert!(
        matches!(outcome, ClientSendOutcome::Executed { .. }),
        "expected Executed, got {outcome:?}"
    );
    let requests = seen.lock().unwrap().clone();
    assert!(
        requests.iter().any(|r| r.starts_with("GET /users/42 ")),
        "stub API should have seen GET /users/42, saw {requests:?}"
    );

    // An operation the spec does not define fails loudly rather than reporting success.
    let err = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "execute_operation", "operation_id": "deleteEverything"}),
            Duration::from_secs(30),
        )
        .await;
    assert!(
        err.is_err(),
        "an operation missing from the spec must not report success, got {err:?}"
    );

    // A verb the OpenAPI client does not have is rejected by the protocol.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "openapi_publish"}),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_client unknown");
    assert!(
        matches!(outcome, ClientSendOutcome::Rejected { .. }),
        "expected Rejected, got {outcome:?}"
    );

    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "disconnect"}),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_client disconnect");
    assert!(
        matches!(outcome, ClientSendOutcome::Disconnected),
        "expected Disconnected, got {outcome:?}"
    );

    for _ in 0..1_000 {
        let status = state.get_client(client_id).await.map(|c| c.status);
        if matches!(status, Some(ClientStatus::Disconnected))
            && !state.has_client_handle(client_id).await
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!(
        "client should be Disconnected with no command handle; status={:?} has_handle={}",
        state.get_client(client_id).await.map(|c| c.status),
        state.has_client_handle(client_id).await
    );
}

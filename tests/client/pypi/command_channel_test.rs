//! The dashboard's `[ send ]` path on a PyPI client: `AppState::send_to_client` injects an
//! action from outside the client's own task and the resulting index request really goes
//! out. Zero LLM calls - the client's LLM points at an unreachable URL, so the response
//! event's LLM call fails and the loop must tolerate that; that tolerance is part of what
//! this test verifies.
//!
//! The "index" is a throwaway `TcpListener` on 127.0.0.1 speaking just enough HTTP/1.1.
//! Nothing here contacts pypi.org.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features pypi --test client -- pypi::command_channel --test-threads=100


use std::sync::{Arc, Mutex};
use std::time::Duration;

use netget::cli::management::ClientForm;
use netget::state::app_state::AppState;
use netget::state::client_handles::ClientSendOutcome;
use netget::state::{AccessLogOwner, ClientId, ClientStatus};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

const PACKAGE_JSON: &str =
    r#"{"info":{"name":"requests","version":"2.31.0","summary":"HTTP for Humans"},"urls":[]}"#;

/// A local stand-in for the index. Returns the port and the request lines it saw.
async fn stub_index(body: &'static str) -> (u16, Arc<Mutex<Vec<String>>>) {
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

async fn new_state() -> AppState {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".to_string());
    state
        .set_llm_client(netget::llm::OllamaClient::new(
            "http://127.0.0.1:1".to_string(),
        ))
        .await;
    state
}

/// The regression guard for "register the channel before anything that can block".
async fn wait_for_client_handle(state: &AppState, id: ClientId) {
    for _ in 0..1_000 {
        if state.has_client_handle(id).await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!(
        "PyPI client #{} never registered a command handle",
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
async fn injected_pypi_action_reaches_the_index() {
    let (port, seen) = stub_index(PACKAGE_JSON).await;
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    let client_id = ClientForm {
        protocol: "pypi".to_string(),
        remote_addr: Some(format!("http://127.0.0.1:{port}")),
        instruction: Some("test client".to_string()),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
        tx.clone(),
    )
    .await
    .expect("create pypi client");

    wait_for_client_handle(&state, client_id).await;

    // PyPI's own verb, injected from outside the client's task. `Executed`, not `Sent`:
    // reqwest issues the request but reports no wire byte count.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "get_package_info", "package_name": "requests"}),
            Duration::from_secs(30),
        )
        .await
        .expect("send_to_client");
    match &outcome {
        ClientSendOutcome::Executed { detail } => assert!(
            detail.contains("get_package_info requests"),
            "detail should name the request that ran, got {detail:?}"
        ),
        other => panic!("expected Executed, got {other:?}"),
    }

    let requests = seen.lock().unwrap().clone();
    assert!(
        requests
            .iter()
            .any(|r| r.starts_with("GET /pypi/requests/json ")),
        "stub index should have seen GET /pypi/requests/json, saw {requests:?}"
    );

    wait_for_log_containing(
        &state,
        AccessLogOwner::Client(client_id.as_u32()),
        "injected_action",
    )
    .await;

    // `search_packages` is the honest-`Executed` case worth pinning: PyPI retired its
    // search API, so the action raises its event without contacting the index at all.
    // Reporting `Sent` here would be a lie, and so would swallowing it silently.
    let before = seen.lock().unwrap().len();
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "search_packages", "query": "http"}),
            Duration::from_secs(30),
        )
        .await
        .expect("send_to_client search");
    match &outcome {
        ClientSendOutcome::Executed { detail } => assert!(
            detail.contains("without") && detail.contains("search API is retired"),
            "detail must say the search never reached the wire, got {detail:?}"
        ),
        other => panic!("expected Executed, got {other:?}"),
    }
    assert_eq!(
        seen.lock().unwrap().len(),
        before,
        "search_packages must not put anything on the wire"
    );

    // A verb PyPI does not have is rejected by the protocol, not silently swallowed.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "pypi_upload"}),
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

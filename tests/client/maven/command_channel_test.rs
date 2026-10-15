//! The dashboard's `[ send ]` path on a Maven client: `AppState::send_to_client` injects an
//! action from outside the client's own task and the resulting repository request really
//! goes out. Zero LLM calls - the client's LLM points at an unreachable URL, so both the
//! `maven_connected` call and the response event's call fail and the loop must tolerate
//! that; that tolerance is part of what this test verifies.
//!
//! The "repository" is a throwaway `TcpListener` on 127.0.0.1 speaking just enough
//! HTTP/1.1. Nothing here contacts repo.maven.apache.org.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features maven --test client -- maven::command_channel --test-threads=100

use std::sync::{Arc, Mutex};
use std::time::Duration;

use netget::cli::management::ClientForm;
use netget::state::app_state::AppState;
use netget::state::client_handles::ClientSendOutcome;
use netget::state::{AccessLogOwner, ClientId, ClientStatus};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

const POM_XML: &str = r#"<project><groupId>org.example</groupId><artifactId>demo</artifactId><version>1.0</version></project>"#;

/// A local stand-in for the repository. Returns the port and the request lines it saw.
async fn stub_repository(body: &'static str) -> (u16, Arc<Mutex<Vec<String>>>) {
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
                    "HTTP/1.1 200 OK\r\nContent-Type: application/xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
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

/// The regression guard for rule 2: the handle must exist even though `connect()` makes a
/// `maven_connected` LLM call that a manual routing rule could park for minutes.
async fn wait_for_client_handle(state: &AppState, id: ClientId) {
    for _ in 0..1_000 {
        if state.has_client_handle(id).await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!(
        "Maven client #{} never registered a command handle",
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
async fn injected_maven_action_reaches_the_repository() {
    let (port, seen) = stub_repository(POM_XML).await;
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    let client_id = ClientForm {
        protocol: "maven".to_string(),
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
    .expect("create maven client");

    wait_for_client_handle(&state, client_id).await;

    // Maven's own verb, injected from outside the client's task. `Executed`, not `Sent`:
    // reqwest issues the request but reports no wire byte count.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({
                "type": "download_pom",
                "group_id": "org.example",
                "artifact_id": "demo",
                "version": "1.0"
            }),
            Duration::from_secs(30),
        )
        .await
        .expect("send_to_client");
    match &outcome {
        ClientSendOutcome::Executed { detail } => assert!(
            detail.contains("download_pom org.example:demo:1.0"),
            "detail should name the coordinates that were fetched, got {detail:?}"
        ),
        other => panic!("expected Executed, got {other:?}"),
    }

    let requests = seen.lock().unwrap().clone();
    assert!(
        requests
            .iter()
            .any(|r| r.starts_with("GET /org/example/demo/1.0/demo-1.0.pom ")),
        "stub repository should have seen the POM request, saw {requests:?}"
    );

    wait_for_log_containing(
        &state,
        AccessLogOwner::Client(client_id.as_u32()),
        "injected_action",
    )
    .await;

    // search_versions goes to maven-metadata.xml through the same shared path.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({
                "type": "search_versions",
                "group_id": "org.example",
                "artifact_id": "demo"
            }),
            Duration::from_secs(30),
        )
        .await
        .expect("send_to_client search_versions");
    assert!(
        matches!(outcome, ClientSendOutcome::Executed { .. }),
        "expected Executed, got {outcome:?}"
    );
    let requests = seen.lock().unwrap().clone();
    assert!(
        requests
            .iter()
            .any(|r| r.starts_with("GET /org/example/demo/maven-metadata.xml ")),
        "stub repository should have seen the metadata request, saw {requests:?}"
    );

    // A verb Maven does not have is rejected by the protocol, not silently swallowed.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "maven_deploy"}),
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

/// A bare `host:port` — what the dashboard's `[ + Maven client ]` fills in — is given a scheme
/// at connect: `https://` natively (the browser build gives `http://`, the only scheme its
/// transport speaks). Every URL the client builds is absolute; a scheme-less repository made
/// reqwest refuse each request as a relative URL. An explicit scheme is kept as given.
#[tokio::test]
async fn a_bare_repository_address_is_given_a_scheme() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();
    let mut stored = Vec::new();
    for remote in ["127.0.0.1:1", "http://127.0.0.1:1/maven2"] {
        let client_id = ClientForm {
            protocol: "maven".to_string(),
            remote_addr: Some(remote.to_string()),
            instruction: Some("test client".to_string()),
            ..Default::default()
        }
        .create(
            &state,
            netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
            tx.clone(),
        )
        .await
        .expect("create maven client");
        let url = state
            .with_client_mut(client_id, |c| {
                c.get_protocol_field("repository_url")
                    .and_then(|v| v.as_str())
                    .map(str::to_string)
            })
            .await
            .flatten();
        stored.push(url);
    }
    assert_eq!(
        stored,
        vec![
            Some("https://127.0.0.1:1".to_string()),
            Some("http://127.0.0.1:1/maven2".to_string())
        ]
    );
}

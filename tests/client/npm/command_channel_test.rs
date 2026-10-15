//! The dashboard's `[ send ]` path on an NPM client: `AppState::send_to_client` injects an
//! action from outside the client's own task and the resulting registry request really goes
//! out. Zero LLM calls - the client's LLM points at an unreachable URL, so the response
//! event's LLM call fails and the loop must tolerate that; that tolerance is part of what
//! this test verifies.
//!
//! The "registry" is a throwaway `TcpListener` on 127.0.0.1 speaking just enough HTTP/1.1.
//! Nothing here contacts registry.npmjs.org, which is why `search_packages` and
//! `download_tarball` are exercised only through their rejection/`Rejected` paths: NPM's
//! search endpoint is hardcoded to the public registry.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features npm --test client -- npm::command_channel --test-threads=100

use std::sync::{Arc, Mutex};
use std::time::Duration;

use netget::cli::management::ClientForm;
use netget::state::app_state::AppState;
use netget::state::client_handles::ClientSendOutcome;
use netget::state::{AccessLogOwner, ClientId, ClientStatus};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

/// A minimal `/-/v1/search` body, in the shape the client parses.
const SEARCH_JSON: &str =
    r#"{"objects":[{"package":{"name":"express","version":"4.18.2"}}],"total":1}"#;

const PACKAGE_JSON: &str = r#"{"name":"express","description":"fast web framework","dist-tags":{"latest":"4.18.2"},"versions":{"4.18.2":{"dist":{"tarball":"http://127.0.0.1:1/express.tgz"}}}}"#;

/// A local stand-in for the registry. Returns the port and the request lines it saw.
async fn stub_registry(body: &'static str) -> (u16, Arc<Mutex<Vec<String>>>) {
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
        "NPM client #{} never registered a command handle",
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
async fn injected_npm_action_reaches_the_registry() {
    let (port, seen) = stub_registry(PACKAGE_JSON).await;
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    let client_id = ClientForm {
        protocol: "npm".to_string(),
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
    .expect("create npm client");

    wait_for_client_handle(&state, client_id).await;

    // NPM's own verb, injected from outside the client's task. The outcome is
    // `Executed`, not `Sent`: reqwest issues the request but reports no wire byte
    // count, so claiming a number would be a lie.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "get_package_info", "package_name": "express", "version": "latest"}),
            Duration::from_secs(30),
        )
        .await
        .expect("send_to_client");
    match &outcome {
        ClientSendOutcome::Executed { detail } => {
            assert!(
                detail.contains("get_package_info express@latest")
                    && detail.contains("version 4.18.2"),
                "detail should name the request that ran and what the registry answered, \
                 got {detail:?}"
            );
        }
        other => panic!("expected Executed, got {other:?}"),
    }

    // Awaited, so by the time the outcome came back the request had really gone out.
    let requests = seen.lock().unwrap().clone();
    assert!(
        requests.iter().any(|r| r.starts_with("GET /express ")),
        "stub registry should have seen GET /express, saw {requests:?}"
    );

    // Recorded on the client like LLM-produced traffic.
    wait_for_log_containing(
        &state,
        AccessLogOwner::Client(client_id.as_u32()),
        "injected_action",
    )
    .await;

    // A verb NPM does not have is rejected by the protocol, not silently swallowed.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "npm_publish"}),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_client unknown");
    assert!(
        matches!(outcome, ClientSendOutcome::Rejected { .. }),
        "expected Rejected, got {outcome:?}"
    );

    // An injected disconnect ends the command loop and drops the handle, so the rail
    // stops offering [ send ].
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

/// A parked response event must not wedge the command loop.
///
/// This is the regression guard for the shape of `apply_action`: it awaits the **network**
/// half only and raises `npm_package_info_received` from its own task. With a `*` -> manual
/// routing rule - the default for a client created through the dashboard, which is exactly
/// the workflow `[ send ]` exists for - that event parks until a human answers it. If the
/// loop awaited the event too, the second `[ send ]` below would time out instead of
/// returning an outcome, which is what an operator injecting two commands in a row hits.
#[tokio::test]
async fn a_parked_response_event_does_not_block_the_next_injected_command() {
    let (port, seen) = stub_registry(PACKAGE_JSON).await;
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    let client_id = ClientForm {
        protocol: "npm".to_string(),
        remote_addr: Some(format!("http://127.0.0.1:{port}")),
        instruction: Some("test client".to_string()),
        // The dashboard's default for an interactively created client: a human answers.
        event_handlers: Some(vec![serde_json::json!({
            "event_pattern": "*",
            "handler": { "type": "manual", "timeout_secs": 300 }
        })]),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
        tx.clone(),
    )
    .await
    .expect("create npm client");

    wait_for_client_handle(&state, client_id).await;

    let first = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "get_package_info", "package_name": "express"}),
            Duration::from_secs(30),
        )
        .await
        .expect("first send_to_client");
    assert!(
        matches!(first, ClientSendOutcome::Executed { .. }),
        "expected Executed, got {first:?}"
    );

    // The response event is now parked waiting for a human, exactly as the rail shows it.
    let mut parked = None;
    for _ in 0..1_000 {
        parked = state
            .list_intercepts()
            .await
            .into_iter()
            .find(|i| i.event_type == "npm_package_info_received");
        if parked.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    let parked = parked.expect("npm_package_info_received should be parked for a manual answer");

    // ... and the loop is still free. A 10s budget is far below the 300s intercept timeout,
    // so this can only pass if the command loop is not waiting on that answer.
    let second = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "get_package_info", "package_name": "express"}),
            Duration::from_secs(10),
        )
        .await
        .expect("second send_to_client must not wait on the parked event");
    assert!(
        matches!(second, ClientSendOutcome::Executed { .. }),
        "expected Executed, got {second:?}"
    );

    let requests = seen.lock().unwrap().clone();
    assert_eq!(
        requests
            .iter()
            .filter(|r| r.starts_with("GET /express "))
            .count(),
        2,
        "both injected commands should have reached the registry, saw {requests:?}"
    );

    // The question really was still open the whole time.
    assert!(
        state
            .list_intercepts()
            .await
            .iter()
            .any(|i| i.id == parked.id),
        "the first response event should still be parked"
    );
    state.dismiss_intercept(parked.id).await;
}

/// `search_packages` must query the registry this client was configured with.
///
/// It used to hardcode `https://registry.npmjs.org/-/v1/search` while every other verb
/// honoured the declared `registry_url` startup parameter, so a client pointed at a private
/// registry silently queried the public one -- and the behaviour could not be tested at all
/// without reaching the real internet, which this project forbids.
#[tokio::test]
async fn injected_search_queries_the_configured_registry_not_the_public_one() {
    let (port, seen) = stub_registry(SEARCH_JSON).await;
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    let client_id = ClientForm {
        protocol: "npm".to_string(),
        remote_addr: Some(format!("http://127.0.0.1:{port}")),
        instruction: Some("search client".to_string()),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
        tx.clone(),
    )
    .await
    .expect("create npm client");

    wait_for_client_handle(&state, client_id).await;

    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "search_packages", "query": "express", "limit": 1}),
            Duration::from_secs(30),
        )
        .await
        .expect("send_to_client search_packages");
    assert!(
        matches!(outcome, ClientSendOutcome::Executed { .. }),
        "expected Executed, got {outcome:?}"
    );

    // The proof: the loopback stub saw the search, so the request did not go to
    // registry.npmjs.org. Nothing in this test can reach the public internet.
    let requests = seen.lock().unwrap().clone();
    assert!(
        requests.iter().any(|r| r.starts_with("GET /-/v1/search?")),
        "search must hit the configured registry's /-/v1/search, saw {requests:?}"
    );
}

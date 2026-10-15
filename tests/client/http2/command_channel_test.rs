//! The dashboard's `[ send ]` path on an HTTP/2 client: `AppState::send_to_client` injects an
//! action from outside the client's own task, and the request reaches a NetGet HTTP/2 server of
//! our own over cleartext h2c (the client uses `http2_prior_knowledge()`; the server is started
//! without `tls_enabled`). Zero LLM calls - the server answers through a `*` static handler and
//! the client's LLM points at an unreachable URL.
//!
//! Why `Executed` and not `Sent`: reqwest owns the socket and never reports how many bytes the
//! request serialised to, so a byte count would be invented. The detail carries the response
//! status instead.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features http2 --test client -- http2::command_channel --test-threads=100


use std::time::Duration;

use netget::cli::management::{ClientForm, ServerForm};
use netget::state::app_state::AppState;
use netget::state::client_handles::ClientSendOutcome;
use netget::state::{AccessLogOwner, ClientId, ClientStatus, ServerId};
use tokio::sync::mpsc;

async fn new_state() -> AppState {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".to_string());
    state
        .set_llm_client(netget::llm::OllamaClient::new(
            "http://127.0.0.1:1".to_string(),
        ))
        .await;
    state
}

async fn wait_for_port(state: &AppState, id: ServerId) -> u16 {
    for _ in 0..1_000 {
        if let Some(s) = state.get_server(id).await {
            if let Some(addr) = s.local_addr {
                return addr.port();
            }
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("HTTP/2 server #{} never bound a port", id.as_u32());
}

async fn wait_for_client_handle(state: &AppState, id: ClientId) {
    for _ in 0..1_000 {
        if state.has_client_handle(id).await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!(
        "HTTP/2 client #{} never registered a command handle",
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
async fn injected_http2_request_reaches_our_own_server() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    let server_id = ServerForm {
        protocol: "http2".to_string(),
        port: Some(0),
        event_handlers: Some(vec![serde_json::json!({
            "event_pattern": "*",
            "handler": {
                "type": "static",
                "actions": [ {
                    "type": "send_http2_response",
                    "status": 200,
                    "headers": { "content-type": "text/plain" },
                    "body": "hello from netget"
                } ]
            }
        })]),
        ..Default::default()
    }
    .create(&state, tx.clone())
    .await
    .expect("create http2 server");
    let port = wait_for_port(&state, server_id).await;

    let client_id = ClientForm {
        protocol: "http2".to_string(),
        remote_addr: Some(format!("127.0.0.1:{port}")),
        instruction: Some("test client".to_string()),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
        tx.clone(),
    )
    .await
    .expect("create http2 client");

    // The handle must exist as soon as connect() returns, or the dashboard greys out
    // [ send ] on a client that is up.
    wait_for_client_handle(&state, client_id).await;

    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({
                "type": "send_http2_request",
                "method": "GET",
                "path": "/dashboard-marker"
            }),
            Duration::from_secs(20),
        )
        .await
        .expect("send_to_client");
    match &outcome {
        ClientSendOutcome::Executed { detail } => {
            assert!(
                detail.contains("GET /dashboard-marker") && detail.contains("-> 200"),
                "expected the awaited exchange in the detail, got {detail:?}"
            );
        }
        other => panic!("expected Executed, got {other:?}"),
    }

    wait_for_log_containing(
        &state,
        AccessLogOwner::Client(client_id.as_u32()),
        "injected_action",
    )
    .await;
    wait_for_log_containing(
        &state,
        AccessLogOwner::Server(server_id.as_u32()),
        "/dashboard-marker",
    )
    .await;

    // An action the protocol does not know is rejected, not silently swallowed.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "no_such_action"}),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_client unknown action");
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

//! The dashboard's `[ send ]` path on an etcd client: `AppState::send_to_client` injects an
//! action from outside the connect task and the operation runs on the *live* etcd session -
//! the one `connect_with_llm_actions` established - reaching a NetGet etcd server of our own.
//!
//! Zero LLM calls: the server answers through static handlers and the client's LLM points at
//! an unreachable URL, so its connected-event call fails and the connect path must tolerate
//! that. Verifying it does is part of the point.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features etcd --test client -- etcd::command_channel --test-threads=100


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
    panic!("etcd server #{} never bound a port", id.as_u32());
}

async fn wait_for_client_handle(state: &AppState, id: ClientId) {
    for _ in 0..1_000 {
        if state.has_client_handle(id).await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!(
        "etcd client #{} never registered a command handle",
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
async fn injected_etcd_operation_reaches_our_own_server() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    let server_id = ServerForm {
        protocol: "etcd".to_string(),
        port: Some(0),
        event_handlers: Some(vec![
            serde_json::json!({
                "event_pattern": "etcd_put_request",
                "handler": {
                    "type": "static",
                    "actions": [ { "type": "etcd_put_response", "revision": 7 } ]
                }
            }),
            serde_json::json!({
                "event_pattern": "etcd_range_request",
                "handler": {
                    "type": "static",
                    "actions": [ {
                        "type": "etcd_range_response",
                        "kvs": [ {
                            "key": "/dashboard/marker",
                            "value": "hello",
                            "create_revision": 7,
                            "mod_revision": 7,
                            "version": 1,
                            "lease": 0
                        } ],
                        "more": false,
                        "count": 1
                    } ]
                }
            }),
        ]),
        ..Default::default()
    }
    .create(&state, tx.clone())
    .await
    .expect("create etcd server");
    let port = wait_for_port(&state, server_id).await;

    let client_id = ClientForm {
        protocol: "etcd".to_string(),
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
    .expect("create etcd client");

    // Regression guard for "register the channel BEFORE the connected-event LLM call":
    // the handle must exist without anything having answered that call.
    wait_for_client_handle(&state, client_id).await;

    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({
                "type": "etcd_put", "key": "/dashboard/marker", "value": "hello"
            }),
            Duration::from_secs(20),
        )
        .await
        .expect("send_to_client etcd_put");

    // Deliberately `Executed`, never `Sent`: `etcd-client` owns the HTTP/2 connection and
    // never reports how many bytes a request serialised to, so a byte count here would be
    // invented. The detail carries what etcd actually answered instead.
    match &outcome {
        ClientSendOutcome::Executed { detail } => {
            assert!(
                detail.contains("/dashboard/marker") && detail.contains("revision 7"),
                "detail should carry the key and the revision our server returned, got {detail:?}"
            );
        }
        other => panic!("expected Executed, got {other:?}"),
    }

    // Recorded on the client like LLM-produced traffic, and received by the server.
    wait_for_log_containing(
        &state,
        AccessLogOwner::Client(client_id.as_u32()),
        "injected_action",
    )
    .await;
    wait_for_log_containing(
        &state,
        AccessLogOwner::Server(server_id.as_u32()),
        "/dashboard/marker",
    )
    .await;

    // A second operation on the same handle proves the session really is reused rather
    // than re-dialled per action.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "etcd_get", "key": "/dashboard/marker"}),
            Duration::from_secs(20),
        )
        .await
        .expect("send_to_client etcd_get");
    match &outcome {
        ClientSendOutcome::Executed { detail } => {
            assert!(
                detail.contains("1 key-value pair"),
                "detail should carry the pair count, got {detail:?}"
            );
        }
        other => panic!("expected Executed, got {other:?}"),
    }

    // An unknown verb is refused, not silently swallowed.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "definitely_not_an_etcd_action"}),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_client unknown");
    assert!(
        matches!(outcome, ClientSendOutcome::Rejected { .. }),
        "expected Rejected, got {outcome:?}"
    );

    // An injected disconnect ends the command loop and takes the handle with it.
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

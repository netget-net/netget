//! The dashboard's `[ call_xmlrpc_method ]` path on an XML-RPC client:
//! `AppState::send_to_client` injects an action from outside the client's own tasks and the
//! call reaches a NetGet XML-RPC server of our own. Zero LLM calls - the server answers
//! through a `*` static handler and the client's LLM points at an unreachable URL (its
//! connected-event call fails; the loop tolerates that, and the command loop is registered
//! before that call by design).
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features xmlrpc --test client -- xmlrpc::command_channel --test-threads=100


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
    panic!("XML-RPC server #{} never bound a port", id.as_u32());
}

async fn wait_for_client_handle(state: &AppState, id: ClientId) {
    for _ in 0..1_000 {
        if state.has_client_handle(id).await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!(
        "XML-RPC client #{} never registered a command handle",
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
async fn injected_xmlrpc_call_reaches_our_own_server() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    let server_id = ServerForm {
        protocol: "XML-RPC".to_string(),
        port: Some(0),
        event_handlers: Some(vec![serde_json::json!({
            "event_pattern": "*",
            "handler": {
                "type": "static",
                "actions": [ {
                    "type": "xmlrpc_success_response",
                    "value_type": "string",
                    "value": "injected-marker-ok"
                } ]
            }
        })]),
        ..Default::default()
    }
    .create(&state, tx.clone())
    .await
    .expect("create xmlrpc server");
    let port = wait_for_port(&state, server_id).await;

    let client_id = ClientForm {
        protocol: "XML-RPC".to_string(),
        remote_addr: Some(format!("http://127.0.0.1:{port}/RPC2")),
        instruction: Some("test client".to_string()),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
        tx.clone(),
    )
    .await
    .expect("create xmlrpc client");

    // Registered before (not after) the connected-event LLM call, which this client awaits
    // inline: the regression guard for "[ send ] reads 'no command channel' during a park".
    wait_for_client_handle(&state, client_id).await;

    // XML-RPC rides on HTTP through a blocking library, so no byte count can honestly be
    // reported; the outcome describes the call that really completed.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({
                "type": "call_xmlrpc_method",
                "method_name": "injected.marker",
                "params": ["hello", 3]
            }),
            Duration::from_secs(10),
        )
        .await
        .expect("send_to_client");
    match &outcome {
        ClientSendOutcome::Executed { detail } => {
            assert!(
                detail.contains("injected.marker") && detail.contains("2 param(s)"),
                "detail should name the method and its parameter count, got {detail:?}"
            );
            assert!(
                detail.contains("server returned a result"),
                "the server answered with a value, so the detail must say so: {detail:?}"
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
        "injected.marker",
    )
    .await;

    // An action the protocol does not know is Rejected - never silently swallowed.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "no_such_action"}),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_client rejected action");
    assert!(
        matches!(outcome, ClientSendOutcome::Rejected { .. }),
        "expected Rejected, got {outcome:?}"
    );

    // An injected disconnect ends the command loop and drops the handle.
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

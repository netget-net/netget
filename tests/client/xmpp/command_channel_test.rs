//! The dashboard's `[ send ]` path on an XMPP client.
//!
//! What this pins without a server: the command channel is registered before the session is
//! up (and so before the `xmpp_connected` LLM call, which a manual rule can park for minutes),
//! injected actions run through the protocol's own `execute_action` so an unknown name is
//! refused rather than swallowed, the outcome is recorded in the client's access log, and an
//! injected `disconnect` shuts the stream down, drops the handle and fails a session that never
//! came up.
//!
//! The "server" is a loopback listener that accepts and never answers, so the client sits with
//! its session pending - `ClientForm::create` does not return until it is online or has failed,
//! which is why it runs in its own task here.
//!
//! What it does **not** pin: a stanza actually reaching a peer. `tokio_xmpp::Client::send_stanza`
//! resolves only once the stanza has been written to the transport, and no XMPP server this
//! suite can start (the NetGet XMPP server does not complete tokio-xmpp's STARTTLS/SASL
//! negotiation) gives us that transport - so `send_message` is left to a real server, exactly as
//! `tests/client/xmpp/e2e_test.rs` does. See `src/client/xmpp/AGENTS.md`.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features xmpp --test client -- xmpp::command_channel --test-threads=100

#![cfg(unix)]

use std::time::Duration;

use netget::cli::management::ClientForm;
use netget::state::app_state::AppState;
use netget::state::client_handles::ClientSendOutcome;
use netget::state::{AccessLogOwner, ClientId};
use tokio::net::TcpListener;
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

/// The id of the one client in `state`, once `create` has registered it.
async fn wait_for_client(state: &AppState) -> ClientId {
    for _ in 0..1_000 {
        if let Some(client) = state.get_all_clients().await.first() {
            return client.id;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("the XMPP client was never registered");
}

async fn wait_for_client_handle(state: &AppState, id: ClientId) {
    for _ in 0..1_000 {
        if state.has_client_handle(id).await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!(
        "XMPP client #{} never registered a command handle",
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
async fn injected_actions_run_in_the_xmpp_client() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    // Accept and hold the connection without a word: the session stays pending throughout,
    // which is precisely the state in which [ send ] must still be reachable.
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let target = listener.local_addr().expect("local addr");
    let holder = tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = listener.accept().await {
            held.push(stream);
        }
    });

    let create_state = state.clone();
    let create = tokio::spawn(async move {
        ClientForm {
            protocol: "xmpp".to_string(),
            remote_addr: Some(target.to_string()),
            instruction: Some("test client".to_string()),
            startup_params: Some(serde_json::json!({
                "jid": "netget@example.invalid",
                "password": "secret",
                "session_timeout_secs": 120,
            })),
            ..Default::default()
        }
        .create(
            &create_state,
            netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
            tx.clone(),
        )
        .await
    });
    let client_id = wait_for_client(&state).await;

    // The regression guard for "register the channel before the connected-event LLM call".
    wait_for_client_handle(&state, client_id).await;

    // Runs without touching the stream, so it is answerable with no server: the honest
    // outcome is Executed with a reason, never Sent{0}.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "wait_for_more"}),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_client wait_for_more");
    match &outcome {
        ClientSendOutcome::Executed { detail } => assert!(
            detail.contains("nothing sent"),
            "detail should say nothing went on the wire, got {detail:?}"
        ),
        other => panic!("expected Executed for wait_for_more, got {other:?}"),
    }

    // Unknown names are refused by the protocol's own execute_action.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "not_an_xmpp_action"}),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_client unknown");
    assert!(
        matches!(outcome, ClientSendOutcome::Rejected { .. }),
        "expected Rejected, got {outcome:?}"
    );

    // Injected actions are recorded on the client like LLM-produced traffic.
    wait_for_log_containing(
        &state,
        AccessLogOwner::Client(client_id.as_u32()),
        "injected_action",
    )
    .await;

    // An injected disconnect closes the stream; the event loop then runs its normal exit path.
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

    let mut handle_gone = false;
    for _ in 0..1_000 {
        if !state.has_client_handle(client_id).await {
            handle_gone = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    assert!(
        handle_gone,
        "the command handle should be gone after an injected disconnect"
    );

    // The session never came up, so closing the client fails its start.
    let err = tokio::time::timeout(Duration::from_secs(10), create)
        .await
        .expect("create should return promptly once the client is closed")
        .expect("create task")
        .expect_err("a client closed before its session came up did not start");
    assert!(
        err.to_string().contains("closed"),
        "the error should say the client was closed, got: {err}"
    );
    holder.abort();
}

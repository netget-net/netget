//! Does the Nostr client answer the relay events that arrived during a model call together,
//! when it batches?
//!
//! The owned mock relay serves a subscription; it sends `first`, which the mock model answers
//! slowly, then `second` and — 200 ms later — `third` while that call runs. They wait in the
//! client's dispatcher queue. Batching off is the control, in the same test as the claim:
//! three model calls, one per event. Batching on: two, the second triggered by `third` with
//! `second` listed above it.

use super::common::{mock_peer, signed};
use crate::helpers::mock_builder::MockLlmBuilder;
use crate::helpers::mock_ollama::MockOllamaServer;
use netget::cli::management::ClientForm;
use netget::state::{app_state::AppState, client_handles::ClientSendOutcome};
use serde_json::{json, Value};
use std::time::Duration;
use tokio::sync::mpsc;

const EVENT: &str = "nostr_received_event";

fn text(data: &Value) -> String {
    data["event"]["content"]
        .as_str()
        .unwrap_or_default()
        .to_string()
}

async fn calls(mock: &MockOllamaServer) -> Vec<(Value, String)> {
    mock.recorded_calls()
        .await
        .into_iter()
        .filter(|c| c.context.event_type.as_deref() == Some(EVENT))
        .map(|c| (c.context.event_data.clone(), c.context.prompt.clone()))
        .collect()
}

async fn wait_for(mock: &MockOllamaServer, want: &str) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        let calls = calls(mock).await;
        if calls.iter().any(|(d, _)| text(d) == want) {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "`{want}` never reached the model; calls: {calls:#?}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn session(batching: bool) -> Vec<(Value, String)> {
    let mock = MockOllamaServer::start(
        MockLlmBuilder::new()
            .on_event(EVENT)
            .and_event_data_contains("event", r#""content":"first""#)
            .respond_with_actions(json!([]))
            .after_delay(Duration::from_millis(1500))
            .expect_calls(1)
            .and()
            .on_any()
            .respond_with_actions(json!([]))
            .expect_at_least(0)
            .build(),
    )
    .await
    .expect("mock ollama");
    let state = AppState::new_with_options(false, mock.base_url());
    let llm = netget::llm::OllamaClient::new(mock.base_url());
    state.set_llm_client(llm.clone()).await;

    let peer = mock_peer("normal").await;
    let (tx, _rx) = mpsc::unbounded_channel();
    let id = ClientForm {
        protocol: "nostr".into(),
        remote_addr: Some(peer.address.clone()),
        instruction: Some("Note what the relay sends.".into()),
        batching: Some(batching),
        ..Default::default()
    }
    .create(&state, llm, tx)
    .await
    .expect("create client");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while !state.has_client_handle(id).await {
        assert!(tokio::time::Instant::now() < deadline, "no command channel");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let outcome = state
        .send_to_client(
            id,
            json!({"type":"nostr_subscribe","subscription_id":"live","filters":[{"kinds":[1],"limit":0}]}),
            Duration::from_secs(5),
        )
        .await
        .unwrap();
    assert!(
        matches!(outcome, ClientSendOutcome::Executed { .. }),
        "{outcome:?}"
    );

    peer.frame(json!(["EVENT", "live", signed("first")])).await;
    wait_for(&mock, "first").await;
    peer.frame(json!(["EVENT", "live", signed("second")])).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    peer.frame(json!(["EVENT", "live", signed("third")])).await;
    wait_for(&mock, "third").await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    let calls = calls(&mock).await;
    let _ = state.remove_client(id).await;
    peer.stop().await;
    calls
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn nostr_client_answers_relay_events_that_arrived_during_a_call_together() {
    let separate = session(false).await;
    let texts: Vec<String> = separate.iter().map(|(d, _)| text(d)).collect();
    assert_eq!(
        texts,
        ["first", "second", "third"],
        "CONTROL FAILED: with batching off each relay event must be its own model call"
    );

    let batched = session(true).await;
    let texts: Vec<String> = batched.iter().map(|(d, _)| text(d)).collect();
    assert_eq!(
        texts,
        ["first", "third"],
        "the two events that arrived during the first call must be one model call, triggered \
         by the newest"
    );
    let prompt = &batched[1].1;
    let before = &prompt[..prompt.rfind(&format!("Event: {EVENT}")).expect("trigger")];
    assert!(
        before.lines().any(
            |l| l.starts_with(&format!("(1) {EVENT} ")) && l.contains(r#""content":"second""#)
        ),
        "the earlier event must be listed as arrived and not yet answered:\n{prompt}"
    );
    assert!(
        before.contains("answers all 2 together"),
        "the model must be told it answers both:\n{prompt}"
    );
}

//! What a Nostr client gets when the model cannot answer: a refusal in NIP-01's own terms —
//! never silence, never an invented acceptance, never the error text.
//!
//! * the backend is down → a published event gets `OK false "error: …"` (or `"rate-limited: …"`
//!   when the backend is overloaded), a subscription gets `CLOSED`; `decision=fail_closed_llm_error`;
//! * the handler produced nothing for an event → `OK false`, `decision=model_silent` — silence
//!   must not read as acceptance;
//! * the handler produced an answer that does not fit (events for a published event, events
//!   NetGet cannot sign for a subscription) → the same refusals, `decision=fail_closed_bad_action`.
//!
//! In every case the connection stays usable.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features nostr --test server -- nostr::llm_failure --test-threads=100


use super::common::{self, event_frame, note, Peer};
use netget::cli::management::ServerForm;
use serde_json::json;
use tokio::sync::mpsc;

const LEAKS: &[&str] = &[
    "http://",
    "127.0.0.1:1",
    "ollama",
    "Ollama",
    "retries",
    ".rs:",
    "error sending request",
    "Connection refused",
];

fn assert_no_leak(text: &str) {
    for leak in LEAKS {
        assert!(!text.contains(leak), "`{leak}` reached the wire: {text}");
    }
}

#[tokio::test]
async fn a_backend_failure_refuses_in_nip01_terms_and_logs_fail_closed_llm_error() {
    let state = common::new_state().await;
    let (tx, mut rx) = mpsc::unbounded_channel();
    let server_id = ServerForm {
        protocol: "nostr".to_string(),
        port: Some(0),
        instruction: Some("A relay for film notes".to_string()),
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .expect("create nostr relay");
    let port = common::wait_for_port(&state, server_id).await;
    let mut peer = Peer::connect(port).await;

    let event = note("a note nobody can decide on", vec![], 1);
    peer.send(&event_frame(&event)).await;
    // Generous: the failure path runs through the retry loop first.
    let ok = peer.json(120).await;
    assert_eq!(ok[0], "OK");
    assert_eq!(ok[1], event.id.as_str());
    assert_eq!(
        ok[2], false,
        "a failed decision is never an acceptance: {ok}"
    );
    let message = ok[3].as_str().unwrap();
    assert!(
        message == "error: the relay could not decide on this event"
            || message == "rate-limited: the relay is at capacity, retry later",
        "{message}"
    );
    assert_no_leak(&ok.to_string());
    common::wait_for_log(&mut rx, "decision=fail_closed_llm_error", 30).await;

    peer.send_json(json!(["REQ", "films", {"kinds": [1]}]))
        .await;
    let closed = peer.json(120).await;
    assert_eq!(closed[0], "CLOSED", "{closed}");
    assert_eq!(closed[1], "films");
    assert!(
        closed[2].as_str().unwrap().starts_with("error:")
            || closed[2].as_str().unwrap().starts_with("rate-limited:"),
        "{closed}"
    );
    assert_no_leak(&closed.to_string());
}

#[tokio::test]
async fn a_handler_that_answers_nothing_refuses_the_event_and_says_model_silent() {
    let state = common::new_state().await;
    let (_id, port, mut rx) = common::start(
        &state,
        vec![
            json!({"event_pattern": "nostr_event", "handler": {"type": "static", "actions": []}}),
            json!({"event_pattern": "nostr_req", "handler": {"type": "static", "actions": []}}),
        ],
        None,
    )
    .await;
    let mut peer = Peer::connect(port).await;
    let event = note("undecided", vec![], 1);
    peer.send(&event_frame(&event)).await;
    assert_eq!(
        peer.json(10).await,
        json!([
            "OK",
            event.id,
            false,
            "error: the relay made no decision on this event"
        ])
    );
    common::wait_for_log(&mut rx, "decision=model_silent", 10).await;

    // A subscription nobody supplied events for has none: EOSE, and it stays open.
    peer.send_json(json!(["REQ", "empty", {}])).await;
    assert_eq!(peer.json(10).await, json!(["EOSE", "empty"]));
}

#[tokio::test]
async fn answers_that_do_not_fit_are_refused_as_bad_actions() {
    let state = common::new_state().await;
    let (_id, port, mut rx) = common::start(
        &state,
        vec![
            // Events are an answer to a subscription, not to a published event.
            json!({"event_pattern": "nostr_event", "handler": {"type": "static", "actions": [
                {"type": "send_nostr_events", "events": [{"kind": 1, "content": "x"}]}
            ]}}),
            // An event without a kind cannot be signed.
            json!({"event_pattern": "nostr_req", "handler": {"type": "static", "actions": [
                {"type": "send_nostr_events", "events": [{"content": "no kind"}]}
            ]}}),
        ],
        None,
    )
    .await;
    let mut peer = Peer::connect(port).await;
    let event = note("answered wrongly", vec![], 1);
    peer.send(&event_frame(&event)).await;
    assert_eq!(
        peer.json(10).await,
        json!([
            "OK",
            event.id,
            false,
            "error: the relay made no decision on this event"
        ])
    );
    common::wait_for_log(&mut rx, "decision=fail_closed_bad_action", 10).await;

    peer.send_json(json!(["REQ", "films", {}])).await;
    assert_eq!(
        peer.json(10).await,
        json!([
            "CLOSED",
            "films",
            "error: the relay could not answer this subscription"
        ])
    );
    common::wait_for_log(&mut rx, "decision=fail_closed_bad_action", 10).await;
}

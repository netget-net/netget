//! What a Gemini client gets when the model cannot answer: a temporary-failure status, never
//! silence and never the error text.
//!
//! The specification's choices, and why:
//!
//! * **41 SERVER UNAVAILABLE** is defined as "unavailable due to overload or maintenance" — the
//!   `WireFailure::Overloaded` category exactly, so a client backs off and retries.
//! * **40 TEMPORARY FAILURE** is the generic temporary failure, for every other backend error
//!   and for a model that produced no response. `42 CGI ERROR` names a dynamic-content process
//!   dying and would put an implementation detail in the client's face; `44 SLOW DOWN` demands a
//!   wait in seconds that nothing knows.
//!
//! Neither is a permanent failure: nothing about the request was wrong.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features gemini --test server -- gemini::llm_failure --test-threads=100


use super::common::{self, raw_request, split_response};
use netget::cli::management::ServerForm;
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

#[tokio::test]
async fn a_backend_failure_answers_40_and_logs_fail_closed_llm_error() {
    let state = common::new_state().await;
    let (tx, mut rx) = mpsc::unbounded_channel();
    let server_id = ServerForm {
        protocol: "gemini".to_string(),
        port: Some(0),
        instruction: Some("A capsule about cats".to_string()),
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .expect("create gemini server");
    let port = common::wait_for_port(&state, server_id).await;

    let response = raw_request(port, b"gemini://localhost/", 120).await;
    let (header, body) = split_response(&response);
    assert!(
        header == "40 request could not be processed"
            || header == "41 backend at capacity, retry later",
        "expected a temporary failure, got {header:?}"
    );
    assert!(body.is_empty());
    for leak in LEAKS {
        assert!(
            !header.contains(leak),
            "`{leak}` reached the wire: {header:?}"
        );
    }
    common::wait_for_log(&mut rx, "decision=fail_closed_llm_error", 30).await;
}

#[tokio::test]
async fn a_handler_that_answers_nothing_gets_40_and_model_silent() {
    let state = common::new_state().await;
    let silent = serde_json::json!({
        "event_pattern": "gemini_request",
        "handler": {"type": "static", "actions": []}
    });
    let (_id, port, mut rx) = common::start(&state, vec![silent], None).await;
    let response = raw_request(port, b"gemini://localhost/", 30).await;
    assert_eq!(
        split_response(&response).0,
        "40 request could not be processed",
        "a request nobody answered must not be answered with an invented page or 51"
    );
    common::wait_for_log(&mut rx, "decision=model_silent", 10).await;
}

#[tokio::test]
async fn a_model_refusal_is_sent_and_logged_as_model_reject() {
    let state = common::new_state().await;
    let refuse = serde_json::json!({
        "event_pattern": "gemini_request",
        "handler": {"type": "static", "actions": [
            {"type": "send_gemini_response", "status": 52, "meta": "", "body": "ignored"}
        ]}
    });
    let (_id, port, mut rx) = common::start(&state, vec![refuse], None).await;
    let response = raw_request(port, b"gemini://localhost/old", 30).await;
    let (header, body) = split_response(&response);
    assert_eq!(
        header, "52 Gone",
        "an empty meta takes the status's default"
    );
    assert!(
        body.is_empty(),
        "a body is never sent after a non-2x status"
    );
    common::wait_for_log(&mut rx, "decision=model_reject", 10).await;
}

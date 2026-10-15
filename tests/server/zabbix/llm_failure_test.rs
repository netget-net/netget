//! What a sender gets when the model cannot answer: `processed: 0; failed: N; total: N` —
//! the one answer `zabbix_sender` turns into exit status 2. Never silence, never an internal
//! error string, never an invented `processed: N`.
//!
//! Why not `{"response":"failed"}`: zabbix_sender 7.4 prints a warning on it and exits **0**
//! (measured), so a script checking `$?` would believe its values were stored. Counting every
//! value as failed is the answer the sender acts on.
//!
//! The outcomes, identical on the wire and distinct in the log:
//!
//! * backend down → `decision=fail_closed_llm_error`;
//! * the handler answered nothing → `decision=model_silent`;
//! * counts that do not add up to the request → `decision=fail_closed_mismatched_reply`;
//! * `processed: 0` from the model itself → sent as-is, `decision=model_reject`;
//! * `close_connection` from the model → no bytes, `decision=model_close`.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features zabbix --test server -- zabbix::llm_failure --test-threads=100


use super::common::{self, exchange, response, sender_data};
use netget::cli::management::ServerForm;
use netget::server::zabbix::wire;
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

fn two_values() -> Vec<u8> {
    wire::encode(&sender_data(&[("h", "a", "1"), ("h", "b", "2")]))
}

fn info_prefix(body: &serde_json::Value) -> String {
    let info = body["info"].as_str().unwrap_or_default();
    info.split("; seconds spent").next().unwrap().to_string()
}

#[tokio::test]
async fn a_backend_failure_counts_every_value_failed() {
    let state = common::new_state().await;
    let (tx, mut rx) = mpsc::unbounded_channel();
    let server_id = ServerForm {
        protocol: "zabbix".to_string(),
        port: Some(0),
        instruction: Some("Accept every value".to_string()),
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .expect("create zabbix server");
    let port = common::wait_for_port(&state, server_id).await;

    // Generous: the failure path runs through the retry loop first.
    let reply = exchange(port, &two_values(), 120).await;
    let text = String::from_utf8_lossy(&reply);
    for leak in LEAKS {
        assert!(!text.contains(leak), "`{leak}` reached the wire: {text}");
    }
    let (_, _, body) = response(&reply);
    assert_eq!(body["response"], "success");
    assert_eq!(info_prefix(&body), "processed: 0; failed: 2; total: 2");
    common::wait_for_log(&mut rx, "decision=fail_closed_llm_error", 30).await;
}

async fn against(handler: serde_json::Value) -> (Vec<u8>, mpsc::UnboundedReceiver<String>) {
    let state = common::new_state().await;
    let (_id, port, rx) = common::start(&state, vec![handler], None).await;
    let reply = exchange(port, &two_values(), 30).await;
    (reply, rx)
}

fn static_handler(actions: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "event_pattern": "zabbix_sender_data",
        "handler": {"type": "static", "actions": actions}
    })
}

#[tokio::test]
async fn a_handler_that_answers_nothing_counts_every_value_failed() {
    let (reply, mut rx) = against(static_handler(serde_json::json!([]))).await;
    let (_, _, body) = response(&reply);
    assert_eq!(
        info_prefix(&body),
        "processed: 0; failed: 2; total: 2",
        "values nobody accepted must not be reported as processed"
    );
    common::wait_for_log(&mut rx, "decision=model_silent", 10).await;
}

#[tokio::test]
async fn counts_that_do_not_add_up_are_refused() {
    let (reply, mut rx) = against(static_handler(serde_json::json!([
        {"type": "send_zabbix_result", "processed": 5, "failed": 0}
    ])))
    .await;
    let (_, _, body) = response(&reply);
    assert_eq!(
        info_prefix(&body),
        "processed: 0; failed: 2; total: 2",
        "processed 5 of a two-value request must not reach the sender"
    );
    common::wait_for_log(&mut rx, "decision=fail_closed_mismatched_reply", 10).await;
}

#[tokio::test]
async fn a_model_rejection_is_sent_and_logged_as_model_reject() {
    let (reply, mut rx) = against(static_handler(serde_json::json!([
        {"type": "send_zabbix_result", "processed": 0, "failed": 2}
    ])))
    .await;
    let (_, _, body) = response(&reply);
    assert_eq!(info_prefix(&body), "processed: 0; failed: 2; total: 2");
    common::wait_for_log(&mut rx, "decision=model_reject", 10).await;
}

#[tokio::test]
async fn a_model_close_sends_nothing() {
    let (reply, mut rx) = against(static_handler(
        serde_json::json!([{"type": "close_connection"}]),
    ))
    .await;
    assert!(
        reply.is_empty(),
        "close_connection must not answer: {reply:?}"
    );
    common::wait_for_log(&mut rx, "decision=model_close", 10).await;
}

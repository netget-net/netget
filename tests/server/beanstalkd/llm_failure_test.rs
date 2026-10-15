//! What a beanstalkd client gets when the model cannot answer: `INTERNAL_ERROR` — never
//! silence, never an internal error string, never an invented job or an invented `DELETED`.
//!
//! Four ways the model can fail to answer, all identical on the wire and distinct in the log:
//!
//! * the backend is down → `decision=fail_closed_llm_error`;
//! * the handler ran and produced nothing → `decision=model_silent`;
//! * the handler produced a reply that does not answer the command (`RESERVED` to a `delete`)
//!   → `decision=fail_closed_mismatched_reply`. NetGet renders every byte, so a wrong *shape*
//!   is the one way left for a model to put something a client would misread on the wire;
//! * the handler asked to keep the client waiting on a command that is not a reserve → the
//!   same `fail_closed_mismatched_reply`: only a worker in `reserve` may be left waiting.
//!
//! Unlike DICT's `420`, each of these is a complete beanstalkd answer to one command, so the
//! session continues and the next command is answered.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features beanstalkd --test server -- beanstalkd::llm_failure --test-threads=100

use super::common::{self, Peer};
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
async fn a_backend_failure_answers_internal_error_and_logs_fail_closed_llm_error() {
    let state = common::new_state().await;
    let (tx, mut rx) = mpsc::unbounded_channel();
    // A non-empty instruction and no handlers: every queue command goes to the model, and the
    // model's endpoint is a dead port.
    let server_id = ServerForm {
        protocol: "beanstalkd".to_string(),
        port: Some(0),
        instruction: Some("A work queue".to_string()),
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .expect("create beanstalkd server");
    let port = common::wait_for_port(&state, server_id).await;

    let mut peer = Peer::connect(port).await;
    // Commands NetGet answers itself still work with the backend down.
    peer.send("use jobs").await;
    assert_eq!(peer.line(10).await, "USING jobs\r\n");

    peer.put(b"hello").await;
    // Generous: the failure path runs through the retry loop first.
    let reply = peer.line(120).await;
    assert!(
        reply == "INTERNAL_ERROR\r\n" || reply == "OUT_OF_MEMORY\r\n",
        "expected INTERNAL_ERROR (or OUT_OF_MEMORY when overloaded), got {reply:?}"
    );
    for leak in LEAKS {
        assert!(
            !reply.contains(leak),
            "`{leak}` reached the wire: {reply:?}"
        );
    }
    common::wait_for_log(&mut rx, "decision=fail_closed_llm_error", 30).await;
    // A complete answer to one command: the session goes on.
    peer.send("list-tube-used").await;
    assert_eq!(peer.line(10).await, "USING jobs\r\n");
}

async fn one_command_against(
    handler: serde_json::Value,
    command: &str,
) -> (
    String,
    mpsc::UnboundedReceiver<String>,
    Peer,
    netget::state::app_state::AppState,
) {
    let state = common::new_state().await;
    let (_id, port, rx) = common::start(&state, vec![handler], None).await;
    let mut peer = Peer::connect(port).await;
    peer.send(command).await;
    let reply = peer.line(30).await;
    (reply, rx, peer, state)
}

#[tokio::test]
async fn a_handler_that_answers_nothing_gets_internal_error_and_model_silent() {
    let (reply, mut rx, mut peer, _state) = one_command_against(
        serde_json::json!({
            "event_pattern": "beanstalkd_job_command",
            "handler": {"type": "static", "actions": []}
        }),
        "delete 5",
    )
    .await;
    assert_eq!(
        reply, "INTERNAL_ERROR\r\n",
        "a delete nobody answered must not be answered with an invented DELETED or NOT_FOUND"
    );
    common::wait_for_log(&mut rx, "decision=model_silent", 10).await;
    peer.send("list-tube-used").await;
    assert_eq!(peer.line(10).await, "USING default\r\n");
}

#[tokio::test]
async fn a_reply_that_does_not_fit_the_command_is_refused() {
    let (reply, mut rx, _peer, _state) = one_command_against(
        serde_json::json!({
            "event_pattern": "beanstalkd_job_command",
            "handler": {"type": "static", "actions": [{
                "type": "reserve_beanstalkd_job", "job_id": 5, "body": "not an answer to delete"
            }]}
        }),
        "delete 5",
    )
    .await;
    assert_eq!(
        reply, "INTERNAL_ERROR\r\n",
        "RESERVED is not an answer to delete and must not reach the client"
    );
    common::wait_for_log(&mut rx, "decision=fail_closed_mismatched_reply", 10).await;
}

#[tokio::test]
async fn kicked_without_a_count_does_not_answer_kick() {
    let (reply, mut rx, _peer, _state) = one_command_against(
        serde_json::json!({
            "event_pattern": "beanstalkd_job_command",
            "handler": {"type": "static", "actions": [
                {"type": "send_beanstalkd_status", "status": "KICKED"}
            ]}
        }),
        "kick 10",
    )
    .await;
    assert_eq!(
        reply, "INTERNAL_ERROR\r\n",
        "kick is answered `KICKED <count>`; a bare KICKED is kick-job's answer"
    );
    common::wait_for_log(&mut rx, "decision=fail_closed_mismatched_reply", 10).await;
}

#[tokio::test]
async fn only_a_reserve_may_be_left_waiting() {
    let (reply, mut rx, _peer, _state) = one_command_against(
        serde_json::json!({
            "event_pattern": "beanstalkd_job_command",
            "handler": {"type": "static", "actions": [{"type": "wait_for_beanstalkd_job"}]}
        }),
        "delete 5",
    )
    .await;
    assert_eq!(reply, "INTERNAL_ERROR\r\n");
    common::wait_for_log(&mut rx, "decision=fail_closed_mismatched_reply", 10).await;
}

#[tokio::test]
async fn a_model_refusal_is_sent_and_logged_as_model_reject() {
    let (reply, mut rx, mut peer, _state) = one_command_against(
        serde_json::json!({
            "event_pattern": "beanstalkd_job_command",
            "handler": {"type": "static", "actions": [
                {"type": "send_beanstalkd_status", "status": "NOT_FOUND"}
            ]}
        }),
        "delete 5",
    )
    .await;
    assert_eq!(reply, "NOT_FOUND\r\n");
    common::wait_for_log(&mut rx, "decision=model_reject", 10).await;
    peer.send("list-tube-used").await;
    assert_eq!(peer.line(10).await, "USING default\r\n");
}

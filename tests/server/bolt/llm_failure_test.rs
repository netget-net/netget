//! What a Bolt client gets when nobody can answer: FAILURE
//! `Neo.TransientError.General.DatabaseUnavailable` with a fixed message — never silence, never
//! the error text, never invented rows — and a connection that recovers on RESET, which is
//! Bolt's own way back from a failed query.
//!
//! Every way of not answering looks the same on the wire and differs in the log:
//!
//! * the backend is down → `decision=fail_closed_llm_error`;
//! * the handler ran and produced nothing → `decision=model_silent`;
//! * it produced rows the executor refused (a record narrower than `fields`) →
//!   `decision=fail_closed_invalid_answer`;
//! * it answered a query with a login decision → `decision=fail_closed_mismatched_reply`.
//!
//! A login nobody can decide is refused and closed: letting it in would turn a backend outage
//! into an open database.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features bolt --test server -- bolt::llm_failure --test-threads=100


use super::common::{self, *};
use netget::cli::management::ServerForm;
use netget::server::bolt::packstream::Value;
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

const TRANSIENT: &str = "Neo.TransientError.General.DatabaseUnavailable";

fn assert_no_leak(v: &Value) {
    let text = format!("{v:?}");
    for leak in LEAKS {
        assert!(!text.contains(leak), "`{leak}` reached the wire: {text}");
    }
}

#[tokio::test]
async fn a_backend_failure_on_a_query_is_a_transient_failure_and_reset_recovers() {
    let state = common::new_state().await;
    let (tx, mut rx) = mpsc::unbounded_channel();
    // Logins are a static handler; queries go to the model, whose endpoint is a dead port.
    let server_id = ServerForm {
        protocol: "bolt".to_string(),
        port: Some(0),
        instruction: Some("A graph of people".to_string()),
        event_handlers: Some(vec![common::accept_logins()]),
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .expect("create bolt server");
    let port = common::wait_for_port(&state, server_id).await;

    let mut peer = Peer::connect_and_login(port).await;
    peer.send_all(&[run("MATCH (n) RETURN n"), pull(-1)]).await;
    // Generous: the failure path runs through the retry loop first.
    let failure = peer
        .try_recv(120)
        .await
        .expect("closed instead of answering");
    assert_failure(&failure, TRANSIENT);
    assert_no_leak(&failure);
    assert_ignored(&peer.recv().await);
    common::wait_for_log(&mut rx, "decision=fail_closed_llm_error", 30).await;

    // The connection is still usable: RESET, then something NetGet answers itself.
    peer.send(&reset()).await;
    assert_success(&peer.recv().await);
    peer.send_all(&[run("CALL db.ping()"), pull(-1)]).await;
    assert_success(&peer.recv().await);
    assert_eq!(record_values(&peer.recv().await), [Value::Bool(true)]);
}

#[tokio::test]
async fn a_login_nobody_can_decide_is_refused_and_closed() {
    let state = common::new_state().await;
    let (tx, mut rx) = mpsc::unbounded_channel();
    let server_id = ServerForm {
        protocol: "bolt".to_string(),
        port: Some(0),
        instruction: Some("A graph of people".to_string()),
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .expect("create bolt server");
    let port = common::wait_for_port(&state, server_id).await;

    let mut peer = Peer::connect(port).await;
    peer.handshake(CYPHER_SHELL_PROPOSALS).await;
    peer.send(&hello()).await;
    assert_success(&peer.recv().await);
    peer.send(&logon("neo4j", "pw")).await;
    let failure = peer
        .try_recv(120)
        .await
        .expect("closed instead of answering");
    assert_failure(&failure, TRANSIENT);
    assert_no_leak(&failure);
    peer.expect_eof(10).await;
    common::wait_for_log(&mut rx, "decision=fail_closed_llm_error", 30).await;
}

#[tokio::test]
async fn a_handler_that_answers_nothing_is_model_silent() {
    let state = common::new_state().await;
    let silent = serde_json::json!({
        "event_pattern": "bolt_query",
        "handler": {"type": "static", "actions": []}
    });
    let (_id, port, mut rx) =
        common::start(&state, vec![common::accept_logins(), silent], None).await;
    let mut peer = Peer::connect_and_login(port).await;
    peer.send_all(&[run("MATCH (n) RETURN n"), pull(-1)]).await;
    assert_failure(&peer.recv().await, TRANSIENT);
    assert_ignored(&peer.recv().await);
    common::wait_for_log(&mut rx, "decision=model_silent", 10).await;
}

#[tokio::test]
async fn rows_the_executor_refuses_are_an_invalid_answer_not_a_result() {
    let state = common::new_state().await;
    let narrow = serde_json::json!({
        "event_pattern": "bolt_query",
        "handler": {"type": "static", "actions": [{
            "type": "send_bolt_records", "fields": ["a", "b"], "records": [["only-one"]]
        }]}
    });
    let (_id, port, mut rx) =
        common::start(&state, vec![common::accept_logins(), narrow], None).await;
    let mut peer = Peer::connect_and_login(port).await;
    peer.send_all(&[run("MATCH (n) RETURN n.a AS a, n.b AS b"), pull(-1)])
        .await;
    assert_failure(&peer.recv().await, TRANSIENT);
    common::wait_for_log(&mut rx, "decision=fail_closed_invalid_answer", 10).await;
}

#[tokio::test]
async fn a_login_decision_is_not_an_answer_to_a_query() {
    let state = common::new_state().await;
    let wrong = serde_json::json!({
        "event_pattern": "*",
        "handler": {"type": "static", "actions": [{"type": "accept_bolt_login"}]}
    });
    let (_id, port, mut rx) = common::start(&state, vec![wrong], None).await;
    let mut peer = Peer::connect_and_login(port).await;
    peer.send_all(&[run("MATCH (n) RETURN n"), pull(-1)]).await;
    assert_failure(&peer.recv().await, TRANSIENT);
    common::wait_for_log(&mut rx, "decision=fail_closed_mismatched_reply", 10).await;
}

#[tokio::test]
async fn a_model_failure_code_is_sent_and_logged_as_model_reject() {
    let state = common::new_state().await;
    let refuse = serde_json::json!({
        "event_pattern": "bolt_query",
        "handler": {"type": "static", "actions": [{
            "type": "send_bolt_failure",
            "code": "Neo.ClientError.Database.DatabaseNotFound",
            "message": "Database does not exist. Database name: 'nope'."
        }]}
    });
    let (_id, port, mut rx) =
        common::start(&state, vec![common::accept_logins(), refuse], None).await;
    let mut peer = Peer::connect_and_login(port).await;
    peer.send_all(&[run("MATCH (n) RETURN n"), pull(-1)]).await;
    let failure = peer.recv().await;
    assert_failure(&failure, "Neo.ClientError.Database.DatabaseNotFound");
    assert_eq!(
        meta(&failure).get("message"),
        Some(&Value::string(
            "Database does not exist. Database name: 'nope'."
        ))
    );
    common::wait_for_log(&mut rx, "decision=model_reject", 10).await;
}

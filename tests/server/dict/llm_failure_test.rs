//! What a DICT client gets when the model cannot answer: `420 Server temporarily unavailable`,
//! then EOF — never silence, never an internal error string, never an invented definition.
//!
//! Three ways the model can fail to answer, and all three must look the same on the wire while
//! staying distinct in the log:
//!
//! * the backend is down → `decision=fail_closed_llm_error`;
//! * the handler ran and produced nothing → `decision=model_silent`;
//! * the handler produced a reply that does not answer the command (a `152` match list to a
//!   DEFINE) → `decision=fail_closed_mismatched_reply`. NetGet renders every byte, so a wrong
//!   *shape* is the one way left for a model to put something a client would misread on the
//!   wire, and refusing it is NetGet's decision, not the model's.
//!
//! `420` is RFC 2229's "Server temporarily unavailable". There is no DICT code for "the
//! dictionary could not decide", and every 5xx the server could send instead (552 no match,
//! 550 invalid database) is a claim about the dictionary that nothing made.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features dict --test server -- dict::llm_failure --test-threads=100

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
async fn a_backend_failure_answers_420_closes_and_logs_fail_closed_llm_error() {
    let state = common::new_state().await;
    let (tx, mut rx) = mpsc::unbounded_channel();
    // A non-empty instruction and no handlers: every content command goes to the model, and
    // the model's endpoint is a dead port.
    let server_id = ServerForm {
        protocol: "dict".to_string(),
        port: Some(0),
        instruction: Some("Define any word".to_string()),
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .expect("create dict server");
    let port = common::wait_for_port(&state, server_id).await;

    let mut peer = Peer::connect(port).await;
    assert!(peer.line(10).await.starts_with("220 "));
    // Commands NetGet answers itself still work with the backend down.
    peer.send("CLIENT failure-test").await;
    assert_eq!(peer.line(10).await, "250 ok\r\n");

    peer.send("DEFINE * hello").await;
    // Generous: the failure path runs through the retry loop first.
    let reply = peer.line(120).await;
    assert!(
        reply == "420 Server temporarily unavailable\r\n"
            || reply == "420 Server temporarily unavailable, backend at capacity\r\n",
        "expected a 420, got {reply:?}"
    );
    for leak in LEAKS {
        assert!(
            !reply.contains(leak),
            "`{leak}` reached the wire: {reply:?}"
        );
    }
    assert_eq!(
        peer.line(10).await,
        "",
        "the connection must close after 420"
    );
    common::wait_for_log(&mut rx, "decision=fail_closed_llm_error", 30).await;
}

#[tokio::test]
async fn a_handler_that_answers_nothing_gets_420_and_model_silent() {
    let state = common::new_state().await;
    let silent = serde_json::json!({
        "event_pattern": "dict_define",
        "handler": {"type": "static", "actions": []}
    });
    let (_id, port, mut rx) = common::start(&state, vec![silent], None).await;
    let mut peer = Peer::connect(port).await;
    assert!(peer.line(10).await.starts_with("220 "));
    peer.send("DEFINE * hello").await;
    assert_eq!(
        peer.line(30).await,
        "420 Server temporarily unavailable\r\n",
        "a DEFINE nobody answered must not be answered with an invented 552"
    );
    assert_eq!(peer.line(10).await, "");
    common::wait_for_log(&mut rx, "decision=model_silent", 10).await;
}

#[tokio::test]
async fn a_reply_that_does_not_fit_the_command_is_refused_with_420() {
    let state = common::new_state().await;
    let wrong_shape = serde_json::json!({
        "event_pattern": "dict_define",
        "handler": {"type": "static", "actions": [{
            "type": "send_dict_matches",
            "matches": [{"database": "wn", "word": "hello"}]
        }]}
    });
    let (_id, port, mut rx) = common::start(&state, vec![wrong_shape], None).await;
    let mut peer = Peer::connect(port).await;
    assert!(peer.line(10).await.starts_with("220 "));
    peer.send("DEFINE * hello").await;
    assert_eq!(
        peer.line(30).await,
        "420 Server temporarily unavailable\r\n",
        "a 152 match list is not an answer to DEFINE and must not reach the client"
    );
    assert_eq!(peer.line(10).await, "");
    common::wait_for_log(&mut rx, "decision=fail_closed_mismatched_reply", 10).await;
}

#[tokio::test]
async fn a_model_refusal_is_sent_and_logged_as_model_reject() {
    let state = common::new_state().await;
    let refuse = serde_json::json!({
        "event_pattern": "dict_define",
        "handler": {"type": "static", "actions": [{"type": "send_dict_error", "code": 550}]}
    });
    let (_id, port, mut rx) = common::start(&state, vec![refuse], None).await;
    let mut peer = Peer::connect(port).await;
    assert!(peer.line(10).await.starts_with("220 "));
    peer.send("DEFINE nosuchdb hello").await;
    assert_eq!(
        peer.line(30).await,
        "550 Invalid database, use \"SHOW DB\" for list of databases\r\n"
    );
    // A refusal is an answer: the session goes on.
    peer.send("STATUS").await;
    assert!(peer.line(10).await.starts_with("210 "));
    common::wait_for_log(&mut rx, "decision=model_reject", 10).await;
}

//! What an NSQ client gets when the model cannot, or will not, answer.
//!
//! * A publish the backend could not decide gets `E_PUB_FAILED` (`E_MPUB_FAILED` for MPUB) with
//!   a fixed text and the close — nsqd's own shape for a failed publish, never an invented OK.
//! * A subscription gets `E_INVALID SUB failed: …` and the close — never an invented OK either.
//! * RDY, FIN and REQ take no reply in nsqd, so a failure there delivers nothing and the
//!   connection stays.
//! * A model that answers nothing, or refuses, is logged as such and told apart from an outage.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features nsq --test server -- nsq::llm_failure --test-threads=100

use super::common::{self, static_handler, Peer};
use netget::cli::management::ServerForm;
use netget::server::nsq::wire::Command;
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

fn assert_fixed(text: &str, expected_prefix: &str) {
    assert!(
        text == format!("{expected_prefix} broker backend unavailable")
            || text == format!("{expected_prefix} broker backend at capacity"),
        "{text:?}"
    );
    for leak in LEAKS {
        assert!(!text.contains(leak), "`{leak}` reached the wire: {text}");
    }
}

/// A server with a real instruction and a dead backend: every event no handler answers goes to
/// a model that cannot be reached.
async fn failing_server(
    handlers: Vec<serde_json::Value>,
) -> (
    netget::state::app_state::AppState,
    u16,
    mpsc::UnboundedReceiver<String>,
) {
    let state = common::new_state().await;
    let (tx, rx) = mpsc::unbounded_channel();
    let server_id = ServerForm {
        protocol: "nsq".to_string(),
        port: Some(0),
        instruction: Some("A broker that accepts everything".to_string()),
        event_handlers: if handlers.is_empty() {
            None
        } else {
            Some(handlers)
        },
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .expect("create nsq server");
    let port = common::wait_for_port(&state, server_id).await;
    (state, port, rx)
}

#[tokio::test]
async fn a_backend_failure_refuses_publishes_and_subscriptions() {
    let (_state, port, mut rx) = failing_server(Vec::new()).await;

    let mut peer = Peer::connect(port).await;
    peer.command(&Command::Pub {
        topic: "t".into(),
        body: b"x".to_vec(),
    })
    .await;
    // Generous: the failure path runs through the retry loop first.
    let text = peer.expect_error(120).await;
    assert_fixed(&text, "E_PUB_FAILED PUB failed:");
    assert!(
        peer.rest(10).await.is_empty(),
        "E_PUB_FAILED is fatal, as in nsqd"
    );
    common::wait_for_log(&mut rx, "decision=fail_closed_llm_error", 30).await;

    let mut peer = Peer::connect(port).await;
    peer.command(&Command::Mpub {
        topic: "t".into(),
        messages: vec![b"a".to_vec()],
    })
    .await;
    assert_fixed(&peer.expect_error(120).await, "E_MPUB_FAILED MPUB failed:");

    let mut peer = Peer::connect(port).await;
    peer.command(&Command::Sub {
        topic: "t".into(),
        channel: "c".into(),
    })
    .await;
    assert_fixed(&peer.expect_error(120).await, "E_INVALID SUB failed:");
    assert!(peer.rest(10).await.is_empty());
}

#[tokio::test]
async fn a_backend_failure_on_rdy_delivers_nothing_and_keeps_the_connection() {
    let (_state, port, mut rx) = failing_server(vec![static_handler(
        "nsq_subscribe",
        serde_json::json!([{"type": "send_nsq_ok"}]),
    )])
    .await;
    let mut peer = Peer::connect(port).await;
    peer.command(&Command::Sub {
        topic: "t".into(),
        channel: "c".into(),
    })
    .await;
    peer.expect_response(b"OK", 30).await;
    common::drain(&mut rx);
    peer.command(&Command::Rdy(5)).await;
    let log = common::wait_for_log(&mut rx, "decision=fail_closed_llm_error", 120).await;
    assert!(
        log.last().unwrap().contains("NSQ RDY from"),
        "{:?}",
        log.last()
    );
    peer.command(&Command::Nop).await;
    peer.quiet_for(1).await;
}

async fn one_publish(actions: serde_json::Value) -> (String, mpsc::UnboundedReceiver<String>) {
    let state = common::new_state().await;
    let (_id, port, rx) =
        common::start(&state, vec![static_handler("nsq_publish", actions)], None).await;
    let mut peer = Peer::connect(port).await;
    peer.command(&Command::Pub {
        topic: "t".into(),
        body: b"x".to_vec(),
    })
    .await;
    let frame = peer.frame(30).await;
    let text = format!(
        "{}:{}",
        frame.frame_type,
        String::from_utf8_lossy(&frame.data)
    );
    let _keep = state;
    (text, rx)
}

#[tokio::test]
async fn a_handler_that_answers_nothing_refuses_the_publish() {
    let (text, mut rx) = one_publish(serde_json::json!([])).await;
    assert_eq!(text, "1:E_PUB_FAILED PUB failed", "silence is not an OK");
    common::wait_for_log(&mut rx, "decision=model_silent", 10).await;
}

#[tokio::test]
async fn a_model_refusal_is_sent_and_logged_as_model_reject() {
    let (text, mut rx) = one_publish(serde_json::json!([
        {"type": "send_nsq_error", "code": "E_PUB_FAILED", "message": "topic is read-only"}
    ]))
    .await;
    assert_eq!(text, "1:E_PUB_FAILED topic is read-only");
    common::wait_for_log(&mut rx, "decision=model_reject", 10).await;
}

#[tokio::test]
async fn the_first_reply_wins() {
    let (text, mut rx) = one_publish(serde_json::json!([
        {"type": "send_nsq_ok"},
        {"type": "send_nsq_error", "code": "E_PUB_FAILED", "message": "second thoughts"}
    ]))
    .await;
    assert_eq!(text, "0:OK");
    common::wait_for_log(&mut rx, "decision=model_answer", 10).await;
}

#[tokio::test]
async fn a_non_fatal_refusal_of_a_fin_keeps_the_connection() {
    let state = common::new_state().await;
    let handlers = vec![
        static_handler(
            "nsq_subscribe",
            serde_json::json!([
                {"type": "send_nsq_ok"},
                {"type": "deliver_nsq_messages", "messages": [{"body": "one"}]}
            ]),
        ),
        static_handler("nsq_ready", serde_json::json!([])),
        static_handler(
            "nsq_finish",
            serde_json::json!([
                {"type": "send_nsq_error", "code": "E_FIN_FAILED", "message": "already done"}
            ]),
        ),
    ];
    let (_id, port, mut rx) = common::start(&state, handlers, None).await;
    let mut peer = Peer::connect(port).await;
    peer.command(&Command::Sub {
        topic: "t".into(),
        channel: "c".into(),
    })
    .await;
    peer.expect_response(b"OK", 30).await;
    peer.command(&Command::Rdy(1)).await;
    let m = peer.expect_message(30).await;
    peer.command(&Command::Fin(String::from_utf8(m.id.to_vec()).unwrap()))
        .await;
    assert_eq!(peer.expect_error(30).await, "E_FIN_FAILED already done");
    common::wait_for_log(&mut rx, "decision=model_reject", 10).await;
    peer.command(&Command::Nop).await;
    peer.quiet_for(1).await;
}

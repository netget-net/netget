//! What a Gearman client gets when the model cannot run its job: `WORK_FAIL` — which the
//! `gearman` CLI exits 1 on — or, for a client that enabled exceptions, `WORK_EXCEPTION` with a
//! fixed text. Never silence (the client would wait forever for an outcome), never an internal
//! error string, never an invented `WORK_COMPLETE`.
//!
//! `ERROR` is not used for this: `gearman` exits **0** on an `ERROR` packet (measured), so it
//! would read as success to a script checking `$?`.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features gearman --test server -- gearman::llm_failure --test-threads=100

use super::common::{self, req, Peer};
use netget::cli::management::ServerForm;
use netget::server::gearman::wire;
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
async fn a_backend_failure_fails_the_job_or_raises_a_fixed_exception() {
    let state = common::new_state().await;
    let (tx, mut rx) = mpsc::unbounded_channel();
    let server_id = ServerForm {
        protocol: "gearman".to_string(),
        port: Some(0),
        instruction: Some("Reverse every workload".to_string()),
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .expect("create gearman server");
    let port = common::wait_for_port(&state, server_id).await;

    let mut peer = Peer::connect(port).await;
    peer.send(&req(wire::SUBMIT_JOB, &[b"reverse", b"", b"abc"]))
        .await;
    let (t, created, _) = peer.packet(10).await;
    assert_eq!(t, wire::JOB_CREATED);
    // Generous: the failure path runs through the retry loop first.
    let (t, args, raw) = peer.packet(120).await;
    assert_eq!((t, &args[0]), (wire::WORK_FAIL, &created[0]));
    let text = String::from_utf8_lossy(&raw);
    for leak in LEAKS {
        assert!(!text.contains(leak), "`{leak}` reached the wire: {text}");
    }
    common::wait_for_log(&mut rx, "decision=fail_closed_llm_error", 30).await;

    // With exceptions on, the same failure carries a fixed text.
    peer.send(&req(wire::OPTION_REQ, &[b"exceptions"])).await;
    assert_eq!(peer.packet(10).await.0, wire::OPTION_RES);
    peer.send(&req(wire::SUBMIT_JOB, &[b"reverse", b"", b"abc"]))
        .await;
    assert_eq!(peer.packet(10).await.0, wire::JOB_CREATED);
    let (t, args, _) = peer.packet(120).await;
    assert_eq!(t, wire::WORK_EXCEPTION);
    assert!(
        args[1] == b"job server backend unavailable"
            || args[1] == b"job server backend at capacity",
        "{:?}",
        String::from_utf8_lossy(&args[1])
    );
}

async fn one_job(
    actions: serde_json::Value,
) -> (
    u32,
    Vec<Vec<u8>>,
    Vec<(u32, Vec<Vec<u8>>)>,
    mpsc::UnboundedReceiver<String>,
) {
    let state = common::new_state().await;
    let handler = serde_json::json!({
        "event_pattern": "gearman_job_submitted",
        "handler": {"type": "static", "actions": actions}
    });
    let (_id, port, rx) = common::start(&state, vec![handler], None).await;
    let mut peer = Peer::connect(port).await;
    peer.send(&req(wire::SUBMIT_JOB, &[b"reverse", b"", b"abc"]))
        .await;
    let (t, created, _) = peer.packet(10).await;
    assert_eq!(t, wire::JOB_CREATED);
    // Read until the outcome.
    let mut seen = Vec::new();
    loop {
        let (t, args, _) = peer.packet(30).await;
        let done = matches!(
            t,
            wire::WORK_COMPLETE | wire::WORK_FAIL | wire::WORK_EXCEPTION | wire::ERROR
        );
        seen.push((t, args));
        if done {
            break;
        }
    }
    // Nothing may follow the outcome: the next packet is the answer to the next request.
    peer.send(&req(wire::ECHO_REQ, &[b"after"])).await;
    let (next, _, _) = peer.packet(10).await;
    assert_eq!(
        next,
        wire::ECHO_RES,
        "a packet followed the job's outcome: {seen:?}"
    );
    let _keep = state;
    (t, created, seen, rx)
}

#[tokio::test]
async fn a_handler_that_answers_nothing_fails_the_job() {
    let (_, created, seen, mut rx) = one_job(serde_json::json!([])).await;
    assert_eq!(
        seen,
        vec![(wire::WORK_FAIL, vec![created[0].clone()])],
        "a job nobody ran must not complete"
    );
    common::wait_for_log(&mut rx, "decision=model_silent", 10).await;
}

#[tokio::test]
async fn progress_without_an_outcome_is_finished_with_work_fail() {
    let (_, created, seen, mut rx) = one_job(serde_json::json!([
        {"type": "send_gearman_status", "numerator": 1, "denominator": 3}
    ]))
    .await;
    let h = created[0].clone();
    assert_eq!(
        seen,
        vec![
            (
                wire::WORK_STATUS,
                vec![h.clone(), b"1".to_vec(), b"3".to_vec()]
            ),
            (wire::WORK_FAIL, vec![h])
        ],
        "the client must not be left waiting for an outcome that never comes"
    );
    common::wait_for_log(&mut rx, "decision=fail_closed_unfinished", 10).await;
}

#[tokio::test]
async fn an_answer_for_another_job_is_refused() {
    let (_, created, seen, mut rx) = one_job(serde_json::json!([
        {"type": "complete_gearman_job", "result": "stolen", "job_handle": "H:elsewhere:9"}
    ]))
    .await;
    assert_eq!(
        seen,
        vec![(wire::WORK_FAIL, vec![created[0].clone()])],
        "a WORK_COMPLETE for another handle must not reach this client"
    );
    common::wait_for_log(&mut rx, "decision=fail_closed_mismatched_reply", 10).await;
}

#[tokio::test]
async fn a_model_error_is_sent_and_logged_as_model_reject() {
    let (_, _created, seen, mut rx) = one_job(serde_json::json!([
        {"type": "send_gearman_error", "code": "queue_full", "text": "try again later"}
    ]))
    .await;
    assert_eq!(
        seen,
        vec![(
            wire::ERROR,
            vec![b"queue_full".to_vec(), b"try again later".to_vec()]
        )]
    );
    common::wait_for_log(&mut rx, "decision=model_reject", 10).await;
}

#[tokio::test]
async fn nothing_follows_the_outcome() {
    let (_, created, seen, mut rx) = one_job(serde_json::json!([
        {"type": "complete_gearman_job", "result": "cba"},
        {"type": "send_gearman_data", "data": "late"}
    ]))
    .await;
    assert_eq!(
        seen,
        vec![(
            wire::WORK_COMPLETE,
            vec![created[0].clone(), b"cba".to_vec()]
        )]
    );
    common::wait_for_log(&mut rx, "decision=model_answer", 10).await;
}

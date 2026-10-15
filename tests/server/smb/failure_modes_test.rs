//! `src/server/smb/CLAUDE.md`'s failure sections, read as a list of assertions and tested.
//!
//! Every operation the model decides — session_setup, create, read, write, query_info,
//! query_directory — can end three ways that are not an approval, and the document promises
//! three things about them:
//!
//! 1. **On the wire, none of them is success.** A model that answers with some other action
//!    (`model_reject`) and a model that answers with nothing (`fail_closed_no_action`) are both
//!    `STATUS_ACCESS_DENIED`. A backend that fails (`fail_closed_llm_error`) is
//!    `STATUS_INTERNAL_ERROR` — distinguishable from the model's own refusal — except at
//!    session_setup, where every refusal is `STATUS_ACCESS_DENIED` because a login is either
//!    granted or not.
//! 2. **In the log, all three are told apart**, by a `decision=` token naming the path or the
//!    user, because the wire cannot carry the difference between refusing and saying nothing.
//! 3. **An overload is `STATUS_INSUFFICIENT_RESOURCES`**, the closest NTSTATUS to "retryable",
//!    including underneath the context layer `call_llm` wraps it in.
//!
//! Before this file, the create and read LLM failures were tested and nothing else here was.
//! Writing it found that the WRITE refusal logged no `decision=` token at all while the
//! document said every refusal did.
//!
//! The model is an in-process mock with rules for the approving and refusing answers and none
//! for the failing ones: a request that matches no rule gets HTTP 500, which is the same shape
//! as a backend outage.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features smb --test server -- smb::failure_modes --test-threads=100


use std::time::Duration;

use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::mpsc;

use super::wire_util::{self as w, nbss, read_frame};
use crate::helpers::mock_builder::MockLlmBuilder;
use crate::helpers::mock_ollama::MockOllamaServer;

async fn call(stream: &mut TcpStream, message: Vec<u8>) -> Vec<u8> {
    stream.write_all(&nbss(message)).await.expect("write");
    tokio::time::timeout(Duration::from_secs(60), read_frame(stream))
        .await
        .expect("no reply within 60s")
        .expect("read reply")
}

/// The three ways an answer is not an approval, as the test names its paths and users.
const OUTCOMES: [(&str, &str); 3] = [
    ("reject", "model_reject"),
    ("silent", "fail_closed_no_action"),
    ("fail", "fail_closed_llm_error"),
];

/// Rules for the approving answers and for `reject` / `silent`; none for `fail`.
fn mock() -> crate::helpers::mock_config::MockLlmConfig {
    let mut b = MockLlmBuilder::new()
        .on_event("smb_operation")
        .and_event_data_contains("operation", "session_setup")
        .and_event_data_contains("username", "alice")
        .respond_with_actions(serde_json::json!([{"type": "smb_auth_success"}]))
        .expect_at_least(1)
        .and()
        .on_event("smb_operation")
        .and_event_data_contains("operation", "session_setup")
        .and_event_data_contains("username", "reject")
        .respond_with_actions(serde_json::json!([{"type": "show_message", "message": "no"}]))
        .expect_calls(1)
        .and()
        .on_event("smb_operation")
        .and_event_data_contains("operation", "session_setup")
        .and_event_data_contains("username", "silent")
        .respond_with_actions(serde_json::json!([]))
        .expect_calls(1)
        .and()
        // Every path under /ok opens: a directory if it says so, otherwise a file whose size
        // is unknown, so QUERY_INFO has to ask.
        .on_event("smb_operation")
        .and_event_data_contains("operation", "create")
        .and_event_data_contains("path", "/ok")
        .respond_with_actions_from_event(|event| {
            let path = event["path"].as_str().unwrap_or_default().to_string();
            if path.contains("dir") {
                serde_json::json!([{"type": "smb_create_directory", "path": path}])
            } else {
                serde_json::json!([{"type": "smb_create_file", "path": path}])
            }
        })
        .expect_at_least(1)
        .and();
    for op in ["create", "read", "write", "query_info", "query_directory"] {
        b = b
            .on_event("smb_operation")
            .and_event_data_contains("operation", op)
            .and_event_data_contains("path", "reject")
            .respond_with_actions(serde_json::json!([{"type": "show_message", "message": "no"}]))
            .expect_calls(1)
            .and()
            .on_event("smb_operation")
            .and_event_data_contains("operation", op)
            .and_event_data_contains("path", "silent")
            .respond_with_actions(serde_json::json!([]))
            .expect_calls(1)
            .and();
    }
    b.build()
}

/// NEGOTIATE, then an NTLMSSP login as `user` in two legs. Returns the final reply.
async fn log_in_as(s: &mut TcpStream, mid: &mut u64, user: &str) -> Vec<u8> {
    let first = call(s, w::session_setup_with(*mid, 0, &w::ntlmssp_negotiate())).await;
    *mid += 1;
    assert_eq!(w::status(&first), w::STATUS_MORE_PROCESSING_REQUIRED);
    let sid = w::session_id(&first);
    let reply = call(
        s,
        w::session_setup_with(*mid, sid, &w::ntlmssp_authenticate(user)),
    )
    .await;
    *mid += 1;
    reply
}

#[tokio::test]
async fn every_decision_fails_closed_on_the_wire_and_is_told_apart_in_the_log() {
    let mock = MockOllamaServer::start(mock()).await.expect("mock");
    let state = AppState::new_with_options(false, mock.base_url());
    state
        .set_llm_client(netget::llm::OllamaClient::new(mock.base_url()))
        .await;
    let (tx, mut rx) = mpsc::unbounded_channel();
    let server_id = ServerForm {
        protocol: "smb".to_string(),
        port: Some(0),
        host: Some("127.0.0.1".to_string()),
        instruction: Some("A file server.".to_string()),
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .expect("create smb server");
    let mut port = None;
    for _ in 0..300 {
        if let Some(addr) = state.get_server(server_id).await.and_then(|s| s.local_addr) {
            port = Some(addr.port());
            break;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    let port = port.expect("smb bound a port");

    let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let mut mid = 1u64;
    call(&mut s, w::negotiate(0)).await;

    // session_setup: all three refusals are ACCESS_DENIED.
    for (who, _) in OUTCOMES {
        let reply = log_in_as(&mut s, &mut mid, who).await;
        assert_eq!(
            w::status(&reply),
            w::STATUS_ACCESS_DENIED,
            "a login the model did not grant ({who}) must be refused"
        );
    }
    let ok = log_in_as(&mut s, &mut mid, "alice").await;
    assert_eq!(w::status(&ok), w::STATUS_SUCCESS, "alice is admitted");
    let sid = w::session_id(&ok);
    let tree = call(&mut s, w::tree_connect(mid, sid, r"\\127.0.0.1\share")).await;
    mid += 1;
    let tid = w::tree_id(&tree);

    // The model's refusals are ACCESS_DENIED; a backend failure is not a refusal.
    let refused = |outcome: &str| {
        if outcome == "fail" {
            w::STATUS_INTERNAL_ERROR
        } else {
            w::STATUS_ACCESS_DENIED
        }
    };

    for (outcome, _) in OUTCOMES {
        // create
        let r = call(&mut s, w::create(mid, tid, sid, &format!("c_{outcome}"))).await;
        mid += 1;
        assert_eq!(w::status(&r), refused(outcome), "CREATE /c_{outcome}");

        // read, write and query_info, each on a file opened for it
        let open = call(&mut s, w::create(mid, tid, sid, &format!("ok_r_{outcome}"))).await;
        mid += 1;
        let fid = w::create_file_id(&open);
        let r = call(&mut s, w::read(mid, tid, sid, &fid, 0, 64)).await;
        mid += 1;
        assert_eq!(w::status(&r), refused(outcome), "READ /ok_r_{outcome}");

        let open = call(&mut s, w::create(mid, tid, sid, &format!("ok_w_{outcome}"))).await;
        mid += 1;
        let fid = w::create_file_id(&open);
        let r = call(&mut s, w::write(mid, tid, sid, &fid, b"data")).await;
        mid += 1;
        assert_eq!(w::status(&r), refused(outcome), "WRITE /ok_w_{outcome}");

        let open = call(&mut s, w::create(mid, tid, sid, &format!("ok_q_{outcome}"))).await;
        mid += 1;
        let fid = w::create_file_id(&open);
        // FileStandardInformation needs the size, which the model has not given.
        let r = call(&mut s, w::query_info(mid, tid, sid, &fid, 1, 5)).await;
        mid += 1;
        assert_eq!(
            w::status(&r),
            refused(outcome),
            "QUERY_INFO /ok_q_{outcome}"
        );

        let open = call(
            &mut s,
            w::create_with(mid, tid, sid, &format!("okdir_d_{outcome}"), 1),
        )
        .await;
        mid += 1;
        let fid = w::create_file_id(&open);
        let r = call(&mut s, w::query_directory(mid, tid, sid, &fid, 37, "*")).await;
        mid += 1;
        assert_eq!(
            w::status(&r),
            refused(outcome),
            "QUERY_DIRECTORY /okdir_d_{outcome}"
        );
    }

    // The log tells every one of them apart.
    let mut log = Vec::new();
    while let Ok(line) = rx.try_recv() {
        log.push(line);
    }
    let mut missing = Vec::new();
    for (outcome, decision) in OUTCOMES {
        let token = format!("decision={decision}");
        for subject in [
            format!("\"{outcome}\""),
            format!("/c_{outcome}"),
            format!("/ok_r_{outcome}"),
            format!("/ok_w_{outcome}"),
            format!("/ok_q_{outcome}"),
            format!("/okdir_d_{outcome}"),
        ] {
            if !log
                .iter()
                .any(|l| l.contains(&subject) && l.contains(&token))
            {
                missing.push(format!("{subject} with {token}"));
            }
        }
    }
    assert!(
        missing.is_empty(),
        "these refusals left no log line naming what was refused and why:\n  {}\n\nlog:\n{}",
        missing.join("\n  "),
        log.join("\n")
    );

    mock.wait_for_expectations(30).await;
    mock.verify_calls().await.expect("mock expectations");
    let _ = state.remove_server(server_id).await;
}

/// An overload is `STATUS_INSUFFICIENT_RESOURCES` and everything else `STATUS_INTERNAL_ERROR`,
/// including underneath the context layer `call_llm` reports a rate-limiter refusal in.
#[test]
fn an_overload_is_insufficient_resources_and_everything_else_is_internal_error() {
    use netget::llm::RateLimitError;
    use netget::server::smb::status_for_llm_failure;

    for refusal in [
        RateLimitError::QueueFull { max_queued: 128 },
        RateLimitError::QueueTimeout { waited_secs: 120 },
        RateLimitError::TokenLimit {
            limit: 10_000,
            window_secs: 60,
        },
    ] {
        assert_eq!(
            status_for_llm_failure(&anyhow::Error::new(refusal)),
            w::STATUS_INSUFFICIENT_RESOURCES,
            "{refusal:?}"
        );
        assert_eq!(
            status_for_llm_failure(&anyhow::Error::new(refusal).context("LLM call failed")),
            w::STATUS_INSUFFICIENT_RESOURCES,
            "{refusal:?} under a context layer"
        );
    }
    assert_eq!(
        status_for_llm_failure(&anyhow::anyhow!("connection refused")),
        w::STATUS_INTERNAL_ERROR
    );
}

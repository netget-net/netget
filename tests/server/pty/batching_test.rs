//! Batching on the PTY server: input typed on the terminal while the model is answering.
//!
//! A separate reader task drains the PTY master while the model answers, so each write the
//! terminal program makes keeps its own boundary instead of piling up in the PTY buffer. With
//! batching off the dispatcher answers one read per call; with it on, every read waiting is
//! handed to `call_llm_batch` together — the newest is the trigger, the earlier ones are listed
//! above it.
//!
//! Driven in-process: the test opens the slave through the server's symlink, as a terminal
//! program would. The first write is answered slowly; two more are written, 200 ms apart, during
//! that call. Off is the control and runs first in the same test: three calls, one per write.
//! On: two calls, the second triggered by `third` with `second` listed as not yet answered.
#![cfg(unix)]

use std::io::Write;
use std::path::Path;
use std::time::Duration;

use crate::helpers::mock_builder::MockLlmBuilder;
use crate::helpers::mock_ollama::MockOllamaServer;
use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use tokio::sync::mpsc;

async fn wait_for_path(path: &Path) {
    for _ in 0..600 {
        if path.exists() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("{} was never created", path.display());
}

/// Write `first`, then `second` and `third` while the model answers it. Returns the prompt and
/// event data of every `pty_input_received` call the model received.
async fn calls_for_three_writes(batching: bool) -> Vec<(String, serde_json::Value)> {
    let mock = MockOllamaServer::start(
        MockLlmBuilder::new()
            .on_event("pty_input_received")
            .and_event_data_contains("data", "first")
            .respond_with_actions(serde_json::json!([]))
            .after_delay(Duration::from_millis(1500))
            .expect_calls(1)
            .and()
            .on_event("pty_input_received")
            .respond_with_actions(serde_json::json!([]))
            .expect_at_least(1)
            .build(),
    )
    .await
    .expect("mock ollama");

    let state = AppState::new_with_options(false, mock.base_url());
    state
        .set_llm_client(netget::llm::OllamaClient::new(mock.base_url()))
        .await;
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("batch.pty");
    let (tx, _rx) = mpsc::unbounded_channel();
    let id = ServerForm {
        protocol: "pty".to_string(),
        port: None,
        instruction: Some("Acknowledge everything.".to_string()),
        startup_params: Some(serde_json::json!({ "link_path": path.to_string_lossy() })),
        batching: Some(batching),
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .expect("create pty server");
    wait_for_path(&path).await;

    // The terminal program: the slave device, opened through the server's symlink. The slave
    // is in raw mode, so each write reaches the master as written, with no line discipline.
    let mut writer = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .expect("open the PTY slave");
    writer.write_all(b"first").expect("write");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while mock.call_count().await == 0 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "first never reached the model"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // Two writes the reader sees separately, both during the slow first call.
    writer.write_all(b"second").expect("write");
    tokio::time::sleep(Duration::from_millis(200)).await;
    writer.write_all(b"third").expect("write");

    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let reached = mock.recorded_calls().await.iter().any(|c| {
            c.context.event_data["data"]
                .as_str()
                .is_some_and(|d| d.contains("third"))
        });
        if reached {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "third never reached the model"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // Long enough for a stray extra call to show up in the count.
    tokio::time::sleep(Duration::from_millis(300)).await;

    let calls = mock
        .recorded_calls()
        .await
        .into_iter()
        .filter(|c| c.context.event_type.as_deref() == Some("pty_input_received"))
        .map(|c| (c.context.prompt.clone(), c.context.event_data.clone()))
        .collect();
    let _ = state.remove_server(id).await;
    calls
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn input_typed_during_a_call_is_answered_together() {
    // === Control: batching off. Every write is its own call. ===
    let separate = calls_for_three_writes(false).await;
    let data: Vec<_> = separate.iter().map(|(_, d)| d["data"].clone()).collect();
    assert_eq!(
        data,
        vec!["first", "second", "third"],
        "CONTROL FAILED: with batching off each write that arrived during the call must be its \
         own model call, or the two-call result below proves nothing"
    );

    // The session is a connection the core keeps history on: the second call is shown the first
    // exchange above its own event.
    assert_history_carries_first(&separate[1].0);

    // === The claim: the two writes made during the first call come back as one. ===
    let batched = calls_for_three_writes(true).await;
    let data: Vec<_> = batched.iter().map(|(_, d)| d["data"].clone()).collect();
    assert_eq!(
        data,
        vec!["first", "third"],
        "the two writes made during the first call must be answered in one follow-up call, \
         triggered by the newest"
    );
    let (prompt, _) = &batched[1];
    let trigger_at = prompt
        .rfind("Event ID: pty_input_received")
        .expect("trigger");
    let before = &prompt[..trigger_at];
    assert!(
        before.contains(r#""data":"second""#),
        "the earlier write must be listed as arrived and not yet answered:\n{prompt}"
    );
    assert!(
        before.contains("answers all 2 together"),
        "the model must be told it answers both:\n{prompt}"
    );
    assert_history_carries_first(prompt);
}

/// The prompt shows the first exchange as history ahead of the event(s) it asks about.
fn assert_history_carries_first(prompt: &str) {
    let history_at = prompt
        .find("Earlier on this connection")
        .unwrap_or_else(|| panic!("no history block in the prompt:\n{prompt}"));
    let trigger_at = prompt
        .rfind("Event ID: pty_input_received")
        .expect("trigger");
    assert!(
        history_at < trigger_at && prompt[history_at..trigger_at].contains(r#""data":"first"#),
        "the history block must carry the first exchange:\n{prompt}"
    );
}

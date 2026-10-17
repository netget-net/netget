//! Batching on the stdio server: input arriving on stdin while the model is answering.
//!
//! A separate reader task drains stdin while the model answers, so each read keeps its own
//! boundary instead of piling up in the pipe. With batching off the dispatcher answers one read
//! per call; with it on, every read waiting is handed to `call_llm_batch` together — the newest
//! is the trigger, the earlier ones are listed above it.
//!
//! stdio takes over the process's own stdin, so this cannot run in-process: like
//! `e2e_test.rs`, it spawns the NetGet binary as a real child (`--server stdio --batching
//! <bool>`) with a piped stdin and an in-process mock model. The first line is answered slowly;
//! two more are written, 200 ms apart, during that call. Off is the control and runs first in
//! the same test: three calls, one per line. On: two calls, the second triggered by `third`
//! with `second` listed as arrived and not yet answered.
#![cfg(unix)]

use std::process::Stdio;
use std::time::Duration;

use crate::helpers::child_guard;
use crate::helpers::mock_builder::MockLlmBuilder;
use crate::helpers::mock_ollama::MockOllamaServer;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;

/// Write `first`, then `second` and `third` while the model answers it. Returns the prompt and
/// event data of every `stdio_input_received` call the model received.
async fn calls_for_three_lines(batching: bool) -> Vec<(String, serde_json::Value)> {
    let mock = MockOllamaServer::start(
        MockLlmBuilder::new()
            .on_event("stdio_input_received")
            .and_event_data_contains("data", "first")
            .respond_with_actions(serde_json::json!([]))
            .after_delay(Duration::from_millis(1500))
            .expect_calls(1)
            .and()
            .on_event("stdio_input_received")
            .respond_with_actions(serde_json::json!([]))
            .expect_at_least(1)
            .and()
            .on_any()
            .respond_with_actions(serde_json::json!([]))
            .expect_at_least(0)
            .build(),
    )
    .await
    .expect("mock ollama");

    let mut child = Command::new(env!("CARGO_BIN_EXE_netget"))
        .arg("--model")
        .arg("qwen3-coder:30b")
        .arg("--log-level")
        .arg("info")
        .arg("--ollama-url")
        .arg(mock.base_url())
        .arg("--server")
        .arg("stdio")
        .arg("--batching")
        .arg(batching.to_string())
        .arg("--")
        .arg("Acknowledge every line.")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn netget");
    // `kill_on_drop` does not run when this binary is SIGKILLed; the tie is the OS-level half.
    let pid = child.id();
    if let Some(pid) = pid {
        child_guard::tie_child(pid);
    }

    let mut stdin = child.stdin.take().expect("child stdin");
    // Drain stdout so a full pipe can never stall the child.
    let mut stdout = child.stdout.take().expect("child stdout");
    let drain = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        while matches!(stdout.read(&mut buf).await, Ok(n) if n > 0) {}
    });

    // The pipe holds `first` until the stdio server claims stdin and reads it.
    stdin.write_all(b"first\n").await.expect("write");
    stdin.flush().await.expect("flush");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    while mock.call_count().await == 0 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "first never reached the model"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // Two lines the reader sees as separate reads, both during the slow first call.
    stdin.write_all(b"second\n").await.expect("write");
    stdin.flush().await.expect("flush");
    tokio::time::sleep(Duration::from_millis(200)).await;
    stdin.write_all(b"third\n").await.expect("write");
    stdin.flush().await.expect("flush");

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
        .filter(|c| c.context.event_type.as_deref() == Some("stdio_input_received"))
        .map(|c| (c.context.prompt.clone(), c.context.event_data.clone()))
        .collect();

    let _ = child.kill().await;
    // After the kill, never before: a tie released first leaves nothing watching.
    if let Some(pid) = pid {
        child_guard::untie_child(pid);
    }
    drain.abort();
    calls
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lines_arriving_during_a_call_are_answered_together() {
    // === Control: batching off. Every read is its own call. ===
    let separate = calls_for_three_lines(false).await;
    let data: Vec<_> = separate.iter().map(|(_, d)| d["data"].clone()).collect();
    assert_eq!(
        data,
        vec!["first\n", "second\n", "third\n"],
        "CONTROL FAILED: with batching off each read that arrived during the call must be its \
         own model call, or the two-call result below proves nothing"
    );

    // === The claim: the two lines written during the first call come back as one. ===
    let batched = calls_for_three_lines(true).await;
    let data: Vec<_> = batched.iter().map(|(_, d)| d["data"].clone()).collect();
    assert_eq!(
        data,
        vec!["first\n", "third\n"],
        "the two lines written during the first call must be answered in one follow-up call, \
         triggered by the newest"
    );
    let (prompt, _) = &batched[1];
    let trigger_at = prompt
        .rfind("Event ID: stdio_input_received")
        .expect("trigger");
    let before = &prompt[..trigger_at];
    assert!(
        before.contains(r#""data":"second\n""#),
        "the earlier line must be listed as arrived and not yet answered:\n{prompt}"
    );
    assert!(
        before.contains("answers all 2 together"),
        "the model must be told it answers both:\n{prompt}"
    );
}

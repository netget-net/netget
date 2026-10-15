//! End-to-end test for the stdio (pipe-filter) server.
//!
//! stdio takes over the *process's own* stdin/stdout, so the shared harness (which passes the
//! prompt as an arg and never pipes stdin) cannot drive it. This test spawns the NetGet binary
//! directly as a **real child process** with piped stdin/stdout — exactly the
//! `prog | netget ... | prog` use case — points it at an in-process mock Ollama, feeds a line on
//! stdin, and asserts the model's bytes on stdout. LLM interaction is asserted via the mock's
//! `verify_calls()`.
//!
//! ## Why startup uses actions-JSON, not a natural-language prompt
//!
//! NetGet's prompt resolution (`get_actions_json` -> `piped_stdin`) does a **blocking**
//! `read_to_string` on stdin whenever the invocation is not actions-JSON — it supports
//! `cat prompt.txt | netget`. With an open (never-EOF) stdin pipe that call blocks forever,
//! *before* any server starts, so a natural-language prompt can never hand stdin to the stdio
//! server. Starting via a `{"actions": [...]}` argument (or `--load`) returns before
//! `piped_stdin()` is called, leaving stdin intact for the server. This is the sanctioned way to
//! launch the stdio protocol; see `src/server/stdio/CLAUDE.md`.
//!
//! Platform: Unix/Linux/macOS only.
#![cfg(unix)]

use super::super::super::helpers::child_guard;
use super::super::super::helpers::mock_builder::MockLlmBuilder;
use super::super::super::helpers::mock_ollama::MockOllamaServer;
use super::super::super::helpers::E2EResult;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;

/// NetGet as a stdio filter: a line typed on stdin is answered by the model with an uppercased
/// line on stdout. Driven by a real child process with piped stdin/stdout.
#[tokio::test]
async fn test_stdio_pipe_filter() -> E2EResult<()> {
    // Only the per-line event needs the LLM; startup is a deterministic actions-JSON open_server.
    let mock = MockLlmBuilder::new()
        .on_event("stdio_input_received")
        .and_event_data_contains("data", "hello")
        .respond_with_actions(serde_json::json!([{
            "type": "write_stdout",
            "data": "HELLO\n"
        }]))
        .expect_calls(1)
        .and()
        .build();
    let mock_server = MockOllamaServer::start(mock).await?;

    // Start via actions-JSON so NetGet does not drain/block on stdin for prompt resolution.
    let actions = serde_json::json!({
        "actions": [{
            "type": "open_server",
            "base_stack": "stdio",
            "instruction": "For each stdin line, write its uppercase form to stdout"
        }]
    })
    .to_string();

    let mut child = Command::new(env!("CARGO_BIN_EXE_netget"))
        .arg("--model")
        .arg("qwen3-coder:30b")
        .arg("--log-level")
        .arg("info")
        .arg("--ollama-url")
        .arg(mock_server.base_url())
        .arg(actions)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()?;
    // `kill_on_drop` covers the normal and unwinding-panic paths and nothing else: `Drop` does
    // not run when this binary is `SIGKILL`ed, aborts, or is interrupted mid-run — which is how
    // 78 orphaned `netget` processes accumulated on one machine in ten hours. The tie is the
    // OS-level half. See `tests/helpers/child_guard.rs`.
    let pid = child.id();
    if let Some(pid) = pid {
        child_guard::tie_child(pid);
    }

    let mut stdin = child.stdin.take().ok_or("no child stdin")?;
    let mut lines = BufReader::new(child.stdout.take().ok_or("no child stdout")?).lines();

    // Let the process load the action and have the stdio server claim stdin.
    tokio::time::sleep(Duration::from_millis(2000)).await;

    // Type a line. Keep the stdin handle alive (no EOF) so the session stays open; we assert the
    // response, then kill the child.
    stdin.write_all(b"hello\n").await?;
    stdin.flush().await?;

    // Read stdout until the model's uppercased answer appears (tolerating the interleaved status
    // lines the non-interactive runner also prints to stdout).
    let found = tokio::time::timeout(Duration::from_secs(15), async {
        while let Ok(Some(line)) = lines.next_line().await {
            if line.contains("HELLO") {
                return true;
            }
        }
        false
    })
    .await
    .unwrap_or(false);

    let _ = child.kill().await;
    // After the kill, never before: a tie released first leaves nothing watching.
    if let Some(pid) = pid {
        child_guard::untie_child(pid);
    }

    assert!(
        found,
        "stdout should carry the model's uppercased 'HELLO' written via write_stdout"
    );

    mock_server.verify_calls().await?;
    Ok(())
}

/// The pipe-filter, launched the sanctioned way: `prog | netget --server stdio | prog`, with a
/// **live** (never-EOF) piped stdin. Asserts the two IMPROVEMENTS-item-12 fixes together:
///
/// 1. **Bootstrap does not drain stdin.** The `--server` flag returns before NetGet's prompt
///    resolution (`get_actions_json`/`get_prompt`) would blocking-`read_to_string` stdin, so the
///    stdio server gets a live stdin and answers the typed line — a blocked bootstrap would hang
///    here and the model would never be called.
/// 2. **Status is OFF stdout.** NetGet's own status/log lines (`[SERVER] Using model`, `Server #N
///    started`, `Waiting for connections`, `[STATUS] ...`) go to stderr in `--server stdio` mode,
///    so the child's stdout carries ONLY the model's `write_stdout` payload — a clean downstream
///    pipe. We assert stdout is pristine AND that the status text actually appears on stderr
///    (proving it was rerouted, not lost).
#[tokio::test]
async fn test_stdio_server_flag_clean_stdout() -> E2EResult<()> {
    let mock = MockLlmBuilder::new()
        .on_event("stdio_input_received")
        .and_event_data_contains("data", "hello")
        .respond_with_actions(serde_json::json!([{
            "type": "write_stdout",
            "data": "HELLO\n"
        }]))
        .expect_calls(1)
        .and()
        .build();
    let mock_server = MockOllamaServer::start(mock).await?;

    // Launch via the --server flag with the instruction as the trailing prompt. No actions-JSON,
    // no drained stdin: the fix under test is that this path leaves stdin live for the server.
    let mut child = Command::new(env!("CARGO_BIN_EXE_netget"))
        .arg("--model")
        .arg("qwen3-coder:30b")
        .arg("--log-level")
        .arg("info")
        .arg("--ollama-url")
        .arg(mock_server.base_url())
        .arg("--server")
        .arg("stdio")
        .arg("--")
        .arg("For each stdin line, write its uppercase form to stdout")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;
    // `kill_on_drop` covers the normal and unwinding-panic paths and nothing else: `Drop` does
    // not run when this binary is `SIGKILL`ed, aborts, or is interrupted mid-run — which is how
    // 78 orphaned `netget` processes accumulated on one machine in ten hours. The tie is the
    // OS-level half. See `tests/helpers/child_guard.rs`.
    let pid = child.id();
    if let Some(pid) = pid {
        child_guard::tie_child(pid);
    }

    let mut stdin = child.stdin.take().ok_or("no child stdin")?;
    let mut stdout_lines = BufReader::new(child.stdout.take().ok_or("no child stdout")?).lines();

    // Drain stderr in the background into a shared buffer (so its pipe never fills), and so we can
    // assert the status text was routed here rather than dropped.
    let stderr_buf = std::sync::Arc::new(tokio::sync::Mutex::new(String::new()));
    let stderr_buf_reader = stderr_buf.clone();
    let mut stderr_lines = BufReader::new(child.stderr.take().ok_or("no child stderr")?).lines();
    let stderr_task = tokio::spawn(async move {
        while let Ok(Some(line)) = stderr_lines.next_line().await {
            let mut buf = stderr_buf_reader.lock().await;
            buf.push_str(&line);
            buf.push('\n');
        }
    });

    // Let the process validate the model, start the stdio server, and claim stdin.
    tokio::time::sleep(Duration::from_millis(2500)).await;

    stdin.write_all(b"hello\n").await?;
    stdin.flush().await?;

    // Collect EVERY stdout line up to and including the payload. Any NetGet status line wrongly
    // left on stdout would be emitted during startup and therefore appear here before HELLO.
    let mut stdout_seen: Vec<String> = Vec::new();
    let found = tokio::time::timeout(Duration::from_secs(15), async {
        while let Ok(Some(line)) = stdout_lines.next_line().await {
            let is_payload = line.contains("HELLO");
            stdout_seen.push(line);
            if is_payload {
                return true;
            }
        }
        false
    })
    .await
    .unwrap_or(false);

    let _ = child.kill().await;
    // After the kill, never before: a tie released first leaves nothing watching.
    if let Some(pid) = pid {
        child_guard::untie_child(pid);
    }
    let _ = stderr_task.await;

    assert!(
        found,
        "stdout should carry the model's 'HELLO' (a hung bootstrap or wrong routing would fail this).\nstdout saw: {stdout_seen:?}"
    );

    // stdout must be pristine: nothing but the payload. None of NetGet's status/log vocabulary.
    let status_markers = [
        "[SERVER]",
        "[STATUS]",
        "Using model",
        "started",
        "Waiting for connections",
        "is running",
        "Server stopped",
    ];
    for line in &stdout_seen {
        if line.contains("HELLO") {
            continue;
        }
        for marker in status_markers {
            assert!(
                !line.contains(marker),
                "NetGet status line leaked onto stdout (should be on stderr): {line:?}"
            );
        }
    }

    // And prove the status was rerouted to stderr, not merely suppressed.
    let stderr = stderr_buf.lock().await.clone();
    assert!(
        stderr.contains("Waiting for connections") || stderr.contains("Using model"),
        "expected NetGet status text on stderr; stderr was:\n{stderr}"
    );

    mock_server.verify_calls().await?;
    Ok(())
}

/// When the LLM backend fails, the filter must not go silent *and* must not corrupt the payload
/// stream. stdout is the data channel a downstream process parses, so nothing diagnostic goes
/// there; fd 2 is where a Unix filter says it could not do its job, so it carries one
/// category-only line — never the backend error, the model name, or a URL.
///
/// The mock answers with prose the action parser cannot use, which is what `call_llm` surfaces as
/// an `Err` after its retries.
#[tokio::test]
async fn test_stdio_llm_failure_writes_category_to_stderr_only() -> E2EResult<()> {
    let mock = MockLlmBuilder::new()
        .on_event("stdio_input_received")
        .respond_with_raw("Sorry, I would rather not answer in that format.")
        .expect_at_least(1)
        .and()
        .build();
    let mock_server = MockOllamaServer::start(mock).await?;

    let mut child = Command::new(env!("CARGO_BIN_EXE_netget"))
        .arg("--model")
        .arg("qwen3-coder:30b")
        .arg("--log-level")
        .arg("info")
        .arg("--ollama-url")
        .arg(mock_server.base_url())
        .arg("--server")
        .arg("stdio")
        .arg("--")
        .arg("For each stdin line, write its uppercase form to stdout")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;
    // `kill_on_drop` covers the normal and unwinding-panic paths and nothing else: `Drop` does
    // not run when this binary is `SIGKILL`ed, aborts, or is interrupted mid-run — which is how
    // 78 orphaned `netget` processes accumulated on one machine in ten hours. The tie is the
    // OS-level half. See `tests/helpers/child_guard.rs`.
    let pid = child.id();
    if let Some(pid) = pid {
        child_guard::tie_child(pid);
    }

    let mut stdin = child.stdin.take().ok_or("no child stdin")?;
    let mut stdout_lines = BufReader::new(child.stdout.take().ok_or("no child stdout")?).lines();

    let stderr_buf = std::sync::Arc::new(tokio::sync::Mutex::new(String::new()));
    let stderr_buf_reader = stderr_buf.clone();
    let mut stderr_lines = BufReader::new(child.stderr.take().ok_or("no child stderr")?).lines();
    let stderr_task = tokio::spawn(async move {
        while let Ok(Some(line)) = stderr_lines.next_line().await {
            let mut buf = stderr_buf_reader.lock().await;
            buf.push_str(&line);
            buf.push('\n');
        }
    });

    // Collect anything that reaches stdout; the assertion below is that the failure notice is not
    // among it.
    let stdout_buf = std::sync::Arc::new(tokio::sync::Mutex::new(String::new()));
    let stdout_buf_reader = stdout_buf.clone();
    let stdout_task = tokio::spawn(async move {
        while let Ok(Some(line)) = stdout_lines.next_line().await {
            let mut buf = stdout_buf_reader.lock().await;
            buf.push_str(&line);
            buf.push('\n');
        }
    });

    tokio::time::sleep(Duration::from_millis(2500)).await;
    stdin.write_all(b"hello\n").await?;
    stdin.flush().await?;

    // Wait for the category line on stderr (the retries take a moment).
    let found = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if stderr_buf.lock().await.contains("could not be processed")
                || stderr_buf.lock().await.contains("backend at capacity")
            {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await
    .unwrap_or(false);

    let _ = child.kill().await;
    // After the kill, never before: a tie released first leaves nothing watching.
    if let Some(pid) = pid {
        child_guard::untie_child(pid);
    }
    let _ = stderr_task.await;
    let _ = stdout_task.await;

    let stderr = stderr_buf.lock().await.clone();
    let stdout = stdout_buf.lock().await.clone();

    assert!(
        found,
        "a backend failure must leave a category-only notice on stderr, not silence.\nstderr was:\n{stderr}"
    );

    // stdout stays pristine: the failure notice never touches the payload stream.
    assert!(
        !stdout.contains("could not be processed") && !stdout.contains("backend at capacity"),
        "the failure notice leaked onto the payload stream (stdout):\n{stdout}"
    );

    // And the notice carries no internals. These are the tokens that leaked historically
    // (tests/wire_failure_test.rs FORBIDDEN_TOKENS); they may appear elsewhere on stderr, which is
    // the log channel, so only the notice line itself is inspected.
    for line in stderr.lines().filter(|l| l.contains("netget: ")) {
        for token in ["✗", "retries", "http://", "11434", "qwen", "/Users/"] {
            assert!(
                !line.contains(token),
                "the peer-visible failure line leaked {token:?}: {line:?}"
            );
        }
    }

    mock_server.verify_calls().await?;
    Ok(())
}

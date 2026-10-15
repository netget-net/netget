//! End-to-end tests for the named pipe (POSIX FIFO) server.
//!
//! These spawn the real NetGet binary and validate behaviour against a *real, independent* FIFO
//! peer: the test itself opens the FIFO paths with `std::fs` and writes/reads bytes, exactly as a
//! shell `echo > fifo` / `cat fifo` would. No NetGet-against-NetGet.
//!
//! Platform: Unix/Linux/macOS only.
#![cfg(unix)]

use super::super::super::helpers::{self, E2EResult, NetGetConfig};
use std::io::{Read, Write};
use std::time::Duration;

const IN_FIFO: &str = "./tmp/netget-test-fifo.in";
const OUT_FIFO: &str = "./tmp/netget-test-fifo.out";

const FAIL_IN_FIFO: &str = "./tmp/netget-test-fifo-fail.in";
const FAIL_OUT_FIFO: &str = "./tmp/netget-test-fifo-fail.out";

/// Wait until `path` exists, rather than sleeping a fixed interval and hoping.
///
/// Startup returns when the harness has *parsed* the server's start line, not when the protocol
/// has created its filesystem object, so the gap has to be waited out. A fixed sleep is enough
/// alone and not when a hundred tests run together, which is the shape CLAUDE.md warns about
/// under "Running tests".
async fn wait_for_path(path: &str, secs: u64) -> E2EResult<()> {
    let deadline = std::time::Instant::now() + Duration::from_secs(secs);
    while std::time::Instant::now() < deadline {
        if std::path::Path::new(path).exists() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    Err(format!("{path} was never created within {secs}s").into())
}

/// Round-trip: a real writer writes to the input FIFO, the mocked LLM answers with
/// write_named_pipe_data, and a real reader reads the model's bytes off the response FIFO.
#[tokio::test]
async fn test_named_pipe_request_response() -> E2EResult<()> {
    let _ = std::fs::create_dir_all("./tmp");
    let _ = std::fs::remove_file(IN_FIFO);
    let _ = std::fs::remove_file(OUT_FIFO);

    let prompt = "Create a named pipe FIFO server. Read from netget-test-fifo.in and, for each \
                  write, answer PONG on netget-test-fifo.out";

    let server = helpers::start_netget_server(NetGetConfig::new(prompt).with_mock(|mock| {
        mock.on_instruction_containing("named pipe")
            .and_instruction_containing("netget-test-fifo")
            .respond_with_actions(serde_json::json!([{
                "type": "open_server",
                "port": 0,
                "base_stack": "NAMED_PIPE",
                "instruction": "Answer PONG for each write",
                "startup_params": {
                    "pipe_path": IN_FIFO,
                    "response_pipe_path": OUT_FIFO
                }
            }]))
            .expect_calls(1)
            .and()
            .on_event("named_pipe_data_received")
            .and_event_data_contains("data", "PING")
            .respond_with_actions(serde_json::json!([{
                "type": "write_named_pipe_data",
                "data": "PONG\n"
            }]))
            .expect_calls(1)
            .and()
    }))
    .await?;

    // Wait for both FIFO nodes, not for a guessed interval: opening a FIFO that does not exist
    // yet fails outright, and opening one the server has not opened yet blocks.
    wait_for_path(IN_FIFO, 30).await?;
    wait_for_path(OUT_FIFO, 30).await?;

    // Real independent peer: open the FIFOs with std::fs and drive them. FIFO opens block on
    // peer availability, and reads block on data, so run them on a blocking thread under a timeout.
    let response = tokio::time::timeout(
        Duration::from_secs(15),
        tokio::task::spawn_blocking(|| -> std::io::Result<String> {
            // Writer opens the input FIFO (server holds it open, so this returns immediately).
            let mut writer = std::fs::OpenOptions::new().write(true).open(IN_FIFO)?;
            writer.write_all(b"PING\n")?;
            writer.flush()?;

            // Reader opens the response FIFO and reads the model's bytes.
            let mut reader = std::fs::OpenOptions::new().read(true).open(OUT_FIFO)?;
            let mut buf = [0u8; 64];
            let n = reader.read(&mut buf)?;
            Ok(String::from_utf8_lossy(&buf[..n]).to_string())
        }),
    )
    .await
    .map_err(|_| "Timed out waiting for FIFO round-trip")???;

    assert!(
        response.contains("PONG"),
        "Response FIFO should carry PONG, got: {response:?}"
    );

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;

    let _ = std::fs::remove_file(IN_FIFO);
    let _ = std::fs::remove_file(OUT_FIFO);
    Ok(())
}

/// LLM failure: the reader gets a category, never a diagnosis, and never silence.
///
/// A reader parked in `read()` on the response FIFO has no timeout of its own, so a backend
/// failure that writes nothing hangs it forever. The server writes one attributed line carrying
/// only a `WireFailure` category; this asserts both halves — that something arrives, and that
/// nothing from netget's internals (the backend URL, the model name, its retry text) is in it.
#[tokio::test]
async fn test_named_pipe_llm_failure_answers_with_a_category_only() -> E2EResult<()> {
    let _ = std::fs::create_dir_all("./tmp");
    let _ = std::fs::remove_file(FAIL_IN_FIFO);
    let _ = std::fs::remove_file(FAIL_OUT_FIFO);

    let prompt = "Create a named pipe FIFO server. Read from netget-test-fifo-fail.in and answer \
                  on netget-test-fifo-fail.out";

    // Only the startup instruction is mocked. The `named_pipe_data_received` event matches no
    // rule, so the mock answers HTTP 500 and `call_llm` returns Err after its retries — the
    // backend-failure path under test.
    let server = helpers::start_netget_server(NetGetConfig::new(prompt).with_mock(|mock| {
        mock.on_instruction_containing("named pipe")
            .and_instruction_containing("netget-test-fifo-fail")
            .respond_with_actions(serde_json::json!([{
                "type": "open_server",
                "port": 0,
                "base_stack": "NAMED_PIPE",
                "instruction": "Answer for each write",
                "startup_params": {
                    "pipe_path": FAIL_IN_FIFO,
                    "response_pipe_path": FAIL_OUT_FIFO
                }
            }]))
            .expect_calls(1)
            .and()
    }))
    .await?;

    wait_for_path(FAIL_IN_FIFO, 30).await?;
    wait_for_path(FAIL_OUT_FIFO, 30).await?;

    let response = tokio::time::timeout(
        Duration::from_secs(60),
        tokio::task::spawn_blocking(|| -> std::io::Result<String> {
            let mut writer = std::fs::OpenOptions::new().write(true).open(FAIL_IN_FIFO)?;
            writer.write_all(b"PING\n")?;
            writer.flush()?;

            let mut reader = std::fs::OpenOptions::new().read(true).open(FAIL_OUT_FIFO)?;
            let mut buf = [0u8; 256];
            let n = reader.read(&mut buf)?;
            Ok(String::from_utf8_lossy(&buf[..n]).to_string())
        }),
    )
    .await
    .map_err(|_| "Timed out waiting for the failure notice on the response FIFO")???;

    assert!(
        response.starts_with("netget: "),
        "the reader must get an attributed failure line, got: {response:?}"
    );
    // The categories WireFailure can produce; nothing else may be on the pipe.
    assert!(
        response.contains("request could not be processed")
            || response.contains("backend at capacity"),
        "the line must carry a WireFailure category, got: {response:?}"
    );
    for token in [
        "✗", "retries", "http://", "11434", "LLM", "ollama", "Ollama", "/Users/",
    ] {
        assert!(
            !response.contains(token),
            "the failure notice leaked {token:?}: {response:?}"
        );
    }

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;

    let _ = std::fs::remove_file(FAIL_IN_FIFO);
    let _ = std::fs::remove_file(FAIL_OUT_FIFO);
    Ok(())
}

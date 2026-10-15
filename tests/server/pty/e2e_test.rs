//! End-to-end tests for the pseudo-terminal (PTY) server.
//!
//! Validated against a *real terminal client*: the test opens the slave PTY device (via the
//! server's symlink) with `std::fs` and drives it exactly as `screen`/`cat` would — reading what
//! the model puts on the terminal and typing input back. No NetGet-against-NetGet.
//!
//! Platform: Unix/Linux/macOS only.
#![cfg(unix)]

use super::super::super::helpers::{self, E2EResult, NetGetConfig};
use std::io::{Read, Write};
use std::time::Duration;

const LINK: &str = "./tmp/netget-test.pty";

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

/// The model role-plays a shell: it prints a prompt on connect (send_first / pty_opened) and
/// answers a typed `whoami` with `root`. A real terminal client opens the slave and checks both.
#[tokio::test]
async fn test_pty_prompt_and_command() -> E2EResult<()> {
    let _ = std::fs::create_dir_all("./tmp");
    let _ = std::fs::remove_file(LINK);

    let prompt =
        "Open a pseudo terminal symlinked at netget-test.pty. Print the prompt 'netget$ ' \
                  on connect and answer the whoami command with root";

    let server = helpers::start_netget_server(NetGetConfig::new(prompt).with_mock(|mock| {
        mock.on_instruction_containing("pseudo terminal")
            .and_instruction_containing("netget-test.pty")
            .respond_with_actions(serde_json::json!([{
                "type": "open_server",
                "port": 0,
                "base_stack": "PTY",
                "instruction": "Shell role-play: prompt then answer whoami",
                "startup_params": {
                    "link_path": LINK,
                    "send_first": true
                }
            }]))
            .expect_calls(1)
            .and()
            .on_event("pty_opened")
            .respond_with_actions(serde_json::json!([{
                "type": "write_pty_output",
                "data": "netget$ "
            }]))
            .expect_calls(1)
            .and()
            .on_event("pty_input_received")
            .and_event_data_contains("data", "whoami")
            .respond_with_actions(serde_json::json!([{
                "type": "write_pty_output",
                "data": "root\n"
            }]))
            .expect_calls(1)
            .and()
    }))
    .await?;

    // Wait for the symlink the server creates, not for a guessed interval: opening it before it
    // exists fails outright. The banner is then waited for by the read below, which blocks.
    wait_for_path(LINK, 30).await?;

    // Real terminal client: open the slave device through the symlink and drive it. PTY reads
    // block until data, so run on a blocking thread under a timeout.
    let (banner, response) = tokio::time::timeout(
        Duration::from_secs(15),
        tokio::task::spawn_blocking(|| -> std::io::Result<(String, String)> {
            let mut tty = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(LINK)?;

            // Read the banner the model wrote on connect.
            let mut buf = [0u8; 256];
            let n = tty.read(&mut buf)?;
            let banner = String::from_utf8_lossy(&buf[..n]).to_string();

            // Type a command; the server reads it as pty_input_received and answers.
            tty.write_all(b"whoami\n")?;
            tty.flush()?;

            let n = tty.read(&mut buf)?;
            let response = String::from_utf8_lossy(&buf[..n]).to_string();
            Ok((banner, response))
        }),
    )
    .await
    .map_err(|_| "Timed out driving the PTY")???;

    assert!(
        banner.contains("netget$"),
        "Terminal should show the prompt banner, got: {banner:?}"
    );
    assert!(
        response.contains("root"),
        "whoami should be answered with root, got: {response:?}"
    );

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;

    let _ = std::fs::remove_file(LINK);
    Ok(())
}

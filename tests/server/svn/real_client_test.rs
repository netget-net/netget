//! SVN against the real `svn` client (1.14.5).
//!
//! # Why this file is the only evidence that counts for this protocol
//!
//! `tests/server/svn/{e2e_test,llm_failure_test,peer_inject_test}.rs` all write
//! `"<command>\n"` themselves and read the reply with `read_line`. That is a line-oriented
//! protocol which only NetGet speaks: ra_svn frames on **tuple structure** — matching parens
//! and byte-counted strings — and a real client's very first message ends in a space with no
//! newline anywhere in it. Those tests passed for months against a server no `svn` client
//! could talk to at all.
//!
//! These tests drive the real Subversion command-line client end to end: greeting, capability
//! tuple, auth-request, the `ANONYMOUS` token (a counted string containing a newline — the
//! second thing a line reader cannot survive), auth success, repository info, and then the
//! commands each subcommand issues. They **fail** when `svn` is absent rather than skipping,
//! because a skip would leave SVN's maturity rating resting on nothing.
//!
//! # What this proves, and what it does not
//!
//! `svn info`, `svn ls` and `svn log` complete and print data they parsed off our wire. It
//! does **not** prove `svn checkout`, `svn update` or `svn commit` work: those drive the
//! editor/report command set and svndiff, none of which this server implements. See
//! `src/server/svn/CLAUDE.md`.
//!
//! # LLM call budget
//!
//! One mocked call per handshake step plus one per command: 8 for `info`, 7 for `ls`, 8 for
//! `log`. Each test uses its own server so a failure names the subcommand that caused it.

use crate::helpers::mock_builder::MockLlmBuilder;
use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
use std::time::Duration;
use tempfile::TempDir;

/// Repository root for the session the client asked for.
///
/// `svn` requires the root it is told about to be a prefix of the URL it opened, and that URL
/// carries an ephemeral port no static handler could know — so it is taken from the event,
/// which is exactly how a model would have to do it.
fn repository_root(url: &str) -> String {
    match url.rfind('/') {
        // Leave the "svn://" scheme's own slashes alone.
        Some(cut) if cut > "svn://".len() => url[..cut].to_string(),
        _ => url.to_string(),
    }
}

/// Fail loudly when the client is missing, rather than passing silently without it.
async fn require_svn() -> E2EResult<()> {
    match tokio::process::Command::new("svn")
        .arg("--version")
        .arg("--quiet")
        .output()
        .await
    {
        Ok(out) if out.status.success() => {
            println!(
                "svn present: {}",
                String::from_utf8_lossy(&out.stdout).trim()
            );
            Ok(())
        }
        Ok(out) => Err(format!("`svn --version` exited {}", out.status).into()),
        Err(e) => Err(format!(
            "svn not available ({e}): these tests drive the real Subversion client against \
             NetGet's ra_svn server, and they are the only evidence that any third-party \
             client can speak to it. Skipping would leave SVN's maturity rating resting on \
             nothing. Install it with `brew install subversion` (macOS) or \
             `apt-get install subversion` (Debian/Ubuntu)."
        )
        .into()),
    }
}

/// The three handshake steps, identical for every subcommand: greeting, auth-request, then
/// accept and describe the repository.
fn handshake_rules(mock: MockLlmBuilder) -> MockLlmBuilder {
    mock.on_event("svn_greeting")
        .respond_with_actions(serde_json::json!([{
            "type": "send_svn_greeting",
            "min_version": 2,
            "max_version": 2,
            "mechanisms": ["ANONYMOUS"]
        }]))
        .expect_calls(1)
        .and()
        .on_event("svn_client_capabilities")
        .respond_with_actions(serde_json::json!([{
            "type": "send_svn_auth_request",
            "mechanisms": ["ANONYMOUS"],
            "realm": "netget lab"
        }]))
        .expect_calls(1)
        .and()
        // Two tuples in one answer: the client reads the auth success *and* the repository
        // info before it sends its first command.
        .on_event("svn_auth_response")
        .respond_with_actions_from_event(|event| {
            let url = event["url"].as_str().unwrap_or_default().to_string();
            serde_json::json!([
                {"type": "send_svn_auth_success"},
                {
                    "type": "send_svn_repos_info",
                    "uuid": "8f3c1d2e-4b5a-4c6d-9e7f-0a1b2c3d4e5f",
                    "repository_root": repository_root(&url)
                }
            ])
        })
        .expect_calls(1)
        .and()
}

async fn run_svn(args: &[&str], work: &TempDir, what: &str) -> E2EResult<String> {
    // `tokio::process`, not `std::process`: `#[tokio::test]` is a current-thread runtime, and a
    // blocking `output()` parks the only worker that could drain the child's pipes.
    let output = tokio::time::timeout(
        Duration::from_secs(120),
        tokio::process::Command::new("svn")
            .args(args)
            .arg("--non-interactive")
            .arg("--config-dir")
            .arg(work.path())
            .output(),
    )
    .await
    .map_err(|_| format!("svn {what} did not finish within 120s"))??;

    let mut out = String::from_utf8_lossy(&output.stdout).into_owned();
    out.push_str(&String::from_utf8_lossy(&output.stderr));
    println!("--- svn {what} ---\n{out}\n--- end ---");

    if !output.status.success() {
        return Err(format!(
            "the real svn client could not complete `svn {what}` (exit {}):\n{out}",
            output.status
        )
        .into());
    }
    Ok(out)
}

#[tokio::test]
async fn test_svn_info_against_real_svn_client() -> E2EResult<()> {
    println!("\n=== E2E Test: real `svn info` against NetGet's ra_svn server ===");
    require_svn().await?;

    let prompt = "Listen on port {AVAILABLE_PORT} via SVN. Serve the lab repository";
    let config = NetGetConfig::new_no_scripts(prompt).with_mock(|mock| {
        handshake_rules(
            mock.on_instruction_containing("via SVN")
                .respond_with_actions(serde_json::json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "SVN",
                    "instruction": "Serve the lab repository"
                }]))
                .expect_calls(1)
                .and(),
        )
        // ONE rule that branches on the command, not one rule per command: rules are
        // first-match-wins, so two rules on the same event with nothing to tell them apart
        // would leave the second at zero calls.
        .on_event("svn_command")
        .respond_with_actions_from_event(|event| {
            match event["command"].as_str().unwrap_or_default() {
                "get-latest-rev" => serde_json::json!([
                    {"type": "send_svn_success", "data": "42"}
                ]),
                "stat" => serde_json::json!([{
                    "type": "send_svn_stat",
                    "kind": "dir",
                    "size": 0,
                    "has_props": false,
                    "created_rev": 42,
                    "created_date": "2026-01-01T00:00:00.000000Z",
                    "last_author": "netget"
                }]),
                // `( success ( ( ) ) )` is ra_svn's empty optional: no lock on that path.
                "get-lock" => serde_json::json!([
                    {"type": "send_svn_response", "response": "( success ( ( ) ) )"}
                ]),
                _ => serde_json::json!([{
                    "type": "send_svn_failure",
                    "error_code": 210001,
                    "message": "Not implemented"
                }]),
            }
        })
        // 1.14.5 issues get-latest-rev, stat, get-latest-rev, get-lock. Pinned as "at least"
        // because the sequence is the client's business and a later version may reorder it;
        // what is asserted below is that `svn` exited 0 having printed what it read.
        .expect_at_least(3)
        .and()
    });

    let server = start_netget_server(config).await?;
    let work = TempDir::new()?;
    let url = format!("svn://127.0.0.1:{}/lab", server.port);
    let out = run_svn(&["info", &url], &work, "info").await?;

    // Each needle is a field the client parsed out of a *different* tuple: the revision from
    // get-latest-rev, the UUID from the repos-info that follows the auth success, the kind and
    // author from the stat dirent. Asserting only "exit 0" would pass against a client that
    // gave up politely.
    for needle in [
        "Revision: 42",
        "Repository UUID: 8f3c1d2e-4b5a-4c6d-9e7f-0a1b2c3d4e5f",
        "Node Kind: directory",
        "Last Changed Author: netget",
        "Last Changed Rev: 42",
    ] {
        assert!(
            out.contains(needle),
            "svn did not report `{needle}` — it never read that tuple:\n{out}"
        );
    }

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

#[tokio::test]
async fn test_svn_ls_against_real_svn_client() -> E2EResult<()> {
    println!("\n=== E2E Test: real `svn ls` against NetGet's ra_svn server ===");
    require_svn().await?;

    let prompt = "Listen on port {AVAILABLE_PORT} via SVN. Serve the lab repository";
    let config = NetGetConfig::new_no_scripts(prompt).with_mock(|mock| {
        handshake_rules(
            mock.on_instruction_containing("via SVN")
                .respond_with_actions(serde_json::json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "SVN",
                    "instruction": "Serve the lab repository"
                }]))
                .expect_calls(1)
                .and(),
        )
        .on_event("svn_command")
        .respond_with_actions_from_event(|event| {
            match event["command"].as_str().unwrap_or_default() {
                "get-latest-rev" => serde_json::json!([
                    {"type": "send_svn_success", "data": "42"}
                ]),
                "stat" => serde_json::json!([{
                    "type": "send_svn_stat",
                    "kind": "dir",
                    "created_rev": 42,
                    "created_date": "2026-01-01T00:00:00.000000Z",
                    "last_author": "netget"
                }]),
                "get-dir" => serde_json::json!([{
                    "type": "send_svn_list",
                    "items": [
                        {"name": "trunk", "kind": "dir", "revision": 1},
                        {"name": "branches", "kind": "dir", "revision": 1},
                        {"name": "README.txt", "kind": "file", "size": 1234, "revision": 5}
                    ]
                }]),
                _ => serde_json::json!([{
                    "type": "send_svn_failure",
                    "error_code": 210001,
                    "message": "Not implemented"
                }]),
            }
        })
        .expect_at_least(2)
        .and()
    });

    let server = start_netget_server(config).await?;
    let work = TempDir::new()?;
    let url = format!("svn://127.0.0.1:{}/lab", server.port);
    let out = run_svn(&["ls", &url], &work, "ls").await?;

    // The trailing slash is the client's own rendering of `kind = dir`, so it is evidence the
    // kind word was read and not merely the name.
    for needle in ["trunk/", "branches/", "README.txt"] {
        assert!(
            out.contains(needle),
            "svn ls did not list `{needle}`:\n{out}"
        );
    }

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

#[tokio::test]
async fn test_svn_log_against_real_svn_client() -> E2EResult<()> {
    println!("\n=== E2E Test: real `svn log` against NetGet's ra_svn server ===");
    require_svn().await?;

    let prompt = "Listen on port {AVAILABLE_PORT} via SVN. Serve the lab repository";
    let config = NetGetConfig::new_no_scripts(prompt).with_mock(|mock| {
        handshake_rules(
            mock.on_instruction_containing("via SVN")
                .respond_with_actions(serde_json::json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "SVN",
                    "instruction": "Serve the lab repository"
                }]))
                .expect_calls(1)
                .and(),
        )
        .on_event("svn_command")
        .respond_with_actions_from_event(|event| {
            match event["command"].as_str().unwrap_or_default() {
                "get-latest-rev" => serde_json::json!([
                    {"type": "send_svn_success", "data": "42"}
                ]),
                // `log` is a *stream*: zero or more bare log-entry tuples, then the word
                // `done`, then the command response. No action models that, so it goes
                // through the raw escape hatch — which is what a model would have to do too,
                // and the reason `log` is named as a limitation in the protocol's CLAUDE.md.
                "log" => serde_json::json!([{
                    "type": "send_svn_response",
                    "response": "( ( ) 42 ( 6:netget ) \
                                 ( 27:2026-01-01T00:00:00.000000Z ) ( 12:first commit ) ) \
                                 done ( success ( ) )"
                }]),
                _ => serde_json::json!([{
                    "type": "send_svn_failure",
                    "error_code": 210001,
                    "message": "Not implemented"
                }]),
            }
        })
        .expect_at_least(2)
        .and()
    });

    let server = start_netget_server(config).await?;
    let work = TempDir::new()?;
    let url = format!("svn://127.0.0.1:{}/lab", server.port);
    let out = run_svn(&["log", &url], &work, "log").await?;

    for needle in ["r42", "netget", "first commit"] {
        assert!(
            out.contains(needle),
            "svn log did not report `{needle}`:\n{out}"
        );
    }

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

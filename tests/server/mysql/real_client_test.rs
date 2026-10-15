//! The **real `mysql` CLI** against NetGet's MySQL server.
//!
//! This is the second independent client. The first, `mysql_async`, is a Rust reimplementation
//! that shares no code with the client a person actually types — and until this test existed
//! it was the *only* thing that had ever completed a session here, because the server offered
//! `mysql_native_password` and MySQL 9.0 deleted that client plugin:
//!
//! ```text
//! ERROR 2059 (HY000): Authentication plugin 'mysql_native_password' cannot be loaded
//! ```
//!
//! So the protocol's Beta rating rested entirely on one client being more permissive than the
//! one a user would reach for. That is the shape the project `CLAUDE.md` calls "one client
//! agreeing with one bug", and the only way to find it is to run the other client.
//!
//! **This test must fail, not skip, when `mysql` is absent.** A `println!("SKIP")` and
//! `Ok(())` is a silent pass on any machine without the binary, which is exactly how a
//! maturity claim outlives the thing that justified it (`tests/server/npm/e2e_test.rs` says
//! the same in its own words).
//!
//! # What the CLI sends before it sends anything you asked for
//!
//! Two queries of its own, and the second one is a trap worth knowing about. Captured from a
//! real `mysqld` 9.3.0 for comparison:
//!
//! | query | what a real MySQL server answers |
//! |---|---|
//! | `select @@version_comment limit 1` | a one-row result set (the banner) |
//! | `select $$` | **ERR 1064, SQLSTATE 42000** — a syntax error |
//!
//! A server that answers `select $$` with a *result set* leaves the client holding an unread
//! one, and the next statement — the one the test is actually about — fails with
//! `ERROR 2014 (HY000): Commands out of sync`. That is a NetGet configuration mistake rather
//! than a protocol defect, but it presents as one, so the rules below answer that probe the
//! way the real server does.

use super::super::super::helpers::{self, E2EResult, NetGetConfig};
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;
use tokio::time::timeout;

/// Fail unless a usable `mysql` client is on PATH, and say which one it is.
///
/// Not a skip. See the module docs.
async fn require_mysql_cli() -> E2EResult<String> {
    let out = timeout(
        Duration::from_secs(30),
        Command::new("mysql")
            .arg("--version")
            .stdin(Stdio::null())
            .output(),
    )
    .await
    .map_err(|_| "`mysql --version` did not finish within 30s")?;

    match out {
        Ok(out) if out.status.success() => {
            Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
        }
        Ok(out) => Err(format!(
            "`mysql --version` exited {}: this test's whole point is driving the real mysql \
             client binary against NetGet's server",
            out.status
        )
        .into()),
        Err(e) => Err(format!(
            "the mysql client is not available ({e}): this test drives the real `mysql` binary, \
             which is the *second* independent client this protocol's maturity rating rests on, \
             and skipping it would leave that rating resting on mysql_async alone. Install it \
             with `brew install mysql` (macOS) or `apt-get install -y mysql-client` (Debian/\
             Ubuntu)."
        )
        .into()),
    }
}

/// Run the `mysql` client against a NetGet server and return (stdout, stderr, success).
///
/// `tokio::process::Command`, not `std::process`: `#[tokio::test]` runs a current-thread
/// runtime, and a blocking `output()` parks the only worker — which is also the task that has
/// to drain the child's pipes, so the test deadlocks rather than failing.
async fn mysql_cli(port: u16, args: &[&str]) -> E2EResult<(String, String, bool)> {
    let mut cmd = Command::new("mysql");
    // `--no-defaults` has to come first — the client rejects it anywhere else — and it is here
    // so that an operator's own `my.cnf` cannot change what this test measures.
    cmd.arg("--no-defaults")
        .args(["-h", "127.0.0.1"])
        .args(["-P", &port.to_string()])
        .args(["-u", "root"])
        .arg("--protocol=TCP")
        // The server offers no TLS.
        .arg("--ssl-mode=DISABLED")
        .args(args)
        .stdin(Stdio::null());

    let out = timeout(Duration::from_secs(60), cmd.output())
        .await
        .map_err(|_| format!("the mysql client did not finish within 60s (args: {args:?})"))??;

    Ok((
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
        out.status.success(),
    ))
}

/// One connection, one `SELECT` whose rows the model authors, one statement that errors.
///
/// `--force` is what makes those two fit in a single session: without it the client stops at
/// the first error, and the error is the second half of what this test is for.
#[tokio::test]
async fn test_mysql_real_client_selects_and_errors() -> E2EResult<()> {
    println!("\n=== E2E Test: MySQL against the real mysql client ===");
    let version = require_mysql_cli().await?;
    println!("client: {version}");

    let prompt = "Open MySQL on port {AVAILABLE_PORT}. Answer SELECT id, email FROM users with \
        mysql_query_response columns=[{name:'id',type:'INT'},{name:'email',type:'VARCHAR'}] \
        rows=[[1,'alice@example.com'],[2,'bob@example.com']]. Answer a query naming an unknown \
        table with mysql_error_response error_code 1146. Answer SELECT @@* with \
        mysql_query_response columns=[{name:'v',type:'VARCHAR'}] rows=[['netget']].";

    let config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock.on_instruction_containing("Open MySQL")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "MySQL",
                    "instruction": "Answer MySQL queries"
                }
            ]))
            .expect_calls(1)
            .and()
            // The CLI's banner query. `expect_at_least`, not `expect_calls`: how many system
            // variables a client asks about is the client's business and varies by version.
            .on_event("mysql_query")
            .and_event_data_contains("query", "@@")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "mysql_query_response",
                    "columns": [{"name": "v", "type": "VARCHAR"}],
                    "rows": [["netget"]]
                }
            ]))
            .expect_at_least(1)
            .and()
            // The CLI's `select $$` probe — see the module docs. Deliberately carries no
            // expectation: it is this client's startup behaviour rather than anything NetGet
            // does, so asserting a count would make the test fail on a client that stopped
            // sending it. Answering it correctly, on the other hand, is load-bearing.
            .on_event("mysql_query")
            .and_event_data_contains("query", "$$")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "mysql_error_response",
                    "error_code": 1064,
                    "message": "You have an error in your SQL syntax"
                }
            ]))
            .and()
            .on_event("mysql_query")
            .and_event_data_contains("query", "FROM users")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "mysql_query_response",
                    "columns": [
                        {"name": "id", "type": "INT"},
                        {"name": "email", "type": "VARCHAR"}
                    ],
                    "rows": [[1, "alice@example.com"], [2, "bob@example.com"]]
                }
            ]))
            .expect_calls(1)
            .and()
            .on_event("mysql_query")
            .and_event_data_contains("query", "missing_table")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "mysql_error_response",
                    "error_code": 1146,
                    "message": "Table 'netget.missing_table' doesn't exist"
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let server = helpers::start_netget_server(config).await?;
    println!("Server started on port {}", server.port);

    let (stdout, stderr, _ok) = mysql_cli(
        server.port,
        &[
            "--force",
            "-e",
            "SELECT id, email FROM users; SELECT * FROM missing_table",
        ],
    )
    .await?;
    println!("--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}");

    // The connection itself. Before `caching_sha2_password` was offered, this client could not
    // get past its own plugin loader and every assertion below was unreachable.
    assert!(
        !stderr.contains("ERROR 2059"),
        "the client could not load an authentication plugin, so it never reached the query \
         phase: {stderr}"
    );
    assert!(
        !stderr.contains("ERROR 2014") && !stderr.contains("Commands out of sync"),
        "the client and server disagree about how many packets a reply is: {stderr}"
    );

    // The rows the model authored, as the client printed them. Tab-separated, because batch
    // mode is what `-e` selects.
    assert!(
        stdout.contains("id\temail"),
        "the column names the model declared are missing from the client's output: {stdout}"
    );
    assert!(
        stdout.contains("1\talice@example.com"),
        "the first row the model authored is missing from the client's output: {stdout}"
    );
    assert!(
        stdout.contains("2\tbob@example.com"),
        "the second row the model authored is missing from the client's output: {stdout}"
    );

    // The error, in the client's own vocabulary: code, SQLSTATE and message. 42S02 is what
    // 1146 maps to, and the client prints the mapping the *server* sent it.
    assert!(
        stderr.contains("ERROR 1146 (42S02)"),
        "the client did not report the model's error code and SQLSTATE: {stderr}"
    );
    assert!(
        stderr.contains("Table 'netget.missing_table' doesn't exist"),
        "the client did not report the model's error message verbatim: {stderr}"
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    println!("✓ the real mysql client completed a session\n");
    Ok(())
}

/// The same connection phase, with a password on the command line.
///
/// This is the branch that needs the `AuthMoreData` packet: a client that sent a 32-byte
/// `caching_sha2_password` scramble blocks reading for `0x01 0x03` before it will accept the
/// OK packet, while a client with an empty password expects the OK alone. One connection with
/// a password is therefore not redundant with the test above — it exercises the other half of
/// `src/server/mysql/caching_sha2.rs`, and nothing about the password is checked, because
/// **this server verifies nothing**.
#[tokio::test]
async fn test_mysql_real_client_with_a_password_completes_fast_auth() -> E2EResult<()> {
    println!("\n=== E2E Test: MySQL real client, caching_sha2 fast-auth path ===");
    require_mysql_cli().await?;

    let prompt = "Open MySQL on port {AVAILABLE_PORT}. Answer SELECT 1 with mysql_query_response \
        columns=[{name:'one',type:'INT'}] rows=[[1]].";

    let config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock.on_instruction_containing("Open MySQL")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "MySQL",
                    "instruction": "Answer MySQL queries"
                }
            ]))
            .expect_calls(1)
            .and()
            .on_event("mysql_query")
            .and_event_data_contains("query", "@@")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "mysql_query_response",
                    "columns": [{"name": "v", "type": "VARCHAR"}],
                    "rows": [["netget"]]
                }
            ]))
            .expect_at_least(1)
            .and()
            .on_event("mysql_query")
            .and_event_data_contains("query", "$$")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "mysql_error_response",
                    "error_code": 1064,
                    "message": "You have an error in your SQL syntax"
                }
            ]))
            .and()
            .on_event("mysql_query")
            .and_event_data_contains("query", "SELECT 1")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "mysql_query_response",
                    "columns": [{"name": "one", "type": "INT"}],
                    "rows": [[1]]
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let server = helpers::start_netget_server(config).await?;
    println!("Server started on port {}", server.port);

    let (stdout, stderr, ok) = mysql_cli(
        server.port,
        &["--password=netget-does-not-check-this", "-e", "SELECT 1"],
    )
    .await?;
    println!("--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}");

    assert!(
        ok,
        "the client failed a session in which it sent a caching_sha2_password scramble — the \
         fast-auth-success packet is what it was waiting for. stderr: {stderr}"
    );
    assert!(
        stdout.contains("one") && stdout.contains('1'),
        "the row the model authored is missing from the client's output: {stdout}"
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    println!("✓ the fast-auth-success path completed\n");
    Ok(())
}

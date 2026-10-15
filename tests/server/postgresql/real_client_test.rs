//! `psql` — a second, independent client for the PostgreSQL server.
//!
//! The rest of this directory drives `tokio-postgres`. That is a genuine third-party
//! implementation, but it is **one** implementation, and a rating resting on one client is a
//! rating resting on that client's leniency: elsewhere in this repository a second, stricter
//! peer showed that no conformant implementation could complete a call at all, because the
//! failure path happened to be right and the success path was broken.
//!
//! `psql` 14 is libpq — C, shipped by the PostgreSQL project, sharing no line of code with
//! tokio-postgres. What it adds over tokio-postgres, specifically:
//!
//! - **The SSL negotiation.** libpq defaults to `sslmode=prefer`, so psql opens every
//!   connection with an `SSLRequest` packet and expects a single `N` byte back before it sends
//!   the StartupMessage. tokio-postgres with `NoTls` skips that exchange entirely, so nothing
//!   in this directory had ever driven it.
//! - **The rendered result.** psql formats what it received, so the assertions here are on the
//!   bytes a human would see: `t`/`f` for booleans, a real NULL distinguished from an empty
//!   string by `\pset null`, and the column order and count.
//! - **The SQLSTATE.** `\set VERBOSITY verbose` makes psql print the five-character error code
//!   from the `ErrorResponse`'s `C` field, so the code the model chose is asserted on the wire
//!   rather than inferred.
//!
//! What psql 14 does **not** add: the extended query protocol. psql sends every statement as a
//! simple `Query` message (`\bind` arrived in psql 16), so Parse/Bind/Describe/Execute and the
//! binary result format stay proven by `extended_query_test.rs` and by nothing else here. The
//! two clients are complementary rather than overlapping, which is the point.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features postgresql \
//!       --test server -- server::postgresql::real_client --test-threads=8


use crate::helpers::{self, E2EResult, NetGetConfig};
use std::time::Duration;
use tokio::time::timeout;

/// Every `psql` invocation in this file goes through here.
///
/// `tokio::process::Command`, not `std::process`: `#[tokio::test]` runs a current-thread
/// runtime, so a blocking `output()` parks the only worker and the harness tasks draining the
/// netget child's stdout/stderr stop running. The pipes fill, netget blocks inside a log call
/// while it is serving this very query, and psql times out against a server that is behaving
/// perfectly. The symptom looks exactly like a protocol bug.
async fn psql(args: &[&str], what: &str) -> E2EResult<std::process::Output> {
    let out = timeout(
        Duration::from_secs(60),
        tokio::process::Command::new("psql")
            // -X: ignore ~/.psqlrc, so a developer's local settings cannot change what is
            // asserted here. -w: never prompt for a password (the server has no auth, but a
            // prompt would hang rather than fail).
            .arg("-X")
            .arg("-w")
            .args(args)
            .env("PGCONNECT_TIMEOUT", "15")
            .env("PGPASSWORD", "")
            .output(),
    )
    .await
    .map_err(|_| format!("psql {what} did not finish within 60s"))??;
    Ok(out)
}

/// The binary *is* the evidence. A machine without it must say so.
///
/// A `println!("SKIP")` + `Ok(())` here would be a silent pass on every runner that does not
/// have psql installed, which is exactly how a maturity claim outlives the thing that
/// justified it. `.github/workflows/ci.yml`'s `registry-audit` job installs
/// `postgresql-client` for this reason.
async fn require_psql() -> E2EResult<String> {
    match tokio::process::Command::new("psql")
        .arg("--version")
        .output()
        .await
    {
        Ok(out) if out.status.success() => {
            Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
        }
        Ok(out) => Err(format!(
            "`psql --version` exited {}: this test's whole point is driving the real psql \
             binary against NetGet's PostgreSQL server",
            out.status
        )
        .into()),
        Err(e) => Err(format!(
            "psql not available ({e}): this test's whole point is driving the real psql \
             (libpq) client against NetGet's PostgreSQL server, and skipping it would leave \
             PostgreSQL's second-client evidence resting on nothing. Install it with \
             `brew install libpq` / `apt-get install postgresql-client`."
        )
        .into()),
    }
}

/// The rows the model authors, in the order psql must print them.
///
/// Four columns of four different types, three rows, and a NULL in two different positions —
/// enough that `RowDescription`/`DataRow` repetition is real and that a column-count or
/// column-order mistake shows up as a wrong line rather than as a wrong count.
fn expected_csv() -> Vec<&'static str> {
    vec![
        "id,name,active,score",
        "1,alice,t,9.5",
        "2,bob,f,<NULL>",
        "3,<NULL>,t,0.25",
    ]
}

/// One netget server; two psql sessions against it.
///
/// LLM calls: 1 startup + 3 statements = **4**.
#[tokio::test]
async fn psql_completes_a_session_against_the_postgresql_server() -> E2EResult<()> {
    let version = require_psql().await?;
    println!("\n=== E2E: real psql client ({version}) ===");

    let prompt = "Open PostgreSQL on port {AVAILABLE_PORT}. Answer SELECT against users with \
        postgresql_query_response, answer INSERT with postgresql_ok_response, and answer a \
        query against an unknown relation with postgresql_error_response code 42P01.";

    let config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock.on_instruction_containing("Open PostgreSQL")
            .respond_with_actions(serde_json::json!([{
                "type": "open_server",
                "port": 0,
                "base_stack": "PostgreSQL",
                "instruction": "Answer queries for the users table"
            }]))
            .expect_calls(1)
            .and()
            // ONE rule that branches on the event, rather than three rules on the same event
            // id: rules are first-match-wins, so three of those would have the first answer
            // every statement and the other two report zero calls.
            .on_event("postgresql_query")
            .respond_with_actions_from_event(|event| {
                let query = event
                    .get("query")
                    .and_then(|q| q.as_str())
                    .unwrap_or_default()
                    .to_ascii_uppercase();
                if query.contains("NOPE") {
                    serde_json::json!([{
                        "type": "postgresql_error_response",
                        "severity": "ERROR",
                        "code": "42P01",
                        "message": "relation \"nope\" does not exist"
                    }])
                } else if query.contains("INSERT") {
                    serde_json::json!([{
                        "type": "postgresql_ok_response",
                        "tag": "INSERT 0 1"
                    }])
                } else {
                    serde_json::json!([{
                        "type": "postgresql_query_response",
                        "columns": [
                            {"name": "id", "type": "int4"},
                            {"name": "name", "type": "text"},
                            {"name": "active", "type": "bool"},
                            {"name": "score", "type": "float8"}
                        ],
                        "rows": [
                            [1, "alice", true, 9.5],
                            [2, "bob", false, null],
                            [3, null, true, 0.25]
                        ]
                    }])
                }
            })
            .expect_calls(3)
            .and()
    });

    let server = timeout(
        Duration::from_secs(60),
        helpers::start_netget_server(config),
    )
    .await
    .map_err(|_| "netget startup timed out")??;
    let port = server.port.to_string();
    println!("PostgreSQL server on port {port}");

    // ---- Session 1: the startup handshake, a multi-row SELECT, and a command tag ----
    //
    // Two statements on one connection, so the second is answered on a session that is
    // already established rather than on a fresh one.
    let out = psql(
        &[
            "--csv",
            "-P",
            "null=<NULL>",
            "-h",
            "127.0.0.1",
            "-p",
            &port,
            "-U",
            "netget",
            "-d",
            "netget",
            "-c",
            "SELECT id, name, active, score FROM users ORDER BY id",
            "-c",
            "INSERT INTO users (id, name) VALUES (4, 'dave')",
        ],
        "select+insert",
    )
    .await?;

    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    println!("psql stdout:\n{stdout}\npsql stderr:\n{stderr}");

    assert!(
        out.status.success(),
        "psql exited {} — it could not complete the session.\nstdout:\n{stdout}\nstderr:\n{stderr}",
        out.status
    );

    // The values psql printed, not merely that it exited 0. `t`/`f` are the text-format
    // encoding of a bool; `<NULL>` is `\pset null`, so it distinguishes a real SQL NULL from
    // the empty string the server used to send in its place.
    let lines: Vec<&str> = stdout
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    for expected in expected_csv() {
        assert!(
            lines.contains(&expected),
            "psql did not print the line `{expected}`.\nIt printed:\n{stdout}"
        );
    }

    // Exactly three data rows reached psql, in order — RowDescription/DataRow repetition, not
    // one row repeated or a truncated set.
    let data_rows: Vec<&&str> = lines
        .iter()
        .filter(|l| l.starts_with('1') || l.starts_with('2') || l.starts_with('3'))
        .collect();
    assert_eq!(
        data_rows.len(),
        3,
        "expected exactly 3 data rows from psql, got {data_rows:?}\nfull output:\n{stdout}"
    );

    // The command tag, verbatim, from `postgresql_ok_response`.
    assert!(
        lines.contains(&"INSERT 0 1"),
        "psql did not print the command tag `INSERT 0 1`.\nIt printed:\n{stdout}"
    );

    // ---- Session 2: the error path, with the SQLSTATE psql prints ----
    let out = psql(
        &[
            "-h",
            "127.0.0.1",
            "-p",
            &port,
            "-U",
            "netget",
            "-d",
            "netget",
            // A psql meta-command: it is not sent to the server and costs no LLM call. With
            // verbose errors psql prints the ErrorResponse's `C` field, so the SQLSTATE the
            // model chose is asserted rather than assumed.
            "-c",
            "\\set VERBOSITY verbose",
            "-c",
            "SELECT * FROM nope",
        ],
        "error path",
    )
    .await?;

    let err_stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let err_stderr = String::from_utf8_lossy(&out.stderr).to_string();
    println!("psql error stdout:\n{err_stdout}\npsql error stderr:\n{err_stderr}");

    assert!(
        !out.status.success(),
        "psql exited 0 on a statement the server answered with an ErrorResponse.\n\
         stdout:\n{err_stdout}\nstderr:\n{err_stderr}"
    );
    assert!(
        err_stderr.contains("ERROR:"),
        "psql did not render an ERROR.\nstderr:\n{err_stderr}"
    );
    assert!(
        err_stderr.contains("42P01"),
        "psql did not print the SQLSTATE the model chose (42P01).\nstderr:\n{err_stderr}"
    );
    assert!(
        err_stderr.contains("relation \"nope\" does not exist"),
        "psql did not print the message the model chose.\nstderr:\n{err_stderr}"
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

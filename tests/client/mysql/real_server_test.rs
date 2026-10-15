//! The MySQL client against a real **`mysqld`** — the evidence its maturity rating rests on.
//!
//! NetGet's MySQL client is `mysql_async`, a Rust implementation of the client protocol. The
//! server here is Oracle's `mysqld` (C++), initialised per test with
//! `mysqld --initialize-insecure` into the guard's temporary directory and started on a probed
//! loopback port with X Protocol off. What the server holds afterwards is read back with the
//! `mysql` command-line client (libmysqlclient) — a second, independent client. Nothing on the
//! wire was written by this repository except NetGet.
//!
//! Condition 4 of the client bar — the client acts on the model's answer, asserted on the wire
//! — is asserted from the server's side: `mysql` reads back a table the model created, a row
//! the model inserted, and a second row the model built out of the `SELECT` result it was
//! shown. Each result event is matched on the query that produced it and on what the server
//! said about it (`affected_rows`, `last_insert_id`, the rows), so a result the model never saw
//! cannot satisfy the mock.
//!
//! **No test here skips.** A missing `mysqld` or `mysql` fails with the install command.
//!
//! LLM calls: 6.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features mysql --test client -- mysql::real_server_test --test-threads=100


use crate::helpers::real_server::{run_tool, InstallHint, RealServer};
use crate::helpers::*;
use serde_json::json;
use std::process::Command;
use std::time::Duration;

const MYSQLD: InstallHint = InstallHint {
    brew: "mysql",
    apt: "mysql-server (and, on Ubuntu, unload its AppArmor profile: \
          `sudo apparmor_parser -R /etc/apparmor.d/usr.sbin.mysqld`, which confines mysqld to \
          /var/lib/mysql)",
};
const MYSQL_CLI: InstallHint = InstallHint {
    brew: "mysql",
    apt: "mysql-client",
};

/// A throwaway MySQL server: `--initialize-insecure` into the guard's temp dir (a passwordless
/// `root@localhost`), then `mysqld` on 127.0.0.1 only with its socket, pid file and error log
/// in the same dir. `--no-defaults` comes first on both so no `my.cnf` on the machine can move
/// the data directory, the socket or the error log — Ubuntu's sends the log to
/// `/var/log/mysql`, where the readiness line would never be seen. `init.sql` creates the
/// database the client is told to use, so the `database` startup parameter is exercised too.
async fn start_mysqld() -> E2EResult<RealServer> {
    RealServer::builder("mysqld", MYSQLD)
        .config_file("init.sql", "CREATE DATABASE IF NOT EXISTS netget_e2e;\n")
        .setup_command(
            "mysqld",
            MYSQLD,
            [
                "--no-defaults",
                "--initialize-insecure",
                "--datadir={dir}/data",
                "--log-error-verbosity=1",
            ],
        )
        .args([
            "--no-defaults",
            "--datadir={dir}/data",
            "--port={port}",
            "--bind-address=127.0.0.1",
            "--socket={dir}/mysql.sock",
            "--pid-file={dir}/mysqld.pid",
            "--mysqlx=OFF",
            "--skip-log-bin",
            "--init-file={dir}/init.sql",
        ])
        .ready_when_log_matches(r"ready for connections\.")
        .startup_timeout(Duration::from_secs(60))
        .start()
        .await
}

/// `mysql -N -B -e <sql>` as `root` over TCP against the test server, trailing newline trimmed.
async fn mysql_cli(server: &RealServer, sql: &str) -> E2EResult<String> {
    let mut cmd = Command::new("mysql");
    cmd.args([
        "--no-defaults",
        "--protocol=TCP",
        "-h",
        "127.0.0.1",
        "-P",
        &server.port.to_string(),
        "-u",
        "root",
        "-N",
        "-B",
        "-e",
        sql,
    ]);
    Ok(run_tool(cmd, "mysql", MYSQL_CLI)
        .await?
        .trim_end_matches('\n')
        .to_string())
}

/// CREATE, INSERT, SELECT, and an INSERT built from the SELECT's rows — each step decided by
/// the model after it saw the previous step's result.
///
/// 1. `mysql_connected` → `CREATE TABLE notes (id AUTO_INCREMENT, body TEXT)` in the database
///    the client connected to.
/// 2. The CREATE's result (matched on its query and `affected_rows` 0) → `INSERT … 'hello from
///    the model'`.
/// 3. The INSERT's result, matched on `affected_rows` 1 and `last_insert_id` 1 — the server's
///    OK packet, not the empty result set → `SELECT id, body`.
/// 4. The SELECT's result, matched on the query, `row_count` 1 **and** the body in `result` →
///    `INSERT … 'the model saw: <body> (id <id>)'`, both values taken from the row.
/// 5. That INSERT's result → nothing.
///
/// Then `mysql` must read exactly those two bodies back, in order.
///
/// LLM calls: 6 (startup, mysql_connected, four mysql_result_received).
#[tokio::test]
async fn mysql_client_creates_inserts_and_selects_against_mysqld() -> E2EResult<()> {
    let server = start_mysqld().await?;
    let result = creates_inserts_and_selects(&server).await;
    server.with_log(result)
}

async fn creates_inserts_and_selects(server: &RealServer) -> E2EResult<()> {
    let addr = server.addr();
    let config = NetGetConfig::new(format!(
        "Connect to MySQL at {addr}. MYSQL-REAL-SERVER-STARTUP-TURN."
    ))
    .with_mock(move |mock| {
        mock.on_instruction_containing("MYSQL-REAL-SERVER-STARTUP-TURN")
            .respond_with_actions(json!([{
                "type": "open_client",
                "protocol": "MySQL",
                "remote_addr": addr,
                "startup_params": {"username": "root", "database": "netget_e2e"},
                "instruction": "Create a notes table, store a note, read it back, and record \
                                what you read."
            }]))
            .expect_calls(1)
            .and()
            .on_event("mysql_connected")
            .respond_with_actions(json!([{
                "type": "execute_query",
                "query": "CREATE TABLE notes (id INT AUTO_INCREMENT PRIMARY KEY, body TEXT NOT NULL)"
            }]))
            .expect_calls(1)
            .and()
            // Most specific first: the last INSERT's own result also names `notes`.
            .on_event("mysql_result_received")
            .and_event_data_contains("query", "the model saw")
            .and_event_data_contains("affected_rows", "1")
            .respond_with_actions(json!([]))
            .expect_calls(1)
            .and()
            .on_event("mysql_result_received")
            .and_event_data_contains("query", "CREATE TABLE notes")
            .and_event_data_contains("affected_rows", "0")
            .respond_with_actions(json!([{
                "type": "execute_query",
                "query": "INSERT INTO notes (body) VALUES ('hello from the model')"
            }]))
            .expect_calls(1)
            .and()
            .on_event("mysql_result_received")
            .and_event_data_contains("query", "INSERT INTO notes")
            .and_event_data_contains("affected_rows", "1")
            .and_event_data_contains("last_insert_id", "1")
            .respond_with_actions(json!([{
                "type": "execute_query",
                "query": "SELECT id, body FROM notes ORDER BY id"
            }]))
            .expect_calls(1)
            .and()
            .on_event("mysql_result_received")
            .and_event_data_contains("query", "SELECT id, body FROM notes")
            .and_event_data_contains("row_count", "1")
            .and_event_data_contains("result", "hello from the model")
            .respond_with_actions_from_event(|event| {
                let row = &event["result"][0];
                // The text protocol carries every value as a string; the id is "1".
                let id = row["id"]
                    .as_str()
                    .map(str::to_string)
                    .unwrap_or_else(|| row["id"].to_string());
                json!([{
                    "type": "execute_query",
                    "query": format!(
                        "INSERT INTO notes (body) VALUES ('the model saw: {} (id {})')",
                        row["body"].as_str().unwrap_or(""),
                        id
                    )
                }])
            })
            .expect_calls(1)
            .and()
    });

    let client = start_netget_client(config).await?;
    // The last expectation is the final INSERT's result, so once every rule is satisfied the
    // server has already committed everything the model sent (autocommit is on).
    client.wait_for_mocks(30).await;
    client.verify_mocks().await?;

    assert_eq!(
        mysql_cli(server, "SELECT body FROM netget_e2e.notes ORDER BY id").await?,
        "hello from the model\nthe model saw: hello from the model (id 1)",
        "mysqld must hold the row the model inserted and the one it built from the SELECT"
    );
    assert_eq!(
        mysql_cli(
            server,
            "SELECT DATA_TYPE FROM information_schema.COLUMNS \
             WHERE TABLE_SCHEMA = 'netget_e2e' AND TABLE_NAME = 'notes' AND COLUMN_NAME = 'body'"
        )
        .await?,
        "text",
        "the table must be the one the model's CREATE TABLE defined"
    );

    client.stop().await?;
    Ok(())
}

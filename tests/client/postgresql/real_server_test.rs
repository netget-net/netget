//! The PostgreSQL client against a real **`postgres`** — the evidence its maturity rating rests
//! on.
//!
//! NetGet's PostgreSQL client is `tokio-postgres`, a Rust implementation of the frontend
//! protocol. The server here is the PostgreSQL server itself (C), initialised per test with
//! `initdb` into the guard's temporary directory (`-A trust -U netget`) and started on a probed
//! loopback port. What the server holds afterwards is read back with `psql`, which is libpq —
//! a second, independent client. Nothing on the wire was written by this repository except
//! NetGet.
//!
//! Condition 4 of the client bar — the client acts on the model's answer, asserted on the wire
//! — is asserted from the server's side: `psql` reads back a table the model created, a row the
//! model inserted, and a second row the model built out of the `SELECT` result it was shown.
//! Each result event is matched on the query that produced it and, for the `SELECT`, on the
//! row's value, so a result the model never saw cannot satisfy the mock.
//!
//! **No test here skips.** A missing `initdb`, `postgres` or `psql` fails with the install
//! command.
//!
//! LLM calls: 6.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features postgresql --test client -- postgresql::real_server_test --test-threads=100

use crate::helpers::real_server::{run_tool, InstallHint, RealServer};
use crate::helpers::*;
use serde_json::json;
use std::process::Command;
use std::time::Duration;

const POSTGRES: InstallHint = InstallHint {
    brew: "postgresql@17",
    apt: "postgresql (its server binaries live in /usr/lib/postgresql/<major>/bin, which the \
          test searches)",
};
const PSQL: InstallHint = InstallHint {
    brew: "postgresql@17",
    apt: "postgresql-client",
};

/// A throwaway PostgreSQL cluster: `initdb` into the guard's temp dir with trust auth and a
/// `netget` superuser, then `postgres` on 127.0.0.1 only, with its unix socket in the same
/// dir and durability off. Stopped with `SIGINT` (fast shutdown) so the postmaster removes its
/// System V shared memory segment; see `RealServerBuilder::graceful_stop`.
async fn start_postgres() -> E2EResult<RealServer> {
    RealServer::builder("postgres", POSTGRES)
        .setup_command(
            "initdb",
            POSTGRES,
            [
                "-D",
                "{dir}/data",
                "-A",
                "trust",
                "-U",
                "netget",
                "-E",
                "UTF8",
                "--locale=C",
                "--no-sync",
            ],
        )
        .args([
            "-D",
            "{dir}/data",
            "-p",
            "{port}",
            "-k",
            "{dir}",
            "-c",
            "listen_addresses=127.0.0.1",
            "-c",
            "fsync=off",
        ])
        .ready_when_log_matches("database system is ready to accept connections")
        .graceful_stop(nix::sys::signal::Signal::SIGINT, Duration::from_secs(10))
        .start()
        .await
}

/// `psql -At -c <sql>` as `netget` against the test cluster, trailing newline trimmed.
async fn psql(server: &RealServer, sql: &str) -> E2EResult<String> {
    let mut cmd = Command::new("psql");
    cmd.args([
        "-h",
        "127.0.0.1",
        "-p",
        &server.port.to_string(),
        "-U",
        "netget",
        "-d",
        "postgres",
        "-X",
        "-A",
        "-t",
        "-v",
        "ON_ERROR_STOP=1",
        "-c",
        sql,
    ]);
    Ok(run_tool(cmd, "psql", PSQL)
        .await?
        .trim_end_matches('\n')
        .to_string())
}

/// CREATE, INSERT, SELECT, and an INSERT built from the SELECT's rows — each step decided by
/// the model after it saw the previous step's result.
///
/// 1. `postgresql_connected` → `CREATE TABLE netget_notes (id serial, body text)`.
/// 2. The CREATE's result (matched on its query) → `INSERT … 'hello from the model'`.
/// 3. The INSERT's result → `SELECT id, body FROM netget_notes`.
/// 4. The SELECT's result, matched on the query **and** on `rows` containing the body the
///    model inserted → `INSERT … 'the model saw: <body> (id <id>)'`, both values taken from
///    the row PostgreSQL returned.
/// 5. That INSERT's result → nothing.
///
/// Then `psql` must read exactly those two bodies back, in order.
///
/// LLM calls: 6 (startup, postgresql_connected, four postgresql_query_result).
#[tokio::test]
async fn postgresql_client_creates_inserts_and_selects_against_postgres() -> E2EResult<()> {
    let server = start_postgres().await?;
    let result = creates_inserts_and_selects(&server).await;
    server.with_log(result)
}

async fn creates_inserts_and_selects(server: &RealServer) -> E2EResult<()> {
    let addr = server.addr();
    let config = NetGetConfig::new(format!(
        "Connect to PostgreSQL at {addr}. POSTGRES-REAL-SERVER-STARTUP-TURN."
    ))
    .with_mock(move |mock| {
        mock.on_instruction_containing("POSTGRES-REAL-SERVER-STARTUP-TURN")
            .respond_with_actions(json!([{
                "type": "open_client",
                "protocol": "PostgreSQL",
                "remote_addr": addr,
                "startup_params": {"user": "netget", "database": "postgres"},
                "instruction": "Create a notes table, store a note, read it back, and record \
                                what you read."
            }]))
            .expect_calls(1)
            .and()
            .on_event("postgresql_connected")
            .and_event_data_contains("user", "netget")
            .respond_with_actions(json!([{
                "type": "execute_query",
                "query": "CREATE TABLE netget_notes (id serial PRIMARY KEY, body text NOT NULL)"
            }]))
            .expect_calls(1)
            .and()
            // Most specific first: the last INSERT's own result also names netget_notes.
            .on_event("postgresql_query_result")
            .and_event_data_contains("query", "the model saw")
            .respond_with_actions(json!([]))
            .expect_calls(1)
            .and()
            .on_event("postgresql_query_result")
            .and_event_data_contains("query", "CREATE TABLE netget_notes")
            .and_event_data_contains("row_count", "0")
            .respond_with_actions(json!([{
                "type": "execute_query",
                "query": "INSERT INTO netget_notes (body) VALUES ('hello from the model')"
            }]))
            .expect_calls(1)
            .and()
            .on_event("postgresql_query_result")
            .and_event_data_contains("query", "INSERT INTO netget_notes")
            .respond_with_actions(json!([{
                "type": "execute_query",
                "query": "SELECT id, body FROM netget_notes ORDER BY id"
            }]))
            .expect_calls(1)
            .and()
            .on_event("postgresql_query_result")
            .and_event_data_contains("query", "SELECT id, body FROM netget_notes")
            .and_event_data_contains("row_count", "1")
            .and_event_data_contains("rows", "hello from the model")
            .respond_with_actions_from_event(|event| {
                let row = &event["rows"][0];
                json!([{
                    "type": "execute_query",
                    "query": format!(
                        "INSERT INTO netget_notes (body) VALUES ('the model saw: {} (id {})')",
                        row["body"].as_str().unwrap_or(""),
                        row["id"]
                    )
                }])
            })
            .expect_calls(1)
            .and()
    });

    let client = start_netget_client(config).await?;
    // The last expectation is the final INSERT's result, so once every rule is satisfied the
    // server has already committed everything the model sent (each query autocommits).
    client.wait_for_mocks(30).await;
    client.verify_mocks().await?;

    assert_eq!(
        psql(server, "SELECT body FROM netget_notes ORDER BY id").await?,
        "hello from the model\nthe model saw: hello from the model (id 1)",
        "postgres must hold the row the model inserted and the one it built from the SELECT"
    );
    assert_eq!(
        psql(
            server,
            "SELECT data_type FROM information_schema.columns \
             WHERE table_name = 'netget_notes' AND column_name = 'body'"
        )
        .await?,
        "text",
        "the table must be the one the model's CREATE TABLE defined"
    );

    client.stop().await?;
    Ok(())
}

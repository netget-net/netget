//! NetGet's Snowflake server against **snowflake-connector-python 4.8.0**, Snowflake's official
//! Python driver — an independent implementation of the client side of the connector protocol
//! that shares no code with NetGet. Until this test the server had only ever faced `reqwest`.
//!
//! What it shows, from the driver's side:
//! - the model's login decision: `analyst` gets a session, `intruder` is refused and the driver
//!   raises the model's own error number (390100);
//! - the driver gzips every request body (`Content-Encoding: gzip`), and the server reads it;
//! - the model's rowset reaches the driver and its own JSON-result converters type it:
//!   FIXED with a scale as a `Decimal`, BOOLEAN, DATE from a day count, TIMESTAMP_NTZ from
//!   `seconds.fraction`, NULL;
//! - the model's query error reaches the driver as a `ProgrammingError` with its errno and
//!   SQLSTATE;
//! - the driver's logout (`POST /session?delete=true`) is answered.
//!
//! **Fails rather than skips** without `NETGET_SNOWFLAKE_PEERS` (from
//! `tests/client/snowflake/install_peers.sh`). LLM calls: 8.


use super::super::super::helpers::real_server::{run_tool, InstallHint};
use super::super::super::helpers::{self, E2EResult, NetGetConfig};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::process::Command;

const PEERS: InstallHint = InstallHint {
    brew: "python@3.12 go, then `sh tests/client/snowflake/install_peers.sh <dir>` and export \
           the NETGET_SNOWFLAKE_PEERS it prints",
    apt:
        "python3-venv golang-go build-essential, then `sh tests/client/snowflake/install_peers.sh \
          <dir>` and export the NETGET_SNOWFLAKE_PEERS it prints",
};

fn python() -> E2EResult<PathBuf> {
    let root = std::env::var_os("NETGET_SNOWFLAKE_PEERS")
        .map(PathBuf::from)
        .ok_or(
            "NETGET_SNOWFLAKE_PEERS is not set. This test drives NetGet's Snowflake server with \
             snowflake-connector-python and FAILS rather than skipping without it: run \
             `sh tests/client/snowflake/install_peers.sh /some/dir` and export the \
             NETGET_SNOWFLAKE_PEERS it prints.",
        )?;
    let python = root.join("venv/bin/python");
    if !python.is_file() {
        return Err(format!(
            "{} is missing; re-run tests/client/snowflake/install_peers.sh",
            python.display()
        )
        .into());
    }
    Ok(python)
}

async fn driver(port: u16, user: &str, sql: &str) -> E2EResult<Value> {
    let mut cmd = Command::new(python()?);
    cmd.arg("-I")
        .arg(format!(
            "{}/tests/server/snowflake/connector_peer.py",
            env!("CARGO_MANIFEST_DIR")
        ))
        .args(["127.0.0.1", &port.to_string(), user, "secret", sql]);
    let out = run_tool(cmd, "python (NETGET_SNOWFLAKE_PEERS venv)", PEERS).await?;
    let last = out.trim().lines().last().unwrap_or("null").to_string();
    Ok(serde_json::from_str(&last).map_err(|e| format!("{e}: driver printed {out}"))?)
}

#[tokio::test]
async fn the_official_python_driver_logs_in_queries_and_logs_out() -> E2EResult<()> {
    let config = NetGetConfig::new(
        "Start a Snowflake server on port {AVAILABLE_PORT}. SF-DRIVER-STARTUP-TURN.",
    )
    .with_mock(|mock| {
        mock.on_instruction_containing("SF-DRIVER-STARTUP-TURN")
            .respond_with_actions(json!([{
                "type": "open_server", "port": 0, "base_stack": "snowflake",
                "instruction": "Log in analyst only; answer the notes query; refuse the rest."
            }]))
            .expect_calls(1)
            .and()
            .on_event("snowflake_login")
            .and_event_data_contains("login_name", "intruder")
            .respond_with_actions(json!([{"type": "snowflake_error", "code": "390100",
                "message": "Incorrect username or password was specified."}]))
            .expect_calls(1)
            .and()
            .on_event("snowflake_login")
            .and_event_data_contains("login_name", "analyst")
            .and_event_data_contains("has_password", "true")
            .respond_with_actions(json!([{"type": "snowflake_login_success",
                "token": "tok-1", "master_token": "mtok-1", "session_id": 77}]))
            .expect_calls(2)
            .and()
            .on_event("snowflake_query")
            .and_event_data_contains("sql_text", "FROM notes")
            .and_event_data_contains("has_auth_token", "true")
            .respond_with_actions(json!([{
                "type": "snowflake_query_response", "query_id": "q-notes",
                "rowtype": [
                    {"name": "ID", "type": "fixed", "precision": 38, "scale": 0},
                    {"name": "AMOUNT", "type": "fixed", "precision": 9, "scale": 2},
                    {"name": "BODY", "type": "text"},
                    {"name": "OK", "type": "boolean"},
                    {"name": "DV", "type": "date"},
                    {"name": "TS", "type": "timestamp_ntz", "scale": 9}
                ],
                "rowset": [
                    ["1", "123.45", "hello", "1", "20740", "1791981296.123456000"],
                    ["2", null, null, null, null, null]
                ]
            }]))
            .expect_calls(1)
            .and()
            .on_event("snowflake_query")
            .and_event_data_contains("sql_text", "nope")
            .respond_with_actions(json!([{"type": "snowflake_error", "code": "002003",
                "sql_state": "42S02",
                "message": "SQL compilation error: Object 'NOPE' does not exist or not authorized."}]))
            .expect_calls(1)
            .and()
            .on_event("snowflake_session")
            .and_event_data_contains("operation", "logout")
            .respond_with_actions(json!([{"type": "snowflake_session_response"}]))
            .expect_calls(2)
            .and()
    });
    let server = helpers::start_netget_server(config).await?;
    let port = server.port;

    let out = driver(port, "analyst", "SELECT * FROM notes ORDER BY id").await?;
    assert_eq!(
        out["rows"],
        json!([
            [
                1,
                "123.45",
                "hello",
                true,
                "2026-10-14",
                "2026-10-14 12:34:56.123456"
            ],
            [2, null, null, null, null, null]
        ]),
        "the driver's own converters must type the model's rowset: {out:#}"
    );
    assert_eq!(out["sfqid"], "q-notes");
    assert_eq!(out["description"][1], json!(["AMOUNT", "FIXED", 2]));

    let out = driver(port, "analyst", "SELECT * FROM nope").await?;
    assert_eq!(out["error"], "ProgrammingError", "{out:#}");
    assert_eq!(out["errno"], 2003);
    assert_eq!(out["sqlstate"], "42S02");
    assert!(out["msg"].as_str().unwrap().contains("NOPE"));

    let out = driver(port, "intruder", "SELECT 1").await?;
    assert_eq!(out["errno"], 390100, "{out:#}");
    assert!(out.get("rows").is_none());

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    assert!(
        server
            .output_contains("op=logout decision=model_answer")
            .await,
        "the driver's POST /session?delete=true must reach the model as a logout"
    );
    server.stop().await?;
    Ok(())
}

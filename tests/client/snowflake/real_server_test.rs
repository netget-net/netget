//! The Snowflake client with the model in the loop, against two **independent** servers of
//! Snowflake's connector protocol — never NetGet's own Snowflake server:
//!
//! * **fakesnow 0.11.22** — Python (Starlette), SQL run on DuckDB, every SELECT answered as an
//!   Arrow stream (`rowsetBase64`), DML as a JSON rowset.
//! * **snowflake-emulator v0.0.9** (nnnkkk7) — Go (chi), SQL run on DuckDB, every result as a
//!   JSON rowset.
//!
//! Condition 4 of the client bar — the client acts on the model's answer, asserted on the wire —
//! is asserted from the server's side: a **second session** reads back what the model wrote,
//! including a row the model built from the typed values this client decoded. For fakesnow that
//! session is Snowflake's own Python driver (`snowflake-connector-python`); for the emulator,
//! which cannot read the gzip bodies that driver sends, it is the REST protocol by hand. Each
//! server's own access log shows the logout.
//!
//! **No test here skips.** Without `NETGET_SNOWFLAKE_PEERS` (from `install_peers.sh`) every test
//! fails and says how to install the servers.
//!
//! LLM calls: 7 (fakesnow chain), 7 (emulator chain), 8 (follow-up bound), 2 (LLM failure).
//!
//!   sh tests/client/snowflake/install_peers.sh /tmp/sf && export NETGET_SNOWFLAKE_PEERS=/tmp/sf
//!   ./cargo-isolated.sh test --no-default-features --features tcp,snowflake --test client -- snowflake:: --test-threads=4

use crate::helpers::real_server::{run_tool, InstallHint, RealServer};
use crate::helpers::*;
use serde_json::{json, Value};
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

const PEERS: InstallHint = InstallHint {
    brew: "python@3.12 go, then `sh tests/client/snowflake/install_peers.sh <dir>` and export \
           the NETGET_SNOWFLAKE_PEERS it prints",
    apt:
        "python3-venv golang-go build-essential, then `sh tests/client/snowflake/install_peers.sh \
          <dir>` and export the NETGET_SNOWFLAKE_PEERS it prints",
};

/// The directory `install_peers.sh` filled.
pub fn peers_root() -> E2EResult<PathBuf> {
    let root = std::env::var_os("NETGET_SNOWFLAKE_PEERS")
        .map(PathBuf::from)
        .ok_or(
            "NETGET_SNOWFLAKE_PEERS is not set. The Snowflake client's evidence is fakesnow and \
             snowflake-emulator, two independent servers of Snowflake's connector protocol, and \
             this test FAILS rather than skipping without them: run \
             `sh tests/client/snowflake/install_peers.sh /some/dir` (needs python3 with venv and \
             Go with a C toolchain) and export the NETGET_SNOWFLAKE_PEERS it prints.",
        )?;
    for needed in [
        "venv/bin/fakesnow",
        "venv/bin/python",
        "bin/snowflake-emulator",
    ] {
        if !root.join(needed).is_file() {
            return Err(format!(
                "{} is missing; re-run tests/client/snowflake/install_peers.sh {}",
                root.join(needed).display(),
                root.display()
            )
            .into());
        }
    }
    Ok(root)
}

/// fakesnow's HTTP server on a loopback port, its in-memory databases shared by every session.
pub async fn start_fakesnow() -> E2EResult<RealServer> {
    let bin = peers_root()?.join("venv/bin/fakesnow");
    RealServer::builder(&bin.to_string_lossy(), PEERS)
        .args(["-s", "--host", "127.0.0.1", "-p", "{port}"])
        .ready_when_log_matches(r"Uvicorn running on")
        .startup_timeout(Duration::from_secs(60))
        .start()
        .await
}

/// snowflake-emulator on a loopback port, DuckDB in memory, stages in the guard's directory.
pub async fn start_emulator() -> E2EResult<RealServer> {
    let bin = peers_root()?.join("bin/snowflake-emulator");
    RealServer::builder(&bin.to_string_lossy(), PEERS)
        .env("PORT", "{port}")
        .env("STAGE_DIR", "{dir}/stages")
        .ready_when_log_matches(r"Starting Snowflake Emulator on port")
        .startup_timeout(Duration::from_secs(60))
        .start()
        .await
}

/// Read rows back over a session of the peer's own: `connector` is snowflake-connector-python,
/// `rest` the REST protocol by hand.
pub async fn readback(
    mode: &str,
    server: &RealServer,
    database: &str,
    sql: &str,
) -> E2EResult<Value> {
    let root = peers_root()?;
    let (host, port) = server
        .addr()
        .rsplit_once(':')
        .map(|(h, p)| (h.to_string(), p.to_string()))
        .unwrap();
    let mut cmd = Command::new(root.join("venv/bin/python"));
    cmd.arg("-I")
        .arg(format!(
            "{}/tests/client/snowflake/readback.py",
            env!("CARGO_MANIFEST_DIR")
        ))
        .args([mode, &host, &port, database, "PUBLIC", sql]);
    let out = run_tool(cmd, "python (NETGET_SNOWFLAKE_PEERS venv)", PEERS).await?;
    Ok(serde_json::from_str(
        out.trim().lines().last().unwrap_or("null"),
    )?)
}

/// The model's view of a decoded row, flattened into one string it writes back, so a value
/// decoded wrongly (a BIGINT as a string, a lost scale, a timestamp off by a zone, a NULL
/// counted as a value) changes what the second session reads back.
fn summarise(rows: &Value, keys: &[&str]) -> String {
    let r = &rows[0];
    let nulls = rows[1]
        .as_object()
        .map(|o| o.values().filter(|v| v.is_null()).count())
        .unwrap_or(0);
    let parts: Vec<String> = keys
        .iter()
        .map(|k| match &r[*k] {
            Value::String(s) => s.clone(),
            other => other.to_string(),
        })
        .collect();
    format!("the model saw: {}|nulls {nulls}", parts.join("|"))
}

const FAKESNOW_KEYS: &[&str] = &[
    "BODY", "AMOUNT", "OK", "DV", "TV", "TS", "RATIO", "V", "BIG",
];

/// Create a ten-column table, insert, read the rows back typed (Arrow), insert a row the model
/// built from the decoded values, read a server error, log out.
#[tokio::test]
async fn snowflake_client_runs_the_models_sql_against_fakesnow() -> E2EResult<()> {
    let server = start_fakesnow().await?;
    let result = fakesnow_chain(&server).await;
    server.with_log(result)
}

async fn fakesnow_chain(server: &RealServer) -> E2EResult<()> {
    let addr = server.addr();
    let config = NetGetConfig::new(format!(
        "Connect to the Snowflake endpoint at {addr}. SF-FAKESNOW-STARTUP-TURN."
    ))
    .with_mock(move |mock| {
        mock.on_instruction_containing("SF-FAKESNOW-STARTUP-TURN")
            .respond_with_actions(json!([{
                "type": "open_client",
                "protocol": "Snowflake",
                "remote_addr": addr,
                "startup_params": {
                    "username": "analyst", "password": "secret",
                    "account": "netget-evidence", "database": "EVIDENCE", "schema": "PUBLIC"
                },
                "instruction": "Keep notes in a table, read them back, and record what you read."
            }]))
            .expect_calls(1)
            .and()
            .on_event("snowflake_connected")
            .and_event_data_contains("database", "EVIDENCE")
            .respond_with_actions(json!([
                {"type": "run_sql", "sql":
                    "CREATE TABLE notes (id INT, amount NUMBER(9,2), body VARCHAR, ok BOOLEAN, \
                     dv DATE, tv TIME, ts TIMESTAMP_NTZ, ratio FLOAT, v VARIANT, big NUMBER(38,0))"},
                {"type": "run_sql", "sql":
                    "INSERT INTO notes SELECT 1, 123.45, 'hello from the model', TRUE, \
                     '2026-10-14'::DATE, '12:34:56'::TIME, \
                     '2026-10-14 12:34:56.123456'::TIMESTAMP_NTZ, 1.5, \
                     PARSE_JSON('{\"k\":[1,2]}'), 3000000000 \
                     UNION ALL SELECT 2, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL"}
            ]))
            .expect_calls(1)
            .and()
            .on_event("snowflake_query_result")
            .and_event_data_contains("sql", "the model saw")
            .and_event_data_contains("rows_affected", "1")
            .respond_with_actions(json!([{"type": "run_sql", "sql": "SELECT nosuch FROM notes"}]))
            .expect_calls(1)
            .and()
            .on_event("snowflake_query_result")
            .and_event_data_contains("sql", "CREATE TABLE notes")
            .respond_with_actions(json!([]))
            .expect_calls(1)
            .and()
            .on_event("snowflake_query_result")
            .and_event_data_contains("sql", "INSERT INTO notes SELECT")
            .and_event_data_contains("rows_affected", "2")
            .respond_with_actions(json!([{"type": "run_sql", "sql": "SELECT * FROM notes ORDER BY id"}]))
            .expect_calls(1)
            .and()
            .on_event("snowflake_query_result")
            .and_event_data_contains("sql", "SELECT * FROM notes")
            .and_event_data_contains("result_format", "arrow")
            .and_event_data_contains("rows", "hello from the model")
            .respond_with_actions_from_event(|e| {
                json!([{"type": "run_sql", "sql": format!(
                    "INSERT INTO notes (id, body) VALUES (3, '{}')",
                    summarise(&e["rows"], FAKESNOW_KEYS))}])
            })
            .expect_calls(1)
            .and()
            .on_event("snowflake_error")
            .and_event_data_contains("sql", "nosuch")
            .and_event_data_contains("code", "002043")
            .respond_with_actions(json!([{"type": "logout"}]))
            .expect_calls(1)
            .and()
    });

    let client = start_netget_client(config).await?;
    client.wait_for_mocks(90).await;
    client.verify_mocks().await?;

    let rows = readback(
        "connector",
        server,
        "EVIDENCE",
        "SELECT id, body FROM notes ORDER BY id",
    )
    .await?;
    assert_eq!(
        rows,
        json!([
            [1, "hello from the model"],
            [2, null],
            [
                3,
                "the model saw: hello from the model|123.45|true|2026-10-14|12:34:56.000000000|\
                 2026-10-14T12:34:56.123456000|1.5|{\"k\":[1,2]}|3000000000|nulls 9"
            ]
        ]),
        "snowflake-connector-python must read back exactly what the model wrote"
    );
    server
        .wait_for_log("POST /session?delete=true", Duration::from_secs(30))
        .await?;
    client.stop().await?;
    Ok(())
}

const EMULATOR_KEYS: &[&str] = &["body", "amount", "ok", "ratio", "big"];

/// The same chain against snowflake-emulator, whose results are JSON rowsets.
#[tokio::test]
async fn snowflake_client_runs_the_models_sql_against_snowflake_emulator() -> E2EResult<()> {
    let server = start_emulator().await?;
    let result = emulator_chain(&server).await;
    server.with_log(result)
}

async fn emulator_chain(server: &RealServer) -> E2EResult<()> {
    let addr = server.addr();
    let config = NetGetConfig::new(format!(
        "Connect to the Snowflake endpoint at {addr}. SF-EMULATOR-STARTUP-TURN."
    ))
    .with_mock(move |mock| {
        mock.on_instruction_containing("SF-EMULATOR-STARTUP-TURN")
            .respond_with_actions(json!([{
                "type": "open_client",
                "protocol": "Snowflake",
                "remote_addr": addr,
                "startup_params": {"username": "analyst", "password": "secret", "database": "EVIDENCE"},
                "instruction": "Keep notes in a table and read them back."
            }]))
            .expect_calls(1)
            .and()
            .on_event("snowflake_connected")
            .respond_with_actions(json!([
                {"type": "run_sql", "sql":
                    "CREATE TABLE notes (id INTEGER, amount DECIMAL(9,2), body VARCHAR, \
                     ok BOOLEAN, ratio DOUBLE, big BIGINT)"},
                {"type": "run_sql", "sql":
                    "INSERT INTO notes VALUES (1, 123.45, 'hello from the model', TRUE, 1.5, \
                     3000000000), (2, NULL, NULL, NULL, NULL, NULL)"}
            ]))
            .expect_calls(1)
            .and()
            .on_event("snowflake_query_result")
            .and_event_data_contains("sql", "the model saw")
            .respond_with_actions(json!([{"type": "run_sql", "sql": "SELECT nosuch FROM notes"}]))
            .expect_calls(1)
            .and()
            .on_event("snowflake_query_result")
            .and_event_data_contains("sql", "CREATE TABLE notes")
            .respond_with_actions(json!([]))
            .expect_calls(1)
            .and()
            .on_event("snowflake_query_result")
            .and_event_data_contains("sql", "INSERT INTO notes VALUES")
            .and_event_data_contains("total", "2")
            .respond_with_actions(json!([{"type": "run_sql", "sql": "SELECT * FROM notes ORDER BY id"}]))
            .expect_calls(1)
            .and()
            .on_event("snowflake_query_result")
            .and_event_data_contains("sql", "SELECT * FROM notes")
            .and_event_data_contains("result_format", "json")
            .and_event_data_contains("rows", "hello from the model")
            .respond_with_actions_from_event(|e| {
                json!([{"type": "run_sql", "sql": format!(
                    "INSERT INTO notes (id, body) VALUES (3, '{}')",
                    summarise(&e["rows"], EMULATOR_KEYS))}])
            })
            .expect_calls(1)
            .and()
            .on_event("snowflake_error")
            .and_event_data_contains("sql", "nosuch")
            .and_event_data_contains("message", "nosuch")
            .respond_with_actions(json!([{"type": "logout"}]))
            .expect_calls(1)
            .and()
    });

    let client = start_netget_client(config).await?;
    client.wait_for_mocks(90).await;
    client.verify_mocks().await?;

    let rows = readback(
        "rest",
        server,
        "EVIDENCE",
        "SELECT id, body FROM notes ORDER BY id",
    )
    .await?;
    // The emulator writes a NULL as "" in a JSON rowset, so row 2 holds no JSON null by the
    // time it reaches the model: "nulls 0". This client does not guess that "" meant NULL; it
    // hands the number, boolean and float cells on as the server's text with decode warnings.
    assert_eq!(
        rows,
        json!([
            ["1", "hello from the model"],
            ["2", ""],
            [
                "3",
                "the model saw: hello from the model|123.45|true|1.5|3000000000|nulls 0"
            ]
        ]),
        "a second session must read back exactly what the model wrote"
    );
    server
        .wait_for_log("/session?delete=true", Duration::from_secs(30))
        .await?;
    client.stop().await?;
    Ok(())
}

/// A model that answers every result with another statement stops at MAX_FOLLOWUP_DEPTH: the
/// connected turn and seven follow-ups, so one CREATE and seven INSERTs reach fakesnow.
#[tokio::test]
async fn followup_chain_stops_at_the_bound() -> E2EResult<()> {
    let server = start_fakesnow().await?;
    let result = followup_bound(&server).await;
    server.with_log(result)
}

async fn followup_bound(server: &RealServer) -> E2EResult<()> {
    let addr = server.addr();
    let depth = ::netget::client::snowflake::MAX_FOLLOWUP_DEPTH as usize;
    let config = NetGetConfig::new(format!(
        "Connect to the Snowflake endpoint at {addr}. SF-LOOP-STARTUP-TURN."
    ))
    .with_mock(move |mock| {
        mock.on_instruction_containing("SF-LOOP-STARTUP-TURN")
            .respond_with_actions(json!([{
                "type": "open_client",
                "protocol": "Snowflake",
                "remote_addr": addr,
                "startup_params": {"username": "analyst", "password": "x", "database": "LOOPDB", "schema": "PUBLIC"},
                "instruction": "Count forever."
            }]))
            .expect_calls(1)
            .and()
            .on_event("snowflake_connected")
            .respond_with_actions(json!([{"type": "run_sql", "sql": "CREATE TABLE hits (n INT)"}]))
            .expect_calls(1)
            .and()
            .on_event("snowflake_query_result")
            .respond_with_actions(json!([{"type": "run_sql", "sql": "INSERT INTO hits VALUES (1)"}]))
            .expect_calls(depth - 1)
            .and()
    });
    let client = start_netget_client(config).await?;
    client.wait_for_any(&["decision=followup_depth"], 60).await;
    assert!(
        client.output_contains("decision=followup_depth").await,
        "the chain must stop at the bound and say so"
    );
    client.wait_for_mocks(30).await;
    client.verify_mocks().await?;
    let rows = readback("connector", server, "LOOPDB", "SELECT COUNT(*) FROM hits").await?;
    assert_eq!(
        rows,
        json!([[depth - 1]]),
        "fakesnow must hold exactly {} inserted rows",
        depth - 1
    );
    client.stop().await?;
    Ok(())
}

/// When the model cannot be asked, nothing is sent on its behalf: the client logs in and
/// fakesnow receives no query from it.
#[tokio::test]
async fn llm_failure_sends_nothing() -> E2EResult<()> {
    let server = start_fakesnow().await?;
    let result = llm_failure(&server).await;
    server.with_log(result)
}

async fn llm_failure(server: &RealServer) -> E2EResult<()> {
    let addr = server.addr();
    let config = NetGetConfig::new(format!(
        "Connect to the Snowflake endpoint at {addr}. SF-FAIL-STARTUP-TURN."
    ))
    .with_mock(move |mock| {
        mock.on_instruction_containing("SF-FAIL-STARTUP-TURN")
            .respond_with_actions(json!([{
                "type": "open_client",
                "protocol": "Snowflake",
                "remote_addr": addr,
                "startup_params": {"username": "analyst", "password": "x"},
                "instruction": "Drop every table."
            }]))
            .expect_calls(1)
            .and()
        // No rule answers snowflake_connected: the mock model fails that call.
    });
    let client = start_netget_client(config).await?;
    client
        .wait_for_any(&["decision=fail_closed_llm_error"], 90)
        .await;
    assert!(
        client
            .output_contains("decision=fail_closed_llm_error")
            .await,
        "the failed turn must be logged as failing closed"
    );
    let log = server.log();
    assert!(
        log.contains("/session/v1/login-request"),
        "NetGet must have logged in:\n{log}"
    );
    assert!(
        !log.contains("/queries/v1/query-request"),
        "fakesnow received a query NetGet sent without the model:\n{log}"
    );
    client.stop().await?;
    Ok(())
}

/// A refused login fails client creation; the model is never asked about the session. fakesnow
/// admits anyone, so the refusal comes from the emulator, which requires a login name and a
/// password.
#[tokio::test]
async fn a_refused_login_fails_the_client() -> E2EResult<()> {
    let server = start_emulator().await?;
    let result = refused_login(&server).await;
    server.with_log(result)
}

async fn refused_login(server: &RealServer) -> E2EResult<()> {
    let addr = server.addr();
    let config = NetGetConfig::new(format!(
        "Connect to the Snowflake endpoint at {addr}. SF-REFUSED-STARTUP-TURN."
    ))
    .with_mock(move |mock| {
        mock.on_instruction_containing("SF-REFUSED-STARTUP-TURN")
            .respond_with_actions(json!([{
                "type": "open_client",
                "protocol": "Snowflake",
                "remote_addr": addr,
                "startup_params": {"username": "analyst", "password": ""},
                "instruction": "Read everything."
            }]))
            .expect_calls(1)
            .and()
            .on_event("snowflake_connected")
            .respond_with_actions(json!([]))
            .expect_calls(0)
            .and()
    });
    let client = start_netget_client(config).await?;
    client
        .wait_for_any(&["decision=fail_closed_login"], 60)
        .await;
    assert!(
        client.output_contains("decision=fail_closed_login").await,
        "the refused login must fail the client"
    );
    client.verify_mocks().await?;
    client.stop().await?;
    Ok(())
}

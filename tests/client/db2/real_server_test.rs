//! The Db2 client with the model in the loop, against **Apache Derby 10.17.1.0's network
//! server** — a Java DRDA server that shares no code with NetGet — the evidence its maturity
//! rating rests on.
//!
//! Condition 4 of the client bar — the client acts on the model's answer, asserted on the wire
//! — is asserted from Derby's side: Derby's own `ij` client (over Derby's DRDA client driver)
//! reads back the rows the model inserted, including one the model built out of the typed
//! values the client decoded from a SELECT, and not the row the model rolled back. Derby's
//! statement log shows what ran. A recording proxy between NetGet and Derby hands both
//! directions to tshark's DRDA dissector.
//!
//! **No test here skips.** A missing `java`, missing Derby jars or a missing tshark fails.
//!
//! LLM calls: 11 (main chain), 8 (follow-up bound), 2 (LLM failure).
//!
//!   python3 tests/client/db2/install_derby.py /tmp/derby && export NETGET_DERBY_LIB=/tmp/derby
//!   ./cargo-isolated.sh test --no-default-features --features tcp,db2 --test client -- db2:: --test-threads=4

use super::derby::{derby_log, ij, start_derby, RecordingProxy};
use crate::helpers::pcap_oracle::PcapOracle;
use crate::helpers::real_server::RealServer;
use crate::helpers::*;
use serde_json::{json, Value};

const PASSWORD: &str = "secret";

/// The model's view of a row, flattened into one string it writes back to the database, so a
/// value decoded wrongly (a BIGINT as a string, a DECIMAL rounded, a NULL as a value) changes
/// what `ij` reads back.
fn summarise(rows: &Value) -> String {
    let r = &rows[0];
    let nulls = rows[1]
        .as_object()
        .map(|o| o.values().filter(|v| v.is_null()).count())
        .unwrap_or(0);
    format!(
        "the model saw: {}|{}|{}|{}|{}|{}|{}|{}|{}|nulls {}",
        r["BODY"].as_str().unwrap_or("?"),
        r["SMALLV"],
        r["BIGV"],
        r["CODE"].as_str().unwrap_or("?"),
        r["AMOUNT"].as_str().unwrap_or("?"),
        r["DV"].as_str().unwrap_or("?"),
        r["TV"].as_str().unwrap_or("?"),
        r["TSV"].as_str().unwrap_or("?"),
        r["RATIO"],
        nulls
    )
}

/// Create, insert, commit, select typed rows, insert a row built from them, commit, insert and
/// roll back, then a bad statement whose error SQLCA the model reads.
#[tokio::test]
async fn db2_client_runs_the_models_sql_against_derby() -> E2EResult<()> {
    let server = start_derby(Some(PASSWORD)).await?;
    let result = models_sql(&server).await;
    server.with_log(result)
}

async fn models_sql(server: &RealServer) -> E2EResult<()> {
    let proxy = RecordingProxy::start(server.addr()).await?;
    let addr = proxy.addr.clone();
    let config = NetGetConfig::new(format!(
        "Connect to the Db2 database at {addr}. DB2-REAL-SERVER-STARTUP-TURN."
    ))
    .with_mock(move |mock| {
        mock.on_instruction_containing("DB2-REAL-SERVER-STARTUP-TURN")
            .respond_with_actions(json!([{
                "type": "open_client",
                "protocol": "Db2",
                "remote_addr": addr,
                "startup_params": {
                    "database": "netget_model_evidence;create=true",
                    "username": "app",
                    "password": PASSWORD
                },
                "instruction": "Keep notes in a table, read them back, and record what you read."
            }]))
            .expect_calls(1)
            .and()
            .on_event("db2_connected")
            .and_event_data_contains("server_class", "Derby")
            .respond_with_actions(json!([
                {"type": "execute_statement", "sql":
                    "CREATE TABLE notes (id INT NOT NULL, smallv SMALLINT, bigv BIGINT, \
                     body VARCHAR(200), code CHAR(4), amount DECIMAL(9,2), dv DATE, tv TIME, \
                     tsv TIMESTAMP, ratio DOUBLE)"},
                {"type": "execute_statement", "sql":
                    "INSERT INTO notes VALUES (1, 7, 3000000000, 'hello from the model', 'ab', \
                     123.45, '2026-10-14', '12:34:56', '2026-10-14 12:34:56.123456', 1.5), \
                     (2, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)"}
            ]))
            .expect_calls(1)
            .and()
            .on_event("db2_statement_result")
            .and_event_data_contains("sql", "CREATE TABLE notes")
            .respond_with_actions(json!([]))
            .expect_calls(1)
            .and()
            .on_event("db2_statement_result")
            .and_event_data_contains("sql", "the model saw")
            .and_event_data_contains("row_count", "1")
            .respond_with_actions(json!([]))
            .expect_calls(1)
            .and()
            .on_event("db2_statement_result")
            .and_event_data_contains("sql", "to be rolled back")
            .respond_with_actions(json!([]))
            .expect_calls(1)
            .and()
            .on_event("db2_statement_result")
            .and_event_data_contains("sql", "INSERT INTO notes")
            .and_event_data_contains("row_count", "2")
            .respond_with_actions(json!([{"type": "commit"}]))
            .expect_calls(1)
            .and()
            .on_event("db2_transaction_result")
            .and_event_data_contains("outcome", "rolled_back")
            .and_event_data_contains("statements", "to be rolled back")
            .respond_with_actions(
                json!([{"type": "execute_query", "sql": "SELECT nosuch FROM notes"}]),
            )
            .expect_calls(1)
            .and()
            .on_event("db2_transaction_result")
            .and_event_data_contains("outcome", "committed")
            .and_event_data_contains("statements", "the model saw")
            .respond_with_actions(json!([]))
            .expect_calls(1)
            .and()
            .on_event("db2_transaction_result")
            .and_event_data_contains("outcome", "committed")
            .and_event_data_contains("statements", "hello from the model")
            .respond_with_actions(
                json!([{"type": "execute_query", "sql": "SELECT * FROM notes ORDER BY id"}]),
            )
            .expect_calls(1)
            .and()
            .on_event("db2_query_result")
            .and_event_data_contains("row_count", "2")
            .and_event_data_contains("rows", "hello from the model")
            .respond_with_actions_from_event(|e| {
                json!([
                    {"type": "execute_statement", "sql": format!(
                        "INSERT INTO notes (id, body) VALUES (3, '{}')", summarise(&e["rows"]))},
                    {"type": "commit"},
                    {"type": "execute_statement", "sql":
                        "INSERT INTO notes (id, body) VALUES (4, 'to be rolled back')"},
                    {"type": "rollback"}
                ])
            })
            .expect_calls(1)
            .and()
            .on_event("db2_error")
            .and_event_data_contains("sqlstate", "42X04")
            .and_event_data_contains("message_tokens", "NOSUCH")
            .respond_with_actions(json!([]))
            .expect_calls(1)
            .and()
    });

    let client = start_netget_client(config).await?;
    client.wait_for_mocks(60).await;
    client.verify_mocks().await?;

    let out = ij(
        server,
        "netget_model_evidence",
        PASSWORD,
        "SELECT CAST(id AS CHAR(2)) || ':' || COALESCE(body, 'NULL') FROM notes ORDER BY id;",
    )
    .await?;
    for expected in [
        "1 :hello from the model",
        "2 :NULL",
        "3 :the model saw: hello from the model|7|3000000000|ab  |123.45|2026-10-14|12:34:56|2026-10-14-12.34.56.123456000|1.5|nulls 9",
        "3 rows selected",
    ] {
        assert!(out.contains(expected), "ij must read {expected:?}; it read:\n{out}");
    }
    assert!(
        !out.contains("to be rolled back"),
        "the rolled-back row survived:\n{out}"
    );

    let log = derby_log(server);
    for statement in [
        "CREATE TABLE notes",
        "SELECT * FROM notes ORDER BY id",
        "to be rolled back",
    ] {
        assert!(
            log.contains(statement),
            "Derby's statement log lacks {statement:?}:\n{log}"
        );
    }

    // tshark's DRDA dissector reads both directions of what NetGet and Derby said.
    let recording = proxy.recording.lock().unwrap().clone();
    assert!(recording.iter().any(|(up, _)| *up) && recording.iter().any(|(up, _)| !*up));
    let mut oracle = PcapOracle::tcp("db2");
    for (to_server, bytes) in &recording {
        oracle = if *to_server {
            oracle.to_server(bytes)
        } else {
            oracle.from_server(bytes)
        };
    }
    oracle.assert_clean();

    client.stop().await?;
    Ok(())
}

/// A model that answers every result with another statement stops at MAX_FOLLOWUP_DEPTH: the
/// connected turn and seven follow-ups, so one CREATE and seven INSERTs reach Derby.
#[tokio::test]
async fn followup_chain_stops_at_the_bound() -> E2EResult<()> {
    let server = start_derby(None).await?;
    let result = followup_bound(&server).await;
    server.with_log(result)
}

async fn followup_bound(server: &RealServer) -> E2EResult<()> {
    let addr = server.addr();
    let depth = ::netget::client::db2::MAX_FOLLOWUP_DEPTH as usize;
    let config = NetGetConfig::new(format!(
        "Connect to the Db2 database at {addr}. DB2-LOOP-STARTUP-TURN."
    ))
    .with_mock(move |mock| {
        mock.on_instruction_containing("DB2-LOOP-STARTUP-TURN")
            .respond_with_actions(json!([{
                "type": "open_client",
                "protocol": "Db2",
                "remote_addr": addr,
                "startup_params": {"database": "loopdb;create=true", "username": "app", "autocommit": true},
                "instruction": "Count forever."
            }]))
            .expect_calls(1)
            .and()
            .on_event("db2_connected")
            .respond_with_actions(json!([{"type": "execute_statement", "sql": "CREATE TABLE hits (n INT)"}]))
            .expect_calls(1)
            .and()
            .on_event("db2_statement_result")
            .respond_with_actions(json!([{"type": "execute_statement", "sql": "INSERT INTO hits VALUES (1)"}]))
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
    let out = ij(server, "loopdb", "x", "SELECT COUNT(*) FROM hits;").await?;
    let count = depth - 1;
    assert!(
        out.lines().any(|l| l.trim() == count.to_string()),
        "Derby must hold exactly {count} inserted rows:\n{out}"
    );
    client.stop().await?;
    Ok(())
}

/// When the model cannot be asked, nothing is sent on its behalf: the connection stays open
/// and Derby executes no statement from it.
#[tokio::test]
async fn llm_failure_sends_nothing() -> E2EResult<()> {
    let server = start_derby(None).await?;
    let result = llm_failure(&server).await;
    server.with_log(result)
}

async fn llm_failure(server: &RealServer) -> E2EResult<()> {
    let addr = server.addr();
    let config = NetGetConfig::new(format!(
        "Connect to the Db2 database at {addr}. DB2-FAIL-STARTUP-TURN."
    ))
    .with_mock(move |mock| {
        mock.on_instruction_containing("DB2-FAIL-STARTUP-TURN")
            .respond_with_actions(json!([{
                "type": "open_client",
                "protocol": "Db2",
                "remote_addr": addr,
                "startup_params": {"database": "faildb;create=true", "username": "app", "password": "x"},
                "instruction": "Drop every table."
            }]))
            .expect_calls(1)
            .and()
        // No rule answers db2_connected: the mock model fails that call.
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
    let log = derby_log(server);
    assert!(
        log.contains("Connection number"),
        "NetGet must have connected:\n{log}"
    );
    assert!(
        !log.contains("Begin compiling") && !log.contains("Executing"),
        "Derby executed something NetGet sent without the model:\n{log}"
    );
    client.stop().await?;
    Ok(())
}

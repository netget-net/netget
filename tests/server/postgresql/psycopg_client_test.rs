//! psycopg 3 over libpq against NetGet's PostgreSQL server: the extended query protocol from a
//! second, independent client.
//!
//! # Why
//!
//! psql 14 sends every statement as a simple Query, so until this test the extended protocol —
//! Parse, Bind, Describe, Execute, binary result columns, bound parameters — rested on
//! tokio-postgres alone. And tokio-postgres is not independent of the server where it matters
//! most: pgwire encodes binary values with `postgres-types`, the same crate tokio-postgres decodes
//! them with. libpq is C and shares nothing with either.
//!
//! It is also the client that found the largest defect this file covers: **the model never saw a
//! bound parameter.** Every parameterised statement psycopg sends is `… WHERE id = $1` with the
//! value in the Bind message, and the server handed the model the text with `$1` in it and
//! nothing else — so every answer to a parameterised query was made up without the value it was
//! about. The event now carries `parameters` (and `parameter_types`), which the mock below
//! answers from, so a server that drops them fails here.
//!
//! # What it drives
//!
//! | step | asserted |
//! |---|---|
//! | binary select | six columns — int4, text, bool, float8, date, timestamp — decoded from binary to Python values |
//! | text select | the same statement with another value, in text format; the row carries that value |
//! | string and null params | a text and a NULL parameter reach the model as `"Ada"` and `null` |
//! | insert | a parameterised write's command tag becomes `rowcount` 1 |
//! | error | the model's `42P01` arrives as `UndefinedTable` |
//! | prepared 1, 2 | a named prepared statement executed twice with different values |
//!
//! It hard-fails when psycopg is missing, and the pcap oracle reads every byte it exchanged.

use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
use serde_json::json;
use std::time::Duration;

fn require_psycopg() {
    let ok = std::process::Command::new("python3")
        .args(["-c", "import psycopg"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    assert!(
        ok,
        "`python3 -c 'import psycopg'` failed. This test drives psycopg 3 over libpq against \
         NetGet's PostgreSQL server; it is the extended-protocol client independent of the \
         server's pgwire/postgres-types stack, so it must fail rather than skip. Install with \
         `python3 -m pip install 'psycopg[binary]'`."
    );
}

/// The first bound parameter as an integer, whichever format the client bound it in.
fn first_int(e: &serde_json::Value) -> Option<i64> {
    let p = &e["parameters"][0];
    p.as_i64()
        .or_else(|| p.as_str().and_then(|s| s.parse().ok()))
}

fn server() -> NetGetConfig {
    NetGetConfig::new("Open PostgreSQL on port {AVAILABLE_PORT}. Serve the users table").with_mock(
        |mock| {
            mock.on_instruction_containing("Open PostgreSQL")
                .respond_with_actions(json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "PostgreSQL",
                    "instruction": "Serve the users table"
                }]))
                .expect_calls(1)
                .and()
                .on_event("postgresql_query")
                .respond_with_actions_from_event(|e| {
                    let q = e["query"].as_str().unwrap_or_default();
                    if q.contains("nowhere") {
                        return json!([{"type": "postgresql_error_response", "code": "42P01",
                                       "message": "relation \"nowhere\" does not exist"}]);
                    }
                    if q.starts_with("INSERT") {
                        return if e["parameters"] == json!(["43", "Grace"])
                            || e["parameters"] == json!([43, "Grace"])
                        {
                            json!([{"type": "postgresql_ok_response", "tag": "INSERT 0 1"}])
                        } else {
                            json!([{"type": "postgresql_error_response", "code": "XX000",
                                    "message": format!("parameters {}", e["parameters"])}])
                        };
                    }
                    if q.contains("nick IS NOT DISTINCT FROM") {
                        return if e["parameters"] == json!(["Ada", null]) {
                            json!([{"type": "postgresql_query_response",
                                    "columns": [{"name": "name", "type": "text"}],
                                    "rows": [["Ada"]]}])
                        } else {
                            json!([{"type": "postgresql_error_response", "code": "XX000",
                                    "message": format!("parameters {}", e["parameters"])}])
                        };
                    }
                    let Some(id) = first_int(e) else {
                        return json!([{"type": "postgresql_error_response", "code": "XX000",
                                       "message": "no parameter reached the model"}]);
                    };
                    if q.starts_with("SELECT id FROM") {
                        return json!([{"type": "postgresql_query_response",
                                       "columns": [{"name": "id", "type": "int4"}],
                                       "rows": [[id]]}]);
                    }
                    json!([{"type": "postgresql_query_response",
                            "columns": [
                                {"name": "id", "type": "int4"}, {"name": "name", "type": "text"},
                                {"name": "active", "type": "bool"},
                                {"name": "score", "type": "float8"},
                                {"name": "born", "type": "date"},
                                {"name": "seen_at", "type": "timestamp"}],
                            "rows": [[id, "Ada", true, 9.5, "1815-12-10", "2026-11-13 12:30:00"]]}])
                })
                // binary, text, string+null, insert, error, prepared x2
                .expect_calls(7)
                .and()
        },
    )
}

#[tokio::test]
async fn psycopg_drives_the_extended_protocol_with_parameters_and_binary_results() -> E2EResult<()>
{
    require_psycopg();
    let server = start_netget_server(server()).await?;
    crate::helpers::wait_for_server_listening(&server, Duration::from_secs(30)).await?;
    let (relay, streams) = crate::helpers::recording_relay::tcp_relay(
        format!("127.0.0.1:{}", server.port).parse().unwrap(),
    )
    .await;

    let script = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/server/postgresql/psycopg_client.py"
    );
    let out = tokio::time::timeout(
        Duration::from_secs(120),
        tokio::process::Command::new("python3")
            .arg("-I")
            .arg(script)
            .arg(relay.port().to_string())
            .output(),
    )
    .await
    .expect("the psycopg client did not finish within 120s")?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    println!(
        "--- psycopg (exit {:?}) ---\n{stdout}\n{stderr}",
        out.status.code()
    );
    assert!(
        out.status.success() && stdout.contains("ALL OK"),
        "the psycopg client failed:\n{stdout}\n{stderr}"
    );

    // Wireshark's pgsql dissector over the whole session: startup, Parse/Bind/Describe/Execute
    // with parameters, binary DataRows, the command tag and the ErrorResponse.
    let connections = crate::helpers::recording_relay::recorded(&streams);
    assert!(
        !connections.is_empty(),
        "psycopg's traffic did not cross the relay"
    );
    for chunks in &connections {
        crate::helpers::recording_relay::replay(
            crate::helpers::pcap_oracle::PcapOracle::tcp("postgresql"),
            chunks,
        )
        .assert_clean();
    }

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

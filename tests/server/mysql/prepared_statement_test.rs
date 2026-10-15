//! MySQL over the **binary** protocol (`COM_STMT_PREPARE` / `COM_STMT_EXECUTE`), and rows
//! whose value count disagrees with the column list.
//!
//! Every other test in this directory uses `conn.query*`, which is `COM_QUERY` — the text
//! protocol, where opensrv-mysql writes every cell as a length-encoded string whatever the
//! column type says. `conn.exec*` prepares and then executes, and there opensrv encodes each
//! cell **according to the declared column type**; handing it a Rust type it cannot write as
//! that type is an `io::Error` that ends the session rather than a wrong value.
//!
//! So the protocol's own advertised example — `columns: [{"name": "id", "type": "INT"}]` —
//! is exactly the shape that has to work here.


use super::super::super::helpers::{self, E2EResult, NetGetConfig};
use mysql_async::prelude::*;
use std::time::Duration;

/// `count_placeholders` decides what the server tells the client at PREPARE time, so a `?`
/// inside a literal or a comment counted as a parameter would desync every execute.
#[test]
fn placeholder_counting_skips_literals_and_comments() {
    use netget::server::mysql::count_placeholders;

    assert_eq!(count_placeholders("SELECT 1"), 0);
    assert_eq!(count_placeholders("SELECT ?"), 1);
    assert_eq!(
        count_placeholders("SELECT * FROM t WHERE a = ? AND b = ?"),
        2
    );
    assert_eq!(count_placeholders("SELECT '?' FROM t WHERE a = ?"), 1);
    assert_eq!(count_placeholders(r#"SELECT "?" , ?"#), 1);
    assert_eq!(count_placeholders("SELECT `we?rd` FROM t WHERE a = ?"), 1);
    assert_eq!(count_placeholders("SELECT 'it''s ?' , ?"), 1);
    assert_eq!(count_placeholders(r"SELECT 'a\'? b' , ?"), 1);
    assert_eq!(count_placeholders("SELECT 1 -- ? not a param\n, ?"), 1);
    assert_eq!(count_placeholders("SELECT 1 # ? nope\n, ?"), 1);
    assert_eq!(count_placeholders("SELECT /* ? no */ ?"), 1);
    // `--` without following whitespace is arithmetic, not a comment.
    assert_eq!(count_placeholders("SELECT a--b, ?"), 1);
    // Unterminated literal: everything after it is inside the literal, so no placeholder.
    assert_eq!(count_placeholders("SELECT 'unterminated ?"), 0);
}

fn opts(port: u16) -> mysql_async::OptsBuilder {
    mysql_async::OptsBuilder::default()
        .ip_or_hostname("127.0.0.1")
        .tcp_port(port)
        .user(Some("root"))
        .pass(Some(""))
        .prefer_socket(false)
}

/// A prepared `SELECT` returning typed columns. Ints, floats and strings all have to survive
/// the binary encoder, and a JSON `null` has to arrive as SQL NULL rather than as the
/// four-character string "NULL".
#[tokio::test]
async fn prepared_statement_returns_typed_columns() -> E2EResult<()> {
    let prompt = "Open MySQL on port {AVAILABLE_PORT} and answer queries about widgets.";

    let config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock.on_instruction_containing("Open MySQL")
            .respond_with_actions(serde_json::json!([{
                "type": "open_server",
                "port": 0,
                "base_stack": "MySQL",
                "instruction": "Answer MySQL queries"
            }]))
            .expect_calls(1)
            .and()
            .on_event("mysql_query")
            .respond_with_actions_from_event(|event| {
                let query = event
                    .get("query")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_uppercase();
                if query.contains("@@") {
                    serde_json::json!([{
                        "type": "mysql_query_response",
                        "columns": [{"name": "value", "type": "VARCHAR"}],
                        "rows": [["1000"]]
                    }])
                } else {
                    serde_json::json!([{
                        "type": "mysql_query_response",
                        "columns": [
                            {"name": "id", "type": "INT"},
                            {"name": "big", "type": "BIGINT"},
                            {"name": "ratio", "type": "DOUBLE"},
                            {"name": "name", "type": "VARCHAR"},
                            {"name": "note", "type": "TEXT"}
                        ],
                        "rows": [[7, 9000000000i64, 1.5, "widget", null]]
                    }])
                }
            })
            .expect_at_least(1)
            .and()
    });

    let server = helpers::start_netget_server(config).await?;

    let pool = mysql_async::Pool::new(opts(server.port));
    let mut conn = tokio::time::timeout(Duration::from_secs(20), pool.get_conn()).await??;

    let row: Option<(i32, i64, f64, String, Option<String>)> = tokio::time::timeout(
        Duration::from_secs(20),
        conn.exec_first("SELECT id, big, ratio, name, note FROM widgets", ()),
    )
    .await??;

    let row = row.ok_or("prepared SELECT returned no row")?;
    assert_eq!(row.0, 7, "INT column");
    assert_eq!(row.1, 9_000_000_000, "BIGINT column");
    assert!((row.2 - 1.5).abs() < f64::EPSILON, "DOUBLE column");
    assert_eq!(row.3, "widget", "VARCHAR column");
    assert_eq!(
        row.4, None,
        "JSON null must arrive as SQL NULL, not \"NULL\""
    );

    drop(conn);
    drop(pool);
    server.verify_mocks().await?;
    Ok(())
}

/// A prepared statement with a bound parameter. The server declares no database and does not
/// substitute parameters — the model sees the `?` — but the *count* it reports at PREPARE has
/// to match the statement, or the client refuses to execute it at all.
#[tokio::test]
async fn prepared_statement_with_a_bound_parameter_executes() -> E2EResult<()> {
    let prompt = "Open MySQL on port {AVAILABLE_PORT} and answer queries about widgets.";

    let config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock.on_instruction_containing("Open MySQL")
            .respond_with_actions(serde_json::json!([{
                "type": "open_server",
                "port": 0,
                "base_stack": "MySQL",
                "instruction": "Answer MySQL queries"
            }]))
            .expect_calls(1)
            .and()
            .on_event("mysql_query")
            .respond_with_actions_from_event(|event| {
                let query = event
                    .get("query")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_uppercase();
                if query.contains("@@") {
                    serde_json::json!([{
                        "type": "mysql_query_response",
                        "columns": [{"name": "value", "type": "VARCHAR"}],
                        "rows": [["1000"]]
                    }])
                } else {
                    serde_json::json!([{
                        "type": "mysql_query_response",
                        "columns": [{"name": "id", "type": "INT"}],
                        "rows": [[42]]
                    }])
                }
            })
            .expect_at_least(1)
            .and()
    });

    let server = helpers::start_netget_server(config).await?;

    let pool = mysql_async::Pool::new(opts(server.port));
    let mut conn = tokio::time::timeout(Duration::from_secs(20), pool.get_conn()).await??;

    let id: Option<i32> = tokio::time::timeout(
        Duration::from_secs(20),
        conn.exec_first("SELECT id FROM widgets WHERE id = ?", (42,)),
    )
    .await??;

    assert_eq!(id, Some(42));

    drop(conn);
    drop(pool);
    server.verify_mocks().await?;
    Ok(())
}

/// A row the model got wrong: fewer values than columns in one row, more in the next.
/// Neither may kill the connection — PostgreSQL's handler already pads and truncates, and a
/// miscounted row is among the likeliest things a model produces.
#[tokio::test]
async fn miscounted_rows_do_not_kill_the_connection() -> E2EResult<()> {
    let prompt = "Open MySQL on port {AVAILABLE_PORT} and answer queries about gadgets.";

    let config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock.on_instruction_containing("Open MySQL")
            .respond_with_actions(serde_json::json!([{
                "type": "open_server",
                "port": 0,
                "base_stack": "MySQL",
                "instruction": "Answer MySQL queries"
            }]))
            .expect_calls(1)
            .and()
            .on_event("mysql_query")
            .respond_with_actions_from_event(|event| {
                let query = event
                    .get("query")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_uppercase();
                if query.contains("@@") {
                    serde_json::json!([{
                        "type": "mysql_query_response",
                        "columns": [{"name": "value", "type": "VARCHAR"}],
                        "rows": [["1000"]]
                    }])
                } else {
                    serde_json::json!([{
                        "type": "mysql_query_response",
                        "columns": [
                            {"name": "a", "type": "VARCHAR"},
                            {"name": "b", "type": "VARCHAR"}
                        ],
                        "rows": [["only-one"], ["x", "y", "extra"]]
                    }])
                }
            })
            .expect_at_least(1)
            .and()
    });

    let server = helpers::start_netget_server(config).await?;

    let pool = mysql_async::Pool::new(opts(server.port));
    let mut conn = tokio::time::timeout(Duration::from_secs(20), pool.get_conn()).await??;

    let rows: Vec<(Option<String>, Option<String>)> = tokio::time::timeout(
        Duration::from_secs(20),
        conn.query("SELECT a, b FROM gadgets"),
    )
    .await??;

    assert_eq!(rows.len(), 2, "both rows should arrive");
    assert_eq!(rows[0].0.as_deref(), Some("only-one"));
    assert_eq!(rows[0].1, None, "a short row is padded with NULL");
    assert_eq!(rows[1].0.as_deref(), Some("x"));
    assert_eq!(rows[1].1.as_deref(), Some("y"));

    // The connection must still be usable afterwards.
    let follow_up: Option<(Option<String>, Option<String>)> = tokio::time::timeout(
        Duration::from_secs(20),
        conn.query_first("SELECT a, b FROM gadgets"),
    )
    .await??;
    assert!(
        follow_up.is_some(),
        "connection survived the miscounted rows"
    );

    drop(conn);
    drop(pool);
    server.verify_mocks().await?;
    Ok(())
}

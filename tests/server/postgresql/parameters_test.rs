//! Bound parameters, promised columns and cell values, through tokio-postgres.
//!
//! Three defects, each a reply the client could not tell from a real one:
//!
//! * **Parameters never reached the model.** `do_describe_statement` reported zero parameters, so
//!   tokio-postgres refused to send any (`expected 0 parameters but got 1`), and a client that sent
//!   them anyway (psycopg) had the statement answered with `$1` still in the text. The statement
//!   now declares one type per `$n`, and the event carries `parameters`.
//! * **The rows did not have to match the columns already described.** tokio-postgres describes a
//!   statement before binding it, and the model was asked again at Execute with nothing saying
//!   what it had promised. The event now carries `columns`, and an answer with a different number
//!   of columns fails closed rather than reaching a client that decodes it by the wrong
//!   description.
//! * **A cell that could not be its column's type was sent as something else.** `"abc"` in an
//!   `int4` column went out as `0`, `3000000000` wrapped to a negative number. Both now fail the
//!   statement (`XX000`), and a numeric string is still read as its number.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features mcp-stdio,sqlite \
//!       --test server -- server::postgresql::parameters_test --test-threads=8

use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
use serde_json::json;
use std::time::Duration;
use tokio_postgres::types::Type;
use tokio_postgres::NoTls;

fn columns(names: &[(&str, &str)]) -> serde_json::Value {
    json!(names
        .iter()
        .map(|(n, t)| json!({"name": n, "type": t}))
        .collect::<Vec<_>>())
}

fn rows_answer(cols: serde_json::Value, rows: serde_json::Value) -> serde_json::Value {
    json!([{"type": "postgresql_query_response", "columns": cols, "rows": rows}])
}

fn server() -> NetGetConfig {
    NetGetConfig::new("Open PostgreSQL on port {AVAILABLE_PORT}. Answer queries").with_mock(
        |mock| {
            mock.on_instruction_containing("Open PostgreSQL")
                .respond_with_actions(json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "PostgreSQL",
                    "instruction": "Answer queries"
                }]))
                .expect_calls(1)
                .and()
                .on_event("postgresql_query")
                .respond_with_actions_from_event(|e| {
                    let q = e["query"].as_str().unwrap_or_default();
                    let describing = e["describe_only"] == json!(true);
                    if q.contains("FROM labels") {
                        let cols = columns(&[("id", "int4"), ("label", "text")]);
                        if describing {
                            return rows_answer(cols, json!([]));
                        }
                        // The parameter, and the columns the Describe promised, both arrive.
                        if e["columns"][1]["name"] != json!("label") {
                            return json!([{"type": "postgresql_error_response", "code": "XX000",
                                       "message": "the described columns did not arrive"}]);
                        }
                        let id: i64 = e["parameters"][0]
                            .as_str()
                            .and_then(|s| s.parse().ok())
                            .unwrap_or(-1);
                        return rows_answer(cols, json!([[id, format!("label-{id}")]]));
                    }
                    if q.contains("FROM typed") {
                        let cols = columns(&[("id", "int4")]);
                        if e["parameter_types"] != json!(["int4"]) {
                            return json!([{"type": "postgresql_error_response", "code": "XX000",
                                       "message": "the parameter type did not arrive"}]);
                        }
                        if describing {
                            return rows_answer(cols, json!([]));
                        }
                        return rows_answer(cols, json!([[e["parameters"][0].clone()]]));
                    }
                    if q.contains("FROM mismatch") {
                        // Two columns described, one answered: the client must not get it.
                        if describing {
                            return rows_answer(
                                columns(&[("a", "int4"), ("b", "int4")]),
                                json!([]),
                            );
                        }
                        return rows_answer(columns(&[("a", "int4")]), json!([[1]]));
                    }
                    if q.contains("FROM bad") {
                        return rows_answer(columns(&[("n", "int4")]), json!([["abc"]]));
                    }
                    if q.contains("FROM overflow") {
                        return rows_answer(columns(&[("n", "int4")]), json!([[3_000_000_000i64]]));
                    }
                    if q.contains("FROM good") {
                        return rows_answer(
                            columns(&[("n", "int4"), ("ok", "bool")]),
                            json!([["42", "t"]]),
                        );
                    }
                    json!([{"type": "postgresql_error_response", "code": "XX000",
                        "message": format!("unexpected {q}")}])
                })
                // labels: describe + execute; typed: describe + 2 executes; mismatch: describe +
                // execute; bad, overflow, good: one each
                .expect_calls(10)
                .and()
        },
    )
}

#[tokio::test]
async fn parameters_reach_the_model_and_the_answer_keeps_its_promised_shape() -> E2EResult<()> {
    let server = start_netget_server(server()).await?;
    let (client, connection) = tokio::time::timeout(
        Duration::from_secs(30),
        tokio_postgres::connect(
            &format!(
                "host=127.0.0.1 port={} user=netget dbname=netget",
                server.port
            ),
            NoTls,
        ),
    )
    .await
    .expect("connect timed out")?;
    tokio::spawn(connection);

    // An untyped parameter: the statement declares it text, and the value is bound as text.
    let rows = client
        .query("SELECT id, label FROM labels WHERE id = $1", &[&"5"])
        .await?;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].get::<_, i32>(0), 5);
    assert_eq!(rows[0].get::<_, &str>(1), "label-5");

    // A typed parameter, bound in binary, executed twice with different values: each Execute
    // asks with its own value and answers in the described shape.
    let stmt = client
        .prepare_typed("SELECT id FROM typed WHERE id = $1", &[Type::INT4])
        .await?;
    assert_eq!(stmt.params(), &[Type::INT4]);
    for id in [7i32, 8] {
        let rows = client.query(&stmt, &[&id]).await?;
        assert_eq!(
            rows[0].get::<_, i32>(0),
            id,
            "the bound value did not reach the model"
        );
    }

    // An answer with fewer columns than the Describe promised is refused, not sent.
    let err = client
        .query("SELECT a, b FROM mismatch WHERE x = $1", &[&"1"])
        .await
        .expect_err("rows that do not match the described columns must not be sent");
    assert_eq!(
        err.as_db_error().map(|e| e.code().code()),
        Some("XX000"),
        "a column mismatch fails closed with XX000: {err}"
    );

    // A value that is not its column's type fails the statement, whichever way it is wrong.
    for sql in ["SELECT n FROM bad", "SELECT n FROM overflow"] {
        let err = client
            .simple_query(sql)
            .await
            .expect_err("an unencodable cell must fail the statement");
        assert_eq!(
            err.as_db_error().map(|e| e.code().code()),
            Some("XX000"),
            "{sql}: {err}"
        );
    }
    // And a value that is its type written as a string is read as that type.
    let rows = client.query("SELECT n, ok FROM good", &[]).await?;
    assert_eq!(rows[0].get::<_, i32>(0), 42);
    assert!(rows[0].get::<_, bool>(1));

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

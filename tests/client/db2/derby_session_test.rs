//! The Db2 client's DRDA session against Apache Derby's network server, without a model: the
//! handshake, statements, typed rows, transactions, errors and multi-block answer sets, each
//! asserted on what Derby answered and on what Derby's own `ij` client reads back.
//!
//! These tests call [`netget::client::db2::Conn`] — the same session object the client runs
//! the model's actions through — so a decoding defect shows up here with the value it got
//! wrong, rather than as a mock rule that did not match. `real_server_test.rs` then drives the
//! whole client with the model in the loop.
//!
//! No LLM calls. Fails rather than skips without java or the Derby jars.

use super::derby::{derby_log, ij};
use super::real_server_test::start_derby;
use crate::helpers::E2EResult;
use netget::client::db2::{wire, Conn};
use serde_json::{json, Value};
use std::time::Duration;
use tokio::net::TcpStream;

async fn open(
    port: u16,
    database: &str,
    user: &str,
    password: Option<&str>,
) -> anyhow::Result<Conn> {
    let stream = TcpStream::connect(("127.0.0.1", port)).await?;
    let local = stream.local_addr()?;
    let mut conn = Conn::new(stream, Duration::from_secs(60), false);
    conn.handshake(
        database,
        user,
        password,
        "DNC10170",
        wire::correlation_token(local, [1, 2, 3, 4, 5, 6]),
    )
    .await?;
    Ok(conn)
}

async fn run(conn: &mut Conn, name: &str, data: Value) -> (String, Value) {
    let (event, payload) = conn
        .perform(name, &data)
        .await
        .unwrap_or_else(|e| panic!("{name} {data}: the connection failed: {e:#}"));
    (event.id.clone(), payload)
}

/// A database name longer than 18 bytes, so every SQL command's PKGNAMCSN takes the extended
/// form, which Derby checks against the name ACCRDB opened.
const LONG_DB: &str = "netget_session_evidence;create=true";

#[tokio::test]
async fn statements_typed_rows_transactions_and_errors_against_derby() -> E2EResult<()> {
    let server = start_derby(None).await?;
    let result = session(&server).await;
    server.with_log(result)
}

async fn session(server: &crate::helpers::real_server::RealServer) -> E2EResult<()> {
    let mut conn = open(server.port, LONG_DB, "app", Some("anything")).await?;
    assert_eq!(conn.repr.typdefnam, "QTDSQLASC");

    let (ev, r) = run(
        &mut conn,
        "execute_statement",
        json!({"sql":
        "CREATE TABLE t (id INT NOT NULL, s SMALLINT, b BIGINT, v VARCHAR(40), c CHAR(5), \
         d DECIMAL(10,2), neg DECIMAL(5,3), dt DATE, tm TIME, ts TIMESTAMP, dbl DOUBLE, \
         r REAL, ok BOOLEAN)"}),
    )
    .await;
    assert_eq!(ev, "db2_statement_result", "{r}");
    assert_eq!(r["sqlcode"], 0);

    let (ev, r) = run(
        &mut conn,
        "execute_statement",
        json!({"sql":
        "INSERT INTO t VALUES (1, -7, 3000000000, 'héllo wörld', 'ab', 123.45, -0.5, \
         '2026-10-14', '12:34:56', '2026-10-14 12:34:56.123456', 1.5, 0.25, TRUE), \
         (2, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)"}),
    )
    .await;
    assert_eq!(ev, "db2_statement_result", "{r}");
    assert_eq!(
        r["row_count"], 2,
        "SQLERRD3 must carry the rows inserted: {r}"
    );

    let (ev, r) = run(&mut conn, "commit", json!({})).await;
    assert_eq!(ev, "db2_transaction_result", "{r}");
    assert_eq!(r["outcome"], "committed");
    assert_eq!(r["statements"].as_array().map(Vec::len), Some(2), "{r}");

    let (ev, r) = run(
        &mut conn,
        "execute_query",
        json!({"sql": "SELECT * FROM t ORDER BY id", "max_rows": 10}),
    )
    .await;
    assert_eq!(ev, "db2_query_result", "{r}");
    assert_eq!(r["row_count"], 2);
    assert_eq!(r["truncated"], false);
    let names: Vec<&str> = r["columns"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        ["ID", "S", "B", "V", "C", "D", "NEG", "DT", "TM", "TS", "DBL", "R", "OK"]
    );
    assert_eq!(r["columns"][0]["nullable"], false);
    assert_eq!(r["columns"][5]["type"], "DECIMAL(10,2)");
    assert_eq!(
        r["rows"][0],
        json!({"ID": 1, "S": -7, "B": 3000000000i64, "V": "héllo wörld", "C": "ab   ",
               "D": "123.45", "NEG": "-0.500", "DT": "2026-10-14", "TM": "12:34:56",
               "TS": "2026-10-14-12.34.56.123456000", "DBL": 1.5, "R": 0.25, "OK": true}),
        "every type must decode to its value"
    );
    assert_eq!(
        r["rows"][1],
        json!({"ID": 2, "S": null, "B": null, "V": null, "C": null, "D": null, "NEG": null,
               "DT": null, "TM": null, "TS": null, "DBL": null, "R": null, "OK": null})
    );

    // A bad statement is an error SQLCA, delivered as db2_error, and the session goes on.
    let (ev, r) = run(
        &mut conn,
        "execute_query",
        json!({"sql": "SELECT nosuch FROM t"}),
    )
    .await;
    assert_eq!(ev, "db2_error", "{r}");
    assert_eq!(r["sqlstate"], "42X04", "{r}");
    assert!(r["sqlcode"].as_i64().unwrap() < 0);
    assert!(r["message_tokens"].to_string().contains("NOSUCH"), "{r}");
    let (ev, r) = run(
        &mut conn,
        "execute_statement",
        json!({"sql": "INSERT INTO nosuch VALUES (1)"}),
    )
    .await;
    assert_eq!(ev, "db2_error", "{r}");
    assert_eq!(r["sqlstate"], "42X05", "{r}");

    // Rollback undoes; the rows are gone for an independent client too.
    let (ev, r) = run(
        &mut conn,
        "execute_statement",
        json!({"sql": "DELETE FROM t"}),
    )
    .await;
    assert_eq!(
        (ev.as_str(), &r["row_count"]),
        ("db2_statement_result", &json!(2))
    );
    let (ev, r) = run(&mut conn, "rollback", json!({})).await;
    assert_eq!(ev, "db2_transaction_result");
    assert_eq!(r["outcome"], "rolled_back", "{r}");

    // An answer set larger than one 32767-byte query block: rows split across blocks and
    // fetched with CNTQRY.
    let (ev, r) = run(
        &mut conn,
        "execute_statement",
        json!({"sql": "CREATE TABLE big (n INT, filler VARCHAR(200))"}),
    )
    .await;
    assert_eq!(ev, "db2_statement_result", "{r}");
    for chunk in 0..6 {
        let values: Vec<String> = (0..100)
            .map(|i| {
                let n = chunk * 100 + i;
                format!("({n}, '{}')", format!("row{n:04}-").repeat(18))
            })
            .collect();
        let (ev, r) = run(
            &mut conn,
            "execute_statement",
            json!({"sql": format!("INSERT INTO big VALUES {}", values.join(","))}),
        )
        .await;
        assert_eq!(
            (ev.as_str(), &r["row_count"]),
            ("db2_statement_result", &json!(100)),
            "{r}"
        );
    }
    run(&mut conn, "commit", json!({})).await;
    let (ev, r) = run(
        &mut conn,
        "execute_query",
        json!({"sql": "SELECT n, filler FROM big ORDER BY n", "max_rows": 1000}),
    )
    .await;
    assert_eq!(
        ev,
        "db2_query_result",
        "{}",
        &r.to_string()[..300.min(r.to_string().len())]
    );
    assert_eq!(r["row_count"], 600);
    assert_eq!(r["truncated"], false);
    for (i, row) in r["rows"].as_array().unwrap().iter().enumerate() {
        assert_eq!(row["N"], i, "row order and values across query blocks");
        assert_eq!(row["FILLER"], format!("row{i:04}-").repeat(18));
    }

    // max_rows stops the fetch, says so, and closes the cursor (the next query still works).
    let (ev, r) = run(
        &mut conn,
        "execute_query",
        json!({"sql": "SELECT n FROM big ORDER BY n", "max_rows": 5}),
    )
    .await;
    assert_eq!(ev, "db2_query_result");
    assert_eq!(
        (r["row_count"].clone(), r["truncated"].clone()),
        (json!(5), json!(true))
    );
    let (ev, r) = run(
        &mut conn,
        "execute_query",
        json!({"sql": "SELECT COUNT(*) AS c FROM big"}),
    )
    .await;
    assert_eq!(ev, "db2_query_result", "{r}");
    assert_eq!(r["rows"][0]["C"], 600);

    // What Derby's own client reads back: the committed rows.
    let out = ij(
        server,
        "netget_session_evidence",
        "anything",
        "SELECT id, v, d FROM t ORDER BY id;",
    )
    .await?;
    assert!(
        out.contains("héllo wörld") && out.contains("123.45"),
        "{out}"
    );
    assert!(out.contains("2 rows selected"), "{out}");
    let log = derby_log(server);
    assert!(
        log.contains("DELETE FROM t"),
        "Derby's statement log:\n{log}"
    );
    Ok(())
}

/// A refused login fails the handshake with the server's reason; it never reads as connected.
#[tokio::test]
async fn refused_login_fails_the_handshake() -> E2EResult<()> {
    let server = start_derby(Some("right")).await?;
    let result = async {
        let err = match open(server.port, "authdb;create=true", "app", Some("wrong")).await {
            Ok(_) => return Err("a wrong password opened the database".into()),
            Err(e) => format!("{e:#}"),
        };
        // The refusal is SECCHK's own, with Derby's reason, not a later step failing.
        assert!(err.contains("login refused: SECCHKCD 0x"), "{err}");
        assert!(err.contains("decision=refused"), "{err}");
        let conn = open(server.port, "authdb;create=true", "app", Some("right")).await;
        assert!(
            conn.is_ok(),
            "the right password must open it: {:?}",
            conn.err()
        );
        Ok::<(), Box<dyn std::error::Error>>(())
    }
    .await;
    server.with_log(result)
}

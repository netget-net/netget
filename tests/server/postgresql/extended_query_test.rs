//! The extended query protocol — Parse/Describe/Bind/Execute — which every existing test in
//! this directory avoids.
//!
//! `tests/server/postgresql/CLAUDE.md` carried "Extended Query Protocol Timeout (CRITICAL) …
//! **Status: UNRESOLVED** - root cause unknown" and told readers to "use simple queries
//! instead". Every test in `test.rs` duly calls `client.simple_query(...)`, so the claim was
//! never measured. This file measures it: `client.query(...)` and `client.prepare(...)` take
//! the extended path.
//!
//! This is the same shape as the MySQL defect found in this batch — a whole protocol path
//! nobody tested because the suite only ever exercised the text protocol.
//!
//! Zero LLM calls: a `*` static handler answers, and `instruction: Some(String::new())` keeps
//! `ServerForm::create` from substituting its default instruction (which would make the server
//! consult the model). That also makes the "timeout waiting for the LLM" hypothesis
//! unnecessary to control for: there is no LLM in the loop at all, so a hang here would be
//! ours.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features postgresql --test server -- postgresql::extended_query --test-threads=100


use std::time::Duration;

use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use netget::state::ServerId;
use tokio::sync::mpsc;

async fn new_state() -> AppState {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".to_string());
    state
        .set_llm_client(netget::llm::OllamaClient::new(
            "http://127.0.0.1:1".to_string(),
        ))
        .await;
    state
}

async fn wait_for_port(state: &AppState, id: ServerId) -> u16 {
    for _ in 0..100 {
        if let Some(s) = state.get_server(id).await {
            if let Some(addr) = s.local_addr {
                return addr.port();
            }
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("PostgreSQL server #{} never bound a port", id.as_u32());
}

/// A server that answers every query with one `int4` column and one row.
async fn start_server(state: &AppState) -> u16 {
    let (tx, _rx) = mpsc::unbounded_channel();
    let server_id = ServerForm {
        protocol: "postgresql".to_string(),
        port: Some(0),
        instruction: Some(String::new()),
        event_handlers: Some(vec![serde_json::json!({
            "event_pattern": "*",
            "handler": {
                "type": "static",
                "actions": [ {
                    "type": "postgresql_query_response",
                    "columns": [{"name": "id", "type": "int4"}],
                    "rows": [[7]]
                } ]
            }
        })]),
        ..Default::default()
    }
    .create(state, tx)
    .await
    .expect("create postgresql server");
    wait_for_port(state, server_id).await
}

async fn connect(port: u16) -> tokio_postgres::Client {
    let (client, connection) = tokio_postgres::connect(
        &format!("host=127.0.0.1 port={port} user=netget dbname=netget"),
        tokio_postgres::NoTls,
    )
    .await
    .expect("connect");
    tokio::spawn(async move {
        let _ = connection.await;
    });
    client
}

/// `client.query` is Parse → Describe → Bind → Execute, not a simple query. The documented
/// claim was that this times out; it does not.
#[tokio::test]
async fn an_extended_protocol_query_returns_a_typed_row() {
    let state = new_state().await;
    let port = start_server(&state).await;
    let client = connect(port).await;

    let rows = tokio::time::timeout(
        Duration::from_secs(20),
        client.query("SELECT id FROM users", &[]),
    )
    .await
    .expect(
        "the extended query protocol hung - this is the 'Extended Query Protocol Timeout' the \
         tests CLAUDE.md called CRITICAL and UNRESOLVED. No LLM is in this loop, so the hang \
         would be ours",
    )
    .expect("extended query succeeded");

    assert_eq!(rows.len(), 1, "expected exactly one row");
    let id: i32 = rows[0].get("id");
    assert_eq!(
        id, 7,
        "the int4 column must arrive as a real i32, not as text - the extended protocol asks \
         for the declared type and tokio-postgres decodes by it"
    );
}

/// An explicitly prepared statement, kept and executed twice. `prepare` is where a wrong field
/// description surfaces: tokio-postgres reads the RowDescription from Describe and decodes the
/// later DataRow by it, so a mismatch between the two is a decode error rather than a wrong
/// value.
#[tokio::test]
async fn a_prepared_statement_describes_its_columns_and_executes_twice() {
    let state = new_state().await;
    let port = start_server(&state).await;
    let client = connect(port).await;

    let stmt = tokio::time::timeout(
        Duration::from_secs(20),
        client.prepare("SELECT id FROM users WHERE id = 7"),
    )
    .await
    .expect("prepare hung")
    .expect("prepare succeeded");

    assert_eq!(stmt.columns().len(), 1, "one column described");
    assert_eq!(stmt.columns()[0].name(), "id");
    assert_eq!(
        stmt.columns()[0].type_(),
        &tokio_postgres::types::Type::INT4,
        "the declared int4 must reach the client's field description"
    );

    for attempt in 1..=2 {
        let rows = tokio::time::timeout(Duration::from_secs(20), client.query(&stmt, &[]))
            .await
            .unwrap_or_else(|_| panic!("execute #{attempt} hung"))
            .unwrap_or_else(|e| panic!("execute #{attempt} failed: {e}"));
        assert_eq!(rows.len(), 1, "execute #{attempt} returned one row");
        let id: i32 = rows[0].get("id");
        assert_eq!(id, 7, "execute #{attempt} decoded the int4");
    }
}

/// The extended path must fail closed too. With no handler and no reachable LLM backend, a
/// query has to come back as an error, never as an empty result set — an empty set reads as
/// "the query ran and matched no rows", a claim about the data that nothing supports.
#[tokio::test]
async fn an_unanswerable_extended_query_errors_rather_than_returning_no_rows() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    // No event_handlers at all, and the LLM endpoint is a closed port: nothing can answer.
    let server_id = ServerForm {
        protocol: "postgresql".to_string(),
        port: Some(0),
        instruction: Some("Answer queries about a users table".to_string()),
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .expect("create postgresql server");
    let port = wait_for_port(&state, server_id).await;
    let client = connect(port).await;

    let outcome = tokio::time::timeout(
        Duration::from_secs(40),
        client.query("SELECT id FROM users", &[]),
    )
    .await
    .expect("the server neither answered nor failed - it went silent on the extended path");

    match outcome {
        Ok(rows) => panic!(
            "expected an ErrorResponse, got {} row(s). An empty or fabricated result set is \
             indistinguishable from a real answer, which is the fail-open this protocol \
             deliberately refuses",
            rows.len()
        ),
        Err(e) => {
            let db = e
                .as_db_error()
                .expect("expected a database ErrorResponse carrying a SQLSTATE");
            assert_eq!(
                db.code(),
                &tokio_postgres::error::SqlState::from_code("XX000"),
                "expected XX000 (internal_error); got {:?}",
                db.code()
            );
            let message = db.message();
            assert!(
                message.contains("netget"),
                "the peer should get netget's own failure category, got {message:?}"
            );
            // The peer gets a category; the error text stays in the log.
            for leak in ["http://", "Ollama", "reqwest", "connection refused"] {
                assert!(
                    !message.to_lowercase().contains(&leak.to_lowercase()),
                    "the wire message leaked backend detail ({leak:?}): {message:?}"
                );
            }
        }
    }
}

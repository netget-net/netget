//! What a PostgreSQL client gets when the LLM backend fails: an ErrorResponse with a SQLSTATE.
//!
//! PostgreSQL's ErrorResponse carries a five-character SQLSTATE, which is what a driver uses to
//! classify a failure. `XX000` (internal_error) is the honest code for "the component that
//! would have produced this answer did not". The assertion reads it back through
//! `tokio-postgres`, an independent implementation of the wire protocol.

use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
use std::time::Duration;
use tokio_postgres::error::SqlState;
use tokio_postgres::NoTls;

#[tokio::test]
async fn test_postgresql_answers_error_response_when_llm_fails() -> E2EResult<()> {
    let prompt = "Open PostgreSQL on port {AVAILABLE_PORT}. Answer queries about a users table.";

    let server_config = NetGetConfig::new_no_scripts(prompt).with_mock(|mock| {
        mock.on_instruction_containing("Open PostgreSQL")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "PostgreSQL",
                    "instruction": "Answer queries about a users table"
                }
            ]))
            .expect_calls(1)
            .and()
        // No rule for `postgresql_query`: the mock answers 500.
    });

    let server = start_netget_server(server_config).await?;
    crate::helpers::wait_for_server_listening(&server, Duration::from_secs(30)).await?;

    let (client, connection) = tokio_postgres::connect(
        &format!(
            "host=127.0.0.1 port={} user=netget dbname=netget",
            server.port
        ),
        NoTls,
    )
    .await?;
    tokio::spawn(async move {
        let _ = connection.await;
    });

    let outcome = tokio::time::timeout(
        Duration::from_secs(25),
        client.simple_query("SELECT id FROM users"),
    )
    .await
    .map_err(|_| {
        "PostgreSQL neither answered nor failed within 25s - the server went silent on LLM \
         failure, which is the exact defect this test exists to catch"
    })?;

    let error = match outcome {
        Ok(rows) => panic!(
            "PostgreSQL reported success ({} messages) despite the backend being unavailable",
            rows.len()
        ),
        Err(e) => e,
    };
    println!("PostgreSQL error: {error:?}");

    let code = error
        .code()
        .unwrap_or_else(|| panic!("expected an ErrorResponse with a SQLSTATE, got {error:?}"));
    assert_eq!(
        code,
        &SqlState::INTERNAL_ERROR,
        "an LLM failure must be reported as SQLSTATE XX000, got {code:?}"
    );
    // `Error::to_string()` is just "db error"; the server's text lives on the DbError itself.
    let db_message = error
        .as_db_error()
        .map(|db| db.message().to_string())
        .unwrap_or_default();
    assert!(
        db_message.contains("netget"),
        "the ErrorResponse message should name the source of the failure: {db_message:?}"
    );

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

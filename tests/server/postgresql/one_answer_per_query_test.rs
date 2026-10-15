//! One query, one answer — and the server says which, from the statement.
//!
//! Two things the real-model eval found (`postgresql/current-user` 1/5 in the committed
//! baseline): the model answered `SELECT current_user` with the command tag `INSERT 0 1`, and
//! answered one query with several response actions. The query event now carries `answer_with`,
//! derived from the statement's first keyword, and a second response action for the same query
//! is dropped with `decision=duplicate_response_dropped` rather than silently.
//!
//! Driven with `tokio-postgres`, an independent implementation of the wire protocol.

use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
use std::time::Duration;
use tokio_postgres::{NoTls, SimpleQueryMessage};

#[tokio::test]
async fn a_second_result_for_one_query_is_dropped_and_logged() -> E2EResult<()> {
    let prompt = "Open PostgreSQL on port {AVAILABLE_PORT}. Report the current user.";

    let server_config = NetGetConfig::new_no_scripts(prompt).with_mock(|mock| {
        mock.on_instruction_containing("Open PostgreSQL")
            .respond_with_actions(serde_json::json!([{
                "type": "open_server",
                "port": 0,
                "base_stack": "PostgreSQL",
                "instruction": "Report the current user as netget_eval"
            }]))
            .expect_calls(1)
            .and()
            // The rule matches only if the server told the model a SELECT returns rows.
            .on_event("postgresql_query")
            .and_event_data_contains("answer_with", "postgresql_query_response")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "postgresql_query_response",
                    "columns": [{"name": "current_user", "type": "text"}],
                    "rows": [["first-answer"]]
                },
                {
                    "type": "postgresql_query_response",
                    "columns": [{"name": "current_user", "type": "text"}],
                    "rows": [["second-answer"]]
                }
            ]))
            .expect_calls(1)
            .and()
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

    let messages = tokio::time::timeout(
        Duration::from_secs(25),
        client.simple_query("SELECT current_user"),
    )
    .await
    .map_err(|_| "no answer to SELECT current_user within 25s")??;

    let values: Vec<String> = messages
        .iter()
        .filter_map(|m| match m {
            SimpleQueryMessage::Row(row) => row.get(0).map(str::to_string),
            _ => None,
        })
        .collect();
    assert_eq!(
        values,
        vec!["first-answer".to_string()],
        "exactly the first result set reaches the client"
    );

    server
        .wait_for_any(&["decision=duplicate_response_dropped"], 15)
        .await;
    assert!(
        server
            .output_contains("decision=duplicate_response_dropped")
            .await,
        "the dropped second answer must be logged, not discarded in silence"
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

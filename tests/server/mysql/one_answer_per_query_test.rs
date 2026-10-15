//! One query, one answer — and the server says which, from the statement.
//!
//! The real-model eval (`mysql/server-version` 1/5 in the committed baseline) saw the model
//! answer the client's `SELECT @@version_comment` / `SELECT VERSION()` with OK packets, and one
//! query with a run of alternating response actions. The query event now carries `answer_with`,
//! derived from the statement's first keyword, and a second response action for the same query
//! is dropped with `decision=duplicate_response_dropped` rather than silently.
//!
//! Driven with `mysql_async`, an independent client implementation.

use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
use mysql_async::prelude::Queryable;
use std::time::Duration;

#[tokio::test]
async fn a_second_result_for_one_query_is_dropped_and_logged() -> E2EResult<()> {
    let prompt = "Open MySQL on port {AVAILABLE_PORT}. Report the server version.";

    let server_config = NetGetConfig::new_no_scripts(prompt).with_mock(|mock| {
        mock.on_instruction_containing("Open MySQL")
            .respond_with_actions(serde_json::json!([{
                "type": "open_server",
                "port": 0,
                "base_stack": "MySQL",
                "instruction": "Report the server version as 8.0.36-netget-eval"
            }]))
            .expect_calls(1)
            .and()
            // The driver's own `SELECT @@…` setup queries.
            .on_event("mysql_query")
            .and_event_data_contains("query", "@@")
            .respond_with_actions(serde_json::json!([{
                "type": "mysql_query_response",
                "columns": [{"name": "value", "type": "VARCHAR"}],
                "rows": [["1000"]]
            }]))
            .expect_at_least(0)
            .and()
            // Matches only if the server told the model a SELECT returns rows.
            .on_event("mysql_query")
            .and_event_data_contains("query", "VERSION()")
            .and_event_data_contains("answer_with", "mysql_query_response")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "mysql_query_response",
                    "columns": [{"name": "version", "type": "VARCHAR"}],
                    "rows": [["first-answer"]]
                },
                {"type": "mysql_ok_response", "affected_rows": 0}
            ]))
            .expect_calls(1)
            .and()
    });

    let server = start_netget_server(server_config).await?;
    crate::helpers::wait_for_server_listening(&server, Duration::from_secs(30)).await?;

    let opts = mysql_async::OptsBuilder::default()
        .ip_or_hostname("127.0.0.1")
        .tcp_port(server.port)
        .user(Some("root"))
        .pass(Some(""))
        .prefer_socket(false);
    let pool = mysql_async::Pool::new(opts);

    let version: Option<String> = tokio::time::timeout(Duration::from_secs(25), async {
        let mut conn = pool.get_conn().await?;
        conn.query_first("SELECT VERSION()").await
    })
    .await
    .map_err(|_| "no answer to SELECT VERSION() within 25s")??;
    assert_eq!(
        version.as_deref(),
        Some("first-answer"),
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
    let _ = pool.disconnect().await;
    server.stop().await?;
    Ok(())
}

//! E2E tests for PostgreSQL client
//!
//! These tests verify PostgreSQL client functionality by spawning the actual NetGet binary
//! and testing client behavior as a black-box.

mod postgresql_client_tests {
    use crate::helpers::*;

    /// The follow-up chain against NetGet's own server: every result the model is shown can
    /// drive another query, and the chain stops at the client's depth bound.
    ///
    /// The model here answers **every** `postgresql_query_result` with another `SELECT`, which
    /// is the runaway the bound exists for. `postgresql_connected` issues the first query at
    /// depth 0 and each result's follow-up runs one level deeper; the result at depth 4
    /// (`MAX_FOLLOWUP_DEPTH`) is shown to the model but its answer is dropped. So the server
    /// must see exactly **five** queries and the client exactly **five** result events. Fewer
    /// would mean a follow-up's rows never reached the model; more would mean the chain had no
    /// bound.
    ///
    /// The real-server evidence for this client is `real_server_test.rs`; this file is
    /// same-project and kept for the bound, which a real server has no reason to exercise.
    ///
    /// LLM calls: server 1 startup + 5 queries; client 1 startup + 1 connect + 5 results = 13.
    #[tokio::test]
    async fn a_query_result_chain_is_followed_and_bounded() -> E2EResult<()> {
        let server_config = NetGetConfig::new(
            "Listen on port {AVAILABLE_PORT} via PostgreSQL. Answer SELECT queries.",
        )
        .with_mock(|mock| {
            mock.on_instruction_containing("Listen on port")
                .and_instruction_containing("PostgreSQL")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "PostgreSQL",
                        "instruction": "Answer SELECT queries"
                    }
                ]))
                .expect_calls(1)
                .and()
                // ONE rule branching on the event, not two rules on the same event: rules are
                // first-match-wins, so a second rule for the follow-up would report zero calls
                // while the first answered everything.
                .on_event("postgresql_query")
                .respond_with_actions_from_event(|e| {
                    let query = e["query"].as_str().unwrap_or("").to_uppercase();
                    let value = if query.contains("SECOND") { 2 } else { 1 };
                    serde_json::json!([
                        {
                            "type": "postgresql_query_response",
                            "columns": [{"name": "n", "type": "int4"}],
                            "rows": [[value]]
                        }
                    ])
                })
                // The assertion: 1 query from the connect event + 4 bounded follow-ups.
                .expect_calls(5)
                .and()
        });

        let mut server = start_netget_server(server_config).await?;
        server.wait_for_any(&["listening", "Running"], 30).await;

        let client_config = NetGetConfig::new(format!(
            "Connect to 127.0.0.1:{} via PostgreSQL. Query, then query again.",
            server.port
        ))
        .with_mock(|mock| {
            mock.on_instruction_containing("Connect to")
                .and_instruction_containing("PostgreSQL")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_client",
                        "remote_addr": format!("127.0.0.1:{}", server.port),
                        "protocol": "PostgreSQL",
                        "instruction": "Query, then query again"
                    }
                ]))
                .expect_calls(1)
                .and()
                .on_event("postgresql_connected")
                .respond_with_actions(serde_json::json!([
                    { "type": "execute_query", "query": "SELECT 1 AS first" }
                ]))
                .expect_calls(1)
                .and()
                .on_event("postgresql_query_result")
                .respond_with_actions(serde_json::json!([
                    { "type": "execute_query", "query": "SELECT 2 AS second" }
                ]))
                // Exactly five: one per query. Without the depth bound this never stops.
                .expect_calls(5)
                .and()
        });

        let mut client = start_netget_client(client_config).await?;
        client.wait_for_any(&["connected"], 30).await;

        server.wait_for_mocks(30).await;
        client.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        client.verify_mocks().await?;

        server.stop().await?;
        client.stop().await?;
        Ok(())
    }
}

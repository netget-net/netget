//! E2E tests for MSSQL client
//!
//! These tests verify MSSQL client functionality by spawning the actual NetGet binary
//! and testing client behavior as a black-box.

mod mssql_client_tests {
    use crate::helpers::*;
    use std::time::Duration;

    /// Test MSSQL client connection and query execution with mocks
    /// LLM calls: 6 (server startup, server query response, client startup, client connection, client query result, wait)
    #[tokio::test]
    async fn test_mssql_client_connect_and_query_with_mocks() -> E2EResult<()> {
        println!("\n=== E2E Test: MSSQL Client Connect and Query (Mocked) ===");

        // Start an MSSQL server listening on an available port with mocks
        let server_config = NetGetConfig::new(
            "Listen on port {AVAILABLE_PORT} via MSSQL. For SELECT 1 query, respond with result 1.",
        )
        .with_mock(|mock| {
            mock
                // Mock 1: Server startup
                .on_instruction_containing("Listen on port")
                .and_instruction_containing("MSSQL")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "MSSQL",
                        "instruction": "Respond to SELECT 1 with result 1"
                    }
                ]))
                .expect_calls(1)
                .and()
                // The MSSQL server makes login a model decision: `mssql_login_ack` admits the
                // session and nothing else does, so a suite that only mocks `mssql_query` never
                // gets a connection to run a query on.
                .on_event("mssql_login")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "mssql_login_ack"
                    }
                ]))
                .expect_at_least(1)
                .and()
                // Mock 2: SELECT 1 query received
                .on_event("mssql_query")
                .and_event_data_contains("query", "SELECT 1")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "mssql_query_response",
                        "columns": [{"name": "result", "type": "INT"}],
                        "rows": [[1]]
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let server = start_netget_server(server_config).await?;
        println!("Server started on port {}", server.port);

        // Give server time to start
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Now start an MSSQL client that connects and sends a query
        let client_config = NetGetConfig::new(format!(
            "Connect to 127.0.0.1:{} via MSSQL. Execute SELECT 1 query.",
            server.port
        ))
        .with_mock(|mock| {
            mock
                // Mock 1: Client startup
                .on_instruction_containing("Connect to")
                .and_instruction_containing("MSSQL")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_client",
                        "remote_addr": format!("127.0.0.1:{}", server.port),
                        "protocol": "MSSQL",
                        "instruction": "Execute SELECT 1 query"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2: MSSQL connected event
                .on_event("mssql_connected")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "execute_query",
                        "query": "SELECT 1"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 3: MSSQL query result received
                .on_event("mssql_query_result")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "wait_for_more"
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let client = start_netget_client(client_config).await?;
        println!("Client started");

        // Give client time to connect and execute query
        tokio::time::sleep(Duration::from_millis(1000)).await;

        // Verify client output shows connection
        client.wait_for_any(&["connected"], 30).await;
        assert!(
            client.output_contains("connected").await,
            "Client should show connection message. Output: {:?}",
            client.get_output().await
        );

        println!("✅ MSSQL client connected and executed query successfully");

        // Verify mock expectations were met
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last response routinely lands
        // after the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        client.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        client.verify_mocks().await?;

        // Cleanup
        server.stop().await?;
        client.stop().await?;

        Ok(())
    }

    /// Test MSSQL client can execute multi-row queries with mocks
    /// LLM calls: 6 (server startup, server query response, client startup, client connection, client query result, wait)
    #[tokio::test]
    async fn test_mssql_client_multi_row_query_with_mocks() -> E2EResult<()> {
        println!("\n=== E2E Test: MSSQL Client Multi-Row Query (Mocked) ===");

        // Start an MSSQL server with multi-row response
        let server_config = NetGetConfig::new(
            "Listen on port {AVAILABLE_PORT} via MSSQL. For SELECT * FROM users, return 3 users.",
        )
        .with_mock(|mock| {
            mock
                // Mock 1: Server startup
                .on_instruction_containing("MSSQL")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "MSSQL",
                        "instruction": "Return 3 users for SELECT * FROM users"
                    }
                ]))
                .expect_calls(1)
                .and()
                // The MSSQL server makes login a model decision: `mssql_login_ack` admits the
                // session and nothing else does, so a suite that only mocks `mssql_query` never
                // gets a connection to run a query on.
                .on_event("mssql_login")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "mssql_login_ack"
                    }
                ]))
                .expect_at_least(1)
                .and()
                // Mock 2: SELECT * FROM users query
                .on_event("mssql_query")
                .and_event_data_contains("query", "SELECT * FROM users")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "mssql_query_response",
                        "columns": [
                            {"name": "id", "type": "INT"},
                            {"name": "name", "type": "NVARCHAR"}
                        ],
                        "rows": [
                            [1, "Alice"],
                            [2, "Bob"],
                            [3, "Charlie"]
                        ]
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let server = start_netget_server(server_config).await?;
        println!("Server started on port {}", server.port);

        tokio::time::sleep(Duration::from_millis(500)).await;

        // Client that queries for users
        let client_config = NetGetConfig::new(format!(
            "Connect to 127.0.0.1:{} via MSSQL. Query SELECT * FROM users.",
            server.port
        ))
        .with_mock(|mock| {
            mock.on_instruction_containing("MSSQL")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_client",
                        "remote_addr": format!("127.0.0.1:{}", server.port),
                        "protocol": "MSSQL",
                        "instruction": "Query SELECT * FROM users"
                    }
                ]))
                .expect_calls(1)
                .and()
                .on_event("mssql_connected")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "execute_query",
                        "query": "SELECT * FROM users"
                    }
                ]))
                .expect_calls(1)
                .and()
                .on_event("mssql_query_result")
                .and_event_data_contains("rows", "Alice")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "wait_for_more"
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let client = start_netget_client(client_config).await?;
        println!("Client started");

        tokio::time::sleep(Duration::from_millis(1000)).await;

        // Verify client received data
        client.wait_for_any(&["connected"], 30).await;
        assert!(
            client.output_contains("connected").await,
            "Client should show connection. Output: {:?}",
            client.get_output().await
        );

        println!("✅ MSSQL client executed multi-row query successfully");

        // Verify mock expectations
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last response routinely lands
        // after the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        client.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        client.verify_mocks().await?;

        // Cleanup
        server.stop().await?;
        client.stop().await?;

        Ok(())
    }
}

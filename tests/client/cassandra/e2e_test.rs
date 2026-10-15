//! E2E tests for Cassandra client
//!
//! These tests verify Cassandra client functionality by spawning the actual NetGet binary
//! and testing client behavior as a black-box.

mod cassandra_client_tests {
    use crate::helpers::*;
    use std::time::Duration;

    /// Test Cassandra client connection and query execution
    /// LLM calls: 3 (server startup, client connection, query execution)
    #[tokio::test]
    async fn test_cassandra_client_connect_and_query() -> E2EResult<()> {
        // Start a Cassandra server listening on an available port with mocks
        let server_config = NetGetConfig::new(
            "Listen on port {AVAILABLE_PORT} via Cassandra. Accept CQL queries. For SELECT * FROM system.local, return a result set with host_id and cluster_name columns.",
        )
            .with_mock(|mock| {
                mock
                    // Mock 1: Server startup
                    .on_instruction_containing("Cassandra")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "open_server",
                            "port": 0,
                            "base_stack": "Cassandra",
                            "instruction": "Accept CQL queries and respond to SELECT * FROM system.local"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // Mock 2: the CQL handshake. STARTUP must be answered with
                    // cassandra_ready and OPTIONS with cassandra_supported, or the server
                    // fails closed and the driver never finishes connecting -- so
                    // cassandra_connected never fires and every later rule sees 0 calls.
                    // The scylla driver opens more than one connection (a control
                    // connection plus a data connection), so STARTUP arrives more than
                    // once. Pinning this to exactly 1 fails on the driver's own behaviour.
                    .on_event("cassandra_startup")
                    .respond_with_actions(serde_json::json!([
                        { "type": "cassandra_ready" }
                    ]))
                    .expect_at_least(1)
                    .and()
                    .on_event("cassandra_options")
                    .respond_with_actions(serde_json::json!([
                        { "type": "cassandra_supported" }
                    ]))
                    .expect_at_least(0)
                    .and()
                    // Mock 3: Query received from client. The event is `cassandra_query`;
                    // `cassandra_query_received` was never an event this server raises, so
                    // this rule could not match and the query went unanswered.
                    .on_event("cassandra_query")
                    .and_event_data_contains("query", "SELECT * FROM system.local")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "cassandra_result_rows",
                            "columns": [
                                {"name": "host_id", "type": "uuid"},
                                {"name": "cluster_name", "type": "varchar"}
                            ],
                            "rows": [
                                ["550e8400-e29b-41d4-a716-446655440000", "Test Cluster"]
                            ]
                        }
                    ]))
                    .expect_at_least(1)
                    .and()
                    // The scylla driver's control connection issues its own queries
                    // before the test's -- system.local WHERE key='local', system.peers,
                    // system_schema.types -- and they arrive as `cassandra_query` too.
                    // With no rule to match, mock_ollama answers 500, the server replies
                    // with a CQL ERROR frame, and the session never establishes: the
                    // circuit breaker then opens and every later expectation reports 0.
                    // Empty rows are enough for the driver, which is what the server-side
                    // suite does. Unconstrained, so it must stay last.
                    .on_event("cassandra_query")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "cassandra_result_rows",
                            "columns": [],
                            "rows": []
                        }
                    ]))
                    .expect_at_least(0)
                    .and()
            });

        let mut server = start_netget_server(server_config).await?;

        // Give server time to start
        tokio::time::sleep(Duration::from_millis(1000)).await;

        // Now start a Cassandra client that connects and sends a query with mocks
        let client_config = NetGetConfig::new(format!(
            "Connect to 127.0.0.1:{} via Cassandra. Execute 'SELECT * FROM system.local' query.",
            server.port
        ))
        .with_mock(|mock| {
            mock
                // Mock 1: Client startup
                .on_instruction_containing("Connect to")
                .and_instruction_containing("Cassandra")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_client",
                        "remote_addr": format!("127.0.0.1:{}", server.port),
                        "protocol": "Cassandra",
                        "instruction": "Execute SELECT * FROM system.local query"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2: Client connected
                .on_event("cassandra_connected")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "execute_cql_query",
                        "query": "SELECT * FROM system.local"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 3: Response received
                .on_event("cassandra_result_received")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "wait_for_more"
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let mut client = start_netget_client(client_config).await?;

        // Give client time to connect and execute query
        tokio::time::sleep(Duration::from_millis(1000)).await;

        // Verify client output shows connection
        client.wait_for_any(&["connected"], 30).await;
        assert!(
            client.output_contains("connected").await,
            "Client should show connection message. Output: {:?}",
            client.get_output().await
        );

        println!("✅ Cassandra client connected and executed query successfully");

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

    /// Test Cassandra client with consistency level
    /// LLM calls: 3 (server startup, client connection, query with consistency)
    #[tokio::test]
    async fn test_cassandra_client_with_consistency() -> E2EResult<()> {
        // Start a Cassandra server with mocks
        let server_config = NetGetConfig::new(
            "Listen on port {AVAILABLE_PORT} via Cassandra. Accept CQL queries and log consistency levels.",
        )
            .with_mock(|mock| {
                mock
                    // Mock 1: Server startup
                    .on_instruction_containing("Cassandra")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "open_server",
                            "port": 0,
                            "base_stack": "Cassandra",
                            "instruction": "Accept CQL queries and log consistency levels"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // Every CQL connection opens with OPTIONS then STARTUP. Without
                    // rules for both, mock_ollama answers 500, the server sends a CQL
                    // ERROR frame and the driver never gets a session -- so the client
                    // fails to connect and `cassandra_connected` never fires.
                    .on_event("cassandra_options")
                    .respond_with_actions(serde_json::json!([
                        { "type": "cassandra_supported" }
                    ]))
                    .expect_at_least(0)
                    .and()
                    .on_event("cassandra_startup")
                    .respond_with_actions(serde_json::json!([
                        { "type": "cassandra_ready" }
                    ]))
                    .expect_at_least(0)
                    .and()
                    // Mock 2: Query received with consistency level
                    .on_event("cassandra_query")
                    .and_event_data_contains("query", "SELECT * FROM system.local")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "cassandra_result_rows",
                            "columns": [
                                {"name": "host_id", "type": "uuid"},
                                {"name": "cluster_name", "type": "varchar"}
                            ],
                            "rows": [
                                ["550e8400-e29b-41d4-a716-446655440000", "Test Cluster"]
                            ]
                        }
                    ]))
                    .expect_at_least(1)
                    .and()
                    // The scylla driver's control connection issues its own queries
                    // before the test's -- system.local WHERE key='local', system.peers,
                    // system_schema.types -- and they arrive as `cassandra_query` too.
                    // With no rule to match, mock_ollama answers 500, the server replies
                    // with a CQL ERROR frame, and the session never establishes: the
                    // circuit breaker then opens and every later expectation reports 0.
                    // Empty rows are enough for the driver, which is what the server-side
                    // suite does. Unconstrained, so it must stay last.
                    .on_event("cassandra_query")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "cassandra_result_rows",
                            "columns": [],
                            "rows": []
                        }
                    ]))
                    .expect_at_least(0)
                    .and()
            });

        let mut server = start_netget_server(server_config).await?;

        tokio::time::sleep(Duration::from_millis(1000)).await;

        // Client with specific consistency level instruction with mocks
        let client_config = NetGetConfig::new(format!(
            "Connect to 127.0.0.1:{} via Cassandra. Execute 'SELECT * FROM system.local' with QUORUM consistency.",
            server.port
        ))
            .with_mock(|mock| {
                mock
                    // Mock 1: Client startup
                    .on_instruction_containing("Connect to")
                    .and_instruction_containing("Cassandra")
                    .and_instruction_containing("QUORUM")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "open_client",
                            "remote_addr": format!("127.0.0.1:{}", server.port),
                            "protocol": "Cassandra",
                            "instruction": "Execute SELECT with QUORUM consistency"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // Mock 2: Client connected
                    .on_event("cassandra_connected")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "execute_cql_query",
                            "query": "SELECT * FROM system.local",
                            "consistency": "QUORUM"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // Mock 3: Response received
                    .on_event("cassandra_result_received")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "wait_for_more"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
            });

        let mut client = start_netget_client(client_config).await?;

        tokio::time::sleep(Duration::from_millis(1000)).await;

        // Verify the client is Cassandra protocol
        assert_eq!(
            client.protocol, "Cassandra",
            "Client should be Cassandra protocol"
        );

        println!("✅ Cassandra client executed query with consistency level");

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

    /// Test Cassandra client multi-step query execution
    /// LLM calls: 4+ (server startup, client connection, multiple queries)
    #[tokio::test]
    async fn test_cassandra_client_multi_query() -> E2EResult<()> {
        // Start a Cassandra server that handles multiple queries with mocks
        let server_config = NetGetConfig::new(
            "Listen on port {AVAILABLE_PORT} via Cassandra. Accept CQL queries. For SELECT queries, return mock results.",
        )
            .with_mock(|mock| {
                mock
                    // Mock 1: Server startup
                    .on_instruction_containing("Cassandra")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "open_server",
                            "port": 0,
                            "base_stack": "Cassandra",
                            "instruction": "Accept CQL queries and return mock results"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // Every CQL connection opens with OPTIONS then STARTUP. Without
                    // rules for both, mock_ollama answers 500, the server sends a CQL
                    // ERROR frame and the driver never gets a session -- so the client
                    // fails to connect and `cassandra_connected` never fires.
                    .on_event("cassandra_options")
                    .respond_with_actions(serde_json::json!([
                        { "type": "cassandra_supported" }
                    ]))
                    .expect_at_least(0)
                    .and()
                    .on_event("cassandra_startup")
                    .respond_with_actions(serde_json::json!([
                        { "type": "cassandra_ready" }
                    ]))
                    .expect_at_least(0)
                    .and()
                    // Mock 2: First query (system.local)
                    .on_event("cassandra_query")
                    .and_event_data_contains("query", "system.local")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "cassandra_result_rows",
                            "columns": [
                                {"name": "host_id", "type": "uuid"}
                            ],
                            "rows": [
                                ["550e8400-e29b-41d4-a716-446655440000"]
                            ]
                        }
                    ]))
                    .expect_at_least(1)
                    .and()
                    // Mock 3: Second query (system.peers)
                    .on_event("cassandra_query")
                    .and_event_data_contains("query", "system.peers")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "cassandra_result_rows",
                            "columns": [
                                {"name": "peer", "type": "inet"}
                            ],
                            "rows": [
                                ["127.0.0.2"]
                            ]
                        }
                    ]))
                    .expect_at_least(1)
                    .and()
                    // The scylla driver's control connection issues its own queries
                    // before the test's -- system.local WHERE key='local', system.peers,
                    // system_schema.types -- and they arrive as `cassandra_query` too.
                    // With no rule to match, mock_ollama answers 500, the server replies
                    // with a CQL ERROR frame, and the session never establishes: the
                    // circuit breaker then opens and every later expectation reports 0.
                    // Empty rows are enough for the driver, which is what the server-side
                    // suite does. Unconstrained, so it must stay last.
                    .on_event("cassandra_query")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "cassandra_result_rows",
                            "columns": [],
                            "rows": []
                        }
                    ]))
                    .expect_at_least(0)
                    .and()
            });

        let mut server = start_netget_server(server_config).await?;

        tokio::time::sleep(Duration::from_millis(1000)).await;

        // Client that executes multiple queries with mocks
        let client_config = NetGetConfig::new(format!(
            "Connect to 127.0.0.1:{} via Cassandra. First, query system.local. Then query system.peers.",
            server.port
        ))
            .with_mock(|mock| {
                mock
                    // Mock 1: Client startup
                    .on_instruction_containing("Connect to")
                    .and_instruction_containing("Cassandra")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "open_client",
                            "remote_addr": format!("127.0.0.1:{}", server.port),
                            "protocol": "Cassandra",
                            "instruction": "Query system.local then system.peers"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // Mock 2: Client connected - send first query
                    .on_event("cassandra_connected")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "execute_cql_query",
                            "query": "SELECT * FROM system.local"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // Mock 3: both responses, told apart by what came back.
                    //
                    // This was two rules on `cassandra_result_received` with nothing to
                    // distinguish them. Rules are first-match-wins, so the first one won
                    // every time: it answered each result with another query, which
                    // produced another result, forever -- 99 calls before the test gave
                    // up, and the second rule never matched at all. One rule that branches
                    // on the event is the only way to express "then" here.
                    .on_event("cassandra_result_received")
                    .respond_with_actions_from_event(|e| {
                        let rows = e["rows"].to_string();
                        if rows.contains("127.0.0.2") {
                            // system.peers came back: the chain is done.
                            serde_json::json!([{ "type": "wait_for_more" }])
                        } else {
                            serde_json::json!([
                                {
                                    "type": "execute_cql_query",
                                    "query": "SELECT * FROM system.peers"
                                }
                            ])
                        }
                    })
                    // Two results: system.local, then system.peers.
                    .expect_calls(2)
                    .and()
            });

        let mut client = start_netget_client(client_config).await?;

        tokio::time::sleep(Duration::from_millis(2000)).await;

        // Verify client connected
        client.wait_for_any(&["connected"], 30).await;
        assert!(
            client.output_contains("connected").await,
            "Client should show connection. Output: {:?}",
            client.get_output().await
        );

        println!("✅ Cassandra client executed multiple queries");

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
}

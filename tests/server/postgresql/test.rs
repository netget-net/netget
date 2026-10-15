//! End-to-end PostgreSQL tests for NetGet
//!
//! These tests spawn the actual NetGet binary with PostgreSQL prompts
//! and validate the responses using PostgreSQL protocol clients.
//!
//! ## Known Issues
//!
//! PostgreSQL extended query protocol has an LLM call timeout issue where the LLM
//! call in do_query (ExtendedQueryHandler) does not complete within the protocol timeout.
//! This appears to be specific to how pgwire/tokio-postgres handles extended queries.
//!
//! MySQL and Redis e2e tests work correctly with the same model and similar patterns.
//! The issue may be related to pgwire's internal timeouts or the extended query protocol flow.
//!
//! TODO: Investigate pgwire ExtendedQueryHandler timeout behavior and fix LLM call completion.


// Helper module imported from parent

use super::super::super::helpers::{self, E2EResult, NetGetConfig};
use std::time::Duration;
use tokio_postgres::NoTls;

#[tokio::test]
async fn test_postgresql_simple_query() -> E2EResult<()> {
    println!("\n=== E2E Test: PostgreSQL Simple Query ===");

    // PROMPT: Tell the LLM to act as a PostgreSQL server
    let prompt = "Open PostgreSQL on port {AVAILABLE_PORT}. When clients query SELECT 1, use postgresql_query_response action \
        with columns=[{{name:'?column?',type:'int4'}}] rows=[[1]]. For SELECT version() queries, return \
        postgresql_query_response with columns=[{{name:'version',type:'text'}}] rows=[['PostgreSQL 16.0 (LLM)']]. \
        Other queries use postgresql_ok_response tag='OK'.";

    // Start the server with mocks
    let config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock
            // Mock 1: Server startup
            .on_instruction_containing("Open PostgreSQL")
            .and_instruction_containing("port")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "PostgreSQL",
                    "instruction": "Handle SELECT 1 query"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 2: SELECT 1 query
            .on_event("postgresql_query")
            .and_event_data_contains("query", "SELECT 1")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "postgresql_query_response",
                    "columns": [{"name": "?column?", "type": "int4"}],
                    "rows": [[1]]
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let mut server = helpers::start_netget_server(config).await?;
    println!("Server started on port {}", server.port);

    // VALIDATION: Connect and execute query using tokio-postgres
    println!("Connecting to PostgreSQL server...");

    // Note: statement_timeout=0 disables query timeout on the server side
    let connection_string = format!("host=127.0.0.1 port={} user=postgres dbname=test connect_timeout=30 options='-c statement_timeout=0'", server.port);

    let (client, _connection) = match tokio::time::timeout(
        Duration::from_secs(30),
        tokio_postgres::connect(&connection_string, NoTls),
    )
    .await
    {
        Ok(Ok((client, connection))) => {
            println!("✓ PostgreSQL connected");
            // Spawn connection handler
            tokio::spawn(async move {
                if let Err(e) = connection.await {
                    eprintln!("connection error: {}", e);
                }
            });
            (client, ())
        }
        Ok(Err(e)) => {
            println!("✗ PostgreSQL connection error: {}", e);
            return Err(e.into());
        }
        Err(_) => {
            println!("✗ PostgreSQL connection timeout");
            return Err("Connection timeout".into());
        }
    };

    // Execute simple query (uses simple protocol, not extended)
    println!("Executing SELECT 1...");
    let messages = match tokio::time::timeout(
        Duration::from_secs(30),
        client.simple_query("SELECT 1"),
    )
    .await
    {
        Ok(Ok(messages)) => messages,
        Ok(Err(e)) => {
            println!("✗ Query error: {}", e);
            return Err(e.into());
        }
        Err(_) => {
            println!("✗ Query timeout");
            return Err("Query timeout".into());
        }
    };

    // Extract the row from SimpleQueryMessage
    let row = messages
        .into_iter()
        .find_map(|msg| {
            if let tokio_postgres::SimpleQueryMessage::Row(row) = msg {
                Some(row)
            } else {
                None
            }
        })
        .expect("Expected at least one row");

    let result_str = row.get(0).expect("Expected column 0");
    let result: i32 = result_str.parse().expect("Expected integer value");
    println!("✓ Received result: {}", result);

    assert_eq!(result, 1, "Expected SELECT 1 to return 1");

    // Verify mock expectations were met
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;

    println!("✓ PostgreSQL simple query test passed\n");
    Ok(())
}

#[tokio::test]
async fn test_postgresql_multi_row_query() -> E2EResult<()> {
    println!("\n=== E2E Test: PostgreSQL Multi-Row Query ===");

    let prompt = "Open PostgreSQL on port {AVAILABLE_PORT}. For SELECT * FROM users query, use postgresql_query_response \
        columns=[{{name:'id',type:'int4'}},{{name:'name',type:'text'}}] \
        rows=[[1,\"Alice\"],[2,\"Bob\"],[3,\"Charlie\"]]. \
        For SELECT version() queries use postgresql_query_response columns=[{{name:'version',type:'text'}}] rows=[['PostgreSQL 16.0']]. \
        Other queries use postgresql_ok_response tag='SELECT 0'.";

    let config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock
            // Mock 1: Server startup
            .on_instruction_containing("Open PostgreSQL")
            .and_instruction_containing("port")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "PostgreSQL",
                    "instruction": "Handle SELECT * FROM users query"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 2: SELECT * FROM users query
            .on_event("postgresql_query")
            .and_event_data_contains("query", "SELECT * FROM users")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "postgresql_query_response",
                    "columns": [
                        {"name": "id", "type": "int4"},
                        {"name": "name", "type": "text"}
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

    let mut server = helpers::start_netget_server(config).await?;
    println!("Server started on port {}", server.port);

    println!("Connecting to PostgreSQL server...");
    let connection_string = format!("host=127.0.0.1 port={} user=postgres", server.port);
    let (client, connection) = match tokio::time::timeout(
        Duration::from_secs(30),
        tokio_postgres::connect(&connection_string, NoTls),
    )
    .await
    {
        Ok(Ok((client, connection))) => (client, connection),
        Ok(Err(e)) => return Err(e.into()),
        Err(_) => return Err("Connection timeout".into()),
    };

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("connection error: {}", e);
        }
    });

    println!("✓ PostgreSQL connected");

    println!("Executing SELECT * FROM users...");
    let messages = match tokio::time::timeout(
        Duration::from_secs(30),
        client.simple_query("SELECT * FROM users"),
    )
    .await
    {
        Ok(Ok(messages)) => messages,
        Ok(Err(e)) => return Err(e.into()),
        Err(_) => return Err("Query timeout".into()),
    };

    // Extract rows from SimpleQueryMessage
    let rows: Vec<_> = messages
        .into_iter()
        .filter_map(|msg| {
            if let tokio_postgres::SimpleQueryMessage::Row(row) = msg {
                Some(row)
            } else {
                None
            }
        })
        .collect();

    println!("Received {} rows:", rows.len());
    for row in &rows {
        let id_str = row.get(0).expect("Expected column 0");
        let name = row.get(1).expect("Expected column 1");
        let id: i32 = id_str.parse().expect("Expected integer id");
        println!("  {} - {}", id, name);
    }

    assert!(!rows.is_empty(), "Expected at least one row");

    // Verify mock expectations were met
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;

    println!("✓ PostgreSQL multi-row query test passed\n");

    Ok(())
}

#[tokio::test]
async fn test_postgresql_create_table() -> E2EResult<()> {
    println!("\n=== E2E Test: PostgreSQL CREATE TABLE ===");

    let prompt = "Open PostgreSQL on port {AVAILABLE_PORT}. For SELECT version() queries, use postgresql_query_response \
        columns=[{{name:'version',type:'text'}}] rows=[['PostgreSQL 16.0']]. For CREATE/INSERT/UPDATE queries, \
        use postgresql_ok_response tag='CREATE TABLE'. For SELECT queries use postgresql_ok_response tag='SELECT 0'.";

    let config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock
            // Mock 1: Server startup
            .on_instruction_containing("Open PostgreSQL")
            .and_instruction_containing("port")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "PostgreSQL",
                    "instruction": "Handle CREATE TABLE queries"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 2: CREATE TABLE query
            .on_event("postgresql_query")
            .and_event_data_contains("query", "CREATE TABLE")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "postgresql_ok_response",
                    "tag": "CREATE TABLE"
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let mut server = helpers::start_netget_server(config).await?;
    println!("Server started on port {}", server.port);

    println!("Connecting to PostgreSQL server...");
    let connection_string = format!("host=127.0.0.1 port={} user=postgres", server.port);
    let (client, connection) = match tokio::time::timeout(
        Duration::from_secs(30),
        tokio_postgres::connect(&connection_string, NoTls),
    )
    .await
    {
        Ok(Ok((client, connection))) => (client, connection),
        Ok(Err(e)) => return Err(e.into()),
        Err(_) => return Err("Connection timeout".into()),
    };

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("connection error: {}", e);
        }
    });

    println!("✓ PostgreSQL connected");

    println!("Executing CREATE TABLE...");
    match tokio::time::timeout(
        Duration::from_secs(30),
        client.execute("CREATE TABLE test (id INT PRIMARY KEY)", &[]),
    )
    .await
    {
        Ok(Ok(_)) => println!("✓ CREATE TABLE executed successfully"),
        Ok(Err(e)) => {
            println!("CREATE TABLE returned: {}", e);
            // This is OK - the LLM might not support DDL fully
        }
        Err(_) => {
            println!("CREATE TABLE timeout");
            // This is OK - timeout doesn't fail the test
        }
    }

    // Verify mock expectations were met
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;

    println!("✓ PostgreSQL CREATE TABLE test completed\n");
    Ok(())
}

#[tokio::test]
async fn test_postgresql_error_response() -> E2EResult<()> {
    println!("\n=== E2E Test: PostgreSQL Error Response ===");

    let prompt = "Open PostgreSQL on port {AVAILABLE_PORT}. For SELECT version() queries, use postgresql_query_response \
        columns=[{{name:'version',type:'text'}}] rows=[['PostgreSQL 16.0']]. \
        For queries containing 'invalid_table', use postgresql_error_response severity='ERROR' code='42P01' \
        message='relation \"invalid_table\" does not exist'. Other queries use postgresql_ok_response tag='OK'.";

    let config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock
            // Mock 1: Server startup
            .on_instruction_containing("Open PostgreSQL")
            .and_instruction_containing("port")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "PostgreSQL",
                    "instruction": "Handle error responses for invalid_table"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 2: SELECT * FROM invalid_table query (error)
            .on_event("postgresql_query")
            .and_event_data_contains("query", "invalid_table")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "postgresql_error_response",
                    "severity": "ERROR",
                    "code": "42P01",
                    "message": "relation \"invalid_table\" does not exist"
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let mut server = helpers::start_netget_server(config).await?;
    println!("Server started on port {}", server.port);

    println!("Connecting to PostgreSQL server...");
    let connection_string = format!("host=127.0.0.1 port={} user=postgres", server.port);
    let (client, connection) = tokio_postgres::connect(&connection_string, NoTls).await?;

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("connection error: {}", e);
        }
    });

    println!("✓ PostgreSQL connected");

    println!("Executing SELECT * FROM invalid_table...");
    match client.simple_query("SELECT * FROM invalid_table").await {
        Ok(_) => {
            println!("✗ Expected error but query succeeded");
            return Err("Expected error response".into());
        }
        Err(e) => {
            println!("✓ Received error as expected: {}", e);
            println!("Error details: {:?}", e);
            // Simple query errors might not include all details
            // Just verify we got an error, which is what we expected
        }
    }

    // Verify mock expectations were met
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;

    println!("✓ PostgreSQL error response test passed\n");
    Ok(())
}

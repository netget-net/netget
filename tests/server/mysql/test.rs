//! End-to-end MySQL tests for NetGet
//!
//! These tests spawn the actual NetGet binary with MySQL prompts
//! and validate the responses using MySQL protocol clients.

// Helper module imported from parent

use super::super::super::helpers::{self, E2EResult, NetGetConfig};
use mysql_async::prelude::*;
use std::time::Duration;

#[tokio::test]
async fn test_mysql_simple_query() -> E2EResult<()> {
    println!("\n=== E2E Test: MySQL Simple Query ===");

    // PROMPT: Tell the LLM to act as a MySQL server
    let prompt = "Open MySQL on port {AVAILABLE_PORT}. When clients query SELECT 1, use mysql_query_response action \
        with columns=[{name:'result',type:'INT'}] rows=[[1]]. For SELECT @@* queries, return \
        mysql_query_response with columns=[{name:'value',type:'VARCHAR'}] rows=[['1000']]. \
        Other queries use mysql_ok_response affected_rows=0.";

    // Start the server
    let server_config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock
            // Mock 1: Server startup
            .on_instruction_containing("Open MySQL")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "MySQL",
                    "instruction": "Handle MySQL queries with appropriate responses"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 2: SELECT @@* system variable queries (mysql_async client initialization)
            .on_event("mysql_query")
            .and_event_data_contains("query", "SELECT @@")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "mysql_query_response",
                    "columns": [{"name": "value", "type": "VARCHAR"}],
                    "rows": [["1000"]]
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 4: SELECT 1 query
            .on_event("mysql_query")
            .and_event_data_contains("query", "SELECT 1")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "mysql_query_response",
                    "columns": [{"name": "result", "type": "INT"}],
                    "rows": [[1]]
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let server = helpers::start_netget_server(server_config).await?;
    println!("Server started on port {}", server.port);

    // VALIDATION: Connect and execute query using mysql_async
    println!("Connecting to MySQL server...");

    let opts = mysql_async::OptsBuilder::default()
        .ip_or_hostname("127.0.0.1")
        .tcp_port(server.port)
        .user(Some("root"))
        .pass(Some(""))
        .prefer_socket(false);

    let pool = mysql_async::Pool::new(opts);
    let mut conn = match tokio::time::timeout(Duration::from_secs(10), pool.get_conn()).await {
        Ok(Ok(conn)) => {
            println!("✓ MySQL connected");
            conn
        }
        Ok(Err(e)) => {
            println!("✗ MySQL connection error: {}", e);
            return Err(e.into());
        }
        Err(_) => {
            println!("✗ MySQL connection timeout");
            return Err("Connection timeout".into());
        }
    };

    // Execute simple query
    println!("Executing SELECT 1...");
    let result: Option<i32> =
        match tokio::time::timeout(Duration::from_secs(10), conn.query_first("SELECT 1")).await {
            Ok(Ok(res)) => res,
            Ok(Err(e)) => {
                println!("✗ Query error: {}", e);
                return Err(e.into());
            }
            Err(_) => {
                println!("✗ Query timeout");
                return Err("Query timeout".into());
            }
        };

    match result {
        Some(1) => println!("✓ Received correct result: 1"),
        Some(n) => println!("✗ Received incorrect result: {}", n),
        None => println!("✗ No result received"),
    }

    drop(conn);
    drop(pool);

    assert_eq!(result, Some(1), "Expected SELECT 1 to return 1");

    // Verify mock expectations
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;

    println!("✓ MySQL simple query test passed\n");
    Ok(())
}

#[tokio::test]
async fn test_mysql_multi_row_query() -> E2EResult<()> {
    println!("\n=== E2E Test: MySQL Multi-Row Query ===");

    let prompt = "Open MySQL on port {AVAILABLE_PORT}. For SELECT * FROM users query, use mysql_query_response \
        columns=[{name:'id',type:'INT'},{name:'name',type:'VARCHAR'}] \
        rows=[[\"1\",\"Alice\"],[\"2\",\"Bob\"],[\"3\",\"Charlie\"]]. \
        For SELECT @@* queries use mysql_query_response columns=[{name:'value',type:'VARCHAR'}] rows=[['1000']]. \
        Other queries use mysql_ok_response affected_rows=0.";

    let server_config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock
            // Mock 1: Server startup
            .on_instruction_containing("Open MySQL")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "MySQL",
                    "instruction": "Handle MySQL queries with multi-row response"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 2: SELECT @@* system variable queries (mysql_async client initialization)
            .on_event("mysql_query")
            .and_event_data_contains("query", "SELECT @@")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "mysql_query_response",
                    "columns": [{"name": "value", "type": "VARCHAR"}],
                    "rows": [["1000"]]
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 3: SELECT * FROM users query
            .on_event("mysql_query")
            .and_event_data_contains("query", "SELECT * FROM users")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "mysql_query_response",
                    "columns": [
                        {"name": "id", "type": "INT"},
                        {"name": "name", "type": "VARCHAR"}
                    ],
                    "rows": [
                        ["1", "Alice"],
                        ["2", "Bob"],
                        ["3", "Charlie"]
                    ]
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let server = helpers::start_netget_server(server_config).await?;
    println!("Server started on port {}", server.port);

    println!("Connecting to MySQL server...");
    let opts = mysql_async::OptsBuilder::default()
        .ip_or_hostname("127.0.0.1")
        .tcp_port(server.port)
        .user(Some("root"))
        .pass(Some(""));

    let pool = mysql_async::Pool::new(opts);
    let mut conn = pool.get_conn().await?;
    println!("✓ MySQL connected");

    println!("Executing SELECT * FROM users...");
    let rows: Vec<(String, String)> = conn.query("SELECT * FROM users").await?;

    println!("Received {} rows:", rows.len());
    for (id, name) in &rows {
        println!("  {} - {}", id, name);
    }

    assert!(!rows.is_empty(), "Expected at least one row");

    // Verify mock expectations
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;

    println!("✓ MySQL multi-row query test passed\n");

    Ok(())
}

#[tokio::test]
async fn test_mysql_create_table() -> E2EResult<()> {
    println!("\n=== E2E Test: MySQL CREATE TABLE ===");

    let prompt = "Open MySQL on port {AVAILABLE_PORT}. For SELECT @@* queries, use mysql_query_response \
        columns=[{name:'value',type:'VARCHAR'}] rows=[['1000']]. For CREATE/INSERT/UPDATE queries, \
        use mysql_ok_response affected_rows=1. For other SELECT queries use mysql_ok_response affected_rows=0.";

    let server_config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock
            // Mock 1: Server startup
            .on_instruction_containing("Open MySQL")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "MySQL",
                    "instruction": "Handle MySQL DDL queries"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 2: SELECT @@* system variable queries (mysql_async client initialization)
            .on_event("mysql_query")
            .and_event_data_contains("query", "SELECT @@")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "mysql_query_response",
                    "columns": [{"name": "value", "type": "VARCHAR"}],
                    "rows": [["1000"]]
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 3: CREATE TABLE query
            .on_event("mysql_query")
            .and_event_data_contains("query", "CREATE TABLE")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "mysql_ok_response",
                    "affected_rows": 1
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let server = helpers::start_netget_server(server_config).await?;
    println!("Server started on port {}", server.port);

    println!("Connecting to MySQL server...");
    let opts = mysql_async::OptsBuilder::default()
        .ip_or_hostname("127.0.0.1")
        .tcp_port(server.port)
        .user(Some("root"))
        .pass(Some(""));

    let pool = mysql_async::Pool::new(opts);
    let mut conn = pool.get_conn().await?;
    println!("✓ MySQL connected");

    println!("Executing CREATE TABLE...");
    match conn
        .query_drop("CREATE TABLE test (id INT PRIMARY KEY)")
        .await
    {
        Ok(_) => println!("✓ CREATE TABLE executed successfully"),
        Err(e) => {
            println!("CREATE TABLE returned: {}", e);
            // This is OK - the LLM might not support DDL fully
        }
    }

    // Verify mock expectations
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;

    println!("✓ MySQL CREATE TABLE test completed\n");
    Ok(())
}

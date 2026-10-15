//! End-to-end MSSQL tests for NetGet
//!
//! These tests spawn the actual NetGet binary with MSSQL prompts
//! and validate the responses using tiberius TDS protocol client.


use super::super::super::helpers::{self, E2EResult, NetGetConfig};
use std::time::Duration;
use tiberius::{AuthMethod, Client, Config, EncryptionLevel, QueryItem};
use tokio::net::TcpStream;
use tokio_util::compat::TokioAsyncWriteCompatExt;

#[tokio::test]
async fn test_mssql_simple_query() -> E2EResult<()> {
    println!("\n=== E2E Test: MSSQL Simple Query ===");

    // PROMPT: Tell the LLM to act as an MSSQL server (using mssql_ok_response for compatibility)
    let prompt = "Open MSSQL on port {AVAILABLE_PORT}. For all queries, use mssql_ok_response rows_affected=1.";

    // Start the server
    let server_config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock
            // Mock 1: Server startup
            .on_instruction_containing("Open MSSQL")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "MSSQL",
                    "instruction": "Handle MSSQL queries with appropriate responses"
                }
            ]))
            .expect_calls(1)
            .and()
            // The login is now an explicit decision: `mssql_login_ack` admits the session and
            // nothing else does, so every test that wants to run a query has to say so.
            .on_event("mssql_login")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "mssql_login_ack"
                }
            ]))
            .expect_at_least(1)
            .and()
            // Mock 2: SELECT 1 query
            .on_event("mssql_query")
            .and_event_data_contains("query", "SELECT 1")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "mssql_ok_response",
                    "rows_affected": 1
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let server = helpers::start_netget_server(server_config).await?;
    println!("Server started on port {}", server.port);

    // VALIDATION: Connect and execute query using tiberius
    println!("Connecting to MSSQL server...");

    let mut config = Config::new();
    config.host("127.0.0.1");
    config.port(server.port);
    config.authentication(AuthMethod::None);
    config.encryption(EncryptionLevel::NotSupported);

    let tcp = match tokio::time::timeout(
        Duration::from_secs(10),
        TcpStream::connect(("127.0.0.1", server.port)),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => {
            println!("✗ TCP connection error: {}", e);
            return Err(e.into());
        }
        Err(_) => {
            println!("✗ TCP connection timeout");
            return Err("Connection timeout".into());
        }
    };

    let mut client = match tokio::time::timeout(
        Duration::from_secs(10),
        Client::connect(config, tcp.compat_write()),
    )
    .await
    {
        Ok(Ok(c)) => {
            println!("✓ MSSQL connected");
            c
        }
        Ok(Err(e)) => {
            println!("✗ MSSQL connection error: {}", e);
            return Err(e.into());
        }
        Err(_) => {
            println!("✗ MSSQL connection timeout");
            return Err("Connection timeout".into());
        }
    };

    // Execute simple query
    println!("Executing SELECT 1...");
    let query_result =
        match tokio::time::timeout(Duration::from_secs(10), client.query("SELECT 1", &[])).await {
            Ok(Ok(stream)) => {
                println!("✓ Query executed successfully");
                stream
            }
            Ok(Err(e)) => {
                println!("✗ Query error: {}", e);
                return Err(e.into());
            }
            Err(_) => {
                println!("✗ Query timeout");
                return Err("Query timeout".into());
            }
        };

    // Consume the result stream (but don't validate contents since we're using mssql_ok_response)
    let _rows: Vec<_> = query_result.into_results().await?;
    println!("✓ Query results received");

    // Verify mock expectations
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;

    println!("✓ MSSQL simple query test passed\n");
    Ok(())
}

#[tokio::test]
async fn test_mssql_multi_row_query() -> E2EResult<()> {
    println!("\n=== E2E Test: MSSQL Multi-Row Query ===");

    let prompt = "Open MSSQL on port {AVAILABLE_PORT}. For all queries, use mssql_ok_response rows_affected=3.";

    let server_config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock
            // Mock 1: Server startup
            .on_instruction_containing("Open MSSQL")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "MSSQL",
                    "instruction": "Handle MSSQL queries with multi-row response"
                }
            ]))
            .expect_calls(1)
            .and()
            // The login is now an explicit decision: `mssql_login_ack` admits the session and
            // nothing else does, so every test that wants to run a query has to say so.
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
                    "type": "mssql_ok_response",
                    "rows_affected": 3
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let server = helpers::start_netget_server(server_config).await?;
    println!("Server started on port {}", server.port);

    println!("Connecting to MSSQL server...");
    let mut config = Config::new();
    config.host("127.0.0.1");
    config.port(server.port);
    config.authentication(AuthMethod::None);
    config.encryption(EncryptionLevel::NotSupported);

    let tcp = TcpStream::connect(("127.0.0.1", server.port)).await?;
    let mut client = Client::connect(config, tcp.compat_write()).await?;
    println!("✓ MSSQL connected");

    println!("Executing SELECT * FROM users...");
    let query_result = match tokio::time::timeout(
        Duration::from_secs(10),
        client.query("SELECT * FROM users", &[]),
    )
    .await
    {
        Ok(Ok(stream)) => {
            println!("✓ Query executed successfully");
            stream
        }
        Ok(Err(e)) => {
            println!("✗ Query error: {}", e);
            return Err(e.into());
        }
        Err(_) => {
            println!("✗ Query timeout");
            return Err("Query timeout".into());
        }
    };

    // Consume the result stream (but don't validate contents since we're using mssql_ok_response)
    let _rows: Vec<_> = query_result.into_results().await?;
    println!("✓ Query results received");

    // Verify mock expectations
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;

    println!("✓ MSSQL multi-row query test passed\n");
    Ok(())
}

#[tokio::test]
async fn test_mssql_create_table() -> E2EResult<()> {
    println!("\n=== E2E Test: MSSQL CREATE TABLE ===");

    let prompt = "Open MSSQL on port {AVAILABLE_PORT}. For CREATE/INSERT/UPDATE queries, \
        use mssql_ok_response rows_affected=1. For SELECT queries use mssql_ok_response rows_affected=0.";

    let server_config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock
            // Mock 1: Server startup
            .on_instruction_containing("Open MSSQL")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "MSSQL",
                    "instruction": "Handle MSSQL DDL queries"
                }
            ]))
            .expect_calls(1)
            .and()
            // The login is now an explicit decision: `mssql_login_ack` admits the session and
            // nothing else does, so every test that wants to run a query has to say so.
            .on_event("mssql_login")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "mssql_login_ack"
                }
            ]))
            .expect_at_least(1)
            .and()
            // Mock 2: CREATE TABLE query
            .on_event("mssql_query")
            .and_event_data_contains("query", "CREATE TABLE")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "mssql_ok_response",
                    "rows_affected": 1
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let server = helpers::start_netget_server(server_config).await?;
    println!("Server started on port {}", server.port);

    println!("Connecting to MSSQL server...");
    let mut config = Config::new();
    config.host("127.0.0.1");
    config.port(server.port);
    config.authentication(AuthMethod::None);
    config.encryption(EncryptionLevel::NotSupported);

    let tcp = TcpStream::connect(("127.0.0.1", server.port)).await?;
    let mut client = Client::connect(config, tcp.compat_write()).await?;
    println!("✓ MSSQL connected");

    println!("Executing CREATE TABLE...");
    let result = client
        .execute("CREATE TABLE test (id INT PRIMARY KEY)", &[])
        .await;

    match result {
        Ok(total) => {
            println!(
                "✓ CREATE TABLE executed successfully, rows affected: {:?}",
                total
            );
        }
        Err(e) => {
            println!("CREATE TABLE returned: {}", e);
            // This might fail, which is OK for this test
        }
    }

    // Verify mock expectations
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;

    println!("✓ MSSQL CREATE TABLE test completed\n");
    Ok(())
}

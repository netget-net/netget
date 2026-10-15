//! MongoDB client E2E tests with mock LLM
//!
//! The peer every one of these talks to is NetGet's **own** MongoDB server, driven by the
//! same mock model. That server lives behind a *separate* feature (`mongodb-server`), so the
//! gate below names both. Built with `--features mongodb` alone all four used to compile and
//! then fail at the first step with `Protocol 'MongoDB' exists but is not compiled into this
//! build` — a hard failure that looked like a client defect and was a missing cfg.
//!
//! Note what that peer means for the client's maturity: the official driver is the thing
//! under test here, not the thing corroborating it, so these are not evidence against a
//! third-party server.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features mongodb,mongodb-server \
//!       --test client -- mongodb --test-threads=100


use crate::helpers::*;
use tokio::time::{sleep, Duration};

#[tokio::test]
async fn test_mongodb_client_with_server_mocks() -> E2EResult<()> {
    // Start MongoDB server (mocked)
    let server_config =
        NetGetConfig::new("Listen on port {AVAILABLE_PORT} via MongoDB").with_mock(|mock| {
            mock
                // Mock initial instruction to start the server
                .on_instruction_containing("MongoDB")
                .respond_with_actions(serde_json::json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "MongoDB",
                    "instruction": "MongoDB server for testing"
                }]))
                .expect_calls(1)
                .and()
                // Mock mongodb_command event for find
                .on_event("mongodb_command")
                .and_event_data_contains("command", "find")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "find_response",
                        "documents": [
                            {"name": "Alice", "age": 30},
                            {"name": "Bob", "age": 25}
                        ]
                    }
                ]))
                .expect_calls(1)
                .and()
        });

    let server = start_netget_server(server_config).await?;

    // Start MongoDB client (mocked)
    let client_config = NetGetConfig::new(format!(
        "Connect to MongoDB at 127.0.0.1:{} database testdb. \
         Find all users with age greater than 20.",
        server.port
    ))
    .with_mock(|mock| {
        mock
            // Mock initial instruction to start the client
            .on_instruction_containing("Connect to MongoDB")
            .respond_with_actions(serde_json::json!([{
                "type": "open_client",
                "protocol": "mongodb",
                "remote_addr": format!("127.0.0.1:{}", server.port),
                "instruction": "MongoDB client for testing"
            }]))
            .expect_calls(1)
            .and()
            // Mock mongodb_connected event
            .on_event("mongodb_connected")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "find_documents",
                    "collection": "users",
                    "filter": {"age": {"$gt": 20}}
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock mongodb_result_received event
            .on_event("mongodb_result_received")
            .and_event_data_contains("result_type", "find")
            .respond_with_actions(serde_json::json!([
                {"type": "disconnect"}
            ]))
            .expect_calls(1)
            .and()
    });

    let client = start_netget_client(client_config).await?;

    // Wait for operations to complete

    // Verify mocks
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last response routinely lands
    // after the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    client.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    client.verify_mocks().await?;

    Ok(())
}

#[tokio::test]
async fn test_mongodb_client_insert_workflow_with_mocks() -> E2EResult<()> {
    // Start MongoDB server (mocked)
    let server_config =
        NetGetConfig::new("Listen on port {AVAILABLE_PORT} via MongoDB").with_mock(|mock| {
            mock
                // Mock initial instruction to start the server
                .on_instruction_containing("MongoDB")
                .respond_with_actions(serde_json::json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "MongoDB",
                    "instruction": "MongoDB server for testing"
                }]))
                .expect_calls(1)
                .and()
                // Mock mongodb_command event for insert
                .on_event("mongodb_command")
                .and_event_data_contains("command", "insert")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "insert_response",
                        "inserted_count": 1
                    }
                ]))
                .expect_calls(1)
                .and()
        });

    let server = start_netget_server(server_config).await?;

    // Start MongoDB client (mocked)
    let client_config = NetGetConfig::new(format!(
        "Connect to MongoDB at 127.0.0.1:{} database testdb. \
         Insert a new user named Charlie aged 35.",
        server.port
    ))
    .with_mock(|mock| {
        mock
            // Mock initial instruction to start the client
            .on_instruction_containing("Connect to MongoDB")
            .respond_with_actions(serde_json::json!([{
                "type": "open_client",
                "protocol": "mongodb",
                "remote_addr": format!("127.0.0.1:{}", server.port),
                "instruction": "MongoDB client for testing"
            }]))
            .expect_calls(1)
            .and()
            // Mock mongodb_connected event
            .on_event("mongodb_connected")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "insert_document",
                    "collection": "users",
                    "document": {"name": "Charlie", "age": 35}
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock mongodb_result_received event
            .on_event("mongodb_result_received")
            .and_event_data_contains("result_type", "insert")
            .respond_with_actions(serde_json::json!([
                {"type": "disconnect"}
            ]))
            .expect_calls(1)
            .and()
    });

    let client = start_netget_client(client_config).await?;

    // Wait for operations to complete

    // Verify mocks
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last response routinely lands
    // after the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    client.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    client.verify_mocks().await?;

    Ok(())
}

#[tokio::test]
async fn test_mongodb_client_update_workflow_with_mocks() -> E2EResult<()> {
    // Start MongoDB server (mocked)
    let server_config =
        NetGetConfig::new("Listen on port {AVAILABLE_PORT} via MongoDB").with_mock(|mock| {
            mock
                // Mock initial instruction to start the server
                .on_instruction_containing("MongoDB")
                .respond_with_actions(serde_json::json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "MongoDB",
                    "instruction": "MongoDB server for testing"
                }]))
                .expect_calls(1)
                .and()
                // Mock mongodb_command event for update
                .on_event("mongodb_command")
                .and_event_data_contains("command", "update")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "update_response",
                        "matched_count": 1,
                        "modified_count": 1
                    }
                ]))
                .expect_calls(1)
                .and()
        });

    let server = start_netget_server(server_config).await?;

    // Start MongoDB client (mocked)
    let client_config = NetGetConfig::new(format!(
        "Connect to MongoDB at 127.0.0.1:{} database testdb. \
         Update Alice's age to 31.",
        server.port
    ))
    .with_mock(|mock| {
        mock
            // Mock initial instruction to start the client
            .on_instruction_containing("Connect to MongoDB")
            .respond_with_actions(serde_json::json!([{
                "type": "open_client",
                "protocol": "mongodb",
                "remote_addr": format!("127.0.0.1:{}", server.port),
                "instruction": "MongoDB client for testing"
            }]))
            .expect_calls(1)
            .and()
            // Mock mongodb_connected event
            .on_event("mongodb_connected")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "update_documents",
                    "collection": "users",
                    "filter": {"name": "Alice"},
                    "update": {"$set": {"age": 31}}
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock mongodb_result_received event
            .on_event("mongodb_result_received")
            .and_event_data_contains("result_type", "update")
            .respond_with_actions(serde_json::json!([
                {"type": "disconnect"}
            ]))
            .expect_calls(1)
            .and()
    });

    let client = start_netget_client(client_config).await?;

    // Wait for operations to complete

    // Verify mocks
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last response routinely lands
    // after the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    client.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    client.verify_mocks().await?;

    Ok(())
}

#[tokio::test]
async fn test_mongodb_client_delete_workflow_with_mocks() -> E2EResult<()> {
    // Start MongoDB server (mocked)
    let server_config =
        NetGetConfig::new("Listen on port {AVAILABLE_PORT} via MongoDB").with_mock(|mock| {
            mock
                // Mock initial instruction to start the server
                .on_instruction_containing("MongoDB")
                .respond_with_actions(serde_json::json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "MongoDB",
                    "instruction": "MongoDB server for testing"
                }]))
                .expect_calls(1)
                .and()
                // Mock mongodb_command event for delete
                .on_event("mongodb_command")
                .and_event_data_contains("command", "delete")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "delete_response",
                        "deleted_count": 1
                    }
                ]))
                .expect_calls(1)
                .and()
        });

    let server = start_netget_server(server_config).await?;

    // Start MongoDB client (mocked)
    let client_config = NetGetConfig::new(format!(
        "Connect to MongoDB at 127.0.0.1:{} database testdb. \
         Delete user Bob.",
        server.port
    ))
    .with_mock(|mock| {
        mock
            // Mock initial instruction to start the client
            .on_instruction_containing("Connect to MongoDB")
            .respond_with_actions(serde_json::json!([{
                "type": "open_client",
                "protocol": "mongodb",
                "remote_addr": format!("127.0.0.1:{}", server.port),
                "instruction": "MongoDB client for testing"
            }]))
            .expect_calls(1)
            .and()
            // Mock mongodb_connected event
            .on_event("mongodb_connected")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "delete_documents",
                    "collection": "users",
                    "filter": {"name": "Bob"}
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock mongodb_result_received event
            .on_event("mongodb_result_received")
            .and_event_data_contains("result_type", "delete")
            .respond_with_actions(serde_json::json!([
                {"type": "disconnect"}
            ]))
            .expect_calls(1)
            .and()
    });

    let client = start_netget_client(client_config).await?;

    // Wait for operations to complete

    // Verify mocks
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last response routinely lands
    // after the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    client.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    client.verify_mocks().await?;

    Ok(())
}

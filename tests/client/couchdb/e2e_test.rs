//! CouchDB client E2E tests
//!
//! Tests the CouchDB client implementation against NetGet CouchDB server.
//! Uses mocks for LLM responses to keep test suite fast (< 10 LLM calls).

use crate::helpers::*;
use serde_json::json;
use std::time::Duration;

/// Test client connection and server info retrieval
#[tokio::test]
async fn test_couchdb_client_connect() -> E2EResult<()> {
    // Start CouchDB server
    let server_config = NetGetConfig::new(
        "Listen for CouchDB connections on port {AVAILABLE_PORT}",
    )
    .with_mock(|mock| {
        mock.on_instruction_containing("Listen for CouchDB")
            .respond_with_actions(json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "CouchDB",
                    "instruction": "Handle CouchDB protocol events"
                }
            ]))
            .and()
            .on_event("couchdb_request")
            .and_event_data_contains("operation", "server_info")
            .respond_with_actions(json!([{
                "type": "send_server_info",
                "version": "3.5.1",
                "uuid": "test-uuid",
                "vendor_name": "NetGet LLM CouchDB"
            }]))
            .and()
    });

    let server = start_netget_server(server_config).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Start CouchDB client
    let client_config = NetGetConfig::new(format!(
        "Connect to 127.0.0.1:{} as CouchDB client. Fetch server info.",
        server.port
    ))
    .with_mock(|mock| {
        mock.on_instruction_containing("Connect to")
            .and_instruction_containing("CouchDB")
            .respond_with_actions(json!([{
                "type": "open_client",
                "remote_addr": format!("127.0.0.1:{}", server.port),
                "protocol": "CouchDB",
                "instruction": "Fetch server info"
            }]))
            .and()
            .on_event("couchdb_connected")
            .respond_with_actions(json!([{
                "type": "wait_for_more"
            }]))
            .and()
    });

    let client = start_netget_client(client_config).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last response routinely lands
    // after the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    client.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    client.verify_mocks().await?;
    server.stop().await?;
    client.stop().await?;
    Ok(())
}

/// Test database operations via client
#[tokio::test]
async fn test_couchdb_client_database_operations() -> E2EResult<()> {
    // Start CouchDB server
    let server_config = NetGetConfig::new(
        "Listen for CouchDB connections on port {AVAILABLE_PORT}",
    )
    .with_mock(|mock| {
        mock.on_instruction_containing("Listen for CouchDB")
            .respond_with_actions(json!([{
                "type": "open_server",
                "port": 0,
                "base_stack": "CouchDB",
                "instruction": "Handle CouchDB protocol events"
            }]))
            .and()
            .on_event("couchdb_request")
            .and_event_data_contains("operation", "server_info")
            .respond_with_actions(json!([{
                "type": "send_server_info",
                "version": "3.5.1"
            }]))
            .and()
            .on_event("couchdb_request")
            .and_event_data_contains("operation", "db_create")
            .and_event_data_contains("database", "testdb")
            .respond_with_actions(json!([{
                "type": "send_couchdb_response",
                "status_code": 201,
                "body": "{\"ok\": true}"
            }]))
            .and()
            .on_event("couchdb_request")
            .and_event_data_contains("operation", "all_dbs")
            .respond_with_actions(json!([{
                "type": "send_all_dbs",
                "databases": ["testdb"]
            }]))
            .and()
            .on_event("couchdb_request")
            .and_event_data_contains("operation", "db_delete")
            .and_event_data_contains("database", "testdb")
            .respond_with_actions(json!([{
                "type": "send_couchdb_response",
                "status_code": 200,
                "body": "{\"ok\": true}"
            }]))
            .and()
    });

    let server = start_netget_server(server_config).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Start CouchDB client
    let client_config = NetGetConfig::new(format!(
        "Connect to 127.0.0.1:{} as CouchDB client. Create database 'testdb', list databases, delete 'testdb'.",
        server.port
    ))
    .with_mock(|mock| {
        mock.on_instruction_containing("Connect to")
            .and_instruction_containing("CouchDB")
            .respond_with_actions(json!([{
                "type": "open_client",
                "remote_addr": format!("127.0.0.1:{}", server.port),
                "protocol": "CouchDB",
                "instruction": "Create testdb, list databases, delete testdb"
            }]))
            .and()
            .on_event("couchdb_connected")
            .respond_with_actions(json!([{
                "type": "create_database",
                "database": "testdb"
            }]))
            .and()
            .on_event("couchdb_response_received")
            .and_event_data_contains("operation", "create_database")
            .respond_with_actions(json!([{
                "type": "list_databases"
            }]))
            .and()
            .on_event("couchdb_response_received")
            .and_event_data_contains("operation", "list_databases")
            .respond_with_actions(json!([{
                "type": "delete_database",
                "database": "testdb"
            }]))
            .and()
            .on_event("couchdb_response_received")
            .and_event_data_contains("operation", "delete_database")
            .respond_with_actions(json!([{
                "type": "wait_for_more"
            }]))
            .and()
    });

    let client = start_netget_client(client_config).await?;
    tokio::time::sleep(Duration::from_millis(2000)).await;

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last response routinely lands
    // after the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    client.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    client.verify_mocks().await?;
    server.stop().await?;
    client.stop().await?;
    Ok(())
}

/// Test document CRUD operations via client
#[tokio::test]
async fn test_couchdb_client_document_crud() -> E2EResult<()> {
    // Start CouchDB server
    let server_config = NetGetConfig::new(
        "Listen for CouchDB connections on port {AVAILABLE_PORT}",
    )
    .with_mock(|mock| {
        mock.on_instruction_containing("Listen for CouchDB")
            .respond_with_actions(json!([{
                "type": "open_server",
                "port": 0,
                "base_stack": "CouchDB",
                "instruction": "Handle CouchDB protocol events"
            }]))
            .and()
            .on_event("couchdb_request")
            .and_event_data_contains("operation", "server_info")
            .respond_with_actions(json!([{
                "type": "send_server_info",
                "version": "3.5.1"
            }]))
            .and()
            .on_event("couchdb_request")
            .and_event_data_contains("operation", "db_info")
            .and_event_data_contains("database", "testdb")
            .respond_with_actions(json!([{
                "type": "send_db_info",
                "db_name": "testdb",
                "doc_count": 0,
                "update_seq": "0"
            }]))
            .and()
            .on_event("couchdb_request")
            .and_event_data_contains("operation", "doc_put")
            .and_event_data_contains("doc_id", "user1")
            .respond_with_actions(json!([{
                "type": "send_doc_response",
                "success": true,
                "doc_id": "user1",
                "rev": "1-abc123"
            }]))
            .and()
            .on_event("couchdb_request")
            .and_event_data_contains("operation", "doc_get")
            .and_event_data_contains("doc_id", "user1")
            .respond_with_actions(json!([{
                "type": "send_doc_response",
                "success": true,
                "doc_id": "user1",
                "rev": "1-abc123",
                "document": {"name": "Alice", "age": 30}
            }]))
            .and()
            .on_event("couchdb_request")
            .and_event_data_contains("operation", "doc_delete")
            .and_event_data_contains("doc_id", "user1")
            .respond_with_actions(json!([{
                "type": "send_couchdb_response",
                "status_code": 200,
                "body": "{\"ok\": true}"
            }]))
            .and()
    });

    let server = start_netget_server(server_config).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Start CouchDB client
    let client_config = NetGetConfig::new(format!(
        "Connect to 127.0.0.1:{} as CouchDB client. Create document user1, get it, update age to 31, delete it.",
        server.port
    ))
    .with_mock(|mock| {
        mock.on_instruction_containing("Connect to")
            .and_instruction_containing("CouchDB")
            .respond_with_actions(json!([{
                "type": "open_client",
                "remote_addr": format!("127.0.0.1:{}", server.port),
                "protocol": "CouchDB",
                "instruction": "Create user1, get, update, delete"
            }]))
            .and()
            .on_event("couchdb_connected")
            .respond_with_actions(json!([{
                "type": "create_document",
                "database": "testdb",
                "doc_id": "user1",
                "document": {"name": "Alice", "age": 30}
            }]))
            .and()
            .on_event("couchdb_response_received")
            .and_event_data_contains("operation", "create_document")
            .respond_with_actions(json!([{
                "type": "get_document",
                "database": "testdb",
                "doc_id": "user1"
            }]))
            .and()
            .on_event("couchdb_response_received")
            .and_event_data_contains("operation", "get_document")
            .respond_with_actions(json!([{
                "type": "update_document",
                "database": "testdb",
                "doc_id": "user1",
                "document": {"_rev": "1-abc123", "name": "Alice", "age": 31}
            }]))
            .and()
            .on_event("couchdb_response_received")
            .and_event_data_contains("operation", "update_document")
            .respond_with_actions(json!([{
                "type": "delete_document",
                "database": "testdb",
                "doc_id": "user1",
                "rev": "2-def456"
            }]))
            .and()
            .on_event("couchdb_response_received")
            .and_event_data_contains("operation", "delete_document")
            .respond_with_actions(json!([{
                "type": "wait_for_more"
            }]))
            .and()
    });

    let client = start_netget_client(client_config).await?;
    tokio::time::sleep(Duration::from_millis(3000)).await;

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last response routinely lands
    // after the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    client.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    client.verify_mocks().await?;
    server.stop().await?;
    client.stop().await?;
    Ok(())
}

/// Test conflict detection and resolution
#[tokio::test]
async fn test_couchdb_client_conflict_handling() -> E2EResult<()> {
    // Start CouchDB server
    let server_config = NetGetConfig::new(
        "Listen for CouchDB connections on port {AVAILABLE_PORT}",
    )
    .with_mock(|mock| {
        mock.on_instruction_containing("Listen for CouchDB")
            .respond_with_actions(json!([{
                "type": "open_server",
                "port": 0,
                "base_stack": "CouchDB",
                "instruction": "Handle CouchDB protocol events"
            }]))
            .and()
            .on_event("couchdb_request")
            .and_event_data_contains("operation", "server_info")
            .respond_with_actions(json!([{
                "type": "send_server_info",
                "version": "3.5.1"
            }]))
            .and()
            .on_event("couchdb_request")
            .and_event_data_contains("operation", "db_info")
            .and_event_data_contains("database", "testdb")
            .respond_with_actions(json!([{
                "type": "send_db_info",
                "db_name": "testdb",
                "doc_count": 0,
                "update_seq": "0"
            }]))
            .and()
            .on_event("couchdb_request")
            .and_event_data_contains("operation", "doc_put")
            .and_event_data_contains("doc_id", "user1")
            .respond_with_actions(json!([{
                "type": "send_doc_response",
                "success": false,
                "doc_id": "user1",
                "rev": "2-current",
                "error": "conflict",
                "reason": "Document update conflict"
            }]))
            .and()
            .on_event("couchdb_request")
            .and_event_data_contains("operation", "doc_get")
            .and_event_data_contains("doc_id", "user1")
            .respond_with_actions(json!([{
                "type": "send_doc_response",
                "success": true,
                "doc_id": "user1",
                "rev": "2-current",
                "document": {"name": "Alice", "age": 31}
            }]))
            .and()
            .on_event("couchdb_request")
            .and_event_data_contains("operation", "doc_put")
            .and_event_data_contains("doc_id", "user1")
            .respond_with_actions(json!([{
                "type": "send_doc_response",
                "success": true,
                "doc_id": "user1",
                "rev": "3-updated"
            }]))
            .and()
    });

    let server = start_netget_server(server_config).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Start CouchDB client
    let client_config = NetGetConfig::new(format!(
        "Connect to 127.0.0.1:{} as CouchDB client. Try to update user1 with old revision, handle conflict.",
        server.port
    ))
    .with_mock(|mock| {
        mock.on_instruction_containing("Connect to")
            .and_instruction_containing("CouchDB")
            .respond_with_actions(json!([{
                "type": "open_client",
                "remote_addr": format!("127.0.0.1:{}", server.port),
                "protocol": "CouchDB",
                "instruction": "Update user1 with old rev, handle conflict"
            }]))
            .and()
            .on_event("couchdb_connected")
            .respond_with_actions(json!([{
                "type": "update_document",
                "database": "testdb",
                "doc_id": "user1",
                "document": {"_rev": "1-old", "name": "Alice", "age": 32}
            }]))
            .and()
            .on_event("couchdb_conflict")
            .and_event_data_contains("doc_id", "user1")
            .respond_with_actions(json!([{
                "type": "get_document",
                "database": "testdb",
                "doc_id": "user1"
            }]))
            .and()
            .on_event("couchdb_response_received")
            .and_event_data_contains("operation", "get_document")
            .respond_with_actions(json!([{
                "type": "update_document",
                "database": "testdb",
                "doc_id": "user1",
                "document": {"_rev": "2-current", "name": "Alice", "age": 32}
            }]))
            .and()
            .on_event("couchdb_response_received")
            .and_event_data_contains("operation", "update_document")
            .respond_with_actions(json!([{
                "type": "wait_for_more"
            }]))
            .and()
    });

    let client = start_netget_client(client_config).await?;
    tokio::time::sleep(Duration::from_millis(3000)).await;

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last response routinely lands
    // after the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    client.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    client.verify_mocks().await?;
    server.stop().await?;
    client.stop().await?;
    Ok(())
}

/// Test bulk operations via client
#[tokio::test]
async fn test_couchdb_client_bulk_operations() -> E2EResult<()> {
    // Start CouchDB server
    let server_config = NetGetConfig::new(
        "Listen for CouchDB connections on port {AVAILABLE_PORT}",
    )
    .with_mock(|mock| {
        mock.on_instruction_containing("Listen for CouchDB")
            .respond_with_actions(json!([{
                "type": "open_server",
                "port": 0,
                "base_stack": "CouchDB",
                "instruction": "Handle CouchDB protocol events"
            }]))
            .and()
            .on_event("couchdb_request")
            .and_event_data_contains("operation", "server_info")
            .respond_with_actions(json!([{
                "type": "send_server_info",
                "version": "3.5.1"
            }]))
            .and()
            .on_event("couchdb_request")
            .and_event_data_contains("operation", "db_info")
            .and_event_data_contains("database", "testdb")
            .respond_with_actions(json!([{
                "type": "send_db_info",
                "db_name": "testdb",
                "doc_count": 0,
                "update_seq": "0"
            }]))
            .and()
            .on_event("couchdb_request")
            .and_event_data_contains("operation", "bulk_docs")
            .respond_with_actions(json!([{
                "type": "send_bulk_docs_response",
                "results": [
                    {"ok": true, "id": "doc1", "rev": "1-abc"},
                    {"ok": true, "id": "doc2", "rev": "1-def"},
                    {"ok": true, "id": "doc3", "rev": "1-ghi"}
                ]
            }]))
            .and()
            .on_event("couchdb_request")
            .and_event_data_contains("operation", "all_docs")
            .respond_with_actions(json!([{
                "type": "send_all_docs",
                "total_rows": 3,
                "rows": [
                    {"id": "doc1", "key": "doc1", "value": {"rev": "1-abc"}},
                    {"id": "doc2", "key": "doc2", "value": {"rev": "1-def"}},
                    {"id": "doc3", "key": "doc3", "value": {"rev": "1-ghi"}}
                ]
            }]))
            .and()
    });

    let server = start_netget_server(server_config).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Start CouchDB client
    let client_config = NetGetConfig::new(format!(
        "Connect to 127.0.0.1:{} as CouchDB client. Insert 3 documents in bulk, list all documents.",
        server.port
    ))
    .with_mock(|mock| {
        mock.on_instruction_containing("Connect to")
            .and_instruction_containing("CouchDB")
            .respond_with_actions(json!([{
                "type": "open_client",
                "remote_addr": format!("127.0.0.1:{}", server.port),
                "protocol": "CouchDB",
                "instruction": "Bulk insert 3 docs, list all"
            }]))
            .and()
            .on_event("couchdb_connected")
            .respond_with_actions(json!([{
                "type": "bulk_docs",
                "database": "testdb",
                "docs": [
                    {"_id": "doc1", "name": "Alice"},
                    {"_id": "doc2", "name": "Bob"},
                    {"_id": "doc3", "name": "Charlie"}
                ]
            }]))
            .and()
            .on_event("couchdb_response_received")
            .and_event_data_contains("operation", "bulk_docs")
            .respond_with_actions(json!([{
                "type": "list_documents",
                "database": "testdb"
            }]))
            .and()
            .on_event("couchdb_response_received")
            .and_event_data_contains("operation", "list_documents")
            .respond_with_actions(json!([{
                "type": "wait_for_more"
            }]))
            .and()
    });

    let client = start_netget_client(client_config).await?;
    tokio::time::sleep(Duration::from_millis(3000)).await;

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last response routinely lands
    // after the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    client.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    client.verify_mocks().await?;
    server.stop().await?;
    client.stop().await?;
    Ok(())
}

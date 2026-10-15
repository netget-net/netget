//! Elasticsearch client E2E tests
//!
//! Tests the Elasticsearch client protocol implementation with mock LLM responses.
//! Budget: < 10 LLM calls per test suite.


use crate::helpers::*;
use serde_json::json;
use std::time::Duration;

/// Test Elasticsearch client index and search operations
/// LLM calls: 4 (client startup, connected, index response, search response)
#[tokio::test]
async fn test_elasticsearch_client_index_and_search() -> E2EResult<()> {
    println!("\n=== Test: Elasticsearch Client Index and Search ===");

    // Start a local Elasticsearch server first (using netcat as a simple TCP server)
    // For now, we'll use a mock Elasticsearch server via TCP

    // Start Elasticsearch server
    let server_prompt = "Start Elasticsearch on port {AVAILABLE_PORT}";
    let server_config = NetGetConfig::new(server_prompt)
        .with_log_level("off")
        .with_mock(|mock| {
            mock
                // Mock 1: Server startup
                .on_instruction_containing("Start Elasticsearch")
                .respond_with_actions(json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "HTTP",
                        "protocol": "ELASTICSEARCH",
                        "instruction": "Elasticsearch test server"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2: Index request
                // The Elasticsearch server raises `elasticsearch_request` (carrying method,
                // path and index). `http_request` is a different protocol's event, so
                // these rules never matched and every request fell through to a real
                // LLM call that answered 500.
                .on_event("elasticsearch_request")
                // The client POSTs to /{index}/_doc/{id} -- valid Elasticsearch for an
                // explicit id, and what it does whether or not an id is given. The path
                // constraint matters because this rule is first: unconstrained, a plain
                // "POST" would also swallow the /_search request below.
                .and_event_data_contains("method", "POST")
                .and_event_data_contains("path", "/_doc")
                .respond_with_actions(json!([
                    {
                        "type": "send_elasticsearch_response",
                        "status_code": 200,
                        "body": json!({
                            "_index": "test-index",
                            "_id": "test-doc-1",
                            "_version": 1,
                            "result": "created"
                        }).to_string()
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 3: Search request
                // The Elasticsearch server raises `elasticsearch_request` (carrying method,
                // path and index). `http_request` is a different protocol's event, so
                // these rules never matched and every request fell through to a real
                // LLM call that answered 500.
                .on_event("elasticsearch_request")
                .and_event_data_contains("method", "POST")
                .and_event_data_contains("path", "/_search")
                .respond_with_actions(json!([
                    {
                        "type": "send_elasticsearch_response",
                        "status_code": 200,
                        "body": json!({
                            "took": 1,
                            "hits": {
                                "total": {"value": 1},
                                "hits": [
                                    {
                                        "_index": "test-index",
                                        "_id": "test-doc-1",
                                        "_source": {"title": "Test", "content": "Hello World"}
                                    }
                                ]
                            }
                        }).to_string()
                    }
                ]))
                .expect_calls(1)
                .and()
        });

    let mut server = start_netget_server(server_config).await?;
    println!("Server started on port {}", server.port);

    // Give server time to start
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Start Elasticsearch client
    let client_prompt = format!(
        "Connect to 127.0.0.1:{} via Elasticsearch. Index a document with title='Test' and content='Hello World', then search for it.",
        server.port
    );
    let client_config = NetGetConfig::new(client_prompt)
        .with_log_level("off")
        .with_mock(|mock| {
            mock
                // Mock 1: Client startup
                .on_instruction_containing("Connect to")
                .and_instruction_containing("Elasticsearch")
                .respond_with_actions(json!([
                    {
                        "type": "open_client",
                        "remote_addr": format!("127.0.0.1:{}", server.port),
                        "protocol": "Elasticsearch",
                        "instruction": "Index document and search"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2: Client connected - index document
                .on_event("elasticsearch_connected")
                .respond_with_actions(json!([
                    {
                        "type": "index_document",
                        "index": "test-index",
                        "id": "test-doc-1",
                        "document": json!({"title": "Test", "content": "Hello World"})
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 3: Index response - search
                .on_event("elasticsearch_response_received")
                .and_event_data_contains("operation", "index_document")
                .respond_with_actions(json!([
                    {
                        "type": "search",
                        "index": "test-index",
                        "query": json!({"match_all": {}})
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 4: Search response - wait
                .on_event("elasticsearch_response_received")
                .and_event_data_contains("operation", "search")
                .respond_with_actions(json!([
                    {
                        "type": "wait_for_more"
                    }
                ]))
                .expect_calls(1)
                .and()
        });

    let mut client = start_netget_client(client_config).await?;

    // Give client time to connect and perform operations

    // Verify client output
    client.wait_for_any(&["Elasticsearch"], 30).await;
    assert!(
        client.output_contains("Elasticsearch").await,
        "Client should show Elasticsearch connection"
    );

    println!("✅ Elasticsearch client indexed and searched successfully");

    // Wait for the exchange itself, not for a sleep long enough to probably cover it.
    // The search response reached the client a few hundred ms after the fixed 2s sleep
    // expired, and the test reported it as never having happened.
    client.wait_for_mocks(15).await;
    server.wait_for_mocks(15).await;

    // Verify mock expectations were met
    server.verify_mocks().await?;
    client.verify_mocks().await?;

    // Cleanup
    client.stop().await?;
    server.stop().await?;

    println!("=== Test Complete ===\n");
    Ok(())
}

/// Test Elasticsearch client bulk operations
/// LLM calls: 3 (client startup, connected, bulk response)
#[tokio::test]
async fn test_elasticsearch_client_bulk_operations() -> E2EResult<()> {
    println!("\n=== Test: Elasticsearch Client Bulk Operations ===");

    // Start Elasticsearch server
    let server_config = NetGetConfig::new("Start Elasticsearch on port {AVAILABLE_PORT}")
        .with_log_level("off")
        .with_mock(|mock| {
            mock
                // Mock 1: Server startup
                .on_instruction_containing("Start Elasticsearch")
                .respond_with_actions(json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "HTTP",
                        "protocol": "ELASTICSEARCH",
                        "instruction": "Elasticsearch test server"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2: Bulk request
                // The Elasticsearch server raises `elasticsearch_request` (carrying method,
                // path and index). `http_request` is a different protocol's event, so
                // these rules never matched and every request fell through to a real
                // LLM call that answered 500.
                .on_event("elasticsearch_request")
                .and_event_data_contains("path", "/_bulk")
                .respond_with_actions(json!([
                    {
                        "type": "send_elasticsearch_response",
                        "status_code": 200,
                        "body": json!({
                            "took": 2,
                            "errors": false,
                            "items": [
                                {"index": {"_index": "products", "_id": "1", "result": "created"}},
                                {"index": {"_index": "products", "_id": "2", "result": "created"}},
                                {"index": {"_index": "products", "_id": "3", "result": "created"}}
                            ]
                        }).to_string()
                    }
                ]))
                .expect_calls(1)
                .and()
        });

    let mut server = start_netget_server(server_config).await?;
    println!("Server started on port {}", server.port);

    tokio::time::sleep(Duration::from_millis(500)).await;

    // Start Elasticsearch client with bulk instruction
    let client_config = NetGetConfig::new(format!(
        "Connect to 127.0.0.1:{} via Elasticsearch. Use bulk operation to index 3 products: laptop (price=999), phone (price=699), tablet (price=499)",
        server.port
    ))
        .with_log_level("off")
        .with_mock(|mock| {
            mock
                // Mock 1: Client startup
                .on_instruction_containing("Elasticsearch")
                .and_instruction_containing("bulk")
                .respond_with_actions(json!([
                    {
                        "type": "open_client",
                        "remote_addr": format!("127.0.0.1:{}", server.port),
                        "protocol": "Elasticsearch",
                        "instruction": "Bulk index 3 products"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2: Client connected - send bulk request
                .on_event("elasticsearch_connected")
                .respond_with_actions(json!([
                    {
                        "type": "bulk_operation",
                        // The structured shape the action declares -- one entry per
                        // document with `action`/`index`/`id`/`document`. Raw Elasticsearch
                        // NDJSON meta/source pairs have no `action` field, so the client
                        // refused the whole batch with "Missing 'action' field".
                        "operations": [
                            {"action": "index", "index": "products", "id": "1",
                             "document": {"name": "laptop", "price": 999}},
                            {"action": "index", "index": "products", "id": "2",
                             "document": {"name": "phone", "price": 699}},
                            {"action": "index", "index": "products", "id": "3",
                             "document": {"name": "tablet", "price": 499}}
                        ]
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 3: Bulk response
                .on_event("elasticsearch_response_received")
                .and_event_data_contains("operation", "bulk_operation")
                .respond_with_actions(json!([
                    {
                        "type": "wait_for_more"
                    }
                ]))
                .expect_calls(1)
                .and()
        });

    let mut client = start_netget_client(client_config).await?;

    println!("✅ Elasticsearch bulk operations completed");

    // Verify mock expectations
    // Wait for the exchange itself, not for a sleep long enough to probably cover it.
    client.wait_for_mocks(15).await;
    server.wait_for_mocks(15).await;

    server.verify_mocks().await?;
    client.verify_mocks().await?;

    // Cleanup
    client.stop().await?;
    server.stop().await?;

    println!("=== Test Complete ===\n");
    Ok(())
}

/// Test Elasticsearch client document lifecycle (index, get, delete)
/// LLM calls: 5 (client startup, connected, index response, get response, delete response)
#[tokio::test]
async fn test_elasticsearch_client_document_lifecycle() -> E2EResult<()> {
    println!("\n=== Test: Elasticsearch Client Document Lifecycle ===");

    // Start Elasticsearch server
    let server_config = NetGetConfig::new("Start Elasticsearch on port {AVAILABLE_PORT}")
        .with_log_level("off")
        .with_mock(|mock| {
            mock
                // Mock 1: Server startup
                .on_instruction_containing("Start Elasticsearch")
                .respond_with_actions(json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "HTTP",
                        "protocol": "ELASTICSEARCH",
                        "instruction": "Elasticsearch test server"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2: Index request
                // The Elasticsearch server raises `elasticsearch_request` (carrying method,
                // path and index). `http_request` is a different protocol's event, so
                // these rules never matched and every request fell through to a real
                // LLM call that answered 500.
                .on_event("elasticsearch_request")
                // The client POSTs to /{index}/_doc/{id} -- valid Elasticsearch for an
                // explicit id, and what it does whether or not an id is given. The path
                // constraint matters because this rule is first: unconstrained, a plain
                // "POST" would also swallow the /_search request below.
                .and_event_data_contains("method", "POST")
                .and_event_data_contains("path", "/_doc")
                .respond_with_actions(json!([
                    {
                        "type": "send_elasticsearch_response",
                        "status_code": 200,
                        "body": json!({"_index": "test-index", "_id": "test-doc-1", "result": "created"}).to_string()
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 3: Get request
                // The Elasticsearch server raises `elasticsearch_request` (carrying method,
                // path and index). `http_request` is a different protocol's event, so
                // these rules never matched and every request fell through to a real
                // LLM call that answered 500.
                .on_event("elasticsearch_request")
                .and_event_data_contains("method", "GET")
                .respond_with_actions(json!([
                    {
                        "type": "send_elasticsearch_response",
                        "status_code": 200,
                        "body": json!({"_index": "test-index", "_id": "test-doc-1", "found": true, "_source": {"test": "data"}}).to_string()
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 4: Delete request
                // The Elasticsearch server raises `elasticsearch_request` (carrying method,
                // path and index). `http_request` is a different protocol's event, so
                // these rules never matched and every request fell through to a real
                // LLM call that answered 500.
                .on_event("elasticsearch_request")
                .and_event_data_contains("method", "DELETE")
                .respond_with_actions(json!([
                    {
                        "type": "send_elasticsearch_response",
                        "status_code": 200,
                        "body": json!({"_index": "test-index", "_id": "test-doc-1", "result": "deleted"}).to_string()
                    }
                ]))
                .expect_calls(1)
                .and()
        });

    let mut server = start_netget_server(server_config).await?;
    println!("Server started on port {}", server.port);

    tokio::time::sleep(Duration::from_millis(500)).await;

    // Start Elasticsearch client
    let client_config = NetGetConfig::new(format!(
        "Connect to 127.0.0.1:{} via Elasticsearch. Index a document with id 'test-doc-1', then get it, then delete it",
        server.port
    ))
        .with_log_level("off")
        .with_mock(|mock| {
            mock
                // Mock 1: Client startup
                .on_instruction_containing("Elasticsearch")
                .respond_with_actions(json!([
                    {
                        "type": "open_client",
                        "remote_addr": format!("127.0.0.1:{}", server.port),
                        "protocol": "Elasticsearch",
                        "instruction": "Index, get, delete document"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2: Connected - index
                .on_event("elasticsearch_connected")
                .respond_with_actions(json!([
                    {
                        "type": "index_document",
                        "index": "test-index",
                        "id": "test-doc-1",
                        "document": json!({"test": "data"})
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 3: Index response - get
                .on_event("elasticsearch_response_received")
                .and_event_data_contains("operation", "index_document")
                .respond_with_actions(json!([
                    {
                        "type": "get_document",
                        "index": "test-index",
                        "id": "test-doc-1"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 4: Get response - delete
                .on_event("elasticsearch_response_received")
                .and_event_data_contains("operation", "get_document")
                .respond_with_actions(json!([
                    {
                        "type": "delete_document",
                        "index": "test-index",
                        "id": "test-doc-1"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 5: Delete response - done
                .on_event("elasticsearch_response_received")
                .and_event_data_contains("operation", "delete_document")
                .respond_with_actions(json!([
                    {
                        "type": "disconnect"
                    }
                ]))
                .expect_calls(1)
                .and()
        });

    let mut client = start_netget_client(client_config).await?;

    println!("✅ Elasticsearch document lifecycle completed");

    // Verify mock expectations
    // Wait for the exchange itself, not for a sleep long enough to probably cover it.
    client.wait_for_mocks(15).await;
    server.wait_for_mocks(15).await;

    server.verify_mocks().await?;
    client.verify_mocks().await?;

    // Cleanup
    client.stop().await?;
    server.stop().await?;

    println!("=== Test Complete ===\n");
    Ok(())
}

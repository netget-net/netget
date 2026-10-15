//! CouchDB server E2E tests
//!
//! Tests the CouchDB server implementation against real HTTP clients.
//! Uses mocks for LLM responses to keep test suite fast (< 10 LLM calls).

use crate::server::helpers::*;
use reqwest;
use serde_json::json;

/// Test server info endpoint (GET /)
#[tokio::test]
async fn test_couchdb_server_info() -> E2EResult<()> {
    let config = NetGetConfig::new("Listen for CouchDB connections on port {AVAILABLE_PORT}")
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
                .expect_calls(1)
                .and()
        });

    let test_state = start_netget_server(config).await?;
    let port = test_state.port;

    // Test server info
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://127.0.0.1:{}/", port))
        .send()
        .await?;

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await?;
    assert_eq!(body["couchdb"], "Welcome");
    assert_eq!(body["version"], "3.5.1");

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    test_state.wait_for_mocks(30).await;
    test_state.verify_mocks().await?;
    test_state.stop().await?;
    Ok(())
}

/// Test database creation and operations
#[tokio::test]
async fn test_couchdb_database_operations() -> E2EResult<()> {
    let config = NetGetConfig::new("Listen for CouchDB connections on port {AVAILABLE_PORT}")
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
                // Create database
                .on_event("couchdb_request")
                .and_event_data_contains("operation", "db_create")
                .and_event_data_contains("database", "testdb")
                .respond_with_actions(json!([{
                    "type": "send_couchdb_response",
                    "status_code": 201,
                    "body": "{\"ok\": true}"
                }]))
                .expect_calls(1)
                .and()
                // Database info
                .on_event("couchdb_request")
                .and_event_data_contains("operation", "db_info")
                .and_event_data_contains("database", "testdb")
                .respond_with_actions(json!([{
                    "type": "send_db_info",
                    "db_name": "testdb",
                    "doc_count": 0,
                    "update_seq": "0"
                }]))
                .expect_calls(1)
                .and()
                // Delete database
                .on_event("couchdb_request")
                .and_event_data_contains("operation", "db_delete")
                .and_event_data_contains("database", "testdb")
                .respond_with_actions(json!([{
                    "type": "send_couchdb_response",
                    "status_code": 200,
                    "body": "{\"ok\": true}"
                }]))
                .expect_calls(1)
                .and()
        });

    let test_state = start_netget_server(config).await?;
    let port = test_state.port;
    let client = reqwest::Client::new();
    let base_url = format!("http://127.0.0.1:{}", port);

    // Create database
    let resp = client.put(format!("{}/testdb", base_url)).send().await?;
    assert_eq!(resp.status(), 201);
    let body: serde_json::Value = resp.json().await?;
    assert_eq!(body["ok"], true);

    // Get database info
    let resp = client.get(format!("{}/testdb", base_url)).send().await?;
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await?;
    assert_eq!(body["db_name"], "testdb");
    assert_eq!(body["doc_count"], 0);

    // Delete database
    let resp = client.delete(format!("{}/testdb", base_url)).send().await?;
    assert_eq!(resp.status(), 200);

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    test_state.wait_for_mocks(30).await;
    test_state.verify_mocks().await?;
    test_state.stop().await?;
    Ok(())
}

/// Test document CRUD operations
#[tokio::test]
async fn test_couchdb_document_crud() -> E2EResult<()> {
    let config = NetGetConfig::new("Listen for CouchDB connections on port {AVAILABLE_PORT}")
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
                // Create document. A create carries no `_rev` in its body; the update
                // below does, and that is the only thing separating the two PUTs — they
                // share method, path, operation and doc_id. Without it both rules match
                // identically, the first one answers twice and the second never fires.
                .on_event("couchdb_request")
                .and_event_data_contains("operation", "doc_put")
                .and_event_data_contains("doc_id", "user1")
                .and_event_data_contains("request_body", "\"age\":30")
                .respond_with_actions(json!([{
                    "type": "send_doc_response",
                    "success": true,
                    "doc_id": "user1",
                    "rev": "1-abc123"
                }]))
                .expect_calls(1)
                .and()
                // Get document
                .on_event("couchdb_request")
                .and_event_data_contains("operation", "doc_get")
                .and_event_data_contains("doc_id", "user1")
                .respond_with_actions(json!([{
                    "type": "send_doc_response",
                    "success": true,
                    "doc_id": "user1",
                    "rev": "1-abc123",
                    "document": {"_id": "user1", "_rev": "1-abc123", "name": "Alice", "age": 30}
                }]))
                .expect_calls(1)
                .and()
                // Update document (body carries `_rev`, unlike the create above)
                .on_event("couchdb_request")
                .and_event_data_contains("operation", "doc_put")
                .and_event_data_contains("doc_id", "user1")
                .and_event_data_contains("request_body", "_rev")
                .respond_with_actions(json!([{
                    "type": "send_doc_response",
                    "success": true,
                    "doc_id": "user1",
                    "rev": "2-def456"
                }]))
                .expect_calls(1)
                .and()
                // Delete document
                .on_event("couchdb_request")
                .and_event_data_contains("operation", "doc_delete")
                .and_event_data_contains("doc_id", "user1")
                .respond_with_actions(json!([{
                    "type": "send_doc_response",
                    "success": true,
                    "doc_id": "user1",
                    "rev": "3-ghi789"
                }]))
                .expect_calls(1)
                .and()
        });

    let test_state = start_netget_server(config).await?;
    let port = test_state.port;
    let client = reqwest::Client::new();
    let base_url = format!("http://127.0.0.1:{}/testdb", port);

    // Create document
    let doc = json!({"name": "Alice", "age": 30});
    let resp = client
        .put(format!("{}/user1", base_url))
        .json(&doc)
        .send()
        .await?;
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await?;
    assert_eq!(body["ok"], true);
    assert_eq!(body["id"], "user1");
    let rev1 = body["rev"].as_str().unwrap();

    // Get document
    let resp = client.get(format!("{}/user1", base_url)).send().await?;
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await?;
    assert_eq!(body["_id"], "user1");
    assert_eq!(body["name"], "Alice");
    assert_eq!(body["age"], 30);

    // Update document
    let doc = json!({"_id": "user1", "_rev": rev1, "name": "Alice", "age": 31});
    let resp = client
        .put(format!("{}/user1", base_url))
        .json(&doc)
        .send()
        .await?;
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await?;
    let rev2 = body["rev"].as_str().unwrap();

    // Delete document
    let resp = client
        .delete(format!("{}/user1?rev={}", base_url, rev2))
        .send()
        .await?;
    assert_eq!(resp.status(), 200);

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    test_state.wait_for_mocks(30).await;
    test_state.verify_mocks().await?;
    test_state.stop().await?;
    Ok(())
}

/// Test conflict detection (409)
#[tokio::test]
async fn test_couchdb_conflict_detection() -> E2EResult<()> {
    let config = NetGetConfig::new("Listen for CouchDB connections on port {AVAILABLE_PORT}")
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
                .and_event_data_contains("operation", "doc_put")
                .respond_with_actions(json!([{
                    "type": "send_doc_response",
                    "success": false,
                    "doc_id": "user1",
                    "rev": "2-current",
                    "error": "conflict",
                    "reason": "Document update conflict"
                }]))
                .expect_calls(1)
                .and()
        });

    let test_state = start_netget_server(config).await?;
    let port = test_state.port;
    let client = reqwest::Client::new();
    let base_url = format!("http://127.0.0.1:{}/testdb", port);

    // Try to update with old revision
    let doc = json!({"_id": "user1", "_rev": "1-old", "name": "Alice", "age": 31});
    let resp = client
        .put(format!("{}/user1", base_url))
        .json(&doc)
        .send()
        .await?;
    assert_eq!(resp.status(), 409);
    let body: serde_json::Value = resp.json().await?;
    assert_eq!(body["error"], "conflict");

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    test_state.wait_for_mocks(30).await;
    test_state.verify_mocks().await?;
    test_state.stop().await?;
    Ok(())
}

/// Test bulk operations
#[tokio::test]
async fn test_couchdb_bulk_operations() -> E2EResult<()> {
    let config = NetGetConfig::new("Listen for CouchDB connections on port {AVAILABLE_PORT}")
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
                // Bulk docs
                .on_event("couchdb_request")
                .and_event_data_contains("operation", "bulk_docs")
                .respond_with_actions(json!([{
                    "type": "send_bulk_docs_response",
                    "results": [
                        {"ok": true, "id": "doc1", "rev": "1-abc"},
                        {"ok": true, "id": "doc2", "rev": "1-def"}
                    ]
                }]))
                .expect_calls(1)
                .and()
                // All docs
                .on_event("couchdb_request")
                .and_event_data_contains("operation", "all_docs")
                .respond_with_actions(json!([{
                    "type": "send_all_docs",
                    "total_rows": 2,
                    "rows": [
                        {"id": "doc1", "key": "doc1", "value": {"rev": "1-abc"}},
                        {"id": "doc2", "key": "doc2", "value": {"rev": "1-def"}}
                    ]
                }]))
                .expect_calls(1)
                .and()
        });

    let test_state = start_netget_server(config).await?;
    let port = test_state.port;
    let client = reqwest::Client::new();
    let base_url = format!("http://127.0.0.1:{}/testdb", port);

    // Bulk docs
    let docs = json!({
        "docs": [
            {"_id": "doc1", "name": "Alice"},
            {"_id": "doc2", "name": "Bob"}
        ]
    });
    let resp = client
        .post(format!("{}/_bulk_docs", base_url))
        .json(&docs)
        .send()
        .await?;
    // Real CouchDB answers POST /{db}/_bulk_docs with 201 Created, and so does
    // `send_bulk_docs_response`.
    assert_eq!(resp.status(), 201);
    let body: serde_json::Value = resp.json().await?;
    assert_eq!(body.as_array().unwrap().len(), 2);

    // All docs
    let resp = client.get(format!("{}/_all_docs", base_url)).send().await?;
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await?;
    assert_eq!(body["total_rows"], 2);

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    test_state.wait_for_mocks(30).await;
    test_state.verify_mocks().await?;
    test_state.stop().await?;
    Ok(())
}

/// Test view queries
#[tokio::test]
async fn test_couchdb_view_query() -> E2EResult<()> {
    let config = NetGetConfig::new("Listen for CouchDB connections on port {AVAILABLE_PORT}")
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
                .and_event_data_contains("operation", "view_query")
                .respond_with_actions(json!([{
                    "type": "send_view_response",
                    "total_rows": 2,
                    "rows": [
                        {"id": "user1", "key": 25, "value": "Alice"},
                        {"id": "user2", "key": 30, "value": "Bob"}
                    ]
                }]))
                .expect_calls(1)
                .and()
        });

    let test_state = start_netget_server(config).await?;
    let port = test_state.port;
    let client = reqwest::Client::new();
    let base_url = format!("http://127.0.0.1:{}/testdb", port);

    // Query view
    let resp = client
        .get(format!("{}/_design/users/_view/by_age", base_url))
        .send()
        .await?;
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await?;
    assert_eq!(body["total_rows"], 2);
    assert_eq!(body["rows"].as_array().unwrap().len(), 2);

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    test_state.wait_for_mocks(30).await;
    test_state.verify_mocks().await?;
    test_state.stop().await?;
    Ok(())
}

/// Test basic authentication
#[tokio::test]
async fn test_couchdb_basic_auth() -> E2EResult<()> {
    let config =
        NetGetConfig::new("Listen for CouchDB connections on port {AVAILABLE_PORT} with basic auth enabled (username: admin, password: secret)")
            .with_mock(|mock| {
                mock.on_instruction_containing("Listen for CouchDB")
                    .respond_with_actions(json!([
                        {
                            "type": "open_server",
                            "port": 0,
                            "base_stack": "CouchDB",
                            "instruction": "Handle CouchDB protocol events with authentication",
                            "startup_params": {
                                "enable_auth": true,
                                "admin_username": "admin",
                                "admin_password": "secret"
                            }
                        }
                    ]))
                    .and()
                    // Only the *authenticated* request reaches the LLM. Basic auth is
                    // enforced in the server before `call_llm`, so an unauthenticated
                    // request is refused with 401 without consulting the model at all —
                    // fail closed. A rule keyed on `server_info` alone would match both
                    // requests, so declaring one per request made the first answer twice.
                    .on_event("couchdb_request")
                    .and_event_data_contains("operation", "server_info")
                    .and_event_data_contains("authorization", "***")
                    .respond_with_actions(json!([{
                        "type": "send_server_info",
                        "version": "3.5.1"
                    }]))
                    .expect_calls(1)
                    .and()
            });

    let test_state = start_netget_server(config).await?;
    let port = test_state.port;
    let client = reqwest::Client::new();
    let base_url = format!("http://127.0.0.1:{}", port);

    // Request without auth: refused by the server itself, no LLM call
    let resp = client.get(&base_url).send().await?;
    assert_eq!(resp.status(), 401);
    assert!(
        resp.headers()
            .get("www-authenticate")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .starts_with("Basic"),
        "401 must carry a Basic challenge"
    );

    // Wrong credentials are refused too
    let resp = client
        .get(&base_url)
        .basic_auth("admin", Some("wrong"))
        .send()
        .await?;
    assert_eq!(resp.status(), 401);

    // Request with auth
    let resp = client
        .get(&base_url)
        .basic_auth("admin", Some("secret"))
        .send()
        .await?;
    assert_eq!(resp.status(), 200);

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    test_state.wait_for_mocks(30).await;
    test_state.verify_mocks().await?;
    test_state.stop().await?;
    Ok(())
}

/// Test changes feed
#[tokio::test]
async fn test_couchdb_changes_feed() -> E2EResult<()> {
    let config = NetGetConfig::new("Listen for CouchDB connections on port {AVAILABLE_PORT}")
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
                .and_event_data_contains("operation", "changes")
                .respond_with_actions(json!([{
                    "type": "send_changes_response",
                    "results": [
                        {"seq": "1-abc", "id": "doc1", "changes": [{"rev": "1-xyz"}]},
                        {"seq": "2-def", "id": "doc2", "changes": [{"rev": "1-uvw"}]}
                    ],
                    "last_seq": "2-def"
                }]))
                .expect_calls(1)
                .and()
        });

    let test_state = start_netget_server(config).await?;
    let port = test_state.port;
    let client = reqwest::Client::new();
    let base_url = format!("http://127.0.0.1:{}/testdb", port);

    // Get changes
    let resp = client.get(format!("{}/_changes", base_url)).send().await?;
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await?;
    assert_eq!(body["last_seq"], "2-def");
    assert_eq!(body["results"].as_array().unwrap().len(), 2);

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    test_state.wait_for_mocks(30).await;
    test_state.verify_mocks().await?;
    test_state.stop().await?;
    Ok(())
}

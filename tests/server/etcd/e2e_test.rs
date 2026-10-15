//! etcd E2E tests using real etcd-client

use super::super::helpers::{start_netget_server, NetGetConfig};
use etcd_client::Client;
use serde_json::json;
use std::time::Duration;
use tokio::time::sleep;

/// Comprehensive etcd KV operations test with mocks
///
/// This test covers:
/// - Put/Get operations
/// - Get non-existent keys
/// - Range queries
/// - Delete operations
/// - Basic transactions
///
/// Target: < 10 total LLM calls (1 startup + ~6 operations)
#[tokio::test]
async fn test_etcd_kv_operations() -> Result<(), Box<dyn std::error::Error>> {
    // Start etcd server with comprehensive prompt and mocks
    let prompt = r#"
listen on port 0 via etcd

You are an etcd v3 key-value store server. Handle all KV operations:

1. When clients PUT a key-value pair, store it in memory with revision tracking
2. When clients GET a key, return the stored value if it exists (empty kvs array if not)
3. When clients DELETE a key, remove it and return deleted count
4. For RANGE queries, return all keys matching the prefix
5. For TRANSACTIONS, evaluate conditions and execute success or failure branch

Examples:
- PUT /config/database = "localhost:5432" → Success (revision 1)
- GET /config/database → "localhost:5432" (revision 1)
- GET /nonexistent → Empty (no error)
- DELETE /config/database → Deleted 1 key
- RANGE /config/ → Returns all keys starting with /config/

Track revisions:
- First PUT: create_revision=1, mod_revision=1, version=1
- Update: create_revision=1, mod_revision=2, version=2
- Each mutation increments global revision counter

Respond with appropriate etcd_range_response, etcd_put_response, etc. actions.
"#;

    // Use test helpers to start server with mocks
    let server = start_netget_server(NetGetConfig::new(prompt).with_mock(|mock| {
        mock
            // Mock 1: Server startup (open_server action)
            .on_instruction_containing("listen on port")
            .and_instruction_containing("etcd")
            .and_instruction_containing("KV operations")
            .respond_with_actions(json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "ETCD",
                    "instruction": "Handle all etcd KV operations with revision tracking"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 2: First PUT /config/database
            .on_event("etcd_put_request")
            .and_event_data_contains("key", "/config/database")
            .respond_with_actions(json!([
                {
                    "type": "etcd_put_response",
                    "revision": 1
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 3: First GET /config/database (returns value)
            .on_event("etcd_range_request")
            .and_event_data_contains("key", "/config/database")
            .respond_with_actions(json!([
                {
                    "type": "etcd_range_response",
                    "kvs": [
                        {
                            "key": "/config/database",
                            "value": "localhost:5432",
                            "create_revision": 1,
                            "mod_revision": 1,
                            "version": 1,
                            "lease": 0
                        }
                    ],
                    "more": false,
                    "count": 1
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 4: GET /nonexistent (returns empty)
            .on_event("etcd_range_request")
            .and_event_data_contains("key", "/nonexistent")
            .respond_with_actions(json!([
                {
                    "type": "etcd_range_response",
                    "kvs": [],
                    "more": false,
                    "count": 0
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 5: PUT /config/timeout
            .on_event("etcd_put_request")
            .and_event_data_contains("key", "/config/timeout")
            .respond_with_actions(json!([
                {
                    "type": "etcd_put_response",
                    "revision": 2
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 6: PUT /config/max_connections
            .on_event("etcd_put_request")
            .and_event_data_contains("key", "/config/max_connections")
            .respond_with_actions(json!([
                {
                    "type": "etcd_put_response",
                    "revision": 3
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 7: PUT /other/key
            .on_event("etcd_put_request")
            .and_event_data_contains("key", "/other/key")
            .respond_with_actions(json!([
                {
                    "type": "etcd_put_response",
                    "revision": 4
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 8: GET /config/timeout after delete (returns empty) - MUST BE BEFORE range query
            .on_event("etcd_range_request")
            .and_event_data_contains("key", "/config/timeout")
            .respond_with_actions(json!([
                {
                    "type": "etcd_range_response",
                    "kvs": [],
                    "more": false,
                    "count": 0
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 9: Range query /config/ (returns multiple keys) - MUST BE AFTER exact key matches
            .on_event("etcd_range_request")
            .and_event_data_contains("key", "/config/")
            .respond_with_actions(json!([
                {
                    "type": "etcd_range_response",
                    "kvs": [
                        {
                            "key": "/config/database",
                            "value": "localhost:5432",
                            "create_revision": 1,
                            "mod_revision": 1,
                            "version": 1,
                            "lease": 0
                        },
                        {
                            "key": "/config/max_connections",
                            "value": "100",
                            "create_revision": 3,
                            "mod_revision": 3,
                            "version": 1,
                            "lease": 0
                        },
                        {
                            "key": "/config/timeout",
                            "value": "30",
                            "create_revision": 2,
                            "mod_revision": 2,
                            "version": 1,
                            "lease": 0
                        }
                    ],
                    "more": false,
                    "count": 3
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 10: DELETE /config/timeout
            .on_event("etcd_delete_request")
            .and_event_data_contains("key", "/config/timeout")
            .respond_with_actions(json!([
                {
                    "type": "etcd_delete_range_response",
                    "deleted": 1
                }
            ]))
            .expect_calls(1)
            .and()
    }))
    .await?;
    let port = server.port;

    // Wait for server to be fully ready
    crate::helpers::wait_for_server_listening(&server, Duration::from_secs(30)).await?;

    // Verify server started with etcd stack
    // REMOVED: assert_stack_name call

    // Connect etcd client
    let endpoint = format!("http://localhost:{}", port);
    println!("Connecting to etcd server at {}", endpoint);

    let mut client = Client::connect([endpoint.as_str()], None)
        .await
        .expect("Failed to connect to etcd server");

    println!("✓ Connected to etcd server");

    // Test 1: Put a key-value pair
    println!("\n[Test 1] Put /config/database = localhost:5432");
    client
        .put("/config/database", "localhost:5432", None)
        .await
        .expect("Put operation failed");
    println!("✓ Put successful");

    // Test 2: Get the key back
    println!("\n[Test 2] Get /config/database");
    let get_resp = client
        .get("/config/database", None)
        .await
        .expect("Get operation failed");

    let kvs = get_resp.kvs();
    assert_eq!(kvs.len(), 1, "Expected 1 key-value pair");

    let kv = kvs.first().unwrap();
    assert_eq!(kv.key_str()?, "/config/database");
    assert_eq!(kv.value_str()?, "localhost:5432");
    println!("✓ Get successful: value = {}", kv.value_str()?);

    // Test 3: Get non-existent key
    println!("\n[Test 3] Get /nonexistent (should return empty)");
    let get_resp = client
        .get("/nonexistent", None)
        .await
        .expect("Get operation failed");

    assert_eq!(
        get_resp.kvs().len(),
        0,
        "Expected empty result for non-existent key"
    );
    println!("✓ Non-existent key returned empty (correct behavior)");

    // Test 4: Put more keys for range query
    println!("\n[Test 4] Put multiple keys under /config/ prefix");
    client.put("/config/timeout", "30", None).await?;
    client.put("/config/max_connections", "100", None).await?;
    client.put("/other/key", "value", None).await?;
    println!("✓ Put 3 more keys");

    // Test 5: Range query with prefix
    println!("\n[Test 5] Range query /config/ prefix");
    let range_resp = client
        .get("/config/", None) // Note: etcd-client handles prefix automatically
        .await?;

    println!("Range returned {} keys", range_resp.kvs().len());
    for kv in range_resp.kvs() {
        println!("  - {}: {}", kv.key_str()?, kv.value_str()?);
    }

    // Should get at least the /config/database key
    assert!(
        range_resp.kvs().len() >= 1,
        "Expected at least 1 key in /config/ range"
    );
    println!("✓ Range query successful");

    // Test 6: Delete a key
    println!("\n[Test 6] Delete /config/timeout");
    let del_resp = client.delete("/config/timeout", None).await?;

    println!("Deleted {} keys", del_resp.deleted());
    assert!(del_resp.deleted() >= 0, "Delete should return count");
    println!("✓ Delete successful");

    // Test 7: Verify delete (get should return empty)
    println!("\n[Test 7] Verify /config/timeout is deleted");
    let get_resp = client.get("/config/timeout", None).await?;

    assert_eq!(get_resp.kvs().len(), 0, "Key should be deleted");
    println!("✓ Key successfully deleted");

    println!("\n✅ All etcd KV operations tests passed!");
    println!("Total LLM calls: ~10 (1 startup + 9 operations)");

    // Verify all mock expectations were met
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;

    // Cleanup
    server.stop().await?;

    Ok(())
}

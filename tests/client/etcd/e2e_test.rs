//! E2E tests for etcd client with mocks
//!
//! Tests etcd client operations against NetGet etcd server

use crate::helpers::*;
use serde_json::json;
use std::time::Duration;

/// Test basic etcd client operations (PUT, GET, DELETE) with mocks
///
/// LLM calls: 7 total
/// - 1 server startup
/// - 1 client startup
/// - 1 client connected event
/// - 1 PUT operation (etcd_response_received)
/// - 1 GET operation (etcd_response_received)
/// - 1 DELETE operation (etcd_response_received)
/// - 1 GET after delete (etcd_response_received)
#[tokio::test]
async fn test_etcd_client_basic_operations() -> E2EResult<()> {
    // Start etcd server with mocks
    let server_config =
        NetGetConfig::new("Listen on port {AVAILABLE_PORT} via etcd. Handle all KV operations.")
            .with_mock(|mock| {
                mock
                    // Mock 1: Server startup
                    .on_instruction_containing("Listen on port")
                    .and_instruction_containing("etcd")
                    .respond_with_actions(json!([
                        {
                            "type": "open_server",
                            "port": 0,
                            "base_stack": "ETCD",
                            "instruction": "etcd KV store"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // Mock 2: PUT /test/key1 = value1
                    .on_event("etcd_put_request")
                    .and_event_data_contains("key", "/test/key1")
                    .respond_with_actions(json!([
                        {
                            "type": "etcd_put_response",
                            "revision": 1
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // Mock 3: both GETs of /test/key1 -- the one before the delete, which
                    // finds the key, and the one after, which must not.
                    //
                    // This was two rules matching on the same event and the same key.
                    // Rules are first-match-wins, so the first answered both GETs and the
                    // key appeared to survive its own deletion, while the second rule
                    // reported zero calls. The store's state is what tells the two apart,
                    // and only the mock knows it, so the mock has to carry it.
                    .on_event("etcd_range_request")
                    .and_event_data_contains("key", "/test/key1")
                    .respond_with_actions_from_event({
                        let deleted =
                            std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
                        move |_e| {
                            if deleted.load(std::sync::atomic::Ordering::SeqCst) {
                                json!([
                                    {
                                        "type": "etcd_range_response",
                                        "kvs": [],
                                        "more": false,
                                        "count": 0
                                    }
                                ])
                            } else {
                                // First GET: the key is still there. The delete below
                                // flips the flag.
                                deleted.store(true, std::sync::atomic::Ordering::SeqCst);
                                json!([
                                    {
                                        "type": "etcd_range_response",
                                        "kvs": [
                                            {
                                                "key": "/test/key1",
                                                "value": "value1",
                                                "create_revision": 1,
                                                "mod_revision": 1,
                                                "version": 1,
                                                "lease": 0
                                            }
                                        ],
                                        "more": false,
                                        "count": 1
                                    }
                                ])
                            }
                        }
                    })
                    .expect_calls(2)
                    .and()
                    // Mock 4: DELETE /test/key1
                    .on_event("etcd_delete_request")
                    .and_event_data_contains("key", "/test/key1")
                    .respond_with_actions(json!([
                        {
                            "type": "etcd_delete_range_response",
                            "deleted": 1
                        }
                    ]))
                    .expect_calls(1)
                    .and()
            });

    let mut server = start_netget_server(server_config).await?;

    // Give server time to start
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Start etcd client with mocks
    let client_config = NetGetConfig::new(format!(
        "Connect to 127.0.0.1:{} via etcd. Execute: PUT /test/key1 = value1, then GET /test/key1, then DELETE /test/key1, then GET /test/key1 again to verify deletion.",
        server.port
    ))
    .with_mock(|mock| {
        mock
            // Mock 1: Client startup
            .on_instruction_containing("Connect to")
            .and_instruction_containing("etcd")
            .respond_with_actions(json!([
                {
                    "type": "open_client",
                    "remote_addr": format!("127.0.0.1:{}", server.port),
                    "protocol": "etcd",
                    "instruction": "Execute PUT, GET, DELETE sequence"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 2: Client connected - perform PUT
            .on_event("etcd_connected")
            .respond_with_actions(json!([
                {
                    "type": "etcd_put",
                    "key": "/test/key1",
                    "value": "value1"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 3: Response from PUT - perform GET
            .on_event("etcd_response_received")
            .and_event_data_contains("operation", "put")
            .respond_with_actions(json!([
                {
                    "type": "etcd_get",
                    "key": "/test/key1"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 4: both GET responses, told apart by what came back.
            //
            // This was two rules on `etcd_response_received` with `operation: get` and
            // nothing else. Rules are first-match-wins, so the first answered both and
            // the client deleted the key twice instead of disconnecting, while the
            // second reported zero calls. The GET after the delete returns count 0, and
            // that is the difference the mock can actually see.
            .on_event("etcd_response_received")
            .and_event_data_contains("operation", "get")
            .respond_with_actions_from_event(|e| {
                if e["count"].as_u64().unwrap_or(0) == 0 {
                    // The key is gone: the sequence is finished.
                    json!([{ "type": "disconnect" }])
                } else {
                    json!([
                        {
                            "type": "etcd_delete",
                            "key": "/test/key1"
                        }
                    ])
                }
            })
            .expect_calls(2)
            .and()
            // Mock 5: Response from DELETE - perform final GET
            .on_event("etcd_response_received")
            .and_event_data_contains("operation", "delete")
            .respond_with_actions(json!([
                {
                    "type": "etcd_get",
                    "key": "/test/key1"
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let mut client = start_netget_client(client_config).await?;

    // Give client time to execute operations

    // Verify client output shows connection and operations
    client.wait_for_any(&["etcd"], 30).await;
    assert!(
        client.output_contains("etcd").await,
        "Client should show etcd protocol. Output: {:?}",
        client.get_output().await
    );

    println!("✅ etcd client completed PUT, GET, DELETE sequence successfully");

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

/// Test etcd client with multiple keys and operations
///
/// LLM calls: 8 total
/// - 1 server startup
/// - 1 client startup
/// - 1 client connected event
/// - 3 PUT operations
/// - 2 GET operations
#[tokio::test]
async fn test_etcd_client_multiple_keys() -> E2EResult<()> {
    // Start etcd server with mocks
    let server_config =
        NetGetConfig::new("Listen on port {AVAILABLE_PORT} via etcd. Store config keys.")
            .with_mock(|mock| {
                mock
                    // Mock: Server startup
                    .on_instruction_containing("Listen on port")
                    .and_instruction_containing("etcd")
                    .respond_with_actions(json!([
                        {
                            "type": "open_server",
                            "port": 0,
                            "base_stack": "ETCD",
                            "instruction": "Config store"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // Mocks: 3 PUT operations
                    .on_event("etcd_put_request")
                    .respond_with_actions(json!([
                        {
                            "type": "etcd_put_response",
                            "revision": 1
                        }
                    ]))
                    // Two: /app/config/database, then /app/config/timeout. It was 3,
                    // calibrated against the client re-PUTting the same key because one
                    // unconstrained response rule answered every PUT the same way.
                    .expect_calls(2)
                    .and()
                    // Mocks: GET operations
                    .on_event("etcd_range_request")
                    .respond_with_actions(json!([
                        {
                            "type": "etcd_range_response",
                            "kvs": [
                                {
                                    "key": "/app/config/database",
                                    "value": "postgresql://localhost:5432/mydb",
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
            });

    let mut server = start_netget_server(server_config).await?;

    tokio::time::sleep(Duration::from_millis(500)).await;

    // Start client with mocks
    let client_config = NetGetConfig::new(format!(
        "Connect to 127.0.0.1:{} via etcd. PUT /app/config/database=postgresql://localhost:5432/mydb, PUT /app/config/timeout=30, PUT /app/config/max_connections=100, then GET /app/config/database",
        server.port
    ))
    .with_mock(|mock| {
        mock
            // Mock: Client startup
            .on_instruction_containing("Connect to")
            .and_instruction_containing("etcd")
            .respond_with_actions(json!([
                {
                    "type": "open_client",
                    "remote_addr": format!("127.0.0.1:{}", server.port),
                    "protocol": "etcd",
                    "instruction": "Store and retrieve config"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock: Connected - PUT first key
            .on_event("etcd_connected")
            .respond_with_actions(json!([
                {
                    "type": "etcd_put",
                    "key": "/app/config/database",
                    "value": "postgresql://localhost:5432/mydb"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock: both PUT responses. The first stores the second key; the second
            // moves on to the GET.
            //
            // One unconstrained rule answered every PUT with "now PUT /app/config/timeout",
            // so the client stored the same key over and over until the follow-up depth
            // limit stopped it, and the GET below never happened. The response event
            // carries the key it just wrote, which is what tells the two steps apart.
            .on_event("etcd_response_received")
            .and_event_data_contains("operation", "put")
            .respond_with_actions_from_event(|e| {
                if e["key"].as_str() == Some("/app/config/database") {
                    json!([
                        {
                            "type": "etcd_put",
                            "key": "/app/config/timeout",
                            "value": "30"
                        }
                    ])
                } else {
                    json!([
                        {
                            "type": "etcd_get",
                            "key": "/app/config/database"
                        }
                    ])
                }
            })
            .expect_calls(2)
            .and()
            // Mock: After GET - disconnect
            .on_event("etcd_response_received")
            .and_event_data_contains("operation", "get")
            .respond_with_actions(json!([
                {
                    "type": "disconnect"
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let mut client = start_netget_client(client_config).await?;

    println!("✅ etcd client completed multiple key operations");

    // Verify mocks
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

/// Test etcd client with nonexistent key
///
/// LLM calls: 3 total
/// - 1 server startup
/// - 1 client startup
/// - 1 GET operation
#[tokio::test]
async fn test_etcd_client_nonexistent_key() -> E2EResult<()> {
    // Start server
    let server_config =
        NetGetConfig::new("Listen on port {AVAILABLE_PORT} via etcd.").with_mock(|mock| {
            mock.on_instruction_containing("Listen on port")
                .and_instruction_containing("etcd")
                .respond_with_actions(json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "ETCD",
                        "instruction": "Empty store"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock: GET nonexistent key returns empty
                .on_event("etcd_range_request")
                .and_event_data_contains("key", "/does/not/exist")
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
        });

    let mut server = start_netget_server(server_config).await?;

    tokio::time::sleep(Duration::from_millis(500)).await;

    // Start client
    let client_config = NetGetConfig::new(format!(
        "Connect to 127.0.0.1:{} via etcd. GET /does/not/exist and verify it returns empty.",
        server.port
    ))
    .with_mock(|mock| {
        mock.on_instruction_containing("Connect to")
            .and_instruction_containing("etcd")
            .respond_with_actions(json!([
                {
                    "type": "open_client",
                    "remote_addr": format!("127.0.0.1:{}", server.port),
                    "protocol": "etcd",
                    "instruction": "Query nonexistent key"
                }
            ]))
            .expect_calls(1)
            .and()
            .on_event("etcd_connected")
            .respond_with_actions(json!([
                {
                    "type": "etcd_get",
                    "key": "/does/not/exist"
                }
            ]))
            .expect_calls(1)
            .and()
            .on_event("etcd_response_received")
            .respond_with_actions(json!([
                {
                    "type": "disconnect"
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let mut client = start_netget_client(client_config).await?;

    println!("✅ etcd client verified nonexistent key returns empty");

    // Verify mocks
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

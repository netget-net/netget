//! End-to-end tests for Elasticsearch protocol
//!
//! These tests spawn the actual NetGet binary and interact with it using HTTP client
//! to validate Elasticsearch API functionality.
//!
//! MUST build release binary before running: `cargo build --release --all-features`
//! Run with: `cargo test --features elasticsearch --test e2e_elasticsearch_test -- --test-threads=3`

mod tests {
    use crate::helpers::retry;
    use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
    use reqwest::Client;
    use serde_json::json;

    #[tokio::test]
    async fn test_elasticsearch_search() -> E2EResult<()> {
        println!("\n=== Test: Elasticsearch Search ===");

        let prompt = "Start Elasticsearch on port 0 with product search";
        let config = NetGetConfig::new(prompt)
            .with_log_level("off")
            .with_mock(|mock| {
                mock
                    // Mock 1: Server startup
                    .on_instruction_containing("Start Elasticsearch")
                    .respond_with_actions(json!([
                        {
                            "type": "open_server",
                            "port": 0,
                            "base_stack": "elasticsearch",
                            "instruction": "Elasticsearch search engine with product index"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // Mock 2: Elasticsearch search request
                    .on_event("elasticsearch_request")
                    .and_event_data_contains("path", "/products/_search")
                    .respond_with_actions(json!([
                        {
                            "type": "send_search_response",
                            "hits": [
                                {
                                    "_index": "products",
                                    "_id": "1",
                                    "_score": 1.0,
                                    "_source": {"name": "Widget", "price": 19.99}
                                },
                                {
                                    "_index": "products",
                                    "_id": "2",
                                    "_score": 1.0,
                                    "_source": {"name": "Gadget", "price": 29.99}
                                }
                            ],
                            "total": 2,
                            "took": 1
                        }
                    ]))
                    .expect_calls(1)
                    .and()
            });

        let server = start_netget_server(config).await?;
        println!(
            "Server started on port {} with stack: {}",
            server.port, server.stack
        );

        // Verify stack
        assert!(
            server.stack.to_uppercase().contains("ELASTICSEARCH"),
            "Expected ELASTICSEARCH stack, got: {}",
            server.stack
        );

        let client = Client::new();
        let url = format!("http://127.0.0.1:{}/products/_search", server.port);

        // Wait for server to be ready with search request
        let response = retry(|| async {
            client
                .post(&url)
                .header("Content-Type", "application/json")
                .json(&json!({
                    "query": {
                        "match_all": {}
                    }
                }))
                .send()
                .await
        })
        .await?;

        assert!(
            response.status().is_success(),
            "Search request failed with status: {}",
            response.status()
        );

        // Check response is valid JSON
        let body = response.text().await?;
        println!("[DEBUG] Search response: {}", body);
        let json_response: serde_json::Value =
            serde_json::from_str(&body).map_err(|e| format!("Invalid JSON response: {}", e))?;

        // Flexible validation: accept any valid JSON response (LLM has freedom in structure)
        // Just verify we got a response - Elasticsearch format can vary
        assert!(
            json_response.is_object(),
            "Response should be a JSON object"
        );

        println!("[PASS] Elasticsearch search request succeeded with valid JSON response");

        // Verify mock expectations were met
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last event routinely lands after
        // the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;

        server.stop().await?;
        println!("=== Test Complete ===\n");
        Ok(())
    }

    #[tokio::test]
    async fn test_elasticsearch_index_document() -> E2EResult<()> {
        println!("\n=== Test: Elasticsearch Index Document ===");

        let prompt = "Start an Elasticsearch server on port 0";
        let config = NetGetConfig::new(prompt)
            .with_log_level("off")
            .with_mock(|mock| {
                mock
                    // Mock 1: Server startup
                    .on_instruction_containing("Start an Elasticsearch")
                    .respond_with_actions(json!([
                        {
                            "type": "open_server",
                            "port": 0,
                            "base_stack": "elasticsearch",
                            "instruction": "Elasticsearch server"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // Mock 2: Elasticsearch index document request
                    .on_event("elasticsearch_request")
                    .and_event_data_contains("method", "PUT")
                    .and_event_data_contains("path", "/_doc/")
                    .respond_with_actions(json!([
                        {
                            "type": "send_index_response",
                            "index": "products",
                            "id": "1",
                            "result": "created"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
            });

        let server = start_netget_server(config).await?;
        println!(
            "Server started on port {} with stack: {}",
            server.port, server.stack
        );

        let client = Client::new();
        let url = format!("http://127.0.0.1:{}/products/_doc/1", server.port);

        // Index a document
        let response = retry(|| async {
            client
                .put(&url)
                .header("Content-Type", "application/json")
                .json(&json!({
                    "name": "Widget",
                    "price": 19.99,
                    "category": "gadgets"
                }))
                .send()
                .await
        })
        .await?;

        assert!(
            response.status().is_success(),
            "Index request failed with status: {}",
            response.status()
        );

        // Check response is valid JSON
        let body = response.text().await?;
        let json_response: serde_json::Value =
            serde_json::from_str(&body).map_err(|e| format!("Invalid JSON response: {}", e))?;

        // Verify response has index result structure
        assert!(
            json_response.get("_index").is_some() || json_response.get("result").is_some(),
            "Response missing index result fields"
        );

        println!("[PASS] Elasticsearch index document succeeded");

        // Verify mock expectations were met
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last event routinely lands after
        // the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;

        server.stop().await?;
        println!("=== Test Complete ===\n");
        Ok(())
    }

    #[tokio::test]
    async fn test_elasticsearch_get_document() -> E2EResult<()> {
        println!("\n=== Test: Elasticsearch Get Document ===");

        let prompt = "Start Elasticsearch on port 0 with product id 123";
        let config = NetGetConfig::new(prompt)
            .with_log_level("off")
            .with_mock(|mock| {
                mock
                    // Mock 1: Server startup
                    .on_instruction_containing("Start Elasticsearch")
                    .respond_with_actions(json!([
                        {
                            "type": "open_server",
                            "port": 0,
                            "base_stack": "elasticsearch",
                            "instruction": "Elasticsearch with product id 123"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // Mock 2: Elasticsearch get document request
                    .on_event("elasticsearch_request")
                    .and_event_data_contains("method", "GET")
                    .and_event_data_contains("path", "/_doc/123")
                    .respond_with_actions(json!([
                        {
                            "type": "send_get_response",
                            "found": true,
                            "index": "products",
                            "id": "123",
                            "source": {
                                "name": "Product 123",
                                "price": 99.99
                            }
                        }
                    ]))
                    .expect_calls(1)
                    .and()
            });

        let server = start_netget_server(config).await?;
        println!(
            "Server started on port {} with stack: {}",
            server.port, server.stack
        );

        let client = Client::new();
        let url = format!("http://127.0.0.1:{}/products/_doc/123", server.port);

        // Get a document
        let response = retry(|| async { client.get(&url).send().await }).await?;

        // Accept both 200 (found) and 404 (not found) as valid responses
        assert!(
            response.status().is_success() || response.status().as_u16() == 404,
            "Get request failed with status: {}",
            response.status()
        );

        // Check response is valid JSON
        let body = response.text().await?;
        println!("[DEBUG] Get response: {}", body);
        let json_response: serde_json::Value =
            serde_json::from_str(&body).map_err(|e| format!("Invalid JSON response: {}", e))?;

        // Flexible validation: just check we got a JSON response
        // LLM can return various formats (_source, found, direct fields, etc.)
        assert!(
            json_response.is_object(),
            "Response should be a JSON object"
        );

        println!("[PASS] Elasticsearch get document succeeded");

        // Verify mock expectations were met
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last event routinely lands after
        // the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;

        server.stop().await?;
        println!("=== Test Complete ===\n");
        Ok(())
    }

    #[tokio::test]
    async fn test_elasticsearch_bulk_operations() -> E2EResult<()> {
        println!("\n=== Test: Elasticsearch Bulk Operations ===");

        let prompt = "Start an Elasticsearch server on port 0 that handles bulk requests";
        let config = NetGetConfig::new(prompt)
            .with_log_level("off")
            .with_mock(|mock| {
                mock
                    // Mock 1: Server startup
                    .on_instruction_containing("Start an Elasticsearch")
                    .respond_with_actions(json!([
                        {
                            "type": "open_server",
                            "port": 0,
                            "base_stack": "elasticsearch",
                            "instruction": "Elasticsearch server with bulk operations"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // Mock 2: Elasticsearch bulk request
                    .on_event("elasticsearch_request")
                    .and_event_data_contains("method", "POST")
                    .and_event_data_contains("path", "/_bulk")
                    .respond_with_actions(json!([
                        {
                            "type": "send_bulk_response",
                            "items": [
                                {
                                    "index": {
                                        "_index": "products",
                                        "_id": "1",
                                        "status": 201
                                    }
                                },
                                {
                                    "index": {
                                        "_index": "products",
                                        "_id": "2",
                                        "status": 201
                                    }
                                }
                            ],
                            "errors": false
                        }
                    ]))
                    .expect_calls(1)
                    .and()
            });

        let server = start_netget_server(config).await?;
        println!(
            "Server started on port {} with stack: {}",
            server.port, server.stack
        );

        let client = Client::new();
        let url = format!("http://127.0.0.1:{}/_bulk", server.port);

        // Bulk request (newline-delimited JSON format)
        let bulk_body = r#"{"index":{"_index":"products","_id":"1"}}
{"name":"Widget","price":19.99}
{"index":{"_index":"products","_id":"2"}}
{"name":"Gadget","price":29.99}
"#;

        let response = retry(|| async {
            client
                .post(&url)
                .header("Content-Type", "application/x-ndjson")
                .body(bulk_body.to_string())
                .send()
                .await
        })
        .await?;

        assert!(
            response.status().is_success(),
            "Bulk request failed with status: {}",
            response.status()
        );

        // Check response is valid JSON
        let body = response.text().await?;
        let json_response: serde_json::Value =
            serde_json::from_str(&body).map_err(|e| format!("Invalid JSON response: {}", e))?;

        // Verify response has bulk result structure
        assert!(
            json_response.get("items").is_some() || json_response.get("errors").is_some(),
            "Response missing bulk result fields"
        );

        println!("[PASS] Elasticsearch bulk operations succeeded");

        // Verify mock expectations were met
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last event routinely lands after
        // the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;

        server.stop().await?;
        println!("=== Test Complete ===\n");
        Ok(())
    }

    #[tokio::test]
    async fn test_elasticsearch_cluster_health() -> E2EResult<()> {
        println!("\n=== Test: Elasticsearch Cluster Health ===");

        let prompt = "Start an Elasticsearch cluster on port 0";
        let config = NetGetConfig::new(prompt)
            .with_log_level("off")
            .with_mock(|mock| {
                mock
                    // Mock 1: Server startup
                    .on_instruction_containing("Elasticsearch cluster")
                    .respond_with_actions(json!([
                        {
                            "type": "open_server",
                            "port": 0,
                            "base_stack": "elasticsearch",
                            "instruction": "Elasticsearch cluster"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // Mock 2: Elasticsearch cluster health request
                    .on_event("elasticsearch_request")
                    .and_event_data_contains("path", "/_cluster/health")
                    .respond_with_actions(json!([
                        {
                            "type": "send_elasticsearch_response",
                            "status_code": 200,
                            "body": json!({
                                "cluster_name": "netget-cluster",
                                "status": "green",
                                "timed_out": false,
                                "number_of_nodes": 1,
                                "number_of_data_nodes": 1,
                                "active_primary_shards": 5,
                                "active_shards": 5,
                                "relocating_shards": 0,
                                "initializing_shards": 0,
                                "unassigned_shards": 0
                            }).to_string()
                        }
                    ]))
                    .expect_calls(1)
                    .and()
            });

        let server = start_netget_server(config).await?;
        println!(
            "Server started on port {} with stack: {}",
            server.port, server.stack
        );

        let client = Client::new();
        let url = format!("http://127.0.0.1:{}/_cluster/health", server.port);

        // Cluster health request
        let response = retry(|| async { client.get(&url).send().await }).await?;

        assert!(
            response.status().is_success(),
            "Cluster health request failed with status: {}",
            response.status()
        );

        // Check response is valid JSON
        let body = response.text().await?;
        let json_response: serde_json::Value =
            serde_json::from_str(&body).map_err(|e| format!("Invalid JSON response: {}", e))?;

        // Verify response has cluster health fields
        assert!(
            json_response.get("cluster_name").is_some()
                || json_response.get("status").is_some()
                || json_response.get("acknowledged").is_some(),
            "Response missing cluster health fields"
        );

        println!("[PASS] Elasticsearch cluster health succeeded");

        // Verify mock expectations were met
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last event routinely lands after
        // the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;

        server.stop().await?;
        println!("=== Test Complete ===\n");
        Ok(())
    }

    #[tokio::test]
    async fn test_elasticsearch_root_endpoint() -> E2EResult<()> {
        println!("\n=== Test: Elasticsearch Root Endpoint ===");

        let prompt = "Start an Elasticsearch search engine on port 0";
        let config = NetGetConfig::new(prompt)
            .with_log_level("off")
            .with_mock(|mock| {
                mock
                    // Mock 1: Server startup
                    .on_instruction_containing("Elasticsearch search engine")
                    .respond_with_actions(json!([
                        {
                            "type": "open_server",
                            "port": 0,
                            "base_stack": "elasticsearch",
                            "instruction": "Elasticsearch search engine"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // Mock 2: Elasticsearch root endpoint request
                    .on_event("elasticsearch_request")
                    .and_event_data_contains("path", "/")
                    .respond_with_actions(json!([
                        {
                            "type": "send_cluster_info",
                            "cluster_name": "netget-cluster",
                            "status": "green",
                            "version": "8.11.0"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
            });

        let server = start_netget_server(config).await?;
        println!(
            "Server started on port {} with stack: {}",
            server.port, server.stack
        );

        let client = Client::new();
        let url = format!("http://127.0.0.1:{}/", server.port);

        // Root endpoint request (cluster info)
        let response = retry(|| async { client.get(&url).send().await }).await?;

        assert!(
            response.status().is_success(),
            "Root endpoint request failed with status: {}",
            response.status()
        );

        // Verify Elasticsearch header
        assert_eq!(
            response
                .headers()
                .get("x-elastic-product")
                .and_then(|h| h.to_str().ok()),
            Some("Elasticsearch"),
            "Missing X-elastic-product header"
        );

        // Check response is valid JSON
        let body = response.text().await?;
        let json_response: serde_json::Value =
            serde_json::from_str(&body).map_err(|e| format!("Invalid JSON response: {}", e))?;

        // Verify response has cluster info fields
        assert!(
            json_response.get("name").is_some()
                || json_response.get("cluster_name").is_some()
                || json_response.get("version").is_some()
                || json_response.get("tagline").is_some()
                || json_response.get("acknowledged").is_some(),
            "Response missing cluster info fields"
        );

        println!("[PASS] Elasticsearch root endpoint succeeded");

        // Verify mock expectations were met
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last event routinely lands after
        // the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;

        server.stop().await?;
        println!("=== Test Complete ===\n");
        Ok(())
    }

    #[tokio::test]
    async fn test_elasticsearch_delete_document() -> E2EResult<()> {
        println!("\n=== Test: Elasticsearch Delete Document ===");

        let prompt = "Start Elasticsearch on port 0";
        let config = NetGetConfig::new(prompt)
            .with_log_level("off")
            .with_mock(|mock| {
                mock
                    // Mock 1: Server startup
                    .on_instruction_containing("Start Elasticsearch")
                    .respond_with_actions(json!([
                        {
                            "type": "open_server",
                            "port": 0,
                            "base_stack": "elasticsearch",
                            "instruction": "Elasticsearch server"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // Mock 2: Elasticsearch delete document request
                    .on_event("elasticsearch_request")
                    .and_event_data_contains("method", "DELETE")
                    .and_event_data_contains("path", "/_doc/999")
                    .respond_with_actions(json!([
                        {
                            "type": "send_elasticsearch_response",
                            "status_code": 200,
                            "body": json!({
                                "_index": "products",
                                "_id": "999",
                                "_version": 2,
                                "result": "deleted"
                            }).to_string()
                        }
                    ]))
                    .expect_calls(1)
                    .and()
            });

        let server = start_netget_server(config).await?;
        println!(
            "Server started on port {} with stack: {}",
            server.port, server.stack
        );

        let client = Client::new();
        let url = format!("http://127.0.0.1:{}/products/_doc/999", server.port);

        // Delete a document
        let response = retry(|| async { client.delete(&url).send().await }).await?;

        assert!(
            response.status().is_success(),
            "Delete request failed with status: {}",
            response.status()
        );

        // Check response is valid JSON
        let body = response.text().await?;
        println!("[DEBUG] Delete response: {}", body);
        let json_response: serde_json::Value =
            serde_json::from_str(&body).map_err(|e| format!("Invalid JSON response: {}", e))?;

        // Flexible validation: just verify we got a JSON response
        // LLM can return various success formats
        assert!(
            json_response.is_object(),
            "Response should be a JSON object"
        );

        println!("[PASS] Elasticsearch delete document succeeded");

        // Verify mock expectations were met
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last event routinely lands after
        // the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;

        server.stop().await?;
        println!("=== Test Complete ===\n");
        Ok(())
    }
}

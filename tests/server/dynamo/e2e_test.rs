//! End-to-end tests for DynamoDB protocol
//!
//! These tests spawn the actual NetGet binary and interact with it using HTTP client
//! to validate DynamoDB API functionality.
//!
//! Run with:
//! `cargo test --no-default-features --features dynamo --test server -- server::dynamo`
//!
//! Two corrections to what this header used to say. `--test` names a cargo *target*
//! (`tests/server.rs`), not a module path, so `--test server::dynamo::e2e_test` matched no
//! target and cargo listed the available targets and exited having run nothing. And no
//! release build is needed first: the harness resolves the binary through
//! `CARGO_BIN_EXE_netget`, which is the binary cargo built for *this* test with *these*
//! features (`tests/helpers/common.rs`).

mod tests {
    use crate::helpers::retry;
    use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
    use reqwest::Client;
    use serde_json::json;

    #[tokio::test]
    async fn test_dynamo_get_item() -> E2EResult<()> {
        println!("\n=== Test: DynamoDB GetItem ===");

        let prompt = "Start a DynamoDB-compatible server on port 0 that stores user data in memory";
        let config = NetGetConfig::new(prompt)
            .with_log_level("off")
            .with_mock(|mock| {
                mock
                    // Mock 1: Server startup (user command)
                    .on_instruction_containing("DynamoDB")
                    .and_instruction_containing("server")
                    .respond_with_actions(json!([
                        {
                            "type": "open_server",
                            "port": 0,
                            "base_stack": "DYNAMO",
                            "instruction": "Handle DynamoDB operations and respond with appropriate JSON"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // Mock 2: GetItem operation (dynamo_request event)
                    .on_event("dynamo_request")
                    .and_event_data_contains("operation", "GetItem")
                    .respond_with_actions(json!([
                        {
                            "type": "send_dynamo_response",
                            "status_code": 200,
                            "body": "{\"Item\":{\"id\":{\"S\":\"user-123\"},\"name\":{\"S\":\"Alice\"}}}"
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
            server.stack.to_lowercase().contains("dynamo"),
            "Expected DynamoDB stack, got: {}",
            server.stack
        );

        let client = Client::new();
        let url = format!("http://127.0.0.1:{}", server.port);

        // Wait for server to be ready
        retry(|| async {
            client
                .post(&url)
                .header("x-amz-target", "DynamoDB_20120810.GetItem")
                .header("Content-Type", "application/x-amz-json-1.0")
                .json(&json!({
                    "TableName": "Users",
                    "Key": {
                        "id": {"S": "user-123"}
                    }
                }))
                .send()
                .await
        })
        .await?;

        println!("[PASS] DynamoDB GetItem request succeeded");

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
    async fn test_dynamo_put_item() -> E2EResult<()> {
        println!("\n=== Test: DynamoDB PutItem ===");

        let prompt = "Start a DynamoDB server on port 0";
        let config = NetGetConfig::new(prompt)
            .with_log_level("off")
            .with_mock(|mock| {
                mock
                    // Mock 1: Server startup (user command)
                    .on_instruction_containing("DynamoDB")
                    .and_instruction_containing("server")
                    .respond_with_actions(json!([
                        {
                            "type": "open_server",
                            "port": 0,
                            "base_stack": "DYNAMO",
                            "instruction": "Handle DynamoDB operations and respond with appropriate JSON"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // Mock 2: PutItem operation (dynamo_request event)
                    .on_event("dynamo_request")
                    .and_event_data_contains("operation", "PutItem")
                    .respond_with_actions(json!([
                        {
                            "type": "send_dynamo_response",
                            "status_code": 200,
                            "body": "{}"
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
        let url = format!("http://127.0.0.1:{}", server.port);

        // PutItem request
        let response = retry(|| async {
            client
                .post(&url)
                .header("x-amz-target", "DynamoDB_20120810.PutItem")
                .header("Content-Type", "application/x-amz-json-1.0")
                .json(&json!({
                    "TableName": "Users",
                    "Item": {
                        "id": {"S": "user-456"},
                        "name": {"S": "Bob"},
                        "email": {"S": "bob@example.com"}
                    }
                }))
                .send()
                .await
        })
        .await?;

        assert!(
            response.status().is_success(),
            "PutItem request failed with status: {}",
            response.status()
        );

        println!("[PASS] DynamoDB PutItem request succeeded");

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
    async fn test_dynamo_query() -> E2EResult<()> {
        println!("\n=== Test: DynamoDB Query ===");

        let prompt = "Start a DynamoDB-compatible database server on port 0";
        let config = NetGetConfig::new(prompt)
            .with_log_level("off")
            .with_mock(|mock| {
                mock
                    // Mock 1: Server startup (user command)
                    .on_instruction_containing("DynamoDB")
                    .and_instruction_containing("server")
                    .respond_with_actions(json!([
                        {
                            "type": "open_server",
                            "port": 0,
                            "base_stack": "DYNAMO",
                            "instruction": "Handle DynamoDB operations and respond with appropriate JSON"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // Mock 2: Query operation (dynamo_request event)
                    .on_event("dynamo_request")
                    .and_event_data_contains("operation", "Query")
                    .respond_with_actions(json!([
                        {
                            "type": "send_dynamo_response",
                            "status_code": 200,
                            "body": "{\"Items\":[{\"id\":{\"S\":\"user-123\"},\"name\":{\"S\":\"Alice\"}}],\"Count\":1,\"ScannedCount\":1}"
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
        let url = format!("http://127.0.0.1:{}", server.port);

        // Query request
        let response = retry(|| async {
            client
                .post(&url)
                .header("x-amz-target", "DynamoDB_20120810.Query")
                .header("Content-Type", "application/x-amz-json-1.0")
                .json(&json!({
                    "TableName": "Users",
                    "KeyConditionExpression": "id = :id",
                    "ExpressionAttributeValues": {
                        ":id": {"S": "user-123"}
                    }
                }))
                .send()
                .await
        })
        .await?;

        assert!(
            response.status().is_success(),
            "Query request failed with status: {}",
            response.status()
        );

        // Check response is valid JSON
        let body = response.text().await?;
        let _: serde_json::Value =
            serde_json::from_str(&body).map_err(|e| format!("Invalid JSON response: {}", e))?;

        println!("[PASS] DynamoDB Query request succeeded with valid JSON");

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
    async fn test_dynamo_create_table() -> E2EResult<()> {
        println!("\n=== Test: DynamoDB CreateTable ===");

        let prompt = "Start a DynamoDB API server on port 0 that can create tables";
        let config = NetGetConfig::new(prompt)
            .with_log_level("off")
            .with_mock(|mock| {
                mock
                    // Mock 1: Server startup (user command)
                    .on_instruction_containing("DynamoDB")
                    .and_instruction_containing("server")
                    .respond_with_actions(json!([
                        {
                            "type": "open_server",
                            "port": 0,
                            "base_stack": "DYNAMO",
                            "instruction": "Handle DynamoDB operations and respond with appropriate JSON"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // Mock 2: CreateTable operation (dynamo_request event)
                    .on_event("dynamo_request")
                    .and_event_data_contains("operation", "CreateTable")
                    .respond_with_actions(json!([
                        {
                            "type": "send_dynamo_response",
                            "status_code": 200,
                            "body": "{\"TableDescription\":{\"TableName\":\"Products\",\"TableStatus\":\"ACTIVE\"}}"
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
        let url = format!("http://127.0.0.1:{}", server.port);

        // CreateTable request
        let response = retry(|| async {
            client
                .post(&url)
                .header("x-amz-target", "DynamoDB_20120810.CreateTable")
                .header("Content-Type", "application/x-amz-json-1.0")
                .json(&json!({
                    "TableName": "Products",
                    "KeySchema": [
                        {"AttributeName": "id", "KeyType": "HASH"}
                    ],
                    "AttributeDefinitions": [
                        {"AttributeName": "id", "AttributeType": "S"}
                    ],
                    "BillingMode": "PAY_PER_REQUEST"
                }))
                .send()
                .await
        })
        .await?;

        assert!(
            response.status().is_success(),
            "CreateTable request failed with status: {}",
            response.status()
        );

        println!("[PASS] DynamoDB CreateTable request succeeded");

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
    async fn test_dynamo_multiple_operations() -> E2EResult<()> {
        println!("\n=== Test: DynamoDB Multiple Operations ===");

        let prompt = "Start a DynamoDB server on port 0 that remembers items across requests";
        let config = NetGetConfig::new(prompt)
            .with_log_level("off")
            .with_mock(|mock| {
                mock
                    // Mock 1: Server startup (user command)
                    .on_instruction_containing("DynamoDB")
                    .and_instruction_containing("server")
                    .respond_with_actions(json!([
                        {
                            "type": "open_server",
                            "port": 0,
                            "base_stack": "DYNAMO",
                            "instruction": "Handle DynamoDB operations and respond with appropriate JSON"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // Mock 2: PutItem operation (dynamo_request event)
                    .on_event("dynamo_request")
                    .and_event_data_contains("operation", "PutItem")
                    .respond_with_actions(json!([
                        {
                            "type": "send_dynamo_response",
                            "status_code": 200,
                            "body": "{}"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // Mock 3: GetItem operation (dynamo_request event)
                    .on_event("dynamo_request")
                    .and_event_data_contains("operation", "GetItem")
                    .respond_with_actions(json!([
                        {
                            "type": "send_dynamo_response",
                            "status_code": 200,
                            "body": "{\"Item\":{\"orderId\":{\"S\":\"order-001\"},\"amount\":{\"N\":\"99.99\"}}}"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // Mock 4: DeleteItem operation (dynamo_request event)
                    .on_event("dynamo_request")
                    .and_event_data_contains("operation", "DeleteItem")
                    .respond_with_actions(json!([
                        {
                            "type": "send_dynamo_response",
                            "status_code": 200,
                            "body": "{}"
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
        let url = format!("http://127.0.0.1:{}", server.port);

        // 1. PutItem
        let put_response = retry(|| async {
            client
                .post(&url)
                .header("x-amz-target", "DynamoDB_20120810.PutItem")
                .header("Content-Type", "application/x-amz-json-1.0")
                .json(&json!({
                    "TableName": "Orders",
                    "Item": {
                        "orderId": {"S": "order-001"},
                        "amount": {"N": "99.99"}
                    }
                }))
                .send()
                .await
        })
        .await?;

        assert!(put_response.status().is_success());
        println!("[PASS] PutItem succeeded");

        // 2. GetItem (should retrieve the item the LLM "remembered")
        let get_response = client
            .post(&url)
            .header("x-amz-target", "DynamoDB_20120810.GetItem")
            .header("Content-Type", "application/x-amz-json-1.0")
            .json(&json!({
                "TableName": "Orders",
                "Key": {
                    "orderId": {"S": "order-001"}
                }
            }))
            .send()
            .await?;

        assert!(get_response.status().is_success());
        println!("[PASS] GetItem succeeded");

        // 3. DeleteItem
        let delete_response = client
            .post(&url)
            .header("x-amz-target", "DynamoDB_20120810.DeleteItem")
            .header("Content-Type", "application/x-amz-json-1.0")
            .json(&json!({
                "TableName": "Orders",
                "Key": {
                    "orderId": {"S": "order-001"}
                }
            }))
            .send()
            .await?;

        assert!(delete_response.status().is_success());
        println!("[PASS] DeleteItem succeeded");

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

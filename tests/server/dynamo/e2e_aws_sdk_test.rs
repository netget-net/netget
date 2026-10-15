//! End-to-end tests for DynamoDB protocol using AWS SDK
//!
//! These tests use the actual AWS SDK for Rust to validate full compatibility
//! with real DynamoDB clients. This is the most realistic test scenario.
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
    use crate::helpers::{retry, with_aws_sdk_timeout};
    use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
    use aws_config::BehaviorVersion;
    use aws_sdk_dynamodb::types::{
        AttributeDefinition, AttributeValue, KeySchemaElement, KeyType, ScalarAttributeType,
    };
    use aws_sdk_dynamodb::Client;
    use std::collections::HashMap;

    /// Create a DynamoDB client pointing to our local NetGet server
    async fn create_dynamodb_client(port: u16) -> Client {
        let endpoint_url = format!("http://127.0.0.1:{}", port);

        let config = aws_config::defaults(BehaviorVersion::latest())
            .endpoint_url(&endpoint_url)
            .region(aws_config::Region::new("us-east-1"))
            .credentials_provider(aws_sdk_dynamodb::config::Credentials::new(
                "test", "test", None, None, "test",
            ))
            .load()
            .await;

        Client::new(&config)
    }

    #[tokio::test]
    async fn test_aws_sdk_create_table() -> E2EResult<()> {
        println!("\n=== Test: AWS SDK CreateTable ===");

        let prompt = "Start a DynamoDB server on port 0 that can create and manage tables";
        let config = NetGetConfig::new(prompt)
            .with_log_level("off")
            .with_mock(|mock| {
                mock
                    // Mock 1: Server startup instruction
                    .on_instruction_containing("Start a DynamoDB")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "open_server",
                            "port": 0,
                            "base_stack": "DYNAMO",
                            "instruction": "DynamoDB server that can create and manage tables"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // Mock 2: CreateTable request
                    .on_event("dynamo_request")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "send_dynamo_response",
                            "status_code": 200,
                            "body": "{\"TableDescription\":{\"TableName\":\"Users\",\"TableStatus\":\"ACTIVE\"}}"
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

        let client = create_dynamodb_client(server.port).await;

        // Wait for server to be ready and create table
        let result = retry(|| async {
            client
                .create_table()
                .table_name("Users")
                .key_schema(
                    KeySchemaElement::builder()
                        .attribute_name("userId")
                        .key_type(KeyType::Hash)
                        .build()
                        .unwrap(),
                )
                .attribute_definitions(
                    AttributeDefinition::builder()
                        .attribute_name("userId")
                        .attribute_type(ScalarAttributeType::S)
                        .build()
                        .unwrap(),
                )
                .billing_mode(aws_sdk_dynamodb::types::BillingMode::PayPerRequest)
                .send()
                .await
        })
        .await;

        match result {
            Ok(_) => println!("[PASS] CreateTable succeeded via AWS SDK"),
            Err(e) => println!("[INFO] CreateTable attempt: {}", e),
        }

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
    async fn test_aws_sdk_put_and_get_item() -> E2EResult<()> {
        println!("\n=== Test: AWS SDK PutItem and GetItem ===");

        let prompt = "Start a DynamoDB server on port 0 that remembers items stored with PutItem";
        let config = NetGetConfig::new(prompt)
            .with_log_level("off")
            .with_mock(|mock| {
                mock
                    // Mock 1: Server startup
                    .on_instruction_containing("Start a DynamoDB")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "open_server",
                            "port": 0,
                            "base_stack": "DYNAMO",
                            "instruction": "DynamoDB server that remembers items"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // Mock 2: PutItem request
                    .on_event("dynamo_request")
                    .and_event_data_contains("operation", "PutItem")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "send_dynamo_response",
                            "status_code": 200,
                            "body": "{}"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // Mock 3: GetItem request
                    .on_event("dynamo_request")
                    .and_event_data_contains("operation", "GetItem")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "send_dynamo_response",
                            "status_code": 200,
                            "body": "{\"Item\":{\"userId\":{\"S\":\"user-123\"},\"name\":{\"S\":\"Alice\"},\"email\":{\"S\":\"alice@example.com\"},\"age\":{\"N\":\"30\"}}}"
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

        let client = create_dynamodb_client(server.port).await;

        // PutItem with AWS SDK
        let put_result = retry(|| async {
            let mut item = HashMap::new();
            item.insert(
                "userId".to_string(),
                AttributeValue::S("user-123".to_string()),
            );
            item.insert("name".to_string(), AttributeValue::S("Alice".to_string()));
            item.insert(
                "email".to_string(),
                AttributeValue::S("alice@example.com".to_string()),
            );
            item.insert("age".to_string(), AttributeValue::N("30".to_string()));

            client
                .put_item()
                .table_name("Users")
                .set_item(Some(item))
                .send()
                .await
        })
        .await;

        match put_result {
            Ok(_) => println!("[PASS] PutItem succeeded via AWS SDK"),
            Err(e) => println!("[INFO] PutItem attempt: {}", e),
        }

        // GetItem with AWS SDK
        let get_result = with_aws_sdk_timeout(
            client
                .get_item()
                .table_name("Users")
                .key("userId", AttributeValue::S("user-123".to_string()))
                .send(),
        )
        .await;

        match get_result {
            Ok(output) => {
                println!(
                    "[PASS] GetItem succeeded via AWS SDK. Has item: {}",
                    output.item.is_some()
                );
            }
            Err(e) => {
                println!("[INFO] GetItem attempt: {}", e);
            }
        }

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
    async fn test_aws_sdk_update_item() -> E2EResult<()> {
        println!("\n=== Test: AWS SDK UpdateItem ===");

        let prompt = "Start a DynamoDB server on port 0";
        let config = NetGetConfig::new(prompt)
            .with_log_level("off")
            .with_mock(|mock| {
                mock
                    // Mock 1: Server startup
                    .on_instruction_containing("Start a DynamoDB")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "open_server",
                            "port": 0,
                            "base_stack": "DYNAMO",
                            "instruction": "DynamoDB server"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // Mock 2: PutItem request
                    .on_event("dynamo_request")
                    .and_event_data_contains("operation", "PutItem")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "send_dynamo_response",
                            "status_code": 200,
                            "body": "{}"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // Mock 3: UpdateItem request
                    .on_event("dynamo_request")
                    .and_event_data_contains("operation", "UpdateItem")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "send_dynamo_response",
                            "status_code": 200,
                            "body": "{\"Attributes\":{\"price\":{\"N\":\"79.99\"}}}"
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

        let client = create_dynamodb_client(server.port).await;

        // First, put an item
        retry(|| async {
            let mut item = HashMap::new();
            item.insert(
                "productId".to_string(),
                AttributeValue::S("prod-001".to_string()),
            );
            item.insert("price".to_string(), AttributeValue::N("99.99".to_string()));

            client
                .put_item()
                .table_name("Products")
                .set_item(Some(item))
                .send()
                .await
        })
        .await?;

        println!("[INFO] Initial PutItem succeeded");

        // UpdateItem with AWS SDK
        let update_result = with_aws_sdk_timeout(
            client
                .update_item()
                .table_name("Products")
                .key("productId", AttributeValue::S("prod-001".to_string()))
                .update_expression("SET price = :newprice")
                .expression_attribute_values(":newprice", AttributeValue::N("79.99".to_string()))
                .send(),
        )
        .await;

        match update_result {
            Ok(_) => println!("[PASS] UpdateItem succeeded via AWS SDK"),
            Err(e) => println!("[INFO] UpdateItem attempt: {}", e),
        }

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
    async fn test_aws_sdk_delete_item() -> E2EResult<()> {
        println!("\n=== Test: AWS SDK DeleteItem ===");

        let prompt = "Start a DynamoDB server on port 0";
        let config = NetGetConfig::new(prompt)
            .with_log_level("off")
            .with_mock(|mock| {
                mock
                    // Mock 1: Server startup
                    .on_instruction_containing("Start a DynamoDB")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "open_server",
                            "port": 0,
                            "base_stack": "DYNAMO",
                            "instruction": "DynamoDB server"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // Mock 2: PutItem request
                    .on_event("dynamo_request")
                    .and_event_data_contains("operation", "PutItem")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "send_dynamo_response",
                            "status_code": 200,
                            "body": "{}"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // Mock 3: DeleteItem request
                    .on_event("dynamo_request")
                    .and_event_data_contains("operation", "DeleteItem")
                    .respond_with_actions(serde_json::json!([
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

        let client = create_dynamodb_client(server.port).await;

        // First, put an item
        retry(|| async {
            let mut item = HashMap::new();
            item.insert(
                "orderId".to_string(),
                AttributeValue::S("order-999".to_string()),
            );
            item.insert(
                "status".to_string(),
                AttributeValue::S("pending".to_string()),
            );

            client
                .put_item()
                .table_name("Orders")
                .set_item(Some(item))
                .send()
                .await
        })
        .await?;

        println!("[INFO] Initial PutItem succeeded");

        // DeleteItem with AWS SDK
        let delete_result = with_aws_sdk_timeout(
            client
                .delete_item()
                .table_name("Orders")
                .key("orderId", AttributeValue::S("order-999".to_string()))
                .send(),
        )
        .await;

        match delete_result {
            Ok(_) => println!("[PASS] DeleteItem succeeded via AWS SDK"),
            Err(e) => println!("[INFO] DeleteItem attempt: {}", e),
        }

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
    async fn test_aws_sdk_query() -> E2EResult<()> {
        println!("\n=== Test: AWS SDK Query ===");

        let prompt = "Start a DynamoDB server on port 0 that can query items";
        let config = NetGetConfig::new(prompt)
            .with_log_level("off")
            .with_mock(|mock| {
                mock
                    // Mock 1: Server startup
                    .on_instruction_containing("Start a DynamoDB")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "open_server",
                            "port": 0,
                            "base_stack": "DYNAMO",
                            "instruction": "DynamoDB server that can query items"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // Mock 2: PutItem request
                    .on_event("dynamo_request")
                    .and_event_data_contains("operation", "PutItem")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "send_dynamo_response",
                            "status_code": 200,
                            "body": "{}"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // Mock 3: Query request
                    .on_event("dynamo_request")
                    .and_event_data_contains("operation", "Query")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "send_dynamo_response",
                            "status_code": 200,
                            "body": "{\"Items\":[{\"customerId\":{\"S\":\"cust-001\"},\"orderDate\":{\"S\":\"2024-01-01\"}}],\"Count\":1}"
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

        let client = create_dynamodb_client(server.port).await;

        // Put a few items first
        retry(|| async {
            let mut item1 = HashMap::new();
            item1.insert(
                "customerId".to_string(),
                AttributeValue::S("cust-001".to_string()),
            );
            item1.insert(
                "orderDate".to_string(),
                AttributeValue::S("2024-01-01".to_string()),
            );

            client
                .put_item()
                .table_name("CustomerOrders")
                .set_item(Some(item1))
                .send()
                .await
        })
        .await?;

        println!("[INFO] Initial PutItem succeeded");

        // Query with AWS SDK
        let query_result = with_aws_sdk_timeout(
            client
                .query()
                .table_name("CustomerOrders")
                .key_condition_expression("customerId = :cid")
                .expression_attribute_values(":cid", AttributeValue::S("cust-001".to_string()))
                .send(),
        )
        .await;

        match query_result {
            Ok(output) => {
                println!(
                    "[PASS] Query succeeded via AWS SDK. Item count: {}",
                    output.count
                );
            }
            Err(e) => {
                println!("[INFO] Query attempt: {}", e);
            }
        }

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
    async fn test_aws_sdk_scan() -> E2EResult<()> {
        println!("\n=== Test: AWS SDK Scan ===");

        let prompt = "Start a DynamoDB server on port 0 that supports table scans";
        let config = NetGetConfig::new(prompt)
            .with_log_level("off")
            .with_mock(|mock| {
                mock
                    // Mock 1: Server startup
                    .on_instruction_containing("Start a DynamoDB")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "open_server",
                            "port": 0,
                            "base_stack": "DYNAMO",
                            "instruction": "DynamoDB server that supports table scans"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // Mock 2: PutItem request
                    .on_event("dynamo_request")
                    .and_event_data_contains("operation", "PutItem")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "send_dynamo_response",
                            "status_code": 200,
                            "body": "{}"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // Mock 3: Scan request
                    .on_event("dynamo_request")
                    .and_event_data_contains("operation", "Scan")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "send_dynamo_response",
                            "status_code": 200,
                            "body": "{\"Items\":[{\"itemId\":{\"S\":\"item-001\"},\"category\":{\"S\":\"electronics\"}}],\"Count\":1}"
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

        let client = create_dynamodb_client(server.port).await;

        // Put multiple items
        retry(|| async {
            let mut item1 = HashMap::new();
            item1.insert(
                "itemId".to_string(),
                AttributeValue::S("item-001".to_string()),
            );
            item1.insert(
                "category".to_string(),
                AttributeValue::S("electronics".to_string()),
            );

            client
                .put_item()
                .table_name("Inventory")
                .set_item(Some(item1))
                .send()
                .await
        })
        .await?;

        println!("[INFO] Initial PutItem succeeded");

        // Scan with AWS SDK
        let scan_result = with_aws_sdk_timeout(client.scan().table_name("Inventory").send()).await;

        match scan_result {
            Ok(output) => {
                println!(
                    "[PASS] Scan succeeded via AWS SDK. Item count: {}",
                    output.count
                );
            }
            Err(e) => {
                println!("[INFO] Scan attempt: {}", e);
            }
        }

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
    async fn test_aws_sdk_batch_write() -> E2EResult<()> {
        println!("\n=== Test: AWS SDK BatchWriteItem ===");

        let prompt = "Start a DynamoDB server on port 0 that supports batch operations";
        let config = NetGetConfig::new(prompt)
            .with_log_level("off")
            .with_mock(|mock| {
                mock
                    // Mock 1: Server startup
                    .on_instruction_containing("Start a DynamoDB")
                    .and_instruction_containing("batch")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "open_server",
                            "port": 0,
                            "base_stack": "DYNAMO",
                            "instruction": "DynamoDB server with batch operations"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // Mock 2: BatchWriteItem request
                    .on_event("dynamo_request")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "send_dynamo_response",
                            "status_code": 200,
                            "body": "{\"UnprocessedItems\":{}}"
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

        let client = create_dynamodb_client(server.port).await;

        // BatchWriteItem with AWS SDK
        let batch_result = retry(|| async {
            let mut item1 = HashMap::new();
            item1.insert("id".to_string(), AttributeValue::S("batch-1".to_string()));
            item1.insert("data".to_string(), AttributeValue::S("first".to_string()));

            let mut item2 = HashMap::new();
            item2.insert("id".to_string(), AttributeValue::S("batch-2".to_string()));
            item2.insert("data".to_string(), AttributeValue::S("second".to_string()));

            let put_request1 = aws_sdk_dynamodb::types::PutRequest::builder()
                .set_item(Some(item1))
                .build()
                .unwrap();

            let put_request2 = aws_sdk_dynamodb::types::PutRequest::builder()
                .set_item(Some(item2))
                .build()
                .unwrap();

            let write_request1 = aws_sdk_dynamodb::types::WriteRequest::builder()
                .put_request(put_request1)
                .build();

            let write_request2 = aws_sdk_dynamodb::types::WriteRequest::builder()
                .put_request(put_request2)
                .build();

            client
                .batch_write_item()
                .request_items("BatchTest", vec![write_request1, write_request2])
                .send()
                .await
        })
        .await;

        match batch_result {
            Ok(_) => println!("[PASS] BatchWriteItem succeeded via AWS SDK"),
            Err(e) => println!("[INFO] BatchWriteItem attempt: {}", e),
        }

        // Verify mocks
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
    async fn test_aws_sdk_describe_table() -> E2EResult<()> {
        println!("\n=== Test: AWS SDK DescribeTable ===");

        let prompt = "Start a DynamoDB server on port 0";
        let config = NetGetConfig::new(prompt)
            .with_log_level("off")
            .with_mock(|mock| {
                mock
                    // Mock 1: Server startup
                    .on_instruction_containing("Start a DynamoDB")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "open_server",
                            "port": 0,
                            "base_stack": "DYNAMO",
                            "instruction": "DynamoDB server"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // Mock 2: DescribeTable request
                    .on_event("dynamo_request")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "send_dynamo_response",
                            "status_code": 200,
                            "body": "{\"Table\":{\"TableName\":\"TestTable\",\"TableStatus\":\"ACTIVE\",\"ItemCount\":0}}"
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

        let client = create_dynamodb_client(server.port).await;

        // DescribeTable with AWS SDK
        let describe_result =
            retry(|| async { client.describe_table().table_name("TestTable").send().await }).await;

        match describe_result {
            Ok(_) => println!("[PASS] DescribeTable succeeded via AWS SDK"),
            Err(e) => println!("[INFO] DescribeTable attempt: {}", e),
        }

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

//! E2E tests for DynamoDB client
//!
//! These tests verify DynamoDB client functionality by connecting to a local
//! DynamoDB instance (DynamoDB Local or LocalStack).
//!
//! **Prerequisites**:
//! - DynamoDB Local running on localhost:8000, or
//! - LocalStack running on localhost:4566
//!
//! To start DynamoDB Local:
//! ```bash
//! java -Djava.library.path=./DynamoDBLocal_lib -jar DynamoDBLocal.jar -sharedDb -inMemory -port 8000
//! ```
//!
//! Or with Docker:
//! ```bash
//! docker run -p 8000:8000 amazon/dynamodb-local -jar DynamoDBLocal.jar -inMemory -sharedDb
//! ```

mod dynamodb_client_tests {
    use aws_sdk_dynamodb::Client;
    use std::collections::HashMap;
    use std::time::Duration;

    /// Helper to create a DynamoDB client for setup/verification
    async fn create_test_client() -> Client {
        let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(aws_config::Region::new("us-east-1"))
            .endpoint_url("http://localhost:8000")
            .load()
            .await;
        Client::new(&config)
    }

    /// Helper to create a test table
    async fn create_test_table(client: &Client, table_name: &str) -> anyhow::Result<()> {
        use aws_sdk_dynamodb::types::{
            AttributeDefinition, KeySchemaElement, KeyType, ProvisionedThroughput,
            ScalarAttributeType,
        };

        let result = client
            .create_table()
            .table_name(table_name)
            .attribute_definitions(
                AttributeDefinition::builder()
                    .attribute_name("id")
                    .attribute_type(ScalarAttributeType::S)
                    .build()?,
            )
            .key_schema(
                KeySchemaElement::builder()
                    .attribute_name("id")
                    .key_type(KeyType::Hash)
                    .build()?,
            )
            .provisioned_throughput(
                ProvisionedThroughput::builder()
                    .read_capacity_units(5)
                    .write_capacity_units(5)
                    .build()?,
            )
            .send()
            .await;

        // Ignore error if table already exists
        if let Err(e) = result {
            if !e.to_string().contains("ResourceInUseException") {
                return Err(e.into());
            }
        }

        Ok(())
    }

    /// Helper to delete a test table
    async fn delete_test_table(client: &Client, table_name: &str) -> anyhow::Result<()> {
        let result = client.delete_table().table_name(table_name).send().await;

        // Ignore error if table doesn't exist
        if let Err(e) = result {
            if !e.to_string().contains("ResourceNotFoundException") {
                return Err(e.into());
            }
        }

        Ok(())
    }

    /// Test DynamoDB client PutItem and GetItem operations
    /// This test uses manual SDK calls instead of NetGet for now
    #[tokio::test]
    #[ignore = "Requires DynamoDB Local or LocalStack running on localhost:8000"]
    async fn test_dynamodb_client_put_and_get() -> anyhow::Result<()> {
        let client = create_test_client().await;
        let table_name = "netget_test_users";

        // Setup: Create table
        create_test_table(&client, table_name).await?;

        // Wait for table to be active
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Put an item
        use aws_sdk_dynamodb::types::AttributeValue;
        let mut item = HashMap::new();
        item.insert("id".to_string(), AttributeValue::S("user123".to_string()));
        item.insert("name".to_string(), AttributeValue::S("Alice".to_string()));
        item.insert("age".to_string(), AttributeValue::N("30".to_string()));

        client
            .put_item()
            .table_name(table_name)
            .set_item(Some(item))
            .send()
            .await?;

        println!("✅ DynamoDB PutItem succeeded");

        // Get the item
        let mut key = HashMap::new();
        key.insert("id".to_string(), AttributeValue::S("user123".to_string()));

        let result = client
            .get_item()
            .table_name(table_name)
            .set_key(Some(key))
            .send()
            .await?;

        assert!(result.item.is_some(), "Item should be retrieved");
        let item = result.item.unwrap();
        assert_eq!(
            item.get("name").and_then(|v| v.as_s().ok()),
            Some(&"Alice".to_string()),
            "Name should match"
        );
        assert_eq!(
            item.get("age").and_then(|v| v.as_n().ok()),
            Some(&"30".to_string()),
            "Age should match"
        );

        println!("✅ DynamoDB GetItem succeeded");

        // Cleanup
        delete_test_table(&client, table_name).await?;

        Ok(())
    }

    /// Test DynamoDB client Scan operation
    #[tokio::test]
    #[ignore = "Requires DynamoDB Local or LocalStack running on localhost:8000"]
    async fn test_dynamodb_client_scan() -> anyhow::Result<()> {
        let client = create_test_client().await;
        let table_name = "netget_test_scan";

        // Setup: Create table
        create_test_table(&client, table_name).await?;
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Put multiple items
        use aws_sdk_dynamodb::types::AttributeValue;
        for i in 1..=3 {
            let mut item = HashMap::new();
            item.insert("id".to_string(), AttributeValue::S(format!("user{}", i)));
            item.insert("name".to_string(), AttributeValue::S(format!("User{}", i)));
            item.insert("age".to_string(), AttributeValue::N((20 + i).to_string()));

            client
                .put_item()
                .table_name(table_name)
                .set_item(Some(item))
                .send()
                .await?;
        }

        println!("✅ DynamoDB PutItem (multiple) succeeded");

        // Scan the table
        let result = client.scan().table_name(table_name).send().await?;

        assert!(result.items.is_some(), "Scan should return items");
        let items = result.items.unwrap();
        assert_eq!(items.len(), 3, "Should have 3 items");

        println!("✅ DynamoDB Scan succeeded");

        // Cleanup
        delete_test_table(&client, table_name).await?;

        Ok(())
    }

    /// Test DynamoDB client UpdateItem operation
    #[tokio::test]
    #[ignore = "Requires DynamoDB Local or LocalStack running on localhost:8000"]
    async fn test_dynamodb_client_update() -> anyhow::Result<()> {
        let client = create_test_client().await;
        let table_name = "netget_test_update";

        // Setup: Create table
        create_test_table(&client, table_name).await?;
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Put an item
        use aws_sdk_dynamodb::types::AttributeValue;
        let mut item = HashMap::new();
        item.insert("id".to_string(), AttributeValue::S("user123".to_string()));
        item.insert("name".to_string(), AttributeValue::S("Alice".to_string()));
        item.insert("age".to_string(), AttributeValue::N("30".to_string()));

        client
            .put_item()
            .table_name(table_name)
            .set_item(Some(item))
            .send()
            .await?;

        // Update the item
        let mut key = HashMap::new();
        key.insert("id".to_string(), AttributeValue::S("user123".to_string()));

        let mut attr_values = HashMap::new();
        attr_values.insert(":age".to_string(), AttributeValue::N("31".to_string()));

        client
            .update_item()
            .table_name(table_name)
            .set_key(Some(key.clone()))
            .update_expression("SET age = :age")
            .set_expression_attribute_values(Some(attr_values))
            .send()
            .await?;

        println!("✅ DynamoDB UpdateItem succeeded");

        // Verify the update
        let result = client
            .get_item()
            .table_name(table_name)
            .set_key(Some(key))
            .send()
            .await?;

        assert!(result.item.is_some(), "Item should be retrieved");
        let item = result.item.unwrap();
        assert_eq!(
            item.get("age").and_then(|v| v.as_n().ok()),
            Some(&"31".to_string()),
            "Age should be updated"
        );

        println!("✅ DynamoDB GetItem verified update");

        // Cleanup
        delete_test_table(&client, table_name).await?;

        Ok(())
    }

    /// Test DynamoDB client DeleteItem operation
    #[tokio::test]
    #[ignore = "Requires DynamoDB Local or LocalStack running on localhost:8000"]
    async fn test_dynamodb_client_delete() -> anyhow::Result<()> {
        let client = create_test_client().await;
        let table_name = "netget_test_delete";

        // Setup: Create table
        create_test_table(&client, table_name).await?;
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Put an item
        use aws_sdk_dynamodb::types::AttributeValue;
        let mut item = HashMap::new();
        item.insert("id".to_string(), AttributeValue::S("user123".to_string()));
        item.insert("name".to_string(), AttributeValue::S("Alice".to_string()));

        client
            .put_item()
            .table_name(table_name)
            .set_item(Some(item))
            .send()
            .await?;

        // Delete the item
        let mut key = HashMap::new();
        key.insert("id".to_string(), AttributeValue::S("user123".to_string()));

        client
            .delete_item()
            .table_name(table_name)
            .set_key(Some(key.clone()))
            .send()
            .await?;

        println!("✅ DynamoDB DeleteItem succeeded");

        // Verify deletion
        let result = client
            .get_item()
            .table_name(table_name)
            .set_key(Some(key))
            .send()
            .await?;

        assert!(result.item.is_none(), "Item should be deleted");

        println!("✅ DynamoDB GetItem verified deletion");

        // Cleanup
        delete_test_table(&client, table_name).await?;

        Ok(())
    }
}

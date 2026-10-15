//! MongoDB server E2E tests with mock LLM


use crate::helpers::*;

#[tokio::test]
async fn test_mongodb_find_with_mocks() -> E2EResult<()> {
    let config = NetGetConfig::new(
        "Listen on port {AVAILABLE_PORT} via MongoDB. \
         When queried for users, return Alice (age 30) and Bob (age 25).",
    )
    .with_mock(|mock| {
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
            // Mock mongodb_command event when client queries
            .on_event("mongodb_command")
            .and_event_data_contains("command", "find")
            .and_event_data_contains("collection", "users")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "find_response",
                    "documents": [
                        {
                            "_id": {"$oid": "507f1f77bcf86cd799439011"},
                            "name": "Alice",
                            "age": 30
                        },
                        {
                            "_id": {"$oid": "507f191e810c19729de860ea"},
                            "name": "Bob",
                            "age": 25
                        }
                    ]
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let server = start_netget_server(config).await?;

    // Connect with MongoDB client
    let uri = format!("mongodb://127.0.0.1:{}", server.port);
    let client = mongodb::Client::with_uri_str(&uri).await?;
    let db = client.database("testdb");
    let collection = db.collection::<mongodb::bson::Document>("users");

    // Execute find query
    use futures::stream::TryStreamExt;
    let cursor = collection.find(mongodb::bson::doc! {}).await?;
    let documents: Vec<mongodb::bson::Document> = cursor.try_collect().await?;

    // Verify results
    assert_eq!(documents.len(), 2, "Expected 2 documents");
    assert_eq!(documents[0].get_str("name")?, "Alice");
    assert_eq!(documents[0].get_i32("age")?, 30);
    assert_eq!(documents[1].get_str("name")?, "Bob");
    assert_eq!(documents[1].get_i32("age")?, 25);

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    Ok(())
}

#[tokio::test]
async fn test_mongodb_insert_with_mocks() -> E2EResult<()> {
    let config =
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

    let server = start_netget_server(config).await?;

    // Connect with MongoDB client
    let uri = format!("mongodb://127.0.0.1:{}", server.port);
    let client = mongodb::Client::with_uri_str(&uri).await?;
    let db = client.database("testdb");
    let collection = db.collection::<mongodb::bson::Document>("users");

    // Insert document
    let doc = mongodb::bson::doc! {
        "name": "Charlie",
        "age": 35
    };
    let result = collection.insert_one(doc).await?;
    assert!(result.inserted_id.as_object_id().is_some());

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    Ok(())
}

#[tokio::test]
async fn test_mongodb_update_with_mocks() -> E2EResult<()> {
    let config =
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

    let server = start_netget_server(config).await?;

    // Connect with MongoDB client
    let uri = format!("mongodb://127.0.0.1:{}", server.port);
    let client = mongodb::Client::with_uri_str(&uri).await?;
    let db = client.database("testdb");
    let collection = db.collection::<mongodb::bson::Document>("users");

    // Update document
    let filter = mongodb::bson::doc! { "name": "Alice" };
    let update = mongodb::bson::doc! { "$set": { "age": 31 } };
    let result = collection.update_one(filter, update).await?;
    assert_eq!(result.matched_count, 1);
    assert_eq!(result.modified_count, 1);

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    Ok(())
}

#[tokio::test]
async fn test_mongodb_delete_with_mocks() -> E2EResult<()> {
    let config =
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

    let server = start_netget_server(config).await?;

    // Connect with MongoDB client
    let uri = format!("mongodb://127.0.0.1:{}", server.port);
    let client = mongodb::Client::with_uri_str(&uri).await?;
    let db = client.database("testdb");
    let collection = db.collection::<mongodb::bson::Document>("users");

    // Delete document
    let filter = mongodb::bson::doc! { "name": "Bob" };
    let result = collection.delete_one(filter).await?;
    assert_eq!(result.deleted_count, 1);

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    Ok(())
}

#[tokio::test]
async fn test_mongodb_error_with_mocks() -> E2EResult<()> {
    let config =
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
                // Mock mongodb_command event for error response
                .on_event("mongodb_command")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "error_response",
                        "error_code": 11000,
                        "error_message": "Duplicate key error"
                    }
                ]))
                .expect_calls(1)
                .and()
        });

    let server = start_netget_server(config).await?;

    // Connect with MongoDB client
    let uri = format!("mongodb://127.0.0.1:{}", server.port);
    let client = mongodb::Client::with_uri_str(&uri).await?;
    let db = client.database("testdb");
    let collection = db.collection::<mongodb::bson::Document>("users");

    // Try to insert document - should get error response
    let doc = mongodb::bson::doc! { "name": "duplicate" };
    if let Err(e) = collection.insert_one(doc).await {
        println!("MongoDB error (expected): {}", e);
    }

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    Ok(())
}

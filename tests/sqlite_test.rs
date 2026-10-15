//! Unit tests for SQLite database functionality
//!
//! These tests verify the core SQLite integration including:
//! - Database creation (file-based and in-memory)
//! - Schema tracking and introspection
//! - SQL execution (DDL, DML, DQL)
//! - Database ownership and cleanup
//! - Connection management

#![cfg(feature = "sqlite")]

use anyhow::Result;
use netget::state::app_state::AppState;
use netget::state::client::ClientId;
use netget::state::server::ServerId;
use netget::state::sqlite::{DatabaseOwner, QueryResult};

/// Helper function to create a test AppState
async fn create_test_state() -> AppState {
    AppState::new()
}

#[tokio::test]
async fn test_create_in_memory_database() -> Result<()> {
    let state = create_test_state().await;

    // Create in-memory database
    let db_id = state
        .create_database(
            "test_memory_db".to_string(),
            ":memory:".to_string(), // path still works directly for test helpers
            DatabaseOwner::Global,
            None,
        )
        .await?;

    // Verify database was created
    let db = state.get_database(db_id).await;
    assert!(db.is_some());

    let db = db.unwrap();
    assert_eq!(db.name, "test_memory_db");
    assert_eq!(db.path, ":memory:");
    assert!(matches!(db.owner, DatabaseOwner::Global));
    assert_eq!(db.tables.len(), 0); // No tables yet

    Ok(())
}

#[tokio::test]
async fn test_create_file_based_database() -> Result<()> {
    let state = create_test_state().await;

    // Create file-based database in temp directory
    let temp_path = format!("/tmp/test_db_{}.db", std::process::id());

    let db_id = state
        .create_database(
            "test_file_db".to_string(),
            temp_path.clone(),
            DatabaseOwner::Global,
            None,
        )
        .await?;

    // Verify database was created
    let db = state.get_database(db_id).await;
    assert!(db.is_some());

    let db = db.unwrap();
    assert_eq!(db.name, "test_file_db");
    assert_eq!(db.path, temp_path);

    // Cleanup
    state.delete_database(db_id).await?;
    std::fs::remove_file(&temp_path).ok();

    Ok(())
}

#[tokio::test]
async fn test_create_database_with_schema() -> Result<()> {
    let state = create_test_state().await;

    // Create database with initial schema
    let schema_ddl = r#"
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            email TEXT UNIQUE
        );
        CREATE TABLE posts (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            title TEXT,
            content TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
    "#;

    let db_id = state
        .create_database(
            "test_schema_db".to_string(),
            ":memory:".to_string(),
            DatabaseOwner::Global,
            Some(schema_ddl),
        )
        .await?;

    // Verify schema was created
    let db = state.get_database(db_id).await.unwrap();
    assert_eq!(db.tables.len(), 2);

    // Check users table
    let users_table = db.tables.iter().find(|t| t.name == "users");
    assert!(users_table.is_some());
    let users_table = users_table.unwrap();
    assert_eq!(users_table.columns.len(), 3);
    assert!(users_table.columns.iter().any(|c| c.contains("id")));
    assert!(users_table.columns.iter().any(|c| c.contains("name")));
    assert!(users_table.columns.iter().any(|c| c.contains("email")));

    // Check posts table
    let posts_table = db.tables.iter().find(|t| t.name == "posts");
    assert!(posts_table.is_some());
    let posts_table = posts_table.unwrap();
    assert_eq!(posts_table.columns.len(), 4);

    Ok(())
}

#[tokio::test]
async fn test_execute_insert_and_select() -> Result<()> {
    let state = create_test_state().await;

    // Create database with schema
    let schema_ddl = r#"
        CREATE TABLE items (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            price REAL
        );
    "#;

    let db_id = state
        .create_database(
            "test_insert_db".to_string(),
            ":memory:".to_string(),
            DatabaseOwner::Global,
            Some(schema_ddl),
        )
        .await?;

    // Insert data
    let insert_sql = "INSERT INTO items (name, price) VALUES ('Widget', 9.99), ('Gadget', 19.99)";
    let result = state.execute_sql(db_id, insert_sql).await?;

    match result {
        QueryResult::Modified { affected_rows } => {
            assert_eq!(affected_rows, 2);
        }
        _ => panic!("Expected Modified result"),
    }

    // Query data
    let select_sql = "SELECT * FROM items ORDER BY id";
    let result = state.execute_sql(db_id, select_sql).await?;

    match result {
        QueryResult::Select { rows, columns } => {
            assert_eq!(columns.len(), 3);
            assert_eq!(columns[0], "id");
            assert_eq!(columns[1], "name");
            assert_eq!(columns[2], "price");
            assert_eq!(rows.len(), 2);

            // Check first row (rows are Vec<Vec<Value>>, indexed by position)
            assert_eq!(rows[0][1].as_str().unwrap(), "Widget");
            assert_eq!(rows[0][2].as_f64().unwrap(), 9.99);

            // Check second row
            assert_eq!(rows[1][1].as_str().unwrap(), "Gadget");
            assert_eq!(rows[1][2].as_f64().unwrap(), 19.99);
        }
        _ => panic!("Expected Select result"),
    }

    Ok(())
}

#[tokio::test]
async fn test_execute_update_and_delete() -> Result<()> {
    let state = create_test_state().await;

    // Create database with data
    let schema_ddl = r#"
        CREATE TABLE products (
            id INTEGER PRIMARY KEY,
            name TEXT,
            stock INTEGER
        );
        INSERT INTO products (name, stock) VALUES ('Apple', 10), ('Banana', 20), ('Cherry', 15);
    "#;

    let db_id = state
        .create_database(
            "test_update_db".to_string(),
            ":memory:".to_string(),
            DatabaseOwner::Global,
            Some(schema_ddl),
        )
        .await?;

    // Update data
    let update_sql = "UPDATE products SET stock = 25 WHERE name = 'Banana'";
    let result = state.execute_sql(db_id, update_sql).await?;

    match result {
        QueryResult::Modified { affected_rows } => {
            assert_eq!(affected_rows, 1);
        }
        _ => panic!("Expected Modified result"),
    }

    // Verify update
    let select_sql = "SELECT stock FROM products WHERE name = 'Banana'";
    let result = state.execute_sql(db_id, select_sql).await?;

    match result {
        QueryResult::Select { rows, .. } => {
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0][0].as_i64().unwrap(), 25);
        }
        _ => panic!("Expected Select result"),
    }

    // Delete data
    let delete_sql = "DELETE FROM products WHERE name = 'Cherry'";
    let result = state.execute_sql(db_id, delete_sql).await?;

    match result {
        QueryResult::Modified { affected_rows } => {
            assert_eq!(affected_rows, 1);
        }
        _ => panic!("Expected Modified result"),
    }

    // Verify deletion
    let count_sql = "SELECT COUNT(*) as count FROM products";
    let result = state.execute_sql(db_id, count_sql).await?;

    match result {
        QueryResult::Select { rows, .. } => {
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0][0].as_i64().unwrap(), 2); // 3 - 1 deleted = 2
        }
        _ => panic!("Expected Select result"),
    }

    Ok(())
}

#[tokio::test]
async fn test_schema_tracking_after_ddl() -> Result<()> {
    let state = create_test_state().await;

    // Create database with initial schema
    let schema_ddl = "CREATE TABLE initial (id INTEGER PRIMARY KEY)";

    let db_id = state
        .create_database(
            "test_tracking_db".to_string(),
            ":memory:".to_string(),
            DatabaseOwner::Global,
            Some(schema_ddl),
        )
        .await?;

    // Verify initial schema
    let db = state.get_database(db_id).await.unwrap();
    assert_eq!(db.tables.len(), 1);
    assert_eq!(db.tables[0].name, "initial");

    // Add new table via DDL
    let add_table_sql = "CREATE TABLE added (id INTEGER, name TEXT)";
    state.execute_sql(db_id, add_table_sql).await?;

    // Verify schema was updated
    let db = state.get_database(db_id).await.unwrap();
    assert_eq!(db.tables.len(), 2);
    assert!(db.tables.iter().any(|t| t.name == "initial"));
    assert!(db.tables.iter().any(|t| t.name == "added"));

    // Drop table
    let drop_table_sql = "DROP TABLE initial";
    state.execute_sql(db_id, drop_table_sql).await?;

    // Verify schema was updated
    let db = state.get_database(db_id).await.unwrap();
    assert_eq!(db.tables.len(), 1);
    assert_eq!(db.tables[0].name, "added");

    Ok(())
}

#[tokio::test]
async fn test_row_count_tracking() -> Result<()> {
    let state = create_test_state().await;

    // Create database with schema
    let schema_ddl = "CREATE TABLE counters (id INTEGER PRIMARY KEY, value INTEGER)";

    let db_id = state
        .create_database(
            "test_count_db".to_string(),
            ":memory:".to_string(),
            DatabaseOwner::Global,
            Some(schema_ddl),
        )
        .await?;

    // Initial row count should be 0
    let db = state.get_database(db_id).await.unwrap();
    assert_eq!(db.tables[0].row_count, 0);

    // Insert rows
    let insert_sql = "INSERT INTO counters (value) VALUES (1), (2), (3)";
    state.execute_sql(db_id, insert_sql).await?;

    // Verify row count updated
    let db = state.get_database(db_id).await.unwrap();
    assert_eq!(db.tables[0].row_count, 3);

    // Insert more rows
    let insert_sql = "INSERT INTO counters (value) VALUES (4), (5)";
    state.execute_sql(db_id, insert_sql).await?;

    // Verify row count updated
    let db = state.get_database(db_id).await.unwrap();
    assert_eq!(db.tables[0].row_count, 5);

    Ok(())
}

#[tokio::test]
async fn test_database_ownership_server() -> Result<()> {
    let state = create_test_state().await;
    let server_id = ServerId::new(42);

    // Create database owned by server
    let db_id = state
        .create_database(
            "server_db".to_string(),
            ":memory:".to_string(),
            DatabaseOwner::Server(server_id),
            None,
        )
        .await?;

    // Verify ownership
    let db = state.get_database(db_id).await.unwrap();
    match db.owner {
        DatabaseOwner::Server(sid) => assert_eq!(sid, server_id),
        _ => panic!("Expected Server ownership"),
    }

    // Verify database appears in server's database list
    let server_dbs = state.get_databases_by_server(server_id).await;
    assert_eq!(server_dbs.len(), 1);
    assert_eq!(server_dbs[0].id, db_id);

    Ok(())
}

#[tokio::test]
async fn test_database_ownership_client() -> Result<()> {
    let state = create_test_state().await;
    let client_id = ClientId::new(99);

    // Create database owned by client
    let db_id = state
        .create_database(
            "client_db".to_string(),
            ":memory:".to_string(),
            DatabaseOwner::Client(client_id),
            None,
        )
        .await?;

    // Verify ownership
    let db = state.get_database(db_id).await.unwrap();
    match db.owner {
        DatabaseOwner::Client(cid) => assert_eq!(cid, client_id),
        _ => panic!("Expected Client ownership"),
    }

    Ok(())
}

#[tokio::test]
async fn test_list_all_databases() -> Result<()> {
    let state = create_test_state().await;

    // Create multiple databases
    let db1 = state
        .create_database(
            "db1".to_string(),
            ":memory:".to_string(),
            DatabaseOwner::Global,
            None,
        )
        .await?;

    let db2 = state
        .create_database(
            "db2".to_string(),
            ":memory:".to_string(),
            DatabaseOwner::Server(ServerId::new(1)),
            None,
        )
        .await?;

    let db3 = state
        .create_database(
            "db3".to_string(),
            ":memory:".to_string(),
            DatabaseOwner::Client(ClientId::new(1)),
            None,
        )
        .await?;

    // List all databases
    let all_dbs = state.get_all_databases().await;
    assert_eq!(all_dbs.len(), 3);

    let db_ids: Vec<_> = all_dbs.iter().map(|db| db.id).collect();
    assert!(db_ids.contains(&db1));
    assert!(db_ids.contains(&db2));
    assert!(db_ids.contains(&db3));

    Ok(())
}

#[tokio::test]
async fn test_delete_database() -> Result<()> {
    let state = create_test_state().await;

    // Create database
    let db_id = state
        .create_database(
            "test_delete".to_string(),
            ":memory:".to_string(),
            DatabaseOwner::Global,
            None,
        )
        .await?;

    // Verify it exists
    assert!(state.get_database(db_id).await.is_some());

    // Delete database
    state.delete_database(db_id).await?;

    // Verify it's gone
    assert!(state.get_database(db_id).await.is_none());

    Ok(())
}

#[tokio::test]
async fn test_cleanup_databases_for_server() -> Result<()> {
    let state = create_test_state().await;
    let server_id = ServerId::new(123);

    // Create databases for different owners
    let server_db1 = state
        .create_database(
            "server_db1".to_string(),
            ":memory:".to_string(),
            DatabaseOwner::Server(server_id),
            None,
        )
        .await?;

    let server_db2 = state
        .create_database(
            "server_db2".to_string(),
            ":memory:".to_string(),
            DatabaseOwner::Server(server_id),
            None,
        )
        .await?;

    let global_db = state
        .create_database(
            "global_db".to_string(),
            ":memory:".to_string(),
            DatabaseOwner::Global,
            None,
        )
        .await?;

    // Verify all exist
    assert_eq!(state.get_all_databases().await.len(), 3);

    // Cleanup databases for server
    state.cleanup_databases_for_server(server_id).await?;

    // Verify only global database remains
    let remaining = state.get_all_databases().await;
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].id, global_db);

    // Verify server databases are gone
    assert!(state.get_database(server_db1).await.is_none());
    assert!(state.get_database(server_db2).await.is_none());

    Ok(())
}

#[tokio::test]
async fn test_cleanup_databases_for_client() -> Result<()> {
    let state = create_test_state().await;
    let client_id = ClientId::new(456);

    // Create databases for different owners
    let client_db = state
        .create_database(
            "client_db".to_string(),
            ":memory:".to_string(),
            DatabaseOwner::Client(client_id),
            None,
        )
        .await?;

    let global_db = state
        .create_database(
            "global_db".to_string(),
            ":memory:".to_string(),
            DatabaseOwner::Global,
            None,
        )
        .await?;

    // Verify both exist
    assert_eq!(state.get_all_databases().await.len(), 2);

    // Cleanup databases for client
    state.cleanup_databases_for_client(client_id).await?;

    // Verify only global database remains
    let remaining = state.get_all_databases().await;
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].id, global_db);

    // Verify client database is gone
    assert!(state.get_database(client_db).await.is_none());

    Ok(())
}

#[tokio::test]
async fn test_query_result_format() -> Result<()> {
    let state = create_test_state().await;

    // Create database with data
    let schema_ddl = r#"
        CREATE TABLE formats (
            id INTEGER PRIMARY KEY,
            name TEXT,
            value REAL
        );
        INSERT INTO formats (name, value) VALUES ('First', 1.5), ('Second', 2.5);
    "#;

    let db_id = state
        .create_database(
            "format_db".to_string(),
            ":memory:".to_string(),
            DatabaseOwner::Global,
            Some(schema_ddl),
        )
        .await?;

    // Execute SELECT and check format
    let result = state.execute_sql(db_id, "SELECT * FROM formats").await?;

    let formatted = result.format();
    // Format creates a table with columns separated by " | "
    assert!(formatted.contains("id"));
    assert!(formatted.contains("name"));
    assert!(formatted.contains("value"));
    assert!(formatted.contains("First"));
    assert!(formatted.contains("Second"));
    // Should have 2 data rows (plus header)
    assert_eq!(formatted.lines().count(), 4); // header + separator + 2 rows

    // Execute INSERT and check format
    let result = state
        .execute_sql(
            db_id,
            "INSERT INTO formats (name, value) VALUES ('Third', 3.5)",
        )
        .await?;

    let formatted = result.format();
    assert!(formatted.contains("row(s) affected"));

    Ok(())
}

#[tokio::test]
async fn test_concurrent_queries() -> Result<()> {
    let state = create_test_state().await;

    // Create database with schema
    let schema_ddl = "CREATE TABLE concurrent (id INTEGER PRIMARY KEY, value INTEGER)";

    let db_id = state
        .create_database(
            "concurrent_db".to_string(),
            ":memory:".to_string(),
            DatabaseOwner::Global,
            Some(schema_ddl),
        )
        .await?;

    // Execute multiple queries concurrently
    let state1 = state.clone();
    let state2 = state.clone();
    let state3 = state.clone();

    let handle1 = tokio::spawn(async move {
        state1
            .execute_sql(db_id, "INSERT INTO concurrent (value) VALUES (1)")
            .await
    });

    let handle2 = tokio::spawn(async move {
        state2
            .execute_sql(db_id, "INSERT INTO concurrent (value) VALUES (2)")
            .await
    });

    let handle3 = tokio::spawn(async move {
        state3
            .execute_sql(db_id, "INSERT INTO concurrent (value) VALUES (3)")
            .await
    });

    // Wait for all to complete
    let results = tokio::try_join!(handle1, handle2, handle3)?;
    assert!(results.0.is_ok());
    assert!(results.1.is_ok());
    assert!(results.2.is_ok());

    // Verify all inserts succeeded
    let result = state
        .execute_sql(db_id, "SELECT COUNT(*) as count FROM concurrent")
        .await?;

    match result {
        QueryResult::Select { rows, .. } => {
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0][0].as_i64().unwrap(), 3);
        }
        _ => panic!("Expected Select result"),
    }

    Ok(())
}

#[tokio::test]
async fn test_sql_error_handling() -> Result<()> {
    let state = create_test_state().await;

    let db_id = state
        .create_database(
            "error_db".to_string(),
            ":memory:".to_string(),
            DatabaseOwner::Global,
            None,
        )
        .await?;

    // Test invalid SQL
    let result = state.execute_sql(db_id, "INVALID SQL SYNTAX").await;
    assert!(result.is_err());

    // Test query on non-existent table
    let result = state
        .execute_sql(db_id, "SELECT * FROM nonexistent_table")
        .await;
    assert!(result.is_err());

    Ok(())
}

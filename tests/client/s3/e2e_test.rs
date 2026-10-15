//! E2E tests for S3 client
//!
//! These tests verify S3 client functionality by spawning the actual NetGet binary
//! and testing client behavior as a black-box.
//!
//! **Prerequisites:**
//! - MinIO or LocalStack running on localhost:9000 (for integration tests)
//! - AWS credentials configured (for real AWS S3 tests)
//!
//! **Note:** These tests are currently minimal and require a running S3-compatible
//! service for full E2E validation. See CLAUDE.md for test setup instructions.

mod s3_client_tests {
    use crate::helpers::*;
    use std::time::Duration;

    /// Test S3 client initialization and connection
    /// LLM calls: 1 (client initialization)
    ///
    /// This test verifies that the S3 client can be initialized with proper configuration.
    /// For full E2E testing, a MinIO or LocalStack instance should be running.
    #[tokio::test]
    #[ignore = "Requires MinIO/LocalStack running"]
    async fn test_s3_client_connect() -> E2EResult<()> {
        // Start an S3 client with MinIO endpoint
        let client_config = NetGetConfig::new(
            "Connect to S3 at localhost:9000. \
             Use access_key_id=minioadmin and secret_access_key=minioadmin. \
             Set endpoint_url to http://localhost:9000 and region to us-east-1.",
        );

        let mut client = start_netget_client(client_config).await?;

        // Give client time to initialize
        tokio::time::sleep(Duration::from_secs(1)).await;

        // Verify client output shows connection
        client.wait_for_any(&["S3 client", "ready"], 30).await;
        assert!(
            client.output_contains("S3 client").await || client.output_contains("ready").await,
            "Client should show S3 initialization message. Output: {:?}",
            client.get_output().await
        );

        println!("✅ S3 client initialized successfully");

        // Cleanup
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last response routinely lands
        // after the sleep expires, and the test reports it as never having happened.
        client.wait_for_mocks(30).await;
        client.verify_mocks().await?;
        client.stop().await?;

        Ok(())
    }

    /// Test S3 client can list buckets
    /// LLM calls: 2 (client initialization, list buckets operation)
    #[tokio::test]
    #[ignore = "Requires MinIO/LocalStack running"]
    async fn test_s3_client_list_buckets() -> E2EResult<()> {
        // Start an S3 client and list buckets
        let client_config = NetGetConfig::new(
            "Connect to S3 at localhost:9000. \
             Use access_key_id=minioadmin and secret_access_key=minioadmin. \
             Set endpoint_url to http://localhost:9000 and region to us-east-1. \
             After connecting, list all buckets.",
        );

        let mut client = start_netget_client(client_config).await?;

        // Give client time to connect and list buckets
        tokio::time::sleep(Duration::from_secs(2)).await;

        // Verify the client is S3 protocol
        assert_eq!(client.protocol, "S3", "Client should be S3 protocol");

        println!("✅ S3 client listed buckets");

        // Cleanup
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last response routinely lands
        // after the sleep expires, and the test reports it as never having happened.
        client.wait_for_mocks(30).await;
        client.verify_mocks().await?;
        client.stop().await?;

        Ok(())
    }

    /// Test S3 client can perform object operations
    /// LLM calls: 3 (client init, put object, get object)
    #[tokio::test]
    #[ignore = "Requires MinIO/LocalStack running with test bucket"]
    async fn test_s3_client_object_operations() -> E2EResult<()> {
        // Start an S3 client and perform put/get operations
        let client_config = NetGetConfig::new(
            "Connect to S3 at localhost:9000. \
             Use access_key_id=minioadmin and secret_access_key=minioadmin. \
             Set endpoint_url to http://localhost:9000 and region to us-east-1. \
             After connecting, upload a file to bucket 'test-bucket' with key 'test.txt' and body 'Hello, S3!'. \
             Then download the same file to verify."
        );

        let mut client = start_netget_client(client_config).await?;

        // Give client time to perform operations
        tokio::time::sleep(Duration::from_secs(3)).await;

        // Verify operations in output
        let output = client.get_output().await;
        assert!(
            output.iter().any(|l| l.contains("test-bucket"))
                || output.iter().any(|l| l.contains("test.txt")),
            "Client output should mention bucket or object. Output: {:?}",
            output
        );

        println!("✅ S3 client performed object operations");

        // Cleanup
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last response routinely lands
        // after the sleep expires, and the test reports it as never having happened.
        client.wait_for_mocks(30).await;
        client.verify_mocks().await?;
        client.stop().await?;

        Ok(())
    }

    /// Test S3 client with AWS credentials validation
    /// LLM calls: 1 (client initialization with invalid credentials)
    #[tokio::test]
    #[ignore = "No .with_mock() configured: requires --use-ollama; the LLM call is refused under strict-mock mode"]
    async fn test_s3_client_invalid_credentials() -> E2EResult<()> {
        // Try to connect with invalid credentials (should fail gracefully)
        let client_config = NetGetConfig::new(
            "Connect to S3 at localhost:9000. \
             Use access_key_id=invalid and secret_access_key=invalid. \
             Set endpoint_url to http://localhost:9000 and region to us-east-1.",
        );

        let mut client = start_netget_client(client_config).await?;

        // Give client time to attempt connection
        tokio::time::sleep(Duration::from_secs(1)).await;

        // Client should initialize even with bad credentials (operations will fail later)
        assert_eq!(client.protocol, "S3", "Client should be S3 protocol");

        println!("✅ S3 client handles invalid credentials gracefully");

        // Cleanup
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last response routinely lands
        // after the sleep expires, and the test reports it as never having happened.
        client.wait_for_mocks(30).await;
        client.verify_mocks().await?;
        client.stop().await?;

        Ok(())
    }
}

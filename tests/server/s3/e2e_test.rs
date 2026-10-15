//! End-to-end tests for S3 protocol
//!
//! These tests spawn the actual NetGet binary and interact with it using rust-s3 client
//! to validate S3 API functionality.
//!
//! Run with:
//! `cargo test --no-default-features --features s3 --test server -- server::s3`
//!
//! Two corrections to what this header used to say. `--test` names a cargo *target*
//! (`tests/server.rs`), not a module path, so `--test server::s3::e2e_test` matched no
//! target and cargo listed the available targets and exited having run nothing. And no
//! release build is needed first: the harness resolves the binary through
//! `CARGO_BIN_EXE_netget`, which is the binary cargo built for *this* test with *these*
//! features (`tests/helpers/common.rs`).

mod tests {
    use crate::helpers::retry;
    use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
    use s3::bucket::Bucket;
    use s3::creds::Credentials;
    use s3::region::Region;

    /// Helper to create S3 bucket client
    fn create_s3_bucket(port: u16, bucket_name: &str) -> Box<Bucket> {
        let endpoint = format!("http://127.0.0.1:{}", port);
        let region = Region::Custom {
            region: "us-east-1".to_string(),
            endpoint,
        };

        // Credentials not used (no auth), but required by rust-s3
        let credentials = Credentials::new(Some("test"), Some("test"), None, None, None).unwrap();

        // Use path-style addressing for localhost (required for IP addresses)
        // Virtual-hosted-style (bucket.hostname) doesn't work with IPs
        Bucket::new(bucket_name, region, credentials)
            .unwrap()
            .with_path_style()
    }

    #[tokio::test]
    async fn test_s3_comprehensive() -> E2EResult<()> {
        println!("\n=== Test: S3 Comprehensive Operations ===");

        // Single comprehensive prompt covering all test scenarios
        let prompt = "Start an S3-compatible server on port {AVAILABLE_PORT}. Create a bucket called 'test-bucket' with objects: hello.txt containing 'Hello, World!' and data.json containing '{\"message\": \"test data\"}'. When clients list objects return both files with sizes, when they get hello.txt return the text content, when they put new objects acknowledge them, when they head or delete objects respond appropriately.";

        let config = NetGetConfig::new(prompt)
            .with_log_level("off")
            .with_mock(|mock| {
                mock
                    // Mock 1: Server startup
                    .on_instruction_containing("Start an S3")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "open_server",
                            "port": 0,
                            "base_stack": "S3",
                            "instruction": "S3 server with test-bucket containing hello.txt and data.json"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // Mock 2: ListObjects — exactly once. `is_truncated` is not set, so there
                    // is no pagination, and the operations around it now succeed on the first
                    // try, so nothing retries.
                    .on_event("s3_request")
                    .and_event_data_contains("operation", "ListObjects")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "send_s3_object_list",
                            "objects": [
                                {"key": "hello.txt", "size": 13},
                                {"key": "data.json", "size": 23}
                            ]
                        }
                    ]))
                    // Was 15, with the comment "rust-s3 client may paginate/retry". That number
                    // was calibrated against a broken run: PutObject/HeadObject/DeleteObject
                    // were mocked with `send_http_response`, an action S3 cannot execute, so
                    // every one of them failed and the test's `retry` helper hammered the
                    // server. With those mocks answering `send_s3_write_result` the traffic is
                    // deterministic.
                    .expect_calls(1)
                    .and()
                    // Mock 3: GetObject hello.txt
                    .on_event("s3_request")
                    .and_event_data_contains("operation", "GetObject")
                    .and_event_data_contains("key", "hello.txt")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "send_s3_object",
                            "content": "Hello, World!",
                            "content_type": "text/plain"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // Mock 4: PutObject test.txt
                    .on_event("s3_request")
                    .and_event_data_contains("operation", "PutObject")
                    .and_event_data_contains("key", "test.txt")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "send_s3_write_result",
                            "status_code": 200,
                            "etag": "\"9a0364b9e99bb480dd25e1f0284c8555\""
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // Mock 5: HeadObject hello.txt
                    .on_event("s3_request")
                    .and_event_data_contains("operation", "HeadObject")
                    .and_event_data_contains("key", "hello.txt")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "send_s3_write_result",
                            "status_code": 200,
                            "content_length": 13,
                            "content_type": "text/plain"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // Mock 6: DeleteObject test.txt
                    .on_event("s3_request")
                    .and_event_data_contains("operation", "DeleteObject")
                    .and_event_data_contains("key", "test.txt")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "send_s3_write_result",
                            "status_code": 204
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
            server.stack.contains("S3"),
            "Expected S3 stack, got: {}",
            server.stack
        );

        let bucket = create_s3_bucket(server.port, "test-bucket");

        // Test 1: List buckets (requires special handling with rust-s3)
        println!("Test 1: Listing buckets...");
        // Note: rust-s3 doesn't have a direct ListBuckets API, so we test bucket existence indirectly

        // Test 2: List objects in bucket.
        //
        // Every assertion below is on rust-s3's *parsed* result, not on a status code: what
        // is being proven is that an independent S3 client accepted and understood our
        // ListBucketResult XML. Swallowing the error into a `[INFO]` println, as this used
        // to, left the maturity rating resting on the mock call count alone.
        println!("Test 2: Listing objects in test-bucket...");
        let results = retry(|| async { bucket.list("".to_string(), None).await })
            .await
            .expect("rust-s3 rejected our ListObjects response");

        let listing = results
            .first()
            .expect("ListObjects returned no ListBucketResult");
        assert_eq!(
            listing.name, "test-bucket",
            "ListBucketResult must carry the bucket name"
        );
        let objects: Vec<&str> = listing
            .contents
            .iter()
            .map(|obj| obj.key.as_str())
            .collect();
        assert!(
            objects.contains(&"hello.txt") && objects.contains(&"data.json"),
            "expected both mocked keys in the listing, got {:?}",
            objects
        );
        println!("[PASS] ListObjects parsed by rust-s3: {:?}", objects);

        // Test 3: Get existing object (hello.txt) — the body must arrive byte for byte.
        println!("Test 3: Getting hello.txt...");
        let data = retry(|| async { bucket.get_object("/hello.txt").await })
            .await
            .expect("rust-s3 rejected our GetObject response");
        assert_eq!(
            String::from_utf8_lossy(&data.bytes()),
            "Hello, World!",
            "GetObject body must be exactly what send_s3_object was given"
        );
        println!("[PASS] GetObject returned the exact mocked body");

        // Test 4: Put new object
        println!("Test 4: Putting new object test.txt...");
        let response = retry(|| async { bucket.put_object("/test.txt", b"Test content").await })
            .await
            .expect("rust-s3 rejected our PutObject response");
        assert_eq!(
            response.status_code(),
            200,
            "PutObject must return the status send_s3_write_result asked for"
        );
        println!("[PASS] PutObject acknowledged with 200");

        // Test 5: Head object (check existence).
        //
        // HeadObject and DeleteObject below were the two operations this suite issued
        // *without* `retry` and with the error swallowed into a println. That mattered:
        // the whole reason `expect_calls(1)` is evidence is that a response rust-s3
        // rejected makes `retry` re-issue the request and blow the count. Outside `retry`,
        // a rejected response is one call and a silent pass — so these two verbs were
        // named in the Beta rating while being asserted by nothing.
        println!("Test 5: Checking if hello.txt exists with HeadObject...");
        let (head, status) = retry(|| async { bucket.head_object("/hello.txt").await })
            .await
            .expect("rust-s3 rejected our HeadObject response");
        assert_eq!(status, 200, "HeadObject must return 200");
        assert_eq!(
            head.content_length,
            Some(13),
            "HeadObject must carry the Content-Length send_s3_write_result asked for"
        );
        assert_eq!(
            head.content_type.as_deref(),
            Some("text/plain"),
            "HeadObject must carry the Content-Type send_s3_write_result asked for"
        );
        println!("[PASS] HeadObject headers parsed by rust-s3");

        // Test 6: Delete object
        println!("Test 6: Deleting test.txt...");
        let response = retry(|| async { bucket.delete_object("/test.txt").await })
            .await
            .expect("rust-s3 rejected our DeleteObject response");
        assert_eq!(
            response.status_code(),
            204,
            "DeleteObject must return the 204 send_s3_write_result asked for"
        );
        println!("[PASS] DeleteObject acknowledged with 204");

        println!("\n[PASS] All five S3 operations were accepted by rust-s3");

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
    async fn test_s3_get_object() -> E2EResult<()> {
        println!("\n=== Test: S3 GetObject ===");

        let prompt = "Start an S3 server on port {AVAILABLE_PORT} with bucket 'my-bucket' containing file 'data.txt' with content 'S3 Test Data'";
        let config = NetGetConfig::new(prompt)
            .with_log_level("off")
            .with_mock(|mock| {
                mock
                    // Mock 1: Server startup
                    .on_instruction_containing("Start an S3")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "open_server",
                            "port": 0,
                            "base_stack": "S3",
                            "instruction": "S3 server with my-bucket containing data.txt"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // Mock 2: GetObject data.txt
                    .on_event("s3_request")
                    .and_event_data_contains("operation", "GetObject")
                    .and_event_data_contains("key", "data.txt")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "send_s3_object",
                            "content": "S3 Test Data",
                            "content_type": "text/plain"
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

        assert!(
            server.stack.contains("S3"),
            "Expected S3 stack, got: {}",
            server.stack
        );

        let bucket = create_s3_bucket(server.port, "my-bucket");

        // Get object
        let data = retry(|| async { bucket.get_object("/data.txt").await })
            .await
            .expect("rust-s3 rejected our GetObject response");
        assert_eq!(
            String::from_utf8_lossy(&data.bytes()),
            "S3 Test Data",
            "GetObject body must be exactly what send_s3_object was given"
        );
        println!("[PASS] GetObject returned the exact mocked body");

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
    async fn test_s3_put_and_list() -> E2EResult<()> {
        println!("\n=== Test: S3 PutObject and ListObjects ===");

        let prompt = "Start an S3 server on port {AVAILABLE_PORT} with empty bucket 'uploads'. Accept any file uploads and list them when requested.";
        let config = NetGetConfig::new(prompt)
            .with_log_level("off")
            .with_mock(|mock| {
                mock
                    // Mock 1: Server startup
                    .on_instruction_containing("Start an S3")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "open_server",
                            "port": 0,
                            "base_stack": "S3",
                            "instruction": "S3 server with empty uploads bucket"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // Mock 2: PutObject file.txt
                    .on_event("s3_request")
                    .and_event_data_contains("operation", "PutObject")
                    .and_event_data_contains("key", "file.txt")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "send_s3_write_result",
                            "status_code": 200,
                            "etag": "\"0cc175b9c0f1b6a831c399e269772661\""
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // Mock 3: ListObjects
                    .on_event("s3_request")
                    .and_event_data_contains("operation", "ListObjects")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "send_s3_object_list",
                            "objects": [
                                {"key": "file.txt", "size": 19}
                            ]
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

        let bucket = create_s3_bucket(server.port, "uploads");

        // Put object
        println!("Uploading file.txt...");
        let response =
            retry(|| async { bucket.put_object("/file.txt", b"Upload test content").await })
                .await
                .expect("rust-s3 rejected our PutObject response");
        assert_eq!(response.status_code(), 200, "PutObject must return 200");
        println!("[PASS] PutObject acknowledged with 200");

        // List objects
        println!("Listing objects...");
        let results = retry(|| async { bucket.list("".to_string(), None).await })
            .await
            .expect("rust-s3 rejected our ListObjects response");
        let listing = results
            .first()
            .expect("ListObjects returned no ListBucketResult");
        assert_eq!(listing.name, "uploads");
        let objects: Vec<&str> = listing
            .contents
            .iter()
            .map(|obj| obj.key.as_str())
            .collect();
        assert_eq!(
            objects,
            vec!["file.txt"],
            "listing must be exactly what send_s3_object_list was given"
        );
        println!("[PASS] ListObjects parsed by rust-s3: {:?}", objects);

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

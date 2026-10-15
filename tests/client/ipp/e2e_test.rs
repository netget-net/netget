//! E2E tests for IPP client
//!
//! These tests verify IPP client functionality by spawning the actual NetGet binary
//! and testing client behavior as a black-box.
//! Test strategy: Use netget binary to start IPP server + client, < 10 LLM calls total.

mod ipp_client_tests {
    use crate::helpers::*;
    use std::time::Duration;

    /// Test IPP client can query printer attributes via Get-Printer-Attributes
    /// LLM calls: 4 (server startup, server request, client startup, client connected)
    #[tokio::test]
    async fn test_ipp_get_printer_attributes() -> E2EResult<()> {
        println!("\n=== E2E Test: IPP Client Get-Printer-Attributes ===");

        // Start an IPP server that responds to Get-Printer-Attributes
        let server_config = NetGetConfig::new(
            "Listen on port {AVAILABLE_PORT} via IPP. When clients send Get-Printer-Attributes, respond with printer-name='NetGet Test Printer', printer-state='idle'."
        )
        .with_mock(|mock| {
            mock
                // Mock 1: Server startup
                .on_instruction_containing("Listen on port")
                .and_instruction_containing("IPP")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "IPP",
                        "instruction": "IPP printer responding to Get-Printer-Attributes"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2: Server receives IPP request
                .on_event("ipp_request_received")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "ipp_printer_attributes",
                        "attributes": {
                            "printer-name": "NetGet Test Printer",
                            "printer-state": "idle"
                        }
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let server = start_netget_server(server_config).await?;
        println!("Server started on port {}", server.port);

        // Give server time to start
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Start IPP client that connects and queries printer
        let client_config = NetGetConfig::new(format!(
            "Connect to http://127.0.0.1:{}/printers/test via IPP. Query printer attributes.",
            server.port
        ))
        .with_mock(|mock| {
            mock
                // Mock 1: Client startup
                .on_instruction_containing("Connect to")
                .and_instruction_containing("IPP")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_client",
                        "remote_addr": format!("http://127.0.0.1:{}/printers/test", server.port),
                        "protocol": "IPP",
                        "instruction": "Query printer attributes"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2: Client connected (ipp_connected event)
                .on_event("ipp_connected")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "get_printer_attributes"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 3: Client receives response (ipp_response_received event)
                .on_event("ipp_response_received")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "wait_for_more"
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let client = start_netget_client(client_config).await?;

        // Give client time to connect and query

        // Verify client output shows connection
        client.wait_for_any(&["connected", "IPP"], 30).await;
        assert!(
            client.output_contains("connected").await || client.output_contains("IPP").await,
            "Client should show connection message. Output: {:?}",
            client.get_output().await
        );

        println!("✅ IPP client successfully queried printer attributes");

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

    /// Test IPP client can submit a print job via Print-Job
    /// LLM calls: 4 (server startup, server request, client startup, client connected)
    #[tokio::test]
    async fn test_ipp_print_job() -> E2EResult<()> {
        println!("\n=== E2E Test: IPP Client Print-Job ===");

        // Start an IPP server that accepts print jobs
        let server_config = NetGetConfig::new(
            "Listen on port {AVAILABLE_PORT} via IPP. When clients send Print-Job, accept the job and respond with job-id=42, job-state='processing'."
        )
        .with_mock(|mock| {
            mock
                // Mock 1: Server startup
                .on_instruction_containing("Listen on port")
                .and_instruction_containing("IPP")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "IPP",
                        "instruction": "IPP printer accepting print jobs"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2: Server receives Print-Job request
                .on_event("ipp_request_received")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "ipp_job_attributes",
                        "attributes": {
                            "job-id": 42,
                            "job-state": "processing"
                        }
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let server = start_netget_server(server_config).await?;
        println!("Server started on port {}", server.port);

        tokio::time::sleep(Duration::from_millis(500)).await;

        // Start IPP client that submits a print job
        let client_config = NetGetConfig::new(format!(
            "Connect to http://127.0.0.1:{}/printers/test via IPP. Submit a print job with text 'Test Document'.",
            server.port
        ))
        .with_mock(|mock| {
            mock
                // Mock 1: Client startup
                .on_instruction_containing("Connect to")
                .and_instruction_containing("IPP")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_client",
                        "remote_addr": format!("http://127.0.0.1:{}/printers/test", server.port),
                        "protocol": "IPP",
                        "instruction": "Submit print job with test document"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2: Client connected
                .on_event("ipp_connected")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "print_job",
                        "job_name": "Test Job",
                        "document_format": "text/plain",
                        "document_data": "VGVzdCBEb2N1bWVudA==" // "Test Document" in base64
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 3: Client receives job response
                .on_event("ipp_response_received")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "wait_for_more"
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let client = start_netget_client(client_config).await?;

        server.wait_for_mocks(30).await;

        // Verify client is IPP protocol
        assert_eq!(client.protocol, "IPP", "Client should be IPP protocol");

        println!("✅ IPP client successfully submitted print job");

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

    /// Test IPP client can check job status via Get-Job-Attributes
    /// LLM calls: 4 (server startup, server request, client startup, client connected)
    #[tokio::test]
    async fn test_ipp_get_job_attributes() -> E2EResult<()> {
        println!("\n=== E2E Test: IPP Client Get-Job-Attributes ===");

        // Start an IPP server that responds to Get-Job-Attributes
        let server_config = NetGetConfig::new(
            "Listen on port {AVAILABLE_PORT} via IPP. When clients send Get-Job-Attributes, respond with job-id=100, job-state='completed'."
        )
        .with_mock(|mock| {
            mock
                // Mock 1: Server startup
                .on_instruction_containing("Listen on port")
                .and_instruction_containing("IPP")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "IPP",
                        "instruction": "IPP server responding to Get-Job-Attributes"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2: Server receives Get-Job-Attributes request
                .on_event("ipp_request_received")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "ipp_job_attributes",
                        "attributes": {
                            "job-id": 100,
                            "job-state": "completed"
                        }
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let server = start_netget_server(server_config).await?;
        println!("Server started on port {}", server.port);

        tokio::time::sleep(Duration::from_millis(500)).await;

        // Start IPP client that queries job status
        let client_config = NetGetConfig::new(format!(
            "Connect to http://127.0.0.1:{}/printers/test via IPP. Check status of job ID 100.",
            server.port
        ))
        .with_mock(|mock| {
            mock
                // Mock 1: Client startup
                .on_instruction_containing("Connect to")
                .and_instruction_containing("IPP")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_client",
                        "remote_addr": format!("http://127.0.0.1:{}/printers/test", server.port),
                        "protocol": "IPP",
                        "instruction": "Check job status for job 100"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2: Client connected
                .on_event("ipp_connected")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "get_job_attributes",
                        "job_id": 100
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 3: Client receives job status
                .on_event("ipp_response_received")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "wait_for_more"
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let client = start_netget_client(client_config).await?;

        println!("✅ IPP client successfully queried job attributes");

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
}

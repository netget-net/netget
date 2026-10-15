//! E2E tests for PyPI protocol with mocks
//!
//! These tests verify PyPI server functionality using mock LLM responses.
//! Test strategy: Mock HTTP responses for PEP 503 endpoints, < 10 LLM calls total.

mod pypi_server_tests {
    use crate::helpers::*;
    use std::time::Duration;

    /// Test PyPI package index endpoint with mocks
    /// LLM calls: 2 (server startup, http_request for /simple/)
    #[tokio::test]
    async fn test_pypi_package_index_with_mocks() -> E2EResult<()> {
        // Start a PyPI server with mocks
        let server_config = NetGetConfig::new(
            "Listen on port {AVAILABLE_PORT} via pypi. Serve package index with hello-world package."
        )
        .with_mock(|mock| {
            mock
                // Mock 1: Server startup
                .on_instruction_containing("Listen on port")
                .and_instruction_containing("pypi")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "PyPI",
                        "instruction": "PyPI server - serve package index"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2: PyPI request for /simple/
                .on_event("pypi_request")
                .and_event_data_contains("path", "/simple/")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "send_pypi_response",
                        "status": 200,
                        "headers": {
                            "Content-Type": "text/html"
                        },
                        "body": "<!DOCTYPE html><html><body><a href=\"hello-world/\">hello-world</a></body></html>"
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let mut server = start_netget_server(server_config).await?;

        tokio::time::sleep(Duration::from_millis(500)).await;

        // Make HTTP request to trigger pypi_request event
        let url = format!("http://127.0.0.1:{}/simple/", server.port);
        let output = tokio::time::timeout(
            Duration::from_secs(10),
            tokio::task::spawn_blocking(move || {
                std::process::Command::new("curl")
                    .arg("-s")
                    .arg("--max-time")
                    .arg("5")
                    .arg(&url)
                    .output()
            }),
        )
        .await
        .map_err(|_| "curl timeout")?
        .map_err(|_| "curl spawn failed")?
        .map_err(|e| format!("curl failed: {}", e))?;

        // Wait for server to fully process the request
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Asserted, not printed. All three tests in this file used to end at
        // `println!("... {} bytes", output.stdout.len())` and never look at the body,
        // so the only thing they checked was that a mock rule had been hit — a
        // response of the wrong shape, or the wrong body entirely, passed. The
        // not-found test additionally called curl without `-w`, so it never saw a
        // status code at all despite being named for one.
        let body = String::from_utf8_lossy(&output.stdout);
        assert!(
            body.contains("hello-world/"),
            "the package index did not carry the PEP 503 anchor the mock served: {body:?}"
        );
        println!(
            "✅ PyPI server served the package index ({} bytes)",
            body.len()
        );

        // Add timeout to mock verification to prevent indefinite hanging
        tokio::time::timeout(Duration::from_secs(10), server.verify_mocks())
            .await
            .map_err(|_| "Mock verification timed out after 10s")??;

        tokio::time::timeout(Duration::from_secs(5), server.stop())
            .await
            .map_err(|_| "Server stop timed out after 5s")??;

        Ok(())
    }

    /// Test PyPI package page endpoint with mocks
    /// LLM calls: 2 (server startup, http_request for /simple/hello-world/)
    #[tokio::test]
    async fn test_pypi_package_page_with_mocks() -> E2EResult<()> {
        // Start a PyPI server
        let server_config = NetGetConfig::new(
            "Listen on port {AVAILABLE_PORT} via pypi. Serve hello-world package page with wheel file."
        )
        .with_mock(|mock| {
            mock
                // Mock 1: Server startup
                .on_instruction_containing("Listen on port")
                .and_instruction_containing("pypi")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "PyPI",
                        "instruction": "PyPI server - serve hello-world package"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2: PyPI request for package page
                .on_event("pypi_request")
                .and_event_data_contains("path", "hello-world")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "send_pypi_response",
                        "status": 200,
                        "headers": {
                            "Content-Type": "text/html"
                        },
                        "body": "<!DOCTYPE html><html><body><a href=\"../../packages/h/hello-world/hello_world-1.0.0-py3-none-any.whl#sha256=abc123\">hello_world-1.0.0-py3-none-any.whl</a></body></html>"
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let mut server = start_netget_server(server_config).await?;

        tokio::time::sleep(Duration::from_millis(500)).await;

        // Make HTTP request to trigger pypi_request event
        let url = format!("http://127.0.0.1:{}/simple/hello-world/", server.port);
        let output = tokio::time::timeout(
            Duration::from_secs(10),
            tokio::task::spawn_blocking(move || {
                std::process::Command::new("curl")
                    .arg("-s")
                    .arg("--max-time")
                    .arg("5")
                    .arg(&url)
                    .output()
            }),
        )
        .await
        .map_err(|_| "curl timeout")?
        .map_err(|_| "curl spawn failed")?
        .map_err(|e| format!("curl failed: {}", e))?;

        // Wait for server to fully process the request
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Asserted, not printed: see the note in the package-index test above.
        let body = String::from_utf8_lossy(&output.stdout);
        assert!(
            body.contains("hello_world-1.0.0-py3-none-any.whl"),
            "the project page did not carry the distribution filename the mock served: \
             {body:?}"
        );
        assert!(
            body.contains("#sha256="),
            "the project page carried no PEP 503 hash fragment, which is what pip \
             verifies the download against: {body:?}"
        );
        println!(
            "✅ PyPI server served the project page ({} bytes)",
            body.len()
        );

        // Add timeout to mock verification to prevent indefinite hanging
        tokio::time::timeout(Duration::from_secs(10), server.verify_mocks())
            .await
            .map_err(|_| "Mock verification timed out after 10s")??;

        tokio::time::timeout(Duration::from_secs(5), server.stop())
            .await
            .map_err(|_| "Server stop timed out after 5s")??;

        Ok(())
    }

    /// Test PyPI 404 for non-existent package with mocks
    /// LLM calls: 2 (server startup, http_request for unknown package)
    #[tokio::test]
    async fn test_pypi_package_not_found_with_mocks() -> E2EResult<()> {
        // Start a PyPI server
        let server_config = NetGetConfig::new(
            "Listen on port {AVAILABLE_PORT} via pypi. Return 404 for non-existent packages.",
        )
        .with_mock(|mock| {
            mock
                // Mock 1: Server startup
                .on_instruction_containing("Listen on port")
                .and_instruction_containing("pypi")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "PyPI",
                        "instruction": "PyPI server - return 404 for unknown packages"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2: PyPI request for non-existent package
                .on_event("pypi_request")
                .and_event_data_contains("path", "nonexistent")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "send_pypi_response",
                        "status": 404,
                        "body": "Not Found"
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let mut server = start_netget_server(server_config).await?;

        tokio::time::sleep(Duration::from_millis(500)).await;

        // Make HTTP request to trigger pypi_request event
        let url = format!(
            "http://127.0.0.1:{}/simple/nonexistent-package/",
            server.port
        );
        // `-w '%{http_code}'` and `-o /dev/null`: this test is named for a status code
        // and was invoking curl in a way that could never show it one.
        let output = tokio::time::timeout(
            Duration::from_secs(10),
            tokio::task::spawn_blocking(move || {
                std::process::Command::new("curl")
                    .arg("-s")
                    .arg("-o")
                    .arg("/dev/null")
                    .arg("-w")
                    .arg("%{http_code}")
                    .arg("--max-time")
                    .arg("5")
                    .arg(&url)
                    .output()
            }),
        )
        .await
        .map_err(|_| "curl timeout")?
        .map_err(|_| "curl spawn failed")?
        .map_err(|e| format!("curl failed: {}", e))?;

        // Wait for server to fully process the request
        tokio::time::sleep(Duration::from_millis(500)).await;

        let status = String::from_utf8_lossy(&output.stdout);
        assert_eq!(
            status.trim(),
            "404",
            "a project the index does not serve must come back 404, not {status}"
        );
        println!("✅ PyPI server returned 404 for a non-existent package");

        // Add timeout to mock verification to prevent indefinite hanging
        tokio::time::timeout(Duration::from_secs(10), server.verify_mocks())
            .await
            .map_err(|_| "Mock verification timed out after 10s")??;

        tokio::time::timeout(Duration::from_secs(5), server.stop())
            .await
            .map_err(|_| "Server stop timed out after 5s")??;

        Ok(())
    }
}

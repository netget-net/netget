//! E2E tests for HTTP/HTTPS Proxy with mocks
//!
//! These tests verify Proxy functionality using mock LLM responses.
//! Test strategy: Mock proxy decisions, < 10 LLM calls total.

#[cfg(unix)]
mod proxy_server_tests {
    use crate::helpers::*;
    use std::time::Duration;

    /// Test HTTP proxy pass-through with mocks
    /// LLM calls: 1 (server startup only - no actual requests sent)
    #[tokio::test]
    async fn test_proxy_http_passthrough_with_mocks() -> E2EResult<()> {
        // Start a Proxy server with mocks
        let server_config = NetGetConfig::new(
            "Listen on port {AVAILABLE_PORT} using proxy stack. Pass all HTTP requests through unchanged."
        )
        .with_mock(|mock| {
            mock
                // Mock: Server startup only
                .on_instruction_containing("Listen on port")
                .and_instruction_containing("proxy")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "Proxy",
                        "instruction": "Pass all HTTP requests through unchanged"
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let server = start_netget_server(server_config).await?;

        // Give server time to start
        tokio::time::sleep(Duration::from_millis(500)).await;

        println!("✅ Proxy server started successfully");

        // Verify mock expectations were met
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last event routinely lands after
        // the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;

        // Cleanup
        server.stop().await?;

        Ok(())
    }

    /// Test HTTP proxy blocking with mocks
    /// LLM calls: 1 (server startup only - no actual requests sent)
    #[tokio::test]
    async fn test_proxy_http_block_with_mocks() -> E2EResult<()> {
        // Start a Proxy server that blocks requests
        let server_config = NetGetConfig::new(
            "Listen on port {AVAILABLE_PORT} using proxy stack. Block all requests with 403 status."
        )
        .with_mock(|mock| {
            mock
                // Mock: Server startup only
                .on_instruction_containing("Listen on port")
                .and_instruction_containing("proxy")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "Proxy",
                        "instruction": "Block all requests with 403 status"
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let server = start_netget_server(server_config).await?;

        tokio::time::sleep(Duration::from_millis(500)).await;

        println!("✅ Proxy server started successfully");

        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last event routinely lands after
        // the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;

        Ok(())
    }

    /// Test HTTPS proxy CONNECT handling with mocks
    /// LLM calls: 1 (server startup only - no actual requests sent)
    #[tokio::test]
    async fn test_proxy_https_connect_with_mocks() -> E2EResult<()> {
        // Start a Proxy server for HTTPS
        let server_config = NetGetConfig::new(
            "Listen on port {AVAILABLE_PORT} using proxy stack with no certificate. Allow all HTTPS connections."
        )
        .with_mock(|mock| {
            mock
                // Mock: Server startup only (no startup_params needed for passthrough mode - it's the default)
                .on_instruction_containing("Listen on port")
                .and_instruction_containing("proxy")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "Proxy",
                        "instruction": "Allow all HTTPS connections"
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let server = start_netget_server(server_config).await?;

        tokio::time::sleep(Duration::from_millis(500)).await;

        println!("✅ Proxy server started successfully");

        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last event routinely lands after
        // the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;

        Ok(())
    }

    /// Test proxy header modification with mocks
    /// LLM calls: 1 (server startup only - no actual requests sent)
    #[tokio::test]
    async fn test_proxy_modify_headers_with_mocks() -> E2EResult<()> {
        // Start a Proxy server that modifies headers
        let server_config = NetGetConfig::new(
            "Listen on port {AVAILABLE_PORT} using proxy stack. Add header X-Proxy-Modified: NetGet to all requests."
        )
        .with_mock(|mock| {
            mock
                // Mock: Server startup only
                .on_instruction_containing("Listen on port")
                .and_instruction_containing("proxy")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "Proxy",
                        "instruction": "Add header X-Proxy-Modified: NetGet"
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let server = start_netget_server(server_config).await?;

        tokio::time::sleep(Duration::from_millis(500)).await;

        println!("✅ Proxy server started successfully");

        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last event routinely lands after
        // the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;

        Ok(())
    }

    /// Test MITM mode initialization with certificate generation
    /// LLM calls: 1 (server startup with certificate generation)
    #[tokio::test]
    async fn test_proxy_mitm_initialization() -> E2EResult<()> {
        // Start a Proxy server in MITM mode with certificate generation
        let server_config = NetGetConfig::new(
            "Listen on port {AVAILABLE_PORT} using proxy stack with certificate generation (MITM mode). Inspect all HTTPS traffic."
        )
        .with_mock(|mock| {
            mock
                // Mock: Server startup with MITM mode
                .on_instruction_containing("Listen on port")
                .and_instruction_containing("MITM")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "Proxy",
                        // No "mode" key: proxy declares no such startup parameter, and an
                        // undeclared key fails validation before add_server, so the server
                        // never started and the test asserted nothing. certificate_mode
                        // "generate" is what selects MITM.
                        "startup_params": {
                            "certificate_mode": "generate"
                        },
                        "instruction": "Inspect all HTTPS traffic"
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let mut server = start_netget_server(server_config).await?;

        tokio::time::sleep(Duration::from_millis(500)).await;

        println!("✅ Proxy server initialized in MITM mode with certificate generation");

        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last event routinely lands after
        // the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;

        Ok(())
    }

    /// Test MITM mode HTTPS interception and request inspection
    /// LLM calls: 2 (server startup, https request inspection)
    #[tokio::test]
    async fn test_proxy_mitm_https_interception() -> E2EResult<()> {
        // Start a Proxy server in MITM mode that inspects HTTPS requests
        let server_config = NetGetConfig::new(
            "Listen on port {AVAILABLE_PORT} using proxy stack with certificate generation. Inspect HTTPS requests and pass them through."
        )
        .with_mock(|mock| {
            mock
                // Mock 1: Server startup
                .on_instruction_containing("Listen on port")
                .and_instruction_containing("certificate generation")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "Proxy",
                        // No "mode" key: proxy declares no such startup parameter, and an
                        // undeclared key fails validation before add_server, so the server
                        // never started and the test asserted nothing. certificate_mode
                        // "generate" is what selects MITM.
                        "startup_params": {
                            "certificate_mode": "generate"
                        },
                        "instruction": "Inspect HTTPS requests and pass them through"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2: HTTPS request received after TLS decryption
                .on_event("proxy_http_request")
                .and_event_data_contains("url", "https://")
                // `handle_request_pass`, not `proxy_passthrough` - the latter is not a
                // proxy action and was rejected as unknown.
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "handle_request_pass"
                    }
                ]))
                // Cannot be 1: this test drives no client through the proxy, so no
                // request event is ever raised. See the note above the assertion below.
                .expect_calls(0)
                .and()
        });

        let mut server = start_netget_server(server_config).await?;

        tokio::time::sleep(Duration::from_millis(500)).await;

        // This test starts the server and stops it. No client is driven through the
        // proxy, so nothing is intercepted; the mock above exists only so the action
        // name is validated against the registry. The real request/response coverage
        // lives in tests/server/proxy/test.rs.
        println!("✅ Proxy server started in MITM mode (no traffic driven by this test)");

        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last event routinely lands after
        // the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;

        Ok(())
    }

    /// Test MITM mode request modification
    /// LLM calls: 2 (server startup, request modification)
    #[tokio::test]
    async fn test_proxy_mitm_request_modification() -> E2EResult<()> {
        // Start a Proxy server in MITM mode that modifies HTTPS requests
        let server_config = NetGetConfig::new(
            "Listen on port {AVAILABLE_PORT} using proxy stack with certificate generation. Add Authorization header to all HTTPS requests to api.example.com."
        )
        .with_mock(|mock| {
            mock
                // Mock 1: Server startup
                .on_instruction_containing("Listen on port")
                .and_instruction_containing("certificate generation")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "Proxy",
                        // No "mode" key: proxy declares no such startup parameter, and an
                        // undeclared key fails validation before add_server, so the server
                        // never started and the test asserted nothing. certificate_mode
                        // "generate" is what selects MITM.
                        "startup_params": {
                            "certificate_mode": "generate"
                        },
                        "instruction": "Add Authorization header to HTTPS requests"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2: HTTPS request to api.example.com - add auth header
                .on_event("proxy_http_request")
                .and_event_data_contains("host", "api.example.com")
                // `handle_request_modify` with a `headers` object, not
                // `proxy_modify_request` with `add_headers` - neither name existed.
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "handle_request_modify",
                        "headers": {
                            "Authorization": "Bearer TOKEN123"
                        }
                    }
                ]))
                .expect_calls(0)
                .and()
        });

        let mut server = start_netget_server(server_config).await?;

        tokio::time::sleep(Duration::from_millis(500)).await;

        println!("✅ Proxy server started in MITM modify config (no traffic driven)");

        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last event routinely lands after
        // the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;

        Ok(())
    }

    /// Test MITM mode request blocking
    /// LLM calls: 2 (server startup, request blocking)
    #[tokio::test]
    async fn test_proxy_mitm_request_blocking() -> E2EResult<()> {
        // Start a Proxy server in MITM mode that blocks certain HTTPS requests
        let server_config = NetGetConfig::new(
            "Listen on port {AVAILABLE_PORT} using proxy stack with certificate generation. Block HTTPS requests containing sensitive data."
        )
        .with_mock(|mock| {
            mock
                // Mock 1: Server startup
                .on_instruction_containing("Listen on port")
                .and_instruction_containing("certificate generation")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "Proxy",
                        // No "mode" key: proxy declares no such startup parameter, and an
                        // undeclared key fails validation before add_server, so the server
                        // never started and the test asserted nothing. certificate_mode
                        // "generate" is what selects MITM.
                        "startup_params": {
                            "certificate_mode": "generate"
                        },
                        "instruction": "Block HTTPS requests with sensitive data"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2: HTTPS request with sensitive data - block it
                .on_event("proxy_http_request")
                .and_event_data_contains("url", "https://")
                // `handle_request_block`, not `proxy_block`.
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "handle_request_block",
                        "status": 403,
                        "body": "Request blocked: contains sensitive data"
                    }
                ]))
                .expect_calls(0)
                .and()
        });

        let mut server = start_netget_server(server_config).await?;

        tokio::time::sleep(Duration::from_millis(500)).await;

        println!("✅ Proxy server started in MITM blocking config (no traffic driven)");

        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last event routinely lands after
        // the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;

        Ok(())
    }

    /// Test that the CA certificate is exported to the declared `ca_export_path`.
    ///
    /// This is a startup *parameter*, not an action. It used to be tested by mocking an
    /// `export_ca_certificate` action, which (a) no longer exists - it was one of six
    /// configuration actions removed for serialising their arguments and writing nothing -
    /// and (b) was keyed on an instruction the test never sent after startup, so the mock
    /// could not fire and the test asserted only that a server started.
    ///
    /// LLM calls: 1 (server startup)
    #[tokio::test]
    async fn test_proxy_export_ca_certificate() -> E2EResult<()> {
        let export_dir = std::env::temp_dir().join(format!(
            "netget-proxy-ca-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&export_dir)?;
        let ca_path = export_dir.join("netget-ca.crt");

        let server_config = NetGetConfig::new(
            "Listen on port {AVAILABLE_PORT} using proxy stack with certificate generation. Export CA certificate."
        )
        .with_mock({
            let ca_path = ca_path.clone();
            move |mock| {
                mock.on_instruction_containing("Listen on port")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "open_server",
                            "port": 0,
                            "base_stack": "Proxy",
                            "startup_params": {
                                "certificate_mode": "generate",
                                "ca_export_path": ca_path.to_string_lossy(),
                            },
                            "instruction": "MITM proxy with certificate export"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
            }
        });

        let mut server = start_netget_server(server_config).await?;

        let pem = std::fs::read_to_string(&ca_path).unwrap_or_else(|e| {
            panic!("ca_export_path {} was not written: {e}", ca_path.display())
        });
        assert!(
            pem.starts_with("-----BEGIN CERTIFICATE-----"),
            "ca_export_path must receive a PEM certificate, got: {:?}",
            &pem[..pem.len().min(64)]
        );
        assert!(
            pem.trim_end().ends_with("-----END CERTIFICATE-----"),
            "exported PEM is truncated"
        );
        assert!(
            !pem.contains("PRIVATE KEY"),
            "the CA private key must never be written to disk"
        );

        println!("✅ CA certificate exported to {}", ca_path.display());

        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last event routinely lands after
        // the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;

        let _ = std::fs::remove_dir_all(&export_dir);

        Ok(())
    }

    /// Test MITM response modification with mocks
    /// LLM calls: 1 (server startup with response modification config)
    /// Note: Full request/response flow testing would require actual HTTP server setup
    #[tokio::test]
    async fn test_proxy_mitm_response_modification_with_mocks() -> E2EResult<()> {
        // Start a Proxy server in MITM mode with response modification enabled
        let server_config = NetGetConfig::new(
            "Listen on port {AVAILABLE_PORT} using proxy stack with certificate generation. Intercept all HTTP responses and modify them."
        )
        .with_mock(|mock| {
            mock
                // Mock 1: Server startup with response filter enabled
                .on_instruction_containing("Listen on port")
                .and_instruction_containing("certificate generation")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "Proxy",
                        "startup_params": {
                            "certificate_mode": "generate",
                            "request_filter_mode": "all",
                            "response_filter_mode": "all"
                        },
                        "instruction": "MITM proxy with response modification"
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let mut server = start_netget_server(server_config).await?;

        tokio::time::sleep(Duration::from_millis(500)).await;

        println!("✅ MITM proxy initialized with response modification enabled");

        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last event routinely lands after
        // the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;

        Ok(())
    }

    /// Test MITM response blocking with mocks
    /// LLM calls: 1 (server startup with response blocking config)
    /// Note: Full request/response flow testing would require actual HTTP server setup
    #[tokio::test]
    async fn test_proxy_mitm_response_blocking_with_mocks() -> E2EResult<()> {
        // Start a Proxy server in MITM mode with response blocking capability
        let server_config = NetGetConfig::new(
            "Listen on port {AVAILABLE_PORT} using proxy stack with certificate generation. Block all HTTP responses containing sensitive data."
        )
        .with_mock(|mock| {
            mock
                // Mock 1: Server startup with response filter enabled
                .on_instruction_containing("Listen on port")
                .and_instruction_containing("certificate generation")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "Proxy",
                        "startup_params": {
                            "certificate_mode": "generate",
                            "request_filter_mode": "none",
                            "response_filter_mode": "all"
                        },
                        "instruction": "MITM proxy with response blocking for sensitive data"
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let mut server = start_netget_server(server_config).await?;

        tokio::time::sleep(Duration::from_millis(500)).await;

        println!("✅ MITM proxy initialized with response blocking enabled");

        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last event routinely lands after
        // the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;

        Ok(())
    }
}

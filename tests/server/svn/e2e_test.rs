// These were all `#[ignore]`d for a documentation-read retry that no longer happens.
//
// `REQUIRE_DOCS_FOR_OPEN_ACTIONS` (src/events/handler.rs) is a compile-time `false`, and every
// `DocumentationRequired` path is behind it, so the forced second round-trip whose synthetic
// prompt dropped the original instruction — the thing that made these unmockable — is gone.
// Four of the five passed unchanged once the ignore was lifted; the fifth failed only because
// it still carried a mock rule for the retry, which now never matches.
//
// Lesson worth keeping: an `#[ignore]` citing a defect elsewhere goes stale silently when that
// defect is fixed, and nothing re-checks it. Re-run ignored tests with `--include-ignored`
// after landing an infrastructure fix.
mod svn_e2e_test {
    use crate::helpers::{E2EResult, NetGetConfig};
    use std::time::Duration;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpStream;

    async fn send_svn_command(addr: &str, command: &str) -> String {
        let stream = TcpStream::connect(addr)
            .await
            .expect("Failed to connect to SVN server");

        let mut reader = BufReader::new(stream);

        // Read greeting from server
        let mut greeting = String::new();
        tokio::time::timeout(Duration::from_secs(10), reader.read_line(&mut greeting))
            .await
            .expect("Timeout reading greeting")
            .expect("Failed to read greeting");

        // Send command
        let command_with_newline = format!("{}\n", command.trim());
        reader
            .get_mut()
            .write_all(command_with_newline.as_bytes())
            .await
            .expect("Failed to send command");

        // Read response
        let mut response = String::new();
        tokio::time::timeout(Duration::from_secs(10), reader.read_line(&mut response))
            .await
            .expect("Timeout reading response")
            .expect("Failed to read response");

        response
    }

    #[tokio::test]
    async fn test_svn_greeting() -> E2EResult<()> {
        println!("\n=== E2E Test: SVN Greeting with Mocks ===");

        let config = NetGetConfig::new("Listen on port {AVAILABLE_PORT} via SVN")
            .with_log_level("info")
            .with_mock(|mock| {
                mock
                    // Mock 1: Server startup
                    .on_instruction_containing("Listen on port")
                    .and_instruction_containing("SVN")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "open_server",
                            "port": 0,
                            "base_stack": "SVN",
                            "instruction": "SVN server with protocol greeting"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // Mock 2: SVN greeting event
                    .on_event("svn_greeting")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "send_svn_greeting",
                            "min_version": 2,
                            "max_version": 2,
                            "mechanisms": ["ANONYMOUS"],
                            "capabilities": ["edit-pipeline", "svndiff1"]
                        }
                    ]))
                    .expect_calls(1)
                    .and()
            });

        let mut server = crate::helpers::netget::start_netget(config).await?;

        // Extract server port
        assert!(!server.servers.is_empty(), "Expected at least one server");
        let port = server.servers[0].port;
        let addr = format!("127.0.0.1:{}", port);

        // Wait for server to be ready
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Connect and read greeting
        let stream = TcpStream::connect(&addr).await.expect("Failed to connect");
        let mut reader = BufReader::new(stream);

        let mut greeting = String::new();
        tokio::time::timeout(Duration::from_secs(10), reader.read_line(&mut greeting))
            .await
            .expect("Timeout reading greeting")
            .expect("Failed to read greeting");

        println!("Received greeting: {}", greeting);

        assert!(
            greeting.contains("success") || greeting.contains("2"),
            "Greeting should contain success and version 2: {}",
            greeting
        );

        println!("✓ SVN greeting test passed");

        // Verify mock expectations
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last event routinely lands after
        // the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;

        // Cleanup
        server.stop().await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_svn_get_latest_rev() -> E2EResult<()> {
        println!("\n=== E2E Test: SVN Get Latest Revision with Mocks ===");

        let config = NetGetConfig::new("Listen on port {AVAILABLE_PORT} via SVN")
            .with_log_level("info")
            .with_mock(|mock| {
                mock
                    // Mock 1: Server startup
                    .on_instruction_containing("Listen on port")
                    .and_instruction_containing("SVN")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "open_server",
                            "port": 0,
                            "base_stack": "SVN",
                            "instruction": "SVN server"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // Mock 2: SVN greeting event
                    .on_event("svn_greeting")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "send_svn_greeting",
                            "min_version": 2,
                            "max_version": 2,
                            "mechanisms": ["ANONYMOUS"],
                            "capabilities": ["edit-pipeline"]
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // Mock 3: get-latest-rev command
                    .on_event("svn_command")
                    .and_event_data_contains("command", "get-latest-rev")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "send_svn_success",
                            "data": "42"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
            });

        let mut server = crate::helpers::netget::start_netget(config).await?;

        // Extract server port
        assert!(!server.servers.is_empty(), "Expected at least one server");
        let port = server.servers[0].port;
        let addr = format!("127.0.0.1:{}", port);

        // Wait for server to be ready
        tokio::time::sleep(Duration::from_millis(500)).await;

        let response = send_svn_command(&addr, "( get-latest-rev )").await;
        println!("Received response: {}", response);

        assert!(
            response.contains("success") || response.contains("42"),
            "Response should contain success or revision 42: {}",
            response
        );

        println!("✓ SVN get-latest-rev test passed");

        // Verify mock expectations
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last event routinely lands after
        // the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;

        // Cleanup
        server.stop().await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_svn_get_dir() -> E2EResult<()> {
        println!("\n=== E2E Test: SVN Get Directory Listing with Mocks ===");

        let config = NetGetConfig::new("Listen on port {AVAILABLE_PORT} via SVN")
            .with_log_level("info")
            .with_mock(|mock| {
                mock.on_instruction_containing("Listen on port")
                    .and_instruction_containing("SVN")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "open_server",
                            "port": 0,
                            "base_stack": "SVN",
                            "instruction": "SVN server that lists trunk/branches/tags for get-dir"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    .on_event("svn_greeting")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "send_svn_greeting",
                            "min_version": 2,
                            "max_version": 2,
                            "mechanisms": ["ANONYMOUS"],
                            "capabilities": ["edit-pipeline"]
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    .on_event("svn_command")
                    .and_event_data_contains("command", "get-dir")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "send_svn_list",
                            "items": [
                                {"name": "trunk", "kind": "dir"},
                                {"name": "branches", "kind": "dir"},
                                {"name": "tags", "kind": "dir"}
                            ]
                        }
                    ]))
                    .expect_calls(1)
                    .and()
            });

        let mut server = crate::helpers::netget::start_netget(config).await?;

        assert!(!server.servers.is_empty(), "Expected at least one server");
        let port = server.servers[0].port;
        let addr = format!("127.0.0.1:{}", port);

        tokio::time::sleep(Duration::from_millis(500)).await;

        let response = send_svn_command(&addr, "( get-dir )").await;
        println!("Received response: {}", response);

        assert!(
            response.contains("success") || response.contains("trunk") || response.contains("dir"),
            "Response should contain success or directory listing: {}",
            response
        );

        println!("✓ SVN get-dir test passed");

        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last event routinely lands after
        // the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_svn_error_response() -> E2EResult<()> {
        println!("\n=== E2E Test: SVN Error Response with Mocks ===");

        let config = NetGetConfig::new("Listen on port {AVAILABLE_PORT} via SVN")
            .with_log_level("info")
            .with_mock(|mock| {
                mock.on_instruction_containing("Listen on port")
                    .and_instruction_containing("SVN")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "open_server",
                            "port": 0,
                            "base_stack": "SVN",
                            "instruction": "SVN server that fails any command with 'Path not found'"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    .on_event("svn_greeting")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "send_svn_greeting",
                            "min_version": 2,
                            "max_version": 2,
                            "mechanisms": ["ANONYMOUS"],
                            "capabilities": ["edit-pipeline"]
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    .on_event("svn_command")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "send_svn_failure",
                            "error_code": 210005,
                            "message": "Path not found"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
            });

        let mut server = crate::helpers::netget::start_netget(config).await?;

        assert!(!server.servers.is_empty(), "Expected at least one server");
        let port = server.servers[0].port;
        let addr = format!("127.0.0.1:{}", port);

        tokio::time::sleep(Duration::from_millis(500)).await;

        let response = send_svn_command(&addr, "( stat /nonexistent )").await;
        println!("Received response: {}", response);

        assert!(
            response.contains("failure")
                || response.contains("error")
                || response.contains("not found"),
            "Response should indicate failure: {}",
            response
        );

        println!("✓ SVN error response test passed");

        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last event routinely lands after
        // the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_svn_connection_stats() -> E2EResult<()> {
        // Verifies connection tracking indirectly via the server's debug log,
        // since AppState connection introspection is not part of the black-box
        // (subprocess) test surface.
        println!("\n=== E2E Test: SVN Connection Stats with Mocks ===");

        let config = NetGetConfig::new("Listen on port {AVAILABLE_PORT} via SVN")
            .with_log_level("debug")
            .with_mock(|mock| {
                mock.on_instruction_containing("Listen on port")
                    .and_instruction_containing("SVN")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "open_server",
                            "port": 0,
                            "base_stack": "SVN",
                            "instruction": "SVN server that accepts everything"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    .on_event("svn_greeting")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "send_svn_greeting",
                            "min_version": 2,
                            "max_version": 2,
                            "mechanisms": ["ANONYMOUS"],
                            "capabilities": ["edit-pipeline"]
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    .on_event("svn_command")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "send_svn_success"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
            });

        let mut server = crate::helpers::netget::start_netget(config).await?;

        assert!(!server.servers.is_empty(), "Expected at least one server");
        let port = server.servers[0].port;
        let addr = format!("127.0.0.1:{}", port);

        tokio::time::sleep(Duration::from_millis(500)).await;

        // Send command
        let _response = send_svn_command(&addr, "( get-latest-rev )").await;

        // Verify the server logged the incoming connection
        server.wait_for_log("SVN client connected from", 5).await?;

        println!("✓ SVN connection stats test passed");

        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last event routinely lands after
        // the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;
        Ok(())
    }
}

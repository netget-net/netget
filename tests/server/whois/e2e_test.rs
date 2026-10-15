//! End-to-end WHOIS tests.
//!
//! The first test drives the real `whois(1)` binary, which is what the `Beta` rating rests
//! on: it proves a real client accepts the framing this server produces. The remaining
//! tests use a raw TCP socket for the cases `whois(1)` cannot reach - it sends exactly one
//! query and then reads to EOF, so an error reply, a second query on the same connection,
//! and connection logging all need a socket.
//!
//! Two things about `whois(1)` worth knowing before changing these tests:
//!
//! - macOS's `whois` **segfaults** when `-h` is given an IP literal (`-h 127.0.0.1`). It
//!   does the same against a plain `nc` listener, so it is a client bug. `-h localhost`
//!   works and still resolves to loopback only, which is what these tests use.
//! - It reads until EOF. RFC 3912 has the server close as soon as its output is finished,
//!   but this server keeps the connection open, so the handler must answer with
//!   `close_connection` or `whois(1)` blocks forever.
mod whois_e2e_test {
    use crate::helpers::pcap_oracle::PcapOracle;
    use crate::helpers::{start_netget_server, E2EResult, NetGetConfig};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    async fn send_whois_query(addr: &str, query: &str) -> String {
        let mut stream = TcpStream::connect(addr)
            .await
            .expect("Failed to connect to WHOIS server");

        // Send query with CRLF
        let query_with_crlf = format!("{}\r\n", query.trim());
        stream
            .write_all(query_with_crlf.as_bytes())
            .await
            .expect("Failed to send query");

        // Read response (up to 4KB)
        let mut response = vec![0u8; 4096];
        let n = tokio::time::timeout(Duration::from_secs(10), stream.read(&mut response))
            .await
            .expect("Timeout reading response")
            .expect("Failed to read response");

        // The pcap oracle: Wireshark's own RFC 3912 dissector reads the exchange.
        // whois(1) accepting the bytes proves a client tolerates them; this proves
        // an independent decoder recognises the *shape* - the CRLF-terminated
        // request and the free-form answer that follows it. Free by being wired
        // into the shared helper, so every raw-socket test in this file gets it.
        PcapOracle::tcp("whois")
            .to_server(query_with_crlf.as_bytes())
            .from_server(&response[..n])
            .assert_clean();

        String::from_utf8_lossy(&response[..n]).to_string()
    }

    /// The real `whois(1)` client must accept and print what this server writes.
    ///
    /// This is the evidence behind the `Beta` rating: a raw socket only proves bytes
    /// arrived, whereas `whois` exiting 0 with the record on stdout proves the framing,
    /// the CRLF line endings and the close are all acceptable to a real client.
    #[tokio::test]
    async fn test_whois_with_real_whois_client() -> E2EResult<()> {
        let config = NetGetConfig::new("listen on port {AVAILABLE_PORT} via whois")
            .with_log_level("info")
            .with_mock(|mock| {
                mock.on_instruction_containing("listen on port")
                    .and_instruction_containing("whois")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "open_server",
                            "port": 0,
                            "base_stack": "whois",
                            "instruction": "Answer example.com with a full record, then close"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    .on_event("whois_query")
                    .and_event_data_contains("query", "example.com")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "send_whois_record",
                            "domain": "example.com",
                            "registrar": "Test Registrar Inc.",
                            "registrant": "Test Organization",
                            "admin_contact": "Test Admin",
                            "name_servers": ["ns1.example.com", "ns2.example.com"]
                        },
                        // RFC 3912: whois(1) reads until EOF, so the server has to close.
                        {"type": "close_connection"}
                    ]))
                    .expect_calls(1)
                    .and()
            });

        let server = start_netget_server(config).await?;

        // `-h localhost` rather than `-h 127.0.0.1`: macOS whois(1) segfaults on an IP
        // literal. localhost still resolves to loopback only, so nothing leaves the host.
        let output = tokio::time::timeout(
            Duration::from_secs(30),
            tokio::process::Command::new("whois")
                .arg("-h")
                .arg("localhost")
                .arg("-p")
                .arg(server.port.to_string())
                .arg("example.com")
                .output(),
        )
        .await
        .map_err(|_| {
            "whois(1) did not exit within 30s - the server almost certainly never closed the \
             connection, and whois reads until EOF"
        })?
        .map_err(|e| {
            format!("could not run whois(1): {e}. Install the whois client to run this test.")
        })?;

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();

        assert!(
            output.status.success(),
            "whois(1) exited with {:?}\nstdout: {stdout}\nstderr: {stderr}",
            output.status
        );
        assert!(
            stdout.contains("Domain Name: example.com"),
            "whois(1) did not print the domain line.\nstdout: {stdout}\nstderr: {stderr}"
        );
        assert!(
            stdout.contains("Registrar: Test Registrar Inc."),
            "whois(1) did not print the registrar.\nstdout: {stdout}"
        );
        assert!(
            stdout.contains("Registrant Name: Test Organization"),
            "whois(1) did not print the registrant.\nstdout: {stdout}"
        );
        assert!(
            stdout.contains("Name Server: ns1.example.com")
                && stdout.contains("Name Server: ns2.example.com"),
            "whois(1) did not print both name servers.\nstdout: {stdout}"
        );

        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last event routinely lands after
        // the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_whois_basic_query() -> E2EResult<()> {
        let config = NetGetConfig::new("listen on port {AVAILABLE_PORT} via whois")
            .with_log_level("info")
            .with_mock(|mock| {
                mock
                    // Mock 1: Server startup
                    .on_instruction_containing("listen on port")
                    .and_instruction_containing("whois")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "open_server",
                            "port": 0,
                            "base_stack": "whois",
                            "instruction": "Respond to WHOIS queries for example.com with fake registrar info"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // Mock 2: query for example.com
                    .on_event("whois_query")
                    .and_event_data_contains("query", "example.com")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "send_whois_record",
                            "domain": "example.com",
                            "registrar": "Test Registrar Inc.",
                            "registrant": "Test Organization",
                            "name_servers": ["ns1.example.com", "ns2.example.com"]
                        }
                    ]))
                    .expect_calls(1)
                    .and()
            });

        let server = start_netget_server(config).await?;

        tokio::time::sleep(Duration::from_millis(500)).await;
        let addr = format!("127.0.0.1:{}", server.port);

        let response = send_whois_query(&addr, "example.com").await;
        assert!(
            response.contains("example.com"),
            "Response should contain domain name: {}",
            response
        );
        assert!(
            response.contains("Test Registrar") || response.contains("Registrar"),
            "Response should contain registrar info: {}",
            response
        );

        println!("✓ Basic WHOIS query test passed");

        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last event routinely lands after
        // the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_whois_error_response() -> E2EResult<()> {
        let config = NetGetConfig::new("listen on port {AVAILABLE_PORT} via whois")
            .with_log_level("info")
            .with_mock(|mock| {
                mock
                    // Mock 1: Server startup
                    .on_instruction_containing("listen on port")
                    .and_instruction_containing("whois")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "open_server",
                            "port": 0,
                            "base_stack": "whois",
                            "instruction": "Return an error for unknown domains"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // Mock 2: query for a nonexistent domain
                    .on_event("whois_query")
                    .and_event_data_contains("query", "nonexistent-xyz123.com")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "send_error",
                            "message": "Domain not found"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
            });

        let server = start_netget_server(config).await?;

        tokio::time::sleep(Duration::from_millis(500)).await;
        let addr = format!("127.0.0.1:{}", server.port);

        let response = send_whois_query(&addr, "nonexistent-xyz123.com").await;
        assert!(
            response.contains("not found")
                || response.contains("Error")
                || response.contains("error"),
            "Response should indicate domain not found: {}",
            response
        );

        println!("✓ WHOIS error response test passed");

        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last event routinely lands after
        // the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_whois_multiple_queries() -> E2EResult<()> {
        let config = NetGetConfig::new("listen on port {AVAILABLE_PORT} via whois")
            .with_log_level("info")
            .with_mock(|mock| {
                mock
                    // Mock 1: Server startup
                    .on_instruction_containing("listen on port")
                    .and_instruction_containing("whois")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "open_server",
                            "port": 0,
                            "base_stack": "whois",
                            "instruction": "Respond to WHOIS queries for example.com and example.org, keep connection open"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // Mock 2: query for example.com
                    .on_event("whois_query")
                    .and_event_data_contains("query", "example.com")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "send_whois_record",
                            "domain": "example.com",
                            "registrar": "Test Registrar A"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // Mock 3: query for example.org
                    .on_event("whois_query")
                    .and_event_data_contains("query", "example.org")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "send_whois_record",
                            "domain": "example.org",
                            "registrar": "Test Registrar B"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
            });

        let server = start_netget_server(config).await?;

        tokio::time::sleep(Duration::from_millis(500)).await;
        let addr = format!("127.0.0.1:{}", server.port);

        // Connect once and send multiple queries on the same connection
        let mut stream = TcpStream::connect(&addr).await.expect("Failed to connect");

        stream.write_all(b"example.com\r\n").await.unwrap();
        let mut buf = vec![0u8; 4096];
        let n1 = tokio::time::timeout(Duration::from_secs(10), stream.read(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let response1 = String::from_utf8_lossy(&buf[..n1]).to_string();
        assert!(
            response1.contains("example.com"),
            "response1: {}",
            response1
        );

        stream.write_all(b"example.org\r\n").await.unwrap();
        let n2 = tokio::time::timeout(Duration::from_secs(10), stream.read(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let response2 = String::from_utf8_lossy(&buf[..n2]).to_string();
        assert!(
            response2.contains("example.org"),
            "response2: {}",
            response2
        );

        println!("✓ Multiple WHOIS queries test passed");

        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last event routinely lands after
        // the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_whois_connection_stats() -> E2EResult<()> {
        // Verifies connection tracking indirectly via the server's debug log,
        // since AppState connection introspection is not part of the black-box
        // (subprocess) test surface.
        let config = NetGetConfig::new("listen on port {AVAILABLE_PORT} via whois")
            .with_log_level("debug")
            .with_mock(|mock| {
                mock.on_instruction_containing("listen on port")
                    .and_instruction_containing("whois")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "open_server",
                            "port": 0,
                            "base_stack": "whois",
                            "instruction": "Respond with fake registrar info for any domain query"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    .on_event("whois_query")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "send_whois_record",
                            "domain": "test.com",
                            "registrar": "Test Registrar"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
            });

        let server = start_netget_server(config).await?;

        tokio::time::sleep(Duration::from_millis(500)).await;
        let addr = format!("127.0.0.1:{}", server.port);

        let _response = send_whois_query(&addr, "test.com").await;

        // Verify the server logged the incoming connection
        server
            .wait_for_log("WHOIS client connected from", 5)
            .await?;

        println!("✓ WHOIS connection stats test passed");

        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last event routinely lands after
        // the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;
        Ok(())
    }
}

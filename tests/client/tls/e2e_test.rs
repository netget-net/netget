//! E2E tests for TLS client
//!
//! These tests verify TLS client functionality by spawning the actual NetGet binary
//! and testing client behavior as a black-box.
//! Test strategy: Use netget binary to start TLS server + TLS client, < 10 LLM calls total.

mod tls_client_tests {
    use crate::helpers::*;
    use ::netget::logging::patterns;
    use std::time::Duration;

    /// Helper to generate CA certificate and server certificate signed by that CA
    /// Returns (ca_pem, server_cert_path, server_key_path)
    fn generate_ca_signed_certs() -> E2EResult<(String, String, String)> {
        use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, SanType};
        use std::fs;
        use time::{Duration as TimeDuration, OffsetDateTime};

        // 1. Generate CA certificate
        let mut ca_params = CertificateParams::default();
        let mut ca_dn = DistinguishedName::new();
        ca_dn.push(DnType::CommonName, "Test CA");
        ca_dn.push(DnType::OrganizationName, "NetGet Test");
        ca_params.distinguished_name = ca_dn;
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);

        let now = OffsetDateTime::now_utc();
        ca_params.not_before = now;
        ca_params.not_after = now + TimeDuration::days(365);

        let ca_key_pair = KeyPair::generate()?;
        let ca_cert = ca_params.self_signed(&ca_key_pair)?;

        // 2. Generate server certificate signed by CA
        let mut server_params = CertificateParams::default();
        let mut server_dn = DistinguishedName::new();
        server_dn.push(DnType::CommonName, "localhost");
        server_params.distinguished_name = server_dn;
        server_params.subject_alt_names = vec![
            SanType::DnsName("localhost".try_into().unwrap()),
            SanType::IpAddress(std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))),
        ];
        server_params.not_before = now;
        server_params.not_after = now + TimeDuration::days(365);

        let server_key_pair = KeyPair::generate()?;

        // Create Issuer from CA params and key pair (Issuer::new takes ownership)
        let issuer = rcgen::Issuer::new(ca_params.clone(), &ca_key_pair);
        let server_cert = server_params.signed_by(&server_key_pair, &issuer)?;

        // 3. Write to temporary files
        let temp_dir = std::env::temp_dir();
        let ca_pem = ca_cert.pem();
        let server_cert_pem = server_cert.pem();
        let server_key_pem = server_key_pair.serialize_pem();

        let server_cert_path = temp_dir.join(format!(
            "netget_test_server_cert_{}.pem",
            std::process::id()
        ));
        let server_key_path =
            temp_dir.join(format!("netget_test_server_key_{}.pem", std::process::id()));

        fs::write(&server_cert_path, server_cert_pem)?;
        fs::write(&server_key_path, server_key_pem)?;

        Ok((
            ca_pem,
            server_cert_path.to_string_lossy().to_string(),
            server_key_path.to_string_lossy().to_string(),
        ))
    }

    /// Test TLS client connection to NetGet TLS server with self-signed certificates
    /// LLM calls: 4 (server startup, client startup, server data received, client connected)
    #[tokio::test]
    async fn test_tls_client_connect_to_server() -> E2EResult<()> {
        // Start a TLS server listening on an available port with mocks
        let server_config = NetGetConfig::new(
            "Listen on port {AVAILABLE_PORT} via TLS. Accept connections and echo received data back.",
        )
        .with_mock(|mock| {
            mock
                // Mock 1: Server startup (user command)
                .on_instruction_containing("Listen on port")
                .and_instruction_containing("TLS")
                .and_instruction_containing("echo")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "TLS",
                        "instruction": "Echo server - respond with exactly what is received"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2: Server receives encrypted data (tls_data_received event)
                .on_event("tls_data_received")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "send_tls_data",
                        "data": "HELLO_TLS" // UTF-8 string (echoed back)
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let server = start_netget_server(server_config).await?;

        // Wait for TLS server to be listening
        server
            .wait_for_pattern(
                "TLS server (action-based) listening on",
                Duration::from_secs(5),
            )
            .await?;

        // Now start a TLS client that connects to this server with mocks
        // IMPORTANT: accept_invalid_certs: true because server uses self-signed cert
        let client_config = NetGetConfig::new(format!(
            "Connect to 127.0.0.1:{} via TLS (accept invalid certificates). Send 'HELLO_TLS' and wait for response.",
            server.port
        ))
        .with_mock(|mock| {
            mock
                // Mock 1: Client startup (user command)
                .on_instruction_containing("Connect to")
                .and_instruction_containing("TLS")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_client",
                        "remote_addr": format!("127.0.0.1:{}", server.port),
                        "protocol": "TLS",
                        "instruction": "Send HELLO_TLS and wait for echo",
                        "startup_params": {
                            "accept_invalid_certs": true
                        }
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2: Client connected after TLS handshake (tls_client_connected event)
                .on_event("tls_client_connected")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "send_tls_data",
                        "data": "HELLO_TLS" // UTF-8 string
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let client = start_netget_client(client_config).await?;

        // Wait for TLS handshake and data exchange
        client
            .wait_for_patterns(
                &[
                    "TLS handshake complete",       // TLS handshake succeeded
                    patterns::TLS_CLIENT_CONNECTED, // Client connected
                    patterns::TLS_CLIENT_SENT,      // Client sent HELLO_TLS
                ],
                Duration::from_secs(10), // Longer timeout for TLS handshake
            )
            .await?;

        // Wait for server to receive and process the encrypted data
        server
            .wait_for_pattern("TLS received", Duration::from_secs(5))
            .await?;

        println!("✅ TLS client connected to server with TLS handshake and sent data successfully");

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

    /// Test TLS client with certificate validation using custom CA
    /// This test uses a local TLS server with a CA-signed certificate to verify proper validation
    /// LLM calls: 4 (server startup, client startup, server data received, client connected)
    #[tokio::test]
    async fn test_tls_client_certificate_validation() -> E2EResult<()> {
        // Generate CA and server certificates
        let (ca_pem, server_cert_path, server_key_path) = generate_ca_signed_certs()?;

        // Start a TLS server with CA-signed certificate
        let server_config = NetGetConfig::new(
            "Listen on port {AVAILABLE_PORT} via TLS. Accept connections and echo received data back.",
        )
        .with_mock(|mock| {
            mock
                // Mock 1: Server startup (user command)
                .on_instruction_containing("Listen on port")
                .and_instruction_containing("TLS")
                .and_instruction_containing("echo")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "TLS",
                        "instruction": "Echo server - respond with exactly what is received",
                        "startup_params": {
                            "cert_path": server_cert_path,
                            "key_path": server_key_path
                        }
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2: Server receives encrypted data (tls_data_received event)
                .on_event("tls_data_received")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "send_tls_data",
                        "data": "HELLO_VALIDATED" // UTF-8 string (echoed back)
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let server = start_netget_server(server_config).await?;

        // Wait for TLS server to be listening
        server
            .wait_for_pattern(
                "TLS server (action-based) listening on",
                Duration::from_secs(5),
            )
            .await?;

        // Connect with TLS client using custom CA certificate (proper validation)
        let client_config = NetGetConfig::new(format!(
            "Connect to 127.0.0.1:{} via TLS with certificate validation. Send 'HELLO_VALIDATED' and wait for response.",
            server.port
        ))
        .with_mock(|mock| {
            mock
                // Mock 1: Client startup (user command)
                .on_instruction_containing("Connect to")
                .and_instruction_containing("TLS")
                .and_instruction_containing("validation")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_client",
                        "remote_addr": format!("127.0.0.1:{}", server.port),
                        "protocol": "TLS",
                        "instruction": "Send HELLO_VALIDATED and wait for echo",
                        "startup_params": {
                            "accept_invalid_certs": false,  // Full validation required
                            "custom_ca_cert_pem": ca_pem,   // Trust our custom CA
                            "server_name": "localhost"       // SNI must match cert CN
                        }
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2: Client connected after TLS handshake (tls_client_connected event)
                .on_event("tls_client_connected")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "send_tls_data",
                        "data": "HELLO_VALIDATED" // UTF-8 string
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let client = start_netget_client(client_config).await?;

        // Wait for TLS handshake with validated certificate
        client
            .wait_for_patterns(
                &[
                    "TLS handshake complete",       // TLS handshake succeeded
                    patterns::TLS_CLIENT_CONNECTED, // Client connected
                    patterns::TLS_CLIENT_SENT,      // Client sent HELLO_VALIDATED
                ],
                Duration::from_secs(10),
            )
            .await?;

        // Wait for server to receive and process the encrypted data
        server
            .wait_for_pattern("TLS received", Duration::from_secs(5))
            .await?;

        println!("✅ TLS client successfully validated CA-signed certificate");

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

        // Clean up temporary files
        let _ = std::fs::remove_file(&server_cert_path);
        let _ = std::fs::remove_file(&server_key_path);

        Ok(())
    }

    /// Test TLS client rejects invalid certificates when validation is enabled
    /// LLM calls: 1 (client startup - connection should fail before connected event)
    #[tokio::test]
    async fn test_tls_client_rejects_self_signed_cert() -> E2EResult<()> {
        // Start a TLS server with self-signed certificate
        let server_config =
            NetGetConfig::new("Listen on port {AVAILABLE_PORT} via TLS. Log connections.")
                .with_mock(|mock| {
                    mock.on_instruction_containing("TLS")
                        .respond_with_actions(serde_json::json!([
                            {
                                "type": "open_server",
                                "port": 0,
                                "base_stack": "TLS",
                                "instruction": "Log connections"
                            }
                        ]))
                        .expect_calls(1)
                        .and()
                });

        let server = start_netget_server(server_config).await?;

        // Wait for server listening
        server
            .wait_for_pattern(
                "TLS server (action-based) listening on",
                Duration::from_secs(5),
            )
            .await?;

        // Try to connect with certificate validation enabled (should fail)
        let client_config = NetGetConfig::new(format!(
            "Connect to 127.0.0.1:{} via TLS with certificate validation",
            server.port
        ))
        .with_mock(|mock| {
            mock.on_instruction_containing("TLS")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_client",
                        "remote_addr": format!("127.0.0.1:{}", server.port),
                        "protocol": "TLS",
                        "instruction": "Try to connect",
                        "startup_params": {
                            "accept_invalid_certs": false  // Require valid cert
                        }
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let client = start_netget_client(client_config).await?;

        // Wait for handshake failure (certificate validation error)
        // We expect the connection to fail, not succeed
        let result = client
            .wait_for_pattern("TLS handshake failed", Duration::from_secs(10))
            .await;

        // The handshake should fail
        assert!(
            result.is_ok(),
            "Expected TLS handshake to fail due to self-signed certificate"
        );

        println!("✅ TLS client correctly rejected self-signed certificate");

        // Verify mock expectations
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last response routinely lands
        // after the sleep expires, and the test reports it as never having happened.
        client.wait_for_mocks(30).await;
        client.verify_mocks().await?;

        // Cleanup
        server.stop().await?;
        client.stop().await?;

        Ok(())
    }
}

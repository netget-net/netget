//! End-to-end TLS tests for NetGet
//!
//! This test spawns a single NetGet TLS server with a Python script
//! and validates encrypted communication with custom application protocol.


use super::super::super::helpers::{self, E2EResult, NetGetConfig};
use rustls::{ClientConfig, RootCertStore};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

/// Certificate verifier that accepts all certificates (for testing only)
#[derive(Debug)]
struct NoCertificateVerification;

impl rustls::client::danger::ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

/// Helper to connect to TLS server and send/receive data
async fn tls_exchange(port: u16, send_data: &str) -> E2EResult<String> {
    // Initialize rustls crypto provider (required for rustls 0.23+)
    use rustls::crypto::CryptoProvider;
    let _ = CryptoProvider::install_default(rustls::crypto::ring::default_provider());

    let address: SocketAddr = format!("127.0.0.1:{}", port).parse()?;

    // Create a TLS client config that accepts self-signed certificates (for testing)
    let root_store = RootCertStore::empty();
    let mut config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    // Disable certificate verification for self-signed certs in tests
    config
        .dangerous()
        .set_certificate_verifier(Arc::new(NoCertificateVerification));

    let tls_config = Arc::new(config);
    let connector = TlsConnector::from(tls_config);

    // Connect via TLS
    let tcp_stream = TcpStream::connect(address).await?;
    let domain_name = rustls::pki_types::ServerName::try_from("localhost")
        .map_err(|e| anyhow::anyhow!("Invalid server name: {}", e))?;
    let mut tls_stream = connector.connect(domain_name, tcp_stream).await?;

    // Send data
    tls_stream.write_all(send_data.as_bytes()).await?;
    tls_stream.flush().await?;

    // Read the response. The server may write several independent TLS records
    // (e.g. the connection banner, then the reply to our data), each produced by
    // a separate LLM round-trip, so a single read() would only return the first
    // one. Accumulate until the stream goes idle or closes.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let mut buffer = vec![0u8; 4096];
    let mut response = String::new();

    loop {
        let idle = Duration::from_millis(if response.is_empty() { 5_000 } else { 1_000 });
        let wait = idle.min(deadline.saturating_duration_since(tokio::time::Instant::now()));
        if wait.is_zero() {
            break;
        }

        match tokio::time::timeout(wait, tls_stream.read(&mut buffer)).await {
            // Idle window elapsed: assume the server has said everything it will say.
            Err(_) => break,
            // Clean EOF.
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => response.push_str(&String::from_utf8_lossy(&buffer[..n])),
            // First read must succeed; later I/O errors just end the exchange.
            Ok(Err(e)) if response.is_empty() => return Err(e.into()),
            Ok(Err(_)) => break,
        }
    }

    Ok(response)
}

#[tokio::test]
async fn test_tls_echo_server() -> E2EResult<()> {
    println!("\n=== E2E Test: TLS Echo Server with Script ===");

    // Create a prompt for a simple echo server over TLS
    let prompt = r#"listen on port {AVAILABLE_PORT} via tls. When client connects, send "Welcome to secure echo server\n". Echo back any received data."#;

    // Start server with mocks
    let config = NetGetConfig::new(prompt)
        .with_log_level("info")
        .with_mock(|mock| {
            mock
                // Mock 1: Server startup
                .on_instruction_containing("tls")
                .and_instruction_containing("Welcome to secure echo server")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "TCP",
                        "protocol": "TLS",
                        "instruction": "Send welcome message on connect, echo received data",
                        "send_first": true
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2-4: Send welcome message on connection (3 connections)
                .on_event("tls_connection_opened")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "send_tls_data",
                        "data": "Welcome to secure echo server\n"
                    }
                ]))
                .expect_calls(3)
                .and()
                // Mock 5-6: Echo received data (2 connections send data).
                // Rules are matched first-to-last with no "already satisfied"
                // bookkeeping, so this one must filter on its own payload —
                // an unfiltered tls_data_received rule would also swallow the
                // "Testing" event below.
                .on_event("tls_data_received")
                .and_event_data_contains("data", "Hello, TLS!")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "send_tls_data",
                        "data": "Hello, TLS!\n"
                    }
                ]))
                .expect_calls(1)
                .and()
                .on_event("tls_data_received")
                .and_event_data_contains("data", "Testing")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "send_tls_data",
                        "data": "Testing 123\n"
                    }
                ]))
                .expect_calls(1)
                .and()
        });

    let server = helpers::start_netget_server(config).await?;

    println!("TLS server started on port {}", server.port);

    // Wait for server to fully initialize
    crate::helpers::wait_for_server_listening(&server, Duration::from_secs(30)).await?;

    // Test 1: Connect and check welcome message
    println!("\n[Test 1] Connect and check welcome message...");
    let response1 = tls_exchange(server.port, "").await?;
    assert!(
        response1.contains("Welcome"),
        "Expected welcome message, got: {}",
        response1
    );
    println!("✓ Got welcome message: {:?}", response1.trim());

    // Test 2: Send data and check echo
    println!("\n[Test 2] Send data and check echo...");
    let test_data = "Hello, TLS!\n";
    let response2 = tls_exchange(server.port, test_data).await?;
    assert!(
        response2.contains("Welcome"),
        "Expected welcome message in response"
    );
    assert!(
        response2.contains("Hello, TLS!"),
        "Expected echo of sent data, got: {}",
        response2
    );
    println!("✓ Got echo response");

    // Test 3: Different data
    println!("\n[Test 3] Send different data...");
    let test_data3 = "Testing 123\n";
    let response3 = tls_exchange(server.port, test_data3).await?;
    assert!(
        response3.contains("Welcome"),
        "Expected welcome message in response"
    );
    assert!(
        response3.contains("Testing 123"),
        "Expected echo of sent data, got: {}",
        response3
    );
    println!("✓ Got echo response");

    println!("\n=== All TLS tests passed! ===");

    // Verify mock expectations were met
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;

    Ok(())
}

#[tokio::test]
async fn test_tls_http_like_server() -> E2EResult<()> {
    println!("\n=== E2E Test: TLS HTTP-like Server with Script ===");

    // Create a prompt for a simple HTTP-like server over TLS
    let prompt = r#"listen on port {AVAILABLE_PORT} via tls. Implement a simple HTTP server:
- For GET /: return "HTTP/1.1 200 OK\r\n\r\nWelcome"
- For GET /api: return "HTTP/1.1 200 OK\r\n\r\n{\"status\":\"ok\"}"
- For anything else: return "HTTP/1.1 404 Not Found\r\n\r\n""#;

    // Start server with mocks
    let config = NetGetConfig::new(prompt)
        .with_log_level("info")
        .with_mock(|mock| {
            mock
                // Mock 1: Server startup
                .on_instruction_containing("tls")
                .and_instruction_containing("HTTP server")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "TCP",
                        "protocol": "TLS",
                        "instruction": "HTTP-like server with routing"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2: GET / request. Matched on "GET / HTTP" rather than
                // "GET /" because rules are tried in order and a bare "GET /"
                // substring also matches "GET /api" and "GET /unknown".
                .on_event("tls_data_received")
                .and_event_data_contains("data", "GET / HTTP")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "send_tls_data",
                        "data": "HTTP/1.1 200 OK\r\n\r\nWelcome"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 3: GET /api request
                .on_event("tls_data_received")
                .and_event_data_contains("data", "GET /api")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "send_tls_data",
                        "data": "HTTP/1.1 200 OK\r\n\r\n{\"status\":\"ok\"}"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 4: GET /unknown request
                .on_event("tls_data_received")
                .and_event_data_contains("data", "GET /unknown")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "send_tls_data",
                        "data": "HTTP/1.1 404 Not Found\r\n\r\n"
                    }
                ]))
                .expect_calls(1)
                .and()
        });

    let server = helpers::start_netget_server(config).await?;

    println!("TLS HTTP-like server started on port {}", server.port);

    // Wait for server to fully initialize
    crate::helpers::wait_for_server_listening(&server, Duration::from_secs(30)).await?;

    // Test 1: GET /
    println!("\n[Test 1] Request GET /...");
    let response1 = tls_exchange(server.port, "GET / HTTP/1.1\r\n\r\n").await?;
    assert!(
        response1.contains("200 OK"),
        "Expected 200 OK, got: {}",
        response1
    );
    assert!(
        response1.contains("Welcome"),
        "Expected 'Welcome', got: {}",
        response1
    );
    println!("✓ Got 200 OK response");

    // Test 2: GET /api
    println!("\n[Test 2] Request GET /api...");
    let response2 = tls_exchange(server.port, "GET /api HTTP/1.1\r\n\r\n").await?;
    assert!(
        response2.contains("200 OK"),
        "Expected 200 OK, got: {}",
        response2
    );
    assert!(
        response2.contains("status"),
        "Expected JSON response, got: {}",
        response2
    );
    println!("✓ Got JSON response");

    // Test 3: GET /unknown
    println!("\n[Test 3] Request unknown path...");
    let response3 = tls_exchange(server.port, "GET /unknown HTTP/1.1\r\n\r\n").await?;
    assert!(
        response3.contains("404"),
        "Expected 404, got: {}",
        response3
    );
    println!("✓ Got 404 response");

    println!("\n=== All TLS HTTP-like tests passed! ===");

    // Verify mock expectations were met
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;

    Ok(())
}

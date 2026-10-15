//! End-to-end tests for QUIC protocol implementation
//!
//! These tests spawn a real NetGet instance with QUIC server
//! and use quinn client to test QUIC functionality.


use super::super::helpers::{self, E2EResult, NetGetConfig};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;

/// A prompt saying "quic" must reach this protocol.
///
/// The protocol used to be called `http3` while serving raw QUIC streams. After the
/// rename the lookup path is the thing most likely to silently break, so assert it
/// directly instead of only through `base_stack` in the mocks below. `http3` must
/// *not* resolve here: HTTP/3 has its own server, and resolving it to a raw QUIC
/// socket would misclassify the application protocol.
#[test]
fn quic_keyword_resolves_to_this_protocol() {
    use netget::protocol::server_registry::registry;

    assert_eq!(
        registry().parse_from_str("quic"),
        Some("QUIC".to_string()),
        "\"quic\" must resolve to the QUIC protocol"
    );
    assert_eq!(
        registry().parse_from_str("listen on port 4433 via quic"),
        Some("QUIC".to_string()),
        "a natural-language prompt naming quic must resolve to the QUIC protocol"
    );
    assert_ne!(
        registry().parse_from_str("http3"),
        Some("QUIC".to_string()),
        "\"http3\" must not resolve to the raw QUIC server - it is not an HTTP/3 server"
    );
}

/// Test QUIC echo server - send data and receive it back
#[tokio::test]
async fn test_quic_echo() -> E2EResult<()> {
    let config = NetGetConfig::new("Start a QUIC server on port 0")
        .with_log_level("debug")
        .with_mock(|mock| {
            mock
                // IMPORTANT: Event-specific mocks MUST come first
                // The mock system uses the FIRST matching rule
                // Mock 1: Connection opened - just acknowledge
                .on_event("quic_connection_opened")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "show_message",
                        "message": "Connection opened"
                    }
                ]))
                .and()
                // Mock 2: Stream opened - just acknowledge
                .on_event("quic_stream_opened")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "show_message",
                        "message": "Stream opened"
                    }
                ]))
                .and()
                // Mock 3: LLM receives data and echoes it back
                .on_event("quic_data_received")
                .and_event_data_contains("data", "Hello")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "send_quic_data",
                        "data": "Hello, QUIC!"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 4: Server startup (catch-all for user input, MUST come LAST)
                .on_custom(|ctx| !ctx.instruction.contains("Event ID:"))
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "QUIC",
                        "instruction": "Echo back all data received"
                    }
                ]))
                .expect_calls(1)
                .and()
        });

    let server = helpers::start_netget_server(config).await?;
    let port = server.port;

    println!("✓ QUIC server started on port {}", port);

    // Install rustls crypto provider for client
    let _ = rustls::crypto::ring::default_provider().install_default();

    // Configure QUIC client to skip certificate validation (self-signed cert)
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let mut client_crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();

    // CRITICAL: Accept invalid certificates (self-signed)
    client_crypto
        .dangerous()
        .set_certificate_verifier(Arc::new(SkipServerVerification));

    client_crypto.alpn_protocols = vec![b"netget-quic".to_vec()];

    let client_config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)
            .expect("Failed to create QUIC client config"),
    ));

    let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap())
        .expect("Failed to create client endpoint");
    endpoint.set_default_client_config(client_config);

    // Connect to QUIC server
    let connecting = endpoint
        .connect(format!("127.0.0.1:{}", port).parse().unwrap(), "localhost")
        .expect("Failed to start connection");

    let connection = timeout(Duration::from_secs(10), connecting)
        .await
        .expect("Connection timeout")
        .expect("Failed to complete connection");

    println!("✓ Connected to QUIC server");

    // Open bidirectional stream
    let (mut send, mut recv) = timeout(Duration::from_secs(10), connection.open_bi())
        .await
        .expect("Stream open timeout")
        .expect("Failed to open stream");

    // Send test data
    let test_data = b"Hello, QUIC!";
    send.write_all(test_data)
        .await
        .expect("Failed to send data");
    send.finish().expect("Failed to finish stream");

    println!("✓ Sent data to QUIC server");

    // Read response from LLM
    let response = timeout(Duration::from_secs(5), recv.read_to_end(1024))
        .await
        .expect("Read timeout")
        .expect("Failed to read response");

    println!("✓ Received response: {} bytes", response.len());

    // Verify echo
    assert_eq!(response, test_data.to_vec(), "Expected echo of sent data");

    // Cleanup
    connection.close(0u32.into(), b"done");
    endpoint.wait_idle().await;

    // Verify mock expectations were met
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;

    server.stop().await?;

    Ok(())
}

/// Test QUIC custom response - send command and receive specific response
#[tokio::test]
async fn test_quic_custom_response() -> E2EResult<()> {
    let config = NetGetConfig::new("Start a QUIC server on port 0")
        .with_log_level("debug")
        .with_mock(|mock| {
            mock
                // IMPORTANT: Event-specific mocks MUST come first
                // The mock system uses the FIRST matching rule
                // Mock 1: Connection opened - just acknowledge
                .on_event("quic_connection_opened")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "show_message",
                        "message": "Connection opened"
                    }
                ]))
                .and()
                // Mock 2: Stream opened - just acknowledge
                .on_event("quic_stream_opened")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "show_message",
                        "message": "Stream opened"
                    }
                ]))
                .and()
                // Mock 3: LLM receives PING and responds with PONG
                .on_event("quic_data_received")
                .and_event_data_contains("data", "PING")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "send_quic_data",
                        "data": "PONG"
                    },
                    {
                        "type": "close_this_stream"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 4: Server startup (catch-all for user input, MUST come LAST)
                .on_custom(|ctx| !ctx.instruction.contains("Event ID:"))
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "QUIC",
                        "instruction": "Respond to PING with PONG"
                    }
                ]))
                .expect_calls(1)
                .and()
        });

    let server = helpers::start_netget_server(config).await?;
    let port = server.port;

    println!("✓ QUIC server started on port {}", port);

    // Install rustls crypto provider for client
    let _ = rustls::crypto::ring::default_provider().install_default();

    // Configure QUIC client (same as above)
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let mut client_crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();

    client_crypto
        .dangerous()
        .set_certificate_verifier(Arc::new(SkipServerVerification));

    client_crypto.alpn_protocols = vec![b"netget-quic".to_vec()];

    let client_config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)
            .expect("Failed to create QUIC client config"),
    ));

    let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap())
        .expect("Failed to create client endpoint");
    endpoint.set_default_client_config(client_config);

    // Connect to QUIC server
    let connecting = endpoint
        .connect(format!("127.0.0.1:{}", port).parse().unwrap(), "localhost")
        .expect("Failed to start connection");

    let connection = timeout(Duration::from_secs(10), connecting)
        .await
        .expect("Connection timeout")
        .expect("Failed to complete connection");

    println!("✓ Connected to QUIC server");

    // Open bidirectional stream
    let (mut send, mut recv) = timeout(Duration::from_secs(10), connection.open_bi())
        .await
        .expect("Stream open timeout")
        .expect("Failed to open stream");

    // Send PING
    send.write_all(b"PING").await.expect("Failed to send data");
    send.finish().expect("Failed to finish stream");

    println!("✓ Sent PING to QUIC server");

    // Read PONG response from LLM
    let response = timeout(Duration::from_secs(5), recv.read_to_end(1024))
        .await
        .expect("Read timeout")
        .expect("Failed to read response");

    let response_str = String::from_utf8_lossy(&response);
    println!("✓ Received response: {}", response_str);

    assert_eq!(response_str, "PONG", "Expected PONG response");

    // Cleanup
    connection.close(0u32.into(), b"done");
    endpoint.wait_idle().await;

    // Verify mock expectations were met
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;

    server.stop().await?;

    Ok(())
}

/// Test QUIC multiple streams - verify stream multiplexing
#[tokio::test]
async fn test_quic_multiple_streams() -> E2EResult<()> {
    let config = NetGetConfig::new("Start a QUIC server on port 0")
        .with_log_level("debug")
        .with_mock(|mock| {
            mock
                // IMPORTANT: Event-specific mocks MUST come first
                // The mock system uses the FIRST matching rule
                // Mock 1: Connection opened - just acknowledge
                .on_event("quic_connection_opened")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "show_message",
                        "message": "Connection opened"
                    }
                ]))
                .and()
                // Mock 2: Stream opened - just acknowledge
                .on_event("quic_stream_opened")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "show_message",
                        "message": "Stream opened"
                    }
                ]))
                // A valid model notification may exceed the old five-second peer deadline.
                .after_delay(Duration::from_secs(6))
                .expect_calls(3)
                .and()
                // Mock 3: LLM receives data and echoes it back (matches any stream)
                .on_event("quic_data_received")
                .and_event_data_contains("data", "Stream")
                .respond_with_actions_from_event(|event_data| {
                    // Extract the data from the event and echo it back
                    let data = event_data["data"].as_str().unwrap_or("Stream");
                    serde_json::json!([
                        {
                            "type": "send_quic_data",
                            "data": data
                        }
                    ])
                })
                .expect_calls(3) // Expecting 3 streams
                .and()
                // Mock 4: Server startup (catch-all for user input, MUST come LAST)
                .on_custom(|ctx| !ctx.instruction.contains("Event ID:"))
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "QUIC",
                        "instruction": "Echo back all data on multiple streams"
                    }
                ]))
                .expect_calls(1)
                .and()
        });

    let server = helpers::start_netget_server(config).await?;
    let port = server.port;

    println!("✓ QUIC server started on port {}", port);

    // Install rustls crypto provider for client
    let _ = rustls::crypto::ring::default_provider().install_default();

    // Configure QUIC client
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let mut client_crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();

    client_crypto
        .dangerous()
        .set_certificate_verifier(Arc::new(SkipServerVerification));

    client_crypto.alpn_protocols = vec![b"netget-quic".to_vec()];

    let client_config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)
            .expect("Failed to create QUIC client config"),
    ));

    let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap())
        .expect("Failed to create client endpoint");
    endpoint.set_default_client_config(client_config);

    // Connect to QUIC server
    let connecting = endpoint
        .connect(format!("127.0.0.1:{}", port).parse().unwrap(), "localhost")
        .expect("Failed to start connection");

    let connection = timeout(Duration::from_secs(10), connecting)
        .await
        .expect("Connection timeout")
        .expect("Failed to complete connection");

    println!("✓ Connected to QUIC server");

    // Open 3 streams concurrently
    // The receiver owns a 30-second whole stream exchange. Give it that bound plus
    // a small scheduling margin, and own every client task even on assertion failure.
    let exchange_deadline = netget::utils::quic::EXCHANGE_TIMEOUT + Duration::from_secs(5);
    let mut streams = tokio::task::JoinSet::new();
    for i in 0..3 {
        let conn = connection.clone();
        streams.spawn(async move {
            let (mut send, mut recv) = conn.open_bi().await.expect("Failed to open stream");

            let test_data = format!("Stream {}", i);
            send.write_all(test_data.as_bytes())
                .await
                .expect("Failed to send");
            send.finish().expect("Failed to finish");

            // Read response from LLM
            let response = timeout(exchange_deadline, recv.read_to_end(1024))
                .await
                .expect("Read timeout")
                .expect("Failed to read");
            (test_data, String::from_utf8_lossy(&response).to_string())
        });
    }

    // All three exchanges run concurrently; one deadline bounds the whole group.
    timeout(exchange_deadline, async {
        while let Some(result) = streams.join_next().await {
            let (sent, received) = result.expect("Stream task failed");
            println!("✓ Stream test - sent: {}, received: {}", sent, received);
            assert_eq!(sent, received, "Expected echo on stream");
        }
    })
    .await
    .expect("Stream group timeout");

    // Cleanup
    connection.close(0u32.into(), b"done");
    endpoint.wait_idle().await;

    // Verify mock expectations were met
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;

    server.stop().await?;

    Ok(())
}

/// The payload codec must be a bijection: whatever `encode_quic_payload` hands the model,
/// feeding it straight back into `decode_quic_payload` has to reproduce the original bytes.
///
/// This is the property that was broken. Inbound hex-encoded any non-printable payload while
/// `send_quic_data` wrote its `data` string verbatim with no `encoding` field at all, so the
/// two directions used different alphabets and a QUIC echo server could not echo binary.
#[test]
fn quic_payload_encoding_round_trips() {
    use netget::server::quic::actions::{decode_quic_payload, encode_quic_payload};

    for original in [
        b"Hello, QUIC!".to_vec(),
        b"line one\nline two\r\n".to_vec(),
        // Non-printable and not valid UTF-8 in three different ways.
        vec![0x00, 0xff, 0xfe, 0x01, 0x80, 0x7f, 0xc3, 0x28],
        (0u8..=255).collect::<Vec<u8>>(),
        Vec::new(),
    ] {
        let (data, encoding) = encode_quic_payload(&original);
        let decoded = decode_quic_payload(&data, Some(encoding))
            .unwrap_or_else(|e| panic!("re-decoding {encoding} payload {data:?} failed: {e}"));
        assert_eq!(
            decoded, original,
            "round trip through encoding={encoding} lost bytes"
        );
    }

    // A string that is simultaneously valid text and valid hex must follow the declared
    // encoding, never a guess: this is why the field exists.
    assert_eq!(
        decode_quic_payload("48656c6c6f", None).unwrap(),
        b"48656c6c6f".to_vec(),
        "no 'encoding' must send the characters literally"
    );
    assert_eq!(
        decode_quic_payload("48656c6c6f", Some("hex")).unwrap(),
        b"Hello".to_vec(),
        "encoding=hex must decode the same string to 5 bytes"
    );
    assert_eq!(
        decode_quic_payload("SGVsbG8=", Some("base64")).unwrap(),
        b"Hello".to_vec()
    );

    // Bad input is an error, not a panic and not a silent literal.
    assert!(decode_quic_payload("xyz", Some("hex")).is_err());
    assert!(
        decode_quic_payload("abc", Some("hex")).is_err(),
        "odd digits"
    );
    assert!(decode_quic_payload("hi", Some("rot13")).is_err());
}

/// Test QUIC binary echo: bytes that are neither printable nor valid UTF-8 must survive a
/// full round trip through the LLM event and back out onto the stream.
///
/// This is the test that catches the whole encoding-asymmetry bug class. The payload is
/// chosen so that every shortcut fails: `from_utf8_lossy` would replace 0xff/0xfe/0x80 with
/// U+FFFD, writing `data.as_bytes()` verbatim would put the ASCII hex digits on the wire
/// instead of the bytes, and any printable-ASCII fast path is bypassed by the 0x00.
#[tokio::test]
async fn test_quic_binary_echo_round_trip() -> E2EResult<()> {
    // 0xff/0xfe can never appear in UTF-8; 0xc3 0x28 is an invalid two-byte sequence;
    // 0x00/0x80/0x7f are non-printable. Its hex form is "00fffe01807fc328".
    const BINARY: &[u8] = &[0x00, 0xff, 0xfe, 0x01, 0x80, 0x7f, 0xc3, 0x28];
    const BINARY_HEX: &str = "00fffe01807fc328";

    assert!(
        std::str::from_utf8(&BINARY.to_vec()).is_err(),
        "the test payload must not be valid UTF-8, or it proves nothing"
    );

    let config = NetGetConfig::new("Start a QUIC server on port 0")
        .with_log_level("debug")
        .with_mock(|mock| {
            mock.on_event("quic_connection_opened")
                .respond_with_actions(serde_json::json!([
                    {"type": "show_message", "message": "Connection opened"}
                ]))
                .and()
                .on_event("quic_stream_opened")
                .respond_with_actions(serde_json::json!([
                    {"type": "show_message", "message": "Stream opened"}
                ]))
                .and()
                // Matching on the hex string asserts the inbound half: a non-printable
                // payload must reach the model hex-encoded, not lossily converted.
                .on_event("quic_data_received")
                .and_event_data_contains("data", BINARY_HEX)
                .respond_with_actions_from_event(|event_data| {
                    // Echo exactly the way the event documentation tells the model to:
                    // pass 'data' and 'encoding' straight back through.
                    let data = event_data["data"].as_str().unwrap_or_default();
                    let encoding = event_data["encoding"].as_str().unwrap_or("utf8");
                    assert_eq!(
                        encoding, "hex",
                        "a non-printable payload must be delivered with encoding=hex, got {encoding:?}"
                    );
                    serde_json::json!([
                        {"type": "send_quic_data", "data": data, "encoding": encoding}
                    ])
                })
                .expect_calls(1)
                .and()
                .on_custom(|ctx| !ctx.instruction.contains("Event ID:"))
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "QUIC",
                        "instruction": "Echo back all data received, byte for byte"
                    }
                ]))
                .expect_calls(1)
                .and()
        });

    let server = helpers::start_netget_server(config).await?;
    let port = server.port;

    let _ = rustls::crypto::ring::default_provider().install_default();

    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let mut client_crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_crypto
        .dangerous()
        .set_certificate_verifier(Arc::new(SkipServerVerification));
    client_crypto.alpn_protocols = vec![b"netget-quic".to_vec()];

    let client_config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)
            .expect("Failed to create QUIC client config"),
    ));

    let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap())
        .expect("Failed to create client endpoint");
    endpoint.set_default_client_config(client_config);

    let connection = timeout(
        Duration::from_secs(10),
        endpoint
            .connect(format!("127.0.0.1:{}", port).parse().unwrap(), "localhost")
            .expect("Failed to start connection"),
    )
    .await
    .expect("Connection timeout")
    .expect("Failed to complete connection");

    let (mut send, mut recv) = timeout(Duration::from_secs(10), connection.open_bi())
        .await
        .expect("Stream open timeout")
        .expect("Failed to open stream");

    send.write_all(BINARY).await.expect("Failed to send data");
    send.finish().expect("Failed to finish stream");

    let response = timeout(Duration::from_secs(10), recv.read_to_end(1024))
        .await
        .expect("Read timeout")
        .expect("Failed to read response");

    assert_eq!(
        response,
        BINARY.to_vec(),
        "QUIC must echo binary byte-for-byte; got {} ({:?})",
        hex::encode(&response),
        String::from_utf8_lossy(&response)
    );

    connection.close(0u32.into(), b"done");
    endpoint.wait_idle().await;

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;

    Ok(())
}

/// Certificate verifier that skips all verification (for self-signed certs)
#[derive(Debug)]
struct SkipServerVerification;

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
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

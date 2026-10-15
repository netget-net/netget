//! What a TLS peer gets when the LLM backend fails: a close_notify alert, then EOF.
//!
//! TLS carries no application-level error here - the application protocol is whatever the
//! handler invents, so there is nothing to phrase a reply in. What TLS does have is the alert
//! protocol, and `shutdown()` emits a real close_notify alert record rather than only a FIN.
//!
//! The distinction is exactly what this test asserts. A `read()` that returns `Ok(0)` means the
//! peer received close_notify and rustls reported a clean end of stream; an abrupt TCP close
//! without the alert surfaces as `UnexpectedEof` instead. Asserting `Ok(0)` therefore proves an
//! alert was sent, not merely that the socket went away.
//!
//! (A fatal `internal_error` alert would be more precise, but rustls 0.23 keeps
//! `CommonState::send_fatal_alert` `pub(crate)`; close_notify is the strongest in-spec signal
//! reachable through its public API.)


use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
use rustls::{ClientConfig, RootCertStore};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

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

#[tokio::test]
async fn test_tls_closes_with_alert_when_llm_fails() -> E2EResult<()> {
    let prompt = "listen on port {AVAILABLE_PORT} via tls. Echo whatever arrives";

    let server_config = NetGetConfig::new_no_scripts(prompt).with_mock(|mock| {
        mock.on_instruction_containing("via tls")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "TLS",
                    "instruction": "Echo whatever arrives"
                }
            ]))
            .expect_calls(1)
            .and()
        // No rule for `tls_data_received`: the mock answers 500.
    });

    let server = start_netget_server(server_config).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    use rustls::crypto::CryptoProvider;
    let _ = CryptoProvider::install_default(rustls::crypto::ring::default_provider());

    let mut config = ClientConfig::builder()
        .with_root_certificates(RootCertStore::empty())
        .with_no_client_auth();
    config
        .dangerous()
        .set_certificate_verifier(Arc::new(NoCertificateVerification));
    let connector = TlsConnector::from(Arc::new(config));

    let tcp = TcpStream::connect(format!("127.0.0.1:{}", server.port)).await?;
    let domain = rustls::pki_types::ServerName::try_from("localhost")
        .map_err(|e| format!("invalid server name: {e}"))?;
    let mut tls = connector.connect(domain, tcp).await?;

    tls.write_all(b"HELLO\r\n").await?;
    tls.flush().await?;

    let mut buf = vec![0u8; 4096];
    let read = tokio::time::timeout(Duration::from_secs(20), tls.read(&mut buf))
        .await
        .map_err(|_| {
            "The TLS connection stayed open and silent for 20s after an LLM failure - that is \
             the exact defect this test exists to catch"
        })?;

    match read {
        Ok(0) => { /* close_notify received: the expected outcome */ }
        Ok(n) => panic!(
            "expected the connection to be closed, but the server sent {n} bytes: {:?}",
            String::from_utf8_lossy(&buf[..n])
        ),
        Err(e) => panic!(
            "expected a clean close_notify (read -> Ok(0)), got I/O error {e:?}. An \
             UnexpectedEof here means the socket was dropped without a TLS alert."
        ),
    }

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

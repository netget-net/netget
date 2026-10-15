//! What a raw-QUIC peer gets when the LLM backend fails: `RESET_STREAM`, not silence.
//!
//! A raw QUIC stream has no error frame of its own — there is no status line, no reply code,
//! nothing netget could fill in. The protocol-level way to say "this stream is over and it did
//! not succeed" is `RESET_STREAM` with an application error code, which is what this server
//! now sends. It negotiates ALPN `netget-quic`, so the two application-local codes whose meaning matches are the
//! honest choice: `RAW_INTERNAL_ERROR` (0x0102) for a backend that erred, `RAW_EXCESSIVE_LOAD`
//! (0x0107) for one that is saturated.
//!
//! Before this, the data path logged a warning, put the stream back in `Idle` and wrote
//! nothing. The peer's `read_to_end` blocked until its own timeout with no indication anything
//! had gone wrong — the "reset to Idle and write nothing" shape CLAUDE.md lists under known
//! systemic issues.
//!
//! The second half of the assertion matters as much as the first: the reset carries a *code*
//! and nothing else. No error string reaches the wire, so the backend URL, the model name and
//! netget's own retry text cannot leak the way they did in the ~25 protocols that were taught
//! to answer on failure by interpolating the error into the reply.


use super::super::helpers::{self, E2EResult, NetGetConfig};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;

/// application-local `RAW_INTERNAL_ERROR`. A mock that returns HTTP 500 is not an overload, so this is
/// the code the classifier must land on.
const RAW_INTERNAL_ERROR: u64 = 0x0102;

#[tokio::test]
async fn test_quic_resets_the_stream_when_the_llm_fails() -> E2EResult<()> {
    // Only the startup instruction is mocked. Every event — including
    // `quic_data_received` — is unmatched, so the mock answers HTTP 500 and NetGet reports
    // an LLM failure for that turn.
    let config = NetGetConfig::new("Start a QUIC server on port 0")
        .with_log_level("debug")
        .with_mock(|mock| {
            mock.on_custom(|ctx| !ctx.instruction.contains("Event ID:"))
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

    send.write_all(b"anybody there?")
        .await
        .expect("Failed to send data");
    send.finish().expect("Failed to finish stream");

    // The whole point: this must resolve promptly rather than block to its own timeout.
    let outcome = timeout(Duration::from_secs(20), recv.read_to_end(4096))
        .await
        .map_err(|_| {
            "The QUIC server neither answered nor reset the stream within 20s — it went silent \
             on LLM failure, which is the exact defect this test exists to catch"
        })?;

    match outcome {
        Err(quinn::ReadToEndError::Read(quinn::ReadError::Reset(code))) => {
            assert_eq!(
                code.into_inner(),
                RAW_INTERNAL_ERROR,
                "a backend error must reset with RAW_INTERNAL_ERROR (0x0102); \
                 RAW_EXCESSIVE_LOAD (0x0107) is reserved for an overloaded backend so a client \
                 can tell a retryable failure from a permanent one"
            );
        }
        Err(other) => panic!(
            "expected RESET_STREAM with an application error code, got: {:?}",
            other
        ),
        Ok(bytes) => {
            // A clean EOF with no bytes would still be silence dressed up; anything else
            // would mean netget invented a reply it had no answer for.
            panic!(
                "expected the stream to be reset, but it ended cleanly with {} byte(s): {:?}",
                bytes.len(),
                String::from_utf8_lossy(&bytes)
            );
        }
    }

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

/// Accept the server's self-signed certificate. Same shape as `e2e_test.rs`; duplicated
/// rather than shared because the two files are independently gated.
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

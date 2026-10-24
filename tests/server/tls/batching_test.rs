//! Batching on the TLS server: what arrives while the model is answering.
//!
//! The decrypted stream has no message boundaries, so the server's queue keeps each read that
//! arrived during a call and `ReadQueue::next_or_idle` decides what the next call answers —
//! the whole queue with batching on, one read at a time with it off. The same shape as `tcp`'s
//! `tests/connection_history_test.rs::tcp_batching_joins_or_separates_what_arrived_during_a_call`.
//!
//! The first record is answered slowly; two more records are sent, 200 ms apart, during that
//! call. Off is the control and runs first in the same test: three calls, one per record. On:
//! two calls, the second carrying both records that arrived during the first.

use std::sync::Arc;
use std::time::Duration;

use crate::helpers::mock_builder::MockLlmBuilder;
use crate::helpers::mock_ollama::MockOllamaServer;
use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use netget::state::ServerId;
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_rustls::TlsConnector;

/// Accepts the server's self-signed certificate. This test is about batching, not PKI.
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

pub(super) async fn handshaked_peer(port: u16) -> tokio_rustls::client::TlsStream<TcpStream> {
    use rustls::crypto::CryptoProvider;
    let _ = CryptoProvider::install_default(rustls::crypto::ring::default_provider());

    let mut config = ClientConfig::builder()
        .with_root_certificates(RootCertStore::empty())
        .with_no_client_auth();
    config
        .dangerous()
        .set_certificate_verifier(Arc::new(NoCertificateVerification));

    let tcp = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    let name = rustls::pki_types::ServerName::try_from("localhost").expect("server name");
    TlsConnector::from(Arc::new(config))
        .connect(name, tcp)
        .await
        .expect("TLS handshake with the NetGet server")
}

pub(super) async fn wait_for_port(state: &AppState, id: ServerId) -> u16 {
    for _ in 0..300 {
        if let Some(s) = state.get_server(id).await {
            if let Some(addr) = s.local_addr {
                return addr.port();
            }
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("TLS server #{} never bound a port", id.as_u32());
}

/// `first`, then two separate records while the model answers it. Returns the `data` of every
/// `tls_data_received` the model was asked about.
async fn tls_payloads_for_three_writes(batching: bool) -> Vec<String> {
    let mock = MockOllamaServer::start(
        MockLlmBuilder::new()
            .on_event("tls_data_received")
            .and_event_data_contains("data", "first")
            .respond_with_actions(serde_json::json!([
                { "type": "send_tls_data", "data": "ok first\n", "encoding": "utf8" }
            ]))
            .after_delay(Duration::from_millis(1500))
            .expect_calls(1)
            .and()
            .on_event("tls_data_received")
            .respond_with_actions_from_event(|event| {
                let data = event["data"].as_str().unwrap_or_default().to_string();
                serde_json::json!([{ "type": "send_tls_data", "data": format!("ok {data}\n"), "encoding": "utf8" }])
            })
            .expect_at_least(1)
            .build(),
    )
    .await
    .expect("mock ollama");

    let state = AppState::new_with_options(false, mock.base_url());
    state
        .set_llm_client(netget::llm::OllamaClient::new(mock.base_url()))
        .await;
    let (tx, _rx) = mpsc::unbounded_channel();
    let id = ServerForm {
        protocol: "tls".to_string(),
        port: Some(0),
        instruction: Some("Acknowledge everything.".to_string()),
        batching: Some(batching),
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .expect("create tls server");
    let port = wait_for_port(&state, id).await;

    let mut peer = handshaked_peer(port).await;
    peer.write_all(b"first").await.expect("write");
    peer.flush().await.expect("flush");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while mock.call_count().await == 0 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "first never reached the model"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // Two records the server reads separately, both during the slow first call.
    peer.write_all(b"second").await.expect("write");
    peer.flush().await.expect("flush");
    tokio::time::sleep(Duration::from_millis(200)).await;
    peer.write_all(b"third").await.expect("write");
    peer.flush().await.expect("flush");

    // Read until the answer naming `third` arrives.
    let mut seen = Vec::new();
    let mut buf = [0u8; 1024];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    while !String::from_utf8_lossy(&seen).contains("third") {
        let n = tokio::time::timeout_at(deadline, peer.read(&mut buf))
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "no answer naming third; read so far: {:?}",
                    String::from_utf8_lossy(&seen)
                )
            })
            .expect("read");
        assert!(n > 0, "connection closed before the answer to third");
        seen.extend_from_slice(&buf[..n]);
    }

    let payloads = mock
        .recorded_calls()
        .await
        .into_iter()
        .filter(|c| c.context.event_type.as_deref() == Some("tls_data_received"))
        .map(|c| {
            c.context.event_data["data"]
                .as_str()
                .unwrap_or_default()
                .to_string()
        })
        .collect();
    let _ = state.remove_server(id).await;
    payloads
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tls_batching_joins_or_separates_what_arrived_during_a_call() {
    // === Control: batching off. Every record that arrived during the call is its own call. ===
    let separate = tls_payloads_for_three_writes(false).await;
    assert_eq!(
        separate,
        vec!["first", "second", "third"],
        "CONTROL FAILED: with batching off each read that arrived during the call must be \
         answered on its own, or the joined result below proves nothing"
    );
    // === The claim: with batching on they are the next call's payload, together. ===
    let batched = tls_payloads_for_three_writes(true).await;
    assert_eq!(
        batched,
        vec!["first", "secondthird"],
        "with batching on everything that arrived during the call is the next call's payload"
    );
}

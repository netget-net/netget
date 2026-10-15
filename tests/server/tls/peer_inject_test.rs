//! The dashboard's "message this peer" / "disconnect this peer" path on a TLS connection.
//!
//! TLS is the strongest case in the peer-handle family, because the write half the session
//! already shares (`Arc<Mutex<WriteHalf<TlsStream>>>`) is a rustls stream: an injected
//! `send_tls_data` is **encrypted by the same code that encrypts a modelled one**, and the
//! client decrypts it without knowing the difference. That is what this test asserts — not
//! that `send_to_peer` returned a hopeful outcome, but that plaintext came out of a real
//! rustls client.
//!
//! **Zero LLM calls.** The instruction is empty and the `*` rule is a static handler.
//! `ServerForm::create` substitutes a default instruction whenever `instruction` is `None`,
//! which alone makes a server dynamic, so it is set explicitly rather than defaulted.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features tls \
//!       --test server -- tls::peer_inject --test-threads=100


use std::sync::Arc;
use std::time::Duration;

use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use netget::state::client_handles::ClientSendOutcome;
use netget::state::ServerId;
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
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

async fn new_state() -> AppState {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".to_string());
    state
        .set_llm_client(netget::llm::OllamaClient::new(
            "http://127.0.0.1:1".to_string(),
        ))
        .await;
    state
}

async fn wait_for_port(state: &AppState, id: ServerId) -> u16 {
    for _ in 0..100 {
        if let Some(s) = state.get_server(id).await {
            if let Some(addr) = s.local_addr {
                return addr.port();
            }
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("TLS server #{} never bound a port", id.as_u32());
}

async fn wait_for_peer_handle(state: &AppState, id: ServerId) -> u32 {
    for _ in 0..200 {
        if let Some(s) = state.get_server(id).await {
            for conn in s.connections.values() {
                if state.has_peer_handle(id, conn.id.as_u32()).await {
                    return conn.id.as_u32();
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("TLS server #{} never registered a peer handle", id.as_u32());
}

#[tokio::test]
async fn injected_tls_data_is_encrypted_and_close_sends_eof() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    let server_id = ServerForm {
        protocol: "tls".to_string(),
        port: Some(0),
        instruction: Some(String::new()),
        // The connect event every connection raises is answered with nothing, as the
        // dashboard does; otherwise the `*` rule's answer would be the first bytes the peer
        // reads, ahead of the injected ones.
        event_handlers: Some(vec![
            serde_json::json!({
                "event_pattern": "tls_connection_opened",
                "handler": {"type": "static", "actions": []}
            }),
            serde_json::json!({
                "event_pattern": "*",
                "handler": {
                    "type": "static",
                    "actions": [ { "type": "send_tls_data", "data": "static answer\n" } ]
                }
            }),
        ]),
        ..Default::default()
    }
    .create(&state, tx.clone())
    .await
    .expect("create tls server");
    let port = wait_for_port(&state, server_id).await;

    let mut config = ClientConfig::builder()
        .with_root_certificates(RootCertStore::empty())
        .with_no_client_auth();
    config
        .dangerous()
        .set_certificate_verifier(Arc::new(NoCertificateVerification));
    let connector = TlsConnector::from(Arc::new(config));

    let tcp = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .expect("tcp connect");
    let domain = rustls::pki_types::ServerName::try_from("localhost").expect("server name");
    let mut tls = connector.connect(domain, tcp).await.expect("tls handshake");

    // The handshake is done and the peer has sent no application record. A `manual` rule
    // parks the first record for a human; this is the window in which the operator has to be
    // able to reach the connection.
    let conn = wait_for_peer_handle(&state, server_id).await;

    let outcome = state
        .send_to_peer(
            server_id,
            conn,
            serde_json::json!({"type": "send_tls_data", "data": "injected\n"}),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_peer");
    assert!(
        matches!(outcome, ClientSendOutcome::Sent { bytes_sent: 9 }),
        "expected Sent{{9}}, got {outcome:?}"
    );

    let mut buf = vec![0u8; 64];
    let n = tokio::time::timeout(Duration::from_secs(5), tls.read(&mut buf))
        .await
        .expect("injected record within 5s")
        .expect("read injected record");
    assert_eq!(
        &buf[..n],
        b"injected\n",
        "the injected bytes must arrive decrypted, not as ciphertext or nothing at all"
    );

    // The protocol's own path still works alongside the injected one, over the same lock.
    tls.write_all(b"hello\n").await.expect("write");
    let n = tokio::time::timeout(Duration::from_secs(5), tls.read(&mut buf))
        .await
        .expect("static answer within 5s")
        .expect("read static answer");
    assert_eq!(&buf[..n], b"static answer\n");

    // "disconnect this peer": the write half is shut down, which for a TLS stream emits a
    // real close_notify alert, so the client's read returns a clean `Ok(0)` rather than
    // `UnexpectedEof`.
    let outcome = state
        .send_to_peer(
            server_id,
            conn,
            serde_json::json!({"type": "close_connection"}),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_peer close");
    assert!(
        matches!(outcome, ClientSendOutcome::Disconnected),
        "expected Disconnected, got {outcome:?}"
    );

    let n = tokio::time::timeout(Duration::from_secs(5), tls.read(&mut buf))
        .await
        .expect("EOF within 5s")
        .expect("clean end of stream after close_connection");
    assert_eq!(n, 0, "expected EOF after close_connection");

    for _ in 0..200 {
        if !state.has_peer_handle(server_id, conn).await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("peer handle still registered after the connection closed");
}

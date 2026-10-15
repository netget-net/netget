//! The dashboard's `[ send ]` path on a TLS client: `AppState::send_to_client` injects an
//! action from outside the client's read loop and the plaintext bytes reach the server after
//! TLS encryption. Zero LLM calls — an in-test rustls server with a self-signed cert accepts
//! the handshake (the client connects with `accept_invalid_certs`), the client's LLM points at
//! an unreachable URL (its connected-event call fails; the loop tolerates that), and the
//! injected send goes through the protocol's own `execute_action`, never a model.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features tls --test client -- tls::command_channel --test-threads=100

use std::sync::Arc;
use std::time::Duration;

use netget::cli::management::ClientForm;
use netget::state::app_state::AppState;
use netget::state::client_handles::ClientSendOutcome;
use netget::state::ClientId;
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;

async fn new_state() -> AppState {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".to_string());
    state
        .set_llm_client(netget::llm::OllamaClient::new(
            "http://127.0.0.1:1".to_string(),
        ))
        .await;
    state
}

async fn wait_for_client_handle(state: &AppState, id: ClientId) {
    for _ in 0..1_000 {
        if state.has_client_handle(id).await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!(
        "tls client #{} never registered a command handle",
        id.as_u32()
    );
}

/// A rustls server config with a fresh self-signed cert for "localhost".
fn server_config() -> Arc<ServerConfig> {
    use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, SanType};

    // ServerConfig::builder() panics without a process-level provider; installing is
    // idempotent (returns Err if one is already installed, which is fine).
    let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();

    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "localhost");
    params.distinguished_name = dn;
    params.subject_alt_names = vec![SanType::DnsName("localhost".try_into().unwrap())];

    let key_pair = KeyPair::generate().expect("generate key pair");
    let cert = params.self_signed(&key_pair).expect("self-sign cert");

    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::try_from(key_pair.serialize_der()).expect("private key DER");

    Arc::new(
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .expect("server config"),
    )
}

#[tokio::test]
async fn injected_tls_data_reaches_the_server() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind tls listener");
    let addr = listener.local_addr().expect("listener addr");
    let acceptor = TlsAcceptor::from(server_config());

    // Accept one TLS connection and forward the decrypted bytes the client writes.
    let (bytes_tx, mut bytes_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    tokio::spawn(async move {
        if let Ok((tcp, _)) = listener.accept().await {
            if let Ok(mut tls) = acceptor.accept(tcp).await {
                let mut buf = vec![0u8; 4096];
                loop {
                    match tls.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            let _ = bytes_tx.send(buf[..n].to_vec());
                        }
                    }
                }
            }
        }
    });

    let client_id = ClientForm {
        protocol: "tls".to_string(),
        remote_addr: Some(addr.to_string()),
        instruction: Some("test client".to_string()),
        startup_params: Some(serde_json::json!({ "accept_invalid_certs": true })),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
        tx.clone(),
    )
    .await
    .expect("create tls client");

    wait_for_client_handle(&state, client_id).await;

    // Inject a plaintext send; it is encrypted onto the wire and decrypted server-side.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "send_tls_data", "data": "Hello"}),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_client");
    assert!(
        matches!(outcome, ClientSendOutcome::Sent { bytes_sent: 5 }),
        "expected Sent{{5}}, got {outcome:?}"
    );

    let received = tokio::time::timeout(Duration::from_secs(5), bytes_rx.recv())
        .await
        .expect("bytes within 5s")
        .expect("forwarding channel open");
    assert_eq!(received, b"Hello");

    // Unknown actions are rejected, not swallowed.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "no_such_action"}),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_client (bad action)");
    assert!(
        matches!(outcome, ClientSendOutcome::Rejected { .. }),
        "expected Rejected, got {outcome:?}"
    );

    // Injected disconnect ends the read loop; the handle is dropped on exit.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "disconnect"}),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_client (disconnect)");
    assert!(
        matches!(outcome, ClientSendOutcome::Disconnected),
        "expected Disconnected, got {outcome:?}"
    );

    for _ in 0..1_000 {
        if !state.has_client_handle(client_id).await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("client handle still registered after disconnect");
}

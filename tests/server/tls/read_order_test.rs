//! One TLS connection's reads are answered in the order they arrived.
//!
//! The TLS reader hands each decrypted read to the connection's state machine and goes straight
//! back to `read()`, so a peer that writes in quick succession has several reads in the server at
//! once. Each must be answered after the one before it: the decrypted stream has no message ids,
//! so a reply that overtakes an earlier one is a reply to the wrong message as far as the peer
//! can tell. The same test as `tests/server/tcp/read_order_test.rs`, over TLS.
//!
//! The server presents a certificate this test generated and hands it through `cert_path` /
//! `key_path`; the client trusts exactly that certificate, so the handshake is a verified one.
//! The rule answering every read is static and echoes the read's own bytes, so no model is
//! involved and the answers are as fast as the server can make them — which is when two answers
//! racing each other is most likely. The peer writes numbered tokens one record at a time and
//! reads the echoes back; however the server split or joined the reads, the echoes concatenated
//! must be the tokens in the order they were written. Both with batching off (one read per
//! answer) and on (everything waiting per answer).
//!
//! Loopback only; the LLM endpoint is a dead port, and nothing may reach it.

use std::sync::Arc;
use std::time::Duration;

use netget::cli::management::ServerForm;
use netget::server::tls_cert_manager::{generate_self_signed_cert, CertificateSpec};
use netget::state::app_state::AppState;
use netget::state::ServerId;
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_rustls::TlsConnector;

/// Tokens per connection, each its own write and so its own TLS record.
const TOKENS: usize = 300;
/// Connections per batching mode, each driven at the same time as the others.
const CONNECTIONS: usize = 4;

async fn wait_for_port(state: &AppState, id: ServerId) -> u16 {
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

/// Write `TOKENS` numbered tokens one record each, and return everything echoed back.
async fn echo_tokens(port: u16, connector: TlsConnector, connection: usize) -> (String, String) {
    let tcp = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    let name = rustls::pki_types::ServerName::try_from("localhost").expect("server name");
    let stream = connector
        .connect(name, tcp)
        .await
        .expect("verified TLS handshake with the NetGet server");
    let (mut read_half, mut write_half) = tokio::io::split(stream);
    let sent: String = (0..TOKENS).map(|i| format!("{connection}.{i};")).collect();
    let expected_len = sent.len();

    let writer = tokio::spawn(async move {
        for i in 0..TOKENS {
            write_half
                .write_all(format!("{connection}.{i};").as_bytes())
                .await
                .expect("write");
            write_half.flush().await.expect("flush");
            // Let the server read between writes, so the reads stay small and many of them are
            // in the server at once rather than one large read.
            tokio::task::yield_now().await;
        }
        write_half
    });

    let mut echoed = Vec::with_capacity(expected_len);
    let mut buf = [0u8; 4096];
    let read = tokio::time::timeout(Duration::from_secs(60), async {
        while echoed.len() < expected_len {
            let n = read_half.read(&mut buf).await.expect("read");
            assert!(
                n > 0,
                "connection {connection} closed after {} of {expected_len} echoed bytes",
                echoed.len()
            );
            echoed.extend_from_slice(&buf[..n]);
        }
    })
    .await;
    let _write_half = writer.await.expect("writer");
    assert!(
        read.is_ok(),
        "connection {connection}: only {} of {expected_len} bytes echoed within the deadline",
        echoed.len()
    );
    (sent, String::from_utf8(echoed).expect("utf8 echo"))
}

async fn run(batching: bool) {
    use rustls::crypto::CryptoProvider;
    let _ = CryptoProvider::install_default(rustls::crypto::ring::default_provider());

    // The server's certificate, made here so the client can trust exactly it.
    let (certificate, key) = generate_self_signed_cert(&CertificateSpec {
        san_dns_names: vec!["localhost".to_string()],
        ..CertificateSpec::default()
    })
    .expect("certificate");
    let dir = tempfile::tempdir().expect("tempdir");
    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");
    std::fs::write(&cert_path, certificate.pem()).expect("write cert");
    std::fs::write(&key_path, key.serialize_pem()).expect("write key");
    let mut roots = RootCertStore::empty();
    roots
        .add(certificate.der().clone())
        .expect("trust the server's certificate");
    let connector = TlsConnector::from(Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    ));

    let state = AppState::new_with_options(false, "http://127.0.0.1:1".to_string());
    state
        .set_llm_client(netget::llm::OllamaClient::new(
            "http://127.0.0.1:1".to_string(),
        ))
        .await;
    let (tx, _rx) = mpsc::unbounded_channel();
    let id = ServerForm {
        protocol: "tls".to_string(),
        port: Some(0),
        host: Some("127.0.0.1".to_string()),
        // An empty instruction really is model-free; `None` is replaced by a default one.
        instruction: Some(String::new()),
        batching: Some(batching),
        startup_params: Some(serde_json::json!({
            "cert_path": cert_path.to_string_lossy(),
            "key_path": key_path.to_string_lossy(),
        })),
        event_handlers: Some(vec![serde_json::json!({
            "event_pattern": "tls_data_received",
            "handler": {
                "type": "static",
                "actions": [{
                    "type": "send_tls_data",
                    "data": "{{event.data}}",
                    "encoding": "utf8"
                }]
            }
        })]),
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .expect("create tls server");
    let port = wait_for_port(&state, id).await;

    let peers: Vec<_> = (0..CONNECTIONS)
        .map(|c| tokio::spawn(echo_tokens(port, connector.clone(), c)))
        .collect();
    for peer in peers {
        let (sent, echoed) = peer.await.expect("peer");
        if echoed != sent {
            let at = sent
                .bytes()
                .zip(echoed.bytes())
                .position(|(a, b)| a != b)
                .unwrap_or(0);
            let from = at.saturating_sub(40);
            panic!(
                "batching {}: replies came back out of order from byte {at}:\n  sent   ...{}\n  echoed ...{}",
                if batching { "on" } else { "off" },
                &sent[from..(at + 40).min(sent.len())],
                &echoed[from..(at + 40).min(echoed.len())],
            );
        }
    }
    let _ = state.remove_server(id).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tls_reads_are_answered_in_the_order_they_arrived() {
    run(false).await;
    run(true).await;
}

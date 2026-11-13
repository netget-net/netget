//! Explicit FTPS (RFC 4217) driven from a rustls client: `AUTH TLS` in place on the control
//! connection, `PBSZ`/`PROT` sequencing, TLS data connections, and both handshake bounds from
//! both sides.
//!
//! | Bound | Under it | Over it |
//! |---|---|---|
//! | control handshake after `234`, `idle_timeout_secs` (3) | the client starts it 1s in: TLS session, commands answered | it never does: closed at ~3s |
//! | data handshake, `data_connect_timeout_secs` (3) | the client completes it 1s in: the file crosses | TCP connects, no ClientHello: `425` at ~3s |
//!
//! In-process server, mocked model. Loopback only.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::helpers::mock_builder::MockLlmBuilder;
use crate::helpers::mock_ollama::MockOllamaServer;
use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use serde_json::json;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_rustls::TlsConnector;

const NOTES: &str = "first line\nsecond line\n";

fn mock_rules() -> MockLlmBuilder {
    MockLlmBuilder::new()
        .on_event("ftp_command")
        .and_event_data_contains("command", "CONNECTION_ESTABLISHED")
        .respond_with_actions(
            json!([{"type": "send_ftp_response", "code": 220, "message": "ready"}]),
        )
        .expect_at_least(1)
        .and()
        .on_event("ftp_command")
        .and_event_data_contains("command", "USER")
        .respond_with_actions(json!([{"type": "send_ftp_response", "code": 230, "message": "in"}]))
        .expect_at_least(0)
        .and()
        .on_event("ftp_command")
        .and_event_data_contains("command", "RETR notes.txt")
        .respond_with_actions(json!([{"type": "send_ftp_data", "data": NOTES}]))
        .expect_at_least(0)
        .and()
        .on_event("ftp_command")
        .and_event_data_contains("command", "STOR")
        .respond_with_actions_from_event(|e| {
            json!([{
                "type": "send_ftp_response",
                "code": 226,
                "message": format!("got {}", e["upload_text"].as_str().unwrap_or("-"))
            }])
        })
        .expect_at_least(0)
        .and()
}

struct Certs {
    _dir: tempfile::TempDir,
    params: serde_json::Value,
    connector: TlsConnector,
}

/// A certificate for 127.0.0.1, handed to the server as `cert_path`/`key_path` and trusted by
/// the client as its only root.
fn certs() -> Certs {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let certified =
        rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()]).expect("certificate");
    let dir = tempfile::tempdir().expect("tempdir");
    let cert = dir.path().join("cert.pem");
    let key = dir.path().join("key.pem");
    std::fs::write(&cert, certified.cert.pem()).unwrap();
    std::fs::write(&key, certified.signing_key.serialize_pem()).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(certified.cert.der().clone()).unwrap();
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Certs {
        params: json!({
            "cert_path": cert.to_string_lossy(),
            "key_path": key.to_string_lossy(),
        }),
        connector: TlsConnector::from(Arc::new(config)),
        _dir: dir,
    }
}

struct Ftp {
    _mock: MockOllamaServer,
    _state: AppState,
    port: u16,
}

async fn start(startup_params: serde_json::Value) -> Ftp {
    let mock = MockOllamaServer::start(mock_rules().build())
        .await
        .expect("mock ollama");
    let state = AppState::new_with_options(false, mock.base_url());
    state
        .set_llm_client(netget::llm::OllamaClient::new(mock.base_url()))
        .await;
    let (tx, _rx) = mpsc::unbounded_channel();
    let id = ServerForm {
        protocol: "ftp".to_string(),
        port: Some(0),
        host: Some("127.0.0.1".to_string()),
        instruction: Some("Serve notes.txt over FTPS.".to_string()),
        startup_params: Some(startup_params),
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .expect("create ftp server");
    let mut port = 0;
    for _ in 0..300 {
        if let Some(addr) = state.get_server(id).await.and_then(|s| s.local_addr) {
            port = addr.port();
            break;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    assert_ne!(port, 0, "server never bound");
    Ftp {
        _mock: mock,
        _state: state,
        port,
    }
}

/// One reply line from `reader`.
async fn line<R: AsyncRead + Unpin>(reader: &mut BufReader<R>) -> String {
    let mut line = String::new();
    let n = tokio::time::timeout(Duration::from_secs(15), reader.read_line(&mut line))
        .await
        .expect("no reply within 15s")
        .unwrap();
    assert!(n > 0, "control connection closed");
    assert!(line.ends_with("\r\n"), "{line:?}");
    line.trim_end().to_string()
}

async fn send<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut BufReader<S>,
    command: &str,
) -> String {
    stream
        .get_mut()
        .write_all(format!("{command}\r\n").as_bytes())
        .await
        .unwrap();
    line(stream).await
}

fn ip() -> ServerName<'static> {
    ServerName::IpAddress(std::net::IpAddr::from([127, 0, 0, 1]).into())
}

/// Connect, read the greeting, and send `AUTH TLS`: the plain stream positioned for the
/// handshake.
async fn auth(port: u16) -> TcpStream {
    let mut plain = BufReader::new(TcpStream::connect(("127.0.0.1", port)).await.unwrap());
    assert!(line(&mut plain).await.starts_with("220"));
    assert_eq!(
        send(&mut plain, "AUTH TLS").await,
        "234 AUTH TLS successful; start the TLS handshake"
    );
    assert!(
        plain.buffer().is_empty(),
        "the server wrote past its 234 in the clear"
    );
    plain.into_inner()
}

fn epsv_addr(reply: &str) -> SocketAddr {
    let port: u16 = reply
        .strip_prefix("229 Entering Extended Passive Mode (|||")
        .and_then(|rest| rest.strip_suffix("|)"))
        .unwrap_or_else(|| panic!("not a 229: {reply}"))
        .parse()
        .unwrap();
    SocketAddr::from(([127, 0, 0, 1], port))
}

/// The sequence the RFC requires, and what is refused out of it, all before any handler.
#[tokio::test]
async fn auth_pbsz_prot_are_sequenced_by_the_server() {
    let c = certs();
    let ftp = start(c.params.clone()).await;
    let mut plain = BufReader::new(TcpStream::connect(("127.0.0.1", ftp.port)).await.unwrap());
    assert!(line(&mut plain).await.starts_with("220"));
    assert_eq!(
        send(&mut plain, "PBSZ 0").await,
        "503 PBSZ needs AUTH TLS first"
    );
    assert_eq!(
        send(&mut plain, "PROT P").await,
        "503 PROT needs AUTH TLS first"
    );
    assert_eq!(
        send(&mut plain, "AUTH KERBEROS_V4").await,
        "504 AUTH mechanism not supported; use AUTH TLS"
    );
    // AUTH SSL is what curl sends first; it is the same thing.
    assert!(send(&mut plain, "AUTH SSL").await.starts_with("234 "));
    let tls = c.connector.connect(ip(), plain.into_inner()).await.unwrap();
    let mut tls = BufReader::new(tls);
    assert_eq!(send(&mut tls, "PROT P").await, "503 PROT needs PBSZ first");
    assert_eq!(send(&mut tls, "PBSZ 0").await, "200 PBSZ=0");
    assert!(send(&mut tls, "PROT S").await.starts_with("536 "));
    assert_eq!(
        send(&mut tls, "PROT C").await,
        "200 Protection level set to C"
    );
    assert_eq!(
        send(&mut tls, "AUTH TLS").await,
        "503 The control connection is already TLS"
    );
    // The handler answers over TLS like anywhere else.
    assert_eq!(send(&mut tls, "USER alice").await, "230 in");

    // PROT C: the data connection stays clear text under a TLS control connection.
    let data = epsv_addr(&send(&mut tls, "EPSV").await);
    let mut conn = TcpStream::connect(data).await.unwrap();
    assert!(send(&mut tls, "RETR notes.txt").await.starts_with("150 "));
    let mut got = Vec::new();
    conn.read_to_end(&mut got).await.unwrap();
    assert_eq!(got, b"first line\r\nsecond line\r\n");
    assert_eq!(line(&mut tls).await, "226 Transfer complete");
}

/// The control handshake bound, both sides: a ClientHello 1s after the `234` makes a TLS
/// session; none closes the connection at `idle_timeout_secs`.
#[tokio::test]
async fn control_handshake_must_start_within_the_idle_bound() {
    let c = certs();
    let mut params = c.params.clone();
    params["idle_timeout_secs"] = json!(3);
    let ftp = start(params).await;

    let plain = auth(ftp.port).await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    let mut tls = BufReader::new(c.connector.connect(ip(), plain).await.unwrap());
    assert_eq!(send(&mut tls, "USER alice").await, "230 in");

    let mut plain = auth(ftp.port).await;
    let started = Instant::now();
    let mut rest = Vec::new();
    let read = tokio::time::timeout(Duration::from_secs(15), plain.read_to_end(&mut rest)).await;
    let waited = started.elapsed();
    assert!(read.is_ok(), "the connection was never closed");
    assert!(rest.is_empty(), "the server wrote {rest:?} after its 234");
    assert!(
        waited >= Duration::from_millis(2500) && waited < Duration::from_secs(10),
        "closed after {waited:?}; idle_timeout_secs is 3"
    );
}

/// `PROT P` downloads and uploads over TLS data connections, byte-exact, `ABOR` over TLS; and
/// the data handshake bound, both sides.
#[tokio::test]
async fn prot_p_data_connections_are_tls_and_bounded() {
    let c = certs();
    let mut params = c.params.clone();
    params["data_connect_timeout_secs"] = json!(3);
    let ftp = start(params).await;
    let mut tls = BufReader::new(
        c.connector
            .connect(ip(), auth(ftp.port).await)
            .await
            .unwrap(),
    );
    assert_eq!(send(&mut tls, "PBSZ 0").await, "200 PBSZ=0");
    assert_eq!(
        send(&mut tls, "PROT P").await,
        "200 Protection level set to P"
    );
    assert_eq!(send(&mut tls, "TYPE I").await, "200 Type set to I");

    // Download, the handshake 1s into the 3s window.
    let data = epsv_addr(&send(&mut tls, "EPSV").await);
    let tcp = TcpStream::connect(data).await.unwrap();
    assert!(send(&mut tls, "RETR notes.txt").await.starts_with("150 "));
    tokio::time::sleep(Duration::from_secs(1)).await;
    let mut conn = c.connector.connect(ip(), tcp).await.unwrap();
    let mut got = Vec::new();
    conn.read_to_end(&mut got).await.unwrap();
    assert_eq!(got, NOTES.as_bytes());
    assert_eq!(line(&mut tls).await, "226 Transfer complete");

    // Upload, ended with close_notify.
    let data = epsv_addr(&send(&mut tls, "EPSV").await);
    let tcp = TcpStream::connect(data).await.unwrap();
    assert!(send(&mut tls, "STOR up.txt").await.starts_with("150 "));
    let mut conn = c.connector.connect(ip(), tcp).await.unwrap();
    conn.write_all(b"over tls").await.unwrap();
    conn.shutdown().await.unwrap();
    assert_eq!(line(&mut tls).await, "226 got over tls");

    // ABOR on the TLS control connection ends a TLS upload: 426, then 226.
    let data = epsv_addr(&send(&mut tls, "EPSV").await);
    let tcp = TcpStream::connect(data).await.unwrap();
    assert!(send(&mut tls, "STOR aborted.txt").await.starts_with("150 "));
    let mut conn = c.connector.connect(ip(), tcp).await.unwrap();
    conn.write_all(b"part").await.unwrap();
    conn.flush().await.unwrap();
    assert_eq!(
        send(&mut tls, "ABOR").await,
        "426 Connection closed; transfer aborted"
    );
    assert_eq!(line(&mut tls).await, "226 Abort successful");
    drop(conn);

    // TCP connects and never says hello: 425 at the connect bound, not a clear-text file.
    let data = epsv_addr(&send(&mut tls, "EPSV").await);
    let mut tcp = TcpStream::connect(data).await.unwrap();
    let started = Instant::now();
    assert!(send(&mut tls, "RETR notes.txt").await.starts_with("150 "));
    assert_eq!(line(&mut tls).await, "425 Can't open data connection");
    let waited = started.elapsed();
    assert!(
        waited >= Duration::from_millis(2500) && waited < Duration::from_secs(10),
        "425 after {waited:?}; data_connect_timeout_secs is 3"
    );
    let mut leaked = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), tcp.read_to_end(&mut leaked)).await;
    assert!(
        !String::from_utf8_lossy(&leaked).contains("first line"),
        "the file crossed in the clear under PROT P"
    );
}

/// With no `cert_path`/`key_path` the server generates a certificate and FTPS still works.
#[tokio::test]
async fn generated_certificate_serves_ftps() {
    #[derive(Debug)]
    struct AcceptAny(Arc<rustls::crypto::CryptoProvider>);
    impl rustls::client::danger::ServerCertVerifier for AcceptAny {
        fn verify_server_cert(
            &self,
            _: &rustls::pki_types::CertificateDer<'_>,
            _: &[rustls::pki_types::CertificateDer<'_>],
            _: &ServerName<'_>,
            _: &[u8],
            _: rustls::pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &rustls::pki_types::CertificateDer<'_>,
            dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls12_signature(
                message,
                cert,
                dss,
                &self.0.signature_verification_algorithms,
            )
        }
        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &rustls::pki_types::CertificateDer<'_>,
            dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls13_signature(
                message,
                cert,
                dss,
                &self.0.signature_verification_algorithms,
            )
        }
        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            self.0.signature_verification_algorithms.supported_schemes()
        }
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAny(provider)))
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));

    let ftp = start(json!({})).await;
    let mut tls = BufReader::new(connector.connect(ip(), auth(ftp.port).await).await.unwrap());
    assert_eq!(send(&mut tls, "USER alice").await, "230 in");
}

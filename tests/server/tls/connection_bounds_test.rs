//! The read deadlines on a real, running TLS server, driven from a raw socket and from a real
//! rustls client.
//!
//! **Four claims, and the first is that there are three bounds here rather than two.** One
//! constant used to govern both the wait for the handshake and the wait for the first
//! application record, on the reasoning that from the peer's side they are one condition: it
//! holds a socket and has produced nothing usable. They are not one condition, because they face
//! different peers. The handshake bound faces something that has opened a TCP socket and not yet
//! sent a ClientHello. The first-record bound faces something that has *completed* a handshake —
//! which, here, is usually NetGet's own TLS client: `src/client/tls/mod.rs` runs
//! `TlsConnector::connect` inside its own `connect()` and then writes **no application bytes at
//! all** unprompted, and a client created from the dashboard's `[ + tls client ]` is routed
//! `tls_client_connected` → static-with-no-actions and then `*` → manual
//! (`src/tui/modal/form.rs`). At the 60 seconds both bounds used to share, this server hung up
//! on the operator's own client while they were still looking at it — and, unlike in the
//! handshake phase, there was nothing the peer could have done about it.
//!
//! So: a TCP peer that never sends a ClientHello is closed on `handshake_timeout_secs` (first
//! test); a peer that completes the handshake and then says nothing is closed on
//! `first_byte_timeout_secs` (second test); and a peer that has *sent* application data and then
//! goes quiet is closed on `idle_timeout_secs` (third test). Remove any one of those deadlines
//! and its test hangs until its own window expires, because nothing else in the process will
//! close that socket.
//!
//! **The fourth test is the regression**, and it is deliberately the slow one: proving that the
//! first-record default outlasts the 60 seconds it used to be means waiting past 60 seconds.
//!
//! The values the first three tests use are *overrides*, not the defaults. That is why all three
//! bounds are declared startup parameters: what is asserted here is that each parameter is read
//! and applied to the read it names; the *values* are argued where they are declared, in
//! `src/server/tls/mod.rs`.
//!
//! No mock backend: the LLM endpoint is a dead port. These tests assert on deadlines, not on
//! answers. Loopback only.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features tls --test server -- \
//!       tls::connection_bounds --test-threads=100

use std::sync::Arc;
use std::time::Duration;

use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use netget::state::ServerId;
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_rustls::TlsConnector;

/// The handshake bound the first test drives, as `handshake_timeout_secs`.
const SHORT_HANDSHAKE: Duration = Duration::from_secs(6);

/// The first-application-record bound the second test drives, as `first_byte_timeout_secs`.
const SHORT_FIRST_BYTE: Duration = Duration::from_secs(6);

/// The idle bound the third test drives, as `idle_timeout_secs`.
const SHORT_IDLE: Duration = Duration::from_secs(4);

/// How long the fourth test holds a handshaked-but-silent peer against the *default*
/// first-record bound.
///
/// Past the 60 seconds that bound used to be, by a margin that survives a 100-thread run, and far
/// inside the 300 it now is. A cheaper test cannot exist: the claim is about a number larger than
/// 60, so the wait has to be larger than 60 too.
const PAST_THE_OLD_BOUND: Duration = Duration::from_secs(75);

/// Accepts the server's self-signed certificate. These tests are about clocks, not about PKI.
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

/// A rustls client that has completed the handshake, in the role NetGet's own TLS client is in
/// when the dashboard has answered its connect event with nothing.
async fn handshaked_peer(port: u16) -> tokio_rustls::client::TlsStream<TcpStream> {
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

/// A model-free TLS server: an empty instruction really is model-free, where `None` is replaced
/// by a default one and every event would consult the LLM.
async fn start_server(
    state: &AppState,
    startup_params: Option<serde_json::Value>,
    event_handlers: Option<Vec<serde_json::Value>>,
) -> u16 {
    let (tx, _rx) = mpsc::unbounded_channel();
    let server_id = ServerForm {
        protocol: "tls".to_string(),
        port: Some(0),
        instruction: Some(String::new()),
        startup_params,
        event_handlers,
        ..Default::default()
    }
    .create(state, tx)
    .await
    .expect("create tls server");
    wait_for_port(state, server_id).await
}

#[tokio::test]
async fn a_tcp_peer_that_never_sends_a_client_hello_is_closed_at_the_handshake_bound() {
    let state = new_state().await;
    // A long first-record bound and a short handshake one: if the two were still a single
    // constant, this peer would be held for a minute and the assertion below would time out.
    let port = start_server(
        &state,
        Some(serde_json::json!({
            "handshake_timeout_secs": SHORT_HANDSHAKE.as_secs(),
            "first_byte_timeout_secs": 120,
        })),
        None,
    )
    .await;

    // Deliberately not a TLS client: a bare socket, which is the peer this bound is about.
    let mut peer = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");

    let started = std::time::Instant::now();
    let mut sink = Vec::new();
    let read = tokio::time::timeout(
        SHORT_HANDSHAKE + Duration::from_secs(45),
        peer.read_to_end(&mut sink),
    )
    .await;
    let elapsed = started.elapsed();

    assert!(
        read.is_ok(),
        "a peer that opened a socket and never sent a ClientHello was still holding it, and the \
         rustls state machine behind it, after {}s — either `acceptor.accept()` is unbounded \
         again, or `handshake_timeout_secs` was declared and never read",
        elapsed.as_secs()
    );
    read.unwrap().expect("read to EOF");
    assert!(
        elapsed < Duration::from_secs(60),
        "closed after {}s, which is the 120-second first-record bound rather than the {}s \
         handshake one — the two phases are sharing a constant again, which is the defect this \
         file exists for",
        elapsed.as_secs(),
        SHORT_HANDSHAKE.as_secs()
    );
}

#[tokio::test]
async fn a_handshaked_peer_that_sends_no_application_record_is_closed_at_the_first_byte_bound() {
    let state = new_state().await;
    let port = start_server(
        &state,
        Some(serde_json::json!({
            "first_byte_timeout_secs": SHORT_FIRST_BYTE.as_secs(),
        })),
        None,
    )
    .await;

    let mut peer = handshaked_peer(port).await;

    let started = std::time::Instant::now();
    let mut sink = Vec::new();
    // Generous against the declared bound so an ordinary scheduling delay under
    // --test-threads=100 is not mistaken for a missing deadline; what is asserted is that the
    // read ends at all, and that it ends on this bound rather than on the 300-second default.
    let read = tokio::time::timeout(
        SHORT_FIRST_BYTE + Duration::from_secs(45),
        peer.read_to_end(&mut sink),
    )
    .await;
    let elapsed = started.elapsed();

    assert!(
        read.is_ok(),
        "a peer that completed the handshake and then sent no application record was still \
         holding the socket, the connection task and its AppState entry after {}s — either the \
         first-record deadline is not applied at all, or `first_byte_timeout_secs` was declared \
         and never read and the 300-second default is still in force",
        elapsed.as_secs()
    );
    // A close here may arrive as EOF or as an abrupt reset once the write half goes; both are
    // the server letting go, which is what this test is about.
    let _ = read.unwrap();
    assert!(
        elapsed >= SHORT_FIRST_BYTE / 2,
        "closed after only {}ms — that is not the declared {}s bound, it is something else \
         tearing the connection down, and this test would then pass without the bound existing",
        elapsed.as_millis(),
        SHORT_FIRST_BYTE.as_secs()
    );
}

#[tokio::test]
async fn once_application_data_has_arrived_the_idle_bound_governs_not_the_first_record_one() {
    let state = new_state().await;
    // The two bounds are set far apart and the wrong way round on purpose: if the read loop kept
    // using the first-record bound after data arrived, this connection would live 60 seconds and
    // the assertion below would time out.
    let port = start_server(
        &state,
        Some(serde_json::json!({
            "first_byte_timeout_secs": 60,
            "idle_timeout_secs": SHORT_IDLE.as_secs(),
        })),
        Some(vec![serde_json::json!({
            "event_pattern": "*",
            "handler": {
                "type": "static",
                "actions": [{"type": "send_tls_data", "data": "ack"}]
            }
        })]),
    )
    .await;

    let mut peer = handshaked_peer(port).await;
    peer.write_all(b"hello").await.expect("write a record");
    peer.flush().await.expect("flush");

    // Reading the static rule's answer is what proves the server took the record, which is the
    // state this test is about; without it what follows would be indistinguishable from the
    // first-record case.
    let mut reply = [0u8; 128];
    let n = tokio::time::timeout(Duration::from_secs(20), peer.read(&mut reply))
        .await
        .expect("the static handler did not answer within 20s")
        .expect("read reply");
    assert!(
        n > 0,
        "the static rule did not answer, so what follows is not the post-data state this test \
         is about"
    );

    let started = std::time::Instant::now();
    let mut sink = Vec::new();
    let read = tokio::time::timeout(Duration::from_secs(45), peer.read_to_end(&mut sink)).await;
    let elapsed = started.elapsed();

    assert!(
        read.is_ok(),
        "a connection that had carried application data and then went quiet was never closed — \
         `idle_timeout_secs` was declared and is not being read"
    );
    let _ = read.unwrap();
    assert!(
        elapsed < Duration::from_secs(40),
        "closed after {}s, which is the 60-second first-record bound rather than the {}s idle \
         one — the read loop never switched bounds",
        elapsed.as_secs(),
        SHORT_IDLE.as_secs()
    );
}

#[tokio::test]
async fn the_default_leaves_a_handshaked_silent_peer_alone_for_longer_than_a_person_takes() {
    let state = new_state().await;
    // No startup parameters at all: this is the shipped default, which is the whole point.
    let port = start_server(&state, None, None).await;

    let mut peer = handshaked_peer(port).await;

    // A dashboard-created TLS client is exactly this peer: handshaked inside connect(), answered
    // with nothing, and silent until a person uses [ send message ].
    let mut sink = Vec::new();
    match tokio::time::timeout(PAST_THE_OLD_BOUND, peer.read_to_end(&mut sink)).await {
        // Still open with nothing to read: the passing case.
        Err(_) => {}
        Ok(Ok(0)) => panic!(
            "the server hung up on a handshaked, silent peer within {}s. The default bound for \
             the first application record was 60 seconds — shared with the handshake wait — and \
             that is less than a person takes: NetGet's own TLS client handshakes inside \
             connect() and writes no application bytes until someone types into \
             [ send message ], so the operator watched their own client disappear. See \
             FIRST_RECORD_READ_TIMEOUT in src/server/tls/mod.rs",
            PAST_THE_OLD_BOUND.as_secs()
        ),
        Ok(Ok(n)) => panic!(
            "the server wrote {n} application bytes to a peer that had sent none; this server \
             was started without send_first and without a routing rule to answer with"
        ),
        Ok(Err(e)) => panic!(
            "the connection failed rather than staying open, which is the same defect wearing a \
             different error: {e}"
        ),
    }
}

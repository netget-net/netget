//! The connection cap on a real, running DoT server, driven from the wire.
//!
//! `TLS_HANDSHAKE_TIMEOUT` (10s) and `IDLE_READ_TIMEOUT` (300s) bound how long *one* peer holds
//! a connection. Neither says anything about how many such peers there may be, and until
//! September 2026 this accept loop admitted every connection offered to it — so five minutes
//! multiplied by an unbounded arrival rate was not a bound at all. DoT is the transport a
//! resolver pins and reuses, so every one of those connections is a live TLS session with its
//! own key material and buffers.
//!
//! Three claims:
//!
//! 1. `MAX_CONNECTIONS` peers are admitted — and here they are admitted *properly*, each
//!    completing a real TLS handshake. That is not decoration: a peer that merely opens a
//!    socket is evicted by `TLS_HANDSHAKE_TIMEOUT` after ten seconds, which would free slots on
//!    its own and let claim 3 below pass for a reason that has nothing to do with the permit.
//!    Handshaking moves the held connections onto the 300-second idle bound instead, so nothing
//!    but the cap explains what this test measures.
//! 2. The next one is closed **with nothing written**, and that is the right answer rather than
//!    a shortcut. RFC 7858 puts the whole DNS exchange inside the TLS session, so a DNS message
//!    written to this socket is not a SERVFAIL — it is a malformed TLS record, and the client
//!    reports a handshake failure rather than a busy server. Refusing *inside* TLS would mean
//!    completing a handshake in order to say no, which hands a stranger a certificate signature
//!    per refused connection, and TLS itself has no alert meaning "at capacity" (RFC 8446 §6.2).
//!    So the assertion is exactly "the handshake does not complete, promptly".
//! 3. Closing an admitted connection **frees exactly one slot**. A permit dropped before the
//!    connection ends un-caps the server silently; one never released wedges it shut after
//!    `MAX_CONNECTIONS` peers have ever connected.
//!
//! **How this was proved to fail without the cap**: replace the `accept_bounded` call in
//! `src/server/dot/mod.rs` with a bare `listener.accept().await` (and drop the permit from the
//! connection task). The over-cap peer's handshake then succeeds and the test fails on the
//! assertion that it must not.
//!
//! The server is model-free: an empty instruction really is model-free, where `None` is
//! replaced by a default one. No query is ever sent, so no model call is provoked. Loopback
//! only.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features dot --test server -- dot::connection_bounds --test-threads=100

use std::sync::Arc;
use std::time::Duration;

use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use netget::state::ServerId;
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

use super::e2e_test::NoCertificateVerification;

/// `src/server/dot/mod.rs::MAX_CONNECTIONS`. Deliberately duplicated rather than imported: if
/// the constant moves, this test should be re-read rather than silently follow it.
const MAX_CONNECTIONS: usize = 256;

/// `src/server/dot/mod.rs::TLS_HANDSHAKE_TIMEOUT`, which is what the refusal has to beat for
/// "refused" and "admitted then evicted" to be distinguishable.
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

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
    panic!("DoT server #{} never bound a port", id.as_u32());
}

async fn start_server(state: &AppState) -> (ServerId, u16) {
    let (tx, _rx) = mpsc::unbounded_channel();
    let server_id = ServerForm {
        protocol: "dot".to_string(),
        port: Some(0),
        instruction: Some(String::new()),
        ..Default::default()
    }
    .create(state, tx)
    .await
    .expect("create dot server");
    let port = wait_for_port(state, server_id).await;
    (server_id, port)
}

fn connector() -> TlsConnector {
    use rustls::crypto::CryptoProvider;
    let _ = CryptoProvider::install_default(rustls::crypto::ring::default_provider());

    let mut config = ClientConfig::builder()
        .with_root_certificates(RootCertStore::empty())
        .with_no_client_auth();
    config
        .dangerous()
        .set_certificate_verifier(Arc::new(NoCertificateVerification));
    TlsConnector::from(Arc::new(config))
}

/// Open one DoT connection and complete its TLS handshake, or say why it did not.
///
/// A peer refused at the accept sees EOF before the ServerHello, which rustls reports as an
/// unexpected end of file — so `Err` here is the shape of the refusal, and `Ok` is the shape of
/// an admitted peer.
async fn handshake(port: u16, connector: &TlsConnector) -> std::io::Result<TlsStream<TcpStream>> {
    let tcp = TcpStream::connect(("127.0.0.1", port)).await?;
    let name = rustls::pki_types::ServerName::try_from("localhost").expect("static name");
    connector.connect(name, tcp).await
}

#[tokio::test]
async fn the_handshake_past_the_cap_is_refused_before_it_starts_and_the_slot_comes_back() {
    let state = new_state().await;
    let (_server_id, port) = start_server(&state).await;
    let connector = connector();

    let mut held = Vec::with_capacity(MAX_CONNECTIONS);
    for i in 0..MAX_CONNECTIONS {
        held.push(
            handshake(port, &connector)
                .await
                .unwrap_or_else(|e| panic!("handshake {i} of the cap failed: {e}")),
        );
    }

    let started = std::time::Instant::now();
    let refused = tokio::time::timeout(Duration::from_secs(20), handshake(port, &connector))
        .await
        .expect("the connection past the cap was neither refused nor handshaken — it hung");
    assert!(
        refused.is_err(),
        "the connection past the cap completed a TLS handshake, so it was admitted and there is \
         no cap"
    );
    // A refused peer is closed before the handshake begins; an admitted one that says nothing
    // is held for TLS_HANDSHAKE_TIMEOUT. Without this bound the assertion above would also pass
    // for a peer that was admitted and then evicted, which is the opposite outcome.
    assert!(
        started.elapsed() < TLS_HANDSHAKE_TIMEOUT / 3,
        "the refusal took {:?}, which is close enough to TLS_HANDSHAKE_TIMEOUT that this peer \
         may simply have been admitted and then evicted for saying nothing",
        started.elapsed()
    );

    // Every one of the 256 is a completed handshake, so none of them can have been evicted by
    // the handshake deadline: whatever slot appears below came from the permit and nothing else.
    assert_eq!(
        held.len(),
        MAX_CONNECTIONS,
        "the held connections must all still be open for the next assertion to mean anything"
    );
    drop(held.pop().expect("one held connection"));

    let mut admitted = false;
    for _ in 0..100 {
        match handshake(port, &connector).await {
            Ok(_stream) => {
                admitted = true;
                break;
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
        }
    }
    assert!(
        admitted,
        "the cap never freed its slot after an admitted connection ended — the permit is being \
         held past the life of the connection, which wedges the server shut"
    );
}

#[tokio::test]
async fn an_incomplete_dns_body_releases_its_connection() {
    let state = new_state().await;
    let (server_id, port) = start_server(&state).await;
    let mut stream = handshake(port, &connector()).await.expect("TLS handshake");
    // A full prefix and one body byte bypassed the between-query idle timeout and
    // pinned the session forever. No complete DNS query is sent, so no model is called.
    stream
        .write_all(&[0, 12, 0])
        .await
        .expect("partial DNS message");
    stream.flush().await.expect("flush partial message");
    let mut byte = [0];
    let result = tokio::time::timeout(Duration::from_secs(15), stream.read(&mut byte))
        .await
        .expect("incomplete DNS body kept its connection past the 10-second deadline");
    match result {
        Ok(0) => {}
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::ConnectionReset
            ) => {}
        other => panic!("expected a closed incomplete DNS session, got {other:?}"),
    }
    state
        .remove_server(server_id)
        .await
        .expect("remove DoT server");
}

//! Application data queued while an answer is in flight is bounded, and the peer is told.
//!
//! # What was wrong
//!
//! `ConnectionData::queued_data` is the `Accumulating` half of the Idle → Processing →
//! Accumulating machine: a peer may keep writing while the model is being asked what to say,
//! and those bytes are held until the answer arrives. It had **no ceiling at all**, so the peer
//! decided how much memory one connection cost — and it decided it during a window it also
//! controls the length of. An LLM round-trip is seconds; a `manual` rule parks the record for a
//! **human** and defaults to 300 seconds (`src/state/intercepts.rs`). Times 256 connections.
//!
//! Nothing stands in front of it: TLS here requires no authentication, and the first record a
//! stranger sends opens the window.
//!
//! # What this asserts, and what "refused" means on a TLS wire
//!
//! The refusal is a **close_notify alert, and that is not the alert this deserves**. TLS has a
//! description for exactly this — `record_overflow(22)` — and rustls 0.23 will not send it:
//! `CommonState::send_fatal_alert` is `pub(crate)`, and the only alert its public API emits is
//! `send_close_notify`. Writing the raw seven bytes of a `record_overflow` alert onto the TCP
//! socket underneath is not an alternative either: after the handshake every record is
//! encrypted, so a plaintext one is a protocol violation the peer must reject — it would arrive
//! as garbage rather than as a reason. Asserting `read() -> Ok(0)` is therefore the strongest
//! available evidence, and it is real evidence: an abrupt close with no alert surfaces as
//! `UnexpectedEof`, not `Ok(0)`, which is the same distinction
//! `tests/server/tls/llm_failure_test.rs` rests on. The rest of the refusal is in the log,
//! which is where the project CLAUDE.md says a distinction the wire cannot carry belongs.
//!
//! The second test is what stops the first from being satisfiable by a server that hangs up on
//! everybody: the same exchange, well under the cap, must **not** be closed.

use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
use netget::server::tls::MAX_QUEUED_BYTES;
use rustls::{ClientConfig, RootCertStore};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

/// Comfortably past the cap, and written in chunks so the peer is mid-stream when the server
/// decides — which is the condition the lingering drain exists for.
const OVER_CAP: usize = MAX_QUEUED_BYTES * 2;

/// Comfortably under it. A quarter of the cap is far more than any real request and still
/// nowhere near the ceiling, so a server that closed on this would be closing on traffic.
const UNDER_CAP: usize = MAX_QUEUED_BYTES / 4;

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

async fn tls_connect(port: u16) -> E2EResult<TlsStream<TcpStream>> {
    use rustls::crypto::CryptoProvider;
    let _ = CryptoProvider::install_default(rustls::crypto::ring::default_provider());

    let mut config = ClientConfig::builder()
        .with_root_certificates(RootCertStore::empty())
        .with_no_client_auth();
    config
        .dangerous()
        .set_certificate_verifier(Arc::new(NoCertificateVerification));
    let connector = TlsConnector::from(Arc::new(config));

    let tcp = TcpStream::connect(format!("127.0.0.1:{port}")).await?;
    let domain = rustls::pki_types::ServerName::try_from("localhost")
        .map_err(|e| format!("invalid server name: {e}"))?;
    Ok(connector.connect(domain, tcp).await?)
}

/// A TLS server whose every data event parks for a human, which is the 300-second window the
/// cap exists for. The `manual` handler is also why no model call can happen here: the point of
/// the bound is that the oversized thing never reaches a prompt, and with a manual rule in
/// place a non-zero `tls_data_received` count would mean the routing itself had broken.
fn parked_tls_server(prompt: &'static str) -> NetGetConfig {
    NetGetConfig::new_no_scripts(prompt).with_mock(|mock| {
        mock.on_instruction_containing("via tls")
            .respond_with_actions(serde_json::json!([{
                "type": "open_server",
                "port": 0,
                "base_stack": "TLS",
                "instruction": "Answer whatever arrives",
                // The connect event every connection raises is answered with nothing, as the
                // dashboard does, so the only thing that parks is the first record.
                "event_handlers": [{
                    "event_pattern": "tls_connection_opened",
                    "handler": {"type": "static", "actions": []}
                }, {
                    "event_pattern": "tls_data_received",
                    "handler": {"type": "manual", "timeout_secs": 300}
                }]
            }]))
            .expect_calls(1)
            .and()
            .on_event("tls_data_received")
            .respond_with_actions(serde_json::json!([{
                "type": "send_tls_data",
                "data": "unreachable"
            }]))
            .expect_calls(0)
            .and()
    })
}

/// Open the window: send one record and wait until it is genuinely parked, rather than racing
/// the handler task that moves the connection into `Processing`.
async fn park_the_first_record(
    server: &crate::helpers::server::NetGetServer,
    tls: &mut TlsStream<TcpStream>,
) -> E2EResult<()> {
    tls.write_all(b"OPEN\r\n").await?;
    tls.flush().await?;
    server
        .wait_for_any(&["parked as intercept", "waiting for YOUR answer"], 30)
        .await;
    if !server.output_contains("parked as intercept").await {
        return Err("the first record never parked, so the queue window never opened".into());
    }
    Ok(())
}

#[tokio::test]
async fn data_queued_past_the_cap_is_refused_with_an_alert() -> E2EResult<()> {
    let server = start_netget_server(parked_tls_server(
        "listen on port {AVAILABLE_PORT} via tls. Answer whatever arrives",
    ))
    .await?;
    crate::helpers::wait_for_server_listening(&server, Duration::from_secs(30)).await?;

    let mut tls = tls_connect(server.port).await?;
    park_the_first_record(&server, &mut tls).await?;

    // Now fill the queue. Written in 32 KiB chunks so the server is deciding while the peer is
    // still writing — the state the drain in `refuse_queued_data_overflow` is for. A write that
    // fails part-way is not itself a failure of this test: the server is entitled to have
    // stopped reading once it refused, and what matters is the alert that follows.
    let chunk = vec![0x41u8; 32 * 1024];
    let mut written = 0usize;
    while written < OVER_CAP {
        if tls.write_all(&chunk).await.is_err() {
            break;
        }
        written += chunk.len();
    }
    let _ = tls.flush().await;

    let mut buf = vec![0u8; 4096];
    let read = tokio::time::timeout(Duration::from_secs(30), tls.read(&mut buf))
        .await
        .map_err(|_| {
            "the TLS connection stayed open after the peer queued far more than MAX_QUEUED_BYTES \
             behind a parked record — which is the unbounded growth this test exists to catch"
        })?;

    match read {
        Ok(0) => { /* close_notify: the strongest refusal rustls will emit */ }
        Ok(n) => panic!(
            "expected the connection to be closed, but the server sent {n} bytes: {:?}",
            String::from_utf8_lossy(&buf[..n])
        ),
        Err(e) => panic!(
            "expected a clean close_notify (read -> Ok(0)), got {e:?}. An UnexpectedEof here \
             means the socket was dropped without an alert — which is exactly what happens when \
             a server stops reading and closes with data still in its receive queue, and is why \
             the refusal drains before it closes."
        ),
    }

    // The close reaches the peer before the server's own log line reaches this test's reader
    // of its stdout; under a loaded 32-thread sweep that gap was long enough to fail a check
    // made the instant the read returned. Wait for the line, then assert on it.
    server
        .wait_for_any(&["decision=fail_closed_queued_data_overflow"], 15)
        .await;
    assert!(
        server
            .output_contains("decision=fail_closed_queued_data_overflow")
            .await,
        "the wire cannot carry the reason, so the log must: no \
         decision=fail_closed_queued_data_overflow line was written"
    );

    server.wait_for_mocks(5).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

#[tokio::test]
async fn data_queued_under_the_cap_is_not_refused() -> E2EResult<()> {
    let server = start_netget_server(parked_tls_server(
        "listen on port {AVAILABLE_PORT} via tls. Answer whatever arrives",
    ))
    .await?;
    crate::helpers::wait_for_server_listening(&server, Duration::from_secs(30)).await?;

    let mut tls = tls_connect(server.port).await?;
    park_the_first_record(&server, &mut tls).await?;

    let chunk = vec![0x42u8; 32 * 1024];
    let mut written = 0usize;
    while written < UNDER_CAP {
        tls.write_all(&chunk).await?;
        written += chunk.len();
    }
    tls.flush().await?;

    // A negative assertion needs a deadline, and this one is deliberately generous relative to
    // what it is testing: the refusal in the other test is taken inside the read loop, on the
    // very read that crosses the cap, so if this connection were going to be closed it would be
    // closed long before five seconds. Waiting for a condition is not possible here — the
    // condition is that nothing happens.
    let mut buf = vec![0u8; 4096];
    match tokio::time::timeout(Duration::from_secs(5), tls.read(&mut buf)).await {
        Err(_) => { /* still open and still parked, which is correct */ }
        Ok(Ok(0)) => panic!(
            "the server closed a connection that queued {written} bytes, well under the \
             {MAX_QUEUED_BYTES}-byte cap. A guard that refuses everything passes the \
             over-the-cap test for the wrong reason."
        ),
        Ok(Ok(n)) => panic!("unexpected {n} bytes from a server whose every record is parked"),
        Ok(Err(e)) => panic!("unexpected I/O error on an under-cap connection: {e:?}"),
    }

    assert!(
        !server
            .output_contains("decision=fail_closed_queued_data_overflow")
            .await,
        "the cap fired on traffic well under it"
    );

    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

//! Regression tests for the connection-map race (IMPROVEMENTS item 69).
//!
//! Every stream protocol here follows the same accept-loop shape: split the stream, then
//! spawn a "handle connection" task **and** a reader task. The connection was registered in
//! the shared `connections` map by the *first* of those two tasks, so the reader could reach
//! `handle_data_with_actions` before the insert had happened — and that function returns
//! silently when the connection is not in the map. The payload is then dropped with no
//! response, no error and no log line; the client waits forever for a reply that was never
//! generated. `socket_file` was fixed first (`1f3945ee`); these are the same shape.
//!
//! The tests connect and write **before** the server has accepted, which is the interleaving
//! that loses: `connect()` returns as soon as the kernel completes the handshake and puts the
//! socket on the accept queue, so the payload is already in the receive buffer when the accept
//! loop finally runs, and the reader task's very first poll can return data without ever
//! waiting on the I/O driver. Many connections are opened in one burst so the accept loop is
//! behind and the two spawned tasks compete on a busy runtime.
//!
//! These are probabilistic, not deterministic: nothing in a test can force the tokio scheduler
//! to poll the reader task before the register task. What *is* deterministic is the invariant
//! they assert — after the fix the insert happens synchronously in the accept loop, before the
//! reader task exists, so no interleaving can drop a payload. A pre-fix binary fails these
//! runs intermittently; a fixed one cannot fail them at all.
//!
//! No Ollama is needed: every event is answered by a static handler, which `call_llm` executes
//! in-process before any model call.
//!
//! ```bash
//! cargo test --no-default-features --features tcp,tls,ssh-agent \
//!   --test connection_map_race_test -- --test-threads=100
//! ```

use netget::scripting::{EventHandler, EventHandlerConfig, EventHandlerType, EventPattern};
use netget::state::app_state::AppState;
use netget::state::server::ServerInstance;
use netget::state::ServerId;
use std::sync::Arc;
use std::time::Duration;

/// How many clients connect at once. The burst matters: it leaves connections sitting on the
/// accept queue with their payload already buffered, which is the interleaving that loses.
const BURST: usize = 64;

/// Register a server instance whose events are answered by static handlers (no LLM call).
/// A `null` action answers its event with nothing.
async fn server_with_static_handlers(
    state: &Arc<AppState>,
    protocol: &str,
    handlers: Vec<(&str, serde_json::Value)>,
) -> ServerId {
    let server = ServerInstance::new(ServerId::new(0), 0, protocol.to_string(), String::new());
    let server_id = state.add_server(server).await;

    let mut config = EventHandlerConfig::new();
    for (event, action) in handlers {
        config.add_handler(EventHandler::new(
            EventPattern::specific(event),
            EventHandlerType::static_response(if action.is_null() {
                vec![]
            } else {
                vec![action]
            }),
        ));
    }
    state
        .set_event_handler_config(server_id, Some(config))
        .await;

    server_id
}

/// Number of connections the TUI/state layer knows about for this server.
async fn tracked_connections(state: &Arc<AppState>, server_id: ServerId) -> usize {
    state
        .get_server(server_id)
        .await
        .map(|s| s.connections.len())
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// TCP
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tcp_payload_written_before_accept_is_answered() {
    use netget::llm::ollama_client::OllamaClient;
    use netget::server::TcpServer;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let state = Arc::new(AppState::new());
    let server_id = server_with_static_handlers(
        &state,
        "tcp",
        vec![(
            "tcp_data_received",
            serde_json::json!({"type": "send_tcp_data", "data": "PONG\n", "encoding": "utf8"}),
        )],
    )
    .await;

    // Unroutable LLM endpoint: reaching it at all is a test failure in disguise, since every
    // event here is answered by a static handler.
    let llm = OllamaClient::new("http://127.0.0.1:1");
    let (status_tx, _status_rx) = tokio::sync::mpsc::unbounded_channel();

    let bound = TcpServer::spawn_with_llm_actions(
        "127.0.0.1:0".parse().unwrap(),
        llm,
        state.clone(),
        status_tx,
        false, // send_first: the banner path is not what races here
        server_id,
        // Default bounds: this test is about the connection map, not the clock.
        None,
        None,
    )
    .await
    .expect("TCP server should start");

    let mut clients = Vec::with_capacity(BURST);
    for _ in 0..BURST {
        clients.push(tokio::spawn(async move {
            let mut stream = tokio::net::TcpStream::connect(bound)
                .await
                .expect("connect should succeed");
            // Write immediately: the server has almost certainly not accepted yet.
            stream
                .write_all(b"PING\n")
                .await
                .expect("write should succeed");

            let mut buf = vec![0u8; 64];
            let n = tokio::time::timeout(Duration::from_secs(10), stream.read(&mut buf))
                .await
                .map_err(|_| "timed out waiting for a reply".to_string())?
                .map_err(|e| format!("read failed: {e}"))?;
            Ok::<String, String>(String::from_utf8_lossy(&buf[..n]).to_string())
        }));
    }

    let mut answered = 0usize;
    let mut failures = Vec::new();
    for client in clients {
        match client.await.expect("client task should not panic") {
            Ok(reply) => {
                assert_eq!(reply, "PONG\n", "server answered with unexpected bytes");
                answered += 1;
            }
            Err(e) => failures.push(e),
        }
    }

    assert_eq!(
        answered,
        BURST,
        "{} of {BURST} immediate writes were dropped by the server: {:?} — the connection was \
         not in the map when the reader delivered the payload",
        failures.len(),
        failures
    );

    assert_eq!(
        tracked_connections(&state, server_id).await,
        BURST,
        "every connection must be visible to the TUI/state layer"
    );
}

/// A client that writes and immediately closes must not panic a server task.
///
/// The reader task removes the connection on EOF while the read before it may still be being
/// answered, and a merge step that re-acquired the connection lock used to `unwrap()` the
/// resulting `None`. A panicked socket task is silent — the server keeps reporting `Running`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tcp_write_then_immediate_close_does_not_panic_a_task() {
    use netget::llm::ollama_client::OllamaClient;
    use netget::server::TcpServer;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::AsyncWriteExt;

    static PANICS: AtomicUsize = AtomicUsize::new(0);
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        PANICS.fetch_add(1, Ordering::SeqCst);
        previous(info);
    }));

    let state = Arc::new(AppState::new());
    let server_id = server_with_static_handlers(
        &state,
        "tcp",
        vec![(
            "tcp_data_received",
            serde_json::json!({"type": "send_tcp_data", "data": "PONG\n", "encoding": "utf8"}),
        )],
    )
    .await;

    let llm = OllamaClient::new("http://127.0.0.1:1");
    let (status_tx, _status_rx) = tokio::sync::mpsc::unbounded_channel();

    let bound = TcpServer::spawn_with_llm_actions(
        "127.0.0.1:0".parse().unwrap(),
        llm,
        state.clone(),
        status_tx,
        false,
        server_id,
        None,
        None,
    )
    .await
    .expect("TCP server should start");

    let mut clients = Vec::with_capacity(BURST);
    for _ in 0..BURST {
        clients.push(tokio::spawn(async move {
            let mut stream = tokio::net::TcpStream::connect(bound)
                .await
                .expect("connect should succeed");
            let _ = stream.write_all(b"PING\n").await;
            // Half-close immediately: the reader task sees EOF while the payload is still
            // being handled.
            let _ = stream.shutdown().await;
        }));
    }
    for client in clients {
        client.await.expect("client task should not panic");
    }

    // Let the server finish handling everything it accepted.
    tokio::time::sleep(Duration::from_millis(500)).await;

    assert_eq!(
        PANICS.load(Ordering::SeqCst),
        0,
        "a server task panicked while handling a write-then-close client"
    );
}

// ---------------------------------------------------------------------------
// TLS
// ---------------------------------------------------------------------------

/// Certificate verifier that accepts anything — the server presents a self-signed cert.
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

/// TLS loses this race more readily than plain TCP: the handshake reads from the socket, so
/// application data sent right behind the client's `Finished` is already buffered inside
/// rustls when the reader task makes its first `read()` — it returns data without ever waiting
/// on the I/O driver, while the registering task is still queued.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tls_payload_written_at_handshake_completion_is_answered() {
    use netget::llm::ollama_client::OllamaClient;
    use netget::server::TlsServer;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let _ =
        rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider());

    let state = Arc::new(AppState::new());
    let server_id = server_with_static_handlers(
        &state,
        "tls",
        vec![(
            "tls_data_received",
            serde_json::json!({"type": "send_tls_data", "data": "PONG\n", "encoding": "utf8"}),
        )],
    )
    .await;

    let llm = OllamaClient::new("http://127.0.0.1:1");
    let (status_tx, _status_rx) = tokio::sync::mpsc::unbounded_channel();

    let bound = TlsServer::spawn_with_llm_actions(
        "127.0.0.1:0".parse().unwrap(),
        llm,
        state.clone(),
        status_tx,
        false,
        server_id,
        // tls_config: generate a self-signed one.
        None,
        // handshake / first-record / idle deadlines: the shipped defaults.
        None,
        None,
        None,
    )
    .await
    .expect("TLS server should start");

    let mut client_config = rustls::ClientConfig::builder()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
    client_config
        .dangerous()
        .set_certificate_verifier(Arc::new(NoCertificateVerification));
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));

    // TLS handshakes are expensive; a smaller burst still leaves connections queued.
    let burst = BURST / 4;
    let mut clients = Vec::with_capacity(burst);
    for _ in 0..burst {
        let connector = connector.clone();
        clients.push(tokio::spawn(async move {
            let tcp = tokio::net::TcpStream::connect(bound)
                .await
                .map_err(|e| format!("connect failed: {e}"))?;
            let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
            let mut stream = connector
                .connect(name, tcp)
                .await
                .map_err(|e| format!("handshake failed: {e}"))?;

            // Write the instant the handshake completes.
            stream
                .write_all(b"PING\n")
                .await
                .map_err(|e| format!("write failed: {e}"))?;

            let mut buf = vec![0u8; 64];
            let n = tokio::time::timeout(Duration::from_secs(10), stream.read(&mut buf))
                .await
                .map_err(|_| "timed out waiting for a reply".to_string())?
                .map_err(|e| format!("read failed: {e}"))?;
            Ok::<String, String>(String::from_utf8_lossy(&buf[..n]).to_string())
        }));
    }

    let mut answered = 0usize;
    let mut failures = Vec::new();
    for client in clients {
        match client.await.expect("client task should not panic") {
            Ok(reply) => {
                assert_eq!(reply, "PONG\n", "server answered with unexpected bytes");
                answered += 1;
            }
            Err(e) => failures.push(e),
        }
    }

    assert_eq!(
        answered,
        burst,
        "{} of {burst} immediate writes were dropped by the TLS server: {:?}",
        failures.len(),
        failures
    );
}

// ---------------------------------------------------------------------------
// SSH agent
// ---------------------------------------------------------------------------

/// The agent protocol is a strict request/response sequence, so a dropped request is not just
/// slow — the frame has already been consumed from the read buffer, the client is blocked on a
/// reply that will never come, and nothing retries. `ssh-add -l` hangs.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ssh_agent_request_written_before_accept_is_answered() {
    use netget::llm::ollama_client::OllamaClient;
    use netget::server::SshAgentServer;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
    const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;

    let state = Arc::new(AppState::new());
    let server_id = server_with_static_handlers(
        &state,
        "ssh-agent",
        vec![
            (
                "ssh_agent_connection_opened",
                serde_json::json!({"type": "show_message", "message": "agent connection opened"}),
            ),
            (
                "ssh_agent_request_identities",
                serde_json::json!({
                    "type": "send_identities_list",
                    "identities": [{
                        // "ssh-ed25519" + a 32-byte key, hex-encoded.
                        "public_key_blob_hex": "0000000b7373682d65643235353139000000200101010101010101010101010101010101010101010101010101010101010101",
                        "comment": "race-test-key"
                    }]
                }),
            ),
        ],
    )
    .await;

    let dir = tempfile::tempdir().expect("tempdir");
    let socket_path = dir.path().join("agent.sock");

    let llm = OllamaClient::new("http://127.0.0.1:1");
    let (status_tx, _status_rx) = tokio::sync::mpsc::unbounded_channel();

    SshAgentServer::spawn_with_llm_actions(
        socket_path.clone(),
        llm,
        state.clone(),
        status_tx,
        server_id,
        None,
        None,
    )
    .await
    .expect("SSH agent server should start");

    // uint32 length || byte type
    let request = [0u8, 0, 0, 1, SSH_AGENTC_REQUEST_IDENTITIES];

    let mut clients = Vec::with_capacity(BURST);
    for _ in 0..BURST {
        let socket_path = socket_path.clone();
        clients.push(tokio::spawn(async move {
            let mut stream = tokio::net::UnixStream::connect(&socket_path)
                .await
                .map_err(|e| format!("connect failed: {e}"))?;
            // Write immediately, exactly as ssh-add does.
            stream
                .write_all(&request)
                .await
                .map_err(|e| format!("write failed: {e}"))?;

            let mut header = [0u8; 5];
            tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut header))
                .await
                .map_err(|_| "timed out waiting for a reply".to_string())?
                .map_err(|e| format!("read failed: {e}"))?;
            Ok::<u8, String>(header[4])
        }));
    }

    let mut answered = 0usize;
    let mut failures = Vec::new();
    for client in clients {
        match client.await.expect("client task should not panic") {
            Ok(msg_type) => {
                assert_eq!(
                    msg_type, SSH_AGENT_IDENTITIES_ANSWER,
                    "agent replied with message type {msg_type}, expected IDENTITIES_ANSWER"
                );
                answered += 1;
            }
            Err(e) => failures.push(e),
        }
    }

    assert_eq!(
        answered,
        BURST,
        "{} of {BURST} agent requests went unanswered: {:?} — the frame was consumed and \
         dropped because the connection was not yet in the map",
        failures.len(),
        failures
    );
}

// ---------------------------------------------------------------------------
// Bitcoin
// ---------------------------------------------------------------------------

/// Bitcoin had this bug until `d052d838`, and had it worse than the others: a Bitcoin peer
/// sends `version` the instant it connects, so the race was hit on essentially every
/// connection rather than occasionally. Three E2E tests sat out their 120s read timeouts and
/// the failure count varied per run, which is what disguised it as flakiness.
///
/// The insert lived inside `handle_connection_opened`, spawned alongside the reader task; a
/// miss in `handle_data_with_actions` returned with no event, no queue and no log at all.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bitcoin_version_written_before_accept_is_answered() {
    use bitcoin::consensus::{Decodable, Encodable};
    use bitcoin::p2p::address::Address;
    use bitcoin::p2p::message::{NetworkMessage, RawNetworkMessage};
    use bitcoin::p2p::message_network::VersionMessage;
    use bitcoin::p2p::{Magic, ServiceFlags};
    use netget::llm::ollama_client::OllamaClient;
    use netget::server::bitcoin::BitcoinServer;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let state = Arc::new(AppState::new());
    let server_id = server_with_static_handlers(
        &state,
        "bitcoin",
        vec![
            // Answered, with nothing: unanswered, it goes to the unreachable model below and
            // fails closed, which disconnects the peer - and on a loaded machine that can beat
            // the verack this test is waiting for.
            ("bitcoin_connection_opened", serde_json::Value::Null),
            (
                "bitcoin_message_received",
                serde_json::json!({"type": "send_verack", "network": "mainnet"}),
            ),
        ],
    )
    .await;

    let llm = OllamaClient::new("http://127.0.0.1:1");
    let (status_tx, _status_rx) = tokio::sync::mpsc::unbounded_channel();

    let bound = BitcoinServer::spawn_with_llm_actions(
        "127.0.0.1:0".parse().unwrap(),
        llm,
        state.clone(),
        status_tx,
        server_id,
        "mainnet".to_string(),
    )
    .await
    .expect("Bitcoin server should start");

    // One encoded `version` message, reused by every client in the burst.
    let version_bytes = {
        let addr = std::net::SocketAddr::from(([127, 0, 0, 1], 8333));
        let message = RawNetworkMessage::new(
            Magic::BITCOIN,
            NetworkMessage::Version(VersionMessage {
                version: 70015,
                services: ServiceFlags::NONE,
                timestamp: 1_700_000_000,
                receiver: Address::new(&addr, ServiceFlags::NONE),
                sender: Address::new(&addr, ServiceFlags::NONE),
                nonce: 0x1234_5678,
                user_agent: "/RaceTest:0.1.0/".to_string(),
                start_height: 0,
                relay: false,
            }),
        );
        let mut bytes = Vec::new();
        message
            .consensus_encode(&mut bytes)
            .expect("version message should encode");
        Arc::new(bytes)
    };

    let mut clients = Vec::with_capacity(BURST);
    for _ in 0..BURST {
        let payload = version_bytes.clone();
        clients.push(tokio::spawn(async move {
            let mut stream = tokio::net::TcpStream::connect(bound)
                .await
                .expect("connect should succeed");
            // Write immediately, before the server has accepted — the losing interleaving.
            stream
                .write_all(&payload)
                .await
                .expect("write should succeed");

            // Read one whole message: 24-byte header, then the declared payload length.
            let mut header = [0u8; 24];
            tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut header))
                .await
                .map_err(|_| "timed out waiting for a reply".to_string())?
                .map_err(|e| format!("header read failed: {e}"))?;
            let payload_len =
                u32::from_le_bytes([header[16], header[17], header[18], header[19]]) as usize;
            let mut body = vec![0u8; payload_len];
            if payload_len > 0 {
                tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut body))
                    .await
                    .map_err(|_| "timed out reading payload".to_string())?
                    .map_err(|e| format!("payload read failed: {e}"))?;
            }

            let mut whole = header.to_vec();
            whole.extend_from_slice(&body);
            let decoded = RawNetworkMessage::consensus_decode(&mut std::io::Cursor::new(&whole))
                .map_err(|e| format!("reply did not decode as a Bitcoin message: {e}"))?;
            Ok::<String, String>(match decoded.payload() {
                NetworkMessage::Verack => "verack".to_string(),
                other => format!("unexpected: {other:?}"),
            })
        }));
    }

    let mut answered = 0usize;
    let mut failures = Vec::new();
    for client in clients {
        match client.await.expect("client task should not panic") {
            Ok(reply) => {
                assert_eq!(reply, "verack", "server answered with the wrong message");
                answered += 1;
            }
            Err(e) => failures.push(e),
        }
    }

    assert_eq!(
        answered,
        BURST,
        "{} of {BURST} version messages went unanswered: {:?} — the connection was not in the \
         map when the reader delivered the payload, so the bytes were dropped with no event \
         and no log",
        failures.len(),
        failures
    );
}

//! The dashboard's "message this peer" / "disconnect this peer" path on a Tor relay
//! connection.
//!
//! `AppState::send_to_peer` injects an action into one live connection through the same
//! executor the LLM path uses. **Zero LLM calls**: the relay carries an empty instruction and a
//! `*` static handler with no actions, and nothing here sends a cell the model would be asked
//! about.
//!
//! Unlike SMB, an injected verb on this relay genuinely reaches the wire: `send_destroy`
//! returns `ActionResult::Output` carrying a whole 514-byte DESTROY cell (tor-spec 5.4), which
//! `server::peer_support` writes to the connection's write half. The peer here is a real
//! rustls client — the connection is TLS, so asserting at the socket means decrypting — reusing
//! `peer.rs`'s `NoCertVerifier` and nothing else, because this test wants raw reads (an EOF
//! among them) rather than `RelayPeer`'s cell helpers.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features tor --test server -- tor_relay::peer_inject --test-threads=100

#![cfg(unix)]

use std::sync::Arc;
use std::time::Duration;

use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use netget::state::client_handles::ClientSendOutcome;
use netget::state::ServerId;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::ClientConfig;
use tokio_rustls::TlsConnector;

use super::peer::NoCertVerifier;

/// tor-spec 3: cell command numbers this test builds or checks.
const CELL_COMMAND_VERSIONS: u8 = 7;
const CELL_COMMAND_DESTROY: u8 = 4;
/// A v4 fixed-size cell.
const CELL_LEN: usize = 514;
/// The circuit id the injected DESTROY names. MSB set: the initiator picks it (tor-spec 5.1).
const CIRCUIT_ID: u32 = 0x8000_0001;
/// tor-spec 5.4 DESTROY reason: INTERNAL.
const DESTROY_REASON_INTERNAL: u8 = 2;

/// An `AppState` pointed at a port nothing listens on: any LLM call this test provoked would
/// fail loudly rather than reach a real backend.
async fn new_state() -> AppState {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".to_string());
    state
        .set_llm_client(netget::llm::OllamaClient::new(
            "http://127.0.0.1:1".to_string(),
        ))
        .await;
    state
}

/// A model-free relay: an empty instruction, and a `*` rule answering with no actions.
async fn start_relay(state: &AppState, tx: mpsc::UnboundedSender<String>) -> ServerId {
    ServerForm {
        protocol: "tor_relay".to_string(),
        port: Some(0),
        // `ServerForm::create` substitutes a default instruction for `None`, which makes the
        // server consult the model. An empty one is what "no model" actually looks like.
        instruction: Some(String::new()),
        event_handlers: Some(vec![serde_json::json!({
            "event_pattern": "*",
            "handler": { "type": "static", "actions": [] }
        })]),
        ..Default::default()
    }
    .create(state, tx)
    .await
    .expect("create tor_relay server")
}

async fn wait_for_port(state: &AppState, id: ServerId) -> u16 {
    for _ in 0..200 {
        if let Some(s) = state.get_server(id).await {
            if let Some(addr) = s.local_addr {
                return addr.port();
            }
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("Tor relay #{} never bound a port", id.as_u32());
}

/// The first connection that has a peer handle registered.
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
    panic!("Tor relay #{} never registered a peer handle", id.as_u32());
}

/// TLS to the relay, with no cell traffic of its own.
async fn tls_connect(port: u16) -> tokio_rustls::client::TlsStream<TcpStream> {
    let provider = Arc::new(tokio_rustls::rustls::crypto::aws_lc_rs::default_provider());
    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoCertVerifier))
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));
    let tcp = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .expect("tcp connect");
    connector
        .connect(
            ServerName::try_from("tor-relay.local").expect("server name"),
            tcp,
        )
        .await
        .expect("tls handshake")
}

async fn read_exactly(
    tls: &mut tokio_rustls::client::TlsStream<TcpStream>,
    n: usize,
    what: &str,
) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    tokio::time::timeout(Duration::from_secs(10), tls.read_exact(&mut buf))
        .await
        .unwrap_or_else(|_| panic!("timed out reading {what} ({n} bytes)"))
        .unwrap_or_else(|e| panic!("read error while reading {what}: {e}"));
    buf
}

/// Wait for the connection's counters to reach exactly these values.
///
/// The session updates `AppState` *after* the bytes are on the wire, so a client that has
/// already read them can still be ahead of the bookkeeping.
async fn wait_for_counters(
    state: &AppState,
    id: ServerId,
    conn: u32,
    received: u64,
    sent: u64,
    what: &str,
) {
    let mut last = (0u64, 0u64);
    for _ in 0..200 {
        if let Some(server) = state.get_server(id).await {
            if let Some(c) = server.connections.values().find(|c| c.id.as_u32() == conn) {
                last = (c.bytes_received, c.bytes_sent);
                if last == (received, sent) {
                    return;
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("after {what}, expected (received, sent) = ({received}, {sent}), got {last:?}");
}

#[tokio::test]
async fn injected_destroy_reaches_the_tls_socket_and_close_sends_eof() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();
    let server_id = start_relay(&state, tx.clone()).await;
    let port = wait_for_port(&state, server_id).await;

    let mut tls = tls_connect(port).await;

    // A relay says nothing until the peer sends VERSIONS, so the handle has to exist before
    // any cell has crossed: a manual rule can park what this connection raises for minutes and
    // the operator must be able to reach the peer while it waits.
    let conn = wait_for_peer_handle(&state, server_id).await;

    // The relay's own path, first, so the byte counters below have something from the session
    // itself to show. VERSIONS is answered in Rust (`handle_variable_cell`) — no model.
    let mut versions = Vec::with_capacity(11);
    versions.extend_from_slice(&0u16.to_be_bytes()); // VERSIONS uses a 2-byte circuit id
    versions.push(CELL_COMMAND_VERSIONS);
    versions.extend_from_slice(&6u16.to_be_bytes());
    for v in [3u16, 4, 5] {
        versions.extend_from_slice(&v.to_be_bytes());
    }
    tls.write_all(&versions).await.expect("write VERSIONS");
    tls.flush().await.expect("flush VERSIONS");

    let reply = read_exactly(&mut tls, 7, "the VERSIONS reply").await;
    assert_eq!(
        reply[2], CELL_COMMAND_VERSIONS,
        "the relay must answer VERSIONS with VERSIONS"
    );

    // Counters for the session's own traffic. Nothing counted either direction before this
    // change, so a relay with a peer on it drew 0/0 however much crossed the connection.
    wait_for_counters(&state, server_id, conn, 11, 7, "the VERSIONS exchange").await;

    // An injected wire verb. `send_destroy` is `ActionResult::Output`, so unlike SMB's
    // correlator-bound results it really does put bytes on this socket.
    let outcome = state
        .send_to_peer(
            server_id,
            conn,
            serde_json::json!({
                "type": "send_destroy",
                "circuit_id": format!("0x{CIRCUIT_ID:08x}"),
                "reason": DESTROY_REASON_INTERNAL
            }),
            Duration::from_secs(10),
        )
        .await
        .expect("send_to_peer");
    assert!(
        matches!(outcome, ClientSendOutcome::Sent { bytes_sent } if bytes_sent == CELL_LEN),
        "expected Sent{{{CELL_LEN}}} for an injected DESTROY, got {outcome:?}"
    );

    let cell = read_exactly(&mut tls, CELL_LEN, "the injected DESTROY cell").await;
    assert_eq!(
        u32::from_be_bytes([cell[0], cell[1], cell[2], cell[3]]),
        CIRCUIT_ID,
        "the DESTROY must carry the circuit id the injected action named"
    );
    assert_eq!(cell[4], CELL_COMMAND_DESTROY, "expected a DESTROY cell");
    assert_eq!(cell[5], DESTROY_REASON_INTERNAL, "reason byte");

    // The injected write is counted too — by `peer_support`, on the `Sent` outcome — so the
    // rail's up-counter moves for a message the operator sent from the dashboard.
    wait_for_counters(
        &state,
        server_id,
        conn,
        11,
        7 + CELL_LEN as u64,
        "the injected DESTROY",
    )
    .await;

    // "[ disconnect this peer ]": the dashboard sends a bare `close_connection`, and the
    // executor half-closes the write half.
    let outcome = state
        .send_to_peer(
            server_id,
            conn,
            serde_json::json!({"type": "close_connection"}),
            Duration::from_secs(10),
        )
        .await
        .expect("send_to_peer close");
    assert!(
        matches!(outcome, ClientSendOutcome::Disconnected),
        "expected Disconnected, got {outcome:?}"
    );

    let mut buf = [0u8; 16];
    let n = tokio::time::timeout(Duration::from_secs(10), tls.read(&mut buf))
        .await
        .expect("EOF within 10s")
        .expect("read after close");
    assert_eq!(n, 0, "expected EOF after close_connection");

    for _ in 0..200 {
        if !state.has_peer_handle(server_id, conn).await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("peer handle still registered after the connection closed");
}

/// The session's *own* exit path releases the handle and closes the connection entry — not
/// just the injected-close shortcut in `peer_support`. The peer simply hangs up.
#[tokio::test]
async fn the_session_releases_its_peer_handle_when_the_peer_hangs_up() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();
    let server_id = start_relay(&state, tx.clone()).await;
    let port = wait_for_port(&state, server_id).await;

    let mut tls = tls_connect(port).await;
    let conn = wait_for_peer_handle(&state, server_id).await;

    tls.shutdown().await.expect("client half-close");
    drop(tls);

    for _ in 0..200 {
        if !state.has_peer_handle(server_id, conn).await {
            let server = state.get_server(server_id).await.expect("server");
            let conn_state = server
                .connections
                .values()
                .find(|c| c.id.as_u32() == conn)
                .expect("connection still tracked after it closed");
            assert!(
                matches!(
                    conn_state.status,
                    netget::state::server::ConnectionStatus::Closed
                ),
                "the connection entry must be marked closed, got {:?}",
                conn_state.status
            );
            return;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("peer handle still registered after the peer hung up");
}

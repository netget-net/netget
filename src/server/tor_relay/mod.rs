//! Tor Relay (OR protocol) server - **partial, not interoperable with real Tor**.
//!
//! The link handshake stops after VERSIONS (no CERTS/AUTH_CHALLENGE/NETINFO), relay cell
//! digests are neither computed nor verified, and there is no EXTEND. See `CLAUDE.md` in this
//! directory for the full list of non-conformances. What is implemented:
//! - **Length-driven cell framing**: VERSIONS (2-byte circuit id, variable length) and
//!   commands >= 128 are framed by their length field rather than assumed to be 514 bytes,
//!   and the read is cancellation-safe inside the `select!`
//! - **ntor handshake** for circuit creation (CREATE2/CREATED2) with Curve25519 DH
//! - **Relay cell encryption** using AES-128-CTR with forward/backward keys
//! - **Circuit management** with crypto state and stream multiplexing
//! - **Exit relay functionality** (BEGIN, DATA, END, CONNECTED)
//! - **Bidirectional data forwarding** (TCP ↔ Tor client) via background tasks
//! - **SENDME flow control** at circuit and stream levels (tor-spec compliant)
//! - **Bandwidth tracking** per circuit and aggregate statistics
//! - **Channel-based architecture** for concurrent stream handling
//! - **LLM notification** on circuit creation and on unimplemented RELAY commands. The data
//!   path itself (BEGIN/DATA/END/SENDME, exit target selection) is decided in Rust, and no
//!   exit policy is enforced.
//!
//! ## Architecture
//!
//! ```text
//! TLS Connection (TorRelaySession)
//!     │
//!     ├─ tokio::select! loop
//!     │   ├─ Read TLS stream → Parse cells
//!     │   └─ Write from channel ← Forwarder tasks
//!     │
//!     ├─ CircuitManager (shared across connections)
//!     │   ├─ Circuit 1 (crypto + streams)
//!     │   │   ├─ Stream 1 → TCP connection
//!     │   │   ├─ Stream 2 → TCP connection
//!     │   │   └─ Flow control windows
//!     │   ├─ Circuit 2 (crypto + streams)
//!     │   └─ Statistics tracking
//!     │
//!     └─ Background forwarder tasks (per stream)
//!         └─ TCP → Encrypt → Channel → TLS
//! ```
//!
//! ## Cell Processing Flow
//!
//! 1. **CREATE2**: ntor handshake → CREATED2 response
//! 2. **RELAY/BEGIN**: Parse target → TCP connect → CONNECTED response
//! 3. **RELAY/DATA**: Decrypt → Forward to TCP (client→server) OR Encrypt ← TCP (server→client)
//! 4. **RELAY/END**: Close TCP connection
//! 5. **RELAY/SENDME**: Update flow control windows
//!
//! ## Flow Control (SENDME)
//!
//! - Circuit-level: 1000 cell window, SENDME every 100 cells
//! - Stream-level: 500 cell window, SENDME every 50 cells
//! - Automatic SENDME generation on receive thresholds
//! - Package window prevents overwhelming next hop
//!
//! **Status**: Experimental. Not a usable relay; see `CLAUDE.md`.

pub mod actions;
pub mod circuit;
pub mod stream;

use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, error, info, trace, warn};

#[cfg(unix)]
use crate::llm::action_helper::call_llm;
#[cfg(unix)]
use crate::llm::ollama_client::OllamaClient;
#[cfg(unix)]
use crate::llm::ActionResult;
#[cfg(unix)]
use crate::protocol::Event;
#[cfg(unix)]
use crate::server::TorRelayProtocol;
#[cfg(unix)]
use crate::state::app_state::AppState;
#[cfg(unix)]
use actions::{TOR_RELAY_CIRCUIT_CREATED_EVENT, TOR_RELAY_RELAY_CELL_EVENT};
#[cfg(unix)]
use circuit::{CircuitId, CircuitManager, StreamId};
#[cfg(unix)]
use stream::{build_relay_cell, connect_to_target, end_reason, parse_begin_target, relay_command};

#[cfg(unix)]
use crate::logging::emit::Log;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;

/// The write half of a peer's TLS stream, shared between the session loop and the dashboard's
/// peer-command task (`server::peer_support`).
#[cfg(unix)]
type SharedWrite = Arc<Mutex<tokio::io::WriteHalf<tokio_rustls::server::TlsStream<TcpStream>>>>;

/// Tor Relay server - handles OR protocol connections
pub struct TorRelayServer;

#[cfg(unix)]
impl TorRelayServer {
    /// Spawn Tor Relay server with LLM action integration
    pub async fn spawn_with_llm_actions(
        listen_addr: SocketAddr,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        server_id: crate::state::ServerId,
    ) -> Result<SocketAddr> {
        // Generate self-signed TLS certificate for OR protocol
        let (cert, key) = generate_tls_certificate()?;

        // Configure TLS acceptor
        // `ring`, which is the provider this tree compiles rustls with: `Cargo.toml` pins
        // `rustls`/`tokio-rustls` to `default-features = false, features = ["ring", ...]`
        // because the default `aws_lc_rs` is a C library that does not build for wasm32, and
        // every other TLS site here (`tls`, `dot`, `proxy`, `openvpn`, the binary's own
        // `install_default`) uses `ring` for that reason. Naming `aws_lc_rs` here did not
        // select a different provider - it did not compile at all, so `--features tor` was a
        // hard build error on its own and only ever got as far as a feature set that happened
        // to turn the `aws_lc_rs` feature back on.
        let crypto_provider = tokio_rustls::rustls::crypto::ring::default_provider();
        let tls_config = ServerConfig::builder_with_provider(Arc::new(crypto_provider))
            // TLS 1.2 as well as 1.3. A real Tor relay accepts both -- the link
            // specification's minimum is 1.2 -- and restricted to 1.3 alone this server
            // rejected every peer that sent a 1.2 ClientHello with
            // `SupportedVersionsExtensionRequired`, which is rustls saying "this hello has
            // no supported_versions extension" and reads like a peer bug rather than our
            // own configuration.
            .with_protocol_versions(&[
                &tokio_rustls::rustls::version::TLS13,
                &tokio_rustls::rustls::version::TLS12,
            ])
            .expect("Valid TLS protocol versions")
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .context("Failed to create TLS config")?;

        let acceptor = TlsAcceptor::from(Arc::new(tls_config));

        // Bind TCP listener
        let listener = TcpListener::bind(listen_addr)
            .await
            .context("Failed to bind Tor Relay server")?;

        let actual_addr = listener
            .local_addr()
            .context("Failed to get local address")?;

        Log::new(Some(&status_tx)).info(format!(
            "Tor Relay (OR protocol) server listening on {}",
            actual_addr
        ));

        // Create circuit manager (shared across all connections)
        let circuit_manager = Arc::new(CircuitManager::new());

        // Publish the relay identity.
        //
        // The ntor handshake mixes the relay's identity fingerprint (ID) and its onion
        // public key (B) into `secret_input`, so a peer that does not know both cannot
        // derive the same key material — it gets a CREATED2 it can do nothing with. A real
        // relay publishes them in its router descriptor. This one generates a fresh onion
        // key per process and used to print only the fingerprint, which meant **no peer
        // could ever complete a circuit with it**. Both are public values by design.
        let fingerprint = circuit_manager.identity_fingerprint();
        let onion_key = *circuit_manager.onion_public_key().as_bytes();
        Log::new(Some(&status_tx)).info(format!("Relay fingerprint: {}", hex::encode(fingerprint)));
        Log::new(Some(&status_tx)).info(format!("Relay onion key: {}", hex::encode(onion_key)));

        let protocol = Arc::new(TorRelayProtocol::new());

        // Spawn connection handler
        let task_registrar = app_state.clone();
        let limiter = crate::server::accept_bounded::ConnectionLimiter::new(MAX_CONNECTIONS);
        let accept_handle = tokio::spawn(async move {
            loop {
                match crate::server::accept_bounded::accept_bounded(
                    &listener,
                    &limiter,
                    CONNECTION_CAP_REFUSAL,
                    "Tor Relay",
                    Some(&status_tx),
                )
                .await
                {
                    Ok((stream, remote_addr, permit)) => {
                        let connection_id = crate::server::connection::ConnectionId::new(
                            app_state.get_next_unified_id().await,
                        );
                        Log::new(Some(&status_tx)).debug(format!(
                            "Tor Relay connection {} from {}",
                            connection_id, remote_addr
                        ));

                        let llm_clone = llm_client.clone();
                        let state_clone = app_state.clone();
                        let status_clone = status_tx.clone();
                        let acceptor_clone = acceptor.clone();
                        let protocol_clone = protocol.clone();
                        let circuit_mgr_clone = circuit_manager.clone();

                        // Tracked, not detached: stop_server must abort this task too.
                        let task_owner = app_state.clone();
                        task_owner
                            .spawn_server_task(server_id, async move {
                                // Held for the life of the connection, so the cap counts live
                                // peers rather than accepts.
                                let _permit = permit;
                                if let Err(e) = handle_tor_relay_connection(
                                    stream,
                                    connection_id,
                                    server_id,
                                    remote_addr,
                                    acceptor_clone,
                                    llm_clone,
                                    state_clone,
                                    status_clone,
                                    protocol_clone,
                                    circuit_mgr_clone,
                                )
                                .await
                                {
                                    error!("Tor Relay connection error: {}", e);
                                }
                            })
                            .await;
                    }
                    Err(e) => {
                        Log::new(Some(&status_tx))
                            .error(format!("Failed to accept Tor Relay connection: {}", e));
                    }
                }
            }
        });

        task_registrar
            .register_server_task(server_id, accept_handle)
            .await;

        Ok(actual_addr)
    }
}

#[cfg(not(unix))]
impl TorRelayServer {
    pub async fn spawn_with_llm_actions(
        _listen_addr: SocketAddr,
        _llm_client: OllamaClient,
        _app_state: Arc<AppState>,
        _status_tx: mpsc::UnboundedSender<String>,
        _server_id: crate::state::ServerId,
    ) -> Result<SocketAddr> {
        anyhow::bail!("Tor Relay feature not enabled")
    }
}

/// Generate self-signed TLS certificate for OR protocol
fn generate_tls_certificate() -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>)> {
    use rcgen::{CertificateParams, KeyPair};

    let mut params = CertificateParams::new(vec!["tor-relay.local".to_string()])?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "NetGet Tor Relay");

    let key_pair = KeyPair::generate()?;
    let cert = params.self_signed(&key_pair)?;

    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(key_pair.serialize_der().into());

    Ok((cert_der, key_der))
}

/// Handle individual Tor Relay connection.
///
/// Owns the connection's bookkeeping: the `AppState` entry the dashboard draws the peer row
/// from, and the peer handle that row's `[ message ]` / `[ disconnect ]` buttons need. Both
/// are released here on **every** exit, including a failed TLS handshake, so nothing is left
/// listed as live after the socket has gone.
#[allow(clippy::too_many_arguments)]
async fn handle_tor_relay_connection(
    stream: TcpStream,
    connection_id: crate::server::connection::ConnectionId,
    server_id: crate::state::ServerId,
    remote_addr: SocketAddr,
    acceptor: TlsAcceptor,
    llm_client: OllamaClient,
    app_state: Arc<AppState>,
    status_tx: mpsc::UnboundedSender<String>,
    protocol: Arc<TorRelayProtocol>,
    circuit_manager: Arc<CircuitManager>,
) -> Result<()> {
    // Track the connection. Nothing did this before, so a relay with peers on it showed an
    // empty peer list, no byte counters, and no row for the dashboard to hang a
    // "[ message this peer ]" button on.
    let local_addr = stream
        .local_addr()
        .unwrap_or_else(|_| "0.0.0.0:0".parse().expect("0.0.0.0:0 parses"));
    let now = crate::utils::clock::Instant::now();
    app_state
        .add_connection_to_server(
            server_id,
            crate::state::server::ConnectionState {
                id: connection_id,
                remote_addr,
                local_addr,
                bytes_sent: 0,
                bytes_received: 0,
                packets_sent: 0,
                packets_received: 0,
                last_activity: now,
                status: crate::state::server::ConnectionStatus::Active,
                status_changed_at: now,
                protocol_info: crate::state::server::ProtocolConnectionInfo::empty(),
            },
        )
        .await;
    let _ = status_tx.send("__UPDATE_UI__".to_string());

    let result = run_tor_relay_connection(
        stream,
        connection_id,
        server_id,
        remote_addr,
        acceptor,
        llm_client,
        app_state.clone(),
        status_tx.clone(),
        protocol,
        circuit_manager,
    )
    .await;

    // Every exit path lands here - a TLS handshake that never completed, a clean close, a cell
    // error that returned `Err`, an injected disconnect. Idempotent with the peer task's own
    // close path.
    app_state
        .remove_peer_handle(server_id, connection_id.as_u32())
        .await;
    app_state
        .update_connection_status(
            server_id,
            connection_id,
            crate::state::server::ConnectionStatus::Closed,
        )
        .await;
    let _ = status_tx.send("__UPDATE_UI__".to_string());

    result
}

/// The TLS handshake and the session itself. Split out so its `?` paths cannot skip the
/// teardown in [`handle_tor_relay_connection`].
#[allow(clippy::too_many_arguments)]
async fn run_tor_relay_connection(
    stream: TcpStream,
    connection_id: crate::server::connection::ConnectionId,
    server_id: crate::state::ServerId,
    remote_addr: SocketAddr,
    acceptor: TlsAcceptor,
    llm_client: OllamaClient,
    app_state: Arc<AppState>,
    status_tx: mpsc::UnboundedSender<String>,
    protocol: Arc<TorRelayProtocol>,
    circuit_manager: Arc<CircuitManager>,
) -> Result<()> {
    // Perform TLS handshake
    let tls_stream = match acceptor.accept(stream).await {
        Ok(s) => {
            Log::new(Some(&status_tx)).info(format!("TLS handshake completed for {}", remote_addr));
            s
        }
        Err(e) => {
            // Handshake failure is a client-side condition, not a server error: WARN.
            Log::new(Some(&status_tx))
                .warn(format!("TLS handshake failed for {}: {}", remote_addr, e));
            return Err(e.into());
        }
    };

    // Split the TLS stream (never clone it). The reader stays with the session's `select!`
    // loop; the write half is shared with the peer-command task through an `Arc<Mutex<..>>`,
    // which is the only lock either side takes and is never held across an `.await` that does
    // anything but the write itself. Note the difference from `spawn_stream_forwarder` below:
    // there a lock is held over a whole *exit* TcpStream whose task parks in `read()`, which
    // is why only the read half is taken there. Here nothing reads through the mutex.
    let (reader, writer) = tokio::io::split(tls_stream);
    let write_half: SharedWrite = Arc::new(Mutex::new(writer));

    // Peer messaging: registered BEFORE the first cell is read. A relay says nothing until the
    // peer sends VERSIONS, and a manual `*` rule parks the events this connection raises for
    // minutes - the operator has to be able to reach, or hang up, a connection that is waiting
    // on their own answer.
    let peer_rx = crate::server::peer_support::register_peer_channel(
        &app_state,
        server_id,
        connection_id.as_u32(),
    )
    .await;
    crate::server::peer_support::spawn_peer_command_task(
        peer_rx,
        protocol.clone(),
        app_state.clone(),
        server_id,
        connection_id.as_u32(),
        write_half.clone(),
        status_tx.clone(),
    );

    // Create channel for outgoing cells
    let (outgoing_tx, outgoing_rx) = mpsc::unbounded_channel();

    let mut session = TorRelaySession {
        reader,
        write_half: write_half.clone(),
        connection_id,
        server_id,
        remote_addr,
        llm_client,
        app_state,
        status_tx,
        protocol,
        circuit_manager,
        outgoing_tx,
        outgoing_rx,
    };

    let result = session.handle().await;

    // Make the FIN immediate rather than waiting for the peer task to drop its clone.
    let _ = write_half.lock().await.shutdown().await;
    result
}

/// Tor Relay session handler
struct TorRelaySession {
    /// Read half of the TLS stream, owned outright by the `select!` loop.
    reader: tokio::io::ReadHalf<tokio_rustls::server::TlsStream<TcpStream>>,
    /// Write half, shared with the dashboard's peer-command task.
    write_half: SharedWrite,
    connection_id: crate::server::connection::ConnectionId,
    server_id: crate::state::ServerId,
    remote_addr: SocketAddr,
    llm_client: OllamaClient,
    app_state: Arc<AppState>,
    status_tx: mpsc::UnboundedSender<String>,
    protocol: Arc<TorRelayProtocol>,
    circuit_manager: Arc<CircuitManager>,
    /// Channel for sending outgoing cells (from forwarder tasks)
    outgoing_tx: mpsc::UnboundedSender<Vec<u8>>,
    outgoing_rx: mpsc::UnboundedReceiver<Vec<u8>>,
}

impl TorRelaySession {
    /// Handle Tor Relay session - read cells and process.
    ///
    /// Two properties this loop has to hold, both of which it used to break:
    ///
    /// 1. **Framing follows the cell, not a fixed size.** It used to `read_exact` into a
    ///    514-byte buffer, so the first thing a real Tor client sends - an 11-byte VERSIONS
    ///    cell - blocked it forever and `tor` logged `died in state handshaking`. Any
    ///    variable-length cell (VERSIONS, or command >= 128) did the same.
    /// 2. **The read is cancellation-safe.** `read_exact` is not: dropping it mid-cell when
    ///    the `outgoing_rx` branch of the `select!` wins discards the bytes already taken
    ///    off the TLS stream, permanently desynchronising the connection. `read` is
    ///    cancel-safe, so bytes are accumulated in `inbuf` and cells are framed out of it.
    async fn handle(&mut self) -> Result<()> {
        debug!("Tor Relay session started for {}", self.remote_addr);

        let mut inbuf: Vec<u8> = Vec::with_capacity(4096);
        let mut read_buf = vec![0u8; 4096];
        // False until the peer has sent anything at all; see FIRST_CELL_READ_TIMEOUT.
        let mut seen_cell = false;
        // Only the first cell of a connection may be a VERSIONS cell, and only a VERSIONS
        // cell uses a 2-byte circuit id (tor-spec 3). After it, framing is unambiguous.
        let mut expecting_versions = true;

        loop {
            // Drain every complete cell already buffered before waiting for more bytes.
            while let Some(cell) = take_cell(&mut inbuf, expecting_versions) {
                expecting_versions = false;

                match cell {
                    FramedCell::Variable {
                        command, payload, ..
                    } => {
                        if let Some(response) = self.handle_variable_cell(command, &payload) {
                            self.write_counted(&response).await?;
                        }
                    }
                    FramedCell::Fixed { circuit_id, raw } => {
                        let Some(cell_info) = parse_tor_cell(&raw) else {
                            warn!("Failed to parse Tor cell from {}", self.remote_addr);
                            continue;
                        };
                        debug!(
                            "Tor cell: type={}, circuit_id={}",
                            cell_info.cell_type, cell_info.circuit_id
                        );

                        match self.handle_cell(cell_info, &raw).await {
                            Ok(Some(response)) => {
                                self.write_counted(&response).await?;
                                debug!("Sent response cell ({} bytes)", response.len());
                            }
                            Ok(None) => {}
                            Err(e) => {
                                error!("Failed to handle cell: {}", e);
                                let destroy = self.create_destroy_cell(circuit_id);
                                self.write_counted(&destroy).await?;
                                return Err(e);
                            }
                        }
                    }
                }
            }

            // Re-arm the idle deadline for the wait that follows. It is set here, immediately
            // before the `select!`, rather than kept running across the loop body — and that is
            // deliberate: `handle_cell` above awaits the model, and may park the cell for a
            // human at the dashboard (`src/state/intercepts.rs`, 300s by default). Arming the
            // clock only over the wait means none of that time is ever counted as idle, so an
            // answer that takes minutes cannot close the connection it is an answer for.
            let idle_bound = if seen_cell {
                IDLE_BETWEEN_CELLS_TIMEOUT
            } else {
                FIRST_CELL_READ_TIMEOUT
            };
            let idle_deadline = tokio::time::sleep(idle_bound);
            tokio::pin!(idle_deadline);

            tokio::select! {
                // Nothing at all from the peer, and nothing to send it, for the whole bound.
                _ = &mut idle_deadline => {
                    Log::new(Some(&self.status_tx)).info(format!(
                        "Tor Relay peer {} sent nothing for {}s; closing idle connection",
                        self.remote_addr,
                        idle_bound.as_secs()
                    ));
                    return Ok(());
                }

                // Read incoming bytes from the TLS stream. `read` is cancel-safe: if the
                // other branch wins, nothing has been consumed.
                read_result = self.reader.read(&mut read_buf) => {
                    match read_result {
                        Ok(0) => {
                            Log::new(Some(&self.status_tx)).info(format!(
                                "Tor Relay connection closed by {}",
                                self.remote_addr
                            ));
                            return Ok(());
                        }
                        Ok(n) => {
                            seen_cell = true;
                            trace!("Received {} bytes from {}", n, self.remote_addr);
                            // The rail's down-counter and the peer row's last_activity read
                            // these; nothing updated them before, so every relay connection
                            // showed 0/0 however much traffic crossed it.
                            self.app_state
                                .update_connection_stats(
                                    self.server_id,
                                    self.connection_id,
                                    Some(n as u64),
                                    None,
                                    Some(1),
                                    None,
                                )
                                .await;
                            inbuf.extend_from_slice(&read_buf[..n]);
                        }
                        Err(e) => {
                            error!("Failed to read Tor cell from {}: {}", self.remote_addr, e);
                            return Err(e.into());
                        }
                    }
                }

                // Send outgoing cells from forwarder tasks
                Some(cell) = self.outgoing_rx.recv() => {
                    trace!("Sending outgoing cell ({} bytes)", cell.len());
                    self.write_counted(&cell).await?;
                }
            }
        }
    }

    /// Write one cell to the peer and count it.
    ///
    /// The guard is dropped before the stats update, so nothing awaits `AppState` while
    /// holding the write half - the peer-command task needs the same lock to inject a cell or
    /// a disconnect. A cell must reach the wire whole: a short write desynchronises the peer's
    /// framing for the rest of the connection, which is why the lock is taken around
    /// `write_all` + `flush` together rather than per call.
    async fn write_counted(&self, data: &[u8]) -> Result<()> {
        {
            let mut writer = self.write_half.lock().await;
            writer.write_all(data).await?;
            writer.flush().await?;
        }
        self.app_state
            .update_connection_stats(
                self.server_id,
                self.connection_id,
                None,
                Some(data.len() as u64),
                None,
                Some(1),
            )
            .await;
        Ok(())
    }

    /// Handle a variable-length cell.
    ///
    /// VERSIONS is answered so that a peer's first cell no longer goes unacknowledged. The
    /// rest of the link handshake (CERTS, AUTH_CHALLENGE, NETINFO) is still not implemented,
    /// so a real Tor client gets this far and then gives up - which is a great deal better
    /// than the reader blocking forever, but is still not interoperability.
    fn handle_variable_cell(&self, command: u8, payload: &[u8]) -> Option<Vec<u8>> {
        match command {
            CELL_COMMAND_VERSIONS => {
                let offered: Vec<u16> = payload
                    .chunks_exact(2)
                    .map(|c| u16::from_be_bytes([c[0], c[1]]))
                    .collect();
                Log::new(Some(&self.status_tx))
                    .info(format!("Received VERSIONS cell offering {:?}", offered));

                if !offered.contains(&LINK_PROTOCOL_VERSION) {
                    warn!(
                        "Peer offered link versions {:?}, none of which is {}",
                        offered, LINK_PROTOCOL_VERSION
                    );
                }

                // VERSIONS always uses a 2-byte circuit id (tor-spec 3).
                let mut cell = Vec::with_capacity(7);
                cell.extend_from_slice(&0u16.to_be_bytes());
                cell.push(CELL_COMMAND_VERSIONS);
                cell.extend_from_slice(&2u16.to_be_bytes());
                cell.extend_from_slice(&LINK_PROTOCOL_VERSION.to_be_bytes());
                Some(cell)
            }
            _ => {
                warn!(
                    "Ignoring variable-length cell command {} ({} byte payload): the link \
                     handshake past VERSIONS is not implemented",
                    command,
                    payload.len()
                );
                None
            }
        }
    }

    /// Handle individual cell based on type
    async fn handle_cell(
        &mut self,
        cell_info: TorCellInfo,
        cell_data: &[u8],
    ) -> Result<Option<Vec<u8>>> {
        match cell_info.cell_type.as_str() {
            "CREATE2" => self.handle_create2(cell_info.circuit_id, cell_data).await,
            "RELAY" | "RELAY_EARLY" => self.handle_relay(cell_info.circuit_id, cell_data).await,
            "DESTROY" => {
                debug!(
                    "Received DESTROY for circuit {}",
                    cell_info.circuit_id.as_u32()
                );
                self.circuit_manager
                    .destroy_circuit(cell_info.circuit_id)
                    .await;
                Ok(None)
            }
            "PADDING" => {
                trace!("Received PADDING cell");
                Ok(None)
            }
            _ => {
                warn!("Unhandled cell type: {}", cell_info.cell_type);
                Ok(None)
            }
        }
    }

    /// Handle CREATE2 cell
    async fn handle_create2(
        &mut self,
        circuit_id: CircuitId,
        cell_data: &[u8],
    ) -> Result<Option<Vec<u8>>> {
        debug!("Processing CREATE2 for circuit {}", circuit_id.as_u32());

        // Parse CREATE2 cell:
        // CircID (4) | Command (1) | HTYPE (2) | HLEN (2) | HDATA (HLEN)
        if cell_data.len() < 9 {
            return Err(anyhow::anyhow!("CREATE2 cell too short"));
        }

        let htype = u16::from_be_bytes([cell_data[5], cell_data[6]]);
        let hlen = u16::from_be_bytes([cell_data[7], cell_data[8]]);

        if htype != 0x0002 {
            // ntor
            return Err(anyhow::anyhow!("Unsupported handshake type: {}", htype));
        }

        if hlen != 84 {
            // ntor client handshake is 84 bytes (ID:20 + B:32 + X:32)
            return Err(anyhow::anyhow!("Invalid ntor handshake length: {}", hlen));
        }

        // Extract client's X (last 32 bytes of handshake data)
        let handshake_start = 9;
        let handshake_end = handshake_start + hlen as usize;
        if cell_data.len() < handshake_end {
            return Err(anyhow::anyhow!("Handshake data incomplete"));
        }

        let handshake_data = &cell_data[handshake_start..handshake_end];
        // ntor handshake: ID(20) + B(32) + X(32)
        let client_x: [u8; 32] = handshake_data[52..84].try_into()?;

        // Perform ntor handshake via circuit manager
        let (y, auth) = self
            .circuit_manager
            .handle_create2(circuit_id, client_x)
            .await?;

        Log::new(Some(&self.status_tx)).info(format!(
            "Circuit {} created successfully",
            circuit_id.as_u32()
        ));

        // Log relay statistics (summary: file-only)
        let stats = self.circuit_manager.get_relay_stats().await;
        Log::new(Some(&self.status_tx)).debug(format!(
            "Relay stats: {} circuits, {} streams, sent={} received={}",
            stats.total_circuits,
            stats.total_streams,
            stats.total_bytes_sent,
            stats.total_bytes_received
        ));

        // Send event to LLM
        let event = Event::new(
            &TOR_RELAY_CIRCUIT_CREATED_EVENT,
            serde_json::json!({
                "circuit_id": format!("0x{:08x}", circuit_id.as_u32()),
                "client_ip": self.remote_addr.ip().to_string(),
            }),
        );

        // Act on what the LLM decides. Discarding this result was why the circuit-created
        // event had no effect at all.
        match call_llm(
            &self.llm_client,
            &self.app_state,
            self.server_id,
            Some(self.connection_id),
            &event,
            self.protocol.as_ref(),
        )
        .await
        {
            Ok(execution_result) => {
                for message in execution_result.messages {
                    let _ = self.status_tx.send(message);
                }
                for protocol_result in execution_result.protocol_results {
                    match protocol_result {
                        // A DESTROY chosen here replaces the CREATED2 we were about to send.
                        ActionResult::Output(data) => {
                            info!(
                                "Tor relay circuit 0x{:08x}: CREATE2 answered by the model's \
                                 own cell decision=model_answer",
                                circuit_id.as_u32()
                            );
                            return Ok(Some(data));
                        }
                        ActionResult::CloseConnection => {
                            info!(
                                "Tor relay circuit 0x{:08x}: model closed the connection on \
                                 CREATE2 decision=model_reject",
                                circuit_id.as_u32()
                            );
                            self.circuit_manager.destroy_circuit(circuit_id).await;
                            return Err(anyhow::anyhow!("LLM requested close"));
                        }
                        _ => {}
                    }
                }
            }
            Err(e) => {
                // CREATED2 is admission: it completes the ntor handshake and hands the peer a
                // circuit it will build on. The model was asked whether to admit this one and
                // gave no answer, so admitting it anyway would turn a backend outage into
                // "every circuit accepted". Tear it down instead, in Tor's own vocabulary:
                // DESTROY (tor-spec 5.4) with reason 2 INTERNAL — the fault is the relay's,
                // not the client's and not a protocol violation. The circuit's crypto state
                // is dropped too, so what this relay believes and what the peer was told agree.
                //
                // Non-fatal to the connection: a DESTROY is the wire answer, so WARN.
                Log::new(Some(&self.status_tx)).warn(format!(
                    "Tor relay circuit 0x{:08x}: LLM call failed on CREATE2 ({}) - sent DESTROY \
                     (reason 2 INTERNAL) decision=fail_closed_llm_error",
                    circuit_id.as_u32(),
                    e
                ));
                self.circuit_manager.destroy_circuit(circuit_id).await;
                return Ok(Some(self.create_destroy_cell_with_reason(
                    circuit_id,
                    DESTROY_REASON_INTERNAL,
                )));
            }
        }

        info!(
            "Tor relay circuit 0x{:08x}: CREATED2 sent decision=model_answer",
            circuit_id.as_u32()
        );

        // Build CREATED2 response
        // CircID (4) | Command (1) | HLEN (2) | HDATA (HLEN)
        let mut response = Vec::with_capacity(71);
        response.extend_from_slice(&circuit_id.to_bytes());
        response.push(11); // CREATED2 command (tor-spec 3; 10 is CREATE2)
        response.extend_from_slice(&64u16.to_be_bytes()); // HLEN = 64 (Y:32 + AUTH:32)
        response.extend_from_slice(&y);
        response.extend_from_slice(&auth);

        // Pad to 514 bytes
        response.resize(514, 0);

        Ok(Some(response))
    }

    /// Handle RELAY cell
    async fn handle_relay(
        &mut self,
        circuit_id: CircuitId,
        cell_data: &[u8],
    ) -> Result<Option<Vec<u8>>> {
        trace!("Processing RELAY cell for circuit {}", circuit_id.as_u32());

        // Extract relay payload (skip CircID:4 + Command:1)
        let mut relay_payload = cell_data[5..514].to_vec();

        // Decrypt relay cell
        self.circuit_manager
            .decrypt_relay_cell(circuit_id, &mut relay_payload)
            .await?;

        // Track bytes received from client (entire cell)
        let _ = self.circuit_manager.record_received(circuit_id, 509).await;

        // Track RELAY cell for circuit-level flow control - send SENDME if needed
        let send_circuit_sendme = self
            .circuit_manager
            .record_relay_received(circuit_id)
            .await
            .unwrap_or(false);
        if send_circuit_sendme {
            debug!(
                "Sending circuit-level SENDME for circuit {}",
                circuit_id.as_u32()
            );
            let sendme_cell = build_relay_cell(
                circuit_id.as_u32(),
                0, // Stream ID 0 for circuit-level SENDME
                relay_command::SENDME,
                &[],
            );
            let mut encrypted = sendme_cell.clone();
            self.circuit_manager
                .encrypt_relay_cell(circuit_id, &mut encrypted[5..514])
                .await?;
            let _ = self.outgoing_tx.send(encrypted);
        }

        // Parse relay cell header:
        // Command (1) | Recognized (2) | StreamID (2) | Digest (4) | Length (2) | Data (Length)
        if relay_payload.len() < 11 {
            return Err(anyhow::anyhow!("RELAY cell too short"));
        }

        let relay_cmd = relay_payload[0];
        let recognized = u16::from_be_bytes([relay_payload[1], relay_payload[2]]);
        let stream_id_u16 = u16::from_be_bytes([relay_payload[3], relay_payload[4]]);
        let stream_id = StreamId::new(stream_id_u16);
        let length = u16::from_be_bytes([relay_payload[9], relay_payload[10]]) as usize;

        // `length` comes from the decrypted payload, so it is whatever the peer's ciphertext
        // decrypts to - up to 65535 - while the payload is only 509 bytes. Slicing on it
        // unchecked panicked the connection task on essentially any malformed or
        // wrongly-keyed cell.
        if 11 + length > relay_payload.len() {
            warn!(
                "RELAY cell on circuit {} declares {} bytes of data but only {} remain; dropping",
                circuit_id.as_u32(),
                length,
                relay_payload.len().saturating_sub(11)
            );
            return Ok(None);
        }
        let data = &relay_payload[11..11 + length];

        // Check if this cell is for us (recognized should be 0)
        if recognized != 0 {
            // Not for us, would normally forward but we're endpoint
            trace!("RELAY cell not recognized, dropping");
            return Ok(None);
        }

        let relay_cmd_name = match relay_cmd {
            relay_command::BEGIN => "BEGIN",
            relay_command::DATA => "DATA",
            relay_command::END => "END",
            relay_command::CONNECTED => "CONNECTED",
            relay_command::SENDME => "SENDME",
            relay_command::EXTEND => "EXTEND",
            relay_command::EXTENDED => "EXTENDED",
            relay_command::TRUNCATE => "TRUNCATE",
            relay_command::TRUNCATED => "TRUNCATED",
            relay_command::DROP => "DROP",
            relay_command::RESOLVE => "RESOLVE",
            relay_command::RESOLVED => "RESOLVED",
            relay_command::BEGIN_DIR => "BEGIN_DIR",
            _ => "UNKNOWN",
        };

        debug!(
            "RELAY cell: command={} ({}), stream={}, length={}",
            relay_cmd,
            relay_cmd_name,
            stream_id.as_u16(),
            length
        );

        // Handle specific relay commands
        match relay_cmd {
            relay_command::BEGIN => {
                return self.handle_begin_cell(circuit_id, stream_id, data).await;
            }
            relay_command::BEGIN_DIR => {
                return self.handle_begin_dir_cell(circuit_id, stream_id).await;
            }
            relay_command::DATA => {
                return self.handle_data_cell(circuit_id, stream_id, data).await;
            }
            relay_command::END => {
                return self.handle_end_cell(circuit_id, stream_id, data).await;
            }
            relay_command::SENDME => {
                return self.handle_sendme_cell(circuit_id, stream_id).await;
            }
            _ => {
                // For other commands, send event to LLM
                let event = Event::new(
                    &TOR_RELAY_RELAY_CELL_EVENT,
                    serde_json::json!({
                        "circuit_id": format!("0x{:08x}", circuit_id.as_u32()),
                        "relay_command": relay_cmd_name,
                        "stream_id": stream_id.as_u16(),
                        "length": length,
                        "client_ip": self.remote_addr.ip().to_string(),
                    }),
                );

                // Get LLM response for how to handle this
                match call_llm(
                    &self.llm_client,
                    &self.app_state,
                    self.server_id,
                    Some(self.connection_id),
                    &event,
                    self.protocol.as_ref(),
                )
                .await
                {
                    Ok(execution_result) => {
                        for message in execution_result.messages {
                            let _ = self.status_tx.send(message);
                        }
                        // Execute protocol actions
                        for protocol_result in execution_result.protocol_results {
                            match protocol_result {
                                ActionResult::Output(data) => {
                                    debug!(
                                        "Tor relay circuit 0x{:08x}: RELAY {} answered \
                                         decision=model_answer",
                                        circuit_id.as_u32(),
                                        relay_cmd_name
                                    );
                                    return Ok(Some(data));
                                }
                                ActionResult::CloseConnection => {
                                    info!(
                                        "Tor relay circuit 0x{:08x}: model closed the \
                                         connection on RELAY {} decision=model_reject",
                                        circuit_id.as_u32(),
                                        relay_cmd_name
                                    );
                                    return Err(anyhow::anyhow!("LLM requested close"));
                                }
                                _ => {}
                            }
                        }
                        debug!(
                            "Tor relay circuit 0x{:08x}: RELAY {} left unanswered by the model \
                             decision=model_silent",
                            circuit_id.as_u32(),
                            relay_cmd_name
                        );
                    }
                    Err(e) => {
                        // This branch is reached only for RELAY commands the relay does not
                        // implement itself (EXTEND, TRUNCATE, RESOLVE, DROP, ...), so the
                        // model was the entire answer. Swallowing the error left the peer
                        // waiting on a circuit that would never say anything again.
                        //
                        // Tor's own vocabulary for "this relay cannot carry on with your
                        // circuit" is DESTROY (tor-spec 5.4), with reason 2 INTERNAL: an
                        // error at the relay, not at the client and not a protocol violation.
                        // It needs no relay-cell encryption, so it is still deliverable when
                        // the circuit crypto is the thing that is unhappy, and it is the one
                        // answer that cannot be mistaken for the EXTENDED/RESOLVED/TRUNCATED
                        // the peer asked for. There is no "try again" cell here to express an
                        // overload with, so overload and outage are answered identically and
                        // distinguished only in the log.
                        // Non-fatal: a DESTROY cell (reason 2 INTERNAL) is the wire answer, so WARN.
                        Log::new(Some(&self.status_tx)).warn(format!(
                            "Tor relay circuit 0x{:08x}: LLM call failed on RELAY {} ({}) - sent \
                             DESTROY (reason 2 INTERNAL) decision=fail_closed_llm_error",
                            circuit_id.as_u32(),
                            relay_cmd_name,
                            e
                        ));
                        if crate::llm::is_overload_error(&e) {
                            warn!(
                                "Tor relay circuit {} destroyed: LLM capacity exhausted",
                                circuit_id.as_u32()
                            );
                        }
                        // Drop the circuit's own state too, so the DESTROY we send and what
                        // this relay believes are the same thing.
                        self.circuit_manager.destroy_circuit(circuit_id).await;
                        return Ok(Some(self.create_destroy_cell_with_reason(
                            circuit_id,
                            DESTROY_REASON_INTERNAL,
                        )));
                    }
                }
            }
        }

        // Default: no response
        Ok(None)
    }

    /// Handle BEGIN cell - establish TCP connection to target
    async fn handle_begin_cell(
        &mut self,
        circuit_id: CircuitId,
        stream_id: StreamId,
        data: &[u8],
    ) -> Result<Option<Vec<u8>>> {
        // Parse target address
        let target = parse_begin_target(data)?;

        Log::new(Some(&self.status_tx)).info(format!(
            "BEGIN stream {} on circuit {} to {}",
            stream_id.as_u16(),
            circuit_id.as_u32(),
            target
        ));

        // Create stream in circuit manager.
        //
        // A refusal here is a per-stream condition, not a per-circuit one: the peer has hit
        // MAX_STREAMS_PER_CIRCUIT, or reused a live stream id. Answer END/RESOURCE_LIMIT and
        // keep the circuit up. Propagating with `?` would take the whole connection down
        // through the DESTROY path in `handle()`, which hands a peer that opens too many
        // streams a way to kill everything else riding the same circuit.
        if let Err(e) = self
            .circuit_manager
            .create_stream(circuit_id, stream_id, target.clone())
            .await
        {
            Log::new(Some(&self.status_tx)).warn(format!(
                "Refusing BEGIN stream {} on circuit {}: {}",
                stream_id.as_u16(),
                circuit_id.as_u32(),
                e
            ));
            let end_cell = build_relay_cell(
                circuit_id.as_u32(),
                stream_id.as_u16(),
                relay_command::END,
                &[end_reason::RESOURCE_LIMIT],
            );
            let mut encrypted = end_cell.clone();
            self.circuit_manager
                .encrypt_relay_cell(circuit_id, &mut encrypted[5..514])
                .await?;
            let _ = self.circuit_manager.record_sent(circuit_id, 509).await;
            return Ok(Some(encrypted));
        }

        // Attempt to connect to target
        match connect_to_target(&target).await {
            Ok(tcp_stream) => {
                Log::new(Some(&self.status_tx)).info(format!(
                    "Connected to {} for stream {}",
                    target,
                    stream_id.as_u16()
                ));

                // Store TCP connection in stream
                self.circuit_manager
                    .set_stream_active(circuit_id, stream_id, tcp_stream)
                    .await?;

                // Build CONNECTED response
                let connected_cell = build_relay_cell(
                    circuit_id.as_u32(),
                    stream_id.as_u16(),
                    relay_command::CONNECTED,
                    &[],
                );

                // Encrypt response
                let mut encrypted = connected_cell.clone();
                self.circuit_manager
                    .encrypt_relay_cell(circuit_id, &mut encrypted[5..514])
                    .await?;

                // Track bytes sent to client
                let _ = self.circuit_manager.record_sent(circuit_id, 509).await;

                // Start forwarding task for this stream
                self.spawn_stream_forwarder(circuit_id, stream_id, self.outgoing_tx.clone())
                    .await?;

                Ok(Some(encrypted))
            }
            Err(e) => {
                // Non-fatal: an END cell (CONNECT_REFUSED) is sent to the client, so WARN.
                Log::new(Some(&self.status_tx))
                    .warn(format!("Failed to connect to {}: {}", target, e));

                // Close stream
                let _ = self
                    .circuit_manager
                    .close_stream(circuit_id, stream_id)
                    .await;

                // Build END response with error reason
                let end_cell = build_relay_cell(
                    circuit_id.as_u32(),
                    stream_id.as_u16(),
                    relay_command::END,
                    &[end_reason::CONNECT_REFUSED],
                );

                // Encrypt response
                let mut encrypted = end_cell.clone();
                self.circuit_manager
                    .encrypt_relay_cell(circuit_id, &mut encrypted[5..514])
                    .await?;

                // Track bytes sent to client
                let _ = self.circuit_manager.record_sent(circuit_id, 509).await;

                Ok(Some(encrypted))
            }
        }
    }

    /// Handle BEGIN_DIR cell - create directory stream for serving consensus
    async fn handle_begin_dir_cell(
        &mut self,
        circuit_id: CircuitId,
        stream_id: StreamId,
    ) -> Result<Option<Vec<u8>>> {
        Log::new(Some(&self.status_tx)).info(format!(
            "BEGIN_DIR stream {} on circuit {} (directory request over circuit)",
            stream_id.as_u16(),
            circuit_id.as_u32()
        ));

        // Create directory stream in circuit manager
        self.circuit_manager
            .create_directory_stream(circuit_id, stream_id)
            .await?;

        info!(
            "Directory stream {} ready on circuit {}",
            stream_id.as_u16(),
            circuit_id.as_u32()
        );

        // Build CONNECTED response (same as normal stream)
        let connected_cell = build_relay_cell(
            circuit_id.as_u32(),
            stream_id.as_u16(),
            relay_command::CONNECTED,
            &[],
        );

        // Encrypt response
        let mut encrypted = connected_cell.clone();
        self.circuit_manager
            .encrypt_relay_cell(circuit_id, &mut encrypted[5..514])
            .await?;

        Ok(Some(encrypted))
    }

    /// Handle DATA cell - forward data to TCP connection or handle directory request
    async fn handle_data_cell(
        &mut self,
        circuit_id: CircuitId,
        stream_id: StreamId,
        data: &[u8],
    ) -> Result<Option<Vec<u8>>> {
        trace!(
            "DATA cell for stream {} ({} bytes)",
            stream_id.as_u16(),
            data.len()
        );

        // Track DATA cell for stream-level flow control - send SENDME if needed
        let send_stream_sendme = self
            .circuit_manager
            .record_stream_data_received(circuit_id, stream_id)
            .await
            .unwrap_or(false);

        if send_stream_sendme {
            debug!(
                "Sending stream-level SENDME for stream {}",
                stream_id.as_u16()
            );
            let sendme_cell = build_relay_cell(
                circuit_id.as_u32(),
                stream_id.as_u16(),
                relay_command::SENDME,
                &[],
            );
            let mut encrypted = sendme_cell.clone();
            self.circuit_manager
                .encrypt_relay_cell(circuit_id, &mut encrypted[5..514])
                .await?;
            let _ = self.circuit_manager.record_sent(circuit_id, 509).await;
            let _ = self.outgoing_tx.send(encrypted);
        }

        // Check if this is a directory stream (BEGIN_DIR)
        if self
            .circuit_manager
            .is_directory_stream(circuit_id, stream_id)
            .await?
        {
            return self
                .handle_directory_data(circuit_id, stream_id, data)
                .await;
        }

        // Get the write half of this stream's TCP connection
        if let Some(connection) = self
            .circuit_manager
            .get_stream_writer(circuit_id, stream_id)
            .await?
        {
            // Write data to TCP connection
            let mut conn = connection.lock().await;
            if let Err(e) = conn.write_all(data).await {
                error!("Failed to write to stream {}: {}", stream_id.as_u16(), e);

                // Close stream
                drop(conn); // Release lock before closing
                let _ = self
                    .circuit_manager
                    .close_stream(circuit_id, stream_id)
                    .await;

                // Send END cell
                let end_cell = build_relay_cell(
                    circuit_id.as_u32(),
                    stream_id.as_u16(),
                    relay_command::END,
                    &[end_reason::MISC],
                );

                let mut encrypted = end_cell.clone();
                self.circuit_manager
                    .encrypt_relay_cell(circuit_id, &mut encrypted[5..514])
                    .await?;

                // Track bytes sent to client
                let _ = self.circuit_manager.record_sent(circuit_id, 509).await;

                return Ok(Some(encrypted));
            }

            trace!(
                "Forwarded {} bytes to stream {}",
                data.len(),
                stream_id.as_u16()
            );
        } else {
            warn!("Stream {} not found or not active", stream_id.as_u16());
        }

        Ok(None)
    }

    /// Handle directory stream DATA - accumulate HTTP request and respond
    async fn handle_directory_data(
        &mut self,
        circuit_id: CircuitId,
        stream_id: StreamId,
        data: &[u8],
    ) -> Result<Option<Vec<u8>>> {
        // Append data to directory request buffer
        self.circuit_manager
            .append_directory_data(circuit_id, stream_id, data)
            .await?;

        // Get accumulated request
        let request_data = self
            .circuit_manager
            .get_directory_request(circuit_id, stream_id)
            .await?;

        // Check if we have a complete HTTP request (ends with \r\n\r\n)
        if let Some(pos) = request_data.windows(4).position(|w| w == b"\r\n\r\n") {
            // Extract HTTP request line
            let request_str = String::from_utf8_lossy(&request_data[..pos]);
            let first_line = request_str.lines().next().unwrap_or("");

            debug!("Directory request: {}", first_line);

            // Parse HTTP method and path
            let parts: Vec<&str> = first_line.split_whitespace().collect();
            let (_method, path) = if parts.len() >= 2 {
                (parts[0], parts[1])
            } else {
                ("GET", "/")
            };

            // Generate consensus response
            // TODO: Call LLM to generate dynamic consensus based on path and instruction
            let consensus = if path.contains("consensus") {
                Self::generate_test_consensus()
            } else {
                b"HTTP/1.0 404 Not Found\r\n\r\n".to_vec()
            };

            info!(
                "Serving {} response ({} bytes) for directory path: {}",
                if path.contains("consensus") {
                    "consensus"
                } else {
                    "404"
                },
                consensus.len(),
                path
            );

            // Send response as DATA cells
            self.send_directory_response(circuit_id, stream_id, &consensus)
                .await?;

            // Close stream after response
            let end_cell = build_relay_cell(
                circuit_id.as_u32(),
                stream_id.as_u16(),
                relay_command::END,
                &[end_reason::DONE],
            );

            let mut encrypted = end_cell.clone();
            self.circuit_manager
                .encrypt_relay_cell(circuit_id, &mut encrypted[5..514])
                .await?;

            return Ok(Some(encrypted));
        }

        Ok(None)
    }

    /// Send directory response data as multiple DATA cells
    async fn send_directory_response(
        &mut self,
        circuit_id: CircuitId,
        stream_id: StreamId,
        data: &[u8],
    ) -> Result<()> {
        const MAX_RELAY_PAYLOAD: usize = 498; // tor-spec: relay cell payload max

        for chunk in data.chunks(MAX_RELAY_PAYLOAD) {
            let data_cell = build_relay_cell(
                circuit_id.as_u32(),
                stream_id.as_u16(),
                relay_command::DATA,
                chunk,
            );

            let mut encrypted = data_cell.clone();
            self.circuit_manager
                .encrypt_relay_cell(circuit_id, &mut encrypted[5..514])
                .await?;

            self.outgoing_tx.send(encrypted)?;
            let _ = self.circuit_manager.record_sent(circuit_id, 509).await;
        }

        Ok(())
    }

    /// Handle END cell - close stream
    async fn handle_end_cell(
        &mut self,
        circuit_id: CircuitId,
        stream_id: StreamId,
        data: &[u8],
    ) -> Result<Option<Vec<u8>>> {
        let reason = if data.is_empty() {
            end_reason::DONE
        } else {
            data[0]
        };

        Log::new(Some(&self.status_tx)).debug(format!(
            "END stream {} (reason: {})",
            stream_id.as_u16(),
            reason
        ));

        // Close stream
        let _ = self
            .circuit_manager
            .close_stream(circuit_id, stream_id)
            .await;

        Ok(None)
    }

    /// Handle SENDME cell - update flow control windows
    async fn handle_sendme_cell(
        &mut self,
        circuit_id: CircuitId,
        stream_id: StreamId,
    ) -> Result<Option<Vec<u8>>> {
        if stream_id.as_u16() == 0 {
            // Circuit-level SENDME
            debug!(
                "Received circuit-level SENDME for circuit {}",
                circuit_id.as_u32()
            );
            let _ = self
                .circuit_manager
                .process_circuit_sendme(circuit_id)
                .await;
        } else {
            // Stream-level SENDME
            debug!(
                "Received stream-level SENDME for stream {}",
                stream_id.as_u16()
            );
            let _ = self
                .circuit_manager
                .process_stream_sendme(circuit_id, stream_id)
                .await;
        }
        Ok(None)
    }

    /// Generate a test consensus document for Arti bootstrap
    /// Returns HTTP response with minimal but valid consensus
    fn generate_test_consensus() -> Vec<u8> {
        use crate::utils::clock::{SystemTime, UNIX_EPOCH};

        // Get current time for valid-after/until
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let hour = now - (now % 3600); // Round down to hour

        // Format timestamps (RFC 3339 style for Tor)
        let valid_after = chrono::DateTime::from_timestamp(hour as i64, 0)
            .unwrap()
            .format("%Y-%m-%d %H:%M:%S")
            .to_string();
        let fresh_until = chrono::DateTime::from_timestamp((hour + 3600) as i64, 0)
            .unwrap()
            .format("%Y-%m-%d %H:%M:%S")
            .to_string();
        let valid_until = chrono::DateTime::from_timestamp((hour + 10800) as i64, 0)
            .unwrap()
            .format("%Y-%m-%d %H:%M:%S")
            .to_string();

        let consensus_body = format!(
            "network-status-version 3\n\
             vote-status consensus\n\
             consensus-method 35\n\
             valid-after {}\n\
             fresh-until {}\n\
             valid-until {}\n\
             voting-delay 300 300\n\
             client-versions 0.4.7.0-alpha-dev,0.4.8.0\n\
             server-versions 0.4.7.0-alpha-dev,0.4.8.0\n\
             known-flags Authority BadExit Exit Fast Guard HSDir NoEdConsensus Running Stable StaleDesc Sybil V2Dir Valid\n\
             params CircuitPriorityHalflifeMsec=30000 DoSCircuitCreationEnabled=1 DoSConnectionEnabled=1\n\
             r TestRelay1 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= 127.0.0.1 9001 127.0.0.1 9030\n\
             s Exit Fast Guard HSDir Running Stable V2Dir Valid\n\
             v Tor 0.4.8.0\n\
             w Bandwidth=5000\n\
             p accept 1-65535\n\
             r TestRelay2 BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB= 127.0.0.2 9001 127.0.0.2 9030\n\
             s Exit Fast Guard HSDir Running Stable V2Dir Valid\n\
             v Tor 0.4.8.0\n\
             w Bandwidth=5000\n\
             p accept 1-65535\n\
             r TestRelay3 CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC= 127.0.0.3 9001 127.0.0.3 9030\n\
             s Exit Fast Guard HSDir Running Stable V2Dir Valid\n\
             v Tor 0.4.8.0\n\
             w Bandwidth=5000\n\
             p accept 1-65535\n\
             r TestRelay4 DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD= 127.0.0.4 9001 127.0.0.4 9030\n\
             s Exit Fast Guard HSDir Running Stable V2Dir Valid\n\
             v Tor 0.4.8.0\n\
             w Bandwidth=5000\n\
             p accept 1-65535\n\
             directory-footer\n\
             bandwidth-weights Wbd=0 Wbe=0 Wbg=4096 Wbm=10000 Wdb=10000 Web=10000 Wed=10000 Wee=10000 Weg=10000 Wem=10000 Wgb=10000 Wgd=0 Wgg=5920 Wgm=5920 Wmb=10000 Wmd=0 Wme=0 Wmg=4096 Wmm=10000\n\
             directory-signature 0000000000000000000000000000000000000000 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
             -----BEGIN SIGNATURE-----\n\
             AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
             -----END SIGNATURE-----\n",
            valid_after, fresh_until, valid_until
        );

        // Build HTTP response
        let http_response = format!(
            "HTTP/1.0 200 OK\r\n\
             Content-Type: text/plain\r\n\
             Content-Length: {}\r\n\
             \r\n\
             {}",
            consensus_body.len(),
            consensus_body
        );

        http_response.into_bytes()
    }

    /// Spawn background task to forward data from TCP connection back to Tor client
    async fn spawn_stream_forwarder(
        &self,
        circuit_id: CircuitId,
        stream_id: StreamId,
        outgoing_tx: mpsc::UnboundedSender<Vec<u8>>,
    ) -> Result<()> {
        // Read half only. Holding a lock over the whole TcpStream here parked the
        // client-to-target write path forever, because this task waits in `read()`.
        let connection = self
            .circuit_manager
            .get_stream_reader(circuit_id, stream_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Stream not found"))?;

        let circuit_mgr = self.circuit_manager.clone();
        let status_tx = self.status_tx.clone();

        // Tracked, not detached: stop_server must abort this task too.
        let task_owner = self.app_state.clone();
        task_owner
            .spawn_server_task(self.server_id, async move {
                let mut buffer = vec![0u8; 498]; // Max relay cell data size

                loop {
                    let bytes_read = {
                        let mut conn = connection.lock().await;
                        match conn.read(&mut buffer).await {
                            Ok(0) => {
                                // EOF - connection closed
                                debug!("Stream {} EOF from target", stream_id.as_u16());
                                break;
                            }
                            Ok(n) => n,
                            Err(e) => {
                                error!("Failed to read from stream {}: {}", stream_id.as_u16(), e);
                                break;
                            }
                        }
                    };

                    // Build DATA relay cell
                    let mut data_cell = build_relay_cell(
                        circuit_id.as_u32(),
                        stream_id.as_u16(),
                        relay_command::DATA,
                        &buffer[..bytes_read],
                    );

                    // Encrypt relay cell payload
                    if let Err(e) = circuit_mgr
                        .encrypt_relay_cell(circuit_id, &mut data_cell[5..514])
                        .await
                    {
                        error!(
                            "Failed to encrypt DATA cell for stream {}: {}",
                            stream_id.as_u16(),
                            e
                        );
                        break;
                    }

                    // Track bytes sent to client
                    let _ = circuit_mgr.record_sent(circuit_id, 509).await;

                    // Send encrypted cell through channel
                    if let Err(e) = outgoing_tx.send(data_cell) {
                        error!(
                            "Failed to send DATA cell for stream {}: {}",
                            stream_id.as_u16(),
                            e
                        );
                        break;
                    }

                    trace!(
                        "Forwarded {} bytes from stream {} back to client",
                        bytes_read,
                        stream_id.as_u16()
                    );
                }

                // Send END cell when stream closes
                let mut end_cell = build_relay_cell(
                    circuit_id.as_u32(),
                    stream_id.as_u16(),
                    relay_command::END,
                    &[end_reason::DONE],
                );

                // Encrypt END cell
                if let Ok(_) = circuit_mgr
                    .encrypt_relay_cell(circuit_id, &mut end_cell[5..514])
                    .await
                {
                    let _ = circuit_mgr.record_sent(circuit_id, 509).await;
                    let _ = outgoing_tx.send(end_cell);
                }

                // Close stream
                let _ = circuit_mgr.close_stream(circuit_id, stream_id).await;
                Log::new(Some(&status_tx)).debug(format!("Stream {} closed", stream_id.as_u16()));
            })
            .await;

        Ok(())
    }

    /// Create a DESTROY cell (tor-spec 5.4) carrying `reason`.
    fn create_destroy_cell_with_reason(&self, circuit_id: CircuitId, reason: u8) -> Vec<u8> {
        let mut cell = Vec::with_capacity(FIXED_CELL_LEN);
        cell.extend_from_slice(&circuit_id.to_bytes());
        cell.push(4); // DESTROY command
        cell.push(reason);
        cell.resize(FIXED_CELL_LEN, 0); // Pad to 514 bytes
        cell
    }

    /// Create DESTROY cell for a malformed or unprocessable cell.
    fn create_destroy_cell(&self, circuit_id: CircuitId) -> Vec<u8> {
        self.create_destroy_cell_with_reason(circuit_id, DESTROY_REASON_PROTOCOL)
    }
}

/// Tor cell information
#[derive(Debug, Clone)]
struct TorCellInfo {
    circuit_id: CircuitId,
    cell_type: String,
}

/// The link protocol version this relay frames cells for: 4-byte circuit ids, 514-byte
/// fixed cells.
/// How long to wait for a peer's first cell after the TLS handshake.
///
/// The Tor link protocol is client-speaks-first once TLS is up: the VERSIONS cell is the first
/// thing a client sends and the relay says nothing before it. A peer that has completed TLS and
/// then gone quiet has begun no link handshake, so it gets the short bound — and this is the
/// one an unauthenticated flood lives under, since it never reaches the idle bound below.
const FIRST_CELL_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// How long to wait for a *further* cell once the link is up.
///
/// Fifteen minutes, derived from Tor's own answer to the same question. `KeepalivePeriod`
/// defaults to five minutes: a relay sends a PADDING cell that often on an open connection
/// precisely so an idle-but-live link keeps proving it is live through firewalls that would
/// otherwise drop it. Three of those periods with neither a cell nor a padding keepalive means
/// the peer is gone, not quiet. (Tor's `CircuitIdleTimeout` — an hour — is about circuits, not
/// about a connection that is producing nothing at all, so it is not the number to copy here.)
const IDLE_BETWEEN_CELLS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(900);

/// Concurrent inbound connections this relay admits.
const MAX_CONNECTIONS: usize = crate::server::accept_bounded::DEFAULT_MAX_CONNECTIONS;

/// What a peer over [`MAX_CONNECTIONS`] is told before the socket closes.
///
/// The cap is applied on the raw TCP accept, before the TLS handshake, so the only vocabulary
/// available is TLS's: a plaintext fatal alert record — content type 21, legacy record version
/// 0x0303, length 2, level `fatal`(2), description `internal_error`(80). TLS has no "server
/// busy" alert and the Tor link protocol has nothing at all that may precede VERSIONS, so this
/// is as close as either layer comes. A client reports a fatal alert rather than a bare reset.
const CONNECTION_CAP_REFUSAL: &[u8] = &[0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x50];

const LINK_PROTOCOL_VERSION: u16 = 4;
/// tor-spec 3, command 7. Variable length, and the only cell with a 2-byte circuit id.
const CELL_COMMAND_VERSIONS: u8 = 7;
/// Fixed cell size for link protocol v4: 4 (circuit id) + 1 (command) + 509 (payload).
const FIXED_CELL_LEN: usize = 514;

/// tor-spec 5.4 DESTROY reason: "a protocol error occurred".
const DESTROY_REASON_PROTOCOL: u8 = 1;
/// tor-spec 5.4 DESTROY reason: "internal error at the relay". The relay tearing a circuit
/// down because of a fault of its own, which is exactly what an LLM backend failure is.
const DESTROY_REASON_INTERNAL: u8 = 2;

/// One cell framed off the wire.
#[derive(Debug)]
enum FramedCell {
    /// A fixed-length v4 cell. `raw` is all 514 bytes, so the existing handlers can keep
    /// indexing it directly.
    Fixed { circuit_id: CircuitId, raw: Vec<u8> },
    /// A variable-length cell: VERSIONS (7), or any command >= 128 (VPADDING, CERTS,
    /// AUTH_CHALLENGE, AUTHENTICATE, AUTHORIZE).
    Variable {
        #[allow(dead_code)]
        circuit_id: u32,
        command: u8,
        payload: Vec<u8>,
    },
}

/// Frame one cell out of `buf`, consuming its bytes. `None` means more bytes are needed.
///
/// `expecting_versions` must be true only for the first cell of a connection. tor-spec 3
/// allows VERSIONS only there, and gives it a 2-byte circuit id while every other cell in
/// link protocol v4 has a 4-byte one — so the command byte sits at a different offset and
/// the two layouts are only distinguishable because of that rule.
fn take_cell(buf: &mut Vec<u8>, expecting_versions: bool) -> Option<FramedCell> {
    if expecting_versions && buf.len() >= 3 && buf[2] == CELL_COMMAND_VERSIONS {
        // CircID (2) | Command (1) | Length (2) | Payload (Length)
        if buf.len() < 5 {
            return None;
        }
        let length = u16::from_be_bytes([buf[3], buf[4]]) as usize;
        if buf.len() < 5 + length {
            return None;
        }
        let circuit_id = u16::from_be_bytes([buf[0], buf[1]]) as u32;
        let payload = buf[5..5 + length].to_vec();
        buf.drain(..5 + length);
        return Some(FramedCell::Variable {
            circuit_id,
            command: CELL_COMMAND_VERSIONS,
            payload,
        });
    }

    if buf.len() < 5 {
        return None;
    }
    let circuit_id = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
    let command = buf[4];

    // Commands 128 and above are variable-length in every link protocol version.
    if command >= 128 {
        if buf.len() < 7 {
            return None;
        }
        let length = u16::from_be_bytes([buf[5], buf[6]]) as usize;
        if buf.len() < 7 + length {
            return None;
        }
        let payload = buf[7..7 + length].to_vec();
        buf.drain(..7 + length);
        return Some(FramedCell::Variable {
            circuit_id,
            command,
            payload,
        });
    }

    if buf.len() < FIXED_CELL_LEN {
        return None;
    }
    let raw = buf[..FIXED_CELL_LEN].to_vec();
    buf.drain(..FIXED_CELL_LEN);
    Some(FramedCell::Fixed {
        circuit_id: CircuitId::new(circuit_id),
        raw,
    })
}

/// Parse Tor cell header
///
/// Tor v4 cell format:
/// - Circuit ID: 4 bytes
/// - Command: 1 byte
/// - Payload: 509 bytes (variable-length cells have length field)
///
/// Command types (tor-spec.txt section 3). Note these are the *real* numbers: an earlier
/// version of this table was shifted by one from command 7 onwards, so a client's CREATE2
/// (10) was read as CREATED2 and dropped as "unhandled", and this relay's own CREATED2
/// replies went out with the CREATE2 command byte.
/// - 0: PADDING
/// - 1: CREATE (obsolete)
/// - 2: CREATED (obsolete)
/// - 3: RELAY
/// - 4: DESTROY
/// - 5: CREATE_FAST (obsolete)
/// - 6: CREATED_FAST (obsolete)
/// - 7: VERSIONS (variable length - NOT handled, see below)
/// - 8: NETINFO
/// - 9: RELAY_EARLY
/// - 10: CREATE2
/// - 11: CREATED2
/// - 12: PADDING_NEGOTIATE
///
/// Commands 128+ (VPADDING, CERTS, AUTH_CHALLENGE, AUTHENTICATE, AUTHORIZE) and VERSIONS are
/// variable-length cells. They are framed by `take_cell` and dispatched to
/// `handle_variable_cell` before reaching here, so this function only ever sees the
/// fixed-length 514-byte form.
fn parse_tor_cell(data: &[u8]) -> Option<TorCellInfo> {
    if data.len() < 5 {
        return None;
    }

    // Extract circuit ID (4 bytes, big-endian)
    let circuit_id_bytes: [u8; 4] = data[0..4].try_into().ok()?;
    let circuit_id = CircuitId::from_bytes(&circuit_id_bytes);

    // Extract command byte
    let command = data[4];

    // Map command to cell type
    let cell_type = match command {
        0 => "PADDING",
        1 => "CREATE",
        2 => "CREATED",
        3 => "RELAY",
        4 => "DESTROY",
        5 => "CREATE_FAST",
        6 => "CREATED_FAST",
        7 => "VERSIONS",
        8 => "NETINFO",
        9 => "RELAY_EARLY",
        10 => "CREATE2",
        11 => "CREATED2",
        12 => "PADDING_NEGOTIATE",
        _ => "UNKNOWN",
    };

    Some(TorCellInfo {
        circuit_id,
        cell_type: cell_type.to_string(),
    })
}

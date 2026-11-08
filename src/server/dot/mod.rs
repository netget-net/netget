//! DNS-over-TLS (DoT) server implementation
//!
//! Implements RFC 7858 DNS-over-TLS protocol using hickory-dns and rustls.
//! The LLM controls DNS responses while NetGet handles the TLS transport layer.

pub mod actions;

use crate::llm::action_helper::call_llm;
use crate::llm::ollama_client::OllamaClient;
use crate::logging::emit::Log;
use crate::protocol::Event;
use crate::server::connection::ConnectionId;
use crate::server::dns::StreamQuery;
use crate::server::DotProtocol;
use crate::state::app_state::AppState;
use crate::state::ServerId;
use actions::DOT_QUERY_EVENT;
use anyhow::{Context, Result};
use serde_json::json;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::time::{timeout, Duration};
use tokio_rustls::TlsAcceptor;
use tracing::error;

/// Bound on the TLS handshake for one accepted connection.
///
/// Without it, a peer that completes the TCP handshake and then sends nothing holds
/// `acceptor.accept()` — and the task around it — open forever. That is reachable from the
/// wire by anyone who can connect, and costs a task and a socket per attempt.
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Default bound on how long an established DoT connection may sit without sending a query.
///
/// RFC 7858 §3.4 has the client manage an idle timeout and the server free to close an idle
/// connection; without any bound here a connection that never sends a second query is a
/// permanently parked task. This is deliberately generous — resolvers legitimately pin one
/// TLS connection and reuse it — but finite. It runs only while the server waits for the next
/// length prefix: a query being answered (a model round-trip, a `manual` rule parked for a
/// person) is not idle. Declared as the `idle_timeout_secs` startup parameter (1-3600).
pub const IDLE_READ_TIMEOUT: Duration = Duration::from_secs(300);

/// The largest `idle_timeout_secs` accepted: an hour.
pub const MAX_IDLE_TIMEOUT_SECS: u64 = 3600;

/// Once a length prefix arrives, the peer must finish that DNS message promptly. The
/// between-query idle timeout cannot bound a read that is already waiting for its body.
const MESSAGE_READ_TIMEOUT: Duration = Duration::from_secs(10);

/// Pause after a failed `accept()` before trying again.
///
/// `accept` failing is usually transient (the peer went away between the SYN and the accept)
/// and retrying immediately is right. It is not always transient: at the file-descriptor
/// limit, `accept` returns `EMFILE` instantly and keeps doing so, and a bare `continue` then
/// spins the accept loop at full speed writing a warning per iteration onto an **unbounded**
/// status channel — turning "out of descriptors" into "out of memory". A short pause costs
/// nothing in the transient case and bounds the pathological one.
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(100);

/// Concurrent connections this server admits before it starts refusing.
///
/// [`crate::server::accept_bounded::DEFAULT_MAX_CONNECTIONS`]. [`TLS_HANDSHAKE_TIMEOUT`] and
/// [`IDLE_READ_TIMEOUT`] bound how long *one* peer holds a slot; only a cap bounds how many of
/// them there can be at once, and `IDLE_READ_TIMEOUT` is deliberately five minutes, so without
/// a cap a peer that connects once a second holds three hundred connections before the first
/// one is even eligible to be closed. DoT is the transport a resolver pins and reuses for the
/// life of its process (RFC 7858 §3.4 is written around exactly that), so a real deployment's
/// live-connection count is its resolver count — 256 is far above any of those and far below
/// the descriptor and TLS-session state an unbounded accept loop would let a stranger pin.
const MAX_CONNECTIONS: usize = crate::server::accept_bounded::DEFAULT_MAX_CONNECTIONS;

/// A peer over [`MAX_CONNECTIONS`] gets a **plain close**, with nothing written.
///
/// **DoT's first byte is a TLS record, so there is nothing to say it in.** A DNS response is
/// not merely inapplicable here — it is unreachable: RFC 7858 puts the whole DNS exchange
/// *inside* the TLS session, so a length-prefixed DNS message written to this socket is not a
/// SERVFAIL, it is a malformed TLS record, and the client reports a handshake failure rather
/// than a busy server. (A DNS refusal would be wrong twice over: a response echoes the query's
/// ID and question section, and a peer refused at the accept has sent no query.)
///
/// Refusing *inside* TLS would mean completing a handshake in order to say no, which hands a
/// stranger a certificate signature per refused connection — a cap that costs more to enforce
/// than to ignore. TLS's own record layer has no alert for this: RFC 8446 §6.2 defines nothing
/// meaning "at capacity", and `internal_error` claims this server is broken when it is merely
/// full.
///
/// So the refusal is EOF before the handshake. This is `smtp`'s implicit-TLS reasoning, and
/// every DoT client already has a path for it: RFC 7858 §3.1 has the client fall back or
/// retry when a TLS connection cannot be established. The refusal is logged with
/// `decision=fail_closed_connection_cap`, which is where the real reason lives.
const CONNECTION_CAP_REFUSAL: &[u8] = b"";

/// DNS-over-TLS server
pub struct DotServer;

impl DotServer {
    /// Spawn the DoT server.
    ///
    /// The listener is bound here, *before* the accept loop is spawned, so that
    /// a bind failure (port in use, permission denied) is returned to the
    /// caller instead of being swallowed by the background task - otherwise the
    /// server would be reported as `Running` while nothing is listening.
    /// Binding here also means the returned address carries the real port when
    /// the caller asked for port 0.
    pub async fn spawn(
        bind_addr: SocketAddr,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        server_id: ServerId,
        status_tx: mpsc::UnboundedSender<String>,
        idle_timeout: Duration,
    ) -> Result<SocketAddr> {
        // Generate TLS configuration (use default self-signed cert)
        let tls_config = crate::server::tls_cert_manager::generate_default_tls_config()
            .context("Failed to generate TLS configuration")?;

        Log::new(Some(&status_tx)).info(format!("Starting DoT server on {}", bind_addr));

        let listener = TcpListener::bind(bind_addr)
            .await
            .context("Failed to bind DoT TCP listener")?;

        // Actual bound address (important for port 0 dynamic allocation)
        let local_addr = listener
            .local_addr()
            .context("Failed to get DoT listener local address")?;

        Log::new(Some(&status_tx)).info(format!("DoT server listening on {}", local_addr));

        let task_registrar = app_state.clone();
        let handle = tokio::spawn(async move {
            if let Err(e) = Self::run(
                listener,
                tls_config,
                llm_client,
                app_state,
                server_id,
                status_tx,
                idle_timeout,
            )
            .await
            {
                error!("DoT server error: {}", e);
            }
        });

        // Register the accept loop so stop_server can abort it and release the port.
        task_registrar.register_server_task(server_id, handle).await;

        Ok(local_addr)
    }

    /// Run the DoT accept loop on an already-bound listener
    async fn run(
        listener: TcpListener,
        tls_config: Arc<rustls::ServerConfig>,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        server_id: ServerId,
        status_tx: mpsc::UnboundedSender<String>,
        idle_timeout: Duration,
    ) -> Result<()> {
        let acceptor = TlsAcceptor::from(tls_config);
        let local_addr = listener
            .local_addr()
            .context("Failed to get DoT listener local address")?;

        let limiter = crate::server::accept_bounded::ConnectionLimiter::new(MAX_CONNECTIONS);

        loop {
            match crate::server::accept_bounded::accept_bounded(
                &listener,
                &limiter,
                CONNECTION_CAP_REFUSAL,
                "DOT",
                Some(&status_tx),
            )
            .await
            {
                Ok((stream, peer_addr, permit)) => {
                    Log::new(Some(&status_tx))
                        .debug(format!("DoT TCP connection from {}", peer_addr));

                    // Register the peer in server state before the handshake, so the
                    // dashboard rail shows the connection while TLS is still being
                    // negotiated rather than only once a query arrives. Nothing tracked
                    // DoT connections at all before this: a DoT server showed an empty
                    // peer list however many resolvers were talking to it, and the
                    // byte/packet counters the rail draws stayed at zero.
                    let connection_id = ConnectionId::new(app_state.get_next_unified_id().await);
                    {
                        use crate::state::server::{
                            ConnectionState as ServerConnectionState, ConnectionStatus,
                            ProtocolConnectionInfo,
                        };
                        let now = crate::utils::clock::Instant::now();
                        app_state
                            .add_connection_to_server(
                                server_id,
                                ServerConnectionState {
                                    id: connection_id,
                                    remote_addr: peer_addr,
                                    local_addr,
                                    bytes_sent: 0,
                                    bytes_received: 0,
                                    packets_sent: 0,
                                    packets_received: 0,
                                    last_activity: now,
                                    status: ConnectionStatus::Active,
                                    status_changed_at: now,
                                    protocol_info: ProtocolConnectionInfo::empty(),
                                },
                            )
                            .await;
                    }
                    let _ = status_tx.send("__UPDATE_UI__".to_string());

                    let acceptor = acceptor.clone();
                    let llm_client = llm_client.clone();
                    let conn_state = app_state.clone();
                    let app_state = app_state.clone();
                    let status_tx = status_tx.clone();

                    // Registered, not detached. `stop_server` aborts the tasks a server
                    // registered; an unregistered per-connection task survives it, so a
                    // stopped DoT server went on serving every connection it had already
                    // accepted.
                    let handle = tokio::spawn(async move {
                        // Released when this task ends, and this task is the whole of the
                        // connection — DoT spawns nothing else per peer — so
                        // `MAX_CONNECTIONS` caps live connections rather than accepts.
                        let _permit = permit;
                        if let Err(e) = Self::handle_connection(
                            stream,
                            peer_addr,
                            connection_id,
                            acceptor,
                            llm_client,
                            app_state,
                            server_id,
                            status_tx,
                            idle_timeout,
                        )
                        .await
                        {
                            error!("DoT connection error from {}: {:#}", peer_addr, e);
                        }
                    });
                    conn_state.register_server_task(server_id, handle).await;
                }
                Err(e) => {
                    Log::new(Some(&status_tx))
                        .warn(format!("Failed to accept DoT TCP connection: {}", e));
                    tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
                }
            }
        }
    }

    /// Handle a single DoT connection
    #[allow(clippy::too_many_arguments)]
    async fn handle_connection(
        stream: TcpStream,
        peer_addr: SocketAddr,
        connection_id: ConnectionId,
        acceptor: TlsAcceptor,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        server_id: ServerId,
        status_tx: mpsc::UnboundedSender<String>,
        idle_timeout: Duration,
    ) -> Result<()> {
        let outcome = Self::serve_connection(
            stream,
            peer_addr,
            connection_id,
            acceptor,
            llm_client,
            &app_state,
            server_id,
            &status_tx,
            idle_timeout,
        )
        .await;

        // Mark the peer closed however the session ended — handshake failure, read
        // error, idle timeout or a clean close — so the rail stops drawing it as live
        // and any connection-scoped tasks are cleaned up.
        app_state
            .close_connection_on_server(server_id, connection_id)
            .await;
        let _ = status_tx.send("__UPDATE_UI__".to_string());
        outcome
    }

    #[allow(clippy::too_many_arguments)]
    async fn serve_connection(
        stream: TcpStream,
        peer_addr: SocketAddr,
        connection_id: ConnectionId,
        acceptor: TlsAcceptor,
        llm_client: OllamaClient,
        app_state: &Arc<AppState>,
        server_id: ServerId,
        status_tx: &mpsc::UnboundedSender<String>,
        idle_timeout: Duration,
    ) -> Result<()> {
        let status_tx = status_tx.clone();
        let app_state = app_state.clone();
        // Perform TLS handshake, bounded. An unbounded `accept` is a task a peer can park
        // forever by connecting and saying nothing.
        let mut tls_stream = timeout(TLS_HANDSHAKE_TIMEOUT, acceptor.accept(stream))
            .await
            .map_err(|_| {
                anyhow::anyhow!(
                    "TLS handshake with {peer_addr} did not complete within {:?}",
                    TLS_HANDSHAKE_TIMEOUT
                )
            })?
            .context("TLS handshake failed")?;

        Log::new(Some(&status_tx)).debug(format!("DoT TLS handshake complete with {}", peer_addr));

        Log::new(Some(&status_tx)).info(format!("DoT connection from {}", peer_addr));

        let protocol = DotProtocol::new();

        // Handle DNS queries over TLS
        loop {
            // Read length-prefixed DNS message (2-byte big-endian length)
            let mut len_buf = [0u8; 2];
            let read_len = match timeout(idle_timeout, tls_stream.read_exact(&mut len_buf)).await {
                Ok(r) => r,
                Err(_) => {
                    Log::new(Some(&status_tx)).debug(format!(
                        "DoT connection from {} idle for {}s, closing decision=tcp_idle",
                        peer_addr,
                        idle_timeout.as_secs()
                    ));
                    break;
                }
            };
            match read_len {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    Log::new(Some(&status_tx))
                        .debug(format!("DoT connection from {} closed", peer_addr));
                    break;
                }
                Err(e) => {
                    Log::new(Some(&status_tx))
                        .error(format!("Failed to read DoT length prefix: {}", e));
                    break;
                }
            }

            // A `u16` length cannot exceed 65535, so the old `dns_len > 65535` arm was
            // unreachable and read as a bound that was not there.
            let dns_len = u16::from_be_bytes(len_buf) as usize;

            if dns_len == 0 {
                Log::new(Some(&status_tx))
                    .warn(format!("Invalid DoT DNS message length: {}", dns_len));
                break;
            }

            // Read DNS message
            let mut dns_buf = vec![0u8; dns_len];
            match timeout(MESSAGE_READ_TIMEOUT, tls_stream.read_exact(&mut dns_buf)).await {
                Ok(Ok(_)) => {}
                Ok(Err(e)) => {
                    Log::new(Some(&status_tx))
                        .error(format!("Failed to read DoT DNS message: {}", e));
                    break;
                }
                Err(_) => {
                    Log::new(Some(&status_tx)).warn(format!(
                        "DoT message from {peer_addr} incomplete after {MESSAGE_READ_TIMEOUT:?} \
                         decision=fail_closed_read_timeout"
                    ));
                    break;
                }
            }

            app_state
                .update_connection_stats(
                    server_id,
                    connection_id,
                    Some((dns_len + 2) as u64),
                    None,
                    Some(1),
                    None,
                )
                .await;

            Log::new(Some(&status_tx))
                .debug(format!("DoT received {} bytes from {}", dns_len, peer_addr));
            Log::new(Some(&status_tx))
                .trace(format!("DoT DNS query hex: {}", hex::encode(&dns_buf)));

            // A message that does not decode is not answered, and the connection is closed
            // rather than kept: the DNS server's TCP path does the same, and EOF is something
            // the resolver acts on at once, where an unanswered query on a live connection
            // costs it its whole timeout. Nothing can be answered — no id or question was
            // read — and the screen refuses a compression-pointer chain here too.
            let dns_message = match crate::utils::dns_screen::decode_dns_message(&dns_buf) {
                Ok(msg) => msg,
                Err(e) => {
                    Log::new(Some(&status_tx)).warn(format!(
                        "Failed to parse DoT DNS message from {peer_addr}: {e}; closing \
                         decision=fail_closed_unparseable_query"
                    ));
                    break;
                }
            };

            let log = Log::new(Some(&status_tx));
            let stream_query = StreamQuery::new(&dns_message, "DoT");
            if let Some(formerr) = stream_query.formerr_without_question(peer_addr, &log) {
                if !Self::send_framed(
                    &mut tls_stream,
                    &formerr,
                    peer_addr,
                    connection_id,
                    server_id,
                    &app_state,
                    &status_tx,
                )
                .await
                {
                    break;
                }
                continue;
            }

            let query = &dns_message.queries[0];
            let domain = query.name().to_utf8();
            // Display, not Debug: the model reads this string and echoes it back into
            // `send_dns_nxdomain`'s `query_type`, which parses it with
            // `RecordType::from_str`. Debug and Display agree for the common types and
            // do not for all of them, so `{:?}` was a round-trip waiting to break.
            let query_type = query.query_type().to_string();
            let query_id = dns_message.id;

            log.info(format!(
                "DoT query: {} {} (ID: {})",
                domain, query_type, query_id
            ));

            let event = Event::new(
                &DOT_QUERY_EVENT,
                json!({
                    "query_id": query_id,
                    "domain": domain,
                    "query_type": query_type,
                    "peer_addr": peer_addr.to_string(),
                }),
            );

            log.debug(format!("DoT calling LLM for query from {}", peer_addr));

            let result = call_llm(
                &llm_client,
                &app_state,
                server_id,
                Some(connection_id),
                &event,
                &protocol,
            )
            .await;

            // The DNS server's own rules decide what goes back (`StreamQuery::answer`): the
            // first message an action produced, finished; nothing for `ignore_query`;
            // SERVFAIL — echoing the id and question, which a resolver checks before it reads
            // the rcode — for a backend failure, for bytes that are not a DNS message, and for
            // an answer with nothing sendable in it. RFC 7858 frames each with a two-byte
            // length (`send_framed`).
            if let Some(reply) = stream_query.answer(result, peer_addr, connection_id, &log) {
                if !Self::send_framed(
                    &mut tls_stream,
                    &reply,
                    peer_addr,
                    connection_id,
                    server_id,
                    &app_state,
                    &status_tx,
                )
                .await
                {
                    break;
                }
            }
        }

        // Connection closed
        Log::new(Some(&status_tx)).info(format!("DoT connection from {} closed", peer_addr));

        Ok(())
    }

    /// Write one DNS message to the peer in RFC 7858 framing: a two-byte big-endian
    /// length followed by the message. Returns whether the connection can go on.
    ///
    /// The length is checked rather than cast. `bytes.len() as u16` **wraps**: a
    /// 65540-byte message would announce a length of 4 and then write 65540 bytes, the
    /// peer would read the rest as the next length prefix and the next message, and the
    /// stream would be desynchronised for good. Every message reaching here was encoded by
    /// hickory through `StreamQuery`, whose encoder stops at 65535 octets and turns an
    /// answer that does not fit into SERVFAIL, so this cannot fire from anything the model
    /// sends; if it ever does, the connection is closed
    /// (`decision=fail_closed_oversize_answer`) as the DNS server's TCP path closes it —
    /// the peer reads EOF, never a misframed message.
    #[allow(clippy::too_many_arguments)]
    async fn send_framed(
        tls_stream: &mut tokio_rustls::server::TlsStream<TcpStream>,
        message: &[u8],
        peer_addr: SocketAddr,
        connection_id: ConnectionId,
        server_id: ServerId,
        app_state: &Arc<AppState>,
        status_tx: &mpsc::UnboundedSender<String>,
    ) -> bool {
        let Ok(len) = u16::try_from(message.len()) else {
            Log::new(Some(status_tx)).error(format!(
                "DoT reply of {} bytes to {} does not fit RFC 7858's 16-bit length; closing \
                 decision=fail_closed_oversize_answer",
                message.len(),
                peer_addr
            ));
            return false;
        };

        let mut framed = Vec::with_capacity(message.len() + 2);
        framed.extend_from_slice(&len.to_be_bytes());
        framed.extend_from_slice(message);

        if let Err(e) = tls_stream.write_all(&framed).await {
            Log::new(Some(status_tx)).error(format!(
                "Failed to send DoT response to {}: {}",
                peer_addr, e
            ));
            return false;
        }

        app_state
            .update_connection_stats(
                server_id,
                connection_id,
                None,
                Some(framed.len() as u64),
                None,
                Some(1),
            )
            .await;

        let log = Log::new(Some(status_tx));
        log.debug(format!("DoT sent {} bytes to {}", message.len(), peer_addr));
        log.trace(format!("DoT response hex: {}", hex::encode(message)));
        true
    }
}

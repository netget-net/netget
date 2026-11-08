//! DNS-over-HTTPS (DoH) server implementation
//!
//! Implements RFC 8484 DNS-over-HTTPS protocol using hickory-dns, hyper, and rustls.
//! The LLM controls DNS responses while NetGet handles the HTTPS transport layer.

pub mod actions;

use crate::llm::action_helper::call_llm;
use crate::llm::ollama_client::OllamaClient;
use crate::logging::emit::Log;
use crate::protocol::Event;
use crate::server::connection::ConnectionId;
use crate::server::dns::StreamQuery;
use crate::server::DohProtocol;
use crate::state::app_state::AppState;
use crate::state::ServerId;
use actions::DOH_QUERY_EVENT;
use anyhow::{Context, Result};
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::server::conn::http2;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde_json::json;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::time::{timeout, Duration};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error};

/// Bound on the TLS handshake for one accepted connection.
///
/// Without it, a peer that completes the TCP handshake and then sends nothing holds
/// `acceptor.accept()` — and the task around it — open forever, at no cost to itself.
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// How long an established connection may carry no query at all before it is closed.
///
/// [`TLS_HANDSHAKE_TIMEOUT`] ends at the handshake, and after it hyper owns the HTTP/2 session
/// and applies no idle bound of its own — so a peer that completed TLS and then went quiet, or
/// never sent the HTTP/2 preface, held its slot forever. 300 seconds, chosen to stay above the
/// 90 seconds `reqwest` keeps an idle pooled connection: NetGet's own DoH client is a pooled
/// `reqwest` client, and a bound below the pool's races it and loses a query. RFC 8484 sets no
/// number; resolvers multiplex onto few long-lived connections, and [`MAX_CONNECTIONS`] bounds
/// how many of those can sit idle at once.
///
/// **A query still being answered is not silence.** Each request's service future holds the
/// connection's `ConnectionActivity` busy for the whole of its answer — a model round-trip, or a
/// `manual` rule parked for a human — and the watchdog never fires while anything is in flight.
/// HTTP/2 PING frames are answered by hyper and are not activity. On expiry the connection gets
/// a GOAWAY (`graceful_shutdown`) rather than a bare close, which a client reads as "reconnect
/// for the next query". Declared as the `idle_timeout_secs` startup parameter.
pub const IDLE_BETWEEN_QUERIES_TIMEOUT: Duration = Duration::from_secs(300);

/// How long the GOAWAY sent at the idle bound is given to reach the peer. The connection is idle
/// by definition, so there is nothing to drain; this only stops a peer that has stopped reading
/// from holding the close open.
const GOAWAY_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

/// Largest DoH request body accepted, in bytes.
///
/// A DNS message is at most 65535 bytes by construction (its length is carried in 16 bits
/// wherever DNS is framed over a stream), so anything larger cannot be a DNS query. The body
/// was read with `req.collect()`, which is unbounded: over an established HTTP/2 connection a
/// peer could POST gigabytes to `/dns-query` and NetGet would buffer all of it in memory
/// before discovering it was not a DNS message. This is a hard cap with headroom, not a
/// tuning knob.
pub const MAX_DOH_BODY_BYTES: u64 = 65_535;

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
/// [`crate::server::accept_bounded::DEFAULT_MAX_CONNECTIONS`]. [`TLS_HANDSHAKE_TIMEOUT`]
/// bounds how long one peer can hold a slot without completing a handshake; only a cap bounds
/// how many of them there can be at once, and ten seconds times an unbounded arrival rate is
/// still unbounded. DoH resolvers multiplex every query of a whole client population onto a
/// handful of long-lived HTTP/2 connections — that is what RFC 8484 chose HTTP/2 for — so a
/// real deployment's live-connection count is its *resolver* count, not its query rate, and
/// 256 is far above anything legitimate while still bounding the TLS state an attacker can
/// make this process hold.
const MAX_CONNECTIONS: usize = crate::server::accept_bounded::DEFAULT_MAX_CONNECTIONS;

/// A peer over [`MAX_CONNECTIONS`] gets a **plain close**, with nothing written.
///
/// **This server's first byte is a TLS record, and there is no TLS alert that means "busy".**
/// The three HTTP-carried servers that were capped alongside this one — `hls`, `ipp`, `proxy`
/// — answer 503 with `Retry-After`, and that is right for them because their listeners are
/// plaintext: the refusal is the first thing on the wire and the client parses it as HTTP.
/// Here the peer is mid-`ClientHello` and everything it reads is fed to a TLS record parser,
/// so `HTTP/1.1 503` is not a refusal at all — it is a malformed record, and the client
/// records a TLS protocol failure (a handshake it cannot complete, which several stacks treat
/// as evidence of interception) instead of backing off. `smtp` faced exactly this split and
/// resolved it the same way, speaking 421 on its plain listener and nothing on its
/// implicit-TLS one.
///
/// Answering inside TLS would mean completing a handshake in order to refuse, which hands an
/// attacker a signature verification per refused connection — a cap that costs more to enforce
/// than to ignore. The record layer's own vocabulary does not help either: RFC 8446 §6.2 has
/// no resource-exhaustion alert, and the nearest, `internal_error`, tells the client this
/// server is broken rather than full.
///
/// So the honest answer is EOF before the handshake, which every TLS client already has a
/// path for and treats as a transient connection failure. The refusal is logged with
/// `decision=fail_closed_connection_cap`, and that log line is the diagnosis.
const CONNECTION_CAP_REFUSAL: &[u8] = b"";

/// DNS-over-HTTPS server
pub struct DohServer;

impl DohServer {
    /// Spawn the DoH server.
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
        // Generate TLS configuration (default self-signed cert), advertising `h2`.
        //
        // RFC 8484 DoH runs over HTTP/2, and this server speaks nothing else. Without ALPN in
        // the handshake a real client has no way to learn that: it either negotiates nothing
        // and falls back to HTTP/1.1, which this server cannot answer, or refuses outright.
        // The E2E test papered over it by connecting with `http2_prior_knowledge()`, which
        // skips ALPN entirely — so the gap could not show up there.
        let tls_config =
            crate::server::tls_cert_manager::generate_default_tls_config_with_alpn(&["h2"])
                .context("Failed to generate TLS configuration")?;

        Log::new(Some(&status_tx)).info(format!("Starting DoH server on {}", bind_addr));

        let listener = TcpListener::bind(bind_addr)
            .await
            .context("Failed to bind DoH TCP listener")?;

        // Actual bound address (important for port 0 dynamic allocation)
        let local_addr = listener
            .local_addr()
            .context("Failed to get DoH listener local address")?;

        Log::new(Some(&status_tx)).info(format!("DoH server listening on {}", local_addr));

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
                error!("DoH server error: {}", e);
            }
        });

        // Register the accept loop so stop_server can abort it and release the port.
        task_registrar.register_server_task(server_id, handle).await;

        Ok(local_addr)
    }

    /// Run the DoH accept loop on an already-bound listener
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
            .context("Failed to get DoH listener local address")?;

        let limiter = crate::server::accept_bounded::ConnectionLimiter::new(MAX_CONNECTIONS);

        loop {
            match crate::server::accept_bounded::accept_bounded(
                &listener,
                &limiter,
                CONNECTION_CAP_REFUSAL,
                "DOH",
                Some(&status_tx),
            )
            .await
            {
                Ok((stream, peer_addr, permit)) => {
                    Log::new(Some(&status_tx))
                        .debug(format!("DoH TCP connection from {}", peer_addr));

                    // Register the peer before the handshake. Nothing tracked DoH
                    // connections at all before this, so a DoH server drew an empty peer
                    // list however many resolvers were talking to it, `{client_ip}` in the
                    // `doh_query` log template rendered empty, and the rail's byte counters
                    // stayed at zero.
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

                    // Registered, not detached: `stop_server` aborts the tasks a server
                    // registered, and an unregistered per-connection task outlives it, so a
                    // stopped DoH server went on answering every connection it had already
                    // accepted.
                    let handle = tokio::spawn(async move {
                        // Released when this task ends, and this task is the whole of the
                        // connection — DoH spawns nothing else per peer; hyper's HTTP/2
                        // service runs inside `handle_connection` — so `MAX_CONNECTIONS`
                        // caps live connections rather than accepts.
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
                            // `{:#}`: the cause chain is where rustls says what actually
                            // went wrong. `{}` prints only "TLS handshake failed", which
                            // names the step and not the reason.
                            error!("DoH connection error from {}: {:#}", peer_addr, e);
                        }
                    });
                    conn_state.register_server_task(server_id, handle).await;
                }
                Err(e) => {
                    Log::new(Some(&status_tx))
                        .warn(format!("Failed to accept DoH TCP connection: {}", e));
                    tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
                }
            }
        }
    }

    /// Handle a single DoH connection
    #[allow(clippy::too_many_arguments)]
    async fn handle_connection(
        stream: tokio::net::TcpStream,
        peer_addr: SocketAddr,
        connection_id: ConnectionId,
        acceptor: TlsAcceptor,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        server_id: ServerId,
        status_tx: mpsc::UnboundedSender<String>,
        idle_timeout: Duration,
    ) -> Result<()> {
        let closer = app_state.clone();
        let close_tx = status_tx.clone();
        let outcome = Self::serve_connection(
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
        .await;

        // Mark the peer closed however the session ended — a failed handshake included, so
        // a connection that never got past TLS does not sit in the rail as live.
        closer
            .close_connection_on_server(server_id, connection_id)
            .await;
        let _ = close_tx.send("__UPDATE_UI__".to_string());
        outcome
    }

    #[allow(clippy::too_many_arguments)]
    async fn serve_connection(
        stream: tokio::net::TcpStream,
        peer_addr: SocketAddr,
        connection_id: ConnectionId,
        acceptor: TlsAcceptor,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        server_id: ServerId,
        status_tx: mpsc::UnboundedSender<String>,
        idle_timeout: Duration,
    ) -> Result<()> {
        // Perform TLS handshake, bounded. An unbounded `accept` is a task a peer can park
        // forever by connecting and saying nothing.
        let tls_stream = timeout(TLS_HANDSHAKE_TIMEOUT, acceptor.accept(stream))
            .await
            .map_err(|_| {
                anyhow::anyhow!(
                    "TLS handshake with {peer_addr} did not complete within {:?}",
                    TLS_HANDSHAKE_TIMEOUT
                )
            })?
            .context("TLS handshake failed")?;

        Log::new(Some(&status_tx)).debug(format!("DoH TLS handshake complete with {}", peer_addr));

        // Wrap in TokioIo for hyper compatibility
        let io = TokioIo::new(tls_stream);

        // Whether this connection is answering anything. Every request holds it busy for the
        // whole of its answer, so the idle watchdog below cannot close a connection whose query
        // is waiting on the model or parked for a human. Created after the handshake, so a peer
        // that handshakes and then never sends the HTTP/2 preface is on this clock too.
        let activity = Arc::new(crate::server::accept_bounded::ConnectionActivity::new());
        let activity_for_service = Arc::clone(&activity);
        let idle_log_tx = status_tx.clone();

        // Create service closure
        let service = service_fn(move |req: Request<hyper::body::Incoming>| {
            let llm_client = llm_client.clone();
            let app_state = app_state.clone();
            let status_tx = status_tx.clone();
            let busy = activity_for_service.busy();

            async move {
                let _busy = busy;
                Self::handle_request(
                    req,
                    peer_addr,
                    connection_id,
                    server_id,
                    llm_client,
                    app_state,
                    status_tx,
                )
                .await
            }
        });

        // Serve HTTP/2, raced against the idle watchdog. hyper keeps polling the connection
        // while a request is answered, so a deadline on its reads would fire mid-answer; the
        // watchdog reads ConnectionActivity instead, which is busy for exactly that time.
        let conn =
            http2::Builder::new(hyper_util::rt::TokioExecutor::new()).serve_connection(io, service);
        tokio::pin!(conn);
        let result = tokio::select! {
            result = conn.as_mut() => result,
            _ = crate::server::accept_bounded::watch_idle(Arc::clone(&activity), idle_timeout) => {
                Log::new(Some(&idle_log_tx)).debug(format!(
                    "DoH connection {} from {} carried no query for {}s; sending GOAWAY",
                    connection_id,
                    peer_addr,
                    idle_timeout.as_secs()
                ));
                conn.as_mut().graceful_shutdown();
                timeout(GOAWAY_DRAIN_TIMEOUT, conn.as_mut())
                    .await
                    .unwrap_or(Ok(()))
            }
        };

        if let Err(e) = result {
            debug!("DoH HTTP/2 connection error: {}", e);
        }

        Ok(())
    }

    /// Handle a single DoH HTTP request
    #[allow(clippy::too_many_arguments)]
    async fn handle_request(
        req: Request<hyper::body::Incoming>,
        peer_addr: SocketAddr,
        connection_id: ConnectionId,
        server_id: ServerId,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
    ) -> Result<Response<Full<Bytes>>, hyper::Error> {
        let method = req.method().clone();
        let uri = req.uri().clone();

        Log::new(Some(&status_tx)).debug(format!("DoH request: {} {}", method, uri));

        // Extract DNS query based on method
        let dns_bytes = match method {
            Method::GET => {
                // Extract DNS query from ?dns= parameter (base64url encoded)
                let query = uri.query().unwrap_or("");
                let mut dns_param = None;

                for param in query.split('&') {
                    if let Some(value) = param.strip_prefix("dns=") {
                        dns_param = Some(value);
                        break;
                    }
                }

                match dns_param {
                    Some(encoded) => {
                        // Decode base64url
                        match base64_url_decode(encoded) {
                            Ok(bytes) => bytes,
                            Err(e) => {
                                Log::new(Some(&status_tx))
                                    .warn(format!("Invalid base64url DNS query: {}", e));
                                return Ok(error_response(
                                    StatusCode::BAD_REQUEST,
                                    "Invalid DNS query encoding",
                                ));
                            }
                        }
                    }
                    None => {
                        Log::new(Some(&status_tx))
                            .warn("Missing dns= parameter in DoH GET request");
                        return Ok(error_response(
                            StatusCode::BAD_REQUEST,
                            "Missing dns parameter",
                        ));
                    }
                }
            }
            Method::POST => {
                // Check Content-Type
                if let Some(content_type) = req.headers().get("content-type") {
                    if !is_dns_message_content_type(content_type) {
                        Log::new(Some(&status_tx))
                            .warn(format!("Invalid DoH Content-Type: {:?}", content_type));
                        return Ok(error_response(
                            StatusCode::BAD_REQUEST,
                            "Invalid Content-Type",
                        ));
                    }
                } else {
                    Log::new(Some(&status_tx)).warn("Missing Content-Type in DoH POST");
                    return Ok(error_response(
                        StatusCode::BAD_REQUEST,
                        "Missing Content-Type",
                    ));
                }

                // Read the body under a hard cap.
                //
                // `req.collect()` alone is unbounded — a peer that has completed TLS and the
                // HTTP/2 preface can stream a body of any size and NetGet buffers all of it
                // before deciding it is not DNS. `Limited` stops reading at the cap and
                // errors, so the memory a single request can claim is bounded by a constant.
                use http_body_util::Limited;
                let limited = Limited::new(req.into_body(), MAX_DOH_BODY_BYTES as usize);
                match limited.collect().await {
                    Ok(collected) => collected.to_bytes().to_vec(),
                    Err(e) => {
                        Log::new(Some(&status_tx)).warn(format!(
                            "DoH POST body from {} exceeded {} bytes or could not be read: {}",
                            peer_addr, MAX_DOH_BODY_BYTES, e
                        ));
                        return Ok(error_response(
                            StatusCode::PAYLOAD_TOO_LARGE,
                            "DNS message too large",
                        ));
                    }
                }
            }
            _ => {
                Log::new(Some(&status_tx)).warn(format!("Unsupported DoH method: {}", method));
                return Ok(error_response(
                    StatusCode::METHOD_NOT_ALLOWED,
                    "Only GET and POST are supported",
                ));
            }
        };

        let log = Log::new(Some(&status_tx));
        log.debug(format!("DoH received {} bytes", dns_bytes.len()));
        log.trace(format!("DoH DNS query hex: {}", hex::encode(&dns_bytes)));

        app_state
            .update_connection_stats(
                server_id,
                connection_id,
                Some(dns_bytes.len() as u64),
                None,
                Some(1),
                None,
            )
            .await;

        // Parse DNS query
        let dns_message = match crate::utils::dns_screen::decode_dns_message(&dns_bytes) {
            Ok(msg) => msg,
            Err(e) => {
                Log::new(Some(&status_tx)).warn(format!("Failed to parse DoH DNS message: {}", e));
                return Ok(error_response(
                    StatusCode::BAD_REQUEST,
                    "Invalid DNS message",
                ));
            }
        };

        // A query with no question is answered FORMERR by the server itself, in a 200: RFC 8484
        // §4.2.1 makes 200 the status for any DNS response whatever its rcode, and the client
        // is waiting on this transaction id.
        let log = Log::new(Some(&status_tx));
        let stream_query = StreamQuery::new(&dns_message, "DoH");
        if let Some(formerr) = stream_query.formerr_without_question(peer_addr, &log) {
            Self::count_sent(&app_state, server_id, connection_id, formerr.len()).await;
            return Ok(dns_message_response(formerr));
        }

        let query = &dns_message.queries[0];
        let domain = query.name().to_utf8();
        // Display, not Debug: the model reads this string and echoes it back into
        // `send_dns_nxdomain`'s `query_type`, which parses it with `RecordType::from_str`.
        let query_type = query.query_type().to_string();
        let query_id = dns_message.id;

        log.info(format!(
            "DoH query: {} {} (ID: {})",
            domain, query_type, query_id
        ));

        let event = Event::new(
            &DOH_QUERY_EVENT,
            json!({
                "query_id": query_id,
                "domain": domain,
                "query_type": query_type,
                "peer_addr": peer_addr.to_string(),
                "method": method.to_string(),
            }),
        );

        log.debug(format!("DoH calling LLM for query from {}", peer_addr));

        let protocol = DohProtocol::new();
        let result = call_llm(
            &llm_client,
            &app_state,
            server_id,
            Some(connection_id),
            &event,
            &protocol,
        )
        .await;

        // The DNS server's own rules decide the answer (`StreamQuery::answer`): the first
        // message an action produced, finished; SERVFAIL — id and question echoed — for a
        // backend failure, for bytes that are not a DNS message and for an answer with nothing
        // sendable in it. SERVFAIL goes in a 200, as RFC 8484 §4.2.1 has every DNS response: a
        // 5xx tells the client the *resolver endpoint* is broken, and real DoH clients mark the
        // server down and fail over — a heavier reaction than a transient backend hiccup.
        let failure = result
            .as_ref()
            .err()
            .map(crate::utils::WireFailure::classify);
        match stream_query.answer(result, peer_addr, connection_id, &log) {
            Some(bytes) => {
                log.debug(format!("DoH sending {} bytes", bytes.len()));
                log.trace(format!("DoH response hex: {}", hex::encode(&bytes)));
                Self::count_sent(&app_state, server_id, connection_id, bytes.len()).await;
                Ok(dns_message_response(bytes))
            }
            // Only reachable for a backend failure if not even a SERVFAIL could be built; the
            // failure is then said in HTTP, as a category and never the error text.
            None => Ok(match failure {
                Some(crate::utils::WireFailure::Overloaded) => retry_later_response(),
                Some(failure @ crate::utils::WireFailure::Unavailable) => {
                    error_response(StatusCode::INTERNAL_SERVER_ERROR, failure.prefixed_text())
                }
                // `ignore_query`: HTTP has no silence, so the decision is a 404 with no DNS
                // message in it.
                None => error_response(StatusCode::NOT_FOUND, "Query ignored"),
            }),
        }
    }

    async fn count_sent(
        app_state: &AppState,
        server_id: ServerId,
        connection_id: ConnectionId,
        bytes: usize,
    ) {
        app_state
            .update_connection_stats(
                server_id,
                connection_id,
                None,
                Some(bytes as u64),
                None,
                Some(1),
            )
            .await;
    }
}

/// Decode base64url (URL-safe base64 without padding)
fn base64_url_decode(encoded: &str) -> Result<Vec<u8>> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    URL_SAFE_NO_PAD
        .decode(encoded)
        .context("Failed to decode base64url")
}

/// Build a `200 application/dns-message` response carrying a DNS wire-format body.
///
/// Every header passed to the builder is a constant, so the `expect` below is
/// unreachable regardless of what the model or the network produced.
fn dns_message_response(body: Vec<u8>) -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/dns-message")
        .body(Full::new(Bytes::from(body)))
        .expect("constant status and headers always build a valid response")
}

/// Is this `Content-Type` `application/dns-message`?
///
/// RFC 9110 §8.3 makes the media type case-insensitive and allows parameters after a `;`, so
/// `Application/DNS-Message` and `application/dns-message; charset=utf-8` are both the same
/// type. The check was a byte-for-byte `!=` against the canonical spelling, which rejected
/// both as "Invalid Content-Type" — a conformant client turned away for being conformant.
fn is_dns_message_content_type(value: &hyper::header::HeaderValue) -> bool {
    let Ok(text) = value.to_str() else {
        return false;
    };
    let media_type = text.split(';').next().unwrap_or("").trim();
    media_type.eq_ignore_ascii_case("application/dns-message")
}

/// A `503` telling the client to come back, for a transient backend saturation.
///
/// Distinct from the 500 path on purpose: a client that sees 503 + `Retry-After` backs off,
/// where a 500 is recorded as a permanent fault. This mirrors what `src/server/http` does with
/// the same two `WireFailure` categories.
fn retry_later_response() -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::SERVICE_UNAVAILABLE)
        .header("Content-Type", "text/plain")
        .header("Retry-After", "1")
        .body(Full::new(Bytes::from(
            crate::utils::WireFailure::Overloaded.prefixed_text(),
        )))
        .expect("constant status and headers always build a valid response")
}

/// Create an error response
fn error_response(status: StatusCode, message: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("Content-Type", "text/plain")
        .body(Full::new(Bytes::from(message.to_string())))
        .expect("constant status and headers always build a valid response")
}

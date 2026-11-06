//! HTTP/2 server implementation using h2 crate directly for full server push support

use bytes::Bytes;
use h2::server::{self, SendResponse};
use http::{Request, Response, StatusCode};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::llm::action_helper::call_llm;
use crate::llm::actions::protocol_trait::ActionResult;
use crate::llm::ollama_client::OllamaClient;
use crate::protocol::Event;
use crate::server::connection::ConnectionId;
use crate::server::http_common::handler::{RequestData, RequestFilter};
use crate::server::Http2Protocol;
use crate::state::app_state::AppState;

use super::actions::HTTP2_REQUEST_EVENT;
use super::push::PendingPush;
use crate::logging::emit::Log;

/// How long a peer that has connected and produced nothing may hold a slot.
///
/// HTTP/2 is client-speaks-first: the connection preface (and, over TLS, the ClientHello before
/// it) is the first thing on the wire and the server says nothing before it, so a peer that has
/// completed the TCP handshake and sent no byte has begun no connection at all. 30 seconds,
/// the number every HTTP-shaped server here uses for this state, for `src/server/http/mod.rs`'s
/// reasons. It is safe against NetGet's own HTTP/2 client because that client is **lazy**: it
/// is a pooled `reqwest` client with `http2_prior_knowledge()` and opens no socket until it has
/// a request to send, so nothing here is ever connected and waiting on a person. Declared as the
/// `first_byte_timeout_secs` startup parameter, so an operator can change it.
pub const FIRST_BYTE_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// How long the TLS handshake and the HTTP/2 preface exchange may take once the peer has sent
/// its first byte.
///
/// This phase involves no model and no person — rustls and `h2` answer it by themselves — so
/// there is nothing legitimate a peer can be waiting on, and a peer that sends one byte and then
/// stalls would otherwise hold the slot for as long as it likes, having passed the first-byte
/// bound. Thirty seconds, which is far longer than a real handshake on any network and the same
/// number `tls`'s handshake wait uses.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// How long an established connection may carry no request at all before it is closed.
///
/// 300 seconds, chosen to stay above the 90 seconds `reqwest` keeps an idle pooled connection —
/// NetGet's own HTTP/2 client is a pooled `reqwest` client, and a bound below the pool's races
/// it: the client picks a connection the server is about to close and loses the request. nginx's
/// `http2_idle_timeout` (180s) sits below this; being more generous costs one slot per idle
/// client, and [`MAX_CONNECTIONS`] bounds the slots.
///
/// **A request still being answered is not silence.** Each stream's task holds the connection's
/// [`ConnectionActivity`] busy for the whole of its answer — a model round-trip, or an event a
/// `manual` rule parked for a human (`src/state/intercepts.rs`, 300s by default) — and the
/// watchdog never fires while anything is in flight. HTTP/2 PING frames are answered by `h2`
/// itself and are not counted as activity: a PING carries no request, and a client that only
/// pings is holding a slot for nothing. Declared as the `idle_timeout_secs` startup parameter.
///
/// When it fires the connection is closed with a GOAWAY (`graceful_shutdown`), which every
/// HTTP/2 client treats as "open a new connection for the next request", rather than with a bare
/// FIN that a client could mistake for a crashed server.
pub const IDLE_BETWEEN_REQUESTS_TIMEOUT: Duration = Duration::from_secs(300);

/// How long the GOAWAY sent at the idle bound is given to reach the peer before the socket is
/// dropped anyway. The connection is idle by definition, so there is nothing to drain; this only
/// stops a peer that has stopped reading from holding the close open.
const GOAWAY_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

/// Concurrent connections this server admits.
///
/// 128, the same as HTTP/1.1 and for the same reason: every stream may buffer one request body
/// of up to `http_common::MAX_REQUEST_BODY_BYTES` (8 MiB), which is the largest per-connection
/// cost in NetGet's HTTP family, and the cap is what turns that per-connection cost into a total
/// one. Not configurable: a bound decided by configuration is a bound an attacker can ask you
/// to raise.
const MAX_CONNECTIONS: usize = 128;

/// What a cleartext (h2c) peer over [`MAX_CONNECTIONS`] is told before the socket closes.
///
/// HTTP/1.1 `503 Service Unavailable` with a `Retry-After`, deliberately in the older protocol,
/// for the reason `src/server/etcd/mod.rs` gives: the refused peer has not sent the HTTP/2
/// preface, so nothing has been negotiated, and an HTTP/2 GOAWAY would have to follow a SETTINGS
/// frame this server is declining to exchange. Every HTTP client can read a 503.
///
/// **Over TLS the refusal is a plain close instead** (see `spawn_with_push_support`): plaintext
/// bytes written to a peer that is about to send a ClientHello are a malformed TLS record, not a
/// refusal — the same reasoning that makes `doh` and `dot` close silently.
pub const CONNECTION_CAP_REFUSAL: &[u8] = b"HTTP/1.1 503 Service Unavailable\r\n\
    Content-Length: 0\r\nRetry-After: 5\r\nConnection: close\r\n\r\n";

/// `SETTINGS_MAX_CONCURRENT_STREAMS`: how many streams one peer may have open at once.
///
/// 100, the floor RFC 9113 §6.5.2 recommends so as "not to unnecessarily limit parallelism",
/// and Apache's `H2MaxSessionStreams` default (nginx uses 128). `h2` advertises no limit at all
/// unless told to, so without this one admitted connection could open streams without end, each
/// with a task, a parked request and a body buffer. A stream past the limit is reset by `h2`
/// with `REFUSED_STREAM`, which tells the client the request was not processed and is safe to
/// retry; conforming clients never send one because they read this SETTINGS first.
pub const MAX_CONCURRENT_STREAMS: u32 = 100;

/// `SETTINGS_INITIAL_WINDOW_SIZE`: how much request body a stream may send before this server
/// reads it. 65,535 bytes, the protocol's own default, stated rather than inherited: it bounds
/// what `h2` holds for a stream this server has stopped reading (a refused body, see
/// [`BodyBudget`]), and the handler releases capacity as it reads, so it costs an upload nothing
/// but round trips.
pub const INITIAL_STREAM_WINDOW_BYTES: u32 = 65_535;

/// The connection-level receive window: the most unread request-body bytes `h2` buffers across
/// every stream of one connection together. 1 MiB, so that [`MAX_CONCURRENT_STREAMS`] streams
/// uploading at once do not serialise on the protocol's 64 KiB default while the total stays
/// small next to [`CONNECTION_BODY_BUDGET_BYTES`].
pub const INITIAL_CONNECTION_WINDOW_BYTES: u32 = 1024 * 1024;

/// `SETTINGS_MAX_FRAME_SIZE`: the largest frame payload this server accepts. 16,384 bytes, the
/// protocol minimum and default. Nothing a request carries needs a larger frame, and a larger
/// frame is a larger single allocation a peer can ask for.
pub const MAX_FRAME_BYTES: u32 = 16_384;

/// `SETTINGS_MAX_HEADER_LIST_SIZE`: the largest decoded header list one request may carry.
///
/// 32 KiB, nginx's HTTP/1.1 equivalent (`large_client_header_buffers 4 8k`). `h2`'s own default
/// is 16 MiB, which times [`MAX_CONCURRENT_STREAMS`] is 1.6 GiB of headers per connection; at
/// 32 KiB it is 3.2 MiB. Real browsers send a few kilobytes including cookies.
pub const MAX_HEADER_LIST_BYTES: u32 = 32 * 1024;

/// The request-body bytes all streams of one connection may hold at once.
///
/// Each stream buffers its body whole before the model sees it, up to
/// `http_common::MAX_REQUEST_BODY_BYTES` (8 MiB). Per stream alone, that is 800 MiB a
/// connection at [`MAX_CONCURRENT_STREAMS`] and 100 GiB across [`MAX_CONNECTIONS`] — no bound
/// at all in practice. So the streams of a connection share one budget of the same 8 MiB: a
/// single upload can still use all of it, and the per-connection ceiling is what HTTP/1.1's
/// one-request-at-a-time connection costs. A stream whose body would take the connection past
/// it is answered `503` with `Retry-After` (`decision=refused_connection_body_budget`) and never
/// reaches the model; its bytes are released as soon as it is refused, and every stream's are
/// released when its answer has been sent.
///
/// Per connection that makes body buffers 8 MiB, `h2`'s unread data at most
/// [`INITIAL_CONNECTION_WINDOW_BYTES`] (1 MiB), and decoded headers at most
/// [`MAX_CONCURRENT_STREAMS`] × [`MAX_HEADER_LIST_BYTES`] (3.2 MiB): about 12 MiB, and about
/// 1.5 GiB across [`MAX_CONNECTIONS`].
pub const CONNECTION_BODY_BUDGET_BYTES: usize = crate::server::http_common::MAX_REQUEST_BODY_BYTES;

/// The `h2` server builder every HTTP/2 connection is handshaken with — prior-knowledge h2c,
/// TLS, and the HTTP/1.1 `Upgrade: h2c` path in `src/server/http/mod.rs` alike — so the
/// SETTINGS above hold on every way in.
pub fn bounded_h2_builder() -> server::Builder {
    let mut builder = server::Builder::new();
    builder
        .max_concurrent_streams(MAX_CONCURRENT_STREAMS)
        .initial_window_size(INITIAL_STREAM_WINDOW_BYTES)
        .initial_connection_window_size(INITIAL_CONNECTION_WINDOW_BYTES)
        .max_frame_size(MAX_FRAME_BYTES)
        .max_header_list_size(MAX_HEADER_LIST_BYTES);
    builder
}

/// One connection's share of [`CONNECTION_BODY_BUDGET_BYTES`], cloned into each stream's task.
#[derive(Clone, Default)]
pub struct BodyBudget(Arc<std::sync::atomic::AtomicUsize>);

impl BodyBudget {
    pub fn new() -> Self {
        Self::default()
    }

    /// Bytes currently held by this connection's streams.
    pub fn in_use(&self) -> usize {
        self.0.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn reservation(&self) -> BodyReservation {
        BodyReservation {
            budget: self.clone(),
            held: 0,
        }
    }
}

/// The bytes one stream's body holds against its connection's [`BodyBudget`]; released on drop.
struct BodyReservation {
    budget: BodyBudget,
    held: usize,
}

impl BodyReservation {
    /// Take `n` more bytes, or refuse without taking any if the connection would exceed its
    /// budget.
    fn grow(&mut self, n: usize) -> bool {
        use std::sync::atomic::Ordering;
        let taken = self
            .budget
            .0
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |used| {
                used.checked_add(n)
                    .filter(|&total| total <= CONNECTION_BODY_BUDGET_BYTES)
            })
            .is_ok();
        if taken {
            self.held += n;
        }
        taken
    }
}

impl Drop for BodyReservation {
    fn drop(&mut self) {
        self.budget
            .0
            .fetch_sub(self.held, std::sync::atomic::Ordering::SeqCst);
    }
}

/// The two read bounds a connection is served under, resolved from the startup parameters.
#[derive(Clone, Copy, Debug)]
pub struct H2Bounds {
    pub first_byte: Duration,
    pub idle: Duration,
}

impl H2Bounds {
    /// The declared startup parameters, falling back to the documented defaults.
    pub fn from_secs(first_byte_secs: Option<u64>, idle_secs: Option<u64>) -> Self {
        Self {
            first_byte: first_byte_secs
                .map(Duration::from_secs)
                .unwrap_or(FIRST_BYTE_READ_TIMEOUT),
            idle: idle_secs
                .map(Duration::from_secs)
                .unwrap_or(IDLE_BETWEEN_REQUESTS_TIMEOUT),
        }
    }
}

/// HTTP/2 server with full server push support
pub struct H2Server;

impl H2Server {
    /// Spawn HTTP/2 server using h2 crate directly
    pub async fn spawn_with_push_support(
        listen_addr: SocketAddr,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        server_id: crate::state::ServerId,
        tls_config: Option<Arc<rustls::ServerConfig>>,
        bounds: H2Bounds,
    ) -> anyhow::Result<SocketAddr> {
        // Same reuse semantics as the HTTP/1.1 listener, so a restart on the
        // same port does not fail with EADDRINUSE while the old socket lingers.
        let listener =
            crate::server::socket_helpers::create_reusable_tcp_listener(listen_addr).await?;
        let local_addr = listener.local_addr()?;

        let protocol_name = if tls_config.is_some() {
            "HTTP/2 (TLS, h2 with push)"
        } else {
            "HTTP/2 (h2c with push)"
        };
        Log::to(&status_tx).info(format!(
            "{} server listening on {}",
            protocol_name, local_addr
        ));

        let protocol = Arc::new(Http2Protocol::new());

        // Build the per-server request filter once, up front. This is the code
        // path `Http2Protocol::spawn()` actually uses, so without this the
        // `request_filter` startup param would be silently ignored for HTTP/2.
        let filter = Arc::new(RequestFilter::from_startup_params(
            app_state
                .get_server(server_id)
                .await
                .and_then(|s| s.startup_params)
                .as_ref(),
        ));
        // Fail-open parsing: surface any dropped rule loudly, since the effect
        // is that more requests reach the LLM, not fewer.
        for warning in filter.warnings() {
            let _ = status_tx.send(format!("[ERROR] HTTP/2 request_filter: {}", warning));
        }

        // Create TLS acceptor if TLS is enabled
        let tls_acceptor = tls_config.map(|config| tokio_rustls::TlsAcceptor::from(config));

        // Over TLS a plaintext 503 would be a malformed record, so the refusal is a plain close
        // (see CONNECTION_CAP_REFUSAL).
        let refusal: &'static [u8] = if tls_acceptor.is_some() {
            b""
        } else {
            CONNECTION_CAP_REFUSAL
        };
        let limiter = crate::server::accept_bounded::ConnectionLimiter::new(MAX_CONNECTIONS);

        // Spawn server loop
        let task_registrar = app_state.clone();
        let accept_handle = tokio::spawn(async move {
            loop {
                match crate::server::accept_bounded::accept_bounded(
                    &listener,
                    &limiter,
                    refusal,
                    "HTTP/2",
                    Some(&status_tx),
                )
                .await
                {
                    Ok((tcp_stream, remote_addr, permit)) => {
                        let connection_id =
                            ConnectionId::new(app_state.get_next_unified_id().await);
                        let local_addr_conn = tcp_stream.local_addr().unwrap_or(local_addr);
                        info!(
                            "Accepted {} connection {} from {}",
                            protocol_name, connection_id, remote_addr
                        );

                        // Add connection to ServerInstance
                        use crate::state::server::{
                            ConnectionState as ServerConnectionState, ConnectionStatus,
                            ProtocolConnectionInfo,
                        };
                        let now = crate::utils::clock::Instant::now();
                        let conn_state = ServerConnectionState {
                            id: connection_id,
                            remote_addr,
                            local_addr: local_addr_conn,
                            bytes_sent: 0,
                            bytes_received: 0,
                            packets_sent: 0,
                            packets_received: 0,
                            last_activity: now,
                            status: ConnectionStatus::Active,
                            status_changed_at: now,
                            protocol_info: ProtocolConnectionInfo::new(serde_json::json!({
                                "recent_requests": []
                            })),
                        };
                        app_state
                            .add_connection_to_server(server_id, conn_state)
                            .await;
                        let _ = status_tx.send("__UPDATE_UI__".to_string());

                        let llm_client_clone = llm_client.clone();
                        let app_state_clone = app_state.clone();
                        let status_tx_clone = status_tx.clone();
                        let protocol_clone = protocol.clone();
                        let tls_acceptor_clone = tls_acceptor.clone();
                        let filter_clone = filter.clone();

                        // Tracked, not detached: stop_server must abort this connection too.
                        // A detached one kept reading, answering and calling the model on a
                        // server the operator had stopped.
                        let task_owner = app_state.clone();
                        task_owner
                            .spawn_server_task(server_id, async move {
                                // Held for the life of the connection, so the cap counts live
                                // connections rather than accepts.
                                let _permit = permit;

                                // First-byte bound, before rustls or h2 sees the socket. `peek`
                                // waits for data without consuming it, so the ClientHello or the
                                // connection preface is still there for them afterwards.
                                match tokio::time::timeout(
                                    bounds.first_byte,
                                    tcp_stream.peek(&mut [0u8; 1]),
                                )
                                .await
                                {
                                    Ok(Ok(0)) | Ok(Err(_)) => {
                                        app_state_clone
                                            .close_connection_on_server(server_id, connection_id)
                                            .await;
                                        let _ = status_tx_clone.send("__UPDATE_UI__".to_string());
                                        return;
                                    }
                                    Ok(Ok(_)) => {}
                                    Err(_) => {
                                        debug!(
                                            "{} connection {} sent nothing for {}s; closing \
                                         before the preface",
                                            protocol_name,
                                            connection_id,
                                            bounds.first_byte.as_secs()
                                        );
                                        app_state_clone
                                            .close_connection_on_server(server_id, connection_id)
                                            .await;
                                        let _ = status_tx_clone.send("__UPDATE_UI__".to_string());
                                        return;
                                    }
                                }

                                // Perform TLS handshake if TLS is enabled
                                let result: Result<(), Box<dyn std::error::Error + Send + Sync>> =
                                    if let Some(acceptor) = tls_acceptor_clone {
                                        match tokio::time::timeout(
                                            HANDSHAKE_TIMEOUT,
                                            acceptor.accept(tcp_stream),
                                        )
                                        .await
                                        .unwrap_or_else(|_| {
                                            Err(std::io::Error::new(
                                                std::io::ErrorKind::TimedOut,
                                                "TLS handshake did not complete in time",
                                            ))
                                        }) {
                                            Ok(tls_stream) => {
                                                Log::to(&status_tx_clone).debug(format!(
                                                    "{} TLS handshake complete with {}",
                                                    protocol_name, remote_addr
                                                ));
                                                handle_h2_connection(
                                                    tls_stream,
                                                    connection_id,
                                                    server_id,
                                                    llm_client_clone,
                                                    app_state_clone.clone(),
                                                    status_tx_clone.clone(),
                                                    protocol_clone,
                                                    filter_clone,
                                                    bounds.idle,
                                                )
                                                .await
                                            }
                                            Err(e) => {
                                                Log::to(&status_tx_clone).error(format!(
                                                    "{} TLS handshake failed: {}",
                                                    protocol_name, e
                                                ));
                                                Err(Box::new(e))
                                            }
                                        }
                                    } else {
                                        // No TLS, use plain TCP (h2c)
                                        handle_h2_connection(
                                            tcp_stream,
                                            connection_id,
                                            server_id,
                                            llm_client_clone,
                                            app_state_clone.clone(),
                                            status_tx_clone.clone(),
                                            protocol_clone,
                                            filter_clone,
                                            bounds.idle,
                                        )
                                        .await
                                    };

                                if let Err(e) = result {
                                    error!("{} connection error: {}", protocol_name, e);
                                }

                                // Mark connection as closed
                                app_state_clone
                                    .close_connection_on_server(server_id, connection_id)
                                    .await;
                                let _ = status_tx_clone.send(format!(
                                    "✗ {} connection {connection_id} closed",
                                    protocol_name
                                ));
                                let _ = status_tx_clone.send("__UPDATE_UI__".to_string());
                            })
                            .await;
                    }
                    Err(e) => {
                        error!("Failed to accept HTTP/2 connection: {}", e);
                        break;
                    }
                }
            }
        });

        // Without this, stop_server cannot cancel the accept loop and the socket
        // stays bound after the server is removed.
        task_registrar
            .register_server_task(server_id, accept_handle)
            .await;

        Ok(local_addr)
    }
}

/// Handle a single HTTP/2 connection with full server push support
#[allow(clippy::too_many_arguments)]
async fn handle_h2_connection<T>(
    tcp_stream: T,
    connection_id: ConnectionId,
    server_id: crate::state::ServerId,
    llm_client: OllamaClient,
    app_state: Arc<AppState>,
    status_tx: mpsc::UnboundedSender<String>,
    protocol: Arc<Http2Protocol>,
    filter: Arc<RequestFilter>,
    idle_timeout: Duration,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    // The preface exchange is bounded separately from the first byte: a peer that sent one byte
    // and stalled has passed the first-byte bound and would otherwise sit here forever.
    let mut h2_conn = match tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        bounded_h2_builder().handshake(tcp_stream),
    )
    .await
    {
        Ok(conn) => conn?,
        Err(_) => {
            debug!(
                "HTTP/2 connection {} did not complete the preface in {}s; closing",
                connection_id,
                HANDSHAKE_TIMEOUT.as_secs()
            );
            return Ok(());
        }
    };
    debug!("HTTP/2 handshake complete for connection {}", connection_id);

    // Whether this connection is answering anything. Every stream's task holds it busy for the
    // whole of its answer, so the idle watchdog below cannot close a connection whose request is
    // waiting on the model or parked for a human, however long that takes.
    let activity = Arc::new(crate::server::accept_bounded::ConnectionActivity::new());
    let body_budget = BodyBudget::new();

    // Handle incoming requests. `accept` must keep being polled while streams are answered —
    // it is what drives the connection, including the frames those answers write — so the
    // deadline is a watchdog racing it rather than a timeout around it.
    loop {
        let next = tokio::select! {
            next = h2_conn.accept() => next,
            _ = crate::server::accept_bounded::watch_idle(Arc::clone(&activity), idle_timeout) => {
                debug!(
                    "HTTP/2 connection {} carried no request for {}s; sending GOAWAY",
                    connection_id,
                    idle_timeout.as_secs()
                );
                h2_conn.graceful_shutdown();
                let _ = tokio::time::timeout(GOAWAY_DRAIN_TIMEOUT, async {
                    while let Some(_stream) = h2_conn.accept().await {}
                })
                .await;
                return Ok(());
            }
        };
        let Some(result) = next else { break };
        let (request, send_response) = result?;
        activity.touch();

        let llm_clone = llm_client.clone();
        let app_state_clone = app_state.clone();
        let status_clone = status_tx.clone();
        let protocol_clone = protocol.clone();
        let filter_clone = filter.clone();
        let busy = activity.busy();
        let stream_budget = body_budget.clone();

        // One task per stream, tracked so stop_server aborts an answer in progress too.
        let task_owner = app_state.clone();
        task_owner
            .spawn_server_task(server_id, async move {
                let _busy = busy;
                if let Err(e) = handle_h2_request(
                    request,
                    send_response,
                    connection_id,
                    server_id,
                    llm_clone,
                    app_state_clone,
                    status_clone,
                    protocol_clone,
                    filter_clone,
                    stream_budget,
                )
                .await
                {
                    error!("Error handling HTTP/2 request: {}", e);
                }
            })
            .await;
    }

    Ok(())
}

/// Build an `http::Response<()>` from model- or config-supplied parts without
/// panicking and without failing the whole request: an out-of-range status
/// becomes 500 and headers hyper rejects (e.g. containing CR/LF) are dropped.
fn build_h2_response_head(
    status: u16,
    headers: impl IntoIterator<Item = (String, String)>,
    context: &str,
) -> Response<()> {
    let status_code = StatusCode::from_u16(status).unwrap_or_else(|_| {
        error!(
            "{}: invalid HTTP status {} (must be 100-599), sending 500 instead",
            context, status
        );
        StatusCode::INTERNAL_SERVER_ERROR
    });

    let mut builder = Response::builder().status(status_code);
    for (name, value) in headers {
        match (
            http::header::HeaderName::from_bytes(name.as_bytes()),
            http::header::HeaderValue::from_str(&value),
        ) {
            (Ok(n), Ok(v)) => builder = builder.header(n, v),
            _ => warn!("{}: dropping invalid response header {:?}", context, name),
        }
    }

    builder.body(()).unwrap_or_else(|e| {
        error!(
            "{}: failed to build response ({}), sending bare 500",
            context, e
        );
        let mut fallback = Response::new(());
        *fallback.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
        fallback
    })
}

/// Handle a single HTTP/2 request with server push support
#[allow(clippy::too_many_arguments)]
pub async fn handle_h2_request(
    request: Request<h2::RecvStream>,
    mut send_response: SendResponse<Bytes>,
    connection_id: ConnectionId,
    server_id: crate::state::ServerId,
    llm_client: OllamaClient,
    app_state: Arc<AppState>,
    status_tx: mpsc::UnboundedSender<String>,
    protocol: Arc<Http2Protocol>,
    filter: Arc<RequestFilter>,
    body_budget: BodyBudget,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Extract request metadata
    let method = request.method().to_string();
    // For HTTP/2, only use the path+query portion (not scheme/host)
    let uri = request
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or(request.uri().path())
        .to_string();
    let version = format!("{:?}", request.version());

    // Extract headers
    let mut headers = HashMap::new();
    for (name, value) in request.headers() {
        if let Ok(value_str) = value.to_str() {
            headers.insert(name.to_string(), value_str.to_string());
        }
    }

    // Read request body from h2::RecvStream, bounded by the same cap HTTP/1.1 uses.
    // `release_capacity` re-opens the flow-control window after every chunk, so without
    // a total limit a peer can stream an unbounded amount into this Vec — and the body
    // ends up in an LLM prompt, where anything past a few kilobytes is cost with no
    // benefit. Over the cap the stream is answered 413 and never reaches the model.
    let mut body_stream = request.into_body();
    let mut body_bytes = Vec::new();
    let mut body_too_large = false;
    // Held until this stream's answer has been sent; see CONNECTION_BODY_BUDGET_BYTES.
    let mut reservation = body_budget.reservation();
    let mut over_connection_budget = false;

    loop {
        match body_stream.data().await {
            Some(Ok(chunk)) => {
                if body_bytes.len() + chunk.len()
                    > crate::server::http_common::MAX_REQUEST_BODY_BYTES
                {
                    body_too_large = true;
                    break;
                }
                if !reservation.grow(chunk.len()) {
                    over_connection_budget = true;
                    break;
                }
                body_bytes.extend_from_slice(&chunk);
                // Release flow control capacity for this chunk
                let _ = body_stream.flow_control().release_capacity(chunk.len());
            }
            Some(Err(e)) => {
                warn!("Error reading request body: {}", e);
                let _ = status_tx.send(format!("[WARN] Error reading body: {}", e));
                break;
            }
            None => {
                // End of stream
                break;
            }
        }
    }

    if over_connection_budget {
        let held_by_others = body_budget.in_use().saturating_sub(body_bytes.len());
        // Release this stream's share before answering: it is refused, not waiting.
        drop(body_bytes);
        drop(reservation);
        warn!(
            "HTTP/2 {} {} decision=refused_connection_body_budget: the connection's other \
             streams hold {} of {} body bytes",
            method, uri, held_by_others, CONNECTION_BODY_BUDGET_BYTES
        );
        let _ = status_tx.send(format!("→ HTTP/2 {} {} → 503", method, uri));
        let body = "Service Unavailable: this connection is already buffering as many request \
                    bodies as it may; retry when an earlier request has been answered\n";
        let response = build_h2_response_head(
            503,
            [
                ("content-type".to_string(), "text/plain".to_string()),
                ("retry-after".to_string(), "1".to_string()),
            ],
            "HTTP/2 connection body budget",
        );
        let mut stream = send_response.send_response(response, false)?;
        stream.send_data(Bytes::from(body), true)?;
        app_state
            .update_connection_stats(
                server_id,
                connection_id,
                None,
                Some(body.len() as u64),
                None,
                Some(1),
            )
            .await;
        return Ok(());
    }

    if body_too_large {
        warn!(
            "HTTP/2 {} {} decision=refused_body_too_large: over {} bytes",
            method,
            uri,
            crate::server::http_common::MAX_REQUEST_BODY_BYTES
        );
        let _ = status_tx.send(format!("→ HTTP/2 {} {} → 413", method, uri));
        let body = format!(
            "Payload Too Large: request bodies are limited to {} bytes\n",
            crate::server::http_common::MAX_REQUEST_BODY_BYTES
        );
        let body_len = body.len() as u64;
        let response = build_h2_response_head(
            413,
            [("content-type".to_string(), "text/plain".to_string())],
            "HTTP/2 payload too large",
        );
        let mut stream = send_response.send_response(response, false)?;
        stream.send_data(Bytes::from(body), true)?;
        app_state
            .update_connection_stats(
                server_id,
                connection_id,
                None,
                Some(body_len),
                None,
                Some(1),
            )
            .await;
        return Ok(());
    }

    // Record the inbound message against the *connection* (streams are not in the
    // connection map). This has to happen before the filter check so a filtered
    // request still refreshes last_activity: cleanup_old_connections evicts any
    // connection idle for 10s, and an HTTP/2 connection normally outlives that.
    // A "packet" is one HTTP/2 message; bytes are body only, since h2 has already
    // consumed the HEADERS frame by this point.
    app_state
        .update_connection_stats(
            server_id,
            connection_id,
            Some(body_bytes.len() as u64),
            None,
            Some(1),
            None,
        )
        .await;

    // Log request
    debug!(
        "HTTP/2 request: {} {} {} ({} bytes) from {:?}",
        method,
        uri,
        version,
        body_bytes.len(),
        connection_id
    );
    let _ = status_tx.send(format!(
        "[DEBUG] HTTP/2 request: {} {} {} ({} bytes)",
        method,
        uri,
        version,
        body_bytes.len()
    ));

    // Apply the per-server request filter before spending an LLM call: only
    // allowlisted requests reach the model, everything else gets the configured
    // auto-response (default 404). Same semantics as HTTP/1.1.
    let path = uri.split('?').next().unwrap_or(&uri).to_string();
    if !filter.is_pass_through() {
        let request_data = RequestData {
            method: method.clone(),
            uri: uri.clone(),
            version: version.clone(),
            headers: headers.clone(),
            body_bytes: Bytes::from(body_bytes.clone()),
        };
        if !filter.allows(&request_data, &path) {
            let (status, hdrs, body) = filter.rejection_parts();
            let _ = status_tx.send(format!(
                "↩ HTTP/2 filtered {} {} → {} (no LLM call)",
                method, path, status
            ));
            let body_len = body.len() as u64;
            let response = build_h2_response_head(status, hdrs, "HTTP/2 filtered_response");
            let mut stream = send_response.send_response(response, false)?;
            stream.send_data(Bytes::from(body), true)?;
            app_state
                .update_connection_stats(
                    server_id,
                    connection_id,
                    None,
                    Some(body_len),
                    None,
                    Some(1),
                )
                .await;
            return Ok(());
        }
    }

    // Create event for LLM.
    //
    // Request bodies are attacker-controlled and need not be UTF-8. Action/event design
    // rules forbid handing the model raw bytes or base64, so the body is always presented
    // as (lossily) decoded text — but a non-UTF-8 body is flagged explicitly rather than
    // silently mangled into U+FFFD, so the model knows the text it sees is not the real
    // payload. Same contract as HTTP/1.1.
    let body_is_binary = std::str::from_utf8(&body_bytes).is_err();
    let body_text = String::from_utf8_lossy(&body_bytes);
    let mut event_data = serde_json::json!({
        "method": method,
        "uri": uri,
        "version": version,
        "headers": headers,
        "body": if body_text.is_empty() { "" } else { body_text.as_ref() },
        "body_bytes": body_bytes.len()
    });
    if body_is_binary {
        event_data["body_is_binary"] = serde_json::Value::Bool(true);
    }
    let event = Event::new(&HTTP2_REQUEST_EVENT, event_data);

    // Call LLM to generate response
    match call_llm(
        &llm_client,
        &app_state,
        server_id,
        Some(connection_id),
        &event,
        protocol.as_ref(),
    )
    .await
    {
        Ok(execution_result) => {
            debug!("LLM HTTP/2 response received");

            // Display messages
            for msg in execution_result.messages {
                let _ = status_tx.send(msg);
            }

            // Extract response and pushes from protocol results
            let mut status_code = 200;
            let mut response_headers = HashMap::new();
            let mut response_body = String::new();
            let mut pushes = Vec::new();
            // Did any action actually yield a response? Without this the 200 above is emitted
            // whenever the model answered with nothing, with output that is not JSON, or with
            // JSON carrying no status/headers/body — an empty 200 that a client reads as a
            // successful, empty resource. A server push alone does not count: a PUSH_PROMISE
            // is an extra resource offered alongside an answer, not the answer itself.
            let mut produced_response = false;

            for protocol_result in execution_result.protocol_results {
                match protocol_result {
                    ActionResult::Output(output_data) => {
                        // Parse JSON output
                        if let Ok(json_value) =
                            serde_json::from_slice::<serde_json::Value>(&output_data)
                        {
                            // Check if this is a push directive
                            if json_value
                                .get("_push_directive")
                                .and_then(|v| v.as_bool())
                                .unwrap_or(false)
                            {
                                // This is a push request
                                let push = PendingPush {
                                    path: json_value
                                        .get("path")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("/")
                                        .to_string(),
                                    method: json_value
                                        .get("method")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("GET")
                                        .to_string(),
                                    status: json_value
                                        .get("status")
                                        .and_then(|v| v.as_u64())
                                        .unwrap_or(200)
                                        as u16,
                                    headers: json_value
                                        .get("headers")
                                        .and_then(|v| v.as_object())
                                        .map(|obj| {
                                            obj.iter()
                                                .filter_map(|(k, v)| {
                                                    v.as_str().map(|s| (k.clone(), s.to_string()))
                                                })
                                                .collect()
                                        })
                                        .unwrap_or_default(),
                                    body: json_value
                                        .get("body")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("")
                                        .as_bytes()
                                        .to_vec(),
                                };
                                pushes.push(push);
                            } else {
                                // This is the main HTTP response
                                if let Some(status) =
                                    json_value.get("status").and_then(|v| v.as_u64())
                                {
                                    status_code = status as u16;
                                    produced_response = true;
                                }
                                if let Some(headers_obj) =
                                    json_value.get("headers").and_then(|v| v.as_object())
                                {
                                    for (k, v) in headers_obj {
                                        if let Some(v_str) = v.as_str() {
                                            response_headers.insert(k.clone(), v_str.to_string());
                                            produced_response = true;
                                        }
                                    }
                                }
                                if let Some(body) = json_value.get("body").and_then(|v| v.as_str())
                                {
                                    response_body = body.to_string();
                                    produced_response = true;
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }

            // Execute server pushes BEFORE sending main response
            for push in pushes {
                debug!("Executing server push for {}", push.path);
                let push_body_len = push.body.len();

                // Create push promise request
                let mut push_request = http::Request::builder()
                    .method(push.method.as_str())
                    .uri(&push.path);

                for (name, value) in &push.headers {
                    push_request = push_request.header(name, value);
                }

                if let Ok(push_req) = push_request.body(()) {
                    // Send push promise
                    match send_response.push_request(push_req) {
                        Ok(mut push_stream) => {
                            // Send push response
                            let mut push_response = http::Response::builder().status(push.status);

                            for (name, value) in &push.headers {
                                push_response = push_response.header(name, value);
                            }

                            if let Ok(push_resp) = push_response.body(()) {
                                match push_stream.send_response(push_resp, false) {
                                    Ok(mut stream) => {
                                        if let Err(e) =
                                            stream.send_data(Bytes::from(push.body), true)
                                        {
                                            warn!(
                                                "Failed to send push body for {}: {}",
                                                push.path, e
                                            );
                                        } else {
                                            debug!("Successfully pushed {}", push.path);
                                            let _ = status_tx.send(format!(
                                                "⬆ Pushed {} ({} bytes)",
                                                push.path, push_body_len
                                            ));
                                            // A push is an extra message on the wire.
                                            app_state
                                                .update_connection_stats(
                                                    server_id,
                                                    connection_id,
                                                    None,
                                                    Some(push_body_len as u64),
                                                    None,
                                                    Some(1),
                                                )
                                                .await;
                                        }
                                    }
                                    Err(e) => {
                                        warn!(
                                            "Failed to send push response for {}: {}",
                                            push.path, e
                                        );
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            warn!("Client rejected push for {}: {}", push.path, e);
                        }
                    }
                }
            }

            // Nothing usable came back.
            //
            // If the operator configured a `default_response`, that is a deliberate
            // answer for exactly this case and it is used — the parameter is declared by
            // `request_handling_startup_parameters()`, which HTTP/2 advertises, and until
            // now HTTP/2 read it nowhere, so setting it changed nothing here.
            //
            // With no `default_response`, refuse rather than emitting the pre-set 200,
            // which a client cannot tell from a real, empty answer.
            if !produced_response {
                if let Some((status, hdrs, body)) = filter.default_response_parts() {
                    warn!(
                        "HTTP/2 {} {} decision=default_response: actions ran but none \
                         yielded a response; answering the configured default ({})",
                        method, uri, status
                    );
                    let _ = status_tx.send(format!(
                        "→ HTTP/2 {} {} → {} (configured default_response)",
                        method, uri, status
                    ));
                    let body_len = body.len() as u64;
                    let response = build_h2_response_head(status, hdrs, "HTTP/2 default_response");
                    let mut stream = send_response.send_response(response, false)?;
                    stream.send_data(Bytes::from(body), true)?;
                    app_state
                        .update_connection_stats(
                            server_id,
                            connection_id,
                            None,
                            Some(body_len),
                            None,
                            Some(1),
                        )
                        .await;
                    return Ok(());
                }

                warn!(
                    "HTTP/2 {} {} decision=fail_closed_no_action: actions ran but none \
                     yielded a response",
                    method, uri
                );
                let _ = status_tx.send(format!(
                    "✗ HTTP/2 {} {} → 500 (no response action produced)",
                    method, uri
                ));
                let body = crate::utils::WireFailure::Unavailable.prefixed_text();
                let response = Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(())?;
                let mut stream = send_response.send_response(response, false)?;
                stream.send_data(Bytes::from(body), true)?;
                app_state
                    .update_connection_stats(
                        server_id,
                        connection_id,
                        None,
                        Some(body.len() as u64),
                        None,
                        Some(1),
                    )
                    .await;
                return Ok(());
            }

            // Send main response
            let _ = status_tx.send(format!(
                "→ HTTP/2 {} {} → {} ({} bytes)",
                method,
                uri,
                status_code,
                response_body.len()
            ));

            // Status and headers come from model output; never let a bogus
            // value abort the request without a response.
            let body_len = response_body.len() as u64;
            let response = build_h2_response_head(status_code, response_headers, "HTTP/2");
            let mut stream = send_response.send_response(response, false)?;
            stream.send_data(Bytes::from(response_body), true)?;
            app_state
                .update_connection_stats(
                    server_id,
                    connection_id,
                    None,
                    Some(body_len),
                    None,
                    Some(1),
                )
                .await;
        }
        Err(e) => {
            // Same split HTTP/1.1 makes in `http_common::build_error_response`, which root
            // CLAUDE.md names as the shape to copy: an *overloaded* backend is transient
            // and gets 503 + `Retry-After` so the client backs off, anything else gets 500
            // and is treated as a permanent fault. HTTP/2 answered a flat 500 for both,
            // so a client could not tell "come back in a second" from "this is broken".
            //
            // Only the category reaches the peer; `e` is logged and never rendered onto
            // the wire.
            let failure = crate::utils::WireFailure::classify(&e);
            let (status, decision) = match failure {
                crate::utils::WireFailure::Overloaded => (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "fail_closed_llm_overloaded",
                ),
                crate::utils::WireFailure::Unavailable => {
                    (StatusCode::INTERNAL_SERVER_ERROR, "fail_closed_llm_error")
                }
            };
            error!(
                "HTTP/2 {} {} decision={} status={}: {}",
                method,
                uri,
                decision,
                status.as_u16(),
                e
            );
            let _ = status_tx.send(format!(
                "✗ LLM error for {} {} → {}: {}",
                method,
                uri,
                status.as_u16(),
                e
            ));

            let error_body = failure.prefixed_text();
            let mut builder = Response::builder().status(status);
            if failure.is_overloaded() {
                builder = builder.header(http::header::RETRY_AFTER, "1");
            }
            let response = builder.body(())?;
            let mut stream = send_response.send_response(response, false)?;
            stream.send_data(Bytes::from(error_body), true)?;
            app_state
                .update_connection_stats(
                    server_id,
                    connection_id,
                    None,
                    Some(error_body.len() as u64),
                    None,
                    Some(1),
                )
                .await;
        }
    }

    Ok(())
}

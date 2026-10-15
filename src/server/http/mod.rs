//! HTTP server implementation using hyper
pub mod actions;

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use tokio::sync::mpsc;
use tracing::{debug, error, info};

use crate::llm::action_helper::call_llm;
use crate::llm::ollama_client::OllamaClient;
use crate::logging::emit::Log;
use crate::protocol::Event;
use crate::server::connection::ConnectionId;
use crate::server::HttpProtocol;
use crate::state::app_state::AppState;
use actions::HTTP_REQUEST_EVENT;

/// How long a peer that has connected and produced nothing may hold a slot.
///
/// HTTP is client-speaks-first: the server says nothing until a request line arrives, so a peer
/// that has completed the TCP handshake and sent no byte has asked nothing and negotiated
/// nothing. That state carries no protocol yet, which is why this number is the same across
/// netget's HTTP-shaped servers while the idle bound below is not. Apache's `mod_reqtimeout`
/// gives the request header 20s and nginx's `client_header_timeout` 60s; 30s sits between the
/// two deployed norms.
///
/// hyper's own `header_read_timeout` is **not** this bound: its 30-second default is inert
/// unless `http1::Builder::timer` is also set, which nothing here does — hyper downgrades a
/// defaulted duration to `None` when no timer is present and applies no deadline at all.
const FIRST_BYTE_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// How long a connection with nothing outstanding may sit idle between requests.
///
/// nginx's `keepalive_timeout` default, and this is the one server in the family where copying
/// it needs no further argument: a netget HTTP server's clients are whatever the operator points
/// at it — a browser, `curl`, a generated SDK — so the number the deployed web is already tuned
/// against is the right one. Apache's `KeepAliveTimeout` of 5s is the other end of the range and
/// is tuned for a front-end serving far more connections than this one admits.
///
/// A request still being answered is not silence: the watchdog reads
/// [`ConnectionActivity`](crate::server::accept_bounded::ConnectionActivity), which reports a
/// connection with work in flight — a model round-trip, or an event a `manual` rule parked for a
/// human at the dashboard (`src/state/intercepts.rs`, 300s by default) — as not idle at all. So
/// an answer that takes longer than this bound can never close the connection it is an answer
/// for, which is the `.connectionless()`/TFTP lesson read in reverse.
const IDLE_BETWEEN_REQUESTS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(75);

/// Concurrent connections this server admits.
///
/// Below the shared `DEFAULT_MAX_CONNECTIONS` of 256 on purpose: each admitted connection may
/// buffer one body of up to `http_common::MAX_REQUEST_BODY_BYTES` (8 MiB), which is the largest
/// per-connection cost in netget's HTTP family, and the cap is what turns that per-connection
/// bound into a total one. 128 holds the worst case to the same ~1 GiB ceiling the 4 MiB and
/// 64 KiB servers reach at 256.
///
/// It is not a throughput knob, and it is deliberately not configurable: a bound decided by
/// configuration is a bound an attacker can ask you to raise.
const MAX_CONNECTIONS: usize = 128;

/// What a peer over [`MAX_CONNECTIONS`] is told before the socket closes.
///
/// `503 Service Unavailable` with a `Retry-After`, written directly onto the socket because the
/// peer has not sent a request line for hyper to answer. Fixed bytes: nothing derived from an
/// error reaches the wire (see `crate::utils::wire_failure`).
const CONNECTION_CAP_REFUSAL: &[u8] = b"HTTP/1.1 503 Service Unavailable\r\n\
    Content-Length: 0\r\nRetry-After: 5\r\nConnection: close\r\n\r\n";

/// HTTP server that delegates request handling to LLM
pub struct HttpServer;

impl HttpServer {
    /// Spawn the HTTP server with integrated LLM actions
    pub async fn spawn_with_llm_actions(
        listen_addr: SocketAddr,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        server_id: crate::state::ServerId,
        tls_config: Option<Arc<rustls::ServerConfig>>,
    ) -> anyhow::Result<SocketAddr> {
        let listener =
            crate::server::socket_helpers::create_reusable_tcp_listener(listen_addr).await?;
        let local_addr = listener.local_addr()?;

        let protocol_name = if tls_config.is_some() {
            "HTTPS"
        } else {
            "HTTP"
        };
        Log::new(Some(&status_tx)).info(format!(
            "{} server listening on {}",
            protocol_name, local_addr
        ));

        let protocol = Arc::new(HttpProtocol::new());

        // Build the per-server request filter once, at startup: path regexes
        // compile once for the life of the server, and a bad rule is reported
        // while the caller is still watching the start_server result rather than
        // on the first connection.
        let filter = Arc::new(
            crate::server::http_common::handler::RequestFilter::from_startup_params(
                app_state
                    .get_server(server_id)
                    .await
                    .and_then(|s| s.startup_params)
                    .as_ref(),
            ),
        );
        // Filter parsing is fail-open: a bad rule is dropped, not fatal, so every
        // request would silently reach the LLM. Make that visible in the TUI/MCP
        // status stream, not just in netget.log.
        let filter_log = Log::new(Some(&status_tx));
        for warning in filter.warnings() {
            filter_log.error(format!("HTTP request_filter: {}", warning));
        }

        // Create TLS acceptor if TLS is enabled
        let tls_acceptor = tls_config.map(|config| tokio_rustls::TlsAcceptor::from(config));

        // Spawn server loop
        let task_registrar = app_state.clone();
        let limiter = crate::server::accept_bounded::ConnectionLimiter::new(MAX_CONNECTIONS);
        let accept_handle = tokio::spawn(async move {
            loop {
                match crate::server::accept_bounded::accept_bounded(
                    &listener,
                    &limiter,
                    CONNECTION_CAP_REFUSAL,
                    "HTTP",
                    Some(&status_tx),
                )
                .await
                {
                    Ok((stream, remote_addr, permit)) => {
                        let connection_id =
                            ConnectionId::new(app_state.get_next_unified_id().await);
                        let local_addr_conn = stream.local_addr().unwrap_or(local_addr);
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

                        // Spawn a task to handle this connection
                        // Tracked, not detached: stop_server must abort this task too.
                        let task_owner = app_state.clone();
                        task_owner
                            .spawn_server_task(server_id, async move {
                                // First-byte bound, before hyper sees the socket.
                                //
                                // hyper owns every read once `serve_connection` starts, and a
                                // deadline on those reads would be wrong here rather than merely
                                // awkward: hyper keeps polling the connection for more input
                                // while a request is being answered, so such a deadline would
                                // fire in the middle of a model round-trip. `peek` waits for data
                                // without consuming it, so the request line is still there for
                                // hyper afterwards, and it bounds exactly the case that needs
                                // bounding - a peer that has connected and sent nothing at all.
                                let spoke = matches!(
                                    tokio::time::timeout(
                                        FIRST_BYTE_READ_TIMEOUT,
                                        stream.peek(&mut [0u8; 1]),
                                    )
                                    .await,
                                    Ok(Ok(n)) if n > 0
                                );

                                if !spoke {
                                    Log::new(Some(&status_tx_clone)).debug(format!(
                                        "{} peer {} sent nothing for {}s; closing before any \
                                         request",
                                        protocol_name,
                                        remote_addr,
                                        FIRST_BYTE_READ_TIMEOUT.as_secs()
                                    ));
                                    app_state_clone
                                        .close_connection_on_server(server_id, connection_id)
                                        .await;
                                    let _ = status_tx_clone.send("__UPDATE_UI__".to_string());
                                    return;
                                }

                                // Survives this task: an h2c upgrade moves the connection to a
                                // separate task, and the slot must stay taken while it runs.
                                let permit = std::sync::Arc::new(permit);

                                // Tracks whether this connection is answering anything, so the
                                // idle watchdog in `serve_connection` cannot close a connection
                                // whose answer is still being composed.
                                let activity = std::sync::Arc::new(
                                    crate::server::accept_bounded::ConnectionActivity::new(),
                                );

                                // Perform TLS handshake if TLS is enabled
                                if let Some(acceptor) = tls_acceptor_clone {
                                    match acceptor.accept(stream).await {
                                        Ok(tls_stream) => {
                                            Log::new(Some(&status_tx_clone)).debug(format!(
                                                "{} TLS handshake complete with {}",
                                                protocol_name, remote_addr
                                            ));
                                            let io = TokioIo::new(tls_stream);
                                            Self::serve_connection(
                                                io,
                                                connection_id,
                                                server_id,
                                                llm_client_clone,
                                                app_state_clone.clone(),
                                                status_tx_clone.clone(),
                                                protocol_clone,
                                                filter_clone,
                                                activity,
                                                permit,
                                            )
                                            .await;
                                        }
                                        Err(e) => {
                                            Log::new(Some(&status_tx_clone)).warn(format!(
                                                "{} TLS handshake failed: {}",
                                                protocol_name, e
                                            ));
                                        }
                                    }
                                } else {
                                    // No TLS, use plain TCP
                                    let io = TokioIo::new(stream);
                                    Self::serve_connection(
                                        io,
                                        connection_id,
                                        server_id,
                                        llm_client_clone,
                                        app_state_clone.clone(),
                                        status_tx_clone.clone(),
                                        protocol_clone,
                                        filter_clone,
                                        activity,
                                        permit,
                                    )
                                    .await;
                                }

                                // Mark connection as closed
                                app_state_clone
                                    .close_connection_on_server(server_id, connection_id)
                                    .await;
                                Log::new(Some(&status_tx_clone)).info(format!(
                                    "{} connection {connection_id} closed",
                                    protocol_name
                                ));
                                let _ = status_tx_clone.send("__UPDATE_UI__".to_string());
                            })
                            .await;
                    }
                    Err(e) => {
                        Log::new(Some(&status_tx))
                            .error(format!("Failed to accept HTTP connection: {}", e));
                        break;
                    }
                }
            }
        });

        task_registrar
            .register_server_task(server_id, accept_handle)
            .await;

        Ok(local_addr)
    }

    /// Serve an HTTP connection (helper function to avoid code duplication)
    #[allow(clippy::too_many_arguments)]
    async fn serve_connection<T>(
        io: TokioIo<T>,
        connection_id: ConnectionId,
        server_id: crate::state::ServerId,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        protocol: Arc<HttpProtocol>,
        filter: Arc<crate::server::http_common::handler::RequestFilter>,
        activity: Arc<crate::server::accept_bounded::ConnectionActivity>,
        permit: Arc<crate::server::accept_bounded::ConnectionPermit>,
    ) where
        T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        // Clone for service closure
        let status_for_service = status_tx.clone();
        let app_state_for_service = app_state.clone();
        let activity_for_service = Arc::clone(&activity);

        // The request filter is built once per server in spawn_with_llm_actions.
        // Create a service that handles requests with LLM
        let service = service_fn(move |req: Request<Incoming>| {
            let llm_clone = llm_client.clone();
            let state_clone = app_state_for_service.clone();
            let status_clone = status_for_service.clone();
            let protocol_clone = protocol.clone();
            let filter_clone = filter.clone();
            let activity = Arc::clone(&activity_for_service);
            // Kept alive for the whole request, and cloned into an h2c upgrade if one happens,
            // so the connection cap counts this peer for as long as it is really here.
            let permit_clone = Arc::clone(&permit);
            async move {
                // Held for the whole request, so an answer waiting on the model — or parked for
                // a human by a `manual` rule — reads as work in flight rather than as silence.
                let _busy = activity.busy();
                handle_http_request_with_llm_actions(
                    req,
                    connection_id,
                    server_id,
                    llm_clone,
                    state_clone,
                    status_clone,
                    protocol_clone,
                    filter_clone,
                    permit_clone,
                )
                .await
            }
        });

        // Serve HTTP/1 on this connection with upgrade support, bounded on idle time.
        let conn = http1::Builder::new()
            .serve_connection(io, service)
            .with_upgrades();
        tokio::pin!(conn);
        tokio::select! {
            result = &mut conn => {
                if let Err(err) = result {
                    error!("Error serving HTTP connection: {:?}", err);
                }
            }
            _ = crate::server::accept_bounded::watch_idle(
                Arc::clone(&activity),
                IDLE_BETWEEN_REQUESTS_TIMEOUT,
            ) => {
                debug!(
                    "HTTP connection {} idle for {}s; closing",
                    connection_id,
                    IDLE_BETWEEN_REQUESTS_TIMEOUT.as_secs()
                );
            }
        }
    }
}

/// Handle a single HTTP request, recording per-connection statistics around it.
///
/// This wrapper exists because the counters have to be maintained on *every*
/// exit path, including the ones that never reach the model (h2c upgrade,
/// request filter rejection). Two consumers depend on them:
///
/// - `ServerInstance::cleanup_old_connections` (`src/state/server.rs`) drops any
///   connection whose `last_activity` is older than 10s, and both the TUI and
///   the MCP loop call it on a timer. Without a refresh per request, a keep-alive
///   connection is evicted from the state map 10s after it opens while it is
///   still serving traffic, and every later stat update and the eventual
///   `close_connection_on_server` silently target a connection that is gone.
/// - Connection-scoped scheduled tasks put these counters and the idle time
///   straight into the model's prompt (`src/llm/prompt.rs`), which is what an
///   idle-timeout or rate-limiting instruction is supposed to reason about.
///
/// Semantics, matching the other hyper-based servers (see `oauth2`): a "packet"
/// is one HTTP message, and the byte counts are **message bodies only** —
/// request/status line and headers are not counted, since hyper has already
/// parsed them away by the time we see the request.
#[allow(clippy::too_many_arguments)]
async fn handle_http_request_with_llm_actions(
    req: Request<Incoming>,
    connection_id: ConnectionId,
    server_id: crate::state::ServerId,
    llm_client: OllamaClient,
    app_state: Arc<AppState>,
    status_tx: mpsc::UnboundedSender<String>,
    protocol: Arc<HttpProtocol>,
    filter: Arc<crate::server::http_common::handler::RequestFilter>,
    connection_permit: Arc<crate::server::accept_bounded::ConnectionPermit>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    // Count the inbound message before doing anything else, so a request that is
    // filtered out or upgraded still refreshes last_activity.
    app_state
        .update_connection_stats(server_id, connection_id, None, None, Some(1), None)
        .await;

    let response = handle_http_request_inner(
        req,
        connection_id,
        server_id,
        llm_client,
        app_state.clone(),
        status_tx,
        protocol,
        filter,
        connection_permit,
    )
    .await;

    let bytes_sent = response
        .as_ref()
        .ok()
        .and_then(|resp| {
            use hyper::body::Body;
            resp.body().size_hint().exact()
        })
        .unwrap_or(0);
    app_state
        .update_connection_stats(
            server_id,
            connection_id,
            None,
            Some(bytes_sent),
            None,
            Some(1),
        )
        .await;

    response
}

#[allow(clippy::too_many_arguments)]
async fn handle_http_request_inner(
    req: Request<Incoming>,
    connection_id: ConnectionId,
    server_id: crate::state::ServerId,
    llm_client: OllamaClient,
    app_state: Arc<AppState>,
    status_tx: mpsc::UnboundedSender<String>,
    protocol: Arc<HttpProtocol>,
    filter: Arc<crate::server::http_common::handler::RequestFilter>,
    // Only the h2c upgrade below needs this: the
    // upgraded connection outlives the HTTP/1 task that accepted it, so without carrying the
    // permit across, an upgrade would quietly hand the slot back while the peer was still on it.
    connection_permit: Arc<crate::server::accept_bounded::ConnectionPermit>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    // Check for an HTTP/2 upgrade request (h2c)
    {
        if let Some(upgrade_header) = req.headers().get(hyper::header::UPGRADE) {
            if let Ok(upgrade_value) = upgrade_header.to_str() {
                if upgrade_value.contains("h2c") {
                    Log::new(Some(&status_tx)).info(format!(
                        "HTTP/2 upgrade (h2c) requested on connection {}",
                        connection_id
                    ));

                    // Check for HTTP2-Settings header (required for h2c upgrade)
                    if req.headers().get("HTTP2-Settings").is_none() {
                        // Refused by the protocol before any model call.
                        Log::new(Some(&status_tx)).warn(format!(
                            "HTTP h2c upgrade on connection {} decision=protocol_error: no \
                             HTTP2-Settings header (no LLM call)",
                            connection_id
                        ));
                        let response = Response::builder()
                            .status(400) // Bad Request
                            .body(Full::new(Bytes::from(
                                "HTTP/2 upgrade requires HTTP2-Settings header",
                            )))
                            .unwrap();
                        return Ok(response);
                    }

                    // Spawn task to handle upgrade after 101 response
                    let llm_clone = llm_client.clone();
                    let app_state_clone = app_state.clone();
                    let status_tx_clone = status_tx.clone();
                    let protocol_clone = protocol.clone();
                    let filter_clone = filter.clone();
                    let permit_clone = Arc::clone(&connection_permit);

                    // Tracked, not detached: stop_server must abort this task too.
                    let task_owner = app_state.clone();
                    task_owner
                        .spawn_server_task(server_id, async move {
                            // The upgraded connection outlives the HTTP/1 task, so it carries
                            // the connection-cap slot with it.
                            let _permit = permit_clone;
                            // Wait for upgrade to complete
                            match hyper::upgrade::on(req).await {
                                Ok(upgraded) => {
                                    Log::new(Some(&status_tx_clone)).info(format!(
                                        "Upgraded connection {} to HTTP/2",
                                        connection_id
                                    ));

                                    // Perform h2 handshake on the upgraded connection
                                    use hyper_util::rt::TokioIo;
                                    let io = TokioIo::new(upgraded);

                                    // Use h2 server to handle the upgraded connection
                                    if let Err(e) = handle_upgraded_h2c_connection(
                                        io,
                                        connection_id,
                                        server_id,
                                        llm_clone,
                                        app_state_clone,
                                        status_tx_clone,
                                        protocol_clone,
                                        filter_clone,
                                    )
                                    .await
                                    {
                                        error!("Error handling upgraded h2c connection: {}", e);
                                    }
                                }
                                Err(e) => {
                                    Log::new(Some(&status_tx_clone))
                                        .warn(format!("HTTP/2 upgrade failed: {}", e));
                                }
                            }
                        })
                        .await;

                    // Return 101 Switching Protocols
                    let response = Response::builder()
                        .status(101) // 101 Switching Protocols
                        .header(hyper::header::UPGRADE, "h2c")
                        .header(hyper::header::CONNECTION, "Upgrade")
                        .body(Full::new(Bytes::new()))
                        .unwrap();

                    return Ok(response);
                }
            }
        }
    }

    // Use shared request extraction logic. A body over the shared cap is refused with
    // 413 here rather than being truncated: a truncated body handed to the model looks
    // exactly like a complete one, and the model would answer a request it never saw.
    let request_data =
        match crate::server::http_common::handler::extract_request_data(req, "HTTP", &status_tx)
            .await
        {
            Ok(data) => data,
            Err(too_large) => {
                return Ok(
                    crate::server::http_common::handler::build_payload_too_large_response(
                        &too_large, "HTTP", &status_tx,
                    ),
                );
            }
        };

    // The body is the only part of the request whose byte count survives hyper's
    // parsing; the packet counter was already incremented by the caller.
    if !request_data.body_bytes.is_empty() {
        app_state
            .update_connection_stats(
                server_id,
                connection_id,
                Some(request_data.body_bytes.len() as u64),
                None,
                None,
                None,
            )
            .await;
    }

    // Parse URI into path and query components
    let (path, query_string) = if let Some(pos) = request_data.uri.find('?') {
        (
            request_data.uri[..pos].to_string(),
            Some(request_data.uri[pos + 1..].to_string()),
        )
    } else {
        (request_data.uri.clone(), None)
    };

    // Apply the per-server request filter: only forward matching requests to the
    // LLM; everything else gets the configured auto-response (default 404) with
    // no LLM call. With no filter configured this is a no-op (pass-through).
    if !filter.is_pass_through() && !filter.allows(&request_data, &path) {
        let resp = filter.rejection();
        // The server's own request_filter refused this, not the model, and no LLM call was
        // made. Its own token so it is never read as the model having answered.
        Log::new(Some(&status_tx)).info(format!(
            "HTTP {} {} decision=refused_by_filter -> {} (no LLM call)",
            request_data.method,
            path,
            resp.status().as_u16()
        ));
        return Ok(resp);
    }

    // Parse query parameters into structured object
    let query = if let Some(ref qs) = query_string {
        let mut params = serde_json::Map::new();
        for pair in qs.split('&') {
            if let Some((key, value)) = pair.split_once('=') {
                // URL decode the key and value
                let decoded_key =
                    urlencoding::decode(key).unwrap_or(std::borrow::Cow::Borrowed(key));
                let decoded_value =
                    urlencoding::decode(value).unwrap_or(std::borrow::Cow::Borrowed(value));
                params.insert(
                    decoded_key.to_string(),
                    serde_json::Value::String(decoded_value.to_string()),
                );
            } else {
                // Handle keys without values
                let decoded_key =
                    urlencoding::decode(pair).unwrap_or(std::borrow::Cow::Borrowed(pair));
                params.insert(
                    decoded_key.to_string(),
                    serde_json::Value::String(String::new()),
                );
            }
        }
        serde_json::Value::Object(params)
    } else {
        serde_json::Value::Object(serde_json::Map::new())
    };

    // Create HTTP request event with path, query_string, and parsed query.
    //
    // Request bodies are attacker-controlled and need not be UTF-8. Action/event
    // design rules forbid handing the model raw bytes or base64, so the body is
    // always presented as (lossily) decoded text, and a non-UTF8 body is flagged
    // explicitly rather than silently mangled into U+FFFD.
    let body_is_binary = std::str::from_utf8(&request_data.body_bytes).is_err();
    let body_text = String::from_utf8_lossy(&request_data.body_bytes);
    let mut event_data = serde_json::json!({
        "method": request_data.method,
        "path": path,
        "query": query,
        "headers": request_data.headers,
        "body": if body_text.is_empty() { "" } else { body_text.as_ref() },
        "body_bytes": request_data.body_bytes.len()
    });
    if body_is_binary {
        event_data["body_is_binary"] = serde_json::Value::Bool(true);
    }

    // Add query_string field if present
    if let Some(qs) = query_string {
        event_data["query_string"] = serde_json::Value::String(qs);
    }

    let event = Event::new(&HTTP_REQUEST_EVENT, event_data);

    // Call LLM to generate HTTP response
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
            debug!("LLM HTTP response received");

            // Display messages
            for msg in execution_result.messages {
                let _ = status_tx.send(msg);
            }

            // `build_response` decides this protocol's terminal outcome, and it decides it
            // silently. It lives in `src/server/http_common/handler.rs`, shared with
            // ipp/openapi/…, so the tag has to be applied here at the call site instead.
            //
            // `produced_http_response` is `build_response`'s own predicate, exported so this
            // line cannot drift from the bytes that actually go out: a tag claiming the model
            // answered while the peer received the fallback would be worse than no tag. When
            // it is false the model produced no usable `send_http_response`, and the server
            // answers anyway — with the configured `default_response` if there is one, and
            // otherwise with a blank **200**.
            //
            // **That last branch is a fail-open**, recorded here rather than repaired in
            // this pass: an unreachable model, a model that answered with nothing, and a
            // model that deliberately answered `200 OK` are three different things that all
            // reach the peer as `200 OK` with an empty body. `decision=fail_closed_*` would
            // be a lie on that path, so the silence is tagged as the model's and the
            // fallback that was actually used is named in the same line.
            let produced_response = crate::server::http_common::handler::produced_http_response(
                &execution_result.protocol_results,
            );
            let failure_summary = execution_result
                .failures
                .iter()
                .map(|f| format!("{}: {}", f.action, f.error))
                .collect::<Vec<_>>()
                .join("; ");
            let has_default_response = filter.default_response_parts().is_some();
            let fallback = if has_default_response {
                "default_response"
            } else {
                "blank_200"
            };
            let subject = format!(
                "HTTP {} {} (connection {})",
                request_data.method, request_data.uri, connection_id
            );
            let log = Log::new(Some(&status_tx));
            if produced_response {
                log.info(format!("{} decision=model_answer", subject));
            } else if !failure_summary.is_empty() {
                log.error(format!(
                    "{} decision=model_bad_action fallback={}: the model answered but its \
                     action(s) could not be executed ({}), and the peer is still given an \
                     affirmative response",
                    subject, fallback, failure_summary
                ));
            } else if has_default_response {
                log.warn(format!(
                    "{} decision=model_silent fallback=default_response: the model produced no \
                     send_http_response, so the server's configured default_response was sent",
                    subject
                ));
            } else {
                log.warn(format!(
                    "{} decision=model_silent fallback=blank_200: the model produced no \
                     send_http_response and no default_response is configured, so the peer is \
                     answered 200 with an empty body (fail-open)",
                    subject
                ));
            }

            // Use shared response building logic
            crate::server::http_common::handler::build_response(
                execution_result.protocol_results,
                "HTTP",
                &request_data.method,
                &request_data.uri,
                &status_tx,
                filter.default_response_parts(),
            )
        }
        Err(e) => {
            // Use shared error response building
            crate::server::http_common::handler::build_error_response(
                e,
                "HTTP",
                &request_data.method,
                &request_data.uri,
                &status_tx,
            )
        }
    }
}

/// Handle an upgraded h2c connection (only available with http2 feature)
#[allow(clippy::too_many_arguments)]
async fn handle_upgraded_h2c_connection<T>(
    io: T,
    connection_id: ConnectionId,
    server_id: crate::state::ServerId,
    llm_client: OllamaClient,
    app_state: Arc<AppState>,
    status_tx: mpsc::UnboundedSender<String>,
    _protocol: Arc<HttpProtocol>,
    filter: Arc<crate::server::http_common::handler::RequestFilter>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    use crate::server::Http2Protocol;

    info!("Starting h2c connection for {}", connection_id);

    // Perform h2 server handshake
    // The same SETTINGS as a prior-knowledge HTTP/2 connection: stream count, windows, frame
    // and header-list sizes, and one body budget shared by the connection's streams.
    let mut h2_conn = crate::server::http2::h2_server::bounded_h2_builder()
        .handshake(io)
        .await?;
    let body_budget = crate::server::http2::h2_server::BodyBudget::new();

    let protocol = Arc::new(Http2Protocol::new());

    // The upgraded connection gets the same idle bound as the HTTP/1 one it came from:
    // reaching h2c costs one request, after which an unbounded peer could hold the stream — and
    // the slot it carried across — indefinitely.
    let activity = Arc::new(crate::server::accept_bounded::ConnectionActivity::new());

    // Accept requests on the h2 connection
    loop {
        let accepted = tokio::select! {
            accepted = h2_conn.accept() => accepted,
            _ = crate::server::accept_bounded::watch_idle(
                Arc::clone(&activity),
                IDLE_BETWEEN_REQUESTS_TIMEOUT,
            ) => {
                debug!(
                    "H2C connection {} idle for {}s; closing",
                    connection_id,
                    IDLE_BETWEEN_REQUESTS_TIMEOUT.as_secs()
                );
                break;
            }
        };
        match accepted {
            Some(result) => {
                let (request, send_response) = result?;

                let llm_clone = llm_client.clone();
                let app_state_clone = app_state.clone();
                let status_tx_clone = status_tx.clone();
                let protocol_clone = protocol.clone();
                let filter_clone = filter.clone();
                let activity_clone = Arc::clone(&activity);
                let stream_budget = body_budget.clone();

                // Spawn task to handle this HTTP/2 request
                // Tracked, not detached: stop_server must abort this task too.
                let task_owner = app_state.clone();
                task_owner
                    .spawn_server_task(server_id, async move {
                        // In flight for the whole request, so a model round-trip or a parked
                        // `manual` event reads as work rather than as an idle connection.
                        let _busy = activity_clone.busy();
                        if let Err(e) = crate::server::http2::h2_server::handle_h2_request(
                            request,
                            send_response,
                            connection_id,
                            server_id,
                            llm_clone,
                            app_state_clone,
                            status_tx_clone,
                            protocol_clone,
                            filter_clone,
                            stream_budget,
                        )
                        .await
                        {
                            error!("Error handling h2c request: {}", e);
                        }
                    })
                    .await;
            }
            None => {
                // Connection closed
                info!("H2C connection {} closed", connection_id);
                break;
            }
        }
    }

    Ok(())
}

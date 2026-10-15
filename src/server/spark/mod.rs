//! Apache Spark monitoring REST API server.
//!
//! Serves the Spark monitoring endpoints a client / the History Server UI hits
//! (`/api/v1/applications`, `.../{id}/jobs`, `/stages`, `/executors`). The LLM roleplays the
//! application's control plane, inventing applications/jobs/stages/executors per request.
//!
//! Static vs LLM-driven:
//! - `GET /api/v1/version` — mechanical version banner, answered **statically** (no LLM).
//! - Unrecognised paths get a static 404 (plain text), no LLM call.
//! - `applications`, `jobs`, `stages`, `executors` — **LLM-driven**.
//!
//! Fail-closed: on an LLM error, or when the model produces no `spark_response`, the server
//! answers 503/500 with a JSON error object — never a success-shaped empty array (which a client
//! cannot distinguish from a genuinely empty application list).

pub mod actions;

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::{Body, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use tokio::sync::mpsc;
use tracing::{error, trace, warn};

use crate::llm::ollama_client::OllamaClient;
use crate::llm::ActionResult;
use crate::logging::emit::Log;
use crate::server::accept_bounded::{
    accept_bounded, watch_idle, ConnectionActivity, ConnectionLimiter,
};
use crate::server::connection::ConnectionId;
use crate::server::spark::actions::SparkProtocol;
use crate::state::app_state::AppState;
use crate::{console_error, console_info};

/// Narrow a model-supplied HTTP status to `u16` without wrapping.
///
/// `status as u16` on a `u64` truncates, and the truncation runs in the dangerous
/// direction: `65736 as u16` is `200`, so a nonsense status becomes a success the client
/// believes. Anything outside the real status range falls back to `default`.
///
/// This is `oauth2`'s `status_or` in Spark's vocabulary. The payoff here is a bogus
/// monitoring answer rather than a credential, but the shape is the one the root
/// `CLAUDE.md` catalogues under narrowing casts, and a monitoring client that records a
/// fabricated `200` is exactly what a monitoring API must not do.
fn status_or(value: Option<&serde_json::Value>, default: u16) -> u16 {
    match value.and_then(|v| v.as_u64()) {
        Some(raw) => u16::try_from(raw)
            .ok()
            .filter(|s| (100..=599).contains(s))
            .unwrap_or_else(|| {
                warn!("Spark: ignoring out-of-range status {raw}, using {default}");
                default
            }),
        None => default,
    }
}

/// Largest request body this server will buffer.
///
/// The monitoring API is read-only, so a body is never needed — but it was read with an
/// unbounded `req.into_body().collect()` and then used for nothing but a `trace!`, which
/// made an unauthenticated POST of any size a way to grow the process. Small on purpose.
pub const MAX_REQUEST_BYTES: usize = 64 * 1024;

/// How long a peer that has produced nothing at all may hold this connection.
///
/// HTTP is client-speaks-first: the request line is the first thing on the wire and every
/// monitoring client sends it inside its dial path, so a peer that has connected and sent no byte
/// has begun no request. Thirty seconds sits between nginx's `client_header_timeout` default of
/// 60s and Apache's `RequestReadTimeout header=20`, both of which bound the same thing.
///
/// Enforced with `TcpStream::peek` **before** hyper sees the socket. hyper owns every read once
/// `serve_connection` starts, and a deadline on its reads would be wrong here rather than merely
/// awkward: hyper keeps polling the connection for new frames while a request is being answered,
/// so such a deadline would fire in the middle of an LLM round-trip. `peek` waits for data
/// without consuming it, so the request line is still there for hyper afterwards.
const FIRST_BYTE_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// How long an established connection may sit **silent** between requests.
///
/// This bounds the silence and never a transfer. A request being answered holds
/// `ConnectionActivity` busy for the whole of it - the model round-trip included, and a `manual`
/// rule parking the event for a human at the dashboard (`src/state/intercepts.rs`, 300s by
/// default) - and `watch_idle` reports a busy connection as not idle at all, so the clock only
/// ever runs on a connection with nothing in flight.
///
/// Three minutes. The Spark monitoring API is read-only and polled - a dashboard, a metrics
/// scrape, a `curl` - on a seconds-to-minutes cycle, so the silence this measures is a poller
/// that has stopped rather than a client doing work. Three minutes is above any scrape interval
/// anyone configures and more than twice nginx's `keepalive_timeout` default of 75s; a poller
/// whose connection was closed opens another, as RFC 9112 requires of it.
const IDLE_BETWEEN_REQUESTS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(180);

/// Concurrent connections this server admits.
///
/// Each admitted connection may hold one whole in-memory JSON response, so the cap is what turns
/// that per-connection bound into a total one - the request side is already bounded at
/// [`MAX_REQUEST_BYTES`]. A monitoring API's clients are a handful of pollers, so 256 is far
/// above any real deployment and far below what socket exhaustion needs.
const MAX_CONNECTIONS: usize = crate::server::accept_bounded::DEFAULT_MAX_CONNECTIONS;

/// What a peer over [`MAX_CONNECTIONS`] is told before the socket closes.
///
/// `503 Service Unavailable` with `Retry-After`, in Spark's own vocabulary:
/// a 503 is what a monitoring client and a dashboard both already
/// understand, and a human with `curl` reads it directly.
/// Nothing of netget's is interpolated into it - the peer gets a category and the log gets the
/// reason, under `decision=fail_closed_connection_cap`.
const CONNECTION_CAP_REFUSAL: &[u8] = b"HTTP/1.1 503 Service Unavailable\r\n\
    Content-Length: 0\r\nRetry-After: 5\r\nConnection: close\r\n\r\n";

/// Apache Spark monitoring REST server.
pub struct SparkServer;

impl SparkServer {
    pub async fn spawn_with_llm_actions(
        listen_addr: SocketAddr,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        server_id: crate::state::ServerId,
        spark_version: String,
    ) -> anyhow::Result<SocketAddr> {
        let listener =
            crate::server::socket_helpers::create_reusable_tcp_listener(listen_addr).await?;
        let local_addr = listener.local_addr()?;
        console_info!(status_tx, "Spark REST API listening on {}", local_addr);

        let protocol = Arc::new(SparkProtocol::new());
        let version = Arc::new(spark_version);

        let task_registrar = app_state.clone();
        let limiter = ConnectionLimiter::new(MAX_CONNECTIONS);
        let accept_handle = tokio::spawn(async move {
            loop {
                match accept_bounded(
                    &listener,
                    &limiter,
                    CONNECTION_CAP_REFUSAL,
                    "SPARK",
                    Some(&status_tx),
                )
                .await
                {
                    Ok((stream, remote_addr, permit)) => {
                        let connection_id =
                            ConnectionId::new(app_state.get_next_unified_id().await);
                        let local_addr_conn = stream.local_addr().unwrap_or(local_addr);
                        Log::new(Some(&status_tx)).info(format!(
                            "Spark connection {} from {}",
                            connection_id, remote_addr
                        ));

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
                            protocol_info: ProtocolConnectionInfo::empty(),
                        };
                        app_state
                            .add_connection_to_server(server_id, conn_state)
                            .await;
                        let _ = status_tx.send("__UPDATE_UI__".to_string());

                        let llm_client_clone = llm_client.clone();
                        let app_state_clone = app_state.clone();
                        let status_tx_clone = status_tx.clone();
                        let protocol_clone = protocol.clone();
                        let version_clone = version.clone();

                        let task_owner = app_state.clone();
                        task_owner
                            .spawn_server_task(server_id, async move {
                                // Held for the life of the connection, so the
                                // cap counts live clients, not accepts.
                                let _permit = permit;

                                // The first-byte bound, before hyper sees the
                                // socket. `peek` waits for data without
                                // consuming it, so the request line is still
                                // there for hyper afterwards, and it bounds
                                // exactly the case that needs bounding: a peer
                                // that connected and said nothing at all.
                                let spoke = matches!(
                                    tokio::time::timeout(
                                        FIRST_BYTE_READ_TIMEOUT,
                                        stream.peek(&mut [0u8; 1]),
                                    )
                                    .await,
                                    Ok(Ok(n)) if n > 0
                                );

                                if spoke {
                                    let io = TokioIo::new(stream);
                                    let status_for_service = status_tx_clone.clone();
                                    let app_state_for_service = app_state_clone.clone();

                                    // Whether this connection is answering
                                    // anything. The watchdog below reads it, so
                                    // only genuine silence - never work in
                                    // flight - can close a connection.
                                    let activity = Arc::new(ConnectionActivity::new());
                                    let activity_for_service = Arc::clone(&activity);
                                    let service = service_fn(move |req: Request<Incoming>| {
                                        let llm_clone = llm_client_clone.clone();
                                        let state_clone = app_state_for_service.clone();
                                        let status_clone = status_for_service.clone();
                                        let protocol_clone = protocol_clone.clone();
                                        let version_clone = version_clone.clone();
                                        // Busy for the whole of this request - the
                                        // model round-trip included, and a `manual`
                                        // rule parked for a human - so the idle
                                        // watchdog can never close the connection an
                                        // answer belongs to.
                                        let activity = Arc::clone(&activity_for_service);
                                        async move {
                                            let _busy = activity.busy();
                                            handle_spark_request(
                                                req,
                                                connection_id,
                                                llm_clone,
                                                state_clone,
                                                status_clone,
                                                protocol_clone,
                                                server_id,
                                                version_clone,
                                            )
                                            .await
                                        }
                                    });

                                    let conn = http1::Builder::new().serve_connection(io, service);
                                    tokio::pin!(conn);
                                    tokio::select! {
                                        result = &mut conn => {
                                            if let Err(err) = result {
                                                error!("Error serving Spark connection: {:?}", err);
                                            }
                                        }
                                        // The idle bound, over `ConnectionActivity`
                                        // rather than over a read: hyper owns every
                                        // read once `serve_connection` starts, and
                                        // keeps polling for frames while a request is
                                        // being answered, so a deadline on those reads
                                        // would fire mid-answer. A connection with work
                                        // in flight is not idle at all.
                                        _ = watch_idle(
                                            Arc::clone(&activity),
                                            IDLE_BETWEEN_REQUESTS_TIMEOUT,
                                        ) => {
                                            Log::new(Some(&status_tx_clone)).debug(format!(
                                                "Spark connection {} idle for {}s; closing",
                                                connection_id,
                                                IDLE_BETWEEN_REQUESTS_TIMEOUT.as_secs()
                                            ));
                                        }
                                    }
                                } else {
                                    Log::new(Some(&status_tx_clone)).debug(format!(
                                        "Spark peer {} sent no request within {}s; closing \
                                         decision=fail_closed_first_byte_timeout",
                                        remote_addr,
                                        FIRST_BYTE_READ_TIMEOUT.as_secs()
                                    ));
                                }

                                app_state_clone
                                    .close_connection_on_server(server_id, connection_id)
                                    .await;
                                Log::new(Some(&status_tx_clone))
                                    .info(format!("Spark connection {} closed", connection_id));
                                let _ = status_tx_clone.send("__UPDATE_UI__".to_string());
                            })
                            .await;
                    }
                    Err(e) => {
                        console_error!(status_tx, "Failed to accept Spark connection: {}", e);
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
}

/// Handle one monitoring-API request, then record what crossed the wire.
///
/// The rail's byte counters and the connection-scoped task prompts read
/// `bytes_received`/`bytes_sent`, and this server left both at the zero it registered the
/// connection with, so every Spark peer showed no traffic at all however much it moved.
#[allow(clippy::too_many_arguments)]
async fn handle_spark_request(
    req: Request<Incoming>,
    connection_id: ConnectionId,
    llm_client: OllamaClient,
    app_state: Arc<AppState>,
    status_tx: mpsc::UnboundedSender<String>,
    protocol: Arc<SparkProtocol>,
    server_id: crate::state::ServerId,
    version: Arc<String>,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    let received = req.body().size_hint().lower();
    let response = handle_spark_request_inner(
        req,
        llm_client,
        app_state.clone(),
        status_tx.clone(),
        protocol,
        server_id,
        version,
    )
    .await;

    let sent = response
        .as_ref()
        .ok()
        .and_then(|resp| resp.body().size_hint().exact())
        .unwrap_or(0);
    app_state
        .update_connection_stats(
            server_id,
            connection_id,
            Some(received),
            Some(sent),
            Some(1),
            Some(1),
        )
        .await;
    let _ = status_tx.send("__UPDATE_UI__".to_string());

    response
}

#[allow(clippy::too_many_arguments)]
async fn handle_spark_request_inner(
    req: Request<Incoming>,
    llm_client: OllamaClient,
    app_state: Arc<AppState>,
    status_tx: mpsc::UnboundedSender<String>,
    protocol: Arc<SparkProtocol>,
    server_id: crate::state::ServerId,
    version: Arc<String>,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    let method = req.method().to_string();
    let path = req.uri().path().to_string();

    // The monitoring API takes no request body; this is read only so an unexpected one
    // shows up in the trace log. An over-cap body is dropped rather than refused, because
    // nothing downstream reads it and every endpoint here is a GET.
    let body_bytes = match Limited::new(req.into_body(), MAX_REQUEST_BYTES)
        .collect()
        .await
    {
        Ok(collected) => collected.to_bytes(),
        Err(e) => {
            Log::new(Some(&status_tx)).warn(format!(
                "Spark request body ignored (over {} bytes): {}",
                MAX_REQUEST_BYTES, e
            ));
            Bytes::new()
        }
    };
    let body_str = String::from_utf8_lossy(&body_bytes).to_string();

    let (operation, app_id) = detect_spark_operation(&method, &path);
    Log::new(Some(&status_tx)).debug(format!("Spark {} {} op={}", method, path, operation));
    trace!("Spark request body: {}", body_str);

    if operation == "version" {
        // Answered by the server from a startup parameter; the model is never asked, so the
        // tag says `static_answer` rather than claiming a `model_answer` nobody produced.
        Log::new(Some(&status_tx)).debug(format!(
            "Spark {} {} decision=static_answer: version banner, no LLM call",
            method, path
        ));
        let body = serde_json::json!({ "spark": version.as_str() }).to_string();
        return Ok(build_spark_response(200, body, "application/json"));
    }
    if operation == "unknown" {
        Log::new(Some(&status_tx)).debug(format!(
            "Spark {} {} decision=unknown_endpoint: 404, no LLM call",
            method, path
        ));
        return Ok(build_spark_response(
            404,
            format!("no such endpoint: {path}"),
            "text/plain",
        ));
    }

    let event = crate::protocol::Event::new(
        &actions::SPARK_REQUEST_EVENT,
        serde_json::json!({
            "method": method,
            "path": path,
            "operation": operation,
            "app_id": app_id,
        }),
    );

    let llm_result = crate::llm::action_helper::call_llm(
        &llm_client,
        &app_state,
        server_id,
        None,
        &event,
        protocol.as_ref(),
    )
    .await;

    match llm_result {
        Ok(execution_result) => {
            for result in execution_result.protocol_results {
                if let ActionResult::Custom { name, data } = result {
                    if name == "spark_response" {
                        // Two defects in one expression, and they compounded.
                        // `unwrap_or(200)` made an omitted status a success, so a model that
                        // produced a `spark_response` without deciding one told the client
                        // the job succeeded; and `as u16` narrowed without a range check, so
                        // `65736 as u16 == 200` reached that same success — the LDAP
                        // `result_code as u8` shape.
                        //
                        // `status_or` is oauth2's helper, shared so the idiom is greppable
                        // rather than reinvented. The default is **500, not 200**: a response
                        // the model did not finish describing is a server-side failure, and a
                        // monitoring client recording a fabricated success is exactly what a
                        // monitoring API must not do.
                        let status = status_or(data.get("status"), 500);
                        let mut body = data
                            .get("body")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        // `GET /api/v1/applications/{id}` is the one object in the API: Spark
                        // answers it `{id, name, attempts}`, not `[{...}]`. The model answers it
                        // with `send_spark_applications` and one element, which is sent here as
                        // that element.
                        if operation == "application" && status < 400 {
                            if let Some(one) = single_element(&body) {
                                body = one;
                            }
                        }
                        let ct = data
                            .get("content_type")
                            .and_then(|v| v.as_str())
                            .unwrap_or("application/json");
                        // A 4xx/5xx the model chose is a refusal it decided; a 2xx is an
                        // answer. Both came from the model, and neither is fail-closed.
                        let decision = if status >= 400 {
                            "model_reject"
                        } else {
                            "model_answer"
                        };
                        Log::new(Some(&status_tx)).info(format!(
                            "Spark {} {} op={} decision={}: answering {}",
                            method, path, operation, decision, status
                        ));
                        trace!("Spark response body: {}", body);
                        return Ok(build_spark_response(status, body, ct));
                    }
                }
            }
            // Fail-closed: the model answered but produced no Spark response. A bare `[]` with
            // 200 is a valid "no applications/jobs" result and a client cannot tell it from a
            // backend that never ran — so answer 500 instead of that empty array.
            Log::new(Some(&status_tx)).warn(format!(
                "Spark {} {} op={} decision=model_silent: no spark_response action; answering \
                 500",
                method, path, operation
            ));
            Ok(build_spark_error(
                500,
                "netget: model produced no Spark response",
            ))
        }
        Err(e) => {
            let (status, decision) = match crate::utils::WireFailure::classify(&e) {
                crate::utils::WireFailure::Overloaded => (503u16, "fail_closed_llm_overloaded"),
                crate::utils::WireFailure::Unavailable => (500u16, "fail_closed_llm_error"),
            };
            // One line carrying both sinks: the tag and the error go to `netget.log` and to
            // the status stream the TUI and the test harness read. The *peer* gets only the
            // category below.
            Log::new(Some(&status_tx)).error(format!(
                "Spark {} {} op={} decision={}: answering {}: {}",
                method, path, operation, decision, status, e
            ));
            let reason = crate::utils::WireFailure::classify(&e).prefixed_text();
            Ok(build_spark_error(status, reason))
        }
    }
}

/// The one element of a JSON array that holds exactly one object, re-serialised; `None` for
/// anything else, which is then sent as the model gave it.
fn single_element(body: &str) -> Option<String> {
    match serde_json::from_str::<serde_json::Value>(body).ok()? {
        serde_json::Value::Array(mut items) if items.len() == 1 && items[0].is_object() => {
            serde_json::to_string(&items.remove(0)).ok()
        }
        _ => None,
    }
}

/// Fail-closed JSON error body (distinct from any success array, which is a bare `[...]`).
fn build_spark_error(status: u16, message: &str) -> Response<Full<Bytes>> {
    let body = serde_json::json!({ "error": message, "status": status }).to_string();
    build_spark_response(status, body, "application/json")
}

/// Build a Spark response. `status` originates in model output; `StatusCode::from_u16` rejects
/// out-of-range values where the previous `.unwrap()` shape would panic inside the hyper task.
fn build_spark_response(status: u16, body: String, content_type: &str) -> Response<Full<Bytes>> {
    let status = hyper::StatusCode::from_u16(status).unwrap_or_else(|_| {
        error!("Invalid Spark status code {}, sending 500 instead", status);
        hyper::StatusCode::INTERNAL_SERVER_ERROR
    });
    Response::builder()
        .status(status)
        .header("Content-Type", content_type)
        .body(Full::new(Bytes::from(body)))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::from("[]"))))
}

/// Map a Spark monitoring-API request to an operation name + optional app id.
fn detect_spark_operation(method: &str, path: &str) -> (String, Option<String>) {
    let trimmed = path.trim_start_matches('/');
    let parts: Vec<&str> = trimmed.split('/').filter(|s| !s.is_empty()).collect();

    match (method, parts.as_slice()) {
        ("GET", ["api", "v1", "version"]) => ("version".to_string(), None),
        ("GET", ["api", "v1", "applications"]) => ("applications".to_string(), None),
        ("GET", ["api", "v1", "applications", id]) => {
            ("application".to_string(), Some(id.to_string()))
        }
        ("GET", ["api", "v1", "applications", id, "jobs"]) => {
            ("jobs".to_string(), Some(id.to_string()))
        }
        ("GET", ["api", "v1", "applications", id, "stages"]) => {
            ("stages".to_string(), Some(id.to_string()))
        }
        ("GET", ["api", "v1", "applications", id, "executors"]) => {
            ("executors".to_string(), Some(id.to_string()))
        }
        // Read on every run by Datadog's Spark integration, which is how its absence was found:
        // the model had no truthful way to answer it, only a 404 or a mislabelled array.
        ("GET", ["api", "v1", "applications", id, "storage", "rdd"]) => {
            ("rdd".to_string(), Some(id.to_string()))
        }
        // A per-application sub-resource we don't model explicitly still reaches the LLM as a
        // generic per-application request so the model can answer or 404 it.
        ("GET", ["api", "v1", "applications", id, _rest @ ..]) => {
            ("application_resource".to_string(), Some(id.to_string()))
        }
        _ => ("unknown".to_string(), None),
    }
}

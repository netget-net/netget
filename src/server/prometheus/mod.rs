//! Prometheus exporter: an HTTP `/metrics` endpoint whose metrics the model invents.
//!
//! A real Prometheus server (or `promtool`, or anything else that reads the exposition format)
//! scrapes `GET /metrics`; NetGet raises one `prometheus_scrape` event, and the model answers
//! with `send_metrics` — structured families, never exposition text. NetGet renders the text
//! (format 0.0.4, or OpenMetrics 1.0.0 when the scraper prefers it) in [`exposition`], so the
//! model cannot produce a body a scraper would reject.
//!
//! `GET /` is a static HTML page linking to `/metrics`, like every exporter's. `HEAD /metrics`
//! answers the headers without asking the model. Anything else is a 404 or 405.
//!
//! See `src/server/prometheus/CLAUDE.md`.

pub mod actions;
/// Rendering and validation. Public so it can be tested directly against `promtool`.
pub mod exposition;

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::header::{HeaderValue, ACCEPT, ALLOW, CONTENT_TYPE, RETRY_AFTER, USER_AGENT};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde_json::{json, Value};
use tokio::sync::mpsc;
use tracing::{debug, error, info};

use crate::llm::action_helper::call_llm;
use crate::llm::ollama_client::OllamaClient;
use crate::protocol::Event;
use crate::server::connection::ConnectionId;
use crate::state::app_state::AppState;
use crate::state::ServerId;
use crate::{console_debug, console_error, console_info};

use exposition::MetricFamilies;

/// Largest request body this server will buffer, in bytes.
///
/// A scrape is a `GET` and carries no body, so no legitimate request comes near this. hyper's
/// `Incoming` has no limit of its own, and this server performs no authentication, so without
/// a bound one unauthenticated `POST` could make it buffer without limit. The body is read and
/// discarded before routing, which is what makes the bound apply to every path rather than
/// only to the ones that would have used it.
pub const MAX_REQUEST_BODY_BYTES: usize = 64 * 1024;

/// How long to wait for a peer's first byte after it connects.
///
/// HTTP is client-speaks-first, so a peer that has connected and sent nothing has not begun a
/// request. Enforced with `TcpStream::peek` before hyper sees the socket, so a deadline never
/// runs inside a model round-trip (hyper keeps polling the connection while a request is being
/// answered, so a read deadline would).
const FIRST_BYTE_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// How long a connection may do nothing at all between requests.
///
/// Bounds silence, not work: `ConnectionActivity` reports a connection with a request in flight
/// as not idle, so a slow model or a `manual` rule parked for a human never closes the
/// connection its answer belongs to. Prometheus keeps one connection per target and scrapes on
/// an interval that defaults to a minute, so two minutes keeps that connection alive across
/// scrapes at the default interval; a longer interval simply reconnects.
const IDLE_BETWEEN_REQUESTS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

/// Concurrent connections this server admits.
const MAX_CONNECTIONS: usize = crate::server::accept_bounded::DEFAULT_MAX_CONNECTIONS;

/// What a peer over [`MAX_CONNECTIONS`] is told before the socket closes.
const CONNECTION_CAP_REFUSAL: &[u8] = b"HTTP/1.1 503 Service Unavailable\r\n\
    Content-Length: 0\r\nRetry-After: 5\r\nConnection: close\r\n\r\n";

/// The static landing page every exporter serves at `/`.
const INDEX_HTML: &str = "<html>\n<head><title>NetGet Prometheus Exporter</title></head>\n\
<body>\n<h1>NetGet Prometheus Exporter</h1>\n<p><a href=\"/metrics\">Metrics</a></p>\n</body>\n\
</html>\n";

/// Prometheus exporter server.
pub struct PrometheusServer;

impl PrometheusServer {
    /// Bind, then spawn the accept loop.
    ///
    /// The listener is bound before the task is spawned so a bind failure reaches the caller
    /// and `server_startup` records `ServerStatus::Error`. The accept-loop handle is registered
    /// so `stop_server` can abort it and release the port.
    pub async fn spawn_with_llm_actions(
        listen_addr: SocketAddr,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        server_id: ServerId,
    ) -> anyhow::Result<SocketAddr> {
        let listener =
            crate::server::socket_helpers::create_reusable_tcp_listener(listen_addr).await?;
        let local_addr = listener.local_addr()?;

        console_info!(
            status_tx,
            "Prometheus exporter listening on http://{}/metrics",
            local_addr
        );

        let protocol = Arc::new(actions::PrometheusProtocol::new());
        let task_registrar = app_state.clone();
        let limiter = crate::server::accept_bounded::ConnectionLimiter::new(MAX_CONNECTIONS);
        let accept_handle = tokio::spawn(async move {
            loop {
                match crate::server::accept_bounded::accept_bounded(
                    &listener,
                    &limiter,
                    CONNECTION_CAP_REFUSAL,
                    "Prometheus",
                    Some(&status_tx),
                )
                .await
                {
                    Ok((stream, remote_addr, permit)) => {
                        let connection_id =
                            ConnectionId::new(app_state.get_next_unified_id().await);
                        let local_addr_conn = stream.local_addr().unwrap_or(local_addr);
                        info!(
                            "Prometheus connection {} from {}",
                            connection_id, remote_addr
                        );

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
                                },
                            )
                            .await;
                        let _ = status_tx.send("__UPDATE_UI__".to_string());

                        let ctx = RequestContext {
                            llm_client: llm_client.clone(),
                            app_state: app_state.clone(),
                            status_tx: status_tx.clone(),
                            protocol: protocol.clone(),
                            server_id,
                            connection_id,
                        };
                        let app_state_for_close = app_state.clone();
                        let status_for_close = status_tx.clone();

                        let task_owner = app_state.clone();
                        task_owner
                            .spawn_server_task(server_id, async move {
                                // Held for the life of the connection: dropping it early frees
                                // the slot while the peer is still here.
                                let _permit = permit;

                                // First-byte bound on the raw socket, before hyper sees it.
                                // `peek` does not consume, so the request line is still there.
                                match tokio::time::timeout(
                                    FIRST_BYTE_READ_TIMEOUT,
                                    stream.peek(&mut [0u8; 1]),
                                )
                                .await
                                {
                                    Ok(Ok(n)) if n > 0 => {
                                        serve_connection(TokioIo::new(stream), ctx).await;
                                    }
                                    Ok(_) => {}
                                    Err(_) => {
                                        debug!(
                                            "Prometheus peer {} sent nothing for {}s; closing \
                                             before the request line",
                                            remote_addr,
                                            FIRST_BYTE_READ_TIMEOUT.as_secs()
                                        );
                                    }
                                }

                                app_state_for_close
                                    .close_connection_on_server(server_id, connection_id)
                                    .await;
                                crate::logging::emit::Log::to(&status_for_close)
                                    .info(format!("Prometheus connection {connection_id} closed"));
                                let _ = status_for_close.send("__UPDATE_UI__".to_string());
                            })
                            .await;
                    }
                    Err(e) => {
                        console_error!(status_tx, "Failed to accept Prometheus connection: {}", e);
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

/// Per-connection dependencies, cloned into each hyper service call.
#[derive(Clone)]
struct RequestContext {
    llm_client: OllamaClient,
    app_state: Arc<AppState>,
    status_tx: mpsc::UnboundedSender<String>,
    protocol: Arc<actions::PrometheusProtocol>,
    server_id: ServerId,
    connection_id: ConnectionId,
}

async fn serve_connection<T>(io: TokioIo<T>, ctx: RequestContext)
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let activity = Arc::new(crate::server::accept_bounded::ConnectionActivity::new());
    let activity_for_service = Arc::clone(&activity);

    let service = service_fn(move |req: Request<Incoming>| {
        let ctx = ctx.clone();
        let activity = Arc::clone(&activity_for_service);
        async move {
            let _busy = activity.busy();
            Ok::<_, Infallible>(handle_request(req, ctx).await)
        }
    });

    let conn = http1::Builder::new().serve_connection(io, service);
    tokio::pin!(conn);
    tokio::select! {
        result = &mut conn => {
            if let Err(err) = result {
                debug!("Prometheus connection ended: {:?}", err);
            }
        }
        _ = crate::server::accept_bounded::watch_idle(
            Arc::clone(&activity),
            IDLE_BETWEEN_REQUESTS_TIMEOUT,
        ) => {
            debug!(
                "Prometheus connection idle for {}s; closing",
                IDLE_BETWEEN_REQUESTS_TIMEOUT.as_secs()
            );
        }
    }
}

fn text_response(
    status: StatusCode,
    content_type: &'static str,
    body: String,
) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(Bytes::from(body)));
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static(content_type));
    response
}

/// A plain-text error. Prometheus records the status line as the scrape error and never reads
/// the body as metrics, so a refusal can never be mistaken for an empty exposition.
fn error_response(status: StatusCode, message: &'static str) -> Response<Full<Bytes>> {
    text_response(status, "text/plain; charset=utf-8", format!("{message}\n"))
}

async fn handle_request(req: Request<Incoming>, ctx: RequestContext) -> Response<Full<Bytes>> {
    let (parts, body) = req.into_parts();
    let method = parts.method.clone();
    let path = parts.uri.path().to_string();
    let header = |name| {
        parts
            .headers
            .get(name)
            .and_then(|v: &HeaderValue| v.to_str().ok())
            .map(str::to_string)
    };
    let accept = header(ACCEPT);
    let user_agent = header(USER_AGENT).unwrap_or_default();
    let scrape_timeout = header(hyper::header::HeaderName::from_static(
        "x-prometheus-scrape-timeout-seconds",
    ));

    crate::logging::emit::Log::to(&ctx.status_tx).debug(format!("Prometheus {method} {path}"));

    // Bounded, and read before routing so the bound holds on every path. A body over the cap
    // is refused without the model being asked anything.
    let body_len = match http_body_util::Limited::new(body, MAX_REQUEST_BODY_BYTES)
        .collect()
        .await
    {
        Ok(collected) => collected.to_bytes().len(),
        Err(e) => {
            error!(
                "Prometheus {} {}: decision=fail_closed_body_rejected (limit {} bytes): {}",
                method, path, MAX_REQUEST_BODY_BYTES, e
            );
            return error_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                "netget: request body is larger than this exporter accepts",
            );
        }
    };
    ctx.app_state
        .update_connection_stats(
            ctx.server_id,
            ctx.connection_id,
            Some(body_len as u64),
            None,
            Some(1),
            None,
        )
        .await;

    match (path.as_str(), &method) {
        ("/", &Method::GET) | ("/", &Method::HEAD) => {
            return text_response(
                StatusCode::OK,
                "text/html; charset=utf-8",
                INDEX_HTML.to_string(),
            );
        }
        ("/metrics", &Method::GET) => {}
        ("/metrics", &Method::HEAD) => {
            let format = exposition::negotiate(accept.as_deref());
            return text_response(StatusCode::OK, format.content_type(), String::new());
        }
        ("/metrics", _) | ("/", _) => {
            let mut response = error_response(
                StatusCode::METHOD_NOT_ALLOWED,
                "netget: only GET and HEAD are served here",
            );
            response
                .headers_mut()
                .insert(ALLOW, HeaderValue::from_static("GET, HEAD"));
            return response;
        }
        _ => {
            return error_response(StatusCode::NOT_FOUND, "404 page not found");
        }
    }

    let format = exposition::negotiate(accept.as_deref());
    let mut data = json!({
        "path": path,
        "accept": accept.clone().unwrap_or_default(),
        "user_agent": user_agent,
        "format": format.as_str(),
    });
    if let Some(timeout) = scrape_timeout
        .as_deref()
        .and_then(|t| t.parse::<f64>().ok())
    {
        data["scrape_timeout_seconds"] = json!(timeout);
    }

    console_debug!(
        ctx.status_tx,
        "Calling LLM for Prometheus scrape of {}",
        path
    );
    let event = Event::new(&actions::PROMETHEUS_SCRAPE_EVENT, data);
    let llm_result = call_llm(
        &ctx.llm_client,
        &ctx.app_state,
        ctx.server_id,
        Some(ctx.connection_id),
        &event,
        ctx.protocol.as_ref(),
    )
    .await;

    match llm_result {
        Ok(execution) => {
            let failure_summary = execution.failure_summary();
            for result in execution.protocol_results {
                let crate::llm::ActionResult::Custom { name, data } = result else {
                    continue;
                };
                match name.as_str() {
                    "send_metrics" => {
                        let Some(families) = data
                            .get("metrics")
                            .and_then(|m| MetricFamilies::parse(m).ok())
                        else {
                            // The executor already validated this; failing here means the two
                            // disagree, which must not become a half-rendered body.
                            error!(
                                "Prometheus {}: decision=fail_closed_invalid_exposition \
                                 (executor output did not re-validate)",
                                path
                            );
                            return error_response(
                                StatusCode::INTERNAL_SERVER_ERROR,
                                "netget: the handler's metrics were refused as invalid",
                            );
                        };
                        let body = families.render(format);
                        info!(
                            "Prometheus {}: decision=model_answer format={} families={} samples={}",
                            path,
                            format.as_str(),
                            families.family_count(),
                            families.sample_count()
                        );
                        ctx.app_state
                            .update_connection_stats(
                                ctx.server_id,
                                ctx.connection_id,
                                None,
                                Some(body.len() as u64),
                                None,
                                Some(1),
                            )
                            .await;
                        return text_response(StatusCode::OK, format.content_type(), body);
                    }
                    "send_scrape_error" => {
                        let status = data
                            .get("status")
                            .and_then(Value::as_u64)
                            .and_then(|s| u16::try_from(s).ok())
                            .and_then(|s| StatusCode::from_u16(s).ok())
                            .filter(|s| s.is_client_error() || s.is_server_error())
                            .unwrap_or(StatusCode::SERVICE_UNAVAILABLE);
                        let message = data
                            .get("message")
                            .and_then(Value::as_str)
                            .unwrap_or("scrape refused")
                            .to_string();
                        info!(
                            "Prometheus {}: decision=model_reject status={}",
                            path,
                            status.as_u16()
                        );
                        return text_response(
                            status,
                            "text/plain; charset=utf-8",
                            format!("{}\n", crate::utils::sanitize::line_field(&message)),
                        );
                    }
                    other => debug!("Prometheus: ignoring non-exporter action '{}'", other),
                }
            }
            // Refuse rather than serve an empty exposition: an empty 200 is a claim that the
            // target has no metrics, and "the model said nothing" must not read as that.
            match failure_summary {
                None => error!(
                    "Prometheus {}: decision=fail_closed_no_action (no send_metrics)",
                    path
                ),
                Some(summary) => error!(
                    "Prometheus {}: decision=fail_closed_invalid_exposition ({})",
                    path, summary
                ),
            }
            console_error!(
                ctx.status_tx,
                "Prometheus: the handler returned no usable metrics for {}",
                path
            );
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "netget: the handler returned no usable metrics",
            )
        }
        Err(e) => {
            // The peer gets a category; the log gets the error.
            let failure = crate::utils::WireFailure::classify(&e);
            error!(
                "Prometheus {}: decision=fail_closed_llm_error category={:?} error={}",
                path, failure, e
            );
            console_error!(ctx.status_tx, "Prometheus LLM call failed: {}", e);
            match failure {
                crate::utils::WireFailure::Overloaded => {
                    let mut response =
                        error_response(StatusCode::SERVICE_UNAVAILABLE, failure.prefixed_text());
                    response
                        .headers_mut()
                        .insert(RETRY_AFTER, HeaderValue::from_static("5"));
                    response
                }
                crate::utils::WireFailure::Unavailable => {
                    error_response(StatusCode::INTERNAL_SERVER_ERROR, failure.prefixed_text())
                }
            }
        }
    }
}

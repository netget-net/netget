//! OpenTelemetry HTTP/gRPC receiver — the model decides which exports are accepted.
//!
//! OTLP exporters `POST` to `/v1/traces`, `/v1/metrics` or `/v1/logs` in protobuf or JSON,
//! optionally gzip-compressed. NetGet reads the body (bounded before and after inflation),
//! decodes it, and raises one `otlp_export` event carrying a summary — never the payload. The
//! model answers with a verdict (`accept_otlp`, `accept_otlp_partially`, `reject_otlp`), and
//! NetGet encodes the response in the request's own encoding (see [`codec`]).
//! Generated unary gRPC Export services use the same semantic verdict path on HTTP/2.
//!
//! Everything that is not a well-formed export is answered by NetGet without asking the model:
//! another path (404), method (405), content type or content encoding (415), a body past the
//! cap (413), bad gzip or an undecodable payload (400).
//!
//! See `src/server/otlp/AGENTS.md`.

pub mod actions;
pub mod codec;
mod grpc;

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::{Body, Incoming};
use hyper::header::{HeaderValue, ALLOW, CONTENT_ENCODING, CONTENT_TYPE, RETRY_AFTER};
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use hyper_util::server::conn::auto;
use tokio::sync::mpsc;
use tracing::{debug, info};

use crate::llm::action_helper::call_llm;
use crate::llm::ollama_client::OllamaClient;
use crate::protocol::Event;
use crate::server::connection::ConnectionId;
use crate::state::app_state::AppState;
use crate::state::ServerId;
use crate::{console_error, console_info};

use actions::Verdict;
use codec::{Encoding, Signal};

pub use codec::MAX_BODY_BYTES;

/// How long to wait for a peer's first byte after it connects. HTTP is client-speaks-first;
/// enforced with `TcpStream::peek` before hyper sees the socket, so no deadline runs inside a
/// model round-trip.
const FIRST_BYTE_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// How long a connection may do nothing at all between requests. OTLP exporters keep a
/// connection and send a batch every few seconds (the SDKs' default schedule delay is 5 s for
/// spans and 60 s for metrics), so two minutes keeps it across a metrics interval. A request in
/// flight — the model thinking, or a `manual` rule parked for a human — is not idle.
const IDLE_BETWEEN_REQUESTS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

/// Concurrent connections this server admits.
const MAX_CONNECTIONS: usize = crate::server::accept_bounded::DEFAULT_MAX_CONNECTIONS;

/// What a peer over [`MAX_CONNECTIONS`] is told before the socket closes: a status OTLP
/// clients retry.
const CONNECTION_CAP_REFUSAL: &[u8] = b"HTTP/1.1 503 Service Unavailable\r\n\
    Content-Length: 0\r\nRetry-After: 5\r\nConnection: close\r\n\r\n";

/// The fixed message for an export the model answered with no verdict.
const NO_DECISION: &str = "netget: the receiver reached no decision on this export";

/// OTLP/HTTP receiver.
pub struct OtlpServer;

impl OtlpServer {
    /// Bind, then spawn the accept loop. A bind failure reaches the caller, and the accept-loop
    /// handle is registered so `stop_server` can abort it and release the port.
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
            "OTLP/HTTP receiver listening on http://{}/v1/{{traces,metrics,logs}}",
            local_addr
        );

        let protocol = Arc::new(actions::OtlpProtocol::new());
        let task_registrar = app_state.clone();
        let limiter = crate::server::accept_bounded::ConnectionLimiter::new(MAX_CONNECTIONS);
        let exports = Arc::new(tokio::sync::Semaphore::new(grpc::MAX_EXPORTS));
        let accept_handle = tokio::spawn(async move {
            loop {
                match crate::server::accept_bounded::accept_bounded(
                    &listener,
                    &limiter,
                    CONNECTION_CAP_REFUSAL,
                    "OTLP",
                    Some(&status_tx),
                )
                .await
                {
                    Ok((stream, remote_addr, permit)) => {
                        let connection_id =
                            ConnectionId::new(app_state.get_next_unified_id().await);
                        let local_addr_conn = stream.local_addr().unwrap_or(local_addr);
                        info!("OTLP connection {} from {}", connection_id, remote_addr);

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
                            exports: exports.clone(),
                        };
                        let app_state_for_close = app_state.clone();
                        let status_for_close = status_tx.clone();

                        let task_owner = app_state.clone();
                        task_owner
                            .spawn_server_task(server_id, async move {
                                // Held for the life of the connection.
                                let _permit = permit;
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
                                            "OTLP peer {} sent nothing for {}s; closing",
                                            remote_addr,
                                            FIRST_BYTE_READ_TIMEOUT.as_secs()
                                        );
                                    }
                                }

                                app_state_for_close
                                    .close_connection_on_server(server_id, connection_id)
                                    .await;
                                crate::logging::emit::Log::to(&status_for_close)
                                    .info(format!("OTLP connection {connection_id} closed"));
                                let _ = status_for_close.send("__UPDATE_UI__".to_string());
                            })
                            .await;
                    }
                    Err(e) => {
                        console_error!(status_tx, "Failed to accept OTLP connection: {}", e);
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
    protocol: Arc<actions::OtlpProtocol>,
    server_id: ServerId,
    connection_id: ConnectionId,
    exports: Arc<tokio::sync::Semaphore>,
}

async fn serve_connection<T>(io: TokioIo<T>, ctx: RequestContext)
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let activity = Arc::new(crate::server::accept_bounded::ConnectionActivity::new());
    let activity_for_service = Arc::clone(&activity);

    let children = grpc::OwnedExecutor::default();
    let _children_guard = grpc::ConnectionTasks(children.clone());
    let service = service_fn(move |req: Request<Incoming>| {
        let ctx = ctx.clone();
        let activity = Arc::clone(&activity_for_service);
        async move {
            let _busy = activity.busy();
            let reply = if req
                .headers()
                .get(CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| {
                    v.split(';').next().is_some_and(|v| {
                        v.trim().eq_ignore_ascii_case("application/grpc")
                            || v.trim().eq_ignore_ascii_case("application/grpc+proto")
                    })
                }) {
                grpc::dispatch(req, ctx).await
            } else {
                handle_request(req, ctx)
                    .await
                    .map(|body| body.map_err(|never| match never {}).boxed_unsync())
            };
            Ok::<_, Infallible>(reply)
        }
    });

    let mut builder = auto::Builder::new(children.clone());
    builder
        .http2()
        .max_concurrent_streams(16)
        .initial_stream_window_size(65536)
        .initial_connection_window_size(1048576)
        .max_header_list_size(32768)
        .max_frame_size(16384);
    let conn = builder.serve_connection(io, service);
    tokio::pin!(conn);
    tokio::select! {
        result = &mut conn => {
            if let Err(err) = result {
                debug!("OTLP connection ended: {:?}", err);
            }
        }
        _ = crate::server::accept_bounded::watch_idle(
            Arc::clone(&activity),
            IDLE_BETWEEN_REQUESTS_TIMEOUT,
        ) => {
            debug!(
                "OTLP connection idle for {}s; closing",
                IDLE_BETWEEN_REQUESTS_TIMEOUT.as_secs()
            );
        }
    }
}

fn response(
    status: StatusCode,
    content_type: &'static str,
    body: Vec<u8>,
) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(Bytes::from(body)));
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static(content_type));
    response
}

/// A refusal before the encoding is known: plain text.
fn text(status: StatusCode, message: &'static str) -> Response<Full<Bytes>> {
    response(
        status,
        "text/plain; charset=utf-8",
        format!("{message}\n").into_bytes(),
    )
}

/// A failure in the request's encoding: a `google.rpc.Status`.
fn failure(encoding: Encoding, status: StatusCode, message: &str) -> Response<Full<Bytes>> {
    response(
        status,
        encoding.content_type(),
        codec::status_body(encoding, status.as_u16(), message),
    )
}

async fn handle_request(req: Request<Incoming>, ctx: RequestContext) -> Response<Full<Bytes>> {
    let log = crate::logging::emit::Log::new(Some(&ctx.status_tx));
    let (parts, body) = req.into_parts();
    let path = parts.uri.path().to_string();
    let header = |name| {
        parts
            .headers
            .get(name)
            .and_then(|v: &HeaderValue| v.to_str().ok())
            .map(str::to_string)
    };
    log.debug(format!("OTLP {} {}", parts.method, path));

    let Some(signal) = Signal::from_path(&path) else {
        return text(StatusCode::NOT_FOUND, "404 page not found");
    };
    if parts.method != Method::POST {
        let mut r = text(
            StatusCode::METHOD_NOT_ALLOWED,
            "netget: OTLP exports are POSTed",
        );
        r.headers_mut()
            .insert(ALLOW, HeaderValue::from_static("POST"));
        return r;
    }
    let Some(encoding) = header(CONTENT_TYPE)
        .as_deref()
        .and_then(Encoding::from_content_type)
    else {
        log.warn(format!(
            "OTLP {path}: decision=fail_closed_unsupported_media_type"
        ));
        return text(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "netget: OTLP/HTTP takes application/x-protobuf or application/json",
        );
    };
    let compressed = match header(CONTENT_ENCODING)
        .map(|e| e.trim().to_ascii_lowercase())
        .as_deref()
    {
        None | Some("") | Some("identity") => false,
        Some("gzip") => true,
        Some(_) => {
            log.warn(format!(
                "OTLP {path}: decision=fail_closed_unsupported_encoding"
            ));
            return failure(
                encoding,
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "netget: the only Content-Encoding accepted is gzip",
            );
        }
    };

    // The cap applies to what arrives, and again to what it inflates to.
    let raw = match http_body_util::Limited::new(body, MAX_BODY_BYTES)
        .collect()
        .await
    {
        Ok(collected) => collected.to_bytes(),
        Err(e) => {
            if e.is::<http_body_util::LengthLimitError>() {
                log.warn(format!(
                    "OTLP {path}: decision=fail_closed_too_large (limit {MAX_BODY_BYTES} bytes)"
                ));
                return failure(
                    encoding,
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "netget: the export is larger than this receiver accepts",
                );
            }
            debug!("OTLP {path}: body read failed: {e}");
            return failure(
                encoding,
                StatusCode::BAD_REQUEST,
                "netget: the request body could not be read",
            );
        }
    };
    ctx.app_state
        .update_connection_stats(
            ctx.server_id,
            ctx.connection_id,
            Some(raw.len() as u64),
            None,
            Some(1),
            None,
        )
        .await;
    let body: Vec<u8> = if compressed {
        match codec::gunzip_bounded(&raw, MAX_BODY_BYTES) {
            Ok(inflated) => inflated,
            Err(codec::BodyError::TooLarge) => {
                log.warn(format!(
                    "OTLP {path}: gzip body of {} bytes inflates past {MAX_BODY_BYTES} \
                     decision=fail_closed_too_large",
                    raw.len()
                ));
                return failure(
                    encoding,
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "netget: the export is larger than this receiver accepts",
                );
            }
            Err(codec::BodyError::BadGzip) => {
                log.warn(format!("OTLP {path}: decision=fail_closed_bad_gzip"));
                return failure(
                    encoding,
                    StatusCode::BAD_REQUEST,
                    "netget: the body is not valid gzip",
                );
            }
        }
    } else {
        raw.to_vec()
    };

    let summary = match codec::summarize(signal, encoding, &body) {
        Ok(s) => s,
        Err(e) => {
            log.warn(format!(
                "OTLP {path}: {} payload did not decode decision=fail_closed_bad_payload",
                encoding.as_str()
            ));
            debug!("OTLP {path}: decode error: {e}");
            return failure(
                encoding,
                StatusCode::BAD_REQUEST,
                match encoding {
                    Encoding::Protobuf => "netget: the export is not a valid OTLP protobuf message",
                    Encoding::Json => "netget: the export is not valid OTLP JSON",
                },
            );
        }
    };

    let body_bytes = body.len();
    drop(body);
    respond_to_export(
        ctx, signal, encoding, compressed, body_bytes, summary, "http",
    )
    .await
}

async fn respond_to_export(
    ctx: RequestContext,
    signal: Signal,
    encoding: Encoding,
    compressed: bool,
    body_bytes: usize,
    summary: codec::Summary,
    transport: &str,
) -> Response<Full<Bytes>> {
    let log = crate::logging::emit::Log::new(Some(&ctx.status_tx));
    let path = format!("/v1/{}", signal.as_str());
    let mut data = summary.to_event(signal, encoding, compressed, body_bytes);
    data["transport"] = serde_json::json!(transport);
    data["answer_with"] = serde_json::json!(actions::answer_with(signal, summary.item_count));
    let event = Event::new(&actions::OTLP_EXPORT_EVENT, data);
    let who = summary.services.first().cloned().unwrap_or_default();
    let result = call_llm(
        &ctx.llm_client,
        &ctx.app_state,
        ctx.server_id,
        Some(ctx.connection_id),
        &event,
        ctx.protocol.as_ref(),
    )
    .await;

    let reply = match result {
        Err(e) => {
            let failure_kind = crate::utils::WireFailure::classify(&e);
            log.error(format!(
                "OTLP {path} from {who:?}: decision=fail_closed_llm_error category={:?} error={}",
                failure_kind, e
            ));
            console_error!(ctx.status_tx, "OTLP LLM call failed: {}", e);
            match failure_kind {
                crate::utils::WireFailure::Overloaded => {
                    let mut r = failure(
                        encoding,
                        StatusCode::SERVICE_UNAVAILABLE,
                        failure_kind.prefixed_text(),
                    );
                    r.headers_mut()
                        .insert(RETRY_AFTER, HeaderValue::from_static("5"));
                    r
                }
                crate::utils::WireFailure::Unavailable => failure(
                    encoding,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    failure_kind.prefixed_text(),
                ),
            }
        }
        Ok(execution) => {
            let failures = execution.failure_summary();
            match execution
                .protocol_results
                .iter()
                .find_map(Verdict::from_result)
            {
                Some(Verdict::Accept) => {
                    log.info(format!(
                        "OTLP {path} from {who:?}: decision=model_answer items={}",
                        summary.item_count
                    ));
                    response(
                        StatusCode::OK,
                        encoding.content_type(),
                        codec::export_response(signal, encoding, None),
                    )
                }
                Some(Verdict::Partial {
                    rejected,
                    error_message,
                }) => {
                    let rejected = rejected.clamp(0, summary.item_count as i64);
                    log.info(format!(
                        "OTLP {path} from {who:?}: decision=model_answer partial rejected={} of {}",
                        rejected, summary.item_count
                    ));
                    response(
                        StatusCode::OK,
                        encoding.content_type(),
                        codec::export_response(signal, encoding, Some((rejected, &error_message))),
                    )
                }
                Some(Verdict::Reject {
                    status,
                    message,
                    retry_after_secs,
                }) => {
                    log.info(format!(
                        "OTLP {path} from {who:?}: decision=model_reject status={status}"
                    ));
                    let status =
                        StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
                    let mut r = failure(encoding, status, &message);
                    if let Some(secs) =
                        retry_after_secs.filter(|_| codec::retryable(status.as_u16()))
                    {
                        if let Ok(value) = HeaderValue::from_str(&secs.to_string()) {
                            r.headers_mut().insert(RETRY_AFTER, value);
                        }
                    }
                    r
                }
                None => {
                    log.warn(format!(
                        "OTLP {path} from {who:?}: decision=model_silent ({}); refusing 500",
                        failures.unwrap_or_else(|| "no verdict".to_string())
                    ));
                    failure(encoding, StatusCode::INTERNAL_SERVER_ERROR, NO_DECISION)
                }
            }
        }
    };
    let sent = reply.body().size_hint().exact().unwrap_or(0);
    ctx.app_state
        .update_connection_stats(
            ctx.server_id,
            ctx.connection_id,
            None,
            Some(sent),
            None,
            Some(1),
        )
        .await;
    reply
}

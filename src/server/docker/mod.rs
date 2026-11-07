//! Docker Engine API server: the read-only core a real `docker -H tcp://…` CLI needs.
//!
//! The CLI's first request on every command is `HEAD /_ping`; the `API-Version` header on the
//! answer is what it negotiates down to, and every later request carries that version as a
//! `/v1.xx/` path prefix. NetGet serves `/_ping` and the version check deterministically, and
//! raises one `docker_api_request` event for each read the model decides — `/version`, `/info`,
//! `/containers/json`, `/containers/{id}/json`, `/images/json`, `/networks`, `/volumes`.
//! Mutating endpoints (create, start, exec, pull, delete…) are refused with a 501 in Docker's
//! own `{"message": …}` shape without asking the model.
//!
//! The model names containers, images and states; [`api`] fills everything else the Go decoder
//! expects. See `src/server/docker/CLAUDE.md`.

pub mod actions;
/// Routing and rendering. Public so it can be tested without a socket.
pub mod api;

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::header::{HeaderName, HeaderValue, CONTENT_TYPE, RETRY_AFTER, SERVER};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde_json::{json, Map, Value};
use tokio::sync::mpsc;
use tracing::{debug, error, info};

use crate::llm::action_helper::call_llm;
use crate::llm::ollama_client::OllamaClient;
use crate::protocol::Event;
use crate::server::connection::ConnectionId;
use crate::state::app_state::AppState;
use crate::state::ServerId;
use crate::{console_debug, console_error, console_info};

use api::Route;

/// Largest request body this server will buffer, in bytes.
///
/// Every endpoint served here is a read with no body, and every mutating endpoint is refused,
/// so no legitimate request comes near this. The body is read before routing so the bound
/// holds on every path; without it one unauthenticated `POST /containers/create` could make the
/// server buffer without limit.
pub const MAX_REQUEST_BODY_BYTES: usize = 1024 * 1024;

/// How long to wait for a peer's first byte after it connects.
///
/// HTTP is client-speaks-first. Enforced with `TcpStream::peek` before hyper sees the socket,
/// so the deadline never runs inside a model round-trip.
const FIRST_BYTE_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// How long a connection may do nothing at all between requests.
///
/// The Docker CLI opens a connection per command and closes it when the command ends; SDK
/// clients pool connections and go quiet between calls. `ConnectionActivity` keeps a connection
/// whose request is waiting on the model, or parked for a human, from ever reading as idle.
const IDLE_BETWEEN_REQUESTS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

/// Concurrent connections this server admits.
const MAX_CONNECTIONS: usize = crate::server::accept_bounded::DEFAULT_MAX_CONNECTIONS;

/// What a peer over [`MAX_CONNECTIONS`] is told before the socket closes.
const CONNECTION_CAP_REFUSAL: &[u8] = b"HTTP/1.1 503 Service Unavailable\r\n\
    Content-Type: application/json\r\nContent-Length: 43\r\nRetry-After: 5\r\n\
    Connection: close\r\n\r\n{\"message\":\"netget: too many connections\"}\n";

/// API version advertised by `/_ping` when the `api_version` startup parameter is absent.
///
/// 1.47 is Docker Engine 27.x. Current CLIs (29.x) negotiate down to it without complaint.
pub const DEFAULT_API_VERSION: &str = "1.47";

/// Engine version reported when `engine_version` is absent.
pub const DEFAULT_ENGINE_VERSION: &str = "27.5.1";

/// Per-server configuration.
#[derive(Clone, Debug)]
pub struct DockerConfig {
    pub identity: api::EngineIdentity,
}

/// Docker Engine API server.
pub struct DockerServer;

impl DockerServer {
    /// Bind, then spawn the accept loop. A bind failure reaches the caller so the server is
    /// recorded as `Error`, and the accept-loop handle is registered so `stop_server` frees
    /// the port.
    pub async fn spawn_with_llm_actions(
        listen_addr: SocketAddr,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        server_id: ServerId,
        config: DockerConfig,
    ) -> anyhow::Result<SocketAddr> {
        let listener =
            crate::server::socket_helpers::create_reusable_tcp_listener(listen_addr).await?;
        let local_addr = listener.local_addr()?;

        console_info!(
            status_tx,
            "Docker Engine API listening on tcp://{} (engine {}, API {})",
            local_addr,
            config.identity.engine_version,
            config.identity.api_version
        );

        let protocol = Arc::new(actions::DockerProtocol::new());
        let config = Arc::new(config);
        let task_registrar = app_state.clone();
        let limiter = crate::server::accept_bounded::ConnectionLimiter::new(MAX_CONNECTIONS);
        let accept_handle = tokio::spawn(async move {
            loop {
                match crate::server::accept_bounded::accept_bounded(
                    &listener,
                    &limiter,
                    CONNECTION_CAP_REFUSAL,
                    "Docker",
                    Some(&status_tx),
                )
                .await
                {
                    Ok((stream, remote_addr, permit)) => {
                        let connection_id =
                            ConnectionId::new(app_state.get_next_unified_id().await);
                        let local_addr_conn = stream.local_addr().unwrap_or(local_addr);
                        info!("Docker connection {} from {}", connection_id, remote_addr);

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
                            config: config.clone(),
                            server_id,
                            connection_id,
                        };
                        let app_state_for_close = app_state.clone();
                        let status_for_close = status_tx.clone();

                        let task_owner = app_state.clone();
                        task_owner
                            .spawn_server_task(server_id, async move {
                                // Held for the life of the connection.
                                let _permit = permit;

                                // First-byte bound before hyper sees the socket; `peek` does
                                // not consume, so the request line is still there afterwards.
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
                                            "Docker peer {} sent nothing for {}s; closing",
                                            remote_addr,
                                            FIRST_BYTE_READ_TIMEOUT.as_secs()
                                        );
                                    }
                                }

                                app_state_for_close
                                    .close_connection_on_server(server_id, connection_id)
                                    .await;
                                crate::logging::emit::Log::to(&status_for_close)
                                    .info(format!("Docker connection {connection_id} closed"));
                                let _ = status_for_close.send("__UPDATE_UI__".to_string());
                            })
                            .await;
                    }
                    Err(e) => {
                        console_error!(status_tx, "Failed to accept Docker connection: {}", e);
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
    protocol: Arc<actions::DockerProtocol>,
    config: Arc<DockerConfig>,
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
                debug!("Docker connection ended: {:?}", err);
            }
        }
        _ = crate::server::accept_bounded::watch_idle(
            Arc::clone(&activity),
            IDLE_BETWEEN_REQUESTS_TIMEOUT,
        ) => {
            debug!(
                "Docker connection idle for {}s; closing",
                IDLE_BETWEEN_REQUESTS_TIMEOUT.as_secs()
            );
        }
    }
}

/// Headers every Docker daemon response carries.
fn stamp(response: &mut Response<Full<Bytes>>, identity: &api::EngineIdentity) {
    let headers = response.headers_mut();
    if let Ok(v) = HeaderValue::from_str(&identity.api_version) {
        headers.insert(HeaderName::from_static("api-version"), v);
    }
    if let Ok(v) = HeaderValue::from_str(&format!("Docker/{} (linux)", identity.engine_version)) {
        headers.insert(SERVER, v);
    }
    headers.insert(
        HeaderName::from_static("docker-experimental"),
        HeaderValue::from_static("false"),
    );
    headers.insert(
        HeaderName::from_static("ostype"),
        HeaderValue::from_static("linux"),
    );
}

fn json_response(
    status: StatusCode,
    body: &Value,
    identity: &api::EngineIdentity,
) -> Response<Full<Bytes>> {
    let mut bytes = serde_json::to_vec(body).unwrap_or_else(|_| b"{}".to_vec());
    bytes.push(b'\n');
    let mut response = Response::new(Full::new(Bytes::from(bytes)));
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    stamp(&mut response, identity);
    response
}

/// Docker's error shape. `message` is either NetGet's own fixed text or the model's chosen
/// wording; it never carries an internal error.
fn error_response(
    status: StatusCode,
    message: &str,
    identity: &api::EngineIdentity,
) -> Response<Full<Bytes>> {
    json_response(status, &api::error_body(message), identity)
}

fn parse_query(query: &str) -> Map<String, Value> {
    let mut map = Map::new();
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        let decode = |s: &str| {
            urlencoding::decode(&s.replace('+', " "))
                .map(|c| c.into_owned())
                .unwrap_or_else(|_| s.to_string())
        };
        map.insert(decode(k), Value::String(decode(v)));
    }
    map
}

async fn handle_request(req: Request<Incoming>, ctx: RequestContext) -> Response<Full<Bytes>> {
    let identity = &ctx.config.identity;
    let (parts, body) = req.into_parts();
    let method = parts.method.as_str().to_string();
    let raw_path = parts.uri.path().to_string();
    let query = parse_query(parts.uri.query().unwrap_or(""));

    crate::logging::emit::Log::to(&ctx.status_tx).debug(format!("Docker {method} {raw_path}"));

    // Bounded, and read before routing so the bound holds on every path.
    let body_len = match http_body_util::Limited::new(body, MAX_REQUEST_BODY_BYTES)
        .collect()
        .await
    {
        Ok(collected) => collected.to_bytes().len(),
        Err(e) => {
            error!(
                "Docker {} {}: decision=fail_closed_body_rejected (limit {} bytes): {}",
                method, raw_path, MAX_REQUEST_BODY_BYTES, e
            );
            return error_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                "netget: request body is larger than this server accepts",
                identity,
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

    let (requested_version, path) = api::split_version(&raw_path);
    if let Some(v) = &requested_version {
        let requested = api::parse_version(v);
        let max = api::parse_version(&identity.api_version);
        let min = api::parse_version(api::MIN_API_VERSION);
        if requested > max {
            return error_response(
                StatusCode::BAD_REQUEST,
                &format!(
                    "client version {v} is too new. Maximum supported API version is {}",
                    identity.api_version
                ),
                identity,
            );
        }
        if requested < min {
            return error_response(
                StatusCode::BAD_REQUEST,
                &format!(
                    "client version {v} is too old. Minimum supported API version is {}, \
                     please upgrade your client to a newer version",
                    api::MIN_API_VERSION
                ),
                identity,
            );
        }
    }

    let route = api::resolve(&method, &path);
    match &route {
        Route::Ping => {
            let mut response = Response::new(Full::new(Bytes::from_static(b"OK")));
            let headers = response.headers_mut();
            headers.insert(
                CONTENT_TYPE,
                HeaderValue::from_static("text/plain; charset=utf-8"),
            );
            headers.insert(
                hyper::header::CACHE_CONTROL,
                HeaderValue::from_static("no-cache, no-store, must-revalidate"),
            );
            headers.insert(hyper::header::PRAGMA, HeaderValue::from_static("no-cache"));
            headers.insert(
                HeaderName::from_static("builder-version"),
                HeaderValue::from_static("1"),
            );
            stamp(&mut response, identity);
            return response;
        }
        Route::Mutating => {
            info!(
                "Docker {} {}: decision=fail_closed_not_implemented",
                method, raw_path
            );
            return error_response(
                StatusCode::NOT_IMPLEMENTED,
                "netget's Docker Engine API is read-only: creating, starting, executing in, \
                 pulling and removing are not implemented",
                identity,
            );
        }
        Route::NotFound => {
            return error_response(StatusCode::NOT_FOUND, "page not found", identity);
        }
        _ => {}
    }

    let resource = route.resource().unwrap_or("unknown");
    let mut data = json!({
        "method": method,
        "path": path,
        "api_version": requested_version.clone().unwrap_or_else(|| identity.api_version.clone()),
        "query": query,
        "resource": resource,
    });
    if let Route::ContainerInspect(id) = &route {
        data["id"] = json!(id);
    }
    if let Some(answer_with) = route.answer_with(&data["query"]) {
        data["answer_with"] = json!(answer_with);
    }

    console_debug!(ctx.status_tx, "Calling LLM for Docker {} {}", method, path);
    let event = Event::new(actions::event_for_resource(resource), data);
    let llm_result = call_llm(
        &ctx.llm_client,
        &ctx.app_state,
        ctx.server_id,
        Some(ctx.connection_id),
        &event,
        ctx.protocol.as_ref(),
    )
    .await;

    let response = match llm_result {
        Ok(execution) => {
            let failure_summary = execution.failure_summary();
            let expected = route.answering_action();
            let mut answer = None;
            for result in execution.protocol_results {
                let crate::llm::ActionResult::Custom { name, data } = result else {
                    continue;
                };
                if name == "send_docker_error" {
                    let status = data
                        .get("status")
                        .and_then(Value::as_u64)
                        .and_then(|s| u16::try_from(s).ok())
                        .and_then(|s| StatusCode::from_u16(s).ok())
                        .filter(|s| s.is_client_error() || s.is_server_error())
                        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
                    let message = data
                        .get("message")
                        .and_then(Value::as_str)
                        .unwrap_or("error");
                    info!(
                        "Docker {} {}: decision=model_reject status={}",
                        method,
                        path,
                        status.as_u16()
                    );
                    answer = Some(error_response(
                        status,
                        &crate::utils::sanitize::line_field(message),
                        identity,
                    ));
                    break;
                }
                if Some(name.as_str()) != expected {
                    debug!(
                        "Docker {} {}: ignoring {} (this route is answered by {:?})",
                        method, path, name, expected
                    );
                    continue;
                }
                match render(&route, &data, identity) {
                    Ok(body) => {
                        info!(
                            "Docker {} {}: decision=model_answer action={}",
                            method, path, name
                        );
                        answer = Some(json_response(StatusCode::OK, &body, identity));
                        break;
                    }
                    Err(reason) => {
                        // The executor validated this already; disagreeing here must not
                        // become a half-built document.
                        error!(
                            "Docker {} {}: decision=fail_closed_invalid_answer ({})",
                            method, path, reason
                        );
                    }
                }
            }
            match answer {
                Some(response) => response,
                None => {
                    match failure_summary {
                        Some(summary) => error!(
                            "Docker {} {}: decision=fail_closed_invalid_answer ({})",
                            method, path, summary
                        ),
                        None => error!(
                            "Docker {} {}: decision=fail_closed_no_action (expected {:?})",
                            method, path, expected
                        ),
                    }
                    console_error!(
                        ctx.status_tx,
                        "Docker: the handler returned no usable answer for {} {}",
                        method,
                        path
                    );
                    error_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "netget: the handler returned no usable answer for this request",
                        identity,
                    )
                }
            }
        }
        Err(e) => {
            let failure = crate::utils::WireFailure::classify(&e);
            error!(
                "Docker {} {}: decision=fail_closed_llm_error category={:?} error={}",
                method, path, failure, e
            );
            console_error!(ctx.status_tx, "Docker LLM call failed: {}", e);
            match failure {
                crate::utils::WireFailure::Overloaded => {
                    let mut response = error_response(
                        StatusCode::SERVICE_UNAVAILABLE,
                        failure.prefixed_text(),
                        identity,
                    );
                    response
                        .headers_mut()
                        .insert(RETRY_AFTER, HeaderValue::from_static("5"));
                    response
                }
                crate::utils::WireFailure::Unavailable => error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    failure.prefixed_text(),
                    identity,
                ),
            }
        }
    };
    let sent = hyper::body::Body::size_hint(response.body())
        .exact()
        .unwrap_or(0);
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
    response
}

/// Render the model's answer for a route. The executor has already validated the same data.
fn render(route: &Route, data: &Value, identity: &api::EngineIdentity) -> Result<Value, String> {
    match route {
        Route::Version => api::render_version(data, identity),
        Route::Info => api::render_info(data, identity),
        Route::ContainerList => {
            api::render_container_list(data.get("containers").unwrap_or(&Value::Null))
        }
        Route::ContainerInspect(_) => {
            api::render_container(data.get("container").unwrap_or(&Value::Null))
        }
        Route::ImageList => api::render_images(data.get("images").unwrap_or(&Value::Null)),
        Route::NetworkList => api::render_networks(data.get("networks").unwrap_or(&Value::Null)),
        Route::VolumeList => api::render_volumes(data.get("volumes").unwrap_or(&Value::Null)),
        Route::Ping | Route::Mutating | Route::NotFound => Err("route is not answered".into()),
    }
}

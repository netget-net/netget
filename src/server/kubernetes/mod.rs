//! Kubernetes API server implementation.
//!
//! NetGet impersonates a `kube-apiserver` well enough for a real `kubectl` to talk to it. The
//! transport is plain HTTP/1.1 (optionally under TLS); everything on the wire is JSON, which is
//! what `kubectl` speaks to an apiserver by default — no protobuf, and therefore no `protoc`
//! and no `kube`/`k8s-openapi` dependency.
//!
//! **The model owns the cluster.** There is no resource store here: NetGet never remembers a
//! pod. Every list, get and write is answered by the LLM (or by a script/static handler) via
//! the `k8s_*` actions. What NetGet owns is the envelope — routing, discovery, `Table`
//! rendering and the `Status` error object — the parts a real client will reject if they are
//! wrong.
//!
//! See `src/server/kubernetes/CLAUDE.md` for the discovery/content split and its rationale.

pub mod actions;
mod discovery;
/// `Table` rendering. Public so its cell derivation can be tested directly against the kinds of
/// object a model actually returns, without standing a server up first.
pub mod table;

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::header::{HeaderValue, ACCEPT, CONTENT_TYPE};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde_json::{json, Value};
use tokio::sync::mpsc;
use tracing::{debug, error, info, trace, warn};

use crate::llm::action_helper::call_llm;
use crate::llm::ollama_client::OllamaClient;
use crate::protocol::{Event, EventType};
use crate::server::connection::ConnectionId;
use crate::state::app_state::AppState;
use crate::state::ServerId;
use crate::{console_debug, console_error, console_info};

pub use discovery::{status_object, ApiResource, ApiSurface};

/// Everything the accept loop needs that is not the socket or the LLM.
#[derive(Clone, Debug)]
pub struct KubernetesConfig {
    /// The advertised API discovery surface.
    pub surface: Arc<ApiSurface>,
    /// Version string reported by `GET /version`, e.g. `v1.29.4`.
    pub kubernetes_version: String,
}

impl Default for KubernetesConfig {
    fn default() -> Self {
        Self {
            surface: Arc::new(ApiSurface::builtin()),
            kubernetes_version: DEFAULT_KUBERNETES_VERSION.to_string(),
        }
    }
}

/// Version claimed by `GET /version` when `kubernetes_version` is not supplied.
pub const DEFAULT_KUBERNETES_VERSION: &str = "v1.29.4";

/// Largest request body this server will buffer, in bytes.
///
/// The same 3 MiB a real `kube-apiserver` enforces (`maxRequestBodyBytes` in
/// `k8s.io/apiserver`), and for the same reason: hyper's `Incoming` has no limit of its own, so
/// `collect()` on it buffers whatever the peer chose to send. This server performs no
/// authentication, so that was one unauthenticated `POST` away from exhausting the process —
/// and the body is then embedded whole in an LLM prompt, so there is no legitimate large one
/// either. `Limited` errors as soon as the cap is passed rather than after buffering it.
pub const MAX_REQUEST_BODY_BYTES: usize = 3 * 1024 * 1024;

/// How long to wait for a peer's first byte after it connects.
///
/// Both shapes this server accepts are client-speaks-first: plain HTTP says nothing before the
/// request line, and TLS says nothing before the ClientHello. So a peer that has connected and
/// sent nothing has begun neither, which is the state an unauthenticated flood lives in — and
/// this server performs no authentication at all. Enforced with `TcpStream::peek` on the raw
/// socket *before* either the TLS acceptor or hyper sees it, so those bytes are still there for
/// whichever one gets the stream afterwards.
const FIRST_BYTE_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// How long a connection may do nothing at all between requests.
///
/// **This bounds the silence, not the transfer.** Every response here is a `Full<Bytes>` built
/// before the response is returned, and `?watch=true` — the one long-lived shape the Kubernetes
/// API defines — is explicitly refused rather than streamed, so no legitimate request is held
/// open waiting for something to happen. The watchdog reads `ConnectionActivity`, which reports
/// a connection with a request in flight as **not idle at all**, so an LLM round-trip or a
/// `manual` rule parked for a human can never close the connection it is an answer for.
///
/// Fifteen minutes is the wait between one request finishing and the next one starting. A real
/// `kube-apiserver` closes an idle HTTP/1 connection well before that, and `kubectl` opens a
/// connection, asks, and exits.
const IDLE_BETWEEN_REQUESTS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(900);

/// Concurrent connections this server admits.
///
/// Each admitted connection may buffer a request body of up to [`MAX_REQUEST_BODY_BYTES`], and
/// with TLS configured it also holds a rustls session, so the cap is what turns that
/// per-connection bound into a total one.
const MAX_CONNECTIONS: usize = crate::server::accept_bounded::DEFAULT_MAX_CONNECTIONS;

/// What a peer over [`MAX_CONNECTIONS`] is told before the socket closes.
///
/// A plaintext HTTP `503` with `Retry-After`, deliberately: a refused peer has not completed a
/// TLS handshake, and a TLS alert would have to be preceded by a handshake this server is
/// declining to perform. `kubectl` reports a transport error either way, but the bytes now say
/// why, and a plain `curl` against an http-mode server reads the status directly.
const CONNECTION_CAP_REFUSAL: &[u8] = b"HTTP/1.1 503 Service Unavailable\r\n\
    Content-Length: 0\r\nRetry-After: 5\r\nConnection: close\r\n\r\n";

/// Turn a model-supplied HTTP status code into a `u16`, or `None` when it is not one.
///
/// **The range check has to happen before the cast, not after.** `as u16` on a `u64` truncates
/// silently, and truncation lands on plausible values: `65736 as u16 == 200`, so an
/// out-of-range code the executor somehow let through would become a `200 OK` — a refusal
/// turned into an answer, which is the LDAP `result_code as u8` defect in a different protocol.
/// `execute_status` and `execute_object_response` already bound `code` to 100..600; this is the
/// second lock on the same door, and it fails closed instead of narrowing.
pub fn model_status_code(raw: Option<u64>, default: u16) -> Option<u16> {
    match raw {
        None => Some(default),
        Some(code) if (100..600).contains(&code) => Some(code as u16),
        Some(_) => None,
    }
}

/// Kubernetes API server.
pub struct KubernetesServer;

impl KubernetesServer {
    /// Bind, then spawn the accept loop.
    ///
    /// The listener is bound *before* the task is spawned so a bind failure is returned to the
    /// caller and `server_startup` records `ServerStatus::Error` — a server that reports
    /// `Running` while nothing is listening is worse than one that refuses to start. The
    /// accept-loop handle is registered with `AppState::register_server_task` so `stop_server`
    /// can abort it and release the port.
    pub async fn spawn_with_llm_actions(
        listen_addr: SocketAddr,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        server_id: ServerId,
        tls_config: Option<Arc<rustls::ServerConfig>>,
        config: KubernetesConfig,
    ) -> anyhow::Result<SocketAddr> {
        let listener =
            crate::server::socket_helpers::create_reusable_tcp_listener(listen_addr).await?;
        let local_addr = listener.local_addr()?;

        let scheme = if tls_config.is_some() {
            "https"
        } else {
            "http"
        };
        console_info!(
            status_tx,
            "Kubernetes API server listening on {}://{} (claiming {})",
            scheme,
            local_addr,
            config.kubernetes_version
        );

        let protocol = Arc::new(actions::KubernetesProtocol::new());
        let tls_acceptor = tls_config.map(tokio_rustls::TlsAcceptor::from);
        let config = Arc::new(config);
        let server_address = format!("{scheme}://{local_addr}");

        let task_registrar = app_state.clone();
        let limiter = crate::server::accept_bounded::ConnectionLimiter::new(MAX_CONNECTIONS);
        let accept_handle = tokio::spawn(async move {
            loop {
                match crate::server::accept_bounded::accept_bounded(
                    &listener,
                    &limiter,
                    CONNECTION_CAP_REFUSAL,
                    "Kubernetes",
                    Some(&status_tx),
                )
                .await
                {
                    Ok((stream, remote_addr, permit)) => {
                        let connection_id =
                            ConnectionId::new(app_state.get_next_unified_id().await);
                        let local_addr_conn = stream.local_addr().unwrap_or(local_addr);
                        info!(
                            "Kubernetes API connection {} from {}",
                            connection_id, remote_addr
                        );

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

                        let ctx = RequestContext {
                            llm_client: llm_client.clone(),
                            app_state: app_state.clone(),
                            status_tx: status_tx.clone(),
                            protocol: protocol.clone(),
                            config: config.clone(),
                            server_id,
                            server_address: server_address.clone(),
                        };
                        let tls_acceptor = tls_acceptor.clone();
                        let app_state_for_close = app_state.clone();
                        let status_for_close = status_tx.clone();

                        let task_owner = app_state.clone();
                        task_owner
                            .spawn_server_task(server_id, async move {
                                // Held for the life of the connection: dropping it early
                                // releases the slot while the peer is still here, which
                                // silently un-caps the server.
                                let _permit = permit;

                                // First-byte bound on the raw socket, before either the TLS
                                // acceptor or hyper sees it. Both are client-speaks-first, and
                                // `peek` waits for data without consuming it, so the ClientHello
                                // or the request line is still there afterwards. A deadline on
                                // reads would be wrong rather than merely awkward: hyper keeps
                                // polling the connection for frames *while a request is being
                                // answered*, so it would fire inside an LLM round-trip.
                                match tokio::time::timeout(
                                    FIRST_BYTE_READ_TIMEOUT,
                                    stream.peek(&mut [0u8; 1]),
                                )
                                .await
                                {
                                    Ok(Ok(0)) | Ok(Err(_)) => {
                                        app_state_for_close
                                            .close_connection_on_server(server_id, connection_id)
                                            .await;
                                        let _ = status_for_close.send("__UPDATE_UI__".to_string());
                                        return;
                                    }
                                    Ok(Ok(_)) => {}
                                    Err(_) => {
                                        debug!(
                                            "Kubernetes peer {} sent nothing for {}s; closing \
                                             before the request line",
                                            remote_addr,
                                            FIRST_BYTE_READ_TIMEOUT.as_secs()
                                        );
                                        app_state_for_close
                                            .close_connection_on_server(server_id, connection_id)
                                            .await;
                                        let _ = status_for_close.send("__UPDATE_UI__".to_string());
                                        return;
                                    }
                                }

                                match tls_acceptor {
                                    Some(acceptor) => match acceptor.accept(stream).await {
                                        Ok(tls_stream) => {
                                            debug!(
                                                "Kubernetes TLS handshake complete with {}",
                                                remote_addr
                                            );
                                            serve_connection(TokioIo::new(tls_stream), ctx).await;
                                        }
                                        Err(e) => {
                                            console_error!(
                                                status_for_close,
                                                "Kubernetes TLS handshake failed with {}: {}",
                                                remote_addr,
                                                e
                                            );
                                        }
                                    },
                                    None => {
                                        serve_connection(TokioIo::new(stream), ctx).await;
                                    }
                                }

                                app_state_for_close
                                    .close_connection_on_server(server_id, connection_id)
                                    .await;
                                crate::logging::emit::Log::to(&status_for_close).info(format!(
                                    "Kubernetes API connection {connection_id} closed"
                                ));
                                let _ = status_for_close.send("__UPDATE_UI__".to_string());
                            })
                            .await;
                    }
                    Err(e) => {
                        console_error!(
                            status_tx,
                            "Failed to accept Kubernetes API connection: {}",
                            e
                        );
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
    protocol: Arc<actions::KubernetesProtocol>,
    config: Arc<KubernetesConfig>,
    server_id: ServerId,
    server_address: String,
}

async fn serve_connection<T>(io: TokioIo<T>, ctx: RequestContext)
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    // Tracks whether this connection is answering anything. A request waiting on the model, or
    // parked for a human at the dashboard, holds the count above zero, so the idle watchdog
    // below cannot close the connection the answer belongs to however long it takes — only
    // genuine silence counts.
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
                debug!("Kubernetes API connection ended: {:?}", err);
            }
        }
        _ = crate::server::accept_bounded::watch_idle(
            Arc::clone(&activity),
            IDLE_BETWEEN_REQUESTS_TIMEOUT,
        ) => {
            debug!(
                "Kubernetes API connection idle for {}s; closing",
                IDLE_BETWEEN_REQUESTS_TIMEOUT.as_secs()
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Routing
// ---------------------------------------------------------------------------

/// A request against a resource collection or object.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResourceRoute {
    /// API group; empty for core.
    pub group: String,
    /// Group version.
    pub version: String,
    /// Plural resource name from the URL, e.g. `pods`.
    pub resource: String,
    /// Namespace, when the URL carried `/namespaces/{ns}/`.
    pub namespace: Option<String>,
    /// Object name, when the URL addressed a single object.
    pub name: Option<String>,
    /// Subresource, e.g. `log`, `status`.
    pub subresource: Option<String>,
}

impl ResourceRoute {
    fn group_version(&self) -> String {
        if self.group.is_empty() {
            self.version.clone()
        } else {
            format!("{}/{}", self.group, self.version)
        }
    }
}

/// What a request path resolves to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Route {
    /// `GET /version`
    Version,
    /// `GET /healthz`, `/livez`, `/readyz`
    Health,
    /// `GET /api`
    CoreApiVersions,
    /// `GET /apis`
    ApiGroupList,
    /// `GET /apis/{group}`
    ApiGroup(String),
    /// `GET /api/{version}` or `GET /apis/{group}/{version}`
    ApiResourceList { group: String, version: String },
    /// Anything addressing actual objects.
    Resource(ResourceRoute),
    /// Not part of the served surface.
    Unknown,
}

/// Resolve a request path to a [`Route`].
///
/// Exposed for tests: routing is the part `kubectl` exercises hardest, and getting
/// `/api/v1/namespaces` (list namespaces) to not be confused with
/// `/api/v1/namespaces/default/pods` is the whole trick.
pub fn resolve_route(path: &str) -> Route {
    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    match segments.as_slice() {
        [] => Route::Unknown,
        ["version"] => Route::Version,
        ["healthz"] | ["livez"] | ["readyz"] => Route::Health,
        ["api"] => Route::CoreApiVersions,
        ["apis"] => Route::ApiGroupList,
        ["api", version] => Route::ApiResourceList {
            group: String::new(),
            version: (*version).to_string(),
        },
        ["apis", group] => Route::ApiGroup((*group).to_string()),
        ["apis", group, version] => Route::ApiResourceList {
            group: (*group).to_string(),
            version: (*version).to_string(),
        },
        ["api", version, rest @ ..] => {
            Route::Resource(resource_route(String::new(), (*version).to_string(), rest))
        }
        ["apis", group, version, rest @ ..] => Route::Resource(resource_route(
            (*group).to_string(),
            (*version).to_string(),
            rest,
        )),
        _ => Route::Unknown,
    }
}

fn resource_route(group: String, version: String, rest: &[&str]) -> ResourceRoute {
    // `/namespaces` is both a cluster-scoped resource and the prefix of every namespaced
    // path. It is only a prefix when there is a resource name *after* the namespace.
    if rest.first() == Some(&"namespaces") && rest.len() >= 3 {
        ResourceRoute {
            group,
            version,
            resource: rest[2].to_string(),
            namespace: Some(rest[1].to_string()),
            name: rest.get(3).map(|s| (*s).to_string()),
            subresource: rest.get(4).map(|s| (*s).to_string()),
        }
    } else {
        ResourceRoute {
            group,
            version,
            resource: rest.first().map(|s| (*s).to_string()).unwrap_or_default(),
            namespace: None,
            name: rest.get(1).map(|s| (*s).to_string()),
            subresource: rest.get(2).map(|s| (*s).to_string()),
        }
    }
}

/// Parse a query string into a flat key→value map, keeping the last value for repeated keys.
fn parse_query(query: &str) -> serde_json::Map<String, Value> {
    let mut map = serde_json::Map::new();
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let (key, value) = match pair.split_once('=') {
            Some((k, v)) => (k, v),
            None => (pair, ""),
        };
        map.insert(
            percent_decode(key),
            Value::String(percent_decode(value.replace('+', " ").as_str())),
        );
    }
    map
}

/// Minimal percent-decoding; query values here are selectors like `app%3Dnginx`.
fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("");
            match u8::from_str_radix(hex, 16) {
                Ok(byte) => {
                    out.push(byte);
                    i += 3;
                    continue;
                }
                Err(_) => {
                    out.push(bytes[i]);
                    i += 1;
                    continue;
                }
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// True when the client asked for `Table` output — what `kubectl get` always sends.
fn wants_table(accept: Option<&str>) -> bool {
    accept
        .map(|value| value.to_ascii_lowercase().contains("as=table"))
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Request handling
// ---------------------------------------------------------------------------

fn json_response(status: StatusCode, body: &Value) -> Response<Full<Bytes>> {
    let bytes = serde_json::to_vec(body).unwrap_or_else(|_| b"{}".to_vec());
    let mut response = Response::new(Full::new(Bytes::from(bytes)));
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    response
}

fn status_response(
    code: u16,
    reason: &str,
    message: &str,
    details: Option<Value>,
) -> Response<Full<Bytes>> {
    let status = StatusCode::from_u16(code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    json_response(status, &status_object(code, reason, message, details))
}

fn text_response(status: StatusCode, body: &str) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(Bytes::from(body.to_string())));
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("text/plain"));
    response
}

async fn handle_request(req: Request<Incoming>, ctx: RequestContext) -> Response<Full<Bytes>> {
    let (parts, body) = req.into_parts();
    let method = parts.method.clone();
    let path = parts.uri.path().to_string();
    let query_string = parts.uri.query().unwrap_or("").to_string();
    let query = parse_query(&query_string);
    let accept = parts
        .headers
        .get(ACCEPT)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let user_agent = parts
        .headers
        .get(hyper::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    crate::logging::emit::Log::to(&ctx.status_tx).debug(format!(
        "Kubernetes API {} {}{}",
        method,
        path,
        {
            if query_string.is_empty() {
                String::new()
            } else {
                format!("?{query_string}")
            }
        }
    ));

    let route = resolve_route(&path);
    trace!("Kubernetes API route: {:?}", route);

    // Discovery and health are served deterministically: kubectl performs them before every
    // command and fails opaquely if they are wrong, and they describe the API's shape rather
    // than the cluster's contents. See CLAUDE.md.
    match &route {
        Route::Version => {
            return json_response(
                StatusCode::OK,
                &discovery::version_info(&ctx.config.kubernetes_version),
            )
        }
        Route::Health => return text_response(StatusCode::OK, "ok"),
        Route::CoreApiVersions => {
            return json_response(
                StatusCode::OK,
                &ctx.config.surface.api_versions(&ctx.server_address),
            )
        }
        Route::ApiGroupList => {
            return json_response(StatusCode::OK, &ctx.config.surface.api_group_list())
        }
        Route::ApiGroup(group) => {
            return match ctx.config.surface.api_group(group) {
                Some(value) => json_response(StatusCode::OK, &value),
                None => status_response(
                    404,
                    "NotFound",
                    &format!("the server could not find the requested resource: /apis/{group}"),
                    Some(json!({"group": group})),
                ),
            }
        }
        Route::ApiResourceList { group, version } => {
            return match ctx.config.surface.api_resource_list(group, version) {
                Some(value) => json_response(StatusCode::OK, &value),
                None => status_response(
                    404,
                    "NotFound",
                    &format!("the server could not find the requested resource: {path}"),
                    None,
                ),
            }
        }
        Route::Unknown => {
            return status_response(
                404,
                "NotFound",
                &format!("the server could not find the requested resource: {path}"),
                None,
            )
        }
        Route::Resource(_) => {}
    }

    let Route::Resource(resource_route) = route else {
        unreachable!("non-resource routes returned above");
    };

    // `?watch=true` is a long-lived chunked stream this server does not implement. Say so
    // explicitly rather than answering a watch with a one-shot list, which leaves the client
    // reconnecting in a loop against a body it cannot decode.
    let watching = query
        .get("watch")
        .and_then(Value::as_str)
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false);
    if watching {
        warn!(
            "Kubernetes API watch requested on {} - not implemented",
            path
        );
        return status_response(
            501,
            "NotImplemented",
            "netget's Kubernetes API server does not implement watch (?watch=true); use a \
             polling client or omit --watch",
            None,
        );
    }

    if ctx
        .config
        .surface
        .find(
            &resource_route.group,
            &resource_route.version,
            &resource_route.resource,
        )
        .is_none()
    {
        return status_response(
            404,
            "NotFound",
            &format!(
                "the server could not find the requested resource: {} is not advertised at {}",
                resource_route.resource,
                resource_route.group_version()
            ),
            Some(json!({
                "group": resource_route.group,
                "kind": resource_route.resource,
            })),
        );
    }

    // Bounded, and an unreadable body must never fall through as an empty one: the model would
    // then be shown a create carrying no object and could admit it as though the client had
    // sent none. Over the cap is `RequestEntityTooLarge`, the reason a real apiserver uses and
    // the one `client-go` surfaces without retrying.
    let body_bytes = match http_body_util::Limited::new(body, MAX_REQUEST_BODY_BYTES)
        .collect()
        .await
    {
        Ok(collected) => collected.to_bytes(),
        Err(e) => {
            // The transport error names hyper internals; the peer gets the category only.
            error!(
                "Kubernetes {} {}: decision=fail_closed_body_rejected (limit {} bytes): {}",
                method, path, MAX_REQUEST_BODY_BYTES, e
            );
            console_error!(
                ctx.status_tx,
                "Kubernetes {} {} -> refusing request body (limit {} bytes)",
                method,
                path,
                MAX_REQUEST_BODY_BYTES
            );
            return status_response(
                413,
                "RequestEntityTooLarge",
                "the request body is larger than this server accepts",
                Some(json!({"limitBytes": MAX_REQUEST_BODY_BYTES})),
            );
        }
    };

    let as_table = wants_table(accept.as_deref());
    let is_write = !matches!(method, Method::GET | Method::HEAD);

    let (event_type, mut event_data): (&'static EventType, Value) = if is_write {
        let parsed_body = serde_json::from_slice::<Value>(&body_bytes).ok();
        let mut data = base_event_data(&resource_route, &method, &path, &query, &user_agent);
        match parsed_body {
            Some(value) => data["body"] = value,
            None if !body_bytes.is_empty() => {
                data["body_text"] = json!(String::from_utf8_lossy(&body_bytes).into_owned());
            }
            None => {}
        }
        (&actions::K8S_WRITE_REQUEST, data)
    } else if resource_route.name.is_some() {
        (
            &actions::K8S_GET_REQUEST,
            base_event_data(&resource_route, &method, &path, &query, &user_agent),
        )
    } else {
        (
            &actions::K8S_LIST_REQUEST,
            base_event_data(&resource_route, &method, &path, &query, &user_agent),
        )
    };
    event_data["as_table"] = json!(as_table);

    if ctx.app_state.get_instruction(ctx.server_id).await.is_none() {
        error!("Kubernetes server {} not found in state", ctx.server_id);
        return status_response(
            500,
            "InternalError",
            "netget server instance is no longer registered",
            None,
        );
    }

    console_debug!(
        ctx.status_tx,
        "Calling LLM for Kubernetes {} {}",
        method,
        path
    );

    let event = Event::new(event_type, event_data);
    let llm_result = call_llm(
        &ctx.llm_client,
        &ctx.app_state,
        ctx.server_id,
        None,
        &event,
        ctx.protocol.as_ref(),
    )
    .await;

    match llm_result {
        Ok(execution) => {
            for result in execution.protocol_results {
                let action_name = match &result {
                    crate::llm::ActionResult::Custom { name, .. } => name.clone(),
                    _ => String::new(),
                };
                if let Some(response) =
                    build_response(result, &resource_route, as_table, &ctx.config)
                {
                    // A `k8s_status` is the model *choosing* to refuse (404, 403, 409…). It
                    // must stay distinguishable in the log from netget refusing on the model's
                    // behalf, which is what the two branches below do.
                    if action_name == "k8s_status" {
                        info!(
                            "Kubernetes {} {}: decision=model_reject status={}",
                            method,
                            path,
                            response.status().as_u16()
                        );
                    }
                    return response;
                }
            }
            // No usable action. Refuse rather than inventing an empty list: an empty PodList
            // is a claim about the cluster, and "the model said nothing" must not be
            // indistinguishable from "the model said there are no pods".
            error!(
                "Kubernetes {} {}: decision=fail_closed_no_action (model returned no k8s_* action)",
                method, path
            );
            console_error!(
                ctx.status_tx,
                "Kubernetes: model returned no k8s action for {} {}",
                method,
                path
            );
            status_response(
                500,
                "InternalError",
                "the handler returned no Kubernetes action for this request",
                None,
            )
        }
        Err(e) => {
            // The peer gets a category; the log gets the error. Never interpolate `e` into a
            // `Status` message — it names the backend, the model and netget's own internals.
            let failure = crate::utils::WireFailure::classify(&e);
            error!(
                "Kubernetes {} {}: decision=fail_closed_llm_error category={:?} error={}",
                method, path, failure, e
            );
            console_error!(ctx.status_tx, "Kubernetes LLM call failed: {}", e);
            match failure {
                // Saturated backend: 503 + Retry-After is what client-go backs off on, so the
                // client retries instead of recording a permanent fault.
                crate::utils::WireFailure::Overloaded => {
                    let mut response = status_response(
                        503,
                        "ServiceUnavailable",
                        failure.prefixed_text(),
                        Some(json!({"retryAfterSeconds": 5})),
                    );
                    response
                        .headers_mut()
                        .insert(hyper::header::RETRY_AFTER, HeaderValue::from_static("5"));
                    response
                }
                crate::utils::WireFailure::Unavailable => {
                    status_response(500, "InternalError", failure.prefixed_text(), None)
                }
            }
        }
    }
}

fn base_event_data(
    route: &ResourceRoute,
    method: &Method,
    path: &str,
    query: &serde_json::Map<String, Value>,
    user_agent: &str,
) -> Value {
    let mut data = json!({
        "method": method.as_str(),
        "path": path,
        "api_group": route.group,
        "api_version": route.version,
        "group_version": route.group_version(),
        "resource": route.resource,
        "user_agent": user_agent,
    });
    if let Some(namespace) = &route.namespace {
        data["namespace"] = json!(namespace);
    }
    if let Some(name) = &route.name {
        data["name"] = json!(name);
    }
    if let Some(subresource) = &route.subresource {
        data["subresource"] = json!(subresource);
    }
    for key in ["labelSelector", "fieldSelector", "limit", "resourceVersion"] {
        if let Some(value) = query.get(key) {
            data[key] = value.clone();
        }
    }
    data
}

/// Turn one action result into an HTTP response, or `None` if it is not a Kubernetes action
/// so the caller can keep scanning (a model may emit `notify_operator` alongside the real answer).
fn build_response(
    action_result: crate::llm::ActionResult,
    route: &ResourceRoute,
    as_table: bool,
    config: &KubernetesConfig,
) -> Option<Response<Full<Bytes>>> {
    use crate::llm::ActionResult;

    let ActionResult::Custom { name, data } = action_result else {
        return None;
    };

    match name.as_str() {
        "k8s_list_response" => {
            let item_kind = data
                .get("kind")
                .and_then(Value::as_str)
                .map(|k| k.trim_end_matches("List").to_string())
                .unwrap_or_else(|| kind_for_route(route, config));
            let items: Vec<Value> = data
                .get("items")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            let api_version = data
                .get("apiVersion")
                .and_then(Value::as_str)
                .map(|s| s.to_string())
                .unwrap_or_else(|| route.group_version());
            let resource_version = data
                .get("resourceVersion")
                .and_then(Value::as_str)
                .unwrap_or("1")
                .to_string();

            if as_table {
                return Some(json_response(
                    StatusCode::OK,
                    &table::table_from_items(&item_kind, &items),
                ));
            }
            Some(json_response(
                StatusCode::OK,
                &json!({
                    "kind": format!("{item_kind}List"),
                    "apiVersion": api_version,
                    "metadata": {"resourceVersion": resource_version},
                    "items": items,
                }),
            ))
        }
        "k8s_table_response" => {
            let columns: Vec<Value> = data
                .get("columns")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            let rows: Vec<Value> = data
                .get("rows")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            Some(json_response(
                StatusCode::OK,
                &table::table_from_columns_and_rows(&columns, &rows),
            ))
        }
        "k8s_object_response" => {
            // Defence in depth: `execute_object_response` already requires `object` and a
            // 100..600 `status_code`. If either ever gets past it, refuse — serving `{}` with
            // 200, or degrading an out-of-range code to 200, would be a claim about the
            // cluster that nobody made.
            let Some(object) = data.get("object").cloned() else {
                error!("Kubernetes: decision=fail_closed_no_action (k8s_object_response without 'object')");
                return Some(status_response(
                    500,
                    "InternalError",
                    "the handler returned no object for this request",
                    None,
                ));
            };
            let mut object = object;
            if object.get("kind").is_none() {
                object["kind"] = json!(kind_for_route(route, config));
            }
            if object.get("apiVersion").is_none() {
                object["apiVersion"] = json!(route.group_version());
            }
            let raw_code = data.get("status_code").and_then(Value::as_u64);
            let status =
                match model_status_code(raw_code, 200).and_then(|c| StatusCode::from_u16(c).ok()) {
                    Some(status) => status,
                    None => {
                        error!(
                            "Kubernetes: decision=fail_closed_bad_status (k8s_object_response \
                         status_code {raw_code:?} is not an HTTP status)"
                        );
                        return Some(status_response(
                            500,
                            "InternalError",
                            "the handler returned an unusable status code",
                            None,
                        ));
                    }
                };
            if as_table {
                let kind = object
                    .get("kind")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                return Some(json_response(
                    status,
                    &table::table_from_items(&kind, std::slice::from_ref(&object)),
                ));
            }
            Some(json_response(status, &object))
        }
        "k8s_status" => {
            let raw_code = data.get("code").and_then(Value::as_u64);
            // No usable code means netget refusing on the model's behalf, which is 500 — never
            // a narrowed value that could land inside 2xx and read as success.
            let code = model_status_code(raw_code, 500).unwrap_or_else(|| {
                error!(
                    "Kubernetes: decision=fail_closed_bad_status (k8s_status code {raw_code:?} \
                     is not an HTTP status)"
                );
                500
            });
            let reason = data
                .get("reason")
                .and_then(Value::as_str)
                .unwrap_or("InternalError");
            let message = data
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("unspecified error");
            Some(status_response(
                code,
                reason,
                message,
                data.get("details").cloned(),
            ))
        }
        other => {
            debug!("Kubernetes: ignoring non-Kubernetes action '{}'", other);
            None
        }
    }
}

/// The object kind for a route, taken from the discovery table so the envelope matches what
/// discovery advertised even when the model omitted `kind`.
fn kind_for_route(route: &ResourceRoute, config: &KubernetesConfig) -> String {
    config
        .surface
        .find(&route.group, &route.version, &route.resource)
        .map(|r| r.kind.clone())
        .unwrap_or_else(|| "Unknown".to_string())
}

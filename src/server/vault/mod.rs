//! HashiCorp Vault server, KV version 2: what `vault status` and `vault kv get/put/list/
//! metadata get` need.
//!
//! The CLI's first request for any `kv` command is `GET /v1/sys/internal/ui/mounts/<path>`; the
//! `options.version` it finds there decides whether it uses KV v1 paths or v2's
//! `<mount>/data/…` and `<mount>/metadata/…`. NetGet answers that preflight, seal status, health
//! and leader deterministically from its configuration, and raises `vault_read`, `vault_write`
//! or `vault_list` for everything that touches a secret. **NetGet stores nothing**: the model
//! (or its memory, or the SQLite facility) holds the secrets.
//!
//! `X-Vault-Token` reaches the model only as booleans — present, matches the configured token,
//! a token is configured — never the token itself. See `src/server/vault/CLAUDE.md`.

pub mod actions;
/// Routing and rendering. Public so it can be tested without a socket.
pub mod api;

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::header::{HeaderValue, CACHE_CONTROL, CONTENT_TYPE, RETRY_AFTER};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde_json::{json, Value};
use tokio::sync::mpsc;
use tracing::{debug, error, info};

use crate::llm::action_helper::call_llm;
use crate::llm::ollama_client::OllamaClient;
use crate::protocol::{Event, EventType};
use crate::server::connection::ConnectionId;
use crate::state::app_state::AppState;
use crate::state::ServerId;
use crate::{console_debug, console_error, console_info};

use api::Route;

/// Largest request body this server will buffer, in bytes.
///
/// A KV write carries the secret's key/value pairs, and those are then embedded whole in an LLM
/// prompt, so there is no legitimate large one. Vault's own default `max_request_size` is
/// 32 MiB; this is far below it on purpose. Read before routing so it holds on every path.
pub const MAX_REQUEST_BODY_BYTES: usize = 1024 * 1024;

/// How long to wait for a peer's first byte after it connects (`peek` before hyper).
const FIRST_BYTE_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// How long a connection may do nothing at all between requests. The CLI connects per
/// command; SDK clients pool connections. `ConnectionActivity` keeps a request waiting on the
/// model, or parked for a human, from reading as idle.
const IDLE_BETWEEN_REQUESTS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

/// Concurrent connections this server admits.
const MAX_CONNECTIONS: usize = crate::server::accept_bounded::DEFAULT_MAX_CONNECTIONS;

/// What a peer over [`MAX_CONNECTIONS`] is told before the socket closes.
const CONNECTION_CAP_REFUSAL: &[u8] = b"HTTP/1.1 503 Service Unavailable\r\n\
    Content-Type: application/json\r\nContent-Length: 44\r\nRetry-After: 5\r\n\
    Connection: close\r\n\r\n{\"errors\":[\"netget: too many connections\"]}\n";

/// Version reported by `sys/seal-status` and `sys/health` when `vault_version` is absent.
pub const DEFAULT_VAULT_VERSION: &str = "1.18.3";

/// Per-server configuration.
#[derive(Clone, Debug)]
pub struct VaultConfig {
    pub identity: api::VaultIdentity,
    /// KV v2 mount paths, without slashes (`secret`, `kv/prod`).
    pub kv_mounts: Vec<String>,
    /// The token requests are compared against. `None` means none was configured, and then any
    /// non-empty token counts as matching.
    pub token: Option<String>,
}

/// Vault server.
pub struct VaultServer;

impl VaultServer {
    /// Bind, then spawn the accept loop, registered so `stop_server` frees the port.
    pub async fn spawn_with_llm_actions(
        listen_addr: SocketAddr,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        server_id: ServerId,
        config: VaultConfig,
    ) -> anyhow::Result<SocketAddr> {
        let listener =
            crate::server::socket_helpers::create_reusable_tcp_listener(listen_addr).await?;
        let local_addr = listener.local_addr()?;

        console_info!(
            status_tx,
            "Vault listening on http://{} (KV v2 mounts: {}; token {})",
            local_addr,
            config.kv_mounts.join(", "),
            if config.token.is_some() {
                "configured"
            } else {
                "not configured - any token accepted"
            }
        );

        let protocol = Arc::new(actions::VaultProtocol::new());
        let config = Arc::new(config);
        let task_registrar = app_state.clone();
        let limiter = crate::server::accept_bounded::ConnectionLimiter::new(MAX_CONNECTIONS);
        let accept_handle = tokio::spawn(async move {
            loop {
                match crate::server::accept_bounded::accept_bounded(
                    &listener,
                    &limiter,
                    CONNECTION_CAP_REFUSAL,
                    "Vault",
                    Some(&status_tx),
                )
                .await
                {
                    Ok((stream, remote_addr, permit)) => {
                        let connection_id =
                            ConnectionId::new(app_state.get_next_unified_id().await);
                        let local_addr_conn = stream.local_addr().unwrap_or(local_addr);
                        info!("Vault connection {} from {}", connection_id, remote_addr);

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
                                            "Vault peer {} sent nothing for {}s; closing",
                                            remote_addr,
                                            FIRST_BYTE_READ_TIMEOUT.as_secs()
                                        );
                                    }
                                }

                                app_state_for_close
                                    .close_connection_on_server(server_id, connection_id)
                                    .await;
                                crate::logging::emit::Log::to(&status_for_close)
                                    .info(format!("Vault connection {connection_id} closed"));
                                let _ = status_for_close.send("__UPDATE_UI__".to_string());
                            })
                            .await;
                    }
                    Err(e) => {
                        console_error!(status_tx, "Failed to accept Vault connection: {}", e);
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

#[derive(Clone)]
struct RequestContext {
    llm_client: OllamaClient,
    app_state: Arc<AppState>,
    status_tx: mpsc::UnboundedSender<String>,
    protocol: Arc<actions::VaultProtocol>,
    config: Arc<VaultConfig>,
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
                debug!("Vault connection ended: {:?}", err);
            }
        }
        _ = crate::server::accept_bounded::watch_idle(
            Arc::clone(&activity),
            IDLE_BETWEEN_REQUESTS_TIMEOUT,
        ) => {
            debug!(
                "Vault connection idle for {}s; closing",
                IDLE_BETWEEN_REQUESTS_TIMEOUT.as_secs()
            );
        }
    }
}

fn json_response(status: StatusCode, body: &Value) -> Response<Full<Bytes>> {
    let mut bytes = serde_json::to_vec(body).unwrap_or_else(|_| b"{}".to_vec());
    bytes.push(b'\n');
    let mut response = Response::new(Full::new(Bytes::from(bytes)));
    *response.status_mut() = status;
    let headers = response.headers_mut();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// Vault's error shape. The messages are NetGet's fixed text or the model's chosen wording.
fn error_response(status: StatusCode, errors: &[&str]) -> Response<Full<Bytes>> {
    let errors: Vec<String> = errors.iter().map(|e| e.to_string()).collect();
    json_response(status, &api::errors_body(&errors))
}

/// `(token_present, token_matches_configured, token_configured)`, compared in constant time.
fn token_facts(presented: Option<&str>, configured: Option<&str>) -> (bool, bool, bool) {
    let present = presented.is_some_and(|t| !t.is_empty());
    match configured {
        None => (present, present, false),
        Some(expected) => {
            let matches = presented.is_some_and(|got| {
                got.len() == expected.len()
                    && got
                        .bytes()
                        .zip(expected.bytes())
                        .fold(0u8, |acc, (a, b)| acc | (a ^ b))
                        == 0
            });
            (present, matches, true)
        }
    }
}

async fn handle_request(req: Request<Incoming>, ctx: RequestContext) -> Response<Full<Bytes>> {
    let (parts, body) = req.into_parts();
    let method = parts.method.as_str().to_string();
    let path = parts.uri.path().to_string();
    let query = parts.uri.query().unwrap_or("");
    let list_query = query.split('&').any(|p| p == "list=true" || p == "list=1");
    let version_query = query
        .split('&')
        .find_map(|p| p.strip_prefix("version="))
        .and_then(|v| v.parse::<u64>().ok());
    let presented = parts
        .headers
        .get("x-vault-token")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);

    crate::logging::emit::Log::to(&ctx.status_tx).debug(format!("Vault {method} {path}"));

    let body_bytes = match http_body_util::Limited::new(body, MAX_REQUEST_BODY_BYTES)
        .collect()
        .await
    {
        Ok(collected) => collected.to_bytes(),
        Err(e) => {
            error!(
                "Vault {} {}: decision=fail_closed_body_rejected (limit {} bytes): {}",
                method, path, MAX_REQUEST_BODY_BYTES, e
            );
            return error_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                &["netget: request body is larger than this server accepts"],
            );
        }
    };
    ctx.app_state
        .update_connection_stats(
            ctx.server_id,
            ctx.connection_id,
            Some(body_bytes.len() as u64),
            None,
            Some(1),
            None,
        )
        .await;

    let config = &ctx.config;
    let route = api::resolve(&method, &path, list_query, &config.kv_mounts);
    let (event_type, mut data): (&'static EventType, Value) = match &route {
        Route::SealStatus => {
            return json_response(StatusCode::OK, &api::seal_status(&config.identity))
        }
        Route::Health => return json_response(StatusCode::OK, &api::health(&config.identity)),
        Route::Leader => return json_response(StatusCode::OK, &api::leader()),
        Route::MountPreflight(p) => {
            return match api::preflight_mount(p, &config.kv_mounts) {
                Some(mount) => json_response(StatusCode::OK, &api::mount_preflight(&mount)),
                // What Vault answers for a path no mount covers; the CLI then reports it.
                None => error_response(
                    StatusCode::FORBIDDEN,
                    &[
                        "preflight capability check returned 403, please ensure client's \
                       policies grant access to path",
                    ],
                ),
            };
        }
        Route::Unsupported => {
            info!(
                "Vault {} {}: decision=fail_closed_not_implemented",
                method, path
            );
            return error_response(
                StatusCode::METHOD_NOT_ALLOWED,
                &["netget's Vault implements KV v2 read, write, list and metadata read only"],
            );
        }
        Route::NotFound => {
            let route_name =
                crate::utils::sanitize::line_field(path.strip_prefix("/v1/").unwrap_or(&path));
            return error_response(
                StatusCode::NOT_FOUND,
                &[&format!(
                    "no handler for route \"{route_name}\". route entry not found."
                )],
            );
        }
        Route::ReadData { mount, path } => {
            let answer_with = actions::read_answer_with(&mount, &path, "data");
            let mut d = json!({
                "mount": mount,
                "path": path,
                "what": "data",
                "answer_with": answer_with,
            });
            if let Some(v) = version_query {
                d["version"] = json!(v);
            }
            (&actions::VAULT_READ_EVENT, d)
        }
        Route::ReadMetadata { mount, path } => {
            let answer_with = actions::read_answer_with(&mount, &path, "metadata");
            (
                &actions::VAULT_READ_EVENT,
                json!({
                    "mount": mount,
                    "path": path,
                    "what": "metadata",
                    "answer_with": answer_with,
                }),
            )
        }
        Route::List { mount, path } => (
            &actions::VAULT_LIST_EVENT,
            json!({"mount": mount, "path": path}),
        ),
        Route::WriteData { mount, path } => {
            // KV v2's write body is {"data": {...}, "options": {"cas": N}}. Anything else is
            // Vault's own 400, decided here rather than shown to the model as an empty write.
            let parsed: Option<Value> = serde_json::from_slice(&body_bytes).ok();
            let Some(secret) = parsed
                .as_ref()
                .and_then(|b| b.get("data"))
                .filter(|d| d.is_object())
                .cloned()
            else {
                return error_response(StatusCode::BAD_REQUEST, &["no data provided"]);
            };
            let mut d = json!({"mount": mount, "path": path, "data": secret});
            if let Some(cas) = parsed
                .as_ref()
                .and_then(|b| b.pointer("/options/cas"))
                .and_then(Value::as_u64)
            {
                d["cas"] = json!(cas);
            }
            (&actions::VAULT_WRITE_EVENT, d)
        }
    };

    let (token_present, token_matches, token_configured) =
        token_facts(presented.as_deref(), config.token.as_deref());
    data["token_present"] = json!(token_present);
    data["token_matches_configured"] = json!(token_matches);
    data["token_configured"] = json!(token_configured);

    console_debug!(ctx.status_tx, "Calling LLM for Vault {} {}", method, path);
    let event = Event::new(event_type, data);
    let llm_result = call_llm(
        &ctx.llm_client,
        &ctx.app_state,
        ctx.server_id,
        Some(ctx.connection_id),
        &event,
        ctx.protocol.as_ref(),
    )
    .await;

    let expected = match &route {
        Route::ReadData { .. } | Route::ReadMetadata { .. } => "send_vault_secret",
        Route::WriteData { .. } => "send_vault_write_ok",
        _ => "send_vault_list",
    };
    let response = match llm_result {
        Ok(execution) => {
            let failure_summary = execution.failure_summary();
            let mut answer = None;
            for result in execution.protocol_results {
                let crate::llm::ActionResult::Custom { name, data } = result else {
                    continue;
                };
                if name == "send_vault_error" || name == "send_vault_not_found" {
                    match api::render_error(&data) {
                        Ok((status, errors)) => {
                            info!(
                                "Vault {} {}: decision=model_reject status={}",
                                method, path, status
                            );
                            let refs: Vec<&str> = errors.iter().map(String::as_str).collect();
                            answer = Some(error_response(
                                StatusCode::from_u16(status)
                                    .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                                &refs,
                            ));
                            break;
                        }
                        Err(reason) => error!(
                            "Vault {} {}: decision=fail_closed_invalid_answer ({})",
                            method, path, reason
                        ),
                    }
                    continue;
                }
                if name != expected {
                    debug!(
                        "Vault {} {}: ignoring {} (this route is answered by {})",
                        method, path, name, expected
                    );
                    continue;
                }
                let rendered = match &route {
                    Route::ReadData { .. } => api::render_secret(&data),
                    Route::ReadMetadata { .. } => api::render_metadata(&data),
                    Route::WriteData { .. } => api::render_write_ok(&data),
                    _ => api::render_list(&data),
                };
                match rendered {
                    Ok(body) => {
                        info!(
                            "Vault {} {}: decision=model_answer action={}",
                            method, path, name
                        );
                        answer = Some(json_response(StatusCode::OK, &body));
                        break;
                    }
                    Err(reason) => error!(
                        "Vault {} {}: decision=fail_closed_invalid_answer ({})",
                        method, path, reason
                    ),
                }
            }
            match answer {
                Some(response) => response,
                None => {
                    match failure_summary {
                        Some(summary) => error!(
                            "Vault {} {}: decision=fail_closed_invalid_answer ({})",
                            method, path, summary
                        ),
                        None => error!(
                            "Vault {} {}: decision=fail_closed_no_action (expected {})",
                            method, path, expected
                        ),
                    }
                    console_error!(
                        ctx.status_tx,
                        "Vault: the handler returned no usable answer for {} {}",
                        method,
                        path
                    );
                    error_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        &["netget: the handler returned no usable answer for this request"],
                    )
                }
            }
        }
        Err(e) => {
            let failure = crate::utils::WireFailure::classify(&e);
            error!(
                "Vault {} {}: decision=fail_closed_llm_error category={:?} error={}",
                method, path, failure, e
            );
            console_error!(ctx.status_tx, "Vault LLM call failed: {}", e);
            match failure {
                crate::utils::WireFailure::Overloaded => {
                    let mut response =
                        error_response(StatusCode::SERVICE_UNAVAILABLE, &[failure.prefixed_text()]);
                    response
                        .headers_mut()
                        .insert(RETRY_AFTER, HeaderValue::from_static("5"));
                    response
                }
                crate::utils::WireFailure::Unavailable => error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &[failure.prefixed_text()],
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

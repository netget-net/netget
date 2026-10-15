//! gRPC server implementation with dynamic schema support
//!
//! Implements a gRPC server where the LLM provides protobuf schema definitions
//! and controls RPC request/response handling through JSON.

pub mod actions;
#[cfg(not(target_arch = "wasm32"))]
pub mod http1;
mod reflection;
pub(crate) mod schema;
pub mod stream_codec;
pub(crate) mod streaming;
pub mod value_codec;
pub use value_codec::{dynamic_message_to_json, json_to_dynamic_message, proto_value_to_json};

use anyhow::{bail, Context, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, info, trace, warn};

#[cfg(not(target_arch = "wasm32"))]
use crate::llm::action_helper::call_llm;
#[cfg(not(target_arch = "wasm32"))]
use crate::llm::ollama_client::OllamaClient;
#[cfg(not(target_arch = "wasm32"))]
use crate::llm::ActionResult;
#[cfg(not(target_arch = "wasm32"))]
use crate::logging::emit::Log;
#[cfg(not(target_arch = "wasm32"))]
use crate::protocol::Event;
#[cfg(not(target_arch = "wasm32"))]
use crate::server::grpc::actions::GRPC_UNARY_REQUEST_EVENT;
#[cfg(not(target_arch = "wasm32"))]
use crate::server::GrpcProtocol;
#[cfg(not(target_arch = "wasm32"))]
use crate::state::app_state::AppState;
use crate::{console_error, console_info};
#[cfg(not(target_arch = "wasm32"))]
use bytes::Bytes;
#[cfg(not(target_arch = "wasm32"))]
use http_body_util::{BodyExt, Limited};
#[cfg(not(target_arch = "wasm32"))]
use hyper::{body::Incoming, header::HeaderValue, Request, Response, StatusCode};
#[cfg(not(target_arch = "wasm32"))]
use prost::Message;
#[cfg(not(target_arch = "wasm32"))]
use prost_reflect::{DescriptorPool, DynamicMessage};
#[cfg(not(target_arch = "wasm32"))]
use serde_json::json;

/// Largest request body buffered, before gRPC framing. Matches gRPC's own default
/// `maxReceiveMessageLength` of 4 MiB.
#[cfg(not(target_arch = "wasm32"))]
pub const MAX_REQUEST_BYTES: usize = 4 * 1024 * 1024;

/// How long to wait for a peer's first byte after it connects.
///
/// HTTP/2 is client-speaks-first — the connection preface and the client's SETTINGS frame are
/// the first thing on the wire and the server says nothing before them — and every gRPC client
/// sends them inside its dial path. A peer that has connected and sent nothing has begun no
/// connection at all, which is the state an unauthenticated flood lives in. Enforced with
/// `TcpStream::peek` *before* the socket reaches hyper, so the preface is still there for hyper
/// afterwards.
#[cfg(not(target_arch = "wasm32"))]
const FIRST_BYTE_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// How long a connection may do nothing at all once it is up.
///
/// Keepalive is off by default. This watchdog runs only while there are no live
/// RPCs: a response body retains its busy guard through EOS/drop, including
/// a subscription, flow-control stall or parked handler. Each stream separately
/// has a whole-operation deadline.
#[cfg(not(target_arch = "wasm32"))]
const IDLE_BETWEEN_REQUESTS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(900);

/// Concurrent connections this server admits.
///
/// Each admitted connection may buffer a request of up to [`MAX_REQUEST_BYTES`] and holds an
/// HTTP/2 session with its own flow-control windows, so the cap is what turns that
/// per-connection bound into a total one.
#[cfg(not(target_arch = "wasm32"))]
const MAX_CONNECTIONS: usize = crate::server::accept_bounded::DEFAULT_MAX_CONNECTIONS;

/// What a peer over [`MAX_CONNECTIONS`] is told before the socket closes.
///
/// HTTP/1.1 `503 Service Unavailable` with a `Retry-After`, deliberately in the older protocol —
/// the same choice `src/server/etcd/mod.rs` makes and for the same reason. A refused peer has
/// not sent the HTTP/2 preface yet, so nothing has been negotiated, and a GOAWAY would have to
/// follow a SETTINGS exchange this server is declining to perform. A gRPC client reports a
/// transport failure either way, but the bytes on the wire now say why, and `curl` or a human
/// can read it.
#[cfg(not(target_arch = "wasm32"))]
const CONNECTION_CAP_REFUSAL: &[u8] = b"HTTP/1.1 503 Service Unavailable\r\n\
    Content-Length: 0\r\nRetry-After: 5\r\nConnection: close\r\n\r\n";

/// gRPC status codes (`google.rpc.Code`) this server produces.
///
/// `grpc_error`'s documented `code` string maps onto these. It previously did not map onto
/// anything: the code was parsed, logged, and then folded into a `bail!` message, so every
/// error reached the client as `13 INTERNAL` with the real code smuggled into the text of
/// `grpc-message`.
#[cfg(not(target_arch = "wasm32"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum GrpcStatus {
    Ok = 0,
    Cancelled = 1,
    Unknown = 2,
    InvalidArgument = 3,
    DeadlineExceeded = 4,
    NotFound = 5,
    AlreadyExists = 6,
    PermissionDenied = 7,
    ResourceExhausted = 8,
    FailedPrecondition = 9,
    Aborted = 10,
    OutOfRange = 11,
    Unimplemented = 12,
    Internal = 13,
    Unavailable = 14,
    DataLoss = 15,
    Unauthenticated = 16,
}

#[cfg(not(target_arch = "wasm32"))]
impl GrpcStatus {
    /// Parse the `code` field of a `grpc_error` action. Accepts the canonical spec spellings
    /// (`NOT_FOUND`), lowercase, and the bare integer. Anything unrecognized is `UNKNOWN`
    /// rather than a silent `INTERNAL`, so a typo is visible as a typo.
    fn parse(code: &str) -> Self {
        if let Ok(n) = code.trim().parse::<i32>() {
            return Self::from_i32(n);
        }
        match code.trim().to_ascii_uppercase().replace('-', "_").as_str() {
            "OK" => Self::Ok,
            "CANCELLED" | "CANCELED" => Self::Cancelled,
            "UNKNOWN" => Self::Unknown,
            "INVALID_ARGUMENT" => Self::InvalidArgument,
            "DEADLINE_EXCEEDED" => Self::DeadlineExceeded,
            "NOT_FOUND" => Self::NotFound,
            "ALREADY_EXISTS" => Self::AlreadyExists,
            "PERMISSION_DENIED" => Self::PermissionDenied,
            "RESOURCE_EXHAUSTED" => Self::ResourceExhausted,
            "FAILED_PRECONDITION" => Self::FailedPrecondition,
            "ABORTED" => Self::Aborted,
            "OUT_OF_RANGE" => Self::OutOfRange,
            "UNIMPLEMENTED" | "NOT_IMPLEMENTED" => Self::Unimplemented,
            "INTERNAL" => Self::Internal,
            "UNAVAILABLE" => Self::Unavailable,
            "DATA_LOSS" => Self::DataLoss,
            "UNAUTHENTICATED" => Self::Unauthenticated,
            _ => Self::Unknown,
        }
    }

    fn from_i32(n: i32) -> Self {
        match n {
            0 => Self::Ok,
            1 => Self::Cancelled,
            2 => Self::Unknown,
            3 => Self::InvalidArgument,
            4 => Self::DeadlineExceeded,
            5 => Self::NotFound,
            6 => Self::AlreadyExists,
            7 => Self::PermissionDenied,
            8 => Self::ResourceExhausted,
            9 => Self::FailedPrecondition,
            10 => Self::Aborted,
            11 => Self::OutOfRange,
            12 => Self::Unimplemented,
            14 => Self::Unavailable,
            15 => Self::DataLoss,
            16 => Self::Unauthenticated,
            _ => Self::Internal,
        }
    }
}

/// The gRPC status a failed handler call must be reported as.
///
/// `UNAVAILABLE` (14) when the failure was the LLM backend being saturated, `INTERNAL` (13)
/// otherwise. The distinction is what gRPC client retry policies key on: `UNAVAILABLE` is in
/// the default retryable set and is the code a `grpc-service-config` `retryableStatusCodes`
/// list names, while `INTERNAL` is explicitly *not* retryable. Reporting a transient
/// rate-limiter refusal as `INTERNAL` converts a backlog that clears in seconds into a hard
/// application error for every caller.
///
/// Both are non-zero and both travel through `grpc_error_response`, which sends an empty body,
/// so neither can be mistaken for the `grpc-status: 0` + encoded message a success carries.
///
/// `pub` so `tests/` can exercise the classification directly — the project forbids
/// `#[cfg(test)]` modules in `src/`, and driving the rate limiter to refusal through a spawned
/// binary needs bounds the E2E harness cannot set.
#[cfg(not(target_arch = "wasm32"))]
pub fn grpc_status_for_llm_failure(err: &anyhow::Error) -> GrpcStatus {
    if crate::llm::is_overload_error(err) {
        GrpcStatus::Unavailable
    } else {
        GrpcStatus::Internal
    }
}

/// Classify a peer value conversion refusal without exposing its data in an error header.
#[cfg(not(target_arch = "wasm32"))]
pub fn grpc_status_for_value_failure(error: &anyhow::Error) -> GrpcStatus {
    if error
        .downcast_ref::<value_codec::ValueLimitExceeded>()
        .is_some()
    {
        GrpcStatus::ResourceExhausted
    } else {
        GrpcStatus::InvalidArgument
    }
}

/// Reduce a status message to the visible-ASCII subset `grpc-message` can carry.
///
/// `HeaderValue` accepts only visible ASCII, and these messages come from LLM output and
/// `anyhow` chains — netget's own LLM errors begin with a literal `✗`, and multi-line `anyhow`
/// context chains are routine. Substitution rather than rejection: a mangled character is a far
/// better outcome than a discarded explanation, which is what the static fallback in
/// `grpc_error_response` amounts to. Capped at 512 characters because a status message is a
/// diagnostic, not a payload, and everything is ASCII by then so the cut cannot split a
/// codepoint.
#[cfg(not(target_arch = "wasm32"))]
fn header_safe(message: &str) -> String {
    let mut out = String::with_capacity(message.len().min(512));
    let mut last_was_space = false;
    for c in message.chars() {
        let c = if (' '..='~').contains(&c) { c } else { ' ' };
        if c == ' ' {
            if last_was_space {
                continue;
            }
            last_was_space = true;
        } else {
            last_was_space = false;
        }
        if out.chars().count() >= 512 {
            break;
        }
        out.push(c);
    }
    let trimmed = out.trim();
    if trimmed.is_empty() {
        "internal error".to_string()
    } else {
        trimmed.to_string()
    }
}

/// A handler failure carrying the gRPC status it should be reported as.
#[cfg(not(target_arch = "wasm32"))]
struct GrpcFailure {
    status: GrpcStatus,
    message: String,
}

#[cfg(not(target_arch = "wasm32"))]
impl GrpcFailure {
    fn new(status: GrpcStatus, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl From<anyhow::Error> for GrpcFailure {
    fn from(e: anyhow::Error) -> Self {
        // Classify here too, not only at the explicit call site: `?` on an anyhow error is
        // reachable from several places in this module and an overload must never be reported
        // as a non-retryable INTERNAL just because it took the implicit path.
        //
        // `grpc-message` is a client-visible header, so it carries the category and not the
        // error - see `crate::utils::wire_failure`. The error itself is logged at the call
        // sites that have a status channel.
        let status = grpc_status_for_llm_failure(&e);
        Self::new(status, crate::utils::WireFailure::classify(&e).text())
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl From<serde_json::Error> for GrpcFailure {
    fn from(e: serde_json::Error) -> Self {
        // Logged in full; the peer gets the category only.
        debug!("gRPC JSON conversion failed: {e}");
        Self::new(GrpcStatus::Internal, "request could not be processed")
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl From<prost::EncodeError> for GrpcFailure {
    fn from(e: prost::EncodeError) -> Self {
        debug!("gRPC response encoding failed: {e}");
        Self::new(GrpcStatus::Internal, "could not encode response")
    }
}

/// gRPC server with dynamic schema support
pub struct GrpcServer;

#[cfg(not(target_arch = "wasm32"))]
impl GrpcServer {
    /// Spawn gRPC server with LLM-provided schema and actions
    ///
    /// The LLM provides a protobuf schema definition (as a string) via startup_params.
    /// The server parses requests into JSON, sends to LLM, and encodes JSON responses back to protobuf.
    pub async fn spawn_with_llm_actions(
        listen_addr: SocketAddr,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        server_id: crate::state::ServerId,
        startup_params: Option<crate::protocol::StartupParams>,
    ) -> Result<SocketAddr> {
        // Extract proto schema from startup params
        let proto_schema = startup_params
            .as_ref()
            .map(|p| p.get_string("proto_schema"))
            .transpose()?
            .context(
                "Missing 'proto_schema' in startup_params. LLM must provide protobuf definition.",
            )?;

        trace!("Proto schema:\n{}", proto_schema);
        Log::new(Some(&status_tx)).debug("Compiling protobuf schema for gRPC server");

        let descriptor_pool = schema::load(&proto_schema)
            .await
            .context("Failed to compile/load protobuf schema")?;
        let reflection_enabled = startup_params
            .as_ref()
            .map(|p| p.get_optional_bool("enable_reflection"))
            .transpose()?
            .flatten()
            .unwrap_or(streaming::DEFAULT_REFLECTION);
        let timeout_secs = startup_params
            .as_ref()
            .map(|p| p.get_optional_u64("stream_timeout_secs"))
            .transpose()?
            .flatten()
            .unwrap_or(streaming::DEFAULT_TIMEOUT_SECS);
        anyhow::ensure!(
            (1..=3600).contains(&timeout_secs),
            "stream_timeout_secs must be 1..3600"
        );
        let reflection = if reflection_enabled {
            Some(reflection::Reflection::new(&descriptor_pool)?)
        } else {
            None
        };

        let services = descriptor_pool.services().collect::<Vec<_>>();

        if services.is_empty() {
            bail!("No services found in protobuf schema. Schema must define at least one service.");
        }

        info!("gRPC server starting with {} service(s)", services.len());
        let log = Log::new(Some(&status_tx));
        for service in &services {
            log.info(format!(
                "gRPC service: {} ({} methods)",
                service.full_name(),
                service.methods().count()
            ));
        }

        // Create gRPC server with dynamic handler
        let protocol = Arc::new(GrpcProtocol::new());
        let descriptor_pool_arc = Arc::new(descriptor_pool.clone());

        // Create dynamic gRPC service
        let dynamic_service = DynamicGrpcService {
            llm_client: llm_client.clone(),
            app_state: app_state.clone(),
            status_tx: status_tx.clone(),
            server_id,
            descriptor_pool: descriptor_pool_arc,
            protocol,
            reflection,
            stream_timeout: std::time::Duration::from_secs(timeout_secs),
            streams: Arc::new(tokio::sync::Semaphore::new(streaming::MAX_ACTIVE)),
            next_stream_id: Arc::new(std::sync::atomic::AtomicU32::new(1)),
        };

        // Start HTTP/2 server for gRPC
        let listener =
            crate::server::socket_helpers::create_reusable_tcp_listener(listen_addr).await?;
        let actual_addr = listener.local_addr()?;

        console_info!(status_tx, "gRPC server listening on {}", actual_addr);

        // Spawn server loop
        let service = Arc::new(dynamic_service);
        let task_registrar = app_state.clone();
        let limiter = crate::server::accept_bounded::ConnectionLimiter::new(MAX_CONNECTIONS);
        let accept_handle = tokio::spawn(async move {
            loop {
                match crate::server::accept_bounded::accept_bounded(
                    &listener,
                    &limiter,
                    CONNECTION_CAP_REFUSAL,
                    "gRPC",
                    Some(&status_tx),
                )
                .await
                {
                    Ok((stream, remote_addr, permit)) => {
                        let connection_id = crate::server::connection::ConnectionId::new(
                            service.app_state.get_next_unified_id().await,
                        );
                        debug!("gRPC connection {} from {}", connection_id, remote_addr);
                        Log::new(Some(&status_tx))
                            .debug(format!("gRPC connection from {}", remote_addr));

                        // Add connection to server state
                        use crate::state::server::{
                            ConnectionState as ServerConnectionState, ConnectionStatus,
                            ProtocolConnectionInfo,
                        };
                        let now = crate::utils::clock::Instant::now();
                        let conn_state = ServerConnectionState {
                            id: connection_id,
                            remote_addr,
                            local_addr: actual_addr,
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

                        let service_clone = service.clone();
                        let app_state_clone = app_state.clone();
                        let status_tx_clone = status_tx.clone();

                        // Spawn connection handler
                        // Tracked, not detached: stop_server must abort this task too.
                        let task_owner = app_state.clone();
                        task_owner
                            .spawn_server_task(server_id, async move {
                                // Held for the life of the connection: dropping it early releases
                                // the slot while the peer is still here, which silently un-caps
                                // the server.
                                let _permit = permit;

                                // First-byte bound, before hyper sees the socket. hyper owns every
                                // read once `serve_connection` starts and keeps polling the
                                // connection for frames *while a request is being answered*, so a
                                // deadline on reads would fire in the middle of an LLM round-trip.
                                // `peek` waits for data without consuming it, so the HTTP/2 preface
                                // is still there for hyper afterwards.
                                match tokio::time::timeout(
                                    FIRST_BYTE_READ_TIMEOUT,
                                    stream.peek(&mut [0u8; 1]),
                                )
                                .await
                                {
                                    Ok(Ok(0)) | Ok(Err(_)) => {
                                        app_state_clone
                                            .remove_connection_from_server(server_id, connection_id)
                                            .await;
                                        let _ = status_tx_clone.send("__UPDATE_UI__".to_string());
                                        return;
                                    }
                                    Ok(Ok(_)) => {}
                                    Err(_) => {
                                        Log::new(Some(&status_tx_clone)).debug(format!(
                                        "gRPC peer {} sent nothing for {}s; closing before the \
                                         HTTP/2 preface",
                                        remote_addr,
                                        FIRST_BYTE_READ_TIMEOUT.as_secs()
                                    ));
                                        app_state_clone
                                            .remove_connection_from_server(server_id, connection_id)
                                            .await;
                                        let _ = status_tx_clone.send("__UPDATE_UI__".to_string());
                                        return;
                                    }
                                }

                                let io = hyper_util::rt::TokioIo::new(stream);

                                // Tracks whether this connection is answering anything. A request
                                // waiting on the model, or parked for a human at the dashboard,
                                // holds the count above zero, so the idle watchdog below cannot
                                // close the connection the answer belongs to however long it takes
                                // — only genuine silence counts.
                                let activity = Arc::new(
                                    crate::server::accept_bounded::ConnectionActivity::new(),
                                );
                                let activity_for_service = Arc::clone(&activity);
                                let executor = streaming::OwnedExecutor::default();
                                let _children = streaming::ConnectionTasks(executor.clone());
                                let registry = streaming::Registry::default();
                                let peer_rx = crate::server::peer_support::register_peer_channel(
                                    &app_state_clone,
                                    server_id,
                                    connection_id.as_u32(),
                                )
                                .await;
                                let _ = executor.spawn(streaming::command_loop(
                                    peer_rx,
                                    registry.clone(),
                                    service_clone.clone(),
                                    connection_id,
                                ));
                                let executor_for_service = executor.clone();

                                // Create service function for this connection
                                let grpc_service = hyper::service::service_fn(move |req| {
                                    let service = service_clone.clone();
                                    let conn_id = connection_id;
                                    let activity = Arc::clone(&activity_for_service);
                                    let registry = registry.clone();
                                    let executor = executor_for_service.clone();
                                    async move {
                                        let busy = activity.busy();
                                        service
                                            .handle_grpc_request(
                                                req, conn_id, busy, registry, executor,
                                            )
                                            .await
                                    }
                                });

                                // Serve HTTP/2 connection
                                let conn = hyper::server::conn::http2::Builder::new(executor)
                                    .max_concurrent_streams(16)
                                    .initial_stream_window_size(65536)
                                    .initial_connection_window_size(1048576)
                                    .max_header_list_size(32768)
                                    .max_frame_size(16384)
                                    .serve_connection(io, grpc_service);
                                tokio::pin!(conn);
                                tokio::select! {
                                    result = &mut conn => {
                                        if let Err(e) = result {
                                            Log::new(Some(&status_tx_clone))
                                                .debug(format!("gRPC connection error: {}", e));
                                        }
                                    }
                                    _ = crate::server::accept_bounded::watch_idle(
                                        Arc::clone(&activity),
                                        IDLE_BETWEEN_REQUESTS_TIMEOUT,
                                    ) => {
                                        debug!(
                                            "gRPC connection {} idle for {}s; closing",
                                            connection_id,
                                            IDLE_BETWEEN_REQUESTS_TIMEOUT.as_secs()
                                        );
                                    }
                                }

                                // Clean up connection
                                app_state_clone
                                    .remove_peer_handle(server_id, connection_id.as_u32())
                                    .await;
                                app_state_clone
                                    .remove_connection_from_server(server_id, connection_id)
                                    .await;
                                let _ = status_tx_clone.send("__UPDATE_UI__".to_string());
                            })
                            .await;
                    }
                    Err(e) => {
                        console_error!(status_tx, "Failed to accept gRPC connection: {}", e);
                        break;
                    }
                }
            }
        });

        task_registrar
            .register_server_task(server_id, accept_handle)
            .await;

        Ok(actual_addr)
    }
}

/// Dynamic gRPC service that handles requests using LLM
#[cfg(not(target_arch = "wasm32"))]
#[derive(Clone)]
struct DynamicGrpcService {
    llm_client: OllamaClient,
    app_state: Arc<AppState>,
    status_tx: mpsc::UnboundedSender<String>,
    server_id: crate::state::ServerId,
    descriptor_pool: Arc<DescriptorPool>,
    protocol: Arc<dyn crate::llm::actions::protocol_trait::Server>,
    reflection: Option<Arc<reflection::Reflection>>,
    stream_timeout: std::time::Duration,
    streams: Arc<tokio::sync::Semaphore>,
    next_stream_id: Arc<std::sync::atomic::AtomicU32>,
}

/// HTTP/1 RPC bindings share typed method handling, admission and cancellation with native
/// gRPC. Each binding owns its framing; legacy unary behavior is untouched.
#[cfg(not(target_arch = "wasm32"))]
#[derive(Clone)]
pub(crate) struct HttpCore(Arc<DynamicGrpcService>);
#[cfg(not(target_arch = "wasm32"))]
pub(crate) struct WebAdmission {
    pub(crate) deadline: tokio::time::Instant,
    permit: tokio::sync::OwnedSemaphorePermit,
    timer: streaming::DeadlineGuard,
    pub(crate) method: prost_reflect::MethodDescriptor,
    id: u32,
}
#[cfg(not(target_arch = "wasm32"))]
impl WebAdmission {
    /// Wrap the final status-converted body, so admission survives every reply path.
    pub(crate) fn guard(
        self,
        response: Response<tonic::body::BoxBody>,
        busy: crate::server::accept_bounded::BusyGuard,
    ) -> Response<tonic::body::BoxBody> {
        response.map(|body| http1::hold_body(body, (self.permit, busy, self.timer)))
    }
}
#[cfg(not(target_arch = "wasm32"))]
impl HttpCore {
    pub(crate) fn new(
        ctx: &crate::protocol::SpawnContext,
        pool: DescriptorPool,
        protocol: Arc<dyn crate::llm::actions::protocol_trait::Server>,
        timeout: std::time::Duration,
    ) -> Self {
        Self(Arc::new(DynamicGrpcService {
            llm_client: ctx.llm_client.clone(),
            app_state: ctx.state.clone(),
            status_tx: ctx.status_tx.clone(),
            server_id: ctx.server_id,
            descriptor_pool: Arc::new(pool),
            protocol,
            reflection: None,
            stream_timeout: timeout,
            streams: Arc::new(tokio::sync::Semaphore::new(streaming::MAX_ACTIVE)),
            next_stream_id: Arc::new(std::sync::atomic::AtomicU32::new(1)),
        }))
    }
    pub(crate) async fn commands(
        self,
        commands: mpsc::Receiver<crate::state::client_handles::ClientCommand>,
        registry: streaming::Registry,
        connection: crate::server::connection::ConnectionId,
    ) {
        streaming::command_loop(commands, registry, self.0, connection).await;
    }
    pub(crate) fn prepare(
        &self,
        request: &Request<tonic::body::BoxBody>,
        executor: streaming::OwnedExecutor,
    ) -> Result<WebAdmission, tonic::Status> {
        let method = DynamicGrpcService::parse_grpc_path(request.uri().path())
            .ok()
            .and_then(|(service, method)| {
                self.0
                    .descriptor_pool
                    .get_service_by_name(&service)
                    .and_then(|service| {
                        service
                            .methods()
                            .find(|candidate| candidate.name() == method)
                    })
            });
        let method = method.ok_or_else(|| tonic::Status::unimplemented("unknown RPC method"))?;
        if method.is_client_streaming() {
            return Err(tonic::Status::unimplemented(
                "HTTP/1 RPC binding supports unary and server-streaming methods only",
            ));
        }
        let timeout = streaming::timeout(request.headers(), self.0.stream_timeout)?;
        let deadline = tokio::time::Instant::now() + timeout;
        let permit = self
            .0
            .streams
            .clone()
            .try_acquire_owned()
            .map_err(|_| tonic::Status::unavailable("server at RPC capacity"))?;
        let timer = executor.deadline(deadline)?.retain_expired();
        let id = match self.0.next_stream_id.fetch_update(
            std::sync::atomic::Ordering::Relaxed,
            std::sync::atomic::Ordering::Relaxed,
            |id| id.checked_add(1),
        ) {
            Ok(id) => id,
            Err(_) => {
                return Err(tonic::Status::resource_exhausted(
                    "RPC identifiers exhausted",
                ))
            }
        };
        Ok(WebAdmission {
            deadline,
            permit,
            timer,
            method,
            id,
        })
    }
    pub(crate) async fn request(
        &self,
        request: Request<tonic::body::BoxBody>,
        connection: crate::server::connection::ConnectionId,
        registry: streaming::Registry,
        admission: &WebAdmission,
    ) -> Response<tonic::body::BoxBody> {
        streaming::dispatch(
            request,
            self.0.clone(),
            connection,
            admission.method.clone(),
            registry,
            admission.deadline,
            admission.id,
        )
        .await
    }
}

/// A gRPC response body: the length-prefixed message, then a **trailing HEADERS frame**
/// carrying `grpc-status`.
///
/// `Full<Bytes>` cannot emit trailers at all, which is how the status ended up in the initial
/// headers beside a DATA frame — not gRPC, and `grpcurl` (grpc-go, the reference
/// implementation) refuses such a stream outright:
///
/// ```text
/// Internal: server closed the stream without sending trailers
/// ```
///
/// The specification allows the status in the initial headers **only** for a Trailers-Only
/// reply, which by definition carries no message. So this server could report a *failure* to a
/// real gRPC client and could not report a *success* — every error reply is Trailers-Only by
/// construction and was accidentally correct, while every successful unary call was malformed.
/// That asymmetry is why the error-path test was real evidence and the success-path test had to
/// be written `#[ignore]`d.
///
/// The identical defect was found and fixed in `src/server/etcd/mod.rs` at the same time.
#[cfg(not(target_arch = "wasm32"))]
type GrpcBody = tonic::body::BoxBody;

/// A message frame followed by trailers carrying `grpc-status`.
///
/// Errors do not come through here — `grpc_error_response` is deliberately Trailers-Only.
#[cfg(not(target_arch = "wasm32"))]
fn grpc_body_with_trailers(body: Bytes, status: i32, message: &str) -> GrpcBody {
    use http_body_util::StreamBody;

    let mut trailers = hyper::HeaderMap::new();
    trailers.insert(
        "grpc-status",
        HeaderValue::from_str(&status.to_string())
            .unwrap_or_else(|_| HeaderValue::from_static("13")),
    );
    trailers.insert(
        "grpc-message",
        HeaderValue::from_str(message).unwrap_or_else(|_| HeaderValue::from_static("")),
    );

    let frames: Vec<std::result::Result<hyper::body::Frame<Bytes>, tonic::Status>> = vec![
        Ok(hyper::body::Frame::data(body)),
        Ok(hyper::body::Frame::trailers(trailers)),
    ];

    BodyExt::boxed_unsync(StreamBody::new(futures::stream::iter(frames)))
}

/// An empty body, for a Trailers-Only reply whose status rides in the initial headers.
#[cfg(not(target_arch = "wasm32"))]
fn empty_grpc_body() -> GrpcBody {
    http_body_util::Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed_unsync()
}

#[cfg(not(target_arch = "wasm32"))]
impl DynamicGrpcService {
    /// Handle a gRPC HTTP/2 request
    async fn handle_grpc_request(
        self: Arc<Self>,
        req: Request<Incoming>,
        connection_id: crate::server::connection::ConnectionId,
        busy: crate::server::accept_bounded::BusyGuard,
        registry: streaming::Registry,
        executor: streaming::OwnedExecutor,
    ) -> Result<Response<GrpcBody>, hyper::Error> {
        let reflection = matches!(
            req.uri().path(),
            "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo"
                | "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo"
        );
        let method = Self::parse_grpc_path(req.uri().path())
            .ok()
            .and_then(|(service, method)| {
                self.descriptor_pool
                    .get_service_by_name(&service)
                    .and_then(|service| {
                        service
                            .methods()
                            .find(|candidate| candidate.name() == method)
                    })
            });
        let streaming_method =
            method.filter(|method| method.is_client_streaming() || method.is_server_streaming());
        if reflection || streaming_method.is_some() {
            if req.method() != hyper::Method::POST
                || req.version() != hyper::Version::HTTP_2
                || !req.headers().get("content-type").is_some_and(|value| {
                    value
                        .to_str()
                        .is_ok_and(|value| value.starts_with("application/grpc"))
                })
            {
                return Ok(tonic::Status::invalid_argument(
                    "streaming requires POST application/grpc over HTTP/2",
                )
                .into_http());
            }
            let maximum = if reflection {
                std::time::Duration::from_secs(30)
            } else {
                self.stream_timeout
            };
            let timeout = match streaming::timeout(req.headers(), maximum) {
                Ok(timeout) => timeout,
                Err(status) => return Ok(status.into_http()),
            };
            let deadline = tokio::time::Instant::now() + timeout;
            let permit = match self.streams.clone().try_acquire_owned() {
                Ok(permit) => permit,
                Err(_) => {
                    return Ok(tonic::Status::unavailable("server at stream capacity").into_http())
                }
            };
            let timer = match executor.deadline(deadline) {
                Ok(timer) => timer,
                Err(status) => return Ok(status.into_http()),
            };
            let response = if reflection {
                let Some(state) = self.reflection.clone() else {
                    return Ok(tonic::Status::unimplemented("reflection disabled").into_http());
                };
                reflection::dispatch(req, state, deadline).await
            } else {
                let id = match self.next_stream_id.fetch_update(
                    std::sync::atomic::Ordering::Relaxed,
                    std::sync::atomic::Ordering::Relaxed,
                    |id| id.checked_add(1),
                ) {
                    Ok(id) => id,
                    Err(_) => {
                        return Ok(tonic::Status::resource_exhausted(
                            "stream identifiers exhausted",
                        )
                        .into_http())
                    }
                };
                streaming::dispatch(
                    req.map(|body| {
                        body.map_err(|_| tonic::Status::internal("request transport failed"))
                            .boxed_unsync()
                    }),
                    self.clone(),
                    connection_id,
                    streaming_method.unwrap(),
                    registry,
                    deadline,
                    id,
                )
                .await
            };
            return Ok(response.map(|body| {
                streaming::BodyGuard {
                    body,
                    _permit: permit,
                    _busy: busy,
                    _timer: timer,
                }
                .boxed_unsync()
            }));
        }
        let _busy = busy;
        // Extract service and method from path (format: /package.Service/Method)
        let path = req.uri().path();
        let (service_name, method_name) = match Self::parse_grpc_path(path) {
            Ok((svc, method)) => (svc, method),
            Err(e) => {
                debug!("Invalid gRPC path: {} - {}", path, e);
                return Ok(Self::grpc_error_response(
                    GrpcStatus::Unimplemented,
                    "path must be /package.Service/Method",
                ));
            }
        };

        Log::new(Some(&self.status_tx))
            .debug(format!("gRPC request: {}/{}", service_name, method_name));

        // Validate content-type
        if let Some(content_type) = req.headers().get("content-type") {
            if !content_type
                .to_str()
                .unwrap_or("")
                .starts_with("application/grpc")
            {
                return Ok(Self::grpc_error_response(
                    GrpcStatus::Internal,
                    "expected content-type application/grpc",
                ));
            }
        }

        // Read request body, capped. HTTP/2 flow control bounds the window, not the total, so
        // an unbounded collect() lets one client grow the process without limit.
        let body_bytes = match Limited::new(req.into_body(), MAX_REQUEST_BYTES)
            .collect()
            .await
        {
            Ok(collected) => collected.to_bytes(),
            Err(e) => {
                debug!("Failed to read gRPC request body: {}", e);
                return Ok(Self::grpc_error_response(
                    GrpcStatus::ResourceExhausted,
                    &format!("request body rejected (limit {} bytes)", MAX_REQUEST_BYTES),
                ));
            }
        };

        // Decode gRPC frame (5-byte header: compression flag + 4-byte length + payload)
        let request_payload = match Self::decode_grpc_frame(&body_bytes) {
            Ok(payload) => payload,
            Err(e) => {
                debug!("Failed to decode gRPC frame: {}", e);
                // A set compression flag is UNIMPLEMENTED per the spec, not a generic error:
                // it tells the client to retry without compression.
                let status = if body_bytes.first() == Some(&1) {
                    GrpcStatus::Unimplemented
                } else {
                    GrpcStatus::Internal
                };
                return Ok(Self::grpc_error_response(status, "malformed gRPC frame"));
            }
        };

        trace!("gRPC request payload: {} bytes", request_payload.len());

        // Handle the unary request
        let response_payload = match self
            .handle_unary(&service_name, &method_name, request_payload, connection_id)
            .await
        {
            Ok(payload) => payload,
            Err(failure) => {
                // Was `debug!` on the file log but `[ERROR]` on the TUI - exactly the
                // level drift the Log facade exists to prevent. Reclassified to ERROR on
                // both sinks: this is a genuine failed gRPC call reaching the client.
                Log::new(Some(&self.status_tx))
                    .error(format!("gRPC handler error: {}", failure.message));
                return Ok(Self::grpc_error_response(failure.status, &failure.message));
            }
        };

        // Encode response with gRPC framing
        let response_frame = Self::encode_grpc_frame(&response_payload);

        // Build the HTTP/2 response. The status goes in TRAILERS, not here: `grpc-status` in
        // the initial headers beside a DATA frame is what made grpcurl refuse every successful
        // call, because the stream then ends after DATA with no trailing HEADERS at all.
        let mut response = Response::new(grpc_body_with_trailers(
            Bytes::from(response_frame),
            GrpcStatus::Ok as i32,
            "",
        ));
        *response.status_mut() = StatusCode::OK;
        response
            .headers_mut()
            .insert("content-type", HeaderValue::from_static("application/grpc"));

        Log::new(Some(&self.status_tx))
            .debug(format!("gRPC response: {} bytes", response_payload.len()));

        Ok(response)
    }

    /// Parse gRPC path into service and method names
    fn parse_grpc_path(path: &str) -> Result<(String, String)> {
        // Format: /package.Service/Method
        if !path.starts_with('/') {
            bail!("Path must start with /");
        }

        let parts: Vec<&str> = path[1..].split('/').collect();
        if parts.len() != 2 {
            bail!("Path must be /Service/Method");
        }

        Ok((parts[0].to_string(), parts[1].to_string()))
    }

    /// Decode gRPC frame from bytes
    /// Frame format: 1 byte compression flag + 4 bytes length (big-endian) + payload
    fn decode_grpc_frame(frame: &[u8]) -> Result<Vec<u8>> {
        if frame.len() < 5 {
            bail!("Frame too short (need at least 5 bytes)");
        }

        let compressed = frame[0];
        if compressed != 0 {
            bail!("Compression not supported");
        }

        let length = u32::from_be_bytes([frame[1], frame[2], frame[3], frame[4]]) as usize;

        // Compare against the bytes remaining rather than computing `5 + length`. On a 32-bit
        // target that addition wraps: a length of 0xFFFFFFFF gives `5 + length == 4`, the
        // guard passes, and `frame[5..4]` panics with start > end.
        let available = frame.len() - 5;
        if length > available {
            bail!(
                "frame declares {} bytes but only {} follow the header",
                length,
                available
            );
        }

        Ok(frame[5..5 + length].to_vec())
    }

    /// Encode payload into gRPC frame
    fn encode_grpc_frame(payload: &[u8]) -> Vec<u8> {
        let length = payload.len() as u32;
        let mut frame = Vec::with_capacity(5 + payload.len());

        // Compression flag (0 = not compressed)
        frame.push(0);

        // Length (4 bytes, big-endian)
        frame.extend_from_slice(&length.to_be_bytes());

        // Payload
        frame.extend_from_slice(payload);

        frame
    }

    /// Create a gRPC error reply.
    ///
    /// Two things this must get right, both of which it used to get wrong:
    ///
    /// * **HTTP 200.** gRPC carries application failures in `grpc-status`, not in the HTTP
    ///   status line. A non-200 makes a conformant client discard `grpc-message` and
    ///   synthesize `UNAVAILABLE`/`UNKNOWN`, so the code and text chosen here never reach the
    ///   caller. The old signature took a `StatusCode` and returned 500/404/400/415.
    /// * **No `unwrap()` on the message.** `message` comes from LLM output and `anyhow`
    ///   chains. `HeaderValue` accepts only visible ASCII, so a single non-ASCII character or
    ///   newline in a model's error text made `Builder::body` return `Err` and panicked the
    ///   connection task — skipping the connection cleanup that runs after `serve_connection`
    ///   and leaving the entry permanently `Active`.
    ///
    /// The message is now put through [`header_safe`] first, so the caller keeps the
    /// explanation instead of the static fallback. That fallback had become the *common* case
    /// rather than the last resort: netget's own LLM error strings begin with a literal `✗`, so
    /// every backend failure reached the client with its reason replaced by "internal error".
    fn grpc_error_response(status: GrpcStatus, message: &str) -> Response<GrpcBody> {
        let message = &header_safe(message);
        // **Trailers-Only**, and deliberately so. With no message to send, the specification
        // puts the status in the initial headers and ends the stream there. This is the one
        // placement that is correct; the bug was applying it to replies that *do* carry a body.
        let mut res = Response::new(empty_grpc_body());
        *res.status_mut() = StatusCode::OK;
        let headers = res.headers_mut();
        headers.insert("content-type", HeaderValue::from_static("application/grpc"));
        headers.insert(
            "grpc-status",
            HeaderValue::from_str(&(status as i32).to_string())
                .unwrap_or_else(|_| HeaderValue::from_static("13")),
        );
        headers.insert(
            "grpc-message",
            HeaderValue::from_str(message)
                .unwrap_or_else(|_| HeaderValue::from_static("internal error")),
        );
        res
    }

    /// Handle a gRPC unary request
    async fn handle_unary(
        &self,
        service_name: &str,
        method_name: &str,
        request_bytes: Vec<u8>,
        connection_id: crate::server::connection::ConnectionId,
    ) -> std::result::Result<Vec<u8>, GrpcFailure> {
        // Find service and method descriptors. An unknown service or method is UNIMPLEMENTED,
        // which is what a client expects and what `grpcurl` prints usefully; it used to be
        // reported as INTERNAL over HTTP 500.
        let service_desc = self
            .descriptor_pool
            .services()
            .find(|s| s.full_name() == service_name)
            .ok_or_else(|| {
                GrpcFailure::new(
                    GrpcStatus::Unimplemented,
                    format!("unknown service {}", service_name),
                )
            })?;

        let method_desc = service_desc
            .methods()
            .find(|m| m.name() == method_name)
            .ok_or_else(|| {
                GrpcFailure::new(
                    GrpcStatus::Unimplemented,
                    format!("unknown method {}/{}", service_name, method_name),
                )
            })?;

        let input_desc = method_desc.input();
        let output_desc = method_desc.output();

        Log::new(Some(&self.status_tx))
            .debug(format!("gRPC unary call: {}/{}", service_name, method_name));

        // Decode request using dynamic message. A body this server cannot decode is the
        // client's malformed input, not a server fault.
        let request_msg = DynamicMessage::decode(input_desc.clone(), request_bytes.as_slice())
            .map_err(|e| {
                debug!("gRPC request message did not decode: {e}");
                GrpcFailure::new(
                    GrpcStatus::InvalidArgument,
                    "could not decode request message",
                )
            })?;

        // Convert through the shared bounded field-name JSON codec.
        let request_json = dynamic_message_to_json(&request_msg).map_err(|error| {
            debug!("gRPC request value conversion failed: {error:#}");
            GrpcFailure::new(
                grpc_status_for_value_failure(&error),
                "request value exceeds conversion limits or does not fit field-name JSON",
            )
        })?;

        Log::new(Some(&self.status_tx)).trace(format!(
            "gRPC request JSON: {}",
            serde_json::to_string_pretty(&request_json)?
        ));

        // Build response schema description for LLM
        let response_schema = Self::build_message_schema(&output_desc);

        // Create event for LLM
        let event = Event::new(
            &GRPC_UNARY_REQUEST_EVENT,
            json!({
                "service": service_name,
                "method": method_name,
                "request": request_json,
                "expected_response_schema": response_schema,
            }),
        );

        // Call LLM.
        //
        // A failure here is answered, never swallowed: the caller gets a non-zero grpc-status
        // with an empty body, which no client can confuse with the encoded response message a
        // success carries. `UNAVAILABLE` when the backend was merely saturated so a retry
        // policy can act on it, `INTERNAL` otherwise.
        let execution_result = call_llm(
            &self.llm_client,
            &self.app_state,
            self.server_id,
            Some(connection_id),
            &event,
            self.protocol.as_ref(),
        )
        .await
        .map_err(|e| {
            let status = grpc_status_for_llm_failure(&e);
            console_error!(
                self.status_tx,
                "gRPC {}/{} could not be answered: the handler failed ({}). Replying \
                 grpc-status {} ({:?}); no response message is being invented.",
                service_name,
                method_name,
                e,
                status as i32,
                status
            );
            GrpcFailure::new(
                status,
                crate::utils::WireFailure::classify(&e).prefixed_text(),
            )
        })?;

        // Process action results
        for protocol_result in execution_result.protocol_results {
            match protocol_result {
                ActionResult::Custom { name, data } if name == "grpc_unary_response" => {
                    // Extract response message from LLM
                    let response_json = data
                        .get("message")
                        .context("Missing 'message' in grpc_unary_response")?;

                    // Convert JSON to DynamicMessage
                    let response_msg = json_to_dynamic_message(response_json, &output_desc)
                        .map_err(|e| {
                            debug!("gRPC handler response did not fit the schema: {e}");
                            GrpcFailure::new(
                                GrpcStatus::Internal,
                                "handler's response does not fit the schema",
                            )
                        })?;

                    // Encode to protobuf bytes
                    let mut response_bytes = Vec::new();
                    response_msg
                        .encode(&mut response_bytes)
                        .map_err(anyhow::Error::from)?;

                    Log::new(Some(&self.status_tx))
                        .debug(format!("gRPC response: {} bytes", response_bytes.len()));

                    return Ok(response_bytes);
                }
                ActionResult::Custom { name, data } if name == "grpc_error" => {
                    // The documented `code` now reaches the wire. It used to be parsed,
                    // logged and then folded into a bail! message, so every error was sent
                    // as 13 INTERNAL over HTTP 500 with the real code as text inside
                    // grpc-message.
                    let code = data
                        .get("code")
                        .and_then(|c| c.as_str())
                        .unwrap_or("INTERNAL");
                    let message = data
                        .get("message")
                        .and_then(|m| m.as_str())
                        .unwrap_or("Internal error")
                        .to_string();

                    // `GrpcStatus::parse` maps "OK" (and "0") to GrpcStatus::Ok, so a model
                    // answering the *error* action with code "OK" produced grpc-status 0 — a
                    // successful RPC with an empty body, carrying the error text in
                    // grpc-message where no client looks. An action whose entire purpose is to
                    // fail cannot be allowed to report success; that is the same confusion
                    // between a refusal and an approval the root CLAUDE.md warns about, just
                    // arriving via contradictory model output rather than via silence.
                    let parsed = GrpcStatus::parse(code);
                    let status = if parsed == GrpcStatus::Ok {
                        warn!(
                            "gRPC grpc_error asked for status OK; sending UNKNOWN instead \
                             (decision=model_reject code_coerced): {}",
                            message
                        );
                        GrpcStatus::Unknown
                    } else {
                        parsed
                    };
                    debug!("gRPC error: {} ({:?}) - {}", code, status, message);
                    return Err(GrpcFailure::new(status, message));
                }
                _ => {
                    // Ignore other action results
                }
            }
        }

        // The handler ran but produced no usable action — neither `grpc_unary_response` nor
        // `grpc_error`. This is the fail-open trap: returning an empty message with
        // `grpc-status: 0` here is indistinguishable, to the caller, from a handler that
        // *deliberately* returned an empty response (`grpc_unary_response` with `{}`). A model
        // that never answered would then look like a successful empty reply.
        //
        // Answer it as a failure instead. `INTERNAL` (13), not `UNAVAILABLE`: the backend was
        // reachable and did respond — the response was simply unusable — so this is a genuine
        // application error, not a transient condition a retry policy should hammer. The
        // deliberate-empty case stays structurally distinct: it travels through
        // `grpc_unary_response` above and reaches the wire as `grpc-status: 0`.
        console_error!(
            self.status_tx,
            "gRPC {}/{} could not be answered: the handler returned no usable action \
             (no grpc_unary_response, no grpc_error). Replying grpc-status 13 (INTERNAL); no \
             empty response is being invented.",
            service_name,
            method_name
        );
        Err(GrpcFailure::new(
            GrpcStatus::Internal,
            format!(
                "netget gRPC: handler produced no usable response for {}/{}",
                service_name, method_name
            ),
        ))
    }

    /// Build a JSON schema description of a message type
    fn build_message_schema(message_desc: &prost_reflect::MessageDescriptor) -> serde_json::Value {
        let mut fields = serde_json::Map::new();

        for field in message_desc.fields() {
            let field_type = match field.kind() {
                prost_reflect::Kind::Double => "number (double)",
                prost_reflect::Kind::Float => "number (float)",
                prost_reflect::Kind::Int32
                | prost_reflect::Kind::Sint32
                | prost_reflect::Kind::Sfixed32 => "int32",
                prost_reflect::Kind::Int64
                | prost_reflect::Kind::Sint64
                | prost_reflect::Kind::Sfixed64 => "int64",
                prost_reflect::Kind::Uint32 | prost_reflect::Kind::Fixed32 => "uint32",
                prost_reflect::Kind::Uint64 | prost_reflect::Kind::Fixed64 => "uint64",
                prost_reflect::Kind::Bool => "boolean",
                prost_reflect::Kind::String => "string",
                prost_reflect::Kind::Bytes => "bytes (base64)",
                prost_reflect::Kind::Message(_) => "object",
                prost_reflect::Kind::Enum(_) => "enum (string)",
            };

            let cardinality = match field.cardinality() {
                prost_reflect::Cardinality::Optional => "optional",
                prost_reflect::Cardinality::Required => "required",
                prost_reflect::Cardinality::Repeated => "repeated",
            };

            fields.insert(
                field.name().to_string(),
                json!({
                    "type": field_type,
                    "cardinality": cardinality,
                }),
            );
        }

        json!({
            "type": "object",
            "fields": fields,
        })
    }
}

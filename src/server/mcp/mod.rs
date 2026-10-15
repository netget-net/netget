//! MCP (Model Context Protocol) server implementation
//!
//! This module implements an MCP server that allows LLM to control all server capabilities.
//! MCP is built on JSON-RPC 2.0 and provides a standardized way for LLM applications
//! to access external resources, tools, and prompts.
//!
//! Key features:
//! - JSON-RPC 2.0 over HTTP/SSE transport
//! - Full LLM control over resources, tools, and prompts
//! - Session-based state management
//! - Three-phase initialization (initialize → response → initialized)
//! - Support for resource subscriptions, tool execution, and prompt templates

pub mod actions;
pub mod jsonrpc;

use anyhow::Result;
use axum::{
    extract::{rejection::JsonRejection, DefaultBodyLimit, Json, State as AxumState},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
    Router,
};
use jsonrpc::{ErrorCode, JsonRpcError, JsonRpcMessage, JsonRpcResponse};
use serde_json::Value;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, error, info, trace, warn};

use crate::console_error;
#[cfg(not(target_arch = "wasm32"))]
use crate::llm::action_helper::call_llm;
#[cfg(not(target_arch = "wasm32"))]
use crate::llm::ollama_client::OllamaClient;
#[cfg(not(target_arch = "wasm32"))]
use crate::logging::emit::Log;
#[cfg(not(target_arch = "wasm32"))]
use crate::protocol::Event;
#[cfg(not(target_arch = "wasm32"))]
use crate::server::connection::ConnectionId;
#[cfg(not(target_arch = "wasm32"))]
use crate::server::McpProtocol;
#[cfg(not(target_arch = "wasm32"))]
use crate::state::app_state::AppState;
#[cfg(not(target_arch = "wasm32"))]
use crate::state::server::{ConnectionStatus, ProtocolConnectionInfo, ServerId};
#[cfg(not(target_arch = "wasm32"))]
use actions::{
    MCP_INITIALIZE_EVENT, MCP_PROMPTS_GET_EVENT, MCP_PROMPTS_LIST_EVENT, MCP_RESOURCES_LIST_EVENT,
    MCP_RESOURCES_READ_EVENT, MCP_TOOLS_CALL_EVENT, MCP_TOOLS_LIST_EVENT,
};
#[cfg(not(target_arch = "wasm32"))]
use jsonrpc::RequestId;

/// MCP server shared state
#[derive(Clone)]
pub struct McpServerState {
    /// LLM client for generating responses
    pub llm_client: OllamaClient,
    /// Application state
    pub app_state: Arc<AppState>,
    /// Status message sender
    pub status_tx: mpsc::UnboundedSender<String>,
    /// Server ID for tracking connections
    pub server_id: ServerId,
    /// Protocol implementation
    pub protocol: Arc<McpProtocol>,
    /// Local address the server is bound to
    pub local_addr: SocketAddr,
}

/// The largest JSON-RPC request body this server buffers, and its declared
/// `max_inbound_bytes`.
///
/// Set explicitly on the router as `DefaultBodyLimit`, rather than inherited: axum's own
/// default happens to be the same 2 MiB, but a framework default is a number nobody chose and
/// nothing would notice changing. Enforced while the body is buffered — up front from a
/// `Content-Length`, as it streams for a chunked body — so an over-limit request never reaches
/// the JSON parser, the event or the model. The refusal is a 413 carrying a JSON-RPC error with
/// a fixed message ([`BODY_TOO_LARGE_MESSAGE`]).
pub const MAX_REQUEST_BODY_BYTES: usize = 2 * 1024 * 1024;

/// Message of the JSON-RPC error in the 413 for an over-limit body. Fixed: the peer's length
/// goes to the log.
#[cfg(not(target_arch = "wasm32"))]
const BODY_TOO_LARGE_MESSAGE: &str = "request body too large";

/// Largest slice of a request echoed onto the status channel.
///
/// The whole request used to be serialized onto `status_tx` on every call. That channel is
/// unbounded with no backpressure (see the root CLAUDE.md), so a client posting bodies at
/// axum's 2 MiB default limit could enqueue faster than the TUI drains.
#[cfg(not(target_arch = "wasm32"))]
const MAX_TRACE_BYTES: usize = 4096;

/// MCP revisions this server will echo back in an `initialize` reply.
#[cfg(not(target_arch = "wasm32"))]
const SUPPORTED_PROTOCOL_VERSIONS: &[&str] = &["2024-11-05", "2025-03-26", "2025-06-18"];

/// Implementation-defined JSON-RPC error code for "the backend is at capacity, retry".
///
/// JSON-RPC 2.0 reserves -32000..=-32099 for server-defined errors. Reporting overload as
/// -32603 (InternalError) would tell the caller the server is broken when it is only busy.
#[cfg(not(target_arch = "wasm32"))]
const MCP_SERVER_BUSY_CODE: i32 = -32000;

/// Offered when the client asks for a revision not in the list above.
#[cfg(not(target_arch = "wasm32"))]
const DEFAULT_PROTOCOL_VERSION: &str = "2024-11-05";

/// How long to wait for the peer's first byte after it connects.
///
/// MCP rides on HTTP POST and is client-speaks-first: the request line is the first thing on
/// the wire and the server says nothing before it. A peer that has connected and sent nothing
/// has made no request, which is the state an unauthenticated flood lives in — and the one this
/// server had no bound on at all.
#[cfg(not(target_arch = "wasm32"))]
const FIRST_REQUEST_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// How long to wait for a *further* request on a keep-alive connection.
///
/// MCP is strictly request/response over HTTP, and a client holds its connection open between
/// calls — an editor with an MCP server attached may go minutes between tool calls while a
/// human thinks. Five minutes covers that; a client whose connection is reaped reconnects on
/// its next call and loses nothing, because MCP session state lives in this server's own map
/// and is keyed by session id, not by socket.
///
/// Crucially this bound applies **only while no request is outstanding** — see
/// `relay_mcp_connection`. A request waiting on the model, or parked for a human at the
/// dashboard (`src/state/intercepts.rs`, 300s by default), is not idle and is never timed out.
#[cfg(not(target_arch = "wasm32"))]
const IDLE_BETWEEN_REQUESTS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

/// Concurrent connections this server admits.
#[cfg(not(target_arch = "wasm32"))]
const MAX_CONNECTIONS: usize = crate::server::accept_bounded::DEFAULT_MAX_CONNECTIONS;

/// What a peer over [`MAX_CONNECTIONS`] is told before the socket closes.
///
/// HTTP `503` carrying a JSON-RPC error object with [`MCP_SERVER_BUSY_CODE`] — both layers of
/// this protocol's own vocabulary at once, so an HTTP client sees a 503 with `Retry-After` and
/// a JSON-RPC client that reads the body sees the same "server is at capacity, retry" code this
/// server already returns when the backend is overloaded.
///
/// `Content-Length` is 82, which is the length of the JSON object on the last line.
#[cfg(not(target_arch = "wasm32"))]
const CONNECTION_CAP_REFUSAL: &[u8] = b"HTTP/1.1 503 Service Unavailable\r\n\
    Content-Type: application/json\r\nContent-Length: 82\r\nRetry-After: 5\r\n\
    Connection: close\r\n\r\n\
    {\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":-32000,\"message\":\"server at capacity\"}}";

/// Turn an `mcp_error_response` action result into the JSON-RPC error it describes.
///
/// `mcp_error_response` is offered to the handler on every MCP event. Nothing used to consume
/// its result, so the chosen `code` and `message` were dropped and the caller received either
/// a generic `-32603` or - worse - a *success* reply such as `{"tools": []}`.
#[cfg(not(target_arch = "wasm32"))]
fn mcp_error_from_action(data: &Value) -> JsonRpcError {
    // i64 rather than i32: JSON-RPC codes are small, but `as i32` would wrap a large number
    // into a valid-looking code. Out-of-range values become InternalError.
    let code = data
        .get("code")
        .and_then(|v| v.as_i64())
        .and_then(|n| i32::try_from(n).ok())
        .unwrap_or(ErrorCode::InternalError as i32);

    JsonRpcError {
        code,
        message: data
            .get("message")
            .and_then(|v| v.as_str())
            .unwrap_or("Internal error")
            .to_string(),
        data: data.get("data").cloned(),
    }
}

/// Turn a failed LLM call into the JSON-RPC error the caller gets back.
///
/// Every MCP method routes its failure through here so the shape is identical
/// across all seven, and so the caller always receives a response - `handle_jsonrpc`
/// re-attaches the request `id` to whatever this returns, which is what lets the
/// client match the failure to its request instead of waiting on a reply that
/// never comes.
///
/// Overload is reported separately because it is transient: `-32603` says the
/// server is broken, while a server-defined `-32000` with a retry hint says it is
/// merely full. The JSON-RPC 2.0 spec reserves -32000..=-32099 for exactly this.
///
/// The peer-visible `message` comes from [`WireFailure`], which returns `&'static str`
/// precisely so nothing derived from the error can reach the wire: the backend URL, the
/// model name and the `anyhow` context chain go to the log and the status stream only.
///
/// The log line carries a `decision=` tag so the three outcomes an operator has to tell
/// apart stay greppable: `decision=fail_closed_llm_error_overloaded`,
/// `decision=fail_closed_llm_error_unavailable` (here), `decision=model_reject`
/// (the handler chose `mcp_error`) and `decision=model_no_answer` (the handler ran but
/// produced no usable action).
#[cfg(not(target_arch = "wasm32"))]
fn llm_failure_error(state: &McpServerState, method: &str, e: anyhow::Error) -> JsonRpcError {
    let failure = crate::utils::WireFailure::classify(&e);
    let decision = if failure.is_overloaded() {
        "fail_closed_llm_error_overloaded"
    } else {
        "fail_closed_llm_error_unavailable"
    };
    error!("MCP {} decision={}: {}", method, decision, e);
    Log::new(Some(&state.status_tx)).error(format!("MCP {} decision={}: {}", method, decision, e));

    // `data` reaches the client, so it carries the retry hint and nothing else - the error
    // itself was logged on both channels above. See `crate::utils::wire_failure`.
    if failure.is_overloaded() {
        return JsonRpcError {
            code: MCP_SERVER_BUSY_CODE,
            message: failure.text().to_string(),
            data: Some(serde_json::json!({"retryable": true})),
        };
    }

    JsonRpcError {
        code: ErrorCode::InternalError as i32,
        message: failure.text().to_string(),
        data: Some(serde_json::json!({"retryable": false})),
    }
}

/// Log that the handler explicitly chose to fail this request (`mcp_error`).
///
/// Distinct from a no-answer and from a backend failure: this one the model meant.
#[cfg(not(target_arch = "wasm32"))]
fn log_model_reject(state: &McpServerState, method: &str) {
    warn!(
        "MCP {} decision=model_reject: handler returned mcp_error",
        method
    );
    Log::new(Some(&state.status_tx)).warn(format!(
        "MCP {} decision=model_reject (handler returned mcp_error)",
        method
    ));
}

/// Log that the handler ran without erroring but produced no usable action, so the
/// hardcoded default below is what the caller receives.
#[cfg(not(target_arch = "wasm32"))]
fn log_model_no_answer(state: &McpServerState, method: &str, fallback: &str) {
    warn!(
        "MCP {} decision=model_no_answer: replying with {}",
        method, fallback
    );
    Log::new(Some(&state.status_tx)).warn(format!(
        "MCP {} decision=model_no_answer (replying with {})",
        method, fallback
    ));
}

/// Recover a request id from a payload that failed to parse as a JSON-RPC request.
///
/// JSON-RPC 2.0 requires the id to be echoed whenever it can be determined. The parse-failure
/// path used to pass `None` unconditionally, so a request whose `jsonrpc` field was missing or
/// whose `method` was not a string came back with `"id": null` even though the id was sitting
/// in the payload, leaving the client unable to match the error to its request.
#[cfg(not(target_arch = "wasm32"))]
fn recover_request_id(payload: &Value) -> Option<RequestId> {
    match payload.get("id")? {
        Value::String(s) => Some(RequestId::String(s.clone())),
        Value::Number(n) => n.as_i64().map(RequestId::Number),
        _ => None,
    }
}

/// MCP server that handles Model Context Protocol over HTTP
pub struct McpServer;

#[cfg(not(target_arch = "wasm32"))]
impl McpServer {
    /// Spawn MCP server with Axum on HTTP (default port 8000)
    pub async fn spawn_with_llm_actions(
        listen_addr: SocketAddr,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        server_id: ServerId,
    ) -> Result<SocketAddr> {
        let listener = tokio::net::TcpListener::bind(listen_addr).await?;
        let local_addr = listener.local_addr()?;

        info!("MCP server (JSON-RPC 2.0) listening on {}", local_addr);
        Log::new(Some(&status_tx)).info(format!("MCP server listening on {}", local_addr));

        let protocol = Arc::new(McpProtocol::new());

        let task_registrar = app_state.clone();
        let server_state = McpServerState {
            llm_client,
            app_state,
            status_tx: status_tx.clone(),
            server_id,
            protocol,
            local_addr,
        };

        // Build Axum router
        let app = Router::new()
            .route("/", post(handle_jsonrpc))
            .layer(DefaultBodyLimit::max(MAX_REQUEST_BODY_BYTES))
            .with_state(server_state);

        // `axum::serve` owns its accept loop and takes a concrete `TcpListener`, so there is no
        // seam inside it for a connection cap or a read deadline — the same wall
        // `src/server/nfs/guard.rs` hit with `NFSTcpListener`, and the answer is the same one:
        // NetGet keeps the public listener and runs the crate behind it on a loopback-only
        // ephemeral port, screening every connection on its own side of the socket.
        //
        // The cost is honest and worth stating: the axum handler sees the loopback relay as its
        // peer, so `handle_jsonrpc` cannot report the real client address, and the loopback
        // backend is reachable by other processes on this machine (again as with NFS).
        let backend = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let backend_addr = backend.local_addr()?;

        let backend_status = status_tx.clone();
        let backend_handle = tokio::spawn(async move {
            if let Err(e) = axum::serve(backend, app).await {
                console_error!(backend_status, "MCP server error: {}", e);
            }
        });

        let relay_state = task_registrar.clone();
        let accept_handle = tokio::spawn(async move {
            serve_screened_mcp(listener, backend_addr, status_tx, relay_state, server_id).await;
        });

        // Both tasks are registered: aborting only the front one would leave axum holding the
        // loopback port, so `stop_server` would not actually stop the server.
        task_registrar
            .register_server_task(server_id, backend_handle)
            .await;
        task_registrar
            .register_server_task(server_id, accept_handle)
            .await;

        Ok(local_addr)
    }
}

/// Handle incoming JSON-RPC 2.0 requests
#[cfg(not(target_arch = "wasm32"))]
async fn handle_jsonrpc(
    AxumState(state): AxumState<McpServerState>,
    payload: Result<Json<Value>, JsonRejection>,
) -> Response {
    let payload = match payload {
        Ok(Json(payload)) => payload,
        Err(rejection) if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE => {
            warn!(
                "MCP request body over {} bytes decision=fail_closed_body_too_large",
                MAX_REQUEST_BODY_BYTES
            );
            Log::new(Some(&state.status_tx)).warn(format!(
                "MCP refused a request body over {} bytes (decision=fail_closed_body_too_large)",
                MAX_REQUEST_BODY_BYTES
            ));
            let body = serde_json::json!({
                "jsonrpc": "2.0",
                "id": null,
                "error": {
                    "code": ErrorCode::InvalidRequest.as_i32(),
                    "message": BODY_TOO_LARGE_MESSAGE,
                },
            });
            return (StatusCode::PAYLOAD_TOO_LARGE, Json(body)).into_response();
        }
        // Wrong content type, unparseable JSON: axum's own rejection, as before.
        Err(rejection) => return rejection.into_response(),
    };
    trace!(
        "MCP received JSON-RPC request: {}",
        serde_json::to_string_pretty(&payload).unwrap_or_else(|_| payload.to_string())
    );

    let mut trace_body = serde_json::to_string(&payload).unwrap_or_default();
    if trace_body.len() > MAX_TRACE_BYTES {
        // Truncate on a char boundary: byte-slicing LLM- or client-supplied JSON panics on
        // multi-byte UTF-8 at the cut point.
        let cut = trace_body
            .char_indices()
            .take_while(|(i, _)| *i <= MAX_TRACE_BYTES)
            .last()
            .map(|(i, _)| i)
            .unwrap_or(0);
        trace_body.truncate(cut);
        trace_body.push_str("… (truncated)");
    }
    Log::new(Some(&state.status_tx)).trace(format!("MCP received: {}", trace_body));

    // Parse JSON-RPC message
    let message = match JsonRpcMessage::from_value(payload.clone()) {
        Ok(msg) => msg,
        Err(e) => {
            error!("Failed to parse JSON-RPC message: {:?}", e);
            let response = JsonRpcResponse::error(recover_request_id(&payload), e);
            return Json(response).into_response();
        }
    };

    // Handle based on message type
    match message {
        JsonRpcMessage::Request(req) => {
            let request_id = req.id.clone();
            let method = req.method.clone();

            debug!("MCP request: method={}, id={:?}", method, request_id);

            // Route to appropriate handler
            let result = match method.as_str() {
                "initialize" => handle_initialize(&state, req.params).await,
                "ping" => handle_ping(),
                "resources/list" => handle_resources_list(&state).await,
                "resources/read" => handle_resources_read(&state, req.params).await,
                "resources/subscribe" => handle_resources_subscribe(&state, req.params).await,
                "resources/unsubscribe" => handle_resources_unsubscribe(&state, req.params).await,
                "resources/templates/list" => handle_resources_templates_list(&state).await,
                "tools/list" => handle_tools_list(&state).await,
                "tools/call" => handle_tools_call(&state, req.params).await,
                "prompts/list" => handle_prompts_list(&state).await,
                "prompts/get" => handle_prompts_get(&state, req.params).await,
                "logging/setLevel" => handle_logging_set_level(&state, req.params).await,
                "completion/complete" => handle_completion(&state, req.params).await,
                _ => Err(JsonRpcError::new(ErrorCode::MethodNotFound)),
            };

            let response = match result {
                Ok(value) => {
                    trace!(
                        "MCP response success: {}",
                        serde_json::to_string_pretty(&value).unwrap_or_default()
                    );
                    JsonRpcResponse::success(request_id, value)
                }
                Err(e) => {
                    error!("MCP error: code={}, message={}", e.code, e.message);
                    Log::new(Some(&state.status_tx)).error(format!("MCP error: {}", e.message));
                    JsonRpcResponse::error(request_id, e)
                }
            };

            Json(response).into_response()
        }
        JsonRpcMessage::Notification(notif) => {
            let method = notif.method.clone();
            debug!("MCP notification: method={}", method);

            // Handle notifications (no response)
            match method.as_str() {
                "notifications/initialized" => {
                    handle_initialized(&state).await;
                }
                "notifications/cancelled" => {
                    handle_cancelled(&state, notif.params).await;
                }
                "notifications/progress" => {
                    handle_progress(&state, notif.params).await;
                }
                _ => {
                    debug!("Unknown MCP notification: {}", method);
                }
            }

            // Notifications don't return responses
            StatusCode::NO_CONTENT.into_response()
        }
    }
}

/// Handle initialize request - LLM declares capabilities
#[cfg(not(target_arch = "wasm32"))]
async fn handle_initialize(
    state: &McpServerState,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let connection_id = ConnectionId::new(state.app_state.get_next_unified_id().await);
    let result = handle_initialize_inner(state, params, connection_id).await;
    // Close on every exit path, including the error ones.
    state
        .app_state
        .close_connection_on_server(state.server_id, connection_id)
        .await;
    result
}

#[cfg(not(target_arch = "wasm32"))]
async fn handle_initialize_inner(
    state: &McpServerState,
    params: Option<Value>,
    connection_id: ConnectionId,
) -> Result<Value, JsonRpcError> {
    info!("MCP initialize request");

    // Extract client info from params
    let client_info = params
        .as_ref()
        .and_then(|p| p.get("clientInfo"))
        .map(|c| c.to_string())
        .unwrap_or_else(|| "unknown".to_string());

    debug!("MCP client: {}", client_info);
    let _ = state
        .status_tx
        .send(format!("→ MCP client initializing: {}", client_info));

    // Record the initialize exchange as a connection so it shows up in the TUI and MCP
    // connection lists. It is marked closed at the end of this function: MCP here is
    // request-scoped HTTP POST with no persistent connection, and leaving every entry Active
    // meant an unauthenticated client could grow AppState without bound by repeating
    // `initialize`.
    //
    // No session record is created. `McpSession` held initialized/capabilities/subscriptions
    // plus tools/resources/prompts maps; the map it lived in was write-only - inserted here
    // and read nowhere in the tree - and every mutator on it (`mark_initialized`,
    // `subscribe`, `register_tool`, …) had zero call sites. It was both an unbounded leak and
    // a protocol-level store of tools/resources/prompts, which the no-storage rule forbids.
    // It is gone rather than left half-built: nothing consumed it, so nothing regresses.
    state
        .app_state
        .add_connection_to_server(
            state.server_id,
            crate::state::ConnectionState {
                id: connection_id,
                remote_addr: state.local_addr, // HTTP POST carries no peer addr here
                local_addr: state.local_addr,
                bytes_sent: 0,
                bytes_received: 0,
                packets_sent: 0,
                packets_received: 0,
                last_activity: crate::utils::clock::Instant::now(),
                status: ConnectionStatus::Active,
                status_changed_at: crate::utils::clock::Instant::now(),
                protocol_info: ProtocolConnectionInfo::empty(),
            },
        )
        .await;

    let requested_version = params
        .as_ref()
        .and_then(|p| p.get("protocolVersion"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    // Create event for LLM
    let event = Event::new(
        &MCP_INITIALIZE_EVENT,
        serde_json::json!({
            "method": "initialize",
            "client_info": client_info,
            "protocol_version": requested_version,
            "capabilities": params.as_ref().and_then(|p| p.get("capabilities")),
        }),
    );

    // Reuse the server's protocol instance rather than allocating a throwaway per request.
    let protocol = state.protocol.clone();

    Log::new(Some(&state.status_tx)).debug("MCP calling LLM for initialize request");

    // Call LLM with action system
    let execution_result = match call_llm(
        &state.llm_client,
        &state.app_state,
        state.server_id,
        Some(connection_id),
        &event,
        protocol.as_ref(),
    )
    .await
    {
        Ok(result) => result,
        Err(e) => {
            return Err(llm_failure_error(state, "initialize", e));
        }
    };

    // Display messages from LLM
    let log = Log::new(Some(&state.status_tx));
    for message in &execution_result.messages {
        log.info(format!("{}", message));
    }

    log.debug(format!(
        "MCP got {} protocol results",
        execution_result.protocol_results.len()
    ));

    // Process action results
    for protocol_result in &execution_result.protocol_results {
        use crate::llm::actions::protocol_trait::ActionResult;
        if let ActionResult::Custom { name, data } = protocol_result {
            // A handler that returned mcp_error_response used to be ignored entirely: the
            // loop matched one name and fell through to the hardcoded default, so a chosen
            // JSON-RPC error was silently converted into a *success* reply. Honor it first.
            if name == "mcp_error" {
                log_model_reject(state, "initialize");
                return Err(mcp_error_from_action(data));
            }
            if name == "mcp_initialize" {
                if let Some(response) = data.get("response") {
                    return Ok(response.clone());
                }
            }
        }
    }

    // Default response if the handler does not provide one.
    //
    // The version is negotiated rather than hardcoded: MCP says the server echoes the client's
    // requested version if it can speak it, and otherwise offers its own. This used to answer
    // "2024-11-05" unconditionally, which tells a client on a newer revision that its request
    // was honored when it was not.
    log_model_no_answer(state, "initialize", "the negotiated protocol version");
    let agreed_version = if SUPPORTED_PROTOCOL_VERSIONS.contains(&requested_version.as_str()) {
        requested_version.as_str()
    } else {
        DEFAULT_PROTOCOL_VERSION
    };

    Ok(serde_json::json!({
        "protocolVersion": agreed_version,
        "capabilities": {
            "resources": {},
            "tools": {},
            "prompts": {}
        },
        "serverInfo": {
            "name": "netget-mcp",
            "version": "0.1.0"
        }
    }))
}

/// Handle ping request - simple health check
#[cfg(not(target_arch = "wasm32"))]
fn handle_ping() -> Result<Value, JsonRpcError> {
    Ok(serde_json::json!({}))
}

/// Handle resources/list request - LLM returns available resources
#[cfg(not(target_arch = "wasm32"))]
async fn handle_resources_list(state: &McpServerState) -> Result<Value, JsonRpcError> {
    Log::new(Some(&state.status_tx)).debug("MCP resources/list request");

    // Create event for LLM
    let event = Event::new(
        &MCP_RESOURCES_LIST_EVENT,
        serde_json::json!({
            "method": "resources/list",
        }),
    );

    // Reuse the server's protocol instance rather than allocating a throwaway per request.
    let protocol = state.protocol.clone();

    // Call LLM with action system
    let execution_result = match call_llm(
        &state.llm_client,
        &state.app_state,
        state.server_id,
        None,
        &event,
        protocol.as_ref(),
    )
    .await
    {
        Ok(result) => result,
        Err(e) => {
            return Err(llm_failure_error(state, "resources/list", e));
        }
    };

    // Process action results
    for protocol_result in &execution_result.protocol_results {
        use crate::llm::actions::protocol_trait::ActionResult;
        if let ActionResult::Custom { name, data } = protocol_result {
            // A handler that returned mcp_error_response used to be ignored entirely: the
            // loop matched one name and fell through to the hardcoded default, so a chosen
            // JSON-RPC error was silently converted into a *success* reply. Honor it first.
            if name == "mcp_error" {
                log_model_reject(state, "resources/list");
                return Err(mcp_error_from_action(data));
            }
            if name == "mcp_resources_list" {
                if let Some(response) = data.get("response") {
                    return Ok(response.clone());
                }
            }
        }
    }

    // Default: empty resources list
    log_model_no_answer(state, "resources/list", "an empty resources list");
    Ok(serde_json::json!({"resources": []}))
}

/// Handle resources/read request - LLM returns resource content
#[cfg(not(target_arch = "wasm32"))]
async fn handle_resources_read(
    state: &McpServerState,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let uri = params
        .as_ref()
        .and_then(|p| p.get("uri"))
        .and_then(|u| u.as_str())
        .ok_or_else(|| JsonRpcError::new(ErrorCode::InvalidParams))?;

    Log::new(Some(&state.status_tx)).debug(format!("MCP resources/read: {}", uri));

    // Create event for LLM
    let event = Event::new(
        &MCP_RESOURCES_READ_EVENT,
        serde_json::json!({
            "method": "resources/read",
            "uri": uri,
        }),
    );

    // Reuse the server's protocol instance rather than allocating a throwaway per request.
    let protocol = state.protocol.clone();

    // Call LLM with action system
    let execution_result = match call_llm(
        &state.llm_client,
        &state.app_state,
        state.server_id,
        None,
        &event,
        protocol.as_ref(),
    )
    .await
    {
        Ok(result) => result,
        Err(e) => {
            return Err(llm_failure_error(state, "resources/read", e));
        }
    };

    // Process action results
    for protocol_result in &execution_result.protocol_results {
        use crate::llm::actions::protocol_trait::ActionResult;
        if let ActionResult::Custom { name, data } = protocol_result {
            // A handler that returned mcp_error_response used to be ignored entirely: the
            // loop matched one name and fell through to the hardcoded default, so a chosen
            // JSON-RPC error was silently converted into a *success* reply. Honor it first.
            if name == "mcp_error" {
                log_model_reject(state, "resources/read");
                return Err(mcp_error_from_action(data));
            }
            if name == "mcp_resources_read" {
                if let Some(response) = data.get("response") {
                    return Ok(response.clone());
                }
            }
        }
    }

    // Default: resource not found
    log_model_no_answer(state, "resources/read", "a JSON-RPC error");
    Err(JsonRpcError::custom(
        ErrorCode::InternalError,
        format!("Resource not found: {}", uri),
    ))
}

/// Handle resources/subscribe request
#[cfg(not(target_arch = "wasm32"))]
async fn handle_resources_subscribe(
    _state: &McpServerState,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let uri = params
        .as_ref()
        .and_then(|p| p.get("uri"))
        .and_then(|u| u.as_str())
        .ok_or_else(|| JsonRpcError::new(ErrorCode::InvalidParams))?;

    debug!("MCP resources/subscribe: uri={}", uri);

    // TODO: Add LLM integration for subscription management
    Ok(serde_json::json!({}))
}

/// Handle resources/unsubscribe request
#[cfg(not(target_arch = "wasm32"))]
async fn handle_resources_unsubscribe(
    _state: &McpServerState,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let uri = params
        .as_ref()
        .and_then(|p| p.get("uri"))
        .and_then(|u| u.as_str())
        .ok_or_else(|| JsonRpcError::new(ErrorCode::InvalidParams))?;

    debug!("MCP resources/unsubscribe: uri={}", uri);
    Ok(serde_json::json!({}))
}

/// Handle resources/templates/list request
#[cfg(not(target_arch = "wasm32"))]
async fn handle_resources_templates_list(_state: &McpServerState) -> Result<Value, JsonRpcError> {
    debug!("MCP resources/templates/list");

    // TODO: Add LLM integration
    Ok(serde_json::json!({
        "resourceTemplates": []
    }))
}

/// Handle tools/list request - LLM returns available tools
#[cfg(not(target_arch = "wasm32"))]
async fn handle_tools_list(state: &McpServerState) -> Result<Value, JsonRpcError> {
    Log::new(Some(&state.status_tx)).debug("MCP tools/list request");

    // Create event for LLM
    let event = Event::new(
        &MCP_TOOLS_LIST_EVENT,
        serde_json::json!({
            "method": "tools/list",
        }),
    );

    // Reuse the server's protocol instance rather than allocating a throwaway per request.
    let protocol = state.protocol.clone();

    // Call LLM with action system
    let execution_result = match call_llm(
        &state.llm_client,
        &state.app_state,
        state.server_id,
        None,
        &event,
        protocol.as_ref(),
    )
    .await
    {
        Ok(result) => result,
        Err(e) => {
            return Err(llm_failure_error(state, "tools/list", e));
        }
    };

    // Process action results
    for protocol_result in &execution_result.protocol_results {
        use crate::llm::actions::protocol_trait::ActionResult;
        if let ActionResult::Custom { name, data } = protocol_result {
            // A handler that returned mcp_error_response used to be ignored entirely: the
            // loop matched one name and fell through to the hardcoded default, so a chosen
            // JSON-RPC error was silently converted into a *success* reply. Honor it first.
            if name == "mcp_error" {
                log_model_reject(state, "tools/list");
                return Err(mcp_error_from_action(data));
            }
            if name == "mcp_tools_list" {
                if let Some(response) = data.get("response") {
                    return Ok(response.clone());
                }
            }
        }
    }

    // Default: empty tools list
    log_model_no_answer(state, "tools/list", "an empty tools list");
    Ok(serde_json::json!({"tools": []}))
}

/// Handle tools/call request - LLM executes tool
#[cfg(not(target_arch = "wasm32"))]
async fn handle_tools_call(
    state: &McpServerState,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let tool_name = params
        .as_ref()
        .and_then(|p| p.get("name"))
        .and_then(|n| n.as_str())
        .ok_or_else(|| JsonRpcError::new(ErrorCode::InvalidParams))?;

    let tool_arguments = params.as_ref().and_then(|p| p.get("arguments"));

    Log::new(Some(&state.status_tx)).debug(format!("MCP tools/call: {}", tool_name));

    // Create event for LLM
    let event = Event::new(
        &MCP_TOOLS_CALL_EVENT,
        serde_json::json!({
            "method": "tools/call",
            "name": tool_name,
            "arguments": tool_arguments,
        }),
    );

    // Reuse the server's protocol instance rather than allocating a throwaway per request.
    let protocol = state.protocol.clone();

    // Call LLM with action system
    let execution_result = match call_llm(
        &state.llm_client,
        &state.app_state,
        state.server_id,
        None,
        &event,
        protocol.as_ref(),
    )
    .await
    {
        Ok(result) => result,
        Err(e) => {
            return Err(llm_failure_error(state, "tools/call", e));
        }
    };

    // Process action results
    for protocol_result in &execution_result.protocol_results {
        use crate::llm::actions::protocol_trait::ActionResult;
        if let ActionResult::Custom { name, data } = protocol_result {
            // A handler that returned mcp_error_response used to be ignored entirely: the
            // loop matched one name and fell through to the hardcoded default, so a chosen
            // JSON-RPC error was silently converted into a *success* reply. Honor it first.
            if name == "mcp_error" {
                log_model_reject(state, "tools/call");
                return Err(mcp_error_from_action(data));
            }
            if name == "mcp_tools_call" {
                if let Some(response) = data.get("response") {
                    return Ok(response.clone());
                }
            }
        }
    }

    // Default: tool execution failed
    log_model_no_answer(state, "tools/call", "a JSON-RPC error");
    Err(JsonRpcError::custom(
        ErrorCode::InternalError,
        format!("Tool execution failed: {}", tool_name),
    ))
}

/// Handle prompts/list request - LLM returns available prompts
#[cfg(not(target_arch = "wasm32"))]
async fn handle_prompts_list(state: &McpServerState) -> Result<Value, JsonRpcError> {
    Log::new(Some(&state.status_tx)).debug("MCP prompts/list request");

    // Create event for LLM
    let event = Event::new(
        &MCP_PROMPTS_LIST_EVENT,
        serde_json::json!({
            "method": "prompts/list",
        }),
    );

    // Reuse the server's protocol instance rather than allocating a throwaway per request.
    let protocol = state.protocol.clone();

    // Call LLM with action system
    let execution_result = match call_llm(
        &state.llm_client,
        &state.app_state,
        state.server_id,
        None,
        &event,
        protocol.as_ref(),
    )
    .await
    {
        Ok(result) => result,
        Err(e) => {
            return Err(llm_failure_error(state, "prompts/list", e));
        }
    };

    // Process action results
    for protocol_result in &execution_result.protocol_results {
        use crate::llm::actions::protocol_trait::ActionResult;
        if let ActionResult::Custom { name, data } = protocol_result {
            // A handler that returned mcp_error_response used to be ignored entirely: the
            // loop matched one name and fell through to the hardcoded default, so a chosen
            // JSON-RPC error was silently converted into a *success* reply. Honor it first.
            if name == "mcp_error" {
                log_model_reject(state, "prompts/list");
                return Err(mcp_error_from_action(data));
            }
            if name == "mcp_prompts_list" {
                if let Some(response) = data.get("response") {
                    return Ok(response.clone());
                }
            }
        }
    }

    // Default: empty prompts list
    log_model_no_answer(state, "prompts/list", "an empty prompts list");
    Ok(serde_json::json!({"prompts": []}))
}

/// Handle prompts/get request - LLM returns prompt template
#[cfg(not(target_arch = "wasm32"))]
async fn handle_prompts_get(
    state: &McpServerState,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let prompt_name = params
        .as_ref()
        .and_then(|p| p.get("name"))
        .and_then(|n| n.as_str())
        .ok_or_else(|| JsonRpcError::new(ErrorCode::InvalidParams))?;

    let prompt_arguments = params.as_ref().and_then(|p| p.get("arguments"));

    Log::new(Some(&state.status_tx)).debug(format!("MCP prompts/get: {}", prompt_name));

    // Create event for LLM
    let event = Event::new(
        &MCP_PROMPTS_GET_EVENT,
        serde_json::json!({
            "method": "prompts/get",
            "name": prompt_name,
            "arguments": prompt_arguments,
        }),
    );

    // Reuse the server's protocol instance rather than allocating a throwaway per request.
    let protocol = state.protocol.clone();

    // Call LLM with action system
    let execution_result = match call_llm(
        &state.llm_client,
        &state.app_state,
        state.server_id,
        None,
        &event,
        protocol.as_ref(),
    )
    .await
    {
        Ok(result) => result,
        Err(e) => {
            return Err(llm_failure_error(state, "prompts/get", e));
        }
    };

    // Process action results
    for protocol_result in &execution_result.protocol_results {
        use crate::llm::actions::protocol_trait::ActionResult;
        if let ActionResult::Custom { name, data } = protocol_result {
            // A handler that returned mcp_error_response used to be ignored entirely: the
            // loop matched one name and fell through to the hardcoded default, so a chosen
            // JSON-RPC error was silently converted into a *success* reply. Honor it first.
            if name == "mcp_error" {
                log_model_reject(state, "prompts/get");
                return Err(mcp_error_from_action(data));
            }
            if name == "mcp_prompts_get" {
                if let Some(response) = data.get("response") {
                    return Ok(response.clone());
                }
            }
        }
    }

    // Default: prompt not found
    log_model_no_answer(state, "prompts/get", "a JSON-RPC error");
    Err(JsonRpcError::custom(
        ErrorCode::InternalError,
        format!("Prompt not found: {}", prompt_name),
    ))
}

/// Handle logging/setLevel request
#[cfg(not(target_arch = "wasm32"))]
async fn handle_logging_set_level(
    state: &McpServerState,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let level = params
        .as_ref()
        .and_then(|p| p.get("level"))
        .and_then(|l| l.as_str())
        .unwrap_or("info");

    // Was `debug!` on the file log but `[INFO]` on the TUI - level drift the Log facade
    // exists to prevent. Unified to INFO on both sinks: it was already user-visible.
    Log::new(Some(&state.status_tx)).info(format!("MCP log level set to: {}", level));

    Ok(serde_json::json!({}))
}

/// Handle completion/complete request - LLM provides completions
#[cfg(not(target_arch = "wasm32"))]
async fn handle_completion(
    _state: &McpServerState,
    _params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    debug!("MCP completion/complete");

    // Not wired to the handler. The mcp_completion event type and the
    // mcp_completion_response action are no longer advertised, so nobody is told to write a
    // handler for something that never fires.
    Ok(serde_json::json!({
        "completion": {
            "values": [],
            "total": 0,
            "hasMore": false
        }
    }))
}

/// Handle initialized notification
#[cfg(not(target_arch = "wasm32"))]
async fn handle_initialized(state: &McpServerState) {
    Log::new(Some(&state.status_tx)).info("MCP client initialized");
}

/// Handle cancelled notification
#[cfg(not(target_arch = "wasm32"))]
async fn handle_cancelled(state: &McpServerState, params: Option<Value>) {
    if let Some(req_id) = params.as_ref().and_then(|p| p.get("requestId")) {
        Log::new(Some(&state.status_tx)).debug(format!("MCP cancelled: {:?}", req_id));
    }
}

/// Handle progress notification
#[cfg(not(target_arch = "wasm32"))]
async fn handle_progress(_state: &McpServerState, params: Option<Value>) {
    if let Some(progress) = params {
        trace!("MCP progress: {}", progress);
    }
}

/// Accept on NetGet's own listener, apply the cap and the read deadlines, and relay each
/// admitted connection to the loopback axum backend.
///
/// Runs until the task is aborted, which `stop_server` does through
/// `AppState::register_server_task`.
#[cfg(not(target_arch = "wasm32"))]
async fn serve_screened_mcp(
    listener: tokio::net::TcpListener,
    backend_addr: SocketAddr,
    status_tx: mpsc::UnboundedSender<String>,
    app_state: std::sync::Arc<crate::state::app_state::AppState>,
    server_id: crate::state::ServerId,
) {
    let limiter = crate::server::accept_bounded::ConnectionLimiter::new(MAX_CONNECTIONS);
    loop {
        let (peer_stream, peer_addr, permit) = match crate::server::accept_bounded::accept_bounded(
            &listener,
            &limiter,
            CONNECTION_CAP_REFUSAL,
            "MCP",
            Some(&status_tx),
        )
        .await
        {
            Ok(triple) => triple,
            Err(e) => {
                console_error!(status_tx, "MCP accept failed, listener stopped: {}", e);
                return;
            }
        };

        let status = status_tx.clone();
        // Tracked, not detached: stop_server must abort this task too.
        let task_owner = app_state.clone();
        task_owner
            .spawn_server_task(server_id, async move {
                let _permit = permit;
                relay_mcp_connection(peer_stream, peer_addr, backend_addr, status).await;
            })
            .await;
    }
}

/// Relay one admitted connection, bounding only the peer's *silence*.
///
/// The rule that makes this safe is the one the project learned from TFTP: a connection waiting
/// on a slow answer is not idle. MCP is strictly request/response, so "waiting on us" is exactly
/// "bytes have gone peer → backend and none have come back yet", and `awaiting_response` tracks
/// that. While it is set, the read deadline re-arms instead of closing — so an LLM round-trip,
/// or a request parked for a human at the dashboard for as long as they need, can never be
/// timed out from under itself. Only a peer that has been answered and then says nothing, or
/// that never said anything at all, is closed.
#[cfg(not(target_arch = "wasm32"))]
async fn relay_mcp_connection(
    peer_stream: tokio::net::TcpStream,
    peer_addr: SocketAddr,
    backend_addr: SocketAddr,
    status_tx: mpsc::UnboundedSender<String>,
) {
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let backend_stream = match tokio::net::TcpStream::connect(backend_addr).await {
        Ok(stream) => stream,
        Err(e) => {
            console_error!(status_tx, "MCP could not reach its own backend: {}", e);
            return;
        }
    };

    let (mut peer_read, mut peer_write) = tokio::io::split(peer_stream);
    let (mut backend_read, mut backend_write) = tokio::io::split(backend_stream);

    let awaiting_response = Arc::new(AtomicBool::new(false));

    let to_backend_awaiting = Arc::clone(&awaiting_response);
    let to_backend_status = status_tx.clone();
    let to_backend = tokio::spawn(async move {
        let mut buf = vec![0u8; 16 * 1024];
        let mut seen_request = false;
        loop {
            let bound = if seen_request {
                IDLE_BETWEEN_REQUESTS_TIMEOUT
            } else {
                FIRST_REQUEST_READ_TIMEOUT
            };
            let read = loop {
                match tokio::time::timeout(bound, peer_read.read(&mut buf)).await {
                    Ok(read) => break Some(read),
                    Err(_) => {
                        if to_backend_awaiting.load(Ordering::SeqCst) {
                            // The peer is waiting for an answer we have not produced yet.
                            // That is not silence; re-arm.
                            continue;
                        }
                        Log::new(Some(&to_backend_status)).info(format!(
                            "MCP peer {} sent nothing for {}s; closing idle connection",
                            peer_addr,
                            bound.as_secs()
                        ));
                        break None;
                    }
                }
            };
            let n = match read {
                Some(Ok(0)) | None => break,
                Some(Ok(n)) => n,
                Some(Err(_)) => break,
            };
            seen_request = true;
            to_backend_awaiting.store(true, Ordering::SeqCst);
            if backend_write.write_all(&buf[..n]).await.is_err() {
                break;
            }
        }
        let _ = backend_write.shutdown().await;
    });

    let to_peer_awaiting = Arc::clone(&awaiting_response);
    let to_peer = tokio::spawn(async move {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            match backend_read.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if peer_write.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                    // Answered: from here the peer owes us the next request, so the idle
                    // deadline becomes meaningful again.
                    to_peer_awaiting.store(false, Ordering::SeqCst);
                }
            }
        }
        let _ = peer_write.shutdown().await;
    });

    // Either direction ending ends the connection: a half-open relay would be one more way to
    // hold a socket for nothing.
    tokio::select! {
        _ = to_backend => {}
        _ = to_peer => {}
    }
}

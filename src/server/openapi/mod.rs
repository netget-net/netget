//! OpenAPI 3.1 spec-driven HTTP server implementation
//!
//! The LLM provides an OpenAPI specification and generates responses based on validated requests.
//! Supports both spec-compliant and intentionally non-compliant responses for testing/honeypot purposes.

pub mod actions;

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use serde_json::json;
use std::collections::HashMap;
use tokio::sync::mpsc;
use tokio::sync::RwLock;
use tracing::{debug, error};

use crate::llm::action_helper::call_llm;
use crate::llm::actions::protocol_trait::ActionResult;
use crate::llm::ollama_client::OllamaClient;
use crate::logging::emit::Log;
use crate::protocol::Event;
use crate::server::connection::ConnectionId;
use crate::server::openapi::actions::OpenApiProtocol;
use crate::state::app_state::AppState;

use matchit::Router;
use openapi_rs::model::parse::OpenAPI;

/// Metadata for a matched route
#[derive(Clone, Debug)]
pub struct RouteMetadata {
    pub operation_id: Option<String>,
    pub method: String,
    pub path_template: String,
    pub operation_json: serde_json::Value, // Pre-serialized operation for LLM
}

/// Result of route matching
#[derive(Debug)]
pub enum MatchResult {
    /// Route found and matched
    Found {
        metadata: RouteMetadata,
        params: HashMap<String, String>,
    },
    /// Path exists but method not allowed
    MethodNotAllowed { allowed_methods: Vec<String> },
    /// Path not found in spec
    NotFound,
}

/// OpenAPI server state
pub struct OpenApiState {
    /// Raw OpenAPI specification (YAML or JSON)
    pub spec: Option<String>,
    /// Whether the spec has been successfully parsed
    pub spec_valid: bool,
    /// Parsed OpenAPI specification
    pub parsed_spec: Option<OpenAPI>,
    /// Route matcher for fast path matching
    pub router: Option<Router<RouteMetadata>>,
    /// Whether to ask LLM for invalid requests (404/405/400)
    pub llm_on_invalid: bool,
}

impl OpenApiState {
    pub fn new() -> Self {
        Self {
            spec: None,
            spec_valid: false,
            parsed_spec: None,
            router: None,
            llm_on_invalid: false, // Default: bypass LLM for errors
        }
    }
}

/// Build matchit router from OpenAPI specification
fn build_router(spec: &OpenAPI) -> anyhow::Result<Router<RouteMetadata>> {
    let mut router = Router::new();

    for (path_template, path_item) in &spec.paths {
        // Iterate over operations HashMap (keys: "get", "post", etc.)
        for (method_lower, operation) in &path_item.operations {
            let method = method_lower.to_uppercase();

            // Serialize operation to JSON for LLM
            let operation_json = serde_json::to_value(operation)?;

            let metadata = RouteMetadata {
                operation_id: operation.operation_id.clone(),
                method: method.clone(),
                path_template: path_template.clone(),
                operation_json,
            };

            // Use composite key: METHOD:PATH (e.g., "GET:/users/{id}")
            let route_key = format!("{}:{}", method, path_template);
            router.insert(&route_key, metadata)?;

            debug!("Registered OpenAPI route: {} {}", method, path_template);
        }
    }

    Ok(router)
}

/// Match incoming request against router
fn match_route(router: &Router<RouteMetadata>, method: &str, path: &str) -> MatchResult {
    // Try exact method:path match
    let route_key = format!("{}:{}", method, path);

    match router.at(&route_key) {
        Ok(matched) => {
            // Extract path parameters
            let params: HashMap<String, String> = matched
                .params
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();

            MatchResult::Found {
                metadata: matched.value.clone(),
                params,
            }
        }
        Err(_) => {
            // Check if path exists with different method (for 405)
            let allowed_methods = find_allowed_methods(router, path);

            if !allowed_methods.is_empty() {
                MatchResult::MethodNotAllowed { allowed_methods }
            } else {
                MatchResult::NotFound
            }
        }
    }
}

/// Find which HTTP methods are allowed for a given path
fn find_allowed_methods(router: &Router<RouteMetadata>, path: &str) -> Vec<String> {
    let methods = [
        "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE",
    ];
    let mut allowed = Vec::new();

    for method in &methods {
        let route_key = format!("{}:{}", method, path);
        if router.at(&route_key).is_ok() {
            allowed.push(method.to_string());
        }
    }

    allowed
}

/// Validate request against OpenAPI operation schema
/// Returns Ok(()) if valid, Err(error_message) if invalid
fn validate_request(
    _operation_json: &serde_json::Value,
    _method: &str,
    _path: &str,
    _headers: &HashMap<String, String>,
    _body: &str,
) -> anyhow::Result<()> {
    // TODO: Implement schema validation
    // For now, just return Ok - validation can be added later
    // This would involve:
    // 1. Validate required parameters are present
    // 2. Validate parameter types match schema
    // 3. Validate request body against schema if present
    // 4. Validate Content-Type header

    Ok(())
}

/// How much of a request body is read before the request is refused with 413.
///
/// The body is buffered whole and then embedded in an LLM prompt, so there is no legitimate
/// use for a large one. Matches `http_common::handler::MAX_REQUEST_BODY_BYTES`.
pub const MAX_REQUEST_BODY_BYTES: usize = 8 * 1024 * 1024;

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
/// nginx's `keepalive_timeout` default, which is the number the deployed web is tuned against
/// and the right one here because an OpenAPI server's clients are whatever the specification
/// describes — a browser, `curl`, a generated SDK — with no pooling discipline of their own to
/// argue for more. Apache's `KeepAliveTimeout` of 5s is the other end of the range and is tuned
/// for a server fronting far more connections than this one admits. A request still being
/// answered is not silence: the watchdog reads
/// [`ConnectionActivity`](crate::server::accept_bounded::ConnectionActivity), which reports a
/// connection with work in flight — a model round-trip, or an event a `manual` rule parked for a
/// human — as not idle at all.
const IDLE_BETWEEN_REQUESTS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(75);

/// Concurrent connections this server admits.
///
/// Below the shared `DEFAULT_MAX_CONNECTIONS` of 256 on purpose: each admitted connection may
/// buffer one body of up to [`MAX_REQUEST_BODY_BYTES`] (8 MiB), which is the largest
/// per-connection cost in netget's HTTP family, and the cap is what turns that per-connection
/// bound into a total one. 128 holds the worst case to the same ~1 GiB ceiling the 4 MiB and
/// 64 KiB servers reach at 256, so the number that varies is the one that has to.
const MAX_CONNECTIONS: usize = 128;

/// What a peer over [`MAX_CONNECTIONS`] is told before the socket closes.
///
/// `503 Service Unavailable` with a `Retry-After`, written directly onto the socket because the
/// peer has not sent a request line for hyper to answer. Fixed bytes: nothing derived from an
/// error reaches the wire (see `crate::utils::wire_failure`).
const CONNECTION_CAP_REFUSAL: &[u8] = b"HTTP/1.1 503 Service Unavailable\r\n\
    Content-Length: 0\r\nRetry-After: 5\r\nConnection: close\r\n\r\n";

/// Create immediate 413 response for a body past [`MAX_REQUEST_BODY_BYTES`].
fn payload_too_large() -> Response<Full<Bytes>> {
    Response::builder()
        .status(413)
        .header("Content-Type", "application/json")
        .body(Full::new(Bytes::from(
            json!({
                "error": "Payload Too Large",
                "message": "The request body exceeds this server's limit"
            })
            .to_string(),
        )))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::new())))
}

/// Create immediate 404 Not Found response
fn immediate_404() -> Response<Full<Bytes>> {
    Response::builder()
        .status(404)
        .header("Content-Type", "application/json")
        .body(Full::new(Bytes::from(
            json!({
                "error": "Not Found",
                "message": "The requested path does not exist in the OpenAPI specification"
            })
            .to_string(),
        )))
        .unwrap()
}

/// Create immediate 405 Method Not Allowed response with Allow header
fn immediate_405(allowed_methods: Vec<String>) -> Response<Full<Bytes>> {
    let allow_header = allowed_methods.join(", ");

    Response::builder()
        .status(405)
        .header("Content-Type", "application/json")
        .header("Allow", allow_header.clone())
        .body(Full::new(Bytes::from(
            json!({
                "error": "Method Not Allowed",
                "message": format!("This path does not support the requested method"),
                "allowed_methods": allowed_methods
            })
            .to_string(),
        )))
        .unwrap()
}

/// Create immediate 400 Bad Request response for validation errors
fn immediate_400(error_message: String) -> Response<Full<Bytes>> {
    Response::builder()
        .status(400)
        .header("Content-Type", "application/json")
        .body(Full::new(Bytes::from(
            json!({
                "error": "Bad Request",
                "message": error_message
            })
            .to_string(),
        )))
        .unwrap()
}

/// Build the peer-visible failure response for a request netget could not answer.
///
/// The peer gets a *category*, never the error: no backend URL, no model name, no `anyhow`
/// chain. `Overloaded` is transient, so it is reported as 503 + `Retry-After` and a client
/// backs off; anything else is a 500 so it is not retried forever. See
/// `crate::utils::wire_failure`.
fn failure_response(failure: crate::utils::WireFailure) -> Response<Full<Bytes>> {
    let (status, reason) = if failure.is_overloaded() {
        (503, "Service Unavailable")
    } else {
        (500, "Internal Server Error")
    };

    let body = json!({
        "error": reason,
        "message": failure.text(),
    })
    .to_string();

    let mut builder = Response::builder()
        .status(status)
        .header("Content-Type", "application/json");
    if failure.is_overloaded() {
        builder = builder.header(hyper::header::RETRY_AFTER, "1");
    }

    builder
        .body(Full::new(Bytes::from(body)))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::new())))
}

/// The LLM call itself failed. Log the whole error, answer the peer with a category only.
fn llm_error_response(
    error: anyhow::Error,
    method: &str,
    path: &str,
    status_tx: &mpsc::UnboundedSender<String>,
) -> Response<Full<Bytes>> {
    let failure = crate::utils::WireFailure::classify(&error);
    let category = if failure.is_overloaded() {
        "overloaded"
    } else {
        "unavailable"
    };

    // `Log` writes the file log and the TUI status stream from one call, so the whole error
    // is recorded exactly once — where an operator looks, and nowhere the peer can read.
    Log::new(Some(status_tx)).error(format!(
        "OpenAPI {} {} decision=fail_closed_llm_error category={}: {}",
        method, path, category, error
    ));

    failure_response(failure)
}

/// Handle LLM response and process actions
async fn handle_llm_response(
    execution_result: crate::llm::actions::executor::ExecutionResult,
    status_tx: mpsc::UnboundedSender<String>,
    openapi_state: Arc<RwLock<OpenApiState>>,
    method: String,
    path: String,
) -> Result<Response<Full<Bytes>>, Infallible> {
    debug!("LLM OpenAPI response received");

    // Display messages
    for msg in execution_result.messages {
        let _ = status_tx.send(msg);
    }

    // Default response. `produced_response` stays false until the model actually answers:
    // a silent model must not read on the wire like a successful 200 (see the fail-open
    // rule in CLAUDE.md).
    let mut status_code = 200;
    let mut response_headers = HashMap::new();
    let mut response_body = String::new();
    let mut spec_to_load: Option<String> = None;
    let mut produced_response = false;
    let mut decision = "fail_closed_no_action";

    // Process protocol results
    for protocol_result in execution_result.protocol_results {
        match protocol_result {
            ActionResult::Custom { name, data } => {
                match name.as_str() {
                    "send_openapi_response" => {
                        produced_response = true;
                        decision = "model_response";
                        // Extract response details
                        if let Some(status) = data.get("status_code").and_then(|v| v.as_u64()) {
                            status_code = status as u16;
                        }
                        if let Some(headers_obj) = data.get("headers").and_then(|v| v.as_object()) {
                            for (k, v) in headers_obj {
                                if let Some(v_str) = v.as_str() {
                                    response_headers.insert(k.clone(), v_str.to_string());
                                }
                            }
                        }
                        if let Some(body) = data.get("body").and_then(|v| v.as_str()) {
                            response_body = body.to_string();
                        }
                    }
                    "send_validation_error" => {
                        produced_response = true;
                        decision = "model_reject";
                        // A validation error the model did not give a status for is a 400,
                        // not the 200 the default would otherwise leave in place.
                        status_code = 400;
                        // Extract error details
                        if let Some(status) = data.get("status_code").and_then(|v| v.as_u64()) {
                            status_code = status as u16;
                        }
                        if let Some(message) = data.get("message").and_then(|v| v.as_str()) {
                            response_body = json!({
                                "error": message
                            })
                            .to_string();
                            response_headers
                                .insert("content-type".to_string(), "application/json".to_string());
                        }
                    }
                    "load_openapi_spec" | "reload_spec" => {
                        // LLM provided OpenAPI spec
                        if let Some(spec) = data.get("spec").and_then(|v| v.as_str()) {
                            spec_to_load = Some(spec.to_string());
                        }
                    }
                    "configure_error_handling" => {
                        // LLM configured error handling
                        if let Some(llm_on_invalid) =
                            data.get("llm_on_invalid").and_then(|v| v.as_bool())
                        {
                            let mut state = openapi_state.write().await;
                            state.llm_on_invalid = llm_on_invalid;
                            Log::new(Some(&status_tx))
                                .info(format!("OpenAPI llm_on_invalid set to: {}", llm_on_invalid));
                        }
                    }
                    _ => {
                        debug!("Unknown custom action: {}", name);
                    }
                }
            }
            ActionResult::Output(output_data) => {
                // Legacy fallback for non-action responses
                if let Ok(json_value) = serde_json::from_slice::<serde_json::Value>(&output_data) {
                    produced_response = true;
                    decision = "model_output_legacy";
                    // `as u16` wraps, and this path does not go through the executors that
                    // bound `status_code` to 100-599 — so it was the one remaining route by
                    // which `65736` could reach `build_safe_response` as a perfectly valid
                    // 200. Anything unusable stays at the 500 set below rather than becoming
                    // the success the old default supplied.
                    status_code = 500;
                    match json_value.get("status").and_then(|v| v.as_u64()) {
                        Some(status) => match u16::try_from(status)
                            .ok()
                            .filter(|code| (100..=599).contains(code))
                        {
                            Some(code) => status_code = code,
                            None => error!(
                                "OpenAPI legacy output carried status {} which is not an HTTP \
                                 status; answering 500",
                                status
                            ),
                        },
                        None => status_code = 200,
                    }
                    if let Some(headers_obj) = json_value.get("headers").and_then(|v| v.as_object())
                    {
                        for (k, v) in headers_obj {
                            if let Some(v_str) = v.as_str() {
                                response_headers.insert(k.clone(), v_str.to_string());
                            }
                        }
                    }
                    if let Some(body) = json_value.get("body").and_then(|v| v.as_str()) {
                        response_body = body.to_string();
                    }
                }
            }
            _ => {}
        }
    }

    // Load spec if provided
    if let Some(spec) = spec_to_load {
        let mut state = openapi_state.write().await;
        // Try to parse spec
        match openapi_rs::model::parse::OpenAPI::yaml(&spec) {
            Ok(parsed_spec) => {
                Log::new(Some(&status_tx)).info(format!(
                    "OpenAPI spec loaded successfully: {} bytes",
                    spec.len()
                ));

                // Build router from parsed spec
                match build_router(&parsed_spec) {
                    Ok(router) => {
                        let route_count = parsed_spec.paths.len();
                        Log::new(Some(&status_tx))
                            .info(format!("Built OpenAPI router with {} routes", route_count));

                        state.spec = Some(spec);
                        state.spec_valid = true;
                        state.parsed_spec = Some(parsed_spec);
                        state.router = Some(router);
                    }
                    Err(e) => {
                        Log::new(Some(&status_tx))
                            .error(format!("Failed to build OpenAPI router: {}", e));
                        state.spec = Some(spec);
                        state.spec_valid = false;
                    }
                }
            }
            Err(e) => {
                Log::new(Some(&status_tx)).error(format!("Failed to parse OpenAPI spec: {}", e));
                state.spec = Some(spec);
                state.spec_valid = false;
            }
        }
    }

    // The model was consulted and produced no response action. That is not a success: a
    // silent model used to be answered with 200 and a body naming netget's own internals,
    // so a caller could not tell an answered request from an unanswered one. Fail closed
    // with a category, and keep the reason in the log rather than on the wire. A spec
    // reload or an error-handling change on its own is configuration, not an answer.
    if !produced_response {
        Log::new(Some(&status_tx)).warn(format!(
            "OpenAPI {} {} decision=fail_closed_no_action -> 500 (no response action returned)",
            method, path
        ));
        return Ok(failure_response(crate::utils::WireFailure::Unavailable));
    }

    Log::new(Some(&status_tx)).info(format!(
        "OpenAPI {} {} -> {} ({} bytes, decision={})",
        method,
        path,
        status_code,
        response_body.len(),
        decision
    ));

    // `status_code` and every header name/value here are model output, so this must not be
    // `.body(..).unwrap()`: a `status_code` of 1000, or a header value containing CR/LF (a
    // response-splitting attempt), made the builder return Err and panicked the connection
    // task. `build_safe_response` clamps the status and drops individual bad headers.
    Ok(crate::server::http_common::handler::build_safe_response(
        status_code,
        response_headers,
        response_body,
        "OpenAPI",
    ))
}

/// OpenAPI server that uses LLM to handle spec-driven requests
pub struct OpenApiServer;

impl OpenApiServer {
    /// Spawn OpenAPI server with LLM actions
    ///
    /// ## Startup Parameters
    ///
    /// The LLM can provide OpenAPI specification during server initialization via `startup_params`:
    ///
    /// **Option 1: Inline spec (string)**
    /// ```json
    /// {
    ///   "spec": "openapi: 3.1.0\ninfo:\n  title: My API\n..."
    /// }
    /// ```
    ///
    /// There is no `spec_file` option. It was declared in `get_startup_parameters()` and
    /// documented here, but no code ever read it — a caller passing only `spec_file` hit the
    /// "requires 'spec' parameter" error below. Read the file yourself and pass its contents
    /// as `spec`.
    ///
    /// When a spec is provided via startup_params:
    /// - The spec is immediately parsed and validated
    /// - Route matching is configured automatically
    /// - Invalid requests (404/405) are rejected without asking LLM (unless `llm_on_invalid` is enabled)
    /// - Matched requests receive only the relevant operation spec, not the full spec
    ///
    /// If no spec is provided, the server starts in "dynamic mode" where the LLM can load the spec
    /// later using the `reload_spec` action.
    pub async fn spawn_with_llm_actions(
        listen_addr: SocketAddr,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        server_id: crate::state::ServerId,
        startup_params: Option<crate::protocol::StartupParams>,
    ) -> anyhow::Result<SocketAddr> {
        // Create shared OpenAPI state
        let openapi_state = Arc::new(RwLock::new(OpenApiState::new()));
        let protocol = Arc::new(OpenApiProtocol::new());

        // Check if spec is provided via startup_params (REQUIRED)
        let spec_loaded = if let Some(ref params) = startup_params {
            // Extract required spec parameter
            let spec_content = if let Some(spec_str) = params.get_optional_string("spec")? {
                // Spec provided (LLM must read file and provide content)
                Log::new(Some(&status_tx)).info(format!(
                    "OpenAPI spec provided via startup_params ({} bytes)",
                    spec_str.len()
                ));
                Some(spec_str)
            } else {
                // spec parameter is required
                let msg = "OpenAPI server requires 'spec' parameter in startup_params. LLM must read the spec file and provide content.";
                Log::new(Some(&status_tx)).error(msg);
                return Err(anyhow::anyhow!(msg));
            };

            // If we have spec content, parse and build router
            if let Some(spec) = spec_content {
                let mut state = openapi_state.write().await;
                state.spec = Some(spec.clone());

                match openapi_rs::model::parse::OpenAPI::yaml(&spec) {
                    Ok(parsed) => match build_router(&parsed) {
                        Ok(router) => {
                            let route_count = parsed.paths.len();
                            Log::new(Some(&status_tx)).info(format!(
                                "Successfully built OpenAPI router with {} routes",
                                route_count
                            ));
                            state.parsed_spec = Some(parsed);
                            state.router = Some(router);
                            state.spec_valid = true;
                            true
                        }
                        Err(e) => {
                            let msg = format!("Failed to build router: {}", e);
                            Log::new(Some(&status_tx)).error(&msg);
                            state.spec_valid = false;
                            return Err(anyhow::anyhow!(msg));
                        }
                    },
                    Err(e) => {
                        let msg = format!("Failed to parse OpenAPI spec: {}", e);
                        Log::new(Some(&status_tx)).error(&msg);
                        state.spec_valid = false;
                        return Err(anyhow::anyhow!(msg));
                    }
                }
            } else {
                false
            }
        } else {
            false
        };

        if !spec_loaded {
            Log::new(Some(&status_tx))
                .info("Starting OpenAPI server (spec will be provided by LLM on first request)...");
        } else {
            Log::new(Some(&status_tx)).info("Starting OpenAPI server with pre-loaded spec...");
        }

        // Start HTTP server
        let listener =
            crate::server::socket_helpers::create_reusable_tcp_listener(listen_addr).await?;
        let local_addr = listener.local_addr()?;
        Log::new(Some(&status_tx)).info(format!("OpenAPI server listening on {}", local_addr));

        // Spawn server loop
        let task_registrar = app_state.clone();
        let limiter = crate::server::accept_bounded::ConnectionLimiter::new(MAX_CONNECTIONS);
        let accept_handle = tokio::spawn(async move {
            loop {
                match crate::server::accept_bounded::accept_bounded(
                    &listener,
                    &limiter,
                    CONNECTION_CAP_REFUSAL,
                    "OpenAPI",
                    Some(&status_tx),
                )
                .await
                {
                    Ok((stream, remote_addr, permit)) => {
                        let connection_id =
                            ConnectionId::new(app_state.get_next_unified_id().await);
                        let local_addr_conn = stream.local_addr().unwrap_or(local_addr);
                        Log::new(Some(&status_tx)).info(format!(
                            "OpenAPI connection {} from {}",
                            connection_id, remote_addr
                        ));

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
                        let openapi_state_clone = openapi_state.clone();

                        // Spawn a task to handle this connection
                        // Tracked, not detached: stop_server must abort this task too.
                        let task_owner = app_state.clone();
                        task_owner
                            .spawn_server_task(server_id, async move {
                                // Held for the life of the connection, so the cap counts live
                                // clients rather than accepts.
                                let _permit = permit;

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

                                let io = TokioIo::new(stream);

                                // Clone for service closure
                                let status_for_service = status_tx_clone.clone();
                                let app_state_for_service = app_state_clone.clone();
                                let openapi_state_for_service = openapi_state_clone.clone();

                                // Tracks whether this connection is answering anything. A
                                // request waiting on the model, or parked for a human by a
                                // `manual` rule, holds the count above zero, so the idle watchdog
                                // below cannot close the connection the answer belongs to however
                                // long it takes - only genuine silence counts.
                                let activity = std::sync::Arc::new(
                                    crate::server::accept_bounded::ConnectionActivity::new(),
                                );
                                let activity_for_service = std::sync::Arc::clone(&activity);

                                // Create a service that handles OpenAPI requests with LLM
                                let service = service_fn(move |req: Request<Incoming>| {
                                    let llm_clone = llm_client_clone.clone();
                                    let state_clone = app_state_for_service.clone();
                                    let status_clone = status_for_service.clone();
                                    let protocol_clone = protocol_clone.clone();
                                    let openapi_state_clone = openapi_state_for_service.clone();
                                    let activity = std::sync::Arc::clone(&activity_for_service);
                                    async move {
                                        let _busy = activity.busy();
                                        handle_openapi_request(
                                            req,
                                            connection_id,
                                            llm_clone,
                                            state_clone,
                                            status_clone,
                                            protocol_clone,
                                            openapi_state_clone,
                                            server_id,
                                        )
                                        .await
                                    }
                                });

                                // Serve HTTP/1 on this connection, bounded at both ends.
                                if !spoke {
                                    Log::new(Some(&status_tx_clone)).debug(format!(
                                        "OpenAPI peer {} sent nothing for {}s; closing before \
                                         any request",
                                        remote_addr,
                                        FIRST_BYTE_READ_TIMEOUT.as_secs()
                                    ));
                                } else {
                                    let conn = http1::Builder::new().serve_connection(io, service);
                                    tokio::pin!(conn);
                                    tokio::select! {
                                        result = &mut conn => {
                                            if let Err(err) = result {
                                                error!(
                                                    "Error serving OpenAPI connection: \
                                                     {:?}",
                                                    err
                                                );
                                            }
                                        }
                                        _ = crate::server::accept_bounded::watch_idle(
                                            std::sync::Arc::clone(&activity),
                                            IDLE_BETWEEN_REQUESTS_TIMEOUT,
                                        ) => {
                                            Log::new(Some(&status_tx_clone)).debug(format!(
                                                "OpenAPI connection {} idle for {}s; closing",
                                                connection_id,
                                                IDLE_BETWEEN_REQUESTS_TIMEOUT.as_secs()
                                            ));
                                        }
                                    }
                                }

                                // Mark connection as closed
                                app_state_clone
                                    .close_connection_on_server(server_id, connection_id)
                                    .await;
                                Log::new(Some(&status_tx_clone))
                                    .info(format!("OpenAPI connection {} closed", connection_id));
                                let _ = status_tx_clone.send("__UPDATE_UI__".to_string());
                            })
                            .await;
                    }
                    Err(e) => {
                        Log::new(Some(&status_tx))
                            .error(format!("Failed to accept OpenAPI connection: {}", e));
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

/// Handle a single OpenAPI request
async fn handle_openapi_request(
    req: Request<Incoming>,
    connection_id: ConnectionId,
    llm_client: OllamaClient,
    app_state: Arc<AppState>,
    status_tx: mpsc::UnboundedSender<String>,
    protocol: Arc<OpenApiProtocol>,
    openapi_state: Arc<RwLock<OpenApiState>>,
    server_id: crate::state::ServerId,
) -> Result<Response<Full<Bytes>>, Infallible> {
    // Extract request details
    let method = req.method().to_string();
    let uri = req.uri().to_string();
    let path = req.uri().path().to_string();

    // Extract headers
    let mut headers = HashMap::new();
    for (name, value) in req.headers() {
        if let Ok(value_str) = value.to_str() {
            headers.insert(name.to_string(), value_str.to_string());
        }
    }

    // Read the body, bounded. `Incoming` has no default limit, so this buffered whatever the
    // peer chose to send — and an OpenAPI server is unauthenticated by construction, so a
    // single POST with an endless chunked body was enough to walk the process out of memory.
    // `Limited` errors as soon as the cap is passed, so an oversized upload costs at most the
    // cap rather than all of it.
    //
    // The old arm was worse than unbounded: it swallowed the read failure into an empty body
    // and carried on, so the model was shown a request with no body and answered it as if
    // the peer had sent none. That is the truncated-body trap — the model answers a request
    // it never saw. 413 says what happened, in a form a client can act on.
    let limited = http_body_util::Limited::new(req.into_body(), MAX_REQUEST_BODY_BYTES);
    let body_bytes = match limited.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(e) => {
            Log::new(Some(&status_tx)).warn(format!(
                "OpenAPI {} {} decision=fail_closed_body_too_large: {} (limit {} bytes)",
                method, path, e, MAX_REQUEST_BODY_BYTES
            ));
            return Ok(payload_too_large());
        }
    };

    // DEBUG: Log request summary
    Log::new(Some(&status_tx)).debug(format!(
        "OpenAPI {} {} ({} bytes)",
        method,
        path,
        body_bytes.len()
    ));

    // TRACE: Log full request details (FileOnly — full payloads are not streamed to the TUI)
    let log = Log::new(Some(&status_tx));
    log.trace("OpenAPI request headers:");
    for (name, value) in &headers {
        log.trace(format!("OpenAPI header: {}: {}", name, value));
    }
    if !body_bytes.is_empty() {
        if let Ok(body_str) = std::str::from_utf8(&body_bytes) {
            // Try to pretty-print if it's JSON
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(body_str) {
                let pretty = serde_json::to_string_pretty(&json).unwrap_or(body_str.to_string());
                log.trace(format!("OpenAPI request body (JSON):\n{}", pretty));
            } else {
                log.trace(format!("OpenAPI request body:\n{}", body_str));
            }
        } else {
            log.trace(format!(
                "OpenAPI request body (binary): {} bytes",
                body_bytes.len()
            ));
        }
    }

    // Get current spec info and perform route matching
    let (spec_info, match_result, llm_on_invalid) = {
        let state = openapi_state.read().await;
        let spec_info = json!({
            "spec_loaded": state.spec.is_some(),
            "spec_valid": state.spec_valid
        });

        {
            let match_result = if let Some(router) = state.router.as_ref() {
                Some(match_route(router, &method, &path))
            } else {
                None
            };
            (spec_info, match_result, state.llm_on_invalid)
        }
    };

    // Handle route matching results
    if let Some(match_result) = match_result {
        match match_result {
            MatchResult::Found { metadata, params } => {
                // Validate request if llm_on_invalid is false
                if !llm_on_invalid {
                    let body_text = String::from_utf8_lossy(&body_bytes);
                    if let Err(e) = validate_request(
                        &metadata.operation_json,
                        &method,
                        &path,
                        &headers,
                        &body_text,
                    ) {
                        Log::new(Some(&status_tx)).warn(format!("OpenAPI validation error: {}", e));
                        return Ok(immediate_400(e.to_string()));
                    }
                }

                // Create event with matched route information
                let body_text = String::from_utf8_lossy(&body_bytes);
                let event = Event::new(
                    &*crate::server::openapi::actions::OPENAPI_REQUEST_EVENT,
                    serde_json::json!({
                        "method": method,
                        "path": path,
                        "uri": uri,
                        "headers": headers,
                        "body": if body_text.is_empty() { "" } else { body_text.as_ref() },
                        "spec_info": spec_info,
                        "matched_route": {
                            "operation_id": metadata.operation_id,
                            "path_template": metadata.path_template,
                            "path_params": params,
                            "operation": metadata.operation_json,
                        }
                    }),
                );

                // Call LLM with matched route context
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
                        return handle_llm_response(
                            execution_result,
                            status_tx,
                            openapi_state,
                            method,
                            path,
                        )
                        .await;
                    }
                    Err(e) => {
                        return Ok(llm_error_response(e, &method, &path, &status_tx));
                    }
                }
            }
            MatchResult::MethodNotAllowed { allowed_methods } => {
                if llm_on_invalid {
                    // Let LLM handle 405 error
                    debug!(
                        "OpenAPI 405 Method Not Allowed (LLM will handle): {} {}",
                        method, path
                    );
                } else {
                    // Immediate 405 response
                    Log::new(Some(&status_tx)).info(format!(
                        "OpenAPI 405 Method Not Allowed: {} {} (allowed: {})",
                        method,
                        path,
                        allowed_methods.join(", ")
                    ));
                    return Ok(immediate_405(allowed_methods));
                }
            }
            MatchResult::NotFound => {
                if llm_on_invalid {
                    // Let LLM handle 404 error
                    debug!(
                        "OpenAPI 404 Not Found (LLM will handle): {} {}",
                        method, path
                    );
                } else {
                    // Immediate 404 response
                    Log::new(Some(&status_tx))
                        .info(format!("OpenAPI 404 Not Found: {} {}", method, path));
                    return Ok(immediate_404());
                }
            }
        }
    }

    // If no router or llm_on_invalid is true for errors, call LLM with basic info
    let body_text = String::from_utf8_lossy(&body_bytes);
    let event = Event::new(
        &*crate::server::openapi::actions::OPENAPI_REQUEST_EVENT,
        serde_json::json!({
            "method": method,
            "path": path,
            "uri": uri,
            "headers": headers,
            "body": if body_text.is_empty() { "" } else { body_text.as_ref() },
            "spec_info": spec_info
        }),
    );

    // Call LLM to handle request
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
            handle_llm_response(execution_result, status_tx, openapi_state, method, path).await
        }
        Err(e) => Ok(llm_error_response(e, &method, &path, &status_tx)),
    }
}

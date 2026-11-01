//! S3-compatible object storage server implementation
//!
//! Implements an S3-compatible REST API on port 9000 (default).
//! The LLM controls all operations and maintains "virtual" data through conversation context.

pub mod actions;

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::{Body, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::sync::mpsc;
use tracing::error;

use crate::llm::ollama_client::OllamaClient;
use crate::llm::ActionResult;
use crate::logging::emit::Log;
use crate::server::accept_bounded::{
    accept_bounded, watch_idle, ConnectionActivity, ConnectionLimiter,
};
use crate::server::connection::ConnectionId;
use crate::server::S3Protocol;
use crate::state::app_state::AppState;

/// Largest request body this server will buffer.
///
/// The body was read with an unbounded `req.into_body().collect()`, so a single PUT could
/// grow the process without limit — nothing in HTTP/1.1 bounds a chunked body, and the
/// content is never stored anyway (only its length reaches the model). `Limited` stops at
/// the cap and errors, so the memory one request can claim is bounded by a constant.
pub const MAX_REQUEST_BYTES: usize = 8 * 1024 * 1024;

/// How long a peer that has produced nothing at all may hold this connection.
///
/// HTTP is client-speaks-first: the request line is the first thing on the wire and every
/// S3 client sends it inside its dial path, so a peer that has connected and sent no byte
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
/// Five minutes, which is deliberately more permissive than the service this mimics: AWS's own
/// load balancers ship a 60-second idle timeout and S3 closes idle connections of its own
/// accord, so every SDK already has the reopen path this can exercise - that is what an SDK's
/// connection-pool revalidation is for, and what RFC 9112 requires of any HTTP client. An object
/// body being served is not silence: the response is built under a busy guard and written by
/// hyper, so only the pause between two requests is measured.
const IDLE_BETWEEN_REQUESTS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

/// Concurrent connections this server admits.
///
/// Each admitted connection may hold one whole in-memory object body, so the cap is what turns
/// that per-connection bound into a total one - and object bodies are the largest thing this
/// family serves. 256 is well above the pool any S3 SDK opens against one endpoint (the AWS SDKs
/// default to 50 connections) and far below what socket exhaustion needs.
const MAX_CONNECTIONS: usize = crate::server::accept_bounded::DEFAULT_MAX_CONNECTIONS;

/// What a peer over [`MAX_CONNECTIONS`] is told before the socket closes.
///
/// `503 Service Unavailable` with `Retry-After`, in S3's own vocabulary:
/// a 503 with `Retry-After` is S3's own overload reply (`SlowDown`),
/// so every SDK's retry path already handles it, and a human with `curl` reads it directly.
/// Nothing of netget's is interpolated into it - the peer gets a category and the log gets the
/// reason, under `decision=fail_closed_connection_cap`.
const CONNECTION_CAP_REFUSAL: &[u8] = b"HTTP/1.1 503 Service Unavailable\r\n\
    Content-Length: 0\r\nRetry-After: 5\r\nConnection: close\r\n\r\n";

/// S3 server that delegates API operations to LLM
pub struct S3Server;

impl S3Server {
    /// Spawn the S3 server with integrated LLM actions
    pub async fn spawn_with_llm_actions(
        listen_addr: SocketAddr,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        server_id: crate::state::ServerId,
    ) -> anyhow::Result<SocketAddr> {
        let listener =
            crate::server::socket_helpers::create_reusable_tcp_listener(listen_addr).await?;
        let local_addr = listener.local_addr()?;
        Log::new(Some(&status_tx)).info(format!("S3 server listening on {}", local_addr));

        let protocol = Arc::new(S3Protocol::new());

        // Spawn server loop
        let task_registrar = app_state.clone();
        let limiter = ConnectionLimiter::new(MAX_CONNECTIONS);
        let accept_handle = tokio::spawn(async move {
            loop {
                match accept_bounded(
                    &listener,
                    &limiter,
                    CONNECTION_CAP_REFUSAL,
                    "S3",
                    Some(&status_tx),
                )
                .await
                {
                    Ok((stream, remote_addr, permit)) => {
                        let connection_id =
                            ConnectionId::new(app_state.get_next_unified_id().await);
                        let local_addr_conn = stream.local_addr().unwrap_or(local_addr);
                        Log::new(Some(&status_tx)).info(format!(
                            "S3 connection {} from {}",
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

                        // Spawn a task to handle this connection
                        // Tracked, not detached: stop_server must abort this task too.
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

                                    // Clone for service closure
                                    let status_for_service = status_tx_clone.clone();
                                    let app_state_for_service = app_state_clone.clone();

                                    // Whether this connection is answering
                                    // anything. The watchdog below reads it, so
                                    // only genuine silence - never work in
                                    // flight - can close a connection.
                                    let activity = Arc::new(ConnectionActivity::new());
                                    let activity_for_service = Arc::clone(&activity);
                                    // Create a service that handles S3 requests with LLM
                                    let service = service_fn(move |req: Request<Incoming>| {
                                        let llm_clone = llm_client_clone.clone();
                                        let state_clone = app_state_for_service.clone();
                                        let status_clone = status_for_service.clone();
                                        let protocol_clone = protocol_clone.clone();
                                        // Busy for the whole of this request - the
                                        // model round-trip included, and a `manual`
                                        // rule parked for a human - so the idle
                                        // watchdog can never close the connection an
                                        // answer belongs to.
                                        let activity = Arc::clone(&activity_for_service);
                                        async move {
                                            let _busy = activity.busy();
                                            handle_s3_request_with_llm(
                                                req,
                                                connection_id,
                                                llm_clone,
                                                state_clone,
                                                status_clone,
                                                protocol_clone,
                                                server_id,
                                            )
                                            .await
                                        }
                                    });

                                    // Serve HTTP/1 on this connection
                                    let conn = http1::Builder::new().serve_connection(io, service);
                                    tokio::pin!(conn);
                                    tokio::select! {
                                        result = &mut conn => {
                                            if let Err(err) = result {
                                                error!("Error serving S3 connection: {:?}", err);
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
                                                "S3 connection {} idle for {}s; closing",
                                                connection_id,
                                                IDLE_BETWEEN_REQUESTS_TIMEOUT.as_secs()
                                            ));
                                        }
                                    }
                                } else {
                                    Log::new(Some(&status_tx_clone)).debug(format!(
                                        "S3 peer {} sent no request within {}s; closing \
                                         decision=fail_closed_first_byte_timeout",
                                        remote_addr,
                                        FIRST_BYTE_READ_TIMEOUT.as_secs()
                                    ));
                                }

                                // Mark connection as closed
                                app_state_clone
                                    .close_connection_on_server(server_id, connection_id)
                                    .await;
                                Log::new(Some(&status_tx_clone))
                                    .info(format!("S3 connection {} closed", connection_id));
                                let _ = status_tx_clone.send("__UPDATE_UI__".to_string());
                            })
                            .await;
                    }
                    Err(e) => {
                        Log::new(Some(&status_tx))
                            .error(format!("Failed to accept S3 connection: {}", e));
                        break;
                    }
                }
            }
        });

        // Register the accept loop so stop_server can abort it and release the port.
        task_registrar
            .register_server_task(server_id, accept_handle)
            .await;

        Ok(local_addr)
    }
}

/// Handle a single S3 request with LLM, then record what crossed the wire.
///
/// The rail's byte counters and the connection-scoped task prompts read
/// `bytes_received`/`bytes_sent`, and this server left both at the zero it registered the
/// connection with, so every S3 peer showed no traffic at all however much it moved.
async fn handle_s3_request_with_llm(
    req: Request<Incoming>,
    connection_id: ConnectionId,
    llm_client: OllamaClient,
    app_state: Arc<AppState>,
    status_tx: mpsc::UnboundedSender<String>,
    protocol: Arc<S3Protocol>,
    server_id: crate::state::ServerId,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let received = req.body().size_hint().lower();
    let response = handle_s3_request_inner(
        req,
        llm_client,
        app_state.clone(),
        status_tx.clone(),
        protocol,
        server_id,
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

async fn handle_s3_request_inner(
    req: Request<Incoming>,
    llm_client: OllamaClient,
    app_state: Arc<AppState>,
    status_tx: mpsc::UnboundedSender<String>,
    protocol: Arc<S3Protocol>,
    server_id: crate::state::ServerId,
) -> Result<Response<Full<Bytes>>, Infallible> {
    // Extract request details
    let method = req.method().clone();
    let uri = req.uri().clone();
    let path = uri.path().to_string();

    // Parse bucket and key from path
    // Path format: / (list buckets), /bucket (bucket ops), /bucket/key (object ops)
    let (bucket, key, operation) = parse_s3_path(&method, &path);

    let log = Log::new(Some(&status_tx));
    // FileOnly: the s3_request event's own log_template already reports the request to
    // the TUI at INFO.
    log.debug(format!(
        "S3 request: {} {} bucket={:?} key={:?} operation={}",
        method, path, bucket, key, operation
    ));

    // Read the request body (for PUT operations), capped at MAX_REQUEST_BYTES.
    let body_bytes = match Limited::new(req.into_body(), MAX_REQUEST_BYTES)
        .collect()
        .await
    {
        Ok(collected) => collected.to_bytes(),
        Err(e) => {
            // Refuse rather than continue with an empty body. A truncated or oversized
            // upload used to be reported to the model as a PutObject carrying zero bytes,
            // which the model would then acknowledge as a stored object.
            log.warn(format!(
                "S3 {} {} decision=fail_closed_body_rejected (limit {} bytes): {}",
                operation, path, MAX_REQUEST_BYTES, e
            ));
            return Ok(Response::builder()
                .status(StatusCode::PAYLOAD_TOO_LARGE)
                .header("Content-Type", "application/xml")
                .body(Full::new(Bytes::from(build_error_xml(
                    "EntityTooLarge",
                    "request body rejected",
                ))))
                .unwrap());
        }
    };

    if !body_bytes.is_empty() {
        log.trace(format!("S3 request body ({} bytes)", body_bytes.len()));
    }

    // Create S3 request event
    let event = crate::protocol::Event::new(
        &actions::S3_REQUEST_EVENT,
        serde_json::json!({
            "operation": operation,
            "bucket": bucket,
            "key": key,
            "request_details": {
                "method": method.as_str(),
                "path": path,
                "body_size": body_bytes.len(),
            }
        }),
    );

    // Call LLM to handle request
    let llm_result = crate::llm::action_helper::call_llm(
        &llm_client,
        &app_state,
        server_id,
        None, // Connection ID not needed for stateless HTTP
        &event,
        protocol.as_ref(),
    )
    .await;

    // Process LLM result and build HTTP response
    match llm_result {
        Ok(execution_result) => {
            // Which of the three outcomes this was, for the log. `decision=` is a stable
            // grep target: `model_reject` is the model deliberately refusing the request,
            // `model_answer` is a real S3 response, `model_no_action` is the model saying
            // nothing usable. None of them is `fail_closed_llm_error`, which only the `Err`
            // arm below may write — an operator must be able to tell a model's refusal from
            // netget failing to reach one.
            let decision = execution_result
                .protocol_results
                .iter()
                .find_map(|result| match result {
                    ActionResult::Custom { name, .. } => match name.as_str() {
                        "s3_error" => Some("model_reject"),
                        "s3_object" | "s3_object_list" | "s3_bucket_list" | "s3_write_result" => {
                            Some("model_answer")
                        }
                        _ => None,
                    },
                    _ => None,
                })
                .unwrap_or("model_no_action");
            let failures = execution_result.failures.len();

            // Scan for the first action that is actually an S3 response. This was a
            // `for` loop with an unconditional `return` inside it — so it examined
            // only the first result and, if that was something like `notify_operator`,
            // returned the empty-200 fallback and dropped the real object. It also
            // tripped clippy's `never_loop`, which is how it was found.
            if let Some(response) = execution_result
                .protocol_results
                .into_iter()
                .find_map(|result| process_s3_action_result(result, bucket.as_deref(), &status_tx))
            {
                log.debug(format!("S3 {} {} decision={}", operation, path, decision));
                return Ok(response);
            }

            // The model produced nothing this protocol can turn into a response.
            //
            // This used to answer an empty 200 OK, and for PutObject, CreateBucket,
            // DeleteObject and HeadObject an empty 200 is exactly what S3 returns on success —
            // so a model that declined the operation was reported to the caller as having
            // performed it. It could not simply be made to refuse, because until
            // `send_s3_write_result` existed those four verbs had no affirmative action at all
            // and refusing would have made them permanently impossible. Now they have one, so
            // silence can mean what it should.
            log.warn(format!(
                "S3 {} {} decision={} (no S3 response action; {} action(s) failed to \
                 execute) — answering 500 InternalError",
                operation, path, decision, failures
            ));
            Ok(Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .header("Content-Type", "application/xml")
                .body(Full::new(Bytes::from(build_error_xml(
                    "InternalError",
                    crate::utils::WireFailure::Unavailable.text(),
                ))))
                .unwrap())
        }
        Err(e) => {
            // netget could not reach a decision at all. Fail closed with an S3 `<Error>`
            // document carrying only a category — never the error itself, which names the
            // backend, the model and netget's own retry machinery. The full error goes to
            // the log and the status stream, which is where an operator looks.
            let failure = crate::utils::WireFailure::classify(&e);
            log.warn(format!(
                "S3 {} {} decision=fail_closed_llm_error category={:?}: {}",
                operation, path, failure, e
            ));

            // Distinct codes, so a client backs off rather than recording a permanent
            // fault: an overloaded backend is 503 + Retry-After (the AWS SDKs and rust-s3
            // treat 503 `ServiceUnavailable` as retryable), anything else is 500.
            let (status, code) = match failure {
                crate::utils::WireFailure::Overloaded => {
                    (StatusCode::SERVICE_UNAVAILABLE, "ServiceUnavailable")
                }
                crate::utils::WireFailure::Unavailable => {
                    (StatusCode::INTERNAL_SERVER_ERROR, "InternalError")
                }
            };

            let mut builder = Response::builder()
                .status(status)
                .header("Content-Type", "application/xml");
            if failure == crate::utils::WireFailure::Overloaded {
                builder = builder.header("Retry-After", "5");
            }

            Ok(builder
                .body(Full::new(Bytes::from(build_error_xml(
                    code,
                    failure.text(),
                ))))
                .unwrap())
        }
    }
}

/// Escape a value for inclusion in XML character data or an attribute.
///
/// Every value below reaches the wire from either the request path (bucket and object
/// keys) or model output (error messages, ETags, dates). None of it was escaped before,
/// so a single `&` in a key or message produced a body that is not well-formed XML. Real
/// clients do not recover from that: the AWS CLI silently discards an `<Error>` document
/// it cannot parse and reports a bare HTTP status, losing the S3 error code entirely.
fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    out
}

/// Build an S3 `<Error>` document.
fn build_error_xml(code: &str, message: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<Error>
  <Code>{}</Code>
  <Message>{}</Message>
</Error>"#,
        xml_escape(code),
        xml_escape(message)
    )
}

/// Attach a header whose value came from model output.
///
/// `http::HeaderValue` rejects control characters and non-ASCII bytes, and
/// `Builder::body()` surfaces that as an error which the old `.unwrap()` turned into a
/// panic - killing the connection task on a malformed model response. Skip the header
/// instead and say so in the log.
fn header_or_skip(
    builder: hyper::http::response::Builder,
    name: &'static str,
    value: &str,
) -> hyper::http::response::Builder {
    match hyper::header::HeaderValue::from_str(value) {
        Ok(v) => builder.header(name, v),
        Err(_) => {
            error!(
                "Dropping S3 {} header: {:?} is not a valid HTTP header value",
                name, value
            );
            builder
        }
    }
}

/// Parse S3 path into bucket, key, and operation
fn parse_s3_path(method: &Method, path: &str) -> (Option<String>, Option<String>, String) {
    let parts: Vec<&str> = path
        .trim_start_matches('/')
        .split('/')
        .filter(|s| !s.is_empty())
        .collect();

    match (method, parts.as_slice()) {
        // List buckets: GET /
        (m, []) if m == Method::GET => (None, None, "ListBuckets".to_string()),

        // Bucket operations: GET /bucket, PUT /bucket, DELETE /bucket
        (m, [bucket]) if m == Method::GET => {
            (Some(bucket.to_string()), None, "ListObjects".to_string())
        }
        (m, [bucket]) if m == Method::PUT => {
            (Some(bucket.to_string()), None, "CreateBucket".to_string())
        }
        (m, [bucket]) if m == Method::DELETE => {
            (Some(bucket.to_string()), None, "DeleteBucket".to_string())
        }
        (m, [bucket]) if m == Method::HEAD => {
            (Some(bucket.to_string()), None, "HeadBucket".to_string())
        }

        // Object operations: GET /bucket/key, PUT /bucket/key, DELETE /bucket/key
        (m, parts) if parts.len() >= 2 && m == Method::GET => {
            let bucket = parts[0].to_string();
            let key = parts[1..].join("/");
            (Some(bucket), Some(key), "GetObject".to_string())
        }
        (m, parts) if parts.len() >= 2 && m == Method::PUT => {
            let bucket = parts[0].to_string();
            let key = parts[1..].join("/");
            (Some(bucket), Some(key), "PutObject".to_string())
        }
        (m, parts) if parts.len() >= 2 && m == Method::DELETE => {
            let bucket = parts[0].to_string();
            let key = parts[1..].join("/");
            (Some(bucket), Some(key), "DeleteObject".to_string())
        }
        (m, parts) if parts.len() >= 2 && m == Method::HEAD => {
            let bucket = parts[0].to_string();
            let key = parts[1..].join("/");
            (Some(bucket), Some(key), "HeadObject".to_string())
        }

        // Unknown
        _ => (None, None, "Unknown".to_string()),
    }
}

/// Process LLM action result and build HTTP response
/// Build an S3 response from one action result.
///
/// Returns `None` when the action is not an S3 response action, so the caller can
/// keep scanning. This used to return an empty `200 OK` for anything it did not
/// recognise, and the caller returned unconditionally on the first result — so a
/// model that emitted the documented `notify_operator` + `s3_object` pair had its
/// object silently replaced by an empty body.
fn process_s3_action_result(
    action_result: ActionResult,
    bucket: Option<&str>,
    status_tx: &mpsc::UnboundedSender<String>,
) -> Option<Response<Full<Bytes>>> {
    match action_result {
        ActionResult::Custom { name, data } => {
            match name.as_str() {
                "s3_object" => {
                    // `content_b64` is the canonical form produced by
                    // `S3Protocol::execute_action`, which already validated and decoded
                    // the model's `content`/`encoding` pair. It cannot fail to decode here.
                    use base64::Engine;
                    let content: Vec<u8> = data
                        .get("content_b64")
                        .and_then(|v| v.as_str())
                        .and_then(|s| base64::engine::general_purpose::STANDARD.decode(s).ok())
                        .unwrap_or_default();

                    let content_type = data
                        .get("content_type")
                        .and_then(|v| v.as_str())
                        .unwrap_or("application/octet-stream");

                    let etag = data.get("etag").and_then(|v| v.as_str());

                    // FileOnly: the send_s3_object action's own log_template already
                    // reports "-> S3 send object ({content_type})" to the TUI at INFO.
                    Log::new(Some(status_tx)).debug(format!(
                        "Sending S3 object ({} bytes, {})",
                        content.len(),
                        content_type
                    ));

                    // `send_s3_object` documents an unusable content_type as being replaced
                    // with application/octet-stream; `header_or_skip` alone would drop the
                    // header entirely and answer with no Content-Type at all.
                    let content_type = if hyper::header::HeaderValue::from_str(content_type).is_ok()
                    {
                        content_type
                    } else {
                        error!(
                            "S3 content_type {:?} is not a valid header value; \
                             sending application/octet-stream",
                            content_type
                        );
                        "application/octet-stream"
                    };

                    let mut builder = Response::builder().status(StatusCode::OK);
                    builder = header_or_skip(builder, "Content-Type", content_type);
                    if let Some(etag) = etag {
                        builder = header_or_skip(builder, "ETag", etag);
                    }

                    Some(
                        builder
                            .body(Full::new(Bytes::from(content)))
                            .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()))),
                    )
                }
                "s3_object_list" => {
                    // Send list of objects as XML
                    let objects = data
                        .get("objects")
                        .and_then(|v| v.as_array())
                        .cloned()
                        .unwrap_or_default();

                    let is_truncated = data
                        .get("is_truncated")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);

                    let xml = build_list_objects_xml(bucket, &objects, is_truncated);

                    // FileOnly: the send_s3_object_list action's own log_template already
                    // reports "-> S3 list objects (...)" to the TUI at INFO.
                    Log::new(Some(status_tx)).debug(format!(
                        "Sending S3 object list ({} objects)",
                        objects.len()
                    ));

                    Some(
                        Response::builder()
                            .status(StatusCode::OK)
                            .header("Content-Type", "application/xml")
                            .body(Full::new(Bytes::from(xml)))
                            .unwrap(),
                    )
                }
                "s3_bucket_list" => {
                    // Send list of buckets as XML
                    let buckets = data
                        .get("buckets")
                        .and_then(|v| v.as_array())
                        .cloned()
                        .unwrap_or_default();

                    let xml = build_list_buckets_xml(&buckets);

                    // FileOnly: the send_s3_bucket_list action's own log_template already
                    // reports "-> S3 list buckets (...)" to the TUI at INFO.
                    Log::new(Some(status_tx)).debug(format!(
                        "Sending S3 bucket list ({} buckets)",
                        buckets.len()
                    ));

                    Some(
                        Response::builder()
                            .status(StatusCode::OK)
                            .header("Content-Type", "application/xml")
                            .body(Full::new(Bytes::from(xml)))
                            .unwrap(),
                    )
                }
                "s3_write_result" => {
                    // A body-less acknowledgement: PutObject/CreateBucket/HeadObject answer
                    // 200, DeleteObject answers 204. Each header is attached only when the
                    // model supplied it, so an unadorned acknowledgement is still valid.
                    let status = data
                        .get("status_code")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(200) as u16;
                    let status =
                        StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);

                    Log::new(Some(status_tx))
                        .debug(format!("Sending S3 write acknowledgement ({})", status));

                    // Every header value here is model output, so each goes through
                    // `header_or_skip`. Attaching one directly makes `Builder::body()` fail
                    // instead, and the `unwrap_or_else` below then answers an empty 200 —
                    // silently downgrading a 204 DeleteObject to a 200 because an ETag
                    // contained a newline.
                    let mut builder = Response::builder().status(status);
                    for (field, header) in [
                        ("etag", "ETag"),
                        ("location", "Location"),
                        ("content_type", "Content-Type"),
                        ("last_modified", "Last-Modified"),
                    ] {
                        if let Some(v) = data.get(field).and_then(|v| v.as_str()) {
                            builder = header_or_skip(builder, header, v);
                        }
                    }
                    if let Some(v) = data.get("content_length").and_then(|v| v.as_u64()) {
                        builder = builder.header("Content-Length", v.to_string());
                    }

                    Some(
                        builder
                            .body(Full::new(Bytes::new()))
                            .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()))),
                    )
                }
                "s3_error" => {
                    // Send S3 error response
                    let error_code = data
                        .get("error_code")
                        .and_then(|v| v.as_str())
                        .unwrap_or("InternalError");

                    let message = data
                        .get("message")
                        .and_then(|v| v.as_str())
                        .unwrap_or("An error occurred");

                    let status_code = data
                        .get("status_code")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(500) as u16;

                    let xml = build_error_xml(error_code, message);

                    // FileOnly: the send_s3_error action's own log_template already reports
                    // "-> S3 error {error_code} (...)" to the TUI at INFO.
                    Log::new(Some(status_tx)).debug(format!(
                        "Sending S3 error: {} ({})",
                        error_code, status_code
                    ));

                    Some(
                        Response::builder()
                            .status(
                                StatusCode::from_u16(status_code)
                                    .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                            )
                            .header("Content-Type", "application/xml")
                            .body(Full::new(Bytes::from(xml)))
                            .unwrap(),
                    )
                }
                _ => {
                    // Unknown custom action, return empty response
                    // Not an S3 action: let the caller keep scanning.
                    None
                }
            }
        }
        _ => {
            // For non-custom actions (NoAction, etc.), return 200 OK with empty body
            // Not an S3 action: let the caller keep scanning.
            None
        }
    }
}

/// Build ListBuckets XML response
fn build_list_buckets_xml(buckets: &[serde_json::Value]) -> String {
    let mut xml = String::from(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<ListAllMyBucketsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Owner>
    <DisplayName>netget</DisplayName>
    <ID>netget-user</ID>
  </Owner>
  <Buckets>"#,
    );

    for bucket in buckets {
        let name = bucket.get("name").and_then(|v| v.as_str()).unwrap_or("");
        let creation_date = bucket
            .get("creation_date")
            .and_then(|v| v.as_str())
            .unwrap_or("2024-01-01T00:00:00.000Z");

        xml.push_str(&format!(
            r#"
    <Bucket>
      <Name>{}</Name>
      <CreationDate>{}</CreationDate>
    </Bucket>"#,
            xml_escape(name),
            xml_escape(creation_date)
        ));
    }

    xml.push_str(
        r#"
  </Buckets>
</ListAllMyBucketsResult>"#,
    );

    xml
}

/// Build ListObjects XML response
///
/// `Name`, `Prefix`, `MaxKeys` and `KeyCount` are always-present elements of a real
/// `ListBucketResult`; omitting them left SDKs deserializing a bucket listing with no
/// bucket name and no key count. `bucket` comes from the request path, since the
/// listing action carries only the objects.
fn build_list_objects_xml(
    bucket: Option<&str>,
    objects: &[serde_json::Value],
    is_truncated: bool,
) -> String {
    let mut xml = String::from(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">"#,
    );

    xml.push_str(&format!(
        r#"
  <Name>{}</Name>
  <Prefix></Prefix>
  <MaxKeys>1000</MaxKeys>
  <KeyCount>{}</KeyCount>
  <IsTruncated>{}</IsTruncated>"#,
        xml_escape(bucket.unwrap_or("")),
        objects.len(),
        is_truncated
    ));

    for object in objects {
        let key = object.get("key").and_then(|v| v.as_str()).unwrap_or("");
        let size = object.get("size").and_then(|v| v.as_u64()).unwrap_or(0);
        let last_modified = object
            .get("last_modified")
            .and_then(|v| v.as_str())
            .unwrap_or("2024-01-01T00:00:00.000Z");
        let etag = object
            .get("etag")
            .and_then(|v| v.as_str())
            .unwrap_or("\"default\"");

        xml.push_str(&format!(
            r#"
  <Contents>
    <Key>{}</Key>
    <Size>{}</Size>
    <LastModified>{}</LastModified>
    <ETag>{}</ETag>
    <StorageClass>STANDARD</StorageClass>
  </Contents>"#,
            xml_escape(key),
            size,
            xml_escape(last_modified),
            xml_escape(etag)
        ));
    }

    xml.push_str(
        r#"
</ListBucketResult>"#,
    );

    xml
}

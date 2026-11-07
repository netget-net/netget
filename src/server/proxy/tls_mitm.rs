//! TLS MITM (Man-in-the-Middle) orchestration for HTTPS proxy
//!
//! Handles the complete MITM flow:
//! 1. Accept TLS connection from client (using dynamically generated cert)
//! 2. Connect to upstream server with TLS
//! 3. Proxy decrypted HTTP traffic through LLM filtering
//! 4. Re-encrypt and forward to both sides

use super::cert_cache::CertificateCache;
use super::filter::{FullRequestInfo, ProxyFilterConfig, RequestAction, ResponseAction};
use crate::llm::action_helper::call_llm;
use crate::llm::ollama_client::OllamaClient;
use crate::logging::emit::Log;
use crate::protocol::Event;
use crate::server::connection::ConnectionId;
use crate::server::ProxyProtocol;
use crate::state::app_state::AppState;
use crate::state::ServerId;
use crate::utils::WireFailure;
use anyhow::{Context, Result};
use rustls::pki_types::ServerName;
use rustls::ClientConfig;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tracing::{debug, info, trace, warn};

use super::actions::{PROXY_HTTP_REQUEST_EVENT, PROXY_HTTP_RESPONSE_EVENT};

/// Perform full TLS MITM interception
///
/// This function:
/// 1. Sends "200 Connection Established" to client
/// 2. Performs TLS handshake with client (using generated cert for domain)
/// 3. Connects to upstream server with TLS
/// 4. Proxies HTTP requests/responses through LLM filtering
pub async fn perform_mitm(
    mut client_stream: TcpStream,
    dest_host: &str,
    dest_port: u16,
    peer_addr: SocketAddr,
    _connection_id: ConnectionId,
    server_id: ServerId,
    cert_cache: Arc<CertificateCache>,
    config: ProxyFilterConfig,
    llm_client: OllamaClient,
    app_state: Arc<AppState>,
    status_tx: mpsc::UnboundedSender<String>,
    protocol: Arc<ProxyProtocol>,
) -> Result<()> {
    let start_time = crate::utils::clock::Instant::now();

    Log::to(&status_tx).info(format!(
        "MITM mode: intercepting {}:{} from {}",
        dest_host, dest_port, peer_addr
    ));

    // Step 1: Send "200 Connection Established" to client BEFORE TLS handshake
    client_stream
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await
        .context("Failed to send 200 to client")?;

    trace!("Sent 200 Connection Established to client");

    // Step 2: Generate or retrieve leaf certificate (and its matching key) for this domain
    let (cert_chain, private_key) = cert_cache
        .get_or_generate(dest_host)
        .await
        .context("Failed to generate leaf certificate")?;

    debug!("Generated/retrieved certificate for domain '{}'", dest_host);

    // Install crypto provider (ring) if not already installed
    let _ = rustls::crypto::ring::default_provider().install_default();

    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, private_key)
        .context("Failed to create server TLS config")?;

    let tls_acceptor = TlsAcceptor::from(Arc::new(server_config));

    // Step 4: Perform TLS handshake with client
    let mut client_tls_stream = tls_acceptor
        .accept(client_stream)
        .await
        .context("TLS handshake with client failed")?;

    Log::to(&status_tx).info(format!(
        "MITM client TLS handshake complete for {}",
        dest_host
    ));

    // Step 8: Proxy HTTP traffic through LLM
    // client_tls_stream is established; the upstream is dialled only after the model decides.
    // We read HTTP requests from client, optionally modify via LLM, forward to upstream
    // We read HTTP responses from upstream, optionally modify via LLM, send to client

    // For now, implement simple bidirectional proxying
    // TODO: Parse HTTP requests/responses and apply LLM filtering

    Log::to(&status_tx).info(format!(
        "MITM starting bidirectional HTTPS proxy for {}:{}",
        dest_host, dest_port
    ));

    // Read first HTTP request from client
    let mut request_buffer = vec![0u8; 8192];
    let request_len = client_tls_stream
        .read(&mut request_buffer)
        .await
        .context("Failed to read HTTP request from client")?;

    if request_len == 0 {
        warn!("Client closed connection immediately after TLS handshake");
        return Ok(());
    }

    let request_data = &request_buffer[..request_len];
    let request_str = String::from_utf8_lossy(request_data);

    trace!(
        "Received HTTP request over TLS ({} bytes):\n{}",
        request_len,
        if request_str.len() > 500 {
            format!("{}...", super::truncate_str(&request_str, 500))
        } else {
            request_str.to_string()
        }
    );

    // Parse HTTP request
    let first_line = request_str.lines().next().unwrap_or("");
    let parts: Vec<&str> = first_line.split_whitespace().collect();

    if parts.len() >= 3 {
        let method = parts[0];
        let path = parts[1];

        Log::to(&status_tx).info(format!(
            "MITM request: {} {} -> {}",
            method, path, dest_host
        ));

        // Parse headers
        let mut headers = HashMap::new();
        let mut body_start = 0;

        for (i, line) in request_str.lines().enumerate() {
            if i == 0 {
                continue; // Skip request line
            }
            if line.is_empty() {
                // End of headers
                body_start =
                    request_str[..request_str.find("\r\n\r\n").unwrap_or(request_str.len())].len()
                        + 4;
                break;
            }
            if let Some(colon_pos) = line.find(':') {
                let name = line[..colon_pos].trim().to_string();
                let value = line[colon_pos + 1..].trim().to_string();
                headers.insert(name, value);
            }
        }

        let body = if body_start < request_data.len() {
            &request_data[body_start..]
        } else {
            &[]
        };

        // Build request info for LLM
        let request_info = FullRequestInfo {
            method: method.to_string(),
            url: format!("https://{}{}", dest_host, path),
            path: path.to_string(),
            host: dest_host.to_string(),
            headers: headers.clone(),
            body: body.to_vec(),
            client_addr: peer_addr.to_string(),
        };

        // Consult LLM (simplified - just check if we should pass through)
        let action = consult_llm_for_request(
            &request_info,
            server_id,
            &llm_client,
            &app_state,
            &protocol,
            &status_tx,
        )
        .await
        .unwrap_or_else(|e| {
            // Fail closed. This used to default to `Pass`, which handed the decrypted request
            // straight to its destination unfiltered - so the MITM path became an open relay
            // for exactly as long as the backend was down, and the access log recorded each
            // request as having been passed on purpose. The plaintext HTTP twin in mod.rs was
            // fixed for this; only this half stayed open.
            //
            // The peer is told a category and nothing else: `WireFailure::prefixed_text()`
            // returns `&'static str`, so no part of `e` can reach the wire. The error itself
            // goes to the log and the status stream, which is where an operator looks.
            let failure = WireFailure::classify(&e);
            let status = if failure.is_overloaded() { 503 } else { 502 };
            // Non-fatal: the client gets a 502/503, so WARN not ERROR.
            Log::to(&status_tx).warn(format!(
                "MITM blocking {} {} with {} (decision=llm_error, overloaded={}): {}",
                request_info.method,
                request_info.url,
                status,
                failure.is_overloaded(),
                e
            ));
            RequestAction::Block {
                status,
                body: failure.prefixed_text().to_string(),
            }
        });

        // The upstream is dialled only once the model has let the request through. Dialling
        // first (a TCP connection and a TLS ClientHello carrying the peer's SNI) would let any
        // proxy client make NetGet connect to an arbitrary host:port — a reachability oracle
        // for internal addresses — and would cost a blocked request's destination a handshake.
        if let RequestAction::Block { status, body } = action {
            // Return error response to client. `body` is either the model's own reason or
            // one of the two `WireFailure` categories - never an error string. A 503
            // carries `Retry-After` (see `failure_response`) so a client backs off rather
            // than recording a permanent fault, which is the whole point of keeping
            // Overloaded distinct from Unavailable.
            let response = failure_response(status, &body);

            client_tls_stream
                .write_all(&response)
                .await
                .context("Failed to send blocked response to client")?;

            info!(
                "Blocked MITM request with status {} (upstream {}:{} never dialled)",
                status, dest_host, dest_port
            );
            return Ok(());
        }

        // Build the outbound request before dialling, so a modification that cannot be
        // applied is refused without the upstream ever being contacted.
        let outbound: std::borrow::Cow<'_, [u8]> = match action {
            RequestAction::Block { .. } => unreachable!("answered above"),
            RequestAction::Pass => std::borrow::Cow::Borrowed(request_data),
            ref modify_action @ RequestAction::Modify { .. } => {
                // Reuse the same modification routine as the plaintext HTTP path so
                // headers/path/query_params/body behave identically over TLS. A request it
                // cannot rebuild (a malformed or incomplete chunked body, an undecodable
                // transfer coding) is refused rather than forwarded unmodified.
                match crate::server::proxy::ProxyServer::apply_request_modifications(
                    request_data,
                    modify_action,
                ) {
                    Ok(modified) => std::borrow::Cow::Owned(modified),
                    Err(e) => {
                        Log::to(&status_tx).warn(format!(
                            "MITM refusing {} {} with 400: cannot apply modification: {:#}",
                            request_info.method, request_info.url, e
                        ));
                        client_tls_stream
                            .write_all(&crate::server::proxy::modification_refused_response())
                            .await
                            .context("Failed to send refusal to client")?;
                        return Ok(());
                    }
                }
            }
        };

        let mut upstream_tls_stream = connect_upstream(dest_host, dest_port, &status_tx).await?;
        upstream_tls_stream
            .write_all(&outbound)
            .await
            .context("Failed to forward request to upstream")?;
        trace!("Forwarded request to upstream server");

        // Read response from upstream
        let mut response_buffer = vec![0u8; 16384]; // Larger buffer for responses
        let response_len = upstream_tls_stream
            .read(&mut response_buffer)
            .await
            .context("Failed to read response from upstream")?;

        if response_len == 0 {
            warn!("Upstream server closed connection");
            return Ok(());
        }

        let response_data = &response_buffer[..response_len];
        let response_str = String::from_utf8_lossy(response_data);
        trace!("Received response from upstream ({} bytes)", response_len);

        // Parse HTTP response.
        //
        // `response_blocked` matters: after writing the first response this function degrades
        // to an opaque bidirectional copy, which would happily forward the rest of the
        // upstream response to the client and undo the block we just applied.
        let mut response_blocked = false;
        let response_modified = if config.should_inspect_response(&request_info) {
            // Extract status code and headers
            let first_line = response_str.lines().next().unwrap_or("");
            let status_code = extract_status_code(first_line).unwrap_or(200);

            let mut response_headers = HashMap::new();
            let mut response_body_start = 0;

            for (i, line) in response_str.lines().enumerate() {
                if i == 0 {
                    continue; // Skip status line
                }
                if line.is_empty() {
                    response_body_start = response_str
                        [..response_str.find("\r\n\r\n").unwrap_or(response_str.len())]
                        .len()
                        + 4;
                    break;
                }
                if let Some(colon_pos) = line.find(':') {
                    let name = line[..colon_pos].trim().to_string();
                    let value = line[colon_pos + 1..].trim().to_string();
                    response_headers.insert(name, value);
                }
            }

            let response_body = if response_body_start < response_data.len() {
                &response_data[response_body_start..]
            } else {
                &[]
            };

            trace!(
                "Parsed response: status={}, headers={}, body_len={}",
                status_code,
                response_headers.len(),
                response_body.len()
            );

            // Consult LLM about response
            match consult_llm_for_response(
                &request_info,
                status_code,
                &response_headers,
                response_body,
                server_id,
                &llm_client,
                &app_state,
                &protocol,
                &status_tx,
            )
            .await
            {
                Ok(ResponseAction::Pass) => {
                    trace!("LLM decision: Pass response through");
                    None // No modification
                }
                Ok(ResponseAction::Block { status, body }) => {
                    info!(
                        "MITM blocking response to {} {} with {} (decision=model_reject)",
                        request_info.method, request_info.url, status
                    );
                    response_blocked = true;
                    Some(failure_response(status, &body))
                }
                Ok(ResponseAction::Modify {
                    status: new_status,
                    headers: add_headers,
                    remove_headers,
                    new_body,
                    body_replacements,
                }) => {
                    info!("LLM decision: Modify response");

                    // Body: full replacement first, then regex replacements over
                    // whatever body results. body_replacements was previously
                    // parsed and then dropped, so a documented redaction silently
                    // did nothing.
                    let mut final_body = new_body
                        .unwrap_or_else(|| String::from_utf8_lossy(response_body).to_string());

                    if let Some(replacements) = body_replacements {
                        for replacement in replacements {
                            match regex::Regex::new(&replacement.pattern) {
                                Ok(re) => {
                                    final_body = re
                                        .replace_all(&final_body, replacement.replacement.as_str())
                                        .to_string();
                                }
                                Err(e) => {
                                    warn!(
                                        "Invalid body_replacements pattern {:?}: {}",
                                        replacement.pattern, e
                                    );
                                    let _ = status_tx.send(format!(
                                        "✗ Invalid response body_replacements pattern {:?}: {}",
                                        replacement.pattern, e
                                    ));
                                }
                            }
                        }
                    }

                    Some(rebuild_modified_response(
                        new_status.unwrap_or(status_code),
                        &response_headers,
                        add_headers.as_ref(),
                        remove_headers.as_deref().unwrap_or(&[]),
                        final_body.as_bytes(),
                    ))
                }
                Err(e) => {
                    // Fail closed, same reasoning as the request side. Returning `None` here
                    // delivered the upstream response to the client verbatim - including a
                    // response the model was being asked to redact or block - so a backend
                    // outage silently disabled response filtering altogether.
                    let failure = WireFailure::classify(&e);
                    let status = if failure.is_overloaded() { 503 } else { 502 };
                    Log::to(&status_tx).warn(format!(
                        "MITM blocking response to {} {} with {} (decision=llm_error, overloaded={}): {}",
                        request_info.method,
                        request_info.url,
                        status,
                        failure.is_overloaded(),
                        e
                    ));
                    response_blocked = true;
                    Some(failure_response(status, failure.prefixed_text()))
                }
            }
        } else {
            None // No inspection needed
        };

        // Send response to client (modified or original)
        let final_response = response_modified
            .as_ref()
            .map(|v| v.as_slice())
            .unwrap_or(response_data);

        client_tls_stream
            .write_all(final_response)
            .await
            .context("Failed to send response to client")?;

        trace!("Sent response to client ({} bytes)", final_response.len());

        if response_blocked {
            // We refused this response. Falling through to the copy below would stream the
            // remainder of the upstream response to the client anyway.
            debug!(
                "[ACCESS] {} MITM {}:{} -> response refused, connection closed",
                peer_addr, dest_host, dest_port
            );
            return Ok(());
        }

        // After first request/response, switch to bidirectional copy
        // This handles keep-alive connections and additional requests
        let (mut client_read, mut client_write) = tokio::io::split(client_tls_stream);
        let (mut upstream_read, mut upstream_write) = tokio::io::split(upstream_tls_stream);

        let client_to_upstream = tokio::io::copy(&mut client_read, &mut upstream_write);
        let upstream_to_client = tokio::io::copy(&mut upstream_read, &mut client_write);

        let (up_bytes, down_bytes) = tokio::join!(client_to_upstream, upstream_to_client);
        let up_bytes = up_bytes.unwrap_or(0) + request_len as u64;
        let down_bytes = down_bytes.unwrap_or(0) + response_len as u64;

        let duration = start_time.elapsed();

        Log::to(&status_tx).debug(format!(
            "[ACCESS] {} MITM {}:{} -> {} bytes ({} up, {} down) in {:?}",
            peer_addr,
            dest_host,
            dest_port,
            up_bytes + down_bytes,
            up_bytes,
            down_bytes,
            duration
        ));
    } else {
        warn!("Invalid HTTP request in MITM mode: {}", first_line);
        return Err(anyhow::anyhow!("Invalid HTTP request"));
    }

    Ok(())
}

/// Consult LLM about an HTTP request in MITM mode
async fn consult_llm_for_request(
    request_info: &FullRequestInfo,
    server_id: ServerId,
    llm_client: &OllamaClient,
    app_state: &Arc<AppState>,
    protocol: &Arc<ProxyProtocol>,
    status_tx: &mpsc::UnboundedSender<String>,
) -> Result<RequestAction> {
    use crate::llm::actions::protocol_trait::{ActionResult, Server};
    use serde_json::json;

    Log::to(status_tx).debug("Consulting LLM about MITM request...");

    // Create HTTP request event
    let event = Event::new(
        &PROXY_HTTP_REQUEST_EVENT,
        json!({
            "method": request_info.method,
            "url": request_info.url,
            "host": request_info.host,
            "path": request_info.path,
        }),
    );

    let execution_result = call_llm(
        llm_client,
        app_state,
        server_id,
        None, // TODO: Add connection_id
        &event,
        protocol.as_ref() as &dyn Server,
    )
    .await
    .context("LLM request failed")?;

    // Extract request action from protocol results
    for result in execution_result.protocol_results {
        if let ActionResult::Output(bytes) = result {
            // Deserialize the RequestAction
            let action: RequestAction =
                serde_json::from_slice(&bytes).context("Failed to deserialize RequestAction")?;
            if let RequestAction::Block { status, .. } = &action {
                // The model ruled against this request. Tagged separately from the two
                // failure paths below so an operator can tell a policy decision from an
                // outage in the log.
                info!(
                    "MITM blocking {} {} with {} (decision=model_reject)",
                    request_info.method, request_info.url, status
                );
            }
            return Ok(action);
        }
    }

    // Fail closed, for the same reason the `Err` branch at the call site does: a request this
    // proxy forwards is a request the model was asked to rule on and did not. The caller
    // cannot tell the two apart from the action alone, so the distinction lives in the log -
    // `no_decision` here, `llm_error` there - exactly so a silent model and a dead backend are
    // never diagnosed as each other.
    Log::to(status_tx).warn(format!(
        "MITM blocking {} {} with 502: handler produced no filtering decision \
         (decision=no_decision)",
        request_info.method, request_info.url
    ));
    Ok(RequestAction::Block {
        status: 502,
        body: NO_DECISION_REQUEST_BODY.to_string(),
    })
}

/// Consult LLM about an HTTP response in MITM mode
async fn consult_llm_for_response(
    request_info: &FullRequestInfo,
    status_code: u16,
    response_headers: &HashMap<String, String>,
    response_body: &[u8],
    server_id: ServerId,
    llm_client: &OllamaClient,
    app_state: &Arc<AppState>,
    protocol: &Arc<ProxyProtocol>,
    status_tx: &mpsc::UnboundedSender<String>,
) -> Result<ResponseAction> {
    use crate::llm::actions::protocol_trait::{ActionResult, Server};
    use serde_json::json;

    Log::to(status_tx).debug("Consulting LLM about MITM response...");

    // Create HTTP response event
    let body_preview = if response_body.len() > 200 {
        format!(
            "{}... ({} bytes total)",
            String::from_utf8_lossy(&response_body[..200]),
            response_body.len()
        )
    } else {
        String::from_utf8_lossy(response_body).to_string()
    };

    let event = Event::new(
        &PROXY_HTTP_RESPONSE_EVENT,
        json!({
            "request_method": request_info.method,
            "request_url": request_info.url,
            "status_code": status_code,
            "headers": response_headers,
            "body_preview": body_preview,
        }),
    );

    let execution_result = call_llm(
        llm_client,
        app_state,
        server_id,
        None, // TODO: Add connection_id
        &event,
        protocol.as_ref() as &dyn Server,
    )
    .await
    .context("LLM request failed")?;

    // Extract response action from protocol results
    for result in execution_result.protocol_results {
        if let ActionResult::Output(bytes) = result {
            // Deserialize the ResponseAction
            let action: ResponseAction =
                serde_json::from_slice(&bytes).context("Failed to deserialize ResponseAction")?;
            return Ok(action);
        }
    }

    // Fail closed. `Pass` here delivered the upstream response to the client on the strength
    // of a decision nobody made, and the access log then recorded it as a deliberate pass.
    Log::to(status_tx).warn(format!(
        "MITM blocking response to {} {} with 502: handler produced no filtering decision \
         (decision=no_decision)",
        request_info.method, request_info.url
    ));
    Ok(ResponseAction::Block {
        status: 502,
        body: NO_DECISION_RESPONSE_BODY.to_string(),
    })
}

/// The peer-visible text when the handler answered but chose nothing.
///
/// A constant, not a `format!`, for the same reason [`WireFailure::text`] returns
/// `&'static str`: a string built at the failure site is one interpolation away from carrying
/// netget's internals onto a stranger's connection. See `src/utils/wire_failure.rs`.
const NO_DECISION_REQUEST_BODY: &str =
    "netget proxy: the filtering handler returned no decision for this request, so it was \
     refused";

const NO_DECISION_RESPONSE_BODY: &str =
    "netget proxy: the filtering handler returned no decision for this response, so it was \
     refused";

/// Reason phrase for the handful of statuses this module synthesises itself.
///
/// The model may name any status in a `block` action, so this falls back to a generic phrase
/// rather than indexing a table.
fn reason_phrase(status: u16) -> &'static str {
    match status {
        403 => "Forbidden",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "Blocked",
    }
}

/// Build a complete HTTP/1.1 error response for the client.
///
/// `body` must already be peer-safe - either the model's own reason or a `WireFailure`
/// category. Nothing derived from an internal error may be passed here.
fn failure_response(status: u16, body: &str) -> Vec<u8> {
    let retry_after = if status == 503 {
        "Retry-After: 5\r\n"
    } else {
        ""
    };
    format!(
        "HTTP/1.1 {} {}\r\nContent-Type: text/plain\r\n{}Content-Length: {}\r\nConnection: close\r\n\r\n{}",
        status,
        reason_phrase(status),
        retry_after,
        body.len(),
        body
    )
    .into_bytes()
}

/// Rebuild a modified upstream response as one HTTP/1.1 message the proxy frames itself.
///
/// The upstream's `Content-Length` and `Transfer-Encoding` are dropped: the body is written
/// whole after a single `Content-Length` the proxy computes, so re-emitting the upstream's
/// framing produced two `Content-Length` values, or `chunked` over an unchunked body — the
/// ambiguity response-desync attacks exploit. Model-added headers go through the same
/// checks as the executor (token name, no CR/LF, no framing header), so a value that still
/// carries a line break is dropped rather than written.
pub fn rebuild_modified_response(
    status: u16,
    upstream_headers: &HashMap<String, String>,
    add_headers: Option<&HashMap<String, String>>,
    remove_headers: &[String],
    body: &[u8],
) -> Vec<u8> {
    use crate::server::proxy::filter::{check_header_name, check_header_value, FRAMING_HEADERS};

    let remove_set: std::collections::HashSet<String> =
        remove_headers.iter().map(|h| h.to_lowercase()).collect();
    let added: std::collections::HashSet<String> = add_headers
        .map(|h| h.keys().map(|k| k.to_lowercase()).collect())
        .unwrap_or_default();

    // The reason phrase matches the status, so a 404 is not sent as "404 OK".
    let reason = http::StatusCode::from_u16(status)
        .ok()
        .and_then(|s| s.canonical_reason())
        .unwrap_or("OK");
    let mut out = format!("HTTP/1.1 {} {}\r\n", status, reason);

    // Upstream headers, minus removed, minus framing, minus any the model replaces.
    let mut upstream: Vec<(&String, &String)> = upstream_headers.iter().collect();
    upstream.sort();
    for (name, value) in upstream {
        let key = name.to_lowercase();
        if remove_set.contains(&key)
            || added.contains(&key)
            || FRAMING_HEADERS.contains(&key.as_str())
        {
            continue;
        }
        if check_header_name(name)
            .and_then(|_| check_header_value(name, value))
            .is_err()
        {
            continue;
        }
        out.push_str(&format!("{}: {}\r\n", name, value));
    }

    if let Some(add) = add_headers {
        let mut add: Vec<(&String, &String)> = add.iter().collect();
        add.sort();
        for (name, value) in add {
            let key = name.to_lowercase();
            if FRAMING_HEADERS.contains(&key.as_str()) {
                warn!("Dropping response header {name:?}: the proxy frames the body itself");
                continue;
            }
            if let Err(e) = check_header_name(name).and_then(|_| check_header_value(name, value)) {
                warn!("Dropping response header modification: {}", e);
                continue;
            }
            out.push_str(&format!("{}: {}\r\n", name, value));
        }
    }

    out.push_str(&format!("Content-Length: {}\r\n\r\n", body.len()));
    let mut bytes = out.into_bytes();
    bytes.extend_from_slice(body);
    bytes
}

/// Dial the destination and complete the upstream TLS handshake.
///
/// Called only after the model has let the client's first request through: see the
/// comment at the call site. The upstream certificate is verified against the webpki
/// roots; there is no bypass.
async fn connect_upstream(
    dest_host: &str,
    dest_port: u16,
    status_tx: &mpsc::UnboundedSender<String>,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let dest_addr = format!("{}:{}", dest_host, dest_port);
    let upstream_tcp = TcpStream::connect(&dest_addr)
        .await
        .context(format!("Failed to connect to upstream {}", dest_addr))?;

    debug!("Connected to upstream server {}", dest_addr);

    let root_store =
        rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let client_config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let tls_connector = TlsConnector::from(Arc::new(client_config));

    let server_name =
        ServerName::try_from(dest_host.to_string()).context("Invalid server name for TLS")?;

    let upstream_tls_stream = tls_connector
        .connect(server_name, upstream_tcp)
        .await
        .context("TLS handshake with upstream server failed")?;

    Log::to(&status_tx).info(format!(
        "MITM upstream TLS handshake complete for {}",
        dest_host
    ));
    Ok(upstream_tls_stream)
}

/// Extract HTTP status code from response line
fn extract_status_code(line: &str) -> Option<u16> {
    // Expected format: "HTTP/1.1 200 OK"
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() >= 2 {
        parts[1].parse().ok()
    } else {
        None
    }
}

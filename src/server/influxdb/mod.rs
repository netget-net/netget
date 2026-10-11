//! One-request-per-connection HTTP/1.1 InfluxDB endpoint with owned tasks: v2 writes, Flux
//! queries at `/api/v2/query`, InfluxQL at the v1-compatible `/query`, and `/ping`.
pub mod actions;
pub mod codec;
pub mod query;
use crate::protocol::{Event, SpawnContext};
use crate::server::{
    accept_bounded::{accept_bounded, ConnectionLimiter, DEFAULT_MAX_CONNECTIONS},
    connection::ConnectionId,
};
use crate::state::{
    server::{ConnectionState, ConnectionStatus, ProtocolConnectionInfo},
    AccessLogOwner,
};
use crate::{console_error, console_info};
use anyhow::{ensure, Context, Result};
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::{
    body::Incoming,
    header::{HeaderValue, ALLOW, AUTHORIZATION, CONTENT_ENCODING, CONTENT_TYPE, RETRY_AFTER},
    server::conn::http1,
    service::service_fn,
    Method, Request, Response, StatusCode,
};
use hyper_util::rt::{TokioIo, TokioTimer};
use serde_json::json;
use std::{collections::BTreeMap, convert::Infallible, net::SocketAddr, sync::Arc, time::Duration};
use tokio::sync::Notify;

pub const HEADER_TIMEOUT: Duration = Duration::from_secs(30);
pub const BODY_TIMEOUT: Duration = Duration::from_secs(30);
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(10);
pub const MAX_HEADER_BYTES: usize = 32 * 1024;
pub const MAX_HEADERS: usize = 64;
const CAP_REFUSAL:&[u8]=b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\nRetry-After: 5\r\n\r\n";
#[derive(Clone)]
struct Config {
    token: Option<String>,
    llm_fallback: bool,
}
pub struct InfluxDbServer;
impl InfluxDbServer {
    pub async fn spawn(ctx: SpawnContext) -> Result<SocketAddr> {
        let token = ctx
            .startup_params
            .as_ref()
            .map(|p| p.get_optional_string("auth_token"))
            .transpose()?
            .flatten();
        if let Some(token) = &token {
            codec::validate_token(token)?;
        }
        let llm_fallback = ctx
            .startup_params
            .as_ref()
            .map(|p| p.get_optional_bool("llm_fallback"))
            .transpose()?
            .flatten()
            .unwrap_or(codec::DEFAULT_LLM_FALLBACK);
        let config = Arc::new(Config {
            token,
            llm_fallback,
        });
        let listener = tokio::net::TcpListener::bind(ctx.legacy_listen_addr()).await?;
        let local = listener.local_addr()?;
        console_info!(
            ctx.status_tx,
            "InfluxDB v2 write listening on {} (auth_required={},llm_fallback={})",
            local,
            config.token.is_some(),
            llm_fallback
        );
        let owner = ctx.state.clone();
        let server_id = ctx.server_id;
        owner.spawn_server_task(server_id,async move {
            let limiter=ConnectionLimiter::new(DEFAULT_MAX_CONNECTIONS);
            loop {
                let (stream,peer,permit)=match accept_bounded(&listener,&limiter,CAP_REFUSAL,"InfluxDB",Some(&ctx.status_tx)).await {
                    Ok(value)=>value,
                    Err(error)=>{console_error!(ctx.status_tx,"InfluxDB accept failed: {}",error);break;}
                };
                let id=ConnectionId::new(ctx.state.get_next_unified_id().await);
                let now=crate::utils::clock::Instant::now();
                ctx.state.add_connection_to_server(server_id,ConnectionState {id,remote_addr:peer,local_addr:local,bytes_sent:0,bytes_received:0,packets_sent:0,packets_received:0,last_activity:now,status:ConnectionStatus::Active,status_changed_at:now,protocol_info:ProtocolConnectionInfo::empty()}).await;
                let child_ctx=ctx.clone(); let config=config.clone();
                ctx.state.spawn_server_task(server_id,async move {
                    let _permit=permit;
                    let write_ready=Arc::new(Notify::new());
                    let service_ready=write_ready.clone();
                    let request_ctx=child_ctx.clone();
                    let service=service_fn(move |request| {
                        let ctx=request_ctx.clone(); let config=config.clone(); let ready=service_ready.clone();
                        async move {
                            let response=handle_request(request,peer,id,&ctx,&config).await;
                            ready.notify_one();
                            Ok::<_,Infallible>(response)
                        }
                    });
                    let mut builder=http1::Builder::new();
                    builder.keep_alive(false).timer(TokioTimer::new()).header_read_timeout(HEADER_TIMEOUT).max_headers(MAX_HEADERS).max_buf_size(MAX_HEADER_BYTES);
                    let connection=builder.serve_connection(TokioIo::new(stream),service);
                    tokio::pin!(connection);
                    tokio::select! {
                        result=&mut connection=>{if let Err(error)=result {console_error!(child_ctx.status_tx,"InfluxDB HTTP framing/header error: {}",error);}}
                        _=async {write_ready.notified().await;tokio::time::sleep(WRITE_TIMEOUT).await;}=>{console_error!(child_ctx.status_tx,"InfluxDB decision=fail_closed_response_write_timeout");}
                    }
                    child_ctx.state.remove_connection_from_server(server_id,id).await;
                    let _=child_ctx.status_tx.send("__UPDATE_UI__".into());
                }).await;
            }
        }).await;
        Ok(local)
    }
}
fn response(status: u16, body: serde_json::Value, retry: Option<u16>) -> Response<Full<Bytes>> {
    let bytes = if status == 204 {
        Vec::new()
    } else {
        serde_json::to_vec(&body).unwrap_or_default()
    };
    let mut r = Response::new(Full::new(Bytes::from(bytes)));
    *r.status_mut() = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    r.headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    if let Some(n) = retry {
        if let Ok(v) = HeaderValue::from_str(&n.to_string()) {
            r.headers_mut().insert(RETRY_AFTER, v);
        }
    }
    r
}
fn code(status: u16) -> &'static str {
    match status {
        400 => "invalid",
        401 => "unauthorized",
        403 => "forbidden",
        404 => "not found",
        405 => "method not allowed",
        408 => "request timeout",
        413 => "request too large",
        415 => "unsupported media type",
        422 => "unprocessable entity",
        429 => "too many requests",
        503 => "unavailable",
        _ => "internal error",
    }
}
fn error(status: u16, message: &str) -> Response<Full<Bytes>> {
    response(status, json!({"code":code(status),"message":message}), None)
}
pub(crate) fn query_piece(s: &str) -> Result<String> {
    let b = s.as_bytes();
    let mut at = 0;
    let mut out = Vec::new();
    while at < b.len() {
        match b[at] {
            b'+' => {
                out.push(b' ');
                at += 1;
            }
            b'%' => {
                let pair = b.get(at + 1..at + 3).context("truncated query escape")?;
                let hex = std::str::from_utf8(pair)?;
                out.push(u8::from_str_radix(hex, 16).context("invalid query escape")?);
                at += 3;
            }
            c => {
                out.push(c);
                at += 1;
            }
        }
    }
    Ok(String::from_utf8(out)?)
}
fn targets(query: Option<&str>) -> Result<(String, String, codec::Precision)> {
    let mut params = BTreeMap::new();
    for field in query.context("org and bucket required")?.split('&') {
        let (key, value) = field
            .split_once('=')
            .context("query parameter requires value")?;
        let key = query_piece(key)?;
        let value = query_piece(value)?;
        ensure!(
            ["org", "bucket", "precision"].contains(&key.as_str()),
            "unsupported query parameter"
        );
        ensure!(
            params.insert(key, value).is_none(),
            "duplicate query parameter"
        );
    }
    let org = params
        .remove("org")
        .context("org required (orgID query not implemented)")?;
    let bucket = params.remove("bucket").context("bucket required")?;
    codec::validate_target(&org)?;
    codec::validate_target(&bucket)?;
    let precision =
        codec::Precision::parse(params.get("precision").map(String::as_str).unwrap_or("ns"))?;
    Ok((org, bucket, precision))
}
fn authorized(headers: &hyper::HeaderMap, expected: Option<&str>) -> bool {
    let Some(expected) = expected else {
        return true;
    };
    let values = headers.get_all(AUTHORIZATION).iter().collect::<Vec<_>>();
    if values.len() != 1 {
        return false;
    }
    let Some((scheme, token)) = values[0].to_str().ok().and_then(|v| v.split_once(' ')) else {
        return false;
    };
    if !["Token", "Bearer"].contains(&scheme) || codec::validate_token(token).is_err() {
        return false;
    }
    same_secret(expected, token)
}
/// Compare in time independent of where the first difference is.
fn same_secret(expected: &str, offered: &str) -> bool {
    let mut difference = expected.len() ^ offered.len();
    for at in 0..expected.len().max(offered.len()) {
        difference |= usize::from(
            expected.as_bytes().get(at).copied().unwrap_or(0)
                ^ offered.as_bytes().get(at).copied().unwrap_or(0),
        );
    }
    difference == 0
}
/// A query's credential: the `Token`/`Bearer` header, or for InfluxQL the v1 forms InfluxDB 2
/// accepts in its compatibility API — the token as the `p` parameter, or as the password of
/// HTTP Basic authentication. The user name is not checked, as InfluxDB 2 does not check it.
fn query_authorized(
    headers: &hyper::HeaderMap,
    request: &query::QueryRequest,
    expected: Option<&str>,
) -> bool {
    let Some(expected) = expected else {
        return true;
    };
    if authorized(headers, Some(expected)) {
        return true;
    }
    if request.language != query::Language::Influxql {
        return false;
    }
    if let Some(p) = &request.v1_password {
        return same_secret(expected, p);
    }
    let values = headers.get_all(AUTHORIZATION).iter().collect::<Vec<_>>();
    let [value] = values.as_slice() else {
        return false;
    };
    let Some(encoded) = value.to_str().ok().and_then(|v| v.strip_prefix("Basic ")) else {
        return false;
    };
    use base64::Engine as _;
    let Some(decoded) = base64::engine::general_purpose::STANDARD
        .decode(encoded.trim())
        .ok()
        .and_then(|d| String::from_utf8(d).ok())
    else {
        return false;
    };
    decoded
        .split_once(':')
        .is_some_and(|(_, password)| same_secret(expected, password))
}
fn decide(
    decision: actions::Decision,
    parsed: &codec::ParsedBatch,
) -> Result<Response<Full<Bytes>>> {
    let total = parsed.points.len() + parsed.errors.len();
    let (accepted, message) = match decision {
        actions::Decision::Reject {
            status,
            message,
            retry_after_seconds,
        } => {
            return Ok(response(
                status,
                json!({"code":code(status),"message":message,"accepted_points":0,"rejected_points":total}),
                retry_after_seconds,
            ))
        }
        actions::Decision::Accept => (
            parsed.points.iter().map(|p| p.line).collect::<Vec<_>>(),
            "Invalid line protocol".to_string(),
        ),
        actions::Decision::Partial {
            accepted_lines,
            message,
        } => {
            ensure!(
                accepted_lines
                    .iter()
                    .all(|n| parsed.points.iter().any(|p| p.line == *n)),
                "cannot accept a missing/invalid source line"
            );
            (accepted_lines, message)
        }
    };
    if accepted.len() == total && parsed.errors.is_empty() {
        return Ok(response(204, serde_json::Value::Null, None));
    }
    let line = parsed.errors.first().map(|e| e.line).or_else(|| {
        parsed
            .points
            .iter()
            .find(|p| !accepted.contains(&p.line))
            .map(|p| p.line)
    });
    Ok(response(
        400,
        json!({"code":"invalid","message":format!("partial write: {message}; accepted={} rejected={}",accepted.len(),total-accepted.len()),"line":line,"accepted_points":accepted.len(),"rejected_points":total-accepted.len()}),
        None,
    ))
}
async fn handle_request(
    request: Request<Incoming>,
    peer: SocketAddr,
    id: ConnectionId,
    ctx: &SpawnContext,
    config: &Config,
) -> Response<Full<Bytes>> {
    let (parts, body) = request.into_parts();
    let bytes = match tokio::time::timeout(
        BODY_TIMEOUT,
        Limited::new(body, codec::MAX_BODY_BYTES).collect(),
    )
    .await
    {
        Err(_) => return error(408, "Request body deadline exceeded"),
        Ok(Err(error)) => {
            return if error
                .downcast_ref::<http_body_util::LengthLimitError>()
                .is_some()
            {
                self::error(413, "Request body limit exceeded")
            } else {
                self::error(400, "Incomplete HTTP body")
            };
        }
        Ok(Ok(body)) => body.to_bytes(),
    };
    ctx.state
        .update_connection_stats(
            ctx.server_id,
            id,
            Some(bytes.len() as u64),
            None,
            Some(1),
            None,
        )
        .await;
    match parts.uri.path() {
        "/api/v2/write" => {}
        "/api/v2/query" => {
            return handle_query(&parts, &bytes, peer, id, ctx, config, query::Language::Flux).await
        }
        "/query" => {
            return handle_query(
                &parts,
                &bytes,
                peer,
                id,
                ctx,
                config,
                query::Language::Influxql,
            )
            .await
        }
        "/ping" => return ping(&parts.method),
        _ => {
            return error(
                404,
                "Only /api/v2/write, /api/v2/query, /query and /ping are served",
            )
        }
    }
    if parts.method != Method::POST {
        let mut r = error(405, "Only POST is supported");
        r.headers_mut()
            .insert(ALLOW, HeaderValue::from_static("POST"));
        return r;
    }
    let (org,bucket,precision)=match targets(parts.uri.query()) {Ok(v)=>v,Err(_)=>return error(400,"org, bucket and optional ns/us/ms/s precision required; invalid/duplicate/unsupported query")};
    if !authorized(&parts.headers, config.token.as_deref()) {
        return error(401, "unauthorized access");
    }
    if parts.headers.get_all(CONTENT_ENCODING).iter().count() > 1
        || parts.headers.get_all(CONTENT_TYPE).iter().count() > 1
    {
        return error(400, "Duplicate encoding/content type headers");
    }
    if let Some(ct) = parts.headers.get(CONTENT_TYPE) {
        let valid = ct.to_str().ok().is_some_and(|s| {
            let mut p = s.split(';');
            p.next()
                .is_some_and(|mime| mime.trim().eq_ignore_ascii_case("text/plain"))
                && p.all(|x| x.trim().eq_ignore_ascii_case("charset=utf-8"))
        });
        if !valid {
            return error(415, "Expected text/plain UTF-8 line protocol");
        }
    }
    let encoding = match parts
        .headers
        .get(CONTENT_ENCODING)
        .map(|v| v.to_str())
        .transpose()
    {
        Ok(Some(v)) => v,
        Ok(None) => "identity",
        Err(_) => return error(415, "Invalid content encoding"),
    };
    if !["identity", "gzip"].contains(&encoding) {
        return error(415, "Only identity/gzip encoding supported");
    }
    let body = match codec::decode_body(&bytes, encoding) {
        Ok(b) => b,
        Err(e) => {
            return error(
                if e.to_string().contains("byte limit") {
                    413
                } else {
                    400
                },
                "Malformed or oversized compressed body",
            )
        }
    };
    let received_ns = crate::utils::clock::SystemTime::now()
        .duration_since(crate::utils::clock::UNIX_EPOCH)
        .ok()
        .and_then(|t| i64::try_from(t.as_nanos()).ok());
    let Some(received_ns) = received_ns else {
        return error(500, "Receiver clock out of range");
    };
    let parsed = match codec::parse_batch(&body, precision, received_ns) {
        Ok(batch) => batch,
        Err(e) => {
            return error(
                if e.to_string().contains("limit") {
                    413
                } else {
                    400
                },
                "Invalid/oversized line protocol batch",
            )
        }
    };
    let event = Event::new(
        &actions::INFLUX_WRITE_EVENT,
        json!({"org":org,"bucket":bucket,"precision":precision,"points":parsed.points,"errors":parsed.errors,"authenticated":true,"auth_required":config.token.is_some(),"source_addr":peer.to_string()}),
    );
    let configured = ctx
        .state
        .get_event_handler_config(ctx.server_id)
        .await
        .is_some_and(|c| c.find_handler("influx_write").is_some());
    let decision = if configured || config.llm_fallback {
        match crate::llm::action_helper::call_llm(
            &ctx.llm_client,
            &ctx.state,
            ctx.server_id,
            Some(id),
            &event,
            &actions::InfluxDbProtocol::new(),
        )
        .await
        {
            Ok(result) if result.failures.is_empty() => {
                let decisions = result
                    .protocol_results
                    .iter()
                    .filter_map(|r| match r {
                        crate::llm::ActionResult::Custom { name, data }
                            if name == "influx_write_decision" =>
                        {
                            Some(data.clone())
                        }
                        _ => None,
                    })
                    .collect::<Vec<_>>();
                if decisions.len() > 1 {
                    return failed(ctx, id, event.data, "fail_closed_multiple_decisions").await;
                }
                match decisions
                    .first()
                    .map(|d| serde_json::from_value::<actions::Decision>(d.clone()))
                    .transpose()
                {
                    Ok(Some(d)) => d,
                    Ok(None) => actions::Decision::Accept,
                    Err(_) => {
                        return failed(ctx, id, event.data, "fail_closed_invalid_decision").await
                    }
                }
            }
            Ok(_) => return failed(ctx, id, event.data, "fail_closed_handler_action_error").await,
            Err(_) => return failed(ctx, id, event.data, "fail_closed_handler_error").await,
        }
    } else {
        ctx.state
            .record_access_log(
                AccessLogOwner::Server(ctx.server_id.as_u32()),
                "InfluxDB",
                Some(id.as_u32()),
                "influx_write",
                event.data.clone(),
                vec![json!({"type":"accept_influx_points"})],
            )
            .await;
        actions::Decision::Accept
    };
    match decide(decision, &parsed) {
        Ok(r) => r,
        Err(_) => failed(ctx, id, event.data, "fail_closed_invalid_partial_decision").await,
    }
}
async fn failed(
    ctx: &SpawnContext,
    id: ConnectionId,
    data: serde_json::Value,
    decision: &str,
) -> Response<Full<Bytes>> {
    console_error!(ctx.status_tx, "InfluxDB decision={}", decision);
    ctx.state
        .record_access_log(
            AccessLogOwner::Server(ctx.server_id.as_u32()),
            "InfluxDB",
            Some(id.as_u32()),
            "influx_handler_failed",
            data,
            vec![json!({"decision":decision})],
        )
        .await;
    error(503, "Write handler failed; no acceptance confirmed")
}

/// `GET|HEAD /ping`: 204, as InfluxDB answers it, naming what answered.
fn ping(method: &Method) -> Response<Full<Bytes>> {
    if method != Method::GET && method != Method::HEAD {
        let mut r = error(405, "Only GET and HEAD are supported");
        r.headers_mut()
            .insert(ALLOW, HeaderValue::from_static("GET, HEAD"));
        return r;
    }
    let mut r = response(204, serde_json::Value::Null, None);
    r.headers_mut().remove(CONTENT_TYPE);
    r.headers_mut()
        .insert("X-Influxdb-Version", HeaderValue::from_static("netget"));
    r.headers_mut()
        .insert("X-Influxdb-Build", HeaderValue::from_static("OSS"));
    r
}
/// An error in the dialect's own shape: v2's `{"code","message"}` for Flux, v1's `{"error"}`
/// for InfluxQL.
fn query_error(language: query::Language, status: u16, message: &str) -> Response<Full<Bytes>> {
    match language {
        query::Language::Flux => error(status, message),
        query::Language::Influxql => response(status, json!({ "error": message }), None),
    }
}
fn body_response(status: u16, content_type: &'static str, body: Vec<u8>) -> Response<Full<Bytes>> {
    let mut r = Response::new(Full::new(Bytes::from(body)));
    *r.status_mut() = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    r.headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static(content_type));
    r
}
async fn handle_query(
    parts: &hyper::http::request::Parts,
    body: &[u8],
    peer: SocketAddr,
    id: ConnectionId,
    ctx: &SpawnContext,
    config: &Config,
    language: query::Language,
) -> Response<Full<Bytes>> {
    let allowed = match language {
        query::Language::Flux => parts.method == Method::POST,
        query::Language::Influxql => parts.method == Method::POST || parts.method == Method::GET,
    };
    if !allowed {
        let mut r = query_error(
            language,
            405,
            "Method not supported for this query endpoint",
        );
        let allow = match language {
            query::Language::Flux => "POST",
            query::Language::Influxql => "GET, POST",
        };
        r.headers_mut()
            .insert(ALLOW, HeaderValue::from_static(allow));
        return r;
    }
    if parts
        .headers
        .get(CONTENT_ENCODING)
        .is_some_and(|e| !e.as_bytes().eq_ignore_ascii_case(b"identity"))
    {
        return query_error(language, 415, "Compressed query bodies are not accepted");
    }
    let content_type = parts
        .headers
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok());
    let parsed = match language {
        query::Language::Flux => query::parse_flux(parts.uri.query(), content_type, body),
        query::Language::Influxql => query::parse_influxql(parts.uri.query(), content_type, body),
    };
    let request = match parsed {
        Ok(request) => request,
        Err(e) => {
            return query_error(
                language,
                400,
                &crate::utils::truncate_for_log(&e.to_string(), 512),
            )
        }
    };
    if !query_authorized(&parts.headers, &request, config.token.as_deref()) {
        return query_error(language, 401, "unauthorized access");
    }
    let mut data = serde_json::to_value(&request).unwrap_or_else(|_| json!({}));
    data["authenticated"] = json!(true);
    data["auth_required"] = json!(config.token.is_some());
    data["source_addr"] = json!(peer.to_string());
    let event = Event::new(&actions::INFLUX_QUERY_EVENT, data);
    let configured = ctx
        .state
        .get_event_handler_config(ctx.server_id)
        .await
        .is_some_and(|c| c.find_handler("influx_query").is_some());
    if !configured && !config.llm_fallback {
        // Nothing here holds data, so without a handler or the model there is no answer — and
        // an empty result would be an assertion that there is no data, which nobody made.
        return query_failed(
            ctx,
            id,
            event.data,
            language,
            "fail_closed_no_query_handler",
        )
        .await;
    }
    let answers = match crate::llm::action_helper::call_llm(
        &ctx.llm_client,
        &ctx.state,
        ctx.server_id,
        Some(id),
        &event,
        &actions::InfluxDbProtocol::new(),
    )
    .await
    {
        Ok(result) if result.failures.is_empty() => result
            .protocol_results
            .iter()
            .filter_map(|r| match r {
                crate::llm::ActionResult::Custom { name, data }
                    if name == actions::QUERY_ANSWER =>
                {
                    Some(data.clone())
                }
                _ => None,
            })
            .collect::<Vec<_>>(),
        Ok(_) => {
            return query_failed(
                ctx,
                id,
                event.data,
                language,
                "fail_closed_handler_action_error",
            )
            .await
        }
        Err(_) => {
            return query_failed(ctx, id, event.data, language, "fail_closed_handler_error").await
        }
    };
    let answer = match answers.as_slice() {
        [answer] => answer,
        [] => return query_failed(ctx, id, event.data, language, "fail_closed_no_answer").await,
        _ => {
            return query_failed(
                ctx,
                id,
                event.data,
                language,
                "fail_closed_multiple_answers",
            )
            .await
        }
    };
    match render_answer(answer, &request) {
        Ok(response) => response,
        Err(_) => query_failed(ctx, id, event.data, language, "fail_closed_invalid_answer").await,
    }
}
/// Render the model's answer in the request's dialect.
fn render_answer(
    answer: &serde_json::Value,
    request: &query::QueryRequest,
) -> Result<Response<Full<Bytes>>> {
    if answer["mode"] == "error" {
        let status = u16::try_from(answer["status"].as_u64().context("status")?)?;
        let message = answer["message"].as_str().context("message")?;
        return Ok(query_error(request.language, status, message));
    }
    let action = &answer["action"];
    match request.language {
        query::Language::Flux => {
            ensure!(
                action.get("statements").is_none(),
                "a Flux query is answered with 'tables', not 'statements'"
            );
            let tables =
                query::tables_from_json(action.get("tables").context("tables")?, &mut 0, &mut 0)?;
            Ok(body_response(
                200,
                "text/csv; charset=utf-8",
                query::render_flux(&tables)?.into_bytes(),
            ))
        }
        query::Language::Influxql => {
            let results = query::statements_from_json(action)?;
            ensure!(
                results.len() == request.statements.len(),
                "{} answers for {} statements",
                results.len(),
                request.statements.len()
            );
            Ok(body_response(
                200,
                "application/json",
                query::render_influxql(&results, request.epoch.as_deref())?,
            ))
        }
    }
}
async fn query_failed(
    ctx: &SpawnContext,
    id: ConnectionId,
    data: serde_json::Value,
    language: query::Language,
    decision: &str,
) -> Response<Full<Bytes>> {
    console_error!(ctx.status_tx, "InfluxDB query decision={}", decision);
    ctx.state
        .record_access_log(
            AccessLogOwner::Server(ctx.server_id.as_u32()),
            "InfluxDB",
            Some(id.as_u32()),
            "influx_query_failed",
            data,
            vec![json!({ "decision": decision })],
        )
        .await;
    query_error(
        language,
        503,
        "Query handler failed; no answer is available",
    )
}

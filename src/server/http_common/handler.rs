//! Shared HTTP request/response handling logic

use crate::console_trace;
use crate::llm::ActionResult;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::{Request, Response};
use std::collections::HashMap;
use std::convert::Infallible;
use tokio::sync::mpsc;
use tracing::{debug, error, trace, warn};

/// Extracted request data common to HTTP and HTTP/2
#[derive(Debug)]
pub struct RequestData {
    pub method: String,
    pub uri: String,
    pub version: String,
    pub headers: HashMap<String, String>,
    pub body_bytes: Bytes,
}

/// How much of a request body is read before the request is refused with 413.
///
/// The body is buffered whole and then embedded in an LLM prompt, so there is no
/// legitimate use for a large one: a model cannot read 10 MB, and every byte past a
/// few kilobytes is cost without benefit. Without a cap the buffer is whatever the
/// peer chooses to send — `Incoming` has no default limit — so a single unauthenticated
/// `POST` could exhaust the process's memory. Refusing early is both the safe and the
/// honest answer, and 413 is the code that says exactly that.
pub const MAX_REQUEST_BODY_BYTES: usize = 8 * 1024 * 1024;

/// The request body exceeded [`MAX_REQUEST_BODY_BYTES`] (or could not be read).
///
/// Deliberately a distinct type rather than an empty body: a truncated body handed to
/// the model looks like a complete one, and the model would answer a request it never
/// actually saw.
#[derive(Debug)]
pub struct BodyTooLarge {
    pub method: String,
    pub uri: String,
}

/// Extract request data from hyper Request.
///
/// The body is bounded by [`MAX_REQUEST_BODY_BYTES`]; a larger one yields
/// [`BodyTooLarge`] and the caller answers 413 without spending an LLM call.
pub async fn extract_request_data(
    req: Request<Incoming>,
    protocol_label: &str,
    status_tx: &mpsc::UnboundedSender<String>,
) -> Result<RequestData, BodyTooLarge> {
    // Extract request details first for logging
    let method = req.method().to_string();
    // Only use path+query portion (not scheme/host) for event data
    let uri = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or(req.uri().path())
        .to_string();
    let version = format!("{:?}", req.version());

    // Extract headers
    let mut headers = HashMap::new();
    for (name, value) in req.headers() {
        if let Ok(value_str) = value.to_str() {
            headers.insert(name.to_string(), value_str.to_string());
        }
    }

    // Read body, bounded. `Limited` errors as soon as the cap is passed rather than
    // after buffering the whole thing, so an oversized upload costs at most the cap.
    let limited = http_body_util::Limited::new(req.into_body(), MAX_REQUEST_BODY_BYTES);
    let body_bytes = match limited.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(e) => {
            error!(
                "{} {} {}: refusing request body ({}); limit is {} bytes",
                protocol_label, method, uri, e, MAX_REQUEST_BODY_BYTES
            );
            let _ = status_tx.send(format!(
                "✗ {} {} {} → 413 (request body over {} bytes)",
                protocol_label, method, uri, MAX_REQUEST_BODY_BYTES
            ));
            return Err(BodyTooLarge { method, uri });
        }
    };

    // DEBUG: Log request summary to both file and TUI
    debug!(
        "{} request (action-based): {} {} {} ({} bytes)",
        protocol_label,
        method,
        uri,
        version,
        body_bytes.len(),
    );
    let _ = status_tx.send(format!(
        "[DEBUG] {} request: {} {} {} ({} bytes)",
        protocol_label,
        method,
        uri,
        version,
        body_bytes.len()
    ));

    // TRACE: Log full request details
    trace!("{} request headers:", protocol_label);
    for (name, value) in &headers {
        trace!("  {}: {}", name, value);
        let _ = status_tx.send(format!(
            "[TRACE] {} header: {}: {}",
            protocol_label, name, value
        ));
    }
    if !body_bytes.is_empty() {
        if let Ok(body_str) = std::str::from_utf8(&body_bytes) {
            // Try to pretty-print if it's JSON
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(body_str) {
                let pretty = serde_json::to_string_pretty(&json).unwrap_or(body_str.to_string());
                trace!("{} request body (JSON):\n{}", protocol_label, pretty);
                let _ = status_tx.send(format!(
                    "[TRACE] {} request body (JSON):\r\n{}",
                    protocol_label,
                    pretty.replace('\n', "\r\n")
                ));
            } else {
                trace!("{} request body:\n{}", protocol_label, body_str);
                let _ = status_tx.send(format!(
                    "[TRACE] {} request body:\r\n{}",
                    protocol_label,
                    body_str.replace('\n', "\r\n")
                ));
            }
        } else {
            console_trace!(
                status_tx,
                "{} request body (binary): {} bytes",
                protocol_label,
                body_bytes.len()
            );
        }
    }

    Ok(RequestData {
        method,
        uri,
        version,
        headers,
        body_bytes,
    })
}

/// The 413 answer for a request whose body exceeded [`MAX_REQUEST_BODY_BYTES`].
///
/// Static text: nothing derived from the request or from an internal error reaches the
/// peer, only the fact and the limit.
pub fn build_payload_too_large_response(
    too_large: &BodyTooLarge,
    protocol_label: &str,
    status_tx: &mpsc::UnboundedSender<String>,
) -> Response<Full<Bytes>> {
    warn!(
        "{} {} {} decision=refused_body_too_large: over {} bytes",
        protocol_label, too_large.method, too_large.uri, MAX_REQUEST_BODY_BYTES
    );
    let _ = status_tx.send(format!(
        "→ {} {} {} → 413",
        protocol_label, too_large.method, too_large.uri
    ));
    build_safe_response(
        413,
        [("Content-Type".to_string(), "text/plain".to_string())],
        format!(
            "Payload Too Large: request bodies are limited to {} bytes\n",
            MAX_REQUEST_BODY_BYTES
        ),
        protocol_label,
    )
}

/// Build a hyper `Response` from parts that came from the LLM or from server
/// startup params, without ever panicking.
///
/// Everything here is attacker- or model-influenced, so nothing is trusted:
///
/// - an out-of-range status (`status < 100 || status > 599`) is replaced by 500,
/// - header names/values hyper rejects (notably ones containing CR/LF, i.e.
///   response-splitting attempts) are dropped individually,
/// - if the builder still fails for any reason, a bare 500 is returned.
///
/// The previous implementation ended in `.body(..).unwrap()`, which turned any
/// of the above into a panic inside the connection task.
pub fn build_safe_response(
    status: u16,
    headers: impl IntoIterator<Item = (String, String)>,
    body: String,
    context: &str,
) -> Response<Full<Bytes>> {
    let status_code = match hyper::StatusCode::from_u16(status) {
        Ok(code) => code,
        Err(_) => {
            error!(
                "{}: invalid HTTP status {} (must be 100-599), sending 500 instead",
                context, status
            );
            hyper::StatusCode::INTERNAL_SERVER_ERROR
        }
    };

    let mut builder = Response::builder().status(status_code);
    for (name, value) in headers {
        match (
            hyper::header::HeaderName::from_bytes(name.as_bytes()),
            hyper::header::HeaderValue::from_str(&value),
        ) {
            (Ok(n), Ok(v)) => builder = builder.header(n, v),
            _ => warn!(
                "{}: dropping invalid response header {:?} (name or value is not a legal HTTP header)",
                context, name
            ),
        }
    }

    match builder.body(Full::new(Bytes::from(body))) {
        Ok(response) => response,
        Err(e) => {
            error!(
                "{}: failed to build response ({}), sending bare 500",
                context, e
            );
            let mut fallback =
                Response::new(Full::new(Bytes::from_static(b"Internal Server Error")));
            *fallback.status_mut() = hyper::StatusCode::INTERNAL_SERVER_ERROR;
            fallback
        }
    }
}

/// Walk `results` in order, handing every `Output` payload to `visit`.
///
/// `ActionResult::Multiple` nests, and flattening it is not cosmetic: an `Output` inside a
/// `Multiple` used to be skipped outright, so the request fell through to the fallback as
/// though the model had said nothing. HTTP's own executor never produces `Multiple` today —
/// which is why this went unnoticed — but nine protocols elsewhere in the tree do, and
/// `src/server/vnc/mod.rs`, `jsonrpc`, `openvpn` and `usb/smartcard` each hand-rolled a
/// flatten for exactly this reason.
/// How deep a `Multiple` may nest before this stops descending.
///
/// Only one place in the tree constructs a `Multiple` today (`src/server/xmpp/actions.rs`) and
/// it does not nest, so the recursion below cannot currently run away. The bound is here
/// anyway, because the cost of being wrong about that is not a wrong answer: a Rust stack
/// overflow is a SIGSEGV against the guard page, not a panic, so `catch_unwind` cannot see it
/// and `tokio::spawn` cannot contain it — **the whole NetGet process dies, taking every other
/// server in it.** This tree has had six of those.
///
/// 8 is far above anything a real executor produces; the deepest today is 1.
const MAX_RESULT_NESTING: usize = 8;

fn for_each_output(results: &[ActionResult], visit: &mut impl FnMut(&[u8])) {
    for_each_output_at(results, 0, visit)
}

fn for_each_output_at(results: &[ActionResult], depth: usize, visit: &mut impl FnMut(&[u8])) {
    if depth >= MAX_RESULT_NESTING {
        // Refuse to descend rather than unwinding the whole reply: the outputs already
        // visited are real and the peer should still get them.
        tracing::warn!(
            "http_common: result nesting deeper than {MAX_RESULT_NESTING}, not descending \
             further. An executor is producing nested Multiple results; the outputs found so \
             far are still used."
        );
        return;
    }
    for result in results {
        match result {
            ActionResult::Output(data) => visit(data),
            ActionResult::Multiple(inner) => for_each_output_at(inner, depth + 1, visit),
            _ => {}
        }
    }
}

/// Did the model produce a usable `send_http_response`?
///
/// True when some `Output` payload parses as JSON — the same condition [`build_response`]
/// uses to decide whether to answer from the model or fall back to the server's
/// `default_response` (or, with none configured, a `500`).
///
/// It is public because the *caller* is where that outcome has to be logged: `build_response`
/// is shared by every HTTP-shaped protocol and cannot know what any one of them wants to say
/// about it. Callers use this rather than re-deriving the predicate, so the log line and the
/// bytes on the wire cannot drift apart — a tag claiming the model answered while the peer
/// received the fallback would be worse than no tag at all.
pub fn produced_http_response(results: &[ActionResult]) -> bool {
    let mut produced = false;
    for_each_output(results, &mut |data| {
        if serde_json::from_slice::<serde_json::Value>(data).is_ok() {
            produced = true;
        }
    });
    produced
}

/// Build HTTP response from LLM execution results
pub fn build_response(
    protocol_results: Vec<ActionResult>,
    protocol_label: &str,
    method: &str,
    uri: &str,
    status_tx: &mpsc::UnboundedSender<String>,
    // Fallback for when the model produced no `send_http_response` — the server's
    // `default_response` startup param, as `(status, headers, body)`. With `None` the
    // request is refused with a `500` (see below).
    default_response: Option<(u16, Vec<(String, String)>, String)>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    // Default response in case nothing was produced
    let mut status_code = 200;
    let mut response_headers = HashMap::new();
    let mut response_body = String::new();
    let mut produced_response = false;

    // Nested `Multiple` results are walked too — see `for_each_output`. An `Output` buried in
    // one used to be dropped, which read to the caller as a silent model.
    for_each_output(&protocol_results, &mut |output_data| {
        // Parse the output as JSON containing HTTP response fields
        if let Ok(json_value) = serde_json::from_slice::<serde_json::Value>(output_data) {
            produced_response = true;
            if let Some(status) = json_value.get("status").and_then(|v| v.as_u64()) {
                // `status as u16` truncates, and `65736 as u16` is `200` — a nonsense status
                // silently becoming a success. `build_safe_response` below rejects anything
                // outside 100-599, so keep the value out of range rather than wrapping it
                // into a plausible one.
                status_code = u16::try_from(status).unwrap_or(500);
            }
            if let Some(headers_obj) = json_value.get("headers").and_then(|v| v.as_object()) {
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
    });

    // The model was consulted but returned no send_http_response. The server's configured
    // `default_response` is a deliberate answer for exactly this case and is used when set.
    //
    // Without one the request fails closed with a `500`. Answering `200` with an empty body
    // would make a model that said nothing — or whose action the executor refused —
    // indistinguishable from a model that deliberately answered an empty success, so a client
    // would record an unanswered request as a completed one. `500` with the
    // `WireFailure::Unavailable` category is what a failed backend gets from
    // `build_error_response` and what HTTP/2 (`h2_server.rs`) and OpenAPI answer a silent
    // model with; `503` stays reserved for overload, which this is not, so a client does not
    // retry a request the model will keep declining.
    if !produced_response {
        if let Some((status, headers, body)) = default_response {
            status_code = status;
            response_headers = headers.into_iter().collect();
            response_body = body;
        } else {
            status_code = 500;
            response_headers = HashMap::new();
            response_body = crate::utils::WireFailure::Unavailable
                .prefixed_text()
                .to_string();
        }
    }

    let _ = status_tx.send(format!(
        "→ {} {} {} → {} ({} bytes)",
        protocol_label,
        method,
        uri,
        status_code,
        response_body.len()
    ));

    // Build the HTTP response. Status/headers/body all originate from model
    // output, so this must not be able to panic (see build_safe_response).
    Ok(build_safe_response(
        status_code,
        response_headers,
        response_body,
        protocol_label,
    ))
}

/// Build error response for LLM failures.
///
/// The peer gets a *category*, never the error: `error` is classified by
/// [`crate::utils::WireFailure`] and then only logged. Overload is transient and
/// retryable, which 500 does not say, so it becomes 503 + `Retry-After` and a client
/// backs off instead of recording a permanent server fault — that is the path a second
/// concurrent request takes when `--llm-max-concurrent` is saturated and the queue is
/// full or the wait timed out. Everything else is a 500.
///
/// Both branches carry a `decision=` tag, so an operator reading `netget.log` can tell a
/// saturated backend from a broken one without parsing the error text
/// (`src/server/radius/` is the reference for this).
pub fn build_error_response(
    error: anyhow::Error,
    protocol_label: &str,
    method: &str,
    uri: &str,
    status_tx: &mpsc::UnboundedSender<String>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let failure = crate::utils::WireFailure::classify(&error);
    let (status, decision) = match failure {
        crate::utils::WireFailure::Overloaded => (503, "fail_closed_llm_overloaded"),
        crate::utils::WireFailure::Unavailable => (500, "fail_closed_llm_error"),
    };
    error!(
        "{} {} {} decision={} status={}: {}",
        protocol_label, method, uri, decision, status, error
    );
    // The token goes on both sinks. It used to be on the `error!` alone, so `netget.log`
    // could tell a saturated backend from a broken one and the TUI/MCP status stream — which
    // is what an operator is actually watching, and what the e2e harness reads — could not.
    let _ = status_tx.send(format!(
        "[ERROR] ✗ LLM error for {} {} → {} decision={}: {}",
        method, uri, status, decision, error
    ));

    if status == 503 {
        return Ok(Response::builder()
            .status(503)
            .header(hyper::header::RETRY_AFTER, "1")
            .body(Full::new(Bytes::from(failure.prefixed_text())))
            .unwrap());
    }

    Ok(Response::builder()
        .status(500)
        .body(Full::new(Bytes::from(failure.prefixed_text())))
        .unwrap())
}

// ===== Request filtering =====
//
// A per-server allowlist that decides which requests are worth an LLM call.
// The server declares a `request_filter` in its startup params; a request
// reaches the LLM only if it matches at least one rule. Everything else gets a
// cheap, configurable auto-response (default 404) and never hits the LLM. This
// keeps browser/scanner noise (favicon probes, OPTIONS preflights, asset/XHR
// requests, vuln scans) from wasting slow, billable LLM round-trips.

/// How a single header condition is matched against the request.
#[derive(Debug, Clone)]
enum HeaderExpect {
    /// The header just needs to be present (config value `true`).
    Present,
    /// The header value must contain this substring, case-insensitively
    /// (config value is a string, e.g. `"text/html"`).
    Contains(String),
}

/// A single header match condition. `name` is stored lowercased; request header
/// names (hyper-canonicalised to lowercase) are compared case-insensitively.
#[derive(Debug, Clone)]
struct HeaderMatch {
    name: String,
    expect: HeaderExpect,
}

/// One rule in a `request_filter`. All present conditions must hold (AND); an
/// omitted condition is a wildcard.
#[derive(Debug)]
struct FilterRule {
    /// Allowed request methods (uppercased). `None` = any method.
    methods: Option<Vec<String>>,
    /// Compiled path regex matched against the path (portion before `?`).
    /// `None` = any path.
    path: Option<regex::Regex>,
    /// Header conditions (all must hold).
    headers: Vec<HeaderMatch>,
}

impl FilterRule {
    /// Does this request satisfy every condition in the rule?
    fn matches(&self, req: &RequestData, path: &str) -> bool {
        if let Some(methods) = &self.methods {
            let m = req.method.to_ascii_uppercase();
            if !methods.iter().any(|allowed| allowed == &m) {
                return false;
            }
        }
        if let Some(re) = &self.path {
            if !re.is_match(path) {
                return false;
            }
        }
        for hm in &self.headers {
            // Case-insensitive header-name lookup (request keys are already
            // lowercase, but don't rely on it).
            let value = req
                .headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(&hm.name))
                .map(|(_, v)| v);
            match (&hm.expect, value) {
                (HeaderExpect::Present, Some(_)) => {}
                (HeaderExpect::Contains(needle), Some(v))
                    if v.to_ascii_lowercase()
                        .contains(&needle.to_ascii_lowercase()) => {}
                _ => return false,
            }
        }
        true
    }
}

/// The response returned for requests that match no rule (no LLM call).
#[derive(Debug, Clone)]
struct FilteredResponse {
    status: u16,
    body: String,
    headers: Vec<(String, String)>,
}

impl Default for FilteredResponse {
    fn default() -> Self {
        Self {
            status: 404,
            body: String::new(),
            headers: Vec::new(),
        }
    }
}

/// A per-server request allowlist parsed from `startup_params`.
///
/// With no rules the filter is "pass-through": every request is forwarded to
/// the LLM (unchanged default behavior).
#[derive(Debug)]
pub struct RequestFilter {
    rules: Vec<FilterRule>,
    filtered_response: FilteredResponse,
    /// Canned response used when the model is consulted but produces no
    /// `send_http_response` (an empty action list). With `None` such a request is
    /// refused with a `500`. Set via the `default_response` startup param so a
    /// declined request gets a deliberate answer (e.g. a 404 page) instead.
    default_response: Option<FilteredResponse>,
    /// Human-readable problems found while parsing the config. Callers surface
    /// these on the status channel so a typo is visible in the TUI/MCP stream,
    /// not just in `netget.log`.
    warnings: Vec<String>,
}

impl RequestFilter {
    /// Parse a filter from a server's `startup_params`.
    ///
    /// **Fail-open by design.** A missing `request_filter` yields a pass-through
    /// filter, and any individual malformed rule (or invalid path regex) is
    /// skipped rather than failing the whole server. The consequence is worth
    /// stating plainly: if every rule you wrote is malformed, the filter ends up
    /// empty and *every* request reaches the LLM — slow and billable — instead
    /// of being rejected. Server startup is never failed on a bad filter, so the
    /// only signal is loud logging plus [`RequestFilter::warnings`]; callers are
    /// expected to forward those to the status channel.
    pub fn from_startup_params(params: Option<&serde_json::Value>) -> Self {
        let mut rules = Vec::new();
        let mut warnings = Vec::new();

        match params.and_then(|p| p.get("request_filter")) {
            None | Some(serde_json::Value::Null) => {}
            Some(serde_json::Value::Array(arr)) => {
                for (i, raw) in arr.iter().enumerate() {
                    match Self::parse_rule(raw) {
                        Ok(rule) => rules.push(rule),
                        Err(e) => {
                            let msg =
                                format!("invalid request_filter rule #{}: {} — rule ignored", i, e);
                            error!("{}", msg);
                            warnings.push(msg);
                        }
                    }
                }
                if !arr.is_empty() && rules.is_empty() {
                    let msg = "request_filter was configured but EVERY rule was invalid — \
                               the filter is disabled and every request will reach the LLM \
                               (fail-open)"
                        .to_string();
                    error!("{}", msg);
                    warnings.push(msg);
                }
            }
            Some(other) => {
                let msg = format!(
                    "request_filter must be an array of rule objects, got {} — \
                     filter ignored, every request will reach the LLM (fail-open)",
                    kind_of(other)
                );
                error!("{}", msg);
                warnings.push(msg);
            }
        }

        let filtered_response = params
            .and_then(|p| p.get("filtered_response"))
            .map(|raw| Self::parse_filtered_response(raw, &mut warnings))
            .unwrap_or_default();

        if rules.is_empty() && params.and_then(|p| p.get("filtered_response")).is_some() {
            let msg = "filtered_response is set but no valid request_filter rules exist — \
                       it will never be used"
                .to_string();
            warn!("{}", msg);
            warnings.push(msg);
        }

        // Independent of the filter: what to send when the model is asked and
        // answers with no response action. Absent => a 500 (`build_response`).
        let default_response = params
            .and_then(|p| p.get("default_response"))
            .map(|raw| Self::parse_filtered_response(raw, &mut warnings));

        Self {
            rules,
            filtered_response,
            default_response,
            warnings,
        }
    }

    /// The configured `default_response` as `(status, headers, body)`, or `None`
    /// when there is none and a silent model is answered `500`. Used by
    /// `build_response` when the model produced no `send_http_response`.
    pub fn default_response_parts(&self) -> Option<(u16, Vec<(String, String)>, String)> {
        self.default_response
            .as_ref()
            .map(|r| (r.status, r.headers.clone(), r.body.clone()))
    }

    /// Problems found while parsing the filter config (empty when it is clean).
    /// Every one of these means the filter is doing less than the caller asked.
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    fn parse_rule(raw: &serde_json::Value) -> Result<FilterRule, String> {
        let obj = raw.as_object().ok_or("rule must be an object")?;

        let methods = match obj.get("methods") {
            None | Some(serde_json::Value::Null) => None,
            Some(serde_json::Value::Array(arr)) => Some(
                arr.iter()
                    .filter_map(|m| m.as_str().map(|s| s.to_ascii_uppercase()))
                    .collect::<Vec<_>>(),
            ),
            // Also accept a bare string for convenience: "methods": "GET"
            Some(serde_json::Value::String(s)) => Some(vec![s.to_ascii_uppercase()]),
            Some(_) => return Err("`methods` must be a string or array of strings".into()),
        };

        let path = match obj.get("path") {
            None | Some(serde_json::Value::Null) => None,
            Some(serde_json::Value::String(pattern)) => Some(
                regex::Regex::new(pattern)
                    .map_err(|e| format!("invalid `path` regex {:?}: {}", pattern, e))?,
            ),
            Some(_) => return Err("`path` must be a regex string".into()),
        };

        let mut headers = Vec::new();
        if let Some(hdrs) = obj.get("headers") {
            let map = hdrs.as_object().ok_or("`headers` must be an object")?;
            for (name, matcher) in map {
                let expect = match matcher {
                    serde_json::Value::Bool(true) => HeaderExpect::Present,
                    serde_json::Value::Bool(false) => continue, // explicitly no constraint
                    serde_json::Value::String(s) => HeaderExpect::Contains(s.clone()),
                    _ => {
                        return Err(format!(
                            "header `{}` matcher must be true or a string",
                            name
                        ))
                    }
                };
                headers.push(HeaderMatch {
                    name: name.to_ascii_lowercase(),
                    expect,
                });
            }
        }

        if methods.is_none() && path.is_none() && headers.is_empty() {
            // A rule with no conditions matches everything; allow it (explicit
            // "handle all" escape hatch) rather than treating it as an error.
            debug!("request_filter rule has no conditions — matches all requests");
        }

        Ok(FilterRule {
            methods,
            path,
            headers,
        })
    }

    fn parse_filtered_response(
        raw: &serde_json::Value,
        warnings: &mut Vec<String>,
    ) -> FilteredResponse {
        let mut resp = FilteredResponse::default();
        if let Some(status) = raw.get("status") {
            match status.as_u64() {
                // Reject out-of-range values here rather than truncating with
                // `as u16` and blowing up later while building the response.
                Some(s) if (100..=599).contains(&s) => resp.status = s as u16,
                _ => {
                    let msg = format!(
                        "filtered_response.status {} is not a valid HTTP status (100-599) — using {}",
                        status, resp.status
                    );
                    error!("{}", msg);
                    warnings.push(msg);
                }
            }
        }
        if let Some(body) = raw.get("body").and_then(|v| v.as_str()) {
            resp.body = body.to_string();
        }
        if let Some(headers) = raw.get("headers").and_then(|v| v.as_object()) {
            resp.headers = headers
                .iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                .collect();
        }
        resp
    }

    /// True when no rules are configured — every request goes to the LLM.
    pub fn is_pass_through(&self) -> bool {
        self.rules.is_empty()
    }

    /// Should this request be forwarded to the LLM?
    pub fn allows(&self, req: &RequestData, path: &str) -> bool {
        self.is_pass_through() || self.rules.iter().any(|r| r.matches(req, path))
    }

    /// The configured auto-response as raw parts, for transports that build
    /// their own response type (HTTP/2 through the `h2` crate).
    pub fn rejection_parts(&self) -> (u16, Vec<(String, String)>, String) {
        (
            self.filtered_response.status,
            self.filtered_response.headers.clone(),
            self.filtered_response.body.clone(),
        )
    }

    /// Build the auto-response for a request that matched no rule.
    ///
    /// `filtered_response` comes straight from caller-supplied startup params,
    /// so this goes through the non-panicking builder.
    pub fn rejection(&self) -> Response<Full<Bytes>> {
        build_safe_response(
            self.filtered_response.status,
            self.filtered_response.headers.iter().cloned(),
            self.filtered_response.body.clone(),
            "filtered_response",
        )
    }
}

/// Name of a JSON value's type, for error messages.
fn kind_of(v: &serde_json::Value) -> &'static str {
    match v {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "a boolean",
        serde_json::Value::Number(_) => "a number",
        serde_json::Value::String(_) => "a string",
        serde_json::Value::Array(_) => "an array",
        serde_json::Value::Object(_) => "an object",
    }
}

/// Startup parameters describing the request filter, for `get_startup_parameters()`.
/// Shared by HTTP/1.1 and HTTP/2 so the LLM sees the same schema and examples.
pub fn request_handling_startup_parameters() -> Vec<crate::llm::actions::ParameterDefinition> {
    use crate::llm::actions::ParameterDefinition;
    vec![
        ParameterDefinition {
            name: "request_filter".to_string(),
            type_hint: "array".to_string(),
            description: "RECOMMENDED for any HTTP server a browser or the public internet will \
                reach: set this so you do not spend a slow LLM call on favicon.ico, CORS \
                preflights, and scanner noise. A good default that only reasons about real page \
                loads is [{\"methods\":[\"GET\"],\"headers\":{\"accept\":\"text/html\"}}] — favicon \
                and image probes carry `Accept: image/*`, and preflights are not GET, so they are \
                auto-answered without a model call. \
                Allowlist of request-match rules deciding which requests reach the LLM. \
                A request is handled by the LLM only if it matches at least one rule; requests \
                matching no rule get `filtered_response` (default 404) with NO LLM call. Omit this \
                to send every request to the LLM. Each rule is an object; all present conditions \
                must hold (AND), and rules are OR'd together. Conditions: `methods` (array of HTTP \
                methods, case-insensitive; omit for any), `path` (a regular expression matched \
                against the URL path, e.g. \"^/$\" or \"^/api/\"; omit for any), `headers` (object \
                mapping header name to either true = must be present, or a string = value must \
                contain that substring case-insensitively, e.g. {\"accept\": \"text/html\"}). \
                Example filter that only sends real browser page loads to the LLM (favicon/OPTIONS/\
                XHR are auto-404'd): [{\"methods\":[\"GET\"],\"headers\":{\"accept\":\"text/html\"}}]. \
                Fail-open: a malformed rule (e.g. an invalid `path` regex) is dropped with a loud \
                error instead of failing startup, so a typo means MORE requests reach the LLM, not \
                fewer. Check the server status output after starting."
                .to_string(),
            required: false,
            example: serde_json::json!([
                { "methods": ["GET"], "path": "^/$", "headers": { "accept": "text/html" } },
                { "methods": ["POST"], "path": "^/api/" }
            ]),
            default: None,
        },
        ParameterDefinition {
            name: "filtered_response".to_string(),
            type_hint: "object".to_string(),
            description: "Response returned (without any LLM call) for requests that match no \
                `request_filter` rule. Fields: `status` (number, default 404), `body` (string, \
                default empty), `headers` (object of name→value). Ignored when no request_filter \
                is set."
                .to_string(),
            required: false,
            example: serde_json::json!({ "status": 404, "body": "Not Found" }),
            default: None,
        },
        ParameterDefinition {
            name: "default_response".to_string(),
            type_hint: "object".to_string(),
            description: "Response used when the model IS consulted for a request but returns no \
                send_http_response (an empty answer). Without this, such a request is refused \
                with a 500, because nothing answered it. Set a sensible fallback — commonly a \
                404 page — so a declined request gets a deliberate answer instead. Same shape \
                as filtered_response: `status` (number), `body` (string), `headers` (object of \
                name→value)."
                .to_string(),
            required: false,
            example: serde_json::json!({
                "status": 404,
                "headers": { "Content-Type": "text/html" },
                "body": "<!doctype html><title>Not Found</title><h1>404</h1>"
            }),
            default: None,
        },
    ]
}

/// Form-style URL query decoding used by browser GET forms. Duplicate keys keep
/// the last value, matching the existing event object's contract.
pub fn parse_query(query: Option<&str>) -> serde_json::Value {
    let params: serde_json::Map<String, serde_json::Value> =
        url::form_urlencoded::parse(query.unwrap_or("").as_bytes())
            .map(|(key, value)| {
                (
                    key.into_owned(),
                    serde_json::Value::String(value.into_owned()),
                )
            })
            .collect();
    serde_json::Value::Object(params)
}

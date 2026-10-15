//! Unit tests for the HTTP request filter (allowlist deciding which requests
//! reach the LLM). Pure — no Ollama, no server harness.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features http --test http_request_filter_test -- --test-threads=100


use netget::server::http_common::handler::{RequestData, RequestFilter};
use std::collections::HashMap;

/// Build a RequestData with the given method, and header pairs (stored lowercase,
/// as hyper produces them).
fn req(method: &str, headers: &[(&str, &str)]) -> RequestData {
    let mut map = HashMap::new();
    for (k, v) in headers {
        map.insert(k.to_ascii_lowercase(), v.to_string());
    }
    RequestData {
        method: method.to_string(),
        uri: "/".to_string(),
        version: "HTTP/1.1".to_string(),
        headers: map,
        body_bytes: bytes::Bytes::new(),
    }
}

fn filter(json: serde_json::Value) -> RequestFilter {
    RequestFilter::from_startup_params(Some(&json))
}

#[test]
fn no_filter_is_pass_through() {
    let f = RequestFilter::from_startup_params(None);
    assert!(f.is_pass_through());
    assert!(f.allows(&req("GET", &[]), "/"));
    assert!(f.allows(&req("DELETE", &[]), "/anything"));

    // Explicit empty array is also pass-through.
    let f = filter(serde_json::json!({ "request_filter": [] }));
    assert!(f.is_pass_through());
}

#[test]
fn method_only_rule() {
    let f = filter(serde_json::json!({ "request_filter": [{ "methods": ["GET", "HEAD"] }] }));
    assert!(!f.is_pass_through());
    assert!(f.allows(&req("GET", &[]), "/x"));
    assert!(f.allows(&req("HEAD", &[]), "/x"));
    // Method compare is case-insensitive.
    assert!(f.allows(&req("get", &[]), "/x"));
    assert!(!f.allows(&req("POST", &[]), "/x"));
}

#[test]
fn path_regex_rule() {
    let f = filter(serde_json::json!({ "request_filter": [{ "path": "^/api/" }] }));
    assert!(f.allows(&req("GET", &[]), "/api/users"));
    assert!(f.allows(&req("POST", &[]), "/api/"));
    assert!(!f.allows(&req("GET", &[]), "/"));
    assert!(!f.allows(&req("GET", &[]), "/apix"));

    // Exact root only.
    let f = filter(serde_json::json!({ "request_filter": [{ "path": "^/$" }] }));
    assert!(f.allows(&req("GET", &[]), "/"));
    assert!(!f.allows(&req("GET", &[]), "/home"));
}

#[test]
fn header_present_and_contains() {
    // Header presence
    let f =
        filter(serde_json::json!({ "request_filter": [{ "headers": { "x-internal": true } }] }));
    assert!(f.allows(&req("GET", &[("x-internal", "1")]), "/"));
    assert!(!f.allows(&req("GET", &[]), "/"));

    // Header value contains (case-insensitive)
    let f =
        filter(serde_json::json!({ "request_filter": [{ "headers": { "accept": "text/html" } }] }));
    assert!(f.allows(
        &req("GET", &[("accept", "text/html,application/xhtml")]),
        "/"
    ));
    assert!(f.allows(&req("GET", &[("Accept", "TEXT/HTML")]), "/")); // name + value case-insensitive
    assert!(!f.allows(&req("GET", &[("accept", "image/png")]), "/"));
    assert!(!f.allows(&req("GET", &[]), "/"));
}

#[test]
fn conditions_are_anded_within_a_rule() {
    let f = filter(serde_json::json!({
        "request_filter": [{ "methods": ["GET"], "path": "^/$", "headers": { "accept": "text/html" } }]
    }));
    // All three satisfied
    assert!(f.allows(&req("GET", &[("accept", "text/html")]), "/"));
    // One condition off → rejected
    assert!(!f.allows(&req("POST", &[("accept", "text/html")]), "/"));
    assert!(!f.allows(&req("GET", &[("accept", "text/html")]), "/other"));
    assert!(!f.allows(&req("GET", &[("accept", "application/json")]), "/"));
}

#[test]
fn rules_are_ored() {
    let f = filter(serde_json::json!({
        "request_filter": [
            { "methods": ["GET"], "path": "^/$" },
            { "methods": ["POST"], "path": "^/api/" }
        ]
    }));
    assert!(f.allows(&req("GET", &[]), "/"));
    assert!(f.allows(&req("POST", &[]), "/api/x"));
    assert!(!f.allows(&req("GET", &[]), "/api/x"));
    assert!(!f.allows(&req("POST", &[]), "/"));
}

#[test]
fn favicon_is_rejected_by_a_page_load_filter() {
    // The old hardcoded favicon case, now handled generically: a browser's
    // /favicon.ico probe sends Accept: image/*, so it fails a text/html filter.
    let f = filter(serde_json::json!({
        "request_filter": [{ "methods": ["GET"], "headers": { "accept": "text/html" } }]
    }));
    let favicon = req("GET", &[("accept", "image/avif,image/webp,*/*")]);
    assert!(!f.allows(&favicon, "/favicon.ico"));
    // A real page load still reaches the LLM.
    assert!(f.allows(&req("GET", &[("accept", "text/html")]), "/"));
    // CORS preflight (OPTIONS) is rejected too.
    assert!(!f.allows(&req("OPTIONS", &[("accept", "*/*")]), "/"));
}

#[test]
fn malformed_rules_are_skipped_not_fatal() {
    // Invalid regex → that rule dropped; a valid second rule still works.
    let f = filter(serde_json::json!({
        "request_filter": [
            { "path": "^(unclosed" },
            { "methods": ["GET"] }
        ]
    }));
    assert!(!f.is_pass_through());
    assert!(f.allows(&req("GET", &[]), "/"));
    assert!(!f.allows(&req("POST", &[]), "/"));
}

#[test]
fn rejection_defaults_to_404_and_is_configurable() {
    let f = filter(serde_json::json!({ "request_filter": [{ "methods": ["GET"] }] }));
    assert_eq!(f.rejection().status(), 404);

    let f = filter(serde_json::json!({
        "request_filter": [{ "methods": ["GET"] }],
        "filtered_response": { "status": 204 }
    }));
    assert_eq!(f.rejection().status(), 204);

    let f = filter(serde_json::json!({
        "request_filter": [{ "methods": ["GET"] }],
        "filtered_response": { "status": 418, "headers": { "x-teapot": "yes" } }
    }));
    let resp = f.rejection();
    assert_eq!(resp.status(), 418);
    assert_eq!(resp.headers().get("x-teapot").unwrap(), "yes");
}

// --- default_response: what the server sends when the model returns no action ---

#[test]
fn default_response_parts_reflect_the_startup_param() {
    let f = filter(serde_json::json!({
        "default_response": { "status": 404, "headers": { "Content-Type": "text/html" }, "body": "<h1>404</h1>" }
    }));
    let (status, headers, body) = f
        .default_response_parts()
        .expect("default_response must be parsed");
    assert_eq!(status, 404);
    assert_eq!(body, "<h1>404</h1>");
    assert!(headers
        .iter()
        .any(|(k, v)| k.eq_ignore_ascii_case("content-type") && v.contains("text/html")));
}

#[test]
fn absent_default_response_is_none() {
    assert!(filter(serde_json::json!({}))
        .default_response_parts()
        .is_none());
}

#[test]
fn build_response_uses_default_when_model_produced_nothing() {
    use netget::server::http_common::handler::build_response;
    let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();

    // No protocol_results (empty action list) + a default -> the default is used.
    let with_default = build_response(
        Vec::new(),
        "HTTP",
        "GET",
        "/",
        &tx,
        Some((
            404,
            vec![("Content-Type".into(), "text/html".into())],
            "nope".into(),
        )),
    )
    .unwrap();
    assert_eq!(with_default.status(), 404);

    // No results + no default -> historical empty 200 (unchanged behavior).
    let (tx2, _rx2) = tokio::sync::mpsc::unbounded_channel();
    let without = build_response(Vec::new(), "HTTP", "GET", "/", &tx2, None).unwrap();
    assert_eq!(without.status(), 200);
}

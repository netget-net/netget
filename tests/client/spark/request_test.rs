//! The Spark client's request building and response bounds, without a model.
//!
//! * `request` + `api_url`: every action becomes exactly the path and query Spark documents,
//!   and no id the model can write changes the host, escapes `/api/v1/` or adds a query.
//! * `resolve_endpoint`: the target is mandatory and is a base URL.
//! * `Api::run` against a scripted HTTP server: an oversized body, a body nested past the
//!   depth bound, a redirect, an error page and a body that is not Spark's shape each become a
//!   `spark_error`, never a result; and the projection keeps only its fields, with a peer's
//!   control characters removed.

use netget::client::spark::actions::{app_id, request};
use netget::client::spark::decode::{self, json_depth, MAX_JSON_DEPTH};
use netget::client::spark::{api_url, resolve_endpoint, Api, MAX_ITEMS_LIMIT, MAX_RESPONSE_BYTES};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn url_of(action: Value) -> String {
    let base = url::Url::parse("http://127.0.0.1:18080").unwrap();
    let call = request(&action).unwrap_or_else(|e| panic!("{action}: {e:#}"));
    api_url(&base, &call.segments, &call.query).unwrap()
}

#[test]
fn every_action_becomes_the_documented_request() {
    let b = "http://127.0.0.1:18080/api/v1";
    let a = "local-1792044029340";
    let cases = [
        (json!({"type": "get_version"}), format!("{b}/version")),
        (json!({"type": "list_applications"}), format!("{b}/applications")),
        (
            json!({"type": "list_applications", "status": "running", "min_date": "2026-10-15",
                   "max_end_date": "2026-10-15T06:00:00.000GMT", "limit": 5}),
            format!("{b}/applications?status=running&minDate=2026-10-15&maxEndDate=2026-10-15T06%3A00%3A00.000GMT&limit=5"),
        ),
        (json!({"type": "get_application", "app_id": a}), format!("{b}/applications/{a}")),
        (
            json!({"type": "list_jobs", "app_id": a, "status": ["failed", "RUNNING"]}),
            format!("{b}/applications/{a}/jobs?status=failed&status=running"),
        ),
        (
            json!({"type": "get_job", "app_id": a, "app_attempt_id": "1", "job_id": 3}),
            format!("{b}/applications/{a}/1/jobs/3"),
        ),
        (
            json!({"type": "list_stages", "app_id": a, "status": "skipped"}),
            format!("{b}/applications/{a}/stages?status=skipped&details=false"),
        ),
        (
            json!({"type": "get_stage", "app_id": a, "stage_id": "2"}),
            format!("{b}/applications/{a}/stages/2?details=false"),
        ),
        (
            json!({"type": "get_task_summary", "app_id": a, "stage_id": 2, "stage_attempt_id": 1}),
            format!("{b}/applications/{a}/stages/2/1/taskSummary?quantiles=0.05%2C0.25%2C0.5%2C0.75%2C0.95"),
        ),
        (
            json!({"type": "list_executors", "app_id": a, "include_dead": true}),
            format!("{b}/applications/{a}/allexecutors"),
        ),
        (json!({"type": "get_environment", "app_id": a}), format!("{b}/applications/{a}/environment")),
        (
            json!({"type": "list_sql_executions", "app_id": a, "offset": 10, "max_items": 5}),
            format!("{b}/applications/{a}/sql?details=false&planDescription=false&offset=10&length=5"),
        ),
        (
            json!({"type": "get_sql_execution", "app_id": a, "execution_id": 7}),
            format!("{b}/applications/{a}/sql/7?details=true&planDescription=true"),
        ),
    ];
    for (action, want) in cases {
        assert_eq!(url_of(action.clone()), want, "{action}");
    }
}

/// No id the model writes can leave `/api/v1/applications/` on the target, and every refusal
/// names the parameter.
#[test]
fn ids_cannot_steer_the_request() {
    for bad in [
        "..",
        ".",
        "../../etc/passwd",
        "a/b",
        "a?x=1",
        "a#f",
        "%2e%2e",
        "a b",
        "a\nb",
        "",
        "@evil.example",
        "http://evil.example/",
        ".hidden",
    ] {
        assert!(app_id(bad).is_err(), "app_id {bad:?} must be refused");
        assert!(
            request(&json!({"type": "list_jobs", "app_id": bad})).is_err(),
            "list_jobs app_id {bad:?} must be refused"
        );
    }
    assert!(app_id(&"a".repeat(129)).is_err());
    for bad in [
        json!(-1),
        json!(1.5),
        json!("1/2"),
        json!("01x"),
        json!(u64::MAX),
        json!(null),
    ] {
        assert!(
            request(&json!({"type": "get_job", "app_id": "local-1", "job_id": bad})).is_err(),
            "job_id {bad} must be refused"
        );
    }
    assert!(request(
        &json!({"type": "get_job", "app_id": "local-1", "app_attempt_id": "../x", "job_id": 1})
    )
    .is_err());
    assert!(
        request(&json!({"type": "list_jobs", "app_id": "local-1", "status": "succeeded&x=1"}))
            .is_err()
    );
    assert!(
        request(&json!({"type": "list_applications", "min_date": "2026-10-15&limit=1"})).is_err()
    );
    assert!(request(&json!({"type": "list_applications", "limit": 0})).is_err());
    assert!(request(
        &json!({"type": "get_task_summary", "app_id": "a", "stage_id": 1,
        "stage_attempt_id": 0, "quantiles": [2.0]})
    )
    .is_err());
    assert!(request(
        &json!({"type": "list_jobs", "app_id": "a", "max_items": MAX_ITEMS_LIMIT + 1})
    )
    .is_err());
    assert!(request(&json!({"type": "fetch_url", "url": "http://evil.example/"})).is_err());
    // Even a segment that skipped validation stays one segment on the target.
    let base = url::Url::parse("http://127.0.0.1:18080/history").unwrap();
    let url = api_url(&base, &["a/../../x?y#z".to_string()], &[]).unwrap();
    assert_eq!(
        url,
        "http://127.0.0.1:18080/history/api/v1/a%2F..%2F..%2Fx%3Fy%23z"
    );
    assert!(api_url(&base, &["..".to_string()], &[]).is_err());
}

#[test]
fn the_target_is_mandatory_and_a_base_url() {
    assert!(resolve_endpoint("", None).is_err());
    assert!(resolve_endpoint("  ", Some("  ")).is_err());
    assert_eq!(
        resolve_endpoint("127.0.0.1:4040", None).unwrap().as_str(),
        "http://127.0.0.1:4040/"
    );
    assert_eq!(
        resolve_endpoint("ignored:1", Some("https://gw.example/sparkhistory"))
            .unwrap()
            .as_str(),
        "https://gw.example/sparkhistory"
    );
    for bad in [
        "ftp://h/",
        "http://h/?x=1",
        "http://h/#f",
        "http://u:p@h/",
        "http://h/api/v1",
        "not a url",
    ] {
        assert!(
            resolve_endpoint("", Some(bad)).is_err(),
            "{bad} must be refused"
        );
    }
}

#[test]
fn depth_is_measured_without_recursion_and_bounded() {
    let deep = format!("{}{}", "[".repeat(100_000), "]".repeat(100_000));
    assert_eq!(json_depth(deep.as_bytes()), 100_000);
    assert!(decode::parse(deep.as_bytes()).is_err());
    let ok = format!(
        "{}1{}",
        "[".repeat(MAX_JSON_DEPTH),
        "]".repeat(MAX_JSON_DEPTH)
    );
    assert!(decode::parse(ok.as_bytes()).is_ok());
    let over = format!(
        "{}1{}",
        "[".repeat(MAX_JSON_DEPTH + 1),
        "]".repeat(MAX_JSON_DEPTH + 1)
    );
    assert!(decode::parse(over.as_bytes()).is_err());
    // Brackets inside strings are not nesting.
    assert_eq!(json_depth(br#"{"a":"[[[[\"]]]"}"#), 1);
}

/// A one-shot HTTP server answering every request with `status`, `headers` and `body`, and
/// recording the request lines.
async fn scripted(
    status: &'static str,
    headers: &'static str,
    body: Vec<u8>,
) -> (String, Arc<Mutex<Vec<String>>>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&seen);
    let body = Arc::new(body);
    tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
            let body = Arc::clone(&body);
            let log = Arc::clone(&log);
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                let mut head = Vec::new();
                while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                    match s.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => head.extend_from_slice(&buf[..n]),
                    }
                }
                let text = String::from_utf8_lossy(&head);
                log.lock()
                    .unwrap()
                    .push(text.lines().next().unwrap_or_default().to_string());
                let resp = format!(
                    "HTTP/1.1 {status}\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = s.write_all(resp.as_bytes()).await;
                let _ = s.write_all(&body).await;
            });
        }
    });
    (addr, seen)
}

async fn run(addr: &str, action: Value) -> (String, Value) {
    let api = Api::new(
        resolve_endpoint(addr, None).unwrap(),
        Duration::from_secs(10),
    )
    .unwrap();
    let call = request(&action).unwrap();
    let (event, payload) = api.run(&call).await;
    (event.id.clone(), payload)
}

#[tokio::test]
async fn an_oversized_answer_is_refused_not_read() {
    let body = format!("[{}]", "1,".repeat(MAX_RESPONSE_BYTES / 2) + "1").into_bytes();
    assert!(body.len() > MAX_RESPONSE_BYTES);
    let (addr, _) = scripted("200 OK", "Content-Type: application/json\r\n", body).await;
    let (event, payload) = run(&addr, json!({"type": "list_applications"})).await;
    assert_eq!(event, "spark_error", "{payload}");
    assert!(
        payload["message"]
            .as_str()
            .unwrap()
            .contains(&MAX_RESPONSE_BYTES.to_string()),
        "{payload}"
    );
}

#[tokio::test]
async fn a_deep_answer_is_refused_before_parsing() {
    let body = format!("{}{}", "[".repeat(5000), "]".repeat(5000)).into_bytes();
    let (addr, _) = scripted("200 OK", "", body).await;
    let (event, payload) = run(&addr, json!({"type": "list_jobs", "app_id": "local-1"})).await;
    assert_eq!(event, "spark_error");
    assert!(
        payload["message"].as_str().unwrap().contains("nests 5000"),
        "{payload}"
    );
}

#[tokio::test]
async fn a_redirect_is_reported_not_followed() {
    let (addr, seen) = scripted(
        "302 Found",
        "Location: http://evil.example/api/v1/applications\r\n",
        Vec::new(),
    )
    .await;
    let (event, payload) = run(&addr, json!({"type": "list_applications"})).await;
    assert_eq!(event, "spark_error");
    assert_eq!(payload["http_status"], 302);
    assert!(payload["message"]
        .as_str()
        .unwrap()
        .contains("not followed"));
    assert_eq!(
        seen.lock().unwrap().len(),
        1,
        "exactly one request, to the target"
    );
}

#[tokio::test]
async fn an_error_page_is_the_servers_words_cleaned() {
    let (addr, _) = scripted(
        "404 Not Found",
        "Content-Type: text/plain\r\n",
        b"unknown app: x\x1b[31m\nforged line".to_vec(),
    )
    .await;
    let (event, payload) = run(
        &addr,
        json!({"type": "get_job", "app_id": "x", "job_id": 1}),
    )
    .await;
    assert_eq!(event, "spark_error");
    assert_eq!(payload["http_status"], 404);
    assert_eq!(payload["app_id"], "x");
    let msg = payload["message"].as_str().unwrap();
    assert!(msg.starts_with("unknown app: x"), "{msg}");
    assert!(!msg.contains('\x1b') && !msg.contains('\n'), "{msg:?}");

    let (addr, _) = scripted(
        "500 Server Error",
        "Content-Type: text/html\r\n",
        b"<html><head><title>Error 500 boom</title></head><body>...</body></html>".to_vec(),
    )
    .await;
    let (_, payload) = run(&addr, json!({"type": "list_applications"})).await;
    assert_eq!(payload["message"], "Error 500 boom");
}

#[tokio::test]
async fn an_answer_that_is_not_sparks_shape_is_an_error() {
    let (addr, _) = scripted("200 OK", "", b"[1, 2, 3]".to_vec()).await;
    let (event, _) = run(&addr, json!({"type": "list_jobs", "app_id": "a"})).await;
    assert_eq!(event, "spark_error");
    let (addr, _) = scripted("200 OK", "", b"not json".to_vec()).await;
    let (event, _) = run(&addr, json!({"type": "list_jobs", "app_id": "a"})).await;
    assert_eq!(event, "spark_error");
    let (addr, _) = scripted("200 OK", "", b"{\"nope\": 1}".to_vec()).await;
    let (event, _) = run(&addr, json!({"type": "get_version"})).await;
    assert_eq!(event, "spark_error");
}

#[tokio::test]
async fn entries_are_projected_bounded_and_cleaned() {
    let jobs: Vec<Value> = (0..120)
        .map(|i| {
            json!({"jobId": i, "name": format!("job\u{1b}]0;pwned\u{7}{i}"), "status": "SUCCEEDED",
                   "stageIds": [i], "secretInternal": "x", "killedTasksSummary": {"a": 1},
                   "description": "d".repeat(10_000)})
        })
        .collect();
    let (addr, _) = scripted("200 OK", "", serde_json::to_vec(&jobs).unwrap()).await;
    let (event, payload) = run(
        &addr,
        json!({"type": "list_jobs", "app_id": "a", "max_items": 7}),
    )
    .await;
    assert_eq!(event, "spark_jobs");
    assert_eq!(payload["count"], 7);
    assert_eq!(payload["total"], 120);
    assert_eq!(payload["truncated"], true);
    assert_eq!(payload["app_id"], "a");
    let first = &payload["jobs"][0];
    assert_eq!(first["jobId"], 0);
    assert!(first.get("secretInternal").is_none());
    assert!(first.get("killedTasksSummary").is_none());
    let name = first["name"].as_str().unwrap();
    assert!(
        name.starts_with("job") && name.ends_with('0') && !name.contains('\u{1b}'),
        "{name:?}"
    );
    assert!(
        !name.contains("pwned"),
        "an escape sequence goes as a whole: {name:?}"
    );
    assert!(first["description"].as_str().unwrap().len() <= decode::MAX_TEXT_BYTES + 3);
}

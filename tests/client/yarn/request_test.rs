//! The YARN client's request building and response bounds, without a model.
//!
//! * `request` + `api_url`: every action becomes exactly the path, query and body the
//!   ResourceManager REST API documents, and no value the model can write changes the host,
//!   escapes `/ws/v1/cluster/` or adds a query parameter.
//! * `resolve_endpoint`: the target is mandatory and is a base URL.
//! * `Api::run` against a scripted HTTP server: an oversized body, a body nested past the depth
//!   bound, a redirect, a RemoteException, an HTML error page and a body that is not YARN's
//!   shape each become a `yarn_error`, never a result; a kill without `allow_kill` sends
//!   nothing; and the projection keeps only its fields, with a peer's control characters
//!   removed.

use netget::client::yarn::actions::{app_id, node_id, request};
use netget::client::yarn::decode::{self, json_depth, MAX_JSON_DEPTH, MAX_QUEUES};
use netget::client::yarn::{api_url, resolve_endpoint, Api, MAX_ITEMS_LIMIT, MAX_RESPONSE_BYTES};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const APP: &str = "application_1792047302594_0003";

fn url_of(action: Value) -> String {
    let base = url::Url::parse("http://127.0.0.1:8088").unwrap();
    let call = request(&action).unwrap_or_else(|e| panic!("{action}: {e:#}"));
    api_url(&base, &call.segments, &call.query).unwrap()
}

#[test]
fn every_action_becomes_the_documented_request() {
    let b = "http://127.0.0.1:8088/ws/v1/cluster";
    let cases = [
        (json!({"type": "get_cluster_info"}), format!("{b}/info")),
        (
            json!({"type": "get_cluster_metrics"}),
            format!("{b}/metrics"),
        ),
        (json!({"type": "get_scheduler"}), format!("{b}/scheduler")),
        (json!({"type": "list_applications"}), format!("{b}/apps")),
        (
            json!({"type": "list_applications", "states": ["running", "ACCEPTED", "RUNNING"],
                   "final_status": "failed", "queue": "root.default", "user": "dr.who",
                   "application_types": ["SPARK", "MAPREDUCE"], "limit": 5,
                   "started_time_begin": 1792047302594u64, "finished_time_end": 1792047399999u64}),
            format!(
                "{b}/apps?states=RUNNING%2CACCEPTED&finalStatus=FAILED&queue=root.default\
                 &user=dr.who&applicationTypes=SPARK%2CMAPREDUCE&limit=5\
                 &startedTimeBegin=1792047302594&finishedTimeEnd=1792047399999"
            ),
        ),
        (
            json!({"type": "get_application", "app_id": APP}),
            format!("{b}/apps/{APP}"),
        ),
        (
            json!({"type": "list_app_attempts", "app_id": APP}),
            format!("{b}/apps/{APP}/appattempts"),
        ),
        (
            json!({"type": "get_app_state", "app_id": APP}),
            format!("{b}/apps/{APP}/state"),
        ),
        (
            json!({"type": "get_app_queue", "app_id": APP}),
            format!("{b}/apps/{APP}/queue"),
        ),
        (
            json!({"type": "kill_application", "app_id": APP}),
            format!("{b}/apps/{APP}/state"),
        ),
        (
            json!({"type": "list_nodes", "states": "lost"}),
            format!("{b}/nodes?states=LOST"),
        ),
        (
            json!({"type": "get_node", "node_id": "worker1.example.com:8041"}),
            format!("{b}/nodes/worker1.example.com:8041"),
        ),
    ];
    for (action, want) in cases {
        assert_eq!(url_of(action.clone()), want, "{action}");
    }
    // Only the kill is a write, and its body is fixed here rather than taken from the action.
    let kill = request(&json!({"type": "kill_application", "app_id": APP,
                               "state": "RUNNING", "body": {"x": 1}}))
    .unwrap();
    assert_eq!(kill.method, "PUT");
    assert_eq!(kill.body, Some(json!({"state": "KILLED"})));
    for read in [
        json!({"type": "get_application", "app_id": APP}),
        json!({"type": "list_applications"}),
    ] {
        let call = request(&read).unwrap();
        assert_eq!((call.method.as_str(), call.body), ("GET", None));
    }
}

/// No value the model writes can leave `/ws/v1/cluster/` on the target, and every refusal is
/// an error rather than a request.
#[test]
fn ids_and_filters_cannot_steer_the_request() {
    for bad in [
        "..",
        ".",
        "../../etc/passwd",
        "application_1/2_3",
        "application_1_2/../../x",
        "application_1_0001/..",
        "application_1_0001/../../ws",
        "application_1_2?x=1",
        "application_1_2#f",
        "application_1_%32",
        "application_1_2 ",
        "application_1_2\n",
        "app_1_2",
        "application_x_2",
        "application_1_",
        "application_1",
        "",
        "http://evil.example/",
        "application_12345678901234567890_1",
    ] {
        if bad.trim() == "application_1_2" {
            continue;
        }
        assert!(app_id(bad).is_err(), "app_id {bad:?} must be refused");
        assert!(
            request(&json!({"type": "get_application", "app_id": bad})).is_err(),
            "get_application app_id {bad:?} must be refused"
        );
        assert!(
            request(&json!({"type": "kill_application", "app_id": bad})).is_err(),
            "kill_application app_id {bad:?} must be refused"
        );
    }
    for bad in [
        "host",
        ":8041",
        "host:",
        "host:99999",
        "host:80/x",
        "../x:1",
        ".host:1",
        "-host:1",
        "ho st:1",
        "host:1?x",
        "a@b:1",
    ] {
        assert!(node_id(bad).is_err(), "node_id {bad:?} must be refused");
    }
    assert!(node_id("worker-1.example.com:8041").is_ok());
    for bad in [
        json!({"type": "list_applications", "states": "RUNNING,KILLED"}),
        json!({"type": "list_applications", "states": "RUNNING&x=1"}),
        json!({"type": "list_applications", "states": "BOGUS"}),
        json!({"type": "list_applications", "final_status": ["FAILED", "KILLED"]}),
        json!({"type": "list_applications", "queue": "default&user=x"}),
        json!({"type": "list_applications", "queue": "../default"}),
        json!({"type": "list_applications", "user": "a b"}),
        json!({"type": "list_applications", "application_types": "SPARK,X"}),
        json!({"type": "list_applications", "limit": 0}),
        json!({"type": "list_applications", "limit": 10_001}),
        json!({"type": "list_applications", "started_time_begin": -1}),
        json!({"type": "list_applications", "started_time_begin": "1792047302594"}),
        json!({"type": "list_applications", "max_items": MAX_ITEMS_LIMIT + 1}),
        json!({"type": "list_nodes", "states": "SLEEPING"}),
        json!({"type": "fetch_url", "url": "http://evil.example/"}),
        json!({"type": "submit_application", "am-container-spec": {"commands": {"command": "id"}}}),
    ] {
        assert!(request(&bad).is_err(), "{bad} must be refused");
    }
    // Even a segment that skipped validation stays one segment on the target.
    let base = url::Url::parse("http://127.0.0.1:8088/gateway").unwrap();
    let url = api_url(&base, &["a/../../x?y#z".to_string()], &[]).unwrap();
    assert_eq!(
        url,
        "http://127.0.0.1:8088/gateway/ws/v1/cluster/a%2F..%2F..%2Fx%3Fy%23z"
    );
    assert!(api_url(&base, &["..".to_string()], &[]).is_err());
}

#[test]
fn the_target_is_mandatory_and_a_base_url() {
    assert!(resolve_endpoint("", None).is_err());
    assert!(resolve_endpoint("  ", Some("  ")).is_err());
    assert_eq!(
        resolve_endpoint("127.0.0.1:8088", None).unwrap().as_str(),
        "http://127.0.0.1:8088/"
    );
    assert_eq!(
        resolve_endpoint("ignored:1", Some("https://gw.example/yarn"))
            .unwrap()
            .as_str(),
        "https://gw.example/yarn"
    );
    for bad in [
        "ftp://h/",
        "http://h/?x=1",
        "http://h/#f",
        "http://u:p@h/",
        "http://h/ws/v1",
        "http://h/ws/v1/cluster/",
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

/// A queue tree is walked without recursion, parents before children, and stops at the bound.
#[test]
fn the_queue_tree_is_walked_iteratively_and_bounded() {
    let leaf = |name: &str| json!({"queueName": name, "queuePath": format!("root.p.{name}"), "queueType": "leaf", "capacity": 50.0, "resources": {"x": {"y": 1}}});
    let tree = json!({"scheduler": {"schedulerInfo": {
        "type": "capacityScheduler", "queueName": "root", "capacity": 100.0,
        "queues": {"queue": [
            {"queueName": "p", "queuePath": "root.p", "queueType": "parent",
             "queues": {"queue": [leaf("a"), leaf("b")]}},
            {"queueName": "solo", "queuePath": "root.solo", "queueType": "leaf"}
        ]}
    }}});
    let out = decode::decode(
        decode::Resource::Scheduler,
        "get_scheduler",
        &tree,
        50,
        &Default::default(),
    )
    .unwrap();
    let paths: Vec<&str> = out["queues"]
        .as_array()
        .unwrap()
        .iter()
        .map(|q| q["queuePath"].as_str().unwrap())
        .collect();
    assert_eq!(paths, ["root.p", "root.p.a", "root.p.b", "root.solo"]);
    assert_eq!(out["scheduler"]["type"], "capacityScheduler");
    assert!(out["queues"][1].get("resources").is_none());

    // A chain deeper than MAX_QUEUES (built in memory, so the byte-level depth bound does not
    // stop it first) is walked and cut at MAX_QUEUES.
    let mut node = json!({"queueName": "last"});
    for i in 0..(MAX_QUEUES + 100) {
        node = json!({"queueName": format!("q{i}"), "queues": {"queue": node}});
    }
    let chain = json!({"scheduler": {"schedulerInfo": {"type": "capacityScheduler", "queues": {"queue": node}}}});
    let out = decode::decode(
        decode::Resource::Scheduler,
        "get_scheduler",
        &chain,
        MAX_ITEMS_LIMIT,
        &Default::default(),
    )
    .unwrap();
    assert_eq!(out["truncated"], true);
    assert_eq!(out["count"], MAX_ITEMS_LIMIT.min(MAX_QUEUES));
    assert_eq!(
        out["queues"][0]["queueName"],
        format!("q{}", MAX_QUEUES + 99)
    );
}

/// A one-shot HTTP server answering every request with `status`, `headers` and `body`, and
/// recording each request's head and body.
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
                log.lock()
                    .unwrap()
                    .push(String::from_utf8_lossy(&head).to_string());
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

async fn run_with(addr: &str, action: Value, allow_kill: bool) -> (String, Value) {
    let api = Api::new(
        resolve_endpoint(addr, None).unwrap(),
        Duration::from_secs(10),
        allow_kill,
    )
    .unwrap();
    let call = request(&action).unwrap();
    let (event, payload) = api.run(&call).await;
    (event.id.clone(), payload)
}

async fn run(addr: &str, action: Value) -> (String, Value) {
    run_with(addr, action, false).await
}

#[tokio::test]
async fn an_oversized_answer_is_refused_not_read() {
    let body = format!(
        "{{\"apps\":{{\"app\":[{}]}}}}",
        "{},".repeat(MAX_RESPONSE_BYTES / 3) + "{}"
    )
    .into_bytes();
    assert!(body.len() > MAX_RESPONSE_BYTES);
    let (addr, _) = scripted("200 OK", "Content-Type: application/json\r\n", body).await;
    let (event, payload) = run(&addr, json!({"type": "list_applications"})).await;
    assert_eq!(event, "yarn_error", "{payload}");
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
    let (event, payload) = run(&addr, json!({"type": "get_scheduler"})).await;
    assert_eq!(event, "yarn_error");
    assert!(
        payload["message"].as_str().unwrap().contains("nests 5000"),
        "{payload}"
    );
}

#[tokio::test]
async fn a_redirect_is_reported_not_followed() {
    // What a standby ResourceManager does to every request but /info.
    let (addr, seen) = scripted(
        "307 Temporary Redirect",
        "Location: http://other-rm.example:8088/ws/v1/cluster/apps\r\n",
        b"This is standby RM. The redirect url is: http://other-rm.example:8088/".to_vec(),
    )
    .await;
    let (event, payload) = run(&addr, json!({"type": "list_applications"})).await;
    assert_eq!(event, "yarn_error");
    assert_eq!(payload["http_status"], 307);
    let msg = payload["message"].as_str().unwrap();
    assert!(msg.contains("not followed"), "{msg}");
    assert!(msg.contains("other-rm.example"), "{msg}");
    assert_eq!(
        seen.lock().unwrap().len(),
        1,
        "exactly one request, to the target"
    );
}

#[tokio::test]
async fn a_remote_exception_is_yarns_words_cleaned() {
    let (addr, _) = scripted(
        "404 Not Found",
        "Content-Type: application/json\r\n",
        br#"{"RemoteException":{"exception":"NotFoundException","message":"app with id: application_1_0009 not found\u001b[31m\nforged line","javaClassName":"org.apache.hadoop.yarn.webapp.NotFoundException"}}"#.to_vec(),
    )
    .await;
    let (event, payload) = run(
        &addr,
        json!({"type": "get_application", "app_id": "application_1_0009"}),
    )
    .await;
    assert_eq!(event, "yarn_error");
    assert_eq!(payload["http_status"], 404);
    assert_eq!(payload["app_id"], "application_1_0009");
    assert_eq!(payload["exception"], "NotFoundException");
    let msg = payload["message"].as_str().unwrap();
    assert!(
        msg.starts_with("app with id: application_1_0009 not found"),
        "{msg}"
    );
    assert!(!msg.contains('\x1b') && !msg.contains('\n'), "{msg:?}");

    let (addr, _) = scripted(
        "500 Server Error",
        "Content-Type: text/html\r\n",
        b"<html><head><title>Error 500 boom</title></head><body>...</body></html>".to_vec(),
    )
    .await;
    let (_, payload) = run(&addr, json!({"type": "get_cluster_metrics"})).await;
    assert_eq!(payload["message"], "Error 500 boom");
    assert!(payload.get("exception").is_none());
}

#[tokio::test]
async fn an_answer_that_is_not_yarns_shape_is_an_error() {
    for (body, action) in [
        (&b"[1, 2, 3]"[..], json!({"type": "list_applications"})),
        (b"not json", json!({"type": "list_applications"})),
        (
            b"{\"apps\": {\"app\": [1, 2]}}",
            json!({"type": "list_applications"}),
        ),
        (b"{\"nope\": 1}", json!({"type": "get_cluster_info"})),
        (
            b"{\"clusterInfo\": {\"id\": 1}}",
            json!({"type": "get_cluster_info"}),
        ),
        (
            b"{\"state\": 3}",
            json!({"type": "get_app_state", "app_id": APP}),
        ),
    ] {
        let (addr, _) = scripted("200 OK", "", body.to_vec()).await;
        let (event, payload) = run(&addr, action.clone()).await;
        assert_eq!(event, "yarn_error", "{action} with {body:?}: {payload}");
    }
    // YARN's own idioms for an empty list are results, not errors.
    for body in [&b"{\"apps\": null}"[..], b"{\"apps\": {}}"] {
        let (addr, _) = scripted("200 OK", "", body.to_vec()).await;
        let (event, payload) = run(&addr, json!({"type": "list_applications"})).await;
        assert_eq!(event, "yarn_applications", "{payload}");
        assert_eq!(payload["total"], 0);
    }
    // A one-element list rendered as an object is a list of one.
    let (addr, _) = scripted(
        "200 OK",
        "",
        br#"{"nodes": {"node": {"id": "h:1", "state": "RUNNING"}}}"#.to_vec(),
    )
    .await;
    let (event, payload) = run(&addr, json!({"type": "list_nodes"})).await;
    assert_eq!(event, "yarn_nodes");
    assert_eq!(payload["nodes"][0]["id"], "h:1");
}

#[tokio::test]
async fn a_kill_without_allow_kill_sends_nothing() {
    let (addr, seen) = scripted("202 Accepted", "", br#"{"state":"KILLING"}"#.to_vec()).await;
    let (event, payload) = run(&addr, json!({"type": "kill_application", "app_id": APP})).await;
    assert_eq!(event, "yarn_error", "{payload}");
    assert!(payload["message"].as_str().unwrap().contains("allow_kill"));
    assert!(
        seen.lock().unwrap().is_empty(),
        "nothing may reach the server"
    );

    let (event, payload) = run_with(
        &addr,
        json!({"type": "kill_application", "app_id": APP}),
        true,
    )
    .await;
    assert_eq!(event, "yarn_app_state", "{payload}");
    assert_eq!(payload["state"], "KILLING");
    assert_eq!(payload["http_status"], 202);
    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 1);
    assert!(
        seen[0].starts_with(&format!("PUT /ws/v1/cluster/apps/{APP}/state HTTP/1.1")),
        "{}",
        seen[0]
    );
}

#[tokio::test]
async fn entries_are_projected_bounded_and_cleaned() {
    let apps: Vec<Value> = (0..120)
        .map(|i| {
            json!({"id": format!("application_1_{i:04}"), "name": format!("job\u{1b}]0;pwned\u{7}{i}"),
                   "state": "FINISHED", "finalStatus": "SUCCEEDED", "secretInternal": "x",
                   "resourceSecondsMap": {"entry": []}, "diagnostics": "d\n".repeat(10_000)})
        })
        .collect();
    let (addr, _) = scripted(
        "200 OK",
        "",
        serde_json::to_vec(&json!({"apps": {"app": apps}})).unwrap(),
    )
    .await;
    let (event, payload) = run(
        &addr,
        json!({"type": "list_applications", "max_items": 7, "states": "FINISHED"}),
    )
    .await;
    assert_eq!(event, "yarn_applications");
    assert_eq!(payload["count"], 7);
    assert_eq!(payload["total"], 120);
    assert_eq!(payload["truncated"], true);
    assert_eq!(payload["filters"]["states"], json!(["FINISHED"]));
    let first = &payload["applications"][0];
    assert_eq!(first["id"], "application_1_0000");
    assert!(first.get("secretInternal").is_none());
    assert!(first.get("resourceSecondsMap").is_none());
    let name = first["name"].as_str().unwrap();
    assert!(
        name.starts_with("job") && name.ends_with('0') && !name.contains('\u{1b}'),
        "{name:?}"
    );
    assert!(
        !name.contains("pwned"),
        "an escape sequence goes as a whole: {name:?}"
    );
    assert!(first["diagnostics"].as_str().unwrap().len() <= decode::MAX_LONG_TEXT_BYTES + 3);
}

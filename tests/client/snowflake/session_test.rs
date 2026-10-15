//! The session machinery neither real server exercises — token renewal, polling a query still in
//! progress, the response bound — against a **scripted** HTTP server in this file, plus the exact
//! shape of the login and query requests. No model.
//!
//! A scripted server is not evidence that any real server accepts these requests (that is
//! `real_server_test.rs`); it pins down what this client does with answers the two real servers
//! never give: fakesnow and snowflake-emulator issue no expiring tokens and never answer
//! `333334`.

use netget::client::snowflake::{Login, Session, MAX_RESPONSE_BYTES};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[derive(Debug, Clone)]
struct Seen {
    method: String,
    target: String,
    authorization: Option<String>,
    body: Value,
}

type Handler = Box<dyn Fn(&Seen, usize) -> (u16, Vec<u8>) + Send + Sync>;

/// One HTTP/1.1 server answering every request through `handler` (given the request and how
/// many came before it), one request per connection.
async fn scripted(handler: Handler) -> (String, Arc<Mutex<Vec<Seen>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let seen = Arc::new(Mutex::new(Vec::<Seen>::new()));
    let log = seen.clone();
    let handler = Arc::new(handler);
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            let log = log.clone();
            let handler = handler.clone();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 8192];
                let head_end = loop {
                    let n = sock.read(&mut chunk).await.unwrap_or(0);
                    if n == 0 {
                        return;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        break i + 4;
                    }
                };
                let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
                let header = |name: &str| {
                    head.lines().find_map(|l| {
                        let (k, v) = l.split_once(':')?;
                        k.eq_ignore_ascii_case(name).then(|| v.trim().to_string())
                    })
                };
                let len: usize = header("content-length")
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0);
                while buf.len() < head_end + len {
                    let n = sock.read(&mut chunk).await.unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                }
                let mut first = head.lines().next().unwrap_or("").split(' ');
                let req = Seen {
                    method: first.next().unwrap_or("").to_string(),
                    target: first.next().unwrap_or("").to_string(),
                    authorization: header("authorization"),
                    body: serde_json::from_slice(&buf[head_end..]).unwrap_or(Value::Null),
                };
                let index = {
                    let mut log = log.lock().unwrap();
                    log.push(req.clone());
                    log.len() - 1
                };
                let (status, body) = handler(&req, index);
                let reply = format!(
                    "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = sock.write_all(reply.as_bytes()).await;
                let _ = sock.write_all(&body).await;
                let _ = sock.shutdown().await;
            });
        }
    });
    (base, seen)
}

fn ok(v: Value) -> (u16, Vec<u8>) {
    (200, v.to_string().into_bytes())
}

fn login_ok() -> (u16, Vec<u8>) {
    ok(json!({"success": true, "data": {
        "token": "t1", "masterToken": "m1", "sessionId": 1792039932386523000u64,
        "serverVersion": "9.0.0",
        "sessionInfo": {"databaseName": "DB", "schemaName": "PUBLIC", "warehouseName": "WH", "roleName": "R"}
    }}))
}

fn one_row() -> (u16, Vec<u8>) {
    ok(json!({"success": true, "data": {
        "rowtype": [{"name": "N", "type": "fixed", "scale": 0}],
        "rowset": [["42"]], "total": 1, "queryResultFormat": "json", "queryId": "q1"
    }}))
}

fn login() -> Login {
    Login {
        username: "analyst".into(),
        password: "secret".into(),
        account: Some("acct".into()),
        database: Some("DB".into()),
        schema: Some("PUBLIC".into()),
        warehouse: Some("WH".into()),
        role: Some("R".into()),
    }
}

const TIMEOUT: Duration = Duration::from_secs(20);

#[tokio::test]
async fn login_and_query_requests_have_the_connector_shape() {
    let (base, seen) = scripted(Box::new(|req, _| {
        if req.target.starts_with("/session/v1/login-request") {
            login_ok()
        } else {
            one_row()
        }
    }))
    .await;
    let mut s = Session::login(base, &login(), TIMEOUT).await.unwrap();
    assert_eq!(s.info["database"], "DB");
    assert_eq!(s.info["session_id"], "1792039932386523000");
    let (event, data) = s.execute("SELECT 42 AS N", 10).await;
    assert_eq!(event.id, "snowflake_query_result", "{data:#}");
    assert_eq!(data["rows"], json!([{"N": 42}]));

    let seen = seen.lock().unwrap().clone();
    let login_req = &seen[0];
    assert_eq!(login_req.method, "POST");
    for part in [
        "databaseName=DB",
        "schemaName=PUBLIC",
        "warehouse=WH",
        "roleName=R",
        "request_id=",
    ] {
        assert!(
            login_req.target.contains(part),
            "{} lacks {part}",
            login_req.target
        );
    }
    assert_eq!(login_req.authorization, None);
    let d = &login_req.body["data"];
    assert_eq!(d["LOGIN_NAME"], "analyst");
    assert_eq!(d["PASSWORD"], "secret");
    assert_eq!(d["ACCOUNT_NAME"], "acct");
    assert!(d["SESSION_PARAMETERS"].is_object());
    let q = &seen[1];
    assert!(q.target.starts_with("/queries/v1/query-request?requestId="));
    assert_eq!(q.authorization.as_deref(), Some("Snowflake Token=\"t1\""));
    assert_eq!(q.body["sqlText"], "SELECT 42 AS N");
}

#[tokio::test]
async fn an_expired_session_is_renewed_once_with_the_master_token() {
    let (base, seen) = scripted(Box::new(|req, _| {
        if req.target.starts_with("/session/v1/login-request") {
            login_ok()
        } else if req.target.starts_with("/session/token-request") {
            ok(json!({"success": true, "data": {"sessionToken": "t2", "masterToken": "m2"}}))
        } else if req.authorization.as_deref() == Some("Snowflake Token=\"t1\"") {
            ok(json!({"success": false, "code": "390112", "message": "Your session has expired."}))
        } else {
            one_row()
        }
    }))
    .await;
    let mut s = Session::login(base, &login(), TIMEOUT).await.unwrap();
    let (event, data) = s.execute("SELECT 42 AS N", 10).await;
    assert_eq!(event.id, "snowflake_query_result", "{data:#}");
    let seen = seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 4);
    assert_eq!(
        seen[2].authorization.as_deref(),
        Some("Snowflake Token=\"m1\"")
    );
    assert_eq!(
        seen[2].body,
        json!({"oldSessionToken": "t1", "requestType": "RENEW"})
    );
    assert_eq!(
        seen[3].authorization.as_deref(),
        Some("Snowflake Token=\"t2\"")
    );
}

#[tokio::test]
async fn a_refused_renewal_is_reported_and_not_retried() {
    let (base, seen) = scripted(Box::new(|req, _| {
        if req.target.starts_with("/session/v1/login-request") {
            login_ok()
        } else if req.target.starts_with("/session/token-request") {
            ok(json!({"success": false, "code": "390114", "message": "master token expired"}))
        } else {
            ok(json!({"success": false, "code": "390112", "message": "Your session has expired."}))
        }
    }))
    .await;
    let mut s = Session::login(base, &login(), TIMEOUT).await.unwrap();
    let (event, data) = s.execute("SELECT 1", 10).await;
    assert_eq!(event.id, "snowflake_error");
    assert!(
        data["message"]
            .as_str()
            .unwrap()
            .contains("could not be renewed"),
        "{data:#}"
    );
    assert_eq!(
        seen.lock().unwrap().len(),
        3,
        "login, query, one renewal: no loop"
    );
}

#[tokio::test]
async fn a_query_in_progress_is_polled_at_its_result_url() {
    let (base, seen) = scripted(Box::new(|req, index| {
        if req.target.starts_with("/session/v1/login-request") {
            login_ok()
        } else if req.method == "POST" || index < 3 {
            ok(json!({"success": true, "code": "333334", "data": {"getResultUrl": "/queries/q1/result", "queryId": "q1"}}))
        } else {
            one_row()
        }
    }))
    .await;
    let mut s = Session::login(base, &login(), TIMEOUT).await.unwrap();
    let (event, data) = s.execute("SELECT 42 AS N", 10).await;
    assert_eq!(event.id, "snowflake_query_result", "{data:#}");
    assert_eq!(data["rows"], json!([{"N": 42}]));
    let seen = seen.lock().unwrap().clone();
    let polls: Vec<_> = seen.iter().filter(|r| r.method == "GET").collect();
    assert_eq!(polls.len(), 2);
    assert!(polls.iter().all(|r| r.target == "/queries/q1/result"
        && r.authorization.as_deref() == Some("Snowflake Token=\"t1\"")));
}

#[tokio::test]
async fn a_result_url_on_another_origin_is_refused() {
    let (base, seen) = scripted(Box::new(|req, _| {
        if req.target.starts_with("/session/v1/login-request") {
            login_ok()
        } else {
            ok(json!({"success": true, "code": "333333", "data": {
                "getResultUrl": "http://127.0.0.2:9/queries/q1/result"}}))
        }
    }))
    .await;
    let mut s = Session::login(base, &login(), TIMEOUT).await.unwrap();
    let (event, data) = s.execute("SELECT 1", 10).await;
    assert_eq!(event.id, "snowflake_error");
    assert!(
        data["message"].as_str().unwrap().contains("bound to"),
        "{data:#}"
    );
    assert_eq!(seen.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn an_oversized_or_unreadable_response_is_an_error_not_a_result() {
    let (base, _) = scripted(Box::new(|req, _| {
        if req.target.starts_with("/session/v1/login-request") {
            login_ok()
        } else if req.body["sqlText"] == "big" {
            let filler = "x".repeat(MAX_RESPONSE_BYTES + 1024);
            ok(
                json!({"success": true, "data": {"rowtype": [{"name": "T", "type": "text"}],
                "rowset": [[filler]], "queryResultFormat": "json"}}),
            )
        } else {
            (502, b"<html>Bad Gateway</html>".to_vec())
        }
    }))
    .await;
    let mut s = Session::login(base, &login(), TIMEOUT).await.unwrap();
    let (event, data) = s.execute("big", 10).await;
    assert_eq!(
        event.id, "snowflake_error",
        "an oversized response must not decode"
    );
    assert!(data.get("rows").is_none());
    let (event, data) = s.execute("SELECT 1", 10).await;
    assert_eq!(event.id, "snowflake_error");
    assert!(
        data["message"].as_str().unwrap().contains("HTTP 502"),
        "{data:#}"
    );
}

#[tokio::test]
async fn a_refused_login_is_an_error() {
    let (base, _) = scripted(Box::new(|_, _| {
        ok(json!({"success": false, "code": "390100", "message": "Incorrect username or password was specified.", "data": null}))
    }))
    .await;
    let err = match Session::login(base, &login(), TIMEOUT).await {
        Ok(_) => panic!("a refused login produced a session"),
        Err(e) => format!("{e:#}"),
    };
    assert!(
        err.contains("390100") && err.contains("decision=refused"),
        "{err}"
    );
}

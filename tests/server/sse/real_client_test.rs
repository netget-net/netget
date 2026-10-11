//! NetGet's SSE server against two independent event-stream readers:
//!
//! - the **eventsource** npm package, a WHATWG EventSource for Node: it gets a welcome, a
//!   broadcast another request asked for, and — after an injected `sse_close` — reconnects with
//!   `Last-Event-ID`, which the handler answers by resuming from it.
//! - Python's **httpx-sse**: a multi-line event behind a comment, a 204, and a 404 it refuses
//!   to read as a stream.
//!
//! `install_peers.py` prints `NETGET_SSE_NODE_MODULES` and `NETGET_SSE_PYTHON`; the tests fail
//! rather than skip without them. No LLM calls: a python handler answers every request.
use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use netget::state::client_handles::ClientSendOutcome;
use netget::state::{AccessLogOwner, ServerId};
use serde_json::{json, Value};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::mpsc;

const HANDLER: &str = r#"import json,sys
e=json.load(sys.stdin)['event']; p=e['path']; q=e['query']; last=e['last_event_id']
if p=='/news':
  a=[{'type':'sse_accept','retry_ms':200}]
  a+=[{'type':'sse_event','event':'welcome','id':'1','data':'hello'}] if not last else [{'type':'sse_event','event':'resumed','id':str(int(last)+1),'data':'after '+last}]
elif p=='/post':
  a=[{'type':'sse_broadcast','path':'/news','event':'post','id':'2','data':q.get('msg','')},{'type':'sse_respond','status':202,'body':'queued'}]
elif p=='/multi':
  a=[{'type':'sse_accept'},{'type':'sse_comment','text':'hi'},{'type':'sse_event','event':'multi','id':'x','data':'line1\nline2\n\nline4'},{'type':'sse_close'}]
elif p=='/gone':
  a=[{'type':'sse_respond','status':204}]
else:
  a=[{'type':'sse_respond','status':404,'body':'no such stream'}]
print(json.dumps({'actions':a}))"#;

const HTTPX_SSE: &str = r#"import httpx, httpx_sse, json, sys
base=sys.argv[1]; out={}
with httpx.Client(timeout=10) as c:
    with httpx_sse.connect_sse(c, 'GET', base + '/multi') as es:
        out['multi'] = [{'event': s.event, 'data': s.data, 'id': s.id, 'retry': s.retry} for s in es.iter_sse()]
    out['gone'] = c.get(base + '/gone').status_code
    r = c.get(base + '/missing'); out['missing'] = [r.status_code, r.text]
    try:
        with httpx_sse.connect_sse(c, 'GET', base + '/missing') as es:
            next(es.iter_sse())
        out['sse_error'] = None
    except httpx_sse.SSEError as e:
        out['sse_error'] = str(e)
print(json.dumps(out))"#;

fn env(name: &str) -> String {
    let v = std::env::var(name).unwrap_or_default();
    assert!(
        !v.is_empty(),
        "{name} is required: python3 tests/server/sse/install_peers.py <dir> and export what it prints"
    );
    v
}

async fn server() -> (AppState, ServerId, u16) {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    let (tx, _) = mpsc::unbounded_channel();
    let id = ServerForm {
        protocol: "sse".into(),
        port: Some(0),
        host: Some("127.0.0.1".into()),
        instruction: Some("Stream news".into()),
        event_handlers: Some(vec![
            json!({"event_pattern":"*","handler":{"type":"script","language":"python","code":HANDLER}}),
        ]),
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .unwrap();
    let port = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if let Some(a) = state.get_server(id).await.and_then(|s| s.local_addr) {
                break a.port();
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the SSE server never bound");
    (state, id, port)
}

async fn requests(state: &AppState, id: ServerId) -> Vec<Value> {
    let mut rows = state
        .list_access_logs_for(Some(AccessLogOwner::Server(id.as_u32())), None)
        .await
        .iter()
        .map(|e| serde_json::to_value(e).unwrap())
        .filter(|e| e["event_type"] == "sse_request")
        .collect::<Vec<_>>();
    rows.sort_by_key(|e| e["id"].as_u64());
    rows
}

type Lines = tokio::io::Lines<BufReader<tokio::process::ChildStdout>>;

async fn next_line(lines: &mut Lines) -> Value {
    tokio::time::timeout(Duration::from_secs(30), lines.next_line())
        .await
        .expect("EventSource printed nothing")
        .unwrap()
        .map(|l| serde_json::from_str::<Value>(&l).unwrap())
        .expect("EventSource exited")
}

#[tokio::test]
async fn eventsource_gets_broadcasts_and_resumes_with_last_event_id() {
    let modules = env("NETGET_SSE_NODE_MODULES");
    let (state, id, port) = server().await;
    let script = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/server/sse/peer/eventsource.cjs"
    );
    let mut node = tokio::process::Command::new("node")
        .args([script, &modules, &format!("http://127.0.0.1:{port}/news")])
        .stdout(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("node is required");
    let mut lines = BufReader::new(node.stdout.take().unwrap()).lines();

    let welcome = next_line(&mut lines).await;
    assert_eq!(
        welcome,
        json!({"type": "welcome", "data": "hello", "lastEventId": "1"})
    );

    // Another request broadcasts to every /news stream; the handler answers it 202.
    let posted = reqwest::get(format!("http://127.0.0.1:{port}/post?msg=breaking"))
        .await
        .unwrap();
    assert_eq!(posted.status(), 202);
    assert_eq!(posted.text().await.unwrap(), "queued");
    let post = next_line(&mut lines).await;
    assert_eq!(
        post,
        json!({"type": "post", "data": "breaking", "lastEventId": "2"})
    );

    // Close the stream from the server; EventSource reconnects after the 200 ms retry hint,
    // sending the last event ID it saw.
    let conn = requests(&state, id)
        .await
        .into_iter()
        .find(|r| r["request"]["path"] == "/news")
        .and_then(|r| r["connection_id"].as_u64())
        .expect("no /news request") as u32;
    let closed = state
        .send_to_peer(
            id,
            conn,
            json!({"type": "sse_close"}),
            Duration::from_secs(5),
        )
        .await
        .unwrap();
    assert!(
        !matches!(closed, ClientSendOutcome::Rejected { .. }),
        "{closed:?}"
    );
    let mut resumed = next_line(&mut lines).await;
    while resumed["type"] == "error" {
        resumed = next_line(&mut lines).await;
    }
    assert_eq!(
        resumed,
        json!({"type": "resumed", "data": "after 2", "lastEventId": "3"})
    );
    let news: Vec<Value> = requests(&state, id)
        .await
        .into_iter()
        .filter(|r| r["request"]["path"] == "/news")
        .map(|r| r["request"].clone())
        .collect();
    assert_eq!(news.len(), 2, "{news:?}");
    assert_eq!(news[0]["last_event_id"], "");
    assert_eq!(news[1]["last_event_id"], "2");
    assert_eq!(news[1]["accept"], "text/event-stream");
    assert!(node.wait().await.unwrap().success());
}

#[tokio::test]
async fn httpx_sse_reads_a_multiline_event_and_respects_refusals() {
    let python = env("NETGET_SSE_PYTHON");
    let (_state, _id, port) = server().await;
    let out = tokio::time::timeout(
        Duration::from_secs(60),
        tokio::process::Command::new(python)
            .args(["-c", HTTPX_SSE, &format!("http://127.0.0.1:{port}")])
            .kill_on_drop(true)
            .output(),
    )
    .await
    .expect("httpx-sse did not finish")
    .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let r: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(
        r["multi"],
        json!([{"event": "multi", "data": "line1\nline2\n\nline4", "id": "x", "retry": null}]),
        "{r}"
    );
    assert_eq!(r["gone"], 204, "{r}");
    assert_eq!(r["missing"], json!([404, "no such stream"]), "{r}");
    assert!(
        r["sse_error"]
            .as_str()
            .unwrap_or_default()
            .contains("text/event-stream"),
        "httpx-sse must refuse a non-stream answer: {r}"
    );
}

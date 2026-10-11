//! NetGet's SSE client against two independent event-stream servers, **sse-starlette** (under
//! uvicorn) and **aiohttp-sse**. Each sends events, sets a retry hint and closes the stream;
//! NetGet must reconnect after it with `Last-Event-ID`, which the server logs, and the second
//! stream ends with an event the handler answers by disconnecting. A 404 is a refusal with no
//! reconnect. `install_peers.py` (in tests/server/sse) prints `NETGET_SSE_PYTHON`; the test
//! fails rather than skips without it. No LLM calls: a python chain is the model.
use netget::cli::management::ClientForm;
use netget::state::app_state::AppState;
use netget::state::{AccessLogOwner, ClientId, ClientStatus};
use serde_json::{json, Value};
use std::time::Duration;
use tokio::sync::mpsc;

/// Disconnect on an event of type bye; nothing otherwise.
const CHAIN: &str = r#"import json,sys
i=json.load(sys.stdin)
bye=i['event_type_id']=='sse_event_received' and i['event']['event']=='bye'
print(json.dumps({'actions':[{'type':'disconnect'}] if bye else []}))"#;

const STARLETTE: &str = r#"import asyncio, json, sys
from starlette.applications import Starlette
from starlette.routing import Route
from sse_starlette.sse import EventSourceResponse, ServerSentEvent
import uvicorn
log = open(sys.argv[2], 'a')
async def stream(request):
    last = request.headers.get('last-event-id', '')
    log.write(json.dumps({'last_event_id': last}) + '\n'); log.flush()
    async def gen():
        if not last:
            yield ServerSentEvent(data='first', id='1', event='tick', retry=300)
            yield ServerSentEvent(data='line a\nline b', id='2', event='tick')
            return
        yield ServerSentEvent(data='resumed after ' + last, id='3', event='tick')
        yield ServerSentEvent(data='done', id='4', event='bye')
        await asyncio.sleep(30)
    return EventSourceResponse(gen(), ping=60)
app = Starlette(routes=[Route('/events', stream)])
uvicorn.run(app, host='127.0.0.1', port=int(sys.argv[1]), log_level='warning')"#;

const AIOHTTP: &str = r#"import asyncio, json, sys
from aiohttp import web
from aiohttp_sse import sse_response
log = open(sys.argv[2], 'a')
async def stream(request):
    last = request.headers.get('Last-Event-ID', '')
    log.write(json.dumps({'last_event_id': last}) + '\n'); log.flush()
    async with sse_response(request) as resp:
        if not last:
            await resp.send('one', id='10', event='tick', retry=300)
            return resp
        await resp.send('after ' + last, id='11', event='bye')
        await asyncio.sleep(30)
    return resp
app = web.Application()
app.router.add_get('/events', stream)
web.run_app(app, host='127.0.0.1', port=int(sys.argv[1]), print=None)"#;

fn python() -> String {
    let v = std::env::var("NETGET_SSE_PYTHON").unwrap_or_default();
    assert!(
        !v.is_empty(),
        "NETGET_SSE_PYTHON is required: python3 tests/server/sse/install_peers.py <dir> and export what it prints"
    );
    v
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

async fn start(code: &str, log: &std::path::Path) -> (tokio::process::Child, u16) {
    let port = free_port();
    let child = tokio::process::Command::new(python())
        .args(["-c", code, &port.to_string()])
        .arg(log)
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(30), async {
        while tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_err()
        {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the SSE server never listened");
    (child, port)
}

async fn client(state: &AppState, url: String) -> ClientId {
    let (tx, _) = mpsc::unbounded_channel();
    ClientForm {
        protocol: "sse".into(),
        remote_addr: Some(url),
        instruction: Some("Read the stream".into()),
        event_handlers: Some(vec![
            json!({"event_pattern":"*","handler":{"type":"script","language":"python","code":CHAIN}}),
        ]),
        ..Default::default()
    }
    .create(state, netget::llm::OllamaClient::new("http://127.0.0.1:1"), tx)
    .await
    .expect("connect")
}

async fn events(state: &AppState, id: ClientId) -> Vec<(String, Value)> {
    let mut rows: Vec<Value> = state
        .list_access_logs_for(Some(AccessLogOwner::Client(id.as_u32())), None)
        .await
        .iter()
        .map(|e| serde_json::to_value(e).unwrap())
        .collect();
    rows.sort_by_key(|e| e["id"].as_u64());
    rows.into_iter()
        .map(|e| {
            (
                e["event_type"].as_str().unwrap_or_default().to_string(),
                e["request"].clone(),
            )
        })
        .collect()
}

async fn wait_disconnected(state: &AppState, id: ClientId) {
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if matches!(
                state.get_client(id).await.map(|c| c.status),
                Some(ClientStatus::Disconnected)
            ) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the client never disconnected on bye");
}

fn received(events: &[(String, Value)]) -> Vec<Value> {
    events
        .iter()
        .filter(|(k, _)| k == "sse_event_received")
        .map(|(_, v)| v.clone())
        .collect()
}

fn server_log(path: &std::path::Path) -> Vec<String> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .map(|l| {
            serde_json::from_str::<Value>(l).unwrap()["last_event_id"]
                .as_str()
                .unwrap()
                .to_string()
        })
        .collect()
}

#[tokio::test]
async fn netget_reads_sse_starlette_and_resumes_with_last_event_id() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("starlette.log");
    let (_server, port) = start(STARLETTE, &log).await;
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    let id = client(&state, format!("http://127.0.0.1:{port}/events")).await;
    wait_disconnected(&state, id).await;
    let all = events(&state, id).await;
    assert_eq!(
        received(&all),
        vec![
            json!({"event": "tick", "data": "first", "id": "1"}),
            json!({"event": "tick", "data": "line a\nline b", "id": "2"}),
            json!({"event": "tick", "data": "resumed after 2", "id": "3"}),
            json!({"event": "bye", "data": "done", "id": "4"}),
        ],
        "{all:?}"
    );
    let ended: Vec<&Value> = all
        .iter()
        .filter(|(k, _)| k == "sse_stream_ended")
        .map(|(_, v)| v)
        .collect();
    assert_eq!(ended.len(), 1, "{all:?}");
    assert_eq!(ended[0]["reason"], "closed");
    assert_eq!(
        ended[0]["reconnecting_in_ms"], 300,
        "the server's retry hint"
    );
    let connected: Vec<&Value> = all
        .iter()
        .filter(|(k, _)| k == "sse_connected")
        .map(|(_, v)| v)
        .collect();
    assert_eq!(connected[1]["attempt"], 2);
    assert_eq!(connected[1]["last_event_id"], "2");
    assert_eq!(
        server_log(&log),
        ["", "2"],
        "what the server saw as Last-Event-ID"
    );
}

#[tokio::test]
async fn netget_reads_aiohttp_sse_and_stops_on_a_refusal() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("aiohttp.log");
    let (_server, port) = start(AIOHTTP, &log).await;
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    let id = client(&state, format!("http://127.0.0.1:{port}/events")).await;
    wait_disconnected(&state, id).await;
    let all = events(&state, id).await;
    assert_eq!(
        received(&all),
        vec![
            json!({"event": "tick", "data": "one", "id": "10"}),
            json!({"event": "bye", "data": "after 10", "id": "11"}),
        ],
        "{all:?}"
    );
    assert_eq!(server_log(&log), ["", "10"]);

    // A 404 is a refusal: reported once, and no reconnect follows.
    let other = client(&state, format!("http://127.0.0.1:{port}/missing")).await;
    let refused = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if let Some((_, v)) = events(&state, other)
                .await
                .into_iter()
                .find(|(k, _)| k == "sse_stream_ended")
            {
                return v;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("no refusal reported");
    assert_eq!(refused["reason"], "refused", "{refused}");
    assert_eq!(refused["status"], 404, "{refused}");
    assert!(refused.get("reconnecting_in_ms").is_none(), "{refused}");
    tokio::time::sleep(Duration::from_millis(800)).await;
    assert_eq!(server_log(&log).len(), 2, "a refusal is not retried");
}

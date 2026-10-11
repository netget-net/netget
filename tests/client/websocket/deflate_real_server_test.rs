//! NetGet's WebSocket client with RFC 7692 permessage-deflate, against two independent servers:
//!
//! - Python **websockets** 15 (`tests/server/websocket/peer/deflate_peer.py`), whose defaults
//!   cap both windows at 12 bits, behind a relay that records the client's frames. NetGet
//!   sends a 15 000-byte text that repeats at a distance of 5000 — past a 4 KiB window — so a
//!   client that ignored `client_max_window_bits=12` would send back-references the server
//!   cannot follow. The relay shows the frame had RSV1 set and was a fraction of the text.
//! - Node **ws** 8 (`peer/ws_deflate.cjs`) with no context takeover in either direction: two
//!   long messages each way, each compressed from a fresh context.
//!
//! No LLM calls: a script handler sends, answers the echo, and closes. The peers come from
//! `tests/server/websocket/install_peers.py`; the test fails rather than skips without them.
use netget::cli::management::ClientForm;
use netget::state::app_state::AppState;
use netget::state::{AccessLogOwner, ClientId};
use serde_json::{json, Value};
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::mpsc;

fn env(name: &str) -> String {
    let v = std::env::var(name).unwrap_or_default();
    assert!(
        !v.is_empty(),
        "{name} is required: python3 tests/server/websocket/install_peers.py <dir> and export \
         what it prints"
    );
    v
}

/// The same 5000-letter LCG block the peers build, three times.
fn long_text() -> String {
    let mut x: u64 = 1;
    let block: String = (0..5000)
        .map(|_| {
            x = (x * 1103515245 + 12345) % (1 << 31);
            (b'a' + ((x >> 16) % 26) as u8) as char
        })
        .collect();
    block.repeat(3)
}

/// The handler: the long text on connect, `again:` + it on the first echo, close on the second.
fn handler(long: &str) -> String {
    format!(
        r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']; L={long:?}
a=[]
if t=='websocket_client_connected': a=[{{'type':'send_websocket_text','text':L}}]
elif t=='websocket_client_text_message' and e['text']=='echo:'+L: a=[{{'type':'send_websocket_text','text':'again:'+L}}]
elif t=='websocket_client_text_message': a=[{{'type':'close_websocket','code':1000,'reason':'done'}}]
print(json.dumps({{'actions':a}}))"#
    )
}

struct Peer {
    _child: tokio::process::Child,
    lines: tokio::io::Lines<BufReader<tokio::process::ChildStdout>>,
    port: u16,
}

async fn peer(program: &str, args: &[&str]) -> Peer {
    let mut child = tokio::process::Command::new(program)
        .args(args)
        .stdout(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap_or_else(|e| panic!("{program} could not run: {e}"));
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    let ready = next(&mut lines).await;
    let port = ready["port"].as_u64().expect("ready line") as u16;
    Peer {
        _child: child,
        lines,
        port,
    }
}

async fn next(lines: &mut tokio::io::Lines<BufReader<tokio::process::ChildStdout>>) -> Value {
    let line = tokio::time::timeout(Duration::from_secs(30), lines.next_line())
        .await
        .expect("the peer printed nothing")
        .unwrap()
        .expect("the peer exited");
    serde_json::from_str(&line).unwrap()
}

async fn connect(state: &AppState, port: u16, long: &str) -> ClientId {
    let (tx, _) = mpsc::unbounded_channel();
    ClientForm {
        protocol: "websocket".into(),
        remote_addr: Some(format!("127.0.0.1:{port}")),
        instruction: Some("Send and close".into()),
        startup_params: Some(json!({"path": "/deflate"})),
        event_handlers: Some(vec![
            json!({"event_pattern":"*","handler":{"type":"script","language":"python","code":handler(long)}}),
        ]),
        ..Default::default()
    }
    .create(
        state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
        tx,
    )
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

#[tokio::test]
async fn netget_compresses_within_python_websockets_12_bit_window() {
    let python = env("NETGET_WS_PYTHON");
    let script = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/server/websocket/peer/deflate_peer.py"
    );
    let mut server = peer(&python, &[script, "server"]).await;
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    let long = long_text();
    let id = connect(&state, server.port, &long).await;

    let hello = next(&mut server.lines).await;
    assert!(
        hello["negotiated"]
            .as_str()
            .unwrap_or_default()
            .contains("client_max_window_bits=12"),
        "{hello}"
    );
    assert_eq!(next(&mut server.lines).await, json!({"message": long}));
    assert_eq!(
        next(&mut server.lines).await,
        json!({"message": format!("again:{long}")})
    );
    // After NetGet closes, the relay reports what NetGet put on the wire. The frame is
    // compressed, and its size is itself the evidence that the 12-bit window was honoured:
    // within 4 KiB the 5000-byte repeats cannot be referenced, so only entropy coding applies
    // (~15 000 x log2(26) / 8 = 8.8 KB). A 15-bit window would have referenced them and come
    // in near a third of that.
    let first = next(&mut server.lines).await;
    assert_eq!(first["frame"]["rsv1"], true, "{first}");
    let len = first["frame"]["len"].as_u64().unwrap() as usize;
    assert!(len < long.len(), "compressed: {first}");
    assert!(
        len > long.len() / 2,
        "no back-reference past the 4 KiB window, so the repeats stay in: {first}"
    );

    let all = events(&state, id).await;
    let connected = &all
        .iter()
        .find(|(k, _)| k == "websocket_client_connected")
        .unwrap()
        .1;
    assert_eq!(
        connected["permessage_deflate"]["client_max_window_bits"], 12,
        "{connected}"
    );
    let echoes: Vec<&Value> = all
        .iter()
        .filter(|(k, _)| k == "websocket_client_text_message")
        .map(|(_, v)| v)
        .collect();
    assert_eq!(echoes[0]["text"], format!("echo:{long}"));
}

#[tokio::test]
async fn netget_resets_its_context_for_node_ws_without_context_takeover() {
    let modules = env("NETGET_WS_NODE_MODULES");
    let script = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/server/websocket/peer/ws_deflate.cjs"
    );
    let mut server = peer("node", &[script, &modules, "server"]).await;
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    let long = long_text();
    let id = connect(&state, server.port, &long).await;

    let hello = next(&mut server.lines).await;
    assert_eq!(hello["extensions"], "permessage-deflate", "{hello}");
    assert!(
        hello["offer"]
            .as_str()
            .unwrap_or_default()
            .starts_with("permessage-deflate"),
        "NetGet offered the extension: {hello}"
    );
    assert_eq!(next(&mut server.lines).await, json!({"message": long}));
    assert_eq!(
        next(&mut server.lines).await,
        json!({"message": format!("again:{long}")})
    );
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let all = events(&state, id).await;
            if all
                .iter()
                .filter(|(k, _)| k == "websocket_client_text_message")
                .count()
                >= 2
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("both echoes reach the handler");
    let all = events(&state, id).await;
    let connected = &all
        .iter()
        .find(|(k, _)| k == "websocket_client_connected")
        .unwrap()
        .1;
    let params = &connected["permessage_deflate"];
    assert_eq!(params["server_no_context_takeover"], true, "{params}");
    assert_eq!(params["client_no_context_takeover"], true, "{params}");
}

//! RFC 7692 permessage-deflate on NetGet's WebSocket server, against two independent
//! implementations, neither of which shares code with tungstenite or with
//! `src/server/websocket/deflate.rs`:
//!
//! - Python **websockets** 15 (`peer/deflate_peer.py`, CPython's zlib), through a TCP relay
//!   that records each frame's RSV1 bit and length. It sends a short and a long text, a text
//!   message fragmented across three frames and a binary one, and the relay shows every
//!   frame NetGet sent back had RSV1 set and was smaller than the text it carried — the wire
//!   evidence that NetGet compressed, which the library alone cannot give because an
//!   uncompressed frame is legal on a deflate connection.
//! - Node **ws** 8 (`peer/ws_deflate.cjs`, Node's zlib), offering a 10-bit window for the
//!   server's messages and no context takeover either way. The long message repeats at a
//!   distance of 5000 bytes, so a server that ignored the window would send back-references
//!   ws cannot follow.
//!
//! No LLM calls: a script handler accepts every upgrade and echoes. `install_peers.py` prints
//! the variables; both tests fail rather than skip without them.
use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use netget::state::{AccessLogOwner, ServerId};
use serde_json::{json, Value};
use std::time::Duration;
use tokio::sync::mpsc;

const HANDLER: &str = r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']
if t=='websocket_handshake': a=[{'type':'accept_websocket'}]
elif t=='websocket_text_message': a=[{'type':'send_websocket_text','text':'echo:'+e['text']}]
elif t=='websocket_binary_message': a=[{'type':'send_websocket_binary','data':e['data'],'encoding':e['encoding']}]
else: a=[]
print(json.dumps({'actions':a}))"#;

fn env(name: &str) -> String {
    let v = std::env::var(name).unwrap_or_default();
    assert!(
        !v.is_empty(),
        "{name} is required: python3 tests/server/websocket/install_peers.py <dir> and export \
         what it prints"
    );
    v
}

/// The 5000-letter LCG block the peers build too; three of them repeat at distance 5000.
pub fn long_text() -> String {
    let mut x: u64 = 1;
    let block: String = (0..5000)
        .map(|_| {
            x = (x * 1103515245 + 12345) % (1 << 31);
            (b'a' + ((x >> 16) % 26) as u8) as char
        })
        .collect();
    block.repeat(3)
}

async fn server(deflate: bool) -> (AppState, ServerId, u16) {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    let (tx, _) = mpsc::unbounded_channel();
    let id = ServerForm {
        protocol: "websocket".into(),
        port: Some(0),
        host: Some("127.0.0.1".into()),
        instruction: Some("Echo".into()),
        startup_params: Some(json!({"permessage_deflate": deflate})),
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
    .expect("the WebSocket server never bound");
    (state, id, port)
}

async fn run(program: &str, args: &[&str]) -> Value {
    let out = tokio::time::timeout(
        Duration::from_secs(60),
        tokio::process::Command::new(program)
            .args(args)
            .kill_on_drop(true)
            .output(),
    )
    .await
    .unwrap_or_else(|_| panic!("{program} did not finish"))
    .unwrap_or_else(|e| panic!("{program} could not run: {e}"));
    assert!(
        out.status.success(),
        "{program} failed:\n{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).unwrap()
}

async fn opened_events(state: &AppState, id: ServerId) -> Vec<Value> {
    state
        .list_access_logs_for(Some(AccessLogOwner::Server(id.as_u32())), None)
        .await
        .iter()
        .map(|e| serde_json::to_value(e).unwrap())
        .filter(|e| e["event_type"] == "websocket_connection_opened")
        .map(|e| e["request"].clone())
        .collect()
}

#[tokio::test]
async fn python_websockets_reads_compressed_frames_from_netget() {
    let python = env("NETGET_WS_PYTHON");
    let (state, id, port) = server(true).await;
    let script = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/server/websocket/peer/deflate_peer.py"
    );
    let r = run(&python, &[script, "client", &port.to_string()]).await;

    assert_eq!(r["negotiated"], json!(["permessage-deflate"]), "{r}");
    let long = long_text();
    assert_eq!(
        r["replies"],
        json!([
            format!("echo:{}", "hello ".repeat(100)),
            format!("echo:{long}"),
            "echo:part one, part two, part three",
            {"binary": "00ff".repeat(300)},
        ]),
        "{r}"
    );

    // What crossed the wire from NetGet: four data frames, each compressed and each smaller
    // than what it carried.
    let frames: Vec<&Value> = r["server_frames"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["opcode"].as_u64().unwrap_or(8) < 8)
        .collect();
    let sizes = [605usize, long.len() + 5, 35, 600];
    assert_eq!(frames.len(), sizes.len(), "{r}");
    for (frame, plain) in frames.iter().zip(sizes) {
        assert_eq!(
            frame["rsv1"], true,
            "every NetGet data frame is compressed: {r}"
        );
        // A 35-byte text need not shrink; the repetitive ones must.
        if plain > 100 {
            assert!(
                (frame["len"].as_u64().unwrap() as usize) < plain / 2,
                "a compressed frame carries far fewer bytes than its {plain}-byte message: {r}"
            );
        }
    }
    // The client compressed too, including the fragmented message (RSV1 on its first frame).
    let client: Vec<&Value> = r["client_frames"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["opcode"].as_u64().unwrap_or(8) < 8)
        .collect();
    assert!(
        client
            .iter()
            .any(|f| f["fin"] == false && f["rsv1"] == true),
        "{r}"
    );

    let opened = opened_events(&state, id).await;
    assert_eq!(
        opened[0]["permessage_deflate"]["extension"], "permessage-deflate",
        "{opened:?}"
    );
}

#[tokio::test]
async fn node_ws_with_a_small_window_and_no_context_takeover() {
    let modules = env("NETGET_WS_NODE_MODULES");
    let (state, id, port) = server(true).await;
    let script = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/server/websocket/peer/ws_deflate.cjs"
    );
    let r = run("node", &[script, &modules, "client", &port.to_string()]).await;
    let long = long_text();
    assert_eq!(
        r["replies"],
        json!([
            format!("echo:{long}"),
            "echo:short and sweet",
            format!("echo:{long}")
        ]),
        "{r}"
    );
    // ws reports only the extension's name; the parameters are checked on NetGet's side.
    assert_eq!(r["extensions"], "permessage-deflate", "{r}");
    let opened = opened_events(&state, id).await;
    let params = &opened[0]["permessage_deflate"];
    assert_eq!(params["server_max_window_bits"], 10, "{params}");
    assert_eq!(params["server_no_context_takeover"], true, "{params}");
    assert_eq!(params["client_no_context_takeover"], true, "{params}");
}

#[tokio::test]
async fn an_offer_is_declined_when_the_parameter_turns_deflate_off() {
    let python = env("NETGET_WS_PYTHON");
    let (_state, _id, port) = server(false).await;
    let script = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/server/websocket/peer/deflate_peer.py"
    );
    let r = run(&python, &[script, "client", &port.to_string()]).await;
    assert_eq!(r["negotiated"], json!([]), "{r}");
    assert!(r["extensions"].is_null(), "{r}");
    assert!(
        r["server_frames"]
            .as_array()
            .unwrap()
            .iter()
            .all(|f| f["rsv1"] == false),
        "{r}"
    );
}

/// A decompression bomb: a ~1 KB compressed frame that inflates to 1 MB, against a server
/// whose `max_message_size` is 4096. The inflate is bounded while it runs, so the connection
/// ends without the message ever reaching the handler.
#[tokio::test]
async fn a_message_that_inflates_past_the_limit_closes_the_connection() {
    use std::io::Write;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    let (tx, mut status) = mpsc::unbounded_channel();
    let id = ServerForm {
        protocol: "websocket".into(),
        port: Some(0),
        host: Some("127.0.0.1".into()),
        instruction: Some("Echo".into()),
        startup_params: Some(json!({"max_message_size": 4096})),
        event_handlers: Some(vec![
            json!({"event_pattern":"*","handler":{"type":"script","language":"python","code":HANDLER}}),
        ]),
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .unwrap();
    let port = loop {
        if let Some(a) = state.get_server(id).await.and_then(|s| s.local_addr) {
            break a.port();
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    };

    let mut c = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    c.write_all(
        b"GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
          Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\
          Sec-WebSocket-Extensions: permessage-deflate\r\n\r\n",
    )
    .await
    .unwrap();
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        let mut b = [0u8; 1];
        c.read_exact(&mut b).await.unwrap();
        head.push(b[0]);
    }
    let head = String::from_utf8_lossy(&head).to_string();
    assert!(
        head.contains("Sec-WebSocket-Extensions: permessage-deflate"),
        "{head}"
    );

    // Raw deflate (no zlib header), sync-flushed, tail removed: RFC 7692 section 7.2.1.
    let mut enc = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::best());
    enc.write_all(&vec![b'a'; 1_000_000]).unwrap();
    enc.flush().unwrap();
    let mut payload = enc.get_ref().clone();
    if payload.ends_with(&[0, 0, 0xff, 0xff]) {
        payload.truncate(payload.len() - 4);
    }
    assert!(
        payload.len() < 4096,
        "the bomb fits under the frame limit: {}",
        payload.len()
    );
    let mask = [1u8, 2, 3, 4];
    let mut frame = vec![0xC1u8]; // FIN | RSV1 | text
    frame.push(0x80 | 126);
    frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    frame.extend_from_slice(&mask);
    frame.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
    c.write_all(&frame).await.unwrap();

    // The connection ends: EOF, a reset, or a close frame followed by EOF.
    let ended = tokio::time::timeout(Duration::from_secs(10), async {
        let mut buf = [0u8; 256];
        loop {
            match c.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(_) => continue,
            }
        }
    })
    .await;
    assert!(ended.is_ok(), "the server kept the connection open");
    let delivered = state
        .list_access_logs_for(Some(AccessLogOwner::Server(id.as_u32())), None)
        .await
        .iter()
        .map(|e| serde_json::to_value(e).unwrap())
        .filter(|e| e["event_type"] == "websocket_text_message")
        .count();
    assert_eq!(
        delivered, 0,
        "the inflated message must never reach the handler"
    );
    // And it was the inflate bound that refused it, not tungstenite's message limit after a
    // full inflation: only the deflate layer says "inflates past".
    let mut log = Vec::new();
    while let Ok(line) = status.try_recv() {
        log.push(line);
    }
    assert!(
        log.iter()
            .any(|l| l.contains("inflates past 4096") && l.contains("permessage_deflate_refused")),
        "{log:#?}"
    );
}

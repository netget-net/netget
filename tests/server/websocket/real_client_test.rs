//! Every verb NetGet's WebSocket server implements, driven by three independent RFC 6455
//! implementations — none of them tungstenite (the crate this server frames with), and none of
//! them sharing code with each other:
//!
//! - **Python `websockets` 15** (`peer/verbs.py`)
//! - **Node `ws` 8** (`peer/verbs.cjs`)
//! - **`websocat` 1.14.1**, which is rust-websocket (`websocket` / `websocket-base`)
//!
//! The two library clients run the same scenario: an upgrade offering two subprotocols (the
//! server agrees to one) with the greeting the handshake answer carries as the first message;
//! a multi-byte UTF-8 text echoed; non-UTF-8 binary echoed byte for byte; a text message sent
//! as two frames and reassembled; a client Ping answered with a Pong carrying its payload;
//! three seconds of silence across a 2-second idle bound, which the server's keepalive Ping and
//! the client's automatic Pong carry the connection through; a server-initiated close with the
//! handler's code and reason; a client-initiated close echoed with the client's code; an
//! upgrade with no subprotocol offered; and an upgrade the handler refuses with 403.
//! `websocat` drives the subset its command line exposes: subprotocol, text, binary, its own
//! Pings, and a close with a status code.
//!
//! Every session crosses `recording_relay`, and the pcap oracle reads it with Wireshark's
//! `http` and `websocket` dissectors (`require_named("websocket")` on each upgraded session).
//! No LLM calls: a Python script handler answers every event. Each test fails rather than
//! skips when its peer is missing (`install_peers.py` prints `NETGET_WS_PYTHON` and
//! `NETGET_WS_NODE_MODULES`; websocat is `brew install websocat`).

use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use netget::state::{AccessLogOwner, ServerId};
use serde_json::{json, Value};
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;

const HANDLER: &str = r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']
if t=='websocket_handshake':
    if e['path']=='/reject': a=[{'type':'reject_websocket','status_code':403,'reason':'not here'}]
    else:
        acc={'type':'accept_websocket','greeting':'welcome'}
        if 'chat' in e['subprotocols']: acc['subprotocol']='chat'
        a=[acc]
elif t=='websocket_text_message':
    a=[{'type':'close_websocket','code':4002,'reason':'asked to'}] if e['text']=='close please' else [{'type':'send_websocket_text','text':'echo:'+e['text']}]
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

/// A model-free server answered by [`HANDLER`], with a 2-second idle bound so the keepalive
/// Ping fires inside the scenario.
async fn server() -> (AppState, ServerId, u16) {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    let (tx, _) = mpsc::unbounded_channel();
    let id = ServerForm {
        protocol: "websocket".into(),
        port: Some(0),
        host: Some("127.0.0.1".into()),
        instruction: Some("Echo".into()),
        startup_params: Some(json!({"idle_timeout_secs": 2})),
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

async fn events(state: &AppState, id: ServerId, event_type: &str) -> Vec<Value> {
    state
        .list_access_logs_for(Some(AccessLogOwner::Server(id.as_u32())), None)
        .await
        .iter()
        .map(|e| serde_json::to_value(e).unwrap())
        .filter(|e| e["event_type"] == event_type)
        .map(|e| e["request"].clone())
        .collect()
}

async fn run_json(program: &str, args: &[&str]) -> Value {
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
    serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "{program} printed no JSON report ({e}):\n{}\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    })
}

type Streams = std::sync::Arc<std::sync::Mutex<Vec<crate::helpers::recording_relay::Recording>>>;

/// The pcap oracle over every recorded session: Wireshark's `websocket` dissector must read
/// each upgraded one, and its `http` dissector the refused one.
fn oracle(streams: &Streams, upgraded: usize, refused: usize) {
    use crate::helpers::pcap_oracle::PcapOracle;
    use crate::helpers::recording_relay::{recorded, replay};
    let sessions = recorded(streams);
    assert_eq!(
        sessions.len(),
        upgraded + refused,
        "every connection crossed the relay"
    );
    for (i, session) in sessions.iter().enumerate() {
        let head_from_server = session
            .iter()
            .find(|(to_server, _)| !to_server)
            .map(|(_, b)| String::from_utf8_lossy(b).to_string())
            .unwrap_or_default();
        if head_from_server.starts_with("HTTP/1.1 101") {
            replay(
                PcapOracle::tcp("websocket").require_named("websocket"),
                session,
            )
            .assert_clean();
        } else {
            assert!(
                head_from_server.starts_with("HTTP/1.1 403"),
                "session {i} was neither upgraded nor refused: {head_from_server}"
            );
            replay(PcapOracle::tcp("http").require_named("http"), session).assert_clean();
        }
    }
}

/// What the server saw from either library client's scenario.
async fn assert_server_side(state: &AppState, id: ServerId) {
    let handshakes = events(state, id, "websocket_handshake").await;
    assert_eq!(handshakes.len(), 3, "{handshakes:#?}");
    assert!(
        handshakes
            .iter()
            .any(|h| h["subprotocols"] == json!(["v2.chat.example", "chat"])),
        "{handshakes:#?}"
    );
    let pings = events(state, id, "websocket_ping").await;
    assert!(
        pings.iter().any(|p| p["payload"] == "p1"),
        "the client's Ping reached the handler with its payload: {pings:#?}"
    );
    let texts = events(state, id, "websocket_text_message").await;
    assert!(
        texts.iter().any(|t| t["text"] == "fragment"),
        "the two frames were one message: {texts:#?}"
    );
    let closes = events(state, id, "websocket_close").await;
    assert!(
        closes
            .iter()
            .any(|c| c["code"] == 4001 && c["reason"] == "bye"),
        "the client's close code and reason reached the handler: {closes:#?}"
    );
}

#[tokio::test]
async fn python_websockets_drives_every_verb() {
    let python = env("NETGET_WS_PYTHON");
    let (state, id, port) = server().await;
    let (relay, streams) =
        crate::helpers::recording_relay::tcp_relay(format!("127.0.0.1:{port}").parse().unwrap())
            .await;
    let script = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/server/websocket/peer/verbs.py"
    );
    let r = run_json(&python, &[script, &relay.port().to_string()]).await;

    assert_eq!(r["subprotocol"], "chat", "{r}");
    assert_eq!(r["greeting"], "welcome", "{r}");
    assert_eq!(r["text"], "echo:héllo ✓", "{r}");
    assert_eq!(r["binary"], "00fffe01807fc328", "{r}");
    assert_eq!(r["fragmented"], "echo:fragment", "{r}");
    assert_eq!(r["pong_latency_ok"], true, "{r}");
    assert_eq!(r["after_keepalive"], "echo:after the keepalive", "{r}");
    assert_eq!(
        r["server_close"],
        json!({"code": 4002, "reason": "asked to"}),
        "{r}"
    );
    assert!(r["no_subprotocol"].is_null(), "{r}");
    assert_eq!(
        r["client_close_echo"],
        json!({"code": 4001, "reason": "bye"}),
        "{r}"
    );
    assert_eq!(r["reject"], 403, "{r}");
    assert_server_side(&state, id).await;
    oracle(&streams, 2, 1);
}

#[tokio::test]
async fn node_ws_drives_every_verb() {
    let modules = env("NETGET_WS_NODE_MODULES");
    let (state, id, port) = server().await;
    let (relay, streams) =
        crate::helpers::recording_relay::tcp_relay(format!("127.0.0.1:{port}").parse().unwrap())
            .await;
    let script = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/server/websocket/peer/verbs.cjs"
    );
    let r = run_json("node", &[script, &modules, &relay.port().to_string()]).await;

    assert_eq!(r["subprotocol"], "chat", "{r}");
    assert_eq!(r["greeting"], "welcome", "{r}");
    assert_eq!(r["text"], "echo:héllo ✓", "{r}");
    assert_eq!(r["binary"], "00fffe01807fc328", "{r}");
    assert_eq!(r["fragmented"], "echo:fragment", "{r}");
    assert_eq!(r["pong"], "p1", "{r}");
    assert!(
        r["server_pings"].as_u64().unwrap_or(0) >= 1,
        "the server's keepalive Ping reached ws: {r}"
    );
    assert_eq!(r["after_keepalive"], "echo:after the keepalive", "{r}");
    assert_eq!(
        r["server_close"],
        json!({"code": 4002, "reason": "asked to"}),
        "{r}"
    );
    assert_eq!(r["no_subprotocol"], "", "{r}");
    assert_eq!(
        r["client_close_echo"],
        json!({"code": 4001, "reason": "bye"}),
        "{r}"
    );
    assert_eq!(r["reject"], 403, "{r}");
    assert_server_side(&state, id).await;
    oracle(&streams, 2, 1);
}

/// websocat with stdin piped: `input` is written, then stdin stays open until `until` holds
/// (polled against the server's access log), then it is closed and websocat exits.
async fn websocat(
    args: &[&str],
    input: &[u8],
    state: &AppState,
    id: ServerId,
    until: &str,
) -> Vec<u8> {
    let mut child = tokio::process::Command::new("websocat")
        .args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect(
            "websocat is required and is not installed: brew install websocat, cargo install \
             websocat, or https://github.com/vi/websocat/releases — this test fails rather than \
             skips without it",
        );
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(input).await.unwrap();
    stdin.flush().await.unwrap();
    tokio::time::timeout(Duration::from_secs(20), async {
        while events(state, id, until).await.is_empty() {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("the server never saw {until} from websocat"));
    drop(stdin);
    let out = tokio::time::timeout(Duration::from_secs(20), child.wait_with_output())
        .await
        .expect("websocat did not exit after stdin closed")
        .unwrap();
    out.stdout
}

#[tokio::test]
async fn websocat_drives_subprotocol_text_binary_ping_and_close() {
    let (state, id, port) = server().await;
    let (relay, streams) =
        crate::helpers::recording_relay::tcp_relay(format!("127.0.0.1:{port}").parse().unwrap())
            .await;
    let url = format!("ws://127.0.0.1:{}/session", relay.port());

    // Text mode, offering `chat`, Pinging every second, closing with 4001 "bye".
    let out = websocat(
        &[
            "--protocol",
            "chat",
            "--ping-interval",
            "1",
            "--close-status-code",
            "4001",
            "--close-reason",
            "bye",
            &url,
        ],
        "héllo ✓\n".as_bytes(),
        &state,
        id,
        "websocket_ping",
    )
    .await;
    let text = String::from_utf8_lossy(&out);
    assert!(text.contains("welcome"), "{text}");
    assert!(text.contains("echo:héllo ✓"), "{text}");
    let handshakes = events(&state, id, "websocket_handshake").await;
    assert!(
        handshakes
            .iter()
            .any(|h| h["subprotocols"] == json!(["chat"])),
        "{handshakes:#?}"
    );
    let closes = events(&state, id, "websocket_close").await;
    assert!(
        closes
            .iter()
            .any(|c| c["code"] == 4001 && c["reason"] == "bye"),
        "{closes:#?}"
    );

    // Binary mode: stdin's bytes as one binary message, echoed byte for byte.
    let bytes = [0x00u8, 0xff, 0xfe, 0x01, 0x80, 0x7f, 0xc3, 0x28];
    let out = websocat(
        &["--binary", &url],
        &bytes,
        &state,
        id,
        "websocket_binary_message",
    )
    .await;
    assert!(
        out.windows(bytes.len()).any(|w| w == bytes),
        "the binary echo came back unchanged: {out:02x?}"
    );
    oracle(&streams, 2, 0);
}

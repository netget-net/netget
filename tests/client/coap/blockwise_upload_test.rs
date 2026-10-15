//! Block1 uploads (RFC 7959 §2.3) from NetGet's CoAP client.
//!
//! A request body over the client's `block_size` goes out as Block1 blocks, each answered
//! 2.31 Continue, and the model sees **one** `coap_response` — the answer to the last block —
//! with `blocks_sent`. Three servers, none of which shares code with NetGet:
//!
//! - libcoap's **`coap-server`** (C) stores the body in `/example_data`, and libcoap's
//!   **`coap-client`** reads it back byte for byte;
//! - **aiocoap** (Python, `tests/server/coap/peer/aiocoap_peer.py server`) reassembles it and
//!   reports what it got;
//! - a server written here with **coap-lite**, which lowers the block size in its first 2.31
//!   (the client must continue at the smaller size from the right offset) and, in a second
//!   upload, refuses part way with 4.13 (the refusal must reach the model, not stall).
//!
//! No model: a script handler issues the PUT on `coap_connected` — the same answer a model
//! gives, so condition 4 of the client bar (the client acts on the answer, asserted on the
//! wire) is asserted from each server's side. libcoap and aiocoap are not optional: missing,
//! the test fails.

use crate::helpers::real_server::{run_tool, InstallHint, RealServer};
use crate::helpers::E2EResult;
use coap_lite::{CoapOption, MessageClass, MessageType, Packet, ResponseType};
use netget::cli::management::ClientForm;
use netget::state::app_state::AppState;
use netget::state::{AccessLogOwner, ClientId};
use serde_json::{json, Value};
use std::process::{Command, Stdio};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::UdpSocket;

const LIBCOAP: InstallHint = InstallHint {
    brew: "libcoap",
    apt: "libcoap2-bin (Ubuntu 22.04) or libcoap3-bin",
};

/// 3000 pseudo-random letters (an LCG), the same string the Python peers build.
fn body() -> String {
    let mut x: u64 = 1;
    (0..3000)
        .map(|_| {
            x = (x * 1103515245 + 12345) % (1 << 31);
            (b'a' + ((x >> 16) % 26) as u8) as char
        })
        .collect()
}

/// A client whose handler PUTs [`body`] to `path` as soon as it is connected.
async fn uploading_client(
    addr: String,
    path: &str,
    block_size: Option<u64>,
) -> (AppState, ClientId) {
    let handler = format!(
        r#"import json,sys
x=1; L=[]
for _ in range(3000):
    x=(x*1103515245+12345)%2**31; L.append(chr(97+(x>>16)%26))
i=json.load(sys.stdin)
a=[{{'type':'coap_put','path':{path:?},'payload':''.join(L)}}] if i['event_type_id']=='coap_connected' else []
print(json.dumps({{'actions':a}}))"#
    );
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    let (tx, _) = tokio::sync::mpsc::unbounded_channel();
    let id = ClientForm {
        protocol: "coap".into(),
        remote_addr: Some(addr),
        instruction: Some("Upload".into()),
        startup_params: block_size.map(|b| json!({"block_size": b})),
        event_handlers: Some(vec![json!({
            "event_pattern": "*",
            "handler": {"type": "script", "language": "python", "code": handler}
        })]),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
        tx,
    )
    .await
    .expect("the CoAP client did not start");
    (state, id)
}

/// The `coap_response` to the PUT, once it arrives.
async fn put_response(state: &AppState, id: ClientId) -> Value {
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let found = state
                .list_access_logs_for(Some(AccessLogOwner::Client(id.as_u32())), None)
                .await
                .iter()
                .map(|e| serde_json::to_value(e).unwrap())
                .find(|e| e["event_type"] == "coap_response" && e["request"]["method"] == "PUT")
                .map(|e| e["request"].clone());
            if let Some(r) = found {
                break r;
            }
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
    })
    .await
    .expect("no coap_response to the PUT reached the handler")
}

#[tokio::test]
async fn libcoap_stores_a_block1_upload_that_coap_client_reads_back() -> E2EResult<()> {
    let server = RealServer::builder("coap-server", LIBCOAP)
        .args(["-A", "127.0.0.1", "-p", "{port}", "-v", "7"])
        .ready_when_log_matches(r"created UDP\s+endpoint")
        .without_tcp_readiness()
        .start()
        .await?;
    let result = async {
        // 256-byte blocks: twelve of them.
        let (state, id) = uploading_client(server.addr(), "/example_data", Some(256)).await;
        let response = put_response(&state, id).await;
        assert_eq!(
            response["code"].as_str().unwrap_or("")[..2],
            *"2.",
            "{response}"
        );
        assert_eq!(response["blocks_sent"], 12, "{response}");

        let mut get = Command::new("coap-client");
        get.args([
            "-m",
            "get",
            &format!("coap://127.0.0.1:{}/example_data", server.port),
        ]);
        let stored = run_tool(get, "coap-client", LIBCOAP).await?;
        assert_eq!(
            stored.trim_end_matches('\n'),
            body(),
            "libcoap holds the whole body"
        );
        Ok(())
    }
    .await;
    server.with_log(result)
}

#[tokio::test]
async fn aiocoap_reassembles_a_block1_upload() {
    let python = std::env::var("NETGET_AIOCOAP_PYTHON").unwrap_or_default();
    assert!(
        !python.is_empty(),
        "NETGET_AIOCOAP_PYTHON is required: a python with aiocoap 0.4 installed. This test \
         does not skip."
    );
    let script = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/server/coap/peer/aiocoap_peer.py"
    );
    let mut child = tokio::process::Command::new(&python)
        .args(["-I", script, "server"])
        .stdout(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("the aiocoap peer could not run");
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    let ready = next_line(&mut lines).await;
    let port = ready["port"].as_u64().unwrap();

    // The default block size, 1024: three blocks.
    let (state, id) = uploading_client(format!("127.0.0.1:{port}"), "/upload", None).await;
    let put = next_line(&mut lines).await;
    assert_eq!(put["put"]["size"], 3000, "{put}");
    assert_eq!(
        put["put"]["body"],
        body(),
        "aiocoap reassembled the body byte for byte"
    );
    assert_eq!(
        put["put"]["content_format"], 0,
        "text/plain, from the first block"
    );
    let response = put_response(&state, id).await;
    assert_eq!(response["code"], "2.04", "{response}");
    assert_eq!(response["payload"], "stored 3000");
    assert_eq!(response["blocks_sent"], 3);
}

async fn next_line(lines: &mut tokio::io::Lines<BufReader<tokio::process::ChildStdout>>) -> Value {
    let line = tokio::time::timeout(Duration::from_secs(30), lines.next_line())
        .await
        .expect("the aiocoap peer printed nothing")
        .unwrap()
        .expect("the aiocoap peer exited");
    serde_json::from_str(&line).unwrap()
}

/// One Block1 block as the coap-lite server saw it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Seen {
    num: u32,
    more: bool,
    szx: u8,
    len: usize,
}

fn block_value(v: &[u8]) -> (u32, bool, u8) {
    let n = v.iter().fold(0u32, |acc, b| (acc << 8) | u32::from(*b));
    (n >> 4, n & 0x08 != 0, (n & 0x07) as u8)
}

fn block_bytes(num: u32, more: bool, szx: u8) -> Vec<u8> {
    let v = (num << 4) | (u32::from(more) << 3) | u32::from(szx);
    let b = v.to_be_bytes();
    let first = b.iter().position(|&x| x != 0).unwrap_or(4);
    b[first..].to_vec()
}

/// A server that answers Block1 blocks: 2.31 asking for 256-byte blocks after the first one,
/// and, when `refuse_at` is set, 4.13 to that block. Returns the blocks it saw and the body.
async fn shrinking_server(socket: UdpSocket, refuse_at: Option<u32>) -> (Vec<Seen>, Vec<u8>) {
    let mut seen = Vec::new();
    let mut body = Vec::new();
    let mut buf = vec![0u8; 2048];
    loop {
        let (n, from) = socket.recv_from(&mut buf).await.unwrap();
        let req = Packet::from_bytes(&buf[..n]).unwrap();
        let Some(value) = req.get_option(CoapOption::Block1).and_then(|l| l.front()) else {
            continue;
        };
        let (num, more, szx) = block_value(value);
        seen.push(Seen {
            num,
            more,
            szx,
            len: req.payload.len(),
        });
        let mut reply = Packet::new();
        reply.header.set_version(1);
        reply.header.set_type(MessageType::Acknowledgement);
        reply.header.message_id = req.header.message_id;
        reply.set_token(req.get_token().to_vec());
        if refuse_at == Some(num) {
            reply.header.code = MessageClass::Response(ResponseType::RequestEntityTooLarge);
            socket
                .send_to(&reply.to_bytes().unwrap(), from)
                .await
                .unwrap();
            return (seen, body);
        }
        body.extend_from_slice(&req.payload);
        if more {
            reply.header.code = MessageClass::Response(ResponseType::Continue);
            // RFC 7959 §2.3: the server may answer with a smaller SZX; from then on the client
            // must use it. 4 is 256 bytes.
            reply.add_option(CoapOption::Block1, block_bytes(num, true, szx.min(4)));
        } else {
            reply.header.code = MessageClass::Response(ResponseType::Changed);
            reply.add_option(CoapOption::Block1, block_bytes(num, false, szx));
        }
        socket
            .send_to(&reply.to_bytes().unwrap(), from)
            .await
            .unwrap();
        if !more {
            return (seen, body);
        }
    }
}

#[tokio::test]
async fn the_client_continues_at_the_smaller_block_size_a_server_asks_for() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap().to_string();
    let server = tokio::spawn(shrinking_server(socket, None));
    let (state, id) = uploading_client(addr, "/upload", None).await;
    let (seen, received) = tokio::time::timeout(Duration::from_secs(30), server)
        .await
        .expect("the upload never finished")
        .unwrap();
    assert_eq!(received, body().into_bytes(), "every byte, in order, once");
    // Block 0 at 1024 bytes; the server asked for 256, so the next block is number 4 — byte
    // 1024 at the new size — and the last, block 11, carries the remaining 184.
    assert_eq!(
        seen[0],
        Seen {
            num: 0,
            more: true,
            szx: 6,
            len: 1024
        }
    );
    let nums: Vec<u32> = seen.iter().map(|s| s.num).collect();
    assert_eq!(nums, [0, 4, 5, 6, 7, 8, 9, 10, 11]);
    assert!(seen[1..].iter().all(|s| s.szx == 4));
    assert_eq!(seen.last().unwrap().len, 3000 - 1024 - 7 * 256);
    let response = put_response(&state, id).await;
    assert_eq!(response["code"], "2.04");
    assert_eq!(response["blocks_sent"], 9);
}

#[tokio::test]
async fn a_refusal_part_way_through_an_upload_reaches_the_model() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap().to_string();
    let server = tokio::spawn(shrinking_server(socket, Some(5)));
    let (state, id) = uploading_client(addr, "/upload", None).await;
    let (seen, _) = tokio::time::timeout(Duration::from_secs(30), server)
        .await
        .expect("the server never saw block 5")
        .unwrap();
    assert_eq!(seen.last().unwrap().num, 5);
    let response = put_response(&state, id).await;
    assert_eq!(response["code"], "4.13", "{response}");
    assert_eq!(response["blocks_sent"], 3, "blocks 0, 4 and 5 went out");
}

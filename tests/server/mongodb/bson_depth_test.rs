//! An `OP_MSG`'s command document is decoded by `bson` 3.0, whose `RawDocument` → `Document`
//! conversion recurses once per embedded document or array with no depth limit. An embedded
//! document costs the peer seven bytes a level, and in a debug build 284 levels overflow a
//! 2 MiB stack — a `SIGSEGV` on the guard page that takes the whole process down, before any
//! authentication, far under the server's 48 MB message cap.
//!
//! These tests drive `src/utils/bson_depth.rs`'s pre-scan from a raw socket:
//!
//! - a 10 000-level command document gets MongoDB's own depth error (`ok: 0`, code 15
//!   `Overflow`), and both the same connection and a fresh one still get a `hello` answer;
//! - a document exactly at `MAX_BSON_DEPTH` reaches the handler and is answered; one level
//!   deeper is refused;
//! - a document declaring more bytes than the message holds is refused without being decoded.
//!
//! Without the guard the first test does not fail — the test binary aborts with
//! `fatal runtime error: stack overflow`, which is how the defect was confirmed.
//!
//! Zero LLM calls: `hello` is answered in Rust, a `*` static handler answers every command that
//! gets through with an empty `find_response`, and `instruction: Some(String::new())` keeps
//! `ServerForm::create` from substituting a default instruction.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features mongodb-server \
//!       --test server -- server::mongodb::bson_depth --test-threads=100


use std::time::Duration;

use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use netget::state::ServerId;
use netget::utils::bson_depth::MAX_BSON_DEPTH;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

async fn new_state() -> AppState {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".to_string());
    state
        .set_llm_client(netget::llm::OllamaClient::new(
            "http://127.0.0.1:1".to_string(),
        ))
        .await;
    state
}

async fn wait_for_port(state: &AppState, id: ServerId) -> u16 {
    for _ in 0..100 {
        if let Some(s) = state.get_server(id).await {
            if let Some(addr) = s.local_addr {
                return addr.port();
            }
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("MongoDB server #{} never bound a port", id.as_u32());
}

async fn start_server(state: &AppState) -> u16 {
    let (tx, _rx) = mpsc::unbounded_channel();
    let server_id = ServerForm {
        protocol: "mongodb".to_string(),
        port: Some(0),
        instruction: Some(String::new()),
        event_handlers: Some(vec![serde_json::json!({
            "event_pattern": "*",
            "handler": {
                "type": "static",
                "actions": [ { "type": "find_response", "documents": [] } ]
            }
        })]),
        ..Default::default()
    }
    .create(state, tx)
    .await
    .expect("create mongodb server");
    wait_for_port(state, server_id).await
}

/// A BSON document from raw element bytes.
fn document(elements: &[u8]) -> Vec<u8> {
    let len = (4 + elements.len() + 1) as i32;
    let mut out = len.to_le_bytes().to_vec();
    out.extend_from_slice(elements);
    out.push(0);
    out
}

/// One element: type byte, key, NUL, value bytes.
fn element(kind: u8, key: &str, value: &[u8]) -> Vec<u8> {
    let mut out = vec![kind];
    out.extend_from_slice(key.as_bytes());
    out.push(0);
    out.extend_from_slice(value);
    out
}

fn bson_string(s: &str) -> Vec<u8> {
    let mut out = ((s.len() + 1) as i32).to_le_bytes().to_vec();
    out.extend_from_slice(s.as_bytes());
    out.push(0);
    out
}

/// `{a: {a: … {} …}}` with `levels` documents in all, the outermost included.
fn nested(levels: usize) -> Vec<u8> {
    let mut doc = document(&[]);
    for _ in 1..levels {
        doc = document(&element(0x03, "a", &doc));
    }
    doc
}

/// `{find: "c", filter: <filter>, $db: "test"}` — a command document whose depth is the
/// filter's depth plus one.
fn find_command(filter: &[u8]) -> Vec<u8> {
    let mut elements = element(0x02, "find", &bson_string("c"));
    elements.extend(element(0x03, "filter", filter));
    elements.extend(element(0x02, "$db", &bson_string("test")));
    document(&elements)
}

fn hello_command() -> Vec<u8> {
    let mut elements = element(0x10, "hello", &1i32.to_le_bytes());
    elements.extend(element(0x02, "$db", &bson_string("admin")));
    document(&elements)
}

/// An OP_MSG with one kind-0 section carrying `body` verbatim.
fn op_msg(request_id: i32, body: &[u8]) -> Vec<u8> {
    let len = (16 + 4 + 1 + body.len()) as i32;
    let mut msg = len.to_le_bytes().to_vec();
    msg.extend_from_slice(&request_id.to_le_bytes());
    msg.extend_from_slice(&0i32.to_le_bytes());
    msg.extend_from_slice(&2013i32.to_le_bytes());
    msg.extend_from_slice(&0u32.to_le_bytes());
    msg.push(0);
    msg.extend_from_slice(body);
    msg
}

/// Read one OP_MSG reply and return (responseTo, its body document).
async fn read_reply(stream: &mut TcpStream) -> (i32, bson::Document) {
    let mut header = [0u8; 16];
    tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut header))
        .await
        .expect("a reply within 10s")
        .expect("read reply header");
    let len = i32::from_le_bytes(header[0..4].try_into().unwrap());
    let response_to = i32::from_le_bytes(header[8..12].try_into().unwrap());
    let op_code = i32::from_le_bytes(header[12..16].try_into().unwrap());
    assert_eq!(op_code, 2013, "reply must be an OP_MSG");
    let mut body = vec![0u8; (len - 16) as usize];
    tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut body))
        .await
        .expect("reply body within 10s")
        .expect("read reply body");
    assert_eq!(body[4], 0, "reply section must be kind 0");
    let doc = bson::Document::from_reader(&body[5..]).expect("reply is a BSON document");
    (response_to, doc)
}

fn assert_depth_refusal(doc: &bson::Document) {
    assert_eq!(
        doc.get_i32("ok").ok(),
        Some(0),
        "expected ok: 0, got {doc:?}"
    );
    assert_eq!(
        doc.get_i32("code").ok(),
        Some(15),
        "expected MongoDB's Overflow code, got {doc:?}"
    );
    assert_eq!(
        doc.get_str("errmsg").ok(),
        Some("BSONObj exceeded maximum nested object depth"),
        "expected the fixed depth message, got {doc:?}"
    );
}

/// The headline: 10 000 levels, ~70 KB, from a peer that has not authenticated. Before the
/// guard this aborted the whole process.
#[tokio::test]
async fn a_nesting_bomb_is_refused_and_the_server_survives() {
    let state = new_state().await;
    let port = start_server(&state).await;

    let bomb = find_command(&nested(10_000));
    assert!(bomb.len() > 60_000, "the bomb is {} bytes", bomb.len());

    let mut stream = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    stream.write_all(&op_msg(41, &bomb)).await.expect("write");
    let (response_to, doc) = read_reply(&mut stream).await;
    assert_eq!(response_to, 41, "the refusal must answer the request");
    assert_depth_refusal(&doc);

    // The message was read whole, so the connection is still in step: the same socket
    // answers the next command.
    stream
        .write_all(&op_msg(42, &hello_command()))
        .await
        .expect("write hello");
    let (response_to, doc) = read_reply(&mut stream).await;
    assert_eq!(response_to, 42);
    assert_eq!(
        doc.get_i32("ok").ok(),
        Some(1),
        "hello after a refusal: {doc:?}"
    );

    // And the process is still here for everyone else.
    let mut fresh = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect again");
    fresh
        .write_all(&op_msg(1, &hello_command()))
        .await
        .expect("write hello");
    let (_, doc) = read_reply(&mut fresh).await;
    assert_eq!(doc.get_i32("ok").ok(), Some(1), "fresh hello: {doc:?}");
}

/// The bound must not refuse what it allows: a command exactly `MAX_BSON_DEPTH` documents
/// deep reaches the handler; one more is refused.
#[tokio::test]
async fn a_document_at_the_depth_limit_is_answered_and_one_deeper_is_not() {
    let state = new_state().await;
    let port = start_server(&state).await;

    let mut stream = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");

    // The command document is one level, so the filter gets the rest.
    stream
        .write_all(&op_msg(7, &find_command(&nested(MAX_BSON_DEPTH - 1))))
        .await
        .expect("write");
    let (response_to, doc) = read_reply(&mut stream).await;
    assert_eq!(response_to, 7);
    assert_eq!(
        doc.get_i32("ok").ok(),
        Some(1),
        "a command {MAX_BSON_DEPTH} documents deep must reach the handler: {doc:?}"
    );
    assert!(
        doc.get_document("cursor").is_ok(),
        "expected a cursor: {doc:?}"
    );

    stream
        .write_all(&op_msg(8, &find_command(&nested(MAX_BSON_DEPTH))))
        .await
        .expect("write");
    let (response_to, doc) = read_reply(&mut stream).await;
    assert_eq!(response_to, 8);
    assert_depth_refusal(&doc);
}

/// `bson`'s `reader_to_vec` reserves `Vec::with_capacity` from a document's declared length.
/// A document claiming 2 GiB inside a 26-byte message is refused as malformed — the connection
/// closes, as it does for any undecodable OP_MSG. `bson` also ends up rejecting it, so this
/// pins the behaviour rather than proving the scan: what the scan changes is that the refusal
/// now happens before the 2 GiB reservation instead of after it.
#[tokio::test]
async fn a_document_declaring_more_than_the_message_holds_is_refused() {
    let state = new_state().await;
    let port = start_server(&state).await;

    let mut lying = document(&[]);
    lying[0..4].copy_from_slice(&i32::MAX.to_le_bytes());

    let mut stream = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    stream.write_all(&op_msg(3, &lying)).await.expect("write");
    let mut buf = [0u8; 64];
    let n = tokio::time::timeout(Duration::from_secs(10), stream.read(&mut buf))
        .await
        .expect("the server must close within 10s")
        .unwrap_or(0);
    assert_eq!(n, 0, "expected a close, got {:?}", &buf[..n]);

    let mut fresh = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect again");
    fresh
        .write_all(&op_msg(1, &hello_command()))
        .await
        .expect("write hello");
    let (_, doc) = read_reply(&mut fresh).await;
    assert_eq!(doc.get_i32("ok").ok(), Some(1));
}

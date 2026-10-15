//! The dashboard's "message this peer" / "disconnect this peer" paths on a MongoDB server
//! connection: `AppState::send_to_peer` injects an action into one live connection.
//!
//! Zero LLM calls — the `hello` handshake is answered in Rust, a `*` static handler with no
//! actions covers `mongodb_disconnected`, and the injected actions go straight to the
//! protocol's own executor without an event.
//!
//! **What an injected action can and cannot do here.** MongoDB's five wire verbs
//! (`find_response`, `insert_response`, `update_response`, `delete_response`,
//! `error_response`) are `ActionResult::Custom` results, not `ActionResult::Output`: the
//! reply is framed by the read loop, which is the only thing that holds the request's
//! `requestID` and the namespace the command asked for. An OP_MSG reply that is not a
//! response *to* a request has no `responseTo` to carry, so there is nothing an injected one
//! could put on the wire. It is reported as `Executed`, honestly, rather than silently
//! dropped. `close_connection` is the generic path that does reach the socket — half-close,
//! the peer reads EOF.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features mongodb-server \
//!       --test server -- mongodb::peer_inject --test-threads=100


use std::time::Duration;

use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use netget::state::client_handles::ClientSendOutcome;
use netget::state::ServerId;
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

/// The first connection that has a peer handle registered.
async fn wait_for_peer_handle(state: &AppState, id: ServerId) -> u32 {
    for _ in 0..100 {
        if let Some(s) = state.get_server(id).await {
            for conn in s.connections.values() {
                if state.has_peer_handle(id, conn.id.as_u32()).await {
                    return conn.id.as_u32();
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!(
        "MongoDB server #{} never registered a peer handle",
        id.as_u32()
    );
}

/// One OP_MSG carrying `{hello: 1, $db: "admin"}`.
///
/// Hand-built rather than taken from the driver: the point is to exercise this server's own
/// read/reply path through the now-shared write half with no model in the loop, and `hello`
/// is the one command answered in Rust.
fn hello_op_msg(request_id: i32) -> Vec<u8> {
    // BSON: { "hello": int32(1), "$db": "admin" }
    let mut doc: Vec<u8> = Vec::new();
    doc.push(0x10); // int32
    doc.extend_from_slice(b"hello\0");
    doc.extend_from_slice(&1i32.to_le_bytes());
    doc.push(0x02); // string
    doc.extend_from_slice(b"$db\0");
    doc.extend_from_slice(&6i32.to_le_bytes()); // "admin" + NUL
    doc.extend_from_slice(b"admin\0");
    doc.push(0x00); // document terminator
    let doc_len = (doc.len() + 4) as i32;
    let mut bson = doc_len.to_le_bytes().to_vec();
    bson.extend_from_slice(&doc);

    // OP_MSG body: flagBits (4) + sectionKind (1) + document
    let body_len = 4 + 1 + bson.len();
    let mut msg = ((16 + body_len) as i32).to_le_bytes().to_vec();
    msg.extend_from_slice(&request_id.to_le_bytes());
    msg.extend_from_slice(&0i32.to_le_bytes()); // responseTo
    msg.extend_from_slice(&2013i32.to_le_bytes()); // OP_MSG
    msg.extend_from_slice(&0u32.to_le_bytes()); // flagBits
    msg.push(0x00); // section kind 0
    msg.extend_from_slice(&bson);
    msg
}

#[tokio::test]
async fn injected_action_on_mongodb_peer_and_close_sends_eof() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    // A `*` static handler with no actions answers every event without a model call — here
    // that is only `mongodb_disconnected`, since `hello` never reaches the LLM at all.
    let server_id = ServerForm {
        protocol: "mongodb".to_string(),
        port: Some(0),
        event_handlers: Some(vec![serde_json::json!({
            "event_pattern": "*",
            "handler": { "type": "static", "actions": [] }
        })]),
        ..Default::default()
    }
    .create(&state, tx.clone())
    .await
    .expect("create mongodb server");
    let port = wait_for_port(&state, server_id).await;

    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .expect("connect");

    // MongoDB is client-speaks-first, so the handle must exist before any traffic: a `manual`
    // rule parks the very first command, and the operator has to be able to reach the peer
    // while it waits.
    let conn = wait_for_peer_handle(&state, server_id).await;

    // hello -> the Rust-authored handshake reply. No LLM call, and it proves the reader and
    // the reply path still work through the shared Arc<Mutex<WriteHalf>>.
    let hello = hello_op_msg(7);
    stream.write_all(&hello).await.expect("write hello");

    let mut header = [0u8; 16];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut header))
        .await
        .expect("hello reply within 5s")
        .expect("read hello reply header");
    let reply_len = i32::from_le_bytes([header[0], header[1], header[2], header[3]]);
    let response_to = i32::from_le_bytes([header[8], header[9], header[10], header[11]]);
    let op_code = i32::from_le_bytes([header[12], header[13], header[14], header[15]]);
    assert_eq!(response_to, 7, "reply must name the request it answers");
    assert_eq!(op_code, 2013, "reply must be an OP_MSG");
    let mut body = vec![0u8; (reply_len - 16) as usize];
    stream
        .read_exact(&mut body)
        .await
        .expect("read hello reply body");
    assert!(
        String::from_utf8_lossy(&body).contains("maxWireVersion"),
        "the handshake reply must carry the wire-version range"
    );

    // Both directions are counted.
    let server = state.get_server(server_id).await.expect("server");
    let conn_state = server
        .connections
        .values()
        .find(|c| c.id.as_u32() == conn)
        .expect("connection tracked");
    assert_eq!(conn_state.bytes_received, hello.len() as u64);
    assert_eq!(conn_state.bytes_sent, reply_len as u64);
    assert_eq!(conn_state.packets_received, 1);
    assert_eq!(conn_state.packets_sent, 1);

    // A MongoDB wire verb is bound to the request it answers, so an injected one is executed
    // and writes nothing. Asserting the honest outcome rather than pretending it reached the
    // socket is the point of this case.
    let outcome = state
        .send_to_peer(
            server_id,
            conn,
            serde_json::json!({"type": "find_response", "documents": []}),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_peer find_response");
    assert!(
        matches!(outcome, ClientSendOutcome::Executed { .. }),
        "expected Executed, got {outcome:?}"
    );

    // "disconnect this peer": half-close from outside, the socket reads EOF.
    let outcome = state
        .send_to_peer(
            server_id,
            conn,
            serde_json::json!({"type": "close_connection"}),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_peer close");
    assert!(
        matches!(outcome, ClientSendOutcome::Disconnected),
        "expected Disconnected, got {outcome:?}"
    );

    let mut buf = [0u8; 16];
    let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf))
        .await
        .expect("EOF within 5s")
        .expect("read after close");
    assert_eq!(n, 0, "expected EOF after close_connection");

    // The handle goes away with the connection.
    for _ in 0..100 {
        if !state.has_peer_handle(server_id, conn).await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("peer handle still registered after the connection closed");
}

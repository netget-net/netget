//! The dashboard's "message this peer" / "disconnect this peer" path on an SMB connection.
//!
//! `AppState::send_to_peer` injects an action into one live connection through the same
//! executor the LLM path uses. **Zero LLM calls**: the server carries an empty instruction and
//! a `*` static handler with no actions, and the injected actions never reach the model.
//!
//! What an injected action can and cannot do here is the point of the first test. SMB2 cannot
//! encode a response without the request's MessageId, TreeId and SessionId, so
//! `SmbProtocol::execute_action` returns an `ActionResult::Custom` for every wire verb and the
//! server's own loop is what turns it into a frame. Injected from outside a request there is no
//! request to correlate with, so nothing reaches the socket and the honest outcome is
//! `Executed`, not `Sent`. `close_connection` is the exception and the one that matters: it is
//! resolved by the executor itself into a half-close, so `[ disconnect this peer ]` works.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features smb --test server -- smb::peer_inject --test-threads=100

use std::time::Duration;

use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use netget::state::client_handles::ClientSendOutcome;
use netget::state::ServerId;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

/// An `AppState` pointed at a port nothing listens on: any LLM call this test provoked would
/// fail loudly rather than reach a real backend.
async fn new_state() -> AppState {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".to_string());
    state
        .set_llm_client(netget::llm::OllamaClient::new(
            "http://127.0.0.1:1".to_string(),
        ))
        .await;
    state
}

/// A model-free SMB server: an empty instruction, and a `*` rule answering with no actions.
async fn start_smb_server(state: &AppState, tx: mpsc::UnboundedSender<String>) -> ServerId {
    ServerForm {
        protocol: "smb".to_string(),
        port: Some(0),
        // `ServerForm::create` substitutes a default instruction for `None`, which makes the
        // server consult the model. An empty one is what "no model" actually looks like.
        instruction: Some(String::new()),
        event_handlers: Some(vec![serde_json::json!({
            "event_pattern": "*",
            "handler": { "type": "static", "actions": [] }
        })]),
        ..Default::default()
    }
    .create(state, tx)
    .await
    .expect("create smb server")
}

async fn wait_for_port(state: &AppState, id: ServerId) -> u16 {
    for _ in 0..200 {
        if let Some(s) = state.get_server(id).await {
            if let Some(addr) = s.local_addr {
                return addr.port();
            }
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("SMB server #{} never bound a port", id.as_u32());
}

/// The first connection that has a peer handle registered.
async fn wait_for_peer_handle(state: &AppState, id: ServerId) -> u32 {
    for _ in 0..200 {
        if let Some(s) = state.get_server(id).await {
            for conn in s.connections.values() {
                if state.has_peer_handle(id, conn.id.as_u32()).await {
                    return conn.id.as_u32();
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("SMB server #{} never registered a peer handle", id.as_u32());
}

async fn wait_until_handle_gone(state: &AppState, id: ServerId, conn: u32) {
    for _ in 0..200 {
        if !state.has_peer_handle(id, conn).await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("peer handle for connection #{conn} was never removed");
}

#[tokio::test]
async fn injected_close_disconnects_an_smb_peer_that_has_said_nothing() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();
    let server_id = start_smb_server(&state, tx.clone()).await;
    let port = wait_for_port(&state, server_id).await;

    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .expect("connect");

    // SMB2 is client-speaks-first, so the handle has to exist before any traffic: a manual
    // rule can park the very first NEGOTIATE and the operator must be able to reach the peer
    // while it waits.
    let conn = wait_for_peer_handle(&state, server_id).await;

    // A wire verb, injected from outside the connection task. It executes — and writes
    // nothing, because an SMB2 response cannot be built without the MessageId/SessionId of a
    // request that does not exist here. `Executed` is the truthful outcome; a test asserting
    // `Sent` would be asserting a capability this protocol does not have.
    let outcome = state
        .send_to_peer(
            server_id,
            conn,
            serde_json::json!({
                "type": "smb_read_file",
                "path": "/readme.txt",
                "content": "hello"
            }),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_peer");
    match &outcome {
        ClientSendOutcome::Executed { detail } => {
            assert!(
                detail.contains("smb_read_file"),
                "the detail should name the action the executor resolved, got {detail:?}"
            );
        }
        other => panic!("expected Executed for an SMB wire verb, got {other:?}"),
    }

    // Nothing reached the socket: the peer is still waiting for a server that says nothing
    // until spoken to.
    let mut buf = [0u8; 64];
    let idle = tokio::time::timeout(Duration::from_millis(400), stream.read(&mut buf)).await;
    assert!(
        idle.is_err(),
        "an injected SMB verb must not put bytes on the wire, got {idle:?}"
    );

    // "[ disconnect this peer ]": the dashboard sends a bare `close_connection` whatever the
    // protocol calls its own close verb, and the executor half-closes the write half.
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

    let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf))
        .await
        .expect("EOF within 5s")
        .expect("read after close");
    assert_eq!(n, 0, "expected EOF after close_connection");

    wait_until_handle_gone(&state, server_id, conn).await;
}

/// The session's *own* exit path must release the handle too — not just the injected-close
/// shortcut in `peer_support`. A well-framed 64-byte message with a wrong signature is the
/// cheapest way to make the read loop break, and it also pins the received-byte counter: the
/// 4-byte transport header and the 64-byte message are both counted.
#[tokio::test]
async fn the_session_releases_its_peer_handle_when_the_peer_desyncs() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();
    let server_id = start_smb_server(&state, tx.clone()).await;
    let port = wait_for_port(&state, server_id).await;

    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .expect("connect");
    let conn = wait_for_peer_handle(&state, server_id).await;

    // A Direct TCP frame announcing 64 bytes, then 64 bytes whose signature is not
    // `\xFESMB`, so both reads complete and are counted and the loop breaks straight after.
    stream
        .write_all(&super::wire_util::nbss(vec![0x41u8; 64]))
        .await
        .expect("write a bogus SMB2 message");
    stream.flush().await.expect("flush");

    let mut buf = [0u8; 16];
    let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf))
        .await
        .expect("EOF within 5s")
        .expect("read after the server closed");
    assert_eq!(n, 0, "the server closes a connection whose framing is lost");

    wait_until_handle_gone(&state, server_id, conn).await;

    let server = state.get_server(server_id).await.expect("server");
    let conn_state = server
        .connections
        .values()
        .find(|c| c.id.as_u32() == conn)
        .expect("connection still tracked after it closed");
    assert_eq!(
        conn_state.bytes_received,
        4 + 64,
        "the transport header and the message must both be counted"
    );
}

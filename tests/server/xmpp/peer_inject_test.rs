//! The dashboard's "message this peer" / "disconnect this peer" path on an XMPP server
//! connection: `AppState::send_to_peer` injects a wire action into one live connection and the
//! bytes reach the socket. Zero LLM calls — the server is created with an empty instruction and
//! a static rule that answers every event, so nothing reaches the model. The connection (and its
//! peer handle) is registered the instant the connection is accepted, before any event fires.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features xmpp --test server -- xmpp::peer_inject --test-threads=100

#![cfg(unix)]

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
    panic!("XMPP server #{} never bound a port", id.as_u32());
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
        "XMPP server #{} never registered a peer handle",
        id.as_u32()
    );
}

#[tokio::test]
async fn injected_xmpp_action_reaches_raw_socket_and_close_sends_eof() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    // Both fields below are load-bearing, and together they are what keeps this test model-free.
    //
    // `ServerForm::create` substitutes a default instruction when `instruction` is None, so an
    // explicitly empty one is required to leave the server with no natural-language policy.
    //
    // That alone is not enough, because the stats probe further down really does send a stanza,
    // which fires `xmpp_data_received`. With the backend pointed at a dead port that event fails,
    // and a failed event is answered with a *fatal* stream error and a closed stream (RFC 6120
    // §4.9) — correct behaviour, asserted by `llm_failure_test.rs`, but it would tear down the
    // very connection this test injects into. So the event needs a deterministic answer.
    let server_id = ServerForm {
        protocol: "xmpp".to_string(),
        port: Some(0),
        instruction: Some(String::new()),
        event_handlers: Some(vec![serde_json::json!({
            "event_pattern": "*",
            // `wait_for_more` is the protocol's own "write nothing, keep reading" verb, so the
            // stream stays open and no byte reaches the peer. An empty `actions` array does NOT
            // work here: the event still reaches `call_llm`, which fails against the dead
            // backend and now closes the stream, which this test would then race against.
            "handler": { "type": "static", "actions": [ { "type": "wait_for_more" } ] }
        })]),
        ..Default::default()
    }
    .create(&state, tx.clone())
    .await
    .expect("create xmpp server");
    let port = wait_for_port(&state, server_id).await;

    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .expect("connect");

    let conn = wait_for_peer_handle(&state, server_id).await;

    // A wire verb, injected from outside the connection task. `send_message` returns
    // ActionResult::Output, which the generic peer task writes to this connection's write half.
    let outcome = state
        .send_to_peer(
            server_id,
            conn,
            serde_json::json!({
                "type": "send_message",
                "from": "bot@localhost",
                "to": "alice@localhost",
                "body": "dashboard-marker"
            }),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_peer");
    let bytes_sent = match outcome {
        ClientSendOutcome::Sent { bytes_sent } => bytes_sent,
        other => panic!("expected Sent, got {other:?}"),
    };
    assert!(bytes_sent > 0, "expected a non-empty stanza");

    // The stanza reached the socket, escaping and all.
    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf))
        .await
        .expect("injected stanza within 5s")
        .expect("read injected stanza");
    let got = String::from_utf8_lossy(&buf[..n]);
    assert!(
        got.contains("<message") && got.contains("dashboard-marker"),
        "expected the injected message stanza, got {got:?}"
    );

    // The read-side counter moves without a *successful* LLM call: the server bumps
    // `bytes_received` in its read loop the instant bytes arrive, before it hands the buffer to
    // the model (whose endpoint here is unreachable). This proves `update_connection_stats` is
    // wired on the read path. (The injected write above goes through the generic peer task in
    // `server::peer_support`, which does not touch the counters, so it is not asserted here.)
    let probe = b"<presence/>";
    stream.write_all(probe).await.expect("write probe");
    stream.flush().await.expect("flush probe");
    let mut moved = false;
    for _ in 0..100 {
        if let Some(s) = state.get_server(server_id).await {
            if let Some(c) = s.connections.values().find(|c| c.id.as_u32() == conn) {
                if c.bytes_received >= probe.len() as u64 {
                    moved = true;
                    break;
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    assert!(
        moved,
        "bytes_received should count the probe the client sent"
    );

    // "disconnect this peer" injects `close_connection` (an explicit arm in execute_action, not
    // offered to the model), which returns ActionResult::CloseConnection, so the generic task
    // half-closes the write side.
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

    // Half-close from outside -> the socket reads EOF.
    let mut sink = vec![0u8; 4096];
    let eof = loop {
        let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut sink))
            .await
            .expect("EOF within 5s")
            .expect("read after close");
        if n == 0 {
            break true;
        }
    };
    assert!(eof, "expected EOF after close_stream");

    // The handle goes away with the injected close.
    for _ in 0..100 {
        if !state.has_peer_handle(server_id, conn).await {
            // Also flush the client write half so the server's read loop unblocks cleanly.
            let _ = stream.shutdown().await;
            return;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("peer handle still registered after the injected close");
}

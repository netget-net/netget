//! The dashboard's "message this peer" / "disconnect this peer" path on a BitTorrent tracker
//! connection: `AppState::send_to_peer` injects a wire action into one live connection and the
//! bytes reach the socket.
//!
//! **Zero LLM calls.** The instruction is empty and the `*` rule is a static handler, so the
//! model is never consulted — `ServerForm::create` substitutes a default instruction when
//! `instruction` is `None`, which is enough to make the server dynamic, so it is set explicitly
//! here rather than left to `..Default::default()`.
//!
//! The window under test is the one that matters for this protocol: a tracker says nothing
//! until the announce arrives, and a `manual` rule parks that announce for a human. The handle
//! must therefore exist **before the peer has spoken at all** — which is what
//! `wait_for_peer_handle` asserts by running before a single byte is written.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features torrent-tracker \
//!       --test server -- torrent_tracker::peer_inject --test-threads=100


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
    panic!("tracker server #{} never bound a port", id.as_u32());
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
        "tracker server #{} never registered a peer handle",
        id.as_u32()
    );
}

#[tokio::test]
async fn injected_tracker_action_reaches_raw_socket_and_close_sends_eof() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    let server_id = ServerForm {
        protocol: "torrent_tracker".to_string(),
        port: Some(0),
        // Empty, not absent: `ServerForm::create` substitutes a default instruction for
        // `None`, and any non-empty instruction makes the server consult the model.
        instruction: Some(String::new()),
        event_handlers: Some(vec![serde_json::json!({
            "event_pattern": "*",
            "handler": {
                "type": "static",
                "actions": [ {
                    "type": "send_announce_response",
                    "interval": 1800,
                    "complete": 1,
                    "incomplete": 0,
                    "compact": 1,
                    "peers": []
                } ]
            }
        })]),
        ..Default::default()
    }
    .create(&state, tx.clone())
    .await
    .expect("create torrent_tracker server");
    let port = wait_for_port(&state, server_id).await;

    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .expect("connect");

    // Nothing has been written by either side yet. A tracker connection spends its whole
    // life in this state while a parked announce waits for a human, so this is exactly the
    // point at which the operator must be able to reach the peer.
    let conn = wait_for_peer_handle(&state, server_id).await;

    // A wire verb, injected from outside the connection task, before the peer has spoken.
    let outcome = state
        .send_to_peer(
            server_id,
            conn,
            serde_json::json!({
                "type": "send_announce_response",
                "interval": 900,
                "complete": 2,
                "incomplete": 3,
                "compact": 1,
                "peers": [{"ip": "127.0.0.1", "port": 6881}]
            }),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_peer");
    let bytes_sent = match outcome {
        ClientSendOutcome::Sent { bytes_sent } => bytes_sent,
        other => panic!("expected Sent, got {other:?}"),
    };
    assert!(bytes_sent > 0, "injected action wrote nothing");

    let mut buf = vec![0u8; 512];
    let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf))
        .await
        .expect("injected response within 5s")
        .expect("read injected response");
    let response = String::from_utf8_lossy(&buf[..n]).to_string();
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "expected an HTTP 200 tracker response, got {response:?}"
    );
    assert!(
        response.contains("i900e"),
        "the bencoded body should carry the injected interval, got {response:?}"
    );

    // The injected write is counted like any other: the rail's ↑ counter reads these.
    let mut counted = false;
    for _ in 0..100 {
        let server = state.get_server(server_id).await.expect("server");
        if let Some(c) = server.connections.values().find(|c| c.id.as_u32() == conn) {
            if c.bytes_sent as usize >= bytes_sent {
                counted = true;
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    assert!(counted, "bytes_sent did not count the injected write");

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

    let mut tail = [0u8; 16];
    let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut tail))
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

/// The protocol's own path still works alongside the handle, and the connection entry is
/// closed when the exchange ends.
///
/// The second half is the defect this adoption exposed: `handle_connection` never called
/// `close_connection_on_server`, and `torrent_tracker` is not `.connectionless()`, so every
/// peer the tracker ever served stayed drawn as a live row for the life of the server.
#[tokio::test]
async fn announce_still_answered_and_the_connection_entry_is_closed() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    let server_id = ServerForm {
        protocol: "torrent_tracker".to_string(),
        port: Some(0),
        instruction: Some(String::new()),
        event_handlers: Some(vec![serde_json::json!({
            "event_pattern": "*",
            "handler": {
                "type": "static",
                "actions": [ {
                    "type": "send_announce_response",
                    "interval": 1800,
                    "compact": 1,
                    "peers": []
                } ]
            }
        })]),
        ..Default::default()
    }
    .create(&state, tx.clone())
    .await
    .expect("create torrent_tracker server");
    let port = wait_for_port(&state, server_id).await;

    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .expect("connect");
    let conn = wait_for_peer_handle(&state, server_id).await;

    stream
        .write_all(b"GET /announce?info_hash=%01%02&peer_id=%03&port=6881 HTTP/1.1\r\n\r\n")
        .await
        .expect("write announce");

    let mut buf = vec![0u8; 512];
    let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf))
        .await
        .expect("static answer within 5s")
        .expect("read static answer");
    assert!(
        String::from_utf8_lossy(&buf[..n]).starts_with("HTTP/1.1 200"),
        "expected the static handler's 200"
    );

    for _ in 0..200 {
        let server = state.get_server(server_id).await.expect("server");
        let closed = server
            .connections
            .values()
            .find(|c| c.id.as_u32() == conn)
            .map(|c| c.status != netget::state::server::ConnectionStatus::Active)
            .unwrap_or(true);
        if closed && !state.has_peer_handle(server_id, conn).await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("connection entry stayed Active, or the peer handle outlived the exchange");
}

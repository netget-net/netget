//! The dashboard's "message this peer" / "disconnect this peer" paths on an MSSQL server
//! connection: `AppState::send_to_peer` injects an action into one live connection.
//!
//! Zero LLM calls — PRELOGIN is answered in Rust, nothing here reaches LOGIN7 or a batch, and
//! the injected actions go straight to the protocol's own executor without an event.
//!
//! **What an injected action can and cannot do here.** MSSQL's wire verbs
//! (`mssql_query_response`, `mssql_ok_response`, `mssql_error_response`, `mssql_login_ack`)
//! are `ActionResult::Custom` results, not `ActionResult::Output`: the TDS token stream they
//! describe is framed by the read loop, which is the only thing that knows which request it
//! is answering. TDS has no unsolicited server message — every server packet is a typed
//! response to a request — so there is nothing an injected one could legally put on the wire.
//! It is reported as `Executed`, honestly, rather than silently dropped. `close_connection`
//! is the generic path that does reach the socket: half-close, and the peer reads EOF.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features mssql \
//!       --test server -- mssql::peer_inject --test-threads=100

use std::time::Duration;

use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use netget::state::client_handles::ClientSendOutcome;
use netget::state::ServerId;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

/// TDS PRELOGIN packet type, and the TABULAR_RESULT type the server answers it with.
const TDS_PRELOGIN: u8 = 0x12;
const TDS_TABULAR_RESULT: u8 = 0x04;

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
    panic!("MSSQL server #{} never bound a port", id.as_u32());
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
        "MSSQL server #{} never registered a peer handle",
        id.as_u32()
    );
}

/// Frame one TDS message as a single EOM packet.
fn tds_packet(packet_type: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + payload.len());
    out.push(packet_type);
    out.push(0x01); // status: EOM
    out.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    out.extend_from_slice(&[0x00, 0x00]); // SPID
    out.push(0x01); // packet id
    out.push(0x00); // window
    out.extend_from_slice(payload);
    out
}

/// A minimal PRELOGIN: a VERSION token and the terminator. The server does not read the
/// payload, so this only has to be a well-formed 0x12 packet.
fn prelogin() -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(0x00); // VERSION token
    payload.extend_from_slice(&6u16.to_be_bytes()); // offset
    payload.extend_from_slice(&6u16.to_be_bytes()); // length
    payload.push(0xFF); // terminator
    payload.extend_from_slice(&[0x10, 0x00, 0x00, 0x00, 0x00, 0x00]);
    tds_packet(TDS_PRELOGIN, &payload)
}

#[tokio::test]
async fn injected_action_on_mssql_peer_and_close_sends_eof() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    // A `*` static handler with no actions means no event here can reach a model. Nothing in
    // this test fires one — PRELOGIN is answered in Rust — but an unintended LLM call would
    // otherwise hit the unreachable endpoint above and surface as a timeout rather than as
    // the thing it is.
    let server_id = ServerForm {
        protocol: "mssql".to_string(),
        port: Some(0),
        event_handlers: Some(vec![serde_json::json!({
            "event_pattern": "*",
            "handler": { "type": "static", "actions": [] }
        })]),
        ..Default::default()
    }
    .create(&state, tx.clone())
    .await
    .expect("create mssql server");
    let port = wait_for_port(&state, server_id).await;

    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .expect("connect");

    // TDS is client-speaks-first, so the handle must exist before any traffic: a `manual` rule
    // parks the login itself, and the operator has to be able to reach the peer while it waits.
    let conn = wait_for_peer_handle(&state, server_id).await;

    // PRELOGIN -> the Rust-authored response. No LLM call, and it proves the reader and the
    // reply path still work through the shared Arc<Mutex<WriteHalf>>.
    let request = prelogin();
    stream.write_all(&request).await.expect("write PRELOGIN");

    let mut header = [0u8; 8];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut header))
        .await
        .expect("PRELOGIN reply within 5s")
        .expect("read PRELOGIN reply header");
    assert_eq!(
        header[0], TDS_TABULAR_RESULT,
        "PRELOGIN is answered with a TABULAR_RESULT packet"
    );
    let total = u16::from_be_bytes([header[2], header[3]]) as usize;
    assert!(total > 8, "PRELOGIN reply carries a payload");
    let mut payload = vec![0u8; total - 8];
    stream
        .read_exact(&mut payload)
        .await
        .expect("read PRELOGIN reply payload");
    assert_eq!(
        payload.last(),
        Some(&0x00),
        "the PRELOGIN response ends with the ThreadID field"
    );

    // Both directions are counted.
    let server = state.get_server(server_id).await.expect("server");
    let conn_state = server
        .connections
        .values()
        .find(|c| c.id.as_u32() == conn)
        .expect("connection tracked");
    assert_eq!(conn_state.bytes_received, request.len() as u64);
    assert_eq!(conn_state.bytes_sent, total as u64);
    assert_eq!(conn_state.packets_received, 1);
    assert_eq!(conn_state.packets_sent, 1);

    // A TDS wire verb is bound to the request it answers, so an injected one is executed and
    // writes nothing. Asserting the honest outcome rather than pretending it reached the
    // socket is the point of this case.
    let outcome = state
        .send_to_peer(
            server_id,
            conn,
            serde_json::json!({
                "type": "mssql_query_response",
                "columns": [{"name": "id", "type": "INT"}],
                "rows": [[1]]
            }),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_peer mssql_query_response");
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

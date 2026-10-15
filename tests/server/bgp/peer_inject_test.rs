//! The dashboard's "message this peer" / "disconnect this peer" path on a BGP server
//! connection: `AppState::send_to_peer` injects a wire action into one live session and the
//! bytes reach the socket. Zero LLM calls — the server is created with an *explicitly empty*
//! instruction (the form substitutes a default one otherwise), so the session
//! completes its handshake on the configured OPEN without consulting a model.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features bgp --test server -- bgp::peer_inject --test-threads=100


use std::net::Ipv4Addr;
use std::time::Duration;

use netget::cli::management::ServerForm;
use netget::server::bgp::wire;
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
    panic!("BGP server #{} never bound a port", id.as_u32());
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
    panic!("BGP server #{} never registered a peer handle", id.as_u32());
}

/// One framed BGP message: `(type, full octets)`.
async fn read_bgp_message(stream: &mut TcpStream) -> (u8, Vec<u8>) {
    let mut header = [0u8; wire::BGP_HEADER_LEN];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut header))
        .await
        .expect("BGP header within 5s")
        .expect("read BGP header");
    let (len, msg_type) = wire::parse_header(&header).expect("valid BGP header");
    let mut full = vec![0u8; len];
    full[..wire::BGP_HEADER_LEN].copy_from_slice(&header);
    if len > wire::BGP_HEADER_LEN {
        stream
            .read_exact(&mut full[wire::BGP_HEADER_LEN..])
            .await
            .expect("read BGP body");
    }
    (msg_type, full)
}

#[tokio::test]
async fn injected_bgp_action_reaches_raw_socket_and_close_sends_cease_then_eof() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    // hold_time 0 turns the keepalive ticker off, so every byte this test reads is one it
    // caused.
    let server_id = ServerForm {
        protocol: "bgp".to_string(),
        port: Some(0),
        // Load-bearing: `ServerForm::create` substitutes a default instruction when this is
        // None, and any non-empty instruction makes `operator_wants_dynamic` true, which sends
        // bgp_open to the model. An empty one is what actually keeps this test model-free.
        instruction: Some(String::new()),
        startup_params: Some(serde_json::json!({
            "as_number": 65001,
            "router_id": "10.0.0.1",
            "hold_time": 0,
        })),
        ..Default::default()
    }
    .create(&state, tx.clone())
    .await
    .expect("create bgp server");
    let port = wait_for_port(&state, server_id).await;

    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .expect("connect");

    // The handle exists from the first byte, before any handshake.
    let conn = wait_for_peer_handle(&state, server_id).await;

    // Complete the handshake with the real codec: OPEN -> (OPEN, KEEPALIVE) -> KEEPALIVE.
    let open =
        wire::encode(wire::build_open(65002, 0, Ipv4Addr::new(10, 0, 0, 2))).expect("encode OPEN");
    stream.write_all(&open).await.expect("send OPEN");
    let (t, _) = read_bgp_message(&mut stream).await;
    assert_eq!(t, wire::MSG_OPEN, "expected the server's OPEN");
    let (t, _) = read_bgp_message(&mut stream).await;
    assert_eq!(t, wire::MSG_KEEPALIVE, "expected the server's KEEPALIVE");
    stream
        .write_all(&wire::encode_keepalive())
        .await
        .expect("send KEEPALIVE");

    // A wire verb, injected from outside the session task. BGP's verbs yield Custom intents;
    // the peer task encodes them through the same wire::encode_intent the session uses.
    let outcome = state
        .send_to_peer(
            server_id,
            conn,
            serde_json::json!({"type": "send_bgp_keepalive"}),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_peer keepalive");
    assert!(
        matches!(outcome, ClientSendOutcome::Sent { bytes_sent: 19 }),
        "expected Sent{{19}}, got {outcome:?}"
    );
    let (t, bytes) = read_bgp_message(&mut stream).await;
    assert_eq!(t, wire::MSG_KEEPALIVE);
    assert_eq!(bytes, wire::encode_keepalive());

    // An UPDATE with routes: the injected intent is encoded at the negotiated AS width.
    let outcome = state
        .send_to_peer(
            server_id,
            conn,
            serde_json::json!({
                "type": "send_bgp_update",
                "nlri": ["203.0.113.0/24"], "next_hop": "10.0.0.1", "as_path": [65001], "origin": "IGP",
            }),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_peer update");
    let ClientSendOutcome::Sent { bytes_sent } = outcome else {
        panic!("expected Sent, got {outcome:?}");
    };
    let (t, bytes) = read_bgp_message(&mut stream).await;
    assert_eq!(t, wire::MSG_UPDATE);
    assert_eq!(bytes.len(), bytes_sent);
    let decoded = wire::decode(&bytes, true).expect("decode injected UPDATE");
    let netgauze_bgp_pkt::BgpMessage::Update(update) = decoded else {
        panic!("expected UPDATE, got {decoded:?}");
    };
    assert_eq!(update.nlri().len(), 1);

    // Counters moved in both directions. The inbound OPEN was certainly counted (its reply was
    // read above, and the session counts before it dispatches); the later KEEPALIVE may still
    // be in flight, so it is not relied on.
    let server = state.get_server(server_id).await.expect("server");
    let conn_state = server
        .connections
        .values()
        .find(|c| c.id.as_u32() == conn)
        .expect("connection tracked");
    assert!(
        conn_state.bytes_received >= open.len() as u64,
        "bytes_received should count the OPEN, got {}",
        conn_state.bytes_received
    );
    assert!(
        conn_state.bytes_sent >= (19 + 19 + bytes_sent) as u64,
        "bytes_sent should count everything written, got {}",
        conn_state.bytes_sent
    );
    assert!(conn_state.packets_received >= 1);
    assert!(conn_state.packets_sent >= 4);

    // An action the protocol rejects is reported, not silently swallowed.
    let outcome = state
        .send_to_peer(
            server_id,
            conn,
            serde_json::json!({"type": "send_bgp_update", "nlri": ["not-a-prefix"]}),
            Duration::from_secs(5),
        )
        .await;
    assert!(
        outcome.is_err() || matches!(outcome, Ok(ClientSendOutcome::Rejected { .. })),
        "expected a rejection, got {outcome:?}"
    );

    // "disconnect this peer": Cease / Administrative Shutdown, then EOF.
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
    let (t, bytes) = read_bgp_message(&mut stream).await;
    assert_eq!(t, wire::MSG_NOTIFICATION);
    assert_eq!(
        &bytes[wire::BGP_HEADER_LEN..],
        &[wire::ERR_CEASE, wire::SUB_CEASE_ADMIN_SHUTDOWN]
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

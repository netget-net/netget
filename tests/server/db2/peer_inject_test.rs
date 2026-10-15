//! The dashboard's peer-injection paths on a Db2 (DRDA) server connection:
//! `AppState::send_to_peer` injects an action into one live connection. Zero LLM
//! calls — the one exchange (EXCSAT → EXCSATRD) needs no model, and the injected
//! actions go through the protocol's own executor.
//!
//! Db2's four wire verbs (`db2_accept_connection`, `db2_reject_connection`,
//! `db2_query_ok`, `db2_query_error`) are correlator-bound `ActionResult::Custom`
//! results, so an injected one is reported as executed without writing bytes;
//! `close_connection` is the generic path that does reach the wire (half-close,
//! the peer reads EOF).
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features db2 --test server -- db2::peer_inject --test-threads=100

use std::time::Duration;

use netget::cli::management::ServerForm;
use netget::server::db2::drda;
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
    panic!("Db2 server #{} never bound a port", id.as_u32());
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
    panic!("Db2 server #{} never registered a peer handle", id.as_u32());
}

/// Read exactly one DSS reply from the stream and parse it.
async fn read_dss(stream: &mut TcpStream) -> drda::ParsedDss {
    let mut header = [0u8; 6];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut header))
        .await
        .expect("read DSS header timed out")
        .expect("read DSS header");
    let total = u16::from_be_bytes([header[0], header[1]]) as usize;
    let mut rest = vec![0u8; total - 6];
    stream.read_exact(&mut rest).await.expect("read DSS body");
    let mut buf = header.to_vec();
    buf.extend_from_slice(&rest);
    let (parsed, _consumed) = drda::parse_dss(&buf).expect("parse reply DSS");
    parsed
}

#[tokio::test]
async fn injected_close_connection_sends_eof_and_counters_move() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    // No event handlers are needed: the one exchange (EXCSAT) is answered by the
    // server with no LLM call, and the injected actions go through the executor.
    let server_id = ServerForm {
        protocol: "db2".to_string(),
        port: Some(0),
        ..Default::default()
    }
    .create(&state, tx.clone())
    .await
    .expect("create db2 server");
    let port = wait_for_port(&state, server_id).await;

    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .expect("connect");

    let conn = wait_for_peer_handle(&state, server_id).await;

    // EXCSAT → EXCSATRD (no LLM). Proves the reader/reply path still works through
    // the now-shared Arc<Mutex<WriteHalf>> and moves the connection counters.
    let excsat = drda::encode_dss(
        drda::DSSFMT_RQSDSS,
        false,
        1,
        &drda::encode_object(
            drda::cp::EXCSAT,
            &drda::encode_scalar_str(drda::cp::EXTNAM, "peer-inject-client"),
        ),
    );
    stream.write_all(&excsat).await.expect("write EXCSAT");
    let rd = read_dss(&mut stream).await;
    assert_eq!(rd.codepoint, drda::cp::EXCSATRD, "expected EXCSATRD");
    assert_eq!(rd.correlator, 1);

    // Counters moved on both directions.
    let server = state.get_server(server_id).await.expect("server");
    let conn_state = server
        .connections
        .values()
        .find(|c| c.id.as_u32() == conn)
        .expect("connection tracked");
    assert_eq!(conn_state.bytes_received, excsat.len() as u64);
    assert!(conn_state.bytes_sent > 0, "server wrote the EXCSATRD reply");
    assert_eq!(conn_state.packets_received, 1);
    assert_eq!(conn_state.packets_sent, 1);

    // A Db2 wire verb is correlator-bound: injected, it is executed but writes nothing.
    let outcome = state
        .send_to_peer(
            server_id,
            conn,
            serde_json::json!({"type": "db2_accept_connection"}),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_peer db2_accept_connection");
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

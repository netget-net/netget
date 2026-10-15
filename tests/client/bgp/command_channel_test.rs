//! The dashboard's `[ send_keepalive ]` / `[ disconnect ]` path on a BGP client:
//! `AppState::send_to_client` injects an action from outside the client's read loop and the
//! bytes reach a NetGet BGP server of our own. Zero LLM calls — the server has no policy, so
//! its handshake is static, and the client has no instruction, so its `bgp_connected` event
//! never consults a model.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features bgp --test client -- bgp::command_channel --test-threads=100
//!
//! Condition waits here poll for up to ~30s (1_000 x 30ms).
//!
//! That budget is deliberately generous, and it is not a latency assertion: the loop exits
//! the moment the condition holds, so a healthy run costs milliseconds. It was 3s, which is
//! ample when this test runs alone and far too little at `--test-threads=100`, where the
//! handshake it waits on competes with a hundred other tests for the runtime. The test then
//! reported the condition as never happening when it simply had not happened *yet* -- a
//! failure that pointed at the protocol instead of at the deadline.


use std::time::Duration;

use netget::cli::management::{ClientForm, ServerForm};
use netget::state::app_state::AppState;
use netget::state::client_handles::ClientSendOutcome;
use netget::state::server::ConnectionStatus;
use netget::state::{AccessLogOwner, ClientId, ClientStatus, ServerId};
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
    for _ in 0..1_000 {
        if let Some(s) = state.get_server(id).await {
            if let Some(addr) = s.local_addr {
                return addr.port();
            }
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("BGP server #{} never bound a port", id.as_u32());
}

async fn wait_for_client_handle(state: &AppState, id: ClientId) {
    for _ in 0..1_000 {
        if state.has_client_handle(id).await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!(
        "BGP client #{} never registered a command handle",
        id.as_u32()
    );
}

/// Wait until the server's one connection reports Established and return its inbound byte count.
async fn wait_for_established(state: &AppState, id: ServerId) -> u64 {
    for _ in 0..1_000 {
        if let Some(s) = state.get_server(id).await {
            if let Some(conn) = s.connections.values().next() {
                if conn.protocol_info.get("bgp_state") == Some(&serde_json::json!("Established")) {
                    return conn.bytes_received;
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!(
        "BGP session on server #{} never reached Established",
        id.as_u32()
    );
}

async fn wait_for_log_containing(state: &AppState, owner: AccessLogOwner, needle: &str) {
    for _ in 0..1_000 {
        for entry in state.list_access_logs_for(Some(owner), None).await {
            if serde_json::to_string(&entry)
                .unwrap_or_default()
                .contains(needle)
            {
                return;
            }
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("no access-log entry for {owner:?} containing {needle:?}");
}

#[tokio::test]
async fn injected_bgp_client_action_reaches_our_own_server() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    // hold_time 0 on both sides: no keepalive tickers, so every inbound byte the server counts
    // after Established is one this test injected.
    let server_id = ServerForm {
        protocol: "bgp".to_string(),
        port: Some(0),
        startup_params: Some(serde_json::json!({
            "as_number": 65001,
            "router_id": "10.0.0.1",
            "hold_time": 0,
        })),
        // The server answers bgp_open through the LLM and fails CLOSED when it cannot
        // reach one -- deliberately, so a peering policy that cannot be evaluated never
        // admits a neighbour. This test points its LLM at an unreachable URL, so without
        // a static handler here the handshake can never complete and the session never
        // reaches Established. This is the shape the protocol's own
        // `get_startup_examples()` documents.
        event_handlers: Some(vec![serde_json::json!({
            "event_pattern": "bgp_open",
            "handler": {
                "type": "static",
                "actions": [{
                    "type": "send_bgp_open",
                    "my_as": 65001,
                    "hold_time": 0,
                    "router_id": "10.0.0.1"
                }]
            }
        })]),
        ..Default::default()
    }
    .create(&state, tx.clone())
    .await
    .expect("create bgp server");
    let port = wait_for_port(&state, server_id).await;

    let client_id = ClientForm {
        protocol: "bgp".to_string(),
        remote_addr: Some(format!("127.0.0.1:{port}")),
        startup_params: Some(serde_json::json!({
            "local_as": 65002,
            "router_id": "10.0.0.2",
            "hold_time": 0,
        })),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
        tx.clone(),
    )
    .await
    .expect("create bgp client");

    wait_for_client_handle(&state, client_id).await;
    let before = wait_for_established(&state, server_id).await;

    // The client's own wire verb, injected from outside its loop.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "send_keepalive"}),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_client");
    assert!(
        matches!(outcome, ClientSendOutcome::Sent { bytes_sent: 19 }),
        "expected Sent{{19}}, got {outcome:?}"
    );

    // Recorded on the client like LLM-produced traffic, and received by the server.
    wait_for_log_containing(
        &state,
        AccessLogOwner::Client(client_id.as_u32()),
        "injected_action",
    )
    .await;
    let mut seen = false;
    for _ in 0..1_000 {
        let server = state.get_server(server_id).await.expect("server");
        let conn = server.connections.values().next().expect("connection");
        if conn.bytes_received >= before + 19 {
            seen = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    assert!(seen, "server never counted the injected KEEPALIVE");

    // An injected disconnect writes a Cease NOTIFICATION and ends the session on both sides.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "disconnect"}),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_client disconnect");
    assert!(
        matches!(outcome, ClientSendOutcome::Disconnected),
        "expected Disconnected, got {outcome:?}"
    );

    let mut client_down = false;
    let mut server_side_closed = false;
    for _ in 0..1_000 {
        if let Some(c) = state.get_client(client_id).await {
            client_down = c.status == ClientStatus::Disconnected;
        }
        if let Some(s) = state.get_server(server_id).await {
            server_side_closed = s
                .connections
                .values()
                .all(|c| c.status == ConnectionStatus::Closed);
        }
        if client_down && server_side_closed {
            // The handle goes with the session: the rail must stop offering [ send ].
            assert!(
                !state.has_client_handle(client_id).await,
                "command handle still registered after the read loop exited"
            );
            return;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("after injected disconnect: client_down={client_down} server_side_closed={server_side_closed}");
}

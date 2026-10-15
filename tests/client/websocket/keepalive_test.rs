//! NetGet's WebSocket client keeps answering Pings while a model turn is parked.
//!
//! The peer is NetGet's own WebSocket server with `idle_timeout_secs = 2`: it Pings at half the
//! bound and closes with 1001 a peer that sends no frame at all — not even a Pong — for two
//! seconds. Two of the client's turns are parked on `manual` rules for ten seconds each — its
//! `websocket_client_connected` turn, then the turn for the server's reply to what it sent — and
//! after each the test checks, from the server's side, that the connection is still live, then
//! answers it and checks that the answer arrived.
//!
//! That only holds if something keeps polling the client's stream while the turn waits:
//! tungstenite queues a Pong when it reads a Ping and flushes it on the *next* read. A client
//! that ran the model turn inside its read loop — or, for the connected turn, before starting
//! the read loop at all — read nothing for the whole turn, and the server hung up on it.
//!
//! This is NetGet against NetGet on purpose: the server's liveness bound is the thing the client
//! has to satisfy, and it is the one peer here with a configurable bound short enough to test.
//! It is regression evidence for the client's keep-alive, not interoperability evidence.
//!
//! Zero LLM calls: every server event is answered by a static rule, the one client event by the
//! manual rule, and both model URLs are unreachable.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features websocket --test client -- websocket::keepalive --test-threads=100


use std::time::Duration;

use netget::cli::management::{ClientForm, ServerForm};
use netget::state::app_state::AppState;
use netget::state::intercepts::InterceptOwner;
use netget::state::{AccessLogOwner, ClientStatus, ServerId};
use tokio::sync::mpsc;

/// The server's liveness bound, in seconds. It Pings at half of it.
const IDLE_TIMEOUT_SECS: u64 = 2;
/// How long the connected turn stays parked: five server windows.
const PARKED_FOR: Duration = Duration::from_secs(10);

async fn wait_for_port(state: &AppState, id: ServerId) -> u16 {
    for _ in 0..1_000 {
        if let Some(s) = state.get_server(id).await {
            if let Some(addr) = s.local_addr {
                return addr.port();
            }
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("WebSocket server #{} never bound a port", id.as_u32());
}

async fn live_connections(state: &AppState, id: ServerId) -> usize {
    state
        .get_server(id)
        .await
        .map(|s| {
            s.connections
                .values()
                .filter(|c| !matches!(c.status, netget::state::server::ConnectionStatus::Closed))
                .count()
        })
        .unwrap_or(0)
}

async fn wait_for_client_intercept(
    state: &AppState,
    event_type: &str,
) -> netget::state::intercepts::InterceptView {
    for _ in 0..500 {
        if let Some(v) =
            state.list_intercepts().await.into_iter().find(|v| {
                matches!(v.owner, InterceptOwner::Client(_)) && v.event_type == event_type
            })
        {
            return v;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("the client's {event_type} turn never parked");
}

async fn wait_for_server_log(state: &AppState, id: ServerId, needle: &str) {
    for _ in 0..500 {
        if state
            .list_access_logs_for(Some(AccessLogOwner::Server(id.as_u32())), None)
            .await
            .iter()
            .any(|e| {
                serde_json::to_string(e)
                    .unwrap_or_default()
                    .contains(needle)
            })
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("{needle:?} never reached the server");
}

#[tokio::test]
async fn websocket_client_survives_a_parked_turn_longer_than_the_servers_idle_bound() {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".to_string());
    state
        .set_llm_client(netget::llm::OllamaClient::new(
            "http://127.0.0.1:1".to_string(),
        ))
        .await;
    let (tx, _rx) = mpsc::unbounded_channel();

    let server_id = ServerForm {
        protocol: "websocket".to_string(),
        port: Some(0),
        instruction: Some(String::new()),
        startup_params: Some(serde_json::json!({"idle_timeout_secs": IDLE_TIMEOUT_SECS})),
        event_handlers: Some(vec![
            serde_json::json!({
                "event_pattern": "websocket_handshake",
                "handler": {"type": "static", "actions": [{"type": "accept_websocket"}]}
            }),
            // Every text message is answered, so the client has a message turn to park too.
            serde_json::json!({
                "event_pattern": "websocket_text_message",
                "handler": {"type": "static", "actions": [
                    {"type": "send_websocket_text", "text": "server-reply"}
                ]}
            }),
            // Everything else is answered with nothing: the assertions are the connection
            // table and the access log.
            serde_json::json!({
                "event_pattern": "*",
                "handler": {"type": "static", "actions": []}
            }),
        ]),
        ..Default::default()
    }
    .create(&state, tx.clone())
    .await
    .expect("create websocket server");
    let port = wait_for_port(&state, server_id).await;

    // Created in the background: nothing about the connected turn should hold up `create`, and
    // the test must not deadlock if it does.
    let client_form = ClientForm {
        protocol: "websocket".to_string(),
        remote_addr: Some(format!("127.0.0.1:{port}")),
        instruction: Some("keepalive test client".to_string()),
        event_handlers: Some(vec![
            serde_json::json!({
                "event_pattern": "websocket_client_connected",
                "handler": {"type": "manual", "timeout_secs": 120}
            }),
            serde_json::json!({
                "event_pattern": "websocket_client_text_message",
                "handler": {"type": "manual", "timeout_secs": 120}
            }),
        ]),
        ..Default::default()
    };
    let state_bg = state.clone();
    let tx_bg = tx.clone();
    let create = tokio::spawn(async move {
        client_form
            .create(
                &state_bg,
                netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
                tx_bg,
            )
            .await
    });

    let intercept = wait_for_client_intercept(&state, "websocket_client_connected").await;
    assert_eq!(
        live_connections(&state, server_id).await,
        1,
        "the server should hold the client's connection"
    );

    // The parked interval is the scenario itself, not a wait for a condition: a human who takes
    // ten seconds to answer. The server Pings every second and gives up after two.
    tokio::time::sleep(PARKED_FOR).await;

    assert_eq!(
        live_connections(&state, server_id).await,
        1,
        "the server closed the client's connection while its turn was parked for {}s against \
         a {}s liveness bound — the client stopped answering Pings",
        PARKED_FOR.as_secs(),
        IDLE_TIMEOUT_SECS
    );

    state
        .resolve_intercept(
            intercept.id,
            vec![serde_json::json!({"type": "send_websocket_text", "text": "still-here"})],
        )
        .await
        .expect("answer the parked websocket_client_connected turn");

    let client_id = tokio::time::timeout(Duration::from_secs(10), create)
        .await
        .expect("ClientForm::create never returned")
        .unwrap()
        .expect("create websocket client");

    // The answered turn's message reached the server.
    wait_for_server_log(&state, server_id, "still-here").await;

    // Second half: a *message* turn, which runs while the read loop keeps reading. The server
    // answered "still-here" with a reply; the client's turn for that reply parks.
    let intercept = wait_for_client_intercept(&state, "websocket_client_text_message").await;
    tokio::time::sleep(PARKED_FOR).await;
    assert_eq!(
        live_connections(&state, server_id).await,
        1,
        "the server closed the client's connection while a message turn was parked for {}s \
         against a {}s liveness bound — the client stopped answering Pings",
        PARKED_FOR.as_secs(),
        IDLE_TIMEOUT_SECS
    );
    state
        .resolve_intercept(
            intercept.id,
            vec![serde_json::json!({"type": "send_websocket_text", "text": "second-turn"})],
        )
        .await
        .expect("answer the parked websocket_client_text_message turn");
    wait_for_server_log(&state, server_id, "second-turn").await;

    assert!(
        matches!(
            state.get_client(client_id).await.map(|c| c.status),
            Some(ClientStatus::Connected)
        ),
        "the client must still be connected; status is {:?}",
        state.get_client(client_id).await.map(|c| c.status)
    );
    assert_eq!(live_connections(&state, server_id).await, 1);
}

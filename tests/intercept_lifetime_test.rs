//! A request parked by a `manual` handler lives exactly as long as the connection it came
//! from.
//!
//! The defect this pins: a peer hung up while its request was parked, and the request stayed
//! in `list_intercepts`; answering it reported "Answered" and the server counted the bytes it
//! wrote into the closed connection. Two things now hold, both asserted against `AppState`
//! directly — the MCP tools and the dashboard both drive these same methods:
//!
//! 1. **Closing the connection (or stopping the instance) withdraws the request.** The waiting
//!    dispatcher wakes at once with "no answer" and takes the fail-closed path, and the
//!    request leaves the list.
//! 2. **Answering a request whose connection has already ended is refused**, even if it is
//!    still parked — the case of a request parked after its connection closed, or one whose
//!    protocol learned of the close late. Nothing is delivered.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use netget::server::connection::ConnectionId;
use netget::state::client::{ClientId, ClientInstance, ClientStatus};
use netget::state::intercepts::InterceptOwner;
use netget::state::server::{
    ConnectionState, ConnectionStatus, ProtocolConnectionInfo, ServerId, ServerInstance,
};
use netget::state::AppState;

fn connection(id: u32) -> ConnectionState {
    let addr: SocketAddr = format!("127.0.0.1:{}", 41000 + id).parse().unwrap();
    ConnectionState {
        id: ConnectionId::new(id),
        remote_addr: addr,
        local_addr: "127.0.0.1:6379".parse().unwrap(),
        bytes_sent: 0,
        bytes_received: 0,
        packets_sent: 0,
        packets_received: 0,
        last_activity: Instant::now(),
        status: ConnectionStatus::Active,
        status_changed_at: Instant::now(),
        protocol_info: ProtocolConnectionInfo::new(serde_json::json!({})),
    }
}

async fn server_with_connection(state: &AppState, conn: u32) -> ServerId {
    let server = ServerInstance::new(ServerId::new(0), 6379, "redis".into(), String::new());
    let server_id = state.add_server(server).await;
    state
        .add_connection_to_server(server_id, connection(conn))
        .await;
    server_id
}

async fn park(
    state: &AppState,
    owner: InterceptOwner,
    connection_id: Option<u32>,
) -> (u64, tokio::sync::oneshot::Receiver<Vec<serde_json::Value>>) {
    state
        .park_intercept(
            owner,
            connection_id,
            "redis_subscribe",
            "SUBSCRIBE news",
            Some(serde_json::json!({"command": "SUBSCRIBE", "channels": ["news"]})),
            300,
        )
        .await
}

/// The waiting dispatcher must learn the request is gone now, not after its 300s timeout.
async fn assert_withdrawn(rx: tokio::sync::oneshot::Receiver<Vec<serde_json::Value>>) {
    match tokio::time::timeout(Duration::from_secs(2), rx).await {
        Ok(Err(_)) => {}
        Ok(Ok(actions)) => panic!("a withdrawn request must deliver nothing, got {actions:?}"),
        Err(_) => panic!("the dispatcher was left waiting on a request whose peer is gone"),
    }
}

#[tokio::test]
async fn closing_the_connection_withdraws_its_parked_request() {
    let state = AppState::new();
    let server_id = server_with_connection(&state, 5).await;
    let (id, rx) = park(&state, InterceptOwner::Server(server_id), Some(5)).await;
    // A request on another connection of the same server is not touched.
    state
        .add_connection_to_server(server_id, connection(6))
        .await;
    let (other, _other_rx) = park(&state, InterceptOwner::Server(server_id), Some(6)).await;
    assert_eq!(state.list_intercepts().await.len(), 2);

    state
        .close_connection_on_server(server_id, ConnectionId::new(5))
        .await;

    assert_withdrawn(rx).await;
    let listed: Vec<u64> = state.list_intercepts().await.iter().map(|v| v.id).collect();
    assert_eq!(
        listed,
        vec![other],
        "only the closed connection's request leaves the list"
    );
    let err = state
        .resolve_intercept(id, vec![serde_json::json!({"type": "redis_error"})])
        .await
        .expect_err("a withdrawn request cannot be answered");
    assert!(err.contains("no longer waiting"), "{err}");
}

#[tokio::test]
async fn answering_a_request_whose_connection_has_ended_is_refused() {
    let state = AppState::new();
    let server_id = server_with_connection(&state, 7).await;
    state
        .close_connection_on_server(server_id, ConnectionId::new(7))
        .await;
    // Parked after the close was recorded — what a protocol that learns of the close late
    // (or a dispatcher racing it) produces.
    let (id, rx) = park(&state, InterceptOwner::Server(server_id), Some(7)).await;

    let err = state
        .resolve_intercept(
            id,
            vec![serde_json::json!({"type": "redis_accept_subscription"})],
        )
        .await
        .expect_err("an answer for a closed connection must not be reported as delivered");
    assert!(
        err.contains("connection #7 has closed"),
        "the refusal says why: {err}"
    );
    assert_withdrawn(rx).await;
    assert!(state.list_intercepts().await.is_empty());
}

#[tokio::test]
async fn a_request_whose_closed_connection_was_reaped_is_not_listed() {
    let state = AppState::new();
    let server_id = server_with_connection(&state, 8).await;
    state
        .close_connection_on_server(server_id, ConnectionId::new(8))
        .await;
    // The closed connection moves to the server's history.
    state.cleanup_closed_connections(0).await;
    let (_id, rx) = park(&state, InterceptOwner::Server(server_id), Some(8)).await;

    assert!(
        state.list_intercepts().await.is_empty(),
        "a request for a connection in the closed history is nobody's to answer"
    );
    assert_withdrawn(rx).await;
}

#[tokio::test]
async fn stopping_the_server_withdraws_its_requests() {
    let state = AppState::new();
    let server_id = server_with_connection(&state, 9).await;
    let (_id, rx) = park(&state, InterceptOwner::Server(server_id), Some(9)).await;

    state.remove_server(server_id).await;

    assert_withdrawn(rx).await;
    assert!(state.list_intercepts().await.is_empty());
}

#[tokio::test]
async fn a_disconnected_client_withdraws_its_requests() {
    let state = AppState::new();
    let client_id = state
        .add_client(ClientInstance::new(
            ClientId::new(0),
            "127.0.0.1:6379".into(),
            "redis".into(),
            String::new(),
        ))
        .await;
    state
        .update_client_status(client_id, ClientStatus::Connected)
        .await;
    let (_id, rx) = park(&state, InterceptOwner::Client(client_id), None).await;
    assert_eq!(state.list_intercepts().await.len(), 1);

    state
        .update_client_status(client_id, ClientStatus::Disconnected)
        .await;

    assert_withdrawn(rx).await;
    assert!(state.list_intercepts().await.is_empty());
}

/// The live case is unchanged: a request on an open connection is answered and delivered.
#[tokio::test]
async fn a_live_connections_request_is_still_answered() {
    let state = AppState::new();
    let server_id = server_with_connection(&state, 10).await;
    let (id, rx) = park(&state, InterceptOwner::Server(server_id), Some(10)).await;

    let answer = vec![serde_json::json!({"type": "redis_accept_subscription"})];
    state
        .resolve_intercept(id, answer.clone())
        .await
        .expect("a live connection's request is answerable");
    assert_eq!(rx.await.expect("delivered"), answer);
}

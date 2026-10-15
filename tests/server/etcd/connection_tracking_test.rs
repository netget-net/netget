//! An etcd server's connections must be visible in `AppState`.
//!
//! This server tracked none: it never minted a `ConnectionId`, never called
//! `add_connection_to_server`, and never recorded a byte. The dashboard rail therefore drew
//! every etcd server with an empty `peers` node however much traffic it was serving, and no
//! part of the UI could tell a busy server from an idle one.
//!
//! Nothing here needs the LLM: the assertion is about connection bookkeeping, and a TCP
//! connection is tracked from the moment it is accepted, before any request is sent.


use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use netget::state::ServerId;
use std::time::Duration;
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
    panic!("etcd server #{} never bound a port", id.as_u32());
}

/// How many connections `AppState` currently holds for this server, in whatever status.
async fn connection_count(state: &AppState, id: ServerId) -> usize {
    state
        .get_server(id)
        .await
        .map(|s| s.connections.len())
        .unwrap_or(0)
}

#[tokio::test]
async fn etcd_connections_appear_in_app_state_and_close_when_the_peer_goes() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    // An empty instruction keeps this genuinely model-free: `ServerForm::create` substitutes
    // a default instruction for `None`, which would make the server consult the model.
    let server_id = ServerForm {
        protocol: "etcd".to_string(),
        port: Some(0),
        instruction: Some(String::new()),
        ..Default::default()
    }
    .create(&state, tx.clone())
    .await
    .expect("create etcd server");
    let port = wait_for_port(&state, server_id).await;

    assert_eq!(
        connection_count(&state, server_id).await,
        0,
        "a freshly bound etcd server should have no connections"
    );

    let stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .expect("connect to the etcd server");

    let mut tracked = false;
    for _ in 0..100 {
        if connection_count(&state, server_id).await == 1 {
            tracked = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    assert!(
        tracked,
        "an accepted etcd connection never reached AppState, so the dashboard rail cannot \
         show it"
    );

    // Dropping the socket ends `serve_connection`, which must mark the connection closed
    // rather than leaving it Active forever. etcd is not `.connectionless()`, so the 10s idle
    // sweep would never reap it either.
    drop(stream);

    let mut closed = false;
    for _ in 0..200 {
        if let Some(s) = state.get_server(server_id).await {
            if !s.connections.is_empty()
                && s.connections
                    .values()
                    .all(|c| matches!(c.status, netget::state::server::ConnectionStatus::Closed))
            {
                closed = true;
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    assert!(
        closed,
        "the etcd connection stayed Active after the peer hung up"
    );

    state.remove_server(server_id).await;
}

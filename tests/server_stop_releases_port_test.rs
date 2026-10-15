//! Regression test: stopping a server must release its listening socket.
//!
//! Before the fix, protocol `spawn` implementations discarded the accept/recv
//! loop `JoinHandle`, so `remove_server` could not abort it. Dropping a Tokio
//! `JoinHandle` only detaches the task — the loop kept running and held the
//! socket, so the port leaked until process exit. These tests start a real
//! server (TCP via Telnet, UDP via the UDP protocol), stop it, and assert the
//! port can be rebound **as soon as `remove_server` returns**. An abort only
//! requests cancellation; `remove_server` now waits for the aborted tasks, so a
//! stop followed by a start on the same port cannot race the runtime. (These
//! tests used to poll for a second, and two ICS suites that rebound at once
//! failed on loaded CI runners.)
//!
//! No Ollama required — no client ever connects, so no LLM call is made.
//!
//! Run with (either or both features):
//!   ./cargo-isolated.sh test --no-default-features --features telnet,udp --test server_stop_releases_port_test -- --test-threads=100

use netget::state::app_state::AppState;
use netget::state::server::ServerInstance;
use netget::state::ServerId;
use std::net::SocketAddr;
use std::sync::Arc;

/// True if a plain (non-reuse) TCP bind on `addr` succeeds — i.e. the port is free.
fn tcp_port_is_free(addr: SocketAddr) -> bool {
    std::net::TcpListener::bind(addr).is_ok()
}

/// True if a plain UDP bind on `addr` succeeds — i.e. the port is free.
fn udp_port_is_free(addr: SocketAddr) -> bool {
    std::net::UdpSocket::bind(addr).is_ok()
}

/// Register a placeholder server instance so register_server_task has a slot.
async fn add_placeholder(state: &Arc<AppState>, proto: &str) -> ServerId {
    let server = ServerInstance::new(ServerId::new(0), 0, proto.to_string(), String::new());
    state.add_server(server).await
}

#[tokio::test]
async fn stopping_telnet_server_releases_tcp_port() {
    use netget::llm::ollama_client::OllamaClient;
    use netget::server::TelnetServer;

    let state = Arc::new(AppState::new());
    let server_id = add_placeholder(&state, "telnet").await;

    let llm = OllamaClient::new("http://127.0.0.1:1");
    let (status_tx, _status_rx) = tokio::sync::mpsc::unbounded_channel();

    let bound: SocketAddr = TelnetServer::spawn_with_llm_actions(
        "127.0.0.1:0".parse().unwrap(),
        llm,
        state.clone(),
        status_tx,
        server_id,
        // send_first: this test only checks that stopping releases the port,
        // so no connect-time banner is wanted.
        false,
        // first-byte / idle read deadlines: the shipped defaults.
        None,
        None,
    )
    .await
    .expect("telnet server should start");

    assert!(
        !tcp_port_is_free(bound),
        "port {} should be held while the server is running",
        bound.port()
    );

    assert!(state.remove_server(server_id).await.is_some());

    assert!(
        tcp_port_is_free(bound),
        "TCP port {} was still held when remove_server returned — listener leaked or released late",
        bound.port()
    );
}

#[tokio::test]
async fn stopping_udp_server_releases_udp_port() {
    use netget::llm::ollama_client::OllamaClient;
    use netget::server::UdpServer;

    let state = Arc::new(AppState::new());
    let server_id = add_placeholder(&state, "udp").await;

    let llm = OllamaClient::new("http://127.0.0.1:1");
    let (status_tx, _status_rx) = tokio::sync::mpsc::unbounded_channel();

    let bound: SocketAddr = UdpServer::spawn_with_llm_actions(
        "127.0.0.1:0".parse().unwrap(),
        llm,
        state.clone(),
        status_tx,
        server_id,
    )
    .await
    .expect("udp server should start");

    assert!(
        !udp_port_is_free(bound),
        "UDP port {} should be held while the server is running",
        bound.port()
    );

    assert!(state.remove_server(server_id).await.is_some());

    assert!(
        udp_port_is_free(bound),
        "UDP port {} was still held when remove_server returned — recv loop leaked or released late",
        bound.port()
    );
}

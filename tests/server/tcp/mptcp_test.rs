//! `multipath: true` on the tcp server and client (`src/utils/mptcp.rs`).
//!
//! On Linux the server listens on an `IPPROTO_MPTCP` socket and every connection's events and
//! status say whether MPTCP was negotiated: an MPTCP peer is `mptcp: true`, a plain TCP peer
//! (which the kernel serves from the same listener) is `mptcp: false`. Elsewhere the option is
//! refused with the platform's reason instead of quietly opening a plain TCP socket.
//!
//! No model: every event is answered by a static rule keyed on the `mptcp` field.

use netget::llm::ollama_client::OllamaClient;
use netget::scripting::{EventHandler, EventHandlerConfig, EventHandlerType, EventPattern};
use netget::server::TcpServer;
use netget::state::app_state::AppState;
use netget::state::server::ServerInstance;
use netget::state::ServerId;
use std::sync::Arc;

async fn tcp_server_instance(state: &Arc<AppState>) -> ServerId {
    let server = ServerInstance::new(ServerId::new(0), 0, "TCP".to_string(), String::new());
    let server_id = state.add_server(server).await;
    let rule = |mptcp: bool, reply: &str| {
        let mut m = serde_json::Map::new();
        m.insert("mptcp".to_string(), serde_json::json!(mptcp));
        EventHandler::new(
            EventPattern::specific("tcp_data_received"),
            EventHandlerType::static_response(vec![
                serde_json::json!({"type": "send_tcp_data", "data": reply}),
            ]),
        )
        .with_match(m)
    };
    let mut config = EventHandlerConfig::new();
    config.add_handler(rule(true, "MPTCP\n"));
    config.add_handler(rule(false, "PLAIN\n"));
    state
        .set_event_handler_config(server_id, Some(config))
        .await;
    server_id
}

async fn spawn(state: &Arc<AppState>, server_id: ServerId) -> anyhow::Result<std::net::SocketAddr> {
    let (status_tx, _status_rx) = tokio::sync::mpsc::unbounded_channel();
    TcpServer::spawn_with_options(
        "127.0.0.1:0".parse().unwrap(),
        // Unroutable: every event here has a static rule.
        OllamaClient::new("http://127.0.0.1:1"),
        state.clone(),
        status_tx,
        false,
        server_id,
        None,
        None,
        true,
    )
    .await
}

/// Linux: MPTCP is negotiated with an MPTCP peer and reported as such; a plain peer on the
/// same listener is reported as having fallen back. Needs `net.mptcp.enabled=1`.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn multipath_server_reports_what_each_connection_negotiated() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn exchange(mut stream: tokio::net::TcpStream) -> String {
        stream.write_all(b"hi\n").await.expect("write");
        let mut buf = [0u8; 32];
        let n = tokio::time::timeout(std::time::Duration::from_secs(10), stream.read(&mut buf))
            .await
            .expect("reply in time")
            .expect("read");
        String::from_utf8_lossy(&buf[..n]).to_string()
    }

    let state = Arc::new(AppState::new());
    let server_id = tcp_server_instance(&state).await;
    let addr = spawn(&state, server_id)
        .await
        .expect("an MPTCP listener should open on Linux with net.mptcp.enabled=1");

    let mptcp_peer = netget::utils::mptcp::connect(addr)
        .await
        .expect("MPTCP connect");
    assert_eq!(netget::utils::mptcp::is_mptcp(&mptcp_peer).unwrap(), true);
    assert_eq!(exchange(mptcp_peer).await, "MPTCP\n");

    let plain_peer = tokio::net::TcpStream::connect(addr)
        .await
        .expect("TCP connect");
    assert_eq!(exchange(plain_peer).await, "PLAIN\n");

    let server = state.get_server(server_id).await.expect("server");
    let mut seen: Vec<bool> = server
        .connections
        .values()
        .filter_map(|c| c.protocol_info.data.get("mptcp").and_then(|v| v.as_bool()))
        .collect();
    seen.sort();
    assert_eq!(
        seen,
        vec![false, true],
        "each connection's status carries mptcp"
    );
}

/// Linux: the client connects over MPTCP and records what it negotiated.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn multipath_client_records_negotiated_mptcp() {
    use netget::client::tcp::TcpClient;
    use netget::state::{ClientId, ClientInstance};

    let state = Arc::new(AppState::new());
    let server_id = tcp_server_instance(&state).await;
    let addr = spawn(&state, server_id).await.expect("MPTCP listener");

    let client_id = state
        .add_client(ClientInstance::new(
            ClientId::new(0),
            addr.to_string(),
            "TCP".to_string(),
            String::new(),
        ))
        .await;
    let (status_tx, _status_rx) = tokio::sync::mpsc::unbounded_channel();
    TcpClient::connect_with_options(
        addr.to_string(),
        OllamaClient::new("http://127.0.0.1:1"),
        state.clone(),
        status_tx,
        client_id,
        true,
    )
    .await
    .expect("multipath client connects");
    let client = state.get_client(client_id).await.expect("client");
    assert_eq!(
        client.get_protocol_field("mptcp"),
        Some(&serde_json::json!(true))
    );
}

/// Everywhere else `multipath: true` is refused with the platform's reason, on both sides.
#[cfg(not(target_os = "linux"))]
#[tokio::test]
async fn multipath_is_refused_off_linux_with_the_reason() {
    use netget::client::tcp::TcpClient;
    use netget::state::{ClientId, ClientInstance};

    let state = Arc::new(AppState::new());
    let server_id = tcp_server_instance(&state).await;
    let err = spawn(&state, server_id)
        .await
        .expect_err("multipath must not silently open plain TCP")
        .to_string();
    let reason = netget::utils::mptcp::UNSUPPORTED_REASON.expect("not Linux");
    assert_eq!(err, reason);
    #[cfg(target_os = "macos")]
    assert!(
        err.contains("macOS") && err.contains("Network.framework"),
        "{err}"
    );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let client_id = state
        .add_client(ClientInstance::new(
            ClientId::new(0),
            addr.to_string(),
            "TCP".to_string(),
            String::new(),
        ))
        .await;
    let (status_tx, _status_rx) = tokio::sync::mpsc::unbounded_channel();
    let err = TcpClient::connect_with_options(
        addr.to_string(),
        OllamaClient::new("http://127.0.0.1:1"),
        state.clone(),
        status_tx,
        client_id,
        true,
    )
    .await
    .expect_err("multipath client must be refused")
    .to_string();
    assert_eq!(err, reason);
}

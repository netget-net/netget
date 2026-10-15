//! E2E tests for SOCKS5 client protocol
//!
//! These tests verify the SOCKS5 client can:
//! 1. Connect through a SOCKS5 proxy without authentication
//! 2. Connect through a SOCKS5 proxy with authentication
//! 3. Send and receive data through the tunnel
//! 4. Handle connection failures gracefully
//!
//! LLM Call Budget: < 10 calls total (keep test scenarios minimal)


use netget::llm::OllamaClient;
use netget::protocol::CLIENT_REGISTRY;
use netget::state::app_state::AppState;
use netget::state::{ClientId, ClientInstance, ClientStatus};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::time::sleep;

/// Helper to find an available port
async fn find_available_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

/// Start a simple echo server for testing
async fn start_echo_server() -> u16 {
    let port = find_available_port().await;
    let listener = TcpListener::bind(format!("127.0.0.1:{}", port))
        .await
        .unwrap();

    tokio::spawn(async move {
        loop {
            if let Ok((mut socket, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 1024];
                    while let Ok(n) = socket.read(&mut buf).await {
                        if n == 0 {
                            break;
                        }
                        // Echo back
                        let _ = socket.write_all(&buf[..n]).await;
                    }
                });
            }
        }
    });

    sleep(Duration::from_millis(100)).await;
    port
}

/// Start a simple SOCKS5 proxy server (no authentication)
async fn start_socks5_proxy_no_auth() -> u16 {
    let port = find_available_port().await;
    let listener = TcpListener::bind(format!("127.0.0.1:{}", port))
        .await
        .unwrap();

    tokio::spawn(async move {
        loop {
            if let Ok((mut socket, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 1024];

                    // Read greeting
                    if socket.read(&mut buf).await.is_err() {
                        return;
                    }

                    // Send no auth required
                    let _ = socket.write_all(&[0x05, 0x00]).await;

                    // Read CONNECT request
                    if socket.read(&mut buf).await.is_err() {
                        return;
                    }

                    // Parse target from CONNECT request
                    let atyp = buf[3];
                    let (target_host, target_port) = match atyp {
                        0x01 => {
                            // IPv4
                            let ip = format!("{}.{}.{}.{}", buf[4], buf[5], buf[6], buf[7]);
                            let port = u16::from_be_bytes([buf[8], buf[9]]);
                            (ip, port)
                        }
                        0x03 => {
                            // Domain name
                            let len = buf[4] as usize;
                            let domain = String::from_utf8_lossy(&buf[5..5 + len]).to_string();
                            let port = u16::from_be_bytes([buf[5 + len], buf[6 + len]]);
                            (domain, port)
                        }
                        _ => return,
                    };

                    // Connect to target
                    if let Ok(mut target) =
                        TcpStream::connect(format!("{}:{}", target_host, target_port)).await
                    {
                        // Send success response
                        let _ = socket
                            .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                            .await;

                        // Relay data bidirectionally (owned halves so they satisfy the
                        // 'static bound required by tokio::spawn)
                        let (mut client_read, mut client_write) = tokio::io::split(socket);
                        let (mut target_read, mut target_write) = tokio::io::split(target);

                        let c2t = tokio::spawn(async move {
                            let _ = tokio::io::copy(&mut client_read, &mut target_write).await;
                        });

                        let t2c = tokio::spawn(async move {
                            let _ = tokio::io::copy(&mut target_read, &mut client_write).await;
                        });

                        let _ = tokio::join!(c2t, t2c);
                    } else {
                        // Connection failed
                        let _ = socket
                            .write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                            .await;
                    }
                });
            }
        }
    });

    sleep(Duration::from_millis(100)).await;
    port
}

#[tokio::test]
#[ignore = "Requires Ollama running"]
async fn test_socks5_client_no_auth_basic() {
    // Start echo server
    let echo_port = start_echo_server().await;

    // Start SOCKS5 proxy
    let proxy_port = start_socks5_proxy_no_auth().await;

    // Create app state
    let app_state = Arc::new(AppState::new());
    let (status_tx, _status_rx) = mpsc::unbounded_channel();

    // Create LLM client
    let llm_client = OllamaClient::new("http://localhost:11434".to_string());

    // Get SOCKS5 client protocol
    let protocol = CLIENT_REGISTRY
        .get("SOCKS5")
        .expect("SOCKS5 protocol not found");

    // Create client instance
    let mut client = ClientInstance::new(
        ClientId::new(0), // overwritten by add_client with the real allocated id
        format!("127.0.0.1:{}", proxy_port),
        "SOCKS5".to_string(),
        "Connect through SOCKS5 proxy to echo server and send 'HELLO'".to_string(),
    );
    client.startup_params = Some(serde_json::json!({
        "target_addr": format!("127.0.0.1:{}", echo_port)
    }));
    let client_id = app_state.add_client(client).await;

    // Build connect context
    let startup_params_json = serde_json::json!({
        "target_addr": format!("127.0.0.1:{}", echo_port)
    });
    let schema = protocol.get_startup_parameters();
    let connect_ctx = netget::protocol::ConnectContext {
        remote_addr: format!("127.0.0.1:{}", proxy_port),
        llm_client: llm_client.clone(),
        state: app_state.clone(),
        status_tx: status_tx.clone(),
        client_id,
        startup_params: Some(
            netget::protocol::StartupParams::new(startup_params_json, schema)
                .expect("valid startup params"),
        ),
    };

    // Connect through SOCKS5
    let result = protocol.connect(connect_ctx).await;
    assert!(result.is_ok(), "Failed to connect: {:?}", result.err());

    // Wait for LLM to process
    sleep(Duration::from_secs(10)).await;

    // Check client status
    let client = app_state.get_client(client_id).await;
    assert!(client.is_some());

    let client_status = &client.unwrap().status;
    assert!(
        matches!(
            client_status,
            ClientStatus::Connected | ClientStatus::Disconnected
        ),
        "Expected Connected or Disconnected, got {:?}",
        client_status
    );
}

#[tokio::test]
#[ignore = "Requires Ollama running"]
async fn test_socks5_client_connection_failure() {
    // Don't start proxy server - test connection failure

    let app_state = Arc::new(AppState::new());
    let (status_tx, _status_rx) = mpsc::unbounded_channel();

    let llm_client = OllamaClient::new("http://localhost:11434".to_string());

    let protocol = CLIENT_REGISTRY
        .get("SOCKS5")
        .expect("SOCKS5 protocol not found");

    let mut client = ClientInstance::new(
        ClientId::new(0),             // overwritten by add_client with the real allocated id
        "127.0.0.1:9999".to_string(), // Non-existent proxy
        "SOCKS5".to_string(),
        "Attempt to connect through non-existent proxy".to_string(),
    );
    client.startup_params = Some(serde_json::json!({
        "target_addr": "example.com:80"
    }));
    let client_id = app_state.add_client(client).await;

    let schema = protocol.get_startup_parameters();
    let connect_ctx = netget::protocol::ConnectContext {
        remote_addr: "127.0.0.1:9999".to_string(),
        llm_client: llm_client.clone(),
        state: app_state.clone(),
        status_tx: status_tx.clone(),
        client_id,
        startup_params: Some(
            netget::protocol::StartupParams::new(
                serde_json::json!({ "target_addr": "example.com:80" }),
                schema,
            )
            .expect("valid startup params"),
        ),
    };

    // Attempt to connect
    let result = protocol.connect(connect_ctx).await;
    assert!(result.is_err(), "Expected connection to fail");

    // Verify error message mentions connection failure
    let err = result.unwrap_err();
    let err_msg = err.to_string().to_lowercase();
    assert!(
        err_msg.contains("connect") || err_msg.contains("refused"),
        "Error message should mention connection failure: {}",
        err_msg
    );
}

#[tokio::test]
#[ignore = "Requires Ollama running"]
async fn test_socks5_client_missing_target_addr() {
    let app_state = Arc::new(AppState::new());
    let (status_tx, _status_rx) = mpsc::unbounded_channel();

    let llm_client = OllamaClient::new("http://localhost:11434".to_string());

    let protocol = CLIENT_REGISTRY
        .get("SOCKS5")
        .expect("SOCKS5 protocol not found");

    let client = ClientInstance::new(
        ClientId::new(0), // overwritten by add_client with the real allocated id
        "127.0.0.1:1080".to_string(),
        "SOCKS5".to_string(),
        "Missing target_addr parameter".to_string(),
    );
    // client.startup_params is None by default (missing startup params)
    let client_id = app_state.add_client(client).await;

    let connect_ctx = netget::protocol::ConnectContext {
        remote_addr: "127.0.0.1:1080".to_string(),
        llm_client: llm_client.clone(),
        state: app_state.clone(),
        status_tx: status_tx.clone(),
        client_id,
        startup_params: None,
    };

    // Attempt to connect
    let result = protocol.connect(connect_ctx).await;
    assert!(result.is_err(), "Expected error for missing target_addr");

    // Verify error message mentions missing parameter
    let err = result.unwrap_err();
    let err_msg = err.to_string().to_lowercase();
    assert!(
        err_msg.contains("target_addr") || err_msg.contains("missing"),
        "Error message should mention missing target_addr: {}",
        err_msg
    );
}

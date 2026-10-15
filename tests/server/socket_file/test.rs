//! End-to-end Unix domain socket tests for NetGet
//!
//! These tests spawn the actual NetGet binary with socket file prompts
//! and validate the responses using UnixStream connections.
//!
//! Platform: Unix/Linux only

#![cfg(unix)]

use super::super::super::helpers::{self, E2EResult, NetGetConfig};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

/// Wait until `path` exists, rather than sleeping a fixed interval and hoping.
///
/// Startup returns when the harness has *parsed* the server's start line, not when the protocol
/// has created its filesystem object, so the gap has to be waited out. A fixed sleep is enough
/// alone and not when a hundred tests run together, which is the shape CLAUDE.md warns about
/// under "Running tests".
async fn wait_for_path(path: &str, secs: u64) -> E2EResult<()> {
    let deadline = std::time::Instant::now() + Duration::from_secs(secs);
    while std::time::Instant::now() < deadline {
        if std::path::Path::new(path).exists() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    Err(format!("{path} was never created within {secs}s").into())
}

#[tokio::test]
async fn test_socket_echo() -> E2EResult<()> {
    println!("\n=== E2E Test: Socket File Echo Server ===");

    // PROMPT: Tell the LLM to echo back with ACK prefix
    let prompt = "Create socket file at /tmp/netget-test-echo.sock. When you receive any data, reply with 'ACK: ' followed by the received data";

    // Start the server with mocks
    let server = helpers::start_netget_server(
        NetGetConfig::new(prompt)
            .with_mock(|mock| {
                mock
                    // Mock 1: Server startup (user command)
                    .on_instruction_containing("socket file")
                    .and_instruction_containing("netget-test-echo.sock")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "open_server",
                            "port": 0,
                            "base_stack": "SOCKET_FILE",
                            "instruction": "When you receive any data, reply with 'ACK: ' followed by the received data",
                            "startup_params": {
                                "socket_path": "./tmp/netget-test-echo.sock"
                            }
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // Mock 2: Data received on socket
                    .on_event("socket_file_data_received")
                    .and_event_data_contains("data", "Hello, Socket!")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "send_socket_data",
                            "data": "ACK: Hello, Socket!"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
            })
    ).await?;
    println!("Server started with socket file");

    // Wait for the socket node itself, not for a guessed interval.
    wait_for_path("./tmp/netget-test-echo.sock", 30).await?;

    // The node must be owner-only. `bind` creates it 0777 & ~umask (srwxr-xr-x under the usual
    // umask 022), and both Linux and macOS check write permission on the node at connect(2), so
    // the default let any local user speak to it; the server chmods it 0600 right after bind.
    // This cannot prove another uid is refused — the test runs as one user — but it does fail if
    // the chmod is ever dropped.
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata("./tmp/netget-test-echo.sock")?
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode, 0o600,
            "socket node should be owner-only, got {mode:o}"
        );
    }

    // VALIDATION: Send data and verify echo response
    println!("Connecting Unix socket client...");
    let mut stream = UnixStream::connect("./tmp/netget-test-echo.sock").await?;
    println!("✓ Unix socket client connected");

    // Send test data
    let test_message = "Hello, Socket!";
    println!("Sending: {}", test_message);
    stream.write_all(test_message.as_bytes()).await?;
    stream.flush().await?;

    // Read response with timeout
    let mut buffer = vec![0u8; 1024];
    match tokio::time::timeout(Duration::from_secs(10), stream.read(&mut buffer)).await {
        Ok(Ok(n)) if n > 0 => {
            let response = String::from_utf8_lossy(&buffer[..n]);
            println!("Received: {}", response);

            // Verify response format
            assert!(
                response.contains("ACK"),
                "Response should contain 'ACK', got: {}",
                response
            );
            assert!(
                response.contains(test_message),
                "Response should echo the message, got: {}",
                response
            );

            println!("✓ Socket file echo test passed");
        }
        Ok(Ok(_)) => return Err("Connection closed without response".into()),
        Ok(Err(e)) => return Err(format!("Read error: {}", e).into()),
        Err(_) => return Err("Response timeout".into()),
    }

    // Verify mock expectations were met
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;

    server.stop().await?;

    // Cleanup socket file
    let _ = std::fs::remove_file("./tmp/netget-test-echo.sock");

    println!("=== Test passed ===\n");
    Ok(())
}

#[tokio::test]
async fn test_socket_ping_pong() -> E2EResult<()> {
    println!("\n=== E2E Test: Socket File PING/PONG ===");

    // PROMPT: Tell the LLM to respond to PING with PONG
    let prompt = "Create socket file at /tmp/netget-test-ping.sock. When you receive 'PING', respond with 'PONG\\n'";

    // Start the server with mocks
    let server = helpers::start_netget_server(NetGetConfig::new(prompt).with_mock(|mock| {
        mock
            // Mock 1: Server startup
            .on_instruction_containing("socket file")
            .and_instruction_containing("netget-test-ping.sock")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "SOCKET_FILE",
                    "instruction": "When you receive 'PING', respond with 'PONG\\n'",
                    "startup_params": {
                        "socket_path": "./tmp/netget-test-ping.sock"
                    }
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 2: PING received
            .on_event("socket_file_data_received")
            .and_event_data_contains("data", "PING")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "send_socket_data",
                    "data": "PONG\n"
                }
            ]))
            .expect_calls(1)
            .and()
    }))
    .await?;
    println!("Server started with socket file");

    // Wait for the socket node itself, not for a guessed interval.
    wait_for_path("./tmp/netget-test-ping.sock", 30).await?;

    // VALIDATION: Verify PING/PONG
    println!("Connecting Unix socket client...");
    let mut stream = UnixStream::connect("./tmp/netget-test-ping.sock").await?;
    println!("✓ Unix socket client connected");

    // Send PING
    println!("Sending: PING");
    stream.write_all(b"PING").await?;
    stream.flush().await?;

    // Read PONG
    let mut buffer = vec![0u8; 1024];
    match tokio::time::timeout(Duration::from_secs(10), stream.read(&mut buffer)).await {
        Ok(Ok(n)) if n > 0 => {
            let response = String::from_utf8_lossy(&buffer[..n]);
            println!("Received: {}", response.trim());
            assert!(
                response.contains("PONG"),
                "Expected PONG response, got: {}",
                response
            );
            println!("✓ PING/PONG test passed");
        }
        Ok(Ok(_)) => return Err("Connection closed without response".into()),
        Ok(Err(e)) => return Err(format!("Read error: {}", e).into()),
        Err(_) => return Err("Response timeout".into()),
    }

    // Verify mock expectations were met
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;

    server.stop().await?;

    // Cleanup socket file
    let _ = std::fs::remove_file("./tmp/netget-test-ping.sock");

    println!("=== Test passed ===\n");
    Ok(())
}

#[tokio::test]
async fn test_socket_line_protocol() -> E2EResult<()> {
    println!("\n=== E2E Test: Socket File Line Protocol ===");

    // PROMPT: Tell the LLM to respond to line-based commands
    let prompt = "Create socket file at /tmp/netget-test-line.sock. When you receive a line ending with \\n, respond with 'OK: <line>\\n'";

    // Start the server with mocks
    let server = helpers::start_netget_server(
        NetGetConfig::new(prompt)
            .with_mock(|mock| {
                mock
                    // Mock 1: Server startup
                    .on_instruction_containing("socket file")
                    .and_instruction_containing("netget-test-line.sock")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "open_server",
                            "port": 0,
                            "base_stack": "SOCKET_FILE",
                            "instruction": "When you receive a line ending with \\n, respond with 'OK: <line>\\n'",
                            "startup_params": {
                                "socket_path": "./tmp/netget-test-line.sock"
                            }
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // Mock 2: Line received
                    .on_event("socket_file_data_received")
                    .and_event_data_contains("data", "TEST COMMAND")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "send_socket_data",
                            "data": "OK: TEST COMMAND\n"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
            })
    ).await?;
    println!("Server started with socket file");

    // Wait for the socket node itself, not for a guessed interval.
    wait_for_path("./tmp/netget-test-line.sock", 30).await?;

    // VALIDATION: Send line and verify response
    println!("Connecting Unix socket client...");
    let mut stream = UnixStream::connect("./tmp/netget-test-line.sock").await?;
    println!("✓ Unix socket client connected");

    // Send command line
    let command = "TEST COMMAND\n";
    println!("Sending: {}", command.trim());
    stream.write_all(command.as_bytes()).await?;
    stream.flush().await?;

    // Read response
    let mut buffer = vec![0u8; 1024];
    match tokio::time::timeout(Duration::from_secs(10), stream.read(&mut buffer)).await {
        Ok(Ok(n)) if n > 0 => {
            let response = String::from_utf8_lossy(&buffer[..n]);
            println!("Received: {}", response.trim());

            assert!(
                response.starts_with("OK:"),
                "Expected OK: response, got: {}",
                response
            );
            assert!(
                response.contains("TEST COMMAND"),
                "Response should contain command, got: {}",
                response
            );
            println!("✓ Line protocol test passed");
        }
        Ok(Ok(_)) => return Err("Connection closed without response".into()),
        Ok(Err(e)) => return Err(format!("Read error: {}", e).into()),
        Err(_) => return Err("Response timeout".into()),
    }

    // Verify mock expectations were met
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;

    server.stop().await?;

    // Cleanup socket file
    let _ = std::fs::remove_file("./tmp/netget-test-line.sock");

    println!("=== Test passed ===\n");
    Ok(())
}

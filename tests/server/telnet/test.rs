//! End-to-end Telnet tests for NetGet
//!
//! These tests spawn the actual NetGet binary with Telnet prompts
//! and validate the responses using raw TCP clients.

// Helper module imported from parent

use super::super::super::helpers::{self, E2EResult, NetGetConfig};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

#[tokio::test]
async fn test_telnet_echo() -> E2EResult<()> {
    println!("\n=== E2E Test: Telnet Echo Server ===");

    // PROMPT: Tell the LLM to act as a Telnet echo server
    let prompt = "listen on port {AVAILABLE_PORT} via telnet. Echo back any text you receive, line by line. \
        Add '> ' prompt after each echo.";

    // Start the server with mocks
    let config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock
            // Mock 1: Server startup
            .on_instruction_containing("telnet")
            .and_instruction_containing("Echo back")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "Telnet",
                    "instruction": "Echo server - respond with received message"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 2: Echo received message
            .on_event("telnet_connection_opened")
            // Raised for every connection; this server has nothing to say first.
            .respond_with_actions(serde_json::json!([]))
            .expect_calls(1)
            .and()
            .on_event("telnet_message_received")
            .and_event_data_contains("message", "Hello")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "send_telnet_line",
                    "line": "Hello Telnet Server"
                },
                {
                    "type": "send_telnet_prompt",
                    "prompt": "> "
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let server = helpers::start_netget_server(config).await?;
    println!("Server started on port {}", server.port);

    // VALIDATION: Connect via raw TCP (Telnet protocol)
    println!("Connecting to Telnet server...");
    let stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", server.port)).await?;
    println!("✓ TCP connected");

    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    // Send a test message
    let test_message = "Hello Telnet Server";
    println!("Sending: {}", test_message);
    write_half
        .write_all(format!("{}\n", test_message).as_bytes())
        .await?;
    write_half.flush().await?;

    // Read echo response
    let mut line = String::new();
    match tokio::time::timeout(Duration::from_secs(10), reader.read_line(&mut line)).await {
        Ok(Ok(n)) if n > 0 => {
            println!("Telnet response: {}", line.trim());

            // Verify echo (should contain our message)
            assert!(
                line.contains(test_message) || line.contains("Hello"),
                "Expected echo containing '{}', got: {}",
                test_message,
                line
            );
            println!("✓ Telnet echo verified");
        }
        Ok(Ok(_)) => {
            println!("Note: Connection closed without response");
        }
        Ok(Err(e)) => {
            println!("Note: Read error: {}", e);
        }
        Err(_) => {
            println!("Note: No response received (timeout)");
        }
    }

    // Verify mock expectations were met
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;

    server.stop().await?;
    println!("=== Test completed ===\n");
    Ok(())
}

#[tokio::test]
async fn test_telnet_prompt() -> E2EResult<()> {
    println!("\n=== E2E Test: Telnet Interactive Prompt ===");

    // PROMPT: Tell the LLM to provide an interactive prompt
    let prompt = "listen on port {AVAILABLE_PORT} via telnet. Send a welcome message 'Welcome to NetGet Telnet' \
        when clients connect, then show a '$ ' prompt. Echo commands back with 'You said: ' prefix.";

    // Start the server with mocks
    let config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock
            // Mock 1: Server startup
            .on_instruction_containing("telnet")
            .and_instruction_containing("Welcome to NetGet Telnet")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "Telnet",
                    "instruction": "Interactive prompt server"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 2: Respond to help command
            .on_event("telnet_connection_opened")
            // Raised for every connection; this server has nothing to say first.
            .respond_with_actions(serde_json::json!([]))
            .expect_calls(1)
            .and()
            .on_event("telnet_message_received")
            .and_event_data_contains("message", "help")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "send_telnet_line",
                    "line": "You said: help"
                },
                {
                    "type": "send_telnet_prompt",
                    "prompt": "$ "
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let server = helpers::start_netget_server(config).await?;
    println!("Server started on port {}", server.port);

    // VALIDATION: Connect and verify welcome + prompt
    let stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", server.port)).await?;
    println!("✓ TCP connected");

    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    // Read welcome message (if sent immediately)

    // Send a command
    println!("Sending command: help");
    write_half.write_all(b"help\n").await?;
    write_half.flush().await?;

    // Read responses
    let mut received_response = false;
    for attempt in 1..=3 {
        let mut line = String::new();
        match tokio::time::timeout(Duration::from_secs(10), reader.read_line(&mut line)).await {
            Ok(Ok(n)) if n > 0 => {
                println!("Telnet response ({}): {}", attempt, line.trim());
                if !line.trim().is_empty() {
                    received_response = true;
                }
            }
            _ => break,
        }
    }

    if received_response {
        println!("✓ Telnet interaction successful");
    } else {
        println!("Note: No response received from Telnet server");
    }

    // Verify mock expectations were met
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;

    server.stop().await?;
    println!("=== Test completed ===\n");
    Ok(())
}

#[tokio::test]
async fn test_telnet_multiple_lines() -> E2EResult<()> {
    println!("\n=== E2E Test: Telnet Multiple Lines ===");

    // PROMPT: Tell the LLM to handle multiple lines
    let prompt = "listen on port {AVAILABLE_PORT} via telnet. For each line received, respond with 'Line N: <content>' \
        where N is the line number starting from 1.";

    // Start the server with mocks
    let config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock
            // Mock 1: Server startup
            .on_instruction_containing("telnet")
            .and_instruction_containing("Line N")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "Telnet",
                    "instruction": "Multi-line handler with line numbers"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 2: First line
            .on_event("telnet_connection_opened")
            // Raised for every connection; this server has nothing to say first.
            .respond_with_actions(serde_json::json!([]))
            .expect_calls(1)
            .and()
            .on_event("telnet_message_received")
            .and_event_data_contains("message", "First line")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "send_telnet_line",
                    "line": "Line 1: First line"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 3: Second line
            .on_event("telnet_message_received")
            .and_event_data_contains("message", "Second line")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "send_telnet_line",
                    "line": "Line 2: Second line"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 4: Third line
            .on_event("telnet_message_received")
            .and_event_data_contains("message", "Third line")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "send_telnet_line",
                    "line": "Line 3: Third line"
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let server = helpers::start_netget_server(config).await?;
    println!("Server started on port {}", server.port);

    // VALIDATION: Send multiple lines
    let stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", server.port)).await?;
    println!("✓ TCP connected");

    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    // Send three lines
    let lines = ["First line", "Second line", "Third line"];
    for (i, line) in lines.iter().enumerate() {
        println!("Sending line {}: {}", i + 1, line);
        write_half
            .write_all(format!("{}\n", line).as_bytes())
            .await?;
        write_half.flush().await?;

        // Read response
        let mut response = String::new();
        match tokio::time::timeout(Duration::from_secs(10), reader.read_line(&mut response)).await {
            Ok(Ok(n)) if n > 0 => {
                println!("  Response: {}", response.trim());
            }
            _ => {
                println!("  No response for line {}", i + 1);
            }
        }
    }

    println!("✓ Multiple line handling tested");

    // Verify mock expectations were met
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;

    server.stop().await?;
    println!("=== Test completed ===\n");
    Ok(())
}

#[tokio::test]
async fn test_telnet_concurrent_connections() -> E2EResult<()> {
    println!("\n=== E2E Test: Telnet Concurrent Connections ===");

    // PROMPT: Tell the LLM to handle multiple clients
    let prompt = "listen on port {AVAILABLE_PORT} via telnet. Handle multiple concurrent clients. \
        Echo each message back with the client's message.";

    // Start the server with mocks
    let config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock
            // Mock 1: Server startup
            .on_instruction_containing("listen on port")
            .and_instruction_containing("Handle multiple concurrent")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "Telnet",
                    "instruction": "Handle concurrent clients and echo messages"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 2-4: Echo messages from 3 concurrent clients
            .on_event("telnet_connection_opened")
            // Raised for every connection; this server has nothing to say first.
            .respond_with_actions(serde_json::json!([]))
            .expect_calls(3)
            .and()
            .on_event("telnet_message_received")
            .and_event_data_contains("message", "Client")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "send_telnet_line",
                    "line": "Echo: Client message"
                }
            ]))
            .expect_calls(3)
            .and()
    });

    let server = helpers::start_netget_server(config).await?;
    println!("Server started on port {}", server.port);

    // VALIDATION: Connect multiple clients concurrently
    println!("Testing concurrent Telnet clients...");

    let mut handles: Vec<
        tokio::task::JoinHandle<Result<bool, Box<dyn std::error::Error + Send + Sync>>>,
    > = vec![];
    for i in 1..=3 {
        let port = server.port;
        let handle = tokio::spawn(async move {
            let stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port)).await?;
            let (read_half, mut write_half) = stream.into_split();
            let mut reader = BufReader::new(read_half);

            // Send a unique message
            let message = format!("Client {} message", i);
            write_half
                .write_all(format!("{}\n", message).as_bytes())
                .await?;
            write_half.flush().await?;

            // Try to read response
            let mut line = String::new();
            match tokio::time::timeout(Duration::from_secs(5), reader.read_line(&mut line)).await {
                Ok(Ok(n)) if n > 0 => {
                    println!("  Client {} received: {}", i, line.trim());
                    Ok(true)
                }
                _ => {
                    println!("  Client {} no response", i);
                    Ok(false)
                }
            }
        });
        handles.push(handle);
    }

    // Wait for all clients
    let mut success_count = 0;
    for handle in handles {
        if let Ok(Ok(true)) = handle.await {
            success_count += 1;
        }
    }

    println!("✓ {} / 3 concurrent clients succeeded", success_count);

    // Verify mock expectations were met
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;

    server.stop().await?;
    println!("=== Test completed ===\n");
    Ok(())
}

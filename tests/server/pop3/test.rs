//! End-to-end POP3 tests for NetGet
//!
//! These tests spawn the actual NetGet binary with POP3 prompts
//! and validate the responses using POP3 protocol clients.


// Helper module imported from parent

use super::super::super::helpers::{self, E2EResult, NetGetConfig};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

#[tokio::test]
async fn test_pop3_greeting() -> E2EResult<()> {
    println!("\n=== E2E Test: POP3 Greeting (+OK) ===");

    // PROMPT: Tell the LLM to send POP3 greeting
    let prompt =
        "listen on port {AVAILABLE_PORT} via pop3. When a client connects, send POP3 greeting: \
        '+OK POP3 server ready'";

    // Start the server with mocks
    let config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock
            // Mock: Server startup (only match initial user prompt)
            .on_prompt_containing("listen on port")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "pop3",
                    "instruction": "Send POP3 greeting when client connects"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock: Client connects (CONNECTION_ESTABLISHED command)
            .on_event("pop3_command")
            .and_event_data_contains("command", "CONNECTION_ESTABLISHED")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "send_pop3_greeting",
                    "message": "POP3 server ready"
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let mut server = helpers::start_netget_server(config).await?;
    println!("Server started on port {}", server.port);

    // VALIDATION: Connect and expect +OK greeting
    println!("Connecting to POP3 server...");
    let stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", server.port)).await?;
    println!("✓ TCP connected");

    let (read_half, _write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    // Read greeting
    let mut line = String::new();
    match tokio::time::timeout(Duration::from_secs(10), reader.read_line(&mut line)).await {
        Ok(Ok(n)) if n > 0 => {
            println!("POP3 greeting: {}", line.trim());

            // Verify POP3 greeting (+OK)
            assert!(
                line.starts_with("+OK") || line.contains("+OK"),
                "Expected POP3 greeting starting with '+OK', got: {}",
                line
            );
            println!("✓ POP3 greeting (+OK) verified");
        }
        Ok(Ok(_)) => {
            println!("Note: Connection closed without greeting");
        }
        Ok(Err(e)) => {
            println!("Note: Read error: {}", e);
        }
        Err(_) => {
            println!("Note: No greeting received (timeout)");
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
async fn test_pop3_authentication() -> E2EResult<()> {
    println!("\n=== E2E Test: POP3 Authentication (USER/PASS) ===");

    // PROMPT: Tell the LLM to handle USER and PASS commands
    let prompt = "listen on port {AVAILABLE_PORT} via pop3. Send greeting '+OK POP3 ready'. \
        When client sends USER command, respond with '+OK user accepted'. \
        When client sends PASS command, respond with '+OK logged in'";

    // Start the server with mocks
    let config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock
            // Mock 1: Server startup (only match initial user prompt)
            .on_prompt_containing("listen on port")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "pop3",
                    "instruction": "Handle USER and PASS commands"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 2: Client connects - send greeting
            .on_event("pop3_command")
            .and_event_data_contains("command", "CONNECTION_ESTABLISHED")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "send_pop3_greeting",
                    "message": "POP3 ready"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 3: USER command received
            .on_event("pop3_command")
            .and_event_data_contains("command", "USER alice")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "send_pop3_ok",
                    "message": "user accepted"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 4: PASS command received
            .on_event("pop3_command")
            .and_event_data_contains("command", "PASS secret")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "send_pop3_ok",
                    "message": "logged in"
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let mut server = helpers::start_netget_server(config).await?;
    println!("Server started on port {}", server.port);

    // VALIDATION: Send USER and PASS, verify responses
    let stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", server.port)).await?;
    println!("✓ TCP connected");

    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    // Read greeting
    let mut line = String::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), reader.read_line(&mut line)).await;
    println!("Greeting: {}", line.trim());

    // Send USER command
    println!("Sending: USER alice");
    write_half.write_all(b"USER alice\r\n").await?;
    write_half.flush().await?;

    // Read USER response
    line.clear();
    match tokio::time::timeout(Duration::from_secs(10), reader.read_line(&mut line)).await {
        Ok(Ok(n)) if n > 0 => {
            println!("POP3 USER response: {}", line.trim());
            assert!(
                line.contains("+OK"),
                "Expected +OK response for USER, got: {}",
                line
            );
            println!("✓ USER command accepted");
        }
        Ok(Ok(_)) => panic!("Connection closed after USER"),
        Ok(Err(e)) => panic!("Read error after USER: {}", e),
        Err(_) => panic!("No response to USER (timeout)"),
    }

    // Send PASS command
    println!("Sending: PASS secret");
    write_half.write_all(b"PASS secret\r\n").await?;
    write_half.flush().await?;

    // Read PASS response
    line.clear();
    match tokio::time::timeout(Duration::from_secs(10), reader.read_line(&mut line)).await {
        Ok(Ok(n)) if n > 0 => {
            println!("POP3 PASS response: {}", line.trim());
            assert!(
                line.contains("+OK"),
                "Expected +OK response for PASS, got: {}",
                line
            );
            println!("✓ PASS command accepted (authenticated)");
        }
        Ok(Ok(_)) => panic!("Connection closed after PASS"),
        Ok(Err(e)) => panic!("Read error after PASS: {}", e),
        Err(_) => panic!("No response to PASS (timeout)"),
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
async fn test_pop3_stat() -> E2EResult<()> {
    println!("\n=== E2E Test: POP3 STAT Command ===");

    // PROMPT: Tell the LLM to handle STAT command
    let prompt = "listen on port {AVAILABLE_PORT} via pop3. Send greeting '+OK POP3 ready'. \
        Accept USER and PASS with '+OK'. \
        When client sends STAT, respond with '+OK 3 1024' (3 messages, 1024 bytes total)";

    // Start the server with mocks
    let config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock
            // Mock 1: Server startup (only match initial user prompt)
            .on_prompt_containing("listen on port")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "pop3",
                    "instruction": "Handle USER, PASS, and STAT commands"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 2: Client connects - send greeting
            .on_event("pop3_command")
            .and_event_data_contains("command", "CONNECTION_ESTABLISHED")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "send_pop3_greeting",
                    "message": "POP3 ready"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 3: STAT command received (must come before generic mock)
            .on_event("pop3_command")
            .and_event_data_contains("command", "STAT")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "send_pop3_stat",
                    "message_count": 3,
                    "total_size": 1024
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 4-5: USER and PASS commands (generic catch-all)
            .on_event("pop3_command")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "send_pop3_ok"
                }
            ]))
            .expect_calls(2)
            .and()
    });

    let mut server = helpers::start_netget_server(config).await?;
    println!("Server started on port {}", server.port);

    // VALIDATION: Authenticate and send STAT
    let stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", server.port)).await?;
    println!("✓ TCP connected");

    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    // Read greeting
    let mut line = String::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), reader.read_line(&mut line)).await;
    println!("Greeting: {}", line.trim());

    // Authenticate (USER + PASS)
    write_half.write_all(b"USER alice\r\n").await?;
    write_half.flush().await?;
    line.clear();
    let _ = tokio::time::timeout(Duration::from_secs(5), reader.read_line(&mut line)).await;
    println!("USER response: {}", line.trim());

    write_half.write_all(b"PASS secret\r\n").await?;
    write_half.flush().await?;
    line.clear();
    let _ = tokio::time::timeout(Duration::from_secs(5), reader.read_line(&mut line)).await;
    println!("PASS response: {}", line.trim());

    // Send STAT command
    println!("Sending: STAT");
    write_half.write_all(b"STAT\r\n").await?;
    write_half.flush().await?;

    // Read STAT response
    line.clear();
    match tokio::time::timeout(Duration::from_secs(10), reader.read_line(&mut line)).await {
        Ok(Ok(n)) if n > 0 => {
            println!("POP3 STAT response: {}", line.trim());
            assert!(
                line.contains("+OK") && (line.contains("3") || line.contains("1024")),
                "Expected +OK with message count and size, got: {}",
                line
            );
            println!("✓ STAT response verified");
        }
        Ok(Ok(_)) => panic!("Connection closed after STAT"),
        Ok(Err(e)) => panic!("Read error after STAT: {}", e),
        Err(_) => panic!("No response to STAT (timeout)"),
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
async fn test_pop3_quit() -> E2EResult<()> {
    println!("\n=== E2E Test: POP3 QUIT Command ===");

    // PROMPT: Tell the LLM to handle QUIT command
    let prompt = "listen on port {AVAILABLE_PORT} via pop3. Send greeting '+OK POP3 ready'. \
        When client sends QUIT, respond with '+OK goodbye' and close connection";

    // Start the server with mocks
    let config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock
            // Mock 1: Server startup (only match initial user prompt)
            .on_prompt_containing("listen on port")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "pop3",
                    "instruction": "Handle QUIT command"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 2: Client connects - send greeting
            .on_event("pop3_command")
            .and_event_data_contains("command", "CONNECTION_ESTABLISHED")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "send_pop3_greeting",
                    "message": "POP3 ready"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 3: QUIT command received
            .on_event("pop3_command")
            .and_event_data_contains("command", "QUIT")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "send_pop3_ok",
                    "message": "goodbye"
                },
                {
                    "type": "close_connection"
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let mut server = helpers::start_netget_server(config).await?;
    println!("Server started on port {}", server.port);

    // VALIDATION: Send QUIT and verify response
    let stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", server.port)).await?;
    println!("✓ TCP connected");

    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    // Read greeting
    let mut line = String::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), reader.read_line(&mut line)).await;
    println!("Greeting: {}", line.trim());

    // Send QUIT command
    println!("Sending: QUIT");
    write_half.write_all(b"QUIT\r\n").await?;
    write_half.flush().await?;

    // Read QUIT response
    line.clear();
    match tokio::time::timeout(Duration::from_secs(10), reader.read_line(&mut line)).await {
        Ok(Ok(n)) if n > 0 => {
            println!("POP3 QUIT response: {}", line.trim());
            assert!(
                line.contains("+OK"),
                "Expected +OK response for QUIT, got: {}",
                line
            );
            println!("✓ QUIT response verified");
        }
        Ok(Ok(_)) => {
            println!("✓ Connection closed (expected after QUIT)");
        }
        Ok(Err(e)) => panic!("Read error after QUIT: {}", e),
        Err(_) => panic!("No response to QUIT (timeout)"),
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

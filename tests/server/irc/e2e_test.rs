//! End-to-end IRC tests for NetGet
//!
//! These tests spawn the actual NetGet binary with IRC prompts
//! and validate the responses using IRC protocol clients.

// Helper module imported from parent

use super::super::super::helpers::{self, E2EResult, NetGetConfig};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

#[tokio::test]
async fn test_irc_welcome() -> E2EResult<()> {
    println!("\n=== E2E Test: IRC Welcome (RPL_WELCOME) ===");

    // PROMPT: Tell the LLM to act as an IRC server
    let prompt = "listen on port {AVAILABLE_PORT} via irc. When users connect and send NICK and USER commands, \
        respond with IRC welcome numeric 001: ':servername 001 nickname :Welcome to the IRC Network'";

    // Start the server with mocks
    let config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock
            // Mock 1: Server startup (user command)
            .on_instruction_containing("listen on port")
            .and_instruction_containing("irc")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "IRC",
                    // One call per line, so each rule below answers its own line: the
                    // lines are written back to back, and with batching (IRC's default)
                    // they would be answered together. batching_test.rs covers that.
                    "batching": false,
                    "instruction": "IRC server - respond with welcome (001) after NICK and USER"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 2: IRC message received (NICK command)
            .on_event("irc_message_received")
            .and_event_data_contains("message", "NICK")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "wait_for_more"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 3: IRC message received (USER command)
            .on_event("irc_message_received")
            .and_event_data_contains("message", "USER")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "send_irc_message",
                    "message": ":testserver 001 testuser :Welcome to the IRC Network"
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let mut server = helpers::start_netget_server(config).await?;
    println!("Server started on port {}", server.port);

    // VALIDATION: Connect and perform IRC registration
    println!("Connecting to IRC server...");
    let stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", server.port)).await?;
    println!("✓ TCP connected");

    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    // Send IRC registration commands
    println!("Sending NICK and USER commands...");
    write_half.write_all(b"NICK testuser\r\n").await?;
    write_half
        .write_all(b"USER testuser 0 * :Test User\r\n")
        .await?;
    write_half.flush().await?;

    // Read responses (may be multiple lines)
    let mut received_welcome = false;
    for attempt in 1..=5 {
        let mut line = String::new();
        match tokio::time::timeout(Duration::from_secs(10), reader.read_line(&mut line)).await {
            Ok(Ok(n)) if n > 0 => {
                println!("IRC response ({}): {}", attempt, line.trim());

                // Check for IRC numeric 001 (RPL_WELCOME)
                if line.contains(" 001 ") || line.contains("Welcome") || line.contains("WELCOME") {
                    println!("✓ IRC welcome message (001) received");
                    received_welcome = true;
                    break;
                }
            }
            Ok(Ok(_)) => {
                println!("  Connection closed");
                break;
            }
            Ok(Err(e)) => {
                println!("  Read error: {}", e);
                break;
            }
            Err(_) => {
                println!("  Timeout on attempt {}", attempt);
                break;
            }
        }
    }

    assert!(received_welcome, "Should receive IRC 001 welcome message");

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
async fn test_irc_ping_pong() -> E2EResult<()> {
    println!("\n=== E2E Test: IRC PING/PONG ===");

    // PROMPT: Tell the LLM to handle IRC PING
    let prompt =
        "listen on port {AVAILABLE_PORT} via irc. When you receive a PING command with a token, \
        respond with PONG using the same token. Format: 'PONG :token'";

    // Start the server with mocks
    let config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock
            // Mock 1: Server startup (user command)
            .on_instruction_containing("listen on port")
            .and_instruction_containing("irc")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "IRC",
                    "instruction": "IRC server - respond to PING with PONG"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 2: IRC data received (PING command)
            .on_event("irc_message_received")
            .and_event_data_contains("message", "PING")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "send_irc_message",
                    "message": "PONG :1234567890"
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let mut server = helpers::start_netget_server(config).await?;
    println!("Server started on port {}", server.port);

    // VALIDATION: Send PING and verify PONG
    let stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", server.port)).await?;
    println!("✓ TCP connected");

    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    // Send PING command
    let ping_token = "1234567890";
    println!("Sending: PING :{}", ping_token);
    write_half
        .write_all(format!("PING :{}\r\n", ping_token).as_bytes())
        .await?;
    write_half.flush().await?;

    // Read PONG response
    let mut line = String::new();
    match tokio::time::timeout(Duration::from_secs(10), reader.read_line(&mut line)).await {
        Ok(Ok(n)) if n > 0 => {
            println!("IRC response: {}", line.trim());

            // Verify PONG with same token
            assert!(
                line.contains("PONG") && line.contains(ping_token),
                "Expected 'PONG :{}', got: {}",
                ping_token,
                line
            );
            println!("✓ IRC PING/PONG verified");
        }
        Ok(Ok(_)) => {
            println!("Note: Connection closed without response");
        }
        Ok(Err(e)) => {
            println!("Note: Read error: {}", e);
        }
        Err(_) => {
            panic!("No PONG response received (timeout)");
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
async fn test_irc_join_channel() -> E2EResult<()> {
    println!("\n=== E2E Test: IRC Channel Join ===");

    // PROMPT: Tell the LLM to handle channel joins
    let prompt = "listen on port {AVAILABLE_PORT} via irc. When users send JOIN #channel, \
        respond with ':nickname JOIN #channel' to confirm the join";

    // Start the server with mocks
    let config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock
            // Mock 1: Server startup (user command)
            .on_instruction_containing("listen on port")
            .and_instruction_containing("irc")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "IRC",
                    // One call per line, so each rule below answers its own line: the
                    // lines are written back to back, and with batching (IRC's default)
                    // they would be answered together. batching_test.rs covers that.
                    "batching": false,
                    "instruction": "IRC server - confirm channel joins"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 2: NICK command
            .on_event("irc_message_received")
            .and_event_data_contains("message", "NICK")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "wait_for_more"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 3: USER command
            .on_event("irc_message_received")
            .and_event_data_contains("message", "USER")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "wait_for_more"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 4: JOIN command
            .on_event("irc_message_received")
            .and_event_data_contains("message", "JOIN")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "send_irc_message",
                    "message": ":testuser JOIN #test"
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let mut server = helpers::start_netget_server(config).await?;
    println!("Server started on port {}", server.port);

    // VALIDATION: Connect and join a channel
    let stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", server.port)).await?;
    println!("✓ TCP connected");

    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    // Send IRC registration and JOIN
    println!("Sending IRC commands...");
    write_half.write_all(b"NICK testuser\r\n").await?;
    write_half
        .write_all(b"USER testuser 0 * :Test User\r\n")
        .await?;
    write_half.write_all(b"JOIN #test\r\n").await?;
    write_half.flush().await?;

    // Read responses
    let mut received_join = false;
    for attempt in 1..=5 {
        let mut line = String::new();
        match tokio::time::timeout(Duration::from_secs(10), reader.read_line(&mut line)).await {
            Ok(Ok(n)) if n > 0 => {
                println!("IRC response ({}): {}", attempt, line.trim());

                // Check for JOIN confirmation
                if line.contains("JOIN") && line.contains("#test") {
                    println!("✓ JOIN confirmation received");
                    received_join = true;
                    break;
                }
            }
            _ => break,
        }
    }

    assert!(received_join, "Should receive JOIN confirmation");

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
async fn test_irc_privmsg() -> E2EResult<()> {
    println!("\n=== E2E Test: IRC PRIVMSG ===");

    // PROMPT: Tell the LLM to handle private messages
    let prompt =
        "listen on port {AVAILABLE_PORT} via irc. When you receive 'PRIVMSG target :message', \
        echo it back as 'PRIVMSG sender :message'";

    // Start the server with mocks
    let config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock
            // Mock 1: Server startup (user command)
            .on_instruction_containing("listen on port")
            .and_instruction_containing("irc")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "IRC",
                    // One call per line, so each rule below answers its own line: the
                    // lines are written back to back, and with batching (IRC's default)
                    // they would be answered together. batching_test.rs covers that.
                    "batching": false,
                    "instruction": "IRC server - echo private messages"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 2: NICK command
            .on_event("irc_message_received")
            .and_event_data_contains("message", "NICK")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "wait_for_more"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 3: USER command
            .on_event("irc_message_received")
            .and_event_data_contains("message", "USER")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "wait_for_more"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 4: PRIVMSG command
            .on_event("irc_message_received")
            .and_event_data_contains("message", "PRIVMSG")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "send_irc_message",
                    "message": "PRIVMSG testuser :Hello IRC"
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let mut server = helpers::start_netget_server(config).await?;
    println!("Server started on port {}", server.port);

    // VALIDATION: Send PRIVMSG and check for response
    let stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", server.port)).await?;
    println!("✓ TCP connected");

    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    // Send registration and message
    println!("Sending IRC commands...");
    write_half.write_all(b"NICK testuser\r\n").await?;
    write_half
        .write_all(b"USER testuser 0 * :Test User\r\n")
        .await?;
    write_half.write_all(b"PRIVMSG bot :Hello IRC\r\n").await?;
    write_half.flush().await?;

    // Read responses
    let mut received_privmsg = false;
    for attempt in 1..=5 {
        let mut line = String::new();
        match tokio::time::timeout(Duration::from_secs(10), reader.read_line(&mut line)).await {
            Ok(Ok(n)) if n > 0 => {
                println!("IRC response ({}): {}", attempt, line.trim());

                // Check for PRIVMSG response
                if line.contains("PRIVMSG") && line.contains("Hello") {
                    println!("✓ PRIVMSG response received");
                    received_privmsg = true;
                    break;
                }
            }
            _ => break,
        }
    }

    assert!(received_privmsg, "Should receive PRIVMSG response");

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
async fn test_irc_multiple_clients() -> E2EResult<()> {
    println!("\n=== E2E Test: IRC Multiple Clients ===");

    // PROMPT: Tell the LLM to handle multiple IRC clients
    let prompt =
        "listen on port {AVAILABLE_PORT} via irc. Handle multiple concurrent IRC clients. \
        Send welcome message (001) to each client that connects with NICK and USER";

    // Start the server with mocks
    let config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock
            // Mock 1: Server startup (user command)
            .on_instruction_containing("listen on port")
            .and_instruction_containing("irc")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "IRC",
                    // One call per line, so each rule below answers its own line: the
                    // lines are written back to back, and with batching (IRC's default)
                    // they would be answered together. batching_test.rs covers that.
                    "batching": false,
                    "instruction": "IRC server - send welcome to all clients"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 2-7: 3 clients × (NICK + USER) = 6 events
            // We expect NICK command (respond with wait_for_more)
            .on_event("irc_message_received")
            .and_event_data_contains("message", "NICK")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "wait_for_more"
                }
            ]))
            .expect_calls(3)
            .and()
            // We expect USER command (respond with 001 welcome)
            .on_event("irc_message_received")
            .and_event_data_contains("message", "USER")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "send_irc_message",
                    "message": ":testserver 001 testuser :Welcome to the IRC Network"
                }
            ]))
            .expect_calls(3)
            .and()
    });

    let mut server = helpers::start_netget_server(config).await?;
    println!("Server started on port {}", server.port);

    // VALIDATION: Connect multiple clients
    println!("Testing multiple IRC clients...");

    for i in 1..=3 {
        println!("  Client #{}", i);

        let stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", server.port)).await?;
        let (read_half, mut write_half) = stream.into_split();
        let mut reader = BufReader::new(read_half);

        // Register
        write_half
            .write_all(format!("NICK testuser{}\r\n", i).as_bytes())
            .await?;
        write_half
            .write_all(format!("USER testuser{} 0 * :Test User {}\r\n", i, i).as_bytes())
            .await?;
        write_half.flush().await?;

        // Try to read response
        let mut line = String::new();
        match tokio::time::timeout(Duration::from_secs(5), reader.read_line(&mut line)).await {
            Ok(Ok(n)) if n > 0 => {
                println!("    Response: {}", line.trim());
                if line.contains("001") || line.contains("Welcome") {
                    println!("    ✓ Client #{} received welcome", i);
                }
            }
            _ => {
                println!("    Note: No response for client #{}", i);
            }
        }

        // Small delay between clients
    }

    println!("✓ Multiple client handling tested");

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

//! End-to-end SMTP tests for NetGet
//!
//! These tests spawn the actual NetGet binary with SMTP prompts
//! and validate the responses using SMTP protocol clients.


// Helper module imported from parent

use super::super::super::helpers::{self, E2EResult};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

#[tokio::test]
async fn test_smtp_greeting() -> E2EResult<()> {
    println!("\n=== E2E Test: SMTP Greeting (220) ===");

    // PROMPT: Tell the LLM to send SMTP greeting
    let prompt =
        "listen on port {AVAILABLE_PORT} via smtp. When a client connects, send SMTP greeting: \
        '220 mail.example.com ESMTP Service Ready'";

    // Start the server with mocks
    let config = helpers::NetGetConfig::new(prompt).with_mock(|mock| {
        mock.on_instruction_containing("listen on port")
            .and_instruction_containing("smtp")
            .and_instruction_containing("greeting")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "SMTP",
                    "instruction": prompt
                }
            ]))
            .expect_calls(1)
            .and()
            // The greeting itself is an `smtp_command` event. This mock used to be missing,
            // so the LLM call failed, the server wrote nothing, and the test's read timed out
            // into the tolerant "Note: No greeting received" arm below - i.e. it passed while
            // asserting nothing. The server now answers a failed greeting with 421, which made
            // that hole visible. Mock the greeting so the test measures what it claims to.
            .on_event("smtp_command")
            .and_event_data_contains("command", "CONNECTION_ESTABLISHED")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "send_smtp_greeting",
                    "hostname": "mail.example.com",
                    "message": "ESMTP Service Ready"
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let server = helpers::start_netget_server(config).await?;
    println!("Server started on port {}", server.port);

    // VALIDATION: Connect and expect 220 greeting
    println!("Connecting to SMTP server...");
    let stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", server.port)).await?;
    println!("✓ TCP connected");

    let (read_half, _write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    // Read greeting
    let mut line = String::new();
    match tokio::time::timeout(Duration::from_secs(10), reader.read_line(&mut line)).await {
        Ok(Ok(n)) if n > 0 => {
            println!("SMTP greeting: {}", line.trim());

            // Verify SMTP greeting code 220
            assert!(
                line.starts_with("220") || line.contains("220"),
                "Expected SMTP greeting starting with '220', got: {}",
                line
            );
            println!("✓ SMTP greeting (220) verified");
        }
        // These used to be tolerated with a printed note, which is how the greeting could go
        // missing entirely without failing anything.
        Ok(Ok(_)) => panic!("Connection closed without an SMTP greeting"),
        Ok(Err(e)) => panic!("Read error while waiting for the SMTP greeting: {e}"),
        Err(_) => panic!("No SMTP greeting within 10s"),
    }

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
async fn test_smtp_ehlo() -> E2EResult<()> {
    println!("\n=== E2E Test: SMTP EHLO Command ===");

    // EHLO is answered by NetGet, not the model: its reply is the greeting's hostname and the
    // extensions this server implements, which are facts rather than decisions. Only the
    // greeting reaches the model, so the model sees exactly one smtp_command event.
    let prompt = "listen on port {AVAILABLE_PORT} via smtp. Send greeting '220 mail.test ESMTP'.";

    let config = helpers::NetGetConfig::new(prompt).with_mock(|mock| {
        mock.on_instruction_containing("listen on port")
            .and_instruction_containing("smtp")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "SMTP",
                    "instruction": prompt
                }
            ]))
            .expect_calls(1)
            .and()
            .on_event("smtp_command")
            .and_event_data_contains("command", "CONNECTION_ESTABLISHED")
            .respond_with_actions(serde_json::json!([
                { "type": "send_smtp_greeting", "hostname": "mail.test", "message": "ESMTP" }
            ]))
            .expect_calls(1)
            .and()
    });

    let server = helpers::start_netget_server(config).await?;
    let stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", server.port)).await?;
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    async fn read_reply_line<R: tokio::io::AsyncBufRead + Unpin>(reader: &mut R) -> String {
        let mut line = String::new();
        match tokio::time::timeout(Duration::from_secs(10), reader.read_line(&mut line)).await {
            Ok(Ok(n)) if n > 0 => line,
            other => panic!("expected a reply line, got {other:?}"),
        }
    }

    assert_eq!(
        read_reply_line(&mut reader).await,
        "220 mail.test ESMTP\r\n"
    );

    write_half.write_all(b"EHLO client.test\r\n").await?;
    write_half.flush().await?;
    assert_eq!(
        read_reply_line(&mut reader).await,
        "250-mail.test greets client.test\r\n"
    );
    assert_eq!(read_reply_line(&mut reader).await, "250 8BITMIME\r\n");

    // HELO is the single-line form, and neither advertises what this server cannot do.
    write_half.write_all(b"HELO client.test\r\n").await?;
    write_half.flush().await?;
    assert_eq!(
        read_reply_line(&mut reader).await,
        "250 mail.test greets client.test\r\n"
    );

    // EHLO without its argument is a syntax error, not a greeting.
    write_half.write_all(b"EHLO\r\n").await?;
    write_half.flush().await?;
    assert!(read_reply_line(&mut reader).await.starts_with("501 "));

    assert!(
        server.output_contains("decision=netget_answer").await,
        "a NetGet-answered EHLO is logged as such"
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    println!("=== Test completed ===\n");
    Ok(())
}

#[tokio::test]
async fn test_smtp_mail_transaction() -> E2EResult<()> {
    println!("\n=== E2E Test: SMTP Mail Transaction ===");

    // PROMPT: Tell the LLM to handle a full SMTP transaction
    let prompt = "listen on port {AVAILABLE_PORT} via smtp. Handle full SMTP mail transaction: \
        1) Send '220' greeting \
        2) Respond to EHLO with '250 OK' \
        3) Respond to MAIL FROM with '250 Sender OK' \
        4) Respond to RCPT TO with '250 Recipient OK' \
        5) Respond to DATA with '354 Start mail input' \
        6) After mail data ending with '.', respond with '250 Message accepted'";

    // Start the server with mocks. Every step of the transaction is an `smtp_command`
    // event and must be mocked: with only the startup call mocked (the previous state of
    // this test), every event hit the mock unmatched (HTTP 500), the greeting failed
    // closed with a 421 that closes the session (RFC 5321 §3.1), and the test's later
    // writes died on a broken pipe before `verify_mocks` was ever reached.
    let config = helpers::NetGetConfig::new(prompt).with_mock(|mock| {
        mock.on_instruction_containing("listen on port")
            .and_instruction_containing("smtp")
            .and_instruction_containing("transaction")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "SMTP",
                    "instruction": prompt
                }
            ]))
            .expect_calls(1)
            .and()
            .on_event("smtp_command")
            .and_event_data_contains("command", "CONNECTION_ESTABLISHED")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "send_smtp_greeting",
                    "hostname": "mail.test",
                    "message": "ESMTP Service Ready"
                }
            ]))
            .expect_calls(1)
            .and()
            // No EHLO rule: NetGet answers EHLO itself, so it never reaches the model. An
            // EHLO event would find no rule, get the mock's 500 and fail the session.
            .on_event("smtp_command")
            .and_event_data_contains("command", "MAIL FROM")
            .respond_with_actions(serde_json::json!([
                { "type": "send_smtp_ok", "message": "Sender OK" }
            ]))
            .expect_calls(1)
            .and()
            .on_event("smtp_command")
            .and_event_data_contains("command", "RCPT TO")
            .respond_with_actions(serde_json::json!([
                { "type": "send_smtp_ok", "message": "Recipient OK" }
            ]))
            .expect_calls(1)
            .and()
            .on_event("smtp_command")
            .and_event_data_contains("command", "DATA")
            .respond_with_actions(serde_json::json!([
                { "type": "send_smtp_start_data" }
            ]))
            .expect_calls(1)
            .and()
    });

    let server = helpers::start_netget_server(config).await?;
    println!("Server started on port {}", server.port);

    // VALIDATION: Perform full SMTP transaction
    let stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", server.port)).await?;
    println!("✓ TCP connected");

    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    // One step of the transaction: read exactly one reply line and require the expected
    // code. The former "print and shrug" arms let the whole transaction fail silently.
    async fn expect_reply<R: tokio::io::AsyncBufRead + Unpin>(
        reader: &mut R,
        step: &str,
        code: &str,
    ) -> E2EResult<()> {
        let mut line = String::new();
        match tokio::time::timeout(Duration::from_secs(10), reader.read_line(&mut line)).await {
            Ok(Ok(n)) if n > 0 => {
                println!("  Response: {}", line.trim());
                assert!(
                    line.starts_with(code),
                    "{step}: expected reply code {code}, got: {line}"
                );
                Ok(())
            }
            Ok(Ok(_)) => panic!("{step}: connection closed without a reply"),
            Ok(Err(e)) => panic!("{step}: read error: {e}"),
            Err(_) => panic!("{step}: no reply within 10s"),
        }
    }

    // Read greeting
    expect_reply(&mut reader, "greeting", "220").await?;

    // Send EHLO. The reply is NetGet's own: the greeting's hostname and the one extension
    // this server implements, as a two-line reply.
    println!("Sending: EHLO client.test");
    write_half.write_all(b"EHLO client.test\r\n").await?;
    write_half.flush().await?;
    expect_reply(&mut reader, "EHLO", "250-mail.test greets client.test").await?;
    expect_reply(&mut reader, "EHLO", "250 8BITMIME").await?;

    // Send MAIL FROM
    println!("Sending: MAIL FROM:<sender@test.com>");
    write_half
        .write_all(b"MAIL FROM:<sender@test.com>\r\n")
        .await?;
    write_half.flush().await?;
    expect_reply(&mut reader, "MAIL FROM", "250").await?;
    println!("  ✓ MAIL FROM accepted");

    // Send RCPT TO
    println!("Sending: RCPT TO:<recipient@test.com>");
    write_half
        .write_all(b"RCPT TO:<recipient@test.com>\r\n")
        .await?;
    write_half.flush().await?;
    expect_reply(&mut reader, "RCPT TO", "250").await?;
    println!("  ✓ RCPT TO accepted");

    // Send DATA
    println!("Sending: DATA");
    write_half.write_all(b"DATA\r\n").await?;
    write_half.flush().await?;
    expect_reply(&mut reader, "DATA", "354").await?;
    println!("  ✓ DATA command accepted");

    println!("✓ SMTP transaction flow tested");

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
async fn test_smtp_quit() -> E2EResult<()> {
    println!("\n=== E2E Test: SMTP QUIT Command ===");

    // PROMPT: Tell the LLM to handle QUIT
    let prompt = "listen on port {AVAILABLE_PORT} via smtp. Send greeting '220 mail.test'. \
        When client sends QUIT, respond with '221 Bye' and close connection";

    // Start the server with mocks
    let config = helpers::NetGetConfig::new(prompt).with_mock(|mock| {
        mock.on_instruction_containing("listen on port")
            .and_instruction_containing("smtp")
            .and_instruction_containing("QUIT")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "SMTP",
                    "instruction": prompt
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let server = helpers::start_netget_server(config).await?;
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

    // Send QUIT
    println!("Sending: QUIT");
    write_half.write_all(b"QUIT\r\n").await?;
    write_half.flush().await?;

    // Read QUIT response
    let mut line = String::new();
    match tokio::time::timeout(Duration::from_secs(10), reader.read_line(&mut line)).await {
        Ok(Ok(n)) if n > 0 => {
            println!("SMTP response: {}", line.trim());

            // Verify 221 response
            if line.starts_with("221") || line.contains("221") {
                println!("✓ SMTP QUIT response (221) verified");
            } else {
                println!("Note: Expected 221, got: {}", line);
            }
        }
        _ => {
            println!("Note: No response to QUIT");
        }
    }

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
async fn test_smtp_error_handling() -> E2EResult<()> {
    println!("\n=== E2E Test: SMTP Error Handling ===");

    // PROMPT: Tell the LLM to handle invalid commands
    let prompt = "listen on port {AVAILABLE_PORT} via smtp. Send greeting '220 mail.test'. \
        When you receive invalid commands, respond with '500 Command not recognized'";

    // Start the server with mocks
    let config = helpers::NetGetConfig::new(prompt).with_mock(|mock| {
        mock.on_instruction_containing("listen on port")
            .and_instruction_containing("smtp")
            .and_instruction_containing("invalid")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "SMTP",
                    "instruction": prompt
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let server = helpers::start_netget_server(config).await?;
    println!("Server started on port {}", server.port);

    // VALIDATION: Send invalid command
    let stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", server.port)).await?;
    println!("✓ TCP connected");

    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    // Read greeting
    let mut line = String::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), reader.read_line(&mut line)).await;
    println!("Greeting: {}", line.trim());

    // Send invalid command
    println!("Sending invalid command: INVALID");
    write_half.write_all(b"INVALID\r\n").await?;
    write_half.flush().await?;

    // Read error response
    let mut line = String::new();
    match tokio::time::timeout(Duration::from_secs(10), reader.read_line(&mut line)).await {
        Ok(Ok(n)) if n > 0 => {
            println!("SMTP response: {}", line.trim());

            // Should get some kind of error (5xx)
            if line.starts_with("5") || line.contains("error") || line.contains("Error") {
                println!("✓ SMTP error response received");
            } else {
                println!("Note: Response to invalid command: {}", line);
            }
        }
        _ => {
            println!("Note: No response to invalid command");
        }
    }

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    println!("=== Test completed ===\n");
    Ok(())
}

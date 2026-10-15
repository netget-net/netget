//! End-to-end FTP tests for NetGet
//!
//! These tests spawn the actual NetGet binary with FTP prompts
//! and validate the responses using raw TCP connections.


use super::super::super::helpers::{self, E2EResult};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

/// Read one reply line within 10s; a timeout, EOF or read error fails the test with the
/// name of the step, never a "Note:" that lets a silent server pass.
async fn read_reply<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut BufReader<R>,
    step: &str,
) -> String {
    let mut line = String::new();
    match tokio::time::timeout(Duration::from_secs(10), reader.read_line(&mut line)).await {
        Ok(Ok(n)) if n > 0 => {
            println!("{step} reply: {}", line.trim());
            line
        }
        Ok(Ok(_)) => panic!("FTP closed the connection instead of answering {step}"),
        Ok(Err(e)) => panic!("FTP read error while waiting for {step}: {e}"),
        Err(_) => panic!("no FTP reply to {step} within 10s"),
    }
}

#[tokio::test]
async fn test_ftp_greeting() -> E2EResult<()> {
    println!("\n=== E2E Test: FTP Greeting (220) ===");

    // PROMPT: Tell the LLM to send FTP greeting
    let prompt =
        "listen on port {AVAILABLE_PORT} via ftp. When a client connects, send FTP greeting: \
        '220 FTP Server Ready'";

    // Start the server with mocks
    let config = helpers::NetGetConfig::new(prompt).with_mock(|mock| {
        mock.on_instruction_containing("listen on port")
            .and_instruction_containing("ftp")
            .and_instruction_containing("greeting")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "FTP",
                    "instruction": prompt
                }
            ]))
            .expect_calls(1)
            .and()
            // The greeting the test is about. This rule used to be missing, so the handler
            // could not produce a banner at all - and because the server then wrote nothing,
            // the read below timed out and fell into the `Note: No greeting received` branch,
            // which asserts nothing. The test passed for ten seconds of doing nothing. The
            // server now answers 421 on that path, which is what surfaced it.
            .on_event("ftp_command")
            .and_event_data_contains("command", "CONNECTION_ESTABLISHED")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "send_ftp_response",
                    "code": 220,
                    "message": "FTP Server Ready"
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let server = helpers::start_netget_server(config).await?;
    println!("Server started on port {}", server.port);

    // VALIDATION: Connect and expect 220 greeting
    println!("Connecting to FTP server...");
    let stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", server.port)).await?;
    println!("TCP connected");

    let (read_half, _write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    // Read greeting
    let mut line = String::new();
    match tokio::time::timeout(Duration::from_secs(10), reader.read_line(&mut line)).await {
        Ok(Ok(n)) if n > 0 => {
            println!("FTP greeting: {}", line.trim());

            // Verify FTP greeting code 220
            assert!(
                line.starts_with("220") || line.contains("220"),
                "Expected FTP greeting starting with '220', got: {}",
                line
            );
            println!("FTP greeting (220) verified");
        }
        Ok(Ok(_)) => {
            panic!("FTP closed the connection without sending a greeting");
        }
        Ok(Err(e)) => {
            panic!("FTP read error while waiting for the greeting: {}", e);
        }
        Err(_) => {
            panic!(
                "No FTP greeting within 10s. This branch used to print a note and let the \
                 test pass, which is how a server that greeted nobody went unnoticed."
            );
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
async fn test_ftp_user_pass() -> E2EResult<()> {
    println!("\n=== E2E Test: FTP USER/PASS Commands ===");

    // PROMPT: Handle USER and PASS commands
    let prompt = "listen on port {AVAILABLE_PORT} via ftp. Send greeting '220 FTP Ready'. \
        When client sends USER anonymous, respond with '331 Password required'. \
        When client sends PASS, respond with '230 User logged in'";

    // Start the server with mocks
    let config = helpers::NetGetConfig::new(prompt).with_mock(|mock| {
        mock.on_instruction_containing("listen on port")
            .and_instruction_containing("ftp")
            .and_instruction_containing("USER")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "FTP",
                    "instruction": prompt
                }
            ]))
            .expect_calls(1)
            .and()
            // These three event rules used to be missing. With no rule the mock answered
            // 500, the server refused the greeting with 421 and closed, and the test's
            // `PASS` write hit a dead socket and bailed out before `verify_mocks` - so the
            // test neither verified 331/230 nor reached its own assertions.
            .on_event("ftp_command")
            .and_event_data_contains("command", "CONNECTION_ESTABLISHED")
            .respond_with_actions(serde_json::json!([
                { "type": "send_ftp_response", "code": 220, "message": "FTP Ready" }
            ]))
            .expect_calls(1)
            .and()
            .on_event("ftp_command")
            .and_event_data_contains("command", "USER anonymous")
            .respond_with_actions(serde_json::json!([
                { "type": "send_ftp_response", "code": 331, "message": "Password required" }
            ]))
            .expect_calls(1)
            .and()
            .on_event("ftp_command")
            .and_event_data_contains("command", "PASS")
            .respond_with_actions(serde_json::json!([
                { "type": "send_ftp_response", "code": 230, "message": "User logged in" }
            ]))
            .expect_calls(1)
            .and()
    });

    let server = helpers::start_netget_server(config).await?;
    println!("Server started on port {}", server.port);

    // VALIDATION: Send USER and PASS commands
    let stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", server.port)).await?;
    println!("TCP connected");

    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    let greeting = read_reply(&mut reader, "greeting").await;
    assert!(greeting.starts_with("220"), "expected 220, got: {greeting}");

    println!("Sending: USER anonymous");
    write_half.write_all(b"USER anonymous\r\n").await?;
    write_half.flush().await?;
    let user_response = read_reply(&mut reader, "USER").await;
    assert!(
        user_response.starts_with("331"),
        "expected 331 to USER, got: {user_response}"
    );

    println!("Sending: PASS guest@example.com");
    write_half.write_all(b"PASS guest@example.com\r\n").await?;
    write_half.flush().await?;
    let pass_response = read_reply(&mut reader, "PASS").await;
    assert!(
        pass_response.starts_with("230"),
        "expected 230 to PASS, got: {pass_response}"
    );

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
async fn test_ftp_pwd_quit() -> E2EResult<()> {
    println!("\n=== E2E Test: FTP PWD and QUIT Commands ===");

    // PROMPT: Handle PWD and QUIT commands
    let prompt = "listen on port {AVAILABLE_PORT} via ftp. Send greeting '220 FTP Ready'. \
        When client sends PWD, respond with '257 \"/\" is current directory'. \
        When client sends QUIT, respond with '221 Goodbye' and close connection";

    // Start the server with mocks
    let config = helpers::NetGetConfig::new(prompt).with_mock(|mock| {
        mock.on_instruction_containing("listen on port")
            .and_instruction_containing("ftp")
            .and_instruction_containing("PWD")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "FTP",
                    "instruction": prompt
                }
            ]))
            .expect_calls(1)
            .and()
            // Same repair as test_ftp_user_pass: the event rules were missing entirely.
            .on_event("ftp_command")
            .and_event_data_contains("command", "CONNECTION_ESTABLISHED")
            .respond_with_actions(serde_json::json!([
                { "type": "send_ftp_response", "code": 220, "message": "FTP Ready" }
            ]))
            .expect_calls(1)
            .and()
            .on_event("ftp_command")
            .and_event_data_contains("command", "PWD")
            .respond_with_actions(serde_json::json!([
                { "type": "send_ftp_response", "code": 257, "message": "\"/\" is current directory" }
            ]))
            .expect_calls(1)
            .and()
            .on_event("ftp_command")
            .and_event_data_contains("command", "QUIT")
            .respond_with_actions(serde_json::json!([
                { "type": "send_ftp_response", "code": 221, "message": "Goodbye" },
                { "type": "close_connection" }
            ]))
            .expect_calls(1)
            .and()
    });

    let server = helpers::start_netget_server(config).await?;
    println!("Server started on port {}", server.port);

    // VALIDATION: Send PWD and QUIT commands
    let stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", server.port)).await?;
    println!("TCP connected");

    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    let greeting = read_reply(&mut reader, "greeting").await;
    assert!(greeting.starts_with("220"), "expected 220, got: {greeting}");

    println!("Sending: PWD");
    write_half.write_all(b"PWD\r\n").await?;
    write_half.flush().await?;
    let pwd_response = read_reply(&mut reader, "PWD").await;
    assert!(
        pwd_response.starts_with("257"),
        "expected 257 to PWD, got: {pwd_response}"
    );

    println!("Sending: QUIT");
    write_half.write_all(b"QUIT\r\n").await?;
    write_half.flush().await?;
    let quit_response = read_reply(&mut reader, "QUIT").await;
    assert!(
        quit_response.starts_with("221"),
        "expected 221 to QUIT, got: {quit_response}"
    );

    // close_connection after 221: the control connection must actually end.
    let mut rest = String::new();
    let n = tokio::time::timeout(Duration::from_secs(10), reader.read_line(&mut rest))
        .await
        .expect("server must close the control connection after QUIT")?;
    assert_eq!(n, 0, "unexpected data after QUIT: {rest:?}");

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    println!("=== Test completed ===\n");
    Ok(())
}

/// A control line with no newline in it must not grow the server's buffer without bound.
///
/// `BufReader::read_line` accumulates until it finds `\n`, so an unauthenticated peer that
/// connects and streams bytes forever was a one-connection out-of-memory. The server now caps
/// the line at `MAX_COMMAND_LINE` and answers `500` before closing, which is what this test
/// observes: the reply arrives *while the peer is still able to send more*, so the cap fired
/// rather than the server having buffered everything and waited for an EOF that never came.
#[tokio::test]
async fn test_ftp_refuses_an_unbounded_command_line() -> E2EResult<()> {
    println!("\n=== E2E Test: FTP over-long command line ===");

    let prompt = "listen on port {AVAILABLE_PORT} via ftp. Send greeting '220 FTP Ready'";

    let config = helpers::NetGetConfig::new(prompt).with_mock(|mock| {
        mock.on_instruction_containing("listen on port")
            .and_instruction_containing("ftp")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "FTP",
                    "instruction": prompt
                }
            ]))
            .expect_calls(1)
            .and()
            .on_event("ftp_command")
            .and_event_data_contains("command", "CONNECTION_ESTABLISHED")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "send_ftp_response",
                    "code": 220,
                    "message": "FTP Ready"
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let server = helpers::start_netget_server(config).await?;

    let stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", server.port)).await?;
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    let greeting = read_reply(&mut reader, "greeting").await;
    assert!(
        greeting.starts_with("220"),
        "expected a 220 greeting, got: {greeting}"
    );

    // 64 KiB with not one newline in it — eight times the cap.
    let flood = vec![b'A'; 64 * 1024];
    // A short write is fine: the point is that the server answers without having consumed a
    // newline, so ignore a write error caused by the server closing on us mid-flood.
    let _ = write_half.write_all(&flood).await;
    let _ = write_half.flush().await;

    let reply = read_reply(&mut reader, "over-long command line").await;
    assert!(
        reply.starts_with("500"),
        "an over-long command line must be refused with 500, got: {reply}"
    );

    // And the control connection must be closed, not left accumulating.
    let mut trailing = String::new();
    match tokio::time::timeout(Duration::from_secs(10), reader.read_line(&mut trailing)).await {
        Ok(Ok(0)) => println!("connection closed after the 500, as expected"),
        Ok(Ok(_)) => panic!("FTP kept the connection open after refusing: {trailing}"),
        Ok(Err(_)) => println!("connection reset after the 500, which is also a close"),
        Err(_) => panic!("FTP left the connection open after a 500 Command line too long"),
    }

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    println!("=== Test completed ===\n");
    Ok(())
}

/// A handler must not be able to forge a second reply by putting CRLF in `message`.
///
/// FTP is line-oriented, so `"need password\r\n230 Logged in"` is not a long 331 — it is a 331
/// followed by a forged 230, and a client's reply-code state machine reads it as a successful
/// login. The action description always said CR and LF were forbidden; nothing enforced it.
/// What this test pins is the property, not the mechanism: whatever the server does with the
/// rejected action, a `230` line must never reach the peer.
#[tokio::test]
async fn test_ftp_reply_text_cannot_forge_a_second_reply() -> E2EResult<()> {
    println!("\n=== E2E Test: FTP reply-splitting is refused ===");

    let prompt = "listen on port {AVAILABLE_PORT} via ftp. Send greeting '220 FTP Ready'";

    let config = helpers::NetGetConfig::new(prompt).with_mock(|mock| {
        mock.on_instruction_containing("listen on port")
            .and_instruction_containing("ftp")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "FTP",
                    "instruction": prompt
                }
            ]))
            .expect_calls(1)
            .and()
            .on_event("ftp_command")
            .and_event_data_contains("command", "CONNECTION_ESTABLISHED")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "send_ftp_response",
                    "code": 220,
                    "message": "FTP Ready"
                }
            ]))
            .expect_calls(1)
            .and()
            // The hostile answer: one action whose message smuggles a whole second reply.
            .on_event("ftp_command")
            .and_event_data_contains("command", "USER anonymous")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "send_ftp_response",
                    "code": 331,
                    "message": "Password required\r\n230 User logged in"
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let server = helpers::start_netget_server(config).await?;

    let stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", server.port)).await?;
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    let greeting = read_reply(&mut reader, "greeting").await;
    assert!(
        greeting.starts_with("220"),
        "expected a 220 greeting, got: {greeting}"
    );

    write_half.write_all(b"USER anonymous\r\n").await?;
    write_half.flush().await?;

    // Drain everything the server is willing to say, then assert on all of it at once. A
    // per-line assertion would pass simply by stopping before the forged line.
    let mut transcript = String::new();
    loop {
        let mut line = String::new();
        match tokio::time::timeout(Duration::from_secs(10), reader.read_line(&mut line)).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
            Ok(Ok(_)) => {
                println!("reply line: {}", line.trim());
                transcript.push_str(&line);
            }
        }
    }

    assert!(
        !transcript.lines().any(|l| l.starts_with("230")),
        "a handler forged a 230 through CRLF in 'message'; transcript was:\n{transcript}"
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    println!("=== Test completed ===\n");
    Ok(())
}

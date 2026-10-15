//! What a POP3 client gets when the LLM backend fails: `-ERR`, never silence and never `+OK`.
//!
//! POP3 has exactly two response forms, and only one of them can be read as success. Every
//! failure path here writes `-ERR`, so there is no arrangement of a broken backend that logs a
//! client in or hands it a message. The RFC 2449 extended response code says whether retrying
//! is worth anything: `[SYS/TEMP]` for capacity exhaustion, `[SYS/PERM]` otherwise - the same
//! split HTTP makes between 503 and 500.
//!
//! Both paths used to write nothing at all and close the socket, which for the greeting meant
//! the client blocked on a banner that was never coming.


use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

async fn read_line(reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>) -> E2EResult<String> {
    let mut line = String::new();
    let n = tokio::time::timeout(Duration::from_secs(20), reader.read_line(&mut line))
        .await
        .map_err(|_| {
            "No POP3 response within 20s - the server went silent on LLM failure, which is the \
             exact defect this test exists to catch"
        })??;
    if n == 0 {
        return Err("POP3 connection closed without a response".into());
    }
    Ok(line)
}

/// The greeting fails: `-ERR` rather than a banner that never arrives.
#[tokio::test]
async fn test_pop3_answers_err_when_greeting_llm_fails() -> E2EResult<()> {
    let prompt = "listen on port {AVAILABLE_PORT} via pop3. Serve a mailbox for alice";

    let config = NetGetConfig::new_no_scripts(prompt).with_mock(|mock| {
        mock.on_instruction_containing("via pop3")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "pop3",
                    "instruction": "Serve a mailbox for alice"
                }
            ]))
            .expect_calls(1)
            .and()
        // No rule for `pop3_command`, so even CONNECTION_ESTABLISHED fails.
    });

    let server = start_netget_server(config).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let stream = TcpStream::connect(format!("127.0.0.1:{}", server.port)).await?;
    let (read_half, _write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    let greeting = read_line(&mut reader).await?;
    println!("POP3 greeting: {}", greeting.trim());
    assert!(
        greeting.starts_with("-ERR "),
        "expected -ERR instead of a banner that cannot be honoured, got: {greeting}"
    );
    assert!(
        !greeting.starts_with("+OK"),
        "a backend failure must never open a usable session: {greeting}"
    );
    assert!(
        greeting.contains("[SYS/PERM]") || greeting.contains("[SYS/TEMP]"),
        "the -ERR should carry an RFC 2449 response code: {greeting}"
    );
    assert!(
        greeting.contains("netget"),
        "the text should name the source of the failure: {greeting}"
    );

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

/// USER fails: `-ERR`. An `+OK` here would advance the authorization state machine on the
/// strength of a backend that never answered.
#[tokio::test]
async fn test_pop3_refuses_user_when_llm_fails() -> E2EResult<()> {
    let prompt = "listen on port {AVAILABLE_PORT} via pop3. Greet, then serve alice's mailbox";

    let config = NetGetConfig::new_no_scripts(prompt).with_mock(|mock| {
        mock.on_instruction_containing("via pop3")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "pop3",
                    "instruction": "Greet, then serve alice's mailbox"
                }
            ]))
            .expect_calls(1)
            .and()
            // Only the greeting is answered. USER is not.
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

    let server = start_netget_server(config).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let stream = TcpStream::connect(format!("127.0.0.1:{}", server.port)).await?;
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    let greeting = read_line(&mut reader).await?;
    println!("POP3 greeting: {}", greeting.trim());
    assert!(
        greeting.starts_with("+OK"),
        "expected the mocked greeting, got: {greeting}"
    );

    write_half.write_all(b"USER alice\r\n").await?;
    write_half.flush().await?;

    let reply = read_line(&mut reader).await?;
    println!("POP3 USER reply: {}", reply.trim());
    assert!(
        reply.starts_with("-ERR "),
        "expected -ERR refusing the command, got: {reply}"
    );
    assert!(
        !reply.starts_with("+OK"),
        "an LLM outage must never advance POP3 authorization: {reply}"
    );
    assert!(
        reply.contains("[SYS/PERM]") || reply.contains("[SYS/TEMP]"),
        "the -ERR should carry an RFC 2449 response code: {reply}"
    );

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

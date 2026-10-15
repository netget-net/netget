//! What an SMTP client gets when the LLM backend fails: a 4xx, never silence and never a 2xx.
//!
//! SMTP already has the right vocabulary for "the backend is unavailable, come back later":
//! the 4xx class (RFC 5321 §4.2.1) means a transient failure, and a sending MTA that receives
//! one requeues the message instead of bouncing it. Two places can fail:
//!
//! * the greeting, where the server owes the client a 220 - answered with 421 and a close,
//!   which RFC 5321 §3.1 defines precisely as "I am declining this session";
//! * any command afterwards - answered with 451.
//!
//! Both are refusals. That is deliberate: a failure must never be able to look like acceptance,
//! or an outage would silently report mail as delivered.


use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

async fn read_line(reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>) -> E2EResult<String> {
    let mut line = String::new();
    let n = tokio::time::timeout(Duration::from_secs(20), reader.read_line(&mut line))
        .await
        .map_err(|_| {
            "No SMTP reply within 20s - the server went silent, which is the exact defect these \
             tests exist to catch"
        })??;
    if n == 0 {
        return Err("SMTP connection closed without a reply".into());
    }
    Ok(line)
}

/// The greeting itself fails: the client must get 421 rather than wait for a 220 that never
/// comes.
#[tokio::test]
async fn test_smtp_answers_421_when_greeting_llm_fails() -> E2EResult<()> {
    let prompt = "listen on port {AVAILABLE_PORT} via smtp. Accept mail for example.com";

    let server_config = NetGetConfig::new_no_scripts(prompt).with_mock(|mock| {
        mock.on_instruction_containing("via smtp")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "SMTP",
                    "instruction": "Accept mail for example.com"
                }
            ]))
            .expect_calls(1)
            .and()
        // No rule for `smtp_command`, so even CONNECTION_ESTABLISHED fails.
    });

    let server = start_netget_server(server_config).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let stream = TcpStream::connect(format!("127.0.0.1:{}", server.port)).await?;
    let (read_half, _write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    let greeting = read_line(&mut reader).await?;
    println!("SMTP greeting: {}", greeting.trim());
    assert!(
        greeting.starts_with("421 "),
        "expected 421 (service not available) instead of a 220 that cannot be honoured, got: {greeting}"
    );

    // 421 means the connection closes; the next read must be EOF, not a hang.
    let mut trailing = String::new();
    let n = tokio::time::timeout(Duration::from_secs(10), reader.read_line(&mut trailing))
        .await
        .map_err(|_| "the server did not close the connection after 421")??;
    assert_eq!(n, 0, "expected EOF after 421, got: {trailing}");

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

/// The greeting succeeds and a later command fails: the client must get 451, and the session
/// must stay usable.
#[tokio::test]
async fn test_smtp_answers_451_when_command_llm_fails() -> E2EResult<()> {
    let prompt = "listen on port {AVAILABLE_PORT} via smtp. Greet then accept mail";

    let server_config = NetGetConfig::new_no_scripts(prompt).with_mock(|mock| {
        mock.on_instruction_containing("via smtp")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "SMTP",
                    "instruction": "Greet then accept mail"
                }
            ]))
            .expect_calls(1)
            .and()
            // Only the greeting is answered. Every command after it fails.
            .on_event("smtp_command")
            .and_event_data_contains("command", "CONNECTION_ESTABLISHED")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "send_smtp_greeting",
                    "hostname": "mail.example.com",
                    "message": "ESMTP NetGet"
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let server = start_netget_server(server_config).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let stream = TcpStream::connect(format!("127.0.0.1:{}", server.port)).await?;
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    let greeting = read_line(&mut reader).await?;
    println!("SMTP greeting: {}", greeting.trim());
    assert!(
        greeting.starts_with("220 "),
        "expected the mocked 220 greeting, got: {greeting}"
    );

    // MAIL, not EHLO: NetGet answers EHLO itself, so it never reaches the failing backend.
    write_half
        .write_all(b"MAIL FROM:<sender@client.example.com>\r\n")
        .await?;
    write_half.flush().await?;

    let reply = read_line(&mut reader).await?;
    println!("SMTP MAIL reply: {}", reply.trim());
    assert!(
        reply.starts_with("451 "),
        "expected a 451 transient failure, got: {reply}"
    );
    assert!(
        !reply.starts_with('2'),
        "a backend failure must never be reported as success: {reply}"
    );

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

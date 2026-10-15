//! What an IMAP client gets when the LLM backend fails: a refusal, never silence.
//!
//! Two places can fail and both used to write nothing:
//!
//! * the greeting, where the client is blocked reading a banner before it may send anything at
//!   all. RFC 3501 §7.1.5 lets a server refuse a connection with an untagged `BYE`, so that is
//!   what goes out, followed by a close.
//! * any command afterwards - answered `NO` with the tag echoed, so the client can correlate
//!   it with the command it sent.
//!
//! `NO`, not `BAD`. `BAD` means "I did not understand that command", which invites a client to
//! stop using it permanently; a backend failure is a refusal to run a command that was
//! perfectly well formed. And neither is `OK`: the LOGIN case below is the one that matters,
//! because an `OK` there would authenticate a session during an outage.

use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

async fn read_line(reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>) -> E2EResult<String> {
    let mut line = String::new();
    let n = tokio::time::timeout(Duration::from_secs(20), reader.read_line(&mut line))
        .await
        .map_err(|_| {
            "No IMAP response within 20s - the server went silent on LLM failure, which is the \
             exact defect this test exists to catch"
        })??;
    if n == 0 {
        return Err("IMAP connection closed without a response".into());
    }
    Ok(line)
}

/// The greeting fails: an untagged BYE, then EOF. Not a hang, and not an `* OK`.
#[tokio::test]
async fn test_imap_answers_bye_when_greeting_llm_fails() -> E2EResult<()> {
    let prompt = "listen on port {AVAILABLE_PORT} via imap. Serve INBOX for alice";

    let config = NetGetConfig::new_no_scripts(prompt).with_mock(|mock| {
        mock.on_instruction_containing("via imap")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "imap",
                    "instruction": "Serve INBOX for alice"
                }
            ]))
            .expect_calls(1)
            .and()
        // No rule for `imap_connection`, so producing the banner fails.
    });

    let server = start_netget_server(config).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let stream = TcpStream::connect(format!("127.0.0.1:{}", server.port)).await?;
    let (read_half, _write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    let greeting = read_line(&mut reader).await?;
    println!("IMAP greeting: {}", greeting.trim());
    assert!(
        greeting.starts_with("* BYE "),
        "expected an untagged BYE refusing the connection, got: {greeting}"
    );
    assert!(
        !greeting.starts_with("* OK"),
        "a backend failure must never open a usable session: {greeting}"
    );
    assert!(
        greeting.contains("[SERVERBUG]") || greeting.contains("[UNAVAILABLE]"),
        "the BYE should carry an RFC 5530 response code so the client can classify it: {greeting}"
    );
    assert!(
        greeting.contains("netget"),
        "the text should name the source of the failure: {greeting}"
    );

    let mut trailing = String::new();
    let n = tokio::time::timeout(Duration::from_secs(10), reader.read_line(&mut trailing))
        .await
        .map_err(|_| "the server did not close the connection after BYE")??;
    assert_eq!(n, 0, "expected EOF after BYE, got: {trailing}");

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

/// LOGIN fails: a tagged NO. This is the fail-closed case - an `OK` here would log the client
/// in on the strength of a backend that never answered.
#[tokio::test]
async fn test_imap_refuses_login_when_llm_fails() -> E2EResult<()> {
    let prompt = "listen on port {AVAILABLE_PORT} via imap. Greet, then serve INBOX";

    let config = NetGetConfig::new_no_scripts(prompt).with_mock(|mock| {
        mock.on_instruction_containing("via imap")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "imap",
                    "instruction": "Greet, then serve INBOX"
                }
            ]))
            .expect_calls(1)
            .and()
            // Only the greeting is answered. LOGIN is not.
            .on_event("imap_connection")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "send_imap_response",
                    "response": "* OK IMAP4rev1 NetGet ready"
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
    println!("IMAP greeting: {}", greeting.trim());
    assert!(
        greeting.starts_with("* OK"),
        "expected the mocked greeting, got: {greeting}"
    );

    write_half.write_all(b"A001 LOGIN alice secret\r\n").await?;
    write_half.flush().await?;

    let reply = read_line(&mut reader).await?;
    println!("IMAP LOGIN reply: {}", reply.trim());
    assert!(
        reply.starts_with("A001 NO "),
        "expected a tagged NO refusing the login, got: {reply}"
    );
    assert!(
        !reply.contains("A001 OK"),
        "an LLM outage must never authenticate a session: {reply}"
    );
    assert!(
        reply.contains("[SERVERBUG]") || reply.contains("[UNAVAILABLE]"),
        "the NO should carry an RFC 5530 response code: {reply}"
    );

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

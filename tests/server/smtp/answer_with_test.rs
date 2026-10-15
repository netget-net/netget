//! Each SMTP command is told which answer it takes, and gets exactly one.
//!
//! The real-model eval (`./run-eval.sh smtp`) found llama3.1:8b answering EHLO and MAIL with
//! the 220 greeting action, answering one greeting with five greetings, and accepting a
//! recipient the instruction said to refuse. Three changes answer that, and this file pins each
//! from the wire:
//!
//! * the event carries `answer_with` (and, for MAIL/RCPT, the `address` and its `domain`) -
//!   every rule below matches only on those fields, so a missing hint is an unmatched event;
//! * a second reply to one command is dropped and logged `decision=duplicate_response_dropped`,
//!   because SMTP reads it as the answer to the *next* command;
//! * between a 354 and the terminating `.`, a line is message text - `EHLO` in a body is not
//!   answered by NetGet and reaches the model as a body line.

use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

async fn read_line(reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>) -> E2EResult<String> {
    let mut line = String::new();
    let n = tokio::time::timeout(Duration::from_secs(20), reader.read_line(&mut line))
        .await
        .map_err(|_| "no SMTP reply within 20s")??;
    if n == 0 {
        return Err("SMTP connection closed without a reply".into());
    }
    Ok(line)
}

#[tokio::test]
async fn each_command_is_told_its_answer_and_gets_exactly_one() -> E2EResult<()> {
    let prompt = "listen on port {AVAILABLE_PORT} via smtp. Accept mail for example.com only";

    let server_config = NetGetConfig::new_no_scripts(prompt).with_mock(|mock| {
        mock.on_instruction_containing("via smtp")
            .respond_with_actions(serde_json::json!([{
                "type": "open_server",
                "port": 0,
                "base_stack": "SMTP",
                "instruction": "Accept mail for example.com only"
            }]))
            .expect_calls(1)
            .and()
            // A stray 250 and two banners for one connection: only the first banner may
            // reach the wire - the action answer_with names wins over one listed before it.
            .on_event("smtp_command")
            .and_event_data_contains("answer_with", "send_smtp_greeting")
            .respond_with_actions(serde_json::json!([
                {"type": "send_smtp_ok", "message": "stray acknowledgement"},
                {"type": "send_smtp_greeting", "hostname": "mail.test", "message": "first"},
                {"type": "send_smtp_greeting", "hostname": "mail.test", "message": "second"}
            ]))
            .expect_calls(1)
            .and()
            // A body line: told it takes no reply.
            .on_event("smtp_command")
            .and_event_data_contains("answer_with", "wait_for_more")
            .respond_with_actions(serde_json::json!([{"type": "wait_for_more"}]))
            .expect_calls(1)
            .and()
            .on_event("smtp_command")
            .and_event_data_contains("answer_with", "accept the message")
            .respond_with_actions(serde_json::json!([
                {"type": "send_smtp_ok", "message": "queued"}
            ]))
            .expect_calls(1)
            .and()
            // Two replies to MAIL: the second would be read as RCPT's answer.
            .on_event("smtp_command")
            .and_event_data_contains("answer_with", "accept this sender")
            .and_event_data_contains("domain", "example.com")
            .respond_with_actions(serde_json::json!([
                {"type": "send_smtp_ok", "message": "sender ok"},
                {"type": "send_smtp_ok", "message": "stale second reply"}
            ]))
            .expect_calls(1)
            .and()
            .on_event("smtp_command")
            .and_event_data_contains("address", "bob@elsewhere.test")
            .and_event_data_contains("domain", "elsewhere.test")
            .respond_with_actions(serde_json::json!([
                {"type": "send_smtp_error", "code": 550, "message": "no such domain here"}
            ]))
            .expect_calls(1)
            .and()
            .on_event("smtp_command")
            .and_event_data_contains("address", "alice@example.com")
            .respond_with_actions(serde_json::json!([
                {"type": "send_smtp_ok", "message": "recipient ok"}
            ]))
            .expect_calls(1)
            .and()
            .on_event("smtp_command")
            .and_event_data_contains("answer_with", "send_smtp_start_data")
            .respond_with_actions(serde_json::json!([{"type": "send_smtp_start_data"}]))
            .expect_calls(1)
            .and()
    });

    let server = start_netget_server(server_config).await?;
    let stream = TcpStream::connect(format!("127.0.0.1:{}", server.port)).await?;
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    assert_eq!(read_line(&mut reader).await?, "220 mail.test first\r\n");

    write_half.write_all(b"EHLO client.test\r\n").await?;
    assert_eq!(
        read_line(&mut reader).await?,
        "250-mail.test greets client.test\r\n",
        "EHLO must be answered by its own reply, not by the dropped second banner"
    );
    assert_eq!(read_line(&mut reader).await?, "250 8BITMIME\r\n");

    write_half
        .write_all(b"MAIL FROM:<postmaster@example.com>\r\n")
        .await?;
    assert_eq!(read_line(&mut reader).await?, "250 sender ok\r\n");

    write_half
        .write_all(b"RCPT TO:<bob@elsewhere.test>\r\n")
        .await?;
    let refused = read_line(&mut reader).await?;
    assert_eq!(
        refused, "550 no such domain here\r\n",
        "RCPT got a stale reply: the second MAIL answer reached the wire"
    );

    write_half
        .write_all(b"RCPT TO:<alice@example.com>\r\n")
        .await?;
    assert_eq!(read_line(&mut reader).await?, "250 recipient ok\r\n");

    write_half.write_all(b"DATA\r\n").await?;
    assert!(read_line(&mut reader).await?.starts_with("354 "));

    // Message text that looks like a command. NetGet must not answer it, and the model is
    // told it takes no reply; the next line the client reads is the answer to ".".
    write_half
        .write_all(b"EHLO this is a line of the body\r\n.\r\n")
        .await?;
    assert_eq!(read_line(&mut reader).await?, "250 queued\r\n");

    server
        .wait_for_any(&["decision=duplicate_response_dropped"], 15)
        .await;
    server
        .wait_for_log("decision=duplicate_response_dropped", 30)
        .await?;

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

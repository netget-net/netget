//! Each POP3 command is told which answer it takes, gets exactly one, and RETR's message is
//! written by NetGet from structured fields.
//!
//! The real-model eval (`./run-eval.sh pop3`, `pop3/message-subject` 0/5) found llama3.1:8b
//! answering the greeting with a greeting *and* a `+OK`, so every later reply arrived one
//! command late, and answering `RETR` with a bare `send_pop3_ok` - one `+OK` line, after which
//! poplib waited for the body and its terminating `.` until its timeout. This file pins the
//! fixes from the wire:
//!
//! * the event carries `answer_with` and `message_number` - the rules below match only on them;
//! * a second reply to one command is dropped, logged `decision=duplicate_response_dropped`;
//! * `send_pop3_retr` takes `from`/`subject`/`body` and NetGet writes the headers, the octet
//!   count and the terminating `.`;
//! * `CAPA` is answered by NetGet without a model call;
//! * a `RETR` answered as a `+OK` and the message as raw `send_pop3_message` text is framed by
//!   NetGet (status line, CRLF, terminating `.`), logged `decision=multiline_assembled`.

use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

async fn read_line(reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>) -> E2EResult<String> {
    let mut line = String::new();
    let n = tokio::time::timeout(Duration::from_secs(20), reader.read_line(&mut line))
        .await
        .map_err(|_| "no POP3 reply within 20s")??;
    if n == 0 {
        return Err("POP3 connection closed without a reply".into());
    }
    Ok(line)
}

#[tokio::test]
async fn each_command_is_told_its_answer_and_retr_is_rendered_from_fields() -> E2EResult<()> {
    let prompt = "listen on port {AVAILABLE_PORT} via pop3. One message from alice.";

    let server_config = NetGetConfig::new_no_scripts(prompt).with_mock(|mock| {
        mock.on_instruction_containing("via pop3")
            .respond_with_actions(serde_json::json!([{
                "type": "open_server",
                "port": 0,
                "base_stack": "POP3",
                "instruction": "One message from alice."
            }]))
            .expect_calls(1)
            .and()
            // A greeting and a stray +OK: the +OK must not become USER's reply.
            .on_event("pop3_command")
            .and_event_data_contains("answer_with", "send_pop3_greeting")
            .respond_with_actions(serde_json::json!([
                {"type": "send_pop3_greeting", "message": "eval ready"},
                {"type": "send_pop3_ok", "message": "stale second reply"}
            ]))
            .expect_calls(1)
            .and()
            .on_event("pop3_command")
            .and_event_data_contains("answer_with", "accept the user name")
            .respond_with_actions(serde_json::json!([
                {"type": "send_pop3_ok", "message": "user accepted"}
            ]))
            .expect_calls(1)
            .and()
            // The eval's shape: a bare +OK and *then* the STAT line. The STAT line is the answer.
            .on_event("pop3_command")
            .and_event_data_contains("answer_with", "send_pop3_stat")
            .respond_with_actions(serde_json::json!([
                {"type": "send_pop3_ok"},
                {"type": "send_pop3_stat", "message_count": 7, "total_size": 7000}
            ]))
            .expect_calls(1)
            .and()
            .on_event("pop3_command")
            .and_event_data_contains("answer_with", "send_pop3_retr")
            .and_event_data_contains("message_number", "1")
            .respond_with_actions(serde_json::json!([{
                "type": "send_pop3_retr",
                "from": "alice@example.com",
                "subject": "Quarterly figures are in",
                "body": "See attached.\n.hidden line"
            }]))
            .expect_calls(1)
            .and()
            // The eval's other shape: a bare +OK, then the message as raw text with no
            // terminator. NetGet frames it.
            .on_event("pop3_command")
            .and_event_data_contains("answer_with", "send_pop3_retr")
            .and_event_data_contains("message_number", "2")
            .respond_with_actions(serde_json::json!([
                {"type": "send_pop3_ok", "message": "message follows"},
                {"type": "send_pop3_message",
                 "message": "From: bob@example.com\nSubject: Second\n\nHello."}
            ]))
            .expect_calls(1)
            .and()
    });

    let server = start_netget_server(server_config).await?;
    let stream = TcpStream::connect(format!("127.0.0.1:{}", server.port)).await?;
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    assert_eq!(read_line(&mut reader).await?, "+OK eval ready\r\n");

    // CAPA never reaches the model: there is no rule for it, so an event would fail.
    write_half.write_all(b"CAPA\r\n").await?;
    let mut capa = Vec::new();
    loop {
        let line = read_line(&mut reader).await?;
        let done = line == ".\r\n";
        capa.push(line);
        if done {
            break;
        }
    }
    assert_eq!(
        capa.concat(),
        "+OK Capability list follows\r\nUSER\r\nTOP\r\nUIDL\r\nRESP-CODES\r\n.\r\n"
    );

    write_half.write_all(b"USER eval\r\n").await?;
    assert_eq!(
        read_line(&mut reader).await?,
        "+OK user accepted\r\n",
        "USER got a stale reply: the greeting's second answer reached the wire"
    );

    write_half.write_all(b"STAT\r\n").await?;
    assert_eq!(
        read_line(&mut reader).await?,
        "+OK 7 7000\r\n",
        "STAT got the stray +OK instead of the STAT line"
    );

    write_half.write_all(b"RETR 1\r\n").await?;
    let status = read_line(&mut reader).await?;
    assert!(status.starts_with("+OK "), "RETR status: {status}");
    let mut body = Vec::new();
    loop {
        let line = read_line(&mut reader).await?;
        if line == ".\r\n" {
            break;
        }
        body.push(line);
    }
    assert_eq!(
        body.concat(),
        "From: alice@example.com\r\nSubject: Quarterly figures are in\r\n\r\nSee attached.\r\n..hidden line\r\n",
        "headers written from the fields, body byte-stuffed"
    );
    // The advertised octet count is what was actually sent before the terminator.
    let octets: usize = status
        .split_whitespace()
        .nth(1)
        .and_then(|n| n.parse().ok())
        .expect("RETR status carries an octet count");
    assert_eq!(octets, body.concat().len());

    write_half.write_all(b"RETR 2\r\n").await?;
    assert!(read_line(&mut reader).await?.starts_with("+OK "));
    let mut second = String::new();
    loop {
        let line = read_line(&mut reader).await?;
        if line == ".\r\n" {
            break;
        }
        second.push_str(&line);
    }
    assert_eq!(
        second, "From: bob@example.com\r\nSubject: Second\r\n\r\nHello.\r\n",
        "a +OK and the message as raw text are framed into one RETR answer"
    );
    server
        .wait_for_log("decision=multiline_assembled", 30)
        .await?;

    server
        .wait_for_log("decision=duplicate_response_dropped", 30)
        .await?;
    server.wait_for_log("decision=netget_answer", 30).await?;

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

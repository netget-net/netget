//! Where a message ends, and how large one may be, decided from the wire.
//!
//! * **Only `<CRLF>.<CRLF>` ends a message** (RFC 5321 §4.1.1.4). A `.` line ended by a bare LF,
//!   or after a line that was, is message text. Treating `<LF>.<LF>` as the end is the
//!   disagreement SMTP smuggling exploits: the rest of the "message" — here a `MAIL FROM` — is
//!   then read as a command. Verified by making `ends_message` accept a trimmed `.`: the model is
//!   then handed a message without the smuggled line, and the line is answered as a command.
//! * **A message over `SIZE` is refused by NetGet** with `552 5.3.4`, read to its end so the
//!   session stays in step, and never reaches the model (the message rule expects one call, for
//!   the first message only). Verified by removing the `TooBig` arm's early `continue`.

use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

async fn read_line(reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>) -> E2EResult<String> {
    let mut line = String::new();
    let n = tokio::time::timeout(Duration::from_secs(60), reader.read_line(&mut line))
        .await
        .map_err(|_| "no SMTP reply within 60s")??;
    if n == 0 {
        return Err("SMTP connection closed without a reply".into());
    }
    Ok(line)
}

#[tokio::test]
async fn only_crlf_dot_crlf_ends_a_message_and_size_is_enforced() -> E2EResult<()> {
    let config = NetGetConfig::new_no_scripts("listen on port {AVAILABLE_PORT} via smtp")
        .with_mock(|mock| {
            mock.on_instruction_containing("via smtp")
                .respond_with_actions(serde_json::json!([{
                    "type": "open_server", "port": 0, "base_stack": "SMTP",
                    "instruction": "accept everything"
                }]))
                .expect_calls(1)
                .and()
                .on_event("smtp_command")
                .and_event_data_contains("command", "CONNECTION_ESTABLISHED")
                .respond_with_actions(serde_json::json!([
                    {"type": "send_smtp_greeting", "hostname": "mx.test", "message": "ESMTP"}
                ]))
                .expect_calls(1)
                .and()
                // The smuggled MAIL FROM must be inside the one message the model is handed.
                .on_event("smtp_command")
                .and_event_data_contains("answer_with", "accept the message")
                .and_event_data_contains("body", "MAIL FROM:<smuggled@evil.test>")
                .respond_with_actions(serde_json::json!([
                    {"type": "send_smtp_ok", "message": "2.0.0 one message"}
                ]))
                .expect_calls(1)
                .and()
                .on_event("smtp_command")
                .and_event_data_contains("address", "sender@example.com")
                .respond_with_actions(serde_json::json!([{"type": "send_smtp_ok"}]))
                .expect_calls(2)
                .and()
                .on_event("smtp_command")
                .and_event_data_contains("answer_with", "accept mail for this recipient")
                .respond_with_actions(serde_json::json!([{"type": "send_smtp_ok"}]))
                .expect_calls(2)
                .and()
                .on_event("smtp_command")
                .and_event_data_contains("answer_with", "send_smtp_start_data")
                .respond_with_actions(serde_json::json!([{"type": "send_smtp_start_data"}]))
                .expect_calls(2)
                .and()
                .on_event("smtp_command")
                .and_event_data_contains("answer_with", "send_smtp_quit")
                .respond_with_actions(serde_json::json!([
                    {"type": "send_smtp_quit"}, {"type": "close_connection"}
                ]))
                .expect_calls(1)
                .and()
        });

    let server = start_netget_server(config).await?;
    let stream = TcpStream::connect(format!("127.0.0.1:{}", server.port)).await?;
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    assert!(read_line(&mut reader).await?.starts_with("220 "));

    let transaction = b"MAIL FROM:<sender@example.com>\r\n";
    for (command, code) in [
        (&transaction[..], "250"),
        (b"RCPT TO:<rcpt@example.com>\r\n", "250"),
        (b"DATA\r\n", "354"),
    ] {
        write_half.write_all(command).await?;
        let reply = read_line(&mut reader).await?;
        assert!(reply.starts_with(code), "{command:?} -> {reply:?}");
    }

    // `<LF>.<LF>` and `<LF>.<CRLF>` are text; only the final `<CRLF>.<CRLF>` ends it.
    write_half
        .write_all(
            b"Subject: smuggle\r\n\r\nfirst\r\n\n.\nMAIL FROM:<smuggled@evil.test>\r\n\n.\r\nlast\r\n.\r\n",
        )
        .await?;
    assert_eq!(
        read_line(&mut reader).await?,
        "250 2.0.0 one message\r\n",
        "the first reply after the message must be the answer to the whole message"
    );

    // A second message, one byte over SIZE: refused by NetGet, after the whole of it.
    for (command, code) in [
        (&transaction[..], "250"),
        (b"RCPT TO:<rcpt@example.com>\r\n", "250"),
        (b"DATA\r\n", "354"),
    ] {
        write_half.write_all(command).await?;
        let reply = read_line(&mut reader).await?;
        assert!(reply.starts_with(code), "{command:?} -> {reply:?}");
    }
    let line = [b'x'; 1022];
    let mut chunk = Vec::with_capacity(1024 * 1024);
    for _ in 0..1024 {
        chunk.extend_from_slice(&line);
        chunk.extend_from_slice(b"\r\n");
    }
    // 10 chunks of exactly 1 MiB is MAX_MESSAGE_BYTES itself; one more line passes it.
    assert_eq!(
        chunk.len() * 10,
        netget::server::smtp::MAX_MESSAGE_BYTES,
        "the probe must sit exactly at the limit"
    );
    for _ in 0..10 {
        write_half.write_all(&chunk).await?;
    }
    write_half.write_all(b"x\r\n.\r\n").await?;
    assert_eq!(
        read_line(&mut reader).await?,
        "552 5.3.4 Message size exceeds fixed maximum message size\r\n"
    );

    write_half.write_all(b"QUIT\r\n").await?;
    assert!(read_line(&mut reader).await?.starts_with("221"));

    server
        .wait_for_log("decision=refused_message_too_big", 30)
        .await?;
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

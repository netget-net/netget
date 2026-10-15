//! One command, one completion reply.
//!
//! The real-model eval saw llama3.1:8b answer a new connection with five `220`s. The client
//! read the first as the greeting and each of the rest as the answer to the next command it
//! sent, so `USER anonymous` read `220 FTP Server Ready` and no login ever happened
//! (`ftp/anonymous-login` 0/5). RFC 959 gives each command exactly one completion reply,
//! optionally after preliminary 1xx replies; the server now sends up to the first completion
//! reply and drops the rest with `decision=duplicate_response_dropped`.
//!
//! See `src/server/ftp/CLAUDE.md`.

use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

async fn read_reply(
    reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>,
    what: &str,
) -> E2EResult<String> {
    let mut line = String::new();
    let n = tokio::time::timeout(Duration::from_secs(30), reader.read_line(&mut line))
        .await
        .map_err(|_| format!("no FTP reply to {what} within 30s"))??;
    assert!(n > 0, "FTP closed the control connection instead of {what}");
    Ok(line)
}

#[tokio::test]
async fn replies_after_the_completion_reply_are_dropped_not_sent() -> E2EResult<()> {
    let prompt = "listen on port {AVAILABLE_PORT} via ftp. Let anyone log in anonymously";

    let config = NetGetConfig::new_no_scripts(prompt).with_mock(|mock| {
        mock.on_instruction_containing("via ftp")
            .respond_with_actions(serde_json::json!([{
                "type": "open_server",
                "port": 0,
                "base_stack": "FTP",
                "instruction": "Let anyone log in anonymously"
            }]))
            .expect_calls(1)
            .and()
            // The greeting, three times over - the shape the model produced.
            .on_event("ftp_command")
            .and_event_data_contains("command", "CONNECTION_ESTABLISHED")
            .respond_with_actions(serde_json::json!([
                {"type": "send_ftp_response", "code": 220, "message": "first greeting"},
                {"type": "send_ftp_response", "code": 220, "message": "second greeting"},
                {"type": "send_ftp_response", "code": 220, "message": "third greeting"}
            ]))
            .expect_calls(1)
            .and()
            .on_event("ftp_command")
            .and_event_data_contains("command", "USER")
            // The server names the reply USER expects; the rule matches only if it did.
            .and_event_data_contains("answer_with", "331")
            .respond_with_actions(serde_json::json!([
                {"type": "send_ftp_response", "code": 331, "message": "Send your e-mail as password"}
            ]))
            .expect_calls(1)
            .and()
    });

    let server = start_netget_server(config).await?;
    let stream = TcpStream::connect(format!("127.0.0.1:{}", server.port)).await?;
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    let greeting = read_reply(&mut reader, "the greeting").await?;
    assert_eq!(greeting, "220 first greeting\r\n");

    write_half.write_all(b"USER anonymous\r\n").await?;
    write_half.flush().await?;
    let reply = read_reply(&mut reader, "USER").await?;
    assert!(
        reply.starts_with("331 "),
        "USER must be answered by its own reply, not by a greeting the server sent twice: \
         {reply:?}"
    );

    server
        .wait_for_any(&["decision=duplicate_response_dropped"], 15)
        .await;
    assert!(
        server
            .output_contains("decision=duplicate_response_dropped")
            .await,
        "the two dropped greetings must be logged"
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

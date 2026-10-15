//! CAPABILITIES and MODE READER are NetGet's, every other command is told its answer, and a
//! command gets exactly one reply.
//!
//! The real-model eval (`./run-eval.sh nntp`) scored all three NNTP cases 0/5. llama3.1:8b
//! answered CAPABILITIES - which nntplib sends from its constructor - with the 200 greeting, so
//! nntplib raised before the command under test was sent; answered one greeting with two; and
//! answered an unknown group with `501` where RFC 3977 says `411`. This file pins each fix from
//! the wire:
//!
//! * CAPABILITIES and MODE READER are answered by NetGet with no model call (there is no rule
//!   for them below), MODE READER repeating the greeting's own 200/201;
//! * GROUP carries `group` and an `answer_with` naming 411 for a missing group - the rules match
//!   only on those fields;
//! * a second reply to one command is dropped, logged `decision=duplicate_response_dropped`.

use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

async fn read_line(reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>) -> E2EResult<String> {
    let mut line = String::new();
    let n = tokio::time::timeout(Duration::from_secs(20), reader.read_line(&mut line))
        .await
        .map_err(|_| "no NNTP reply within 20s")??;
    if n == 0 {
        return Err("NNTP connection closed without a reply".into());
    }
    Ok(line)
}

#[tokio::test]
async fn mechanics_are_netgets_and_each_command_gets_one_answer() -> E2EResult<()> {
    let prompt = "listen on port {AVAILABLE_PORT} via nntp. Carry only comp.lang.eval.";

    let server_config = NetGetConfig::new_no_scripts(prompt).with_mock(|mock| {
        mock.on_instruction_containing("via nntp")
            .respond_with_actions(serde_json::json!([{
                "type": "open_server",
                "port": 0,
                "base_stack": "NNTP",
                "instruction": "Carry only comp.lang.eval."
            }]))
            .expect_calls(1)
            .and()
            .on_event("nntp_command_received")
            .and_event_data_contains("answer_with", "code 200 (posting allowed) or 201")
            .respond_with_actions(serde_json::json!([
                {"type": "send_nntp_response", "code": 201, "text": "eval news"},
                {"type": "send_nntp_response", "code": 201, "text": "stale second greeting"}
            ]))
            .expect_calls(1)
            .and()
            .on_event("nntp_command_received")
            .and_event_data_contains("group", "alt.nothing.here")
            .and_event_data_contains("answer_with", "code 411")
            .respond_with_actions(serde_json::json!([
                {"type": "send_nntp_response", "code": 411, "text": "No such newsgroup"},
                {"type": "send_nntp_response", "code": 411, "text": "stale second reply"}
            ]))
            .expect_calls(1)
            .and()
            .on_event("nntp_command_received")
            .and_event_data_contains("group", "comp.lang.eval")
            // A stray status line first: the group line answer_with names is the reply.
            .respond_with_actions(serde_json::json!([
                {"type": "send_nntp_response", "code": 200, "text": "stray status"},
                {"type": "send_nntp_group", "name": "comp.lang.eval",
                 "count": 42, "low": 1, "high": 42}
            ]))
            .expect_calls(1)
            .and()
    });

    let server = start_netget_server(server_config).await?;
    let stream = TcpStream::connect(format!("127.0.0.1:{}", server.port)).await?;
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    assert_eq!(read_line(&mut reader).await?, "201 eval news\r\n");

    write_half.write_all(b"CAPABILITIES\r\n").await?;
    let mut capabilities = String::new();
    loop {
        let line = read_line(&mut reader).await?;
        let done = line == ".\r\n";
        capabilities.push_str(&line);
        if done {
            break;
        }
    }
    assert_eq!(
        capabilities, "101 Capability list:\r\nVERSION 2\r\nREADER\r\nLIST ACTIVE\r\nOVER\r\nIHAVE\r\nSTREAMING\r\n.\r\n",
        "CAPABILITIES got a stale reply or the model's: the second greeting reached the wire"
    );

    write_half.write_all(b"MODE READER\r\n").await?;
    assert_eq!(
        read_line(&mut reader).await?,
        "201 Reader mode, posting prohibited\r\n",
        "MODE READER repeats the greeting's 201"
    );

    write_half.write_all(b"GROUP alt.nothing.here\r\n").await?;
    assert_eq!(read_line(&mut reader).await?, "411 No such newsgroup\r\n");

    write_half.write_all(b"GROUP comp.lang.eval\r\n").await?;
    assert_eq!(
        read_line(&mut reader).await?,
        "211 42 1 42 comp.lang.eval\r\n",
        "GROUP got a stale reply: the unknown group's second answer reached the wire"
    );

    server
        .wait_for_log("decision=duplicate_response_dropped", 30)
        .await?;
    server.wait_for_log("decision=netget_answer", 30).await?;

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

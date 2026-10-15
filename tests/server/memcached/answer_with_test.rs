//! Each memcached command is told its answer, a get never returns a key it was not asked for,
//! and a command gets exactly one reply.
//!
//! The real-model eval (`./run-eval.sh memcached`) found llama3.1:8b answering
//! `get nothing-here` with the value of `motd` - the one key the instruction gave - which
//! pymemcache rejects with `KeyError`, and answering `stats` with the action's example verbatim
//! and no `version`. This file pins the fixes from the wire:
//!
//! * the get and stats events carry `answer_with` - the rules below match only on it;
//! * a `VALUE` block for a key the client did not request is dropped, logged
//!   `decision=unrequested_key_dropped`, so the reply is the miss the instruction meant;
//! * a second reply to one command is dropped, logged `decision=duplicate_response_dropped`.


use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

async fn read_line(reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>) -> E2EResult<String> {
    let mut line = String::new();
    let n = tokio::time::timeout(Duration::from_secs(20), reader.read_line(&mut line))
        .await
        .map_err(|_| "no memcached reply within 20s")??;
    if n == 0 {
        return Err("memcached closed the connection without a reply".into());
    }
    Ok(line)
}

async fn read_until_end(
    reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>,
) -> E2EResult<String> {
    let mut reply = String::new();
    loop {
        let line = read_line(reader).await?;
        let done = line == "END\r\n";
        reply.push_str(&line);
        if done {
            return Ok(reply);
        }
    }
}

#[tokio::test]
async fn gets_answer_only_requested_keys_and_each_command_gets_one_reply() -> E2EResult<()> {
    let prompt = "listen on port {AVAILABLE_PORT} via memcached. Only motd is held.";

    let config = NetGetConfig::new_no_scripts(prompt).with_mock(|mock| {
        mock.on_instruction_containing("via memcached")
            .respond_with_actions(serde_json::json!([{
                "type": "open_server",
                "port": 0,
                "base_stack": "memcached",
                "instruction": "Only motd is held."
            }]))
            .expect_calls(1)
            .and()
            // The eval's wrong answer: the held key's value for a key that was not asked for.
            .on_event("memcached_get")
            .and_event_data_contains("answer_with", "nothing-here")
            .respond_with_actions(serde_json::json!([{
                "type": "send_memcached_values",
                "values": [{"key": "motd", "value": "hello"}]
            }]))
            .expect_calls(1)
            .and()
            // Two replies to one get: the second must not answer stats.
            .on_event("memcached_get")
            .and_event_data_contains("answer_with", "motd")
            .respond_with_actions(serde_json::json!([
                {"type": "send_memcached_values", "values": [{"key": "motd", "value": "hello"}]},
                {"type": "send_memcached_values", "values": [{"key": "motd", "value": "stale"}]}
            ]))
            .expect_calls(1)
            .and()
            .on_event("memcached_stats")
            .and_event_data_contains("answer_with", "goes in version")
            // A stray ERROR line first: the stats block answer_with names is the reply.
            .respond_with_actions(serde_json::json!([
                {"type": "send_memcached_error", "kind": "ERROR"},
                {"type": "send_memcached_stats",
                 "stats": {"version": "1.6.21", "curr_items": "12"}}
            ]))
            .expect_calls(1)
            .and()
    });

    let server = start_netget_server(config).await?;
    let stream = TcpStream::connect(format!("127.0.0.1:{}", server.port)).await?;
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    write_half.write_all(b"get nothing-here\r\n").await?;
    assert_eq!(
        read_until_end(&mut reader).await?,
        "END\r\n",
        "a VALUE for a key the client did not request reached the wire"
    );

    write_half.write_all(b"get motd\r\n").await?;
    assert_eq!(
        read_until_end(&mut reader).await?,
        "VALUE motd 0 5\r\nhello\r\nEND\r\n"
    );

    write_half.write_all(b"stats\r\n").await?;
    assert_eq!(
        read_until_end(&mut reader).await?,
        "STAT version 1.6.21\r\nSTAT curr_items 12\r\nEND\r\n",
        "stats got a stale reply: the get's second answer reached the wire"
    );

    server
        .wait_for_log("decision=unrequested_key_dropped", 30)
        .await?;
    server
        .wait_for_log("decision=duplicate_response_dropped", 30)
        .await?;

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

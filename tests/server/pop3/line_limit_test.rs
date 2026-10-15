//! An oversized command line is refused before it is buffered, and before a model call.
//!
//! `AsyncBufReadExt::read_line` grows its `String` until it finds a `\n` and bounds nothing, so
//! a peer that connects to POP3 and streams bytes without ever sending a newline made the
//! server allocate without limit. One connection, no authentication, no model call — the line
//! never completes, so `process_command` is never reached and nothing downstream can refuse it.
//! `line.clear()` bounded accumulation *across* commands and did nothing within one.
//!
//! The load-bearing assertion is **zero** `pop3_command` calls for the oversized line, not
//! merely that the reply is `-ERR`. A cap that refused after building the event would still
//! have put the peer's bytes in a prompt, which is the thing the bound exists to prevent.
//!
//! The second test is what stops the first from passing vacuously: a normal command on a
//! server with the same cap must still be answered. A guard that refused everything would
//! satisfy the first assertion perfectly.

use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

/// Larger than `MAX_COMMAND_BYTES` (1 KiB) in `src/server/pop3/mod.rs`.
const OVERSIZED: usize = 4096;

async fn read_line(reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>) -> E2EResult<String> {
    let mut line = String::new();
    let n = tokio::time::timeout(Duration::from_secs(20), reader.read_line(&mut line))
        .await
        .map_err(|_| "No POP3 response within 20s")??;
    if n == 0 {
        return Err("POP3 connection closed without a response".into());
    }
    Ok(line)
}

fn open_pop3_server() -> serde_json::Value {
    serde_json::json!([{
        "type": "open_server",
        "port": 0,
        "base_stack": "pop3",
        "instruction": "Greet, then serve alice's mailbox"
    }])
}

fn greeting_action() -> serde_json::Value {
    serde_json::json!([{ "type": "send_pop3_greeting", "message": "POP3 server ready" }])
}

#[tokio::test]
async fn an_oversized_command_line_is_refused_without_reaching_the_model() -> E2EResult<()> {
    let prompt = "listen on port {AVAILABLE_PORT} via pop3. Greet, then serve alice's mailbox";

    let config = NetGetConfig::new_no_scripts(prompt).with_mock(|mock| {
        mock.on_instruction_containing("via pop3")
            .respond_with_actions(open_pop3_server())
            .expect_calls(1)
            .and()
            .on_event("pop3_command")
            .and_event_data_contains("command", "CONNECTION_ESTABLISHED")
            .respond_with_actions(greeting_action())
            .expect_calls(1)
            .and()
            // The load-bearing expectation. If the cap ever stops firing, the oversized line
            // completes, an event is built from it and this count goes to 1.
            .on_event("pop3_command")
            .respond_with_actions(serde_json::json!([{
                "type": "send_pop3_ok", "message": "should never be reached"
            }]))
            .expect_calls(0)
            .and()
    });

    let server = start_netget_server(config).await?;
    // Condition, not a fixed sleep: a write that races the bind is refused at connect and
    // reads exactly like a broken limit.
    server.wait_for_any(&["listening on"], 30).await;

    let stream = TcpStream::connect(format!("127.0.0.1:{}", server.port)).await?;
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    let greeting = read_line(&mut reader).await?;
    assert!(
        greeting.starts_with("+OK"),
        "expected the mocked banner, got: {greeting}"
    );

    // A valid verb, then bulk, and deliberately **no newline** — the whole point is that the
    // line never terminates, so nothing downstream ever sees a command to refuse.
    let mut oversized = b"USER ".to_vec();
    oversized.resize(OVERSIZED, b'a');
    write_half.write_all(&oversized).await?;
    write_half.flush().await?;

    let reply = read_line(&mut reader).await?;
    println!("POP3 oversized-line reply: {}", reply.trim());

    assert!(
        reply.starts_with("-ERR"),
        "an oversized line must be refused in POP3's own vocabulary, got: {reply}"
    );
    assert!(
        !reply.starts_with("+OK"),
        "a `+OK` here would admit a peer whose command was never parsed: {reply}"
    );

    // The refusal closes: there is no resynchronisation point mid-line.
    let mut rest = Vec::new();
    let closed = tokio::time::timeout(Duration::from_secs(20), reader.read_to_end(&mut rest)).await;
    assert!(
        closed.is_ok(),
        "the server must close after refusing an oversized line, not leave the peer connected"
    );

    server
        .wait_for_any(&["decision=fail_closed_oversized_command"], 30)
        .await;
    assert!(
        server
            .output_contains("decision=fail_closed_oversized_command")
            .await,
        "the refusal must be greppable: no decision=fail_closed_oversized_command in the log"
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    Ok(())
}

/// A command under the cap is still answered, so the bound is not a refusal of everything.
#[tokio::test]
async fn a_command_under_the_cap_is_still_answered() -> E2EResult<()> {
    let prompt = "listen on port {AVAILABLE_PORT} via pop3. Greet, then serve alice's mailbox";

    let config = NetGetConfig::new_no_scripts(prompt).with_mock(|mock| {
        mock.on_instruction_containing("via pop3")
            .respond_with_actions(open_pop3_server())
            .expect_calls(1)
            .and()
            .on_event("pop3_command")
            .and_event_data_contains("command", "CONNECTION_ESTABLISHED")
            .respond_with_actions(greeting_action())
            .expect_calls(1)
            .and()
            .on_event("pop3_command")
            .and_event_data_contains("command", "USER")
            .respond_with_actions(serde_json::json!([{
                "type": "send_pop3_ok", "message": "user accepted"
            }]))
            .expect_calls(1)
            .and()
    });

    let server = start_netget_server(config).await?;
    server.wait_for_any(&["listening on"], 30).await;

    let stream = TcpStream::connect(format!("127.0.0.1:{}", server.port)).await?;
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    let greeting = read_line(&mut reader).await?;
    assert!(greeting.starts_with("+OK"), "banner: {greeting}");

    // 900 bytes: comfortably inside the 1 KiB cap, and far longer than any real USER line.
    let mut user = b"USER ".to_vec();
    user.resize(900, b'a');
    user.extend_from_slice(b"\r\n");
    write_half.write_all(&user).await?;
    write_half.flush().await?;

    let reply = read_line(&mut reader).await?;
    assert!(
        reply.starts_with("+OK"),
        "a command inside the cap must still be answered, got: {reply}"
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    Ok(())
}

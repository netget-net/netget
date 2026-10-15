//! An oversized command line is refused before it is buffered, and before a model call.
//!
//! `AsyncBufReadExt::read_line` grows its `String` until it finds a `\n` and bounds nothing, so
//! a peer that connects to IMAP and streams bytes without ever sending a newline made the
//! server allocate without limit. This is reachable before `LOGIN`, so no authentication stands
//! in front of it, and the line never completes, so `handle_command` never sees a command it
//! could refuse.
//!
//! The load-bearing assertion is **zero** `imap_command` calls for the oversized line. A cap
//! that refused after building the event would still have put the peer's bytes in a prompt.
//!
//! The refusal is an untagged `* BYE`, not a tagged `NO`, and that is forced by the situation
//! rather than chosen: an IMAP tag is the *first* token of a line, and the line never arrived,
//! so there is nothing to correlate a tagged response to. RFC 3501 §7.1.5 makes `* BYE` the
//! server's way of ending a session unilaterally.

use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

/// Larger than `MAX_COMMAND_BYTES` (8 KiB) in `src/server/imap/mod.rs`.
const OVERSIZED: usize = 32 * 1024;

async fn read_line(reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>) -> E2EResult<String> {
    let mut line = String::new();
    let n = tokio::time::timeout(Duration::from_secs(20), reader.read_line(&mut line))
        .await
        .map_err(|_| "No IMAP response within 20s")??;
    if n == 0 {
        return Err("IMAP connection closed without a response".into());
    }
    Ok(line)
}

fn open_imap_server() -> serde_json::Value {
    serde_json::json!([{
        "type": "open_server",
        "port": 0,
        "base_stack": "imap",
        "instruction": "Greet, then serve INBOX"
    }])
}

fn greeting_action() -> serde_json::Value {
    serde_json::json!([{
        "type": "send_imap_response",
        "response": "* OK IMAP4rev1 NetGet ready"
    }])
}

#[tokio::test]
async fn an_oversized_command_line_is_refused_without_reaching_the_model() -> E2EResult<()> {
    let prompt = "listen on port {AVAILABLE_PORT} via imap. Greet, then serve INBOX";

    let config = NetGetConfig::new_no_scripts(prompt).with_mock(|mock| {
        mock.on_instruction_containing("via imap")
            .respond_with_actions(open_imap_server())
            .expect_calls(1)
            .and()
            .on_event("imap_connection")
            .respond_with_actions(greeting_action())
            .expect_calls(1)
            .and()
            // The load-bearing expectation: the oversized line must never become an event.
            .on_event("imap_command")
            .respond_with_actions(serde_json::json!([{
                "type": "send_imap_response",
                "response": "* OK should never be reached"
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
        greeting.starts_with("* OK"),
        "expected the mocked greeting, got: {greeting}"
    );

    // A plausible tag and verb, then bulk, and deliberately **no newline**.
    let mut oversized = b"A001 LOGIN ".to_vec();
    oversized.resize(OVERSIZED, b'a');
    write_half.write_all(&oversized).await?;
    write_half.flush().await?;

    let reply = read_line(&mut reader).await?;
    println!("IMAP oversized-line reply: {}", reply.trim());

    assert!(
        reply.starts_with("* BYE"),
        "an oversized line must end the session with an untagged BYE, got: {reply}"
    );
    assert!(
        !reply.contains("A001 OK"),
        "a tagged OK here would authenticate a session whose command was never parsed: {reply}"
    );

    // The refusal closes: there is no resynchronisation point mid-line.
    let mut rest = Vec::new();
    let closed = tokio::time::timeout(Duration::from_secs(20), reader.read_to_end(&mut rest)).await;
    assert!(
        closed.is_ok(),
        "the server must close after refusing an oversized line"
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
    let prompt = "listen on port {AVAILABLE_PORT} via imap. Greet, then serve INBOX";

    let config = NetGetConfig::new_no_scripts(prompt).with_mock(|mock| {
        mock.on_instruction_containing("via imap")
            .respond_with_actions(open_imap_server())
            .expect_calls(1)
            .and()
            .on_event("imap_connection")
            .respond_with_actions(greeting_action())
            .expect_calls(1)
            .and()
            .on_event("imap_command")
            .respond_with_actions(serde_json::json!([{
                "type": "send_imap_response",
                "response": "A001 OK CAPABILITY completed"
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
    assert!(greeting.starts_with("* OK"), "greeting: {greeting}");

    // 4 KiB: inside the 8 KiB cap, and far longer than any real command.
    let mut cmd = b"A001 CAPABILITY ".to_vec();
    cmd.resize(4096, b'a');
    cmd.extend_from_slice(b"\r\n");
    write_half.write_all(&cmd).await?;
    write_half.flush().await?;

    let reply = read_line(&mut reader).await?;
    assert!(
        reply.starts_with("A001 OK"),
        "a command inside the cap must still be answered, got: {reply}"
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    Ok(())
}

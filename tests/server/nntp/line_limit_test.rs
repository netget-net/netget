//! An oversized command line is refused before it is buffered, and before a model call.
//!
//! `AsyncBufReadExt::read_line` grows its `String` until it finds a `\n` and bounds nothing, so
//! a peer that connects to NNTP and streams bytes without ever sending a newline made the
//! server allocate without limit. No authentication stands in front of it, and the line never
//! completes, so nothing downstream ever sees a command it could refuse.
//!
//! The load-bearing assertion is **zero** `nntp_command_received` calls for the oversized line.
//! A cap that refused after building the event would still have put the peer's bytes in a
//! prompt, which is what the bound exists to prevent.
//!
//! RFC 3977 §3.1 caps the command line at 512 octets and `501` is its syntax-error response, so
//! the refusal is expressed in NNTP's own vocabulary rather than as a bare close — a client
//! that reads a closed socket reports a transport fault, not the refusal it was given.


use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

/// Larger than `MAX_COMMAND_BYTES` (4 KiB) in `src/server/nntp/mod.rs`.
const OVERSIZED: usize = 16 * 1024;

async fn read_line(reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>) -> E2EResult<String> {
    let mut line = String::new();
    let n = tokio::time::timeout(Duration::from_secs(20), reader.read_line(&mut line))
        .await
        .map_err(|_| "No NNTP response within 20s")??;
    if n == 0 {
        return Err("NNTP connection closed without a response".into());
    }
    Ok(line)
}

fn open_nntp_server() -> serde_json::Value {
    serde_json::json!([{
        "type": "open_server",
        "port": 0,
        "base_stack": "nntp",
        "instruction": "Greet, then serve misc.test"
    }])
}

fn greeting_action() -> serde_json::Value {
    serde_json::json!([{
        "type": "send_nntp_response",
        "code": 200,
        "text": "NetGet NNTP Service Ready"
    }])
}

#[tokio::test]
async fn an_oversized_command_line_is_refused_without_reaching_the_model() -> E2EResult<()> {
    let prompt = "listen on port {AVAILABLE_PORT} via nntp. Greet, then serve misc.test";

    let config = NetGetConfig::new_no_scripts(prompt).with_mock(|mock| {
        mock.on_instruction_containing("via nntp")
            .respond_with_actions(open_nntp_server())
            .expect_calls(1)
            .and()
            .on_event("nntp_command_received")
            .and_event_data_contains("command", "GREETING")
            .respond_with_actions(greeting_action())
            .expect_calls(1)
            .and()
            // The load-bearing expectation: the oversized line must never become an event.
            .on_event("nntp_command_received")
            .respond_with_actions(serde_json::json!([{
                "type": "send_nntp_response", "code": 200, "text": "should never be reached"
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
    println!("NNTP greeting: {}", greeting.trim());

    // A valid verb, then bulk, and deliberately **no newline**.
    let mut oversized = b"GROUP ".to_vec();
    oversized.resize(OVERSIZED, b'a');
    write_half.write_all(&oversized).await?;
    write_half.flush().await?;

    let reply = read_line(&mut reader).await?;
    println!("NNTP oversized-line reply: {}", reply.trim());

    assert!(
        reply.starts_with("501"),
        "an oversized line must be refused with NNTP's own 501, got: {reply}"
    );
    assert!(
        !reply.starts_with("2"),
        "a 2xx here would report success for a command that was never parsed: {reply}"
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
    let prompt = "listen on port {AVAILABLE_PORT} via nntp. Greet, then serve misc.test";

    let config = NetGetConfig::new_no_scripts(prompt).with_mock(|mock| {
        mock.on_instruction_containing("via nntp")
            .respond_with_actions(open_nntp_server())
            .expect_calls(1)
            .and()
            .on_event("nntp_command_received")
            .and_event_data_contains("command", "GREETING")
            .respond_with_actions(greeting_action())
            .expect_calls(1)
            .and()
            .on_event("nntp_command_received")
            .and_event_data_contains("command", "GROUP")
            .respond_with_actions(serde_json::json!([{
                "type": "send_nntp_group",
                "name": "misc.test", "count": 3, "low": 1, "high": 3
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
    println!("NNTP greeting: {}", greeting.trim());

    // 2 KiB: inside the 4 KiB cap, and longer than any real GROUP line.
    let mut cmd = b"GROUP misc.test ".to_vec();
    cmd.resize(2048, b'a');
    cmd.extend_from_slice(b"\r\n");
    write_half.write_all(&cmd).await?;
    write_half.flush().await?;

    let reply = read_line(&mut reader).await?;
    assert!(
        reply.starts_with("211"),
        "a command inside the cap must still be answered, got: {reply}"
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    Ok(())
}

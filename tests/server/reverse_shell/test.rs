//! End-to-end tests for the reverse-shell listener emulation.
//!
//! Every test drives the real `netget` binary with a raw TCP client — exactly what an operator's
//! `nc`/`socat` is — and asserts that the model-supplied shell output appears on the wire, and
//! that the fail-closed path drops the connection when the model gives no usable answer.
//!
//! These assert emulation behaviour only: NetGet never executes the operator's commands, so the
//! output is whatever the mocked model returns.


use super::super::super::helpers::{self, E2EResult, NetGetConfig};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const READ_TIMEOUT: Duration = Duration::from_secs(15);

/// Read from the stream until `needle` appears or a read times out / EOFs.
/// Returns everything accumulated so far.
async fn read_until(stream: &mut TcpStream, needle: &str) -> String {
    let mut acc = String::new();
    let mut buf = vec![0u8; 4096];
    for _ in 0..8 {
        match tokio::time::timeout(READ_TIMEOUT, stream.read(&mut buf)).await {
            Ok(Ok(0)) => break, // EOF
            Ok(Ok(n)) => {
                acc.push_str(&String::from_utf8_lossy(&buf[..n]));
                if acc.contains(needle) {
                    break;
                }
            }
            _ => break,
        }
    }
    acc
}

#[tokio::test]
async fn test_reverse_shell_command_output() -> E2EResult<()> {
    println!("\n=== E2E Test: reverse-shell command output ===");

    let prompt = "reverse-shell listener on port {AVAILABLE_PORT} emulating a compromised ubuntu box for a CTF";

    let server = helpers::start_netget_server(NetGetConfig::new(prompt).with_mock(|mock| {
        mock
            // Session opened: greet with a prompt. (Registered before the instruction rule.)
            .on_event("reverse_shell_session_opened")
            .respond_with_actions(serde_json::json!([
                { "type": "send_shell_prompt", "prompt": "$ " }
            ]))
            .expect_calls(1)
            .and()
            // The operator typed `whoami`: the model role-plays the shell's answer.
            .on_event("reverse_shell_command")
            .and_event_data_contains("command", "whoami")
            .respond_with_actions(serde_json::json!([
                { "type": "send_shell_output", "output": "www-data\n" }
            ]))
            .expect_calls(1)
            .and()
            // Interpretation → start the listener. Least specific, registered last.
            .on_instruction_containing("reverse")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "reverse-shell",
                    "instruction": "Emulate a shell on a compromised ubuntu host"
                }
            ]))
            .expect_calls(1)
            .and()
    }))
    .await?;
    println!("Listener started on port {}", server.port);

    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", server.port)).await?;

    // Drain the opening prompt (sent on connect, like a reverse shell landing).
    let opening = read_until(&mut stream, "$ ").await;
    println!("Opening: {opening:?}");

    // Operator types a command.
    stream.write_all(b"whoami\n").await?;
    stream.flush().await?;

    let response = read_until(&mut stream, "www-data").await;
    println!("Response: {response:?}");
    assert!(
        response.contains("www-data"),
        "Expected the model-supplied shell output 'www-data', got: {response:?}"
    );

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    println!("=== Test passed ===\n");
    Ok(())
}

#[tokio::test]
async fn test_reverse_shell_fails_closed_on_no_answer() -> E2EResult<()> {
    println!("\n=== E2E Test: reverse-shell fails closed ===");

    let prompt = "reverse-shell listener on port {AVAILABLE_PORT} for a lab";

    let server = helpers::start_netget_server(NetGetConfig::new(prompt).with_mock(|mock| {
        mock.on_event("reverse_shell_session_opened")
            .respond_with_actions(serde_json::json!([
                { "type": "send_shell_prompt", "prompt": "$ " }
            ]))
            .expect_calls(1)
            .and()
            // The command event is answered with ONLY show_message: a valid action that produces
            // no protocol output. The server must treat this as "no usable answer" and fail
            // closed (shut the socket), NOT invent output or keep a silent session open.
            .on_event("reverse_shell_command")
            .respond_with_actions(serde_json::json!([
                { "type": "show_message", "message": "no shell output produced" }
            ]))
            .expect_calls(1)
            .and()
            .on_instruction_containing("reverse")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "reverse-shell",
                    "instruction": "Reverse-shell listener for a lab"
                }
            ]))
            .expect_calls(1)
            .and()
    }))
    .await?;
    println!("Listener started on port {}", server.port);

    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", server.port)).await?;
    let _opening = read_until(&mut stream, "$ ").await;

    stream.write_all(b"anything\n").await?;
    stream.flush().await?;

    // Fail-closed: the server writes one category line, then half-closes, so a read must
    // eventually return EOF (0 bytes).
    let mut buf = vec![0u8; 1024];
    let mut saw_eof = false;
    let mut tail = String::new();
    for _ in 0..8 {
        match tokio::time::timeout(READ_TIMEOUT, stream.read(&mut buf)).await {
            Ok(Ok(0)) => {
                saw_eof = true;
                break;
            }
            Ok(Ok(n)) => {
                tail.push_str(&String::from_utf8_lossy(&buf[..n]));
                continue;
            }
            _ => break,
        }
    }
    assert!(
        saw_eof,
        "Expected the connection to be closed (EOF) after a no-usable-answer, but it stayed open"
    );

    // The operator is told a *category* before the FIN, so a dropped session is not mistaken
    // for the far-end implant dying.
    assert!(
        tail.contains("[netget] request could not be processed"),
        "Expected the fail-closed category notice before EOF, got: {tail:?}"
    );

    // And nothing from netget's internals reaches the operator's terminal. These are the
    // tokens that actually leaked in the incident tests/wire_failure_test.rs documents.
    for token in [
        "\u{2717}", "retries", "http://", "11434", "qwen", "/Users/", "LLM", "ollama", "Ollama",
    ] {
        assert!(
            !tail.contains(token),
            "fail-closed notice leaked {token:?} to the operator: {tail:?}"
        );
    }

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    println!("=== Test passed ===\n");
    Ok(())
}

/// Greeting with silence must keep the session, not drop it.
///
/// `reverse_shell_session_opened`'s own description offers "stay silent and wait for their first
/// command", and there was no way to say it: `call_llm` builds the tool list from the event, and
/// `no_shell_output` was missing from that event's actions. A model taking the description at
/// its word answered with zero actions, which `consult` reads as `NoUsableAnswer` — so following
/// the documentation produced a failure notice and a FIN before the operator typed anything.
///
/// The distinction this pins is the one the protocol is careful about everywhere else: a
/// deliberate "print nothing" is not the same as "no answer came back".
#[tokio::test]
async fn test_silent_greeting_keeps_the_session() -> E2EResult<()> {
    println!("\n=== E2E Test: reverse-shell silent greeting ===");

    let prompt = "reverse-shell listener on port {AVAILABLE_PORT} that stays quiet until spoken to";

    let server = helpers::start_netget_server(NetGetConfig::new(prompt).with_mock(|mock| {
        mock.on_event("reverse_shell_session_opened")
            .respond_with_actions(serde_json::json!([
                { "type": "no_shell_output" }
            ]))
            .expect_calls(1)
            .and()
            .on_event("reverse_shell_command")
            .and_event_data_contains("command", "id")
            .respond_with_actions(serde_json::json!([
                { "type": "send_shell_output", "output": "uid=33(www-data)\n" }
            ]))
            .expect_calls(1)
            .and()
            .on_instruction_containing("reverse-shell")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "reverse-shell",
                    "instruction": "Quiet shell emulation"
                }
            ]))
            .expect_calls(1)
            .and()
    }))
    .await?;
    println!("Listener started on port {}", server.port);

    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", server.port)).await?;

    // Nothing on connect, and — the part that matters — the session is still open. Before the
    // fix this read returned the fail-closed notice followed by EOF.
    let mut buf = vec![0u8; 1024];
    match tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf)).await {
        Err(_) => println!("✓ silent greeting, session still open"),
        Ok(Ok(0)) => {
            return Err(
                "listener hung up on a silent greeting instead of waiting for a command".into(),
            )
        }
        Ok(Ok(n)) => {
            return Err(format!(
                "listener wrote {:?} to a session the model answered with no_shell_output",
                String::from_utf8_lossy(&buf[..n])
            )
            .into())
        }
        Ok(Err(e)) => return Err(format!("read error after connect: {}", e).into()),
    }

    // The session really is usable: the first command still gets its answer.
    stream.write_all(b"id\n").await?;
    stream.flush().await?;
    let out = read_until(&mut stream, "www-data").await;
    assert!(
        out.contains("uid=33(www-data)"),
        "the session did not survive the silent greeting; got {out:?}"
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    println!("=== Test passed ===\n");
    Ok(())
}

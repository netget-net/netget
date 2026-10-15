//! Every terminal outcome of an IRC line is grep-able as `decision=<token>`.
//!
//! IRC's numeric 400 is written on the backend-failure path and nowhere else, but the *log*
//! has to carry more than that: a model that answered, a model that refused by hanging up and
//! a model that produced nothing all leave the server going quietly back to reading. Only the
//! token tells them apart, and for the registration path — where the client is waiting on 001
//! — that is the difference between "we denied you" and "we never asked anyone".

use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

async fn read_line(reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>) -> E2EResult<String> {
    let mut line = String::new();
    let n = tokio::time::timeout(Duration::from_secs(20), reader.read_line(&mut line))
        .await
        .map_err(|_| "No IRC response within 20s")??;
    if n == 0 {
        return Err("IRC connection closed without a response".into());
    }
    Ok(line)
}

fn open_irc_server() -> serde_json::Value {
    serde_json::json!([
        {
            "type": "open_server",
            "port": 0,
            "base_stack": "IRC",
            "instruction": "Welcome clients that register"
        }
    ])
}

/// The backend fails while the client is mid-registration. The client gets 400 and a closed
/// link — never 001 — and the log says the server, not the model, decided that.
#[tokio::test]
async fn test_irc_llm_failure_is_tagged_fail_closed_and_never_registers() -> E2EResult<()> {
    let prompt = "listen on port {AVAILABLE_PORT} via irc. Welcome clients that register";

    let config = NetGetConfig::new_no_scripts(prompt).with_mock(|mock| {
        mock.on_instruction_containing("via irc")
            .respond_with_actions(open_irc_server())
            .expect_calls(1)
            .and()
            // Not an action: the repair loop exhausts and `call_llm` returns Err.
            .on_event("irc_message_received")
            .respond_with_raw("the backend is having a bad day and this is not an action")
            .expect_at_least(1)
            .and()
    });

    let server = start_netget_server(config).await?;
    // Condition, not a fixed sleep: under `--test-threads=100` the listener can be a second
    // or more behind the process starting.
    server.wait_for_any(&["listening on"], 30).await;

    let stream = TcpStream::connect(format!("127.0.0.1:{}", server.port)).await?;
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    write_half.write_all(b"NICK tester\r\n").await?;
    write_half.flush().await?;

    let reply = read_line(&mut reader).await?;
    println!("IRC reply: {}", reply.trim());
    assert!(
        reply.contains(" 400 "),
        "a backend failure must answer ERR_UNKNOWNERROR, got: {reply}"
    );
    assert!(
        !reply.contains(" 001 "),
        "a backend failure must never complete registration: {reply}"
    );
    // The trailing parameter of a numeric is printed verbatim by a real IRC client, so it is
    // the one place netget's own error text must never reach.
    assert!(
        !reply.contains("LLM") && !reply.contains("Ollama") && !reply.contains("retries"),
        "the numeric's trailing parameter must be a category, not an error: {reply}"
    );

    server
        .wait_for_any(&["decision=fail_closed_llm_error"], 30)
        .await;
    let lines = server.get_output().await;
    assert!(
        lines
            .iter()
            .any(|l| l.contains("decision=fail_closed_llm_error")),
        "the backend failure must be distinguishable in the log from a model that refused. \
         Output was:\n{}",
        lines.join("\n")
    );
    assert!(
        !lines.iter().any(|l| l.contains("decision=model_reject")),
        "a backend failure must never be reported as the model's refusal. Output was:\n{}",
        lines.join("\n")
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

/// The model answers and the answer reaches the client: `decision=model_answer`. This is the
/// control — without it, a token emitted unconditionally would satisfy the test above.
#[tokio::test]
async fn test_irc_successful_answer_is_tagged_model_answer() -> E2EResult<()> {
    let prompt = "listen on port {AVAILABLE_PORT} via irc. Welcome clients that register";

    let config = NetGetConfig::new_no_scripts(prompt).with_mock(|mock| {
        mock.on_instruction_containing("via irc")
            .respond_with_actions(open_irc_server())
            .expect_calls(1)
            .and()
            .on_event("irc_message_received")
            .and_event_data_contains("message", "NICK")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "send_irc_welcome",
                    "nickname": "tester",
                    "server": "irc.example.com",
                    "message": "Welcome to the IRC Network"
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let server = start_netget_server(config).await?;
    // Condition, not a fixed sleep: under `--test-threads=100` the listener can be a second
    // or more behind the process starting.
    server.wait_for_any(&["listening on"], 30).await;

    let stream = TcpStream::connect(format!("127.0.0.1:{}", server.port)).await?;
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    write_half.write_all(b"NICK tester\r\n").await?;
    write_half.flush().await?;

    let reply = read_line(&mut reader).await?;
    println!("IRC reply: {}", reply.trim());
    assert!(
        reply.contains(" 001 "),
        "expected the mocked RPL_WELCOME, got: {reply}"
    );

    server.wait_for_any(&["decision=model_answer"], 30).await;
    let lines = server.get_output().await;
    assert!(
        lines.iter().any(|l| l.contains("decision=model_answer")),
        "an applied answer must be tagged model_answer. Output was:\n{}",
        lines.join("\n")
    );
    assert!(
        !lines.iter().any(|l| l.contains("decision=fail_closed")),
        "a successful request must not log any fail_closed token. Output was:\n{}",
        lines.join("\n")
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

//! POP3's authentication path fails closed, and the log says so in the repo's own vocabulary.
//!
//! This is the OAuth2 question asked of POP3: when the backend is unreachable, does `PASS`
//! answer `+OK`? It does not, and it structurally cannot — the only `+OK` this protocol can
//! produce comes from an action the model named, and `pop3_failure_reply` is `-ERR` in every
//! branch. These tests pin both halves of that claim:
//!
//! 1. a backend outage on `PASS` writes `-ERR` and logs `decision=fail_closed_llm_*`;
//! 2. a model that *deliberately* denies the login writes `-ERR` too, and logs
//!    `decision=model_reject`.
//!
//! The pair is the point. On the wire those two are the same `-ERR`, so if the log conflated
//! them an operator could not tell a denied password from an unreachable model — which is
//! exactly the distinction the OAuth2 post-mortem says must never be lost.


use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

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
    serde_json::json!([
        {
            "type": "open_server",
            "port": 0,
            "base_stack": "pop3",
            "instruction": "Greet, then serve alice's mailbox"
        }
    ])
}

fn greeting_action() -> serde_json::Value {
    serde_json::json!([
        {
            "type": "send_pop3_greeting",
            "message": "POP3 server ready"
        }
    ])
}

/// The backend dies between the greeting and `PASS`. The client is refused, not admitted, and
/// the refusal is logged as netget's own rather than as the model's.
#[tokio::test]
async fn test_pop3_backend_failure_on_pass_is_err_and_tagged_fail_closed() -> E2EResult<()> {
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
            // Everything after the greeting: not an action, so the repair loop exhausts and
            // `call_llm` returns Err. This is the backend-outage path on the auth commands.
            .on_event("pop3_command")
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

    let greeting = read_line(&mut reader).await?;
    assert!(
        greeting.starts_with("+OK"),
        "expected the mocked banner, got: {greeting}"
    );

    write_half.write_all(b"USER alice\r\n").await?;
    write_half.flush().await?;
    let reply = read_line(&mut reader).await?;
    println!("POP3 USER reply: {}", reply.trim());

    assert!(
        reply.starts_with("-ERR"),
        "a backend outage must refuse, never admit: {reply}"
    );
    assert!(
        !reply.starts_with("+OK"),
        "an LLM outage that answered +OK would be a mailbox granted by a backend failure: \
         {reply}"
    );
    assert!(
        !reply.contains("LLM") && !reply.contains("Ollama") && !reply.contains("retries"),
        "the peer gets a category, never netget's own error text: {reply}"
    );

    server
        .wait_for_any(
            &[
                "decision=fail_closed_llm_error",
                "decision=fail_closed_llm_overloaded",
            ],
            30,
        )
        .await;
    let lines = server.get_output().await;
    assert!(
        lines.iter().any(|l| {
            l.contains("decision=fail_closed_llm_error")
                || l.contains("decision=fail_closed_llm_overloaded")
        }),
        "a refusal netget decided must be logged as fail_closed, not as the model's. \
         Output was:\n{}",
        lines.join("\n")
    );
    assert!(
        !lines.iter().any(|l| l.contains("decision=model_reject")),
        "a backend failure must never be reported as a model denial — that conflation is the \
         OAuth2 defect. Output was:\n{}",
        lines.join("\n")
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

/// The model reaches a decision and the decision is "no". Same `-ERR` on the wire, a different
/// token in the log. Without this test the one above proves only that *something* was tagged.
#[tokio::test]
async fn test_pop3_model_denial_is_tagged_model_reject_not_fail_closed() -> E2EResult<()> {
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
            .respond_with_actions(serde_json::json!([
                {
                    "type": "send_pop3_err",
                    "message": "no such mailbox"
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

    let greeting = read_line(&mut reader).await?;
    assert!(
        greeting.starts_with("+OK"),
        "expected the mocked banner, got: {greeting}"
    );

    write_half.write_all(b"USER mallory\r\n").await?;
    write_half.flush().await?;
    let reply = read_line(&mut reader).await?;
    println!("POP3 USER reply: {}", reply.trim());

    assert!(
        reply.starts_with("-ERR"),
        "the model denied the login, so the wire must carry -ERR: {reply}"
    );
    assert!(
        reply.contains("no such mailbox"),
        "the model's own denial text should reach the client: {reply}"
    );

    server.wait_for_any(&["decision=model_reject"], 30).await;
    let lines = server.get_output().await;
    assert!(
        lines.iter().any(|l| l.contains("decision=model_reject")),
        "a denial the model decided must be logged as model_reject. Output was:\n{}",
        lines.join("\n")
    );
    assert!(
        !lines.iter().any(|l| l.contains("decision=fail_closed")),
        "the backend answered, so nothing here may be tagged fail_closed — otherwise a real \
         outage would be indistinguishable from a denied password. Output was:\n{}",
        lines.join("\n")
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

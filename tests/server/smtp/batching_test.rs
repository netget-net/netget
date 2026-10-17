//! Pipelined SMTP commands that arrive while the model is answering are answered together —
//! and every command still gets exactly its own reply, in order.
//!
//! The client sends `MAIL FROM`, whose answer the mock delays, and while that call is running
//! pipelines `RCPT TO:<b>`, `RCPT TO:<c>` and `NOOP` in one write. One test holds three runs:
//!
//! * **control, batching off** — four model calls, one per command;
//! * **batching on** — two calls, the second listing both RCPTs above its `NOOP` trigger, and
//!   the wire carries the same replies in the same order as the control;
//! * **batching on, an answer one reply short** — every pipelined command is answered `451`
//!   (temporary, accepts nothing) and the next command is answered normally: the session is
//!   still in step.

use std::time::Duration;

use crate::helpers::mock_builder::MockLlmBuilder;
use crate::helpers::mock_ollama::MockOllamaServer;
use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use netget::state::ServerId;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::mpsc;

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Off,
    On,
    OnShortAnswer,
}

async fn wait_for_port(state: &AppState, id: ServerId) -> u16 {
    for _ in 0..300 {
        if let Some(s) = state.get_server(id).await {
            if let Some(addr) = s.local_addr {
                return addr.port();
            }
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("server #{} never bound a port", id.as_u32());
}

async fn read_reply<R: tokio::io::AsyncBufRead + Unpin>(reader: &mut R) -> String {
    let mut line = String::new();
    let n = tokio::time::timeout(Duration::from_secs(30), reader.read_line(&mut line))
        .await
        .expect("an SMTP reply within 30s")
        .expect("read");
    assert!(n > 0, "connection closed before a reply");
    line.trim_end().to_string()
}

/// Returns the replies the client read and, for every `smtp_command` model call other than
/// the greeting, its prompt and event data.
async fn run(mode: Mode) -> (Vec<String>, Vec<(String, serde_json::Value)>) {
    let batched_answer = if mode == Mode::OnShortAnswer {
        serde_json::json!([
            {"type": "send_smtp_ok", "message": "b accepted"},
            {"type": "send_smtp_error", "code": 550, "message": "c refused"}
        ])
    } else {
        serde_json::json!([
            {"type": "send_smtp_ok", "message": "b accepted"},
            {"type": "send_smtp_error", "code": 550, "message": "c refused"},
            {"type": "send_smtp_ok", "message": "noop done"}
        ])
    };
    let mock = MockOllamaServer::start(
        MockLlmBuilder::new()
            .on_event("smtp_command")
            .and_event_data_contains("command", "CONNECTION_ESTABLISHED")
            .respond_with_actions(serde_json::json!([
                {"type": "send_smtp_greeting", "hostname": "mail.test", "message": "ready"}
            ]))
            .expect_calls(1)
            .and()
            // The batch: three pipelined commands, `NOOP` the newest.
            .on_event("smtp_command")
            .and_event_data_contains("command", "NOOP")
            .and_prompt_containing("answers all 3 together")
            .respond_with_actions(batched_answer)
            .expect_calls(if mode == Mode::Off { 0 } else { 1 })
            .and()
            // Answered slowly, so the rest arrives during this call.
            .on_event("smtp_command")
            .and_event_data_contains("command", "MAIL FROM")
            .respond_with_actions(serde_json::json!([
                {"type": "send_smtp_ok", "message": "sender ok"}
            ]))
            .after_delay(Duration::from_millis(1500))
            .expect_calls(1)
            .and()
            // One command at a time.
            .on_event("smtp_command")
            .respond_with_actions_from_event(|event| {
                let command = event["command"].as_str().unwrap_or_default();
                if command.contains("<b@example.com>") {
                    serde_json::json!([{"type": "send_smtp_ok", "message": "b accepted"}])
                } else if command.contains("<c@example.com>") {
                    serde_json::json!([{"type": "send_smtp_error", "code": 550, "message": "c refused"}])
                } else {
                    serde_json::json!([{"type": "send_smtp_ok", "message": "noop done"}])
                }
            })
            .expect_calls(match mode {
                Mode::Off => 3,
                Mode::On => 0,
                Mode::OnShortAnswer => 1,
            })
            .build(),
    )
    .await
    .expect("mock ollama");

    let state = AppState::new_with_options(false, mock.base_url());
    state
        .set_llm_client(netget::llm::OllamaClient::new(mock.base_url()))
        .await;
    let (tx, _rx) = mpsc::unbounded_channel();
    let id = ServerForm {
        protocol: "smtp".to_string(),
        port: Some(0),
        instruction: Some("Accept mail for b@example.com, refuse c@example.com.".to_string()),
        batching: Some(mode != Mode::Off),
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .expect("create smtp server");
    let port = wait_for_port(&state, id).await;

    let stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    let greeting = read_reply(&mut reader).await;
    assert!(greeting.starts_with("220"), "greeting: {greeting}");

    write_half
        .write_all(b"MAIL FROM:<a@example.com>\r\n")
        .await
        .expect("write");
    // Greeting + MAIL: the slow call is running.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while mock.call_count().await < 2 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "MAIL never reached the model"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    write_half
        .write_all(b"RCPT TO:<b@example.com>\r\nRCPT TO:<c@example.com>\r\nNOOP\r\n")
        .await
        .expect("write");
    let mut replies = Vec::new();
    for _ in 0..4 {
        replies.push(read_reply(&mut reader).await);
    }
    if mode == Mode::OnShortAnswer {
        // Alone, so answered on its own: proves the session is still in step.
        write_half.write_all(b"NOOP\r\n").await.expect("write");
        replies.push(read_reply(&mut reader).await);
    }

    mock.verify_calls().await.expect("mock expectations");
    let calls = mock
        .recorded_calls()
        .await
        .into_iter()
        .filter(|c| c.context.event_type.as_deref() == Some("smtp_command"))
        .filter(|c| c.context.event_data["command"] != "CONNECTION_ESTABLISHED")
        .map(|c| (c.context.prompt.clone(), c.context.event_data.clone()))
        .collect();
    let _ = state.remove_server(id).await;
    (replies, calls)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pipelined_commands_are_answered_together_one_reply_each() {
    let expected = [
        "250 sender ok",
        "250 b accepted",
        "550 c refused",
        "250 noop done",
    ];

    // === Control: batching off. One call per command, replies in command order. ===
    let (replies, calls) = run(Mode::Off).await;
    assert_eq!(
        calls.len(),
        4,
        "CONTROL FAILED: with batching off every command must be its own model call: {:#?}",
        calls.iter().map(|(_, d)| d).collect::<Vec<_>>()
    );
    assert_eq!(replies, expected, "CONTROL FAILED: replies out of order");

    // === Batching on: the three pipelined commands are one call, the wire is unchanged. ===
    let (replies, calls) = run(Mode::On).await;
    assert_eq!(
        calls.len(),
        2,
        "the three commands pipelined during MAIL's call must be answered in one: {:#?}",
        calls.iter().map(|(_, d)| d).collect::<Vec<_>>()
    );
    assert_eq!(
        replies, expected,
        "each pipelined command must get its own reply, in order"
    );
    let (prompt, trigger) = &calls[1];
    assert_eq!(
        trigger["command"], "NOOP",
        "the newest command is the trigger"
    );
    assert!(
        trigger["pipelined"]
            .as_str()
            .is_some_and(|p| p.contains("exactly one reply each")),
        "the model must be told one reply per command: {trigger}"
    );
    let before = &prompt[..prompt.rfind("Event ID: smtp_command").expect("trigger")];
    let b = before
        .find("RCPT TO:<b@example.com>")
        .expect("RCPT b listed");
    let c = before
        .find("RCPT TO:<c@example.com>")
        .expect("RCPT c listed");
    assert!(b < c, "earlier commands are listed in the order sent");

    // === Batching on, one reply short: 451 to each, and the session stays in step. ===
    let (replies, _) = run(Mode::OnShortAnswer).await;
    assert_eq!(replies[0], "250 sender ok");
    for reply in &replies[1..4] {
        assert!(
            reply.starts_with("451 "),
            "an answer one reply short must answer every pipelined command 451, got {replies:?}"
        );
    }
    assert_eq!(
        replies[4], "250 noop done",
        "the next command must be answered as its own: {replies:?}"
    );
}

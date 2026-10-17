//! Pipelined NNTP commands (RFC 3977 §3.5) that arrive while the model is answering are
//! answered together — and every command still gets exactly its own response, in order.
//!
//! The client sends `GROUP misc.test`, whose answer the mock delays, and while that call is
//! running pipelines `STAT 1`, `NEXT` and `DATE` in one write. One test holds three runs: the
//! control with batching off (four calls), batching on (two calls, identical responses in the
//! same order), and batching on with an answer one response short (`403` to each pipelined
//! command, after which the next command is answered normally).

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
        .expect("an NNTP response within 30s")
        .expect("read");
    assert!(n > 0, "connection closed before a response");
    line.trim_end().to_string()
}

fn respond(code: u64, text: &str) -> serde_json::Value {
    serde_json::json!({"type": "send_nntp_response", "code": code, "text": text})
}

async fn run(mode: Mode) -> (Vec<String>, Vec<(String, serde_json::Value)>) {
    let mut batched_answer = vec![
        respond(223, "1 <a@example.test>"),
        respond(421, "no next article"),
        respond(111, "20261016120000"),
    ];
    if mode == Mode::OnShortAnswer {
        batched_answer.pop();
    }
    let mock = MockOllamaServer::start(
        MockLlmBuilder::new()
            .on_event("nntp_command_received")
            .and_event_data_contains("command", "GREETING")
            .respond_with_actions(serde_json::json!([respond(201, "ready")]))
            .expect_calls(1)
            .and()
            .on_event("nntp_command_received")
            .and_event_data_contains("command", "DATE")
            .and_prompt_containing("answers all 3 together")
            .respond_with_actions(serde_json::Value::Array(batched_answer))
            .expect_calls(if mode == Mode::Off { 0 } else { 1 })
            .and()
            .on_event("nntp_command_received")
            .and_event_data_contains("command", "GROUP")
            .respond_with_actions(serde_json::json!([respond(211, "2 1 2 misc.test")]))
            .after_delay(Duration::from_millis(1500))
            .expect_calls(1)
            .and()
            .on_event("nntp_command_received")
            .respond_with_actions_from_event(|event| {
                let command = event["command"].as_str().unwrap_or_default();
                let answer = if command.starts_with("STAT") {
                    respond(223, "1 <a@example.test>")
                } else if command.starts_with("NEXT") {
                    respond(421, "no next article")
                } else {
                    respond(111, "20261016120000")
                };
                serde_json::json!([answer])
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
        protocol: "nntp".to_string(),
        port: Some(0),
        instruction: Some("One group, misc.test, with articles 1 and 2.".to_string()),
        batching: Some(mode != Mode::Off),
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .expect("create nntp server");
    let port = wait_for_port(&state, id).await;

    let stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    let greeting = read_reply(&mut reader).await;
    assert!(greeting.starts_with("201"), "greeting: {greeting}");

    write_half
        .write_all(b"GROUP misc.test\r\n")
        .await
        .expect("write");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while mock.call_count().await < 2 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "GROUP never reached the model"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    write_half
        .write_all(b"STAT 1\r\nNEXT\r\nDATE\r\n")
        .await
        .expect("write");
    let mut replies = Vec::new();
    for _ in 0..4 {
        replies.push(read_reply(&mut reader).await);
    }
    if mode == Mode::OnShortAnswer {
        write_half.write_all(b"DATE\r\n").await.expect("write");
        replies.push(read_reply(&mut reader).await);
    }

    mock.verify_calls().await.expect("mock expectations");
    let calls = mock
        .recorded_calls()
        .await
        .into_iter()
        .filter(|c| c.context.event_type.as_deref() == Some("nntp_command_received"))
        .filter(|c| c.context.event_data["command"] != "GREETING")
        .map(|c| (c.context.prompt.clone(), c.context.event_data.clone()))
        .collect();
    let _ = state.remove_server(id).await;
    (replies, calls)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pipelined_commands_are_answered_together_one_response_each() {
    let expected = [
        "211 2 1 2 misc.test",
        "223 1 <a@example.test>",
        "421 no next article",
        "111 20261016120000",
    ];

    // === Control: batching off. One call per command, responses in command order. ===
    let (replies, calls) = run(Mode::Off).await;
    assert_eq!(
        calls.len(),
        4,
        "CONTROL FAILED: with batching off every command must be its own model call: {:#?}",
        calls.iter().map(|(_, d)| d).collect::<Vec<_>>()
    );
    assert_eq!(replies, expected, "CONTROL FAILED: responses out of order");

    // === Batching on: the three pipelined commands are one call, the wire is unchanged. ===
    let (replies, calls) = run(Mode::On).await;
    assert_eq!(
        calls.len(),
        2,
        "the three commands pipelined during GROUP's call must be answered in one: {:#?}",
        calls.iter().map(|(_, d)| d).collect::<Vec<_>>()
    );
    assert_eq!(
        replies, expected,
        "each pipelined command must get its own response, in order"
    );
    let (prompt, trigger) = &calls[1];
    assert_eq!(
        trigger["command"], "DATE",
        "the newest command is the trigger"
    );
    let before = &prompt[..prompt
        .rfind("Event ID: nntp_command_received")
        .expect("trigger")];
    let stat = before.find("STAT 1").expect("STAT listed");
    let next = before.find("\"NEXT\"").expect("NEXT listed");
    assert!(stat < next, "earlier commands are listed in the order sent");

    // === Batching on, one response short: 403 to each, and the session stays in step. ===
    let (replies, _) = run(Mode::OnShortAnswer).await;
    assert_eq!(replies[0], "211 2 1 2 misc.test");
    for reply in &replies[1..4] {
        assert!(
            reply.starts_with("403 "),
            "an answer one response short must answer every pipelined command 403, got {replies:?}"
        );
    }
    assert_eq!(
        replies[4], "111 20261016120000",
        "the next command must be answered as its own: {replies:?}"
    );
}

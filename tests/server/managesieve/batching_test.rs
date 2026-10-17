//! Pipelined ManageSieve script commands that arrive while the model is answering are answered
//! together — and every command still gets exactly its own response, in order.
//!
//! After logging in, the client sends `LISTSCRIPTS`, whose answer the mock delays, and while
//! that call is running pipelines `GETSCRIPT "a"`, `DELETESCRIPT "b"` and `HAVESPACE "c" 100`
//! in one write. One test holds three runs: the control with batching off (four command calls),
//! batching on (two calls, identical responses in the same order — the script literal included),
//! and batching on with an answer one short (`NO (TRYLATER)` to each pipelined command, after
//! which the next command is answered normally).

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

async fn read_line<R: tokio::io::AsyncBufRead + Unpin>(reader: &mut R) -> String {
    let mut line = String::new();
    let n = tokio::time::timeout(Duration::from_secs(30), reader.read_line(&mut line))
        .await
        .expect("a ManageSieve line within 30s")
        .expect("read");
    assert!(n > 0, "connection closed before a response");
    line.trim_end().to_string()
}

/// Lines up to and including the next `OK`/`NO`/`BYE` status line.
async fn read_response<R: tokio::io::AsyncBufRead + Unpin>(reader: &mut R) -> Vec<String> {
    let mut lines = Vec::new();
    loop {
        let line = read_line(reader).await;
        let done = ["OK", "NO", "BYE"]
            .iter()
            .any(|s| line == *s || line.starts_with(&format!("{s} ")));
        lines.push(line);
        if done {
            return lines;
        }
    }
}

fn answer_for(command: &str) -> serde_json::Value {
    match command {
        "GETSCRIPT" => serde_json::json!({"type": "managesieve_script", "script": "keep;"}),
        "DELETESCRIPT" => {
            serde_json::json!({"type": "managesieve_no", "code": "NONEXISTENT", "message": "no b"})
        }
        _ => serde_json::json!({"type": "managesieve_ok"}),
    }
}

async fn run(mode: Mode) -> (Vec<String>, Vec<(String, serde_json::Value)>) {
    let mut batched_answer: Vec<serde_json::Value> = ["GETSCRIPT", "DELETESCRIPT", "HAVESPACE"]
        .iter()
        .map(|c| answer_for(c))
        .collect();
    if mode == Mode::OnShortAnswer {
        batched_answer.pop();
    }
    let mock = MockOllamaServer::start(
        MockLlmBuilder::new()
            .on_event("managesieve_auth")
            .respond_with_actions(serde_json::json!([{"type": "managesieve_ok"}]))
            .expect_calls(1)
            .and()
            .on_event("managesieve_command")
            .and_event_data_contains("command", "HAVESPACE")
            .and_prompt_containing("answers all 3 together")
            .respond_with_actions(serde_json::Value::Array(batched_answer))
            .expect_calls(if mode == Mode::Off { 0 } else { 1 })
            .and()
            .on_event("managesieve_command")
            .and_event_data_contains("command", "LISTSCRIPTS")
            .respond_with_actions(serde_json::json!([
                {"type": "managesieve_scripts", "scripts": [{"name": "a", "active": true}]}
            ]))
            .after_delay(Duration::from_millis(1500))
            .expect_calls(1)
            .and()
            .on_event("managesieve_command")
            .respond_with_actions_from_event(|event| {
                serde_json::json!([answer_for(event["command"].as_str().unwrap_or_default())])
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
        protocol: "managesieve".to_string(),
        port: Some(0),
        instruction: Some("alice has one script, a, which is active.".to_string()),
        batching: Some(mode != Mode::Off),
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .expect("create managesieve server");
    let port = wait_for_port(&state, id).await;

    let stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    let greeting = read_response(&mut reader).await;
    assert!(greeting.last().unwrap().starts_with("OK"), "{greeting:?}");
    write_half
        .write_all(b"AUTHENTICATE \"PLAIN\" \"AGFsaWNlAHNlY3JldA==\"\r\n")
        .await
        .expect("write");
    let login = read_response(&mut reader).await;
    assert!(login[0].starts_with("OK"), "login: {login:?}");

    write_half
        .write_all(b"LISTSCRIPTS\r\n")
        .await
        .expect("write");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while mock.call_count().await < 2 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "LISTSCRIPTS never reached the model"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    write_half
        .write_all(b"GETSCRIPT \"a\"\r\nDELETESCRIPT \"b\"\r\nHAVESPACE \"c\" 100\r\n")
        .await
        .expect("write");
    let mut lines = Vec::new();
    for _ in 0..4 {
        lines.extend(read_response(&mut reader).await);
    }
    if mode == Mode::OnShortAnswer {
        write_half
            .write_all(b"HAVESPACE \"d\" 1\r\n")
            .await
            .expect("write");
        lines.extend(read_response(&mut reader).await);
    }

    mock.verify_calls().await.expect("mock expectations");
    let calls = mock
        .recorded_calls()
        .await
        .into_iter()
        .filter(|c| c.context.event_type.as_deref() == Some("managesieve_command"))
        .map(|c| (c.context.prompt.clone(), c.context.event_data.clone()))
        .collect();
    let _ = state.remove_server(id).await;
    (lines, calls)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pipelined_script_commands_are_answered_together_one_response_each() {
    let expected = [
        "\"a\" ACTIVE",
        "OK \"Listscripts completed.\"",
        "{5}",
        "keep;",
        "OK \"Getscript completed.\"",
        "NO (NONEXISTENT) \"no b\"",
        "OK \"havespace completed.\"",
    ];

    // === Control: batching off. One call per command, responses in command order. ===
    let (lines, calls) = run(Mode::Off).await;
    assert_eq!(
        calls.len(),
        4,
        "CONTROL FAILED: with batching off every command must be its own model call: {:#?}",
        calls.iter().map(|(_, d)| d).collect::<Vec<_>>()
    );
    assert_eq!(lines, expected, "CONTROL FAILED: responses out of order");

    // === Batching on: the three pipelined commands are one call, the wire is unchanged. ===
    let (lines, calls) = run(Mode::On).await;
    assert_eq!(
        calls.len(),
        2,
        "the three commands pipelined during LISTSCRIPTS' call must be answered in one: {:#?}",
        calls.iter().map(|(_, d)| d).collect::<Vec<_>>()
    );
    assert_eq!(
        lines, expected,
        "each pipelined command must get its own response, in order"
    );
    let (prompt, trigger) = &calls[1];
    assert_eq!(
        trigger["command"], "HAVESPACE",
        "the newest command is the trigger"
    );
    let before = &prompt[..prompt
        .rfind("Event ID: managesieve_command")
        .expect("trigger")];
    let get = before
        .find(r#""command":"GETSCRIPT""#)
        .expect("GETSCRIPT listed");
    let delete = before
        .find(r#""command":"DELETESCRIPT""#)
        .expect("DELETESCRIPT listed");
    assert!(
        get < delete,
        "earlier commands are listed in the order sent"
    );

    // === Batching on, one answer short: NO (TRYLATER) to each, and still in step. ===
    let (lines, _) = run(Mode::OnShortAnswer).await;
    assert_eq!(lines[..2], expected[..2]);
    for line in &lines[2..5] {
        assert!(
            line.starts_with("NO (TRYLATER)"),
            "an answer one short must refuse every pipelined command: {lines:?}"
        );
    }
    assert_eq!(
        lines[5], "OK \"havespace completed.\"",
        "the next command must be answered as its own: {lines:?}"
    );
}

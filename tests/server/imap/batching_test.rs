//! Pipelined IMAP commands that arrive while the model is answering are answered together —
//! each command's untagged data, then its own tagged completion, in the order sent.
//!
//! Batching is `Off` by default for IMAP (see `metadata()`), so every run here sets it. The
//! client sends `a1 NOOP`, whose answer the mock delays, and while that call is running
//! pipelines `a2 LIST "" *`, `a3 STATUS INBOX (MESSAGES)` and `a4 NOOP` in one write. One test
//! holds three runs: the control with batching off (four calls), batching on (two calls,
//! identical lines in the same order, every completion carrying its own tag), and batching on
//! with an answer whose last command has no completion (`<tag> NO` to each pipelined command,
//! after which the next command is answered normally).

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
        .expect("an IMAP line within 30s")
        .expect("read");
    assert!(n > 0, "connection closed before a reply");
    line.trim_end().to_string()
}

fn ok(tag: &str, message: &str) -> serde_json::Value {
    serde_json::json!({"type": "send_imap_response", "tag": tag, "status": "OK", "message": message})
}

fn untagged(response_type: &str, data: &str) -> serde_json::Value {
    serde_json::json!({"type": "send_imap_untagged", "response_type": response_type, "data": data})
}

fn answer_for(tag: &str) -> Vec<serde_json::Value> {
    match tag {
        "a2" => vec![
            serde_json::json!({"type": "send_imap_list", "mailboxes": [{"name": "INBOX", "delimiter": "/"}]}),
            ok("a2", "list done"),
        ],
        "a3" => vec![
            untagged("STATUS", "INBOX (MESSAGES 2)"),
            ok("a3", "status done"),
        ],
        other => vec![ok(other, "noop done")],
    }
}

async fn run(mode: Mode) -> (Vec<String>, Vec<(String, serde_json::Value)>) {
    let mut batched_answer: Vec<serde_json::Value> = ["a2", "a3", "a4"]
        .iter()
        .flat_map(|t| answer_for(t))
        .collect();
    if mode == Mode::OnShortAnswer {
        batched_answer.pop();
    }
    let mock = MockOllamaServer::start(
        MockLlmBuilder::new()
            .on_event("imap_connection")
            .respond_with_actions(serde_json::json!([
                {"type": "send_imap_greeting", "hostname": "imap.test"}
            ]))
            .expect_calls(1)
            .and()
            .on_event("imap_command")
            .and_event_data_contains("tag", "a4")
            .and_prompt_containing("answers all 3 together")
            .respond_with_actions(serde_json::Value::Array(batched_answer))
            .expect_calls(if mode == Mode::Off { 0 } else { 1 })
            .and()
            .on_event("imap_command")
            .and_event_data_contains("tag", "a1")
            .respond_with_actions(serde_json::json!([ok("a1", "noop done")]))
            .after_delay(Duration::from_millis(1500))
            .expect_calls(1)
            .and()
            .on_event("imap_command")
            .respond_with_actions_from_event(|event| {
                serde_json::Value::Array(answer_for(event["tag"].as_str().unwrap_or_default()))
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
        protocol: "imap".to_string(),
        port: Some(0),
        instruction: Some("One mailbox, INBOX, with two messages.".to_string()),
        batching: Some(mode != Mode::Off),
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .expect("create imap server");
    let port = wait_for_port(&state, id).await;

    let stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    let greeting = read_reply(&mut reader).await;
    assert!(greeting.starts_with("* OK"), "greeting: {greeting}");

    write_half.write_all(b"a1 NOOP\r\n").await.expect("write");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while mock.call_count().await < 2 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "a1 never reached the model"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    write_half
        .write_all(b"a2 LIST \"\" *\r\na3 STATUS INBOX (MESSAGES)\r\na4 NOOP\r\n")
        .await
        .expect("write");
    let mut lines = Vec::new();
    loop {
        let line = read_reply(&mut reader).await;
        let done = line.starts_with("a4 ");
        lines.push(line);
        if done {
            break;
        }
    }
    if mode == Mode::OnShortAnswer {
        write_half.write_all(b"a5 NOOP\r\n").await.expect("write");
        lines.push(read_reply(&mut reader).await);
    }

    mock.verify_calls().await.expect("mock expectations");
    let calls = mock
        .recorded_calls()
        .await
        .into_iter()
        .filter(|c| c.context.event_type.as_deref() == Some("imap_command"))
        .map(|c| (c.context.prompt.clone(), c.context.event_data.clone()))
        .collect();
    let _ = state.remove_server(id).await;
    (lines, calls)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pipelined_commands_are_answered_together_each_with_its_own_tag() {
    let expected = [
        "a1 OK noop done",
        "* LIST () \"/\" \"INBOX\"",
        "a2 OK list done",
        "* STATUS INBOX (MESSAGES 2)",
        "a3 OK status done",
        "a4 OK noop done",
    ];

    // === Control: batching off. One call per command, lines in command order. ===
    let (lines, calls) = run(Mode::Off).await;
    assert_eq!(
        calls.len(),
        4,
        "CONTROL FAILED: with batching off every command must be its own model call: {:#?}",
        calls.iter().map(|(_, d)| d).collect::<Vec<_>>()
    );
    assert_eq!(lines, expected, "CONTROL FAILED: lines out of order");

    // === Batching on: the three pipelined commands are one call, the wire is unchanged. ===
    let (lines, calls) = run(Mode::On).await;
    assert_eq!(
        calls.len(),
        2,
        "the three commands pipelined during a1's call must be answered in one: {:#?}",
        calls.iter().map(|(_, d)| d).collect::<Vec<_>>()
    );
    assert_eq!(
        lines, expected,
        "each pipelined command must get its own data and its own tagged completion, in order"
    );
    let (prompt, trigger) = &calls[1];
    assert_eq!(trigger["tag"], "a4", "the newest command is the trigger");
    assert!(
        trigger["answer_with"]
            .as_str()
            .is_some_and(|a| a.contains("tag a4")),
        "a batched command is told to complete with its own tag: {trigger}"
    );
    let before = &prompt[..prompt.rfind("Event ID: imap_command").expect("trigger")];
    let list = before.find("\"a2\"").expect("a2 listed");
    let status = before.find("\"a3\"").expect("a3 listed");
    assert!(
        list < status,
        "earlier commands are listed in the order sent"
    );

    // === Batching on, a4 left without a completion: NO to each, and still in step. ===
    let (lines, _) = run(Mode::OnShortAnswer).await;
    assert_eq!(lines[0], "a1 OK noop done");
    for (line, tag) in lines[1..4].iter().zip(["a2", "a3", "a4"]) {
        assert!(
            line.starts_with(&format!("{tag} NO ")),
            "an unusable batch answer must refuse every pipelined command with its own tag, \
             and write none of the model's data: {lines:?}"
        );
    }
    assert_eq!(
        lines[4], "a5 OK noop done",
        "the next command must be answered as its own: {lines:?}"
    );
}

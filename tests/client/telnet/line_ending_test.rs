//! What each Telnet client action puts on the wire, read from the server's side of the socket.
//!
//! Telnet servers are line-oriented: a line exists when its end of line (RFC 854's CRLF) has
//! arrived, and an answer sent without one is never read. A small model answering a quiz
//! question with `send_text` was the case that showed it (the restart-check measurement in the
//! root `AGENTS.md`). So the bytes are pinned here exactly, on every path an action can take:
//!
//! - the model's answer to `telnet_connected`, which ran its own copy of the executor;
//! - the model's answer to `telnet_data_received`;
//! - an action injected with `send_to_client` (the dashboard's `[ send ]`, MCP).
//!
//! `send_command` is one line ending in exactly one CRLF — a line ending the model wrote itself
//! is not doubled — and `send_text` is the text with nothing added. A local listener plays the
//! server; the model is a mock. The prompt the model was shown for the question is checked too:
//! it must name `send_command` as the usual answer, which is what steers a model to a line.

use std::time::Duration;

use crate::helpers::mock_builder::MockLlmBuilder;
use crate::helpers::mock_ollama::MockOllamaServer;
use netget::cli::management::ClientForm;
use netget::state::app_state::AppState;
use netget::state::client_handles::ClientSendOutcome;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

/// Read exactly `want.len()` bytes, then check nothing else follows within a short window, so
/// a doubled line ending or a line ending added to `send_text` is caught rather than left
/// unread in the socket.
async fn expect_exactly(socket: &mut TcpStream, want: &[u8], what: &str) {
    let mut got = vec![0u8; want.len()];
    tokio::time::timeout(Duration::from_secs(20), socket.read_exact(&mut got))
        .await
        .unwrap_or_else(|_| panic!("{what}: nothing arrived within 20 s"))
        .unwrap_or_else(|e| panic!("{what}: read failed: {e}"));
    let mut extra = [0u8; 64];
    let more = match tokio::time::timeout(Duration::from_millis(400), socket.read(&mut extra)).await
    {
        Ok(Ok(n)) => extra[..n].to_vec(),
        _ => Vec::new(),
    };
    assert_eq!(
        (
            String::from_utf8_lossy(&got).to_string(),
            String::from_utf8_lossy(&more).to_string()
        ),
        (String::from_utf8_lossy(want).to_string(), String::new()),
        "{what}: the server must receive exactly these bytes and nothing after them"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn each_action_puts_exactly_its_bytes_on_the_wire() {
    let mock = MockOllamaServer::start(
        MockLlmBuilder::new()
            // The model writes its own line ending, as llama3.1:8b did in the measurement.
            .on_event("telnet_connected")
            .respond_with_actions(serde_json::json!([
                {"type": "send_command", "command": "hello\r\n"}
            ]))
            .expect_calls(1)
            .and()
            .on_event("telnet_data_received")
            .and_event_data_contains("data", "Question 1")
            .respond_with_actions(serde_json::json!([
                {"type": "send_command", "command": "Paris"}
            ]))
            .expect_calls(1)
            .and()
            .on_event("telnet_data_received")
            .and_event_data_contains("data", "Press a key")
            .respond_with_actions(serde_json::json!([
                {"type": "send_text", "text": "y"}
            ]))
            .expect_calls(1)
            .and()
            .build(),
    )
    .await
    .expect("mock ollama");

    let state = AppState::new_with_options(false, mock.base_url());
    let llm = netget::llm::OllamaClient::new(mock.base_url());
    state.set_llm_client(llm.clone()).await;

    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("bind");
    let port = listener.local_addr().unwrap().port();

    let (tx, _rx) = mpsc::unbounded_channel();
    let id = ClientForm {
        protocol: "telnet".to_string(),
        remote_addr: Some(format!("127.0.0.1:{port}")),
        instruction: Some("Say hello, then answer each question.".to_string()),
        batching: Some(false),
        restart_check: Some(false),
        ..Default::default()
    }
    .create(&state, llm, tx)
    .await
    .expect("create client");

    let (mut socket, _) = tokio::time::timeout(Duration::from_secs(10), listener.accept())
        .await
        .expect("client never connected")
        .expect("accept");

    // The connect event's answer: one line, its own CRLF not doubled.
    expect_exactly(
        &mut socket,
        b"hello\r\n",
        "send_command on telnet_connected",
    )
    .await;

    // An answer to a line from the server: one line.
    socket
        .write_all(b"Welcome. Question 1: what is the capital of France?\r\n")
        .await
        .expect("write");
    expect_exactly(
        &mut socket,
        b"Paris\r\n",
        "send_command on telnet_data_received",
    )
    .await;

    // send_text: the characters and nothing else.
    socket.write_all(b"Press a key: ").await.expect("write");
    expect_exactly(&mut socket, b"y", "send_text on telnet_data_received").await;

    // Injected actions run the same executor.
    let outcome = state
        .send_to_client(
            id,
            serde_json::json!({"type": "send_command", "command": "status"}),
            Duration::from_secs(10),
        )
        .await
        .expect("inject send_command");
    assert!(
        matches!(outcome, ClientSendOutcome::Sent { bytes_sent: 8 }),
        "injected send_command: {outcome:?}"
    );
    expect_exactly(&mut socket, b"status\r\n", "injected send_command").await;

    let outcome = state
        .send_to_client(
            id,
            serde_json::json!({"type": "send_text", "text": "no newline"}),
            Duration::from_secs(10),
        )
        .await
        .expect("inject send_text");
    assert!(
        matches!(outcome, ClientSendOutcome::Sent { bytes_sent: 10 }),
        "injected send_text: {outcome:?}"
    );
    expect_exactly(&mut socket, b"no newline", "injected send_text").await;

    // What the model was shown when the question arrived.
    let calls = mock.recorded_calls().await;
    let question = calls
        .iter()
        .find(|c| {
            c.context.event_type.as_deref() == Some("telnet_data_received")
                && c.context.event_data.to_string().contains("Question 1")
        })
        .expect("the question reached the model");
    let prompt = &question.context.prompt;
    assert!(
        prompt.contains("Reply with send_command (one line, the usual answer)"),
        "the event must name send_command as the usual answer:\n{prompt}"
    );
    assert!(
        prompt.contains("This is the normal way to answer anything the server says."),
        "send_command must be described as the way to answer:\n{prompt}"
    );
    assert!(
        prompt.contains("so do not use it to answer a question or a prompt"),
        "send_text must say it is not for answers:\n{prompt}"
    );

    mock.wait_for_expectations(30).await;
    mock.verify_calls().await.expect("mock expectations");
    let _ = state.remove_client(id).await;
}

//! Command lines an operator sends while the model is answering are answered together.
//!
//! The first command is answered slowly; two more arrive during that call. With batching off
//! each must be its own model call — the control, without which the batched result below
//! could be a mock that never saw the later lines at all. With batching on the two must come
//! back as one call whose trigger is the newest command and whose prompt lists the earlier one
//! as arrived and not yet answered. Control and claim are one test, so a dead control takes
//! the claim down with it.

use std::time::Duration;

use crate::helpers::mock_builder::MockLlmBuilder;
use crate::helpers::mock_ollama::MockOllamaServer;
use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use netget::state::ServerId;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

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

async fn read_until(stream: &mut tokio::net::TcpStream, needle: &str) {
    let mut seen = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let mut buf = [0u8; 1024];
    while !String::from_utf8_lossy(&seen).contains(needle) {
        let n = tokio::time::timeout_at(deadline, stream.read(&mut buf))
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "no {needle:?} arrived; read so far: {:?}",
                    String::from_utf8_lossy(&seen)
                )
            })
            .expect("read");
        assert!(
            n > 0,
            "closed before {needle:?}; read so far: {:?}",
            String::from_utf8_lossy(&seen)
        );
        seen.extend_from_slice(&buf[..n]);
    }
}

/// Send `first`, then — while the model answers it — `second` and `third` in one write, and
/// return `(prompt, event data)` for every `reverse_shell_command` call.
async fn prompts_for_three_commands(batching: bool) -> Vec<(String, serde_json::Value)> {
    let mock = MockOllamaServer::start(
        MockLlmBuilder::new()
            .on_event("reverse_shell_session_opened")
            .respond_with_actions(serde_json::json!([
                { "type": "send_shell_prompt", "prompt": "$ " }
            ]))
            .expect_calls(1)
            .and()
            .on_event("reverse_shell_command")
            .and_event_data_contains("command", "first")
            .respond_with_actions(serde_json::json!([
                { "type": "send_shell_output", "output": "got first\n" }
            ]))
            .after_delay(Duration::from_millis(1500))
            .expect_calls(1)
            .and()
            .on_event("reverse_shell_command")
            .respond_with_actions_from_event(|event| {
                let command = event["command"].as_str().unwrap_or_default().to_string();
                serde_json::json!([{ "type": "send_shell_output", "output": format!("got {command}\n") }])
            })
            .expect_at_least(1)
            .and()
            .on_any()
            .respond_with_actions(serde_json::json!([]))
            .expect_at_least(0)
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
        protocol: "reverse-shell".to_string(),
        port: Some(0),
        instruction: Some("Emulate a shell.".to_string()),
        batching: Some(batching),
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .expect("create reverse-shell listener");
    let port = wait_for_port(&state, id).await;

    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    read_until(&mut stream, "$ ").await;

    stream.write_all(b"first\n").await.expect("write");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let command_calls = |calls: Vec<crate::helpers::mock_config::MockCallRecord>| {
        calls
            .into_iter()
            .filter(|c| c.context.event_type.as_deref() == Some("reverse_shell_command"))
            .collect::<Vec<_>>()
    };
    while command_calls(mock.recorded_calls().await).is_empty() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the first command never reached the model"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    stream.write_all(b"second\nthird\n").await.expect("write");
    read_until(&mut stream, "got third").await;

    let prompts = command_calls(mock.recorded_calls().await)
        .into_iter()
        .map(|c| (c.context.prompt.clone(), c.context.event_data.clone()))
        .collect();
    let _ = state.remove_server(id).await;
    prompts
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reverse_shell_commands_sent_during_a_call_are_answered_together() {
    // === Control: batching off. Every command is its own call. ===
    let separate = prompts_for_three_commands(false).await;
    assert_eq!(
        separate.len(),
        3,
        "CONTROL FAILED: with batching off each command must be its own model call, or the \
         two-call result below proves nothing. Got {} calls: {:#?}",
        separate.len(),
        separate.iter().map(|(_, d)| d).collect::<Vec<_>>()
    );

    // === The claim: the two commands sent during the slow call come back as one. ===
    let batched = prompts_for_three_commands(true).await;
    assert_eq!(
        batched.len(),
        2,
        "the two commands sent during the first call must be answered in one follow-up call; \
         got {} calls: {:#?}",
        batched.len(),
        batched.iter().map(|(_, d)| d).collect::<Vec<_>>()
    );
    let (prompt, current) = &batched[1];
    assert_eq!(
        current["command"], "third",
        "the newest command is the batch's trigger"
    );
    let trigger_at = prompt
        .rfind("Event ID: reverse_shell_command")
        .expect("trigger");
    let before = &prompt[..trigger_at];
    assert!(
        before.contains(r#"(1) reverse_shell_command {"command":"second""#),
        "the earlier command must be listed as arrived and not yet answered:\n{prompt}"
    );
    assert!(
        before.contains("answers all 2 together"),
        "the model must be told it answers both:\n{prompt}"
    );
}

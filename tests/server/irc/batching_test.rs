//! Lines an IRC peer sends while the model is answering are answered together.
//!
//! The first line is answered slowly; two more arrive during that call. With batching off
//! each must be its own model call — the control, without which the batched result below
//! could be a mock that never saw the later lines at all. With batching on the two must come
//! back as one call whose trigger is the newest line and whose prompt lists the earlier one
//! as arrived and not yet answered. Control and claim are one test, so a dead control takes
//! the claim down with it.

use std::time::Duration;

use crate::helpers::mock_builder::MockLlmBuilder;
use crate::helpers::mock_ollama::MockOllamaServer;
use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use netget::state::ServerId;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
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

async fn read_until<R: tokio::io::AsyncBufRead + Unpin>(reader: &mut R, needle: &str) {
    let mut seen = String::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let mut line = String::new();
        let read = tokio::time::timeout_at(deadline, reader.read_line(&mut line))
            .await
            .unwrap_or_else(|_| panic!("no line containing {needle:?}; read so far: {seen:?}"))
            .expect("read");
        assert!(read > 0, "closed before {needle:?}; read so far: {seen:?}");
        seen.push_str(&line);
        if line.contains(needle) {
            return;
        }
    }
}

/// Send `PRIVMSG #c :first`, then — while the model answers it — two more PRIVMSGs in one
/// write, and return `(prompt, event data)` for every `irc_message_received` call.
async fn prompts_for_three_lines(batching: bool) -> Vec<(String, serde_json::Value)> {
    let mock = MockOllamaServer::start(
        MockLlmBuilder::new()
            .on_event("irc_message_received")
            .and_event_data_contains("message", "first")
            .respond_with_actions(serde_json::json!([
                { "type": "send_irc_message", "message": ":netget NOTICE tester :got first" }
            ]))
            .after_delay(Duration::from_millis(1500))
            .expect_calls(1)
            .and()
            .on_event("irc_message_received")
            .respond_with_actions_from_event(|event| {
                let message = event["message"].as_str().unwrap_or_default();
                let word = message.rsplit(':').next().unwrap_or_default().to_string();
                serde_json::json!([{
                    "type": "send_irc_message",
                    "message": format!(":netget NOTICE tester :got {word}")
                }])
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
        protocol: "irc".to_string(),
        port: Some(0),
        instruction: Some("Acknowledge every message.".to_string()),
        batching: Some(batching),
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .expect("create irc server");
    let port = wait_for_port(&state, id).await;

    let stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    write_half
        .write_all(b"PRIVMSG #c :first\r\n")
        .await
        .expect("write");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while mock.call_count().await == 0 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the first line never reached the model"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    write_half
        .write_all(b"PRIVMSG #c :second\r\nPRIVMSG #c :third\r\n")
        .await
        .expect("write");
    read_until(&mut reader, "got third").await;

    let prompts = mock
        .recorded_calls()
        .await
        .into_iter()
        .filter(|c| c.context.event_type.as_deref() == Some("irc_message_received"))
        .map(|c| (c.context.prompt.clone(), c.context.event_data.clone()))
        .collect();
    let _ = state.remove_server(id).await;
    prompts
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn irc_lines_sent_during_a_call_are_answered_together() {
    // === Control: batching off. Every line is its own call. ===
    let separate = prompts_for_three_lines(false).await;
    assert_eq!(
        separate.len(),
        3,
        "CONTROL FAILED: with batching off each line must be its own model call, or the \
         two-call result below proves nothing. Got {} calls: {:#?}",
        separate.len(),
        separate.iter().map(|(_, d)| d).collect::<Vec<_>>()
    );

    // === The claim: the two lines that arrived during the slow call come back as one. ===
    let batched = prompts_for_three_lines(true).await;
    assert_eq!(
        batched.len(),
        2,
        "the two lines sent during the first call must be answered in one follow-up call; \
         got {} calls: {:#?}",
        batched.len(),
        batched.iter().map(|(_, d)| d).collect::<Vec<_>>()
    );
    let (prompt, current) = &batched[1];
    assert_eq!(
        current["message"], "PRIVMSG #c :third",
        "the newest line is the batch's trigger"
    );
    let trigger_at = prompt
        .rfind("Event ID: irc_message_received")
        .expect("trigger");
    let before = &prompt[..trigger_at];
    assert!(
        before.contains(r#"(1) irc_message_received {"message":"PRIVMSG #c :second"}"#),
        "the earlier line must be listed as arrived and not yet answered:\n{prompt}"
    );
    assert!(
        before.contains("answers all 2 together"),
        "the model must be told it answers both:\n{prompt}"
    );
}

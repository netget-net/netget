//! Pipelined RCPT commands (RFC 2033 requires PIPELINING) that arrive while the model is
//! deciding an earlier recipient are decided together — and every RCPT still gets exactly its
//! own reply, in order.
//!
//! After LHLO and MAIL, the client sends `RCPT TO:<b>`, whose decision the mock delays, and
//! while that call is running pipelines `RCPT TO:<c>` and `RCPT TO:<d>` in one write. One test
//! holds three runs: the control with batching off (three recipient calls), batching on (two
//! calls, identical replies in the same order), and batching on with an answer one decision
//! short (`451 4.3.0` to both pipelined
//! RCPTs — neither accepted — after which the session is still in step).

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
        .expect("an LMTP reply within 30s")
        .expect("read");
    assert!(n > 0, "connection closed before a reply");
    line.trim_end().to_string()
}

/// Read one possibly multi-line reply and return its last line.
async fn read_final<R: tokio::io::AsyncBufRead + Unpin>(reader: &mut R) -> String {
    loop {
        let line = read_reply(reader).await;
        if line.as_bytes().get(3) != Some(&b'-') {
            return line;
        }
    }
}

fn decide(accept: bool) -> serde_json::Value {
    serde_json::json!({"type": "lmtp_recipient_reply", "accept": accept})
}

async fn run(mode: Mode) -> (Vec<String>, Vec<(String, serde_json::Value)>) {
    let mut batched_answer = vec![decide(false), decide(true)];
    if mode == Mode::OnShortAnswer {
        batched_answer.pop();
    }
    let mock = MockOllamaServer::start(
        MockLlmBuilder::new()
            .on_event("lmtp_recipient")
            .and_event_data_contains("recipient", "d@example.test")
            .and_prompt_containing("answers all 2 together")
            .respond_with_actions(serde_json::Value::Array(batched_answer))
            .expect_calls(if mode == Mode::Off { 0 } else { 1 })
            .and()
            .on_event("lmtp_recipient")
            .and_event_data_contains("recipient", "b@example.test")
            .respond_with_actions(serde_json::json!([decide(true)]))
            .after_delay(Duration::from_millis(1500))
            .expect_calls(1)
            .and()
            .on_event("lmtp_recipient")
            .respond_with_actions_from_event(|event| {
                let recipient = event["recipient"].as_str().unwrap_or_default();
                serde_json::json!([decide(!recipient.starts_with("c@"))])
            })
            .expect_calls(match mode {
                Mode::Off => 2,
                Mode::On => 0,
                Mode::OnShortAnswer => 0,
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
        protocol: "lmtp".to_string(),
        port: Some(0),
        instruction: Some("Mailboxes b and d exist; c does not.".to_string()),
        batching: Some(mode != Mode::Off),
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .expect("create lmtp server");
    let port = wait_for_port(&state, id).await;

    let stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    assert!(read_reply(&mut reader).await.starts_with("220"));
    write_half
        .write_all(b"LHLO client.test\r\n")
        .await
        .expect("write");
    assert!(read_final(&mut reader).await.starts_with("250 "));
    write_half
        .write_all(b"MAIL FROM:<a@example.test>\r\n")
        .await
        .expect("write");
    assert!(read_reply(&mut reader).await.starts_with("250 "));

    write_half
        .write_all(b"RCPT TO:<b@example.test>\r\n")
        .await
        .expect("write");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while mock.call_count().await < 1 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "RCPT b never reached the model"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    write_half
        .write_all(b"RCPT TO:<c@example.test>\r\nRCPT TO:<d@example.test>\r\n")
        .await
        .expect("write");
    let mut replies = Vec::new();
    for _ in 0..3 {
        replies.push(read_reply(&mut reader).await);
    }
    // Still in step: the next command's reply is its own.
    write_half.write_all(b"NOOP\r\n").await.expect("write");
    replies.push(read_reply(&mut reader).await);

    mock.verify_calls().await.expect("mock expectations");
    let calls = mock
        .recorded_calls()
        .await
        .into_iter()
        .filter(|c| c.context.event_type.as_deref() == Some("lmtp_recipient"))
        .map(|c| (c.context.prompt.clone(), c.context.event_data.clone()))
        .collect();
    let _ = state.remove_server(id).await;
    (replies, calls)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pipelined_recipients_are_decided_together_one_reply_each() {
    let codes = |replies: &[String]| -> Vec<String> {
        replies
            .iter()
            .map(|r| r[..9.min(r.len())].to_string())
            .collect()
    };
    let expected = ["250 2.1.5", "550 5.1.1", "250 2.1.5", "250 2.0.0"];

    // === Control: batching off. One call per RCPT, replies in RCPT order. ===
    let (replies, calls) = run(Mode::Off).await;
    assert_eq!(
        calls.len(),
        3,
        "CONTROL FAILED: with batching off every RCPT must be its own model call: {:#?}",
        calls.iter().map(|(_, d)| d).collect::<Vec<_>>()
    );
    assert_eq!(codes(&replies), expected, "CONTROL FAILED: {replies:?}");
    assert!(replies[0].contains("<b@example.test>") && replies[2].contains("<d@example.test>"));

    // === Batching on: the two pipelined RCPTs are one call, the wire is unchanged. ===
    let (replies, calls) = run(Mode::On).await;
    assert_eq!(
        calls.len(),
        2,
        "the two RCPTs pipelined during b's call must be decided in one: {:#?}",
        calls.iter().map(|(_, d)| d).collect::<Vec<_>>()
    );
    assert_eq!(
        codes(&replies),
        expected,
        "each pipelined RCPT must get its own reply, in order: {replies:?}"
    );
    assert!(
        replies[2].contains("<d@example.test>"),
        "d's acceptance must name d: {replies:?}"
    );
    let (prompt, trigger) = &calls[1];
    assert_eq!(
        trigger["recipient"], "d@example.test",
        "the newest RCPT is the trigger"
    );
    let before = &prompt[..prompt.rfind("Event ID: lmtp_recipient").expect("trigger")];
    assert!(
        before.contains("c@example.test"),
        "the earlier RCPT must be listed above the trigger:\n{prompt}"
    );

    // === Batching on, one decision short: 451 to both, nothing accepted, still in step. ===
    let (replies, _) = run(Mode::OnShortAnswer).await;
    assert_eq!(
        codes(&replies),
        ["250 2.1.5", "451 4.3.0", "451 4.3.0", "250 2.0.0"],
        "an answer one decision short must refuse every pipelined RCPT temporarily: {replies:?}"
    );
}

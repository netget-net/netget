//! Does the IRC client answer the lines its server sent during a model call together, when it
//! batches - and does it still answer PING while the model is busy?
//!
//! The client used to call the model inline in its read loop, so nothing was read while the
//! model was answering: lines waited in the kernel, and so did the server's PING, which a
//! server with a ping timeout counts against the client. A reader task now answers PING
//! itself and queues every other line; the answering loop takes one line per call (off) or
//! hands every line waiting to `call_llm_for_client_batch` (on), one event per line.
//!
//! A raw `TcpListener` plays the server: it welcomes the client (001), sends a PRIVMSG
//! `first`, which the mock model answers slowly, then `second`, a PING, and `third` during that
//! call. Batching off is the control, in the same test as the claim: it must give three model
//! calls, or a two-call result would prove nothing.

use std::time::Duration;

use crate::helpers::mock_builder::MockLlmBuilder;
use crate::helpers::mock_ollama::MockOllamaServer;
use netget::cli::management::ClientForm;
use netget::state::app_state::AppState;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::mpsc;

const DATA_EVENT: &str = "irc_message_received";

/// One session: returns the (message, prompt) of every message event the model was asked
/// about, in order.
async fn session(batching: bool) -> Vec<(String, String)> {
    let mock = MockOllamaServer::start(
        MockLlmBuilder::new()
            .on_event(DATA_EVENT)
            .and_event_data_contains("message", "first")
            .respond_with_actions(serde_json::json!([]))
            .after_delay(Duration::from_millis(1500))
            .expect_calls(1)
            .and()
            .on_any()
            .respond_with_actions(serde_json::json!([]))
            .expect_at_least(0)
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
        protocol: "irc".to_string(),
        remote_addr: Some(format!("127.0.0.1:{port}")),
        instruction: Some("Note what is said in the channel.".to_string()),
        batching: Some(batching),
        ..Default::default()
    }
    .create(&state, llm, tx)
    .await
    .expect("create client");
    let (socket, _) = tokio::time::timeout(Duration::from_secs(10), listener.accept())
        .await
        .expect("client never connected")
        .expect("accept");
    let (read, mut write) = socket.into_split();
    let mut lines = BufReader::new(read).lines();

    // Registration: NICK and USER, then the welcome that tells the client it is in.
    for _ in 0..2 {
        tokio::time::timeout(Duration::from_secs(10), lines.next_line())
            .await
            .expect("registration")
            .expect("read")
            .expect("line");
    }
    write
        .write_all(b":irc.test 001 netget_user :Welcome\r\n")
        .await
        .expect("write");

    let data_calls = |calls: Vec<crate::helpers::mock_config::MockCallRecord>| {
        calls
            .into_iter()
            .filter(|c| c.context.event_type.as_deref() == Some(DATA_EVENT))
            .map(|c| {
                (
                    c.context.event_data["message"]
                        .as_str()
                        .unwrap_or_default()
                        .to_string(),
                    c.context.prompt.clone(),
                )
            })
            .collect::<Vec<_>>()
    };

    write
        .write_all(b":alice!a@host PRIVMSG #chan :first\r\n")
        .await
        .expect("write");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    while data_calls(mock.recorded_calls().await).is_empty() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "`first` never reached the model"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // During the slow first call: a message, a PING that must be answered now rather than
    // after the call, and another message.
    write
        .write_all(b":alice!a@host PRIVMSG #chan :second\r\n")
        .await
        .expect("write");
    write.write_all(b"PING :cookie\r\n").await.expect("write");
    let pong = tokio::time::timeout(Duration::from_millis(1000), lines.next_line())
        .await
        .expect("PING was not answered while the model was busy")
        .expect("read")
        .expect("line");
    assert_eq!(pong, "PONG :cookie");
    write
        .write_all(b":alice!a@host PRIVMSG #chan :third\r\n")
        .await
        .expect("write");

    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        let calls = data_calls(mock.recorded_calls().await);
        if calls.iter().any(|(m, _)| m == "third") {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "`third` never reached the model; calls: {:?}",
            calls.iter().map(|(m, _)| m).collect::<Vec<_>>()
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // Room for a stray extra call to show up before counting.
    tokio::time::sleep(Duration::from_millis(500)).await;

    let calls = data_calls(mock.recorded_calls().await);
    let _ = state.remove_client(id).await;
    calls
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn irc_client_answers_what_arrived_during_a_call_together() {
    let separate = session(false).await;
    let messages: Vec<&str> = separate.iter().map(|(m, _)| m.as_str()).collect();
    assert_eq!(
        messages,
        vec!["first", "second", "third"],
        "CONTROL FAILED: with batching off each line must be its own model call"
    );

    let batched = session(true).await;
    let messages: Vec<&str> = batched.iter().map(|(m, _)| m.as_str()).collect();
    assert_eq!(
        messages,
        vec!["first", "third"],
        "the two lines that arrived during the first call must be one model call, triggered \
         by the newest"
    );
    let prompt = &batched[1].1;
    let trigger_at = prompt
        .rfind("Event: irc_message_received")
        .expect("trigger");
    let before = &prompt[..trigger_at];
    let listed = before
        .find("(1) irc_message_received")
        .expect("the earlier line must be listed as arrived and not yet answered");
    assert!(
        before[listed..].contains("second"),
        "the listed event must be the `second` line:\n{prompt}"
    );
    assert!(
        before.contains("answers all 2 together"),
        "the model must be told it answers both:\n{prompt}"
    );
}

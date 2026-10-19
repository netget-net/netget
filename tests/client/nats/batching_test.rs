//! Does the NATS client answer the messages that arrived during a model call together, when it
//! batches?
//!
//! A hand-written broker (`INFO`, then `MSG` frames) sends `first`, which the mock model answers
//! slowly, then `second` and `third` while that call is running. They wait on the
//! reader→dispatcher queue. Batching off is the control, in the same test as the claim: three
//! model calls, one per message. Batching on: two — `first`, then one call triggered by `third`
//! with `second` listed above it as arrived and not yet answered.
//!
//! The peer is a fake rather than `nats-server` because the property under test is the
//! client's own queueing, not interoperability (`e2e_test.rs` covers that).

use std::time::Duration;

use crate::helpers::mock_builder::MockLlmBuilder;
use crate::helpers::mock_ollama::MockOllamaServer;
use netget::cli::management::ClientForm;
use netget::state::app_state::AppState;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

const EVENT: &str = "nats_message_received";

/// One `MSG` on subject `t`, sid 1.
fn publish(payload: &str) -> Vec<u8> {
    format!("MSG t 1 {}\r\n{payload}\r\n", payload.len()).into_bytes()
}

/// Greet the client and swallow whatever it writes (CONNECT, PING) for the whole session.
async fn accept_connect(socket: &mut TcpStream) {
    socket
        .write_all(b"INFO {\"server_id\":\"fake\",\"max_payload\":1048576}\r\n")
        .await
        .expect("INFO");
    let mut buf = vec![0u8; 4096];
    let n = socket.read(&mut buf).await.expect("CONNECT");
    assert!(
        buf[..n].starts_with(b"CONNECT "),
        "the client must answer INFO with CONNECT"
    );
}

async fn session(batching: bool) -> Vec<(serde_json::Value, String)> {
    let mock = MockOllamaServer::start(
        MockLlmBuilder::new()
            .on_event(EVENT)
            .and_event_data_contains("payload", "first")
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
    let create = tokio::spawn({
        let state = state.clone();
        async move {
            ClientForm {
                protocol: "nats".to_string(),
                remote_addr: Some(format!("127.0.0.1:{port}")),
                instruction: Some("Note what the broker delivers.".to_string()),
                batching: Some(batching),
                ..Default::default()
            }
            .create(&state, llm, tx)
            .await
            .expect("create client")
        }
    });

    let (mut socket, _) = tokio::time::timeout(Duration::from_secs(10), listener.accept())
        .await
        .expect("client never connected")
        .expect("accept");
    accept_connect(&mut socket).await;
    let id = create.await.expect("create task");

    let data_calls = |calls: Vec<crate::helpers::mock_config::MockCallRecord>| {
        calls
            .into_iter()
            .filter(|c| c.context.event_type.as_deref() == Some(EVENT))
            .map(|c| (c.context.event_data.clone(), c.context.prompt.clone()))
            .collect::<Vec<_>>()
    };

    socket.write_all(&publish("first")).await.expect("write");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    while data_calls(mock.recorded_calls().await).is_empty() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "`first` never reached the model"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // Both arrive while the slow first call is still running.
    socket.write_all(&publish("second")).await.expect("write");
    tokio::time::sleep(Duration::from_millis(200)).await;
    socket.write_all(&publish("third")).await.expect("write");

    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        let calls = data_calls(mock.recorded_calls().await);
        if calls.iter().any(|(d, _)| d["payload"] == "third") {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "`third` never reached the model; calls: {:#?}",
            calls.iter().map(|(d, _)| d).collect::<Vec<_>>()
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
async fn nats_client_answers_messages_that_arrived_during_a_call_together() {
    let payloads = |calls: &[(serde_json::Value, String)]| {
        calls
            .iter()
            .map(|(d, _)| d["payload"].as_str().unwrap_or_default().to_string())
            .collect::<Vec<_>>()
    };

    let separate = session(false).await;
    assert_eq!(
        payloads(&separate),
        vec!["first", "second", "third"],
        "CONTROL FAILED: with batching off each message must be its own model call"
    );

    let batched = session(true).await;
    assert_eq!(
        payloads(&batched),
        vec!["first", "third"],
        "the two messages that arrived during the first call must be one model call, \
         triggered by the newest"
    );
    let prompt = &batched[1].1;
    let trigger_at = prompt.rfind(&format!("Event: {EVENT}")).expect("trigger");
    let before = &prompt[..trigger_at];
    let listed = before
        .find(&format!("(1) {EVENT} {{"))
        .map(|at| &before[at..])
        .unwrap_or_default();
    assert!(
        listed.lines().next().unwrap_or_default().contains("second"),
        "the earlier message must be listed as arrived and not yet answered:\n{prompt}"
    );
    assert!(
        before.contains("answers all 2 together"),
        "the model must be told it answers both:\n{prompt}"
    );
}

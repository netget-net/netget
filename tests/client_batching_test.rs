//! Does a client answer what its server sent during a model call together, when it batches?
//!
//! The tcp and telnet clients used to call the model inline in their read loop, so whatever
//! the server sent while the model was answering merged in the kernel buffer and arrived as
//! one read: batching off and on could not even be told apart. Each now has a reader task
//! feeding a bounded queue that keeps read boundaries, and the answering loop takes one read
//! per call (off) or everything waiting (on).
//!
//! A local listener plays the server: it sends `first`, which the mock model answers slowly,
//! then `second` and — 200 ms later, so it is a separate read — `third` during that call.
//! Batching off is the control, in the same test as the claim: it must give three model calls,
//! or a two-call result would prove nothing.
//!
//! - tcp joins what was waiting into one payload, as the tcp server does: `secondthird`.
//! - telnet goes through `call_llm_for_client_batch`, one event per read: the newest is the
//!   trigger and the earlier one is listed above it, as on the server side.

mod helpers;

use std::time::Duration;

use helpers::mock_builder::MockLlmBuilder;
use helpers::mock_ollama::MockOllamaServer;
use netget::cli::management::ClientForm;
use netget::state::app_state::AppState;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;

/// Run one client session against a local server that sends `first`, then `second` and
/// `third` while the model is answering `first`. Returns the (event data, prompt) of every
/// data event the model was asked about, in order.
async fn session(
    protocol: &str,
    data_event: &str,
    first_key: (&str, &str),
    batching: bool,
) -> Vec<(serde_json::Value, String)> {
    let mock = MockOllamaServer::start(
        MockLlmBuilder::new()
            .on_event(data_event)
            .and_event_data_contains(first_key.0, first_key.1)
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
        protocol: protocol.to_string(),
        remote_addr: Some(format!("127.0.0.1:{port}")),
        instruction: Some("Note what the server says.".to_string()),
        batching: Some(batching),
        ..Default::default()
    }
    .create(&state, llm, tx)
    .await
    .expect("create client");

    let (mut socket, _) = tokio::time::timeout(Duration::from_secs(10), listener.accept())
        .await
        .expect("client never connected")
        .expect("accept");

    let data_calls = |calls: Vec<helpers::mock_config::MockCallRecord>| {
        calls
            .into_iter()
            .filter(|c| c.context.event_type.as_deref() == Some(data_event))
            .map(|c| (c.context.event_data.clone(), c.context.prompt.clone()))
            .collect::<Vec<_>>()
    };

    socket.write_all(b"first").await.expect("write");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    while data_calls(mock.recorded_calls().await).is_empty() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "`first` never reached the model"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // Both arrive while the slow first call is still running, as two separate reads.
    socket.write_all(b"second").await.expect("write");
    tokio::time::sleep(Duration::from_millis(200)).await;
    socket.write_all(b"third").await.expect("write");

    // Wait until the model has seen `third`, however it was delivered.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        let calls = data_calls(mock.recorded_calls().await);
        if calls.iter().any(|(data, _)| {
            data.to_string().contains("third") || data.to_string().contains("7468697264")
        }) {
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

fn hex(s: &str) -> String {
    s.bytes().map(|b| format!("{b:02x}")).collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tcp_client_joins_or_separates_what_arrived_during_a_call() {
    let separate = session(
        "tcp",
        "tcp_data_received",
        ("data_hex", &hex("first")),
        false,
    )
    .await;
    let payloads: Vec<String> = separate
        .iter()
        .map(|(d, _)| d["data_hex"].as_str().unwrap_or_default().to_string())
        .collect();
    assert_eq!(
        payloads,
        vec![hex("first"), hex("second"), hex("third")],
        "CONTROL FAILED: with batching off each read must be answered on its own"
    );

    let batched = session(
        "tcp",
        "tcp_data_received",
        ("data_hex", &hex("first")),
        true,
    )
    .await;
    let payloads: Vec<String> = batched
        .iter()
        .map(|(d, _)| d["data_hex"].as_str().unwrap_or_default().to_string())
        .collect();
    assert_eq!(
        payloads,
        vec![hex("first"), hex("secondthird")],
        "with batching on everything that arrived during the call is the next payload"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn telnet_client_answers_what_arrived_during_a_call_together() {
    let separate = session("telnet", "telnet_data_received", ("data", "first"), false).await;
    let data: Vec<String> = separate
        .iter()
        .map(|(d, _)| d["data"].as_str().unwrap_or_default().to_string())
        .collect();
    assert_eq!(
        data,
        vec!["first", "second", "third"],
        "CONTROL FAILED: with batching off each read must be its own model call"
    );

    let batched = session("telnet", "telnet_data_received", ("data", "first"), true).await;
    let data: Vec<String> = batched
        .iter()
        .map(|(d, _)| d["data"].as_str().unwrap_or_default().to_string())
        .collect();
    assert_eq!(
        data,
        vec!["first", "third"],
        "the two reads that arrived during the first call must be one model call, triggered \
         by the newest"
    );
    let prompt = &batched[1].1;
    let trigger_at = prompt
        .rfind("Event: telnet_data_received")
        .expect("trigger");
    let before = &prompt[..trigger_at];
    assert!(
        before.contains(r#"(1) telnet_data_received {"data":"second"}"#),
        "the earlier read must be listed as arrived and not yet answered:\n{prompt}"
    );
    assert!(
        before.contains("answers all 2 together"),
        "the model must be told it answers both:\n{prompt}"
    );
    assert!(
        before.contains("Earlier on this connection"),
        "the session's history (the first read) must be shown too:\n{prompt}"
    );
}

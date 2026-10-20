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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tcp_client_joins_or_separates_what_arrived_during_a_call() {
    let separate = session("tcp", "tcp_data_received", ("data", "first"), false).await;
    let payloads: Vec<String> = separate
        .iter()
        .map(|(d, _)| d["data"].as_str().unwrap_or_default().to_string())
        .collect();
    assert_eq!(
        payloads,
        vec!["first", "second", "third"],
        "CONTROL FAILED: with batching off each read must be answered on its own"
    );

    let batched = session("tcp", "tcp_data_received", ("data", "first"), true).await;
    let payloads: Vec<String> = batched
        .iter()
        .map(|(d, _)| d["data"].as_str().unwrap_or_default().to_string())
        .collect();
    assert_eq!(
        payloads,
        vec!["first", "secondthird"],
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

/// The peer-to-peer runner (`server::p2p_support::connect`, shared by nntp, adc, adc_peer,
/// dc_peer, gnutella, soulseek and soulseek_peer) queues each reply as an event and answers
/// them on a turn task. The model answers the connect with three GROUP commands; each reply is
/// answered slowly, so with batching on the second and third arrive during the first's call.
async fn nntp_reply_calls(batching: bool) -> Vec<String> {
    use netget::cli::management::ServerForm;

    let mock = MockOllamaServer::start(
        MockLlmBuilder::new()
            .on_event("nntp_connected")
            .respond_with_actions(serde_json::json!([
                { "type": "nntp_group", "group_name": "alpha" },
                { "type": "nntp_group", "group_name": "bravo" },
                { "type": "nntp_group", "group_name": "charlie" }
            ]))
            .expect_calls(1)
            .and()
            .on_event("nntp_response_received")
            .respond_with_actions(serde_json::json!([]))
            .after_delay(Duration::from_millis(1500))
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
    let llm = netget::llm::OllamaClient::new(mock.base_url());
    state.set_llm_client(llm.clone()).await;
    let (tx, _rx) = mpsc::unbounded_channel();

    // A model-free server: every command is answered by a static rule.
    let server_id = ServerForm {
        protocol: "nntp".to_string(),
        port: Some(0),
        instruction: Some(String::new()),
        event_handlers: Some(vec![serde_json::json!({
            "event_pattern": "*",
            "handler": {
                "type": "static",
                "actions": [ { "type": "send_nntp_response", "code": 200, "text": "ok" } ]
            }
        })]),
        ..Default::default()
    }
    .create(&state, tx.clone())
    .await
    .expect("create nntp server");
    let mut port = 0;
    for _ in 0..300 {
        if let Some(addr) = state.get_server(server_id).await.and_then(|s| s.local_addr) {
            port = addr.port();
            break;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    assert_ne!(port, 0, "nntp server never bound");

    let client_id = ClientForm {
        protocol: "nntp".to_string(),
        remote_addr: Some(format!("127.0.0.1:{port}")),
        instruction: Some("Select three groups.".to_string()),
        batching: Some(batching),
        ..Default::default()
    }
    .create(&state, llm, tx)
    .await
    .expect("create nntp client");

    let replies = |calls: Vec<helpers::mock_config::MockCallRecord>| {
        calls
            .into_iter()
            .filter(|c| c.context.event_type.as_deref() == Some("nntp_response_received"))
            .map(|c| c.context.prompt.clone())
            .collect::<Vec<_>>()
    };
    // Every reply reaches the model one way or the other; wait for the last call to settle.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let mut last = 0;
    let mut stable_since = tokio::time::Instant::now();
    loop {
        let n = replies(mock.recorded_calls().await).len();
        if n != last {
            last = n;
            stable_since = tokio::time::Instant::now();
        }
        if n > 0 && stable_since.elapsed() > Duration::from_millis(2500) {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "replies never settled"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let prompts = replies(mock.recorded_calls().await);
    let _ = state.remove_client(client_id).await;
    let _ = state.remove_server(server_id).await;
    prompts
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn p2p_runner_answers_replies_that_arrived_during_a_call_together() {
    let separate = nntp_reply_calls(false).await;
    assert_eq!(
        separate.len(),
        3,
        "CONTROL FAILED: with batching off each of the three replies must be its own call"
    );
    let batched = nntp_reply_calls(true).await;
    assert_eq!(
        batched.len(),
        2,
        "the two replies that arrived during the first call must be answered in one call"
    );
    assert!(
        batched[1].contains("answers all 2 together"),
        "the second call must carry both replies:\n{}",
        batched[1]
    );
}

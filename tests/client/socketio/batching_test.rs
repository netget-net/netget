//! Does the Socket.IO client answer the events its server pushed during a model call together,
//! when it batches?
//!
//! The session loop already handed every server event to a dispatcher task over a queue, which
//! answered them one model call each. With batching on the dispatcher now hands every event
//! waiting to `call_llm_for_client_batch`, one event per Socket.IO EVENT packet, the newest
//! the trigger; each keeps its own `ack_id`.
//!
//! A minimal Engine.IO v4 server over tokio-tungstenite, written here, opens the session,
//! accepts the namespace CONNECT and pushes event `first`, which the mock model answers slowly,
//! then `second` and `third` during that call. Batching off is the control, in the same test
//! as the claim: it must give three model calls, or a two-call result would prove nothing.

use std::time::Duration;

use crate::helpers::mock_builder::MockLlmBuilder;
use crate::helpers::mock_ollama::MockOllamaServer;
use futures::{SinkExt, StreamExt};
use netget::cli::management::ClientForm;
use netget::state::app_state::AppState;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;

const DATA_EVENT: &str = "socketio_event";

/// One session: returns the (event name, prompt) of every server event the model was asked
/// about, in order.
async fn session(batching: bool) -> Vec<(String, String)> {
    let mock = MockOllamaServer::start(
        MockLlmBuilder::new()
            .on_event(DATA_EVENT)
            .and_event_data_contains("event", "first")
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
    // The Engine.IO open, then the namespace CONNECT answered: the session is up.
    let accepted = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.expect("accept");
        let mut ws = tokio_tungstenite::accept_async(socket)
            .await
            .expect("WebSocket handshake");
        ws.send(Message::Text(
            r#"0{"sid":"engine-1","upgrades":[],"pingInterval":25000,"pingTimeout":20000,"maxPayload":1000000}"#
                .into(),
        ))
        .await
        .expect("open");
        loop {
            match ws.next().await {
                Some(Ok(Message::Text(t))) if t.starts_with("40") => break,
                Some(Ok(_)) => continue,
                other => panic!("no namespace CONNECT: {other:?}"),
            }
        }
        ws.send(Message::Text(r#"40{"sid":"socket-1"}"#.into()))
            .await
            .expect("connect ack");
        ws
    });

    let (tx, _rx) = mpsc::unbounded_channel();
    let id = ClientForm {
        protocol: "socketio".to_string(),
        remote_addr: Some(format!("127.0.0.1:{port}")),
        instruction: Some("Note what the server pushes.".to_string()),
        batching: Some(batching),
        ..Default::default()
    }
    .create(&state, llm, tx)
    .await
    .expect("create client");
    let mut ws = tokio::time::timeout(Duration::from_secs(10), accepted)
        .await
        .expect("client never connected")
        .expect("server task");

    let data_calls = |calls: Vec<crate::helpers::mock_config::MockCallRecord>| {
        calls
            .into_iter()
            .filter(|c| c.context.event_type.as_deref() == Some(DATA_EVENT))
            .map(|c| {
                (
                    c.context.event_data["event"]
                        .as_str()
                        .unwrap_or_default()
                        .to_string(),
                    c.context.prompt.clone(),
                )
            })
            .collect::<Vec<_>>()
    };

    ws.send(Message::Text(r#"42["first"]"#.into()))
        .await
        .expect("send");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    while data_calls(mock.recorded_calls().await).is_empty() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "`first` never reached the model"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // Both arrive while the slow first call is still running.
    ws.send(Message::Text(r#"42["second"]"#.into()))
        .await
        .expect("send");
    tokio::time::sleep(Duration::from_millis(200)).await;
    ws.send(Message::Text(r#"42["third"]"#.into()))
        .await
        .expect("send");

    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        let calls = data_calls(mock.recorded_calls().await);
        if calls.iter().any(|(e, _)| e == "third") {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "`third` never reached the model; calls: {:?}",
            calls.iter().map(|(e, _)| e).collect::<Vec<_>>()
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // Room for a stray extra call to show up before counting.
    tokio::time::sleep(Duration::from_millis(500)).await;

    let calls = data_calls(mock.recorded_calls().await);
    let _ = state.remove_client(id).await;
    drop(ws);
    calls
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn socketio_client_answers_what_arrived_during_a_call_together() {
    let separate = session(false).await;
    let names: Vec<&str> = separate.iter().map(|(e, _)| e.as_str()).collect();
    assert_eq!(
        names,
        vec!["first", "second", "third"],
        "CONTROL FAILED: with batching off each event must be its own model call"
    );

    let batched = session(true).await;
    let names: Vec<&str> = batched.iter().map(|(e, _)| e.as_str()).collect();
    assert_eq!(
        names,
        vec!["first", "third"],
        "the two events pushed during the first call must be one model call, triggered by \
         the newest"
    );
    let prompt = &batched[1].1;
    let trigger_at = prompt.rfind("Event: socketio_event").expect("trigger");
    let before = &prompt[..trigger_at];
    let listed = before
        .find("(1) socketio_event")
        .expect("the earlier event must be listed as arrived and not yet answered");
    assert!(
        before[listed..].contains("second"),
        "the listed event must be `second`:\n{prompt}"
    );
    assert!(
        before.contains("answers all 2 together"),
        "the model must be told it answers both:\n{prompt}"
    );
}

//! Does the WAMP client answer what its router delivered during a model call together, when it
//! batches - and is an invocation inside a batch still answered when the model leaves it?
//!
//! The session loop already handed every router message to a dispatcher task over a queue,
//! which answered them one model call each. With batching on the dispatcher now hands every
//! event waiting to `call_llm_for_client_batch`, the newest the trigger.
//!
//! A minimal router over tokio-tungstenite, written here, agrees to `wamp.2.json`, welcomes
//! the session and delivers EVENT `first`, which the mock model answers slowly, then an
//! INVOCATION and EVENT `third` during that call. Batching off is the control, in the same
//! test as the claim. The model answers nothing, so in both runs the router must receive
//! `wamp.error.unavailable` for the invocation: a caller must never hang, batch or not.

use std::time::Duration;

use crate::helpers::mock_builder::MockLlmBuilder;
use crate::helpers::mock_ollama::MockOllamaServer;
use futures::{SinkExt, StreamExt};
use netget::cli::management::ClientForm;
use netget::state::app_state::AppState;
use serde_json::{json, Value};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};
use tokio_tungstenite::tungstenite::Message;

const EVENT: &str = "wamp_event";
const INVOCATION: &str = "wamp_invocation";

struct Run {
    /// (event id, first argument, prompt) of every event or invocation the model was asked
    /// about, in order.
    calls: Vec<(String, String, String)>,
    /// What the router received after WELCOME.
    received: Vec<Value>,
}

async fn session(batching: bool) -> Run {
    let mock = MockOllamaServer::start(
        MockLlmBuilder::new()
            .on_event(EVENT)
            .and_event_data_contains("args", "first")
            .respond_with_actions(json!([]))
            .after_delay(Duration::from_millis(1500))
            .expect_calls(1)
            .and()
            .on_any()
            .respond_with_actions(json!([]))
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
    let accepted = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.expect("accept");
        let mut ws = tokio_tungstenite::accept_hdr_async(socket, |_: &Request, mut r: Response| {
            r.headers_mut()
                .insert("sec-websocket-protocol", "wamp.2.json".parse().unwrap());
            Ok(r)
        })
        .await
        .expect("WebSocket handshake");
        match ws.next().await {
            Some(Ok(Message::Text(t))) if t.starts_with("[1,") => {}
            other => panic!("no HELLO: {other:?}"),
        }
        ws.send(Message::Text(
            json!([2, 4242, {"roles": {"broker": {}, "dealer": {}}}]).to_string(),
        ))
        .await
        .expect("welcome");
        ws
    });

    let (tx, _rx) = mpsc::unbounded_channel();
    let id = ClientForm {
        protocol: "wamp".to_string(),
        remote_addr: Some(format!("127.0.0.1:{port}")),
        instruction: Some("Note what the router delivers.".to_string()),
        batching: Some(batching),
        ..Default::default()
    }
    .create(&state, llm, tx)
    .await
    .expect("create client");
    let ws = tokio::time::timeout(Duration::from_secs(10), accepted)
        .await
        .expect("client never connected")
        .expect("router task");
    let (mut sink, mut stream) = ws.split();
    let (received_tx, mut received_rx) = mpsc::unbounded_channel::<Value>();
    let reader = tokio::spawn(async move {
        while let Some(Ok(message)) = stream.next().await {
            if let Message::Text(t) = message {
                if let Ok(v) = serde_json::from_str::<Value>(&t) {
                    let _ = received_tx.send(v);
                }
            }
        }
    });

    let calls_of = |calls: Vec<crate::helpers::mock_config::MockCallRecord>| {
        calls
            .into_iter()
            .filter(|c| matches!(c.context.event_type.as_deref(), Some(EVENT | INVOCATION)))
            .map(|c| {
                (
                    c.context.event_type.clone().unwrap_or_default(),
                    c.context.event_data["args"][0]
                        .as_str()
                        .unwrap_or_default()
                        .to_string(),
                    c.context.prompt.clone(),
                )
            })
            .collect::<Vec<_>>()
    };

    let event = |arg: &str| {
        Message::Text(json!([36, 1, 100, {"topic": "com.test.news"}, [arg]]).to_string())
    };
    sink.send(event("first")).await.expect("send");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    while calls_of(mock.recorded_calls().await).is_empty() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "`first` never reached the model"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // Both arrive while the slow first call is still running.
    sink.send(Message::Text(json!([68, 7, 9, {}, ["second"]]).to_string()))
        .await
        .expect("send");
    tokio::time::sleep(Duration::from_millis(200)).await;
    sink.send(event("third")).await.expect("send");

    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        let calls = calls_of(mock.recorded_calls().await);
        if calls.iter().any(|(_, a, _)| a == "third") {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "`third` never reached the model; calls: {:?}",
            calls.iter().map(|(e, a, _)| (e, a)).collect::<Vec<_>>()
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // Room for a stray extra call, and the invocation's answer, to show up.
    tokio::time::sleep(Duration::from_millis(500)).await;

    let calls = calls_of(mock.recorded_calls().await);
    let mut received = Vec::new();
    while let Ok(v) = received_rx.try_recv() {
        received.push(v);
    }
    let _ = state.remove_client(id).await;
    reader.abort();
    Run { calls, received }
}

fn assert_invocation_answered(run: &Run, which: &str) {
    assert!(
        run.received
            .iter()
            .any(|m| m[0] == 8 && m[1] == 68 && m[2] == 7 && m[4] == "wamp.error.unavailable"),
        "{which}: the invocation the model left unanswered must be answered for it; the \
         router received {:?}",
        run.received
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wamp_client_answers_what_arrived_during_a_call_together() {
    let separate = session(false).await;
    let args: Vec<&str> = separate.calls.iter().map(|(_, a, _)| a.as_str()).collect();
    assert_eq!(
        args,
        vec!["first", "second", "third"],
        "CONTROL FAILED: with batching off each delivery must be its own model call"
    );
    assert_invocation_answered(&separate, "batching off");

    let batched = session(true).await;
    let args: Vec<&str> = batched.calls.iter().map(|(_, a, _)| a.as_str()).collect();
    assert_eq!(
        args,
        vec!["first", "third"],
        "the invocation and the event delivered during the first call must be one model \
         call, triggered by the newest"
    );
    let prompt = &batched.calls[1].2;
    let trigger_at = prompt.rfind("Event: wamp_event").expect("trigger");
    let before = &prompt[..trigger_at];
    let listed = before
        .find("(1) wamp_invocation")
        .expect("the invocation must be listed as arrived and not yet answered");
    assert!(
        before[listed..].contains("second"),
        "the listed invocation must be `second`:\n{prompt}"
    );
    assert!(
        before.contains("answers all 2 together"),
        "the model must be told it answers both:\n{prompt}"
    );
    assert_invocation_answered(&batched, "batching on");
}

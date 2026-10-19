//! Does the NSQ client answer the deliveries that arrived during a model call together, when
//! it batches?
//!
//! A raw listener plays nsqd (frames from the server's own `wire`): after IDENTIFY, SUB and
//! RDY it delivers `first`, which the mock model answers slowly, then `second` and — 200 ms
//! later — `third` while that call runs. They wait in the client's dispatcher queue. Each
//! carries its own message id, so a batched answer can still finish them one by one. Batching
//! off is the control, in the same test as the claim: three model calls, one per delivery.
//! Batching on: two, the second triggered by `third` with `second` listed above it.

use crate::helpers::mock_builder::MockLlmBuilder;
use crate::helpers::mock_ollama::MockOllamaServer;
use netget::cli::management::ClientForm;
use netget::server::nsq::wire as nsq;
use netget::state::{app_state::AppState, client_handles::ClientSendOutcome};
use serde_json::{json, Value};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::sync::mpsc;

const EVENT: &str = "nsq_message";

fn text(data: &Value) -> String {
    data["body"].as_str().unwrap_or_default().to_string()
}

async fn calls(mock: &MockOllamaServer) -> Vec<(Value, String)> {
    mock.recorded_calls()
        .await
        .into_iter()
        .filter(|c| c.context.event_type.as_deref() == Some(EVENT))
        .map(|c| (c.context.event_data.clone(), c.context.prompt.clone()))
        .collect()
}

async fn wait_for(mock: &MockOllamaServer, want: &str) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        let calls = calls(mock).await;
        if calls.iter().any(|(d, _)| text(d) == want) {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "`{want}` never reached the model; calls: {calls:#?}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Inject one request, retrying while the client is not ready for it yet (IDENTIFY or SUB
/// still unanswered).
async fn inject(state: &AppState, id: netget::state::ClientId, mut action: Value) {
    action["type"] = json!("nsq_request");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        match state
            .send_to_client(id, action.clone(), Duration::from_secs(2))
            .await
        {
            Ok(ClientSendOutcome::Sent { .. }) => return,
            other => {
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "{action} never accepted: {other:?}"
                );
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }
    }
}

async fn session(batching: bool) -> Vec<(Value, String)> {
    let mock = MockOllamaServer::start(
        MockLlmBuilder::new()
            .on_event(EVENT)
            .and_event_data_contains("body", "first")
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
        .unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, _rx) = mpsc::unbounded_channel();
    let id = ClientForm {
        protocol: "nsq".into(),
        remote_addr: Some(addr.to_string()),
        instruction: Some("Note what is delivered.".into()),
        batching: Some(batching),
        ..Default::default()
    }
    .create(&state, llm, tx)
    .await
    .expect("create client");

    let (socket, _) = tokio::time::timeout(Duration::from_secs(10), listener.accept())
        .await
        .expect("client never connected")
        .unwrap();
    let mut r = BufReader::new(socket);
    let mut magic = [0; 4];
    r.read_exact(&mut magic).await.unwrap();
    assert_eq!(&magic, nsq::MAGIC_V2);
    let mut line = String::new();
    r.read_line(&mut line).await.unwrap();
    assert_eq!(line, "IDENTIFY\n");
    let len = r.read_u32().await.unwrap();
    let mut body = vec![0; len as usize];
    r.read_exact(&mut body).await.unwrap();
    let features = json!({"max_rdy_count":2500,"tls_v1":false,"snappy":false,"deflate":false,"auth_required":false});
    r.get_mut()
        .write_all(&nsq::response_frame(features.to_string().as_bytes()))
        .await
        .unwrap();

    inject(
        &state,
        id,
        json!({"operation":"subscribe","topic":"a","channel":"b"}),
    )
    .await;
    line.clear();
    r.read_line(&mut line).await.unwrap();
    assert_eq!(line, "SUB a b\n");
    r.get_mut()
        .write_all(&nsq::response_frame(b"OK"))
        .await
        .unwrap();
    inject(&state, id, json!({"operation":"ready","count":10})).await;
    line.clear();
    r.read_line(&mut line).await.unwrap();
    assert_eq!(line, "RDY 10\n");

    let mut socket = r.into_inner();
    let delivery =
        |n: u64, body: &str| nsq::message_frame(1, 1, &nsq::message_id_for(n), body.as_bytes());
    socket.write_all(&delivery(1, "first")).await.unwrap();
    wait_for(&mock, "first").await;
    socket.write_all(&delivery(2, "second")).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    socket.write_all(&delivery(3, "third")).await.unwrap();
    wait_for(&mock, "third").await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    let calls = calls(&mock).await;
    let _ = state.remove_client(id).await;
    calls
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn nsq_client_answers_deliveries_that_arrived_during_a_call_together() {
    let separate = session(false).await;
    let texts: Vec<String> = separate.iter().map(|(d, _)| text(d)).collect();
    assert_eq!(
        texts,
        ["first", "second", "third"],
        "CONTROL FAILED: with batching off each delivery must be its own model call"
    );

    let batched = session(true).await;
    let texts: Vec<String> = batched.iter().map(|(d, _)| text(d)).collect();
    assert_eq!(
        texts,
        ["first", "third"],
        "the two deliveries that arrived during the first call must be one model call, \
         triggered by the newest"
    );
    let prompt = &batched[1].1;
    let before = &prompt[..prompt.rfind(&format!("Event: {EVENT}")).expect("trigger")];
    let listed = before
        .lines()
        .find(|l| l.starts_with(&format!("(1) {EVENT} ")))
        .unwrap_or_else(|| panic!("the earlier delivery must be listed:\n{prompt}"));
    assert!(
        listed.contains(r#""body":"second""#)
            && listed.contains(r#""message_id":"0000000000000002""#),
        "the earlier delivery must be listed with its own message id:\n{prompt}"
    );
    assert!(
        before.contains("answers all 2 together"),
        "the model must be told it answers both:\n{prompt}"
    );
}

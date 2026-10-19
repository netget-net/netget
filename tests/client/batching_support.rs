//! The shared shape of the client batching tests (`tests/client/<p>/batching_test.rs`).
//!
//! A local peer plays the server. It sends whatever carries `alpha` and waits; the mock model
//! answers the `alpha` event slowly; once that call is in flight the peer is released and sends
//! what carries `bravo` and — 200 ms later, so it is a separate read — `charlie`, both during
//! the call. Each test runs it twice, batching off (the control: one model call per message)
//! and on, in the same test, so a dead control takes the claim down with it.

use std::future::Future;
use std::time::Duration;

use crate::helpers::mock_builder::MockLlmBuilder;
use crate::helpers::mock_config::MockCallRecord;
use crate::helpers::mock_ollama::MockOllamaServer;
use netget::cli::management::ClientForm;
use netget::state::app_state::AppState;
use serde_json::Value;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot};

/// How one client session is set up.
pub struct Session<'a> {
    pub protocol: &'a str,
    pub startup_params: Option<Value>,
    /// The event every message from the peer raises.
    pub data_event: &'a str,
    /// The field of `data_event` that carries `alpha`, and how it is spelled there.
    pub alpha: (&'a str, &'a str),
    /// The event the client raises on connect, and what the model answers it with — the
    /// commands whose replies a request/response peer then sends.
    pub connected: Option<(&'a str, Value)>,
}

/// One model call about `data_event`: the trigger's data and the whole prompt.
pub struct Call {
    pub data: Value,
    pub prompt: String,
}

impl Call {
    /// Which of `alpha`, `bravo` and `charlie` the trigger carries, joined in order.
    pub fn markers(&self) -> String {
        let text = self.data.to_string();
        // A byte-stream event may carry the payload hex-encoded.
        let hex = |m: &str| m.bytes().map(|b| format!("{b:02x}")).collect::<String>();
        let mut found: Vec<(usize, &str)> = ["alpha", "bravo", "charlie"]
            .into_iter()
            .filter_map(|m| {
                text.find(m)
                    .or_else(|| text.find(&hex(m)))
                    .map(|at| (at, m))
            })
            .collect();
        found.sort();
        found.into_iter().map(|(_, m)| m).collect()
    }
}

/// Run one session. `peer` gets the listener the client connects to and a signal that the
/// model is answering `alpha`; it must send `alpha` first and the rest only after the signal.
pub async fn run<P, F>(session: &Session<'_>, batching: bool, peer: P) -> Vec<Call>
where
    P: FnOnce(TcpListener, oneshot::Receiver<()>) -> F,
    F: Future<Output = ()> + Send + 'static,
{
    let mut builder = MockLlmBuilder::new()
        .on_event(session.data_event)
        .and_event_data_contains(session.alpha.0, session.alpha.1)
        .respond_with_actions(serde_json::json!([]))
        .after_delay(Duration::from_millis(1500))
        .expect_calls(1)
        .and();
    if let Some((event, actions)) = &session.connected {
        builder = builder
            .on_event(*event)
            .respond_with_actions(actions.clone())
            .expect_calls(1)
            .and();
    }
    let mock = MockOllamaServer::start(
        builder
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

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().unwrap().to_string();
    let (go_tx, go_rx) = oneshot::channel();
    let peer_task = tokio::spawn(peer(listener, go_rx));

    let (tx, _rx) = mpsc::unbounded_channel();
    let id = ClientForm {
        protocol: session.protocol.to_string(),
        remote_addr: Some(addr),
        instruction: Some("Note what the server says.".to_string()),
        startup_params: session.startup_params.clone(),
        batching: Some(batching),
        ..Default::default()
    }
    .create(&state, llm, tx)
    .await
    .expect("create client");

    let data_event = session.data_event.to_string();
    let data_calls = |calls: Vec<MockCallRecord>| {
        calls
            .into_iter()
            .filter(|c| c.context.event_type.as_deref() == Some(data_event.as_str()))
            .map(|c| Call {
                data: c.context.event_data.clone(),
                prompt: c.context.prompt.clone(),
            })
            .collect::<Vec<_>>()
    };

    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    while data_calls(mock.recorded_calls().await).is_empty() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "`alpha` never reached the model"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let _ = go_tx.send(());

    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        let calls = data_calls(mock.recorded_calls().await);
        if calls.iter().any(|c| c.markers().contains("charlie")) {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "`charlie` never reached the model; calls: {:?}",
            calls.iter().map(|c| c.data.to_string()).collect::<Vec<_>>()
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // Room for a stray extra call to show up before counting.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let calls = data_calls(mock.recorded_calls().await);
    let _ = state.remove_client(id).await;
    peer_task.abort();
    calls
}

/// The assertion every per-message client shares: off answers each message alone, on answers
/// `bravo` and `charlie` in one call triggered by `charlie`, with `bravo` listed above it.
pub async fn assert_one_event_per_message<P, F>(session: &Session<'_>, peer: P)
where
    P: Fn(TcpListener, oneshot::Receiver<()>) -> F,
    F: Future<Output = ()> + Send + 'static,
{
    let off: Vec<String> = run(session, false, &peer)
        .await
        .iter()
        .map(Call::markers)
        .collect();
    assert_eq!(
        off,
        vec!["alpha", "bravo", "charlie"],
        "CONTROL FAILED: with batching off each message must be its own model call"
    );

    let on = run(session, true, &peer).await;
    let markers: Vec<String> = on.iter().map(Call::markers).collect();
    assert_eq!(
        markers,
        vec!["alpha", "charlie"],
        "the two messages that arrived during the first call must be one model call, \
         triggered by the newest"
    );
    let prompt = &on[1].prompt;
    let trigger_at = prompt
        .rfind(&format!("Event: {}", session.data_event))
        .expect("trigger");
    let before = &prompt[..trigger_at];
    assert!(
        before.contains(&format!("(1) {} ", session.data_event)) && before.contains("bravo"),
        "the earlier message must be listed as arrived and not yet answered:\n{prompt}"
    );
    assert!(
        before.contains("answers all 2 together"),
        "the model must be told it answers both:\n{prompt}"
    );
}

/// The assertion the byte-stream clients share: off answers each read alone, on joins what
/// arrived during the call into the next payload, as the tcp client does.
pub async fn assert_reads_join<P, F>(session: &Session<'_>, peer: P)
where
    P: Fn(TcpListener, oneshot::Receiver<()>) -> F,
    F: Future<Output = ()> + Send + 'static,
{
    let off: Vec<String> = run(session, false, &peer)
        .await
        .iter()
        .map(Call::markers)
        .collect();
    assert_eq!(
        off,
        vec!["alpha", "bravo", "charlie"],
        "CONTROL FAILED: with batching off each read must reach the model on its own"
    );
    let on: Vec<String> = run(session, true, &peer)
        .await
        .iter()
        .map(Call::markers)
        .collect();
    assert_eq!(
        on,
        vec!["alpha", "bravocharlie"],
        "with batching on everything that arrived during the call is the next payload"
    );
}

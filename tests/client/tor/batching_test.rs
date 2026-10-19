//! Does the Tor client answer what the destination sent during a model call together, when it
//! batches — and does each read reach the model at all?
//!
//! The circuit loop used to call the model inline beside an Idle/Processing/Accumulating
//! machine that could never leave Idle and cleared a queue nothing filled, so what arrived
//! during a call merged in arti's buffer and batching off and on were indistinguishable. The
//! circuit is now read on a registered task feeding a bounded queue (`client/inbound_queue.rs`).
//!
//! A real circuit needs a full Tor bootstrap this repository has no loopback for, so this
//! drives `run_circuit` — the exact loop `connect_with_llm_actions` runs over arti's stream
//! halves — over a plain local socket standing in for the circuit.

use std::sync::Arc;
use std::time::Duration;

use crate::helpers::mock_builder::MockLlmBuilder;
use crate::helpers::mock_ollama::MockOllamaServer;
use netget::state::app_state::AppState;
use netget::state::client::ClientInstance;
use netget::state::ClientId;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};

fn hex(s: &str) -> String {
    s.bytes().map(|b| format!("{b:02x}")).collect()
}

/// Which markers the event's payload carries, in order — `data` is text, or hex when the
/// payload was not printable.
fn markers(data: &serde_json::Value) -> String {
    let text = data.to_string();
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

async fn session(batching: bool) -> Vec<String> {
    let mock = MockOllamaServer::start(
        MockLlmBuilder::new()
            .on_event("tor_data_received")
            .and_event_data_contains("data", "alpha")
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

    let state = Arc::new(AppState::new_with_options(false, mock.base_url()));
    let llm = netget::llm::OllamaClient::new(mock.base_url());
    state.set_llm_client(llm.clone()).await;

    let mut instance = ClientInstance::new(
        ClientId::new(0),
        "example.com:80".to_string(),
        "Tor".to_string(),
        "Note what the destination says.".to_string(),
    );
    instance.batching = batching;
    instance.history_entries = 40;
    let id = state.add_client(instance).await;

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let circuit = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .expect("connect");
    let (mut far_end, _) = listener.accept().await.expect("accept");
    let (read_half, write_half) = tokio::io::split(circuit);
    let command_rx = netget::client::command_support::register_command_channel(&state, id).await;
    let (status_tx, _status_rx) = mpsc::unbounded_channel();
    let loop_task = tokio::spawn(netget::client::tor::run_circuit(
        read_half,
        Arc::new(Mutex::new(write_half)),
        command_rx,
        "example.com:80".to_string(),
        llm,
        state.clone(),
        status_tx,
        id,
    ));

    let data_calls = || async {
        mock.recorded_calls()
            .await
            .into_iter()
            .filter(|c| c.context.event_type.as_deref() == Some("tor_data_received"))
            .map(|c| markers(&c.context.event_data))
            .collect::<Vec<_>>()
    };

    far_end.write_all(b"alpha").await.expect("write");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    while data_calls().await.is_empty() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "`alpha` never reached the model"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    far_end.write_all(b"bravo").await.expect("write");
    tokio::time::sleep(Duration::from_millis(200)).await;
    far_end.write_all(b"charlie").await.expect("write");

    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        let calls = data_calls().await;
        if calls.iter().any(|m| m.contains("charlie")) {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "`charlie` never reached the model; calls: {calls:?}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    let calls = data_calls().await;
    let _ = state.remove_client(id).await;
    loop_task.abort();
    calls
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tor_client_joins_or_separates_what_arrived_during_a_call() {
    assert_eq!(
        session(false).await,
        vec!["alpha", "bravo", "charlie"],
        "CONTROL FAILED: with batching off each read must reach the model on its own"
    );
    assert_eq!(
        session(true).await,
        vec!["alpha", "bravocharlie"],
        "with batching on everything that arrived during the call is the next payload"
    );
}

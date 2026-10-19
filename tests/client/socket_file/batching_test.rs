//! Does the Unix socket client answer what its peer sent during a model call together, when
//! it batches?
//!
//! The client used to call the model inline in its read loop, so whatever the peer sent while
//! the model was answering merged in the socket buffer and came out as one read: batching off
//! and on could not be told apart. A reader task now keeps each read in a bounded queue, and
//! the answering loop takes one read per call (off) or joins everything waiting into one
//! payload (on), as the tcp client does.
//!
//! A `UnixListener` plays the peer: it sends `first`, which the mock model answers slowly,
//! then `second` and - 200 ms later, so it is a separate read - `third` during that call.
//! Batching off is the control, in the same test as the claim.

use std::time::Duration;

use crate::helpers::mock_builder::MockLlmBuilder;
use crate::helpers::mock_ollama::MockOllamaServer;
use netget::cli::management::ClientForm;
use netget::state::app_state::AppState;
use tokio::io::AsyncWriteExt;
use tokio::net::UnixListener;
use tokio::sync::mpsc;

const DATA_EVENT: &str = "socket_file_data_received";

/// One session: returns the `data` of every data event the model was asked about, in order.
async fn session(batching: bool) -> Vec<String> {
    let mock = MockOllamaServer::start(
        MockLlmBuilder::new()
            .on_event(DATA_EVENT)
            .and_event_data_contains("data", "first")
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

    let dir = tempfile::tempdir().expect("tempdir");
    let socket_path = dir.path().join("batching.sock");
    let listener = UnixListener::bind(&socket_path).expect("bind");

    let (tx, _rx) = mpsc::unbounded_channel();
    let id = ClientForm {
        protocol: "SocketFile".to_string(),
        remote_addr: Some(socket_path.to_string_lossy().to_string()),
        instruction: Some("Note what the peer says.".to_string()),
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

    let data_calls = |calls: Vec<crate::helpers::mock_config::MockCallRecord>| {
        calls
            .into_iter()
            .filter(|c| c.context.event_type.as_deref() == Some(DATA_EVENT))
            .map(|c| {
                c.context.event_data["data"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string()
            })
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

    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        let calls = data_calls(mock.recorded_calls().await);
        if calls.iter().any(|d| d.contains("third")) {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "`third` never reached the model; calls: {calls:?}"
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
async fn socket_file_client_joins_or_separates_what_arrived_during_a_call() {
    let separate = session(false).await;
    assert_eq!(
        separate,
        vec!["first", "second", "third"],
        "CONTROL FAILED: with batching off each read must be answered on its own"
    );

    let batched = session(true).await;
    assert_eq!(
        batched,
        vec!["first", "secondthird"],
        "with batching on everything that arrived during the call is the next payload"
    );
}

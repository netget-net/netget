//! Does the TLS client answer what its server sent during a model call together, when it
//! batches?
//!
//! The client used to call the model inline in its read loop, so whatever the server sent
//! while the model was answering waited in the kernel (or undecrypted inside rustls) and came
//! out as one read: batching off and on could not be told apart. A reader task now keeps each
//! read in a bounded queue, and the answering loop takes one read per call (off) or joins
//! everything waiting into one payload (on), as the tcp client does.
//!
//! A TLS listener written here (tokio-rustls, a fresh self-signed certificate) plays the
//! server: it sends `first`, which the mock model answers slowly, then `second` and - 200 ms
//! later, so it is a separate read - `third` during that call. Batching off is the control, in
//! the same test as the claim: it must give three model calls, or a two-call result would
//! prove nothing.

use std::sync::Arc;
use std::time::Duration;

use crate::helpers::mock_builder::MockLlmBuilder;
use crate::helpers::mock_ollama::MockOllamaServer;
use netget::cli::management::ClientForm;
use netget::state::app_state::AppState;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;

const DATA_EVENT: &str = "tls_client_data_received";

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

    let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
    let issued = rcgen::generate_simple_self_signed(vec!["localhost".into()]).expect("cert");
    let cert = issued.cert.der().clone();
    let key = tokio_rustls::rustls::pki_types::PrivateKeyDer::try_from(
        issued.signing_key.serialize_der(),
    )
    .expect("key");
    let config = tokio_rustls::rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .expect("server config");
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));

    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("bind");
    let port = listener.local_addr().unwrap().port();

    let (tx, _rx) = mpsc::unbounded_channel();
    let accepted = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.expect("accept");
        acceptor.accept(socket).await.expect("TLS handshake")
    });
    let id = ClientForm {
        protocol: "tls".to_string(),
        remote_addr: Some(format!("127.0.0.1:{port}")),
        instruction: Some("Note what the server says.".to_string()),
        startup_params: Some(serde_json::json!({
            "accept_invalid_certs": true,
            "server_name": "localhost",
        })),
        batching: Some(batching),
        ..Default::default()
    }
    .create(&state, llm, tx)
    .await
    .expect("create client");
    let mut socket = tokio::time::timeout(Duration::from_secs(10), accepted)
        .await
        .expect("client never connected")
        .expect("server task");

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
    socket.flush().await.expect("flush");
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
    socket.flush().await.expect("flush");
    tokio::time::sleep(Duration::from_millis(200)).await;
    socket.write_all(b"third").await.expect("write");
    socket.flush().await.expect("flush");

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
async fn tls_client_joins_or_separates_what_arrived_during_a_call() {
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

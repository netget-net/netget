//! Does the VNC client answer the clipboard text a server pushed during a model call together,
//! when it batches?
//!
//! The client used to call the model inline in its read loop, so what the server sent while the
//! model was answering waited unread in the socket and was read one message per call afterwards:
//! batching off and on could not be told apart. A reader task now frames whole RFB messages into
//! a bounded queue and the answering loop takes one per call (off) or everything waiting (on).
//!
//! A server written here completes the RFB 3.8 handshake with no security, then sends
//! ServerCutText `first`, which the mock model answers slowly, and `second` and `third` during
//! that call. Batching off is the control, in the same test as the claim: three model calls,
//! one per message, or a two-call result would prove nothing.

use std::time::Duration;

use crate::helpers::mock_builder::MockLlmBuilder;
use crate::helpers::mock_ollama::MockOllamaServer;
use netget::cli::management::ClientForm;
use netget::state::app_state::AppState;
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

const EVENT: &str = "vnc_server_cut_text";

/// A one-connection RFB server. Every string sent on the returned channel goes out as one
/// ServerCutText message.
async fn fake_server() -> (std::net::SocketAddr, mpsc::UnboundedSender<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();
    tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        s.write_all(b"RFB 003.008\n").await.unwrap();
        let mut version = [0u8; 12];
        s.read_exact(&mut version).await.unwrap();
        s.write_all(&[1, 1]).await.unwrap(); // one security type: None
        let mut chosen = [0u8; 1];
        s.read_exact(&mut chosen).await.unwrap();
        s.write_all(&0u32.to_be_bytes()).await.unwrap(); // SecurityResult OK
        let mut shared = [0u8; 1];
        s.read_exact(&mut shared).await.unwrap(); // ClientInit
        let mut init = Vec::new();
        init.extend_from_slice(&64u16.to_be_bytes());
        init.extend_from_slice(&48u16.to_be_bytes());
        init.extend_from_slice(&[32, 24, 0, 1, 0, 255, 0, 255, 0, 255, 16, 8, 0, 0, 0, 0]);
        init.extend_from_slice(&4u32.to_be_bytes());
        init.extend_from_slice(b"test");
        s.write_all(&init).await.unwrap();
        let (mut r, mut w) = s.into_split();
        // SetPixelFormat, SetEncodings and whatever the model sends: read and ignored.
        tokio::spawn(async move {
            let mut sink = Vec::new();
            let _ = r.read_to_end(&mut sink).await;
        });
        while let Some(text) = rx.recv().await {
            let mut msg = vec![3, 0, 0, 0];
            msg.extend_from_slice(&(text.len() as u32).to_be_bytes());
            msg.extend_from_slice(text.as_bytes());
            if w.write_all(&msg).await.is_err() {
                return;
            }
        }
    });
    (addr, tx)
}

/// One session: `first`, then `second` and `third` while the model is answering `first`.
/// Returns the (event data, prompt) of every clipboard event the model was asked about.
async fn session(batching: bool) -> Vec<(Value, String)> {
    let mock = MockOllamaServer::start(
        MockLlmBuilder::new()
            .on_event(EVENT)
            .and_event_data_contains("text", "first")
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

    let (addr, server) = fake_server().await;
    let (tx, _rx) = mpsc::unbounded_channel();
    let id = ClientForm {
        protocol: "vnc".to_string(),
        remote_addr: Some(addr.to_string()),
        instruction: Some("Note what the server puts on the clipboard.".to_string()),
        batching: Some(batching),
        ..Default::default()
    }
    .create(&state, llm, tx)
    .await
    .expect("create client");

    let calls = |records: Vec<crate::helpers::mock_config::MockCallRecord>| {
        records
            .into_iter()
            .filter(|c| c.context.event_type.as_deref() == Some(EVENT))
            .map(|c| (c.context.event_data.clone(), c.context.prompt.clone()))
            .collect::<Vec<_>>()
    };

    server.send("first".to_string()).unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    while calls(mock.recorded_calls().await).is_empty() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "`first` never reached the model"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    server.send("second".to_string()).unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    server.send("third".to_string()).unwrap();

    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        let seen = calls(mock.recorded_calls().await);
        if seen.iter().any(|(data, _)| data["text"] == "third") {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "`third` never reached the model; calls: {:#?}",
            seen.iter().map(|(d, _)| d).collect::<Vec<_>>()
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // Room for a stray extra call to show up before counting.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let seen = calls(mock.recorded_calls().await);
    let _ = state.remove_client(id).await;
    seen
}

fn texts(calls: &[(Value, String)]) -> Vec<String> {
    calls
        .iter()
        .map(|(d, _)| d["text"].as_str().unwrap_or_default().to_string())
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn vnc_client_answers_clipboard_pushed_during_a_call_together() {
    let separate = session(false).await;
    assert_eq!(
        texts(&separate),
        vec!["first", "second", "third"],
        "CONTROL FAILED: with batching off each message must be its own model call"
    );

    let batched = session(true).await;
    assert_eq!(
        texts(&batched),
        vec!["first", "third"],
        "the two messages that arrived during the first call must be one model call, \
         triggered by the newest"
    );
    let prompt = &batched[1].1;
    let trigger_at = prompt.rfind(&format!("Event: {EVENT}")).expect("trigger");
    let before = &prompt[..trigger_at];
    assert!(
        before.contains(&format!(r#"(1) {EVENT} {{"text":"second"}}"#)),
        "the earlier message must be listed as arrived and not yet answered:\n{prompt}"
    );
    assert!(
        before.contains("answers all 2 together"),
        "the model must be told it answers both:\n{prompt}"
    );
}

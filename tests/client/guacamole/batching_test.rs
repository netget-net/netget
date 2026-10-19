//! Does the Guacamole client answer the clipboard changes guacd pushed during a model call
//! together, when it batches?
//!
//! The client's reader already queued whole instructions as events and its dispatcher answered
//! them one per model call. With batching on, the dispatcher now takes everything waiting when
//! a call returns and answers it in one call; with it off, one per call as before.
//!
//! A guacd written here completes the handshake (select, args, connect, ready), sends a `sync`
//! so the client raises `guacamole_ready`, then sends the clipboard `first`, which the mock model
//! answers slowly, and `second` and `third` during that call. Batching off is the control, in the
//! same test as the claim.

use std::time::Duration;

use crate::helpers::mock_builder::MockLlmBuilder;
use crate::helpers::mock_ollama::MockOllamaServer;
use netget::cli::management::ClientForm;
use netget::server::guacamole::wire;
use netget::state::app_state::AppState;
use serde_json::Value;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::sync::mpsc;

const EVENT: &str = "guacamole_clipboard_received";

/// A one-connection guacd. Every string sent on the returned channel goes out as one clipboard
/// stream (clipboard, blob, end).
async fn fake_guacd() -> (std::net::SocketAddr, mpsc::UnboundedSender<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();
    tokio::spawn(async move {
        let (s, _) = listener.accept().await.unwrap();
        let (r, mut w) = s.into_split();
        let mut reader = wire::Reader::new(r);
        let select = reader.next().await.unwrap().unwrap();
        assert_eq!(select.opcode, "select");
        w.write_all(wire::encode("args", &[wire::VERSION, "hostname"]).as_bytes())
            .await
            .unwrap();
        loop {
            let ins = reader.next().await.unwrap().unwrap();
            if ins.opcode == "connect" {
                break;
            }
        }
        w.write_all(wire::encode("ready", &["$batching"]).as_bytes())
            .await
            .unwrap();
        w.write_all(wire::encode("sync", &["1"]).as_bytes())
            .await
            .unwrap();
        // The client's sync replies and acks: read and ignored.
        tokio::spawn(async move { while let Ok(Some(_)) = reader.next().await {} });
        let mut stream = 0u32;
        while let Some(text) = rx.recv().await {
            stream += 1;
            let id = stream.to_string();
            let mut out = wire::encode("clipboard", &[&id, "text/plain"]);
            out.push_str(&wire::blobs(&id, text.as_bytes()));
            out.push_str(&wire::encode("end", &[&id]));
            if w.write_all(out.as_bytes()).await.is_err() {
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

    let (addr, server) = fake_guacd().await;
    let (tx, _rx) = mpsc::unbounded_channel();
    let id = ClientForm {
        protocol: "guacamole".to_string(),
        remote_addr: Some(addr.to_string()),
        instruction: Some("Note what the remote desktop puts on the clipboard.".to_string()),
        startup_params: Some(serde_json::json!({"arguments": {"hostname": "127.0.0.1"}})),
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
async fn guacamole_client_answers_clipboard_pushed_during_a_call_together() {
    let separate = session(false).await;
    assert_eq!(
        texts(&separate),
        vec!["first", "second", "third"],
        "CONTROL FAILED: with batching off each clipboard change must be its own model call"
    );

    let batched = session(true).await;
    assert_eq!(
        texts(&batched),
        vec!["first", "third"],
        "the two changes that arrived during the first call must be one model call, \
         triggered by the newest"
    );
    let prompt = &batched[1].1;
    let trigger_at = prompt.rfind(&format!("Event: {EVENT}")).expect("trigger");
    let before = &prompt[..trigger_at];
    let listed = before
        .lines()
        .find(|l| l.starts_with(&format!("(1) {EVENT} ")))
        .unwrap_or_else(|| panic!("the earlier change must be listed:\n{prompt}"));
    assert!(
        listed.contains(r#""text":"second""#),
        "the listed event must be `second`: {listed}"
    );
    assert!(
        before.contains("answers all 2 together"),
        "the model must be told it answers both:\n{prompt}"
    );
}

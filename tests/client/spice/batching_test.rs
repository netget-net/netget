//! Does the SPICE client answer the notifications a server pushed during a model call together,
//! when it batches?
//!
//! The channel readers already queued whole messages as events and the dispatcher answered them
//! one per model call. With batching on, the dispatcher now takes everything waiting when a call
//! returns and answers it in one call; with it off, one per call as before.
//!
//! A server written here links the main channel (any ticket), sends INIT and an empty channel
//! list, then NOTIFY `first`, which the mock model answers slowly, and `second` and `third`
//! during that call. Batching off is the control, in the same test as the claim.

use std::time::Duration;

use crate::helpers::mock_builder::MockLlmBuilder;
use crate::helpers::mock_ollama::MockOllamaServer;
use netget::cli::management::ClientForm;
use netget::server::spice::wire::{self, channel, common_cap, link_err, msg, msgc};
use netget::state::app_state::AppState;
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

const EVENT: &str = "spice_notify";

fn mini(t: u16, body: &[u8]) -> Vec<u8> {
    let mut v = wire::data_header(true, 0, t, body.len() as u32);
    v.extend_from_slice(body);
    v
}

/// Link one incoming channel, accepting any ticket.
async fn accept_link(s: &mut TcpStream, pubkey: &[u8]) -> wire::LinkMess {
    let mut header = [0u8; wire::LINK_HEADER_BYTES];
    s.read_exact(&mut header).await.unwrap();
    let size = wire::parse_link_header(&header, wire::LINK_MESS_BYTES).unwrap();
    let mut body = vec![0u8; size as usize];
    s.read_exact(&mut body).await.unwrap();
    let link = wire::LinkMess::decode(&body).unwrap();
    let reply = wire::LinkReply {
        error: link_err::OK,
        pubkey: pubkey.to_vec(),
        common_caps: vec![wire::caps_word(&[
            common_cap::AUTH_SELECTION,
            common_cap::AUTH_SPICE,
            common_cap::MINI_HEADER,
        ])],
        channel_caps: vec![],
    };
    s.write_all(&reply.encode()).await.unwrap();
    let mut mechanism = [0u8; 4];
    s.read_exact(&mut mechanism).await.unwrap();
    let mut ticket = [0u8; wire::TICKET_BYTES];
    s.read_exact(&mut ticket).await.unwrap();
    s.write_all(&link_err::OK.to_le_bytes()).await.unwrap();
    link
}

/// A server with a main channel only. Every string sent on the returned channel goes out as
/// one NOTIFY on it.
async fn fake_server() -> (std::net::SocketAddr, mpsc::UnboundedSender<String>) {
    let key = tokio::task::spawn_blocking(wire::generate_ticket_key)
        .await
        .unwrap()
        .unwrap();
    let pubkey = wire::ticket_public_key(&key).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();
    tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        let link = accept_link(&mut s, &pubkey).await;
        assert_eq!(link.channel_type, channel::MAIN);
        let init = wire::main_init(7, 1, 1, 1, 0, 0, 0, 0);
        s.write_all(&mini(msg::MAIN_INIT, &init)).await.unwrap();
        loop {
            let (t, _) = wire::read_message(&mut s, true, 1 << 20).await.unwrap();
            if t == msgc::MAIN_ATTACH_CHANNELS {
                s.write_all(&mini(msg::MAIN_CHANNELS_LIST, &wire::channels_list(&[])))
                    .await
                    .unwrap();
                break;
            }
        }
        let (mut r, mut w) = s.into_split();
        // Whatever else the client sends: read and ignored.
        tokio::spawn(
            async move { while wire::read_message(&mut r, true, 1 << 20).await.is_ok() {} },
        );
        while let Some(text) = rx.recv().await {
            let body = wire::notify(0, wire::NOTIFY_SEVERITY_INFO, 0, &text);
            if w.write_all(&mini(msg::NOTIFY, &body)).await.is_err() {
                return;
            }
        }
    });
    (addr, tx)
}

/// One session: `first`, then `second` and `third` while the model is answering `first`.
/// Returns the (event data, prompt) of every notification the model was asked about.
async fn session(batching: bool) -> Vec<(Value, String)> {
    let mock = MockOllamaServer::start(
        MockLlmBuilder::new()
            .on_event(EVENT)
            .and_event_data_contains("message", "first")
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
        protocol: "SPICE".to_string(),
        remote_addr: Some(addr.to_string()),
        instruction: Some("Note what the server tells you.".to_string()),
        startup_params: Some(serde_json::json!({"password": "anything"})),
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
        if seen.iter().any(|(data, _)| data["message"] == "third") {
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

fn messages(calls: &[(Value, String)]) -> Vec<String> {
    calls
        .iter()
        .map(|(d, _)| d["message"].as_str().unwrap_or_default().to_string())
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn spice_client_answers_notifications_pushed_during_a_call_together() {
    let separate = session(false).await;
    assert_eq!(
        messages(&separate),
        vec!["first", "second", "third"],
        "CONTROL FAILED: with batching off each notification must be its own model call"
    );

    let batched = session(true).await;
    assert_eq!(
        messages(&batched),
        vec!["first", "third"],
        "the two notifications that arrived during the first call must be one model call, \
         triggered by the newest"
    );
    let prompt = &batched[1].1;
    let trigger_at = prompt.rfind(&format!("Event: {EVENT}")).expect("trigger");
    let before = &prompt[..trigger_at];
    let listed = before
        .lines()
        .find(|l| l.starts_with(&format!("(1) {EVENT} ")))
        .unwrap_or_else(|| panic!("the earlier notification must be listed:\n{prompt}"));
    assert!(
        listed.contains(r#""message":"second""#),
        "the listed event must be `second`: {listed}"
    );
    assert!(
        before.contains("answers all 2 together"),
        "the model must be told it answers both:\n{prompt}"
    );
}

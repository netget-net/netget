//! Does the WebRTC client answer the data-channel messages a peer sent during a model call
//! together, when it batches?
//!
//! webrtc-rs awaits a channel's message handler before it reads the channel again, and the
//! handler used to call the model itself, so what the peer sent during a call stayed unread in
//! SCTP (the handler's "queue while processing" arm could never run) and batching off and on
//! could not be told apart. The handler now only queues; each channel's answering task takes one
//! message per call (off) or everything waiting (on).
//!
//! The peer is webrtc-rs in the answering role, in this file: it answers the client's manual
//! offer, the client applies the answer through `send_to_client`, and the peer sends `first` on
//! the client's `netget` channel, which the mock model answers slowly, then `second` and `third`
//! during that call. Batching off is the control, in the same test as the claim. Nothing leaves
//! the machine: neither side has an ICE server.

use std::sync::Arc;
use std::time::Duration;

use crate::helpers::mock_builder::MockLlmBuilder;
use crate::helpers::mock_ollama::MockOllamaServer;
use netget::cli::management::ClientForm;
use netget::state::app_state::AppState;
use netget::state::client_handles::ClientSendOutcome;
use serde_json::Value;
use tokio::sync::mpsc;
use webrtc::api::interceptor_registry::register_default_interceptors;
use webrtc::api::media_engine::MediaEngine;
use webrtc::api::APIBuilder;
use webrtc::data_channel::data_channel_state::RTCDataChannelState;
use webrtc::data_channel::RTCDataChannel;
use webrtc::interceptor::registry::Registry;
use webrtc::peer_connection::configuration::RTCConfiguration;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;
use webrtc::peer_connection::RTCPeerConnection;

const EVENT: &str = "webrtc_message_received";

/// Answer the client's offer and return the peer connection and the client's channel, open.
async fn answer(
    state: &AppState,
    id: netget::state::ClientId,
) -> (Arc<RTCPeerConnection>, Arc<RTCDataChannel>) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let offer = {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(Value::String(offer)) = state
                .get_client(id)
                .await
                .and_then(|c| c.get_protocol_field("sdp_offer").cloned())
            {
                break offer;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "the client never produced an offer"
            );
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
    };
    let offer: RTCSessionDescription = serde_json::from_str(&offer).expect("offer");

    let mut media_engine = MediaEngine::default();
    let registry = register_default_interceptors(Registry::new(), &mut media_engine).unwrap();
    let api = APIBuilder::new()
        .with_media_engine(media_engine)
        .with_interceptor_registry(registry)
        .build();
    let peer = Arc::new(
        api.new_peer_connection(RTCConfiguration::default())
            .await
            .unwrap(),
    );
    let (channel_tx, mut channel_rx) = mpsc::unbounded_channel::<Arc<RTCDataChannel>>();
    peer.on_data_channel(Box::new(move |dc| {
        let _ = channel_tx.send(dc);
        Box::pin(async {})
    }));
    peer.set_remote_description(offer).await.unwrap();
    let answer = peer.create_answer(None).await.unwrap();
    let mut gathered = peer.gathering_complete_promise().await;
    peer.set_local_description(answer).await.unwrap();
    let _ = gathered.recv().await;
    let answer = peer.local_description().await.expect("answer");
    let outcome = state
        .send_to_client(
            id,
            serde_json::json!({
                "type": "apply_answer",
                "answer_json": serde_json::to_string(&answer).unwrap(),
            }),
            Duration::from_secs(10),
        )
        .await
        .expect("apply_answer");
    assert!(
        matches!(outcome, ClientSendOutcome::Executed { .. }),
        "{outcome:?}"
    );

    let channel = tokio::time::timeout(Duration::from_secs(30), channel_rx.recv())
        .await
        .expect("the client's channel never reached the peer")
        .expect("channel");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    while channel.ready_state() != RTCDataChannelState::Open {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the channel never opened"
        );
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    (peer, channel)
}

/// One session: `first`, then `second` and `third` while the model is answering `first`.
/// Returns the (event data, prompt) of every message the model was asked about.
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

    let (tx, _rx) = mpsc::unbounded_channel();
    let id = ClientForm {
        protocol: "webrtc".to_string(),
        remote_addr: Some("manual".to_string()),
        instruction: Some("Note what the peer says.".to_string()),
        startup_params: Some(serde_json::json!({ "ice_servers": [] })),
        batching: Some(batching),
        ..Default::default()
    }
    .create(&state, llm, tx)
    .await
    .expect("create client");
    let (peer, channel) = answer(&state, id).await;

    let calls = |records: Vec<crate::helpers::mock_config::MockCallRecord>| {
        records
            .into_iter()
            .filter(|c| c.context.event_type.as_deref() == Some(EVENT))
            .map(|c| (c.context.event_data.clone(), c.context.prompt.clone()))
            .collect::<Vec<_>>()
    };

    channel.send_text("first".to_string()).await.unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    while calls(mock.recorded_calls().await).is_empty() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "`first` never reached the model"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    channel.send_text("second".to_string()).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    channel.send_text("third".to_string()).await.unwrap();

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
    let _ = peer.close().await;
    seen
}

fn messages(calls: &[(Value, String)]) -> Vec<String> {
    calls
        .iter()
        .map(|(d, _)| d["message"].as_str().unwrap_or_default().to_string())
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn webrtc_client_answers_messages_sent_during_a_call_together() {
    let separate = session(false).await;
    assert_eq!(
        messages(&separate),
        vec!["first", "second", "third"],
        "CONTROL FAILED: with batching off each message must be its own model call"
    );

    let batched = session(true).await;
    assert_eq!(
        messages(&batched),
        vec!["first", "third"],
        "the two messages that arrived during the first call must be one model call, \
         triggered by the newest"
    );
    let prompt = &batched[1].1;
    let trigger_at = prompt.rfind(&format!("Event: {EVENT}")).expect("trigger");
    let before = &prompt[..trigger_at];
    let listed = before
        .lines()
        .find(|l| l.starts_with(&format!("(1) {EVENT} ")))
        .unwrap_or_else(|| panic!("the earlier message must be listed:\n{prompt}"));
    assert!(
        listed.contains(r#""message":"second""#),
        "the listed event must be `second`: {listed}"
    );
    assert!(
        before.contains("answers all 2 together"),
        "the model must be told it answers both:\n{prompt}"
    );
}

//! Does the MQTT-SN client answer the deliveries that arrived during a model call together,
//! when it batches?
//!
//! A stand-in gateway (a UDP socket speaking NetGet's own MQTT-SN codec) accepts the CONNECT,
//! then sends a QoS 0 PUBLISH `first` on short topic `sn`, which the mock model answers slowly,
//! and `second` and `third` while that call runs. They wait on the client's event queue.
//! Batching off is the control, in the same test as the claim: three model calls. Batching on:
//! two — `first`, then one call triggered by `third` with `second` listed above it.
//!
//! The peer is a fake rather than the Paho gateway because the property under test is the
//! client's own queueing, not interoperability (`peer_test.rs` covers that).

use std::time::Duration;

use crate::helpers::mock_builder::MockLlmBuilder;
use crate::helpers::mock_ollama::MockOllamaServer;
use netget::cli::management::ClientForm;
use netget::server::mqtt_sn::packet::{self, Flags, Packet};
use netget::state::app_state::AppState;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

const EVENT: &str = "mqttsn_message_received";

fn publish(payload: &str) -> Vec<u8> {
    packet::encode(&Packet::Publish {
        flags: Flags {
            qos: 0,
            topic_id_type: packet::TOPIC_SHORT,
            ..Flags::default()
        },
        topic: packet::short_topic("sn").expect("short topic"),
        msg_id: 0,
        data: payload.as_bytes().to_vec(),
    })
}

async fn session(batching: bool) -> Vec<(serde_json::Value, String)> {
    let mock = MockOllamaServer::start(
        MockLlmBuilder::new()
            .on_event(EVENT)
            .and_event_data_contains("payload", "first")
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

    let gateway = UdpSocket::bind(("127.0.0.1", 0)).await.expect("bind");
    let port = gateway.local_addr().unwrap().port();

    let (tx, _rx) = mpsc::unbounded_channel();
    let create = tokio::spawn({
        let state = state.clone();
        async move {
            ClientForm {
                protocol: "mqtt_sn".to_string(),
                remote_addr: Some(format!("127.0.0.1:{port}")),
                instruction: Some("Note what the gateway delivers.".to_string()),
                batching: Some(batching),
                ..Default::default()
            }
            .create(&state, llm, tx)
            .await
            .expect("create client")
        }
    });

    let mut buf = vec![0u8; 2048];
    let peer = loop {
        let (n, peer) = tokio::time::timeout(Duration::from_secs(10), gateway.recv_from(&mut buf))
            .await
            .expect("the client never sent CONNECT")
            .expect("recv");
        if matches!(packet::decode(&buf[..n]), Ok(Packet::Connect { .. })) {
            break peer;
        }
    };
    gateway
        .send_to(
            &packet::encode(&Packet::ConnAck {
                rc: packet::ACCEPTED,
            }),
            peer,
        )
        .await
        .expect("CONNACK");
    let id = create.await.expect("create task");

    let data_calls = |calls: Vec<crate::helpers::mock_config::MockCallRecord>| {
        calls
            .into_iter()
            .filter(|c| c.context.event_type.as_deref() == Some(EVENT))
            .map(|c| (c.context.event_data.clone(), c.context.prompt.clone()))
            .collect::<Vec<_>>()
    };

    gateway
        .send_to(&publish("first"), peer)
        .await
        .expect("send");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    while data_calls(mock.recorded_calls().await).is_empty() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "`first` never reached the model"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // Both arrive while the slow first call is still running.
    gateway
        .send_to(&publish("second"), peer)
        .await
        .expect("send");
    tokio::time::sleep(Duration::from_millis(200)).await;
    gateway
        .send_to(&publish("third"), peer)
        .await
        .expect("send");

    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        let calls = data_calls(mock.recorded_calls().await);
        if calls.iter().any(|(d, _)| d["payload"] == "third") {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "`third` never reached the model; calls: {:#?}",
            calls.iter().map(|(d, _)| d).collect::<Vec<_>>()
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
async fn mqtt_sn_client_answers_deliveries_that_arrived_during_a_call_together() {
    let payloads = |calls: &[(serde_json::Value, String)]| {
        calls
            .iter()
            .map(|(d, _)| d["payload"].as_str().unwrap_or_default().to_string())
            .collect::<Vec<_>>()
    };

    let separate = session(false).await;
    assert_eq!(
        payloads(&separate),
        vec!["first", "second", "third"],
        "CONTROL FAILED: with batching off each delivery must be its own model call"
    );

    let batched = session(true).await;
    assert_eq!(
        payloads(&batched),
        vec!["first", "third"],
        "the two deliveries that arrived during the first call must be one model call, \
         triggered by the newest"
    );
    let prompt = &batched[1].1;
    let trigger_at = prompt.rfind(&format!("Event: {EVENT}")).expect("trigger");
    let before = &prompt[..trigger_at];
    let listed = before
        .find(&format!("(1) {EVENT} {{"))
        .map(|at| &before[at..])
        .unwrap_or_default();
    assert!(
        listed.lines().next().unwrap_or_default().contains("second"),
        "the earlier delivery must be listed as arrived and not yet answered:\n{prompt}"
    );
    assert!(
        before.contains("answers all 2 together"),
        "the model must be told it answers both:\n{prompt}"
    );
}

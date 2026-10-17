//! QoS 0 PUBLISHes sent while the model is answering are answered together; a QoS 1 PUBLISH is
//! never folded into a batch and still gets its own PUBACK carrying its own packet id.
//!
//! A raw-socket MQTT 3.1.1 client (as in `answer_with_test.rs`) publishes `first` at QoS 0,
//! which the mock answers slowly; during that call it sends `second` and `third` at QoS 0,
//! `fourth` at QoS 1 with packet id 7, and a PINGREQ. Then it reads until it has the PUBACK and
//! the PINGRESP.
//!
//! Control and claim are one test: with batching off the four PUBLISHes are four model calls,
//! or the three-call result proves nothing.
//!
//! LLM budget: 5 calls with batching off, 4 with it on.

use std::time::Duration;

use crate::helpers::mock_builder::MockLlmBuilder;
use crate::helpers::mock_ollama::MockOllamaServer;
use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use netget::state::ServerId;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

async fn wait_for_port(state: &AppState, id: ServerId) -> u16 {
    for _ in 0..300 {
        if let Some(s) = state.get_server(id).await {
            if let Some(addr) = s.local_addr {
                return addr.port();
            }
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("server #{} never bound a port", id.as_u32());
}

fn build_connect(client_id: &str) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&[0x00, 0x04, b'M', b'Q', b'T', b'T', 0x04, 0x02, 0x00, 0x3C]);
    body.extend_from_slice(&(client_id.len() as u16).to_be_bytes());
    body.extend_from_slice(client_id.as_bytes());
    let mut packet = vec![0x10, body.len() as u8];
    packet.extend_from_slice(&body);
    packet
}

/// A 3.1.1 PUBLISH to `batch/topic`; `packet_id` is written only for QoS 1.
fn build_publish(payload: &str, qos1_packet_id: Option<u16>) -> Vec<u8> {
    let topic = "batch/topic";
    let mut body = Vec::new();
    body.extend_from_slice(&(topic.len() as u16).to_be_bytes());
    body.extend_from_slice(topic.as_bytes());
    if let Some(id) = qos1_packet_id {
        body.extend_from_slice(&id.to_be_bytes());
    }
    body.extend_from_slice(payload.as_bytes());
    let first = if qos1_packet_id.is_some() { 0x32 } else { 0x30 };
    let mut packet = vec![first, body.len() as u8];
    packet.extend_from_slice(&body);
    packet
}

async fn read_packet(stream: &mut TcpStream) -> Vec<u8> {
    let mut header = [0u8; 2];
    tokio::time::timeout(Duration::from_secs(30), stream.read_exact(&mut header))
        .await
        .expect("no MQTT packet within 30s")
        .expect("read MQTT header");
    // Every packet in this test is under 128 bytes, so one length byte.
    let mut body = vec![0u8; header[1] as usize];
    stream.read_exact(&mut body).await.expect("read MQTT body");
    let mut packet = header.to_vec();
    packet.extend_from_slice(&body);
    packet
}

/// Run the exchange; return the (prompt, trigger data) of every `mqtt_publish` call and every
/// packet the broker sent after the CONNACK.
async fn four_publishes(batching: bool) -> (Vec<(String, serde_json::Value)>, Vec<Vec<u8>>) {
    let mock = MockOllamaServer::start(
        MockLlmBuilder::new()
            .on_event("mqtt_connect")
            .respond_with_actions(serde_json::json!([{"type": "mqtt_connack", "return_code": 0}]))
            .expect_calls(1)
            .and()
            .on_event("mqtt_publish")
            .and_event_data_contains("payload", "first")
            .respond_with_actions(serde_json::json!([]))
            .after_delay(Duration::from_millis(1500))
            .expect_calls(1)
            .and()
            // Echo the id from the event: the PUBACK is matched to its PUBLISH by it.
            .on_event("mqtt_publish")
            .and_event_data_contains("payload", "fourth")
            .respond_with_actions_from_event(
                |e| serde_json::json!([{"type": "mqtt_puback", "packet_id": e["packet_id"]}]),
            )
            .expect_calls(1)
            .and()
            .on_event("mqtt_publish")
            .respond_with_actions(serde_json::json!([]))
            .expect_at_least(1)
            .and()
            .on_any()
            .respond_with_actions(serde_json::json!([]))
            .expect_at_least(0)
            .build(),
    )
    .await
    .expect("mock ollama");

    let state = AppState::new_with_options(false, mock.base_url());
    state
        .set_llm_client(netget::llm::OllamaClient::new(mock.base_url()))
        .await;
    let (tx, _rx) = mpsc::unbounded_channel();
    let id = ServerForm {
        protocol: "mqtt".to_string(),
        port: Some(0),
        instruction: Some("Accept every client; take every message.".to_string()),
        batching: Some(batching),
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .expect("create mqtt server");
    let port = wait_for_port(&state, id).await;

    let mut stream = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    stream
        .write_all(&build_connect("batcher"))
        .await
        .expect("CONNECT");
    let connack = read_packet(&mut stream).await;
    assert_eq!(connack, vec![0x20, 0x02, 0x00, 0x00], "CONNACK accepted");

    stream
        .write_all(&build_publish("first", None))
        .await
        .expect("PUBLISH first");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while !mock
        .recorded_calls()
        .await
        .iter()
        .any(|c| c.context.event_type.as_deref() == Some("mqtt_publish"))
    {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the first PUBLISH never reached the model"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let mut rest = build_publish("second", None);
    rest.extend(build_publish("third", None));
    rest.extend(build_publish("fourth", Some(7)));
    rest.extend([0xC0, 0x00]); // PINGREQ
    stream.write_all(&rest).await.expect("write the rest");

    let mut packets = Vec::new();
    loop {
        let packet = read_packet(&mut stream).await;
        let done = packet == [0xD0, 0x00]; // PINGRESP
        packets.push(packet);
        if done {
            break;
        }
    }

    let prompts = mock
        .recorded_calls()
        .await
        .into_iter()
        .filter(|c| c.context.event_type.as_deref() == Some("mqtt_publish"))
        .map(|c| (c.context.prompt.clone(), c.context.event_data.clone()))
        .collect();
    let _ = state.remove_server(id).await;
    (prompts, packets)
}

fn assert_one_puback_for_7(packets: &[Vec<u8>], mode: &str) {
    let pubacks: Vec<&Vec<u8>> = packets.iter().filter(|p| p[0] == 0x40).collect();
    assert_eq!(
        pubacks,
        vec![&vec![0x40, 0x02, 0x00, 0x07]],
        "{mode}: the QoS 1 PUBLISH must get exactly one PUBACK, carrying its own id 7; \
         got {packets:02x?}"
    );
    assert_eq!(
        packets.len(),
        2,
        "{mode}: only the PUBACK and the PINGRESP are owed; got {packets:02x?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn qos0_publishes_during_a_call_are_answered_together_and_qos1_keeps_its_puback() {
    // === Control: batching off. Every PUBLISH is its own call. ===
    let (separate, packets) = four_publishes(false).await;
    assert_eq!(
        separate.len(),
        4,
        "CONTROL FAILED: with batching off each PUBLISH must be its own model call, or the \
         result below proves nothing. Got {:#?}",
        separate.iter().map(|(_, d)| d).collect::<Vec<_>>()
    );
    assert_one_puback_for_7(&packets, "batching off");

    // === The claim: second and third (QoS 0) are one call; fourth (QoS 1) is its own. ===
    let (batched, packets) = four_publishes(true).await;
    let triggers: Vec<&serde_json::Value> = batched.iter().map(|(_, d)| &d["payload"]).collect();
    assert_eq!(
        triggers,
        vec!["first", "third", "fourth"],
        "second and third must be answered in one call triggered by third, and fourth alone"
    );
    let (prompt, _) = &batched[1];
    let trigger_at = prompt.rfind("Event ID: mqtt_publish").expect("trigger");
    assert!(
        prompt[..trigger_at].contains(r#""payload":"second""#),
        "the earlier QoS 0 PUBLISH must be listed above the trigger:\n{prompt}"
    );
    let (fourth_prompt, _) = &batched[2];
    let fourth_trigger = fourth_prompt
        .rfind("Event ID: mqtt_publish")
        .expect("trigger");
    assert!(
        !fourth_prompt[..fourth_trigger].contains("answers all"),
        "the QoS 1 PUBLISH must not be part of a batch:\n{fourth_prompt}"
    );
    assert_one_puback_for_7(&packets, "batching on");
}

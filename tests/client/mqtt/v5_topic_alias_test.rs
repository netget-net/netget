//! NetGet's MQTT 5.0 client ends the connection when a broker sends it a Topic Alias.
//!
//! The client's CONNECT carries no Topic Alias Maximum, which is 0, so a broker MUST NOT send
//! it an alias ([MQTT-3.1.2-27]). rumqttc stores every alias it reads in an unbounded map of its
//! own, so a broker sending a fresh alias per PUBLISH could grow the client's memory without
//! limit. The client treats the first aliased PUBLISH as a protocol violation and closes.
//!
//! The broker here is a fake on 127.0.0.1 written from the OASIS MQTT 5.0 specification: it
//! answers the CONNECT, sends one ordinary QoS 1 PUBLISH — whose PUBACK proves the session
//! survives an unaliased message — and then a PUBLISH carrying a Topic Alias, after which the
//! client must close its side.
//!
//! No LLM calls: a static rule answers every client event with nothing, and the model endpoint
//! is a closed port.
use netget::cli::management::ClientForm;
use netget::state::app_state::AppState;
use netget::state::ClientStatus;
use serde_json::json;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

fn s(text: &str) -> Vec<u8> {
    let mut out = (text.len() as u16).to_be_bytes().to_vec();
    out.extend_from_slice(text.as_bytes());
    out
}

/// A PUBLISH whose remaining length fits one byte.
fn publish(qos: u8, packet_id: u16, topic: &str, props: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut body = s(topic);
    if qos > 0 {
        body.extend(packet_id.to_be_bytes());
    }
    body.push(props.len() as u8);
    body.extend_from_slice(props);
    body.extend_from_slice(payload);
    assert!(body.len() < 128);
    let mut out = vec![0x30 | (qos << 1), body.len() as u8];
    out.extend(body);
    out
}

async fn read_packet(stream: &mut TcpStream) -> Vec<u8> {
    tokio::time::timeout(Duration::from_secs(20), async {
        let mut first = [0u8; 1];
        stream.read_exact(&mut first).await.expect("client closed");
        let mut out = vec![first[0]];
        let mut len = 0usize;
        for i in 0..4 {
            let mut b = [0u8; 1];
            stream.read_exact(&mut b).await.unwrap();
            out.push(b[0]);
            len |= ((b[0] & 0x7F) as usize) << (7 * i);
            if b[0] & 0x80 == 0 {
                break;
            }
        }
        let mut body = vec![0u8; len];
        stream.read_exact(&mut body).await.unwrap();
        out.extend(body);
        out
    })
    .await
    .expect("no packet from the client")
}

#[tokio::test]
async fn a_topic_alias_from_the_broker_ends_the_connection() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let state = AppState::new_with_options(false, "http://127.0.0.1:1".to_string());
    let (tx, _rx) = mpsc::unbounded_channel();
    let id = ClientForm {
        protocol: "mqtt".into(),
        remote_addr: Some(format!("127.0.0.1:{port}")),
        instruction: Some("Listen".into()),
        startup_params: Some(json!({"protocol_version": "5.0", "client_id": "alias-target"})),
        event_handlers: Some(vec![
            json!({"event_pattern": "*", "handler": {"type": "static", "actions": []}}),
        ]),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
        tx,
    )
    .await
    .expect("create mqtt client");

    let (mut broker, _) = tokio::time::timeout(Duration::from_secs(20), listener.accept())
        .await
        .expect("the client never connected")
        .unwrap();

    // CONNECT at level 5. The premise: its property block is empty, so the client advertised
    // no Topic Alias Maximum - which means 0.
    let connect = read_packet(&mut broker).await;
    assert_eq!(connect[0], 0x10, "{connect:02x?}");
    let at = 2 + 6; // fixed header (one-byte length here), then "MQTT"
    assert_eq!(connect[at], 5, "protocol level 5: {connect:02x?}");
    assert_eq!(
        connect[at + 4],
        0,
        "the CONNECT's property block names no Topic Alias Maximum: {connect:02x?}"
    );

    // CONNACK: flags 0, Success, no properties.
    broker.write_all(&[0x20, 0x03, 0x00, 0x00, 0x00]).await.unwrap();

    // Control: an ordinary QoS 1 PUBLISH is acknowledged and the session goes on.
    broker
        .write_all(&publish(1, 7, "plain/topic", &[], b"hello"))
        .await
        .unwrap();
    assert_eq!(
        read_packet(&mut broker).await,
        vec![0x40, 0x02, 0x00, 0x07],
        "PUBACK for the unaliased PUBLISH"
    );

    // A PUBLISH carrying Topic Alias 1 (0x23). The client must close its side.
    broker
        .write_all(&publish(0, 0, "aliased/topic", &[0x23, 0x00, 0x01], b"x"))
        .await
        .unwrap();
    let closed = tokio::time::timeout(Duration::from_secs(10), async {
        let mut buf = [0u8; 256];
        loop {
            match broker.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(_) => continue,
            }
        }
    })
    .await;
    assert!(
        closed.is_ok(),
        "the client kept the connection open after a broker sent a topic alias"
    );

    // The client reports the category, and nothing from the packet.
    let status = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Some(ClientStatus::Error(msg)) = state.get_client(id).await.map(|c| c.status) {
                return msg;
            }
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
    })
    .await
    .expect("the client never reported the violation");
    assert_eq!(status, "protocol violation: topic alias");
}
